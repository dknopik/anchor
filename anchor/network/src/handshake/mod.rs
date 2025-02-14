mod codec;
mod envelope;
pub mod node_info;

use crate::handshake::codec::Codec;
use crate::handshake::node_info::NodeInfo;
use discv5::libp2p_identity::Keypair;
use libp2p::request_response::{
    Behaviour as RequestResponseBehaviour, Config, InboundFailure, Message, OutboundFailure,
    ProtocolSupport, ResponseChannel,
};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{PeerId, StreamProtocol};
use tracing::trace;

pub type Behaviour = RequestResponseBehaviour<Codec>;
pub type Event = <Behaviour as NetworkBehaviour>::ToSwarm;

#[derive(Debug)]
pub enum Error {
    NetworkMismatch { ours: String, theirs: String },
    NodeInfo(node_info::Error),
    Inbound(InboundFailure),
    Outbound(OutboundFailure),
}

/// Event emitted on handshake completion or failure.
#[derive(Debug)]
pub struct Completed {
    pub peer_id: PeerId,
    pub their_info: NodeInfo,
}

#[derive(Debug)]
pub struct Failed {
    pub peer_id: PeerId,
    pub error: Box<Error>,
}

/// Network behaviour handling the handshake protocol.
pub struct Handler {
    /// Local node's information
    node_info: NodeInfo,
}

pub fn create_behaviour(keypair: Keypair) -> Behaviour {
    // NodeInfoProtocol is the protocol.ID used for handshake
    const NODE_INFO_PROTOCOL: &str = "/ssv/info/0.0.1";

    let protocol = StreamProtocol::new(NODE_INFO_PROTOCOL);
    Behaviour::with_codec(
        Codec::new(keypair),
        [(protocol, ProtocolSupport::Full)],
        Config::default(),
    )
}

impl Handler {
    pub fn new(node_info: NodeInfo) -> Self {
        Self { node_info }
    }

    fn verify_node_info(&mut self, node_info: &NodeInfo) -> Result<(), Error> {
        let ours = &self.node_info.network_id;
        if node_info.network_id != *ours {
            return Err(Error::NetworkMismatch {
                ours: ours.clone(),
                theirs: node_info.network_id.clone(),
            });
        }
        Ok(())
    }

    pub fn handle_handshake_event(
        &mut self,
        behaviour: &mut Behaviour,
        event: Event,
    ) -> Option<Result<Completed, Failed>> {
        match event {
            Event::Message {
                peer,
                message:
                    Message::Request {
                        request_id: _,
                        request,
                        channel,
                    },
            } => Some(self.handle_handshake_request(behaviour, peer, request, channel)),
            Event::Message {
                peer,
                message:
                    Message::Response {
                        request_id: _,
                        response,
                    },
            } => Some(self.handle_handshake_response(peer, response)),
            Event::OutboundFailure {
                peer,
                request_id: _,
                error,
            } => Some(Err(Failed {
                peer_id: peer,
                error: Box::new(Error::Outbound(error)),
            })),
            Event::InboundFailure {
                peer,
                request_id: _,
                error,
            } => Some(Err(Failed {
                peer_id: peer,
                error: Box::new(Error::Inbound(error)),
            })),
            Event::ResponseSent { .. } => None,
        }
    }

    pub fn handle_handshake_request(
        &mut self,
        behaviour: &mut Behaviour,
        peer_id: PeerId,
        request: NodeInfo,
        channel: ResponseChannel<NodeInfo>,
    ) -> Result<Completed, Failed> {
        trace!(?peer_id, "handling handshake request");
        // Handle incoming request: send response then verify
        // Any error here is handled by the InboundFailure handler
        let _ = behaviour.send_response(channel, self.node_info.clone());

        self.verify_node_info(&request).map_err(|error| Failed {
            peer_id,
            error: Box::new(error),
        })?;

        Ok(Completed {
            peer_id,
            their_info: request,
        })
    }

    pub fn handle_handshake_response(
        &mut self,
        peer_id: PeerId,
        response: NodeInfo,
    ) -> Result<Completed, Failed> {
        trace!(?peer_id, "handling handshake response");
        self.verify_node_info(&response).map_err(|error| Failed {
            peer_id,
            error: Box::new(error),
        })?;

        Ok(Completed {
            peer_id,
            their_info: response,
        })
    }

    pub fn initiate_handshake(&self, behaviour: &mut Behaviour, peer_id: PeerId) {
        trace!(?peer_id, "initiating handshake");
        behaviour.send_request(&peer_id, self.node_info.clone());
    }
}

#[cfg(test)]
mod tests {
    // Init tracing
    static TRACING: LazyLock<()> = LazyLock::new(|| {
        let env_filter = tracing_subscriber::EnvFilter::new("trace");
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    });

    use super::*;
    use crate::handshake::node_info::NodeMetadata;
    use discv5::libp2p_identity::Keypair;
    use libp2p_swarm::{Swarm, SwarmEvent};
    use libp2p_swarm_test::SwarmExt;
    use std::sync::LazyLock;
    use tokio::select;

    fn node_info(network: &str, version: &str) -> NodeInfo {
        NodeInfo {
            network_id: network.to_string(),
            metadata: Some(NodeMetadata {
                node_version: version.to_string(),
                execution_node: "".to_string(),
                consensus_node: "".to_string(),
                subnets: "".to_string(),
            }),
        }
    }

    #[tokio::test]
    async fn handshake_success() {
        *TRACING;

        let local_key = Keypair::generate_ed25519();
        let remote_key = Keypair::generate_ed25519();

        let mut local_swarm = Swarm::new_ephemeral(|_| create_behaviour(local_key));
        let mut local_handler = Handler::new(node_info("test", "local"));
        let mut remote_swarm = Swarm::new_ephemeral(|_| create_behaviour(remote_key));
        let mut remote_handler = Handler::new(node_info("test", "remote"));

        tokio::spawn(async move {
            local_swarm.listen().with_memory_addr_external().await;

            remote_swarm.connect(&mut local_swarm).await;

            remote_handler
                .initiate_handshake(remote_swarm.behaviour_mut(), *local_swarm.local_peer_id());

            let mut local_completed = false;
            let mut remote_completed = false;

            while !local_completed && !remote_completed {
                select!(
                    SwarmEvent::Behaviour(e) = local_swarm.next_swarm_event() => {
                        let Some(result) = local_handler
                            .handle_handshake_event(local_swarm.behaviour_mut(), e) else {
                            continue;
                        };
                        let Completed {
                            peer_id,
                            their_info,
                        } = result.expect("handshake to succeed");
                        assert_eq!(peer_id, *remote_swarm.local_peer_id());
                        assert_eq!(their_info.metadata.unwrap().node_version, "remote");
                        local_completed = true;
                    }
                    SwarmEvent::Behaviour(e) = remote_swarm.next_swarm_event() => {
                        let Some(result) = remote_handler
                            .handle_handshake_event(remote_swarm.behaviour_mut(), e) else {
                            continue;
                        };
                        let Completed {
                            peer_id,
                            their_info,
                        } = result.expect("handshake to succeed");
                        assert_eq!(peer_id, *local_swarm.local_peer_id());
                        assert_eq!(their_info.metadata.unwrap().node_version, "local");
                        remote_completed = true;
                    }
                    else => {}
                )
            }
        })
        .await
        .expect("tokio runtime failed");
    }

    #[tokio::test]
    async fn mismatched_networks_handshake_failed() {
        *TRACING;

        let local_key = Keypair::generate_ed25519();
        let remote_key = Keypair::generate_ed25519();

        let mut local_swarm = Swarm::new_ephemeral(|_| create_behaviour(local_key));
        let mut local_handler = Handler::new(node_info("test1", "local"));
        let mut remote_swarm = Swarm::new_ephemeral(|_| create_behaviour(remote_key));
        let mut remote_handler = Handler::new(node_info("test2", "remote"));

        tokio::spawn(async move {
            local_swarm.listen().with_memory_addr_external().await;

            remote_swarm.connect(&mut local_swarm).await;

            remote_handler
                .initiate_handshake(remote_swarm.behaviour_mut(), *local_swarm.local_peer_id());

            let mut local_failed = false;
            let mut remote_failed = false;

            while !local_failed && !remote_failed {
                select!(
                    SwarmEvent::Behaviour(e) = local_swarm.next_swarm_event() => {
                        let Some(result) = local_handler
                            .handle_handshake_event(local_swarm.behaviour_mut(), e) else {
                            continue;
                        };
                        let Failed {
                            peer_id,
                            error,
                        } = result.expect_err("handshake to fail");
                        let Error::NetworkMismatch { ours, theirs } = *error else {
                            panic!("expected network mismatch");
                        };
                        assert_eq!(peer_id, *remote_swarm.local_peer_id());
                        assert_eq!(ours, "test1");
                        assert_eq!(theirs, "test2");
                        local_failed = true;
                    }
                    SwarmEvent::Behaviour(e) = remote_swarm.next_swarm_event() => {
                        let Some(result) = remote_handler
                            .handle_handshake_event(remote_swarm.behaviour_mut(), e) else {
                            continue;
                        };
                        let Failed {
                            peer_id,
                            error,
                        } = result.expect_err("handshake to fail");
                        let Error::NetworkMismatch { ours, theirs } = *error else {
                            panic!("expected network mismatch");
                        };
                        assert_eq!(peer_id, *local_swarm.local_peer_id());
                        assert_eq!(ours, "test2");
                        assert_eq!(theirs, "test1");
                        remote_failed = true;
                    }
                    else => {}
                )
            }
        })
        .await
        .expect("tokio runtime failed");
    }
}
