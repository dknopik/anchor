use crate::network::gossipsub::MessageId;
use std::num::{NonZeroU8, NonZeroUsize};
use std::pin::Pin;
use std::time::Duration;

use futures::StreamExt;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::gossipsub::{
    IdentTopic, Message, MessageAcceptance, MessageAuthenticity, ValidationMode,
};
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{futures, gossipsub, identify, ping, PeerId, Swarm, SwarmBuilder};
use lighthouse_network::discovery::DiscoveredPeers;
use lighthouse_network::discv5::enr::k256::sha2::{Digest, Sha256};
use lighthouse_network::EnrExt;
use subnet_tracker::{SubnetEvent, SubnetId};
use task_executor::TaskExecutor;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::behaviour::AnchorBehaviour;
use crate::behaviour::AnchorBehaviourEvent;
use crate::discovery::{Discovery, FIND_NODE_QUERY_CLOSEST_PEERS};
use crate::keypair_utils::load_private_key;
use crate::transport::build_transport;
use crate::Config;

pub struct Network {
    swarm: Swarm<AnchorBehaviour>,
    subnet_event_receiver: mpsc::Receiver<SubnetEvent>,
    peer_id: PeerId,
}

impl Network {
    // Creates an instance of the Network struct to start sending and receiving information on the
    // p2p network.
    pub async fn try_new(
        config: &Config,
        subnet_event_receiver: mpsc::Receiver<SubnetEvent>,
        executor: TaskExecutor,
    ) -> Result<Network, String> {
        let local_keypair: Keypair = load_private_key(&config.network_dir);
        let transport = build_transport(local_keypair.clone(), !config.disable_quic_support);
        let behaviour = build_anchor_behaviour(local_keypair.clone(), config).await;
        let peer_id = local_keypair.public().to_peer_id();

        let mut network = Network {
            swarm: build_swarm(
                executor.clone(),
                local_keypair,
                transport,
                behaviour,
                config,
            ),
            subnet_event_receiver,
            peer_id,
        };

        info!(%peer_id, "Network starting");

        for listen_multiaddr in config.listen_addresses.libp2p_addresses() {
            // If QUIC is disabled, ignore listening on QUIC ports
            if config.disable_quic_support && listen_multiaddr.iter().any(|v| v == Protocol::QuicV1)
            {
                continue;
            }

            network
                .swarm
                .listen_on(listen_multiaddr.clone())
                .map_err(|e| {
                    format!(
                        "Unable to listen on libp2p address: {} : {}",
                        listen_multiaddr, e
                    )
                })?;
            let mut log_address = listen_multiaddr;
            log_address.push(Protocol::P2p(peer_id));
            info!(address = %log_address, "Listening established");
        }
        /*
        TODO
        - Dial peers
        - Subscribe gossip topics
         */

        // TODO: Return channels for input/output
        Ok(network)
    }

    /// Main loop for polling and handling swarm and channels.
    pub async fn run(mut self) {
        let topic = IdentTopic::new("ssv.v2.9");

        match self.swarm.behaviour_mut().gossipsub.subscribe(&topic) {
            Err(e) => {
                warn!(topic = %topic, "error" = ?e, "Failed to subscribe to topic");
            }
            Ok(_) => {
                debug!(topic = %topic, "Subscribed to topic");
            }
        }

        loop {
            tokio::select! {
                swarm_message = self.swarm.select_next_some() => {
                    match swarm_message {
                        SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
                            AnchorBehaviourEvent::Gossipsub(ge) => {
                                match ge {
                                    gossipsub::Event::Message {
                                        propagation_source,
                                        message_id,
                                        message,
                                    } => {
                                        self.on_message_received(
                                            propagation_source,
                                            &message_id,
                                            message,
                                        );
                                    }
                                    // TODO handle gossipsub events
                                    _ => {
                                        debug!(event = ?ge, "Unhandled gossipsub event");
                                    }
                                }
                            },
                            // Inform the peer manager about discovered peers.
                            //
                            // The peer manager will subsequently decide which peers need to be dialed and then dial
                            // them.
                            AnchorBehaviourEvent::Discovery(DiscoveredPeers { peers }) => {
                                //self.peer_manager_mut().peers_discovered(peers);
                                debug!(peers =  ?peers, "Peers discovered");
                                for (enr, _) in peers {
                                    for tcp in enr.multiaddr_tcp() {
                                        trace!(address = ?tcp, "Dialing peer");
                                        if let Err(e) = self.swarm.dial(tcp.clone()) {
                                            error!(address = ?tcp, error = ?e, "Error dialing peer");
                                        }
                                    }
                                }
                            }
                            // TODO handle other behaviour events
                            _ => {
                                debug!(event = ?behaviour_event, "Unhandled behaviour event");
                            }
                        },
                        // TODO handle other swarm events
                        _ => {
                            debug!(event = ?swarm_message, "Unhandled swarm event");
                        }
                    }
                },
                event = self.subnet_event_receiver.recv() => {
                    match event {
                        Some(event) => self.on_subnet_tracker_event(event),
                        None => {
                            error!("subnet tracker has quit");
                            return;
                        }
                    }
                }
                // TODO match input channels
            }
        }
    }

    fn on_message_received(
        &mut self,
        propagation_source: PeerId,
        message_id: &MessageId,
        message: Message,
    ) {
        debug!(
            source = ?propagation_source,
            id = ?message_id,
            "Received SignedSSVMessage"
        );

        let result = self.validate_message(message);
        let acceptance = if let Err(f) = &result {
            f.into()
        } else {
            MessageAcceptance::Accept
        };
        let _ = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(message_id, &propagation_source, acceptance);

        let Ok(_message) = result else {
            return;
        };

        // todo pass on to app
    }

    fn on_subnet_tracker_event(&mut self, event: SubnetEvent) {
        match event {
            SubnetEvent::Join(subnet) => {
                if let Err(err) = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&subnet_to_topic(subnet))
                {
                    error!(?err, subnet = *subnet, "can't subscribe");
                }
                self.swarm
                    .behaviour_mut()
                    .discovery
                    .start_subnet_query(vec![subnet]);
            }
            SubnetEvent::Leave(subnet) => {
                if let Err(err) = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .unsubscribe(&subnet_to_topic(subnet))
                {
                    error!(?err, subnet = *subnet, "can't unsubscribe");
                }
            }
        }
    }
}

fn subnet_to_topic(subnet: SubnetId) -> IdentTopic {
    IdentTopic::new(format!("ssv.{}", *subnet))
}

async fn build_anchor_behaviour(
    local_keypair: Keypair,
    network_config: &Config,
) -> AnchorBehaviour {
    // TODO setup discv5
    let identify = {
        let local_public_key = local_keypair.public();
        let identify_config = identify::Config::new("anchor".into(), local_public_key)
            .with_agent_version(version::version_with_platform())
            .with_cache_size(0);
        identify::Behaviour::new(identify_config)
    };

    // TODO those values might need to be parameterized based on the network
    let slots_per_epoch = 32;
    let seconds_per_slot = 12;
    let duplicate_cache_time = Duration::from_secs(slots_per_epoch * seconds_per_slot); // 6.4 min

    let gossip_message_id = move |message: &gossipsub::Message| {
        gossipsub::MessageId::from(&Sha256::digest(&message.data)[..20])
    };

    // TODO Add Topic Message Validator and Subscription Filter
    let config = gossipsub::ConfigBuilder::default()
        .duplicate_cache_time(duplicate_cache_time)
        .message_id_fn(gossip_message_id)
        .flood_publish(false)
        .validation_mode(ValidationMode::Permissive)
        .mesh_n(8) //D
        .mesh_n_low(6) // Dlo
        .mesh_n_high(12) // Dhi
        .mesh_outbound_min(4) // Dout
        .heartbeat_interval(Duration::from_millis(700))
        .history_length(6)
        .history_gossip(4)
        .max_ihave_length(1500)
        .max_ihave_messages(32)
        .build()
        .unwrap();

    let gossipsub =
        gossipsub::Behaviour::new(MessageAuthenticity::Signed(local_keypair.clone()), config)
            .unwrap();

    let discovery = {
        // Build and start the discovery sub-behaviour
        let mut discovery = Discovery::new(local_keypair.clone(), network_config)
            .await
            .unwrap();
        // start searching for peers
        discovery.discover_peers(FIND_NODE_QUERY_CLOSEST_PEERS);
        discovery
    };

    AnchorBehaviour {
        identify,
        ping: ping::Behaviour::default(),
        gossipsub,
        discovery,
    }
}

fn build_swarm(
    executor: TaskExecutor,
    local_keypair: Keypair,
    transport: Boxed<(PeerId, StreamMuxerBox)>,
    behaviour: AnchorBehaviour,
    _config: &Config,
) -> Swarm<AnchorBehaviour> {
    // use the executor for libp2p
    struct Executor(task_executor::TaskExecutor);
    impl libp2p::swarm::Executor for Executor {
        fn exec(&self, f: Pin<Box<dyn futures::Future<Output = ()> + Send>>) {
            self.0.spawn(f, "libp2p");
        }
    }

    // TODO: revisit once peer manager is integrated
    // let connection_limits = {
    //     let limits = libp2p::connection_limits::ConnectionLimits::default()
    //         .with_max_pending_incoming(Some(5))
    //         .with_max_pending_outgoing(Some(16))
    //         .with_max_established_incoming(Some(
    //             (config.target_peers as f32
    //                 * (1.0 + PEER_EXCESS_FACTOR - MIN_OUTBOUND_ONLY_FACTOR))
    //                 .ceil() as u32,
    //         ))
    //         .with_max_established_outgoing(Some(
    //             (config.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR)).ceil() as u32,
    //         ))
    //         .with_max_established(Some(
    //             (config.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS))
    //                 .ceil() as u32,
    //         ))
    //         .with_max_established_per_peer(Some(1));
    //
    //     libp2p::connection_limits::Behaviour::new(limits)
    // };

    let swarm_config = libp2p::swarm::Config::with_executor(Executor(executor))
        .with_notify_handler_buffer_size(NonZeroUsize::new(7).expect("Not zero"))
        .with_per_connection_event_buffer_size(4)
        .with_dial_concurrency_factor(NonZeroU8::new(1).unwrap());

    // TODO Add metrics later
    SwarmBuilder::with_existing_identity(local_keypair)
        .with_tokio()
        .with_other_transport(|_key| transport)
        .expect("infalible")
        .with_behaviour(|_| behaviour)
        .expect("infalible")
        .with_swarm_config(|_| swarm_config)
        .build()
}

#[cfg(test)]
mod test {
    use crate::network::Network;
    use crate::Config;
    use std::time::Duration;
    use subnet_tracker::test_tracker;
    use task_executor::TaskExecutor;

    #[tokio::test]
    async fn create_network() {
        let handle = tokio::runtime::Handle::current();
        let (_signal, exit) = async_channel::bounded(1);
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let task_executor = TaskExecutor::new(handle, exit, shutdown_tx);
        let subnet_tracker = test_tracker(task_executor.clone(), vec![], Duration::ZERO);
        assert!(
            Network::try_new(&Config::default(), subnet_tracker, task_executor)
                .await
                .is_ok()
        );
    }
}
