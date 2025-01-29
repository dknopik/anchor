use crate::discovery::Discovery;
use libp2p::peer_store::memory_store::MemoryStore;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{connection_limits, gossipsub, identify, peer_store, ping};

#[derive(NetworkBehaviour)]
pub struct AnchorBehaviour {
    /// Provides IP addresses and peer information.
    pub identify: identify::Behaviour,
    /// Used for connection health checks.
    pub ping: ping::Behaviour,
    /// The routing pub-sub mechanism for Anchor.
    pub gossipsub: gossipsub::Behaviour,
    /// Discv5 Discovery protocol.
    pub discovery: Discovery,
    pub peer_store: peer_store::Behaviour<MemoryStore>,
    pub connection_limits: connection_limits::Behaviour,
}
