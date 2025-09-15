use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use lib_crypto::PublicKey;
use crate::types::geographic::GeographicLocation;
use crate::types::mesh_capability::{MeshCapability, SharedResources};
use crate::types::connection_details::ConnectionDetails;

/// ZHTP Mesh Message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZhtpMeshMessage {
    /// Peer discovery and capability announcement
    PeerDiscovery {
        capabilities: Vec<MeshCapability>,
        location: Option<GeographicLocation>,
        shared_resources: SharedResources,
    },
    /// Request for internet connectivity
    ConnectivityRequest {
        requester: PublicKey,
        bandwidth_needed_kbps: u32,
        duration_minutes: u32,
        payment_tokens: u64,
    },
    /// Response to connectivity request
    ConnectivityResponse {
        provider: PublicKey,
        accepted: bool,
        available_bandwidth_kbps: u32,
        cost_tokens_per_mb: u64,
        connection_details: Option<ConnectionDetails>,
    },
    /// Long-range routing message
    LongRangeRoute {
        destination: PublicKey,
        relay_chain: Vec<String>,
        payload: Vec<u8>,
        max_hops: u8,
    },
    /// UBI distribution message
    UbiDistribution {
        recipient: PublicKey,
        amount_tokens: u64,
        distribution_round: u64,
        proof: Vec<u8>, // ZK proof of contribution
    },
    /// Network health report
    HealthReport {
        reporter: PublicKey,
        network_quality: f64,
        available_bandwidth: u64,
        connected_peers: u32,
        uptime_hours: u32,
    },
    /// Native ZHTP protocol request from browser/API clients
    ZhtpRequest {
        requester: PublicKey,
        method: String,
        uri: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        timestamp: u64,
    },
    /// Native ZHTP protocol response to browser/API clients
    ZhtpResponse {
        request_id: u64,
        status: u16,
        status_message: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        timestamp: u64,
    },
}
