use serde::{Deserialize, Serialize};
use lib_crypto::PublicKey;
use crate::protocols::NetworkProtocol;

/// Individual mesh connection between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConnection {
    /// Connected peer identity
    pub peer_id: PublicKey,
    /// Connection protocol (Bluetooth, WiFi Direct, LoRaWAN, etc.)
    pub protocol: NetworkProtocol,
    /// Connection strength/quality (0.0 to 1.0)
    pub signal_strength: f64,
    /// Bandwidth capacity in bytes/second
    pub bandwidth_capacity: u64,
    /// Connection latency in milliseconds
    pub latency_ms: u32,
    /// When connection was established (Unix timestamp)
    pub connected_at: u64,
    /// Total data transferred
    pub data_transferred: u64,
    /// Tokens earned from this connection
    pub tokens_earned: u64,
    /// Connection stability score
    pub stability_score: f64,
}
