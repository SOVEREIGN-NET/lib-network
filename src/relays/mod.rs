// use serde::{Deserialize, Serialize}; // Removed - unused imports
// use lib_crypto::PublicKey; // Removed - unused import
// use crate::types::relay_type::LongRangeRelayType; // Removed - unused import

pub mod long_range_relay;
pub mod lorawan_gateway;
pub mod satellite_info;
pub mod wifi_network;
pub mod regional_relay;  // NEW: Regional relay for mesh blockchain aggregation

pub use lorawan_gateway::*;
pub use satellite_info::*;
pub use wifi_network::*;

// Re-export the main LongRangeRelay from long_range_relay module
pub use long_range_relay::LongRangeRelay;

// Re-export regional relay types
pub use regional_relay::{
    RegionalRelayNode, RelayId, SyncBatchId, MeshRegistration, MeshStatus,
    SyncBatch, BatchStatus, UTXOConflictTracker, UTXOReference, UTXOConflict,
    RelayConfig, RelayStatistics,
};
