use serde::{Deserialize, Serialize};

/// Types of internet connections being shared
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InternetConnectionType {
    /// High-speed fiber connection
    Fiber { speed_mbps: u32 },
    /// Cable internet
    Cable { speed_mbps: u32 },
    /// DSL connection
    DSL { speed_mbps: u32 },
    /// Cellular/5G hotspot
    Cellular { speed_mbps: u32, is_5g: bool },
    /// Satellite internet (Starlink, etc.)
    Satellite { speed_mbps: u32, latency_ms: u32 },
    /// Other connection type
    Other { description: String, speed_mbps: u32 },
}
