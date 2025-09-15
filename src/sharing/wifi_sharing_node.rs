use serde::{Deserialize, Serialize};
use lib_crypto::PublicKey;
use crate::types::*;

/// WiFi sharing node that provides internet access to mesh
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiFiSharingNode {
    /// Node operator's identity
    pub operator: PublicKey,
    /// Available bandwidth for sharing (Mbps)
    pub shared_bandwidth_mbps: u32,
    /// Data cap if any (GB per month)
    pub monthly_data_cap_gb: Option<u32>,
    /// Tokens earned per GB shared
    pub tokens_per_gb: u64,
    /// Connection type and speed
    pub connection_type: InternetConnectionType,
    /// Geographic location (for mesh routing)
    pub location: Option<GeographicLocation>,
    /// Total data shared this month
    pub data_shared_this_month_gb: u32,
    /// Revenue earned this month
    pub revenue_this_month: u64,
}
