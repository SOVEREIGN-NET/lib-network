use serde::{Deserialize, Serialize};

pub mod bluetooth;
pub mod bluetooth_classic;
pub mod wifi_direct;
pub mod lorawan;
pub mod satellite;
pub mod zhtp_auth;
pub mod zhtp_encryption;

// Enhanced protocol implementations with platform-specific optimizations
#[cfg(feature = "enhanced-bluetooth")]
pub mod enhanced_bluetooth;

#[cfg(feature = "enhanced-wifi-direct")]
pub mod enhanced_wifi_direct;

/// Network protocol enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkProtocol {
    /// Bluetooth Low Energy for device-to-device communication
    BluetoothLE,
    /// Bluetooth Classic (BR/EDR) for high-throughput mesh
    BluetoothClassic,
    /// WiFi Direct for medium-range peer connections
    WiFiDirect,
    /// LoRaWAN for long-range low-power communication
    LoRaWAN,
    /// Satellite for global coverage
    Satellite,
    /// TCP for internet bridging
    TCP,
    /// UDP for mesh networking
    UDP,
}
