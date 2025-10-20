//! GATT (Generic Attribute Profile) Common Operations
//! 
//! Shared GATT functionality for characteristic read/write operations

use anyhow::{Result, anyhow};
use tracing::{info, debug};

/// GATT operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GattOperation {
    Read,
    Write,
    WriteWithoutResponse,
    Notify,
    Indicate,
}

/// Parse GATT characteristic properties from string flags
pub fn parse_characteristic_properties(flags: &[String]) -> Vec<GattOperation> {
    let mut operations = Vec::new();
    
    for flag in flags {
        match flag.to_lowercase().as_str() {
            "read" => operations.push(GattOperation::Read),
            "write" => operations.push(GattOperation::Write),
            "write-without-response" => operations.push(GattOperation::WriteWithoutResponse),
            "notify" => operations.push(GattOperation::Notify),
            "indicate" => operations.push(GattOperation::Indicate),
            _ => debug!("Unknown GATT property: {}", flag),
        }
    }
    
    operations
}

/// Check if a characteristic supports a specific operation
pub fn supports_operation(properties: &[String], operation: GattOperation) -> bool {
    parse_characteristic_properties(properties).contains(&operation)
}

/// Validate GATT write data size against MTU
pub fn validate_write_size(data: &[u8], mtu: u16) -> Result<()> {
    // GATT ATT header is 3 bytes
    let max_data_size = (mtu as usize).saturating_sub(3);
    
    if data.len() > max_data_size {
        return Err(anyhow!(
            "Data size {} exceeds MTU limit {} (MTU: {} - 3 byte header)",
            data.len(), max_data_size, mtu
        ));
    }
    
    Ok(())
}

/// Fragment data for GATT transmission
pub fn fragment_data(data: &[u8], mtu: u16) -> Vec<Vec<u8>> {
    let max_chunk_size = (mtu as usize).saturating_sub(3);
    
    data.chunks(max_chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Calculate optimal MTU for connection
pub fn calculate_optimal_mtu(requested_mtu: u16, max_mtu: u16) -> u16 {
    // BLE spec minimum is 23, maximum is typically 512
    const MIN_MTU: u16 = 23;
    const MAX_BLE_MTU: u16 = 512;
    
    let effective_max = max_mtu.min(MAX_BLE_MTU);
    requested_mtu.clamp(MIN_MTU, effective_max)
}

/// GATT message types for unified handling
#[derive(Debug, Clone)]
pub enum GattMessage {
    /// Raw data from GATT write (characteristic UUID, data)
    RawData(String, Vec<u8>),
    /// Mesh handshake
    MeshHandshake(Vec<u8>),
    /// DHT bridge message
    DhtBridge(String),
    /// ZHTP relay query
    RelayQuery(Vec<u8>),
}

impl GattMessage {
    /// Parse raw GATT data into appropriate message type
    pub fn from_raw(char_uuid: &str, data: Vec<u8>) -> Self {
        // Try to parse based on characteristic UUID and data content
        match char_uuid {
            uuid if uuid.contains("6ba7b813") => {
                // Mesh data characteristic
                if data.len() >= 8 {
                    GattMessage::MeshHandshake(data)
                } else if let Ok(text) = String::from_utf8(data.clone()) {
                    if text.starts_with("DHT:") {
                        GattMessage::DhtBridge(text)
                    } else {
                        GattMessage::RawData(char_uuid.to_string(), data)
                    }
                } else {
                    GattMessage::RawData(char_uuid.to_string(), data)
                }
            }
            _ => GattMessage::RawData(char_uuid.to_string(), data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_characteristic_properties() {
        let flags = vec!["read".to_string(), "write".to_string(), "notify".to_string()];
        let ops = parse_characteristic_properties(&flags);
        
        assert_eq!(ops.len(), 3);
        assert!(ops.contains(&GattOperation::Read));
        assert!(ops.contains(&GattOperation::Write));
        assert!(ops.contains(&GattOperation::Notify));
    }
    
    #[test]
    fn test_supports_operation() {
        let flags = vec!["read".to_string(), "write".to_string()];
        
        assert!(supports_operation(&flags, GattOperation::Read));
        assert!(supports_operation(&flags, GattOperation::Write));
        assert!(!supports_operation(&flags, GattOperation::Notify));
    }
    
    #[test]
    fn test_validate_write_size() {
        let data = vec![0u8; 100];
        
        // Should succeed with MTU 150
        assert!(validate_write_size(&data, 150).is_ok());
        
        // Should fail with MTU 50
        assert!(validate_write_size(&data, 50).is_err());
    }
    
    #[test]
    fn test_fragment_data() {
        let data = vec![0u8; 100];
        let fragments = fragment_data(&data, 30); // 30 - 3 = 27 bytes per chunk
        
        assert!(fragments.len() >= 4); // 100 / 27 = ~4 chunks
        assert!(fragments[0].len() <= 27);
    }
    
    #[test]
    fn test_calculate_optimal_mtu() {
        assert_eq!(calculate_optimal_mtu(50, 100), 50);
        assert_eq!(calculate_optimal_mtu(600, 512), 512);
        assert_eq!(calculate_optimal_mtu(10, 100), 23); // Clamps to minimum
    }
}
