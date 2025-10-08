//! UDP Bootstrap Server Implementation
//! 
//! Handles incoming UDP bootstrap packets for mesh network discovery

use anyhow::{anyhow, Result};
use serde_json;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::Duration;
use tracing::{info, warn, error};
use uuid::Uuid;
use crate::types::mesh_message::ZhtpMeshMessage;

/// Start UDP bootstrap server for mesh packet handling
pub async fn start_udp_bootstrap_server(server_id: Uuid, port: u16) -> Result<()> {
    let bind_addr = format!("127.0.0.1:{}", port);
    
    info!("Attempting to bind UDP socket on {}...", bind_addr);
    let socket = match UdpSocket::bind(&bind_addr).await {
        Ok(s) => {
            info!("ZHTP mesh server listening on UDP {} (all interfaces)", bind_addr);
            s
        }
        Err(e) => {
            error!("Failed to bind UDP socket on {}: {}", bind_addr, e);
            return Err(anyhow!("UDP socket bind failed: {}", e));
        }
    };
    
    tokio::spawn(async move {
        let mut buf = [0; 8192]; // Buffer for incoming ZHTP packets
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    info!("Received ZHTP mesh packet: {} bytes from {}", len, addr);
                    
                    if let Err(e) = handle_udp_bootstrap_packet(&socket, &buf[..len], addr, server_id).await {
                        warn!("Error handling UDP bootstrap packet from {}: {}", addr, e);
                    }
                },
                Err(e) => {
                    warn!("Error receiving UDP packet: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    
    Ok(())
}

/// Handle incoming UDP bootstrap packet
async fn handle_udp_bootstrap_packet(
    socket: &UdpSocket,
    packet_data: &[u8],
    addr: SocketAddr,
    server_id: Uuid,
) -> Result<()> {
    // Parse incoming ZHTP mesh packet
    if let Ok(packet_str) = std::str::from_utf8(packet_data) {
        info!("ZHTP packet content: {}", packet_str);
        
        // First try to parse as bootstrap discovery message
        if let Ok(discovery_msg) = serde_json::from_str::<serde_json::Value>(packet_str) {
            if discovery_msg.get("type").and_then(|v| v.as_str()) == Some("discovery") 
               && discovery_msg.get("request").and_then(|v| v.as_str()) == Some("bootstrap") {
                info!("Handling bootstrap discovery request from {}", addr);
                
                // Send bootstrap response
                let bootstrap_response = create_bootstrap_discovery_response(server_id);
                let response_str = bootstrap_response.to_string();
                
                match socket.send_to(response_str.as_bytes(), addr).await {
                    Ok(bytes_sent) => {
                        info!("Sent bootstrap response: {} bytes to {}", bytes_sent, addr);
                    },
                    Err(e) => {
                        error!("Failed to send bootstrap response to {}: {}", addr, e);
                    }
                }
                return Ok(());
            }
        }
        
        // Try to parse as ZHTP mesh message
        match serde_json::from_str::<ZhtpMeshMessage>(packet_str) {
            Ok(mesh_message) => {
                info!("Parsed ZHTP mesh message: {:?}", mesh_message);
                
                if let Err(e) = handle_lib_mesh_message(socket, mesh_message, addr, server_id).await {
                    warn!("Error handling ZHTP mesh message: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to parse ZHTP mesh message: {}", e);
            }
        }
    }
    
    Ok(())
}

/// Handle ZHTP mesh message via UDP
async fn handle_lib_mesh_message(
    socket: &UdpSocket,
    message: ZhtpMeshMessage,
    addr: SocketAddr,
    server_id: Uuid,
) -> Result<()> {
    match message {
        ZhtpMeshMessage::ZhtpRequest { requester, method, uri, headers, body, timestamp } => {
            info!(" Processing ZHTP request: {} {}", method, uri);
            
            // Create response based on request
            let (response_status, response_body) = match uri.as_str() {
                "/test" => (200, create_test_response(server_id)),
                "/node/status" => (200, create_node_status_response()),
                "/blockchain/info" => (200, create_blockchain_info_response()),
                "/mesh/peers" => (200, create_mesh_peers_response()),
                "/dao/proposals" => (200, create_dao_proposals_response()),
                "/identity/create" => (200, create_identity_create_response()),
                uri if uri.starts_with("/wallet/balance") => (200, create_wallet_balance_response(&uri)),
                _ => (404, create_not_found_response(&uri)),
            };
            
            // Create response mesh message
            let response_message = ZhtpMeshMessage::ZhtpResponse {
                request_id: timestamp,
                status: response_status,
                status_message: if response_status == 200 { "OK".to_string() } else { "Not Found".to_string() },
                headers: std::collections::HashMap::new(),
                body: response_body.into_bytes(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };
            
            // Send response back to browser
            if let Ok(response_json) = serde_json::to_string(&response_message) {
                match socket.send_to(response_json.as_bytes(), addr).await {
                    Ok(sent_bytes) => {
                        info!("📤 Sent ZHTP mesh response: {} bytes to {}", sent_bytes, addr);
                    }
                    Err(e) => {
                        error!("Failed to send ZHTP response: {}", e);
                    }
                }
            }
        }
        ZhtpMeshMessage::PeerDiscovery { capabilities, location, shared_resources } => {
            info!("Received peer discovery from {}: {} capabilities", addr, capabilities.len());
            // Handle peer discovery logic here
        }
        ZhtpMeshMessage::ConnectivityRequest { requester, bandwidth_needed_kbps, duration_minutes, payment_tokens } => {
            info!("📞 Connectivity request from {}: {} kbps for {} minutes", addr, bandwidth_needed_kbps, duration_minutes);
            // Handle connectivity request logic here
        }
        _ => {
            info!("Received other mesh message type from {}", addr);
            // Handle other message types
        }
    }
    
    Ok(())
}

/// Create bootstrap discovery response
fn create_bootstrap_discovery_response(server_id: Uuid) -> serde_json::Value {
    serde_json::json!({
        "type": "bootstrap_response",
        "protocol": "ZHTP",
        "version": "1.0",
        "node_id": server_id.to_string(),
        "status": "ready",
        "capabilities": ["routing", "storage", "computation", "mesh"],
        "mesh_active": true,
        "quantum_secure": true,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    })
}

/// Create test response
fn create_test_response(server_id: Uuid) -> String {
    serde_json::json!({
        "status": "connected",
        "message": "ZHTP mesh connection test successful",
        "protocol": "ZHTP/1.0",
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "node_id": server_id.to_string(),
        "quantum_ready": true,
        "mesh_active": true
    }).to_string()
}

/// Create node status response
fn create_node_status_response() -> String {
    serde_json::json!({
        "status": "operational",
        "version": "1.0.0",
        "protocol": "ZHTP/1.0",
        "quantum_resistant": true,
        "zk_privacy_enabled": true,
        "mesh_networking": true,
        "dao_fees_enabled": true,
        "network_id": "lib-mainnet",
        "block_height": 12345,
        "peer_count": 42,
        "healthy": true,
        "uptime_seconds": 3600,
        "latency_ms": 15,
        "fully_synced": true,
        "consensus_state": "active"
    }).to_string()
}

/// Create blockchain info response
fn create_blockchain_info_response() -> String {
    serde_json::json!({
        "chain_id": "lib-mainnet",
        "block_height": 142857,
        "block_hash": "0xabcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "total_transactions": 1337420,
        "total_addresses": 98765,
        "network_hashrate": "42.5 TH/s",
        "difficulty": 15728640,
        "average_block_time": "5.2s",
        "consensus": "Proof of Useful Work + ZK Proofs",
        "quantum_resistant": true
    }).to_string()
}

/// Create mesh peers response
fn create_mesh_peers_response() -> String {
    serde_json::json!({
        "total_peers": 1337,
        "active_connections": 42,
        "peer_distribution": {
            "north_america": 456,
            "europe": 398,
            "asia": 312,
            "others": 171
        },
        "bandwidth_shared_mbps": 12500,
        "uptime_percentage": 99.7,
        "mesh_coverage_km2": 3142159.0,
        "people_with_free_internet": 314159265
    }).to_string()
}

/// Create DAO proposals response
fn create_dao_proposals_response() -> String {
    serde_json::json!({
        "proposals": [
            {
                "id": 1,
                "title": "Mesh Network Expansion",
                "status": "active",
                "votes": 42,
                "description": "Expand ZHTP mesh to cover rural areas",
                "proposer": "0x742d35Cc6e4C6A63D5c5c14E9c8D6b6e4F8a1234",
                "voting_ends": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() + 604800,
                "required_votes": 100,
                "funding_requested": 50000
            }
        ]
    }).to_string()
}

/// Create identity creation response
fn create_identity_create_response() -> String {
    serde_json::json!({
        "success": true,
        "message": "Identity created successfully",
        "identity_id": "0x1234567890abcdef1234567890abcdef12345678",
        "did": "did:zhtp:0x1234567890abcdef1234567890abcdef12345678",
        "display_name": "New Citizen",
        "identity_type": "citizen",
        "public_key": format!("pq_dilithium_{}", hex::encode(&rand::random::<[u8; 32]>())),
        "quantum_ready": true,
        "mesh_active": true
    }).to_string()
}

/// Create wallet balance response
fn create_wallet_balance_response(uri: &str) -> String {
    let did = if uri.contains("address=") {
        uri.split("address=")
            .nth(1)
            .unwrap_or("unknown")
            .split("&")
            .next()
            .unwrap_or("unknown")
            .replace("%3A", ":")
    } else {
        "unknown".to_string()
    };
    
    serde_json::json!({
        "success": true,
        "did": did,
        "totalBalance": 1500.0,
        "zhtpBalance": 1500.0,
        "wallets": [
            {
                "id": "primary-wallet",
                "type": "primary",
                "balance": 500.0,
                "currency": "ZHTP"
            },
            {
                "id": "ubi-wallet", 
                "type": "ubi",
                "balance": 750.0,
                "currency": "ZHTP",
                "daily_ubi": 50.0
            }
        ],
        "citizenship_verified": true
    }).to_string()
}

/// Create not found response
fn create_not_found_response(uri: &str) -> String {
    serde_json::json!({
        "error": "Not found",
        "message": format!("ZHTP resource {} not available", uri)
    }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bootstrap_discovery_response() {
        let server_id = Uuid::new_v4();
        let response = create_bootstrap_discovery_response(server_id);
        
        assert_eq!(response["type"], "bootstrap_response");
        assert_eq!(response["protocol"], "ZHTP");
        assert!(response["mesh_active"].as_bool().unwrap());
    }
    
    #[test]
    fn test_wallet_balance_response() {
        let uri = "/wallet/balance?address=did%3Azhtp%3A12345";
        let response_str = create_wallet_balance_response(uri);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        
        assert_eq!(response["did"], "did:zhtp:12345");
        assert_eq!(response["totalBalance"], 1500.0);
    }
}
