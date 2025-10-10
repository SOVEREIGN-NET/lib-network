//! TCP Bootstrap Server Implementation
//! 
//! Handles incoming TCP bootstrap connections for mesh network entry

use anyhow::{anyhow, Result};
use serde_json;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use tracing::{info, warn, error};
use uuid::Uuid;

/// Start TCP bootstrap server to accept incoming bootstrap connections
pub async fn start_tcp_bootstrap_server(server_id: Uuid, port: u16) -> Result<()> {
    let bind_addr = format!("127.0.0.1:{}", port);
    
    info!("Starting TCP bootstrap server on {}...", bind_addr);
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => {
            info!("TCP bootstrap server listening on {} (all interfaces)", bind_addr);
            l
        }
        Err(e) => {
            error!("Failed to bind TCP listener on {}: {}", bind_addr, e);
            return Err(anyhow!("TCP listener bind failed: {}", e));
        }
    };
    
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    info!("TCP bootstrap connection from {}", addr);
                    
                    let server_id = server_id;
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_bootstrap_connection(&mut stream, addr, server_id).await {
                            warn!("Error handling TCP bootstrap connection from {}: {}", addr, e);
                        }
                    });
                },
                Err(e) => {
                    warn!("Failed to accept TCP connection: {}", e);
                }
            }
        }
    });
    
    Ok(())
}

/// Handle incoming TCP bootstrap connection
pub async fn handle_tcp_bootstrap_connection(
    stream: &mut TcpStream, 
    addr: SocketAddr, 
    server_id: Uuid
) -> Result<()> {
    info!("Handling TCP bootstrap from {}", addr);
    
    // Read handshake with timeout
    let mut buffer = [0u8; 4096];
    let n = match timeout(Duration::from_secs(10), stream.read(&mut buffer)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            error!("Error reading from TCP bootstrap connection {}: {}", addr, e);
            return Err(anyhow!("Read error: {}", e));
        },
        Err(_) => {
            warn!("⏰ TCP bootstrap connection timeout from {}", addr);
            return Err(anyhow!("Connection timeout"));
        }
    };
    
    if n == 0 {
        info!(" TCP connection closed by {}", addr);
        return Ok(());
    }
    
    let handshake_str = String::from_utf8_lossy(&buffer[..n]);
    info!("TCP bootstrap handshake from {}: {}", addr, handshake_str);
    
    // Try to parse handshake
    match serde_json::from_str::<serde_json::Value>(&handshake_str) {
        Ok(handshake) => {
            if handshake.get("type").and_then(|v| v.as_str()) == Some("handshake")
               && handshake.get("protocol").and_then(|v| v.as_str()) == Some("ZHTP") {
                
                info!("Valid ZHTP handshake from {}", addr);
                
                // Send bootstrap response
                let response = serde_json::json!({
                    "type": "handshake_response",
                    "protocol": "ZHTP",
                    "version": "1.0",
                    "node_id": server_id.to_string(),
                    "status": "ready",
                    "capabilities": ["routing", "storage", "computation", "mesh"],
                    "mesh_active": true,
                    "quantum_secure": true,
                    "bootstrap_peer": true,
                    "timestamp": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                });
                
                let response_str = response.to_string();
                match timeout(Duration::from_secs(5), stream.write_all(response_str.as_bytes())).await {
                    Ok(Ok(_)) => {
                        info!("Sent TCP bootstrap response to {}", addr);
                    },
                    Ok(Err(e)) => {
                        error!("Failed to send TCP bootstrap response to {}: {}", addr, e);
                    },
                    Err(_) => {
                        warn!("⏰ Timeout sending TCP bootstrap response to {}", addr);
                    }
                }
            } else {
                warn!("Invalid handshake from {}", addr);
            }
        },
        Err(e) => {
            warn!("Failed to parse handshake from {}: {}", addr, e);
        }
    }
    
    Ok(())
}

/// Generate bootstrap discovery response
pub fn create_bootstrap_response(server_id: Uuid) -> serde_json::Value {
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bootstrap_response_creation() {
        let server_id = Uuid::new_v4();
        let response = create_bootstrap_response(server_id);
        
        assert_eq!(response["type"], "bootstrap_response");
        assert_eq!(response["protocol"], "ZHTP");
        assert_eq!(response["version"], "1.0");
        assert_eq!(response["status"], "ready");
        assert!(response["mesh_active"].as_bool().unwrap());
        assert!(response["quantum_secure"].as_bool().unwrap());
    }
}
