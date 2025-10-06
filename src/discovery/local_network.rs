//! Local Network Discovery via Multicast
//! 
//! Automatically discovers ZHTP nodes on the same local network without needing bootstrap peers

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use tokio::net::UdpSocket;
use tokio::time::{Duration, interval};
use tracing::{info, warn, error, debug};
use uuid::Uuid;

/// Multicast address for ZHTP local discovery (224.0.0.251 is mDNS standard)
const ZHTP_MULTICAST_ADDR: &str = "224.0.1.75"; // Custom ZHTP multicast address
const ZHTP_MULTICAST_PORT: u16 = 37775; // Custom port for ZHTP discovery

/// Local ZHTP node announcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAnnouncement {
    pub node_id: Uuid,
    pub mesh_port: u16,
    pub local_ip: IpAddr,
    pub protocols: Vec<String>,
    pub announced_at: u64,
}

/// Start local network discovery service
pub async fn start_local_discovery(node_id: Uuid, mesh_port: u16) -> Result<()> {
    info!("Starting local network multicast discovery...");
    
    // Start announcement broadcaster
    let announce_node_id = node_id;
    tokio::spawn(async move {
        if let Err(e) = broadcast_announcements(announce_node_id, mesh_port).await {
            error!("Local announcement broadcaster failed: {}", e);
        }
    });
    
    // Start discovery listener
    let listen_node_id = node_id;
    tokio::spawn(async move {
        if let Err(e) = listen_for_announcements(listen_node_id).await {
            error!("Local discovery listener failed: {}", e);
        }
    });
    
    info!(" Local network discovery active on {}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT);
    Ok(())
}

/// Broadcast this node's presence on local network
async fn broadcast_announcements(node_id: Uuid, mesh_port: u16) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    
    let multicast_addr: SocketAddr = format!("{}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT).parse()?;
    
    // Get local IP address
    let local_ip = get_local_ip().await.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    
    let mut interval = interval(Duration::from_secs(30)); // Announce every 30 seconds
    
    loop {
        interval.tick().await;
        
        let announcement = NodeAnnouncement {
            node_id,
            mesh_port,
            local_ip,
            protocols: vec!["tcp".to_string(), "bluetooth".to_string(), "wifi_direct".to_string()],
            announced_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        match serde_json::to_string(&announcement) {
            Ok(announcement_json) => {
                debug!("Broadcasting ZHTP node announcement to {}", multicast_addr);
                if let Err(e) = socket.send_to(announcement_json.as_bytes(), multicast_addr).await {
                    warn!("Failed to send multicast announcement: {}", e);
                }
            },
            Err(e) => {
                warn!("Failed to serialize announcement: {}", e);
            }
        }
    }
}

/// Listen for other ZHTP nodes on local network
async fn listen_for_announcements(our_node_id: Uuid) -> Result<()> {
    let socket = UdpSocket::bind(format!("{}:{}", "0.0.0.0", ZHTP_MULTICAST_PORT)).await?;
    
    // Join multicast group
    let multicast_addr: Ipv4Addr = ZHTP_MULTICAST_ADDR.parse()?;
    socket.join_multicast_v4(multicast_addr, Ipv4Addr::UNSPECIFIED)?;
    
    info!("Listening for ZHTP node announcements on multicast {}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT);
    
    let mut buf = [0; 1024];
    
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let announcement_str = String::from_utf8_lossy(&buf[..len]);
                debug!("Received announcement from {}: {}", addr, announcement_str);
                
                match serde_json::from_str::<NodeAnnouncement>(&announcement_str) {
                    Ok(announcement) => {
                        // Ignore our own announcements
                        if announcement.node_id != our_node_id {
                            info!("Discovered local ZHTP node: {} at {}:{}", 
                                announcement.node_id, 
                                announcement.local_ip, 
                                announcement.mesh_port
                            );
                            
                            // TODO: Add this peer to our connections
                            attempt_connect_to_discovered_peer(&announcement).await;
                        }
                    },
                    Err(e) => {
                        debug!("Invalid announcement format from {}: {}", addr, e);
                    }
                }
            },
            Err(e) => {
                warn!("Error receiving multicast announcement: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Attempt to connect to a newly discovered peer
async fn attempt_connect_to_discovered_peer(announcement: &NodeAnnouncement) {
    let peer_addr = format!("{}:{}", announcement.local_ip, announcement.mesh_port);
    info!("Attempting to connect to discovered peer at {}", peer_addr);
    
    // TODO: Implement actual connection logic
    // This would integrate with the mesh server's connection management
    match tokio::net::TcpStream::connect(&peer_addr).await {
        Ok(_stream) => {
            info!(" Successfully connected to local peer {}", peer_addr);
            // TODO: Complete ZHTP handshake and add to mesh
        },
        Err(e) => {
            warn!("Failed to connect to peer {}: {}", peer_addr, e);
        }
    }
}

/// Get the local IP address of this machine
async fn get_local_ip() -> Result<IpAddr> {
    // Try to connect to a remote address to determine our local IP
    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => {
            if let Ok(_) = socket.connect("8.8.8.8:80").await {
                if let Ok(local_addr) = socket.local_addr() {
                    return Ok(local_addr.ip());
                }
            }
        },
        Err(_) => {}
    }
    
    // Fallback to localhost
    Ok(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
}

/// Discover ZHTP nodes on local network immediately
pub async fn discover_local_peers() -> Result<Vec<NodeAnnouncement>> {
    info!("Scanning for ZHTP peers on local network...");
    
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    
    let multicast_addr: SocketAddr = format!("{}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT).parse()?;
    
    // Send discovery request
    let discovery_request = serde_json::json!({
        "type": "discovery_request",
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    
    socket.send_to(discovery_request.to_string().as_bytes(), multicast_addr).await?;
    
    // Listen for responses (simplified - in real implementation would be more sophisticated)
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    // TODO: Collect actual responses
    Ok(vec![])
}