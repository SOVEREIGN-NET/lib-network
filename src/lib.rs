//! ZHTP Mesh Protocol - Revolutionary Internet Replacement
//! 
//! This package implements the core mesh networking protocol that completely
//! replaces the traditional internet infrastructure. Features:
//! 
//! - Complete ISP bypass through multi-protocol mesh networking
//! - Long-range communication via LoRaWAN, WiFi Direct, and Bluetooth LE
//! - Economic incentives for sharing connectivity and resources
//! - Zero-knowledge privacy for all communications
//! - Post-quantum cryptographic security
//! - Native ZHTP protocol (not HTTP) designed for mesh networks
//! - DHT client layer that uses lib-storage as the DHT implementation backend

// Re-exports for external use
pub use crate::mesh::server::ZhtpMeshServer;
pub use crate::mesh::connection::MeshConnection;
pub use crate::mesh::statistics::MeshProtocolStats;
pub use crate::types::*;
pub use crate::discovery::*;
pub use crate::relays::*;
pub use crate::sharing::*;

// DHT client integration with lib-storage backend
pub use crate::dht::{DHTClient, initialize_dht_client, serve_web4_page};

// Core modules
pub mod types;
pub mod mesh;
pub mod discovery;
pub mod relays;
pub mod sharing;
pub mod routing;
pub mod protocols;
pub mod bootstrap;
pub mod messaging;
pub mod monitoring;
pub mod zk_integration;
pub mod testing;
pub mod platform;
pub mod dht; // DHT client layer that uses lib-storage

// External dependencies for economics, API, and storage
pub use lib_economy as economics;
pub use lib_protocols as api;
pub use lib_storage; // Direct access to storage backend
pub use lib_identity;

// Public API convenience functions
pub use crate::testing::test_utils::create_test_mesh_server;

/// Get active peer count from the mesh network
pub async fn get_active_peer_count() -> Result<usize> {
    // Get peer count from mesh statistics
    let stats = crate::mesh::statistics::get_mesh_statistics().await?;
    Ok(stats.active_peers as usize)
}

/// Get network statistics from the mesh
pub async fn get_network_statistics() -> Result<NetworkStatistics> {
    let mesh_stats = crate::mesh::statistics::get_mesh_statistics().await?;
    
    Ok(NetworkStatistics {
        bytes_sent: mesh_stats.bytes_sent,
        bytes_received: mesh_stats.bytes_received,
        packets_sent: mesh_stats.packets_sent,
        packets_received: mesh_stats.packets_received,
        peer_count: mesh_stats.active_peers as usize,
        connection_count: mesh_stats.active_connections as usize,
    })
}

/// Get mesh status information
pub async fn get_mesh_status() -> Result<MeshStatus> {
    let mesh_stats = crate::mesh::statistics::get_mesh_statistics().await?;
    let discovery_stats = crate::discovery::get_discovery_statistics().await?;
    
    Ok(MeshStatus {
        internet_connected: mesh_stats.internet_connectivity,
        mesh_connected: mesh_stats.mesh_connectivity,
        connectivity_percentage: mesh_stats.connectivity_percentage,
        relay_connectivity: mesh_stats.relay_connectivity,
        active_peers: mesh_stats.active_peers,
        local_peers: discovery_stats.local_peers,
        regional_peers: discovery_stats.regional_peers,
        global_peers: discovery_stats.global_peers,
        relay_peers: discovery_stats.relay_peers,
        churn_rate: mesh_stats.churn_rate,
        coverage: mesh_stats.coverage,
        redundancy: mesh_stats.redundancy,
        stability: mesh_stats.stability,
        protocol_health: mesh_stats.protocol_health,
    })
}

/// Get bandwidth statistics from the mesh
pub async fn get_bandwidth_statistics() -> Result<BandwidthStatistics> {
    let mesh_stats = crate::mesh::statistics::get_mesh_statistics().await?;
    
    Ok(BandwidthStatistics {
        upload_utilization: mesh_stats.upload_utilization,
        download_utilization: mesh_stats.download_utilization,
        efficiency: mesh_stats.bandwidth_efficiency,
        congestion_level: mesh_stats.congestion_level,
    })
}

/// Get latency statistics from the mesh
pub async fn get_latency_statistics() -> Result<LatencyStatistics> {
    let mesh_stats = crate::mesh::statistics::get_mesh_statistics().await?;
    
    Ok(LatencyStatistics {
        average_latency: mesh_stats.average_latency,
        variance: mesh_stats.latency_variance,
        timeout_rate: mesh_stats.timeout_rate,
        jitter: mesh_stats.jitter,
    })
}

/// Initialize complete mesh network with DHT client integration
pub async fn initialize_mesh_with_dht(identity: lib_identity::ZhtpIdentity) -> Result<(ZhtpMeshServer, DHTClient)> {
    info!("🌐 Initializing complete mesh network with DHT integration...");
    
    // Initialize mesh server
    let mesh_server = crate::testing::test_utils::create_test_mesh_server().await?;
    
    // Initialize DHT client with lib-storage backend
    let dht_client = initialize_dht_client(identity).await?;
    
    info!("✅ Mesh network with DHT client integration ready");
    Ok((mesh_server, dht_client))
}

/// Serve a Web4 page through the integrated mesh network and DHT
pub async fn serve_web4_page_through_mesh(
    dht_client: &mut DHTClient, 
    url: &str
) -> Result<serde_json::Value> {
    info!("🌐 Serving Web4 page through integrated mesh+DHT: {}", url);
    
    // Use the DHT client to serve the page through lib-storage backend
    serve_web4_page(dht_client, url).await
}

// Constants
pub const ZHTP_DEFAULT_PORT: u16 = 9333;
pub const ZHTP_PROTOCOL_VERSION: &str = "1.0";
pub const ZHTP_MAX_PACKET_SIZE: usize = 8192;
pub const ZHTP_MESH_DISCOVERY_TIMEOUT_MS: u64 = 10000;
pub const ZHTP_BOOTSTRAP_TIMEOUT_MS: u64 = 5000;

// Error types
pub use anyhow::{Result, Error};

// External dependencies re-exports
pub use serde::{Deserialize, Serialize};
pub use tokio;
pub use uuid::Uuid;

use tracing::info;
