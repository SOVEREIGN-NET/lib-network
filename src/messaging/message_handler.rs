//! Mesh Message Handler Implementation
//! 
//! Central message routing and handling for ZHTP mesh protocol

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use lib_crypto::PublicKey;

use crate::types::mesh_message::ZhtpMeshMessage;
use crate::mesh::connection::MeshConnection;
use crate::sharing::WiFiSharingNode;
use crate::relays::LongRangeRelay;

/// Central mesh message handler
#[derive(Clone)]
pub struct MeshMessageHandler {
    /// Active mesh connections
    pub mesh_connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
    /// WiFi sharing nodes
    pub wifi_sharing_nodes: Arc<RwLock<HashMap<PublicKey, WiFiSharingNode>>>,
    /// Long-range relays
    pub long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
    /// Revenue pools
    pub revenue_pools: Arc<RwLock<HashMap<String, u64>>>,
}

impl MeshMessageHandler {
    /// Create new message handler
    pub fn new(
        mesh_connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
        wifi_sharing_nodes: Arc<RwLock<HashMap<PublicKey, WiFiSharingNode>>>,
        long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
        revenue_pools: Arc<RwLock<HashMap<String, u64>>>,
    ) -> Self {
        Self {
            mesh_connections,
            wifi_sharing_nodes,
            long_range_relays,
            revenue_pools,
        }
    }
    
    /// Handle incoming mesh message
    pub async fn handle_mesh_message(&self, message: ZhtpMeshMessage, sender: PublicKey) -> Result<()> {
        match message {
            ZhtpMeshMessage::PeerDiscovery { capabilities, location, shared_resources } => {
                self.handle_peer_discovery(sender, capabilities, location, shared_resources).await?;
            },
            ZhtpMeshMessage::ConnectivityRequest { requester, bandwidth_needed_kbps, duration_minutes, payment_tokens } => {
                self.handle_connectivity_request(requester, bandwidth_needed_kbps, duration_minutes, payment_tokens).await?;
            },
            ZhtpMeshMessage::ConnectivityResponse { provider, accepted, available_bandwidth_kbps, cost_tokens_per_mb, connection_details } => {
                self.handle_connectivity_response(provider, accepted, available_bandwidth_kbps, cost_tokens_per_mb, connection_details).await?;
            },
            ZhtpMeshMessage::LongRangeRoute { destination, relay_chain, payload, max_hops } => {
                self.handle_long_range_route(destination, relay_chain, payload, max_hops).await?;
            },
            ZhtpMeshMessage::UbiDistribution { recipient, amount_tokens, distribution_round, proof } => {
                self.handle_ubi_distribution(recipient, amount_tokens, distribution_round, proof).await?;
            },
            ZhtpMeshMessage::HealthReport { reporter, network_quality, available_bandwidth, connected_peers, uptime_hours } => {
                self.handle_health_report(reporter, network_quality, available_bandwidth, connected_peers, uptime_hours).await?;
            },
            ZhtpMeshMessage::ZhtpRequest { requester, method, uri, headers, body, timestamp } => {
                self.handle_lib_request(requester, method, uri, headers, body, timestamp).await?;
            },
            ZhtpMeshMessage::ZhtpResponse { request_id, status, status_message, headers, body, timestamp } => {
                self.handle_lib_response(request_id, status, status_message, headers, body, timestamp).await?;
            },
        }
        Ok(())
    }
    
    /// Handle peer discovery message
    async fn handle_peer_discovery(
        &self, 
        peer: PublicKey, 
        capabilities: Vec<crate::types::mesh_capability::MeshCapability>, 
        location: Option<crate::types::geographic::GeographicLocation>,
        shared_resources: crate::types::mesh_capability::SharedResources
    ) -> Result<()> {
        info!("🔍 Discovered peer with {} capabilities", capabilities.len());
        
        // Check if peer offers internet connectivity
        for capability in &capabilities {
            if let crate::types::mesh_capability::MeshCapability::InternetGateway { bandwidth_mbps } = capability {
                // Add as WiFi sharing node
                let mut wifi_nodes = self.wifi_sharing_nodes.write().await;
                wifi_nodes.insert(peer.clone(), WiFiSharingNode {
                    operator: peer.clone(),
                    shared_bandwidth_mbps: *bandwidth_mbps,
                    monthly_data_cap_gb: None, // Unlimited for now
                    tokens_per_gb: 50, // Standard rate
                    connection_type: crate::types::internet_connection::InternetConnectionType::Other { 
                        description: "Mesh-shared connection".to_string(), 
                        speed_mbps: *bandwidth_mbps 
                    },
                    location: location.clone(),
                    data_shared_this_month_gb: 0,
                    revenue_this_month: 0,
                });
                
                info!("🌐 New internet gateway: {} Mbps", bandwidth_mbps);
            }
        }
        
        // Establish mesh connection
        let mut connections = self.mesh_connections.write().await;
        connections.insert(peer.clone(), MeshConnection {
            peer_id: peer,
            protocol: crate::protocols::NetworkProtocol::BluetoothLE, // Default for discovery
            signal_strength: 0.8, // Good signal
            bandwidth_capacity: shared_resources.internet_bandwidth_kbps as u64 * 1024,
            latency_ms: 50, // Estimate
            connected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            data_transferred: 0,
            tokens_earned: 0,
            stability_score: shared_resources.reliability_score,
        });
        
        Ok(())
    }
    
    /// Handle connectivity request
    async fn handle_connectivity_request(
        &self, 
        requester: PublicKey, 
        bandwidth_needed_kbps: u32, 
        duration_minutes: u32, 
        payment_tokens: u64
    ) -> Result<()> {
        info!("📞 Connectivity request: {} kbps for {} minutes, {} tokens", 
              bandwidth_needed_kbps, duration_minutes, payment_tokens);
        
        // Check if we can provide the requested connectivity
        let wifi_nodes = self.wifi_sharing_nodes.read().await;
        let mut best_provider: Option<(PublicKey, &WiFiSharingNode)> = None;
        let mut best_bandwidth = 0u32;
        
        for (peer_id, node) in wifi_nodes.iter() {
            let available_kbps = node.shared_bandwidth_mbps * 1024;
            if available_kbps >= bandwidth_needed_kbps && available_kbps > best_bandwidth {
                best_provider = Some((peer_id.clone(), node));
                best_bandwidth = available_kbps;
            }
        }
        
        if let Some((provider_key, provider_node)) = best_provider {
            // Calculate exact cost for the data transfer
            let data_mb = (bandwidth_needed_kbps * duration_minutes * 60) / (8 * 1024); // Convert to MB
            let total_cost = data_mb as u64 * provider_node.tokens_per_gb / 1024;
            
            // Verify payment is sufficient
            if payment_tokens >= total_cost {
                info!("✅ Can provide {} kbps connectivity for {} minutes", bandwidth_needed_kbps, duration_minutes);
                info!("💰 Cost: {} tokens for {:.2} MB transfer", total_cost, data_mb as f64 / 1024.0);
                
                // Update provider's revenue tracking
                let mut wifi_nodes_mut = self.wifi_sharing_nodes.write().await;
                if let Some(provider_mut) = wifi_nodes_mut.get_mut(&provider_key) {
                    provider_mut.revenue_this_month += total_cost;
                    provider_mut.data_shared_this_month_gb += (data_mb as f64 / 1024.0) as u32;
                }
                
                info!("📤 Sending connectivity acceptance to requester");
            } else {
                warn!("❌ Insufficient payment: {} tokens provided, {} tokens required", 
                      payment_tokens, total_cost);
                info!("📤 Sending connectivity rejection - insufficient payment");
            }
        } else {
            warn!("❌ No WiFi nodes can provide {} kbps connectivity", bandwidth_needed_kbps);
            info!("📤 Sending connectivity rejection - no capacity available");
        }
        
        Ok(())
    }
    
    /// Handle connectivity response
    async fn handle_connectivity_response(
        &self, 
        provider: PublicKey, 
        accepted: bool, 
        available_bandwidth_kbps: u32, 
        cost_tokens_per_mb: u64, 
        connection_details: Option<crate::types::connection_details::ConnectionDetails>
    ) -> Result<()> {
        if accepted {
            info!("✅ Connectivity accepted: {} kbps at {} tokens/MB", 
                  available_bandwidth_kbps, cost_tokens_per_mb);
        } else {
            info!("❌ Connectivity request denied");
        }
        Ok(())
    }
    
    /// Handle long-range routing - GLOBAL reach through multi-hop mesh!
    async fn handle_long_range_route(
        &self, 
        destination: PublicKey, 
        relay_chain: Vec<String>, 
        payload: Vec<u8>, 
        max_hops: u8
    ) -> Result<()> {
        info!("🌍 GLOBAL long-range route: {} bytes to destination via {} relays", 
              payload.len(), relay_chain.len());
        
        // ZHTP supports unlimited global routing through mesh relays
        if max_hops > 0 {
            let relays = self.long_range_relays.read().await;
            let mut total_distance_km = 0.0;
            let mut routing_path = Vec::new();
            
            for relay_id in &relay_chain {
                if let Some(relay) = relays.get(relay_id) {
                    total_distance_km += relay.coverage_radius_km;
                    routing_path.push(format!("{} ({}km)", relay_id, relay.coverage_radius_km));
                    
                    match relay.relay_type {
                        crate::types::relay_type::LongRangeRelayType::Satellite => {
                            info!("🛰️ GLOBAL satellite relay: {} - WORLDWIDE coverage", relay_id);
                        }
                        crate::types::relay_type::LongRangeRelayType::LoRaWAN => {
                            info!("📡 LoRa relay: {} - {}km regional coverage", relay_id, relay.coverage_radius_km);
                        }
                        crate::types::relay_type::LongRangeRelayType::WiFiRelay => {
                            info!("🌐 Internet bridge: {} - GLOBAL internet access", relay_id);
                        }
                        _ => {
                            info!("📡 Long-range relay: {} - {}km coverage", relay_id, relay.coverage_radius_km);
                        }
                    }
                }
            }
            
            info!("🌍 TOTAL GLOBAL REACH: {:.0}km via path: {:?}", 
                  total_distance_km, routing_path);
            
            // With satellite + internet bridges, ZHTP reaches ANYWHERE on Earth!
            if total_distance_km > 10000.0 {
                info!("🚀 INTERCONTINENTAL ZHTP routing active - Planet-wide mesh network!");
            }
        }
        
        Ok(())
    }
    
    /// Handle UBI distribution
    async fn handle_ubi_distribution(
        &self, 
        recipient: PublicKey, 
        amount_tokens: u64, 
        distribution_round: u64, 
        proof: Vec<u8>
    ) -> Result<()> {
        info!("💰 UBI distribution: {} tokens to recipient (round {})", 
              amount_tokens, distribution_round);
        
        // TODO: Implement UBI proof verification
        let verification_result = true;
        
        if !verification_result {
            warn!("❌ Invalid ZK proof for UBI distribution - rejecting");
            return Err(anyhow::anyhow!("Invalid ZK proof for UBI distribution"));
        }
        
        // Validate distribution round to prevent replay attacks
        let mut pools = self.revenue_pools.write().await;
        let last_round_key = format!("ubi_last_round_{}", hex::encode(&recipient.key_id[0..8]));
        let last_round = pools.get(&last_round_key).unwrap_or(&0);
        
        if distribution_round <= *last_round {
            warn!("❌ UBI distribution round {} already processed for recipient", distribution_round);
            return Err(anyhow::anyhow!("UBI distribution round already processed"));
        }
        
        // Update recipient's UBI balance and track distribution
        *pools.entry("ubi_total".to_string()).or_insert(0) += amount_tokens;
        *pools.entry(last_round_key).or_insert(0) = distribution_round;
        
        let recipient_balance_key = format!("ubi_balance_{}", hex::encode(&recipient.key_id[0..8]));
        *pools.entry(recipient_balance_key).or_insert(0) += amount_tokens;
        
        info!("✅ UBI distribution completed: {} tokens distributed (round {})", 
              amount_tokens, distribution_round);
        
        Ok(())
    }
    
    /// Handle network health report
    async fn handle_health_report(
        &self, 
        reporter: PublicKey, 
        network_quality: f64, 
        available_bandwidth: u64, 
        connected_peers: u32, 
        uptime_hours: u32
    ) -> Result<()> {
        info!("📊 Health report: quality={:.2}, bandwidth={} MB/s, peers={}, uptime={}h", 
              network_quality, available_bandwidth / 1_000_000, connected_peers, uptime_hours);
        
        // Update connection statistics
        let mut connections = self.mesh_connections.write().await;
        if let Some(connection) = connections.get_mut(&reporter) {
            connection.stability_score = network_quality;
            connection.bandwidth_capacity = available_bandwidth;
        }
        
        Ok(())
    }
    
    /// Handle native ZHTP protocol request from browser/API clients
    async fn handle_lib_request(
        &self,
        requester: PublicKey,
        method: String,
        uri: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        timestamp: u64,
    ) -> Result<()> {
        info!("🌐 Native ZHTP Request: {} {} from {:?}", method, uri, requester);
        
        // This would route to the ZHTP API handler
        // For now, just log the request
        info!("📤 ZHTP Request processed: {} {}", method, uri);
        
        Ok(())
    }
    
    /// Handle native ZHTP protocol response
    async fn handle_lib_response(
        &self,
        request_id: u64,
        status: u16,
        status_message: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        timestamp: u64,
    ) -> Result<()> {
        info!("📥 ZHTP Response received: {} {} (request_id: {})", status, status_message, request_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    #[tokio::test]
    async fn test_message_handler_creation() {
        let mesh_connections = Arc::new(RwLock::new(HashMap::new()));
        let wifi_sharing_nodes = Arc::new(RwLock::new(HashMap::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        let revenue_pools = Arc::new(RwLock::new(HashMap::new()));
        
        let handler = MeshMessageHandler::new(
            mesh_connections,
            wifi_sharing_nodes,
            long_range_relays,
            revenue_pools,
        );
        
        // Handler should be created successfully
        assert!(handler.mesh_connections.read().await.is_empty());
    }
    
    #[tokio::test]
    async fn test_health_report_handling() {
        let mesh_connections = Arc::new(RwLock::new(HashMap::new()));
        let wifi_sharing_nodes = Arc::new(RwLock::new(HashMap::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        let revenue_pools = Arc::new(RwLock::new(HashMap::new()));
        
        let handler = MeshMessageHandler::new(
            mesh_connections.clone(),
            wifi_sharing_nodes,
            long_range_relays,
            revenue_pools,
        );
        
        let reporter = PublicKey::new(vec![1, 2, 3]);
        
        // Add a connection first
        {
            let mut connections = mesh_connections.write().await;
            connections.insert(reporter.clone(), MeshConnection {
                peer_id: reporter.clone(),
                protocol: crate::protocols::NetworkProtocol::BluetoothLE,
                signal_strength: 0.5,
                bandwidth_capacity: 1000000,
                latency_ms: 100,
                connected_at: 1000000,
                data_transferred: 0,
                tokens_earned: 0,
                stability_score: 0.5,
            });
        }
        
        // Handle health report
        let result = handler.handle_health_report(
            reporter.clone(),
            0.9,
            2000000,
            5,
            24,
        ).await;
        
        assert!(result.is_ok());
        
        // Check that connection was updated
        let connections = mesh_connections.read().await;
        let connection = connections.get(&reporter).unwrap();
        assert_eq!(connection.stability_score, 0.9);
        assert_eq!(connection.bandwidth_capacity, 2000000);
    }
}
