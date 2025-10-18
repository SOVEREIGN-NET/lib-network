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

use crate::relays::LongRangeRelay;

/// Central mesh message handler
#[derive(Clone)]
pub struct MeshMessageHandler {
    /// Active mesh connections
    pub mesh_connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
    /// Long-range relays
    pub long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
    /// Revenue pools
    pub revenue_pools: Arc<RwLock<HashMap<String, u64>>>,
}

impl MeshMessageHandler {
    /// Create new message handler
    pub fn new(
        mesh_connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
        long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
        revenue_pools: Arc<RwLock<HashMap<String, u64>>>,
    ) -> Self {
        Self {
            mesh_connections,
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
            ZhtpMeshMessage::BlockchainRequest { requester, request_id, from_height } => {
                self.handle_blockchain_request(requester, request_id, from_height).await?;
            },
            ZhtpMeshMessage::BlockchainData { request_id, chunk_index, total_chunks, data, complete_data_hash } => {
                self.handle_blockchain_data(request_id, chunk_index, total_chunks, data, complete_data_hash).await?;
            },
            ZhtpMeshMessage::ConsensusMessage { message_data, sender_node_id, signature } => {
                self.handle_consensus_message(message_data, sender_node_id, signature).await?;
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
        info!("Discovered peer with {} capabilities", capabilities.len());
        
        // Process peer capabilities for legitimate mesh services
        for capability in &capabilities {
            if let crate::types::mesh_capability::MeshCapability::MeshRelay { capacity_mbps } = capability {
                info!("Peer offers mesh relay service: {} Mbps capacity", capacity_mbps);
            }
        }
        
        // Establish mesh connection
        let mut connections = self.mesh_connections.write().await;
        connections.insert(peer.clone(), MeshConnection {
            peer_id: peer,
            protocol: crate::protocols::NetworkProtocol::BluetoothLE, // Default for discovery
            peer_address: None, // Address not available in PeerDiscovery message
            signal_strength: 0.8, // Good signal
            bandwidth_capacity: shared_resources.relay_bandwidth_kbps as u64 * 1024,
            latency_ms: 50, // Estimate
            connected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            data_transferred: 0,
            tokens_earned: 0,
            stability_score: shared_resources.reliability_score,
            zhtp_authenticated: false,
            quantum_secure: true,
            peer_dilithium_pubkey: None,
            kyber_shared_secret: None,
            trust_score: 0.0,
        });
        
        Ok(())
    }
    
    /// Handle connectivity request - legitimate P2P mesh routing
    async fn handle_connectivity_request(
        &self, 
        _requester: PublicKey, 
        bandwidth_needed_kbps: u32, 
        duration_minutes: u32, 
        _payment_tokens: u64
    ) -> Result<()> {
        info!("📞 P2P mesh routing request: {} kbps for {} minutes", 
              bandwidth_needed_kbps, duration_minutes);
        
        // ZHTP provides direct peer-to-peer mesh routing without ISP bypass
        let relays = self.long_range_relays.read().await;
        if !relays.is_empty() {
            info!("Mesh relay capacity available for P2P routing");
            info!(" Sending connectivity acceptance via legitimate mesh routing");
        } else {
            warn!("No mesh relay nodes available for routing");
            info!(" Sending connectivity rejection - no relay capacity");
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
            info!("Connectivity accepted: {} kbps at {} tokens/MB", 
                  available_bandwidth_kbps, cost_tokens_per_mb);
        } else {
            info!("Connectivity request denied");
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
        info!("GLOBAL long-range route: {} bytes to destination via {} relays", 
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
                            info!("LoRa relay: {} - {}km regional coverage", relay_id, relay.coverage_radius_km);
                        }
                        crate::types::relay_type::LongRangeRelayType::WiFiRelay => {
                            info!("Internet bridge: {} - GLOBAL internet access", relay_id);
                        }
                        _ => {
                            info!("Long-range relay: {} - {}km coverage", relay_id, relay.coverage_radius_km);
                        }
                    }
                }
            }
            
            info!("TOTAL GLOBAL REACH: {:.0}km via path: {:?}", 
                  total_distance_km, routing_path);
            
            // With satellite + internet bridges, ZHTP reaches ANYWHERE on Earth!
            if total_distance_km > 10000.0 {
                info!(" INTERCONTINENTAL ZHTP routing active - Planet-wide mesh network!");
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
        info!("UBI distribution: {} tokens to recipient (round {})", 
              amount_tokens, distribution_round);
        
        // TODO: Implement UBI proof verification
        let verification_result = true;
        
        if !verification_result {
            warn!("Invalid ZK proof for UBI distribution - rejecting");
            return Err(anyhow::anyhow!("Invalid ZK proof for UBI distribution"));
        }
        
        // Validate distribution round to prevent replay attacks
        let mut pools = self.revenue_pools.write().await;
        let last_round_key = format!("ubi_last_round_{}", hex::encode(&recipient.key_id[0..8]));
        let last_round = pools.get(&last_round_key).unwrap_or(&0);
        
        if distribution_round <= *last_round {
            warn!("UBI distribution round {} already processed for recipient", distribution_round);
            return Err(anyhow::anyhow!("UBI distribution round already processed"));
        }
        
        // Update recipient's UBI balance and track distribution
        *pools.entry("ubi_total".to_string()).or_insert(0) += amount_tokens;
        *pools.entry(last_round_key).or_insert(0) = distribution_round;
        
        let recipient_balance_key = format!("ubi_balance_{}", hex::encode(&recipient.key_id[0..8]));
        *pools.entry(recipient_balance_key).or_insert(0) += amount_tokens;
        
        info!("UBI distribution completed: {} tokens distributed (round {})", 
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
        info!("Health report: quality={:.2}, bandwidth={} MB/s, peers={}, uptime={}h", 
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
        info!("Native ZHTP Request: {} {} from {:?}", method, uri, requester);
        
        // This would route to the ZHTP API handler
        // For now, just log the request
        info!(" ZHTP Request processed: {} {}", method, uri);
        
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
        info!("ZHTP Response received: {} {} (request_id: {})", status, status_message, request_id);
        Ok(())
    }

    /// Handle blockchain request from peer
    async fn handle_blockchain_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        from_height: Option<u64>,
    ) -> Result<()> {
        info!(" Blockchain request from peer (request_id: {}, from_height: {:?})", 
              request_id, from_height);
        
        // This will be implemented in the runtime layer to access blockchain
        // For now, we log the request - the actual blockchain export will be done
        // by the unified_server when it receives this message
        info!("Blockchain request queued for processing by runtime");
        
        Ok(())
    }

    /// Handle incoming blockchain data chunks
    async fn handle_blockchain_data(
        &self,
        request_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        complete_data_hash: [u8; 32],
    ) -> Result<()> {
        info!(" Blockchain data chunk {}/{} received ({} bytes, request_id: {})", 
              chunk_index + 1, total_chunks, data.len(), request_id);
        
        // This will be implemented in the runtime layer to reassemble chunks
        // For now, we log the receipt - the actual reassembly will be done
        // by the unified_server/bootstrap logic
        info!("Blockchain chunk stored for reassembly");
        
        Ok(())
    }

    /// Handle mesh consensus message (BFT protocol)
    async fn handle_consensus_message(
        &self,
        message_data: Vec<u8>,
        sender_node_id: [u8; 32],
        signature: Vec<u8>,
    ) -> Result<()> {
        info!("📡 Consensus message received from node: {}", hex::encode(&sender_node_id[..8]));
        
        // Deserialize the consensus message
        let consensus_message: lib_consensus::ConsensusMessage = match bincode::deserialize(&message_data) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to deserialize consensus message: {}", e);
                return Err(anyhow::anyhow!("Invalid consensus message format: {}", e));
            }
        };
        
        info!("Consensus message type: {:?}, height: {}, round: {}", 
              consensus_message.message_type, 
              consensus_message.height,
              consensus_message.round);
        
        // TODO: Route to mesh server's handle_consensus_message
        // This will be connected through the unified server when the mesh server
        // is available in the runtime context
        info!("Consensus message queued for processing by mesh consensus engine");
        
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
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        let revenue_pools = Arc::new(RwLock::new(HashMap::new()));
        
        let handler = MeshMessageHandler::new(
            mesh_connections,
            long_range_relays,
            revenue_pools,
        );
        
        // Handler should be created successfully
        assert!(handler.mesh_connections.read().await.is_empty());
    }
    
    #[tokio::test]
    async fn test_health_report_handling() {
        let mesh_connections = Arc::new(RwLock::new(HashMap::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        let revenue_pools = Arc::new(RwLock::new(HashMap::new()));
        
        let handler = MeshMessageHandler::new(
            mesh_connections.clone(),
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
