//! Mesh Message Handler Implementation
//! 
//! Central message routing and handling for ZHTP mesh protocol

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use lib_crypto::PublicKey;

use crate::types::mesh_message::ZhtpMeshMessage;
use crate::protocols::NetworkProtocol;
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
    /// Message router for sending responses (Phase 2)
    pub message_router: Option<Arc<RwLock<crate::routing::message_routing::MeshMessageRouter>>>,
    /// Node ID for this handler (Phase 2)
    pub node_id: Option<PublicKey>,
    /// Blockchain sync manager for chunk reassembly
    pub sync_manager: Arc<crate::blockchain_sync::BlockchainSyncManager>,
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
            message_router: None,
            node_id: None,
            sync_manager: Arc::new(crate::blockchain_sync::BlockchainSyncManager::new()),
        }
    }
    
    /// Set message router for sending responses (Phase 2)
    pub fn set_message_router(&mut self, router: Arc<RwLock<crate::routing::message_routing::MeshMessageRouter>>) {
        self.message_router = Some(router);
    }
    
    /// Set node ID (Phase 2)
    pub fn set_node_id(&mut self, node_id: PublicKey) {
        self.node_id = Some(node_id);
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
            ZhtpMeshMessage::BlockchainRequest { requester, request_id, request_type } => {
                self.handle_blockchain_request(requester, request_id, request_type).await?;
            },
            ZhtpMeshMessage::BlockchainData { request_id, chunk_index, total_chunks, data, complete_data_hash } => {
                self.handle_blockchain_data(request_id, chunk_index, total_chunks, data, complete_data_hash).await?;
            },
            ZhtpMeshMessage::NewBlock { block, sender, height, timestamp } => {
                self.handle_new_block(block, sender, height, timestamp).await?;
            },
            ZhtpMeshMessage::NewTransaction { transaction, sender, tx_hash, fee } => {
                self.handle_new_transaction(transaction, sender, tx_hash, fee).await?;
            },
            ZhtpMeshMessage::RouteProbe { probe_id, target } => {
                // TODO: Implement route probe handling
                tracing::info!("Received route probe {} for target {:?}", probe_id, target);
            },
            ZhtpMeshMessage::RouteResponse { probe_id, route_quality, latency_ms } => {
                // TODO: Implement route response handling
                tracing::info!("Received route response for probe {} with quality {} and latency {}ms", 
                    probe_id, route_quality, latency_ms);
            },
        }
        Ok(())
    }
    
    /// Handle peer discovery message
    pub async fn handle_peer_discovery(
        &self, 
        peer: PublicKey, 
        capabilities: Vec<crate::types::mesh_capability::MeshCapability>, 
        _location: Option<crate::types::geographic::GeographicLocation>,
        shared_resources: crate::types::mesh_capability::SharedResources
    ) -> Result<()> {
        info!("Discovered peer {:?} with {} capabilities", 
              hex::encode(&peer.key_id[0..8]), capabilities.len());
        
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
            info!("Connectivity accepted from provider {:?}: {} kbps at {} tokens/MB", 
                  hex::encode(&provider.key_id[0..8]), available_bandwidth_kbps, cost_tokens_per_mb);
            
            // TODO: Use connection_details to establish actual mesh connection
            if let Some(_details) = connection_details {
                info!(" Connection details received - TODO: establish connection");
            }
        } else {
            info!("Connectivity request denied by provider {:?}", hex::encode(&provider.key_id[0..8]));
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
        info!("GLOBAL long-range route: {} bytes to destination {:?} via {} relays", 
              payload.len(), hex::encode(&destination.key_id[0..8]), relay_chain.len());
        
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
    
    /// Handle UBI distribution message
    pub async fn handle_ubi_distribution(
        &self,
        recipient: PublicKey,
        amount_tokens: u64,
        distribution_round: u64,
        proof: Vec<u8>
    ) -> Result<()> {
        info!("UBI distribution: {} tokens to recipient (round {})", 
              amount_tokens, distribution_round);
        
        // TODO: Implement actual ZK proof verification using lib-proofs
        // For now, reject if proof is empty
        if proof.is_empty() {
            warn!("❌ Empty ZK proof for UBI distribution - rejecting");
            return Err(anyhow::anyhow!("UBI distribution requires valid ZK proof"));
        }
        
        // Placeholder: actual verification would use lib-proofs
        // verification_result = lib_proofs::verify_ubi_proof(&proof, &recipient, amount_tokens, distribution_round)?;
        let verification_result = true; // TODO: Replace with actual verification
        
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
    pub async fn handle_health_report(
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
    
    /// Handle native ZHTP protocol request from browser/API clients (UPDATED - Phase 3)
    pub async fn handle_lib_request(
        &self,
        requester: PublicKey,
        method: String,
        uri: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        timestamp: u64,
    ) -> Result<()> {
        info!("📥 Native ZHTP Request: {} {} from {:?}", method, uri, hex::encode(&requester.key_id[0..8]));
        
        // Validate timestamp (replay protection)
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if now.abs_diff(timestamp) > 300 {  // 5 minute window
            warn!("❌ Request timestamp too old/future: {} vs {}", timestamp, now);
            return self.send_error_response(requester, 400, "Request timestamp invalid".to_string()).await;
        }
        
        info!("✅ Timestamp valid, headers: {}, body: {} bytes", headers.len(), body.len());
        
        // For Phase 3, we'll create a simplified ZHTP response
        // In production, this would forward to lib-protocols ZHTP server
        // For now, we'll handle basic requests directly
        
        let (status, status_message, response_body) = match method.as_str() {
            "GET" => {
                info!("Processing GET request for {}", uri);
                // Simulate content retrieval
                if uri == "/health" {
                    (200, "OK".to_string(), b"Mesh node healthy".to_vec())
                } else if uri.starts_with("/content/") {
                    (200, "OK".to_string(), format!("Content for {}", uri).into_bytes())
                } else {
                    (404, "Not Found".to_string(), b"Resource not found".to_vec())
                }
            }
            "POST" => {
                info!("Processing POST request for {}", uri);
                (200, "OK".to_string(), b"Data received".to_vec())
            }
            _ => {
                (405, "Method Not Allowed".to_string(), b"Method not supported".to_vec())
            }
        };
        
        // Generate request ID for tracking
        let request_id = self.generate_request_id().await;
        
        // Create response message
        let mut response_headers = HashMap::new();
        response_headers.insert("Content-Type".to_string(), "text/plain".to_string());
        response_headers.insert("Content-Length".to_string(), response_body.len().to_string());
        response_headers.insert("X-Mesh-Node".to_string(), "ZHTP/1.0".to_string());
        
        let response_message = ZhtpMeshMessage::ZhtpResponse {
            request_id,
            status,
            status_message: status_message.clone(),
            headers: response_headers,
            body: response_body,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        
        // Send response back to requester via mesh
        info!("📤 Sending response {} {} back to requester", status, status_message);
        self.send_response_to_requester(requester, response_message).await?;
        
        info!("✅ ZHTP Request processed: {} {}", method, uri);
        
        Ok(())
    }
    
    /// Send response back through mesh network (NEW - Phase 3)
    async fn send_response_to_requester(
        &self,
        requester: PublicKey,
        response: ZhtpMeshMessage,
    ) -> Result<()> {
        if let Some(router) = &self.message_router {
            if let Some(my_id) = &self.node_id {
                let router_guard = router.read().await;
                router_guard.route_message_with_forwarding(
                    requester.clone(),
                    response,
                    my_id.clone()
                ).await?;
                info!("✅ Response routed back to requester");
            } else {
                warn!("⚠️ Node ID not set, cannot send response");
            }
        } else {
            warn!("⚠️ Message router not available, cannot send response");
        }
        Ok(())
    }
    
    /// Send error response (NEW - Phase 3)
    async fn send_error_response(
        &self,
        requester: PublicKey,
        status: u16,
        message: String,
    ) -> Result<()> {
        let request_id = self.generate_request_id().await;
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/plain".to_string());
        
        let error_message = ZhtpMeshMessage::ZhtpResponse {
            request_id,
            status,
            status_message: message.clone(),
            headers,
            body: message.into_bytes(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        
        self.send_response_to_requester(requester, error_message).await
    }
    
    /// Generate unique request ID (NEW - Phase 3)
    async fn generate_request_id(&self) -> u64 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        
        // Combine timestamp with random bits for uniqueness
        timestamp ^ (rand::random::<u64>() >> 16)
    }
    
    /// Handle native ZHTP protocol response
    pub async fn handle_lib_response(
        &self,
        request_id: u64,
        status: u16,
        status_message: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        timestamp: u64,
    ) -> Result<()> {
        info!("ZHTP Response received: {} {} (request_id: {})", status, status_message, request_id);
        
        // TODO: Implement full ZHTP response handling
        // - Parse response headers
        // - Process response body
        // - Validate timestamp
        // - Match with pending request and fulfill promise
        info!(" Headers: {} present, Body: {} bytes, Timestamp: {}", 
              headers.len(), body.len(), timestamp);
        
        Ok(())
    }

    /// Handle blockchain request from peer (UPDATED - Phase 3)
    /// TODO: This requires lib-blockchain which would create a circular dependency
    /// For now, this is stubbed out and should be implemented at the application layer
    pub async fn handle_blockchain_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        request_type: crate::types::mesh_message::BlockchainRequestType,
    ) -> Result<()> {
        info!("📦 Blockchain request from peer {:?} (request_id: {}, type: {:?})", 
              hex::encode(&requester.key_id[0..8]), request_id, request_type);
        
        // TODO: Implement blockchain integration at application layer
        // This functionality requires lib-blockchain which would create a circular dependency
        warn!("⚠️ Blockchain integration not yet implemented (circular dependency issue)");
        Ok(())
    }
    
    /// Get protocol being used for peer (NEW - Phase 3)
    async fn get_protocol_for_peer(&self, peer_id: &PublicKey) -> Result<NetworkProtocol> {
        let connections = self.mesh_connections.read().await;
        connections.get(peer_id)
            .map(|c| c.protocol.clone())
            .ok_or_else(|| anyhow!("No connection to peer"))
    }
    
    /// Chunk blockchain data for protocol (NEW - Phase 3)
    fn chunk_blockchain_data(
        &self,
        request_id: u64,
        data: Vec<u8>,
        protocol: &NetworkProtocol,
    ) -> Result<Vec<ZhtpMeshMessage>> {
        // Calculate chunk size based on protocol
        let chunk_size = match protocol {
            NetworkProtocol::BluetoothLE => 200,        // BLE 5.0 conservative
            NetworkProtocol::BluetoothClassic => 800,   // Bluetooth Classic larger MTU
            NetworkProtocol::WiFiDirect => 1400,        // WiFi Direct near-ethernet
            NetworkProtocol::LoRaWAN => 50,             // LoRa very small packets
            _ => 512,                                    // Default safe size
        };
        
        // Calculate complete data hash
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let complete_data_hash: [u8; 32] = hasher.finalize().into();
        
        // Split into chunks
        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
        let total_chunks = chunks.len() as u32;
        
        info!("📦 Chunking {} bytes into {} chunks of ~{} bytes", data.len(), total_chunks, chunk_size);
        
        // Create ZhtpMeshMessage for each chunk
        let messages: Vec<ZhtpMeshMessage> = chunks.into_iter().enumerate().map(|(i, chunk)| {
            ZhtpMeshMessage::BlockchainData {
                request_id,
                chunk_index: i as u32,
                total_chunks,
                data: chunk.to_vec(),
                complete_data_hash,
            }
        }).collect();
        
        Ok(messages)
    }

    /// Handle incoming blockchain data chunks
    pub async fn handle_blockchain_data(
        &self,
        request_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        complete_data_hash: [u8; 32],
    ) -> Result<()> {
        info!("📦 Blockchain data chunk {}/{} received ({} bytes, request_id: {})", 
              chunk_index + 1, total_chunks, data.len(), request_id);
        
        // Add chunk to sync manager for reassembly
        match self.sync_manager.add_chunk(request_id, chunk_index, total_chunks, data, complete_data_hash).await {
            Ok(Some(complete_data)) => {
                info!(" All blockchain chunks received and verified! Total: {} bytes", complete_data.len());
                info!("   Hash: {}", hex::encode(complete_data_hash));
                
                // TODO: Forward complete blockchain data to application layer for import
                // This requires lib-blockchain which would create a circular dependency
                // The unified_server handles this properly in handle_udp_mesh()
                info!("✅ Blockchain chunks reassembled successfully");
                info!("   Application layer should import this data via blockchain.evaluate_and_merge_chain()");
            }
            Ok(None) => {
                debug!("Chunk {}/{} buffered, waiting for more chunks", chunk_index + 1, total_chunks);
            }
            Err(e) => {
                warn!("Failed to process blockchain chunk: {}", e);
                return Err(e);
            }
        }
        
        Ok(())
    }
    
    /// Handle new block announcement (NEW - Phase 3)
    /// TODO: This requires lib-blockchain which would create a circular dependency
    pub async fn handle_new_block(
        &self,
        block: Vec<u8>,
        sender: PublicKey,
        height: u64,
        timestamp: u64,
    ) -> Result<()> {
        info!("📦 New block announcement: height {} from {:?} ({} bytes)", 
              height, hex::encode(&sender.key_id[0..4]), block.len());
        
        // TODO: Implement blockchain integration at application layer
        warn!("⚠️ Blockchain integration not yet implemented (circular dependency issue)");
        
        Ok(())
    }
    
    /// Handle new transaction announcement (NEW - Phase 3)
    /// TODO: This requires lib-blockchain which would create a circular dependency
    pub async fn handle_new_transaction(
        &self,
        transaction: Vec<u8>,
        sender: PublicKey,
        tx_hash: [u8; 32],
        fee: u64,
    ) -> Result<()> {
        info!("💰 New transaction from {:?}: hash={}, fee={}", 
              hex::encode(&sender.key_id[0..4]), 
              hex::encode(&tx_hash[0..8]),
              fee);
        
        // TODO: Implement blockchain integration at application layer
        warn!("⚠️ Blockchain integration not yet implemented (circular dependency issue)");
        
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
                peer_address: None,
                signal_strength: 0.5,
                bandwidth_capacity: 1000000,
                latency_ms: 100,
                connected_at: 1000000,
                data_transferred: 0,
                tokens_earned: 0,
                stability_score: 0.5,
                zhtp_authenticated: false,
                quantum_secure: true,
                peer_dilithium_pubkey: None,
                kyber_shared_secret: None,
                trust_score: 0.0,
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
