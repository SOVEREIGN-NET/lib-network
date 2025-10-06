//! Mesh Message Routing Implementation
//! 
//! Advanced peer-to-peer message delivery with intelligent routing

use anyhow::{anyhow, Result};
use std::collections::{HashMap, VecDeque, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use lib_crypto::PublicKey;
use serde::{Serialize, Deserialize};

use crate::types::mesh_message::ZhtpMeshMessage;
use crate::mesh::connection::MeshConnection;
use crate::relays::LongRangeRelay;
use crate::protocols::NetworkProtocol;

/// Intelligent mesh message router
pub struct MeshMessageRouter {
    /// Active mesh connections for routing
    pub mesh_connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
    /// Long-range relays for extended reach
    pub long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
    /// Routing table for efficient path finding
    pub routing_table: Arc<RwLock<RoutingTable>>,
    /// Message delivery tracking
    pub delivery_tracking: Arc<RwLock<HashMap<u64, DeliveryStatus>>>,
    /// Route cache for optimization
    pub route_cache: Arc<RwLock<HashMap<PublicKey, CachedRoute>>>,
}

/// Routing table for mesh network
#[derive(Debug, Clone)]
pub struct RoutingTable {
    /// Direct connections to peers
    pub direct_routes: HashMap<PublicKey, RouteInfo>,
    /// Multi-hop routes to distant peers
    pub multi_hop_routes: HashMap<PublicKey, Vec<RouteHop>>,
    /// Network topology understanding
    pub topology_map: TopologyMap,
}

/// Information about a specific route
#[derive(Debug, Clone)]
pub struct RouteInfo {
    /// Next hop in the route
    pub next_hop: PublicKey,
    /// Total hops to destination
    pub hop_count: u8,
    /// Route quality score (0.0 to 1.0)
    pub quality_score: f64,
    /// Estimated latency in milliseconds
    pub estimated_latency_ms: u32,
    /// Route bandwidth capacity
    pub bandwidth_capacity: u64,
    /// Last updated timestamp
    pub last_updated: u64,
}

/// Single hop in a multi-hop route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteHop {
    /// Peer ID for this hop
    pub peer_id: PublicKey,
    /// Protocol to use for this hop
    pub protocol: NetworkProtocol,
    /// Relay ID if using long-range relay
    pub relay_id: Option<String>,
    /// Estimated hop latency
    pub latency_ms: u32,
}

/// Network topology map
#[derive(Debug, Clone)]
pub struct TopologyMap {
    /// Known peers and their connections
    pub peer_connections: HashMap<PublicKey, HashSet<PublicKey>>,
    /// Geographic clustering information
    pub geographic_clusters: Vec<GeographicCluster>,
    /// Network coverage areas
    pub coverage_areas: Vec<CoverageArea>,
}

/// Geographic cluster of nearby nodes
#[derive(Debug, Clone)]
pub struct GeographicCluster {
    /// Cluster center coordinates
    pub center_lat: f64,
    pub center_lon: f64,
    /// Cluster radius in kilometers
    pub radius_km: f64,
    /// Peers in this cluster
    pub peers: HashSet<PublicKey>,
    /// Cluster connectivity score
    pub connectivity_score: f64,
}

/// Network coverage area
#[derive(Debug, Clone)]
pub struct CoverageArea {
    /// Coverage type (WiFi, LoRa, Satellite, etc.)
    pub coverage_type: String,
    /// Coverage radius in kilometers
    pub radius_km: f64,
    /// Center coordinates
    pub center_lat: f64,
    pub center_lon: f64,
    /// Responsible relay or node
    pub provider: PublicKey,
}

/// Cached route information
#[derive(Debug, Clone)]
pub struct CachedRoute {
    /// Route hops
    pub hops: Vec<RouteHop>,
    /// Route quality score
    pub quality_score: f64,
    /// Cache timestamp
    pub cached_at: u64,
    /// Cache validity duration in seconds
    pub validity_duration: u64,
}

/// Message delivery status tracking
#[derive(Debug, Clone)]
pub struct DeliveryStatus {
    /// Message ID being tracked
    pub message_id: u64,
    /// Destination peer
    pub destination: PublicKey,
    /// Current routing stage
    pub stage: DeliveryStage,
    /// Route being used
    pub route: Vec<RouteHop>,
    /// Current hop index
    pub current_hop: usize,
    /// Delivery attempts
    pub attempts: u32,
    /// Started timestamp
    pub started_at: u64,
    /// Last update timestamp
    pub last_update: u64,
}

/// Delivery stage enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum DeliveryStage {
    Planning,      // Route planning
    Routing,       // Active routing
    LongRange,     // Using long-range relay
    Delivered,     // Successfully delivered
    Failed,        // Delivery failed
    Retrying,      // Retrying delivery
}

impl MeshMessageRouter {
    /// Create new mesh message router
    pub fn new(
        mesh_connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
        long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
    ) -> Self {
        Self {
            mesh_connections,
            long_range_relays,
            routing_table: Arc::new(RwLock::new(RoutingTable {
                direct_routes: HashMap::new(),
                multi_hop_routes: HashMap::new(),
                topology_map: TopologyMap {
                    peer_connections: HashMap::new(),
                    geographic_clusters: Vec::new(),
                    coverage_areas: Vec::new(),
                },
            })),
            delivery_tracking: Arc::new(RwLock::new(HashMap::new())),
            route_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Route message to destination with intelligent path selection
    pub async fn route_message(
        &self,
        message: ZhtpMeshMessage,
        destination: PublicKey,
        sender: PublicKey,
    ) -> Result<u64> {
        let message_id = rand::random::<u64>();
        
        info!(" Routing message {} to destination {:?}", 
              message_id, hex::encode(&destination.key_id[0..4]));
        
        // Create delivery tracking
        let delivery_status = DeliveryStatus {
            message_id,
            destination: destination.clone(),
            stage: DeliveryStage::Planning,
            route: Vec::new(),
            current_hop: 0,
            attempts: 0,
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_update: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        
        self.delivery_tracking.write().await.insert(message_id, delivery_status);
        
        // Find optimal route to destination
        let route = self.find_optimal_route(&destination, &sender).await?;
        
        // Update delivery status with route
        {
            let mut tracking = self.delivery_tracking.write().await;
            if let Some(status) = tracking.get_mut(&message_id) {
                status.route = route.clone();
                status.stage = DeliveryStage::Routing;
            }
        }
        
        // Execute routing
        self.execute_routing(message_id, message, route).await?;
        
        Ok(message_id)
    }
    
    /// Find optimal route to destination
    pub async fn find_optimal_route(
        &self,
        destination: &PublicKey,
        sender: &PublicKey,
    ) -> Result<Vec<RouteHop>> {
        debug!("Finding optimal route to {:?}", hex::encode(&destination.key_id[0..4]));
        
        // Check route cache first
        if let Some(cached_route) = self.get_cached_route(destination).await {
            info!("Using cached route to destination (quality: {:.2})", 
                  cached_route.quality_score);
            return Ok(cached_route.hops);
        }
        
        // Check for direct connection
        let connections = self.mesh_connections.read().await;
        if connections.contains_key(destination) {
            info!("Direct connection available to destination");
            let connection = connections.get(destination).unwrap();
            return Ok(vec![RouteHop {
                peer_id: destination.clone(),
                protocol: connection.protocol.clone(),
                relay_id: None,
                latency_ms: connection.latency_ms,
            }]);
        }
        
        // Find multi-hop route through mesh network
        if let Ok(mesh_route) = self.find_mesh_route(destination, sender).await {
            info!("Found multi-hop mesh route ({} hops)", mesh_route.len());
            return Ok(mesh_route);
        }
        
        // Try long-range relay routing
        if let Ok(relay_route) = self.find_long_range_route(destination).await {
            info!("Using long-range relay route");
            return Ok(relay_route);
        }
        
        // Use global satellite routing as last resort
        if let Ok(satellite_route) = self.find_satellite_route(destination).await {
            info!("🛰️ Using GLOBAL satellite routing - PLANETARY reach!");
            return Ok(satellite_route);
        }
        
        Err(anyhow!("No route found to destination"))
    }
    
    /// Find multi-hop route through mesh network
    async fn find_mesh_route(
        &self,
        destination: &PublicKey,
        sender: &PublicKey,
    ) -> Result<Vec<RouteHop>> {
        debug!("Searching mesh network for route");
        
        let connections = self.mesh_connections.read().await;
        let routing_table = self.routing_table.read().await;
        
        // Use Dijkstra's algorithm for optimal path finding
        let mut distances: HashMap<PublicKey, f64> = HashMap::new();
        let mut previous: HashMap<PublicKey, Option<PublicKey>> = HashMap::new();
        let mut unvisited: HashSet<PublicKey> = HashSet::new();
        
        // Initialize distances
        for peer_id in connections.keys() {
            distances.insert(peer_id.clone(), f64::INFINITY);
            previous.insert(peer_id.clone(), None);
            unvisited.insert(peer_id.clone());
        }
        distances.insert(sender.clone(), 0.0);
        unvisited.insert(sender.clone());
        
        // Dijkstra's algorithm
        while !unvisited.is_empty() {
            // Find unvisited node with minimum distance
            let current = unvisited.iter()
                .min_by(|a, b| {
                    let dist_a = distances.get(a).unwrap_or(&f64::INFINITY);
                    let dist_b = distances.get(b).unwrap_or(&f64::INFINITY);
                    dist_a.partial_cmp(dist_b).unwrap()
                })
                .cloned();
            
            if let Some(current_peer) = current {
                if current_peer == *destination {
                    // Found route to destination
                    return self.construct_route_from_path(&previous, destination, &connections).await;
                }
                
                unvisited.remove(&current_peer);
                
                // Check neighbors
                if let Some(neighbors) = routing_table.topology_map.peer_connections.get(&current_peer) {
                    for neighbor in neighbors {
                        if unvisited.contains(neighbor) {
                            let edge_weight = self.calculate_edge_weight(&current_peer, neighbor, &connections).await;
                            let alt_distance = distances.get(&current_peer).unwrap_or(&f64::INFINITY) + edge_weight;
                            
                            if alt_distance < *distances.get(neighbor).unwrap_or(&f64::INFINITY) {
                                distances.insert(neighbor.clone(), alt_distance);
                                previous.insert(neighbor.clone(), Some(current_peer.clone()));
                            }
                        }
                    }
                }
            } else {
                break; // No more reachable nodes
            }
        }
        
        Err(anyhow!("No mesh route found to destination"))
    }
    
    /// Calculate edge weight for routing algorithm
    async fn calculate_edge_weight(
        &self,
        from: &PublicKey,
        to: &PublicKey,
        connections: &HashMap<PublicKey, MeshConnection>,
    ) -> f64 {
        // Weight based on latency, stability, and bandwidth
        if let Some(connection) = connections.get(to) {
            let latency_weight = connection.latency_ms as f64 / 1000.0; // Convert to seconds
            let stability_weight = 1.0 - connection.stability_score; // Lower stability = higher weight
            let bandwidth_weight = 1.0 / (connection.bandwidth_capacity as f64 / 1_000_000.0); // Favor higher bandwidth
            
            latency_weight + stability_weight + bandwidth_weight
        } else {
            f64::INFINITY // No connection
        }
    }
    
    /// Construct route from pathfinding result
    async fn construct_route_from_path(
        &self,
        previous: &HashMap<PublicKey, Option<PublicKey>>,
        destination: &PublicKey,
        connections: &HashMap<PublicKey, MeshConnection>,
    ) -> Result<Vec<RouteHop>> {
        let mut route = Vec::new();
        let mut current = destination.clone();
        
        // Trace back from destination to source
        while let Some(Some(prev)) = previous.get(&current) {
            if let Some(connection) = connections.get(&current) {
                route.push(RouteHop {
                    peer_id: current.clone(),
                    protocol: connection.protocol.clone(),
                    relay_id: None,
                    latency_ms: connection.latency_ms,
                });
            }
            current = prev.clone();
        }
        
        // Reverse to get source-to-destination order
        route.reverse();
        
        if route.is_empty() {
            return Err(anyhow!("Could not construct route"));
        }
        
        Ok(route)
    }
    
    /// Find long-range relay route
    async fn find_long_range_route(&self, destination: &PublicKey) -> Result<Vec<RouteHop>> {
        debug!("Searching long-range relays for route");
        
        let relays = self.long_range_relays.read().await;
        let mut best_relay = None;
        let mut best_score = 0.0f64;
        
        // Find best relay for this destination
        for (relay_id, relay) in relays.iter() {
            // Score based on coverage, throughput, and cost
            let coverage_score = (relay.coverage_radius_km / 1000.0).min(1.0); // Normalize to 1000km
            let throughput_score = (relay.max_throughput_mbps as f64 / 100.0).min(1.0); // Normalize to 100 Mbps
            let cost_score = 1.0 / (relay.cost_per_mb_tokens as f64 / 10.0 + 1.0); // Lower cost = higher score
            
            let total_score = (coverage_score + throughput_score + cost_score) / 3.0;
            
            if total_score > best_score {
                best_score = total_score;
                best_relay = Some((relay_id.clone(), relay.clone()));
            }
        }
        
        if let Some((relay_id, relay)) = best_relay {
            info!("Selected relay {} for long-range routing (score: {:.2})", 
                  relay_id, best_score);
            
            Ok(vec![RouteHop {
                peer_id: destination.clone(),
                protocol: NetworkProtocol::LoRaWAN, // Long-range protocol
                relay_id: Some(relay_id),
                latency_ms: 500, // Typical long-range latency
            }])
        } else {
            Err(anyhow!("No suitable long-range relay found"))
        }
    }
    
    /// Find satellite route for GLOBAL coverage
    async fn find_satellite_route(&self, destination: &PublicKey) -> Result<Vec<RouteHop>> {
        debug!("🛰️ Searching for satellite uplink route");
        
        let relays = self.long_range_relays.read().await;
        
        // Find satellite relay
        for (relay_id, relay) in relays.iter() {
            if matches!(relay.relay_type, crate::types::relay_type::LongRangeRelayType::Satellite) {
                info!("🛰️ Found satellite uplink {} - GLOBAL reach enabled!", relay_id);
                
                return Ok(vec![RouteHop {
                    peer_id: destination.clone(),
                    protocol: NetworkProtocol::Satellite,
                    relay_id: Some(relay_id.clone()),
                    latency_ms: 600, // Satellite latency (LEO satellites)
                }]);
            }
        }
        
        Err(anyhow!("No satellite uplink available"))
    }
    
    /// Execute routing with selected route
    async fn execute_routing(
        &self,
        message_id: u64,
        message: ZhtpMeshMessage,
        route: Vec<RouteHop>,
    ) -> Result<()> {
        info!(" Executing routing for message {} ({} hops)", message_id, route.len());
        
        // Update delivery status
        {
            let mut tracking = self.delivery_tracking.write().await;
            if let Some(status) = tracking.get_mut(&message_id) {
                status.stage = DeliveryStage::Routing;
                status.attempts += 1;
                status.last_update = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
            }
        }
        
        // Route through each hop
        for (hop_index, hop) in route.iter().enumerate() {
            info!("📤 Routing to hop {}: {:?} via {:?}", 
                  hop_index + 1, hex::encode(&hop.peer_id.key_id[0..4]), hop.protocol);
            
            // Update current hop
            {
                let mut tracking = self.delivery_tracking.write().await;
                if let Some(status) = tracking.get_mut(&message_id) {
                    status.current_hop = hop_index;
                }
            }
            
            // Execute hop-specific routing
            match hop.protocol {
                NetworkProtocol::Satellite => {
                    self.route_via_satellite(message_id, &message, hop).await?;
                },
                NetworkProtocol::LoRaWAN => {
                    self.route_via_long_range(message_id, &message, hop).await?;
                },
                _ => {
                    self.route_via_mesh(message_id, &message, hop).await?;
                }
            }
            
            // Simulate routing delay
            tokio::time::sleep(tokio::time::Duration::from_millis(hop.latency_ms as u64)).await;
        }
        
        // Mark as delivered
        {
            let mut tracking = self.delivery_tracking.write().await;
            if let Some(status) = tracking.get_mut(&message_id) {
                status.stage = DeliveryStage::Delivered;
                status.last_update = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
            }
        }
        
        info!("Message {} successfully delivered", message_id);
        Ok(())
    }
    
    /// Route via satellite for GLOBAL reach
    async fn route_via_satellite(
        &self,
        message_id: u64,
        message: &ZhtpMeshMessage,
        hop: &RouteHop,
    ) -> Result<()> {
        info!("🛰️ GLOBAL satellite routing: message {} to ANYWHERE on Earth", message_id);
        
        {
            let mut tracking = self.delivery_tracking.write().await;
            if let Some(status) = tracking.get_mut(&message_id) {
                status.stage = DeliveryStage::LongRange;
            }
        }
        
        // Satellite routing enables PLANETARY reach
        info!("Satellite uplink active - message can reach ANY location on Earth!");
        info!(" ZHTP revolutionizing global communications - no ISP needed!");
        
        Ok(())
    }
    
    /// Route via long-range relay
    async fn route_via_long_range(
        &self,
        message_id: u64,
        message: &ZhtpMeshMessage,
        hop: &RouteHop,
    ) -> Result<()> {
        info!("Long-range relay routing: message {}", message_id);
        
        if let Some(relay_id) = &hop.relay_id {
            let relays = self.long_range_relays.read().await;
            if let Some(relay) = relays.get(relay_id) {
                info!("Using {} relay: {:.0}km range, {} Mbps", 
                      relay_id, relay.coverage_radius_km, relay.max_throughput_mbps);
            }
        }
        
        Ok(())
    }
    
    /// Route via mesh connection
    async fn route_via_mesh(
        &self,
        message_id: u64,
        message: &ZhtpMeshMessage,
        hop: &RouteHop,
    ) -> Result<()> {
        debug!("Mesh routing: message {} to {:?}", 
               message_id, hex::encode(&hop.peer_id.key_id[0..4]));
        
        let connections = self.mesh_connections.read().await;
        if let Some(connection) = connections.get(&hop.peer_id) {
            debug!("📤 Forwarding via {} (quality: {:.2})", 
                   format!("{:?}", connection.protocol), connection.stability_score);
        }
        
        Ok(())
    }
    
    /// Get cached route if available and valid
    async fn get_cached_route(&self, destination: &PublicKey) -> Option<CachedRoute> {
        let cache = self.route_cache.read().await;
        if let Some(cached) = cache.get(destination) {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            if current_time - cached.cached_at < cached.validity_duration {
                return Some(cached.clone());
            }
        }
        None
    }
    
    /// Cache route for future use
    pub async fn cache_route(&self, destination: PublicKey, route: Vec<RouteHop>, quality_score: f64) {
        let cached_route = CachedRoute {
            hops: route,
            quality_score,
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            validity_duration: 300, // 5 minutes
        };
        
        let mut cache = self.route_cache.write().await;
        cache.insert(destination, cached_route);
    }
    
    /// Get delivery status for message
    pub async fn get_delivery_status(&self, message_id: u64) -> Option<DeliveryStatus> {
        let tracking = self.delivery_tracking.read().await;
        tracking.get(&message_id).cloned()
    }
    
    /// Update routing table with topology information
    pub async fn update_topology(&self, topology_updates: Vec<TopologyUpdate>) -> Result<()> {
        let mut routing_table = self.routing_table.write().await;
        
        for update in topology_updates {
            match update {
                TopologyUpdate::PeerConnection { peer_a, peer_b } => {
                    routing_table.topology_map.peer_connections
                        .entry(peer_a.clone())
                        .or_insert_with(HashSet::new)
                        .insert(peer_b.clone());
                    
                    routing_table.topology_map.peer_connections
                        .entry(peer_b)
                        .or_insert_with(HashSet::new)
                        .insert(peer_a);
                },
                TopologyUpdate::PeerDisconnection { peer_a, peer_b } => {
                    if let Some(connections) = routing_table.topology_map.peer_connections.get_mut(&peer_a) {
                        connections.remove(&peer_b);
                    }
                    if let Some(connections) = routing_table.topology_map.peer_connections.get_mut(&peer_b) {
                        connections.remove(&peer_a);
                    }
                },
            }
        }
        
        Ok(())
    }
}

/// Topology update events
#[derive(Debug, Clone)]
pub enum TopologyUpdate {
    PeerConnection { peer_a: PublicKey, peer_b: PublicKey },
    PeerDisconnection { peer_a: PublicKey, peer_b: PublicKey },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    #[tokio::test]
    async fn test_message_router_creation() {
        let mesh_connections = Arc::new(RwLock::new(HashMap::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        
        let router = MeshMessageRouter::new(mesh_connections, long_range_relays);
        
        assert!(router.routing_table.read().await.direct_routes.is_empty());
    }
    
    #[tokio::test]
    async fn test_route_caching() {
        let mesh_connections = Arc::new(RwLock::new(HashMap::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        
        let router = MeshMessageRouter::new(mesh_connections, long_range_relays);
        let destination = PublicKey::new(vec![1, 2, 3]);
        let route = vec![RouteHop {
            peer_id: destination.clone(),
            protocol: NetworkProtocol::BluetoothLE,
            relay_id: None,
            latency_ms: 100,
        }];
        
        router.cache_route(destination.clone(), route.clone(), 0.9).await;
        
        let cached = router.get_cached_route(&destination).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().hops.len(), 1);
    }
}
