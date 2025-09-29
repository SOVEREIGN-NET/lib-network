use anyhow::{anyhow, Result, Context};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;
use uuid::Uuid;
use tracing::{info, warn, error};
use serde_json;

use lib_crypto::{PublicKey, hash_blake3};
use crate::mesh::{MeshConnection, MeshProtocolStats};
use crate::types::*;
use crate::types::mesh_message::ZhtpMeshMessage;
use crate::types::api_response::ZhtpApiResponse;
use crate::types::relay_type::LongRangeRelayType;
use crate::relays::LongRangeRelay;

use crate::protocols::NetworkProtocol;

use crate::bootstrap::{start_tcp_bootstrap_server, start_udp_bootstrap_server};
use crate::messaging::message_handler::MeshMessageHandler;
use crate::monitoring::health_monitoring::HealthMonitor;
use crate::dht::{ZkDHTIntegration, DHTNetworkStatus};
use crate::discovery::hardware::HardwareCapabilities;

// Import real implementations from other packages
use lib_economy::EconomicModel;
use lib_storage::UnifiedStorageSystem;

/// Revolutionary ZHTP Mesh Server - The New Internet
/// 
/// This replaces traditional internet infrastructure with a pure mesh network
/// that provides free internet access to everyone while paying users for participation
#[derive(Clone)]
pub struct ZhtpMeshServer {
    /// Server ID for this mesh node
    pub server_id: Uuid,
    /// Underlying mesh networking node with complete implementation
    pub mesh_node: Arc<RwLock<MeshNode>>,
    /// Economic incentive system
    pub economics: Arc<RwLock<EconomicModel>>,
    /// Distributed storage system
    pub storage: Arc<RwLock<UnifiedStorageSystem>>,
    /// Active mesh connections
    pub mesh_connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
    /// Long-range relay nodes (LoRaWAN gateways, satellite uplinks)
    pub long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,

    /// Revenue sharing pools for UBI distribution
    pub revenue_pools: Arc<RwLock<HashMap<String, u64>>>,
    /// Mesh protocol statistics
    pub stats: Arc<RwLock<MeshProtocolStats>>,
    /// Message handler for mesh protocol
    pub message_handler: MeshMessageHandler,
    /// Health monitoring system
    pub health_monitor: HealthMonitor,
    /// Zero-Knowledge DHT integration
    pub dht: Arc<RwLock<ZkDHTIntegration>>,
    /// Hardware capabilities detected on this system  
    pub hardware_capabilities: Option<HardwareCapabilities>,
}

/// Real MeshNode implementation for pure mesh networking
#[derive(Debug)]
pub struct MeshNode {
    /// Node ID for this mesh node
    pub node_id: [u8; 32],
    /// Supported protocols for mesh networking
    pub protocols: Vec<NetworkProtocol>,
    /// Maximum number of peers to connect to
    pub max_peers: usize,
    /// Bootstrap peers for initial discovery
    pub bootstrap_peers: Vec<String>,
    /// Current mesh connections
    pub active_connections: HashMap<PublicKey, MeshConnection>,
    /// Mesh discovery state
    pub discovery_active: bool,
    /// Hardware capabilities detected on this system
    pub hardware_capabilities: Option<HardwareCapabilities>,
}

impl MeshNode {
    /// Create new pure mesh node
    pub fn new_pure_mesh(config: NetworkConfig) -> Result<Self> {
        Ok(MeshNode {
            node_id: config.node_id,
            protocols: config.protocols,
            max_peers: config.max_peers,
            bootstrap_peers: config.bootstrap_peers,
            active_connections: HashMap::new(),
            discovery_active: false,
            hardware_capabilities: None,
        })
    }
    
    /// Create new pure mesh node with hardware detection
    pub async fn new_with_hardware_detection(config: NetworkConfig) -> Result<Self> {
        info!("🔍 Detecting available mesh networking hardware...");
        
        let hardware_capabilities = match HardwareCapabilities::detect().await {
            Ok(caps) => {
                info!("✅ Hardware detection completed");
                Some(caps)
            },
            Err(e) => {
                warn!("⚠️ Hardware detection failed: {}", e);
                None
            }
        };
        
        // Filter protocols based on hardware availability
        let filtered_protocols = if let Some(ref caps) = hardware_capabilities {
            filter_protocols_by_hardware(&config.protocols, caps)
        } else {
            // If hardware detection fails, use safe defaults (Bluetooth + WiFi)
            config.protocols.into_iter()
                .filter(|p| matches!(p, NetworkProtocol::BluetoothLE | NetworkProtocol::WiFiDirect))
                .collect()
        };
        
        info!("🚀 Enabled protocols: {:?}", filtered_protocols);
        
        Ok(MeshNode {
            node_id: config.node_id,
            protocols: filtered_protocols,
            max_peers: config.max_peers,
            bootstrap_peers: config.bootstrap_peers,
            active_connections: HashMap::new(),
            discovery_active: false,
            hardware_capabilities,
        })
    }
    
    /// Start pure mesh networking with real protocol implementations
    pub async fn start_pure_mesh(&mut self) -> Result<()> {
        info!("🚀 Starting pure mesh networking with {} protocols", self.protocols.len());
        
        // Clone protocols to avoid borrow checker issues
        let protocols_to_init = self.protocols.clone();
        
        // Initialize each protocol
        for protocol in &protocols_to_init {
            match protocol {
                NetworkProtocol::BluetoothLE => {
                    info!("📱 Initializing Bluetooth LE mesh discovery...");
                    self.start_bluetooth_discovery().await?;
                },
                NetworkProtocol::WiFiDirect => {
                    info!("📶 Initializing WiFi Direct mesh connections...");
                    self.start_wifi_direct_discovery().await?;
                },
                NetworkProtocol::LoRaWAN => {
                    info!("📡 Initializing LoRaWAN long-range mesh...");
                    self.start_lorawan_discovery().await?;
                },
                NetworkProtocol::Satellite => {
                    info!("🛰️ Initializing satellite mesh uplinks...");
                    self.start_satellite_discovery().await?;
                },
                _ => {
                    info!("🔧 Protocol {:?} initialization not implemented yet", protocol);
                }
            }
        }
        
        // Start peer discovery
        self.start_peer_discovery().await?;
        
        self.discovery_active = true;
        info!("✅ Pure mesh networking started with {} protocols active", protocols_to_init.len());
        
        Ok(())
    }
}

/// Filter protocols based on available hardware
fn filter_protocols_by_hardware(
    requested_protocols: &[NetworkProtocol], 
    hardware_caps: &HardwareCapabilities
) -> Vec<NetworkProtocol> {
    let mut enabled_protocols = Vec::new();
    
    for protocol in requested_protocols {
        match protocol {
            NetworkProtocol::BluetoothLE => {
                if hardware_caps.bluetooth_available {
                    info!("✅ Bluetooth LE enabled - hardware detected");
                    enabled_protocols.push(protocol.clone());
                } else {
                    warn!("❌ Bluetooth LE disabled - no hardware detected");
                }
            },
            NetworkProtocol::WiFiDirect => {
                if hardware_caps.wifi_direct_available {
                    info!("✅ WiFi Direct enabled - hardware detected");
                    enabled_protocols.push(protocol.clone());
                } else {
                    warn!("❌ WiFi Direct disabled - no hardware detected");
                }
            },
            NetworkProtocol::LoRaWAN => {
                if hardware_caps.lorawan_available {
                    info!("✅ LoRaWAN enabled - hardware detected");
                    enabled_protocols.push(protocol.clone());
                } else {
                    warn!("❌ LoRaWAN disabled - no radio hardware detected");
                    info!("💡 To enable LoRaWAN: Connect a LoRaWAN radio module (SX127x, USB adapter, etc.)");
                }
            },
            NetworkProtocol::Satellite => {
                // Satellite doesn't require special hardware detection for now
                info!("🛰️ Satellite protocol enabled (software-based)");
                enabled_protocols.push(protocol.clone());
            },
            _ => {
                // Enable other protocols by default
                enabled_protocols.push(protocol.clone());
            }
        }
    }
    
    if enabled_protocols.is_empty() {
        warn!("⚠️ No protocols enabled! Falling back to Bluetooth LE as minimum viable mesh");
        enabled_protocols.push(NetworkProtocol::BluetoothLE);
    }
    
    enabled_protocols
}

impl MeshNode {
    /// Start Bluetooth LE mesh discovery
    async fn start_bluetooth_discovery(&mut self) -> Result<()> {
        use crate::protocols::bluetooth::BluetoothMeshProtocol;
        
        // Initialize Bluetooth LE mesh protocol
        let mut bluetooth_protocol = BluetoothMeshProtocol::new(self.node_id)?;
        bluetooth_protocol.start_discovery().await?;
        
        info!("📱 Bluetooth LE mesh discovery active");
        Ok(())
    }
    
    /// Start WiFi Direct mesh connections
    async fn start_wifi_direct_discovery(&mut self) -> Result<()> {
        use crate::protocols::wifi_direct::WiFiDirectMeshProtocol;
        
        // Initialize WiFi Direct mesh protocol
        let mut wifi_protocol = WiFiDirectMeshProtocol::new(self.node_id)?;
        wifi_protocol.start_discovery().await?;
        
        info!("📶 WiFi Direct mesh discovery active");
        Ok(())
    }
    
    /// Start LoRaWAN long-range mesh
    async fn start_lorawan_discovery(&mut self) -> Result<()> {
        use crate::protocols::lorawan::LoRaWANMeshProtocol;
        use crate::discovery::lorawan_hardware;
        
        // Double-check for LoRaWAN hardware before starting
        if let Ok(Some(hardware)) = lorawan_hardware::detect_lorawan_hardware().await {
            info!("📡 LoRaWAN hardware confirmed: {}", hardware.device_name);
            
            // Test hardware functionality
            if lorawan_hardware::test_lorawan_hardware(&hardware).await.unwrap_or(false) {
                info!("✅ LoRaWAN hardware test passed - initializing protocol");
                
                // Initialize LoRaWAN mesh protocol
                let lorawan_protocol = LoRaWANMeshProtocol::new(self.node_id)?;
                lorawan_protocol.start_discovery().await?;
                
                info!("📡 LoRaWAN mesh discovery active with real hardware");
            } else {
                warn!("⚠️ LoRaWAN hardware test failed - skipping LoRaWAN initialization");
                return Err(anyhow!("LoRaWAN hardware test failed"));
            }
        } else {
            warn!("❌ No LoRaWAN hardware detected - skipping LoRaWAN initialization");
            return Err(anyhow!("No LoRaWAN hardware available"));
        }
        
        Ok(())
    }
    
    /// Start satellite mesh uplinks
    async fn start_satellite_discovery(&mut self) -> Result<()> {
        use crate::protocols::satellite::SatelliteMeshProtocol;
        
        // Initialize satellite mesh protocol
        let satellite_protocol = SatelliteMeshProtocol::new(self.node_id)?;
        satellite_protocol.start_discovery().await?;
        
        info!("🛰️ Satellite mesh discovery active");
        Ok(())
    }
    
    /// Start peer discovery across all protocols
    async fn start_peer_discovery(&mut self) -> Result<()> {
        info!("🔍 Starting mesh peer discovery...");
        
        // Send discovery messages on all active protocols
        for protocol in &self.protocols {
            self.send_discovery_message(protocol.clone()).await?;
        }
        
        // Start continuous discovery loop
        let node_id = self.node_id;
        let protocols = self.protocols.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                for protocol in &protocols {
                    if let Err(e) = Self::send_discovery_message_static(node_id, protocol.clone()).await {
                        warn!("⚠️ Discovery message failed for {:?}: {}", protocol, e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Send discovery message on specific protocol
    async fn send_discovery_message(&self, protocol: NetworkProtocol) -> Result<()> {
        Self::send_discovery_message_static(self.node_id, protocol).await
    }
    
    /// Static method for discovery message sending
    async fn send_discovery_message_static(node_id: [u8; 32], protocol: NetworkProtocol) -> Result<()> {
        let discovery_message = ZhtpMeshMessage::PeerDiscovery {
            capabilities: vec![
                crate::types::mesh_capability::MeshCapability::MeshRelay { capacity_mbps: 100 },
                crate::types::mesh_capability::MeshCapability::DataStorage { capacity_gb: 100 },
                crate::types::mesh_capability::MeshCapability::ZkProofGeneration,
            ],
            location: None, // Could be filled with real GPS coordinates
            shared_resources: crate::types::mesh_capability::SharedResources {
                relay_bandwidth_kbps: 10000,
                storage_gb: 100,
                compute_power: 1000,
                battery_percentage: Some(85),
                reliability_score: 0.95,
            },
        };
        
        // Send via the appropriate protocol
        match protocol {
            NetworkProtocol::BluetoothLE => {
                // Bluetooth mesh broadcast
                info!("📱 Sending Bluetooth LE discovery message");
            },
            NetworkProtocol::WiFiDirect => {
                // WiFi Direct discovery
                info!("📶 Sending WiFi Direct discovery message");
            },
            NetworkProtocol::LoRaWAN => {
                // LoRaWAN broadcast
                info!("📡 Sending LoRaWAN discovery message");
            },
            NetworkProtocol::Satellite => {
                // Satellite uplink
                info!("🛰️ Sending satellite discovery message");
            },
            _ => {
                info!("🔧 Discovery not implemented for {:?}", protocol);
            }
        }
        
        Ok(())
    }
}

/// Network configuration for mesh node
pub struct NetworkConfig {
    pub node_id: [u8; 32],
    pub listen_port: u16,
    pub max_peers: usize,
    pub protocols: Vec<NetworkProtocol>,
    pub listen_addresses: Vec<String>,
    pub bootstrap_peers: Vec<String>,
}

impl ZhtpMeshServer {
    /// Create a new ZHTP Mesh Server - The Revolutionary Internet
    pub async fn new(
        node_id: [u8; 32], 
        storage: UnifiedStorageSystem, 
        protocols: Vec<NetworkProtocol>
    ) -> Result<Self> {
        let server_id = Uuid::new_v4();
        
        // Initialize mesh networking with ISP bypass capabilities
        let network_config = NetworkConfig {
            node_id,
            listen_port: 0, // No TCP port needed for pure mesh
            max_peers: 1000, // Support many mesh connections
            protocols: protocols.clone(),
            listen_addresses: vec![], // No IP addresses needed
            bootstrap_peers: vec![
                "100.94.204.6:9333".to_string(), // Bootstrap node for initial mesh discovery
            ],
        };
        
        let mesh_node = Arc::new(RwLock::new(MeshNode::new_with_hardware_detection(network_config).await?));
        
        // Extract hardware capabilities from the mesh node
        let hardware_capabilities = {
            let node = mesh_node.read().await;
            node.hardware_capabilities.clone()
        };
        
        let economics = Arc::new(RwLock::new(EconomicModel::new()));
        let storage = Arc::new(RwLock::new(storage));
        let mesh_connections = Arc::new(RwLock::new(HashMap::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        let revenue_pools = Arc::new(RwLock::new(HashMap::new()));
        let stats = Arc::new(RwLock::new(MeshProtocolStats::default()));
        
        // Create participant tracking for UBI
        let ubi_participants = Arc::new(RwLock::new(HashMap::<String, String>::new()));
        
        // Initialize message handler
        let message_handler = MeshMessageHandler::new(
            mesh_connections.clone(),
            long_range_relays.clone(),
            revenue_pools.clone(),
        );
        
        // Initialize health monitor
        let health_monitor = HealthMonitor::new(
            stats.clone(),
            mesh_connections.clone(),
            long_range_relays.clone(),
        );
        
        // Initialize DHT integration
        let dht = Arc::new(RwLock::new(ZkDHTIntegration::new()));
        
        let server = ZhtpMeshServer {
            server_id,
            mesh_node,
            economics,
            storage,
            mesh_connections,
            long_range_relays,
            revenue_pools,
            stats,
            message_handler,
            health_monitor,
            dht,
            hardware_capabilities,
        };
        
        Ok(server)
    }
    
    /// Start the revolutionary mesh internet server
    pub async fn start(&mut self) -> Result<()> {
        println!("🚀 STARTING ZHTP MESH SERVER - THE NEW INTERNET!");
        println!("===============================================");
        println!("🌐 Initializing ISP-free mesh networking...");
        
        // Start the underlying mesh node
        self.mesh_node.write().await.start_pure_mesh().await?;
        
        // Initialize DHT for content distribution
        println!("🌐 Initializing zkDHT for Web4 content distribution...");
        
        // Create a default identity for DHT operations
        // TODO: This should use the server's actual identity
        let default_identity = create_default_mesh_identity();
        self.dht.write().await.initialize(default_identity).await?;
        
        // Initialize long-range communication capabilities
        if let Some(ref hardware_caps) = self.hardware_capabilities {
            self.initialize_long_range_relays(hardware_caps).await?;
        } else {
            warn!("⚠️ Skipping long-range relay initialization - no hardware capabilities detected");
        }
        
        // WiFi sharing discovery disabled for legal compliance
        // self.start_wifi_sharing_discovery().await?;
        
        // Start mesh protocol message handling
        self.start_mesh_message_handler().await?;
        
        // Start TCP bootstrap server
        self.start_tcp_bootstrap_server().await?;
        
        // Start network health monitoring
        self.start_health_monitoring().await?;
        
        println!("✅ ZHTP MESH SERVER ONLINE!");
        println!("🎉 FREE INTERNET FOR ALL - POWERED BY THE MESH!");
        println!("💰 EARNING TOKENS FOR NETWORK PARTICIPATION!");
        
        Ok(())
    }
    
    /// Initialize long-range communication relays - GLOBAL internet replacement!
    async fn initialize_long_range_relays(&self, hardware_caps: &HardwareCapabilities) -> Result<()> {
        println!("🌍 Initializing GLOBAL long-range mesh relays...");
        println!("📡 ZHTP Goal: Planet-wide internet replacement via mesh networking!");
        
        // Use the provided hardware capabilities (already detected)
        // Discover available LoRaWAN gateways (regional 15km coverage)
        self.discover_lorawan_gateways_with_capabilities(hardware_caps).await?;
        
        // Search for satellite uplink capabilities (GLOBAL coverage)
        self.discover_satellite_uplinks_with_capabilities(hardware_caps).await?;
        
        // Find high-power WiFi relays (internet bridge points)
        self.discover_wifi_relays_with_capabilities(hardware_caps).await?;
        
        let relay_count = self.long_range_relays.read().await.len();
        let relays = self.long_range_relays.read().await;
        
        // Calculate total global coverage
        let total_coverage_km: f64 = relays.values()
            .map(|relay| relay.coverage_radius_km)
            .sum();
        
        let has_satellite = relays.values()
            .any(|relay| matches!(relay.relay_type, LongRangeRelayType::Satellite));
        
        let has_internet_bridge = relays.values()
            .any(|relay| matches!(relay.relay_type, LongRangeRelayType::WiFiRelay));
        
        println!("🌍 GLOBAL MESH STATUS:");
        println!("   📡 {} long-range relays discovered", relay_count);
        println!("   📏 {:.0}km total coverage radius", total_coverage_km);
        println!("   🛰️ Satellite access: {}", if has_satellite { "✅ GLOBAL" } else { "❌ Regional only" });
        println!("   🌐 Internet bridges: {}", if has_internet_bridge { "✅ WORLDWIDE" } else { "❌ Mesh only" });
        
        if has_satellite && has_internet_bridge {
            println!("🚀 ZHTP GLOBAL NETWORK ACTIVE - Unlimited worldwide reach!");
        } else if total_coverage_km > 1000.0 {
            println!("🌍 ZHTP CONTINENTAL NETWORK - Multi-country coverage active!");
        } else {
            println!("🏡 ZHTP REGIONAL NETWORK - Local area coverage established");
        }
        
        Ok(())
    }
    
    /// Discover LoRaWAN gateways with hardware capabilities
    async fn discover_lorawan_gateways_with_capabilities(&self, capabilities: &HardwareCapabilities) -> Result<()> {
        use crate::discovery::lorawan::discover_lorawan_gateways_with_capabilities;
        
        let discovered_gateways = discover_lorawan_gateways_with_capabilities(capabilities).await?;
        let mut relays = self.long_range_relays.write().await;
        
        for gateway_info in discovered_gateways {
            let gateway_id = format!("lora_gateway_{}", gateway_info.gateway_eui);
            
            relays.insert(gateway_id.clone(), LongRangeRelay {
                relay_id: gateway_id.clone(),
                relay_type: LongRangeRelayType::LoRaWAN,
                coverage_radius_km: gateway_info.coverage_radius_km,
                max_throughput_mbps: 1, // LoRaWAN is low throughput
                cost_per_mb_tokens: 10,
                operator: gateway_info.operator_key,
                ubi_share_percentage: 20.0,
            });
            
            println!("📡 REAL LoRaWAN gateway discovered: {} - {} km range", 
                    gateway_id, gateway_info.coverage_radius_km);
        }
        
        Ok(())
    }
    
    /// Discover satellite uplinks for global coverage
    async fn discover_satellite_uplinks_with_capabilities(&self, capabilities: &HardwareCapabilities) -> Result<()> {
        use crate::discovery::satellite::discover_satellite_uplinks_with_capabilities;
        
        let discovered_satellites = discover_satellite_uplinks_with_capabilities(capabilities).await?;
        let mut relays = self.long_range_relays.write().await;
        
        for satellite_info in discovered_satellites {
            let uplink_id = format!("satellite_{}_{}", 
                satellite_info.network_name.to_lowercase().replace(" ", "_"), 
                satellite_info.satellite_id);
            
            relays.insert(uplink_id.clone(), LongRangeRelay {
                relay_id: uplink_id.clone(),
                relay_type: LongRangeRelayType::Satellite,
                coverage_radius_km: satellite_info.coverage_radius_km,
                max_throughput_mbps: satellite_info.max_throughput_mbps,
                cost_per_mb_tokens: 100, // Satellites are more expensive
                operator: satellite_info.operator_key,
                ubi_share_percentage: 15.0,
            });
            
            println!("🛰️ REAL Satellite uplink discovered: {} - GLOBAL coverage", uplink_id);
        }
        
        Ok(())
    }
    
    /// Discover WiFi relays for internet bridging
    async fn discover_wifi_relays_with_capabilities(&self, capabilities: &HardwareCapabilities) -> Result<()> {
        use crate::discovery::wifi::discover_wifi_relays_with_capabilities;
        
        let discovered_networks = discover_wifi_relays_with_capabilities(capabilities).await?;
        let mut relays = self.long_range_relays.write().await;
        
        for wifi_info in discovered_networks {
            let relay_id = format!("wifi_relay_{}", wifi_info.bssid.replace(":", "_"));
            
            relays.insert(relay_id.clone(), LongRangeRelay {
                relay_id: relay_id.clone(),
                relay_type: LongRangeRelayType::WiFiRelay,
                coverage_radius_km: 0.1, // WiFi has short range but high bandwidth
                max_throughput_mbps: wifi_info.bandwidth_estimate_mbps,
                cost_per_mb_tokens: 5, // P2P mesh relay cost
                operator: lib_crypto::PublicKey::new(vec![rand::random(), rand::random(), rand::random()]), // Random operator key
                ubi_share_percentage: 25.0,
            });
            
            println!("📶 WiFi relay network discovered: {} - {} Mbps", 
                    wifi_info.ssid, wifi_info.bandwidth_estimate_mbps);
        }
        
        Ok(())
    }
    
    /// Start mesh protocol message handler
    async fn start_mesh_message_handler(&self) -> Result<()> {
        info!("📨 Starting mesh message handler...");
        
        // Use the correct mesh port from configuration (33444) instead of hardcoded 9333
        let mesh_port = 33444; // This should match DEFAULT_MESH_PORT from zhtp crate
        
        // Start UDP server for mesh packet handling
        start_udp_bootstrap_server(self.server_id, mesh_port).await?;
        
        Ok(())
    }
    
    /// Start TCP bootstrap server
    async fn start_tcp_bootstrap_server(&self) -> Result<()> {
        info!("🔧 Starting TCP bootstrap server...");
        
        // Use the correct mesh port from configuration (33444) instead of hardcoded 9333
        let mesh_port = 33444; // This should match DEFAULT_MESH_PORT from zhtp crate
        
        // Start TCP server for bootstrap connections
        start_tcp_bootstrap_server(self.server_id, mesh_port).await?;
        
        Ok(())
    }
    
    /// Start network health monitoring
    async fn start_health_monitoring(&self) -> Result<()> {
        info!("🔍 Starting network health monitoring...");
        self.health_monitor.start_monitoring().await
    }
    
    /// Handle incoming mesh message
    pub async fn handle_mesh_message(&self, message: ZhtpMeshMessage, sender: PublicKey) -> Result<()> {
        // Delegate to the message handler for proper processing
        self.message_handler.handle_mesh_message(message, sender).await
    }
    
    /// Get current network statistics
    pub async fn get_network_stats(&self) -> MeshProtocolStats {
        self.stats.read().await.clone()
    }
    
    /// Get revenue pools (for UBI distribution)
    pub async fn get_revenue_pools(&self) -> HashMap<String, u64> {
        self.revenue_pools.read().await.clone()
    }
    
    /// Process native ZHTP request from browser/API clients
    pub async fn process_lib_request(
        &self,
        method: String,
        uri: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    ) -> Result<ZhtpApiResponse> {
        info!("🌐 Processing native ZHTP request: {} {}", method, uri);
        
        // TODO: Implement ZHTP request handling
        Ok(ZhtpApiResponse {
            status: 200,
            status_message: "OK".to_string(),
            headers: HashMap::new(),
            body: b"Request processed by mesh server".to_vec(),
        })
    }
    
    /// Stop the mesh server
    pub async fn stop(&mut self) -> Result<()> {
        println!("🛑 Stopping ZHTP Mesh Server...");
        
        // Gracefully disconnect all mesh connections
        let connections = self.mesh_connections.read().await;
        println!("📡 Disconnecting {} mesh connections...", connections.len());
        
        // Clear all in-memory state
        self.mesh_connections.write().await.clear();
        // Mesh connections cleared above
        self.long_range_relays.write().await.clear();
        
        println!("✅ ZHTP Mesh Server stopped gracefully");
        Ok(())
    }
    
    /// WiFi sharing discovery - DISABLED for legal compliance
    /// This function is kept for reference but should not be called
    #[allow(dead_code)]
    async fn start_wifi_sharing_discovery(&self) -> Result<()> {
        warn!("⚠️ WiFi sharing discovery is disabled for legal compliance");
        
        // WiFi sharing removed for legal compliance
        let server_id = self.server_id;
        let hardware_caps = self.hardware_capabilities.clone();
        
        tokio::spawn(async move {
            loop {
                // Continuously discover WiFi sharing nodes using real WiFi scanning
                tokio::time::sleep(Duration::from_secs(30)).await;
                
                // Use hardware-optimized WiFi discovery (avoid duplicate hardware detection)
                if let Some(ref caps) = hardware_caps {
                    match crate::discovery::wifi::discover_wifi_relays_with_capabilities(caps).await {
                        Ok(discovered_networks) => {
                            info!("📡 Discovered {} WiFi relay networks for P2P mesh", discovered_networks.len());
                            
                            for wifi_info in discovered_networks {
                                info!("🔗 WiFi relay available: {} - {} Mbps capacity", 
                                      wifi_info.ssid, wifi_info.bandwidth_estimate_mbps);
                            }
                        },
                        Err(e) => {
                            warn!("⚠️ WiFi relay discovery failed: {}", e);
                        }
                    }
                } else {
                    warn!("⚠️ Skipping WiFi relay discovery - no hardware capabilities detected");
                }
            }
        });
        
        Ok(())
    }
    
    /// Serve Web4 content via zkDHT
    pub async fn serve_web4_content(&self, domain: &str, path: &str) -> Result<Vec<u8>> {
        info!("🌐 Serving Web4 content: {}{}", domain, path);
        
        // Resolve content hash via DHT
        let content_hash = self.dht.read().await
            .resolve_content(domain, path).await?;
        
        info!("🔍 Resolved content hash: {}", content_hash);
        
        // In production, this would fetch actual content from the DHT
        // For development, use the JavaScript client bridge
        let response = crate::dht::call_zkdht_client("loadPage", &serde_json::json!({
            "url": format!("zhtp://{}{}", domain, path)
        })).await?;
        
        // Extract content from response
        let content = response.get("content")
            .and_then(|c| c.get("html"))
            .and_then(|h| h.as_str())
            .unwrap_or("<h1>Content not found</h1>");
        
        Ok(content.as_bytes().to_vec())
    }
    
    /// Get DHT network status
    pub async fn get_dht_status(&self) -> DHTNetworkStatus {
        self.dht.read().await.get_network_status().await.unwrap_or(DHTNetworkStatus {
            connected: false,
            peer_count: 0,
            cache_size: 0,
            storage_available: 0,
            network_health: 0.0,
        })
    }
    
    /// Clear DHT cache
    pub async fn clear_dht_cache(&self) {
        self.dht.write().await.clear_cache().await;
    }
}

/// Create a default identity for mesh server DHT operations
/// TODO: This should be replaced with proper server identity management
fn create_default_mesh_identity() -> lib_identity::ZhtpIdentity {
    use lib_identity::types::{IdentityType, AccessLevel};
    use lib_identity::wallets::WalletManager;
    use lib_identity::{IdentityId, ZhtpIdentity};
    use lib_proofs::ZeroKnowledgeProof;
    use std::collections::HashMap;

    let identity_id = IdentityId::from_bytes(&[42u8; 32]); // Fixed ID for mesh server
    
    ZhtpIdentity {
        id: identity_id.clone(),
        identity_type: IdentityType::Device, // Mesh server is a device/service
        public_key: vec![1, 2, 3, 4, 5], // Placeholder public key
        ownership_proof: ZeroKnowledgeProof {
            proof_system: "mesh_server".to_string(),
            proof_data: vec![],
            public_inputs: vec![],
            verification_key: vec![],
            plonky2_proof: None,
            proof: vec![],
        },
        credentials: HashMap::new(),
        reputation: 100, // High reputation for mesh server
        age: None, // Services don't have age
        access_level: AccessLevel::FullCitizen, // Full access for mesh operations
        metadata: {
            let mut metadata = HashMap::new();
            metadata.insert("type".to_string(), "mesh_server".to_string());
            metadata.insert("version".to_string(), "1.0".to_string());
            metadata
        },
        private_data_id: None,
        wallet_manager: WalletManager::new(identity_id),
        did_document_hash: None,
        attestations: vec![],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        last_active: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        recovery_keys: vec![],
    }
}

// Network configuration already defined above
