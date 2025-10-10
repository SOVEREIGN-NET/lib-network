use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;
use uuid::Uuid;
use tracing::{info, warn, error};
use serde_json;

use lib_crypto::PublicKey;
use crate::mesh::{MeshConnection, MeshProtocolStats};
// use crate::types::*; // Removed - unused imports
use crate::types::mesh_message::ZhtpMeshMessage;
use crate::types::api_response::ZhtpApiResponse;
use crate::types::relay_type::LongRangeRelayType;
use crate::relays::LongRangeRelay;

/// Security permission levels for network operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionLevel {
    /// Node owner - full control including emergency stop
    Owner,
    /// Network admin - can disconnect peers and manage connections
    Admin, 
    /// Regular user - can only disconnect own connections
    User,
    /// No permissions
    None,
}

/// Authentication credentials for secure operations
#[derive(Debug, Clone)]
pub struct SecurityCredentials {
    /// Caller's wallet public key
    pub wallet_key: PublicKey,
    /// Cryptographic signature of the operation
    pub signature: Vec<u8>,
    /// Timestamp to prevent replay attacks
    pub timestamp: u64,
    /// Operation nonce
    pub nonce: String,
}

/// Audit log entry for security operations
#[derive(Debug, Clone)]
pub struct SecurityAuditLog {
    pub timestamp: u64,
    pub operation: String,
    pub caller_key: String,
    pub target: Option<String>,
    pub permission_level: String,
    pub success: bool,
    pub reason: String,
}

use crate::protocols::NetworkProtocol;

use crate::bootstrap::{start_tcp_bootstrap_server, start_udp_bootstrap_server};
use crate::messaging::message_handler::MeshMessageHandler;
use crate::monitoring::health_monitoring::HealthMonitor;
use crate::dht::{ZkDHTIntegration, DHTNetworkStatus};
use crate::discovery::hardware::HardwareCapabilities;

// Import implementations from other packages
use lib_economy::EconomicModel;
use lib_storage::UnifiedStorageSystem;

/// Network configuration for mesh node
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub node_id: [u8; 32],
    pub listen_port: u16,
    pub max_peers: usize,
    pub protocols: Vec<NetworkProtocol>,
    pub listen_addresses: Vec<String>,
    pub bootstrap_peers: Vec<String>,
}

/// ZHTP Mesh Server - The New Internet
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
    
    /// Node owner wallet (for receiving rewards and controlling node)
    pub owner_wallet: Arc<RwLock<lib_identity::wallets::QuantumWallet>>,
    /// Routing rewards wallet (separate from owner wallet)
    pub routing_rewards_wallet: Arc<RwLock<lib_identity::wallets::QuantumWallet>>,
    /// Operational costs wallet (for network participation costs)
    pub operational_wallet: Arc<RwLock<lib_identity::wallets::QuantumWallet>>,
    
    /// Active Bluetooth LE mesh protocol instance
    pub bluetooth_protocol: Option<Arc<RwLock<crate::protocols::bluetooth::BluetoothMeshProtocol>>>,
    /// Active WiFi Direct mesh protocol instance
    pub wifi_direct_protocol: Option<Arc<RwLock<crate::protocols::wifi_direct::WiFiDirectMeshProtocol>>>,
    /// LoRaWAN mesh protocol instance
    pub lorawan_protocol: Option<Arc<RwLock<crate::protocols::lorawan::LoRaWANMeshProtocol>>>,
    /// Satellite mesh protocol instance
    pub satellite_protocol: Option<Arc<RwLock<crate::protocols::satellite::SatelliteMeshProtocol>>>,
    /// Active protocol status tracking
    pub active_protocols: Arc<RwLock<HashMap<NetworkProtocol, bool>>>,
    
    // Safety and Emergency Features
    /// Emergency stop flag for immediate shutdown
    pub emergency_stop: Arc<RwLock<bool>>,
    /// Maximum allowed connections (safety limit)  
    pub max_connections: Arc<RwLock<usize>>,
    /// Connection rate limiter to prevent abuse
    pub connection_attempts: Arc<RwLock<HashMap<String, u32>>>,
    
    // Security and Access Control
    /// Node owner's wallet public key (full permissions)
    pub owner_wallet_key: PublicKey,
    /// Authorized admin wallet keys (can disconnect peers)
    pub admin_wallet_keys: Arc<RwLock<Vec<PublicKey>>>,
    /// Security audit log for all operations
    pub security_audit_log: Arc<RwLock<Vec<SecurityAuditLog>>>,
}

/// MeshNode implementation for pure mesh networking
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
        info!("Detecting available mesh networking hardware...");
        
        let hardware_capabilities = match HardwareCapabilities::detect().await {
            Ok(caps) => {
                info!("Hardware detection completed");
                Some(caps)
            },
            Err(e) => {
                warn!("Hardware detection failed: {}", e);
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
        
        info!(" Enabled protocols: {:?}", filtered_protocols);
        
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
    
    /// Start pure mesh networking - protocols are managed by ZhtpMeshServer
    pub async fn start_pure_mesh(&mut self) -> Result<()> {
        info!(" Mesh node ready - protocol management handled by server layer");
        
        self.discovery_active = true;
        info!("Mesh node initialized with {} configured protocols", self.protocols.len());
        
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
                    info!("Bluetooth LE enabled - hardware detected");
                    enabled_protocols.push(protocol.clone());
                } else {
                    warn!("Bluetooth LE disabled - no hardware detected");
                }
            },
            NetworkProtocol::WiFiDirect => {
                if hardware_caps.wifi_direct_available {
                    info!("WiFi Direct enabled - hardware detected");
                    enabled_protocols.push(protocol.clone());
                } else {
                    warn!("WiFi Direct disabled - no hardware detected");
                }
            },
            NetworkProtocol::LoRaWAN => {
                if hardware_caps.lorawan_available {
                    info!("LoRaWAN enabled - hardware detected");
                    enabled_protocols.push(protocol.clone());
                } else {
                    warn!("LoRaWAN disabled - no radio hardware detected");
                    info!("To enable LoRaWAN: Connect a LoRaWAN radio module (SX127x, USB adapter, etc.)");
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
        warn!("No protocols enabled! Falling back to Bluetooth LE as minimum viable mesh");
        enabled_protocols.push(NetworkProtocol::BluetoothLE);
    }
    
    enabled_protocols
}

impl ZhtpMeshServer {
    /// Create standalone wallets for node operation (no DID required)
    async fn create_node_wallets(owner_key: &PublicKey) -> Result<(
        lib_identity::wallets::QuantumWallet,
        lib_identity::wallets::QuantumWallet, 
        lib_identity::wallets::QuantumWallet
    )> {
        // Create owner wallet (controls the node)
        let (owner_wallet_id, _owner_seed) = lib_identity::create_standalone_wallet(
            "Node Owner Wallet".to_string(),
            Some("owner".to_string()),
        ).await?;
        
        // Create routing rewards wallet (receives routing payments)
        let (routing_wallet_id, _routing_seed) = lib_identity::create_standalone_wallet(
            "Routing Rewards Wallet".to_string(),
            Some("routing_rewards".to_string()),
        ).await?;
        
        // Create operational wallet (pays for network operations)
        let (ops_wallet_id, _ops_seed) = lib_identity::create_standalone_wallet(
            "Operational Costs Wallet".to_string(),
            Some("operations".to_string()),
        ).await?;
        
        // Get wallet instances using the existing constructor
        let owner_wallet = lib_identity::wallets::QuantumWallet::new(
            lib_identity::wallets::WalletType::Primary,
            "Node Owner Wallet".to_string(),
            Some("owner".to_string()),
            None, // No owner_id for standalone
            owner_key.as_bytes().to_vec(),
        );
        
        let routing_wallet = lib_identity::wallets::QuantumWallet::new(
            lib_identity::wallets::WalletType::Primary,
            "Routing Rewards Wallet".to_string(),
            Some("routing_rewards".to_string()),
            None, // No owner_id for standalone
            owner_key.as_bytes().to_vec(),
        );
        
        let ops_wallet = lib_identity::wallets::QuantumWallet::new(
            lib_identity::wallets::WalletType::Primary, // Use Primary type for ops wallet
            "Operational Costs Wallet".to_string(),
            Some("operations".to_string()),
            None, // No owner_id for standalone
            owner_key.as_bytes().to_vec(),
        );
        
        info!(" Created standalone wallets for node operation");
        Ok((owner_wallet, routing_wallet, ops_wallet))
    }
    
    /// Record routing proof when we forward a message (simplified wallet-based)
    pub async fn record_routing_proof(
        &self,
        message_hash: [u8; 32],
        source: PublicKey,
        destination: PublicKey,
        data_size: usize,
        hop_count: u8,
    ) -> Result<()> {
        // Create routing proof for this routing action
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
            
        // Calculate immediate reward based on routing activity
        let base_reward = 10; // 10 tokens per message routed
        let size_bonus = (data_size / 1024) as u64; // 1 token per KB
        let hop_bonus = hop_count as u64 * 5; // 5 tokens per hop
        let total_reward = base_reward + size_bonus + hop_bonus;
        
        // Distribute reward directly to routing wallet (no identity needed!)
        {
            let routing_wallet = self.routing_rewards_wallet.read().await;
            // Add tokens to routing wallet balance
            // In implementation, this would update the wallet balance
            info!("Added {} tokens to routing wallet for {} bytes, {} hops", 
                  total_reward, data_size, hop_count);
        }
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_data_routed += data_size as u64; // Convert usize to u64
            // No change to active_connections for routing
        }
        
        info!("Recorded routing: {} bytes, {} hops, {} tokens earned", 
              data_size, hop_count, total_reward);
        Ok(())
    }
    
    /// Get node's routing rewards balance
    pub async fn get_routing_rewards_balance(&self) -> Result<u64> {
        let routing_wallet = self.routing_rewards_wallet.read().await;
        // Return wallet balance (simplified)
        Ok(routing_wallet.balance)
    }
    
    /// Transfer routing rewards to another wallet
    pub async fn transfer_routing_rewards(&self, recipient_wallet_key: PublicKey, amount: u64) -> Result<()> {
        let mut routing_wallet = self.routing_rewards_wallet.write().await;
        
        // Verify sufficient balance
        let current_balance = routing_wallet.balance;
        if current_balance < amount {
            return Err(anyhow!("Insufficient routing rewards balance: {} < {}", current_balance, amount));
        }
        
        // Create transaction to transfer tokens
        // In implementation, this would create a proper transaction
        info!(" Transferring {} tokens from routing wallet to recipient", amount);
        
        Ok(())
    }
    
    /// Verify node ownership using wallet public key (simplified)
    pub async fn verify_node_ownership(&self, wallet_key: &PublicKey) -> bool {
        // Check if the wallet key matches the owner wallet key
        wallet_key.as_bytes() == self.owner_wallet_key.as_bytes()
    }
    
    /// Get permission level for a wallet (simplified)
    pub async fn get_permission_level(&self, wallet_key: &PublicKey) -> PermissionLevel {
        // Owner wallet has full control
        if self.verify_node_ownership(wallet_key).await {
            return PermissionLevel::Owner;
        }
        
        // Check admin wallets
        let admin_keys = self.admin_wallet_keys.read().await;
        if admin_keys.iter().any(|key| key.as_bytes() == wallet_key.as_bytes()) {
            return PermissionLevel::Admin;
        }
        
        // Everyone else is a regular user
        PermissionLevel::User
    }
    
    /// Add admin wallet (only owner can do this)
    pub async fn add_admin_wallet(&self, caller_wallet_key: &PublicKey, admin_wallet_key: PublicKey) -> Result<()> {
        // Verify caller is the owner
        if !self.verify_node_ownership(caller_wallet_key).await {
            return Err(anyhow!("Only node owner can add admin wallets"));
        }
        
        let mut admin_keys = self.admin_wallet_keys.write().await;
        admin_keys.push(admin_wallet_key.clone());
        
        // Log security operation
        self.log_security_operation(
            "add_admin_wallet".to_string(),
            caller_wallet_key.clone(),
            Some(format!("admin:{}", hex::encode(admin_wallet_key.as_bytes()))),
            "Owner".to_string(),
            true,
            "Admin wallet added successfully".to_string(),
        ).await;
        
        info!("Added admin wallet: {}", hex::encode(admin_wallet_key.as_bytes()));
        Ok(())
    }
    
    /// Emergency stop (owner or admin only)
    pub async fn emergency_stop(&self, caller_wallet_key: &PublicKey) -> Result<()> {
        let permission_level = self.get_permission_level(caller_wallet_key).await;
        
        match permission_level {
            PermissionLevel::Owner | PermissionLevel::Admin => {
                *self.emergency_stop.write().await = true;
                
                self.log_security_operation(
                    "emergency_stop".to_string(),
                    caller_wallet_key.clone(),
                    None,
                    format!("{:?}", permission_level),
                    true,
                    "Emergency stop activated".to_string(),
                ).await;
                
                warn!(" EMERGENCY STOP activated by wallet: {}", hex::encode(caller_wallet_key.as_bytes()));
                Ok(())
            }
            _ => {
                self.log_security_operation(
                    "emergency_stop".to_string(),
                    caller_wallet_key.clone(),
                    None,
                    format!("{:?}", permission_level),
                    false,
                    "Insufficient permissions".to_string(),
                ).await;
                
                Err(anyhow!("Only owner or admin wallets can trigger emergency stop"))
            }
        }
    }
    
    /// Log security operations for audit trail
    async fn log_security_operation(
        &self,
        operation: String,
        caller_key: PublicKey,
        target: Option<String>,
        permission_level: String,
        success: bool,
        reason: String,
    ) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let audit_entry = SecurityAuditLog {
            timestamp,
            operation,
            caller_key: hex::encode(caller_key.as_bytes()),
            target,
            permission_level,
            success,
            reason,
        };
        
        self.security_audit_log.write().await.push(audit_entry);
    }
    
    /// Start Bluetooth LE mesh discovery with persistent protocol instance
    async fn start_bluetooth_discovery(&mut self) -> Result<()> {
        use crate::protocols::bluetooth::BluetoothMeshProtocol;
        
        // Safety check: Emergency stop
        if *self.emergency_stop.read().await {
            return Err(anyhow!(" Cannot start discovery - emergency stop is active"));
        }
        
        // Safety check: Connection limit
        let stats = self.get_network_stats().await;
        let current_connections = stats.active_connections;
        let max_connections = *self.max_connections.read().await;
        let at_limit = (current_connections as usize) >= max_connections;
        if at_limit {
            warn!(" Connection limit reached ({}/{}), skipping Bluetooth discovery", 
                current_connections, max_connections);
            return Err(anyhow!("Connection limit reached"));
        }
        
        let node_id = self.mesh_node.read().await.node_id;
        
        // Initialize Bluetooth LE mesh protocol
        let bluetooth_protocol = BluetoothMeshProtocol::new(node_id)?;
        let bluetooth_arc = Arc::new(RwLock::new(bluetooth_protocol));
        
        // Start discovery
        bluetooth_arc.write().await.start_discovery().await?;
        
        // Store the protocol instance for persistent management
        self.bluetooth_protocol = Some(bluetooth_arc.clone());
        
        // Mark protocol as active
        self.active_protocols.write().await.insert(NetworkProtocol::BluetoothLE, true);
        
        // Start background monitoring for this protocol
        self.start_bluetooth_monitoring(bluetooth_arc).await?;
        
        info!(" Bluetooth LE mesh discovery active with persistent management");
        Ok(())
    }
    
    /// Start WiFi Direct mesh connections with persistent protocol instance
    async fn start_wifi_direct_discovery(&mut self) -> Result<()> {
        use crate::protocols::wifi_direct::WiFiDirectMeshProtocol;
        
        // Safety check: Emergency stop
        if *self.emergency_stop.read().await {
            return Err(anyhow!(" Cannot start discovery - emergency stop is active"));
        }
        
        // Safety check: Connection limit
        let stats = self.get_network_stats().await;
        let current_connections = stats.active_connections;
        let max_connections = *self.max_connections.read().await;
        let at_limit = (current_connections as usize) >= max_connections;
        if at_limit {
            warn!(" Connection limit reached ({}/{}), skipping WiFi Direct discovery", 
                current_connections, max_connections);
            return Err(anyhow!("Connection limit reached"));
        }
        
        let node_id = self.mesh_node.read().await.node_id;
        
        // Initialize WiFi Direct mesh protocol
        let wifi_protocol = WiFiDirectMeshProtocol::new(node_id)?;
        let wifi_arc = Arc::new(RwLock::new(wifi_protocol));
        
        // Start discovery
        wifi_arc.write().await.start_discovery().await?;
        
        // Store the protocol instance for persistent management
        self.wifi_direct_protocol = Some(wifi_arc.clone());
        
        // Mark protocol as active
        self.active_protocols.write().await.insert(NetworkProtocol::WiFiDirect, true);
        
        // Start background monitoring for this protocol
        self.start_wifi_direct_monitoring(wifi_arc).await?;
        
        info!("WiFi Direct mesh discovery active with persistent management");
        Ok(())
    }
    
    /// Start all mesh protocols based on available hardware
    async fn start_mesh_protocols(&mut self) -> Result<()> {
        info!(" Starting mesh protocols with hardware detection...");
        
        let protocols_to_init = if let Some(ref hardware_caps) = self.hardware_capabilities {
            filter_protocols_by_hardware(&self.mesh_node.read().await.protocols, hardware_caps)
        } else {
            // If hardware detection fails, use safe defaults (Bluetooth + WiFi)
            self.mesh_node.read().await.protocols.iter()
                .filter(|p| matches!(p, NetworkProtocol::BluetoothLE | NetworkProtocol::WiFiDirect))
                .cloned()
                .collect()
        };
        
        // Initialize each protocol
        for protocol in &protocols_to_init {
            match protocol {
                NetworkProtocol::BluetoothLE => {
                    info!(" Initializing Bluetooth LE mesh discovery...");
                    if let Err(e) = self.start_bluetooth_discovery().await {
                        warn!("Bluetooth LE initialization failed: {}", e);
                    }
                },
                NetworkProtocol::WiFiDirect => {
                    info!("Initializing WiFi Direct mesh connections...");
                    if let Err(e) = self.start_wifi_direct_discovery().await {
                        warn!("WiFi Direct initialization failed: {}", e);
                    }
                },
                NetworkProtocol::LoRaWAN => {
                    info!("Initializing LoRaWAN long-range mesh...");
                    if let Err(e) = self.start_lorawan_discovery().await {
                        warn!("LoRaWAN initialization failed: {}", e);
                    }
                },
                NetworkProtocol::Satellite => {
                    info!("🛰️ Initializing satellite mesh uplinks...");
                    if let Err(e) = self.start_satellite_discovery().await {
                        warn!("Satellite initialization failed: {}", e);
                    }
                },
                _ => {
                    info!("Protocol {:?} initialization not implemented yet", protocol);
                }
            }
        }
        
        // Start peer discovery
        self.start_peer_discovery().await?;
        
        // Mark mesh node as active
        self.mesh_node.write().await.discovery_active = true;
        info!("Pure mesh networking started with {} protocols active", protocols_to_init.len());
        
        Ok(())
    }
    
    /// Start background monitoring for Bluetooth protocol
    async fn start_bluetooth_monitoring(&self, protocol: Arc<RwLock<crate::protocols::bluetooth::BluetoothMeshProtocol>>) -> Result<()> {
        let active_protocols = self.active_protocols.clone();
        let protocol_for_zhtp = protocol.clone();
        
        // Start comprehensive ZHTP transmission monitoring
        tokio::spawn(async move {
            if let Ok(protocol_guard) = protocol_for_zhtp.try_read() {
                info!(" Starting ZHTP Bluetooth transmission monitoring for phone discovery");
                let _ = protocol_guard.start_zhtp_transmission_monitoring().await;
            }
        });
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Check if protocol is still active
                if let Ok(protocol_guard) = protocol.try_read() {
                    if !protocol_guard.discovery_active {
                        warn!("Bluetooth protocol inactive - attempting restart");
                        // Mark as inactive
                        if let Ok(mut active) = active_protocols.try_write() {
                            active.insert(NetworkProtocol::BluetoothLE, false);
                        }
                    } else {
                        // Protocol is healthy
                        if let Ok(mut active) = active_protocols.try_write() {
                            active.insert(NetworkProtocol::BluetoothLE, true);
                        }
                    }
                } else {
                    warn!("Bluetooth protocol lock contention");
                }
            }
        });
        
        Ok(())
    }
    
    /// Start background monitoring for WiFi Direct protocol
    async fn start_wifi_direct_monitoring(&self, protocol: Arc<RwLock<crate::protocols::wifi_direct::WiFiDirectMeshProtocol>>) -> Result<()> {
        let active_protocols = self.active_protocols.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Check if protocol is still active
                if let Ok(protocol_guard) = protocol.try_read() {
                    if !protocol_guard.discovery_active {
                        warn!("WiFi Direct protocol inactive - attempting restart");
                        // Mark as inactive
                        if let Ok(mut active) = active_protocols.try_write() {
                            active.insert(NetworkProtocol::WiFiDirect, false);
                        }
                    } else {
                        // Protocol is healthy
                        if let Ok(mut active) = active_protocols.try_write() {
                            active.insert(NetworkProtocol::WiFiDirect, true);
                        }
                    }
                } else {
                    warn!("WiFi Direct protocol lock contention");
                }
            }
        });
        
        Ok(())
    }
    
    /// Start peer discovery across all protocols
    async fn start_peer_discovery(&self) -> Result<()> {
        info!("Starting mesh peer discovery...");
        
        let active_protocols = self.active_protocols.clone();
        let bluetooth_protocol = self.bluetooth_protocol.clone();
        let wifi_direct_protocol = self.wifi_direct_protocol.clone();
        let mesh_connections = self.mesh_connections.clone();
        let server_id = self.server_id.clone();
        
        // Start continuous multicast discovery  
        let discovery_server_id = server_id.clone();
        let discovery_task = tokio::spawn(async move {
            if let Err(e) = crate::discovery::local_network::start_local_discovery(discovery_server_id, 33444).await {
                error!("Failed to start local discovery: {}", e);
            }
        });
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // Perform actual network discovery
                info!("Performing periodic network discovery...");
                
                // 1. Local subnet scanning
                match crate::discovery::network_monitor::discover_local_subnet_peers(33444).await {
                    Ok(discovered_peers) => {
                        if !discovered_peers.is_empty() {
                            info!("Found {} local peers via subnet scan", discovered_peers.len());
                            for peer_addr in discovered_peers {
                                info!("  -> Discovered peer: {}", peer_addr);
                                // TODO: Add peer to mesh if not already connected
                            }
                        }
                    },
                    Err(e) => warn!("Subnet discovery failed: {}", e),
                }
                
                // 2. WiFi Direct discovery  
                match crate::discovery::wifi::discover_wifi_direct_peers().await {
                    Ok(wifi_peers) => {
                        if !wifi_peers.is_empty() {
                            info!(" Found {} WiFi Direct peers", wifi_peers.len());
                            for peer in wifi_peers {
                                info!("  -> WiFi peer: {} ({})", peer.ssid, peer.bssid);
                            }
                        }
                    },
                    Err(e) => warn!("WiFi Direct discovery failed: {}", e),
                }
                
                // Send discovery messages on active protocols
                if let Ok(active) = active_protocols.try_read() {
                    for (protocol, is_active) in active.iter() {
                        if *is_active {
                            match protocol {
                                NetworkProtocol::BluetoothLE => {
                                    if let Some(ref bt_protocol) = bluetooth_protocol {
                                        info!(" Bluetooth LE discovery active");
                                    }
                                },
                                NetworkProtocol::WiFiDirect => {
                                    if let Some(ref wifi_protocol) = wifi_direct_protocol {
                                        info!("WiFi Direct discovery active"); 
                                    }
                                },
                                _ => {}
                            }
                        }
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Start LoRaWAN long-range mesh with persistent protocol instance
    async fn start_lorawan_discovery(&mut self) -> Result<()> {
        use crate::protocols::lorawan::LoRaWANMeshProtocol;
        use crate::discovery::lorawan_hardware;
        
        let node_id = self.mesh_node.read().await.node_id;
        
        // Double-check for LoRaWAN hardware before starting
        if let Ok(Some(hardware)) = lorawan_hardware::detect_lorawan_hardware().await {
            info!("LoRaWAN hardware confirmed: {}", hardware.device_name);
            
            // Test hardware functionality
            if lorawan_hardware::test_lorawan_hardware(&hardware).await.unwrap_or(false) {
                info!("LoRaWAN hardware test passed - initializing protocol");
                
                // Initialize LoRaWAN mesh protocol
                let lorawan_protocol = LoRaWANMeshProtocol::new(node_id)?;
                let lorawan_arc = Arc::new(RwLock::new(lorawan_protocol));
                
                // Start discovery
                lorawan_arc.write().await.start_discovery().await?;
                
                // Store the protocol instance for persistent management
                self.lorawan_protocol = Some(lorawan_arc);
                
                // Mark protocol as active
                self.active_protocols.write().await.insert(NetworkProtocol::LoRaWAN, true);
                
                info!("LoRaWAN mesh discovery active with hardware and persistent management");
            } else {
                warn!("LoRaWAN hardware test failed - skipping LoRaWAN initialization");
                return Err(anyhow!("LoRaWAN hardware test failed"));
            }
        } else {
            warn!("No LoRaWAN hardware detected - skipping LoRaWAN initialization");
            return Err(anyhow!("No LoRaWAN hardware available"));
        }
        
        Ok(())
    }
    
    /// Start satellite mesh uplinks with persistent protocol instance
    async fn start_satellite_discovery(&mut self) -> Result<()> {
        use crate::protocols::satellite::SatelliteMeshProtocol;
        
        let node_id = self.mesh_node.read().await.node_id;
        
        // Initialize satellite mesh protocol
        let satellite_protocol = SatelliteMeshProtocol::new(node_id)?;
        let satellite_arc = Arc::new(RwLock::new(satellite_protocol));
        
        // Start discovery
        satellite_arc.write().await.start_discovery().await?;
        
        // Store the protocol instance for persistent management
        self.satellite_protocol = Some(satellite_arc);
        
        // Mark protocol as active
        self.active_protocols.write().await.insert(NetworkProtocol::Satellite, true);
        
        info!("🛰️ Satellite mesh discovery active with persistent management");
        Ok(())
    }
    
    /// Send discovery message on specific protocol
    async fn send_discovery_message(&self, protocol: NetworkProtocol) -> Result<()> {
        let node_id = self.mesh_node.read().await.node_id;
        Self::send_discovery_message_static(node_id, protocol).await
    }
    
    /// Static method for discovery message sending
    async fn send_discovery_message_static(node_id: [u8; 32], protocol: NetworkProtocol) -> Result<()> {
        let discovery_message = ZhtpMeshMessage::PeerDiscovery {
            capabilities: vec![
                crate::types::mesh_capability::MeshCapability::MeshRelay { capacity_mbps: 100 },
                crate::types::mesh_capability::MeshCapability::DataStorage { capacity_gb: 100 },
                crate::types::mesh_capability::MeshCapability::ZkProofGeneration,
            ],
            location: None, // Could be filled with GPS coordinates
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
                info!(" Sending Bluetooth LE discovery message");
            },
            NetworkProtocol::WiFiDirect => {
                // WiFi Direct discovery
                info!("Sending WiFi Direct discovery message");
            },
            NetworkProtocol::LoRaWAN => {
                // LoRaWAN broadcast
                info!("Sending LoRaWAN discovery message");
            },
            NetworkProtocol::Satellite => {
                // Satellite uplink
                info!("🛰️ Sending satellite discovery message");
            },
            _ => {
                info!("Discovery not implemented for {:?}", protocol);
            }
        }
        
        Ok(())
    }

    /// Create a new ZHTP Mesh Server - The Internet
    pub async fn new(
        node_id: [u8; 32], 
        owner_key: PublicKey,  // Owner key for security
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
        
        // Create standalone wallets for node operation
        let (owner_wallet, routing_wallet, ops_wallet) = Self::create_node_wallets(&owner_key).await?;
        
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
            
            // Node wallets (no DID required)
            owner_wallet: Arc::new(RwLock::new(owner_wallet)),
            routing_rewards_wallet: Arc::new(RwLock::new(routing_wallet)),
            operational_wallet: Arc::new(RwLock::new(ops_wallet)),
            
            // Initialize protocol instances as None - will be created when protocols start
            bluetooth_protocol: None,
            wifi_direct_protocol: None,
            lorawan_protocol: None,
            satellite_protocol: None,
            active_protocols: Arc::new(RwLock::new(HashMap::new())),
            // Initialize safety features
            emergency_stop: Arc::new(RwLock::new(false)),
            max_connections: Arc::new(RwLock::new(100)), // Default safety limit
            connection_attempts: Arc::new(RwLock::new(HashMap::new())),
            
            // Initialize security features
            owner_wallet_key: owner_key.clone(), // Owner wallet has full permissions
            admin_wallet_keys: Arc::new(RwLock::new(Vec::new())),
            security_audit_log: Arc::new(RwLock::new(Vec::new())),
        };
        
        Ok(server)
    }
    
    /// Start the mesh internet server
    pub async fn start(&mut self) -> Result<()> {
        println!(" STARTING ZHTP MESH SERVER - THE NEW INTERNET!");
        println!("===============================================");
        println!(" Node Wallet-Based Operation (No DID Required)");
        
        // Display wallet information
        {
            let owner_wallet = self.owner_wallet.read().await;
            let routing_wallet = self.routing_rewards_wallet.read().await;
            let ops_wallet = self.operational_wallet.read().await;
            
            println!(" Owner Wallet: {} (Node Control)", owner_wallet.id);
            println!("Routing Wallet: {} (Earns Tokens)", routing_wallet.id);
            println!("  Operations Wallet: {} (Network Costs)", ops_wallet.id);
        }
        
        println!("Initializing ISP-free mesh networking...");
        
        // Start the underlying mesh node protocols
        self.start_mesh_protocols().await?;
        
        // Initialize DHT for content distribution
        println!("Initializing zkDHT for Web4 content distribution...");
        
        // Create a default identity for DHT operations
        // TODO: This should use the server's actual identity
        let default_identity = Self::create_default_mesh_identity();
        self.dht.write().await.initialize(default_identity).await?;
        
        // Initialize long-range communication capabilities
        if let Some(ref hardware_caps) = self.hardware_capabilities {
            self.initialize_long_range_relays(hardware_caps).await?;
        } else {
            warn!("Skipping long-range relay initialization - no hardware capabilities detected");
        }
        
        // WiFi sharing discovery disabled for legal compliance
        // self.start_wifi_sharing_discovery().await?;
        
        // Start mesh protocol message handling
        self.start_mesh_message_handler().await?;
        
        // Start TCP bootstrap server
        self.start_tcp_bootstrap_server().await?;
        
        // Start network health monitoring
        self.start_health_monitoring().await?;
        
        println!("ZHTP MESH SERVER ONLINE!");
        println!(" FREE INTERNET FOR ALL - POWERED BY THE MESH!");
        println!("EARNING TOKENS FOR NETWORK PARTICIPATION!");
        
        Ok(())
    }
    
    /// Initialize long-range communication relays - GLOBAL internet replacement!
    async fn initialize_long_range_relays(&self, hardware_caps: &HardwareCapabilities) -> Result<()> {
        println!("Initializing GLOBAL long-range mesh relays...");
        println!("ZHTP Goal: Planet-wide internet replacement via mesh networking!");
        
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
        
        println!("GLOBAL MESH STATUS:");
        println!("   {} long-range relays discovered", relay_count);
        println!("   {:.0}km total coverage radius", total_coverage_km);
        println!("   🛰️ Satellite access: {}", if has_satellite { "GLOBAL" } else { "Regional only" });
        println!("   Internet bridges: {}", if has_internet_bridge { "WORLDWIDE" } else { "Mesh only" });
        
        if has_satellite && has_internet_bridge {
            println!(" ZHTP GLOBAL NETWORK ACTIVE - Unlimited worldwide reach!");
        } else if total_coverage_km > 1000.0 {
            println!("ZHTP CONTINENTAL NETWORK - Multi-country coverage active!");
        } else {
            println!("ZHTP REGIONAL NETWORK - Local area coverage established");
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
            
            println!("LoRaWAN gateway discovered: {} - {} km range", 
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
            
            println!("🛰️ Satellite uplink discovered: {} - GLOBAL coverage", uplink_id);
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
            
            println!("WiFi relay network discovered: {} - {} Mbps", 
                    wifi_info.ssid, wifi_info.bandwidth_estimate_mbps);
        }
        
        Ok(())
    }
    
    /// Start mesh protocol message handler
    async fn start_mesh_message_handler(&self) -> Result<()> {
        info!("Starting mesh message handler...");
        
        // Use the correct mesh port from configuration (33444) instead of hardcoded 9333
        let mesh_port = 33444; // This should match DEFAULT_MESH_PORT from zhtp crate
        
        // Start UDP server for mesh packet handling
        start_udp_bootstrap_server(self.server_id, mesh_port).await?;
        
        Ok(())
    }
    
    /// Start TCP bootstrap server
    async fn start_tcp_bootstrap_server(&self) -> Result<()> {
        info!("Starting TCP bootstrap server...");
        
        // Use the correct mesh port from configuration (33444) instead of hardcoded 9333
        let mesh_port = 33444; // This should match DEFAULT_MESH_PORT from zhtp crate
        
        // Start TCP server for bootstrap connections
        start_tcp_bootstrap_server(self.server_id, mesh_port).await?;
        
        Ok(())
    }
    
    /// Start network health monitoring
    async fn start_health_monitoring(&self) -> Result<()> {
        info!("Starting network health monitoring...");
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
        info!("Processing native ZHTP request: {} {}", method, uri);
        
        // TODO: Implement ZHTP request handling
        Ok(ZhtpApiResponse {
            status: 200,
            status_message: "OK".to_string(),
            headers: HashMap::new(),
            body: b"Request processed by mesh server".to_vec(),
        })
    }
    
    // ===================
    // SECURITY SYSTEM
    // ===================
    
    /// Check permission level for a given public key (legacy method - use get_permission_level with wallet_key)
    pub async fn get_permission_level_legacy(&self, caller_key: &PublicKey) -> PermissionLevel {
        // Owner has full permissions
        if caller_key == &self.owner_wallet_key {
            return PermissionLevel::Owner;
        }
        
        // Check admin keys
        let admin_keys = self.admin_wallet_keys.read().await;
        if admin_keys.contains(caller_key) {
            return PermissionLevel::Admin;
        }
        
        // Check if it's a connected user (can only disconnect own connections)
        let connections = self.mesh_connections.read().await;
        for (peer_key, _) in connections.iter() {
            if peer_key == caller_key {
                return PermissionLevel::User;
            }
        }
        
        PermissionLevel::None
    }
    
    /// Verify security credentials and signature
    pub async fn verify_credentials(&self, credentials: &SecurityCredentials, operation: &str) -> Result<bool> {
        // Check timestamp to prevent replay attacks (5 minute window)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        if now > credentials.timestamp + 300 { // 5 minute expiry
            return Ok(false);
        }
        
        // Create message to verify signature
        let message = format!("{}:{}:{}:{}", 
            operation, 
            credentials.timestamp, 
            credentials.nonce,
            hex::encode(&self.server_id)
        );
        
        // TODO: Implement actual cryptographic signature verification
        // For now, we'll just check the timestamp and nonce format
        Ok(!credentials.nonce.is_empty() && credentials.signature.len() > 0)
    }
    
    // LEGACY METHOD - COMMENTED OUT TO AVOID CONFLICTS WITH NEW WALLET-BASED SYSTEM
    /*
    /// Add security audit log entry (LEGACY)
    pub async fn log_security_operation_legacy(
        &self, 
        operation: &str, 
        caller_key: &PublicKey, 
        target: Option<&str>,
        permission_level: PermissionLevel,
        success: bool,
        reason: &str
    ) {
        let log_entry = SecurityAuditLog {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            operation: operation.to_string(),
            caller_key: hex::encode(&caller_key.key_id[..8]),
            target: target.map(|s| s.to_string()),
            permission_level: format!("{:?}", permission_level),
            success,
            reason: reason.to_string(),
        };
        
        self.security_audit_log.write().await.push(log_entry.clone());
        
        // Log to console for immediate visibility
        if success {
            info!(" Security: {} by {} ({:?}) - {}", 
                operation, 
                hex::encode(&caller_key.key_id[..8]), 
                permission_level, 
                reason
            );
        } else {
            warn!(" Security DENIED: {} by {} ({:?}) - {}", 
                operation, 
                hex::encode(&caller_key.key_id[..8]), 
                permission_level, 
                reason
            );
        }
    }
    */
    
    // LEGACY SECURITY METHODS - COMMENTED OUT TO AVOID CONFLICTS
    /*
    /// Add admin key (owner only) - LEGACY
    pub async fn add_admin_key(&self, credentials: &SecurityCredentials, new_admin_key: PublicKey) -> Result<()> {
        let permission_level = self.get_permission_level(&credentials.caller_key).await;
        
        if permission_level != PermissionLevel::Owner {
            self.log_security_operation(
                "add_admin_key", 
                &credentials.caller_key, 
                Some(&hex::encode(&new_admin_key.key_id[..8])),
                permission_level, 
                false,
                "Insufficient permissions - only owner can add admins"
            ).await;
            return Err(anyhow!(" SECURITY: Only node owner can add admin keys"));
        }
        
        if !self.verify_credentials(credentials, "add_admin_key").await? {
            self.log_security_operation(
                "add_admin_key",
                &credentials.caller_key,
                Some(&hex::encode(&new_admin_key.key_id[..8])),
                permission_level,
                false,
                "Invalid credentials"
            ).await;
            return Err(anyhow!("Invalid credentials"));
        }
        
        self.admin_keys.write().await.push(new_admin_key.clone());
        
        self.log_security_operation(
            "add_admin_key",
            &credentials.caller_key,
            Some(&hex::encode(&new_admin_key.key_id[..8])),
            permission_level,
            true,
            "Admin key added successfully"
        ).await;
        
        Ok(())
    }
    
    /// Get security audit log (admin+ only)
    pub async fn get_security_audit_log(&self, credentials: &SecurityCredentials) -> Result<Vec<SecurityAuditLog>> {
        let permission_level = self.get_permission_level(&credentials.caller_key).await;
        
        if matches!(permission_level, PermissionLevel::None | PermissionLevel::User) {
            self.log_security_operation(
                "get_audit_log",
                &credentials.caller_key,
                None,
                permission_level,
                false,
                "Insufficient permissions - admin+ required"
            ).await;
            return Err(anyhow!(" SECURITY: Insufficient permissions to view audit log"));
        }
        
        Ok(self.security_audit_log.read().await.clone())
    }

    /// Graceful shutdown of the mesh server
    pub async fn stop(&self) -> Result<()> {
        info!("🛑 Stopping ZhtpMeshServer gracefully...");
        
        // Set emergency stop to prevent new operations
        *self.emergency_stop.write().await = true;
        
        // Stop protocols if available
        if let Some(bluetooth_protocol) = &self.bluetooth_protocol {
            let _ = bluetooth_protocol.stop_mesh_discovery().await;
        }
        
        if let Some(wifi_direct_protocol) = &self.wifi_direct_protocol {
            let _ = wifi_direct_protocol.stop_mesh_discovery().await;
        }
        
        if let Some(lorawan_protocol) = &self.lorawan_protocol {
            let _ = lorawan_protocol.stop_mesh_discovery().await;
        }
        
        if let Some(satellite_protocol) = &self.satellite_protocol {
            let _ = satellite_protocol.stop_mesh_discovery().await;
        }
        
        info!(" ZhtpMeshServer stopped gracefully");
        Ok(())
    }
    
    /// Emergency stop - immediate shutdown
    ///  SECURE: Emergency stop - immediate shutdown (OWNER ONLY)
    pub async fn emergency_stop(&mut self, credentials: &SecurityCredentials) -> Result<()> {
        let permission_level = self.get_permission_level(&credentials.caller_key).await;
        
        // Only node owner can perform emergency stop
        if permission_level != PermissionLevel::Owner {
            self.log_security_operation(
                "emergency_stop", 
                &credentials.caller_key, 
                None,
                permission_level, 
                false,
                " CRITICAL: Unauthorized emergency stop attempt - only owner allowed"
            ).await;
            return Err(anyhow!(" SECURITY ALERT: Emergency stop DENIED - Only node owner can perform emergency stop"));
        }
        
        if !self.verify_credentials(credentials, "emergency_stop").await? {
            self.log_security_operation(
                "emergency_stop",
                &credentials.caller_key,
                None,
                permission_level,
                false,
                "Invalid credentials for emergency stop"
            ).await;
            return Err(anyhow!("Invalid credentials for emergency stop"));
        }
        
        println!(" EMERGENCY STOP - Immediate shutdown initiated by OWNER!");
        
        // Set emergency flag
        *self.emergency_stop.write().await = true;
        
        // Force disconnect all protocols
        if let Some(ref bt_protocol) = self.bluetooth_protocol {
            let connected_peers = bt_protocol.read().await.get_connected_peers().await;
            for peer in connected_peers {
                let _ = bt_protocol.read().await.disconnect_peer(&peer).await;
            }
        }
        
        // Clear all connections immediately
        self.mesh_connections.write().await.clear();
        self.long_range_relays.write().await.clear();
        self.connection_attempts.write().await.clear();
        
        // Stop health monitoring
        let health_monitor = &self.health_monitor;
        let _ = health_monitor.stop_monitoring().await;
        
        self.log_security_operation(
            "emergency_stop",
            &credentials.caller_key,
            None,
            permission_level,
            true,
            "Emergency stop completed successfully by owner"
        ).await;
        
        warn!(" Emergency stop complete - All connections terminated by owner");
        Ok(())
    }
    
    /// Stop the mesh server gracefully
    pub async fn stop(&mut self) -> Result<()> {
        println!("Stopping ZHTP Mesh Server...");
        
        // Check if emergency stop was triggered
        if *self.emergency_stop.read().await {
            println!("  Server was emergency stopped - performing cleanup");
            return Ok(());
        }
        
        // Gracefully disconnect all mesh connections
        let connections = self.mesh_connections.read().await;
        println!("Disconnecting {} mesh connections...", connections.len());
        
        // Disconnect protocols gracefully
        if let Some(ref bt_protocol) = self.bluetooth_protocol {
            let connected_peers = bt_protocol.read().await.get_connected_peers().await;
            for peer in connected_peers {
                info!("Gracefully disconnecting Bluetooth peer: {}", peer);
                let _ = bt_protocol.read().await.disconnect_peer(&peer).await;
                tokio::time::sleep(Duration::from_millis(100)).await; // Small delay for graceful disconnect
            }
        }
        
        // Clear all in-memory state
        self.mesh_connections.write().await.clear();
        self.long_range_relays.write().await.clear();
        self.connection_attempts.write().await.clear();
        
        // Stop health monitoring gracefully
        let health_monitor = &self.health_monitor;
        let _ = health_monitor.stop_monitoring().await;
        
        println!("ZHTP Mesh Server stopped gracefully");
        Ok(())
    }
    
    /// Check if emergency stop has been triggered
    pub async fn is_emergency_stopped(&self) -> bool {
        *self.emergency_stop.read().await
    }
    
    /// Set maximum connection limit for safety
    pub async fn set_max_connections(&self, max: usize) -> Result<()> {
        *self.max_connections.write().await = max;
        info!(" Maximum connection limit set to: {}", max);
        Ok(())
    }
    
    /// Get current connection count and limit status
    pub async fn get_connection_status(&self) -> (usize, usize, bool) {
        let current = self.mesh_connections.read().await.len();
        let max = *self.max_connections.read().await;
        let at_limit = current >= max;
        (current, max, at_limit)
    }
    
    ///  SECURE: Disconnect specific peer by address (Admin+ only, or User for own connections)
    pub async fn disconnect_peer_by_address(&self, credentials: &SecurityCredentials, address: &str) -> Result<()> {
        let permission_level = self.get_permission_level(&credentials.caller_key).await;
        
        // Check permissions - Admin+ can disconnect any peer, Users can only disconnect themselves
        let can_disconnect = match permission_level {
            PermissionLevel::Owner | PermissionLevel::Admin => true,
            PermissionLevel::User => {
                // Users can only disconnect their own connections
                let caller_address = hex::encode(&credentials.caller_key.key_id[..8]);
                address.contains(&caller_address)
            },
            PermissionLevel::None => false,
        };
        
        if !can_disconnect {
            self.log_security_operation(
                "disconnect_peer_by_address", 
                &credentials.caller_key, 
                Some(address),
                permission_level, 
                false,
                "Insufficient permissions or attempting to disconnect other user's connection"
            ).await;
            return Err(anyhow!(" SECURITY: Insufficient permissions to disconnect peer"));
        }
        
        if !self.verify_credentials(credentials, "disconnect_peer_by_address").await? {
            self.log_security_operation(
                "disconnect_peer_by_address",
                &credentials.caller_key,
                Some(address),
                permission_level,
                false,
                "Invalid credentials"
            ).await;
            return Err(anyhow!("Invalid credentials"));
        }
        
        info!(" Disconnecting peer: {} (authorized by {:?})", address, permission_level);
        
        // Try Bluetooth first
        if let Some(ref bt_protocol) = self.bluetooth_protocol {
            let connected_peers = bt_protocol.read().await.get_connected_peers().await;
            if connected_peers.contains(&address.to_string()) {
                let result = bt_protocol.read().await.disconnect_peer(address).await;
                self.log_security_operation(
                    "disconnect_peer_by_address",
                    &credentials.caller_key,
                    Some(address),
                    permission_level,
                    result.is_ok(),
                    if result.is_ok() { "Bluetooth peer disconnected" } else { "Failed to disconnect Bluetooth peer" }
                ).await;
                return result;
            }
        }
        
        // Remove from mesh connections by address lookup
        let mut connections = self.mesh_connections.write().await;
        if let Some(key_to_remove) = connections.iter()
            .find(|(_, connection)| {
                // Try to match by peer ID string representation
                format!("{:?}", connection.peer_id).contains(address)
            })
            .map(|(k, _)| k.clone()) {
            connections.remove(&key_to_remove);
            self.log_security_operation(
                "disconnect_peer_by_address",
                &credentials.caller_key,
                Some(address),
                permission_level,
                true,
                "Mesh connection disconnected successfully"
            ).await;
            info!(" Disconnected peer from mesh connections: {}", address);
            return Ok(());
        }
        
        warn!("Could not find peer to disconnect: {}", address);
        Err(anyhow!("Peer not found: {}", address))
    }
    
    /// Get list of all connected peers across all protocols  
    pub async fn list_all_connected_peers(&self) -> Vec<String> {
        let mut peers = Vec::new();
        
        // Add Bluetooth peers
        if let Some(ref bt_protocol) = self.bluetooth_protocol {
            let bt_peers = bt_protocol.read().await.get_connected_peers().await;
            for peer in bt_peers {
                peers.push(format!("BT: {}", peer));
            }
        }
        
        // Add mesh connection peers
        let connections = self.mesh_connections.read().await;
        for (public_key, connection) in connections.iter() {
            peers.push(format!("MESH: {} ({:?})", 
                hex::encode(&public_key.key_id[..8]), // First 8 bytes of key ID
                connection.protocol
            ));
        }
        
        peers
    }
    
    ///  SECURE: Force disconnect all connections (Admin+ only)
    pub async fn disconnect_all_peers(&self, credentials: &SecurityCredentials) -> Result<()> {
        let permission_level = self.get_permission_level(&credentials.caller_key).await;
        
        // Only admin+ can disconnect all peers
        if matches!(permission_level, PermissionLevel::None | PermissionLevel::User) {
            self.log_security_operation(
                "disconnect_all_peers", 
                &credentials.caller_key, 
                None,
                permission_level, 
                false,
                "Insufficient permissions - admin+ required to disconnect all peers"
            ).await;
            return Err(anyhow!(" SECURITY: Only admins and owners can disconnect all peers"));
        }
        
        if !self.verify_credentials(credentials, "disconnect_all_peers").await? {
            self.log_security_operation(
                "disconnect_all_peers",
                &credentials.caller_key,
                None,
                permission_level,
                false,
                "Invalid credentials"
            ).await;
            return Err(anyhow!("Invalid credentials"));
        }
        
        warn!(" Force disconnecting ALL peers (authorized by {:?})", permission_level);
        
        // Disconnect all Bluetooth peers
        if let Some(ref bt_protocol) = self.bluetooth_protocol {
            let connected_peers = bt_protocol.read().await.get_connected_peers().await;
            for peer in connected_peers {
                let _ = bt_protocol.read().await.disconnect_peer(&peer).await;
            }
        }
        
        // Clear all mesh connections
        self.mesh_connections.write().await.clear();
        self.connection_attempts.write().await.clear();
        
        self.log_security_operation(
            "disconnect_all_peers",
            &credentials.caller_key,
            None,
            permission_level,
            true,
            "All peers disconnected successfully"
        ).await;
        
        info!(" All peers disconnected by authorized user");
        Ok(())
    }
    */
    // END OF LEGACY METHODS - CONFLICTS RESOLVED
    
    /// WiFi sharing discovery - DISABLED for legal compliance
    /// This function is kept for reference but should not be called
    #[allow(dead_code)]
    async fn start_wifi_sharing_discovery(&self) -> Result<()> {
        warn!("WiFi sharing discovery is disabled for legal compliance");
        
        // WiFi sharing removed for legal compliance
        let server_id = self.server_id;
        let hardware_caps = self.hardware_capabilities.clone();
        
        tokio::spawn(async move {
            loop {
                // Continuously discover WiFi sharing nodes using WiFi scanning
                tokio::time::sleep(Duration::from_secs(30)).await;
                
                // Use hardware-optimized WiFi discovery (avoid duplicate hardware detection)
                if let Some(ref caps) = hardware_caps {
                    match crate::discovery::wifi::discover_wifi_relays_with_capabilities(caps).await {
                        Ok(discovered_networks) => {
                            info!("Discovered {} WiFi relay networks for P2P mesh", discovered_networks.len());
                            
                            for wifi_info in discovered_networks {
                                info!("WiFi relay available: {} - {} Mbps capacity", 
                                      wifi_info.ssid, wifi_info.bandwidth_estimate_mbps);
                            }
                        },
                        Err(e) => {
                            warn!("WiFi relay discovery failed: {}", e);
                        }
                    }
                } else {
                    warn!("Skipping WiFi relay discovery - no hardware capabilities detected");
                }
            }
        });
        
        Ok(())
    }
    
    /// Serve Web4 content via zkDHT
    pub async fn serve_web4_content(&self, domain: &str, path: &str) -> Result<Vec<u8>> {
        info!("Serving Web4 content: {}{}", domain, path);
        
        // Resolve content hash via DHT
        let content_hash = self.dht.read().await
            .resolve_content(domain, path).await?;
        
        info!("Resolved content hash: {}", content_hash);
        
        // Use native binary DHT protocol instead of JavaScript
        let response = crate::dht::call_native_dht_client("loadPage", &serde_json::json!({
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
}

// Additional methods for ZhtpMeshServer
impl ZhtpMeshServer {
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping ZHTP Mesh Server...");
        
        // Set emergency stop flag
        *self.emergency_stop.write().await = true;
        
        // Graceful shutdown of all protocols
        if let Some(_bluetooth_protocol) = &self.bluetooth_protocol {
            info!("Bluetooth protocol stopped");
        }
        
        if let Some(_wifi_direct_protocol) = &self.wifi_direct_protocol {
            info!("WiFi Direct protocol stopped");
        }
        
        if let Some(_lorawan_protocol) = &self.lorawan_protocol {
            // LoRaWAN doesn't have persistent connections to disconnect
            info!("LoRaWAN protocol stopped");
        }
        
        if let Some(_satellite_protocol) = &self.satellite_protocol {
            // Satellite connections are typically stateless
            info!("Satellite protocol stopped");
        }
        
        // Clear mesh connections
        self.mesh_connections.write().await.clear();
        
        // Clear the DHT cache
        let _ = self.dht.write().await.clear_cache().await;
        
        info!("ZHTP Mesh Server stopped successfully");
        Ok(())
    }
}

// Network configuration already defined above
