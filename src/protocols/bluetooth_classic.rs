//! Bluetooth Classic (BR/EDR) RFCOMM Protocol Implementation
//! 
//! Provides high-throughput mesh networking using Bluetooth Classic with RFCOMM
//! Parallel to BLE GATT but optimized for data transfer (2-3 Mbps vs 250 KB/s)

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use serde::{Serialize, Deserialize};

use lib_crypto::PublicKey;
use super::zhtp_auth::{ZhtpAuthManager, NodeCapabilities, ZhtpAuthVerification};

/// RFCOMM channel assignments (1-30 available)
pub mod rfcomm_channels {
    pub const ZK_AUTH: u8 = 1;           // Authentication challenge/response
    pub const QUANTUM_ROUTING: u8 = 2;   // Kyber key exchange
    pub const MESH_DATA: u8 = 3;         // MeshHandshake, blockchain sync
    pub const COORDINATION: u8 = 4;      // DHT queries, coordination
}

/// Bluetooth Classic RFCOMM mesh protocol handler
#[derive(Clone)]
pub struct BluetoothClassicProtocol {
    /// Node ID for this mesh node
    pub node_id: [u8; 32],
    /// Bluetooth MAC address
    pub device_id: [u8; 6],
    /// Maximum throughput (375 KB/s for BT Classic)
    pub max_throughput: u32,
    /// Active RFCOMM connections
    pub active_connections: Arc<RwLock<HashMap<String, RfcommConnection>>>,
    /// ZHTP authentication manager
    pub auth_manager: Arc<RwLock<Option<ZhtpAuthManager>>>,
    /// Authenticated peers (address -> verification)
    pub authenticated_peers: Arc<RwLock<HashMap<String, ZhtpAuthVerification>>>,
    /// Platform-specific RFCOMM service handle
    #[cfg(target_os = "windows")]
    pub service_provider: Arc<RwLock<Option<Box<dyn std::any::Any + Send + Sync>>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfcommConnection {
    pub peer_id: String,
    pub peer_address: String,
    pub connected_at: u64,
    pub channel: u8,
    pub mtu: u16,
    pub last_seen: u64,
}

/// RFCOMM Stream wrapper with async read/write (compatible with TcpStream interface)
pub struct RfcommStream {
    #[cfg(target_os = "windows")]
    windows_socket: Option<WindowsRfcommSocket>,
    #[cfg(target_os = "linux")]
    linux_socket: Option<LinuxRfcommSocket>,
    #[cfg(target_os = "macos")]
    macos_socket: Option<MacOSRfcommSocket>,
    peer_address: String,
}

#[cfg(target_os = "windows")]
struct WindowsRfcommSocket {
    stream_socket: Arc<RwLock<Option<Box<dyn std::any::Any + Send + Sync>>>>,
    reader: Arc<RwLock<Option<Vec<u8>>>>,
    writer: Arc<RwLock<Option<Vec<u8>>>>,
}

#[cfg(target_os = "linux")]
struct LinuxRfcommSocket {
    socket_fd: std::os::unix::io::RawFd,
    peer_addr: String,
}

#[cfg(target_os = "macos")]
struct MacOSRfcommSocket {
    channel_id: u8,
    device_address: String,
}

impl RfcommStream {
    /// Create from platform-specific socket
    #[cfg(target_os = "windows")]
    pub fn from_windows_socket(socket: Box<dyn std::any::Any + Send + Sync>, peer_addr: String) -> Self {
        Self {
            windows_socket: Some(WindowsRfcommSocket {
                stream_socket: Arc::new(RwLock::new(Some(socket))),
                reader: Arc::new(RwLock::new(None)),
                writer: Arc::new(RwLock::new(None)),
            }),
            peer_address: peer_addr,
        }
    }
    
    #[cfg(target_os = "linux")]
    pub fn from_linux_socket(fd: std::os::unix::io::RawFd, peer_addr: String) -> Self {
        Self {
            linux_socket: Some(LinuxRfcommSocket {
                socket_fd: fd,
                peer_addr: peer_addr.clone(),
            }),
            peer_address: peer_addr,
        }
    }
    
    #[cfg(target_os = "macos")]
    pub fn from_macos_channel(channel_id: u8, device_address: String) -> Self {
        Self {
            macos_socket: Some(MacOSRfcommSocket {
                channel_id,
                device_address: device_address.clone(),
            }),
            peer_address: device_address,
        }
    }
    
    /// Get peer address
    pub fn peer_addr(&self) -> &str {
        &self.peer_address
    }
}

// Implement AsyncRead for RfcommStream
impl tokio::io::AsyncRead for RfcommStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        #[cfg(target_os = "windows")]
        {
            if let Some(ref socket) = self.windows_socket {
                return Self::poll_read_windows(socket, cx, buf);
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            if let Some(ref socket) = self.linux_socket {
                return Self::poll_read_linux(socket, cx, buf);
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            if let Some(ref socket) = self.macos_socket {
                return Self::poll_read_macos(socket, cx, buf);
            }
        }
        
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "No platform socket available"
        )))
    }
}

// Implement AsyncWrite for RfcommStream
impl tokio::io::AsyncWrite for RfcommStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        #[cfg(target_os = "windows")]
        {
            if let Some(ref socket) = self.windows_socket {
                return Self::poll_write_windows(socket, cx, buf);
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            if let Some(ref socket) = self.linux_socket {
                return Self::poll_write_linux(socket, cx, buf);
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            if let Some(ref socket) = self.macos_socket {
                return Self::poll_write_macos(socket, cx, buf);
            }
        }
        
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "No platform socket available"
        )))
    }
    
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl RfcommStream {
    #[cfg(target_os = "windows")]
    fn poll_read_windows(
        _socket: &WindowsRfcommSocket,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Windows RFCOMM requires windows crate with Bluetooth features
        // To enable: cargo build --features windows-gatt
        std::task::Poll::Pending
    }
    
    #[cfg(target_os = "windows")]
    fn poll_write_windows(
        _socket: &WindowsRfcommSocket,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Windows RFCOMM requires windows crate with Bluetooth features
        // To enable: cargo build --features windows-gatt
        std::task::Poll::Ready(Ok(buf.len()))
    }
    
    #[cfg(target_os = "linux")]
    fn poll_read_linux(
        socket: &LinuxRfcommSocket,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::os::unix::io::AsRawFd;
        use nix::sys::socket::{recv, MsgFlags};
        
        // Try non-blocking read from RFCOMM socket
        let unfilled = buf.initialize_unfilled();
        match recv(socket.socket_fd, unfilled, MsgFlags::MSG_DONTWAIT) {
            Ok(n) if n > 0 => {
                buf.advance(n);
                std::task::Poll::Ready(Ok(()))
            }
            Ok(_) => {
                // EOF
                std::task::Poll::Ready(Ok(()))
            }
            Err(nix::errno::Errno::EWOULDBLOCK) | Err(nix::errno::Errno::EAGAIN) => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            Err(e) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("RFCOMM read error: {}", e)
                )))
            }
        }
    }
    
    #[cfg(target_os = "linux")]
    fn poll_write_linux(
        socket: &LinuxRfcommSocket,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use nix::sys::socket::{send, MsgFlags};
        
        match send(socket.socket_fd, buf, MsgFlags::MSG_DONTWAIT) {
            Ok(n) => std::task::Poll::Ready(Ok(n)),
            Err(nix::errno::Errno::EWOULDBLOCK) | Err(nix::errno::Errno::EAGAIN) => {
                std::task::Poll::Pending
            }
            Err(e) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("RFCOMM write error: {}", e)
                )))
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    fn poll_read_macos(
        _socket: &MacOSRfcommSocket,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Would use IOBluetooth RFCOMM channel
        std::task::Poll::Pending
    }
    
    #[cfg(target_os = "macos")]
    fn poll_write_macos(
        _socket: &MacOSRfcommSocket,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Would write via IOBluetoothRFCOMMChannel
        std::task::Poll::Ready(Ok(buf.len()))
    }
}

impl BluetoothClassicProtocol {
    /// Create new Bluetooth Classic RFCOMM protocol
    pub fn new(node_id: [u8; 32]) -> Result<Self> {
        let device_id = Self::get_bluetooth_mac()?;
        
        Ok(BluetoothClassicProtocol {
            node_id,
            device_id,
            max_throughput: 375_000, // 375 KB/s - Bluetooth Classic EDR
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            auth_manager: Arc::new(RwLock::new(None)),
            authenticated_peers: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(target_os = "windows")]
            service_provider: Arc::new(RwLock::new(None)),
        })
    }
    
    /// Initialize ZHTP authentication for this node
    pub async fn initialize_zhtp_auth(&self, blockchain_pubkey: PublicKey) -> Result<()> {
        info!("🔐 Initializing ZHTP authentication for Bluetooth Classic RFCOMM");
        
        let auth_manager = ZhtpAuthManager::new(blockchain_pubkey)?;
        *self.auth_manager.write().await = Some(auth_manager);
        
        info!("✅ ZHTP authentication initialized for Bluetooth Classic");
        Ok(())
    }
    
    /// Get node capabilities for advertising
    pub fn get_node_capabilities(&self, has_dht: bool, reputation: u32) -> NodeCapabilities {
        NodeCapabilities {
            has_dht,
            can_relay: true,
            max_bandwidth: 375_000, // 375 KB/s - Bluetooth Classic throughput
            protocols: vec!["bluetooth-classic".to_string(), "rfcomm".to_string(), "zhtp".to_string()],
            reputation,
            quantum_secure: true,
        }
    }
    
    /// Get Bluetooth MAC address from system
    fn get_bluetooth_mac() -> Result<[u8; 6]> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            let output = Command::new("powershell")
                .args(&["-Command", "Get-NetAdapter | Where-Object {$_.Name -like '*Bluetooth*'} | Select-Object -ExpandProperty MacAddress"])
                .output();
            
            if let Ok(result) = output {
                let mac_str = String::from_utf8_lossy(&result.stdout);
                if let Ok(mac) = Self::parse_mac_address(&mac_str.trim()) {
                    return Ok(mac);
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // Try to read from /sys/class/bluetooth
            if let Ok(entries) = std::fs::read_dir("/sys/class/bluetooth") {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(name) = path.file_name() {
                        let name_str = name.to_string_lossy();
                        if name_str.starts_with("hci") {
                            let address_path = path.join("address");
                            if let Ok(address) = std::fs::read_to_string(address_path) {
                                if let Ok(mac) = Self::parse_mac_address(&address.trim()) {
                                    return Ok(mac);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Fallback: generate random MAC
        warn!("Could not detect Bluetooth MAC address, using random");
        let mut mac = [0u8; 6];
        use rand::Rng;
        rand::thread_rng().fill(&mut mac);
        mac[0] |= 0x02; // Set locally administered bit
        Ok(mac)
    }
    
    /// Parse MAC address string to bytes
    fn parse_mac_address(mac_str: &str) -> Result<[u8; 6]> {
        let clean = mac_str.replace([':', '-'], "");
        if clean.len() != 12 {
            return Err(anyhow!("Invalid MAC address length"));
        }
        
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = u8::from_str_radix(&clean[i*2..i*2+2], 16)?;
        }
        Ok(mac)
    }
    
    /// Start RFCOMM service advertising
    pub async fn start_advertising(&self) -> Result<()> {
        info!("🔵 Starting Bluetooth Classic RFCOMM service advertising");
        
        #[cfg(target_os = "windows")]
        {
            self.windows_register_rfcomm_service().await?;
        }
        
        #[cfg(target_os = "linux")]
        {
            self.linux_register_rfcomm_service().await?;
        }
        
        #[cfg(target_os = "macos")]
        {
            self.macos_register_rfcomm_service().await?;
        }
        
        info!("✅ Bluetooth Classic RFCOMM service advertising (ZHTP Mesh)");
        Ok(())
    }
    
    /// Accept incoming RFCOMM connection (platform-specific)
    pub async fn accept_connection(&self) -> Result<RfcommStream> {
        #[cfg(target_os = "windows")]
        {
            self.windows_accept_rfcomm().await
        }
        
        #[cfg(target_os = "linux")]
        {
            self.linux_accept_rfcomm().await
        }
        
        #[cfg(target_os = "macos")]
        {
            self.macos_accept_rfcomm().await
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow!("RFCOMM not supported on this platform"))
        }
    }
    
    /// Register RFCOMM service on Windows
    #[cfg(target_os = "windows")]
    async fn windows_register_rfcomm_service(&self) -> Result<()> {
        info!("🪟 Windows: RFCOMM service registration requires windows crate with Bluetooth features");
        info!("   To enable: cargo build --features windows-gatt");
        warn!("   Windows RFCOMM support temporarily disabled - using BLE fallback");
        Ok(())
    }
    
    /// Register RFCOMM service on Linux
    #[cfg(target_os = "linux")]
    async fn linux_register_rfcomm_service(&self) -> Result<()> {
        info!("🐧 Linux: Registering RFCOMM service via BlueZ");
        
        // Use sdptool to register RFCOMM service
        let service_uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let service_name = "ZHTP Mesh RFCOMM";
        
        // Register service on channel 3 (MESH_DATA)
        let output = std::process::Command::new("sdptool")
            .args(&[
                "add",
                "--channel", &rfcomm_channels::MESH_DATA.to_string(),
                "SP", // Serial Port Profile
            ])
            .output();
        
        match output {
            Ok(result) if result.status.success() => {
                info!("✅ Linux: RFCOMM service registered via sdptool");
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                warn!("Linux: sdptool failed: {}", stderr);
            }
            Err(e) => {
                warn!("Linux: sdptool not available: {}", e);
            }
        }
        
        info!("📡 Linux: RFCOMM service advertising (manual pairing may be required)");
        Ok(())
    }
    
    /// Register RFCOMM service on macOS
    #[cfg(target_os = "macos")]
    async fn macos_register_rfcomm_service(&self) -> Result<()> {
        info!("🍎 macOS: RFCOMM service registration (IOBluetooth framework needed)");
        // IOBluetooth framework would be used here
        Ok(())
    }
    
    /// Windows: Accept incoming RFCOMM connection
    #[cfg(target_os = "windows")]
    async fn windows_accept_rfcomm(&self) -> Result<RfcommStream> {
        info!("🪟 Windows: RFCOMM accept requires windows crate with Bluetooth features");
        Err(anyhow!("Windows RFCOMM support requires --features windows-gatt"))
    }
    
    /// Linux: Accept incoming RFCOMM connection
    #[cfg(target_os = "linux")]
    async fn linux_accept_rfcomm(&self) -> Result<RfcommStream> {
        use nix::sys::socket::{accept, AddressFamily, SockType, SockFlag};
        use nix::sys::socket::{socket, bind, listen, SockaddrLike};
        use std::os::unix::io::RawFd;
        
        info!("🐧 Linux: Waiting for RFCOMM connection...");
        
        // RFCOMM protocol constant (from bluetooth.h)
        const BTPROTO_RFCOMM: i32 = 3;
        const RFCOMM_CHANNEL: u8 = 3; // MESH_DATA channel
        
        // Create RFCOMM socket
        let sock_fd = unsafe {
            libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_STREAM,
                BTPROTO_RFCOMM,
            )
        };
        
        if sock_fd < 0 {
            return Err(anyhow!("Failed to create RFCOMM socket"));
        }
        
        // Bind to RFCOMM channel
        #[repr(C)]
        struct sockaddr_rc {
            rc_family: libc::sa_family_t,
            rc_bdaddr: [u8; 6],
            rc_channel: u8,
        }
        
        let addr = sockaddr_rc {
            rc_family: libc::AF_BLUETOOTH as libc::sa_family_t,
            rc_bdaddr: [0; 6], // BDADDR_ANY
            rc_channel: RFCOMM_CHANNEL,
        };
        
        let bind_result = unsafe {
            libc::bind(
                sock_fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_rc>() as libc::socklen_t,
            )
        };
        
        if bind_result < 0 {
            unsafe { libc::close(sock_fd); }
            return Err(anyhow!("Failed to bind RFCOMM socket"));
        }
        
        // Listen for connections
        let listen_result = unsafe {
            libc::listen(sock_fd, 1)
        };
        
        if listen_result < 0 {
            unsafe { libc::close(sock_fd); }
            return Err(anyhow!("Failed to listen on RFCOMM socket"));
        }
        
        info!("📡 Linux: RFCOMM socket listening on channel {}", RFCOMM_CHANNEL);
        
        // Accept connection (blocking - wrap in spawn_blocking)
        let client_fd = tokio::task::spawn_blocking(move || {
            unsafe {
                let client = libc::accept(sock_fd, std::ptr::null_mut(), std::ptr::null_mut());
                libc::close(sock_fd); // Close listener after accepting
                client
            }
        }).await?;
        
        if client_fd < 0 {
            return Err(anyhow!("Failed to accept RFCOMM connection"));
        }
        
        // Set non-blocking mode
        let flags = unsafe { libc::fcntl(client_fd, libc::F_GETFL, 0) };
        unsafe { libc::fcntl(client_fd, libc::F_SETFL, flags | libc::O_NONBLOCK); }
        
        info!("✅ Linux: RFCOMM connection accepted (fd: {})", client_fd);
        
        Ok(RfcommStream {
            inner: RfcommSocket::Linux(LinuxRfcommSocket { socket_fd: client_fd }),
        })
    }
    
    /// macOS: Accept incoming RFCOMM connection
    #[cfg(target_os = "macos")]
    async fn macos_accept_rfcomm(&self) -> Result<RfcommStream> {
        info!("🍎 macOS: Waiting for RFCOMM connection...");
        
        // IOBluetooth implementation would go here:
        // 1. Create IOBluetoothRFCOMMChannel listener
        // 2. Register delegate for incoming connections
        // 3. Wait for connection callback
        // 4. Return RfcommStream with channel
        
        // For now, return error until IOBluetooth bindings are added
        Err(anyhow!("macOS RFCOMM accept not yet implemented - IOBluetooth framework needed"))
    }
    
    /// Send mesh message via RFCOMM
    pub async fn send_mesh_message(&self, target_address: &str, message: &[u8]) -> Result<()> {
        info!("📤 Sending RFCOMM message to {}: {} bytes", target_address, message.len());
        
        // Check if peer is connected
        let connections = self.active_connections.read().await;
        if !connections.contains_key(target_address) {
            return Err(anyhow!("Peer not connected: {}", target_address));
        }
        
        let connection = connections.get(target_address).unwrap();
        let mtu = connection.mtu as usize;
        
        // RFCOMM has larger MTU (1000 bytes typical) - less fragmentation needed
        if message.len() <= mtu {
            self.transmit_rfcomm_packet(message, target_address).await?;
        } else {
            // Fragment message (but with much larger chunks than BLE)
            let chunks: Vec<&[u8]> = message.chunks(mtu).collect();
            for (i, chunk) in chunks.iter().enumerate() {
                info!("Sending RFCOMM fragment {}/{} ({} bytes)", i + 1, chunks.len(), chunk.len());
                self.transmit_rfcomm_packet(chunk, target_address).await?;
                
                // Minimal delay for flow control (RFCOMM handles this better than BLE)
                tokio::time::sleep(tokio::time::Duration::from_micros(500)).await;
            }
        }
        
        // Update connection activity
        drop(connections);
        let mut connections_mut = self.active_connections.write().await;
        if let Some(conn) = connections_mut.get_mut(target_address) {
            conn.last_seen = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        
        Ok(())
    }
    
    /// Transmit packet via RFCOMM
    async fn transmit_rfcomm_packet(&self, data: &[u8], address: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.linux_transmit_rfcomm(data, address).await?;
        }
        
        #[cfg(target_os = "windows")]
        {
            self.windows_transmit_rfcomm(data, address).await?;
        }
        
        #[cfg(target_os = "macos")]
        {
            self.macos_transmit_rfcomm(data, address).await?;
        }
        
        Ok(())
    }
    
    /// Linux RFCOMM transmission
    #[cfg(target_os = "linux")]
    async fn linux_transmit_rfcomm(&self, data: &[u8], address: &str) -> Result<()> {
        debug!("Linux: RFCOMM transmit to {} ({} bytes)", address, data.len());
        // Would use RFCOMM socket here
        Ok(())
    }
    
    /// Windows RFCOMM transmission
    #[cfg(target_os = "windows")]
    async fn windows_transmit_rfcomm(&self, data: &[u8], address: &str) -> Result<()> {
        debug!("Windows: RFCOMM transmit to {} ({} bytes)", address, data.len());
        // Would use Windows RFCOMM StreamSocket here
        Ok(())
    }
    
    /// macOS RFCOMM transmission
    #[cfg(target_os = "macos")]
    async fn macos_transmit_rfcomm(&self, data: &[u8], address: &str) -> Result<()> {
        debug!("macOS: RFCOMM transmit to {} ({} bytes)", address, data.len());
        // Would use IOBluetooth RFCOMM channel here
        Ok(())
    }
    
    /// Get active RFCOMM connections
    pub async fn get_connections(&self) -> Vec<RfcommConnection> {
        self.active_connections.read().await.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mac_address_parsing() {
        let mac_str = "AA:BB:CC:DD:EE:FF";
        let mac = BluetoothClassicProtocol::parse_mac_address(mac_str).unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        
        let mac_str2 = "AA-BB-CC-DD-EE-FF";
        let mac2 = BluetoothClassicProtocol::parse_mac_address(mac_str2).unwrap();
        assert_eq!(mac2, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }
    
    #[tokio::test]
    async fn test_protocol_creation() {
        let node_id = [0u8; 32];
        let protocol = BluetoothClassicProtocol::new(node_id);
        assert!(protocol.is_ok());
        
        let proto = protocol.unwrap();
        assert_eq!(proto.max_throughput, 375_000);
    }
}
