//! Edge Node Blockchain Synchronization
//!
//! Lightweight sync manager for bandwidth-constrained devices (BLE, LoRaWAN)
//! using EdgeNodeState from lib-blockchain with ZK bootstrap proofs.

use anyhow::{Result, anyhow};
use lib_blockchain::edge_node_state::{EdgeNodeState, SyncStrategy};
use lib_blockchain::{BlockHeader, TransactionOutput, Hash};
use lib_crypto::PublicKey;
use crate::types::mesh_message::{ZhtpMeshMessage, BlockchainRequestType};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

/// Edge node sync manager for BLE/LoRaWAN constrained devices
pub struct EdgeNodeSyncManager {
    /// Core edge node state (rolling header window + UTXOs)
    edge_state: Arc<RwLock<EdgeNodeState>>,
    /// Current network height (updated from peers)
    network_height: Arc<RwLock<u64>>,
    /// Node's own public keys for UTXO tracking
    my_addresses: Arc<RwLock<Vec<Vec<u8>>>>,
    /// Next request ID
    next_request_id: Arc<RwLock<u64>>,
}

impl EdgeNodeSyncManager {
    /// Create a new edge node sync manager
    /// 
    /// # Arguments
    /// * `max_headers` - Rolling window size (recommended: 500 for ~100KB storage)
    pub fn new(max_headers: usize) -> Self {
        info!("🔧 Initializing EdgeNodeSyncManager with {} header capacity", max_headers);
        Self {
            edge_state: Arc::new(RwLock::new(EdgeNodeState::new(max_headers))),
            network_height: Arc::new(RwLock::new(0)),
            my_addresses: Arc::new(RwLock::new(Vec::new())),
            next_request_id: Arc::new(RwLock::new(1)),
        }
    }

    /// Add a public key to track for incoming payments
    pub async fn add_address(&self, address: Vec<u8>) {
        let mut addresses = self.my_addresses.write().await;
        if !addresses.contains(&address) {
            addresses.push(address.clone());
            self.edge_state.write().await.add_address(address);
            info!("📝 Added address to edge node tracking");
        }
    }

    /// Update the known network height (from peer announcements)
    pub async fn update_network_height(&self, height: u64) {
        let mut current = self.network_height.write().await;
        if height > *current {
            *current = height;
            debug!("📊 Network height updated to {}", height);
        }
    }

    /// Get the current sync strategy based on network state
    pub async fn get_sync_strategy(&self) -> Result<SyncStrategy> {
        let edge_state = self.edge_state.read().await;
        let network_height = *self.network_height.read().await;
        
        if network_height == 0 {
            return Err(anyhow!("Network height unknown - no peers connected"));
        }

        Ok(edge_state.get_sync_strategy(network_height))
    }

    /// Create a sync request message based on current state
    pub async fn create_sync_request(&self, requester: PublicKey) -> Result<(u64, ZhtpMeshMessage)> {
        let strategy = self.get_sync_strategy().await?;
        let mut next_id = self.next_request_id.write().await;
        let request_id = *next_id;
        *next_id += 1;

        let message = match strategy {
            SyncStrategy::HeadersOnly { start_height, count } => {
                info!("📥 Creating HeadersOnly request: height {} count {}", start_height, count);
                ZhtpMeshMessage::HeadersRequest {
                    requester: requester.clone(),
                    request_id,
                    start_height,
                    count: count as u32,
                }
            }
            SyncStrategy::BootstrapProof { proof_up_to_height, headers_from_height: _, headers_count: _ } => {
                let current_height = self.edge_state.read().await.current_height;
                info!("📥 Creating BootstrapProof request: current {} proof up to {}", 
                    current_height, proof_up_to_height);
                ZhtpMeshMessage::BootstrapProofRequest {
                    requester: requester.clone(),
                    request_id,
                    current_height,
                }
            }
        };

        Ok((request_id, message))
    }

    /// Process received block headers
    pub async fn process_headers(&self, headers: Vec<BlockHeader>) -> Result<()> {
        let mut edge_state = self.edge_state.write().await;
        let mut added_count = 0;

        for header in headers {
            edge_state.add_header(header);
            added_count += 1;
        }

        info!("✅ Processed {} headers, current height: {}", 
            added_count, edge_state.current_height);
        Ok(())
    }

    /// Process bootstrap proof response
    pub async fn process_bootstrap_proof(
        &self,
        proof_data: Vec<u8>,
        proof_height: u64,
        headers: Vec<BlockHeader>,
    ) -> Result<()> {
        info!("🔐 Processing bootstrap proof up to height {}", proof_height);
        
        // TODO: Verify ZK proof using lib-proofs ChainRecursiveProof
        // For now, trust the proof and add headers
        
        let mut edge_state = self.edge_state.write().await;
        for header in headers {
            edge_state.add_header(header);
        }

        info!("✅ Bootstrap complete at height {}", edge_state.current_height);
        Ok(())
    }

    /// Add a UTXO that belongs to this edge node
    pub async fn add_utxo(&self, tx_hash: Hash, output_index: u32, output: TransactionOutput) {
        self.edge_state.write().await.add_utxo(tx_hash, output_index, &output);
    }

    /// Remove a spent UTXO
    pub async fn remove_utxo(&self, tx_hash: &Hash, output_index: u32) -> bool {
        self.edge_state.write().await.remove_utxo(tx_hash, output_index)
    }

    /// Get current edge node height
    pub async fn current_height(&self) -> u64 {
        self.edge_state.read().await.current_height
    }

    /// Check if edge node needs bootstrap proof
    pub async fn needs_bootstrap_proof(&self) -> bool {
        let edge_state = self.edge_state.read().await;
        let network_height = *self.network_height.read().await;
        edge_state.needs_bootstrap_proof(network_height)
    }

    /// Get the number of headers currently stored
    pub async fn header_count(&self) -> usize {
        self.edge_state.read().await.headers.len()
    }

    /// Get estimated storage size in bytes
    pub async fn estimated_storage_bytes(&self) -> usize {
        // ~200 bytes per header + ~96 bytes per UTXO
        let header_count = self.header_count().await;
        let utxo_count = self.edge_state.read().await.utxo_count();
        (header_count * 200) + (utxo_count * 96)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_edge_sync_manager_creation() {
        let manager = EdgeNodeSyncManager::new(500);
        assert_eq!(manager.current_height().await, 0);
        assert_eq!(manager.header_count().await, 0);
    }

    #[tokio::test]
    async fn test_add_address() {
        let manager = EdgeNodeSyncManager::new(500);
        let address = vec![1, 2, 3, 4, 5];
        
        manager.add_address(address.clone()).await;
        // Adding same address twice should be idempotent
        manager.add_address(address).await;
    }

    #[tokio::test]
    async fn test_sync_strategy_no_network() {
        let manager = EdgeNodeSyncManager::new(500);
        // Should error when network height is unknown
        assert!(manager.get_sync_strategy().await.is_err());
    }

    #[tokio::test]
    async fn test_sync_strategy_new_network() {
        let manager = EdgeNodeSyncManager::new(500);
        manager.update_network_height(50).await;
        
        let strategy = manager.get_sync_strategy().await.unwrap();
        match strategy {
            SyncStrategy::HeadersOnly { start_height, count } => {
                assert_eq!(start_height, 0);
                assert_eq!(count, 50);
            }
            _ => panic!("Expected HeadersOnly for new network"),
        }
    }

    #[tokio::test]
    async fn test_storage_estimation() {
        let manager = EdgeNodeSyncManager::new(500);
        let initial_storage = manager.estimated_storage_bytes().await;
        assert_eq!(initial_storage, 0); // No headers or UTXOs yet
    }
}
