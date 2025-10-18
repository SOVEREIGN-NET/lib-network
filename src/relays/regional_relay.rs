//! Regional Relay Node for Mesh Blockchain Aggregation
//! 
//! The regional relay acts as an aggregation layer between local mesh networks
//! and the global blockchain, providing:
//! 
//! - Collection of mesh sync transactions from multiple local meshes
//! - Conflict detection between meshes (cross-mesh double-spends)
//! - Batching of sync transactions for efficient global submission
//! - Retry logic for failed submissions
//! - Coordination between meshes in a geographic region
//! 
//! ## Architecture
//! 
//! ```text
//! Local Mesh 1 → MeshSyncTransaction ┐
//! Local Mesh 2 → MeshSyncTransaction ├→ Regional Relay → Batch → Global Chain
//! Local Mesh 3 → MeshSyncTransaction ┘
//! ```
//! 
//! ## Features
//! 
//! - **Multi-Mesh Aggregation**: Collect syncs from 10-100 local meshes
//! - **Conflict Detection**: Detect UTXO double-spends across mesh boundaries
//! - **Batch Optimization**: Combine multiple syncs into efficient batches
//! - **Retry Management**: Handle temporary global chain congestion
//! - **Health Monitoring**: Track mesh sync status and coordination

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

// Import types from other packages
use lib_blockchain::types::Hash;
use lib_blockchain::mesh::types::{MeshId, NodeId};
use lib_blockchain::transaction::MeshSyncTransaction;

/// Regional relay node coordinating multiple local meshes
#[derive(Debug)]
pub struct RegionalRelayNode {
    /// Relay identifier
    pub relay_id: RelayId,
    
    /// Geographic region (e.g., "us-west", "eu-central")
    pub region: String,
    
    /// Registered local meshes
    meshes: Arc<RwLock<HashMap<MeshId, MeshRegistration>>>,
    
    /// Pending mesh sync transactions
    pending_syncs: Arc<RwLock<VecDeque<MeshSyncTransaction>>>,
    
    /// Sync transactions being processed
    processing_syncs: Arc<RwLock<HashMap<SyncBatchId, SyncBatch>>>,
    
    /// Completed sync history (for deduplication)
    completed_syncs: Arc<RwLock<HashSet<Hash>>>,
    
    /// UTXO conflict tracker (cross-mesh double-spend detection)
    utxo_tracker: Arc<RwLock<UTXOConflictTracker>>,
    
    /// Relay configuration
    config: RelayConfig,
    
    /// Statistics
    stats: Arc<RwLock<RelayStatistics>>,
}

/// Relay identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelayId(pub [u8; 32]);

/// Sync batch identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SyncBatchId(pub [u8; 32]);

/// Mesh registration information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshRegistration {
    /// Mesh identifier
    pub mesh_id: MeshId,
    
    /// Coordinator node
    pub coordinator: NodeId,
    
    /// Registration timestamp
    pub registered_at: u64,
    
    /// Last sync received timestamp
    pub last_sync_at: u64,
    
    /// Last sync height
    pub last_sync_height: u64,
    
    /// Total syncs processed
    pub total_syncs: u64,
    
    /// Mesh status
    pub status: MeshStatus,
    
    /// Contact endpoint (optional)
    pub endpoint: Option<String>,
}

/// Mesh status from relay perspective
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MeshStatus {
    /// Mesh is active and syncing regularly
    Active,
    /// Mesh hasn't synced recently (warning)
    Stale,
    /// Mesh has stopped syncing (error)
    Inactive,
    /// Mesh deregistered
    Deregistered,
}

/// Batch of mesh sync transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBatch {
    /// Batch identifier
    pub batch_id: SyncBatchId,
    
    /// Sync transactions in this batch
    pub transactions: Vec<MeshSyncTransaction>,
    
    /// Batch creation timestamp
    pub created_at: u64,
    
    /// Batch status
    pub status: BatchStatus,
    
    /// Retry count (if submission failed)
    pub retry_count: u32,
    
    /// Last submission attempt timestamp
    pub last_attempt_at: Option<u64>,
    
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Batch processing status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BatchStatus {
    /// Batch is being assembled
    Pending,
    /// Ready for submission to global chain
    Ready,
    /// Currently submitting to global chain
    Submitting,
    /// Successfully submitted
    Completed,
    /// Submission failed (will retry)
    Failed,
    /// Permanently rejected (conflicts or invalid)
    Rejected,
}

/// UTXO conflict tracker for cross-mesh double-spend detection
#[derive(Debug, Clone)]
pub struct UTXOConflictTracker {
    /// UTXO → Mesh ID mapping
    utxo_ownership: HashMap<UTXOReference, MeshId>,
    
    /// Detected conflicts
    conflicts: Vec<UTXOConflict>,
}

/// UTXO reference (previous_output, output_index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UTXOReference {
    pub previous_output: Hash,
    pub output_index: u32,
}

/// UTXO conflict between meshes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXOConflict {
    /// UTXO in question
    pub utxo: UTXOReference,
    
    /// First mesh claiming this UTXO
    pub mesh_a: MeshId,
    
    /// Second mesh claiming this UTXO
    pub mesh_b: MeshId,
    
    /// Detection timestamp
    pub detected_at: u64,
    
    /// Resolution status
    pub resolved: bool,
}

/// Relay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Maximum meshes this relay can handle
    pub max_meshes: usize,
    
    /// Maximum pending syncs before backpressure
    pub max_pending_syncs: usize,
    
    /// Batch size (number of syncs per batch)
    pub batch_size: usize,
    
    /// Batch timeout (seconds) - submit even if not full
    pub batch_timeout_secs: u64,
    
    /// Maximum retry attempts for failed batches
    pub max_retries: u32,
    
    /// Retry backoff base (seconds)
    pub retry_backoff_secs: u64,
    
    /// Stale mesh threshold (no sync in N seconds)
    pub stale_threshold_secs: u64,
    
    /// Inactive mesh threshold (no sync in N seconds)
    pub inactive_threshold_secs: u64,
}

/// Relay statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayStatistics {
    /// Total meshes registered
    pub total_meshes: u64,
    
    /// Active meshes
    pub active_meshes: u64,
    
    /// Total syncs received
    pub total_syncs_received: u64,
    
    /// Total syncs submitted to global chain
    pub total_syncs_submitted: u64,
    
    /// Total batches created
    pub total_batches_created: u64,
    
    /// Total batches submitted
    pub total_batches_submitted: u64,
    
    /// Total conflicts detected
    pub total_conflicts_detected: u64,
    
    /// Total retries
    pub total_retries: u64,
    
    /// Average batch size
    pub avg_batch_size: f64,
    
    /// Success rate (percentage)
    pub success_rate: f64,
}

impl RegionalRelayNode {
    /// Create a new regional relay node
    pub fn new(relay_id: RelayId, region: String, config: RelayConfig) -> Self {
        info!("Creating regional relay node: region={}, max_meshes={}", region, config.max_meshes);
        
        Self {
            relay_id,
            region,
            meshes: Arc::new(RwLock::new(HashMap::new())),
            pending_syncs: Arc::new(RwLock::new(VecDeque::new())),
            processing_syncs: Arc::new(RwLock::new(HashMap::new())),
            completed_syncs: Arc::new(RwLock::new(HashSet::new())),
            utxo_tracker: Arc::new(RwLock::new(UTXOConflictTracker::new())),
            config,
            stats: Arc::new(RwLock::new(RelayStatistics::default())),
        }
    }
    
    /// Register a local mesh with this relay
    pub async fn register_mesh(
        &self,
        mesh_id: MeshId,
        coordinator: NodeId,
        endpoint: Option<String>,
    ) -> Result<()> {
        let mut meshes = self.meshes.write().await;
        
        // Check capacity
        if meshes.len() >= self.config.max_meshes {
            return Err(anyhow!(
                "Relay at capacity: {}/{} meshes registered",
                meshes.len(),
                self.config.max_meshes
            ));
        }
        
        // Check if already registered
        if meshes.contains_key(&mesh_id) {
            return Err(anyhow!("Mesh already registered: {:?}", mesh_id));
        }
        
        let now = current_timestamp();
        
        let registration = MeshRegistration {
            mesh_id,
            coordinator,
            registered_at: now,
            last_sync_at: now,
            last_sync_height: 0,
            total_syncs: 0,
            status: MeshStatus::Active,
            endpoint,
        };
        
        meshes.insert(mesh_id, registration);
        
        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_meshes += 1;
        stats.active_meshes += 1;
        
        info!("Mesh registered: {:?} (coordinator: {:?})", mesh_id, coordinator);
        Ok(())
    }
    
    /// Deregister a mesh
    pub async fn deregister_mesh(&self, mesh_id: MeshId) -> Result<()> {
        let mut meshes = self.meshes.write().await;
        
        if let Some(mut registration) = meshes.remove(&mesh_id) {
            registration.status = MeshStatus::Deregistered;
            
            // Update stats
            let mut stats = self.stats.write().await;
            stats.active_meshes = stats.active_meshes.saturating_sub(1);
            
            info!("Mesh deregistered: {:?}", mesh_id);
            Ok(())
        } else {
            Err(anyhow!("Mesh not registered: {:?}", mesh_id))
        }
    }
    
    /// Submit a mesh sync transaction to the relay
    pub async fn submit_sync(&self, sync_tx: MeshSyncTransaction) -> Result<()> {
        // Verify mesh is registered
        let mut meshes = self.meshes.write().await;
        let mesh_reg = meshes.get_mut(&sync_tx.mesh_id)
            .ok_or_else(|| anyhow!("Mesh not registered: {:?}", sync_tx.mesh_id))?;
        
        // Update mesh registration
        mesh_reg.last_sync_at = current_timestamp();
        mesh_reg.last_sync_height = sync_tx.sync_batch.to_height;
        mesh_reg.total_syncs += 1;
        mesh_reg.status = MeshStatus::Active;
        
        drop(meshes); // Release lock
        
        // Check for duplicates
        let sync_hash = self.calculate_sync_hash(&sync_tx);
        let completed = self.completed_syncs.read().await;
        if completed.contains(&sync_hash) {
            warn!("Duplicate sync transaction ignored: {:?}", sync_hash);
            return Ok(());
        }
        drop(completed);
        
        // Check for conflicts
        self.check_conflicts(&sync_tx).await?;
        
        // Add to pending queue
        let mut pending = self.pending_syncs.write().await;
        
        if pending.len() >= self.config.max_pending_syncs {
            return Err(anyhow!(
                "Relay overloaded: {}/{} pending syncs",
                pending.len(),
                self.config.max_pending_syncs
            ));
        }
        
        pending.push_back(sync_tx);
        
        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_syncs_received += 1;
        
        info!("Mesh sync received: {:?} (pending: {})", sync_hash, pending.len());
        Ok(())
    }
    
    /// Check for UTXO conflicts across meshes
    async fn check_conflicts(&self, sync_tx: &MeshSyncTransaction) -> Result<()> {
        let mut tracker = self.utxo_tracker.write().await;
        
        // Extract all UTXOs being spent in this sync
        for tx in &sync_tx.sync_batch.transactions {
            for input in &tx.inputs {
                let utxo_ref = UTXOReference {
                    previous_output: input.previous_output,
                    output_index: input.output_index,
                };
                
                // Check if this UTXO is already claimed by another mesh
                if let Some(&existing_mesh) = tracker.utxo_ownership.get(&utxo_ref) {
                    if existing_mesh != sync_tx.mesh_id {
                        // CONFLICT DETECTED!
                        let conflict = UTXOConflict {
                            utxo: utxo_ref,
                            mesh_a: existing_mesh,
                            mesh_b: sync_tx.mesh_id,
                            detected_at: current_timestamp(),
                            resolved: false,
                        };
                        
                        tracker.conflicts.push(conflict.clone());
                        
                        // Update stats
                        let mut stats = self.stats.write().await;
                        stats.total_conflicts_detected += 1;
                        
                        error!(
                            "UTXO conflict detected: {:?} claimed by both {:?} and {:?}",
                            utxo_ref, existing_mesh, sync_tx.mesh_id
                        );
                        
                        return Err(anyhow!(
                            "Cross-mesh double-spend detected: UTXO {:?}",
                            utxo_ref
                        ));
                    }
                } else {
                    // Register this UTXO as owned by this mesh
                    tracker.utxo_ownership.insert(utxo_ref, sync_tx.mesh_id);
                }
            }
        }
        
        Ok(())
    }
    
    /// Create a batch from pending syncs
    pub async fn create_batch(&self) -> Result<Option<SyncBatch>> {
        let mut pending = self.pending_syncs.write().await;
        
        if pending.is_empty() {
            return Ok(None);
        }
        
        // Determine batch size
        let batch_size = pending.len().min(self.config.batch_size);
        
        // Extract transactions for batch
        let mut transactions = Vec::new();
        for _ in 0..batch_size {
            if let Some(sync_tx) = pending.pop_front() {
                transactions.push(sync_tx);
            }
        }
        
        if transactions.is_empty() {
            return Ok(None);
        }
        
        // Create batch
        let batch_id = self.generate_batch_id(&transactions);
        let batch = SyncBatch {
            batch_id,
            transactions,
            created_at: current_timestamp(),
            status: BatchStatus::Ready,
            retry_count: 0,
            last_attempt_at: None,
            error: None,
        };
        
        // Add to processing
        let mut processing = self.processing_syncs.write().await;
        processing.insert(batch_id, batch.clone());
        
        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_batches_created += 1;
        stats.avg_batch_size = ((stats.avg_batch_size * (stats.total_batches_created - 1) as f64)
            + batch.transactions.len() as f64) / stats.total_batches_created as f64;
        
        info!("Batch created: {:?} with {} syncs", batch_id, batch.transactions.len());
        Ok(Some(batch))
    }
    
    /// Submit batch to global chain (placeholder for actual implementation)
    pub async fn submit_batch(&self, batch_id: SyncBatchId) -> Result<()> {
        let batch_tx_count = {
            let mut processing = self.processing_syncs.write().await;
            
            let batch = processing.get_mut(&batch_id)
                .ok_or_else(|| anyhow!("Batch not found: {:?}", batch_id))?;
            
            // Update status
            batch.status = BatchStatus::Submitting;
            batch.last_attempt_at = Some(current_timestamp());
            
            let tx_count = batch.transactions.len();
            tx_count
        }; // Lock released here
        
        info!("Submitting batch {:?} with {} syncs to global chain", batch_id, batch_tx_count);
        
        // TODO: Actual global chain submission
        // For now, simulate submission
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Mark as completed
        let mut processing = self.processing_syncs.write().await;
        if let Some(batch) = processing.get_mut(&batch_id) {
            batch.status = BatchStatus::Completed;
            
            // Mark syncs as completed
            let mut completed = self.completed_syncs.write().await;
            for sync_tx in &batch.transactions {
                let sync_hash = self.calculate_sync_hash(sync_tx);
                completed.insert(sync_hash);
            }
            
            // Update stats
            let mut stats = self.stats.write().await;
            stats.total_batches_submitted += 1;
            stats.total_syncs_submitted += batch.transactions.len() as u64;
            stats.success_rate = (stats.total_batches_submitted as f64 / stats.total_batches_created as f64) * 100.0;
            
            info!("Batch submitted successfully: {:?}", batch_id);
        }
        
        Ok(())
    }
    
    /// Handle failed batch submission
    pub async fn handle_batch_failure(&self, batch_id: SyncBatchId, error: String) -> Result<()> {
        let mut processing = self.processing_syncs.write().await;
        
        let batch = processing.get_mut(&batch_id)
            .ok_or_else(|| anyhow!("Batch not found: {:?}", batch_id))?;
        
        batch.retry_count += 1;
        batch.error = Some(error.clone());
        
        if batch.retry_count >= self.config.max_retries {
            // Permanently failed
            batch.status = BatchStatus::Rejected;
            warn!("Batch permanently rejected after {} retries: {:?}", batch.retry_count, batch_id);
            
            // Put syncs back in queue for individual reprocessing
            let mut pending = self.pending_syncs.write().await;
            for sync_tx in &batch.transactions {
                pending.push_back(sync_tx.clone());
            }
        } else {
            // Retry later
            batch.status = BatchStatus::Failed;
            
            // Update stats
            let mut stats = self.stats.write().await;
            stats.total_retries += 1;
            
            warn!("Batch failed (retry {}/{}): {:?} - {}", batch.retry_count, self.config.max_retries, batch_id, error);
        }
        
        Ok(())
    }
    
    /// Update mesh statuses based on sync activity
    pub async fn update_mesh_statuses(&self) {
        let mut meshes = self.meshes.write().await;
        let now = current_timestamp();
        
        for registration in meshes.values_mut() {
            let time_since_sync = now.saturating_sub(registration.last_sync_at);
            
            if time_since_sync > self.config.inactive_threshold_secs {
                if registration.status != MeshStatus::Inactive {
                    warn!("Mesh {:?} marked inactive (no sync in {} seconds)", registration.mesh_id, time_since_sync);
                    registration.status = MeshStatus::Inactive;
                }
            } else if time_since_sync > self.config.stale_threshold_secs {
                if registration.status != MeshStatus::Stale {
                    warn!("Mesh {:?} marked stale (no sync in {} seconds)", registration.mesh_id, time_since_sync);
                    registration.status = MeshStatus::Stale;
                }
            } else {
                registration.status = MeshStatus::Active;
            }
        }
    }
    
    /// Get relay statistics
    pub async fn get_statistics(&self) -> RelayStatistics {
        self.stats.read().await.clone()
    }
    
    /// Get mesh status for a specific mesh
    pub async fn get_mesh_status(&self, mesh_id: MeshId) -> Result<MeshRegistration> {
        let meshes = self.meshes.read().await;
        meshes.get(&mesh_id)
            .cloned()
            .ok_or_else(|| anyhow!("Mesh not registered: {:?}", mesh_id))
    }
    
    /// Get all registered meshes
    pub async fn get_all_meshes(&self) -> Vec<MeshRegistration> {
        let meshes = self.meshes.read().await;
        meshes.values().cloned().collect()
    }
    
    /// Get pending sync count
    pub async fn get_pending_count(&self) -> usize {
        self.pending_syncs.read().await.len()
    }
    
    /// Get processing batch count
    pub async fn get_processing_count(&self) -> usize {
        self.processing_syncs.read().await.len()
    }
    
    /// Get all detected conflicts
    pub async fn get_conflicts(&self) -> Vec<UTXOConflict> {
        let tracker = self.utxo_tracker.read().await;
        tracker.conflicts.clone()
    }
    
    // Helper methods
    
    fn calculate_sync_hash(&self, sync_tx: &MeshSyncTransaction) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&sync_tx.mesh_id.0);
        data.extend_from_slice(&sync_tx.sync_batch.from_height.to_le_bytes());
        data.extend_from_slice(&sync_tx.sync_batch.to_height.to_le_bytes());
        data.extend_from_slice(&sync_tx.batch_timestamp.to_le_bytes());
        
        Hash::from_slice(&blake3::hash(&data).as_bytes()[..32])
    }
    
    fn generate_batch_id(&self, transactions: &[MeshSyncTransaction]) -> SyncBatchId {
        let mut data = Vec::new();
        data.extend_from_slice(&self.relay_id.0);
        data.extend_from_slice(&current_timestamp().to_le_bytes());
        for tx in transactions {
            data.extend_from_slice(&tx.mesh_id.0);
        }
        
        let hash_bytes = blake3::hash(&data);
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash_bytes.as_bytes()[..32]);
        SyncBatchId(id)
    }
}

impl UTXOConflictTracker {
    /// Create a new UTXO conflict tracker
    pub fn new() -> Self {
        Self {
            utxo_ownership: HashMap::new(),
            conflicts: Vec::new(),
        }
    }
    
    /// Get total conflicts detected
    pub fn conflict_count(&self) -> usize {
        self.conflicts.len()
    }
    
    /// Get unresolved conflicts
    pub fn unresolved_conflicts(&self) -> Vec<UTXOConflict> {
        self.conflicts.iter()
            .filter(|c| !c.resolved)
            .cloned()
            .collect()
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_meshes: 100,
            max_pending_syncs: 1000,
            batch_size: 10,
            batch_timeout_secs: 60,
            max_retries: 3,
            retry_backoff_secs: 30,
            stale_threshold_secs: 300,      // 5 minutes
            inactive_threshold_secs: 1800,  // 30 minutes
        }
    }
}

impl Default for RelayStatistics {
    fn default() -> Self {
        Self {
            total_meshes: 0,
            active_meshes: 0,
            total_syncs_received: 0,
            total_syncs_submitted: 0,
            total_batches_created: 0,
            total_batches_submitted: 0,
            total_conflicts_detected: 0,
            total_retries: 0,
            avg_batch_size: 0.0,
            success_rate: 100.0,
        }
    }
}

/// Get current timestamp in seconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_relay() -> RegionalRelayNode {
        let relay_id = RelayId([1u8; 32]);
        let region = "test-region".to_string();
        let config = RelayConfig::default();
        RegionalRelayNode::new(relay_id, region, config)
    }
    
    #[tokio::test]
    async fn test_relay_creation() {
        let relay = create_test_relay();
        assert_eq!(relay.region, "test-region");
        assert_eq!(relay.get_pending_count().await, 0);
    }
    
    #[tokio::test]
    async fn test_mesh_registration() {
        let relay = create_test_relay();
        let mesh_id = MeshId([2u8; 32]);
        let coordinator = NodeId([3u8; 32]);
        
        let result = relay.register_mesh(mesh_id, coordinator, None).await;
        assert!(result.is_ok());
        
        let meshes = relay.get_all_meshes().await;
        assert_eq!(meshes.len(), 1);
        assert_eq!(meshes[0].mesh_id, mesh_id);
    }
    
    #[tokio::test]
    async fn test_mesh_deregistration() {
        let relay = create_test_relay();
        let mesh_id = MeshId([2u8; 32]);
        let coordinator = NodeId([3u8; 32]);
        
        relay.register_mesh(mesh_id, coordinator, None).await.unwrap();
        let result = relay.deregister_mesh(mesh_id).await;
        assert!(result.is_ok());
        
        let stats = relay.get_statistics().await;
        assert_eq!(stats.active_meshes, 0);
    }
    
    #[tokio::test]
    async fn test_utxo_conflict_tracker() {
        let mut tracker = UTXOConflictTracker::new();
        assert_eq!(tracker.conflict_count(), 0);
        
        let conflict = UTXOConflict {
            utxo: UTXOReference {
                previous_output: Hash::default(),
                output_index: 0,
            },
            mesh_a: MeshId([1u8; 32]),
            mesh_b: MeshId([2u8; 32]),
            detected_at: current_timestamp(),
            resolved: false,
        };
        
        tracker.conflicts.push(conflict);
        assert_eq!(tracker.conflict_count(), 1);
        assert_eq!(tracker.unresolved_conflicts().len(), 1);
    }
}
