//! Web4 Domain Registry and Content Publishing System
//! 
//! This module provides the formal Web4 domain registry and content publishing
//! infrastructure that was missing from the ZHTP ecosystem. It integrates with
//! the existing DHT and ZDNS systems to provide complete Web4 functionality.

pub mod domain_registry;
pub mod content_publisher;
pub mod types;

pub use domain_registry::*;
pub use content_publisher::*;
pub use types::*;

use anyhow::Result;
use crate::dht::DHTClient;

/// Initialize the Web4 system with DHT backend
pub async fn initialize_web4_system() -> Result<Web4Manager> {
    initialize_web4_system_with_dht(None).await
}

/// Initialize the Web4 system with optional existing DHT client to avoid creating duplicates
pub async fn initialize_web4_system_with_dht(dht_client: Option<DHTClient>) -> Result<Web4Manager> {
    let manager = Web4Manager::new_with_dht(dht_client).await?;
    tracing::info!("Web4 domain registry and content publishing system initialized");
    Ok(manager)
}