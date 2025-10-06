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

/// Initialize the Web4 system with DHT backend
pub async fn initialize_web4_system() -> Result<Web4Manager> {
    let manager = Web4Manager::new().await?;
    tracing::info!("Web4 domain registry and content publishing system initialized");
    Ok(manager)
}