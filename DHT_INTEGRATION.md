# DHT Client Integration Documentation

## Overview

This document describes the integration between the JavaScript DHT client (`zkdht-client.js`) and the Rust DHT backend through the `lib-storage` layer. The integration was implemented to properly connect a copied JavaScript client with the existing SOVEREIGN_NET storage infrastructure.

## Architecture

### Component Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Web4 Browser Client                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              zkdht-client.js                        │   │
│  │  • Content resolution                               │   │
│  │  • Peer discovery                                   │   │
│  │  • DHT queries                                      │   │
│  │  • Caching and mock content                         │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ WebAssembly/API Bridge
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  zhtp-dht-api.js                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │               API Bridge Layer                       │   │
│  │  • Function mapping                                 │   │
│  │  • Error handling                                   │   │
│  │  • Data serialization                               │   │
│  │  • Fallback mechanisms                              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ FFI/WASM calls
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   lib-network/src/dht.rs                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │               DHT Client Layer                       │   │
│  │  • DHTClient struct                                 │   │
│  │  • Peer management                                  │   │
│  │  • Content operations                               │   │
│  │  • Statistics tracking                              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Direct integration
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  lib-storage Backend                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │            UnifiedStorageSystem                     │   │
│  │  • DHT node management                              │   │
│  │  • Content encryption/decryption                    │   │
│  │  • Economic integration                             │   │
│  │  • Identity management                              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Integration Points

### 1. JavaScript Client (`zkdht-client.js`)

**Location**: `lib-network/src/dht-client/zkdht-client.js`

**Key Features**:
- Web4 content loading and resolution
- Peer discovery and connection management
- DHT queries with fallback mechanisms
- Content caching and mock content generation
- WebAssembly integration ready

**Updated Functions**:
```javascript
async connectToDHT()        // Uses dhtApi.initialize() when available
async discoverPeers()       // Uses dhtApi.discoverPeers() with fallback
async resolveContent()      // Uses dhtApi.fetchContent() with fallback
async fetchContent()        // Primary content fetch with API integration
async queryDHT()           // DHT queries with API bridge support
```

### 2. API Bridge (`zhtp-dht-api.js`)

**Location**: `lib-network/src/dht-client/zhtp-dht-api.js`

**Purpose**: Provides seamless integration between JavaScript client and Rust backend

**Key Features**:
- Function mapping between JS and Rust APIs
- Error handling and serialization
- Initialization state management
- Graceful fallback when API unavailable

**API Functions**:
```javascript
async initialize()           // Initialize DHT backend
async discoverPeers(limit)   // Discover network peers
async connectToPeer(peer)    // Connect to specific peer
async fetchContent(hash)     // Fetch content by hash
async queryDHT(query)       // Query DHT for content
async getStatistics()       // Get DHT statistics
```

### 3. Rust DHT Client (`dht.rs`)

**Location**: `lib-network/src/dht.rs`

**Purpose**: Core DHT implementation that bridges to lib-storage

**Key Components**:
```rust
pub struct DHTClient {
    storage_system: Option<UnifiedStorageSystem>,
    connected_peers: Vec<String>,
    is_initialized: bool,
    statistics: DHTStatistics,
}
```

**Core Methods**:
- `initialize()` - Set up storage system and crypto
- `discover_peers()` - Find available network peers
- `connect_to_peer()` - Establish peer connections
- `store_content()` - Store content in DHT
- `fetch_content()` - Retrieve content by hash
- `query_dht()` - Search DHT for content
- `get_statistics()` - Return usage statistics

### 4. Storage Backend Integration

**Integration with lib-storage**:
- Uses `UnifiedStorageSystem` for persistent storage
- Integrates with economic incentive system
- Provides content encryption/decryption
- Manages identity and access control

## Implementation Details

### Error Handling Strategy

1. **Graceful Degradation**: JavaScript client falls back to legacy API when DHT API unavailable
2. **Error Propagation**: Rust errors properly serialized and passed to JavaScript
3. **Timeout Handling**: All async operations have appropriate timeouts
4. **Retry Logic**: Failed operations retry with exponential backoff

### Data Flow

```
User Request (JS) → API Bridge → DHT Client (Rust) → Storage System → Response
                                     ↓
                              Statistics Update
                                     ↓
                              Peer Management Update
```

### Content Storage Format

Content stored in DHT includes:
- **Content Hash**: SHA-256 hash of content
- **Metadata**: Domain, path, content type information
- **Encryption**: Content encrypted using lib-crypto
- **Economic Data**: Storage costs, retrieval fees
- **Identity Info**: Owner identity, access permissions

### Peer Discovery Mechanism

1. **Bootstrap Nodes**: Initial connection to known network nodes
2. **Kademlia DHT**: Structured peer discovery using XOR distance
3. **Peer Scoring**: Quality-based peer selection
4. **Connection Pool**: Managed persistent connections

## Configuration

### Environment Variables

```bash
# DHT Configuration
DHT_BOOTSTRAP_NODES="node1:8080,node2:8080"
DHT_MAX_PEERS=50
DHT_STORAGE_PATH="./dht_storage"

# Network Configuration
NETWORK_PORT=8080
NETWORK_HOST="0.0.0.0"

# Storage Configuration
STORAGE_ENCRYPTION_ENABLED=true
STORAGE_ECONOMIC_ENABLED=true
```

### Build Configuration

```toml
[features]
default = ["lib-storage"]
dht-integration = ["lib-storage", "lib-economy"]
testing = ["dev-dependencies"]
```

## Testing

### Integration Tests

**Location**: `lib-network/tests/dht_integration_test.rs`

**Test Categories**:
1. **Initialization Tests**: DHT client setup and teardown
2. **Peer Discovery Tests**: Network peer finding and connection
3. **Content Operations**: Store and retrieve content functionality
4. **Query Tests**: DHT search and filtering
5. **Statistics Tests**: Metrics and monitoring
6. **Error Handling**: Failure scenarios and recovery
7. **Concurrency Tests**: Multiple simultaneous operations
8. **JS API Compatibility**: JavaScript client expectations

### Running Tests

```bash
# Run all DHT integration tests
cargo test --package lib-network dht_integration

# Run specific test categories
cargo test --package lib-network test_dht_client_initialization
cargo test --package lib-network test_js_api_expected_functions

# Run with logging
RUST_LOG=debug cargo test --package lib-network dht_integration
```

## Usage Examples

### JavaScript Client Usage

```javascript
import { ZKDHTClient } from './zkdht-client.js';

// Initialize client with DHT API
const client = new ZKDHTClient({
    dhtApi: window.dhtApi,  // Provided by zhtp-dht-api.js
    fallbackMode: true     // Enable fallback to legacy API
});

// Connect to DHT network
await client.connectToDHT();

// Discover peers
const peers = await client.discoverPeers();
console.log(`Found ${peers.length} peers`);

// Resolve Web4 content
const content = await client.resolveContent('example.sovereign', '/index.html');

// Query DHT for content
const results = await client.queryDHT('search term');
```

### Rust DHT Client Usage

```rust
use lib_network::dht::DHTClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize DHT client
    let mut client = DHTClient::new();
    client.initialize().await?;
    
    // Store content
    let content = b"Hello, SOVEREIGN_NET!";
    let hash = client.store_content(content, "test content").await?;
    
    // Retrieve content
    let retrieved = client.fetch_content(&hash).await?;
    assert_eq!(retrieved, content);
    
    // Get statistics
    let stats = client.get_statistics().await?;
    println!("DHT Stats: {}", serde_json::to_string_pretty(&stats)?);
    
    Ok(())
}
```

## Performance Considerations

### Optimization Strategies

1. **Connection Pooling**: Reuse persistent connections to peers
2. **Content Caching**: Local cache for frequently accessed content
3. **Batch Operations**: Group multiple operations for efficiency
4. **Lazy Loading**: Initialize components only when needed
5. **Compression**: Compress content before storage and transmission

### Monitoring Metrics

- **Peer Connection Count**: Number of active peer connections
- **Content Cache Hit Rate**: Percentage of requests served from cache
- **Storage Operations**: Total store/retrieve operations
- **Query Response Time**: Average DHT query response time
- **Network Bandwidth**: Total network usage for DHT operations

## Security Considerations

### Data Protection

1. **Content Encryption**: All content encrypted using lib-crypto
2. **Identity Verification**: Peer identities verified using lib-identity
3. **Economic Incentives**: Storage and retrieval costs via lib-economy
4. **Access Control**: Content access permissions enforced

### Network Security

1. **Peer Authentication**: All peers must provide valid identity proofs
2. **DDoS Protection**: Rate limiting and connection throttling
3. **Malicious Content**: Content validation and sandboxing
4. **Privacy Protection**: Zero-knowledge proofs for sensitive operations

## Troubleshooting

### Common Issues

1. **DHT API Not Available**: 
   - Check that `zhtp-dht-api.js` is loaded
   - Verify WebAssembly module compilation
   - Enable fallback mode in JavaScript client

2. **Peer Discovery Fails**:
   - Check network connectivity
   - Verify bootstrap node configuration
   - Check firewall settings

3. **Content Storage Errors**:
   - Verify storage backend initialization
   - Check disk space and permissions
   - Verify economic system balance

4. **Performance Issues**:
   - Monitor peer connection count
   - Check content cache configuration
   - Verify network bandwidth

### Debug Logging

```bash
# Enable detailed DHT logging
RUST_LOG=lib_network::dht=debug cargo run

# Enable storage system logging
RUST_LOG=lib_storage=debug cargo run

# Enable all DHT-related logging
RUST_LOG="lib_network::dht,lib_storage,lib_economy" cargo run
```

## Future Enhancements

### Planned Features

1. **WebRTC Integration**: Direct peer-to-peer connections
2. **Mobile Support**: React Native and mobile browser support
3. **Offline Mode**: Local-first content storage and sync
4. **Advanced Queries**: Full-text search and content filtering
5. **Federation**: Cross-network DHT synchronization

### API Extensions

1. **Streaming API**: Large content streaming support
2. **Subscription API**: Real-time content update notifications
3. **Analytics API**: Detailed usage and performance metrics
4. **Admin API**: Network administration and management tools

---

*This integration documentation is part of the SOVEREIGN_NET project and is licensed under MIT OR Apache-2.0.*
