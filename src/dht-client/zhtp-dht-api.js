/**
 * ZHTP DHT API Bridge
 * 
 * Provides the API interface that the zkDHT client expects,
 * bridging to the Rust DHT implementation in lib-network.
 */

class ZhtpDhtApi {
    constructor(zhtpApi) {
        this.zhtpApi = zhtpApi;
        this.dhtClient = null;
        this.isInitialized = false;
    }

    async initialize(identity) {
        console.log('🔧 Initializing ZHTP DHT API bridge...');
        
        try {
            // Initialize DHT client through ZHTP API
            this.dhtClient = await this.zhtpApi.dht.initializeClient(identity);
            this.isInitialized = true;
            
            console.log('✅ ZHTP DHT API bridge initialized');
            return true;
        } catch (error) {
            console.error('❌ Failed to initialize DHT API bridge:', error);
            return false;
        }
    }

    async connectToPeer(peerAddress) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(`🔗 DHT API: Connecting to peer ${peerAddress}`);
        
        try {
            await this.zhtpApi.dht.connectToPeer(peerAddress);
            console.log(`✅ DHT API: Connected to peer ${peerAddress}`);
            return true;
        } catch (error) {
            console.error(`❌ DHT API: Failed to connect to peer ${peerAddress}:`, error);
            throw error;
        }
    }

    async discoverPeers(region = null, capabilities = []) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log('👥 DHT API: Discovering peers...');
        
        try {
            const peers = await this.zhtpApi.dht.discoverPeers(region, capabilities);
            console.log(`✅ DHT API: Discovered ${peers.length} peers`);
            return peers;
        } catch (error) {
            console.error('❌ DHT API: Peer discovery failed:', error);
            return [];
        }
    }

    async fetchFromPeer(peerAddress, contentHash) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(`📥 DHT API: Fetching content ${contentHash.substring(0, 16)}... from peer ${peerAddress}`);
        
        try {
            const content = await this.zhtpApi.dht.fetchFromPeer(peerAddress, contentHash);
            console.log(`✅ DHT API: Fetched ${content.length} bytes from peer`);
            return content;
        } catch (error) {
            console.error(`❌ DHT API: Failed to fetch from peer ${peerAddress}:`, error);
            throw error;
        }
    }

    async sendDHTQuery(peerAddress, query) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(`📤 DHT API: Sending query to peer ${peerAddress}`);
        
        try {
            const response = await this.zhtpApi.dht.sendQuery(peerAddress, query);
            console.log(`✅ DHT API: Received response from peer ${peerAddress}`);
            return response;
        } catch (error) {
            console.error(`❌ DHT API: Query failed to peer ${peerAddress}:`, error);
            throw error;
        }
    }

    async storeContent(domain, path, content) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(`💾 DHT API: Storing content for ${domain}${path}`);
        
        try {
            const contentHash = await this.zhtpApi.dht.storeContent(domain, path, content);
            console.log(`✅ DHT API: Content stored with hash ${contentHash}`);
            return contentHash;
        } catch (error) {
            console.error(`❌ DHT API: Failed to store content for ${domain}${path}:`, error);
            throw error;
        }
    }

    async resolveContent(domain, path) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(`🔍 DHT API: Resolving content for ${domain}${path}`);
        
        try {
            const contentHash = await this.zhtpApi.dht.resolveContent(domain, path);
            console.log(`✅ DHT API: Content resolved to hash ${contentHash}`);
            return contentHash;
        } catch (error) {
            console.error(`❌ DHT API: Failed to resolve content for ${domain}${path}:`, error);
            throw error;
        }
    }

    async fetchContent(contentHash) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(`📥 DHT API: Fetching content ${contentHash.substring(0, 16)}...`);
        
        try {
            const content = await this.zhtpApi.dht.fetchContent(contentHash);
            console.log(`✅ DHT API: Fetched ${content.length} bytes`);
            return content;
        } catch (error) {
            console.error(`❌ DHT API: Failed to fetch content ${contentHash}:`, error);
            throw error;
        }
    }

    async getStatistics() {
        if (!this.isInitialized) {
            return {};
        }

        try {
            return await this.zhtpApi.dht.getStatistics();
        } catch (error) {
            console.error('❌ DHT API: Failed to get statistics:', error);
            return {};
        }
    }

    async getNetworkStatus() {
        if (!this.isInitialized) {
            return {
                connected: false,
                peerCount: 0,
                cacheSize: 0
            };
        }

        try {
            return await this.zhtpApi.dht.getNetworkStatus();
        } catch (error) {
            console.error('❌ DHT API: Failed to get network status:', error);
            return {
                connected: false,
                peerCount: 0,
                cacheSize: 0
            };
        }
    }
}

export default ZhtpDhtApi;
