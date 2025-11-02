# Mobile FFI Quick Reference

## 🚀 Quick Start

### Android (5 minutes)
```bash
# 1. Build Rust library
cd lib-network/src/mobile/examples/android
./build_android.sh

# 2. Copy to Android project
cp -r ../../../../target/android-libs/jniLibs app/src/main/

# 3. Add ZhtpNative.kt to your project
# 4. Use it:
val result = ZhtpNative.initNode("client", true, true, true, 9333)
ZhtpNative.startNode()
```

### iOS (5 minutes)
```bash
# 1. Build XCFramework
cd lib-network/src/mobile/examples/ios
./build_xcframework.sh

# 2. Add framework to Xcode project (drag & drop)
# 3. Set to "Embed & Sign"
# 4. Add ZhtpClient.swift to your project
# 5. Use it:
let nodeId = try ZhtpClient.initNode()
try ZhtpClient.startNode()
```

## 📋 Core Functions (Both Platforms)

| Function | Android (Kotlin) | iOS (Swift) | Returns |
|----------|-----------------|-------------|---------|
| Initialize | `ZhtpNative.initNode(...)` | `ZhtpClient.initNode(...)` | node_id |
| Start | `ZhtpNative.startNode()` | `ZhtpClient.startNode()` | success |
| Stop | `ZhtpNative.stopNode()` | `ZhtpClient.stopNode()` | success |
| Status | `ZhtpNative.getNodeStatus()` | `ZhtpClient.getStatus()` | JSON |
| Discover | `ZhtpNative.discoverPeers(5)` | `ZhtpClient.discoverPeers(5)` | peers[] |
| Connect | `ZhtpNative.connectToPeer(addr, id)` | `ZhtpClient.connectToPeer(addr, id)` | success |
| Send | `ZhtpNative.sendMessage(id, msg)` | `ZhtpClient.sendMessage(id, msg)` | success |
| Peers | `ZhtpNative.getConnectedPeers()` | `ZhtpClient.getConnectedPeers()` | peers[] |

## 🔌 Platform-Specific Integration

### Android Native APIs
```kotlin
// WiFi Direct
WifiP2pManager.discoverPeers() → ZhtpNative.onWifiDirectPeerDiscovered()
WifiP2pManager.requestConnectionInfo() → ZhtpNative.onWifiDirectConnectionChanged()

// Bluetooth
BluetoothAdapter.startLeScan() → ZhtpNative.onBluetoothDeviceDiscovered()
BluetoothGatt.connect() → ZhtpNative.onBluetoothConnectionChanged()
```

### iOS Native Frameworks
```swift
// MultipeerConnectivity
MCNearbyServiceBrowser.foundPeer → ZhtpClient.notifyMultipeerPeerDiscovered()
MCSession.didChange state → ZhtpClient.notifyMultipeerStateChanged()
MCSession.didReceive data → ZhtpClient.notifyMultipeerDataReceived()

// CoreBluetooth
CBCentralManager.didDiscover → ZhtpClient.notifyBluetoothPeripheralDiscovered()
CBPeripheral.didConnect → ZhtpClient.notifyBluetoothStateChanged()
CBCharacteristic.didUpdateValue → ZhtpClient.notifyBluetoothDataReceived()
```

## 🛠️ Build Commands

### Android
```bash
# Prerequisites
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
export ANDROID_NDK_HOME=/path/to/ndk

# Build
cd lib-network/src/mobile/examples/android
chmod +x build_android.sh
./build_android.sh

# Output
target/android-libs/jniLibs/arm64-v8a/liblib_network.so
```

### iOS
```bash
# Prerequisites
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# Build
cd lib-network/src/mobile/examples/ios
chmod +x build_xcframework.sh
./build_xcframework.sh

# Output
target/ios-framework/ZhtpFramework.xcframework
```

## 📝 Required Permissions

### Android (AndroidManifest.xml)
```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<uses-permission android:name="android.permission.CHANGE_WIFI_STATE" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.BLUETOOTH_SCAN" />
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
<uses-permission android:name="android.permission.NEARBY_WIFI_DEVICES" />
```

### iOS (Info.plist)
```xml
<key>NSBluetoothAlwaysUsageDescription</key>
<string>ZHTP uses Bluetooth for mesh networking</string>
<key>NSLocalNetworkUsageDescription</key>
<string>ZHTP uses local network for peer discovery</string>
<key>NSBonjourServices</key>
<array><string>_zhtp._tcp</string></array>
```

## 📊 JSON Response Format

### Success Response
```json
{
  "success": true,
  "node_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error message here"
}
```

### Node Status
```json
{
  "node_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "Running",
  "connected_peers": 3,
  "config": {
    "enable_wifi_direct": true,
    "enable_bluetooth": true,
    "enable_mdns": true,
    "port": 9333,
    "device_type": "client"
  }
}
```

### Discovered Peers
```json
[
  {
    "node_id": "peer-uuid",
    "address": "192.168.1.100:9333",
    "port": 9333,
    "is_router": true
  }
]
```

## 🔧 Common Issues & Solutions

| Issue | Platform | Solution |
|-------|----------|----------|
| Library not found | Android | Check .so files in `jniLibs/arm64-v8a/` |
| Symbol not found | iOS | Ensure framework is "Embed & Sign" |
| WiFi Direct fails | Android | Enable Location + grant permissions |
| MultipeerConnectivity silent | iOS | Check Info.plist privacy descriptions |
| Node crashes on start | Both | Check logs: `adb logcat` or Xcode console |
| Peers not discovered | Both | Ensure Bluetooth/WiFi enabled on device |

## 📚 Files Created

```
lib-network/src/mobile/
├── mod.rs                      # 300 lines - Common FFI layer
├── android.rs                  # 250 lines - Android JNI bindings  
├── ios.rs                      # 300 lines - iOS C FFI bindings
├── README.md                   # Complete API documentation
├── INTEGRATION_GUIDE.md        # Step-by-step integration guide
├── IMPLEMENTATION_SUMMARY.md   # Technical implementation details
└── examples/
    ├── android/
    │   ├── ZhtpNative.kt      # 100 lines - Kotlin wrapper
    │   ├── ZhtpService.kt     # 150 lines - Foreground service
    │   └── build_android.sh   # 100 lines - Build script
    └── ios/
        ├── ZhtpClient.swift    # 250 lines - Swift wrapper
        └── build_xcframework.sh # 150 lines - XCFramework builder
```

## 🎯 What's Next?

1. **Test the FFI layer** - Build and test on both platforms
2. **Create mobile UIs** - Android (Jetpack Compose) + iOS (SwiftUI)
3. **Firebase setup** - App Distribution, Cloud Functions, FCM
4. **Beta testing** - Deploy to testers via Firebase
5. **Production** - Launch apps on Play Store and App Store

## 💡 Pro Tips

- **Android**: Use foreground service to keep mesh running in background
- **iOS**: Enable background modes for network authentication
- **Both**: Test on physical devices (emulators have limited networking)
- **Battery**: Profile battery usage and optimize discovery intervals
- **Security**: ZHTP handles encryption, no additional work needed
- **Debugging**: Enable verbose logging in Rust with `RUST_LOG=debug`

## 🆘 Need Help?

- 📖 Read: `INTEGRATION_GUIDE.md` for detailed steps
- 📖 Read: `README.md` for API reference
- 🐛 Check: GitHub Issues for known problems
- 💬 Ask: Community support channels

---

**Everything is ready! Start building your mobile mesh networking app now! 🚀**
