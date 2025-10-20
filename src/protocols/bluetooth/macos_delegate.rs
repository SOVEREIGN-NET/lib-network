// Objective-C delegate implementation for Core Bluetooth on macOS
// Creates custom NSObject subclasses that conform to Core Bluetooth protocols

#[cfg(target_os = "macos")]
use objc::declare::ClassDecl;
#[cfg(target_os = "macos")]
use objc::runtime::{Class, Object, Sel, Protocol, BOOL, YES, NO};
#[cfg(target_os = "macos")]
use objc::{msg_send, sel, sel_impl, Encode, Encoding};
#[cfg(target_os = "macos")]
use std::os::raw::c_void;
#[cfg(target_os = "macos")]
use std::sync::Once;
#[cfg(target_os = "macos")]
use tracing::{info, warn, error, debug};

#[cfg(target_os = "macos")]
use super::macos_core::{CoreBluetoothEvent, BluetoothState};

#[cfg(target_os = "macos")]
use super::macos_error::{parse_nserror, log_nserror, NSErrorInfo};

/// One-time registration of custom delegate classes
#[cfg(target_os = "macos")]
static REGISTER_DELEGATES: Once = Once::new();

/// Register all custom Core Bluetooth delegate classes
#[cfg(target_os = "macos")]
pub unsafe fn register_delegate_classes() {
    REGISTER_DELEGATES.call_once(|| {
        register_central_manager_delegate();
        register_peripheral_manager_delegate();
        register_peripheral_delegate();
        info!("✅ Core Bluetooth delegate classes registered");
    });
}

/// Register ZhtpCBCentralManagerDelegate class
#[cfg(target_os = "macos")]
unsafe fn register_central_manager_delegate() {
    let superclass = Class::get("NSObject").expect("NSObject class not found");
    let mut decl = ClassDecl::new("ZhtpCBCentralManagerDelegate", superclass)
        .expect("Failed to declare ZhtpCBCentralManagerDelegate class");
    
    // Add ivar to store the event sender pointer (as raw pointer)
    decl.add_ivar::<usize>("event_sender_ptr");
    
    // Add protocol conformance to CBCentralManagerDelegate
    // Note: Protocol may not be available at runtime without importing CoreBluetooth framework
    if let Some(protocol) = Protocol::get("CBCentralManagerDelegate") {
        decl.add_protocol(protocol);
        debug!("Added CBCentralManagerDelegate protocol");
    } else {
        warn!("CBCentralManagerDelegate protocol not found - continuing without it");
    }
    
    // Implement: - (void)centralManagerDidUpdateState:(CBCentralManager *)central
    extern "C" fn central_manager_did_update_state(this: &Object, _cmd: Sel, central: *mut Object) {
        unsafe {
            // Get state from CBCentralManager
            let state: i64 = msg_send![central, state];
            
            // Map to BluetoothState enum
            let bt_state = match state {
                0 => BluetoothState::Unknown,
                1 => BluetoothState::Resetting,
                2 => BluetoothState::Unsupported,
                3 => BluetoothState::Unauthorized,
                4 => BluetoothState::PoweredOff,
                5 => BluetoothState::PoweredOn,
                _ => BluetoothState::Unknown,
            };
            
            debug!("🔵 Delegate: centralManagerDidUpdateState: {:?}", bt_state);
            
            // Get event sender from ivar and send event
            let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::StateChanged(bt_state));
            }
        }
    }
    
    decl.add_method(
        sel!(centralManagerDidUpdateState:),
        central_manager_did_update_state as extern "C" fn(&Object, Sel, *mut Object)
    );
    
    // Implement: - (void)centralManager:didDiscoverPeripheral:advertisementData:RSSI:
    extern "C" fn central_manager_did_discover_peripheral(
        this: &Object,
        _cmd: Sel,
        central: *mut Object,
        peripheral: *mut Object,
        advertisement_data: *mut Object,
        rssi: *mut Object,
    ) {
        unsafe {
            // Get peripheral identifier (UUID)
            let peripheral_id_obj: *mut Object = msg_send![peripheral, identifier];
            let id_string: *mut Object = msg_send![peripheral_id_obj, UUIDString];
            let id_cstr: *const i8 = msg_send![id_string, UTF8String];
            let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
            
            // Get peripheral name (may be nil)
            let name_obj: *mut Object = msg_send![peripheral, name];
            let name = if !name_obj.is_null() {
                let name_cstr: *const i8 = msg_send![name_obj, UTF8String];
                Some(std::ffi::CStr::from_ptr(name_cstr).to_string_lossy().to_string())
            } else {
                None
            };
            
            // Get RSSI value
            let rssi_value: i32 = msg_send![rssi, intValue];
            
            // Parse advertisement data (NSDictionary)
            let mut ad_data = std::collections::HashMap::new();
            if !advertisement_data.is_null() {
                let keys: *mut Object = msg_send![advertisement_data, allKeys];
                let count: usize = msg_send![keys, count];
                
                for i in 0..count {
                    let key: *mut Object = msg_send![keys, objectAtIndex: i];
                    let value: *mut Object = msg_send![advertisement_data, objectForKey: key];
                    
                    if !key.is_null() {
                        let key_cstr: *const i8 = msg_send![key, UTF8String];
                        let key_str = std::ffi::CStr::from_ptr(key_cstr).to_string_lossy().to_string();
                        
                        // Convert value to string (simplified)
                        if !value.is_null() {
                            let value_desc: *mut Object = msg_send![value, description];
                            let value_cstr: *const i8 = msg_send![value_desc, UTF8String];
                            let value_str = std::ffi::CStr::from_ptr(value_cstr).to_string_lossy().to_string();
                            ad_data.insert(key_str, value_str);
                        }
                    }
                }
            }
            
            debug!("🔍 Delegate: Discovered {} ({}), RSSI: {}", 
                   name.as_deref().unwrap_or("Unknown"), identifier, rssi_value);
            
            // Send event
            let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::PeripheralDiscovered {
                    identifier,
                    name,
                    rssi: rssi_value,
                    advertisement_data: ad_data,
                    peripheral_ptr: peripheral as usize,
                });
            }
        }
    }
    
    decl.add_method(
        sel!(centralManager:didDiscoverPeripheral:advertisementData:RSSI:),
        central_manager_did_discover_peripheral as extern "C" fn(&Object, Sel, *mut Object, *mut Object, *mut Object, *mut Object)
    );
    
    // Implement: - (void)centralManager:didConnectPeripheral:
    extern "C" fn central_manager_did_connect_peripheral(
        this: &Object,
        _cmd: Sel,
        central: *mut Object,
        peripheral: *mut Object,
    ) {
        unsafe {
            let peripheral_id_obj: *mut Object = msg_send![peripheral, identifier];
            let id_string: *mut Object = msg_send![peripheral_id_obj, UUIDString];
            let id_cstr: *const i8 = msg_send![id_string, UTF8String];
            let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
            
            debug!("✅ Delegate: Connected to {}", identifier);
            
            let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::PeripheralConnected(identifier));
            }
        }
    }
    
    decl.add_method(
        sel!(centralManager:didConnectPeripheral:),
        central_manager_did_connect_peripheral as extern "C" fn(&Object, Sel, *mut Object, *mut Object)
    );
    
    // Implement: - (void)centralManager:didDisconnectPeripheral:error:
    extern "C" fn central_manager_did_disconnect_peripheral(
        this: &Object,
        _cmd: Sel,
        central: *mut Object,
        peripheral: *mut Object,
        error: *mut Object,
    ) {
        unsafe {
            let peripheral_id_obj: *mut Object = msg_send![peripheral, identifier];
            let id_string: *mut Object = msg_send![peripheral_id_obj, UUIDString];
            let id_cstr: *const i8 = msg_send![id_string, UTF8String];
            let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
            
            // Use comprehensive error parsing
            if let Some(error_info) = parse_nserror(error) {
                // Log with appropriate level based on error type
                if error_info.cb_error.is_some() {
                    warn!("❌ Delegate: Disconnected from {} - {}", identifier, error_info.to_error_message());
                } else {
                    warn!("❌ Delegate: Disconnected from {} - {}", identifier, error_info.localized_description);
                }
            } else {
                debug!("✅ Delegate: Clean disconnect from {}", identifier);
            }
            
            let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::PeripheralDisconnected(identifier));
            }
        }
    }
    
    decl.add_method(
        sel!(centralManager:didDisconnectPeripheral:error:),
        central_manager_did_disconnect_peripheral as extern "C" fn(&Object, Sel, *mut Object, *mut Object, *mut Object)
    );
    
    // Implement: - (void)centralManager:didFailToConnectPeripheral:error:
    extern "C" fn central_manager_did_fail_to_connect(
        this: &Object,
        _cmd: Sel,
        central: *mut Object,
        peripheral: *mut Object,
        error: *mut Object,
    ) {
        unsafe {
            let peripheral_id_obj: *mut Object = msg_send![peripheral, identifier];
            let id_string: *mut Object = msg_send![peripheral_id_obj, UUIDString];
            let id_cstr: *const i8 = msg_send![id_string, UTF8String];
            let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
            
            // Use comprehensive error parsing
            if let Some(error_info) = parse_nserror(error) {
                error!("❌ Delegate: Failed to connect to {} - {}", identifier, error_info.to_error_message());
                
                // Send ConnectionFailed event with detailed error information
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::ConnectionFailed {
                        peripheral_id: identifier,
                        error_message: error_info.to_error_message(),
                        error_code: error_info.code,
                        error_domain: error_info.domain,
                    });
                }
            } else {
                error!("❌ Delegate: Failed to connect to {} - Unknown error", identifier);
                
                // Send generic failure event
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::ConnectionFailed {
                        peripheral_id: identifier,
                        error_message: "Unknown connection error".to_string(),
                        error_code: -1,
                        error_domain: "Unknown".to_string(),
                    });
                }
            }
        }
    }
    
    decl.add_method(
        sel!(centralManager:didFailToConnectPeripheral:error:),
        central_manager_did_fail_to_connect as extern "C" fn(&Object, Sel, *mut Object, *mut Object, *mut Object)
    );
    
    decl.register();
    debug!("Registered ZhtpCBCentralManagerDelegate class");
}

/// Register ZhtpCBPeripheralManagerDelegate class
#[cfg(target_os = "macos")]
unsafe fn register_peripheral_manager_delegate() {
    let superclass = Class::get("NSObject").expect("NSObject class not found");
    let mut decl = ClassDecl::new("ZhtpCBPeripheralManagerDelegate", superclass)
        .expect("Failed to declare ZhtpCBPeripheralManagerDelegate class");
    
    // Add ivar to store the event sender pointer
    decl.add_ivar::<usize>("event_sender_ptr");
    
    // Add protocol conformance to CBPeripheralManagerDelegate
    if let Some(protocol) = Protocol::get("CBPeripheralManagerDelegate") {
        decl.add_protocol(protocol);
        debug!("Added CBPeripheralManagerDelegate protocol");
    } else {
        warn!("CBPeripheralManagerDelegate protocol not found - continuing without it");
    }
    
    // Implement: - (void)peripheralManagerDidUpdateState:(CBPeripheralManager *)peripheral
    extern "C" fn peripheral_manager_did_update_state(this: &Object, _cmd: Sel, peripheral: *mut Object) {
        unsafe {
            let state: i64 = msg_send![peripheral, state];
            
            let bt_state = match state {
                0 => BluetoothState::Unknown,
                1 => BluetoothState::Resetting,
                2 => BluetoothState::Unsupported,
                3 => BluetoothState::Unauthorized,
                4 => BluetoothState::PoweredOff,
                5 => BluetoothState::PoweredOn,
                _ => BluetoothState::Unknown,
            };
            
            debug!("🔵 Delegate: peripheralManagerDidUpdateState: {:?}", bt_state);
            
            let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::StateChanged(bt_state));
            }
        }
    }
    
    decl.add_method(
        sel!(peripheralManagerDidUpdateState:),
        peripheral_manager_did_update_state as extern "C" fn(&Object, Sel, *mut Object)
    );
    
    // Implement: - (void)peripheralManager:didAddService:error:
    extern "C" fn peripheral_manager_did_add_service(
        this: &Object,
        _cmd: Sel,
        peripheral: *mut Object,
        service: *mut Object,
        error: *mut Object,
    ) {
        unsafe {
            // Use comprehensive error parsing
            if let Some(error_info) = parse_nserror(error) {
                error!("❌ Delegate: Failed to add service - {}", error_info.to_error_message());
            } else {
                let service_uuid_obj: *mut Object = msg_send![service, UUID];
                let uuid_string: *mut Object = msg_send![service_uuid_obj, UUIDString];
                let uuid_cstr: *const i8 = msg_send![uuid_string, UTF8String];
                let uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy().to_string();
                
                debug!("✅ Delegate: Added service: {}", uuid);
                
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::ServiceAdded(uuid));
                }
            }
        }
    }
    
    decl.add_method(
        sel!(peripheralManager:didAddService:error:),
        peripheral_manager_did_add_service as extern "C" fn(&Object, Sel, *mut Object, *mut Object, *mut Object)
    );
    
    // Implement: - (void)peripheralManagerDidStartAdvertising:error:
    extern "C" fn peripheral_manager_did_start_advertising(
        this: &Object,
        _cmd: Sel,
        peripheral: *mut Object,
        error: *mut Object,
    ) {
        unsafe {
            // Use comprehensive error parsing
            if let Some(error_info) = parse_nserror(error) {
                error!("❌ Delegate: Failed to start advertising - {}", error_info.to_error_message());
            } else {
                debug!("📢 Delegate: Started advertising");
                
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::AdvertisingStarted);
                }
            }
        }
    }
    
    decl.add_method(
        sel!(peripheralManagerDidStartAdvertising:error:),
        peripheral_manager_did_start_advertising as extern "C" fn(&Object, Sel, *mut Object, *mut Object)
    );
    
    decl.register();
    debug!("Registered ZhtpCBPeripheralManagerDelegate class");
}

/// Register ZhtpCBPeripheralDelegate class for GATT operations
#[cfg(target_os = "macos")]
unsafe fn register_peripheral_delegate() {
    let superclass = Class::get("NSObject").expect("NSObject class not found");
    let mut decl = ClassDecl::new("ZhtpCBPeripheralDelegate", superclass)
        .expect("Failed to declare ZhtpCBPeripheralDelegate class");
    
    // Add ivar to store the event sender pointer
    decl.add_ivar::<usize>("event_sender_ptr");
    
    // Add protocol conformance to CBPeripheralDelegate
    if let Some(protocol) = Protocol::get("CBPeripheralDelegate") {
        decl.add_protocol(protocol);
        debug!("Added CBPeripheralDelegate protocol");
    } else {
        warn!("CBPeripheralDelegate protocol not found - continuing without it");
    }
    
    // Implement: - (void)peripheral:didDiscoverServices:
    extern "C" fn peripheral_did_discover_services(
        this: &Object,
        _cmd: Sel,
        peripheral: *mut Object,
        error: *mut Object,
    ) {
        unsafe {
            let peripheral_id_obj: *mut Object = msg_send![peripheral, identifier];
            let id_string: *mut Object = msg_send![peripheral_id_obj, UUIDString];
            let id_cstr: *const i8 = msg_send![id_string, UTF8String];
            let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
            
            // Use comprehensive error parsing
            if let Some(error_info) = parse_nserror(error) {
                error!("❌ Delegate: Service discovery failed for {} - {}", identifier, error_info.to_error_message());
                
                // Send error event
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::ServiceDiscoveryFailed {
                        peripheral_id: identifier,
                        error_message: error_info.to_error_message(),
                        error_code: error_info.code,
                    });
                }
            } else {
                // Success - extract discovered services
                let services_array: *mut Object = msg_send![peripheral, services];
                if !services_array.is_null() {
                    let count: usize = msg_send![services_array, count];
                    let mut service_uuids = Vec::new();
                    
                    for i in 0..count {
                        let service: *mut Object = msg_send![services_array, objectAtIndex: i];
                        let uuid_obj: *mut Object = msg_send![service, UUID];
                        let uuid_string: *mut Object = msg_send![uuid_obj, UUIDString];
                        let uuid_cstr: *const i8 = msg_send![uuid_string, UTF8String];
                        let uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy().to_string();
                        service_uuids.push(uuid);
                    }
                    
                    debug!("🔍 Delegate: Discovered {} services for {}", service_uuids.len(), identifier);
                    
                    let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                    if sender_ptr != 0 {
                        let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                        let _ = sender.send(CoreBluetoothEvent::ServicesDiscovered {
                            peripheral_id: identifier,
                            service_uuids,
                        });
                    }
                }
            }
        }
    }
    
    decl.add_method(
        sel!(peripheral:didDiscoverServices:),
        peripheral_did_discover_services as extern "C" fn(&Object, Sel, *mut Object, *mut Object)
    );
    
    // Implement: - (void)peripheral:didDiscoverCharacteristicsForService:error:
    extern "C" fn peripheral_did_discover_characteristics(
        this: &Object,
        _cmd: Sel,
        peripheral: *mut Object,
        service: *mut Object,
        error: *mut Object,
    ) {
        unsafe {
            let peripheral_id_obj: *mut Object = msg_send![peripheral, identifier];
            let id_string: *mut Object = msg_send![peripheral_id_obj, UUIDString];
            let id_cstr: *const i8 = msg_send![id_string, UTF8String];
            let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
            
            let service_uuid_obj: *mut Object = msg_send![service, UUID];
            let service_uuid_string: *mut Object = msg_send![service_uuid_obj, UUIDString];
            let service_uuid_cstr: *const i8 = msg_send![service_uuid_string, UTF8String];
            let service_uuid = std::ffi::CStr::from_ptr(service_uuid_cstr).to_string_lossy().to_string();
            
            // Use comprehensive error parsing
            if let Some(error_info) = parse_nserror(error) {
                error!("❌ Delegate: Characteristic discovery failed for service {} - {}", 
                       service_uuid, error_info.to_error_message());
                
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::CharacteristicDiscoveryFailed {
                        peripheral_id: identifier,
                        service_uuid,
                        error_message: error_info.to_error_message(),
                        error_code: error_info.code,
                    });
                }
            } else {
                // Success - extract characteristics
                let characteristics_array: *mut Object = msg_send![service, characteristics];
                if !characteristics_array.is_null() {
                    let count: usize = msg_send![characteristics_array, count];
                    let mut char_uuids = Vec::new();
                    
                    for i in 0..count {
                        let characteristic: *mut Object = msg_send![characteristics_array, objectAtIndex: i];
                        let uuid_obj: *mut Object = msg_send![characteristic, UUID];
                        let uuid_string: *mut Object = msg_send![uuid_obj, UUIDString];
                        let uuid_cstr: *const i8 = msg_send![uuid_string, UTF8String];
                        let uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy().to_string();
                        char_uuids.push(uuid);
                    }
                    
                    debug!("🔍 Delegate: Discovered {} characteristics for service {}", 
                           char_uuids.len(), service_uuid);
                    
                    let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                    if sender_ptr != 0 {
                        let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                        let _ = sender.send(CoreBluetoothEvent::CharacteristicsDiscovered {
                            peripheral_id: identifier,
                            service_uuid,
                            characteristic_uuids: char_uuids,
                        });
                    }
                }
            }
        }
    }
    
    decl.add_method(
        sel!(peripheral:didDiscoverCharacteristicsForService:error:),
        peripheral_did_discover_characteristics as extern "C" fn(&Object, Sel, *mut Object, *mut Object, *mut Object)
    );
    
    // Implement: - (void)peripheral:didUpdateValueForCharacteristic:error:
    extern "C" fn peripheral_did_update_value(
        this: &Object,
        _cmd: Sel,
        peripheral: *mut Object,
        characteristic: *mut Object,
        error: *mut Object,
    ) {
        unsafe {
            let peripheral_id_obj: *mut Object = msg_send![peripheral, identifier];
            let id_string: *mut Object = msg_send![peripheral_id_obj, UUIDString];
            let id_cstr: *const i8 = msg_send![id_string, UTF8String];
            let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
            
            let char_uuid_obj: *mut Object = msg_send![characteristic, UUID];
            let char_uuid_string: *mut Object = msg_send![char_uuid_obj, UUIDString];
            let char_uuid_cstr: *const i8 = msg_send![char_uuid_string, UTF8String];
            let char_uuid = std::ffi::CStr::from_ptr(char_uuid_cstr).to_string_lossy().to_string();
            
            // Use comprehensive error parsing
            if let Some(error_info) = parse_nserror(error) {
                error!("❌ Delegate: Read failed for characteristic {} - {}", 
                       char_uuid, error_info.to_error_message());
                
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::CharacteristicReadFailed {
                        peripheral_id: identifier,
                        characteristic_uuid: char_uuid,
                        error_message: error_info.to_error_message(),
                        error_code: error_info.code,
                    });
                }
            } else {
                // Success - extract value
                let value: *mut Object = msg_send![characteristic, value];
                let data = if !value.is_null() {
                    let length: usize = msg_send![value, length];
                    let bytes: *const u8 = msg_send![value, bytes];
                    std::slice::from_raw_parts(bytes, length).to_vec()
                } else {
                    Vec::new()
                };
                
                debug!("📖 Delegate: Read {} bytes from characteristic {}", data.len(), char_uuid);
                
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::CharacteristicValueUpdated {
                        peripheral_id: identifier,
                        characteristic_uuid: char_uuid,
                        value: data,
                    });
                }
            }
        }
    }
    
    decl.add_method(
        sel!(peripheral:didUpdateValueForCharacteristic:error:),
        peripheral_did_update_value as extern "C" fn(&Object, Sel, *mut Object, *mut Object, *mut Object)
    );
    
    // Implement: - (void)peripheral:didWriteValueForCharacteristic:error:
    extern "C" fn peripheral_did_write_value(
        this: &Object,
        _cmd: Sel,
        peripheral: *mut Object,
        characteristic: *mut Object,
        error: *mut Object,
    ) {
        unsafe {
            let peripheral_id_obj: *mut Object = msg_send![peripheral, identifier];
            let id_string: *mut Object = msg_send![peripheral_id_obj, UUIDString];
            let id_cstr: *const i8 = msg_send![id_string, UTF8String];
            let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
            
            let char_uuid_obj: *mut Object = msg_send![characteristic, UUID];
            let char_uuid_string: *mut Object = msg_send![char_uuid_obj, UUIDString];
            let char_uuid_cstr: *const i8 = msg_send![char_uuid_string, UTF8String];
            let char_uuid = std::ffi::CStr::from_ptr(char_uuid_cstr).to_string_lossy().to_string();
            
            // Use comprehensive error parsing
            if let Some(error_info) = parse_nserror(error) {
                error!("❌ Delegate: Write failed for characteristic {} - {}", 
                       char_uuid, error_info.to_error_message());
                
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::CharacteristicWriteFailed {
                        peripheral_id: identifier,
                        characteristic_uuid: char_uuid,
                        error_message: error_info.to_error_message(),
                        error_code: error_info.code,
                    });
                }
            } else {
                debug!("✅ Delegate: Write completed for characteristic {}", char_uuid);
                
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::WriteCompleted {
                        peripheral_id: identifier,
                        characteristic_uuid: char_uuid,
                    });
                }
            }
        }
    }
    
    decl.add_method(
        sel!(peripheral:didWriteValueForCharacteristic:error:),
        peripheral_did_write_value as extern "C" fn(&Object, Sel, *mut Object, *mut Object, *mut Object)
    );
    
    // Implement: - (void)peripheral:didUpdateNotificationStateForCharacteristic:error:
    extern "C" fn peripheral_did_update_notification_state(
        this: &Object,
        _cmd: Sel,
        peripheral: *mut Object,
        characteristic: *mut Object,
        error: *mut Object,
    ) {
        unsafe {
            let peripheral_id_obj: *mut Object = msg_send![peripheral, identifier];
            let id_string: *mut Object = msg_send![peripheral_id_obj, UUIDString];
            let id_cstr: *const i8 = msg_send![id_string, UTF8String];
            let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
            
            let char_uuid_obj: *mut Object = msg_send![characteristic, UUID];
            let char_uuid_string: *mut Object = msg_send![char_uuid_obj, UUIDString];
            let char_uuid_cstr: *const i8 = msg_send![char_uuid_string, UTF8String];
            let char_uuid = std::ffi::CStr::from_ptr(char_uuid_cstr).to_string_lossy().to_string();
            
            // Use comprehensive error parsing
            if let Some(error_info) = parse_nserror(error) {
                error!("❌ Delegate: Notification state update failed for {} - {}", 
                       char_uuid, error_info.to_error_message());
                
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::NotificationStateFailed {
                        peripheral_id: identifier,
                        characteristic_uuid: char_uuid,
                        error_message: error_info.to_error_message(),
                        error_code: error_info.code,
                    });
                }
            } else {
                // Check if notifications are now enabled or disabled
                let is_notifying: bool = msg_send![characteristic, isNotifying];
                
                debug!("🔔 Delegate: Notification {} for characteristic {}", 
                       if is_notifying { "enabled" } else { "disabled" }, char_uuid);
                
                let sender_ptr: usize = *this.get_ivar("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::NotificationStateChanged {
                        peripheral_id: identifier,
                        characteristic_uuid: char_uuid,
                        enabled: is_notifying,
                    });
                }
            }
        }
    }
    
    decl.add_method(
        sel!(peripheral:didUpdateNotificationStateForCharacteristic:error:),
        peripheral_did_update_notification_state as extern "C" fn(&Object, Sel, *mut Object, *mut Object, *mut Object)
    );
    
    decl.register();
    debug!("Registered ZhtpCBPeripheralDelegate class");
}

/// Create an instance of ZhtpCBCentralManagerDelegate with event sender
#[cfg(target_os = "macos")]
pub unsafe fn create_central_manager_delegate_instance(
    event_sender: tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>
) -> *mut Object {
    // Ensure delegate class is registered
    register_delegate_classes();
    
    // Get the custom class
    let class = Class::get("ZhtpCBCentralManagerDelegate").expect("Delegate class not registered");
    
    // Create instance: [[ZhtpCBCentralManagerDelegate alloc] init]
    let delegate: *mut Object = msg_send![class, alloc];
    let delegate: *mut Object = msg_send![delegate, init];
    
    // Store event sender pointer in ivar
    // Box the sender to ensure it lives long enough
    let sender_box = Box::new(event_sender);
    let sender_ptr = Box::into_raw(sender_box) as usize;
    delegate.set_ivar("event_sender_ptr", sender_ptr);
    
    info!("✅ Created CBCentralManagerDelegate instance");
    delegate
}

/// Create an instance of ZhtpCBPeripheralManagerDelegate with event sender
#[cfg(target_os = "macos")]
pub unsafe fn create_peripheral_manager_delegate_instance(
    event_sender: tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>
) -> *mut Object {
    // Ensure delegate class is registered
    register_delegate_classes();
    
    // Get the custom class
    let class = Class::get("ZhtpCBPeripheralManagerDelegate").expect("Delegate class not registered");
    
    // Create instance
    let delegate: *mut Object = msg_send![class, alloc];
    let delegate: *mut Object = msg_send![delegate, init];
    
    // Store event sender pointer in ivar
    let sender_box = Box::new(event_sender);
    let sender_ptr = Box::into_raw(sender_box) as usize;
    delegate.set_ivar("event_sender_ptr", sender_ptr);
    
    info!("✅ Created CBPeripheralManagerDelegate instance");
    delegate
}

/// Create an instance of ZhtpCBPeripheralDelegate with event sender
#[cfg(target_os = "macos")]
pub unsafe fn create_peripheral_delegate_instance(
    event_sender: tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>
) -> *mut Object {
    // Ensure delegate class is registered
    register_delegate_classes();
    
    // Get the custom class
    let class = Class::get("ZhtpCBPeripheralDelegate").expect("Peripheral delegate class not registered");
    
    // Create instance
    let delegate: *mut Object = msg_send![class, alloc];
    let delegate: *mut Object = msg_send![delegate, init];
    
    // Store event sender pointer in ivar
    let sender_box = Box::new(event_sender);
    let sender_ptr = Box::into_raw(sender_box) as usize;
    delegate.set_ivar("event_sender_ptr", sender_ptr);
    
    info!("✅ Created CBPeripheralDelegate instance");
    delegate
}
