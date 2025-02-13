//
// Copyright 2025 Wultra s.r.o.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions
// and limitations under the License.
//

/// The `KeychainSecureDataStore` implements `SecureDataStore` interface with the
/// system keychain as underlying data storage. To initialize the data store,
/// you have to provide keychain identifier and optional access group, if the cached
/// data has to be stored across multiple applications.
public class KeychainSecureDataStore: SecureDataStore {
    
    /// Used for the `kSecAttrService` property to uniquely identify this keychain accessor.
    let keychainIdentifier: String
    
    /// AccessGroup is used for the `kSecAttrAccessGroup` property to identify which Keychain Access Group this entry belongs to.
    /// This allows you to use the `KeychainSecureDataStore` with shared keychain access between different applications.
    public let accessGroup: String?
    
    public static let defaultKeychainIdentifier = "com.wultra.WultraCertStore"
    
    /// Initializes secure data store based on system keychain services.
    ///
    /// - Parameter keychainIdentifier: Identifier of the service.
    /// - Parameter accessGroup: Access group for the Keychain Sharing
    public init(keychainIdentifier: String = KeychainSecureDataStore.defaultKeychainIdentifier, accessGroup: String? = nil) {
        self.keychainIdentifier = keychainIdentifier
        self.accessGroup = accessGroup
    }
    
    // MARK: - SecureDataStore protocol
    
    public func save(data: Data, forKey key: String) -> Bool {
        var keychainQueryDictionary: [String: Any] = setupKeychainQueryDictionary(forKey: key)
        
        
        // Assign default protection - Protect the keychain entry so it's only valid when the device is unlocked
        keychainQueryDictionary[SecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        // Do not synchronize in the icloud
        keychainQueryDictionary[SecAttrSynchronizable] = kCFBooleanFalse
        // Set the data
        keychainQueryDictionary[SecValueData] = data
        
        let status: OSStatus = SecItemAdd(keychainQueryDictionary as CFDictionary, nil)
        
        if status == errSecSuccess {
            return true
        } else if status == errSecDuplicateItem {
            return update(data, forKey: key)
        } else {
            return false
        }
    }
    
    public func loadData(forKey key: String) -> Data? {
        var keychainQueryDictionary = setupKeychainQueryDictionary(forKey: key)
        
        // Limit search results to one
        keychainQueryDictionary[SecMatchLimit] = kSecMatchLimitOne
        
        // Specify we want Data/CFData returned
        keychainQueryDictionary[SecReturnData] = kCFBooleanTrue
        
        // Search
        var result: AnyObject?
        let status = SecItemCopyMatching(keychainQueryDictionary as CFDictionary, &result)
        
        return status == noErr ? result as? Data : nil
    }
    
    public func removeData(forKey key: String) {
        let keychainQueryDictionary = setupKeychainQueryDictionary(forKey: key)

        // Delete
        let status: OSStatus = SecItemDelete(keychainQueryDictionary as CFDictionary)

        if status != errSecSuccess {
            WultraDebug.error("Failed to remove data from keychain for key \(key): status \(status)")
        }
    }

    // MARK: - Private Methods
    
    /// Update existing data associated with a specified key name. The existing data will be overwritten by the new data.
    private func update(_ value: Data, forKey key: String) -> Bool {
        
        let keychainQueryDictionary = setupKeychainQueryDictionary(forKey: key)
        let updateDictionary = [SecValueData: value]
        
        // Update
        let status: OSStatus = SecItemUpdate(keychainQueryDictionary as CFDictionary, updateDictionary as CFDictionary)

        return status == errSecSuccess
    }
    
    private func setupKeychainQueryDictionary(forKey key: String) -> [String: Any] {
        // Setup default access as generic password (rather than a certificate, internet password, etc)
        var keychainQueryDictionary: [String: Any] = [SecClass: kSecClassGenericPassword]
        
        // Uniquely identify this keychain accessor
        keychainQueryDictionary[SecAttrService] = keychainIdentifier
        
        // Set the keychain access group if defined
        if let accessGroup = self.accessGroup {
            keychainQueryDictionary[SecAttrAccessGroup] = accessGroup
        }
        
        keychainQueryDictionary[SecAttrAccount] = key
        
        return keychainQueryDictionary
    }
    
    // shortcuts to constants

    private let SecMatchLimit = kSecMatchLimit as String
    private let SecReturnData = kSecReturnData as String
    private let SecValueData = kSecValueData as String
    private let SecAttrAccessible = kSecAttrAccessible as String
    private let SecClass = kSecClass as String
    private let SecAttrService = kSecAttrService as String
    private let SecAttrAccount = kSecAttrAccount as String
    private let SecAttrAccessGroup = kSecAttrAccessGroup as String
    private let SecAttrSynchronizable = kSecAttrSynchronizable as String
}
