//
// Copyright 2018 Wultra s.r.o.
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

import Foundation
import PowerAuth2

/// The `PowerAuthSecureDataStore` implements `SecureDataStore` interface with using
/// `PowerAuth2.PA2Keychain` as underlying data storage. To initialize the data store,
/// you have to provide keychain identifier and optionally access group, if the cached
/// data has to be stored across multiple applications.
///
/// To use this class, you have to add following line into your `Podfile`:
/// ```
/// pod 'WultraSSLPinning/PowerAuthIntegration'
/// ```
public class PowerAuthSecureDataStore: SecureDataStore {
    
    /// The default keychain identifier.
    public static let defaultKeychainIdentifier = "io.getlime.PowerAuthKeychain.WultraCertStore"
    
    /// Underlying keychain object used for data storage.
    private let keychain: PA2Keychain
    
    /// Constructs
    public init(
        keychainIdentifier: String = PowerAuthSecureDataStore.defaultKeychainIdentifier,
        accessGroup: String? = nil)
    {
        keychain = PA2Keychain(identifier: keychainIdentifier, accessGroup: accessGroup)
    }
    
    // MARK: - SecureDataStore protocol
    
    public func save(data: Data, for key: String) -> Bool {
        if keychain.containsData(forKey: key) {
            return keychain.updateValue(data, forKey: key) == .ok
        } else {
            return keychain.addValue(data, forKey: key) == .ok
        }
    }
    
    public func load(dataFor key: String) -> Data? {
        return keychain.data(forKey: key, status: nil)
    }
    
    public func remove(dataFor key: String) {
        keychain.deleteData(forKey: key)
    }
}
