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

///
/// The `CertStore` class implements dynamic SSL certificate fingerprint validation.
///
/// For more information, please read our [online documentation](https://github.com/wultra/ssl-pinning-ios).
///
public class CertStore {
    
    // MARK: - Public interface
    
    /// Initializes `CertStore` with provided configuration, crypto provider and secure data store.
    ///
    /// - Parameter configuration: Configuration for the CertStore object
    /// - Parameter cryptoProvider: Instance of `CryptoProvider` object
    /// - Parameter secureDataStore: Instance of `SecureDataStore` object
    public init(configuration: CertStoreConfiguration, cryptoProvider: CryptoProvider, secureDataStore: SecureDataStore) {
        configuration.validate(cryptoProvider: cryptoProvider)
        self.configuration = configuration
        self.cryptoProvider = cryptoProvider
        self.secureDataStore = secureDataStore
        self.remoteDataProvider = RestAPI(baseURL: configuration.serviceUrl, sslValidationStrategy: configuration.sslValidationStrategy)
    }
    
    /// Internal constructor, suitable for unit tests.
    internal init(configuration: CertStoreConfiguration, cryptoProvider: CryptoProvider, secureDataStore: SecureDataStore, remoteDataProvider: RemoteDataProvider) {
        configuration.validate(cryptoProvider: cryptoProvider)
        self.configuration = configuration
        self.cryptoProvider = cryptoProvider
        self.secureDataStore = secureDataStore
        self.remoteDataProvider = remoteDataProvider
    }

    /// Returns identifier from `CertStoreConfiguration` structure or "default", if no identifier was configured.
    public var instanceIdentifier: String {
        return configuration.identifier ?? "default"
    }

    /// Contains configuration which was provided during the object initialization.
    public let configuration: CertStoreConfiguration
    
    /// Removes all cached data from the memory and the persistent storage.
    ///
    /// ## ⚠️ WARNING
    ///
    /// It's recommended to use this function only for testing or debugging purposes.
    /// If you reset the cache, then all `validate()` functions will return "empty" result,
    /// so you need to update certificates afterwards.
    public func reset() {
        
        WultraDebug.warning("CertStore: reset() should not be used in production build.")
        
        semaphore.wait()
        defer { semaphore.signal() }
        
        cachedData = nil
        secureDataStore.removeData(forKey: self.instanceIdentifier)
    }
    
    // MARK: - Internal members

    let cryptoProvider: CryptoProvider
    let secureDataStore: SecureDataStore
    let remoteDataProvider: RemoteDataProvider
    
    // MARK: - Private members
    
    fileprivate let semaphore = DispatchSemaphore(value: 1)
    
    fileprivate var cacheIsLoaded = false
    fileprivate var cachedData: CachedData?
    fileprivate var fallbackCertificates = [CertificateInfo]()
}


// MARK: - Thread safe access to internal data

internal extension CertStore {
    
    /// Internal function returns array of `CertificateInfo` objects. The array
    /// contains the fallback certificate, if provided, at the last position.
    /// The operation is thread safe.
    func getCertificates() -> [CertificateInfo] {
        // Acquire semaphore
        semaphore.wait()
        defer { semaphore.signal() }
        
        // At first, try to restore cache
        restoreCache()
        
        var result = cachedData?.certificates ?? []
        result.append(contentsOf: fallbackCertificates)
        return result
    }
    
    /// Internal function returns whole `CachedData` structure. The operation is thread safe.
    func getCachedData() -> CachedData? {
        // Acquire semaphore
        semaphore.wait()
        defer { semaphore.signal() }
        
        // At first, try to restore cache
        restoreCache()
        
        return cachedData
    }
    
    /// Internal function allows atomic update of `CachedData` structure. The provided
    /// update closure is called when exclusive access to data is guaranteed.
    func updateCachedData(updateClosure: (CachedData?)->CachedData?) -> Void {
        // Acquire semaphore
        semaphore.wait()
        defer { semaphore.signal() }
        
        // At first, try to restore cache
        restoreCache()
        
        // Call closure with cached data object
        if let newData = updateClosure(cachedData) {
            cachedData = newData
            saveDataToCache(data: newData)
        }
    }
    
    /// Private function tries to load cached data from secureDataStore
    /// and fallback certificate from the configuration. This operation is performed
    /// only once per object's lifetime.
    private func restoreCache() {
        if !cacheIsLoaded {
            cachedData = loadCachedData()
            fallbackCertificates = loadFallbackCertificates()
            cacheIsLoaded = true
        }
    }
}

