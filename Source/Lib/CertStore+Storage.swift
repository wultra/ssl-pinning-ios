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

internal extension CertStore {
    
    /// Loads cached data from the underlying persistent storage.
    /// Returns nil if no such data is stored.
    internal func loadCachedData() -> CachedData? {
        guard let encodedData = secureDataStore.load(dataFor: self.instanceIdentifier) else {
            return nil
        }
        guard let cachedData = try? jsonDecoder().decode(CachedData.self, from: encodedData) else {
            return nil
        }
        return cachedData
    }
    
    /// Saves cached data to the underlying persistent storage.
    internal func saveDataToCache(data: CachedData) {
        guard let encodedData = try? jsonEncoder().encode(data) else {
            return
        }
        _ = secureDataStore.save(data: encodedData, for: self.instanceIdentifier)
    }
    
    /// Loads fallback certificate from configuration provided in CertStore initialization.
    internal func loadFallbackCertificate() -> CertificateInfo? {
        guard let fallbackData = configuration.fallbackCertificateData else {
            return nil
        }
        guard let fallbackEntry = try? jsonDecoder().decode(GetFingerprintsResponse.Entry.self, from: fallbackData) else {
            return nil
        }
        return CertificateInfo(from: fallbackEntry)
    }
    
    /// Returns new instance of `JSONDecoder`, preconfigured for our data types deserialization.
    internal func jsonDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dataDecodingStrategy = .base64
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
    
    /// Returns new instance of `JSONEncoder`, preconfigured for our data types serialization.
    internal func jsonEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dataEncodingStrategy = .base64
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }
}
