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
    func loadCachedData() -> CachedData? {
        guard let encodedData = secureDataStore.loadData(forKey: self.instanceIdentifier) else {
            return nil
        }
        guard let cachedData = try? JSONUtils.decoder.decode(CachedData.self, from: encodedData) else {
            return nil
        }
        return cachedData
    }
    
    /// Saves cached data to the underlying persistent storage.
    func saveDataToCache(data: CachedData) {
        guard let encodedData = try? JSONUtils.encoder.encode(data) else {
            return
        }
        secureDataStore.save(data: encodedData, forKey: self.instanceIdentifier)
    }
    
    /// Loads fallback certificate from configuration provided in CertStore initialization.
    func loadFallbackCertificates() -> [CertificateInfo] {
        guard let fallbackData = configuration.fallbackCertificatesData else {
            return []
        }
        guard let fallback = try? JSONUtils.decoder.decode(ServerResponse.self, from: fallbackData) else {
            return []
        }
        return fallback.fingerprints.map { CertificateInfo(from: $0) }
    }
}
