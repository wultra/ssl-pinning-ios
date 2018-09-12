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

@testable import WultraSSLPinning

extension GetFingerprintsResponse.Entry {
    
    /// Creates a new entry for common name and desired expiration
    static func create(commonName: String, expiration: Expiration, fingerprint: Data? = nil) -> GetFingerprintsResponse.Entry {
        return GetFingerprintsResponse.Entry(
            name: commonName,
            fingerprint: fingerprint ?? .random(count: 32),
            expires: expiration.toDate,
            signature: .random(count: 64)
        )
    }
}


class ResponseGenerator {

    var fingerprints: [GetFingerprintsResponse.Entry] = []
    
    /// Appends a new item at the end of fingerprints
    @discardableResult
    func append(commonName: String, expiration: Expiration = .valid, fingerprint: Data? = nil) -> ResponseGenerator {
        fingerprints.append(
            .create(commonName: commonName, expiration: expiration, fingerprint: fingerprint)
        )
        return self
    }
    
    /// Inserts a new intem at the beginning of fingerprints.
    @discardableResult
    func insertFirst(commonName: String, expiration: Expiration = .valid, fingerprint: Data? = nil) -> ResponseGenerator {
        fingerprints.insert(
            .create(commonName: commonName, expiration: expiration, fingerprint: fingerprint),
            at: 0
        )
        return self
    }
    
    /// Duplicates the last item from fingerprints array
    @discardableResult
    func appendLast() -> ResponseGenerator {
        if let last = fingerprints.last {
            fingerprints.append(last)
        }
        return self
    }
    
    /// Removes all entries
    @discardableResult
    func removeAll() -> ResponseGenerator {
        fingerprints.removeAll()
        return self
    }
    
    /// Generates response data from fingerprints.
    func data() -> Data {
        return GetFingerprintsResponse(fingerprints: fingerprints).toJSON()
    }
}
