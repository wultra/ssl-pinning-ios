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

fileprivate extension FingerprintEntry {
    
    /// Creates a new entry for common name and desired expiration
    static func create(commonName: String, expiration: Expiration, fingerprint: Data?, signature: Data?) -> FingerprintEntry {
        return FingerprintEntry(
            name: commonName,
            fingerprint: fingerprint ?? .random(count: 32),
            expires: expiration.toDate,
            signature: signature
        )
    }
}

extension ServerResponse {
    
    /// Creates a response with single fingerprint
    static func single(commonName: String, expiration: Expiration, fingerprint: Data? = nil, timestamp: Date? = nil) -> ServerResponse {
        return ServerResponse(fingerprints: [.create(commonName: commonName, expiration: expiration, fingerprint: fingerprint, signature: nil)], timestamp: timestamp)
    }
}

class ResponseGenerator {

    var fingerprints: [FingerprintEntry] = []
    var useTimestamp = false
    var signData: ((Data) -> Data)?
    
    /// Appends a new item at the end of fingerprints
    @discardableResult
    func append(commonName: String, expiration: Expiration = .valid, fingerprint: Data? = nil) -> ResponseGenerator {
        fingerprints.append(
            createEntry(commonName: commonName, expiration: expiration, fingerprint: fingerprint)
        )
        return self
    }
    
    /// Inserts a new intem at the beginning of fingerprints.
    @discardableResult
    func insertFirst(commonName: String, expiration: Expiration = .valid, fingerprint: Data? = nil) -> ResponseGenerator {
        fingerprints.insert(
            createEntry(commonName: commonName, expiration: expiration, fingerprint: fingerprint),
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
    
    /// Set response to contain a timestamp.
    @discardableResult
    func setUseTimestamp(useTimestamp: Bool) -> ResponseGenerator {
        self.useTimestamp = useTimestamp
        return self
    }
    
    /// Set entries signed with private key.
    @discardableResult
    @available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
    func signEntry(with privateKey: ECDSA.PrivateKey) -> ResponseGenerator {
        self.signData = { bytes in
            return ECDSA.sign(privateKey: privateKey, data: bytes)
        }
        return self
    }
    
    /// Create entry for list of entries
    private func createEntry(commonName: String, expiration: Expiration, fingerprint: Data?) -> FingerprintEntry {
        let fingerprint = fingerprint ?? Data.random(count: 32)
        let signature: Data?
        if let signData = signData {
            let expirationTimestamp = String(format: "%.0f", ceil(expiration.toDate.timeIntervalSince1970))
            let signedString = "\(commonName)&\(fingerprint.base64EncodedString())&\(expirationTimestamp)"
            guard let bytesToSign = signedString.data(using: .utf8) else {
                fatalError("Failed to prepare data for sign")
            }
            signature = signData(bytesToSign)
        } else {
            signature = .random(count: 64)
        }
        return .create(commonName: commonName, expiration: expiration, fingerprint: fingerprint, signature: signature)
    }
        
    /// Generates response data from fingerprints.
    func data() -> ServerResponse {
        let now = useTimestamp ? Date() : nil
        return ServerResponse(fingerprints: fingerprints, timestamp: now)
    }
}
