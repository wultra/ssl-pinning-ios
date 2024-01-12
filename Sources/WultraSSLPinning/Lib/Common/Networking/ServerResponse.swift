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


/// The `GetFingerprintsResponse` structure defines JSON response received from the server.
internal struct ServerResponse: Codable {
    
    let verifyVersionResult: VerifyVersionResult?

    /// List of Entry objects
    let fingerprints: [FingerprintEntry]
    
    /// Optional timestamp, received from servers that supports challenge & signed responses.
    let timestamp: Date?
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.verifyVersionResult = try container.decodeIfPresent(VerifyVersionResult.self, forKey: .verifyVersionResult)
        self.fingerprints = try container.decodeIfPresent([FingerprintEntry].self, forKey: .fingerprints) ?? []
        self.timestamp = try container.decodeIfPresent(Date.self, forKey: .timestamp)
    }
    
    init(verifyVersionResult: VerifyVersionResult? = nil, fingerprints: [FingerprintEntry], timestamp: Date? = nil) {
        self.verifyVersionResult = verifyVersionResult
        self.fingerprints = fingerprints
        self.timestamp = timestamp
    }
}

internal struct FingerprintEntry: Codable {
    /// Common name
    let name: String
    
    /// Fingerprint data, must be deserialized from BASE64 string
    let fingerprint: Data
    
    /// Expiration date
    let expires: Date
    
    /// ECDSA signature, must be deserialized from BASE64 string.
    /// Property is optional for servers that supports challenge in request
    /// and provides signature for the whole response.
    let signature: Data?
}

struct VerifyVersionResult: Codable {
    
    enum Update: String, Codable {
        case notRequired = "NOT_REQUIRED"
        case suggested = "SUGGESTED"
        case forced = "FORCED"
    }
    
    let update: Update
    let message: String?
}
