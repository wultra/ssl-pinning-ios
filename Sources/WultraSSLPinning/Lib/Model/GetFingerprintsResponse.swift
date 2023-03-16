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
internal struct GetFingerprintsResponse: Codable {

    struct Entry: Codable {
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

    /// List of Entry objects
    let fingerprints: [Entry]
    
    /// Optional timestamp, received from servers that supports challenge & signed responses.
    let timestamp: Date?
}

extension GetFingerprintsResponse.Entry {
    
    /// Returns normalized data which can be used for the signature validation.
    var dataForSignatureValidation: SignedData? {
        guard let signature = signature else {
            return nil
        }
        let expirationTimestamp = String(format: "%.0f", ceil(expires.timeIntervalSince1970))
        let signedString = "\(name)&\(fingerprint.base64EncodedString())&\(expirationTimestamp)"
        guard let signedBytes = signedString.data(using: .utf8) else {
            return nil
        }
        return SignedData(data: signedBytes, signature: signature)
    }
}
