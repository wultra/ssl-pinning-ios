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
/// The `CertificateInfo` structure holds all important information about
/// the stored certificate's fingerprint. Unlike the object received from
/// the server, this structure doesn't contain signature data.
///
internal struct CertificateInfo: Codable {
    
    /// Certificate's common name
    let commonName: String
    
    /// Hash calculated from certificate
    let fingerprint: Data
    
    /// Certificate's expiration date
    let expires: Date
    
    let maxIndex: Int?
    
    let domains: [String]?
    
    /// Minimized keys for (de)serialization
    enum CodingKeys: String, CodingKey {
        case commonName = "n"
        case fingerprint = "f"
        case expires = "e"
        case maxIndex = "m"
        case domains = "d"
    }
    
    init(commonName: String, fingerprint: Data, expires: Date, maxIndex: Int? = nil, domains: [String]? = nil) {
        self.commonName = commonName
        self.fingerprint = fingerprint
        self.expires = expires
        self.maxIndex = maxIndex
        self.domains = domains
    }
}

extension CertificateInfo: Equatable {
    
    /// Operator returns true if both `CertificateInfo` objects are equal.
    static func == (lhs: CertificateInfo, rhs: CertificateInfo) -> Bool {
        return lhs.commonName == rhs.commonName &&
            lhs.fingerprint == rhs.fingerprint &&
            lhs.expires == rhs.expires &&
            lhs.maxIndex == rhs.maxIndex &&
            lhs.domains == rhs.domains
    }
}

extension CertificateInfo {
    
    /// Helper constructor initializes `CertificateInfo` structure from object received from the server.
    init(from responseEntry: GetFingerprintsResponse.Entry) {
        commonName = responseEntry.name
        fingerprint = responseEntry.fingerprint
        expires = responseEntry.expires
        maxIndex = responseEntry.maxIndex
        domains = responseEntry.domains
    }
    
    /// Returns true if certificate is expired. (e.g. "expires" date is lesser than the provided date).
    func isExpired(forDate date: Date) -> Bool {
        return expires.timeIntervalSince(date) < 0
    }
}
