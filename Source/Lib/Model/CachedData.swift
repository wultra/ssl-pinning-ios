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

/// The `CachedData` structure is a model for (de)serializing
/// all persistent data to secure data store.
internal struct CachedData: Codable {
    
    /// Array of certificate info structures
    var certificates: [CertificateInfo]
    
    /// Date of next scheduled silent update from the remote server
    var nextUpdate: Date
    
    /// Minimized keys for (de)serialization
    enum CodingKeys: String, CodingKey {
        case certificates = "c"
        case nextUpdate = "u"
    }
}


extension CachedData {
    
    /// Sorts certificates stored in CachedData structure.
    mutating func sortCertificates() {
        certificates.sort { (lhs, rhs) -> Bool in
            if lhs.commonName == rhs.commonName {
                return lhs.expires > rhs.expires
            }
            return lhs.commonName > rhs.commonName
        }
    }
    
    /// Returns number of certificates which are not expired.
    var numberOfValidCertificates: Int {
        var result = 0
        for info in certificates {
            if !info.isExpired {
                result += 1
            }
        }
        return result
    }
}
