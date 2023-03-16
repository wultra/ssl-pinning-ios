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
/// The `CachedData` structure is a model for (de)serializing
/// all persistent data to secure data store.
///
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

    /// Returns number of certificates which are currently not expired to provided date.
    func numberOfValidCertificates(forDate date: Date) -> Int {
        var result = 0
        for info in certificates {
            if !info.isExpired(forDate: date) {
                result += 1
            }
        }
        return result
    }
}

extension Array where Element == CertificateInfo {
    
    /// Sorts certificates stored in CachedData structure. Entries are alphabetically sorted
    /// by the common name. For entries with the same common name, the entries with expiration
    /// in more distant future will be first. This order allows to have more recent certs at first positions,
    /// so we can more easily calculate when the next silent update will be scheduled.
    mutating func sortCertificates() {
        self.sort { (lhs, rhs) -> Bool in
            if lhs.commonName == rhs.commonName {
                return lhs.expires > rhs.expires
            }
            return lhs.commonName < rhs.commonName
        }
    }
}
