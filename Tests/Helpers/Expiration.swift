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
/// Defines abstract expiration, which can be then converted to date, relative to current date.
/// This basically allows time based unit testing.
///
enum Expiration {
    /// Expiration will be set as "expired"
    case expired
    /// The certificate will expire soon
    case soon
    /// The certificate expiration will be set to the future (2 x "soon" timeout)
    case valid
    /// The certificate will never expire.
    case never
}

extension Expiration {
    
    /// Converts Expiration enum into date, with appropriate offset to current date.
    var toDate: Date {
        return Date(timeIntervalSinceNow: toInterval)
    }
    
    var toInterval: TimeInterval {
        switch self {
        case .expired:  return -100
        case .soon:     return .testExpiration_Soon
        case .valid:    return .testExpiration_Valid
        case .never:    return .testExpiration_Never
        }
    }
}
