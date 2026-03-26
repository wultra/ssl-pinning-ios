//
// Copyright 2026 Wultra s.r.o.
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
/// The `DomainsConfig` structure holds domain-specific SSL pinning configuration
/// received from the server.
///
/// When present, it can selectively bypass SSL pinning for specific domains or
/// for all domains not explicitly listed.
///
internal struct DomainsConfig: Codable {
    
    /// Whether SSL pinning is required for domains not explicitly listed in `domains`.
    let sslPinningRequiredForUnlisted: Bool
    
    /// Domain-specific SSL pinning configuration entries.
    let domains: [DomainConfig]
    
    /// Returns whether SSL pinning is required for the given domain name.
    ///
    /// If the domain is listed, returns its `sslPinningRequired` value.
    /// Otherwise, falls back to `sslPinningRequiredForUnlisted`.
    func isPinningRequired(for domain: String) -> Bool {
        if let config = domains.first(where: { $0.name == domain }) {
            return config.sslPinningRequired
        }
        return sslPinningRequiredForUnlisted
    }
}

///
/// The `DomainConfig` structure holds SSL pinning configuration for a specific domain.
///
internal struct DomainConfig: Codable {
    
    /// The domain name.
    let name: String
    
    /// Whether SSL pinning is required for this domain.
    let sslPinningRequired: Bool
}
