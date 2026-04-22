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

public extension CertStore {
    
    /// The result of fingerprint validation
    enum ValidationResult {
        
        /// The challenged server certificate is trusted.
        ///
        /// The right response on this situation is to continue with the ongoing TLS handshake (e.g. report
        /// [.performDefaultHandling](https://developer.apple.com/documentation/foundation/urlsession/authchallengedisposition)
        /// to the completion callback)
        case trusted
        
        /// The challenged server certificate is not trusted.
        ///
        /// ## Discussion
        ///
        /// The untrusted result means that CertStore has some fingerprints stored in its
        /// database, but none matches the value you requested for validation. The right
        /// response on this situation is to always cancel the ongoing TLS handshake (e.g. report
        /// [.cancelAuthenticationChallenge](https://developer.apple.com/documentation/foundation/urlsession/authchallengedisposition)
        /// to the completion callback)
        case untrusted
        
        /// The fingerprints database is empty, or there's no fingerprint for validated common name.
        /// For both situations, the store is basically unable to determine whether the server
        /// can be trusted or not.
        ///
        /// ## Discussion
        ///
        /// The "empty" validation result typically means that the `CertStore` should update
        /// the list of certificates immediately. Before you do this, you should check whether
        /// the requested common name is what's you're expecting. You can also set the list
        /// of expected common names in `CertStoreConfiguration` and treat all others as untrusted.
        ///
        /// For all situations, the right response on this situation is to always cancel the ongoing
        /// TLS handshake (e.g. report [.cancelAuthenticationChallenge](https://developer.apple.com/documentation/foundation/urlsession/authchallengedisposition)
        /// to the completion callback)
        case empty
    }
    
    // MARK: - Various validate methods
    
    /// Validates whether provided certificate fingerprint at a specific chain depth is valid for given common name.
    ///
    /// When `DomainsConfig` is available from a server update and the domain has `sslPinningRequired` set to `false`,
    /// the validation returns `.trusted` immediately without checking the fingerprint.
    ///
    /// - Parameter commonName: A common name from the leaf server certificate
    /// - Parameter fingerprint: A SHA-256 fingerprint calculated from certificate's data
    /// - Parameter depth: The certificate depth in the TLS chain (0 = leaf, 1..N-1 = intermediate, N = root). When no depth is provided, 0 is used as default.
    ///
    /// - Returns: validation result
    func validate(commonName: String, fingerprint: Data, depth: Int = 0) -> ValidationResult {
        return validateFingerprint(commonName: commonName, fingerprint: fingerprint, depth: depth)
    }
    
    /// Validates whether provided certificate data in DER format is valid for given common name.
    ///
    /// - Parameter commonName: A common name from server's certificate
    /// - Parameter certificateData: Server certificate in DER format
    /// - Parameter depth: The certificate depth in the TLS chain (0 = leaf, 1..N-1 = intermediate, N = root). When no depth is provided, 0 is used as default.
    ///
    /// - Returns: validation result
    func validate(commonName: String, certificateData: Data, depth: Int = 0) -> ValidationResult {
        let fingerprint = cryptoProvider.hashSha256(data: certificateData)
        return validateFingerprint(commonName: commonName, fingerprint: fingerprint, depth: depth)
    }
    
    /// Validates whether provided authentication challenge contains server certificate and its fingerprint is known.
    ///
    /// The common name is extracted from the leaf certificate (depth 0). All pinned entries for that common
    /// name are then checked against the certificates in the chain at their respective stored depths. At least
    /// one pinned entry must match for the challenge to be considered trusted.
    ///
    /// - Parameter challenge: An authentication challenge to be validated
    ///
    /// - Returns: validation result
    func validate(challenge: URLAuthenticationChallenge) -> ValidationResult {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            WultraDebug.print("Server trust from URLAuthenticationChallenge is nil; returning .untrusted without fingerprint validation.")
            return .untrusted
        }
        
        // Common name is always taken from the leaf certificate (index 0).
        guard let leafCert = SecTrustGetCertificateAtIndex(serverTrust, 0),
              let commonName = SecCertificateCopySubjectSummary(leafCert) as String? else {
            WultraDebug.print("Leaf certificate common name is nil; returning .untrusted without fingerprint validation.")
            return .untrusted
        }
        
        let cachedData = getCachedData()
        
        // Check domainsConfig as early as possible
        if cachedData?.isDomainsConfigPinningRequired(for: commonName) == false {
            return .trusted
        }
        
        // Check expected common names
        if let expected = configuration.expectedCommonNames {
            guard expected.contains(commonName) else {
                WultraDebug.print("Common name '\(commonName)' not found in expected list; returning .untrusted without fingerprint validation.")
                return .untrusted
            }
        }
        
        let chainLength = SecTrustGetCertificateCount(serverTrust)
        
        guard let certificates = cachedData?.certificates, !certificates.isEmpty else {
            WultraDebug.print("List of certificates is empty; returning .empty.")
            return .empty
        }
        
        let now = Date()
        // matchAttempts counts how many pinned entries for this CN were checked against the chain.
        // A pinned depth that exceeds the actual chain length is silently skipped.
        var matchAttempts = 0
        
        for info in certificates {
            if info.isExpired(forDate: now) {
                continue
            }
            
            guard info.commonName == commonName else {
                continue
            }
            
            let pinnedDepth = info.depth ?? 0
            guard pinnedDepth >= 0 && pinnedDepth < chainLength else {
                continue
            }
            
            guard let chainCert = SecTrustGetCertificateAtIndex(serverTrust, pinnedDepth) else {
                continue
            }
            
            let certData = SecCertificateCopyData(chainCert) as Data
            let fingerprint = cryptoProvider.hashSha256(data: certData)
            
            matchAttempts += 1
            
            if info.fingerprint == fingerprint {
                return .trusted
            }
        }
        
        // If matchAttempts is greater than 0, then it means that we have certificate for
        // a requested common name, but none matched. In this case, the result is "untrusted".
        //
        // On opposite to that, if no fingerprint comparison was performed, then it means
        // that the database has some certificates, but none for requested common name.
        // That's basically means that we cannot determine validity of the certificate
        // and therefore the "empty" result is returned.
        return matchAttempts > 0 ? .untrusted : .empty
    }
    
    /// Validates whether provided certificate fingerprint at a specific chain depth is valid for given common name.
    /// Method is private, it contains all logic of fingerprint validation.
    ///
    /// When `DomainsConfig` is available from a server update and the domain has `sslPinningRequired` set to `false`,
    /// the validation returns `.trusted` immediately without checking the fingerprint.
    ///
    /// - Parameter commonName: A common name from the leaf server certificate
    /// - Parameter fingerprint: A SHA-256 fingerprint calculated from certificate's data
    /// - Parameter depth: The certificate depth in the TLS chain (0 = leaf, 1..N-1 = intermediate, N = root)
    ///
    /// - Returns: validation result
    private func validateFingerprint(commonName: String, fingerprint: Data, depth: Int) -> ValidationResult {
        let cachedData = getCachedData()
        
        // Check domainsConfig as early as possible
        if cachedData?.isDomainsConfigPinningRequired(for: commonName) == false {
            return .trusted
        }
        
        // Check expected common names
        if let expected = configuration.expectedCommonNames {
            guard expected.contains(commonName) else {
                WultraDebug.print("Common name '\(commonName)' not found in expected list; returning .untrusted without fingerprint validation.")
                return .untrusted
            }
        }
        
        guard let certificates = cachedData?.certificates, !certificates.isEmpty else {
            WultraDebug.print("List of certificates is empty; returning .empty.")
            return .empty
        }
        
        // Current date
        let now = Date()
        // Match attempts counts whether we tested at least one certificate.
        // If not, then the store is empty for the requested common name.
        var matchAttempts = 0
        // Iterate over all entries and look for common name & fingerprint.
        // Also filter an already expired certificates (including the fallback one).
        for info in certificates {
            if info.isExpired(forDate: now) {
                continue
            }
            if info.commonName == commonName && (info.depth ?? 0) == depth {
                matchAttempts += 1
                if info.fingerprint == fingerprint {
                    return .trusted
                }
            }
        }
        
        // If matchAttempts is greater than 0, then it means that we have certificate for
        // a requested common name, but none matched. In this case, the result is "untrusted".
        //
        // On opposite to that, if no fingerprint comparison was performed, then it means
        // that the database has some certificates, but none for requested common name.
        // That's basically means that we cannot determine validity of the certificate
        // and therefore the "empty" result is returned.
        return matchAttempts > 0 ? .untrusted : .empty
    }
    
}

fileprivate extension CachedData {

    /// Returns whether SSL pinning is required for the given domain name.
    ///
    /// - Parameter commonName: The domain name to check.
    /// - Returns: `false` when `DomainsConfig` explicitly disables pinning for this domain; `true` otherwise.
    func isDomainsConfigPinningRequired(for commonName: String) -> Bool {
        guard let domainsConfig else {
            return true
        }

        let isRequired = domainsConfig.isPinningRequired(for: commonName)
        if !isRequired {
            WultraDebug.print("Pinning disabled by domainsConfig for '\(commonName)'; returning .trusted without fingerprint validation.")
        }
        return isRequired
    }
}
