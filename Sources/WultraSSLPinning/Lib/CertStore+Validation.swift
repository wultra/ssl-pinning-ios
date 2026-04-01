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
    
    /// Validates whether provided certificate fingerprint is valid for given common name.
    ///
    /// When `DomainsConfig` is available from a server update and the domain has `sslPinningRequired` set to `false`,
    /// the validation returns `.trusted` immediately without checking the fingerprint.
    ///
    /// - Parameter commonName: A common name from server's certificate
    /// - Parameter fingerprint: A SHA-256 fingerprint calculated from certificate's data
    ///
    /// - Returns: validation result
    func validate(commonName: String, fingerprint: Data) -> ValidationResult {
        // when no depth is specified, compare leaf certificate (default behaviour)
        return validateFingerprint(commonName: commonName, fingerprint: fingerprint, depth: 0)
    }
    
    /// Validates whether provided certificate fingerprint at a specific chain depth is valid for given common name.
    ///
    /// When `DomainsConfig` is available from a server update and the domain has `sslPinningRequired` set to `false`,
    /// the validation returns `.trusted` immediately without checking the fingerprint.
    ///
    /// - Parameter commonName: A common name from the leaf server certificate
    /// - Parameter fingerprint: A SHA-256 fingerprint calculated from certificate's data
    /// - Parameter depth: The certificate depth in the TLS chain (0 = leaf, 1..N-1 = intermediate, N = root)
    ///
    /// - Returns: validation result
    func validate(commonName: String, fingerprint: Data, depth: Int) -> ValidationResult {
        return validateFingerprint(commonName: commonName, fingerprint: fingerprint, depth: depth)
    }
    
    /// Validates whether provided certificate data in DER format is valid for given common name.
    /// Call this method to validate leaf (depth: 0) certificate.
    ///
    /// - Parameter commonName: A common name from server's certificate
    /// - Parameter certificateData: Server certificate in DER format
    ///
    /// - Returns: validation result
    func validate(commonName: String, certificateData: Data) -> ValidationResult {
        return validate(commonName: commonName, certificateData: certificateData, depth: 0)
    }
    
    /// Validates whether provided certificate data in DER format is valid for given common name.
    ///
    /// - Parameter commonName: A common name from server's certificate
    /// - Parameter certificateData: Server certificate in DER format
    /// - Parameter depth: The certificate depth in the TLS chain (0 = leaf, 1..N-1 = intermediate, N = root)
    ///
    /// - Returns: validation result
    func validate(commonName: String, certificateData: Data, depth: Int) -> ValidationResult {
        let fingerprint = cryptoProvider.hashSha256(data: certificateData)
        return validateFingerprint(commonName: commonName, fingerprint: fingerprint, depth: depth)
    }
    
    /// Validates whether provided authentication challenge contains server certificate and its fingerprint is known.
    ///
    /// - Parameter challenge: An authentication challenge to be validated
    ///
    /// - Returns: validation result
    func validate(challenge: URLAuthenticationChallenge) -> ValidationResult {
        return validate(challenge: challenge, depth: 0)
    }
    
    /// Validates whether provided authentication challenge contains server certificate and its fingerprint is known.
    ///
    /// - Parameter challenge: An authentication challenge to be validated
    /// - Parameter depth: The certificate depth in the TLS chain (0 = leaf, 1..N-1 = intermediate, N = root)
    ///
    /// - Returns: validation result
    func validate(challenge: URLAuthenticationChallenge, depth: Int) -> ValidationResult {
        // Acquire various nullable objects at first
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            return .untrusted
        }
        
        // Handle leaf certificate for common name, which should be fetched from leaf certificate
        guard let leafCert = SecTrustGetCertificateAtIndex(serverTrust, 0),
              let commonName = SecCertificateCopySubjectSummary(leafCert) as String? else {
            return .untrusted
        }
        
        // Depth of certificate should be within chain length
        let count = SecTrustGetCertificateCount(serverTrust) // for example count = 3, valid depth values: 0,1,2
        if depth >= count || depth < 0 {
            return .untrusted
        }
        
        // Handle server certificate at specified depth
        guard let serverCert = SecTrustGetCertificateAtIndex(serverTrust, depth) else {
            return .untrusted
        }
        // Acquire certificate data in DER format
        let certData = SecCertificateCopyData(serverCert) as Data
        let fingerprint = cryptoProvider.hashSha256(data: certData)
        
        // Now validate commonName & certificate data & depth
        return validateFingerprint(commonName: commonName, fingerprint: fingerprint, depth: depth)
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
        
        // Check expected common names
        if let expected = configuration.expectedCommonNames {
            guard expected.contains(commonName) else {
                return .untrusted
            }
        }
        
        if let domainsConfig = getCachedData()?.domainsConfig {
            // Check if pinning is required for this domain
            if domainsConfig.isPinningRequired(for: commonName) == false {
                WultraDebug.print("Pinning disabled by domainsConfig for domain '\(commonName)'; returning .trusted without fingerprint validation.")
                return .trusted
            }
        }
        
        // Gets list of fingerprint entries (which is thread safe operation)
        let certificates = getCertificates()
        
        // Check whether store is empty
        guard certificates.count > 0 else {
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
            if info.commonName == commonName && info.depth == depth {
                if info.fingerprint == fingerprint {
                    return .trusted
                }
                matchAttempts += 1
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
