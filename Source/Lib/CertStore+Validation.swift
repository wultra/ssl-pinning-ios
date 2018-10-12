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
    public enum ValidationResult {
        
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
    /// - Parameter commonName: A common name from server's certificate
    /// - Parameter fingerprint: A SHA-256 fingerprint calculated from certificate's data
    ///
    /// - Returns: validation result
    public func validate(commonName: String, fingerprint: Data) -> ValidationResult {
        
        // Check expected common names
        if let expected = configuration.expectedCommonNames {
            guard expected.contains(commonName) else {
                return .untrusted
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
        // Interate over all entries and look for common name & entry
        // We don't care about expiration here. The expiration date is only
        // for caching purposes and indicates that we need to update list of certs.
        for info in certificates {
            if info.isExpired(forDate: now) {
                continue
            }
            if info.commonName == commonName {
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
    
    /// Validates whether provided certificate data in DER format is valid for given common name.
    ///
    /// - Parameter commonName: A common name from server's certificate
    /// - Parameter certificateData: Server certificate in DER format
    ///
    /// - Returns: validation result
    public func validate(commonName: String, certificateData: Data) -> ValidationResult {
        let fingerprint = cryptoProvider.hashSha256(data: certificateData)
        return validate(commonName: commonName, fingerprint: fingerprint)
    }
    
    /// Validates whether provided authentication challenge contains server certificate and its fingerprint is known.
    ///
    /// - Parameter challenge: An authentication challenge to be validated
    ///
    /// - Returns: validation result
    public func validate(challenge: URLAuthenticationChallenge) -> ValidationResult {
        // Acquire various nullable objects at first
        guard let serverTrust = challenge.protectionSpace.serverTrust,
            let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0),
            let commonName = SecCertificateCopySubjectSummary(serverCert) as String? else {
                return .untrusted
        }
        // Acquire certificate data in DER format
        let certData = SecCertificateCopyData(serverCert) as Data
        
        // Now validate commonName & certificate data
        return validate(commonName: commonName, certificateData: certData)
    }
}
