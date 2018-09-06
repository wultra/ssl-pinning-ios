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
        /// The challenged server certificate is trusted (e.g. its fingerprint is in database)
        case trusted
        /// The challenged server certificate is not trusted.
        case untrusted
        /// The fingerprints database is empty. The store is unable to validate fingerprint.
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
        // Gets list of fingerprint entries (which is thread safe operation)
        let certificates = getCertificates()
        
        // Check whether store is empty
        guard certificates.count > 0 else {
            return .empty
        }
        
        // Interate over all entries and look for common name & entry
        // We don't care about expiration here. The expiration date is only
        // for caching purposes and indicates that we need to update list of certs.
        for info in certificates {
            if info.commonName == commonName {
                if info.fingerprint == fingerprint {
                    return .trusted
                }
            }
        }
        return .untrusted
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
