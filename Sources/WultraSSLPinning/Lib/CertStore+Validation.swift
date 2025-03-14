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
    
    /// Validates whether provided authentication challenge contains server certificate and its fingerprint is known.
    ///
    /// - Parameter challenge: An authentication challenge to be validated
    ///
    /// - Returns: validation result
    func validate(challenge: URLAuthenticationChallenge) -> ValidationResult {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            return .untrusted
        }
        
        let certificates = getNonExpiredCertificates(domain: challenge.protectionSpace.host)
        guard certificates.isEmpty == false else {
            return .empty
        }
        
        let chain = CertificateChain(serverTrust: serverTrust, cryptoProvider: cryptoProvider)
        
        for info in certificates {
            let maxIndex = info.maxIndex ?? 0
            for depth in 0...maxIndex {
                guard let cert = chain.getAtIndex(depth) else {
                    continue
                }
                if validate(storedCertificate: info, commonName: cert.commonName, fingerprint: cert.fingerprint) {
                    return .trusted
                }
            }
        }
        
        return .untrusted
    }
    
    func validate(commonName: String, fingerprint: Data, domain: String? = nil) -> ValidationResult {
        let certificates = getNonExpiredCertificates(domain: domain).filter { $0.commonName == commonName }
        guard certificates.isEmpty == false else {
            return .empty
        }
        return certificates.contains { validate(storedCertificate: $0, commonName: commonName, fingerprint: fingerprint) } ? .trusted : .untrusted
    }
    
    private func validate(storedCertificate: CertificateInfo, commonName: String, fingerprint: Data) -> Bool {
        return storedCertificate.commonName == commonName && storedCertificate.fingerprint == fingerprint
    }
    
    private func getNonExpiredCertificates(domain: String? = nil, commonName: String? = nil) -> [CertificateInfo] {
        let now = Date()
        var certificates = getCertificates().filter { $0.isExpired(forDate: now) == false }
        if let domain {
            certificates = certificates.filter { $0.domains == nil || $0.domains!.contains(domain) }
        }
        if let commonName {
            certificates = certificates.filter { $0.commonName == commonName }
        }
        return certificates
    }
}

private class CertificateChain {
    
    private let serverTrust: SecTrust
    private let chainCount: Int
    private let cryptoProvider: CryptoProvider
    private var extractedCertificates: [Int: ExtractedCertificate] = [:]
    
    init(serverTrust: SecTrust, cryptoProvider: CryptoProvider) {
        self.serverTrust = serverTrust
        self.chainCount = SecTrustGetCertificateCount(serverTrust) as Int
        self.cryptoProvider = cryptoProvider
    }
    
    func getAtIndex(_ index: Int) -> ExtractedCertificate? {
        guard index >= 0 && index <= chainCount-1 else {
            return nil
        }
        if let cert = extractedCertificates[index] {
            return cert
        }
        
        guard let serverCert = SecTrustGetCertificateAtIndex(serverTrust, index) else {
            return nil
        }
        var name: CFString?
        
        // get the common name
        guard SecCertificateCopyCommonName(serverCert, &name) == errSecSuccess, let commonName = name as String? else {
            return nil
        }
        
        let certData = SecCertificateCopyData(serverCert) as Data
        let fingerprint = cryptoProvider.hashSha256(data: certData)
        
        let extractedCertificate = ExtractedCertificate(
            commonName: commonName,
            fingerprint: fingerprint
        )
            
        extractedCertificates[index] = extractedCertificate
        return extractedCertificate
    }
    
}

private struct ExtractedCertificate {
    let commonName: String
    let fingerprint: Data
}
