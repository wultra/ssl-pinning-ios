//
// Copyright 2023 Wultra s.r.o.
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
/// The `NetworkConfiguration` structure contains configuration for HTTP REST API.
/// You need to construct this structure with at least `serviceUrl` and `publicKey` properties.
///
public struct NetworkConfiguration {
    
    /// Default constructor.
    public init(
        serviceUrl: URL,
        publicKey: String,
        useChallenge: Bool = false,
        sslValidationStrategy: SSLValidationStrategy = .default)
    {
        self.serviceUrl = serviceUrl
        self.publicKey = publicKey
        self.useChallenge = useChallenge
        self.sslValidationStrategy = sslValidationStrategy
    }
    
    /// Required property, defines URL for getting certificate fingerprints.
    public let serviceUrl: URL
    
    /// Required property, contains ECC public key which will be used for validating data received from the server.
    /// The BASE64 string is expected. If the invalid key is provided, then the libray will crash on fatal error
    /// on the first attempt to use the public key.
    public let publicKey: String
    
    /// If `true`, then the random challenge is generated for each HTTP request. It's is expected, that the response
    /// body is signed with ECDSA and must be valid. The signature is calculated from CHALLENGE + '&' + BODY.
    public let useChallenge: Bool
    
    /// Defines the validation strategy for HTTPS connections initiated from the library itself. The default
    /// validation strategy implements a default URLSession handling.
    ///
    /// Be aware that altering this option may put your application at risk. You should not ship your application
    /// to production with SSL validation turned off.
    public let sslValidationStrategy: SSLValidationStrategy
}

/// Validation strategy decides how HTTPS requests initiated from the library should be handled.
public enum SSLValidationStrategy {
    
    /// Will use default URLSession handling
    case `default`
    
    /// Will trust https connections with invalid certificates
    case noValidation
}

// MARK: - Internal validation

extension NetworkConfiguration {
    /// Performs configuration validation. The result is typically "fatal error" in case that
    /// configuration contains data which cannot be used or warning is printed to the debug output.
    func validate(cryptoProvider: CryptoProvider) {
        // Check "http"
        if serviceUrl.absoluteString.hasPrefix("http:") {
            WultraDebug.warning("CertStore: '.serviceUrl' should point to 'https' server.")
        }
        if sslValidationStrategy == .noValidation {
            WultraDebug.warning("CertStore: '.sslValidationStrategy.noValidation' should not be used in production.")
        }
        
        // Validate EC public key (will crash on fatal error, for invalid key)
        _ = cryptoProvider.importECPublicKey(publicKeyBase64: publicKey)
    }
}

extension SSLValidationStrategy {
    
    internal func validate(challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        switch self {
        case .noValidation:
            if let st = challenge.protectionSpace.serverTrust {
                completionHandler(.useCredential, URLCredential(trust: st))
            } else {
                completionHandler(.performDefaultHandling, nil)
            }
        case .default:
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
