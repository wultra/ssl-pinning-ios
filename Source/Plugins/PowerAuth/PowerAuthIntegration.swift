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

import PowerAuth2

public extension CertStore {
    
    /// Returns validation strategy object which can be used in `PA2ClientConfiguration`.
    /// The constructed validation strategy object will use this instance of `CertStore` for server certificate
    /// validation. Note that the function always constructs new object, so it's effective to create just one instance
    /// of the validator per `CertStore`.
    public func powerAuthSslValidationStrategy() -> PA2ClientSslValidationStrategy {
        return PowerAuthSslPinningValidationStrategy(certStore: self)
    }
    
    /// Creates a new instance of `CertStore` preconfigured with  crypto provider and secure data store,
    /// both implemented on top of PowerAuth SDK. You can use this type of instantiation in case that you're OK
    /// with all defaults defined in this library.
    ///
    /// You can use following code to construct a shared signeton for `CertStore`:
    /// ```
    /// extension CertStore {
    ///     static var shared: CertStore {
    ///         let config = CertStoreConfiguration(
    ///             serviceUrl: URL(string: "https://...")!,
    ///             publicKey: "...."
    ///         )
    ///         return .powerAuthCertStore(configuration: config)
    ///     }
    /// }
    /// ```
    public static func powerAuthCertStore(configuration: CertStoreConfiguration) -> CertStore {
        return CertStore(
            configuration: configuration,
            cryptoProvider: PowerAuthCryptoProvider(),
            secureDataStore: PowerAuthSecureDataStore()
        )
    }
}

///
/// The `PowerAuthSslPinningValidationStrategy` implements SSL pinning with fingerprints, stored in
/// the CertStore. The object implements `PA2ClientSslValidationStrategy` protocol, so it can be used
/// to protect the communication initiated from the PowerAuth SDK itself. To do this, you can simply
/// create an instance of this object and assign it to the `PA2ClientConfiguration` before you construct
/// your `PowerAuthSDK` object.
///
/// For example, this is how the configuration sequence may looks like if you want to use both
/// `PowerAuthSDK` and `CertStore` as singletons:
/// ```
/// extension CertStore {
///     /// Singleton for `CertStore`
///     static var shared: CertStore {
///         let config = CertStoreConfiguration(
///             serviceUrl: URL(string: "https://...")!,
///             publicKey: "BASE64...KEY"
///         )
///         return .powerAuthCertStore(configuration: config)
///     }
/// }
///
/// extension PowerAuthSDK {
///     /// Singleton for `PowerAuthSDK`
///     static var shared: PowerAuthSDK {
///         let config = PowerAuthConfiguration()
///         // Configure your powerauth...
///         let keychain = PA2KeychainConfiguration()
///         // Configure the keychain
///         let client = PA2ClientConfiguration()
///         client.sslValidationStrategy = CertStore.shared.powerAuthSslValidationStrategy()
///         // Configure PA2Client...
///         // And construct the SDK instance
///         guard let powerAuth = PowerAuthSDK(configuration: config, keychainConfiguration: keychain, clientConfiguration: client)
///             else { fatalError() }
///         return powerAuth
///     }
/// }
/// ```
///
public class PowerAuthSslPinningValidationStrategy: NSObject, PA2ClientSslValidationStrategy {
    
    /// `CertStore` object which actually implements the SSL pinning.
    public let certStore: CertStore
    
    /// Initializes object with instance of CertStore.
    public init(certStore: CertStore) {
        self.certStore = certStore
    }
    
    /// Implements SSL certificate validation, as defined in `PA2ClientSslValidationStrategy` protocol.
    public func validateSsl(for session: URLSession, challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Validate challenge and complete handler with an appropriate result.
        switch certStore.validate(challenge: challenge) {
        case .trusted:
            // Accept challenge with a default handling
            completionHandler(.performDefaultHandling, nil)
        case .untrusted, .empty:
            /// Reject challenge
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
