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
/// The `CertStoreConfiguration` structure contains configuration for the `CertStore` class.
/// You need to construct this structure with at least `serviceUrl` and `publicKey` properties.
///
public struct CertStoreConfiguration {
    
    /// Required property, defines URL for getting certificate fingerprints.
    public let serviceUrl: URL
    
    /// Required property, contains ECC public key which will be used for validating data received from the server.
    /// The BASE64 string is expected. If the invalid key is provided, then the libray will crash on fatal error
    /// on the first attempt to use the public key.
    public let publicKey: String
    
    /// Optional property, defines the set of common names which are expected in certificate validation. By setting
    /// this propery, you tell the store to treat all certificates issued for other common names as untrusted.
    public let expectedCommonNames: [String]?
    
    /// Defines instance identifier for case that your application requires more than one instance of CertStore.
    /// The identifier is then used for data identification in the underlying persistend data storage.
    ///
    /// If `nil` is provided, then `CertStore` will use "default" string constant for such identification.
    public let identifier: String?
    
    /// Defines JSON data with a fallback certificates fingerprints.
    ///
    /// ## Discussion
    /// You can configure a fallback certificates which will be used as the last stand during the fingerprint validation.
    /// The JSON should contains the same data as are usually received from the server, except that "signature"
    /// is not validated (but must be provided in JSON). For example:
    /// ```
    /// {
    ///    "fingerprints":[
    ///       {
    ///          "name": "www.google.com",
    ///          "fingerprint": "nu1DOBz31Y5FY6lRNkJV/HdnB6BDVCp7mX0nxkbub7Y=",
    ///          "expires": 1540280280000,
    ///          "signature": ""
    ///       }
    ///    ]
    /// }
    /// """.data(using: .ascii)
    /// ```
    ///
    /// Then, the fallback certificates will be used at the end of the fingerprints validation loop.
    public let fallbackCertificatesData: Data?
    
    // MARK: - Tweaks
    
    /// Defines how often will CertStore periodically check the certificates,
    /// when there's no certificate to be expired soon.
    ///
    /// The default value is one week.
    public let periodicUpdateInterval: TimeInterval
    
    /// Defines the time window before some certificate expires. The CertStore
    /// will ask server more often. The periodicity is defined by `periodicUpdateIntervalDuringExpiration`
    /// property.
    ///
    /// The default value is 2 weeks.
    public let expirationUpdateTreshold: TimeInterval
    
    /// Default constructor.
    public init(
        serviceUrl: URL,
        publicKey: String,
        expectedCommonNames: [String]? = nil,
        identifier: String? = nil,
        fallbackCertificatesData: Data? = nil,
        periodicUpdateInterval: TimeInterval = 7*24*60*60,
        expirationUpdateTreshold: TimeInterval = 14*24*60*60)
    {
        self.serviceUrl = serviceUrl
        self.publicKey = publicKey
        self.expectedCommonNames = expectedCommonNames
        self.identifier = identifier
        self.fallbackCertificatesData = fallbackCertificatesData
        self.periodicUpdateInterval = periodicUpdateInterval
        self.expirationUpdateTreshold = expirationUpdateTreshold
    }
}



// MARK: - Internal validation

extension CertStoreConfiguration {
    
    /// Performs configuration validation. The result is typically "fatal error" in case that
    /// configuration contains data which cannot be used for `CertStore` operation, or warning
    /// printed to the debug output.
    func validate(cryptoProvider: CryptoProvider) {
        // Check "http"
        if serviceUrl.absoluteString.hasPrefix("http:") {
            WultraDebug.warning("CertStore: '.serviceUrl' should point to 'https' server.")
        }
        // Validate fallback certificate data
        if let fallbackData = fallbackCertificatesData {
            let decoder = JSONDecoder()
            decoder.dataDecodingStrategy = .base64
            decoder.dateDecodingStrategy = .secondsSince1970
            if let fallback = try? decoder.decode(GetFingerprintsResponse.self, from: fallbackData) {
                for fallbackEntry in fallback.fingerprints {
                    if let expectedCNs = expectedCommonNames {
                        if !expectedCNs.contains(fallbackEntry.name) {
                            WultraDebug.warning("CertStore: certificate '\(fallbackEntry.name)' in '.fallbackCertificatesData' is issued for common name, which is not included in 'expectedCommonNames'.")
                        }
                    }
                    if fallbackEntry.expires.timeIntervalSinceNow < 0 {
                        WultraDebug.warning("CertStore: certificate '\(fallbackEntry.name)' in '.fallbackCertificateData' is already expired.")
                    }
                }
            } else {
                WultraDebug.error("CertStore: '.fallbackCertificatesData' contains invalid JSON.")
            }
        }
        // Validate EC public key (will crash on fatal error, for invalid key)
        _ = cryptoProvider.importECPublicKey(publicKeyBase64: publicKey)
        
        // Negative TimeIntervals are always fatal
        if periodicUpdateInterval < 0 || expirationUpdateTreshold < 0 {
            WultraDebug.fatalError("CertStoreConfiguration contains negative TimeInterval.")
        }
    }
}
