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
    
    /// Defines instance identifier for case that your application requires more than one instance of CertStore.
    /// The identifier is then used for persistent data storage identification.
    ///
    /// If `nil` is provided, then CertStore will use "default" string constant for such identification.
    public let identifier: String?
    
    /// Defines JSON data with a fallback certificate fingerprint.
    ///
    /// ## Discussion
    /// You can configure a fallback certificate which will be used as the last stand during the fingerprint validation.
    /// The JSON should contains the same data as are usually received from the server, except that "signature"
    /// is not validated (but must be provided in JSON). For example:
    /// ```
    /// let fallbackData = """
    /// {
    ///    "name" : "www.google.com",
    ///    "fingerprint" : "nu1DOBz31Y5FY6lRNkJV/HdnB6BDVCp7mX0nxkbub7Y=",
    ///    "expires" : 1540280280000,
    ///    "signature" : ""
    /// }
    /// """.data(using: .ascii)
    /// ```
    ///
    /// Then, the fallback certificate info will be used at the end of the fingerprint validation loop.
    public let fallbackCertificateData: Data?
    
    
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
    
    /// Defines how often will CertStore check the server for new certificates
    /// when some cached certificate is going to expire soon.
    ///
    /// The default value is 12 hours.
    public let periodicUpdateIntervalDuringExpiration: TimeInterval
    
    /// Default constructor.
    public init(
        serviceUrl: URL,
        publicKey: String,
        identifier: String? = nil,
        fallbackCertificateData: Data? = nil,
        periodicUpdateInterval: TimeInterval = 7*24*60*60,
        expirationUpdateTreshold: TimeInterval = 14*24*60*60,
        periodicUpdateIntervalDuringExpiration: TimeInterval = 12*60*60)
    {
        self.serviceUrl = serviceUrl
        self.publicKey = publicKey
        self.identifier = identifier
        self.fallbackCertificateData = fallbackCertificateData
        self.periodicUpdateInterval = periodicUpdateInterval
        self.expirationUpdateTreshold = expirationUpdateTreshold
        self.periodicUpdateIntervalDuringExpiration = periodicUpdateIntervalDuringExpiration
    }
}
