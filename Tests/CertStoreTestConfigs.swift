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

@testable import WultraSSLPinning

extension CertStoreConfiguration {
    
    static var testConfig: CertStoreConfiguration {
        return CertStoreConfiguration(
            serviceUrl: URL(string: "https://foo.wultra.com")!,
            publicKey: "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo=",
            identifier: nil,
            fallbackCertificatesData: nil,
            periodicUpdateInterval: .testUpdateInterval_PeriodicUpdate,
            expirationUpdateTreshold: .testUpdateInterval_ExpirationThreshold
        )
    }

    static func testConfigWithFallbackCertificate(expiration: Expiration) -> CertStoreConfiguration {
        
        let fallbackData = GetFingerprintsResponse.single(
            commonName: .testCommonName_Fallback,
            expiration: expiration,
            fingerprint: .testFingerprint_Fallback
            ).toJSON()
        return CertStoreConfiguration(
            serviceUrl: URL(string: "https://foo.wultra.com")!,
            publicKey: "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo=",
            identifier: nil,
            fallbackCertificatesData: fallbackData,
            periodicUpdateInterval: .testUpdateInterval_PeriodicUpdate,
            expirationUpdateTreshold: .testUpdateInterval_ExpirationThreshold
        )
    }
    
    static func testConfigWithExpectedCommonNames(_ commonNames: [String]) -> CertStoreConfiguration {
        return CertStoreConfiguration(
            serviceUrl: URL(string: "https://foo.wultra.com")!,
            publicKey: "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo=",
            expectedCommonNames: commonNames,
            identifier: nil,
            fallbackCertificatesData: nil,
            periodicUpdateInterval: .testUpdateInterval_PeriodicUpdate,
            expirationUpdateTreshold: .testUpdateInterval_ExpirationThreshold
        )
    }
}

// MARK: - Constants used in tests

extension String {
    
    static let testCommonName_1             = "abcdefgh.org"
    static let testCommonName_2             = "efgh.org"
    
    static let testCommonName_Unknown       = "www.googol.com"
    static let testCommonName_Fallback      = "api.fallback.org"
}

extension Data {
    
    static let testFingerprint_1            = Data(repeating: 0x01, count: 32)
    static let testFingerprint_2            = Data(repeating: 0x02, count: 32)

    static let testFingerprint_Unknown      = Data(repeating: 0xBB, count: 32)  // Use for completely unknown fingerprints
    static let testFingerprint_Fallback     = Data(repeating: 0xFF, count: 32)  // Use for fallback cert
}

extension TimeInterval {
    
    // Allows detection whether silent update has been scheduled on background
    static let testLatency_ForSilentUpdate: TimeInterval            = 1.0
    static let testLatency_ForFastUpdate: TimeInterval              = 0.5       // We need to count with polling loops, it's in fact very quick
    
    static let testUpdateInterval_ExpirationThreshold: TimeInterval = 10.0      // --> cfg.expirationUpdateTreshold
    static let testUpdateInterval_PeriodicUpdate: TimeInterval      = 5.0       // --> cfg.periodicUpdateInterval
    
    // Intervals for "Expiration" enum
    static let testExpiration_Soon: TimeInterval  = 30.0
    static let testExpiration_Valid: TimeInterval = 60.0
    static let testExpiration_Never: TimeInterval = 365*24*60*60
}
