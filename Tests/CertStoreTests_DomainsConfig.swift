//
// Copyright 2026 Wultra s.r.o.
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

import XCTest
@testable import WultraSSLPinning

///
/// Tests for DomainsConfig functionality: domain-specific SSL pinning bypass,
/// integration with CertStore validation, and DomainsConfig serialization in CachedData.
///
class CertStoreTests_DomainsConfig: XCTestCase {
    
    // MARK: - Helpers
    
    var config: CertStoreConfiguration!
    var certStore: CertStore!
    
    var cryptoProvider: TestingCryptoProvider!
    var dataStore: TestingSecureDataStore!
    var remoteDataProvider: TestingRemoteDataProvider!
    
    let responseGenerator = ResponseGenerator()
    
    func prepareStore(with config: CertStoreConfiguration) {
        self.config = config
        cryptoProvider = TestingCryptoProvider()
        dataStore = TestingSecureDataStore()
        remoteDataProvider = TestingRemoteDataProvider()
        certStore = CertStore(
            configuration: config,
            cryptoProvider: cryptoProvider,
            secureDataStore: dataStore,
            remoteDataProvider: remoteDataProvider
        )
    }
    
    @discardableResult
    func updateStore() -> CertStore.UpdateResult {
        let result = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        return result.value ?? .networkError
    }
    
    /// Performs a forced store update (always hits the network).
    @discardableResult
    func forceUpdateStore() -> CertStore.UpdateResult {
        let result = AsyncHelper.wait { completion in
            certStore.update(mode: .forced) { (result, error) in
                completion.complete(with: result)
            }
        }
        return result.value ?? .networkError
    }
    
    static override func setUp() {
        WultraDebug.verboseLevel = .all
    }
    
    // MARK: - DomainsConfig model tests
    
    /// Tests that a listed domain with sslPinningRequired=false returns false.
    func testDomainsConfig_ListedDomainPinningNotRequired() {
        let config = DomainsConfig(
            sslPinningRequiredForUnlisted: true,
            domains: [
                DomainConfig(name: .testCommonName_1, sslPinningRequired: false)
            ]
        )
        XCTAssertFalse(config.isPinningRequired(for: .testCommonName_1))
    }
    
    /// Tests that a listed domain with sslPinningRequired=true returns true.
    func testDomainsConfig_ListedDomainPinningRequired() {
        let config = DomainsConfig(
            sslPinningRequiredForUnlisted: false,
            domains: [
                DomainConfig(name: .testCommonName_1, sslPinningRequired: true)
            ]
        )
        XCTAssertTrue(config.isPinningRequired(for: .testCommonName_1))
    }
    
    /// Tests that an unlisted domain falls back to sslPinningRequiredForUnlisted=true.
    func testDomainsConfig_UnlistedDomainFallsBackToRequiredTrue() {
        let config = DomainsConfig(
            sslPinningRequiredForUnlisted: true,
            domains: [
                DomainConfig(name: .testCommonName_1, sslPinningRequired: false)
            ]
        )
        XCTAssertTrue(config.isPinningRequired(for: .testCommonName_Unknown))
    }
    
    /// Tests that an unlisted domain falls back to sslPinningRequiredForUnlisted=false.
    func testDomainsConfig_UnlistedDomainFallsBackToRequiredFalse() {
        let config = DomainsConfig(
            sslPinningRequiredForUnlisted: false,
            domains: [
                DomainConfig(name: .testCommonName_1, sslPinningRequired: true)
            ]
        )
        XCTAssertFalse(config.isPinningRequired(for: .testCommonName_Unknown))
    }
    
    /// Tests that DomainsConfig with an empty domains array uses sslPinningRequiredForUnlisted for every domain.
    func testDomainsConfig_EmptyDomainsListUsesDefaultForAll() {
        let configRequired = DomainsConfig(sslPinningRequiredForUnlisted: true, domains: [])
        let configNotRequired = DomainsConfig(sslPinningRequiredForUnlisted: false, domains: [])
        
        XCTAssertTrue(configRequired.isPinningRequired(for: .testCommonName_1))
        XCTAssertTrue(configRequired.isPinningRequired(for: .testCommonName_Unknown))
        XCTAssertFalse(configNotRequired.isPinningRequired(for: .testCommonName_1))
        XCTAssertFalse(configNotRequired.isPinningRequired(for: .testCommonName_Unknown))
    }
    
    // MARK: - DomainsConfig integration with CertStore
    
    /// Tests that when DomainsConfig marks a domain as pinning-not-required, validation returns .trusted
    /// regardless of the fingerprint.
    func testDomainsConfig_PinningNotRequired_ReturnsTrustedWithAnyFingerprint() {
        prepareStore(with: .testConfig)
        
        let domains = DomainsConfig(
            sslPinningRequiredForUnlisted: true,
            domains: [DomainConfig(name: .testCommonName_1, sslPinningRequired: false)]
        )
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1)
                .setDomainsConfig(domains)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // Pinning not required for testCommonName_1 → always trusted regardless of fingerprint
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1), .trusted)
    }
    
    /// Tests that when DomainsConfig marks a domain as pinning-not-required, the depth overload also
    /// returns .trusted immediately.
    func testDomainsConfig_PinningNotRequired_ReturnsTrustedWithDepth() {
        prepareStore(with: .testConfig)
        
        let domains = DomainsConfig(
            sslPinningRequiredForUnlisted: true,
            domains: [DomainConfig(name: .testCommonName_1, sslPinningRequired: false)]
        )
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1, depth: 1)
                .setDomainsConfig(domains)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // Pinning not required → trusted at any depth, any fingerprint
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown, depth: 0), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown, depth: 1), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown, depth: 2), .trusted)
    }
    
    /// Tests that when DomainsConfig marks a domain as pinning-required, normal fingerprint
    /// validation takes place (trusted/untrusted/empty as usual).
    func testDomainsConfig_PinningRequired_NormalValidationApplied() {
        prepareStore(with: .testConfig)
        
        let domains = DomainsConfig(
            sslPinningRequiredForUnlisted: false,
            domains: [DomainConfig(name: .testCommonName_1, sslPinningRequired: true)]
        )
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1)
                .setDomainsConfig(domains)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // Pinning required for testCommonName_1 → regular matching rules
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown), .untrusted)
    }
    
    /// Tests that when DomainsConfig is present and marks an unlisted domain as pinning-not-required
    /// (via sslPinningRequiredForUnlisted=false), any fingerprint is trusted for that domain.
    func testDomainsConfig_UnlistedDomainPinningNotRequired_TrustedForAnyFingerprint() {
        prepareStore(with: .testConfig)
        
        let domains = DomainsConfig(
            sslPinningRequiredForUnlisted: false,
            domains: [DomainConfig(name: .testCommonName_1, sslPinningRequired: true)]
        )
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1)
                .setDomainsConfig(domains)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // testCommonName_2 is not in domains list and unlisted pinning is false → trusted
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_2, fingerprint: .testFingerprint_Unknown), .trusted)
    }
    
    /// Tests that when no DomainsConfig is present in the response, normal validation behaviour applies.
    func testDomainsConfig_Absent_NormalValidationApplied() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1)
                // no domainsConfig set
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown), .untrusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_2, fingerprint: .testFingerprint_Unknown), .empty)
    }
    
    /// Tests that DomainsConfig is persisted in CachedData and survives an app restart.
    func testDomainsConfig_PersistedAndRestoredFromCache() {
        prepareStore(with: .testConfig)
        
        let domains = DomainsConfig(
            sslPinningRequiredForUnlisted: true,
            domains: [DomainConfig(name: .testCommonName_1, sslPinningRequired: false)]
        )
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1)
                .setDomainsConfig(domains)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // Simulate app restart
        let newCertStore = CertStore(
            configuration: config,
            cryptoProvider: cryptoProvider,
            secureDataStore: dataStore,
            remoteDataProvider: remoteDataProvider
        )
        
        // DomainsConfig should have been restored from cache → pinning not required
        XCTAssertEqual(newCertStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown), .trusted)
    }
    
    /// Tests that a subsequent update with no DomainsConfig clears it from cache.
    func testDomainsConfig_ClearedOnUpdateWithoutIt() {
        prepareStore(with: .testConfig)
        
        let domains = DomainsConfig(
            sslPinningRequiredForUnlisted: true,
            domains: [DomainConfig(name: .testCommonName_1, sslPinningRequired: false)]
        )
        
        // First update: include DomainsConfig
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1)
                .setDomainsConfig(domains)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        // Pinning disabled → trusted
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown), .trusted)
        
        // Second update: DomainsConfig absent
        remoteDataProvider.reportData = responseGenerator
            .removeAll()
            .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1)
            // no domainsConfig
            .data()
        
        // Use forced mode so the update always hits the network even though cache is still valid
        XCTAssertEqual(forceUpdateStore(), .ok)
        
        // Now normal validation applies again
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown), .untrusted)
    }
    
    // MARK: - Combined: Depth + DomainsConfig
    
    /// Tests that DomainsConfig bypass takes precedence over depth matching — when pinning
    /// is not required for a domain, it returns .trusted without checking fingerprint or depth.
    func testDepthAndDomainsConfig_BypassTakesPrecedenceOverDepthCheck() {
        prepareStore(with: .testConfig)
        
        let domains = DomainsConfig(
            sslPinningRequiredForUnlisted: true,
            domains: [DomainConfig(name: .testCommonName_1, sslPinningRequired: false)]
        )
        
        // Store a cert only at depth 2
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1, depth: 2)
                .setDomainsConfig(domains)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // Pinning not required → trusted even at wrong depth with wrong fingerprint
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown, depth: 0), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown, depth: 1), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown, depth: 2), .trusted)
    }
    
    /// Tests that DomainsConfig pinning-required for one domain does not affect another domain
    /// whose pinning is bypassed, and vice versa.
    func testDepthAndDomainsConfig_MultipleDomainsMixedPinningRequirements() {
        prepareStore(with: .testConfig)
        
        let domains = DomainsConfig(
            sslPinningRequiredForUnlisted: true,
            domains: [
                DomainConfig(name: .testCommonName_1, sslPinningRequired: false),
                DomainConfig(name: .testCommonName_2, sslPinningRequired: true)
            ]
        )
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1, depth: 0)
                .append(commonName: .testCommonName_2, expiration: .valid, fingerprint: .testFingerprint_2, depth: 1)
                .setDomainsConfig(domains)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // testCommonName_1: pinning not required → always trusted
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown, depth: 0), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown, depth: 1), .trusted)
        
        // testCommonName_2: pinning required, cert stored at depth 1
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_2, fingerprint: .testFingerprint_2, depth: 1), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_2, fingerprint: .testFingerprint_Unknown, depth: 1), .untrusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_2, fingerprint: .testFingerprint_2, depth: 0), .empty)
    }
    
    // MARK: - CachedData serialization
    
    /// Tests that CachedData round-trips correctly through JSON with both domainsConfig and certificate depths.
    func testCachedData_SerializationWithDomainsConfigAndDepth() {
        let expires = Expiration.valid.toDate
        let certs = [
            CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, expires: expires, depth: 0),
            CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_2, expires: expires, depth: 1),
            CertificateInfo(commonName: .testCommonName_2, fingerprint: .testFingerprint_2, expires: expires, depth: 2)
        ]
        let domainsConfig = DomainsConfig(
            sslPinningRequiredForUnlisted: false,
            domains: [DomainConfig(name: .testCommonName_1, sslPinningRequired: true)]
        )
        let cached = CachedData(certificates: certs, nextUpdate: expires, domainsConfig: domainsConfig)
        
        let encoded = cached.toJSON()
        let decoded = try? JSON.decoder.decode(CachedData.self, from: encoded)
        
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.certificates.count, certs.count)
        XCTAssertEqual(decoded?.certificates[0].depth, 0)
        XCTAssertEqual(decoded?.certificates[1].depth, 1)
        XCTAssertEqual(decoded?.certificates[2].depth, 2)
        XCTAssertNotNil(decoded?.domainsConfig)
        XCTAssertEqual(decoded?.domainsConfig?.sslPinningRequiredForUnlisted, false)
        XCTAssertEqual(decoded?.domainsConfig?.domains.count, 1)
        XCTAssertEqual(decoded?.domainsConfig?.domains.first?.name, .testCommonName_1)
        XCTAssertEqual(decoded?.domainsConfig?.domains.first?.sslPinningRequired, true)
    }
    
    /// Tests that CachedData without domainsConfig serialises and deserialises correctly
    /// (backward compatibility with cache entries that pre-date domainsConfig).
    func testCachedData_SerializationWithoutDomainsConfig() {
        let expires = Expiration.valid.toDate
        let certs = [
            CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, expires: expires, depth: 0)
        ]
        let cached = CachedData(certificates: certs, nextUpdate: expires, domainsConfig: nil)
        
        let encoded = cached.toJSON()
        let decoded = try? JSON.decoder.decode(CachedData.self, from: encoded)
        
        XCTAssertNotNil(decoded)
        XCTAssertNil(decoded?.domainsConfig)
        XCTAssertEqual(decoded?.certificates.first?.depth, 0)
    }
}
