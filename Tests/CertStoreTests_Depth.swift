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
/// Tests for certificate depth functionality: depth-aware fingerprint matching,
/// CertificateInfo model depth handling, and depth serialization in CachedData.
///
class CertStoreTests_Depth: XCTestCase {
    
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
    
    static override func setUp() {
        WultraDebug.verboseLevel = .all
    }
    
    // MARK: - Certificate Depth Tests
    
    /// Tests that a leaf-certificate fingerprint (depth 0) is correctly validated when the
    /// server responds with an entry that has no explicit depth (backward compat defaults to 0).
    func testCertDepth_BackwardCompatibility_NoDepthDefaultsToLeaf() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                // no depth specified → should behave as depth 0
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // depth 0 should match the stored leaf cert
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, depth: 0), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1), .trusted)
    }
    
    /// Tests that a cert entry pinned at depth 1 (intermediate) is only trusted at depth 1,
    /// not at depth 0 or depth 2.
    func testCertDepth_IntermediateCert_MatchesOnlyAtCorrectDepth() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1, depth: 1)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // depth 1 — should match
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, depth: 1), .trusted)
        // depth 0 — wrong depth, same CN is known at depth 1 only → untrusted (matchAttempts = 0 at depth 0 → empty)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, depth: 0), .empty)
        // depth 2 — also wrong depth → empty
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, depth: 2), .empty)
    }
    
    /// Tests that wrong fingerprint at the correct depth returns untrusted.
    func testCertDepth_WrongFingerprintAtCorrectDepth_ReturnsUntrusted() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1, depth: 1)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // Known CN at depth 1, but wrong fingerprint → untrusted
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown, depth: 1), .untrusted)
    }
    
    /// Tests that multiple entries for the same CN at different depths are all correctly stored
    /// and validated independently.
    func testCertDepth_MultipleDepthsForSameCN() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1, depth: 0)
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_2, depth: 1)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // Each depth matches its own fingerprint
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, depth: 0), .trusted)
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_2, depth: 1), .trusted)
        
        // Cross-depth: fingerprint 1 at depth 1 → wrong fingerprint at that depth → untrusted
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, depth: 1), .untrusted)
        // Cross-depth: fingerprint 2 at depth 0 → wrong fingerprint at that depth → untrusted
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_2, depth: 0), .untrusted)
    }
    
    /// Tests that the no-argument `validate(commonName:fingerprint:)` and
    /// `validate(commonName:fingerprint:depth:0)` are equivalent.
    func testCertDepth_DefaultValidateEquivalentToDepthZero() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1, depth: 0)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        let resultDefault = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
        let resultDepth0  = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, depth: 0)
        XCTAssertEqual(resultDefault, resultDepth0)
        XCTAssertEqual(resultDefault, .trusted)
    }
    
    /// Tests that a depth-1 entry does not interfere with the legacy depth-less validate path.
    func testCertDepth_DepthOneCertDoesNotAffectLegacyValidate() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1, depth: 1)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        
        // Legacy validate() (depth 0) — no matching depth-0 cert → empty
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1), .empty)
    }
    
    /// Tests that a certificate depth stored in cache is correctly restored after an app restart
    /// (i.e. persisted and loaded from the data store).
    func testCertDepth_PersistedAndRestoredFromCache() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1, depth: 2)
                .data()
        
        XCTAssertEqual(updateStore(), .ok)
        XCTAssertEqual(dataStore.interceptor.called_save, 1)
        
        // Simulate app restart by creating a new CertStore backed by the same data store
        let newCertStore = CertStore(
            configuration: config,
            cryptoProvider: cryptoProvider,
            secureDataStore: dataStore,
            remoteDataProvider: remoteDataProvider
        )
        
        // Should validate correctly from restored cache
        XCTAssertEqual(newCertStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, depth: 2), .trusted)
        XCTAssertEqual(newCertStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, depth: 0), .empty)
    }
    
    // MARK: - CertificateInfo model tests
    
    /// Tests that CertificateInfo initialised from a response entry without a depth defaults to 0.
    func testCertificateInfo_DepthDefaultsToZeroWhenAbsent() {
        let entry = GetFingerprintsResponse.Entry(
            name: .testCommonName_1,
            fingerprint: .testFingerprint_1,
            expires: Expiration.valid.toDate,
            signature: nil,
            depth: nil
        )
        let info = CertificateInfo(from: entry)
        XCTAssertEqual(info.depth, 0)
    }
    
    /// Tests that CertificateInfo initialised from a response entry with depth 2 stores depth 2.
    func testCertificateInfo_DepthIsPreservedFromResponseEntry() {
        let entry = GetFingerprintsResponse.Entry(
            name: .testCommonName_1,
            fingerprint: .testFingerprint_1,
            expires: Expiration.valid.toDate,
            signature: nil,
            depth: 2
        )
        let info = CertificateInfo(from: entry)
        XCTAssertEqual(info.depth, 2)
    }
    
    /// Tests that the convenience CertificateInfo initialiser (without depth) defaults depth to 0.
    func testCertificateInfo_ConvenienceInitDefaultsDepthToZero() {
        let info = CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, expires: Expiration.valid.toDate)
        XCTAssertEqual(info.depth, 0)
    }
    
    /// Tests CertificateInfo equality: two entries with identical fields but different depths are not equal.
    func testCertificateInfo_EqualityConsidersDepth() {
        let expires = Expiration.valid.toDate
        let infoDepth0 = CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, expires: expires, depth: 0)
        let infoDepth1 = CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, expires: expires, depth: 1)
        let infoDepth0Copy = CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, expires: expires, depth: 0)
        
        XCTAssertNotEqual(infoDepth0, infoDepth1)
        XCTAssertEqual(infoDepth0, infoDepth0Copy)
    }
    
    // MARK: - CachedData serialization
    
    /// Tests that CachedData with depth values round-trips correctly through JSON.
    func testCachedData_DepthValuesRoundTrip() {
        let expires = Expiration.valid.toDate
        let certs = [
            CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, expires: expires, depth: 0),
            CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_2, expires: expires, depth: 1),
            CertificateInfo(commonName: .testCommonName_2, fingerprint: .testFingerprint_2, expires: expires, depth: 2)
        ]
        let cached = CachedData(certificates: certs, nextUpdate: expires, domainsConfig: nil)
        
        let encoded = cached.toJSON()
        let decoded = try? JSON.decoder.decode(CachedData.self, from: encoded)
        
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.certificates.count, certs.count)
        XCTAssertEqual(decoded?.certificates[0].depth, 0)
        XCTAssertEqual(decoded?.certificates[1].depth, 1)
        XCTAssertEqual(decoded?.certificates[2].depth, 2)
    }
    
    /// Tests that legacy CachedData JSON without "d" (depth) key in certificates fails to
    /// deserialise, because `CertificateInfo.depth` is a required (non-optional) field.
    ///
    /// This documents a known limitation: cached data written by a version of the library that
    /// pre-dates the depth feature cannot be decoded by this version. On app upgrade the cache
    /// will be cleared and fresh data fetched from the server.
    func testCachedData_LegacyFormatWithoutDepthKey() {
        // Build legacy JSON manually — no "d" key in the certificate entry
        let expiresTimestamp = Expiration.valid.toDate.timeIntervalSince1970
        let fingerprintBase64 = Data.testFingerprint_1.base64EncodedString()
        let legacyJSON = """
        {
            "c": [
                {
                    "n": "\(String.testCommonName_1)",
                    "f": "\(fingerprintBase64)",
                    "e": \(expiresTimestamp)
                }
            ],
            "u": \(expiresTimestamp)
        }
        """.data(using: .utf8)!
        
        // depth is a required (non-optional) field → decoding fails when absent
        let decoded = try? JSON.decoder.decode(CachedData.self, from: legacyJSON)
        XCTAssertNil(decoded, "Legacy cache without 'd' key should fail to decode since depth is a required field")
    }
}
