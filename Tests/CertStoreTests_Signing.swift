//
// Copyright 2020 Wultra s.r.o.
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

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
class CertStoreTests_Signing: XCTestCase {

    var config: CertStoreConfiguration!
    var certStore: CertStore!
    
    var cryptoProvider: CryptoProvider!
    var dataStore: TestingSecureDataStore!
    var remoteDataProvider: TestingRemoteDataProvider!
    
    let responseGenerator = ResponseGenerator()
    let keyPair = ECDSA.generateKeyPair()
    
    func prepareStore() {
        self.config = CertStoreConfiguration(
            serviceUrl: URL(string: "https://example.org/pinning-service")!,
            publicKey: keyPair.publicKey.stringRepresentation
        )
        cryptoProvider = PowerAuthCryptoProvider()
        dataStore = TestingSecureDataStore()
        remoteDataProvider = TestingRemoteDataProvider()
        certStore = CertStore(
            configuration: config,
            cryptoProvider: cryptoProvider,
            secureDataStore: dataStore,
            remoteDataProvider: remoteDataProvider
        )
    }
    
    // MARK: - Unit tests
    
    static override func setUp() {
        WultraDebug.verboseLevel = .all
    }
    
    func testMissingSignatureHeader() {
        // Arrange: valid response body, but no x-cert-pinning-signature header at all.
        prepareStore()
        
        remoteDataProvider.reportData = responseGenerator
            .append(commonName: .testCommonName_1, expiration: .never, fingerprint: .testFingerprint_1)
            .data()
        remoteDataProvider.omitSignatureHeader()
        
        // Act
        let updateResult = AsyncHelper.wait { completion in
            certStore.update { result, error in
                completion.complete(with: result)
            }
        }
        
        // Assert: absent header must be treated as an invalid signature — security-critical.
        XCTAssertEqual(updateResult.value, .invalidSignature)
        
        // The store must remain empty; no certificate should have been persisted.
        XCTAssertEqual(certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1), .empty)
    }
    
    func testSigning() {
        
        prepareStore()
        
        remoteDataProvider.signResponse(with: keyPair.privateKey)
        remoteDataProvider.reportData = responseGenerator
            .append(commonName: .testCommonName_1, expiration: .never, fingerprint: .testFingerprint_1)
            .append(commonName: .testCommonName_2, expiration: .never, fingerprint: .testFingerprint_2)
            .data()
        
        let updateResult = AsyncHelper.wait { completion in
            certStore.update { result, error in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        
        var validateResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
        XCTAssertTrue(validateResult == .trusted)
        validateResult = certStore.validate(commonName: .testCommonName_2, fingerprint: .testFingerprint_2)
        XCTAssertTrue(validateResult == .trusted)
    }
}
