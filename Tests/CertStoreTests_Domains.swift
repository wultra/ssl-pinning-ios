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

import XCTest
@testable import WultraSSLPinning

class CertStoreTests_Domains: XCTestCase {
    
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
    
    // MARK: - Unit tests
    
    static override func setUp() {
        WultraDebug.verboseLevel = .all
    }

    func testSubdomainMismatch() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: "github.com", expiration: .valid, fingerprint: .testFingerprint_1, domains: ["github.com"])
                .data()
        
        let updateResult = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)

        let validationResult = certStore.validate(commonName: "github.com", fingerprint: .testFingerprint_1, domain: "gist.github.com")
        XCTAssertEqual(validationResult, .empty, "Validation should fail for mismatched subdomain (empty)")
    }
    
    func testSubdomainMatch() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: "github.com", expiration: .valid, fingerprint: .testFingerprint_1, domains: ["github.com"])
                .data()
        
        let updateResult = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)

        let validationResult = certStore.validate(commonName: "github.com", fingerprint: .testFingerprint_1, domain: "github.com")
        XCTAssertEqual(validationResult, .trusted, "Validation should match for domain")
    }
    
    func testSubdomainMatchButInvalid() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: "github.com", expiration: .valid, fingerprint: .testFingerprint_2, domains: ["github.com"])
                .data()
        
        let updateResult = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)

        let validationResult = certStore.validate(commonName: "github.com", fingerprint: .testFingerprint_1, domain: "github.com")
        XCTAssertEqual(validationResult, .untrusted, "Validation should fail for proper domain but invalid fingerprint")
    }
    
    func testSubdomainMatchNoDomain() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: "github.com", expiration: .valid, fingerprint: .testFingerprint_1)
                .data()
        
        let updateResult = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)

        let validationResult = certStore.validate(commonName: "github.com", fingerprint: .testFingerprint_1, domain: "github.com")
        XCTAssertEqual(validationResult, .trusted, "Validation should be OK")
    }
    
    func testSubdomainMatchMixed() {
        prepareStore(with: .testConfig)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: "github.com", expiration: .never, fingerprint: .testFingerprint_1, domains: ["github.com"])
                .append(commonName: "github.com", expiration: .valid, fingerprint: .testFingerprint_1)
                .data()
        
        let updateResult = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)

        let validationResult = certStore.validate(commonName: "github.com", fingerprint: .testFingerprint_1, domain: "github.com")
        XCTAssertEqual(validationResult, .trusted, "Validation should be OK")
    }
}
