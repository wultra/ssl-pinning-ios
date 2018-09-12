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

class CertStoreTests_Basics: XCTestCase {
    
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
    
    func allConfigs() -> [(config: CertStoreConfiguration, name: String, hasFallback: Bool)] {
        return [
            (.testConfig, "Without Fallback", false),
            (.testConfigWithFallbackCertificate(expiration: .valid), "Valid Fallback", true),
            (.testConfigWithFallbackCertificate(expiration: .expired), "Expired Fallback", true),
        ]
    }
    
    // MARK: - Unit tests
    
    static override func setUp() {
        WultraDebug.verboseLevel = .all
    }
    
    func testEmptyStore_UpdateNoRemoteData() {
        allConfigs().forEach { (configData) in
            
            var updateResult: Result<CertStore.UpdateResult>
            
            print("Running 'testEmptyStore_UpdateNoRemoteData' for \(configData.name)")
            
            prepareStore(with: configData.config)
            
            remoteDataProvider
                .setNoLatency()
                .reportData = responseGenerator
                    .removeAll()
                    .data()
            
            updateResult = AsyncHelper.wait { completion in
                certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertTrue(updateResult.value == .storeIsEmpty)
            XCTAssertTrue(cryptoProvider.interceptor.called_importECPublicKey == 2)     // One import must be called + one for initial config validation
            XCTAssertTrue(dataStore.interceptor.called_loadData == 1)                   // One load from persistent store must be called
            XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 1)   // One getFingerprints must be called
            
            // Call update again
            
            updateResult = AsyncHelper.wait { completion in
                certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertTrue(updateResult.value == .storeIsEmpty)
            XCTAssertTrue(cryptoProvider.interceptor.called_importECPublicKey == 3)     // One more import
            XCTAssertTrue(dataStore.interceptor.called_loadData == 1)                   // No more load data
            XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 2)   // Yet another getFigerprints
            
        }
    }
    
    
    func testEmptyStore_Validate() {
        allConfigs().forEach { (configData) in
            
            var validationResult: CertStore.ValidationResult
            
            print("Running 'testEmptyStore_Validate' for \(configData.name)")
            
            prepareStore(with: configData.config)
            
            remoteDataProvider
                .setNoLatency()
                .reportData = responseGenerator
                    .removeAll()
                    .data()
            
            validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
            XCTAssertTrue(validationResult == .empty)
            XCTAssertTrue(cryptoProvider.interceptor.called_importECPublicKey == 1)     // Initial config validation
            XCTAssertTrue(dataStore.interceptor.called_loadData == 1)                   // One load from persistent store must be called
            XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 0)   // No access to remote data
            
            validationResult = certStore.validate(commonName: .testCommonName_Unknown, fingerprint: .testFingerprint_Unknown)
            XCTAssertTrue(validationResult == .empty)
            XCTAssertTrue(cryptoProvider.interceptor.called_importECPublicKey == 1)     // Initial config validation
            XCTAssertTrue(dataStore.interceptor.called_loadData == 1)                   // No more loads
            XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 0)   // No access to remote data
            
            validationResult = certStore.validate(commonName: .testCommonName_Fallback, fingerprint: .testFingerprint_Fallback)
            XCTAssertTrue(validationResult == (configData.hasFallback ? .trusted : .empty))
            XCTAssertTrue(cryptoProvider.interceptor.called_importECPublicKey == 1)     // Initial config validation
            XCTAssertTrue(dataStore.interceptor.called_loadData == 1)                   // No more loads
            XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 0)   // No access to remote data
            
            validationResult = certStore.validate(commonName: .testCommonName_Fallback, fingerprint: .testFingerprint_Unknown)
            XCTAssertTrue(validationResult == (configData.hasFallback ? .untrusted : .empty))
            XCTAssertTrue(cryptoProvider.interceptor.called_importECPublicKey == 1)     // Initial config validation
            XCTAssertTrue(dataStore.interceptor.called_loadData == 1)                   // No more loads
            XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 0)   // No access to remote data
        }
    }
    
    func testEmptyStore_UpdateToAlreadyExpiredData() {
        allConfigs().forEach { (configData) in
            
            var updateResult: Result<CertStore.UpdateResult>
            var validationResult: CertStore.ValidationResult
            
            print("Running 'testEmptyStore_UpdateToAlreadyExpiredData' for \(configData.name)")
            
            prepareStore(with: configData.config)
            
            remoteDataProvider
                .setNoLatency()
                .reportData = responseGenerator
                    .removeAll()
                    .append(commonName: .testCommonName_1, expiration: .expired, fingerprint: .testFingerprint_1)
                    .data()
            
            validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
            XCTAssertTrue(validationResult == .empty)
            
            updateResult = AsyncHelper.wait { completion in
                certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            // After update, result should be still "empty", because the loaded certificate is already expired
            XCTAssertTrue(updateResult.value == .storeIsEmpty)
            validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
            XCTAssertTrue(validationResult == .empty)
            
            // Unknown CN
            validationResult = certStore.validate(commonName: .testCommonName_Unknown, fingerprint: .testFingerprint_Unknown)
            XCTAssertTrue(validationResult == .empty)
            validationResult = certStore.validate(commonName: .testCommonName_Unknown, fingerprint: .testFingerprint_Fallback)
            XCTAssertTrue(validationResult == .empty)
            validationResult = certStore.validate(commonName: .testCommonName_Unknown, fingerprint: .testFingerprint_1)
            XCTAssertTrue(validationResult == .empty)
            
            // Validate against fallback
            validationResult = certStore.validate(commonName: .testCommonName_Fallback, fingerprint: .testFingerprint_Fallback)
            XCTAssertTrue(validationResult == (configData.hasFallback ? .trusted : .empty))
            validationResult = certStore.validate(commonName: .testCommonName_Fallback, fingerprint: .testFingerprint_Unknown)
            XCTAssertTrue(validationResult == (configData.hasFallback ? .untrusted : .empty))
        }
    }
    
    func testEmptyStore_UpdateToValidData() {
        allConfigs().forEach { (configData) in
            
            print("Running 'testEmptyStore_UpdateToValidData' for \(configData.name)")
            
            prepareStore(with: configData.config)
            
            remoteDataProvider
                .setNoLatency()
                .reportData = responseGenerator
                    .removeAll()
                    .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1)
                    .data()
            
            var validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
            XCTAssertTrue(validationResult == .empty)
            
            let updateResult: Result<CertStore.UpdateResult> = AsyncHelper.wait { completion in
                certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            // The update must finish with OK
            XCTAssertTrue(updateResult.value == .ok)
            
            // Now the fingerprint is already in store, validation should pass
            validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
            XCTAssertTrue(validationResult == .trusted)
            validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Unknown)
            XCTAssertTrue(validationResult == .untrusted)
            
            // Unknown CN
            validationResult = certStore.validate(commonName: .testCommonName_Unknown, fingerprint: .testFingerprint_Unknown)
            XCTAssertTrue(validationResult == .empty)
            validationResult = certStore.validate(commonName: .testCommonName_Unknown, fingerprint: .testFingerprint_Fallback)
            XCTAssertTrue(validationResult == .empty)
            validationResult = certStore.validate(commonName: .testCommonName_Unknown, fingerprint: .testFingerprint_1)
            XCTAssertTrue(validationResult == .empty)
            
            // Validate against fallback
            validationResult = certStore.validate(commonName: .testCommonName_Fallback, fingerprint: .testFingerprint_Fallback)
            XCTAssertTrue(validationResult == (configData.hasFallback ? .trusted : .empty))
            validationResult = certStore.validate(commonName: .testCommonName_Fallback, fingerprint: .testFingerprint_Unknown)
            XCTAssertTrue(validationResult == (configData.hasFallback ? .untrusted : .empty))
        }
    }
    
    func testEmptyStore_UpdateFails() {
        allConfigs().forEach { (configData) in
            
            print("Running 'testEmptyStore_UpdateFails' for \(configData.name)")
            
            var updateResult: Result<CertStore.UpdateResult>
            var reportedError: Error? = nil
            
            prepareStore(with: configData.config)
            
            // Test network error handling
            
            remoteDataProvider
                .setNoLatency()
                .setReportError(true)
            
            updateResult = AsyncHelper.wait { completion in
                certStore.update { (result, error) in
                    reportedError = error
                    completion.complete(with: result)
                }
            }
            XCTAssertTrue(updateResult.value == .networkError)
            XCTAssertNotNil(reportedError)
            
            // Test invalid signature handling
            
            remoteDataProvider
                .setNoLatency()
                .setReportError(false)
                .reportData = responseGenerator
                    .removeAll()
                    .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_1)
                    .data()
            
            cryptoProvider.failureOnEcdsaValidation = true
            
            updateResult = AsyncHelper.wait { completion in
                certStore.update { (result, error) in
                    reportedError = error
                    completion.complete(with: result)
                }
            }
            XCTAssertTrue(updateResult.value == .invalidSignature)
            XCTAssertNil(reportedError)
            
            // Test complete invalid data
            
            remoteDataProvider
                .setNoLatency()
                .setReportError(false)
                .reportData = "UNEXPECTED SERVER ERROR".data(using: .ascii)
            
            cryptoProvider.failureOnEcdsaValidation = false
            
            updateResult = AsyncHelper.wait { completion in
                certStore.update { (result, error) in
                    reportedError = error
                    completion.complete(with: result)
                }
            }
            XCTAssertTrue(updateResult.value == .invalidData)
            XCTAssertNil(reportedError)
        }
    }
    
    // MARK: - Error handling
    
    // TODO: make test for network error
    
}
