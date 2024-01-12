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

class CertStoreTests_LoadSave: XCTestCase {
    
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
        remoteDataProvider = TestingRemoteDataProvider(
            networkConfig: .init(
                serviceUrl: URL(string: "https://example.org/pinning-service")!,
                publicKey: ""
            ),
            cryptoProvider: cryptoProvider
        )
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
    
    /**
     This test validates whether the loaded list of certificate info objects
     are stored to the persistent storage in right order.
     
     The next purpose is to simulate app restart and validate, whether CertStore
     is able to deserialize its previously stored state.
     */
    func testLoadSave() {
        
        prepareStore(with: .testConfig)
        
        // At first, we need to update an empty store
        remoteDataProvider
            .setNoLatency()
            .reportResponse = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_Fallback)
                .append(commonName: .testCommonName_1, expiration: .never, fingerprint: .testFingerprint_1)
                .append(commonName: .testCommonName_2, expiration: .never, fingerprint: .testFingerprint_2)
                .appendLast()   // duplicit entry, to test filtering
                .data()
        let updateResult = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        XCTAssertTrue(dataStore.interceptor.called_loadData == 1)   // initial load
        XCTAssertTrue(dataStore.interceptor.called_save == 1)       // save after update
        XCTAssertTrue(dataStore.interceptor.called_removeData == 0)
        
        // Now we have data serialized in the dataStore, lets investigate that
        guard let cdata = dataStore.retrieveCachedData(forKey: certStore.instanceIdentifier) else {
            XCTFail("No data were stored")
            return
        }
        XCTAssertEqual(cdata.certificates.count, 3)
        
        // Now we tests whether the certificates were sorted properly by date and name.
        // The sort algorithm sorts cers by common name. If there are more entries for the same
        // common name, then the entries with expiration in more distant future are first.
        
        XCTAssertEqual(cdata.certificates[0].commonName, .testCommonName_1)
        XCTAssertEqual(cdata.certificates[0].fingerprint, .testFingerprint_1)
        XCTAssertEqual(cdata.certificates[1].commonName, .testCommonName_1)
        XCTAssertEqual(cdata.certificates[1].fingerprint, .testFingerprint_Fallback)
        XCTAssertEqual(cdata.certificates[2].commonName, .testCommonName_2)
        XCTAssertEqual(cdata.certificates[2].fingerprint, .testFingerprint_2)
        
        // OK, let's test the deserialization. We need to create a new instance of CertStore,
        // with keeping data in dataStore
        
        certStore = CertStore(
            configuration: .testConfig,
            cryptoProvider: cryptoProvider,
            secureDataStore: dataStore,
            remoteDataProvider: remoteDataProvider)
        // Reset data store's interceptor
        dataStore.interceptor = .clean
        
        // Now try to validate certificates
        var validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
        XCTAssertTrue(validationResult == .trusted)
        validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Fallback)
        XCTAssertTrue(validationResult == .trusted)
        validationResult = certStore.validate(commonName: .testCommonName_2, fingerprint: .testFingerprint_2)
        XCTAssertTrue(validationResult == .trusted)
        
        // After all updates, there must be just one access to load
        XCTAssertTrue(dataStore.interceptor.called_loadData == 1)   // initial deserialization
        XCTAssertTrue(dataStore.interceptor.called_save == 0)
        XCTAssertTrue(dataStore.interceptor.called_removeData == 0)
    }
    
    /**
     This test validates whether the CertStore.reset() really resets the cache
     and whether the store is able to recover after the reset.
     */
    func testReset() {
        
        prepareStore(with: .testConfig)
        
        // At first, we need to update an empty store
        remoteDataProvider
            .setNoLatency()
            .reportResponse = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_Fallback)
                .append(commonName: .testCommonName_1, expiration: .never, fingerprint: .testFingerprint_1)
                .append(commonName: .testCommonName_2, expiration: .never, fingerprint: .testFingerprint_2)
                .data()
        var updateResult = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        XCTAssertTrue(dataStore.interceptor.called_loadData == 1)   // initial load
        XCTAssertTrue(dataStore.interceptor.called_save == 1)       // save after update
        XCTAssertTrue(dataStore.interceptor.called_removeData == 0)
        
        // Now we have data serialized in the dataStore, lets investigate that
        guard let cdata = dataStore.retrieveCachedData(forKey: certStore.instanceIdentifier) else {
            XCTFail("No data were stored")
            return
        }
        XCTAssertEqual(cdata.certificates.count, 3)
        
        // Now try to validate certificates
        var validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
        XCTAssertTrue(validationResult == .trusted)
        validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Fallback)
        XCTAssertTrue(validationResult == .trusted)
        validationResult = certStore.validate(commonName: .testCommonName_2, fingerprint: .testFingerprint_2)
        XCTAssertTrue(validationResult == .trusted)
        
        // Now reset the store
        dataStore.interceptor = .clean
        certStore.reset()
        
        // Validations should return empty now...
        validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
        XCTAssertTrue(validationResult == .empty)
        validationResult = certStore.validate(commonName: .testCommonName_2, fingerprint: .testFingerprint_2)
        XCTAssertTrue(validationResult == .empty)
        
        // Also there must be only one remove issued to data store
        XCTAssertTrue(dataStore.interceptor.called_loadData == 0)   // initial load
        XCTAssertTrue(dataStore.interceptor.called_save == 0)       // save after update
        XCTAssertTrue(dataStore.interceptor.called_removeData == 1)
        
        // Now try to update from remote store, to check whether cert store can recover after the reset.
        dataStore.interceptor = .clean
        updateResult = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        XCTAssertTrue(dataStore.interceptor.called_loadData == 0)   // initial load
        XCTAssertTrue(dataStore.interceptor.called_save == 1)       // save after update
        XCTAssertTrue(dataStore.interceptor.called_removeData == 0)
        
        // And validate again...
        validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
        XCTAssertTrue(validationResult == .trusted)
        validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_Fallback)
        XCTAssertTrue(validationResult == .trusted)
        validationResult = certStore.validate(commonName: .testCommonName_2, fingerprint: .testFingerprint_2)
        XCTAssertTrue(validationResult == .trusted)
    }
}
