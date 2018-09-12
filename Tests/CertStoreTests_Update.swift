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

class CertStoreTests_Update: XCTestCase {
    
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
    
    /**
     This test loads valid certificates and waits until all are expired.
     Then it tries to update with new set of certificates.
     
     ## WARNING
     
     Note that this test depends on real time clock, so any breakpoint
     triggered in the test body may cause a false positive results.
     */
    func testUpdate_WholeCycle() {

        var updateResult: Result<CertStore.UpdateResult>
        var validationResult: CertStore.ValidationResult
        var elapsed: TimeInterval
        
        prepareStore(with: .testConfig)
        
        //
        // [ 1 ] Prepare data for initial cert, which will be expired soon.
        //       The data can be loaded instantly in this phase of test.
        //
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
                .removeAll()
                .append(commonName: .testCommonName_1, expiration: .soon, fingerprint: .testFingerprint_1)
                .data()
        
        updateResult = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
        XCTAssertTrue(validationResult == .trusted)

        //
        // [ 2 ] This update should not call the remote server,
        //       It's too close to last update.
        //
        remoteDataProvider.setLatency(.testLatency_ForSilentUpdate)
        remoteDataProvider.interceptor = .clean
        
        elapsed = Thread.measureElapsedTime {
            updateResult = AsyncHelper.wait { completion in
                self.certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertEqual(updateResult.value, .ok)
        }
        XCTAssertTrue(elapsed < .testLatency_ForFastUpdate)                         // ellapsed must be very short
        XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 0)   // no remote update was called
        
        // Now wait for a while, to get a closer to expiration threshold, but not too close to trigger periodic update.
        Thread.waitFor(interval: .testUpdateInterval_PeriodicUpdate / 2)
        
        //
        // [ 2.1 ] This update must not call the remote server.
        //         There's no reason for that, no certificate is going to expire soon.
        //
        remoteDataProvider.interceptor = .clean
        elapsed = Thread.measureElapsedTime {
            updateResult = AsyncHelper.wait { completion in
                self.certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertEqual(updateResult.value, .ok)
        }
        XCTAssertTrue(elapsed < .testLatency_ForFastUpdate)
        XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 0)
        
        // Wait once more time, to get closer to the expiration point
        Thread.waitFor(interval: .testUpdateInterval_PeriodicUpdate / 2 + 0.1)
        
        //
        // [ 3 ] This update should call remote server, but on the background.
        //       The periodic update did trigger background update
        elapsed = Thread.measureElapsedTime {
            updateResult = AsyncHelper.wait { completion in
                self.certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertEqual(updateResult.value, .ok)
        }
        XCTAssertTrue(elapsed < .testLatency_ForFastUpdate)
        XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 1)
        
        //
        // [ 3.1 ] This update must not call the remote server.
        //         It's too close to previous update
        //
        remoteDataProvider.interceptor = .clean
        elapsed = Thread.measureElapsedTime {
            updateResult = AsyncHelper.wait { completion in
                self.certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertEqual(updateResult.value, .ok)
        }
        XCTAssertTrue(elapsed < .testLatency_ForFastUpdate)
        XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 0)
        
        // Append updated certfificate
        remoteDataProvider
            .reportData = responseGenerator
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_2)
                .data()
        
        updateResult = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)

        
    }
}
