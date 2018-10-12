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
        let refDate = Date()
        
        prepareStore(with: .testConfig)
        
        //
        // [ 1 ] Prepare data for initial cert, which will be expired soon.
        //       The data can be loaded instantly in this phase of test.
        //
        WultraDebug.print(" [ 1   ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
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
        WultraDebug.print(" [ 2   ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        
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
        WultraDebug.print(" [ 2.1 ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        WultraDebug.print("         Next update : \(certStore.getCachedData()?.nextUpdate.timeIntervalSince(refDate) ?? -1)")
        
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
        WultraDebug.print(" [ 3   ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        WultraDebug.print("         Next update : \(certStore.getCachedData()?.nextUpdate.timeIntervalSince(refDate) ?? -1)")
        
        elapsed = Thread.measureElapsedTime {
            updateResult = AsyncHelper.wait { completion in
                self.certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertEqual(updateResult.value, .ok)
        }
        
        // Wait to complete bg update (otherwise there will be race in accessing to interceptor)
        Thread.waitFor(interval: .testLatency_ForFastUpdate)
        
        XCTAssertTrue(elapsed < .testLatency_ForFastUpdate)
        XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 1)
        
        //
        // [ 3.1 ] This update must not call the remote server.
        //         It's too close to previous update.
        WultraDebug.print(" [ 3.1 ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        WultraDebug.print("         Next update : \(certStore.getCachedData()?.nextUpdate.timeIntervalSince(refDate) ?? -1)")
        
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
        XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 1)
        
        // Now wait for the next periodic update
        Thread.waitFor(interval: .testUpdateInterval_PeriodicUpdate)
        
        //
        // [ 3.2 ] This update must call the remote server.
        //         It's triggered by the periodic update.
        WultraDebug.print(" [ 3.2 ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        WultraDebug.print("         Next update : \(certStore.getCachedData()?.nextUpdate.timeIntervalSince(refDate) ?? -1)")
        
        remoteDataProvider.interceptor = .clean
        elapsed = Thread.measureElapsedTime {
            updateResult = AsyncHelper.wait { completion in
                self.certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertEqual(updateResult.value, .ok)
        }
        
        // Wait to complete bg update (otherwise there will be race in accessing to interceptor)
        Thread.waitFor(interval: .testLatency_ForFastUpdate)
        WultraDebug.print("         Next update : \(certStore.getCachedData()?.nextUpdate.timeIntervalSince(refDate) ?? -1)")
        
        XCTAssertTrue(elapsed < .testLatency_ForFastUpdate)
        XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 1)
        
        // Now wait for the next periodic update
        Thread.waitFor(interval: .testUpdateInterval_PeriodicUpdate)
        
        //
        // [ 3.3 ] This update must call the remote server.
        //         It's triggered by the periodic update.
        WultraDebug.print(" [ 3.3 ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        WultraDebug.print("         Next update : \(certStore.getCachedData()?.nextUpdate.timeIntervalSince(refDate) ?? -1)")
        
        remoteDataProvider.interceptor = .clean
        elapsed = Thread.measureElapsedTime {
            updateResult = AsyncHelper.wait { completion in
                self.certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertEqual(updateResult.value, .ok)
        }
        
        // Wait to complete bg update (otherwise there will be race in accessing to interceptor)
        Thread.waitFor(interval: .testLatency_ForFastUpdate)
        WultraDebug.print("         Next update : \(certStore.getCachedData()?.nextUpdate.timeIntervalSince(refDate) ?? -1)")
        
        XCTAssertTrue(elapsed < .testLatency_ForFastUpdate)
        XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 1)
        
        // At this point, we should be in the window, which may trigger update based on
        // the expiration date. So, we need to wait for once more time
        
        Thread.waitFor(interval: .testUpdateInterval_PeriodicUpdate)
        
        //
        // [ 3.4 ] This update must call the remote server.
        //         It's triggered by the periodic update.
        WultraDebug.print(" [ 3.4 ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        WultraDebug.print("         Next update : \(certStore.getCachedData()?.nextUpdate.timeIntervalSince(refDate) ?? -1)")
        
        remoteDataProvider.interceptor = .clean
        elapsed = Thread.measureElapsedTime {
            updateResult = AsyncHelper.wait { completion in
                self.certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertEqual(updateResult.value, .ok)
        }
        
        // Wait to complete bg update (otherwise there will be race in accessing to interceptor)
        Thread.waitFor(interval: .testLatency_ForFastUpdate)
        
        XCTAssertTrue(elapsed < .testLatency_ForFastUpdate)
        XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 1)
        
        // Now wait for a bit shorter time interval, to test, whether the silent update is triggered sooner
        Thread.waitFor(interval: 1.0)
        
        //
        // [ 4.0 ] This update must call the remote server.
        //         It's triggered by the certificate's expiration date.
        WultraDebug.print(" [ 4.0 ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        WultraDebug.print("         Next update : \(certStore.getCachedData()?.nextUpdate.timeIntervalSince(refDate) ?? -1)")
        
        remoteDataProvider.interceptor = .clean
        elapsed = Thread.measureElapsedTime {
            updateResult = AsyncHelper.wait { completion in
                self.certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertEqual(updateResult.value, .ok)
        }
        
        // Wait to complete bg update (otherwise there will be race in accessing to interceptor)
        Thread.waitFor(interval: .testLatency_ForFastUpdate)
        
        XCTAssertTrue(elapsed < .testLatency_ForFastUpdate)
        XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 1)
        
        // Now wait for certificate expiration...
        
        Thread.waitFor(interval: .testUpdateInterval_PeriodicUpdate)
        WultraDebug.print(" [ 4.1 ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        Thread.waitFor(interval: .testUpdateInterval_PeriodicUpdate, message: "Don't worry. This suffering will end someday!")
        WultraDebug.print(" [ 4.2 ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        Thread.waitFor(interval: .testUpdateInterval_PeriodicUpdate, message: "We're almost there...")
        WultraDebug.print(" [ 4.4 ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        Thread.waitFor(interval: 2, message: "Just a second!")
        
        // Ok, now the certificate is expired. The remote update must return the empty store.
        
        //
        // [ 5.0 ] This update must be blocking. All certificates are expired.
        //         It's triggered by the certificate's expiration date.
        WultraDebug.print(" [ 5.0 ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        WultraDebug.print("         Next update : \(certStore.getCachedData()?.nextUpdate.timeIntervalSince(refDate) ?? -1)")
        
        remoteDataProvider.interceptor = .clean
        elapsed = Thread.measureElapsedTime {
            updateResult = AsyncHelper.wait { completion in
                self.certStore.update { (result, error) in
                    completion.complete(with: result)
                }
            }
            XCTAssertEqual(updateResult.value, .storeIsEmpty)
        }
        XCTAssertTrue(elapsed > .testLatency_ForFastUpdate)
        XCTAssertTrue(remoteDataProvider.interceptor.called_getFingerprints == 1)
        
        // The previous certificate is still trusted. We don't update the database in case of update error
        validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_1)
        XCTAssertTrue(validationResult == .empty)
        
        remoteDataProvider
            .reportData = responseGenerator
                .append(commonName: .testCommonName_1, expiration: .valid, fingerprint: .testFingerprint_2)
                .data()
        
        //
        // [ 5.0 ] This update must be blocking. All certificates are expired.
        //         It's triggered by the certificate's expiration date.
        WultraDebug.print(" [ 5.1 ] Elapsed time: \(-refDate.timeIntervalSinceNow)")
        WultraDebug.print("         Next update : \(certStore.getCachedData()?.nextUpdate.timeIntervalSince(refDate) ?? -1)")
        
        updateResult = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        // Check whether outdated cert was removed
        XCTAssertTrue(certStore.getCachedData()?.certificates.count == 1)
        
        // Now try to validate
        validationResult = certStore.validate(commonName: .testCommonName_1, fingerprint: .testFingerprint_2)
        XCTAssertTrue(validationResult == .trusted)
        
    }
}
