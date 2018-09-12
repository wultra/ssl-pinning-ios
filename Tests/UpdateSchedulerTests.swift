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

class UpdateSchedulerTests: XCTestCase {
    
    func testScheduler_PickNewer() {
        
        // Must pick "testCommonName_1 / testFingerprint_1" as closest for update
        
        let certs: [CertificateInfo] = [
            CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_2, expires: Date(timeIntervalSince1970: 200.0)),
            CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, expires: Date(timeIntervalSince1970: 100.0)),
        ]
        let scheduler = UpdateScheduler(periodicUpdateInterval: 20.0, expirationUpdateTreshold: 10.0, thresholdMultiplier: 0.125)
        var now = Date(timeIntervalSince1970: 0)
        var scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 20)
        
        now = Date(timeIntervalSince1970: 80.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 20)
        
        now = Date(timeIntervalSince1970: 100.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 20)
        
        now = Date(timeIntervalSince1970: 192.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == (200-192) * 0.125)
        
        now = Date(timeIntervalSince1970: 220.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 0)
    }
    
    func testScheduler_PickDifferentCA1() {
        
        // Must pick "testCommonName_2" as closest for update
        
        let certs: [CertificateInfo] = [
            CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, expires: Date(timeIntervalSince1970: 200.0)),
            CertificateInfo(commonName: .testCommonName_2, fingerprint: .testFingerprint_2, expires: Date(timeIntervalSince1970: 100.0))
            ]
        let scheduler = UpdateScheduler(periodicUpdateInterval: 20.0, expirationUpdateTreshold: 10.0, thresholdMultiplier: 0.125)
        var now = Date(timeIntervalSince1970: 0)
        var scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 20)
        
        now = Date(timeIntervalSince1970: 80.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 20)
        
        now = Date(timeIntervalSince1970: 92.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == (100-92) * 0.125)
        
        now = Date(timeIntervalSince1970: 110.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 0)
        
        now = Date(timeIntervalSince1970: 220.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 0)
    }

    func testScheduler_PickDifferentCA2() {
        
        // Must pick "testCommonName_2" as closest for update
        
        let certs: [CertificateInfo] = [
            CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_2, expires: Date(timeIntervalSince1970: 200.0)),
            CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, expires: Date(timeIntervalSince1970: 100.0)),
            CertificateInfo(commonName: .testCommonName_2, fingerprint: .testFingerprint_Fallback, expires: Date(timeIntervalSince1970: 100.0))
        ]
        let scheduler = UpdateScheduler(periodicUpdateInterval: 20.0, expirationUpdateTreshold: 10.0, thresholdMultiplier: 0.125)
        var now = Date(timeIntervalSince1970: 0)
        var scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 20)
        
        now = Date(timeIntervalSince1970: 80.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 20)
        
        now = Date(timeIntervalSince1970: 92.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == (100-92) * 0.125)
        
        now = Date(timeIntervalSince1970: 110.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 0)
        
        now = Date(timeIntervalSince1970: 220.0)
        scheduled = scheduler.scheduleNextUpdate(certificates: certs, currentDate: now)
        XCTAssertTrue(scheduled.timeIntervalSince(now) == 0)
    }
}
