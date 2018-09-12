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

class CertificateInfoTests: XCTestCase {
    
    func testSorting() {
        
        var certs: [CertificateInfo] =
            [
                CertificateInfo(commonName: .testCommonName_2, fingerprint: .testFingerprint_2, expires: Date(timeIntervalSince1970: 300.0)),
                CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_2, expires: Date(timeIntervalSince1970: 100.0)),
                CertificateInfo(commonName: .testCommonName_1, fingerprint: .testFingerprint_1, expires: Date(timeIntervalSince1970: 200.0)),
                CertificateInfo(commonName: .testCommonName_2, fingerprint: .testFingerprint_1, expires: Date(timeIntervalSince1970: 200.0)),
                CertificateInfo(commonName: .testCommonName_Unknown, fingerprint: .testFingerprint_Unknown, expires: Date(timeIntervalSince1970: 0)),
            ]
        certs.sortCertificates()
        
        XCTAssertTrue(certs[0].commonName == .testCommonName_1)
        XCTAssertTrue(certs[0].fingerprint == .testFingerprint_1)
        
        XCTAssertTrue(certs[1].commonName == .testCommonName_1)
        XCTAssertTrue(certs[1].fingerprint == .testFingerprint_2)
        
        XCTAssertTrue(certs[2].commonName == .testCommonName_2)
        XCTAssertTrue(certs[2].fingerprint == .testFingerprint_2)
        
        XCTAssertTrue(certs[3].commonName == .testCommonName_2)
        XCTAssertTrue(certs[3].fingerprint == .testFingerprint_1)
        
        XCTAssertTrue(certs[4].commonName == .testCommonName_Unknown)
        XCTAssertTrue(certs[4].fingerprint == .testFingerprint_Unknown)
    }
    
}
