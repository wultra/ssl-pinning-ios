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

class PowerAuthCryptoProviderTests: XCTestCase {
    
    func testSha256() {
        let cp = PowerAuthCryptoProvider()
        
        let vectors = [
            (   "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            ),(
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            ),(
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
            )
        ]
        
        vectors.forEach { (input, hash) in
            guard let inputBytes = input.data(using: .utf8) else {
                XCTFail("Wrong test data")
                return
            }
            guard let expected  = Data.fromHex(hash) else {
                XCTFail("Wrong test data")
                return
            }
            let calculated = cp.hashSha256(data: inputBytes)
            XCTAssertEqual(expected, calculated)
        }

    }
    
    func testEcdsaSignatureValidation() {
        let cp = PowerAuthCryptoProvider()
        let commonName  = "www.google.com"
        let timestamp   = "1540280280000"
        let fingerprint = "nu1DOBz31Y5FY6lRNkJV/HdnB6BDVCp7mX0nxkbub7Y="
        guard
            let publicKeyData = Data(base64Encoded: "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo="),
            let signedData = "\(commonName)&\(fingerprint)&\(timestamp)".data(using: .utf8),
            let signature = Data(base64Encoded: "MEQCIGDeccZP1CqyOCX9//L7duCKY8eYxYfKUAr0z4XWi7//AiAaOyhAtFqpcpULGzVescjmGgVrPIY77h9D45em9y9o8w==")
        else {
            XCTFail("Invalid test data")
            return
        }
        guard let publicKey = cp.importECPublicKey(publicKey: publicKeyData) else {
            XCTFail("Invalid test data")
            return
        }
        let signedDataObject = SignedData(data: signedData, signature: signature)
        let result = cp.ecdsaValidateSignatures(signedData: signedDataObject, publicKey: publicKey)
        XCTAssertTrue(result)
    }
    
}
