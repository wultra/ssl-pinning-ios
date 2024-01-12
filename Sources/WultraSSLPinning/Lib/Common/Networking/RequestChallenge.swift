//
// Copyright 2023 Wultra s.r.o.
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

import Foundation

internal class RequestChallenge {
    
    init(cryptoProvider: CryptoProvider, length: Int = 16) {
        self.cryptoProvider = cryptoProvider
        self.challenge = cryptoProvider.getRandomData(length: length).base64EncodedString()
    }
    
    let challenge: String
    
    private let cryptoProvider: CryptoProvider
    
    func getHeader() -> (headerField: String, value: String) {
        return ("X-Cert-Pinning-Challenge", challenge)
    }
    
    func addToRequest(_ request: inout URLRequest) {
        let header = getHeader()
        request.addValue(header.value, forHTTPHeaderField: header.headerField)
    }
    
    func verifyData(_ data: Data, forSignature signature: String, withKey publicKey: String) -> Bool {
        // Import public key (may crash in fatalError for invalid configuration)
        let pubKey = cryptoProvider.importECPublicKey(publicKeyBase64: publicKey)
        
        guard let signatureData = Data(base64Encoded: signature) else {
            return false
        }
        var signedData = Data(challenge.utf8)
        signedData.append(Data("&".utf8))
        signedData.append(data)
        guard cryptoProvider.ecdsaValidateSignatures(signedData: SignedData(data: signedData, signature: signatureData), publicKey: pubKey) else {
            WultraDebug.error("CertStore: Invalid signature in X-Cert-Pinning-Signature header.")
            return false
        }
        return true
    }
    
    func verifyData(_ data: Data, forHTTPHeaders headers: [String: String], withKey publicKey: String) -> Bool {
        
        guard let signature = headers["x-cert-pinning-signature"] else {
            WultraDebug.error("CertStore: Missing signature header.")
            return false
        }
        return verifyData(data, forSignature: signature, withKey: publicKey)
    }
}
