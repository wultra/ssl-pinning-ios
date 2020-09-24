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

import WultraSSLPinning

class TestingCryptoProvider: CryptoProvider {
    
    struct Interceptor {
        var called_ecdsaValidateSignatures = 0
        var called_importECPublicKey = 0
        var called_hashSha256 = 0
        var called_getRandomData = 0
        
        static var clean: Interceptor { return Interceptor() }
    }
    
    let powerAuthCryptoProvider: CryptoProvider
    
    init() {
        powerAuthCryptoProvider = PowerAuthCryptoProvider()
    }

    // MARK: - Configuration for testing
    
    var failureOnEcdsaValidation = false
    var failureOnImportECPublicKey = false
    
    /// Additional validation closure, which can be used if simple `failureOnEcdsaValidation` is
    /// not sufficient.
    var onEcdsaValidation: ((SignedData, DummyECPublicKey)->Bool)?
    
    var interceptor = Interceptor()
    
    // MARK: - CryptoProvider implementation
    
    func ecdsaValidateSignatures(signedData: SignedData, publicKey: ECPublicKey) -> Bool {
        interceptor.called_ecdsaValidateSignatures += 1
        if let closure = onEcdsaValidation {
            return closure(signedData, publicKey as! DummyECPublicKey)
        }
        return failureOnEcdsaValidation == false
    }
    
    /// You can provide an UTF8 encoded bytes to publicKey, which will then represent the name of the key.
    func importECPublicKey(publicKey: Data) -> ECPublicKey? {
        interceptor.called_importECPublicKey += 1
        if failureOnImportECPublicKey == false {
            let keyName = String(data: publicKey, encoding: .utf8)
            return DummyECPublicKey(keyName: keyName)
        }
        return nil
    }
    
    func hashSha256(data: Data) -> Data {
        interceptor.called_hashSha256 += 1
        return powerAuthCryptoProvider.hashSha256(data: data)
    }
    
    func getRandomData(length: Int) -> Data {
        interceptor.called_getRandomData += 1
        return powerAuthCryptoProvider.getRandomData(length: length)
    }
    
    /// Dummy class returned from importECPublicKey()
    class DummyECPublicKey: ECPublicKey {
        
        let keyName: String
        
        init(keyName: String?) {
            self.keyName = keyName ?? "defaultTestingKey"
        }
    }
}
