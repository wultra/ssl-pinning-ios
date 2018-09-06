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

import PowerAuth2

public class PowerAuthCryptoProvider: CryptoProvider {
    
    // MARK: - CryptoProvider protocol
    
    public func ecdsaValidateSignatures(signedData: SignedData, publicKey: ECPublicKey) -> Bool {
        // Cast abstract interface to PA2ECPublicKey
        guard let ecKey = publicKey as? PA2ECPublicKey else {
            fatalError("Unknown type of ECPublicKey")
        }
        return PA2CryptoUtils.ecdsaValidateSignature(signedData.signature, for: signedData.data, for: ecKey)
    }
    
    public func importECPublicKey(publicKey: Data) -> ECPublicKey? {
        return PA2ECPublicKey(data: publicKey)
    }
    
    public func hashSha256(data: Data) -> Data {
        // Just calculate SHA-256
        return PA2CryptoUtils.hashSha256(data)
    }
}

extension PA2ECPublicKey: ECPublicKey {
}
