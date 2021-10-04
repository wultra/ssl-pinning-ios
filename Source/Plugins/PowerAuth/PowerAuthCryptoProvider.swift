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
import PowerAuthCore

///
/// The `PowerAuthCryptoProvider` implements `CryptoProvider` interface with using
/// functions provided by the PowerAuth SDK. If your application is already using
/// PowerAuth, then this is the recommended implementation for you.
///
public class PowerAuthCryptoProvider: CryptoProvider {
    
    /// Public constructor
    public init() {}
    
    // MARK: - CryptoProvider protocol
    
    public func ecdsaValidateSignatures(signedData: SignedData, publicKey: ECPublicKey) -> Bool {
        // Cast abstract interface to PowerAuthCoreECPublicKey
        guard let ecKey = publicKey as? PowerAuthCoreECPublicKey else {
            WultraDebug.fatalError("Invalid ECPublicKey object.")
        }
        return PowerAuthCoreCryptoUtils.ecdsaValidateSignature(signedData.signature, for: signedData.data, for: ecKey)
    }
    
    public func importECPublicKey(publicKey: Data) -> ECPublicKey? {
        return PowerAuthCoreECPublicKey(data: publicKey)
    }
    
    public func hashSha256(data: Data) -> Data {
        // Just calculate SHA-256
        return PowerAuthCoreCryptoUtils.hashSha256(data)
    }
    
    public func getRandomData(length: Int) -> Data {
        var data = Data(count: length)
        let result = data.withUnsafeMutableBytes { (ptr) -> Int32 in
            if let rawPtr = ptr.baseAddress {
                return SecRandomCopyBytes(kSecRandomDefault, length, rawPtr)
            }
            return errSecAllocate
        }
        guard result == errSecSuccess else {
            WultraDebug.fatalError("Cannot generate enough random bytes")
        }
        return data
    }
}

extension PowerAuthCoreECPublicKey: ECPublicKey {
    // Makes `PowerAuthCoreECPublicKey` compatible with `ECPublicKey` interface
}
