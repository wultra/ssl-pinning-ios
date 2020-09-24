//
// Copyright 2020 Wultra s.r.o.
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
import CryptoKit
@testable import WultraSSLPinning

/// The `ECDSA` helper class provides sign and verify functions for ECDSA-SHA256 signatures.
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
class ECDSA {
    
    typealias PrivateKey = P256.Signing.PrivateKey
    typealias PublicKey = P256.Signing.PublicKey
    
    struct KeyPair {
        let privateKey: PrivateKey
        let publicKey: PublicKey
    }
    
    static func generateKeyPair() -> KeyPair {
        let privateKey = PrivateKey(compactRepresentable: true)
        return KeyPair(privateKey: privateKey, publicKey: privateKey.publicKey)
    }
    
    static func sign(privateKey: PrivateKey, data: Data) -> Data {
        do {
            let signature = try privateKey.signature(for: data)
            return signature.derRepresentation
        } catch {
            fatalError("Signature computation failed. Error: \(error)")
        }
    }
    
    static func verify(publicKey: PublicKey, data: Data, signature: Data) -> Bool {
        do {
            let signature = try P256.Signing.ECDSASignature(derRepresentation: signature)
            return publicKey.isValidSignature(signature, for: data)
        } catch {
            print("Signature validation failed. Error: \(error)")
            return false
        }
    }
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
extension ECDSA.PublicKey {
    var stringRepresentation: String {
        return x963Representation.base64EncodedString()
    }
}

