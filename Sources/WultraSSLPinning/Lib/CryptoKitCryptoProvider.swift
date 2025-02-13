//
// Copyright 2025 Wultra s.r.o.
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

import CryptoKit

/// The `CryptoKitCryptoProvider` implements `CryptoProvider` interface with using
/// functions provided from the CryptoKit.
public class CryptoKitCryptoProvider: CryptoProvider {
    
    /// Public constructor
    public init() {}
    
    /// Validates whether data has not been modified.
    ///
    /// - Parameter signedData: Signed data and the signature
    /// - Parameter publicKey: EC public key. Must be `P256.Signing.PublicKey` from CryptoKit otherwise will result in fatal error.
    ///
    /// - Returns true if all signatures are correct
    public func ecdsaValidateSignatures(signedData: SignedData, publicKey: any ECPublicKey) -> Bool {
        
        // Cast abstract interface to PowerAuthCoreECPublicKey
        guard let ecKey = publicKey as? P256.Signing.PublicKey else {
            WultraDebug.fatalError("Invalid ECPublicKey object (P256.Signing.PublicKey expected).")
        }
        
        do {
            let signature = try P256.Signing.ECDSASignature(derRepresentation: signedData.signature)
            return ecKey.isValidSignature(signature, for: signedData.data)
        } catch {
            print("Signature validation failed. Error: \(error)")
            return false
        }
    }
    
    /// Computes SHA-256 hash from given data.
    ///
    /// - Parameter data: Data to be hashed
    /// - Returns: 32 bytes hash, calculated as `SHA256(data)`
    public func hashSha256(data: Data) -> Data {
        return Data(SHA256.hash(data: data))
    }
    
    /// Generate random data.
    ///
    /// - Parameter length: Number of random bytes to be produced.
    /// - Returns: `Data` with requested number of random bytes.
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
    
    /// Constructs a new ECPublicKey object from given ASN.1 formatted data blob.
    ///
    /// - Parameter publicKey: ASN.1 formatted data blob with EC public ket.
    /// - Returns: Object representing public key (`P256.Signing.PublicKey`) or nil in case of error.
    public func importECPublicKey(publicKey: Data) -> (any ECPublicKey)? {
        return try? P256.Signing.PublicKey(x963Representation: publicKey)
    }
}

@available(iOS 13.0, *)
extension P256.Signing.PublicKey: ECPublicKey {
    // Makes `P256.Signing.PublicKey` compatible with `ECPublicKey` interface
}
