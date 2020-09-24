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

import Foundation

///
/// The `CryptoProvider` protocol defines interface for performing several
/// cryptographic primitives, required by this library.
///
public protocol CryptoProvider: class {
    
    /// Validates whether data has not been modified.
    ///
    /// - Parameter data: Data which has been signed with private key
    /// - Parameter signedData: Array of SignedData structures
    /// - Parameter publicKey: EC public key
    ///
    /// - Returns true if all signatures are correct
    func ecdsaValidateSignatures(signedData: SignedData, publicKey: ECPublicKey) -> Bool
    
    /// Constructs a new ECPublicKey object from given ASN.1 formatted data blob.
    ///
    /// - Parameter publicKey: ASN.1 formatted data blob with EC public ket.
    /// - Returns: Object representing public key or nil in case of error.
    func importECPublicKey(publicKey: Data) -> ECPublicKey?
    
    /// Computes SHA-256 hash from given data.
    ///
    /// - Parameter data: Data to be hashed
    /// - Returns: 32 bytes hash, calculated as `SHA256(data)`
    func hashSha256(data: Data) -> Data
    
    /// Generate random data.
    ///
    /// - Parameter length: Number of random bytes to be produced.
    /// - Returns: `Data` with requested number of random bytes.
    func getRandomData(length: Int) -> Data
}

/// The `SignedData` structure contains data and signature calculated for
/// that data.
public struct SignedData {
    
    /// Data which has been signed with private key.
    public let data: Data
    
    /// Signature calculated from data, with using private key.
    public let signature: Data
}

/// The `ECPublicKey` protocol is an abstract interface representing
/// a public key in EC based cryptography.
public protocol ECPublicKey: class {
}

