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

public extension CertStore {
    
    /// Result from update certificates request.
    public enum UpdateResult {
        
        /// Update succeeded
        case ok
        
        /// The update request succeeded, but the result is still an empty list of certificates.
        /// This may happen when the loading & validating of remote data succeeded, but all loaded
        /// certificates are already expired.
        case empty
        
        /// The update request failed on network error.
        case networkError
        
        /// The update request returned an invalid data from the server.
        case invalidData
        
        /// The update request returned the data which did not pass the signature validation.
        case invalidSignature
    }
    
    /// Updates
    public func update(completionQueue: DispatchQueue = .main, completion: @escaping (UpdateResult)->Void) -> Void {
        
        // Acquire whole cached data structure
        let cachedData = getCachedData()
        
        var needsDirectUpdate = true
        var needsSilentUpdate = false
        
        if let cachedData = cachedData {
            // Check whether there's still some valid certificate. If not, then we have to perform
            // immediate update and application must wait for the result.
            needsDirectUpdate = cachedData.numberOfValidCertificates == 0
            if needsDirectUpdate == false {
                // If direct update is not required, then check whether we should perform a silent one
                needsSilentUpdate = cachedData.nextUpdate.timeIntervalSinceNow < 0
            }
        }
        
        if needsDirectUpdate {
            // Perform direct update and wait for the result
            doUpdate(completionQueue: completionQueue, completion: completion)
            //
        } else {
            // If silent update is required, then start that update now
            // and report "OK" result to completion queue
            if needsSilentUpdate {
                doUpdate(completionQueue: nil, completion: nil)
            }
            // Returns "OK" result to the completion queue
            completionQueue.async {
                completion(.ok)
            }
        }
    }
    
    private func doUpdate(completionQueue: DispatchQueue?, completion: ((UpdateResult)->Void)?) -> Void {
        // Fetch fingerprints data from the remote data provider
        remoteDataProvider.getFingerprints { (data, error) in
            let result: UpdateResult
            if let data = data {
                result = self.processReceivedData(data)
            } else {
                result = .networkError
            }
            completionQueue?.async {
                completion?(result)
            }
        }
    }
    
    /// Private function processes the received data and returns update result.
    /// The function also updates list of cached certificates, when there's a change in the data.
    private func processReceivedData(_ data: Data) -> UpdateResult {
        
        // Try decode data to response object
        guard let response = try? jsonDecoder().decode(GetFingerprintsResponse.self, from: data) else {
            // Failed to decode JSON to our model object
            return .invalidData
        }
        // Import public key (may crash in fatalError for invalid configuration)
        let publicKey = importECPublicKey()
        
        // Try to update cached data with the newly received objects.
        // The `updateCachedData` method guarantees atomicity of the operation.
        var result = UpdateResult.ok
        //
        updateCachedData { (cachedData) -> CachedData? in
            //
            // This closure is called while internal thread lock is acquired.
            //
            var newCertificates = (cachedData?.certificates ?? []).filter { !$0.isExpired }
            
            // Iterate over all entries in the response
            for entry in response.fingerprints {
                // Convert entry to CI
                let newCI = CertificateInfo(from: entry)
                if newCI.isExpired {
                    // Received entry is already expired, just skip it.
                    continue
                }
                if newCertificates.index(of: newCI) != nil {
                    // This particular entry is already in the database, just skip it.
                    // Due to fact, that we're using the same array for newly accepted certs,
                    // then it will also filter duplicities received from the server.
                    continue
                }
                // Validate signature
                guard let signedData = entry.dataForSignatureValidation else {
                    // Failed to construct bytes for signature validation. I think this may
                    // never happen, unless "entry.name" contains some invalid UTF8 chars.
                    result = .invalidData
                    break
                }
                guard cryptoProvider.ecdsaValidateSignatures(signedData: signedData, publicKey: publicKey) else {
                    result = .invalidSignature
                    break
                }
                // Everything looks fine, just append newCI to the list of new certificates.
                newCertificates.append(newCI)
            }
            
            guard result == .ok else {
                // Returning nil here means that we're not modifying cached data. This typically means
                // that next call to "update" will force the next data load.
                return nil
            }
            
            // In case that some CI is going to expire soon, we should trigger the next silent update sooner
            let shorterWaitForSilentUpdate = newCertificates.filter { $0.expires.timeIntervalSinceNow < configuration.expirationUpdateTreshold }.count > 0
            let nextUpdate = Date(timeIntervalSinceNow: shorterWaitForSilentUpdate ? 60*60 : configuration.periodicUpdateInterval)
            
            // Finally, construct a new cached data.
            var newData = CachedData(certificates: newCertificates, nextUpdate: nextUpdate)
            newData.sortCertificates()
            return newData
        }
        //
        return result
    }
    
    /// The private function imports EC public key from `CertStoreConfiguration`. The function
    /// may crash when invalid key is provided.
    private func importECPublicKey() -> ECPublicKey {
        guard let publicKeyData = Data(base64Encoded: configuration.publicKey),
            let publicKey = cryptoProvider.importECPublicKey(publicKey: publicKeyData) else {
                fatalError("CertStoreConfiguration contains invalid public key.")
        }
        return publicKey
    }
}
