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
    
    /// Defines modes of update request
    public enum UpdateMode {
        
        /// The default mode keeps periodicity of handling on the CertStore
        case `default`
        
        /// The forced update tells the `CertStore` that is should update certificates right
        /// now. You should use this mode only if `validate()` method returns "empty" validation
        /// result, otherwise the `.default` is always recommended.
        ///
        /// Note that in "forced" mode the completion block is called always after the update
        /// is finished.
        case forced
    }
    
    /// Result from update certificates request.
    public enum UpdateResult {
        
        /// Update succeeded
        case ok
        
        /// The update request succeeded, but the result is still an empty list of certificates.
        /// This may happen when the loading & validating of remote data succeeded, but all loaded
        /// certificates are already expired.
        case storeIsEmpty
        
        /// The update request failed on a network communication.
        case networkError
        
        /// The update request returned an invalid data from the server.
        case invalidData
        
        /// The update request returned the data which did not pass the signature validation.
        case invalidSignature
    }
    
    /// Tells `CertStore` to update its database of certificates from the remote location.
    ///
    /// ## Discussion
    ///
    /// The update operation basically works in three modes, depending on whether the database of certificates
    /// is empty, or not.
    /// 1. If database of certificates is empty, the the **"immediate"** update is enforced and the "completion" block
    ///    is called after the update is finished. This basically means that the application has to wait for
    ///    certificate fetch.
    ///
    /// 2. If there are some certificates, but some is expire soon, then the **"silent"** update mode is applied
    ///    and the `completion` block is immediately scheduled to the `completionQueue` with `ok` result.
    ///    The update of certificates is performed silently by the library. The silent update is also performed
    ///    periodically, once per week by default.
    ///
    /// 3. If there are some certificates and none is closing to its expiration date, then the `completion`
    ///    block is immediately scheduled to the `completionQueue` with `ok` result.
    ///
    /// - Parameter mode: Mode of update operation (`.default` is recommended)
    /// - Parameter completionQueue: The completion queue for scheduling the completion block callback. The default is `.main`.
    /// - Parameter completion: The completion closure called at the end of operation, with following parameters:
    /// - Parameter result: Resut of the update operation
    /// - Parameter error: An optional error, returned in case that operation failed on communication with the remote location.
    public func update(mode: UpdateMode = .default, completionQueue: DispatchQueue = .main, completion: @escaping (_ result: UpdateResult, _ error: Error?)->Void) -> Void {
        
        // Acquire whole cached data structure
        let cachedData = getCachedData()
        
        var needsDirectUpdate = true
        var needsSilentUpdate = false
        
        if let cachedData = cachedData {
            // Check whether there's still some valid certificate. If not, then we have to perform
            // immediate update and application must wait for the result.
            needsDirectUpdate = cachedData.numberOfValidCertificates == 0 || mode == .forced
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
                completion(.ok, nil)
            }
        }
    }
    
    /// Private function implemens the update operation.
    private func doUpdate(completionQueue: DispatchQueue?, completion: ((UpdateResult, Error?)->Void)?) -> Void {
        // Fetch fingerprints data from the remote data provider
        remoteDataProvider.getFingerprints { response in
            let result: UpdateResult
            if let data = response.value {
                result = self.processReceivedData(data)
            } else {
                result = .networkError
            }
            completionQueue?.async {
                completion?(result, response.error)
            }
        }
    }
    
    /// Private function processes the received data and returns update result.
    /// The function also updates list of cached certificates, when there's a change in the data.
    private func processReceivedData(_ data: Data) -> UpdateResult {
        
        // Try decode data to response object
        guard let response = try? jsonDecoder().decode(GetFingerprintsResponse.self, from: data) else {
            // Failed to decode JSON to our model object
            WultraDebug.error("CertStore: Failed to parse JSON received from the server.")
            return .invalidData
        }
        // Import public key (may crash in fatalError for invalid configuration)
        let publicKey = cryptoProvider.importECPublicKey(publicKeyBase64: configuration.publicKey)
        
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
                    WultraDebug.error("CertStore: Failed to prepare data for signature validation. CN = '\(entry.name)'")
                    result = .invalidData
                    break
                }
                guard cryptoProvider.ecdsaValidateSignatures(signedData: signedData, publicKey: publicKey) else {
                    WultraDebug.error("CertStore: Invalid signature detected. CN = '\(entry.name)'")
                    result = .invalidSignature
                    break
                }
                if let expectedCN = self.configuration.expectedCommonNames {
                    if !expectedCN.contains(newCI.commonName) {
                        // CertStore will store this CI, but validation will ignore this entry, due to fact, that it's not
                        // in "expectedCommonNames" list.
                        WultraDebug.warning("CertStore: Loaded data contains name, which will not be trusted. CN = '\(entry.name)'")
                    }
                }
                // Everything looks fine, just append newCI to the list of new certificates.
                newCertificates.append(newCI)
            }
            
            /// Check whether there's at least one certificate.
            if newCertificates.isEmpty {
                // Looks like it's time to update list of certificates stored on the server.
                WultraDebug.warning("CertStore: Database after update is still empty.")
                result = .storeIsEmpty
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
}

extension CryptoProvider {
    
    /// Convenience method for importing EC public key from provided BASE64 string.
    /// The function may crash on fatal error, when the key is not valid.
    func importECPublicKey(publicKeyBase64: String) -> ECPublicKey {
        guard let publicKeyData = Data(base64Encoded: publicKeyBase64),
            let publicKey = importECPublicKey(publicKey: publicKeyData) else {
                fatalError("CertStoreConfiguration contains invalid public key.")
        }
        return publicKey
    }
}
