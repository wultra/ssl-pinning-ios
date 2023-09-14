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

/// The `RestAPI` class implements downloading list of certificates
/// from a remote server. The class is used internally in the CertStore.
internal class RestAPI: NSObject, URLSessionDelegate, RemoteDataProvider {
    
    let config: NetworkConfiguration
    private let cryptoProvider: CryptoProvider
    private let executionQueue: DispatchQueue
    private let delegateQueue: OperationQueue
    private lazy var session: URLSession = {
        return URLSession(configuration: .ephemeral, delegate: self, delegateQueue: delegateQueue)
    }()
    private lazy var jsonDecoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dataDecodingStrategy = .base64
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }()
    
    /// Returns new instance of `JSONEncoder`, preconfigured for our data types serialization.
    private lazy var jsonEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dataEncodingStrategy = .base64
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }()

    init(config: NetworkConfiguration, cryptoProvider: CryptoProvider) {
        config.validate(cryptoProvider: cryptoProvider)
        let dispatchQueue = DispatchQueue(label: "WultraCertStoreNetworking")
        self.config = config
        self.cryptoProvider = cryptoProvider
        self.executionQueue = dispatchQueue
        self.delegateQueue = OperationQueue()
        self.delegateQueue.underlyingQueue = dispatchQueue
    }
    
    enum NetworkError: Error {
        // Error returned in case of neither data nor error were provided.
        case noDataProvided
        // Error returned when non 2xx status code is returned.
        case invalidHttpStatusCode(statusCode: Int)
        /// The update request returned the data which did not pass the signature validation.
        case invalidSignature
        /// The update request returned an invalid data from the server.
        case invalidData
        // Internal error.
        case internalError(message: String)
    }
    
    func getData(currentDate: Date, completion: @escaping (Result<ServerResponse, Error>) -> Void) {
        executionQueue.async { [weak self] in
            guard let this = self else {
                return
            }
            
            var urlRequest = URLRequest(url: this.config.serviceUrl)
            urlRequest.addValue("application/json", forHTTPHeaderField: "Accept")
            urlRequest.httpMethod = "GET"
            
            let requestChallenge: String?
            if this.config.useChallenge {
                let randomChallenge = this.cryptoProvider.getRandomData(length: 16).base64EncodedString()
                urlRequest.addValue(randomChallenge, forHTTPHeaderField: "X-Cert-Pinning-Challenge")
                requestChallenge = randomChallenge
            } else {
                requestChallenge = nil
            }
            
            RestAPI.logRequest(request: urlRequest)
            
            this.session.dataTask(with: urlRequest) { (data, response, error) in
                
                RestAPI.logResponse(response: response, data: data, error: error)
                
                guard let response = response as? HTTPURLResponse else {
                    completion(.failure(NetworkError.internalError(message: "Invalid HTTPURLResponse object")))
                    return
                }
                let headers = response.allStringHeaders
                let statusCode = response.statusCode
                if statusCode / 100 != 2 {
                    WultraDebug.print("RestAPI: HTTP request failed with status code: \(statusCode)")
                    completion(.failure(NetworkError.invalidHttpStatusCode(statusCode: statusCode)))
                } else if let error = error {
                    WultraDebug.print("RestAPI: HTTP request failed with error: \(error)")
                    completion(.failure(error))
                } else if let data = data {
                    this.processReceivedData(data, challenge: requestChallenge, responseHeaders: headers, requestDate: currentDate, completion: completion)
                } else {
                    WultraDebug.print("RestAPI: HTTP request finished with empty response.")
                    completion(.failure(NetworkError.noDataProvided))
                }
            }.resume()
        }
    }
    
    /// Private function processes the received data and returns update result.
    /// The function also updates list of cached certificates, when there's a change in the data.
    private func processReceivedData(_ data: Data, challenge: String?, responseHeaders: [String:String], requestDate: Date, completion: @escaping (Result<ServerResponse, Error>) -> Void) {
        
        // Import public key (may crash in fatalError for invalid configuration)
        let publicKey = cryptoProvider.importECPublicKey(publicKeyBase64: config.publicKey)
        
        // Validate signature
        if config.useChallenge {
            guard let challenge = challenge else {
                WultraDebug.fatalError("Challenge must be set")
            }
            guard let signature = responseHeaders["x-cert-pinning-signature"] else {
                WultraDebug.error("CertStore: Missing signature header.")
                completion(.failure(NetworkError.invalidSignature))
                return
            }
            guard let signatureData = Data(base64Encoded: signature) else {
                completion(.failure(NetworkError.invalidSignature))
                return
            }
            var signedData = Data(challenge.utf8)
            signedData.append(Data("&".utf8))
            signedData.append(data)
            guard cryptoProvider.ecdsaValidateSignatures(signedData: SignedData(data: signedData, signature: signatureData), publicKey: publicKey) else {
                WultraDebug.error("CertStore: Invalid signature in X-Cert-Pinning-Signature header.")
                completion(.failure(NetworkError.invalidSignature))
                return
            }
        }
        
        // Try decode data to response object
        guard let response = try? jsonDecoder.decode(ServerResponse.self, from: data) else {
            // Failed to decode JSON to our model object
            WultraDebug.error("CertStore: Failed to parse JSON received from the server.")
            completion(.failure(NetworkError.invalidData))
            return
        }
        
        // TODO: delegates
        
        completion(.success(response))
    }
    
    /// Dump HTTP request into debug log.
    /// - Parameter request: URL request to print to log.
    private static func logRequest(request: URLRequest) {
        #if DEBUG
        guard WultraDebug.verboseLevel == .all else {
            return
        }
        let httpMethod = request.httpMethod ?? "nil"
        let urlString = request.url?.absoluteString ?? "nil"
        let headers = request.allHTTPHeaderFields ?? [:]
        var message = "HTTP \(httpMethod) request: → \(urlString)"
        if !headers.isEmpty {
            message += "\n  + Headers: \(headers)"
        }
        if let body = request.httpBody {
            message += "\n  + Body: \(Data.toBodyString(data: body))"
        }
        WultraDebug.print(message)
        #endif
    }
    
    
    /// Dump HTTP response to debug log.
    /// - Parameters:
    ///   - response: Response object
    ///   - data: Received data
    ///   - error: Error in case of failure
    private static func logResponse(response: URLResponse?, data: Data?, error: Error?) {
        #if DEBUG
        guard WultraDebug.verboseLevel == .all else {
            return
        }
        let httpResponse = response as? HTTPURLResponse
        let urlString = response?.url?.absoluteString ?? "nil"
        let statusCode = httpResponse?.statusCode ?? 0
        let headers = httpResponse?.allStringHeaders ?? [:]
        var message = "HTTP \(statusCode) response: ← \(urlString)"
        message += "\n  + Headers: \(headers)"
        message += "\n  + Data: \(Data.toBodyString(data: data))"
        if let error = error {
            message += "\n  + Error: \(error)"
        }
        WultraDebug.print(message)
        #endif
    }
    
    // URLSessionDelegate
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        config.sslValidationStrategy.validate(challenge: challenge, completionHandler: completionHandler)
    }
}

fileprivate extension HTTPURLResponse {
    var allStringHeaders: [String:String] {
        return allHeaderFields
            .reduce(into: [:]) { (result, tuple) in
                guard let key = tuple.key as? String, let value = tuple.value as? String else {
                    return
                }
                result[key.lowercased()] = value
            }
    }
}

fileprivate extension Data {
    
    /// Helper function converts Data object to human readable string representation for
    /// debug purposes. If it's possible to convert data to UTF-8 string then returns such
    /// string, otherwise return Base64 encoded content of data. If data is empty or nil,
    /// then returns "empty" constant.
    ///
    /// - Returns: Human readable string.
    static func toBodyString(data: Data?) -> String {
        guard let data = data, !data.isEmpty else {
            return "empty"
        }
        guard let string = String(data: data, encoding: .utf8) else {
            return data.base64EncodedString()
        }
        return string
    }
}
