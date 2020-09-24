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
/// The `RestAPI` class implements downloading list of certificates
/// from a remote server. The class is used internally in the CertStore.
///
internal class RestAPI: RemoteDataProvider {
    
    private let baseURL: URL
    private let session: URLSession
    private let executionQueue: DispatchQueue
    
    init(baseURL: URL) {
        self.baseURL = baseURL
        self.session = URLSession(configuration: .ephemeral)
        self.executionQueue = DispatchQueue(label: "WultraCertStoreNetworking")
    }
    
    enum NetworkError: Error {
        // Error returned in case of neither data nor error were provided.
        case noDataProvided
        // Error returned when non 2xx status code is returned.
        case invalidHttpStatusCode(statusCode: Int)
        // Internal error.
        case internalError(message: String)
    }
    
    func getFingerprints(request: RemoteDataRequest, completion: @escaping (RemoteDataResponse) -> Void) {
        executionQueue.async { [weak self] in
            guard let this = self else {
                return
            }
            var urlRequest = URLRequest(url: this.baseURL)
            urlRequest.addValue("application/json", forHTTPHeaderField: "Accept")
            request.requestHeaders.forEach { key, value in
                urlRequest.addValue(value, forHTTPHeaderField: key)
            }
            urlRequest.httpMethod = "GET"
            
            this.session.dataTask(with: urlRequest) { (data, response, error) in
                guard let response = response as? HTTPURLResponse else {
                    completion(RemoteDataResponse(result: .failure(NetworkError.internalError(message: "Invalid HTTPURLResponse object")), responseHeaders: [:]))
                    return
                }
                let headers = response.allStringHeaders
                let statusCode = response.statusCode
                if statusCode / 100 != 2 {
                    WultraDebug.print("RestAPI: HTTP request failed with status code: \(statusCode)")
                    completion(RemoteDataResponse(result: .failure(NetworkError.invalidHttpStatusCode(statusCode: statusCode)), responseHeaders: headers))
                } else if let error = error {
                    WultraDebug.print("RestAPI: HTTP request failed with error: \(error)")
                    completion(RemoteDataResponse(result: .failure(error), responseHeaders: headers))
                } else if let data = data {
                    completion(RemoteDataResponse(result: .success(data), responseHeaders: headers))
                } else {
                    WultraDebug.print("RestAPI: HTTP request finished with empty response.")
                    completion(RemoteDataResponse(result: .failure(NetworkError.noDataProvided), responseHeaders: headers))
                }
            }.resume()
        }
    }
}

fileprivate extension HTTPURLResponse {
    var allStringHeaders: [String:String] {
        return allHeaderFields
            .reduce(into: [:]) { (result, tuple) in
                guard let key = tuple.key as? String, let value = tuple.value as? String else {
                    return
                }
                result[key] = value
            }
    }
}
