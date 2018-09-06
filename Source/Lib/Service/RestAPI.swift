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
    }
    
    func getFingerprints(completion: @escaping (Result<Data>) -> Void) {
        executionQueue.async { [weak self] in
            guard let this = self else {
                return
            }
            var request = URLRequest(url: this.baseURL)
            request.addValue("application/json", forHTTPHeaderField: "Accept")
            request.httpMethod = "GET"
            
            this.session.dataTask(with: request) { (data, response, error) in
                if let data = data {
                    completion(.success(data))
                } else if let error = error {
                    WultraDebug.print("RestAPI: HTTP request failed with error: \(error)")
                    completion(.failure(error))
                } else {
                    completion(.failure(NetworkError.noDataProvided))
                }
            }.resume()
        }
    }
}
