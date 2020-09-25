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

class RemoteObject {
    
    enum RemoteError: Error {
        case invalidResponse
        case invalidResponseObject
        case invalidJSON
        case wrongStatusCode
    }
    
    let session: URLSession
    let request: URLRequest
    
    init(session: URLSession = URLSession.shared, request: URLRequest) {
        self.session = session
        self.request = request
    }
    
    func get() -> Data? {
        return getRemoteData()
    }
    
    func get<T>() -> T? where T: Decodable {
        guard let data = getRemoteData() else {
            return nil
        }
        let decoder = JSONDecoder()
        decoder.dataDecodingStrategy = .base64
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(T.self, from: data)
    }

    private func getRemoteData() -> Data? {
        let result: Result<Data, Error> = AsyncHelper.wait(waitTimeout: 4.0) { completion in
            session.dataTask(with: request) { (data, response, error) in
                guard let response = response as? HTTPURLResponse else {
                    completion.complete(with: RemoteError.invalidResponseObject)
                    return
                }
                if response.statusCode / 100 != 2 {
                    completion.complete(with: RemoteError.wrongStatusCode)
                } else if let data = data {
                    completion.complete(with: data)
                } else if let error = error {
                    completion.complete(with: error)
                } else {
                    completion.complete(with: RemoteError.invalidResponse)
                }
            }.resume()
        }
        if case .success(let data) = result {
            return data
        }
        return nil
    }
}
