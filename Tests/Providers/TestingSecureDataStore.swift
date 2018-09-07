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

@testable import WultraSSLPinning

class TestingSecureDataStore: SecureDataStore {
    
    struct Interceptor {
        var called_save = 0
        var called_loadData = 0
        var called_removeData = 0
        
        static var clean: Interceptor { return Interceptor() }
    }
    
    var storage: [String: Data] = [:]
    var interceptor = Interceptor()
    
    // MARK: - Methods for testing
    
    func hasData(forKey key: String) -> Bool {
        return storage.index(forKey: key) != nil
    }
    
    func object<T: Decodable>(forKey key: String, decoder: JSONDecoder? = nil) -> T? {
        guard let data = storage[key] else {
            return nil
        }
        let decoderToUse: JSONDecoder
        if let decoder = decoder {
            decoderToUse = decoder
        } else {
            decoderToUse = JSONDecoder()
            decoderToUse.dataDecodingStrategy = .base64
            decoderToUse.dateDecodingStrategy = .secondsSince1970
        }
        guard let object = try? decoderToUse.decode(T.self, from: data) else {
            return nil
        }
        return object
    }
    
    func retrieveCachedData(forKey key: String) -> CachedData? {
        return object(forKey: key)
    }
    
    func removeAll() {
        storage.removeAll()
    }
    
    // MARK: - SecureDataStore protocol
    
    func save(data: Data, forKey key: String) -> Bool {
        interceptor.called_save += 1
        storage[key] = data
        return true
    }
    
    func loadData(forKey key: String) -> Data? {
        interceptor.called_loadData += 1
        return storage[key]
    }
    
    func removeData(forKey key: String) {
        interceptor.called_removeData += 1
        storage.removeValue(forKey: key)
    }
}
