//
// Copyright 2023 Wultra s.r.o.
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

public class MobileUtilityServer {
    
    public let appUpdate: AppUpdate
    public let certStore: CertStore
    
    private let restApi: RestAPI
    
    public init(networkConfig: NetworkConfiguration, certStoreConfig: CertStoreConfiguration, cryptoProvider: CryptoProvider, secureDataStore: SecureDataStore) {
        restApi = RestAPI(config: networkConfig, cryptoProvider: cryptoProvider)
        appUpdate = .init(remoteDataProvider: restApi)
        certStore = .init(configuration: certStoreConfig, cryptoProvider: cryptoProvider, secureDataStore: secureDataStore, remoteDataProvider: restApi)
    }
    
    public func update(completion: ((Result<Void, Error>) -> Void)? = nil) {
        restApi.getData(tag: "MUS") { result in
            switch result {
            case .success: completion?(.success(()))
            case .failure(let error): completion?(.failure(error))
            }
        }
    }
}

public extension NetworkConfiguration {
    
    static func createMobileUtilityServerURL(baseURL: URL, appName: String) -> URL {
        var appStr = "unknown"
        if let appSemVer = Bundle.main.semanticVersion {
            appStr = "\(appSemVer.major).\(appSemVer.minor).\(appSemVer.patch)"
        }
        let osSemVer = ProcessInfo.processInfo.operatingSystemSemanticVersion
        let osStr = "\(osSemVer.major).\(osSemVer.minor).\(osSemVer.patch)"
        let relativePath = "app/init?appName=\(appName)&appVersion=\(appStr)&osVersion=\(osStr)&platform=IOS"
        
        var url = baseURL
        url.appendPathComponent(relativePath)
        return url
    }
}
