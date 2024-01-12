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

public enum AppUpdateStatus {
    case upToDate
    case updateAvailable(forced: Bool, message: String?)
}

public enum AppUpdateErrors: Error {
    case notSupportedOnServer
}

public protocol AppUpdateDelegate: AnyObject {
    func appUpdateChanged(value: AppUpdateStatus)
}

public class AppUpdate {
    
    public weak var delegate: AppUpdateDelegate?
    
    public private(set) var lastKnownStatus: AppUpdateStatus? {
        didSet {
            
            guard let lastKnownStatus else {
                return
            }
            
            if let oldValue {
                if lastKnownStatus.hasChanged(old: oldValue) {
                    delegate?.appUpdateChanged(value: lastKnownStatus)
                }
            } else {
                delegate?.appUpdateChanged(value: lastKnownStatus)
            }
        }
    }
    
    let remoteDataProvider: RemoteDataProvider
    
    /// Initializes `CertStore` with provided configuration, crypto provider and secure data store.
    ///
    /// - Parameter configuration: Configuration for the AppUpdate object
    /// - Parameter cryptoProvider: Instance of `CryptoProvider` object
    convenience public init(networkConfiguration: NetworkConfiguration, cryptoProvider: CryptoProvider) {
        let restAPI = RestAPI(config: networkConfiguration, cryptoProvider: cryptoProvider)
        self.init(remoteDataProvider: restAPI)
    }
    
    /// Internal constructor, suitable for unit tests.
    internal init(remoteDataProvider: RemoteDataProvider) {
        self.remoteDataProvider = remoteDataProvider
        remoteDataProvider.delegates.add(self)
    }
    
    public func update(completion: @escaping (Result<AppUpdateStatus, Error>) -> Void) {
        remoteDataProvider.getData { result in
            switch result {
            case .success(let success):
                if let data = success.verifyVersionResult {
                    // we dont need to set the result here, it will be done by delegate
                    completion(.success(.from(serverResult: data)))
                } else {
                    completion(.failure(AppUpdateErrors.notSupportedOnServer))
                }
            case .failure(let failure):
                completion(.failure(failure))
            }
        }
    }
}

extension AppUpdate: RemoveDataProviderDelegate {
    func serverDataUpdated(response: ServerResponse, tags: [String]) {
        if let data = response.verifyVersionResult {
            lastKnownStatus = AppUpdateStatus.from(serverResult: data)
        }
    }
}

internal extension AppUpdateStatus {
    
    func hasChanged(old: AppUpdateStatus) -> Bool {
        switch self {
        case .upToDate:
            if case .upToDate = old {
                return false
            } else {
                return true
            }
        case .updateAvailable(let forced, let message):
            if case .updateAvailable(let oldForced, let oldMessage) = old {
                return forced != oldForced || message != oldMessage
            } else {
                return true
            }
        }
    }
    
    static func from(serverResult: VerifyVersionResult) -> AppUpdateStatus {
        switch serverResult.update {
        case .forced: return .updateAvailable(forced: true, message: serverResult.message)
        case .suggested: return .updateAvailable(forced: false, message: serverResult.message)
        case .notRequired: return .upToDate
        }
    }
}
