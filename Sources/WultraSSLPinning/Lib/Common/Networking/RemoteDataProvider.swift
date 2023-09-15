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

///
/// The `RemoteDataProvider` protocol defines an interface for getting
/// fingerprints from remote data location.
/// The protocol is currently implemented by `RestAPI` class and by
/// several dummy implementations used for the unit testing.
///
internal protocol RemoteDataProvider: AnyObject {
    
    var config: NetworkConfiguration { get }
    
    var delegates: MulticastDelegate<RemoveDataProviderDelegate> { get }
    
    /// Gets data containing fingerprints from the remote location.
    func getData(tag: String?, completion: @escaping GetDataComppletion)
}

extension RemoteDataProvider {
    func getData(completion: @escaping GetDataComppletion) {
        getData(tag: nil, completion: completion)
    }
}

internal typealias GetDataComppletion = (Result<ServerResponse, Error>) -> Void

internal protocol RemoveDataProviderDelegate: AnyObject {
    func serverDataUpdated(response: ServerResponse, tags: [String])
}