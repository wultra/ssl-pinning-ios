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

/// The `RemoteDataRequest` internal structure contains information required
/// for constructing HTTP request to acquire data from the remote server.
internal struct RemoteDataRequest {
    /// Request headers.
    let requestHeaders: [String:String]
}

/// The `RemoteDataResponse` internal structure contains response received
/// from the server.
internal struct RemoteDataResponse {
    /// Result with received `Data`.
    let result: Result<Data, Error>
    /// Headers received in the response. Note that all header names are lowercased.
    let responseHeaders: [String:String]
}

///
/// The `RemoteDataProvider` protocol defines an interface for getting
/// fingerprints from remote data location.
/// The protocol is currently implemented by `RestAPI` class and by
/// several dummy implementations used for the unit testing.
///
internal protocol RemoteDataProvider: class {
    
    /// Gets data containing fingerprints from the remote location.
    func getFingerprints(request: RemoteDataRequest, completion: @escaping (RemoteDataResponse) -> Void) -> Void
}
