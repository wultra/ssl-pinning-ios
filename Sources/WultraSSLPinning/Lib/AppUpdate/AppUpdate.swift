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

public class AppUpdate {
    
    // MARK: - Public interface
    
    /// Initializes `CertStore` with provided configuration, crypto provider and secure data store.
    ///
    /// - Parameter configuration: Configuration for the AppUpdate object
    /// - Parameter cryptoProvider: Instance of `CryptoProvider` object
    public init(configuration: AppUpdateConfiguration, networkConfiguration: NetworkConfiguration, cryptoProvider: CryptoProvider) {
        self.remoteDataProvider = RestAPI(config: networkConfiguration, cryptoProvider: cryptoProvider)
    }
    
    /// Internal constructor, suitable for unit tests.
    internal init(configuration: AppUpdateConfiguration, remoteDataProvider: RemoteDataProvider) {
        self.remoteDataProvider = remoteDataProvider
    }
    
    let remoteDataProvider: RemoteDataProvider
}
