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

import XCTest

@testable import WultraSSLPinning

class CertStoreTests_NetworkChallenge: XCTestCase {
    
    // MARK: - Helpers
    
    /*
     This test validates whether the real communication with the Mobile Utility Server works.
     */
    
    // Location of Mobile Utility Server
    let serviceUrl = "https://mobile-utility-server.herokuapp.com/app"
    // Name of application configured at MOS
    let serviceAppName = "rb-ekonto"
    
    //
    
    var config: CertStoreConfiguration!
    var certStore: CertStore!
    
    var cryptoProvider: CryptoProvider!
    var dataStore: TestingSecureDataStore!
    var remoteDataProvider: RemoteDataProvider!
    
    let responseGenerator = ResponseGenerator()
    
    func prepareStore() -> Bool {
        guard let publicKey = getPublicKey() else {
            XCTFail("Failed to acquire public key")
            return false
        }
        self.config = CertStoreConfiguration(
            serviceUrl: serviceUrl(endpointPath: "/init?appName=\(serviceAppName)"),
            publicKey: publicKey,
            useChallenge: true
        )
        cryptoProvider = PowerAuthCryptoProvider()
        dataStore = TestingSecureDataStore()
        remoteDataProvider = RestAPI(baseURL: config.serviceUrl)
        certStore = CertStore(
            configuration: config,
            cryptoProvider: cryptoProvider,
            secureDataStore: dataStore,
            remoteDataProvider: remoteDataProvider
        )
        return true
    }
    
    func serviceUrl(endpointPath: String) -> URL {
        let urlString = "\(serviceUrl)\(endpointPath)"
        return URL(string: urlString)!
    }
    
    struct GetPublicKeyResponse: Decodable {
        let publicKey: String
    }
    
    func getPublicKey() -> String? {
        let request = URLRequest(url: serviceUrl(endpointPath: "/init/public-key?appName=\(serviceAppName)"))
        guard let publicKey: GetPublicKeyResponse = RemoteObject(request: request).get() else {
            return nil
        }
        return publicKey.publicKey
    }
    
    
    // MARK: - Unit tests
    
    static override func setUp() {
        WultraDebug.verboseLevel = .all
    }
    
    func testMobileUtilityServer() {
        
        guard prepareStore() else {
            return
        }
        
        let updateResult = AsyncHelper.wait { completion in
            certStore.update { result, error in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
    }
    
}
