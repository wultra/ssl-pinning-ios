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
 
import XCTest

@testable import WultraSSLPinning

class CertStoreTests_NetworkStatic: XCTestCase {
    
    // MARK: - Helpers
    
    /*
     This test validates whether the real communication with the server works and
     whether the certificate validation works in real scenarios. The list of certificates
     is available at my [public gist](https://gist.github.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c)
     You may contact me (at juraj.durech@wultra.com) to update the list, once the github's
     certificate expires.
     
     You can also use the helper script available at `{GIT_ROOT}/Tests/TestData` to fetch new
     certificate and calculate the new entry for the validation. The `TestData` folder also contains
     private key used for the signature calculation. Please, do not use that key for your own signing :)
     */
    
    // Raw content from my public gist
    static let serviceUrl = URL(string: "https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/34866234bbaa3350dc0ddc5680a65a6f4e7c549e/ssl-pinning-signatures.json")!
    // Public key
    static let publicKey  = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
    
    //
    
    var config: CertStoreConfiguration!
    var certStore: CertStore!
    
    var cryptoProvider: CryptoProvider!
    var dataStore: TestingSecureDataStore!
    var remoteDataProvider: RemoteDataProvider!
    
    let responseGenerator = ResponseGenerator()
    
    func prepareStore() {
        self.config = CertStoreConfiguration(
            serviceUrl: CertStoreTests_NetworkStatic.serviceUrl,
            publicKey: CertStoreTests_NetworkStatic.publicKey
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
    }
    
    // MARK: - Unit tests
    
    static override func setUp() {
        WultraDebug.verboseLevel = .all
    }

    
    func testRealCertificates() {
        
        prepareStore()

        // Update certificates from remote server
        
        let updateResult = AsyncHelper.wait { (completion) in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        
        // Prepare URLSessionDelegate handler
        
        let sessionDelegate = TestingSessionDelegate { (challenge, callback) in
            let validationResult = self.certStore.validate(challenge: challenge)
            switch validationResult {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
            XCTAssertTrue(validationResult == .trusted)
        }
        
        // And finally, try to open https://github.com
        
        let urlSession = URLSession(configuration: .ephemeral, delegate: sessionDelegate, delegateQueue: .main)
        let result: Data? = RemoteObject(session: urlSession, request: URLRequest(url: URL(string: "https://github.com")!)).get()
        XCTAssertNotNil(result)
        XCTAssertTrue(sessionDelegate.interceptor.called_didReceiveChallenge == 1)
    }
}
