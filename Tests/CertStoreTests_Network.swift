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

class CertStoreTests_Network: XCTestCase {
    
    // MARK: - Helpers
    
    /*
     This test validates whether the real communication with the Mobile Utility Server works.
     */
    
    var config: CertStoreConfiguration!
    var certStore: CertStore!
    private var testConfig: TestConfig!
    
    var cryptoProvider: CryptoProvider!
    var dataStore: TestingSecureDataStore!
    var remoteDataProvider: RemoteDataProvider!
    
    let responseGenerator = ResponseGenerator()
    
    override func setUp() {
        
        guard let configPath = Bundle.init(for: CertStoreTests_Network.self).path(forResource: "config", ofType: "json", inDirectory: "Configs") else {
            XCTFail("Failed to find config.json")
            return
        }
        
        do {
            let configContent = try String(contentsOfFile: configPath)
            testConfig = try JSONDecoder().decode(TestConfig.self, from: configContent.data(using: .utf8)!)
        } catch _ {
            XCTFail("Failed to find parse config.json into TestConfig")
            return
        }
        
        guard let publicKey = getPublicKey() else {
            XCTFail("Failed to acquire public key")
            return
        }
        self.config = CertStoreConfiguration(
            serviceUrl: appUrl("/init?appName=\(testConfig.appName)"),
            publicKey: publicKey,
            useChallenge: true
        )
        cryptoProvider = PowerAuthCryptoProvider()
        dataStore = TestingSecureDataStore()
        remoteDataProvider = RestAPI(baseURL: config.serviceUrl, sslValidationStrategy: .default)
        certStore = CertStore(
            configuration: config,
            cryptoProvider: cryptoProvider,
            secureDataStore: dataStore,
            remoteDataProvider: remoteDataProvider
        )
    }
    
    func appUrl(_ endpointPath: String) -> URL {
        let urlString = "\(testConfig.url)/app\(endpointPath)"
        return URL(string: urlString)!
    }
    
    func adminUrl(_ endpointPath: String) -> URL {
        let urlString = "\(testConfig.url)/admin\(endpointPath)"
        return URL(string: urlString)!
    }
    
    struct GetPublicKeyResponse: Decodable {
        let publicKey: String
    }
    
    func getPublicKey() -> String? {
        let request = URLRequest(url: appUrl("/init/public-key?appName=\(testConfig.appName)"))
        guard let publicKey: GetPublicKeyResponse = RemoteObject(request: request).get() else {
            return nil
        }
        return publicKey.publicKey
    }
    
    func updateCertificate() {
        guard let url = URL(string: testConfig.urlToPin) else {
            XCTFail("Failed to parse URL to pin")
            return
        }
        
        let host = url.host() ?? ""
        
        print("Updating certificate for \(host)")
        
        struct AddResponse: Decodable {
            let name: String
        }
        
        var request = URLRequest(url: adminUrl("/apps/\(testConfig.appName)/certificates/auto"))
        request.httpBody = "{ \"domain\": \"\(host)\" }".data(using: .utf8)
        let creds = "\(testConfig.adminLogin):\(testConfig.adminPassword)".data(using: .utf8)?.base64EncodedString() ?? ""
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("Basic \(creds)", forHTTPHeaderField: "authorization")
        guard let result: AddResponse = RemoteObject(request: request).get() else {
            XCTFail("Failed to parse response")
            return
        }
        XCTAssertEqual(result.name, host)
    }
    
    // MARK: - Unit tests
    
    static override func setUp() {
        WultraDebug.verboseLevel = .all
    }
    
    func testRealCertificate() {
        
        updateCertificate()

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
        let result: Data? = RemoteObject(session: urlSession, request: URLRequest(url: URL(string: testConfig.urlToPin)!)).get()
        XCTAssertNotNil(result)
        XCTAssertTrue(sessionDelegate.interceptor.called_didReceiveChallenge == 1)
    }
}

private struct TestConfig: Decodable {
    let url: String
    let appName: String
    let urlToPin: String
    let adminLogin: String
    let adminPassword: String
}
