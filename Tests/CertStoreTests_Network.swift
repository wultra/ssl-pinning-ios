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
        clearCertificates()
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
    
    /// Removes all stored certificates for the `urlToPin` domain via the admin API.
    /// Silently succeeds if the domain has no certificates yet (404 is acceptable).
    func clearCertificates() {
        guard let url = URL(string: testConfig.urlToPin) else {
            XCTFail("Failed to parse URL to pin")
            return
        }
        let host = url.host() ?? ""
        print("Clearing certificates for \(host)")
        
        var components = URLComponents(url: adminUrl("/apps/\(testConfig.appName)/domains"), resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "domain", value: host)]
        var request = URLRequest(url: components.url!)
        let creds = "\(testConfig.adminLogin):\(testConfig.adminPassword)".data(using: .utf8)?.base64EncodedString() ?? ""
        request.httpMethod = "DELETE"
        request.addValue("Basic \(creds)", forHTTPHeaderField: "authorization")
        _ = RemoteObject(request: request).get() as Data?
    }
    
    /// Submits a PEM-encoded certificate for the given domain and depth via the admin API.
    func addCertificatePEM(_ pem: String, domain: String, depth: Int) {
        print("Adding PEM certificate for \(domain) at depth \(depth)")
        
        struct AddPEMResponse: Decodable {
            let name: String
        }
        
        var request = URLRequest(url: adminUrl("/apps/\(testConfig.appName)/certificates/pem"))
        let body: [String: Any] = ["pem": pem, "domain": domain, "depth": depth]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        let creds = "\(testConfig.adminLogin):\(testConfig.adminPassword)".data(using: .utf8)?.base64EncodedString() ?? ""
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("Basic \(creds)", forHTTPHeaderField: "authorization")
        guard let result: AddPEMResponse = RemoteObject(request: request).get() else {
            XCTFail("Failed to add PEM certificate for \(domain) at depth \(depth)")
            return
        }
        XCTAssertEqual(result.name, domain)
    }
    
    /// Configures SSL pinning bypass for the listed domains via the admin API.
    /// Pass an empty array to clear all bypass entries and re-enable pinning for all domains.
    func setDomainsConfigBypass(_ domains: [String]) {
        print("Setting pinning bypass domains: \(domains)")
        
        struct BypassResponse: Decodable {
            let domains: [BypassDomain]
            struct BypassDomain: Decodable {
                let name: String
                let sslPinningRequired: Bool
            }
        }
        
        var request = URLRequest(url: adminUrl("/apps/\(testConfig.appName)/pinning-bypass-domains"))
        request.httpBody = try? JSONSerialization.data(withJSONObject: domains)
        let creds = "\(testConfig.adminLogin):\(testConfig.adminPassword)".data(using: .utf8)?.base64EncodedString() ?? ""
        request.httpMethod = "PUT"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("Basic \(creds)", forHTTPHeaderField: "authorization")
        guard let _: BypassResponse = RemoteObject(request: request).get() else {
            XCTFail("Failed to configure bypass domains")
            return
        }
    }
    
    /// Connects to the given URL and extracts the certificate at the given TLS chain depth as a PEM string.
    /// Returns nil if the connection fails or the depth is out of range.
    func fetchCertPEM(from url: URL, depth: Int) -> String? {
        var certPEM: String?
        
        let certExtractor = TestingSessionDelegate { (challenge, callback) in
            guard let serverTrust = challenge.protectionSpace.serverTrust else {
                callback(.performDefaultHandling, nil)
                return
            }
            let count = SecTrustGetCertificateCount(serverTrust)
            guard depth < count, let cert = SecTrustGetCertificateAtIndex(serverTrust, depth) else {
                callback(.performDefaultHandling, nil)
                return
            }
            let derData = SecCertificateCopyData(cert) as Data
            let base64 = derData.base64EncodedString(options: [.lineLength64Characters])
                .replacingOccurrences(of: "\r\n", with: "\n")
                .replacingOccurrences(of: "\r", with: "\n")
            certPEM = "-----BEGIN CERTIFICATE-----\n\(base64)\n-----END CERTIFICATE-----"
            callback(.performDefaultHandling, nil)
        }
        
        let session = URLSession(configuration: .ephemeral, delegate: certExtractor, delegateQueue: .main)
        let _: Data? = RemoteObject(session: session, request: URLRequest(url: url)).get()
        return certPEM
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
    
    /// Tests that depth-specific pinning works on a real-world TLS connection.
    ///
    /// The test registers the leaf certificate (depth 0) via the `/auto` endpoint and
    /// the intermediate certificate (depth 1) extracted live from the TLS chain via the `/pem`
    /// endpoint. It then verifies that a real HTTPS request succeeds when validated at both depths.
    func testRealCertificateWithDepth() {
        
        guard let url = URL(string: testConfig.urlToPin) else {
            XCTFail("Failed to parse URL to pin")
            return
        }
        let host = url.host() ?? ""
        
        // Register leaf certificate (depth 0)
        updateCertificate()
        
        // Extract intermediate certificate (depth 1) from the live TLS chain and register it
        guard let intermediatePEM = fetchCertPEM(from: url, depth: 1) else {
            XCTFail("Failed to extract intermediate certificate (depth 1) from TLS chain of \(host)")
            return
        }
        addCertificatePEM(intermediatePEM, domain: host, depth: 1)
        
        // Update certificates from remote server
        let updateResult = AsyncHelper.wait { (completion) in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        
        // Validate at depth 0 (leaf certificate)
        let sessionDelegateDepth0 = TestingSessionDelegate { (challenge, callback) in
            let validationResult = self.certStore.validate(challenge: challenge, depth: 0)
            switch validationResult {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
            XCTAssertEqual(validationResult, .trusted, "Expected leaf certificate (depth 0) to be trusted")
        }
        
        let sessionDepth0 = URLSession(configuration: .ephemeral, delegate: sessionDelegateDepth0, delegateQueue: .main)
        let resultDepth0: Data? = RemoteObject(session: sessionDepth0, request: URLRequest(url: url)).get()
        XCTAssertNotNil(resultDepth0)
        XCTAssertEqual(sessionDelegateDepth0.interceptor.called_didReceiveChallenge, 1)
        
        // Validate at depth 1 (intermediate certificate)
        let sessionDelegateDepth1 = TestingSessionDelegate { (challenge, callback) in
            let validationResult = self.certStore.validate(challenge: challenge, depth: 1)
            switch validationResult {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
            XCTAssertEqual(validationResult, .trusted, "Expected intermediate certificate (depth 1) to be trusted")
        }
        
        let sessionDepth1 = URLSession(configuration: .ephemeral, delegate: sessionDelegateDepth1, delegateQueue: .main)
        let resultDepth1: Data? = RemoteObject(session: sessionDepth1, request: URLRequest(url: url)).get()
        XCTAssertNotNil(resultDepth1)
        XCTAssertEqual(sessionDelegateDepth1.interceptor.called_didReceiveChallenge, 1)
    }
    
    /// Tests that DomainsConfig SSL pinning bypass works on a real-world TLS connection.
    ///
    /// The test registers the leaf certificate for the target host, then configures it as a bypass
    /// domain via `PUT /admin/apps/{name}/pinning-bypass-domains`. While the bypass is active,
    /// `validate(challenge:)` must return `.trusted` regardless of what certificate is presented.
    /// After clearing the bypass, the test confirms that normal fingerprint-based pinning is restored.
    func testRealCertificateWithDomainsConfigBypass() {
        
        guard let url = URL(string: testConfig.urlToPin) else {
            XCTFail("Failed to parse URL to pin")
            return
        }
        let host = url.host() ?? ""
        
        // Ensure a clean bypass state before the test
        setDomainsConfigBypass([])
        
        // Register the leaf certificate so the domain is known to the server
        updateCertificate()
        
        // Configure SSL pinning bypass for the target host
        setDomainsConfigBypass([host])
        
        // Update certificates from remote server (picks up the new domainsConfig)
        let updateResult = AsyncHelper.wait { (completion) in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        
        // With bypass active, validate must return .trusted regardless of the certificate
        let sessionDelegateBypass = TestingSessionDelegate { (challenge, callback) in
            let validationResult = self.certStore.validate(challenge: challenge)
            switch validationResult {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
            XCTAssertEqual(validationResult, .trusted, "Expected bypass domain to be trusted without fingerprint check")
        }
        
        let bypassSession = URLSession(configuration: .ephemeral, delegate: sessionDelegateBypass, delegateQueue: .main)
        let bypassResult: Data? = RemoteObject(session: bypassSession, request: URLRequest(url: url)).get()
        XCTAssertNotNil(bypassResult)
        XCTAssertEqual(sessionDelegateBypass.interceptor.called_didReceiveChallenge, 1)
        
        // Clear bypass: restore normal SSL pinning for all domains
        setDomainsConfigBypass([])
        
        // Force update so the cleared DomainsConfig is reflected in the store
        let clearResult = AsyncHelper.wait { (completion) in
            certStore.update(mode: .forced) { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(clearResult.value == .ok)
        
        // With bypass cleared, normal pinning applies; the registered leaf cert should still match
        let sessionDelegatePinning = TestingSessionDelegate { (challenge, callback) in
            let validationResult = self.certStore.validate(challenge: challenge)
            switch validationResult {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
            XCTAssertEqual(validationResult, .trusted, "Expected leaf certificate to be trusted after bypass is cleared")
        }
        
        let pinningSession = URLSession(configuration: .ephemeral, delegate: sessionDelegatePinning, delegateQueue: .main)
        let pinningResult: Data? = RemoteObject(session: pinningSession, request: URLRequest(url: url)).get()
        XCTAssertNotNil(pinningResult)
        XCTAssertEqual(sessionDelegatePinning.interceptor.called_didReceiveChallenge, 1)
    }
    
    /// Tests that passing a depth value far beyond the real TLS chain length (e.g. 10) causes the
    /// SDK to return `.untrusted` immediately — before any stored-fingerprint lookup even occurs.
    ///
    /// The chain for any public site is typically 3 certificates deep (leaf + intermediate + root),
    /// so depth 10 is always out of range and the SDK's bounds check must catch it.
    func testRealCertificateWithOutOfBoundsDepth() {
        
        // Register a valid leaf cert so the store is not empty
        updateCertificate()
        
        let updateResult = AsyncHelper.wait { (completion) in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        
        var validationResult: CertStore.ValidationResult?
        let sessionDelegate = TestingSessionDelegate { (challenge, callback) in
            // depth 10 is way beyond any real TLS chain → SDK returns .untrusted immediately
            validationResult = self.certStore.validate(challenge: challenge, depth: 10)
            callback(.cancelAuthenticationChallenge, nil)
        }
        
        let urlSession = URLSession(configuration: .ephemeral, delegate: sessionDelegate, delegateQueue: .main)
        _ = RemoteObject(session: urlSession, request: URLRequest(url: URL(string: testConfig.urlToPin)!)).get() as Data?
        XCTAssertEqual(validationResult, .untrusted, "Expected .untrusted for depth 10 which exceeds the real TLS chain length")
        XCTAssertEqual(sessionDelegate.interceptor.called_didReceiveChallenge, 1)
    }
    
    /// Tests the full bypass lifecycle when a deliberately wrong fingerprint is stored for a domain.
    ///
    /// The leaf certificate PEM is registered at depth 1 (where the actual intermediate CA sits),
    /// guaranteeing a fingerprint mismatch at that depth. The test then cycles through three phases:
    ///
    /// 1. **Before bypass** — the wrong fingerprint is detected and validation returns `.untrusted`.
    /// 2. **Bypass active** — `domainsConfig` marks the host as not requiring pinning → `.trusted`.
    /// 3. **Bypass cleared** — normal fingerprint-based pinning resumes → `.untrusted` again.
    func testRealCertificateWithDomainsConfigBadFingerprintAndBypass() {
        
        guard let url = URL(string: testConfig.urlToPin) else {
            XCTFail("Failed to parse URL to pin")
            return
        }
        let host = url.host() ?? ""
        
        // Ensure clean bypass state before the test
        setDomainsConfigBypass([])
        
        // Fetch the leaf certificate PEM and register it at depth 1 as a deliberately wrong
        // fingerprint. The actual depth-1 certificate in the TLS chain is the intermediate CA —
        // its fingerprint will never match the leaf cert, guaranteeing .untrusted at depth 1.
        guard let leafPEM = fetchCertPEM(from: url, depth: 0) else {
            XCTFail("Failed to extract leaf certificate PEM for \(host)")
            return
        }
        addCertificatePEM(leafPEM, domain: host, depth: 1)
        
        let updateResult = AsyncHelper.wait { (completion) in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        
        // --- Phase 1: bad fingerprint at depth 1, no bypass → .untrusted ---
        var phase1Result: CertStore.ValidationResult?
        let delegatePhase1 = TestingSessionDelegate { (challenge, callback) in
            phase1Result = self.certStore.validate(challenge: challenge, depth: 1)
            callback(.cancelAuthenticationChallenge, nil)
        }
        _ = RemoteObject(
            session: URLSession(configuration: .ephemeral, delegate: delegatePhase1, delegateQueue: .main),
            request: URLRequest(url: url)
        ).get() as Data?
        XCTAssertEqual(phase1Result, .untrusted, "Expected .untrusted for bad fingerprint at depth 1 before bypass")
        XCTAssertEqual(delegatePhase1.interceptor.called_didReceiveChallenge, 1)
        
        // --- Phase 2: enable bypass → .trusted despite bad fingerprint ---
        setDomainsConfigBypass([host])
        
        let updateResult2 = AsyncHelper.wait { (completion) in
            certStore.update(mode: .forced) { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult2.value == .ok)
        
        var phase2Result: CertStore.ValidationResult?
        let delegatePhase2 = TestingSessionDelegate { (challenge, callback) in
            phase2Result = self.certStore.validate(challenge: challenge, depth: 1)
            switch phase2Result! {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
        }
        let result2: Data? = RemoteObject(
            session: URLSession(configuration: .ephemeral, delegate: delegatePhase2, delegateQueue: .main),
            request: URLRequest(url: url)
        ).get()
        XCTAssertEqual(phase2Result, .trusted, "Expected .trusted when bypass is active (bad fingerprint ignored)")
        XCTAssertNotNil(result2)
        XCTAssertEqual(delegatePhase2.interceptor.called_didReceiveChallenge, 1)
        
        // --- Phase 3: clear bypass → .untrusted again ---
        setDomainsConfigBypass([])
        
        let updateResult3 = AsyncHelper.wait { (completion) in
            certStore.update(mode: .forced) { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult3.value == .ok)
        
        var phase3Result: CertStore.ValidationResult?
        let delegatePhase3 = TestingSessionDelegate { (challenge, callback) in
            phase3Result = self.certStore.validate(challenge: challenge, depth: 1)
            callback(.cancelAuthenticationChallenge, nil)
        }
        _ = RemoteObject(
            session: URLSession(configuration: .ephemeral, delegate: delegatePhase3, delegateQueue: .main),
            request: URLRequest(url: url)
        ).get() as Data?
        XCTAssertEqual(phase3Result, .untrusted, "Expected .untrusted after bypass is cleared (bad fingerprint still stored)")
        XCTAssertEqual(delegatePhase3.interceptor.called_didReceiveChallenge, 1)
    }
}

private struct TestConfig: Decodable {
    let url: String
    let appName: String
    let urlToPin: String
    let adminLogin: String
    let adminPassword: String
}
