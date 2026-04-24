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

/// Test validates if real communication with the Mobile Utility Server works.

class CertStoreTests_Network: XCTestCase {

    var config: CertStoreConfiguration!
    var certStore: CertStore!
    private var testConfig: TestConfig!
    
    var cryptoProvider: CryptoProvider!
    var dataStore: TestingSecureDataStore!
    var remoteDataProvider: RemoteDataProvider!
    
    struct GetPublicKeyResponse: Decodable {
        let publicKey: String
    }
    
    static override func setUp() {
        WultraDebug.verboseLevel = .all
    }
    
    override func setUp() {
        
        guard let configPath = Bundle.init(for: CertStoreTests_Network.self).path(
            forResource: "config",
            ofType: "json",
            inDirectory: "Configs"
        ) else {
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
        
        config = CertStoreConfiguration(
            serviceUrl: appUrl("/init?appName=\(testConfig.appName)"),
            publicKey: publicKey,
            useChallenge: true
        )
        cryptoProvider = CryptoKitCryptoProvider()
        dataStore = TestingSecureDataStore()
        remoteDataProvider = RestAPI(baseURL: config.serviceUrl, sslValidationStrategy: .default)
        certStore = CertStore(
            configuration: config,
            cryptoProvider: cryptoProvider,
            secureDataStore: dataStore,
            remoteDataProvider: remoteDataProvider
        )
        api_clearCertificates()
    }
    
    // MARK: - Helpers
    
    func appUrl(_ endpointPath: String) -> URL {
        URL(string: "\(testConfig.url)/app\(endpointPath)")!
    }
    
    func adminUrl(_ endpointPath: String) -> URL {
        URL(string: "\(testConfig.url)/admin\(endpointPath)")!
    }
    
    lazy var urlToPin: URL = {
        guard let url = URL(string: testConfig.urlToPin) else {
            XCTFail("Failed to parse URL to pin")
            fatalError("Invalid URL to pin in config")
        }
        return url
    }()
    
    lazy var hostToPin: String = {
        guard let host = urlToPin.host else {
            XCTFail("Failed to get host from URL to pin")
            fatalError("Missing host in URL to pin in config")
        }
        return host
    }()
    
    lazy var testCredsBase64: String = { "\(testConfig.adminLogin):\(testConfig.adminPassword)".data(using: .utf8)?.base64EncodedString() ?? ""
    }()
    
    func getPublicKey() -> String? {
        let request = URLRequest(url: appUrl("/init/public-key?appName=\(testConfig.appName)"))
        guard let publicKey: GetPublicKeyResponse = RemoteObject(request: request).get() else {
            return nil
        }
        return publicKey.publicKey
    }
    
    // MARK: - API MUS Certificate management
    
    /// Removes all stored certificates for the `urlToPin` domain via the admin API.
    /// Silently succeeds if the domain has no certificates yet (404 is acceptable).
    func api_clearCertificates() {
        print("Clearing certificates for: \(hostToPin)")
        
        var components = URLComponents(
            url: adminUrl("/apps/\(testConfig.appName)/domains"),
            resolvingAgainstBaseURL: false
        )!
        components.queryItems = [URLQueryItem(name: "domain", value: hostToPin)]
        
        var request = URLRequest(url: components.url!)
        request.httpMethod = "DELETE"
        request.addValue("Basic \(testCredsBase64)", forHTTPHeaderField: "authorization")
        _ = RemoteObject(request: request).get() as Data?
    }
    
    /// Downloads real certificate from urlToPin on the MUS
    func api_updateCertificate() {
        print("Updating certificate for: \(hostToPin)")
        
        struct AddResponse: Decodable {
            let name: String
        }
        
        var request = URLRequest(url: adminUrl("/apps/\(testConfig.appName)/certificates/auto"))
        request.httpBody = "{ \"domain\": \"\(hostToPin)\" }".data(using: .utf8)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("Basic \(testCredsBase64)", forHTTPHeaderField: "authorization")
        
        guard let result: AddResponse = RemoteObject(request: request).get() else {
            XCTFail("Failed to parse response")
            return
        }
        XCTAssertEqual(result.name, hostToPin)
    }
    
    /// Submits a PEM-encoded certificate for the given domain and depth via the admin API.
    func api_addCertificatePEM(_ pem: String, domain: String, depth: Int) {
        print("Adding PEM certificate for: \(domain) at depth: \(depth)")
        
        struct AddPEMResponse: Decodable {
            let name: String
        }
        
        var request = URLRequest(url: adminUrl("/apps/\(testConfig.appName)/certificates/pem"))
        let body: [String: Any] = ["pem": pem, "domain": domain, "depth": depth]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("Basic \(testCredsBase64)", forHTTPHeaderField: "authorization")
        
        guard let result: AddPEMResponse = RemoteObject(request: request).get() else {
            XCTFail("Failed to add PEM certificate for \(domain) at depth \(depth)")
            return
        }
        XCTAssertEqual(result.name, domain)
    }
    
    /// Configures SSL pinning bypass for the listed domains via the admin API.
    /// Pass an empty array to clear all bypass entries and re-enable pinning for all domains.
    func api_setDomainsConfigBypass(_ domains: [String]) {
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
        request.httpMethod = "PUT"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("Basic \(testCredsBase64)", forHTTPHeaderField: "authorization")
        
        guard let _: BypassResponse = RemoteObject(request: request).get() else {
            XCTFail("Failed to configure bypass domains")
            return
        }
    }
    
    /// Connects to the given URL and extracts the certificate at the given TLS chain depth as a PEM string.
    /// Returns nil if the connection fails or the depth is out of range.
    func fetchCertPEM(from url: URL, depth: Int) -> String? {
        print("Fetching certificate PEM for URL: \(url) and depth: \(depth)")
        
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
        
        let session = URLSession(delegate: certExtractor)
        let _: Data? = RemoteObject(session: session, request: URLRequest(url: url)).get()
        return certPEM
    }
    
    // MARK: - Unit tests
    
    /// Fetches urlToPin certificate from the MUS, then compare the fingerprints.
    func testRealCertificate() {
        
        // Register leaf certificate on MUS (depth 0)
        api_updateCertificate()

        // Update certificates from the MUS
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
        
        // And finally, try to open urlToPin https://github.com
        let urlSession = URLSession(delegate: sessionDelegate)
        let result: Data? = RemoteObject(session: urlSession, request: URLRequest(url: urlToPin)).get()
        
        XCTAssertNotNil(result)
        XCTAssertTrue(sessionDelegate.interceptor.called_didReceiveChallenge == 1)
    }
    
    /// Tests that depth-specific pinning works on a real-world TLS connection.
    ///
    /// The test registers both the leaf certificate (depth 0) and the intermediate certificate
    /// (depth 1), then verifies that a single `validate(challenge:)` call returns `.trusted`
    /// by finding a matching pinned entry at any depth in the chain.
    func testRealCertificateWithDepth() {
        
        // Register leaf certificate on MUS (depth 0)
        api_updateCertificate()
        
        // Extract intermediate certificate (depth 1) from the live TLS chain and register it
        guard let intermediatePEM = fetchCertPEM(from: urlToPin, depth: 1) else {
            XCTFail("Failed to extract intermediate certificate (depth 1) from TLS chain of \(hostToPin)")
            return
        }
        // Update the MUS with intermediate PEM for hostToPin
        api_addCertificatePEM(intermediatePEM, domain: hostToPin, depth: 1)
        
        // Update the certificates from the MUS
        let updateResult = AsyncHelper.wait { (completion) in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        
        // Both leaf (depth 0) and intermediate (depth 1) are pinned. A single validate call
        // iterates over all pinned depths and trusts on the first matching certificate.
        let sessionDelegate = TestingSessionDelegate { (challenge, callback) in
            let validationResult = self.certStore.validate(challenge: challenge)
            switch validationResult {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
            XCTAssertEqual(validationResult, .trusted, "Expected at least one pinned depth (0 or 1) to match")
        }
        
        let session = URLSession(delegate: sessionDelegate)
        let result: Data? = RemoteObject(session: session, request: URLRequest(url: urlToPin)).get()
        
        XCTAssertNotNil(result)
        XCTAssertEqual(sessionDelegate.interceptor.called_didReceiveChallenge, 1)
    }
    
    /// Tests that DomainsConfig SSL pinning bypass works on a real-world TLS connection.
    ///
    /// The test registers the leaf certificate for the target host, then configures it as a bypass
    /// domain via `PUT /admin/apps/{name}/pinning-bypass-domains`. While the bypass is active,
    /// `validate(challenge:)` must return `.trusted` regardless of what certificate is presented.
    /// After clearing the bypass, the test confirms that normal fingerprint-based pinning is restored.
    func testRealCertificateWithDomainsConfigBypass() {
        // Ensure a clean bypass state before the test
        api_setDomainsConfigBypass([])
        
        // Register the leaf certificate so the domain is known to the server
        api_updateCertificate()
        
        // Configure SSL pinning bypass for the target host
        api_setDomainsConfigBypass([hostToPin])
        
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
        
        let bypassSession = URLSession(delegate: sessionDelegateBypass)
        let bypassResult: Data? = RemoteObject(session: bypassSession, request: URLRequest(url: urlToPin)).get()
        
        XCTAssertNotNil(bypassResult)
        XCTAssertEqual(sessionDelegateBypass.interceptor.called_didReceiveChallenge, 1)
        
        // Clear bypass: restore normal SSL pinning for all domains
        api_setDomainsConfigBypass([])
        
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
        
        let pinningSession = URLSession(delegate: sessionDelegatePinning)
        let pinningResult: Data? = RemoteObject(session: pinningSession, request: URLRequest(url: urlToPin)).get()
        
        XCTAssertNotNil(pinningResult)
        XCTAssertEqual(sessionDelegatePinning.interceptor.called_didReceiveChallenge, 1)
    }
    
    /// Tests the full bypass lifecycle when a deliberately wrong fingerprint is stored for a domain.
    ///
    /// The leaf (0) certificate PEM is registered at depth 1 (where the actual intermediate CA sits),
    /// guaranteeing a fingerprint mismatch at that depth. The test then cycles through three phases:
    ///
    /// 1. **Before bypass** — the wrong fingerprint is detected and validation returns `.untrusted`.
    /// 2. **Bypass active** — `domainsConfig` marks the host as not requiring pinning → `.trusted`.
    /// 3. **Bypass cleared** — normal fingerprint-based pinning resumes → `.untrusted` again.
    func testRealCertificateWithDomainsConfigBadFingerprintAndBypass() {
        // Ensure clean bypass state before the test
        api_setDomainsConfigBypass([])
        
        // Fetch the leaf certificate PEM and register it at depth 1 as a deliberately wrong
        // fingerprint. The actual depth-1 certificate in the TLS chain is the intermediate CA —
        // its fingerprint will never match the leaf cert, guaranteeing .untrusted at depth 1.
        guard let leafPEM = fetchCertPEM(from: urlToPin, depth: 0) else {
            XCTFail("Failed to extract leaf certificate PEM for \(hostToPin)")
            return
        }
        // Stores the leaf (0) certificate as depth 1 in the MUS
        api_addCertificatePEM(leafPEM, domain: hostToPin, depth: 1)
        
        let updateResult = AsyncHelper.wait { (completion) in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        
        // --- Phase 1: bad fingerprint at depth 1, no bypass → .untrusted ---
        var phase1Result: CertStore.ValidationResult?
        let delegatePhase1 = TestingSessionDelegate { (challenge, callback) in
            phase1Result = self.certStore.validate(challenge: challenge)
            switch phase1Result! {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
        }

        _ = RemoteObject(
            session: URLSession(delegate: delegatePhase1),
            request: URLRequest(url: urlToPin)
        ).get() as Data?
        XCTAssertEqual(phase1Result, .untrusted, "Expected .untrusted for bad fingerprint at depth 1 before bypass")
        XCTAssertEqual(delegatePhase1.interceptor.called_didReceiveChallenge, 1)
        
        // --- Phase 2: enable bypass → .trusted despite bad fingerprint ---
        api_setDomainsConfigBypass([hostToPin])
        
        let updateResult2 = AsyncHelper.wait { (completion) in
            certStore.update(mode: .forced) { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult2.value == .ok)
        
        var phase2Result: CertStore.ValidationResult?
        let delegatePhase2 = TestingSessionDelegate { (challenge, callback) in
            phase2Result = self.certStore.validate(challenge: challenge)
            switch phase2Result! {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
        }
        let result2: Data? = RemoteObject(
            session: URLSession(delegate: delegatePhase2),
            request: URLRequest(url: urlToPin)
        ).get()
        XCTAssertEqual(phase2Result, .trusted, "Expected .trusted when bypass is active (bad fingerprint ignored)")
        XCTAssertNotNil(result2)
        XCTAssertEqual(delegatePhase2.interceptor.called_didReceiveChallenge, 1)
        
        // --- Phase 3: clear bypass → .untrusted again ---
        api_setDomainsConfigBypass([])
        
        let updateResult3 = AsyncHelper.wait { (completion) in
            certStore.update(mode: .forced) { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult3.value == .ok)
        
        var phase3Result: CertStore.ValidationResult?
        let delegatePhase3 = TestingSessionDelegate { (challenge, callback) in
            phase3Result = self.certStore.validate(challenge: challenge)
            switch phase3Result! {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
        }
        _ = RemoteObject(
            session: URLSession(delegate: delegatePhase3),
            request: URLRequest(url: urlToPin)
        ).get() as Data?
        XCTAssertEqual(phase3Result, .untrusted, "Expected .untrusted after bypass is cleared (bad fingerprint still stored)")
        XCTAssertEqual(delegatePhase3.interceptor.called_didReceiveChallenge, 1)
    }
    
    /// Tests the `sslPinningRequiredForUnlisted` field in `domainsConfig` on a real-world server response.
    ///
    /// The backend always sends `sslPinningRequiredForUnlisted: true`, meaning every domain that is
    /// **not** explicitly listed in `domainsConfig.domains` must satisfy normal fingerprint-based
    /// pinning. The test covers three phases in sequence:
    ///
    /// 1. **Listed domain, pinning bypassed** — the target host is added to the bypass list
    ///    (`sslPinningRequired: false`). A real HTTPS connection returns `.trusted` because the
    ///    host is listed and pinning is not required for it.
    ///
    /// 2. **Unlisted domain, `sslPinningRequiredForUnlisted: true`** — while the bypass is still
    ///    active, an unlisted domain is validated directly. Because pinning is required for
    ///    unlisted domains and no cert is stored for it, the SDK returns `.empty`.
    ///
    /// 3. **Previously listed domain becomes unlisted** — after clearing the bypass list the target
    ///    host itself becomes unlisted. With `sslPinningRequiredForUnlisted: true` in effect,
    ///    normal fingerprint-based pinning resumes. The registered leaf cert matches, so a real
    ///    HTTPS connection returns `.trusted`.
    func testRealCertificateWithDomainsConfigSslPinningRequiredForUnlisted() {
        // Register the leaf certificate so the host has a stored fingerprint
        api_updateCertificate()
        
        // Put the host in the bypass list.
        // Server will respond with domainsConfig:
        //   sslPinningRequiredForUnlisted: true  (always hardcoded by the server)
        //   domains: [{ name: hostToPin, sslPinningRequired: false }]
        api_setDomainsConfigBypass([hostToPin])
        
        let updateResult = AsyncHelper.wait { (completion) in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult.value == .ok)
        
        // --- Phase 1: listed domain, pinning not required → .trusted ---
        let sessionDelegateListed = TestingSessionDelegate { (challenge, callback) in
            let validationResult = self.certStore.validate(challenge: challenge)
            switch validationResult {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
            XCTAssertEqual(validationResult, .trusted, "Listed domain with sslPinningRequired=false should be trusted regardless of fingerprint")
        }
        
        let listedSession = URLSession(delegate: sessionDelegateListed)
        let listedResult: Data? = RemoteObject(session: listedSession, request: URLRequest(url: urlToPin)).get()
        
        XCTAssertNotNil(listedResult)
        XCTAssertEqual(sessionDelegateListed.interceptor.called_didReceiveChallenge, 1)
        
        // --- Phase 2: unlisted domain, sslPinningRequiredForUnlisted=true → normal pinning (.empty) ---
        // No real HTTPS connection is needed; the in-memory check is enough to confirm the policy.
        // testCommonName_Unknown is not in the bypass list and has no cert stored → .empty.
        let unlistedResult = certStore.validate(
            commonName: .testCommonName_Unknown,
            fingerprint: .testFingerprint_Unknown
        )
        XCTAssertEqual(unlistedResult, .empty, "Unlisted domain should require normal pinning (sslPinningRequiredForUnlisted=true) and return .empty when no cert is stored")
        
        // --- Phase 3: clear bypass list → host becomes unlisted, sslPinningRequiredForUnlisted=true applies ---
        api_setDomainsConfigBypass([])
        
        let updateResult2 = AsyncHelper.wait { (completion) in
            certStore.update(mode: .forced) { (result, error) in
                completion.complete(with: result)
            }
        }
        XCTAssertTrue(updateResult2.value == .ok)
        
        // The host is now unlisted. sslPinningRequiredForUnlisted=true → normal fingerprint pinning.
        // The registered leaf cert must still match → .trusted.
        let sessionDelegateUnlisted = TestingSessionDelegate { (challenge, callback) in
            let validationResult = self.certStore.validate(challenge: challenge)
            switch validationResult {
            case .trusted:
                callback(.performDefaultHandling, nil)
            case .untrusted, .empty:
                callback(.cancelAuthenticationChallenge, nil)
            }
            XCTAssertEqual(validationResult, .trusted, "Unlisted host with sslPinningRequiredForUnlisted=true should fall back to normal pinning and trust the registered cert")
        }
        let unlistedSession = URLSession(delegate: sessionDelegateUnlisted)
        let unlistedHostResult: Data? = RemoteObject(session: unlistedSession, request: URLRequest(url: urlToPin)).get()
        XCTAssertNotNil(unlistedHostResult)
        XCTAssertEqual(sessionDelegateUnlisted.interceptor.called_didReceiveChallenge, 1)
    }
}

extension URLSession {
    convenience init(delegate: (any URLSessionDelegate)?) {
        self.init(configuration: .ephemeral, delegate: delegate, delegateQueue: .main)
    }
}

private struct TestConfig: Decodable {
    let url: String
    let appName: String
    let urlToPin: String
    let adminLogin: String
    let adminPassword: String
}
