import XCTest
@testable import WultraSSLPinning

class CertificateFetcher: NSObject, URLSessionDelegate {
    
    private(set) var serverTrust: SecTrust?
    private(set) var challenge: URLAuthenticationChallenge?

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        self.challenge = challenge
        self.serverTrust = serverTrust
        
        completionHandler(.performDefaultHandling, nil)
    }
    
    func getCertificateAtIndex(_ index: Int, _ cryptoProvider: CryptoProvider) -> CertData? {
        guard let serverTrust = serverTrust else {
            return nil
        }
        
        let certificateCount = SecTrustGetCertificateCount(serverTrust)
        if certificateCount > index, let certificate = SecTrustGetCertificateAtIndex(serverTrust, index) {
            
            var name: CFString?
            guard SecCertificateCopyCommonName(certificate, &name) == errSecSuccess, let commonName = name as String? else {
                return nil
            }
            
            let certData = SecCertificateCopyData(certificate) as Data
            let fingerprint = cryptoProvider.hashSha256(data: certData)
            return .init(commonName: commonName, fingerprint: fingerprint)
        }
        
        return nil
    }
    
    struct CertData {
        let commonName: String
        let fingerprint: Data
    }
}

class CertStoreTests_Chain: XCTestCase {
    
    var config: CertStoreConfiguration!
    var certStore: CertStore!
    
    var cryptoProvider: TestingCryptoProvider!
    var dataStore: TestingSecureDataStore!
    var remoteDataProvider: TestingRemoteDataProvider!
    
    let responseGenerator = ResponseGenerator()
    
    func prepareStore(with config: CertStoreConfiguration) {
        self.config = config
        cryptoProvider = TestingCryptoProvider()
        dataStore = TestingSecureDataStore()
        remoteDataProvider = TestingRemoteDataProvider()
        certStore = CertStore(
            configuration: config,
            cryptoProvider: cryptoProvider,
            secureDataStore: dataStore,
            remoteDataProvider: remoteDataProvider
        )
    }
    
    static override func setUp() {
        WultraDebug.verboseLevel = .all
    }
    
    func testDownloadAndValidateSecTrustCertificateOnIndex2() {
        
        prepareStore(with: .testConfig)
        
        let certFetcher = CertificateFetcher()
        _ = AsyncHelper.wait { completion in
            let url = URL(string: "https://github.com")!
            let session = URLSession(configuration: .default, delegate: certFetcher, delegateQueue: nil)
            let task = session.dataTask(with: url) { _, response, error in
                if let error = error {
                    XCTFail("Failed to get response: \(error.localizedDescription)")
                }
                completion.complete(with: response)
                
            }
            task.resume()
        }
        
        guard let challenge = certFetcher.challenge, let cert1 = certFetcher.getCertificateAtIndex(1, cryptoProvider), let cert2 = certFetcher.getCertificateAtIndex(2, cryptoProvider) else {
            XCTFail("Failed to retrieve challenge or certificate and index 2")
            return
        }
        
        //  enabling only leafe cert (ends with untrusted)
        
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
            .removeAll()
            .append(commonName: cert2.commonName, expiration: .valid, fingerprint: cert2.fingerprint, maxIndex: 0, domains: ["github.com"])
            .data()
        updateCertStore() // make sure the data are loaded
        XCTAssertEqual(certStore.validate(challenge: challenge), .untrusted) // untrusted, because we only look into index 0
        
        
        
        //  enabling up to index 2 cert (ends with trusted)
            
        prepareStore(with: .testConfig) // reset store
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
            .removeAll()
            .append(commonName: cert2.commonName, expiration: .valid, fingerprint: cert2.fingerprint, maxIndex: 2, domains: ["github.com"])
            .data()
        updateCertStore()
        XCTAssertEqual(certStore.validate(challenge: challenge), .trusted) // trusted, we look up to index 2
        
        
        
        //  enabling up to index 2 cert but wrong subdomain (ends with empty)
        
        prepareStore(with: .testConfig) // reset store
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
            .removeAll()
            .append(commonName: cert2.commonName, expiration: .valid, fingerprint: cert2.fingerprint, maxIndex: 2, domains: ["subdomain.github.com"])
            .data()
        updateCertStore()
        XCTAssertEqual(certStore.validate(challenge: challenge), .empty) // empty - becauase the subdomain does not match
        
        
        
        //  enabling up to index 2 cert but wrong subdomain (ends with empty)
        
        prepareStore(with: .testConfig) // reset store
        remoteDataProvider
            .setNoLatency()
            .reportData = responseGenerator
            .removeAll()
            .append(commonName: cert2.commonName, expiration: .valid, fingerprint: cert2.fingerprint, maxIndex: 1, domains: ["github.com"])
            .append(commonName: cert1.commonName, expiration: .valid, fingerprint: cert1.fingerprint, maxIndex: 1, domains: ["github.com"])
            .data()
        updateCertStore()
        XCTAssertEqual(certStore.validate(challenge: challenge), .trusted) // trusted (cert at index 1 should match
    }
    
    private func updateCertStore() {
        _ = AsyncHelper.wait { completion in
            certStore.update { (result, error) in
                completion.complete(with: result)
            }
        }
    }
}
