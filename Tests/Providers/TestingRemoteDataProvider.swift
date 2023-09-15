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

@testable import WultraSSLPinning

class TestingRemoteDataProvider: RemoteDataProvider {
    
    let delegates = MulticastDelegate<RemoveDataProviderDelegate>()
    
    init(networkConfig: NetworkConfiguration, cryptoProvider: CryptoProvider) {
        networkConfig.validate(cryptoProvider: cryptoProvider)
        self.config = networkConfig
        self.cryptoProvider = cryptoProvider
    }

    struct Interceptor {
        var called_getFingerprints = 0
        
        static var clean: Interceptor { return Interceptor() }
    }
    
    enum SimulatedError: Error {
        case networkError
    }
    
    typealias Response = (object: ServerResponse?, responseData: Data?, signature: String?)
    
    let config: NetworkConfiguration
    let cryptoProvider: CryptoProvider
    
    var interceptor = Interceptor()
    
    var reportError = false
    var reportResponse: ServerResponse?
    
    var simulateResponseTime: TimeInterval = 0.200
    var simulateResponseTimeVariability: TimeInterval = 0.8
    
    var dataGenerator: (()->Response)?
    var challenge: RequestChallenge?
    
    @discardableResult
    func setReportError(_ enabled: Bool) -> TestingRemoteDataProvider {
        reportError = enabled
        return self
    }
    
    @discardableResult
    func setNoLatency() -> TestingRemoteDataProvider {
        simulateResponseTime = 0
        simulateResponseTimeVariability = 0
        return self
    }
    
    @discardableResult
    func setLatency(_ latency: TimeInterval) -> TestingRemoteDataProvider {
        simulateResponseTime = latency
        simulateResponseTimeVariability = 0
        return self
    }
    
    @discardableResult
    func setLatency(min: TimeInterval, max: TimeInterval) -> TestingRemoteDataProvider {
        simulateResponseTime = min
        simulateResponseTimeVariability = max - min
        return self
    }
    
    @discardableResult
    @available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
    func signResponse(with privateKey: ECDSA.PrivateKey) -> TestingRemoteDataProvider {
        challenge = .init(cryptoProvider: cryptoProvider)
        self.dataGenerator = {
            guard let reportResponse = self.reportResponse else {
                return (nil, nil, nil)
            }
            guard let challenge = self.challenge else {
                return (nil, nil, nil)
            }
            let responseData = reportResponse.toJSON()
            var dataToSign = challenge.challenge.data(using: .utf8)!
            dataToSign.append("&".data(using: .ascii)!)
            dataToSign.append(responseData)
            let signature = ECDSA.sign(privateKey: privateKey, data: dataToSign).base64EncodedString()
            return (reportResponse, responseData, signature)
        }
        return self
    }

    // MARK: - RemoteDataProvider impl
    
    func getData(tag: String?, completion: @escaping (Result<ServerResponse, Error>) -> Void) {
        interceptor.called_getFingerprints += 1
        DispatchQueue.global().async {
            if self.simulateResponseTime > 0 {
                let interval: TimeInterval = self.simulateResponseTime + self.simulateResponseTimeVariability * 0.01 * TimeInterval(arc4random_uniform(100))
                Thread.sleep(forTimeInterval: interval)
            }
            // Now generate the result
            let response: Response
            if !self.reportError {
                if let generator = self.dataGenerator {
                    response = generator()
                } else {
                    response = (self.reportResponse, nil, nil)
                }
            } else {
                completion(.failure(SimulatedError.networkError))
                return
            }
            
            guard let object = response.object else {
                completion(.failure(SimulatedError.networkError))
                return
            }
            
            
            if let signature = response.signature, let data = response.responseData {
                guard let challenge = self.challenge else {
                    completion(.failure(SimulatedError.networkError))
                    return
                }
                guard challenge.verifyData(data, forSignature: signature, withKey: self.config.publicKey) else {
                    completion(.failure(SimulatedError.networkError))
                    return
                }
            }
            
            completion(.success(object))
        }
    }
}


