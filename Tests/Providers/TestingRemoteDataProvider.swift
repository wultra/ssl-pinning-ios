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
    
    init(networkConfig: NetworkConfiguration) {
        self.networkConfig = networkConfig
    }

    struct Interceptor {
        var called_getFingerprints = 0
        
        static var clean: Interceptor { return Interceptor() }
    }
    
    enum SimulatedError: Error {
        case networkError
    }
    
    let networkConfig: NetworkConfiguration
    
    var interceptor = Interceptor()
    
    var reportError = false
    var reportData: ServerResponse?
    
    var simulateResponseTime: TimeInterval = 0.200
    var simulateResponseTimeVariability: TimeInterval = 0.8
    
    var dataGenerator: (()->ServerResponse?)?
    
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
//        self.dataGenerator = { requestHeaders in
//            guard let data = self.reportData else {
//                return (nil, [:])
//            }
//            guard let challenge = requestHeaders["X-Cert-Pinning-Challenge"] else {
//                return (nil, [:])
//            }
//            var dataToSign = challenge.data(using: .utf8)!
//            dataToSign.append("&".data(using: .ascii)!)
//            dataToSign.append(data)
//            let signature = ECDSA.sign(privateKey: privateKey, data: dataToSign).base64EncodedString()
//            return (data, ["x-cert-pinning-signature" : signature])
//        }
//        return self
        dataGenerator = { return self.reportData }
        return self
    }

    // MARK: - RemoteDataProvider impl
    
    var config: NetworkConfiguration { .testConfig }
    
    func getData(currentDate: Date, completion: @escaping (Result<ServerResponse, Error>) -> Void) {
        interceptor.called_getFingerprints += 1
        DispatchQueue.global().async {
            if self.simulateResponseTime > 0 {
                let interval: TimeInterval = self.simulateResponseTime + self.simulateResponseTimeVariability * 0.01 * TimeInterval(arc4random_uniform(100))
                Thread.sleep(forTimeInterval: interval)
            }
            // Now generate the result
            let response: ServerResponse?
            if !self.reportError {
                if let generator = self.dataGenerator {
                    response = generator()
                } else {
                    response = self.reportData
                }
            } else {
                response = nil
            }
            if let data = response {
                completion(.success(data))
            } else {
                completion(.failure(SimulatedError.networkError))
            }
        }
    }
}


