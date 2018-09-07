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
    
    struct Interceptor {
        var called_getFingerprints = 0
        
        static var clean: Interceptor { return Interceptor() }
    }
    
    enum SimulatedError: Error {
        case networkError
    }
    
    var interceptor = Interceptor()
    
    var reportError = false
    var reportData: Data?
    
    var simulateResponseTime: TimeInterval = 0.200
    var simulateResponseTimeVariability: TimeInterval = 0.8
    
    var dataGenerator: (()->Data?)?
    
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

    // MARK: - RemoteDataProvider impl
    
    func getFingerprints(completion: @escaping (Result<Data>) -> Void) {
        interceptor.called_getFingerprints += 1
        DispatchQueue.global().async {
            if self.simulateResponseTime > 0 {
                let interval: TimeInterval = 0.200 + self.simulateResponseTimeVariability * 0.01 * TimeInterval(arc4random_uniform(100))
                Thread.sleep(forTimeInterval: interval)
            }
            // Now generate the result
            let data: Data?
            if !self.reportError {
                data = self.dataGenerator?() ?? self.reportData
            } else {
                data = nil
            }
            if let data = data {
                completion(.success(data))
            } else {
                completion(.failure(SimulatedError.networkError))
            }
        }
    }
}


