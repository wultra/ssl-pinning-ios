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

import Foundation

class TestingSessionDelegate: NSObject, URLSessionDelegate {
    
    struct Interceptor {
        var called_didReceiveChallenge = 0
        
        static var clean: Interceptor { return Interceptor() }
    }
    
    var interceptor = Interceptor()
    var onChallenge: (_ challenge: URLAuthenticationChallenge, _ completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) -> Void
    
    init(onChallenge: @escaping (_ challenge: URLAuthenticationChallenge, _ completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) -> Void) {
        self.onChallenge = onChallenge
    }
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        self.interceptor.called_didReceiveChallenge += 1
        self.onChallenge(challenge, completionHandler)
    }
}
