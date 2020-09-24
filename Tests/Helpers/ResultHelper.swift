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

import Foundation

/// This extension provides a compatibility with our previous "Result" implementation.
/// The extension is available only for tests and basically helps with results assertion.
/// It's more convenient to write XCTAssert... conditions with such extension.
extension Result {
    
    /// Contains nullable value, that is valid only when Result contains Success
    var value: Success? {
        if case .success(let value) = self {
            return value
        }
        return nil
    }
}
