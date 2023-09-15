//
// Copyright 2023 Wultra s.r.o.
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

/// `MulticastDelegate` lets you easily create a "multicast delegate" for a given protocol or class.
internal class MulticastDelegate<T> {
    
    private let delegates = NSHashTable<AnyObject>.weakObjects()
    
    func add(_ delegate: T) {
        delegates.add(delegate as AnyObject)
    }
    
    func remove(_ delegate: T) {
        delegates.remove(delegate as AnyObject)
    }
    
    func invoke(_ queue: DispatchQueue? = nil, _ invocation: @escaping (T) -> Void) {
        for delegate in delegates.allObjects {
            if let queue = queue {
                queue.async { invocation(delegate as! T) }
            } else {
                invocation(delegate as! T)
            }
        }
    }
}
