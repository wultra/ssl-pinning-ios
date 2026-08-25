//
// Copyright 2025 Wultra s.r.o.
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

class ConcreteDataStoreTests: XCTestCase {
    
    // MARK: - Helpers
    
    private var timestampCreated: TimeInterval!
    private var stores: [SecureDataStore]!
    
    private func createStores(timestampCreated: TimeInterval = Date().timeIntervalSince1970) {
        self.timestampCreated = timestampCreated
        stores = [
            KeychainSecureDataStore(keychainIdentifier: "DefaultStore_\(timestampCreated)")
        ]
    }
    
    // MARK: - Unit tests
    
    override func setUp() async throws {
        createStores()
    }
    
    static override func setUp() {
        WultraDebug.verboseLevel = .all
    }
    
    func testSaveUpdateRemove() {
        
        let dataToSave = Data.random(count: 16)
        let dataToUpdate = Data.random(count: 16)
        let key = "dataKey"
        
        stores.forEach { store in
            
            XCTAssertTrue(store.save(data: dataToSave, forKey: key))
            
            let dataRetrieved = store.loadData(forKey: key)
            XCTAssertNotNil(dataRetrieved)
            XCTAssertEqual(dataRetrieved, dataToSave)
            
            XCTAssertTrue(store.save(data: dataToUpdate, forKey: key))
            let updatedDataRetrieved = store.loadData(forKey: key)
            XCTAssertNotNil(updatedDataRetrieved)
            XCTAssertEqual(updatedDataRetrieved, dataToUpdate)
            
            store.removeData(forKey: key)
            let dataRetrievedAfterRemoval = store.loadData(forKey: key)
            XCTAssertNil(dataRetrievedAfterRemoval)
        }
    }
    
    func testPersist() {
        
        let dataToSave = Data.random(count: 16)
        let key = "dataKey"
        
        stores.forEach { store in
            XCTAssertTrue(store.save(data: dataToSave, forKey: key))
            let dataRetrieved = store.loadData(forKey: key)
            XCTAssertNotNil(dataRetrieved)
            XCTAssertEqual(dataRetrieved, dataToSave)
        }
        
        // create the storage again
        createStores(timestampCreated: timestampCreated)
        
        // verify that the data persisted
        stores.forEach { store in
            let dataRetrieved = store.loadData(forKey: key)
            XCTAssertNotNil(dataRetrieved)
            XCTAssertEqual(dataRetrieved, dataToSave)
        }
    }
}
