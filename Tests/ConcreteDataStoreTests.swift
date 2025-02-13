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
            PowerAuthSecureDataStore(keychainIdentifier: "PowerAuthStore_\(timestampCreated)"),
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
    
    func testMigration() {
        
        let dataToSave = Data.random(count: 16)
        let dataToUpdate = Data.random(count: 16)
        let key = "dataKey"
        let ksId = "MigrationKeychainTest_\(Date().timeIntervalSince1970)"
        
        // create data stores with the same keychain ids
        let paDs = PowerAuthSecureDataStore(keychainIdentifier: ksId)
        let kcDs = KeychainSecureDataStore(keychainIdentifier: ksId)
        
        // save the data in powerauth data store and verify that keychain data store can access it
        XCTAssertTrue(paDs.save(data: dataToSave, forKey: key))
        let dataRetrieved = paDs.loadData(forKey: key)
        XCTAssertNotNil(dataRetrieved)
        XCTAssertEqual(dataRetrieved, dataToSave)
        let migratedDataRetrieved = kcDs.loadData(forKey: key)
        XCTAssertNotNil(migratedDataRetrieved)
        XCTAssertEqual(dataRetrieved, migratedDataRetrieved)
        
        // modify the data
        XCTAssertTrue(paDs.save(data: dataToUpdate, forKey: key))
        let updatedDataRetrieved = paDs.loadData(forKey: key)
        XCTAssertNotNil(updatedDataRetrieved)
        XCTAssertEqual(updatedDataRetrieved, dataToUpdate)
        let migratedUpdatedDataRetrieved = kcDs.loadData(forKey: key)
        XCTAssertNotNil(migratedUpdatedDataRetrieved)
        XCTAssertEqual(updatedDataRetrieved, migratedUpdatedDataRetrieved)
        
        // remove the data from the powerauth data stores
        paDs.removeData(forKey: key)
        XCTAssertNil(paDs.loadData(forKey: key))
        
        // wereify that the data are removed
        XCTAssertNil(kcDs.loadData(forKey: key))
        
    }
}
