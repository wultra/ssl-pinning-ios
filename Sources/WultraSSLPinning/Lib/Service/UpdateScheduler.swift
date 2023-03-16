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

/// The `UpdateScheduler` struct helps with calculating the next date for
/// the silent update.
internal struct UpdateScheduler {
    
    /// Contains value from `config.periodicUpdateInterval`
    let periodicUpdateInterval: TimeInterval
    
    /// Contains value from `config.expirationUpdateTreshold`
    let expirationUpdateTreshold: TimeInterval
    
    /// Constant to calculate closer date when certificate is going to expire soon.
    let thresholdMultiplier: Double
    
    /// Function calculates the next date for silent update.
    func scheduleNextUpdate(certificates: [CertificateInfo], currentDate: Date = Date()) -> Date {
        // At first, we will look for expired certificate with closest expiration date.
        // We will also ignore older entries for the same common name. We don't need to update frequently
        // once the replacement certificate is in database.
        var processedCommonName = Set<String>()
        // Set nextExpired to approximately +10 years since now. We need just some big, but valid date
        var nextExpired = currentDate.addingTimeInterval(10*365*24*60*60)
        for ci in certificates {
            if processedCommonName.contains(ci.commonName) {
                continue
            }
            processedCommonName.insert(ci.commonName)
            nextExpired = min(nextExpired, ci.expires)
        }
        // Convert expires date to time interval since now
        var nextExpiredInterval = nextExpired.timeIntervalSince(currentDate)
        if nextExpiredInterval > 0 {
            if nextExpiredInterval < expirationUpdateTreshold {
                // If we're below the threshold, then don't wait to certificate expire and ask server
                // more often for the update.
                nextExpiredInterval *= thresholdMultiplier
            }
        } else {
            // Looks like that newest is already expired, set the scheduled date to current
            nextExpiredInterval = 0
        }
        // Finally, choose between periodic update or
        nextExpiredInterval = min(nextExpiredInterval, periodicUpdateInterval)
        return currentDate.addingTimeInterval(nextExpiredInterval)
    }
}
