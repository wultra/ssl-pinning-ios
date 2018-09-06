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

extension Data {

    /// Constructs Data object from hexadecimal string.
    static func fromHex(_ string: String) -> Data? {
        var result = Data()
        result.reserveCapacity(string.count / 2 + 1)        
        var upperHalf: UInt32 = 0
        var count = string.count & 1
        for ch in string.unicodeScalars {
            if (count & 1) == 0 {
                upperHalf = chToByte(ch)
                if upperHalf == 0xff {
                    return nil
                }
            } else {
                let lowerHalf = chToByte(ch)
                if lowerHalf == 0xff {
                    return nil
                }
                result.append(UInt8(upperHalf << 4 | lowerHalf))
            }
            count += 1
        }
        return result
    }

    /// Helper function, converts UnicodeScalar to byte in range 0x0 to 0xf.
    /// If character is invalid, then returns 0xFF
    private static func chToByte(_ char: UnicodeScalar) -> UInt32 {
        if char >= "0" && char <= "9" {
            return char.value - 48
        }
        if char >= "A" && char <= "F" {
            return char.value - 65 + 10
        }
        if char >= "a" && char <= "f" {
            return char.value - 97 + 10
        }

        return 0xff
    }
    
    /// Converts Data object to hexadecimal string.
    var toHex: String {
        var result = ""
        result.reserveCapacity(self.count * 2)
        for byte in self {
            let byteAsUInt = Int(byte)
            result.append(Data.toHexTable[byteAsUInt >> 4])
            result.append(Data.toHexTable[byteAsUInt & 15])
        }
        return result
    }
    
    private static let toHexTable: [Character] = [ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F" ]
}
