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

/// Represents a version conforming to [Semantic Versioning 2.0.0](http://semver.org).
struct Semver {
    
    /// The major version.
    let major: Int
    
    /// The minor version.
    let minor: Int
    
    /// The patch version.
    let patch: Int
    
    /// The pre-release identifiers (if any).
    let prerelease: [String]
    
    /// The build metadatas (if any).
    let buildMetadata: [String]
    
    /// Creates a version with the provided values.
    ///
    /// The result is unchecked. Use `isValid` to validate the version.
    init(major: Int, minor: Int, patch: Int, prerelease: [String] = [], buildMetadata: [String] = []) {
        self.major = major
        self.minor = minor
        self.patch = patch
        self.prerelease = prerelease
        self.buildMetadata = buildMetadata
    }
    
    /// A string representation of prerelease identifiers (if any).
    var prereleaseString: String? {
        return prerelease.isEmpty ? nil : prerelease.joined(separator: ".")
    }
    
    /// A string representation of build metadatas (if any).
    var buildMetadataString: String? {
        return buildMetadata.isEmpty ? nil : buildMetadata.joined(separator: ".")
    }
    
    /// A Boolean value indicating whether the version is pre-release version.
    var isPrerelease: Bool {
        return !prerelease.isEmpty
    }
    
    /// A Boolean value indicating whether the version conforms to Semantic
    /// Versioning 2.0.0.
    ///
    /// An invalid Semver can only be formed with the memberwise initializer
    /// `Semver.init(major:minor:patch:prerelease:buildMetadata:)`.
    var isValid: Bool {
        return major >= 0
            && minor >= 0
            && patch >= 0
            && prerelease.allSatisfy(validatePrereleaseIdentifier)
            && buildMetadata.allSatisfy(validateBuildMetadataIdentifier)
    }
}

extension Semver: Equatable {
    
    /// Semver semantic equality. Build metadata is ignored.
    static func == (lhs: Semver, rhs: Semver) -> Bool {
        return lhs.major == rhs.major &&
            lhs.minor == rhs.minor &&
            lhs.patch == rhs.patch &&
            lhs.prerelease == rhs.prerelease
    }
    
    /// Swift semantic equality.
    static func === (lhs: Semver, rhs: Semver) -> Bool {
        return (lhs == rhs) && (lhs.buildMetadata == rhs.buildMetadata)
    }
    
    /// Swift semantic unequality.
    static func !== (lhs: Semver, rhs: Semver) -> Bool {
        return !(lhs === rhs)
    }
}

extension Semver: Hashable {
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(major)
        hasher.combine(minor)
        hasher.combine(patch)
        hasher.combine(prerelease)
    }
}
    
extension Semver: Comparable {
    
    static func < (lhs: Semver, rhs: Semver) -> Bool {
        guard lhs.major == rhs.major else {
            return lhs.major < rhs.major
        }
        guard lhs.minor == rhs.minor else {
            return lhs.minor < rhs.minor
        }
        guard lhs.patch == rhs.patch else {
            return lhs.patch < rhs.patch
        }
        guard lhs.isPrerelease else {
            return false // Non-prerelease lhs >= potentially prerelease rhs
        }
        guard rhs.isPrerelease else {
            return true // Prerelease lhs < non-prerelease rhs
        }
        return lhs.prerelease.lexicographicallyPrecedes(rhs.prerelease) { lpr, rpr in
            if lpr == rpr { return false }
            // FIXME: deal with big integers
            switch (UInt(lpr), UInt(rpr)) {
            case let (l?, r?):  return l < r
            case (nil, nil):    return lpr < rpr
            case (_?, nil):     return true
            case (nil, _?):     return false
            }
        }
    }
}

extension Semver: Codable {
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let str = try container.decode(String.self)
        guard let version = Semver(str) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid semantic version")
        }
        self = version
    }
}

extension Semver: LosslessStringConvertible {
    
    private static let semverRegex: NSRegularExpression = {
        do {
            return try .init(pattern: #"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([\da-zA-Z\-]+(?:\.[\da-zA-Z\-]+)*))?$"#)
        } catch let e {
            WultraDebug.error("\(e)")
            WultraDebug.fatalError(" Failed to create Regex for semver")
        }
    }()
    
    init?(_ description: String) {
        guard let match = Self.semverRegex.firstMatch(in: description) else {
            return nil
        }
        guard let major = Int(description[match.range(at: 1)]!),
            let minor = Int(description[match.range(at: 2)]!),
            let patch = Int(description[match.range(at: 3)]!) else {
                // version number too large
                return nil
        }
        self.major = major
        self.minor = minor
        self.patch = patch
        prerelease = description[match.range(at: 4)]?.components(separatedBy: ".") ?? []
        buildMetadata = description[match.range(at: 5)]?.components(separatedBy: ".") ?? []
    }
    
    init?(_ description: String?) {
        guard let description = description else {
            return nil
        }
        self.init(description)
    }
    
    var description: String {
        var result = "\(major).\(minor).\(patch)"
        if !prerelease.isEmpty {
            result += "-" + prerelease.joined(separator: ".")
        }
        if !buildMetadata.isEmpty {
            result += "+" + buildMetadata.joined(separator: ".")
        }
        return result
    }
}

extension Semver: ExpressibleByStringLiteral {
    
    init(stringLiteral value: StaticString) {
        guard let v = Semver(value.description) else {
            preconditionFailure("failed to initialize `Semver` using string literal '\(value)'.")
        }
        self = v
    }
}

// MARK: Foundation Extensions
extension Bundle {
    
    /// Use `CFBundleShortVersionString` key
    var semanticVersion: Semver? {
        return (infoDictionary?["CFBundleShortVersionString"] as? String).flatMap(Semver.init(_:))
    }
}

extension ProcessInfo {
    
    var operatingSystemSemanticVersion: Semver {
        let v = operatingSystemVersion
        return Semver(major: v.majorVersion, minor: v.minorVersion, patch: v.patchVersion)
    }
}

// MARK: - Utilities
private func validatePrereleaseIdentifier(_ str: String) -> Bool {
    guard validateBuildMetadataIdentifier(str) else {
        return false
    }
    let isNumeric = str.unicodeScalars.allSatisfy(CharacterSet.asciiDigits.contains)
    return !(isNumeric && (str.first == "0") && (str.count > 1))
}

private func validateBuildMetadataIdentifier(_ str: String) -> Bool {
    return !str.isEmpty && str.unicodeScalars.allSatisfy(CharacterSet.semverIdentifierAllowed.contains)
}

private extension CharacterSet {
    
    static let semverIdentifierAllowed: CharacterSet = {
        var set = CharacterSet(charactersIn: "0"..."9")
        set.insert(charactersIn: "a"..."z")
        set.insert(charactersIn: "A"..."Z")
        set.insert("-")
        return set
    }()
    
    static let asciiDigits = CharacterSet(charactersIn: "0"..."9")
}

private extension String {
    
    subscript(nsRange: NSRange) -> String? {
        guard let r = Range(nsRange, in: self) else {
            return nil
        }
        return String(self[r])
    }
}

private extension NSRegularExpression {
    
    func matches(in string: String, options: NSRegularExpression.MatchingOptions = []) -> [NSTextCheckingResult] {
        let r = NSRange(string.startIndex..<string.endIndex, in: string)
        return matches(in: string, options: options, range: r)
    }
    
    func firstMatch(in string: String, options: NSRegularExpression.MatchingOptions = []) -> NSTextCheckingResult? {
        let r = NSRange(string.startIndex..<string.endIndex, in: string)
        return firstMatch(in: string, options: options, range: r)
    }
}
