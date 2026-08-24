# Dynamic SSL pinning for iOS
<!-- begin remove -->
`WultraSSLPinning` is a library implementing dynamic SSL pinning, written in Swift.  
<!-- end -->
<!-- begin TOC -->

- [Introduction](#introduction)
- [Installation](#installation)
    - [Requirements](#requirements)
    - [Swift PM](#swift-package-manager)
    - [CocoaPods](#cocoapods)
- [Usage](#usage)
    - [Configuration](#configuration)
    - [Update fingerprints](#update-fingerprints)
    - [Fingerprint validation](#fingerprint-validation)
    - [Certificate depth pinning](#certificate-depth-pinning)
    - [Domain bypass configuration](#domain-bypass-configuration)
    - [PowerAuth integration](#powerauth-integration)
- [Migration Guide](#migration-guide)
- [FAQ](#faq)
- [License](#license)
- [Contact](#contact)

<!-- end -->
<!-- begin remove -->
---
<!-- end -->
## Introduction

The SSL pinning (or [public key, or certificate pinning](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning)) is a technique mitigating [Man-in-the-middle attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) against secure HTTP communication. The typical iOS solution is to bundle the hash of the certificate, or the exact data of the certificate, to the application and validate the incoming challenge in the `URLSessionDelegate`. This, in general, works well, but it has, unfortunately, one major drawback - the certificate's expiration date. The certificate expiration forces you to update your application regularly before the certificate expires, but still, some percentage of the users don't update their apps automatically. So, the users on the older version will not be able to contact the application servers.

The solution to this problem is dynamic SSL pinning, where the list of certificate fingerprints is securely downloaded from the remote server. The `WultraSSLPinning` library does precisely this:

- Manages the dynamic list of certificates downloaded from the remote server
- All entries in the list are signed with your private key and validated in the library using the public key (we're using the ECDSA-SHA-256 algorithm)
- Provides easy-to-use fingerprint validation on the TLS handshake.

Before you start using the library, you should also check out our other related projects:

- [Mobile Utility Server](https://github.com/wultra/mobile-utility-server) - the server component that provides dynamic JSON data consumed by this library.
- [Dynamic SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool) - the command line tool written in Java for generating static JSON data consumed by this library.
- [Android version](https://github.com/wultra/ssl-pinning-android) of the library
 

## Installation

### Requirements

- iOS 13.0+
- tvOS 13.0+
- Swift 5

### Swift Package Manager

The [Swift Package Manager](https://swift.org/package-manager) is a tool for automating the distribution of Swift code and is integrated into the `swift` compiler. 

Once you have your Swift package set up, adding this library as a dependency is as easy as adding it to the `dependencies` value of your `Package.swift`.

```swift
dependencies: [
    .package(url: "https://github.com/wultra/ssl-pinning-ios.git", .upToNextMajor(from: "1.8.0"))
]
```

### CocoaPods

[CocoaPods](https://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

To integrate the framework into your Xcode project using CocoaPods, specify it in your `Podfile`:

```ruby
platform :ios, '13.0'
target '<Your Target App>' do
  pod 'WultraSSLPinning'
end
```

---

## Usage

The library provides the following core types:

- `CertStore` - the main class which provides all tasks for dynamic pinning  
- `CertStoreConfiguration` - the configuration structure for the `CertStore` class

The next chapters of this document will explain how to configure and use `CertStore` for SSL pinning purposes.


## Configuration

The following code will configure the `CertStore` object with basic configuration:

```swift
import WultraSSLPinning

let configuration = CertStoreConfiguration(
    serviceUrl: URL(string: "https://...")!,
    publicKey: "BMne....kdh2ak="
)
let certStore = CertStore(configuration: configuration)
```
*We'll use the `certStore` variable in the rest of the documentation as a reference to the already configured `CertStore` instance.*

The configuration has the following properties:

- `serviceUrl` - parameter defining the URL with a remote list of certificates. It is recommended that `serviceUrl` points to a different domain than you're going to protect with pinning. See the [FAQ](#faq) section for more details.
- `publicKey` - contains the public key counterpart to the private key, used for data signing. The Base64 formatted string is expected.
- `expectedCommonNames` - an optional array of strings defining which domains you expect in certificate validation.
- `identifier` - optional string identifier for scenarios, where multiple `CertStore` instances are used in the application
- `fallbackCertificatesData` - optional hardcoded data for fallback fingerprints. See the next chapter of this document for details.
- `periodicUpdateInterval` - defines how often `CertStore` updates the fingerprints silently in the background. The default value is 1 week.
- `expirationUpdateTreshold` - defines the time window before the next certificate will expire. In this time window, `CertStore` will try to update the list of fingerprints more often than usual. The default value is 2 weeks before the next expiration.
- `sslValidationStrategy` - defines the validation strategy for HTTPS connections initiated from the library itself. The `.default` value performs standard certificate chain validation provided by the operating system. Be aware that altering this option may put your application at risk. You should not ship your application to production with SSL validation turned off.

### Predefined fingerprint

The `CertStoreConfiguration` may contain optional data with predefined certificate fingerprints. This technique can speed up the first application's startup when the database of fingerprints is empty. You still need to update your application once the fallback fingerprints expire. 

To configure the property, you need to provide JSON data with fallback fingerprints. The JSON should contain the same data as is usually received from the server, except that the "signature" property is not validated (but must be provided in JSON). The optional `depth` field specifies the certificate chain position (0 = leaf, the default).

> **Important:** Only fallback **certificates** (fingerprints) are supported in `fallbackCertificatesData`. The `domainsConfig` object is intentionally **not** supported in fallback data — domain bypass rules take effect only when received from the server. Any `domainsConfig` present in the fallback JSON is silently ignored.

For example:

```swift
{
   "fingerprints":[
      {
         "name": "github.com",
         "fingerprint": "MRFQDEpmASza4zPsP8ocnd5FyVREDn7kE3Fr/zZjwHQ=",
         "expires": 1591185600,
         "signature": "",
         "depth": 0
      }
   ]
}
""".data(using: .ascii)

let configuration = CertStoreConfiguration(
    serviceUrl: URL(string: "https://...")!,
    publicKey: "BMne....kdh2ak=",
    fallbackCertificatesData: fallbackData!
)
let certStore = CertStore(configuration: configuration)
```

> Note that if you provide the wrong JSON data, then a fatal error will be thrown.


## Update fingerprints

To update the list of fingerprints from the remote server, use the following code:

```swift
certStore.update { result, error in
   if result == .ok {
       // everything's OK, 
       // No action is required, or a silent update was started
   } else {
       // Other error. See `CertStore.UpdateResult` for details.
       // The "error" variable is set in case of a network error.
   }
}
```

You typically have to call the update on your application's startup before you initiate the secure HTTP request to the server, which certificate's expected to be validated with the pinning. The update function works in two basic modes:

- **Blocking mode**, when your application has to wait to download the list of certificates. This typically happens when all certificate fingerprints expire or on the application's first start (e.g., there's no list of certificates)
- **Silent update mode**, when the callback is queued immediately to the completion queue, but the `CertStore` performs the update in the background. The purpose of the silent update is not to block your app's startup but still keep the list of fingerprints up to date. The periodicity of the updates is determined automatically by the `CertStore`, but don't worry, we don't want to eat your users' data plan :)

You can optionally provide the completion dispatch queue for scheduling the completion block. This may be useful for situations when you're calling updates from other than the "main" thread (for example, from your own networking code). The default queue for the completion is `.main`.

## Fingerprint validation

The `CertStore` provides several methods for certificate fingerprint validation. You can choose the one that best suits your scenario:

```swift
// [ 1 ]  If you already have the common name (e.g., domain) and certificate fingerprint

let commonName = "yourdomain.com"
let fingerprint = Data(...)
let validationResult = certStore.validate(commonName: commonName, fingerprint: fingerprint)

// [ 2 ]  If you already have the common name and the certificate data (in DER format)

let commonName = "yourdomain.com"
let certData = Data(...)
let validationResult = certStore.validate(commonName: commonName, certificateData: certData)

// [ 3 ]  You want to validate URLAuthenticationChallenge. `depth` parameter cannot be provide in this case. It is determined automatically from entries stored in `certStore`.

let validationResult = certStore.validate(challenge: challenge)

// [ 4 ]  Validate a certificate at a specific depth (see "Certificate depth pinning")

let validationResult = certStore.validate(commonName: commonName, fingerprint: fingerprint, depth: 1)
let validationResult = certStore.validate(commonName: commonName, certificateData: certData, depth: 1)
```

The `validate(commonName:fingerprint:depth:)` and `validate(commonName:certificateData:depth:)` overloads accept an explicit `depth` and match only entries stored at that depth. `validate(challenge:)` does **not** accept a `depth` parameter — it automatically validates all pinned entries across every depth (see [Certificate depth pinning](#certificate-depth-pinning)).

Each `validate` method returns `CertStore.ValidationResult` enumeration with the following options:

- `trusted` - the server certificate is trusted. You can continue with the communication

  The right response to this situation is to continue with the ongoing TLS handshake (e.g. report
  [.performDefaultHandling](https://developer.apple.com/documentation/foundation/urlsession/authchallengedisposition)
  to the completion callback)
   
- `untrusted` - the server certificate is not trusted. You should cancel the ongoing challenge.

  The untrusted result means that `CertStore` has some fingerprints stored in its
  database, but none matches the value you requested for validation. The right
  response to this situation is always to cancel the ongoing TLS handshake (e.g. report
  [.cancelAuthenticationChallenge](https://developer.apple.com/documentation/foundation/urlsession/authchallengedisposition)
  to the completion callback)

- `empty` - the fingerprints database is empty, or there's no fingerprint for the validated common name.

  The "empty" validation result typically means that the `CertStore` should update
  the list of certificates immediately. Before you do this, you should check whether
  the requested common name is what you're expecting. To simplify this step, you can set 
  the list of expected common names in the `CertStoreConfiguration` and treat all others as untrusted.
    
  For all situations, the right response is always to cancel the ongoing
  TLS handshake (e.g., report [.cancelAuthenticationChallenge](https://developer.apple.com/documentation/foundation/urlsession/authchallengedisposition)
  to the completion callback)


The full challenge handling in your app may look like this:

```swift
class YourUrlSessionDelegate: NSObject, URLSessionDelegate {
    
    let certStore: CertStore
    
    init(certStore: CertStore) {
        self.certStore = certStore
    }
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        switch certStore.validate(challenge: challenge) {
        case .trusted:
            // Accept challenge with a default handling
            completionHandler(.performDefaultHandling, nil)
        case .untrusted, .empty:
            /// Reject challenge
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

## Certificate depth pinning

By default the library pins the **leaf certificate** — the certificate the server presents directly. For stronger protection against a compromised leaf certificate you can instead pin an **intermediate CA** or the **root CA** in the certificate chain.

The `depth` value refers to the position of the certificate in the TLS chain as seen by `SecTrustGetCertificateAtIndex`:

| depth | certificate |
|-------|-------------|
| `0`   | Leaf (server) certificate — default |
| `1`   | First intermediate CA |
| `2`   | Second intermediate CA (if present) |
| `N`   | Root CA |

The [Mobile Utility Server](https://github.com/wultra/mobile-utility-server) stores the `depth` for each registered fingerprint and includes it in the response. When you call `validate(challenge:)`, the SDK automatically iterates over **all** pinned entries for the domain and validates each one against the certificate at its stored depth in the live TLS chain. The challenge is trusted as soon as any entry matches.

```swift
// No depth parameter needed — the SDK resolves depth automatically for each stored entry
func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    switch certStore.validate(challenge: challenge) {
    case .trusted:
        completionHandler(.performDefaultHandling, nil)
    case .untrusted, .empty:
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

To pin an intermediate CA simply register its fingerprint at `depth: 1` in the Mobile Utility Server — no code change is needed in your app.

**Important notes:**

- Depth is **configured server-side** in the Mobile Utility Server and carried in the downloaded fingerprint list. There is no `depth` parameter on `validate(challenge:)`.
- Fingerprints stored at depth 0 are only matched against the leaf certificate; fingerprints stored at depth 1 are only matched against the first intermediate, and so on. A fingerprint stored at one depth is never compared against a certificate at a different depth.
- The leaf common name is always used to look up stored fingerprints, regardless of depth.
- If a stored depth value exceeds the actual TLS chain length, that entry is silently skipped. Other entries for the same domain are still evaluated.
- Multiple fingerprints for the same domain at different depths are fully supported and validated together in a single `validate(challenge:)` call.

## Domain bypass configuration

The [Mobile Utility Server](https://github.com/wultra/mobile-utility-server) can mark specific domains as not requiring SSL pinning. When the server includes this configuration in its response the SDK respects it transparently — no code changes are needed in your app.

### How it works

The server response may include a `domainsConfig` object:

```json
{
  "fingerprints": [...],
  "domainsConfig": {
    "sslPinningRequiredForUnlisted": true,
    "domains": [
      { "name": "bypass.example.com", "sslPinningRequired": false },
      { "name": "api.example.com",    "sslPinningRequired": true  }
    ]
  }
}
```

The SDK applies the following rules on every call to `validate`:

1. If the domain appears in `domains` with `sslPinningRequired: false` → returns `.trusted` immediately, no fingerprint check.
2. If the domain appears in `domains` with `sslPinningRequired: true` → normal fingerprint-based validation applies.
3. If the domain is **not** in the list:
   - `sslPinningRequiredForUnlisted: true` → normal fingerprint-based validation (default server behaviour).
   - `sslPinningRequiredForUnlisted: false` → returns `.trusted` immediately.

The `domainsConfig` is cached locally alongside the fingerprints and cleared whenever the server sends a response without it.

> **Important:** `domainsConfig` is supported **only** when received from the server. It is intentionally **not** supported in `fallbackCertificatesData` — there is no fallback mechanism for domain bypass rules.

## PowerAuth integration

Since a lot of our clients are using dynamic SSL pinning together with our [PowerAuth SDK](https://github.com/wultra/powerauth-mobile-sdk), you can use the following snippet, which implements the `PowerAuthClientSslValidationStrategy` protocol with the functionality of this library:

```swift
import PowerAuth2
import WultraSSLPinning

/// Dynamic SSL pinning implementation for PowerAuth SDK
public class PowerAuthSslPinningValidationStrategy: NSObject, PowerAuthClientSslValidationStrategy {
    
    /// `CertStore` object, which actually implements the SSL pinning.
    public let certStore: CertStore
    
    /// Initializes object with instance of CertStore.
    public init(certStore: CertStore) {
        self.certStore = certStore
    }
    
    /// Implements SSL certificate validation, as defined in `PowerAuthClientSslValidationStrategy` protocol.
    public func validateSsl(for session: URLSession, challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Validate challenge and complete handler with an appropriate result.
        switch certStore.validate(challenge: challenge) {
        case .trusted:
            // Accept challenge with a default handling
            completionHandler(.performDefaultHandling, nil)
        case .untrusted, .empty:
            /// Reject challenge
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

> The `WultraSSLPinning/PowerAuthIntegration` CocoaPods subspec that provided out-of-the-box integration with the PowerAuth SDK has been removed. Use the manual integration shown above instead.
 
## Migration guide

### 1.7.x to 1.8.x

All PowerAuth helpers in the `WultraSSLPinning/PowerAuthIntegration` pod were deprecated.

All PowerAuth helpers are no longer available for Swift Package Manager integration.

- Use `CertStore` initializer directly instead of `CertStore.powerAuthCertStore`
- `PowerAuthSecureDataStore` can be replaced by the `KeychainSecureDataStore` with the same parameters.
- `PowerAuthCryptoProvider` can be replaced by the `CryptoKitCryptoProvider`.
- Replace `PowerAuthSslPinningValidationStrategy` by your own implementation ([example](#powerauth-integration))

### 1.8.x to 1.9.x

The internal cache format was extended with an optional `depth` field for each stored certificate entry. When the field is absent (e.g. in caches written by version 1.8.x), it defaults to `0` (leaf certificate). Existing caches are fully compatible with 1.9.x — no cache reset, server update, or integrator action is required.

`validate(challenge:)` automatically validates **all** pinned entries for the domain, each at its stored depth. The result is `.trusted` as soon as any entry matches, `.untrusted` if entries were found but none matched, and `.empty` if no applicable entries exist. All previously written `validate(challenge:)` call sites continue to compile and behave correctly.

The `depth` parameter is still available on `validate(commonName:fingerprint:depth:)` and `validate(commonName:certificateData:depth:)` for cases where you supply the fingerprint or certificate data yourself.

The `useChallenge` property has been removed from `CertStoreConfiguration`. Challenge-based request signing is now always enabled — the library always sends a random challenge in the `X-Cert-Pinning-Challenge` request header and always validates the ECDSA signature in the `X-Cert-Pinning-Signature` response header.

- Remove `useChallenge` from your `CertStoreConfiguration` initializer call.
- Ensure your server (e.g. [Mobile Utility Server](https://github.com/wultra/mobile-utility-server)) supports challenge-based response signing. Static JSON data generated by the [Dynamic SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool) is no longer supported.

### TBA

The `WultraSSLPinning/PowerAuthIntegration` CocoaPods subspec and its PowerAuth-based helpers (`PowerAuthCryptoProvider`, `PowerAuthSecureDataStore`, `PowerAuthSslPinningValidationStrategy`, and `CertStore.powerAuthSslValidationStrategy()`) have been removed. The library no longer depends on the PowerAuth SDK.

- Replace `PowerAuthCryptoProvider` with `CryptoKitCryptoProvider`.
- Replace `PowerAuthSecureDataStore` with `KeychainSecureDataStore` (using the same parameters).
- Replace `PowerAuthSslPinningValidationStrategy` with your own implementation ([example](#powerauth-integration)).

## FAQ

### Why a different domain for `serviceUrl`?

iOS is using a TLS cache for all secure connections to the remote servers. The cache keeps the already established connection alive for a while to speed up the next HTTPS request (see [Apple's Technical Q&A](https://developer.apple.com/library/archive/qa/qa1727/_index.html) for more information). Unfortunately, you don't have direct control of that cache, so you cannot close an already established connection. That, unfortunately, opens a small door for the attacker. Imagine this scenario:

1. The connection to get the remote list of fingerprints should not be protected with pinning. The list must be accessed for all costs, so protecting it with the pinning may cause the cert store to deadlock itself (or simply move it to the next level, where you need to update the fingerprint, which must protect getting the list of new fingerprints)
2. You usually need to update the list of fingerprints at the application's startup before everything else. 
3. Due to step 1., the attacker can trick your app to get the list of certificates by using his rogue CA. This will not allow him to insert a new entry to the list, but that's not the point.
4. If your API is on the same domain, then your app's connection will reuse the already established connection (opened in step 2. or 3.) via the MitM. And that's it.

Well, not everything's lost. If you're using `URLSession` (probably yes), then you can re-create a new `URLSession` because it has its own TLS cache. But all this is not well documented, so that's why we recommend putting the list of fingerprints on the different domains to avoid this kind of conflict in the TLS cache at all.


### Can the library provide more debug information?

Yes, you can change how much information is printed to the debug console:

```swift
WultraDebug.verboseLevel = .all
```

## License

All sources are licensed using Apache 2.0 license. You can use them with no restrictions. If you are using this library, please let us know. We will be happy to share and promote your project.

## Contact

If you need any assistance, do not hesitate to drop us a line at [hello@wultra.com](mailto:hello@wultra.com) or our official [wultra.com/discord](https://wultra.com/discord) channel.

### Security Disclosure

If you believe you have identified a security vulnerability with WultraSSLPinning, you should report it as soon as possible via email to [support@wultra.com](mailto:support@wultra.com). Please do not post it to a public issue tracker.
