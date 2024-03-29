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
    - [Carthage](#carthage) (experimental)
- [Usage](#usage)
    - [Configuration](#configuration)
    - [Update fingerprints](#update-fingerprints)
    - [Fingerprint validation](#fingerprint-validation)
    - [PowerAuth integration](#powerauth-integration)
- [FAQ](#faq)
- [License](#license)
- [Contact](#contact)

<!-- end -->
<!-- begin remove -->
---
<!-- end -->
## Introduction

The SSL pinning (or [public key, or certificate pinning](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning)) is a technique mitigating [Man-in-the-middle attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) against the secure HTTP communication. The typical iOS solution is to bundle the hash of the certificate, or the exact data of the certificate to the application and validate the incoming challenge in the `URLSessionDelegate`. This in general works well, but it has, unfortunately, one major drawback - the certificate's expiration date. The certificate expiration forces you to update your application regularly before the certificate expires, but still, some percentage of the users don't update their apps automatically. So, the users on the older version, will not be able to contact the application servers.

The solution to this problem is dynamic SSL pinning, where the list of certificate fingerprints is securely downloaded from the remote server. The `WultraSSLPinning` library does precisely this:

- Manages the dynamic list of certificates, downloaded from the remote server
- All entries in the list are signed with your private key and validated in the library using the public key (we're using the ECDSA-SHA-256 algorithm)
- Provides easy-to-use fingerprint validation on the TLS handshake.

Before you start using the library, you should also check our other related projects:

- [Mobile Utility Server](https://github.com/wultra/mobile-utility-server) - the server component that provides dynamic JSON data consumed by this library.
- [Dynamic SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool) - the command line tool written in Java, for generating static JSON data consumed by this library.
- [Android version](https://github.com/wultra/ssl-pinning-android) of the library
 

## Installation

### Requirements

- iOS 12.0+
- tvOS 12.0+
- Xcode 15+
- Swift 5.0+

### Swift Package Manager

The [Swift Package Manager](https://swift.org/package-manager) is a tool for automating the distribution of Swift code and is integrated into the `swift` compiler. 

Once you have your Swift package set up, adding this library as a dependency is as easy as adding it to the `dependencies` value of your `Package.swift`.

```swift
dependencies: [
    .package(url: "https://github.com/wultra/ssl-pinning-ios.git", .upToNextMajor(from: "1.6.0"))
]
```

### CocoaPods

[CocoaPods](https://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

To integrate the framework into your Xcode project using CocoaPods, specify it in your `Podfile`:

```ruby
platform :ios, '12.0'
target '<Your Target App>' do
  pod 'WultraSSLPinning/PowerAuthIntegration'
end
```

The current version of the library depends on the [PowerAuth2](https://github.com/wultra/powerauth-mobile-sdk) framework, version `0.19.1` and greater.

### Carthage

*Note that Carthage integration is experimental. We don't provide support for this type of installation.*

[Carthage](https://github.com/Carthage/Carthage) is a decentralized dependency manager that builds your dependencies and provides you with binary frameworks. You can install Carthage with [Homebrew](https://brew.sh/) using the following command:

```bash
$ brew update
$ brew install carthage
```

To integrate the library into your Xcode project using Carthage, specify it in your `Cartfile`:
```
github "wultra/WultraSSLPinning"
```

Run `carthage update` to build the framework and drag the built `WultraSSLPinning.framework` into your Xcode project.

---

## Usage

The library provides the following core types:

- `CertStore` - the main class which provides all tasks for dynamic pinning  
- `CertStoreConfiguration` - the configuration structure for the `CertStore` class

The next chapters of this document will explain how to configure and use `CertStore` for SSL pinning purposes.


## Configuration

The following code will configure the `CertStore` object with basic configuration, using `PowerAuth2` as the cryptographic provider & secure storage provider:
```swift
import WultraSSLPinning

let configuration = CertStoreConfiguration(
    serviceUrl: URL(string: "https://...")!,
    publicKey: "BMne....kdh2ak=",
    useChallenge: true
)
let certStore = CertStore.powerAuthCertStore(configuration: configuration)
```
*We'll use the `certStore` variable in the rest of the documentation as a reference to the already configured `CertStore` instance.*

The configuration has the following properties:

- `serviceUrl` - parameter defining URL with a remote list of certificates. It is recommended that `serviceUrl` points to a different domain than you're going to protect with pinning. See the [FAQ](#faq) section for more details.
- `publicKey` - contains the public key counterpart to the private key, used for data signing. The Base64 formatted string is expected.
- `useChallenge` - parameter that defines whether the remote server requires a challenge request header:
  - use `true` in case you're connecting to [Mobile Utility Server](https://github.com/wultra/mobile-utility-server) or similar service.
  - use `false` in case the remote server provides static data, generated by [SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool).
- `expectedCommonNames` - an optional array of strings, defining which domains you expect in certificate validation.
- `identifier` - optional string identifier for scenarios, where multiple `CertStore` instances are used in the application
- `fallbackCertificatesData` - optional hardcoded data for fallback fingerprints. See the next chapter of this document for details.
- `periodicUpdateInterval` - defines how often `CertStore` updates the fingerprints silently in the background. The default value is 1 week.
- `expirationUpdateTreshold` - defines the time window before the next certificate will expire. In this time window `CertStore` will try to update the list of fingerprints more often than usual. The default value is 2 weeks before the next expiration.
- `sslValidationStrategy` - defines the validation strategy for HTTPS connections initiated from the library itself. The `.default` value performs standard certificate chain validation provided by the operating system. Be aware that altering this option may put your application at risk. You should not ship your application to production with SSL validation turned off.

### Predefined fingerprint

The `CertStoreConfiguration` may contain optional data with predefined certificate fingerprints. This technique can speed up the first application's startup when the database of fingerprints is empty. You still need to update your application, once the fallback fingerprints expire. 

To configure the property, you need to provide JSON data with fallback fingerprints. The JSON should contain the same data as is usually received from the server, except that the "signature" property is not validated (but must be provided in JSON). For example:

```swift
{
   "fingerprints":[
      {
         "name": "github.com",
         "fingerprint": "MRFQDEpmASza4zPsP8ocnd5FyVREDn7kE3Fr/zZjwHQ=",
         "expires": 1591185600,
         "signature": ""
      }
   ]
}
""".data(using: .ascii)

let configuration = CertStoreConfiguration(
    serviceUrl: URL(string: "https://...")!,
    publicKey: "BMne....kdh2ak=",
    fallbackCertificatesData: fallbackData!
)
let certStore = CertStore.powerAuthCertStore(configuration: configuration)
```

> Note that if you provide the wrong JSON data, then the fatal error is thrown.

### Shared instance

The library doesn't provide singleton for `CertStore`, but you can make it on your own. For example:
```swift
extension CertStore {
    static var shared: CertStore {
        let config = CertStoreConfiguration(
            serviceUrl: URL(string: "https://...")!,
            publicKey: "BMne....kdh2ak="
        )
        return .powerAuthCertStore(configuration: config)
    }
}
```


## Update fingerprints

To update the list of fingerprints from the remote server, use the following code:
```swift
certStore.update { (result, error) in
   if result == .ok {
       // everything's OK, 
       // No action is required, or a silent update was started
   } else if result == .storeIsEmpty {
       // Update succeeded, but it looks like the remote list contains
       // already expired fingerprints. The certStore will probably not be able
       // to validate the fingerprints.
   } else {
       // Other error. See `CertStore.UpdateResult` for details.
       // The "error" variable is set in case of a network error.
   }
}
```

You have to typically call the update on your application's startup before you initiate the secure HTTP request to the server, which certificate's expected to be validated with the pinning. The update function works in two basic modes:

- **Blocking mode**, when your application has to wait to download the list of certificates. This typically happens when all certificate fingerprints expire, or on the application's first start (e.g. there's no list of certificates)
- **Silent update mode**, when the callback is queued immediately to the completion queue, but the `CertStore` performs the update in the background. The purpose of the silent update is to not block your app's startup, but still keep the list of fingerprints up to date. The periodicity of the updates is determined automatically by the `CertStore`, but don't worry, we don't want to eat your users' data plan :)

You can optionally provide the completion dispatch queue for scheduling the completion block. This may be useful for situations when you're calling updates from other than the "main" thread (for example, from your own networking code). The default queue for the completion is `.main`.

## Fingerprint validation

The `CertStore` provides several methods for certificate fingerprint validation. You can choose the one which suits best for your scenario:

```swift
// [ 1 ]  If you already have the common name (e.g. domain) and certificate fingerprint

let commonName = "yourdomain.com"
let fingerprint = Data(...)
let validationResult = certStore.validate(commonName: commonName, fingerprint: fingerprint)

// [ 2 ]  If you already have the common name and the certificate data (in DER format)

let commonName = "yourdomain.com"
let certData = Data(...)
let validationResult = certStore.validate(commonName: commonName, certificateData: certData)

// [ 3 ]  You want to validate URLAuthenticationChallenge

let validationResult = certStore.validate(challenge: challenge)
```

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
    
  For all situations, the right response on this situation is always to cancel the ongoing
  TLS handshake (e.g. report [.cancelAuthenticationChallenge](https://developer.apple.com/documentation/foundation/urlsession/authchallengedisposition)
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

## PowerAuth integration

The `WultraSSLPinning/PowerAuthIntegration` cocoapod sub-spec provides several additional classes which enhance the PowerAuth SDK functionality. The most important one is the `PowerAuthSslPinningValidationStrategy` class, which implements SSL pinning using fingerprints, stored in the `CertStore`. You can simply instantiate this object from the existing `CertStore` and set it to the `PowerAuthClientConfiguration`. Then the class will provide SSL pinning for all communication initiated from the PowerAuth SDK.

For example, this is how the configuration sequence may look like if you want to use both, `PowerAuthSDK` and `CertStore`, as singletons:

```swift
import WultraSSLPinning
import PowerAuth2

extension CertStore {
    /// Singleton for `CertStore`
    static var shared: CertStore {
        let config = CertStoreConfiguration(
            serviceUrl: URL(string: "https://...")!,
            publicKey: "BASE64...KEY"
        )
        return .powerAuthCertStore(configuration: config)
    }
}

extension PowerAuthSDK {
    /// Singleton for `PowerAuthSDK`
    static var shared: PowerAuthSDK {
        // Configure your PA...
        let config = PowerAuthConfiguration()
        config.baseEndpointUrl = ...
        
        // Configure the keychain
        let keychain = PowerAuthKeychainConfiguration()
        keychain.identifier = ...
        
        // Configure PowerAuthClient and assign validation strategy...
        let client = PowerAuthClientConfiguration()
        client.sslValidationStrategy = CertStore.shared.powerAuthSslValidationStrategy()
        
        // And construct the SDK instance
        guard let powerAuth = PowerAuthSDK(configuration: config, keychainConfiguration: keychain, clientConfiguration: client)
            else { fatalError() }
        return powerAuth
    }
}
``` 

---

## FAQ

### Why a different domain for `serviceUrl`?

iOS is using a TLS cache for all secure connections to the remote servers. The cache keeps already established connection alive for a while, to speed up the next HTTPS request (see [Apple's Technical Q&A](https://developer.apple.com/library/archive/qa/qa1727/_index.html) for more information). Unfortunately, you don't have direct control of that cache, so you cannot close an already established connection. That, unfortunately, opens a small door for the attacker. Imagine this scenario:

1. The connection to get the remote list of fingerprints should not be protected with pinning. The list must be accessed for all costs, so protecting it with the pinning may cause the cert store to deadlock itself (or simply move it to the next level, where you need to update the fingerprint which must protect getting the list of new fingerprints)
2. You usually need to update the list of fingerprints at the application's startup, before everything else. 
3. Due to step 1., the attacker can trick your app to get the list of certificates by using his rogue CA. This will not allow him to insert a new entry to the list, but that's not the point.
4. If your API is on the same domain, then your app's connection will reuse the already established connection (opened in step 2. or 3.), via the MitM. And that's it.

Well, not everything's lost. If you're using `URLSession` (probably yes), then you can re-create a new `URLSession`, because it has its own TLS cache. But all this is not well documented, so that's why we recommend putting the list of fingerprints on the different domains, to avoid this kind of conflict in the TLS cache at all.


### Can the library provide more debug information?

Yes, you can change how much information is printed to the debug console:
```swift
WultraDebug.verboseLevel = .all
```

### Why dependency on PowerAuth2?

The library requires several cryptographic primitives, which are typically not available in iOS (like ECDSA). The `PowerAuth2` already provides these functions, and most of our clients are already using the PowerAuth2 framework in their applications. So, for our purposes, it makes sense to glue both libraries together.

But not everything is lost. The core of the library uses the `CryptoProvider` protocol and therefore is implementation independent. We'll provide the standalone version of the pinning library later. 

---

## License

All sources are licensed using Apache 2.0 license. You can use them with no restrictions. If you are using this library, please let us know. We will be happy to share and promote your project.

## Contact

If you need any assistance, do not hesitate to drop us a line at [hello@wultra.com](mailto:hello@wultra.com) or our official [wultra.com/discord](https://wultra.com/discord) channel.

### Security Disclosure

If you believe you have identified a security vulnerability with WultraSSLPinning, you should report it as soon as possible via email to [support@wultra.com](mailto:support@wultra.com). Please do not post it to a public issue tracker.
