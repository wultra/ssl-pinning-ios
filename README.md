# Dynamic SSL pinning

`WultraSSLPinning` is library implementing dynamic SSL pinning, written in Swift.  

- [Introduction](#introduction)
- [Installation](#installation)
    - [Requirements](#requirements)
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

---

## Introduction

The SSL pinning (or [public key, or certificate pinning](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning)) is a technique mitigating [Man-in-the-middle attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) against the secure HTTP communication. The typical iOS solution is to bundle the hash of the certificate, or the exact data of the certificate to the application and validate the incoming challenge in the `URLSessionDelegate`. This in general works well, but it has unfortunately one major drawback in the certificate's expiration date. The certificate expiration forces you to update your application regularly, before the certificate expires, but still, some percentage of the users don't update their apps automatically. So, the users on the older version, will not be able to contact the application servers.

The solution for this problem is the dynamic SSL pinning, where the list of certificate fingerprints are securely downloaded from the remote server. The `WultraSSLPinning` library does exactly that:

- Manages the dynamic list of certificates, downloaded from the remote server
- All entries in the list are signed with your private key, and validated in the library with using the public key (we're using ECDSA-SHA-256 algorithm)
- Provides easy to use fingerprint validation on the TLS handshake.

Before you start using the library, you should also check our other related projects:

- [Dynamic SSL Pinning Tool](https://github.com/wultra/ssl-pinning-tool) - the command line tool written in Java, for generating JSON data consumed by this library.
- [Android version](https://github.com/wultra/ssl-pinning-android) of the library
 

## Installation

### Requirements

- iOS 8.0+
- Xcode 9.4+
- Swift 4.1+

### CocoaPods

[CocoaPods](https://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

To integrate framework into your Xcode project using CocoaPods, specify it in your `Podfile`:

```ruby
platform :ios, '8.0'
target '<Your Target App>' do
  pod 'WultraSSLPinning/PowerAuthIntegration'
end
```

The current version of library depends on [PowerAuth2](https://github.com/wultra/powerauth-mobile-sdk) framework, version `0.19.1` and greater.

### Carthage

*Note that Carthage integration is experimental. We don't provide support for this type of installation.*

[Carthage](https://github.com/Carthage/Carthage) is a decentralized dependency manager that builds your dependencies and provides you with binary frameworks. You can install Carthage with [Homebrew](https://brew.sh) using the following command:

```bash
$ brew update
$ brew install carthage
```

To integrate library into your Xcode project using Carthage, specify it in your `Cartfile`:
```
github "wultra/WultraSSLPinning"
```

Run `carthage update` to build the framework and drag the built `WultraSSLPinning.framework` into your Xcode project.

---

## Usage

The library provides following core types:

- `CertStore` - the main class which provides all tasks for dynamic pinning  
- `CertStoreConfiguration` - the configuration structure for `CertStore` class

The next chapters of this document will explain how to configure and use `CertStore` for the SSL pinning purposes.


## Configuration

Following code will configure `CertStore` object with basic configuration, with using `PowerAuth2` as cryptographic provider & secure storage provider:
```swift
import WultraSSLPinning

let configuration = CertStoreConfiguration(
    serviceUrl: URL(string: "https://...")!,
    publicKey: "BMne....kdh2ak="
)
let certStore = CertStore.powerAuthCertStore(configuration: configuration)
```
*We'll use `certStore` variable in the rest of the documentation as a reference to already configured `CertStore` instance.*

The configuration has following properties:

- `serviceUrl` - parameter defining URL with remote list of certificates. It is recommended that `serviceUrl` points to a different domain than you're going to protect with pinning. See [FAQ](#faq) section for more details.
- `publicKey` - contains public key counterpart to private key, used for data signing. The BASE64 formatted string is expected.
- `expectedCommonNames` - optional array of strings, defining which domains you expect in certificate validation.
- `identifier` - optional string identifier for scenarios, where multiple `CertStore` instances are used in the application
- `fallbackCertificateData` - optional hardcoded data for fallback fingerprint. See the next chapter of this document for details.
- `periodicUpdateInterval` - defines how often will `CertStore` update the fingerprints silently at the background. Default value is 1 week.
- `expirationUpdateTreshold` - defines time window before the next certificate will expire. In this time window `CertStore` will try to update the list of fingerprints more often than usual. Default value is 2 weeks before the next expiration.


### Predefined fingerprint

The `CertStoreConfiguration` may contain an optional data with predefined certificate fingerprint. This technique can speedup the first application's startup when the database of fingerprints is empty. You still need to update your application, once the fallback fingerprint expires. 

To configure the property, you need to provide JSON data with fallback fingerprint. The JSON should contains the same data as are usually received from the server, except that "signature" property is not validated (but must be provided in JSON). For example:

```swift
let fallbackData = """
{
  "name" : "github.com",
  "fingerprint" : "MRFQDEpmASza4zPsP8ocnd5FyVREDn7kE3Fr/zZjwHQ=",
  "expires" : 1591185600,
  "signature" : ""
}
""".data(using: .ascii)

let configuration = CertStoreConfiguration(
    serviceUrl: URL(string: "https://...")!,
    publicKey: "BMne....kdh2ak=",
    fallbackCertificateData: fallbackData!
)
let certStore = CertStore.powerAuthCertStore(configuration: configuration)
```


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

To update list of fingerprints from the remote server, use the following code:
```swift
certStore.update { (result, error) in
   if result == .ok {
       // everything's OK, 
       // No action is required, or silent update was started
   } else if result == .storeIsEmpty {
       // Update succeeded, but it looks like the remote list contains
       // already expired fingerprints. The certStore will probably not be able
       // to validate the fingerprints.
   } else {
       // Other error. See `CertStore.UpdateResult` for details.
       // The "error" variable is set in case of network error.
   }
}
```

You have to typically call the update on your application's startup, before you initiate the secure HTTP request to the server, which certificate's expected to be validated with the pinning. The update function works in two basic modes:

- **Blocking mode**, when your application has to wait for downloading the list of certificates. This typically happens when all certificate fingerprints did expire, or on the application's first start (e.g. there's no list of certificates)
- **Silent update mode**, when the callback is queued immediately to the completion queue, but the `CertStore` performs the update on the background. The purpose of the silent update is to do not block your app's startup, but still keep that the list of fingerprints is up to date. The periodicity of the updates are determined automatically by the `CertStore`, but don't worry, we don't want to eat your users' data plan :)

You can optionally provide the completion dispatch queue for scheduling the completion block. This may be useful for situations, when you're calling update from other than "main" thread (for example, from your own networking code). The default queue for the completion is `.main`.

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

Each `validate` methods returns `CertStore.ValidationResult` enumeration with following options:

- `trusted` - the server certificate is trusted. You can continue with the communication

  The right response on this situation is to continue with the ongoing TLS handshake (e.g. report
  [.performDefaultHandling](https://developer.apple.com/documentation/foundation/urlsession/authchallengedisposition)
  to the completion callback)
   
- `untrusted` - the server certificate is not trusted. You should cancel the ongoing challenge.

  The untrusted result means that `CertStore` has some fingerprints stored in its
  database, but none matches the value you requested for validation. The right
  response on this situation is to always cancel the ongoing TLS handshake (e.g. report
  [.cancelAuthenticationChallenge](https://developer.apple.com/documentation/foundation/urlsession/authchallengedisposition)
  to the completion callback)

- `empty` - the fingerprints database is empty, or there's no fingerprint for validated common name.

  The "empty" validation result typically means that the `CertStore` should update
  the list of certificates immediately. Before you do this, you should check whether
  the requested common name is what's you're expecting. To simplify this step, you can set 
  the list of expected common names in the `CertStoreConfiguration` and treat all others as untrusted.
    
  For all situations, the right response on this situation is to always cancel the ongoing
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

The `WultraSSLPinning/PowerAuthIntegration` cocoapod sub-spec provides a several additional classes which enhances the PowerAuth SDK functionality. The most important one is the `PowerAuthSslPinningValidationStrategy` class, which implements SSL pinning with using fingerprints, stored in the `CertStore`. You can simply instantiate this object from the existing `CertStore` and set it to the `PA2ClientConfiguration`. Then the class will provide SSL pinning for all communication initiated from the PowerAuth SDK.

For example, this is how the configuration sequence may looks like if you want to use both, `PowerAuthSDK` and `CertStore`, as singletons:

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
        let keychain = PA2KeychainConfiguration()
        keychain.identifier = ...
        
        // Configure PA2Client and assign validation strategy...
        let client = PA2ClientConfiguration()
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

### Why different domain for `serviceUrl`?

iOS is using TLS cache for all secure connections to the remote servers. The cache keeps already established connection alive for a while, to speedup the next HTTPS request (see [Apple's Technical Q&A](https://developer.apple.com/library/archive/qa/qa1727/_index.html) for more information). Unfortunately, you don't have the direct control on that cache, so you cannot close already established connection. That unfortunately, opens a small door for the attacker. Imagine this scenario:

1. The connection to get the remote list of fingerprints should not be protected with pinning. The list must be accessed for all costs, so protecting it with the pinning may cause the cert store to deadlock itself (or simply move it to the next level, where you need to update the fingerprint which must protect getting the new list of fingerprints)
2. You usually need to update the list of fingerprints at the application's startup, before everything else. 
3. Due to step 1., the attacker can trick your app to get the list of certificates with using his rogue CA. This will not allow him to insert a new entry to the list, but that's not the point.
4. If your API is on the same domain, then your app's connection will reuse the already established connection (opened in step 2. or 3.), via the MitM. And that's it.

Well, not everything's lost. If you're using `URLSession` (probably yes), then you can re-create a new `URLSession`, because it has its own TLS cache. But all this is not well documented, so that's why we recommend to put the list of fingerprints on the different domain, to avoid conflicts in the TLS cache at all.


### Can library provide more debug information?

Yes, you can change how much information is printed to the debug console:
```swift
WultraDebug.verboseLevel = .all
```

### Why dependency on PowerAuth2?

The library requires several cryptographic primitives, which are normally not available in iOS (like ECDSA). The `PowerAuth2` already provides this functions and most of our clients are already using PowerAuth2 framework in their applications. So, for our purposes it makes sense to glue both libraries together.

But not everything is lost. The core of the library is using `CryptoProvider` protocol and therefore is implementation independent. We'll provide the standalone version of the pinning library later. 

---

## License

All sources are licensed using Apache 2.0 license, you can use them with no restriction. If you are using this library, please let us know. We will be happy to share and promote your project.

## Contact

If you need any assistance, do not hesitate to drop us a line at hello@wultra.com or at our official [gitter.im/wultra](https://gitter.im/wultra) channel.

### Security Disclosure

If you believe you have identified a security vulnerability with WultraSSLPinning, you should report it as soon as possible via email to support@wultra.com. Please do not post it to a public issue tracker.
