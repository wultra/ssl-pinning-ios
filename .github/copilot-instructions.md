# Copilot Instructions for WultraSSLPinning

## Project Overview

WultraSSLPinning is a Swift library implementing **dynamic SSL certificate pinning** for iOS/tvOS. Instead of bundling static certificate hashes, it downloads a signed list of certificate fingerprints from a remote server, validated using ECDSA-SHA-256 signatures. This solves the certificate expiration problem that plagues static pinning.

## Build and Test

Build (release, simulator SDK):

```bash
./Scripts/build.sh
```

Or directly with xcodebuild:

```bash
xcrun xcodebuild \
  -project WultraSSLPinning.xcodeproj \
  -scheme WultraSSLPinning \
  -configuration Release \
  -sdk iphonesimulator \
  build
```

Tests require a running [Mobile Utility Server](https://github.com/wultra/mobile-utility-server) and credentials passed as parameters:

```bash
./Scripts/test.sh -url <server_url> -appname <app> -urltopin <url> -login <admin> -password <pass>
```

These parameters are stored as GitHub Actions secrets. The test script auto-detects the latest iOS simulator.

To run a single test class or method via xcodebuild:

```bash
xcrun xcodebuild test \
  -project WultraSSLPinning.xcodeproj \
  -scheme WultraSSLPinningTests \
  -destination "platform=iOS Simulator,name=iPhone 16" \
  -only-testing:WultraSSLPinningTests/CertStoreTests_Basics/testSomething
```

## Architecture

### Core type: `CertStore`

`CertStore` is the main public class, split across multiple files using extensions:

- `CertStore.swift` — initialization, thread-safe cache access via `DispatchSemaphore`
- `CertStore+Storage.swift` — persistence (load/save cached fingerprints)
- `CertStore+Update.swift` — fetching fingerprint updates from the remote server
- `CertStore+Validation.swift` — certificate validation logic (by fingerprint, certificate data, or `URLAuthenticationChallenge`)

### Protocol-based dependency injection

The library uses protocol abstractions for its core dependencies, making them swappable for testing:

| Protocol | Default Implementation | Purpose |
|---|---|---|
| `CryptoProvider` | `CryptoKitCryptoProvider` | ECDSA signature validation, SHA-256 hashing |
| `SecureDataStore` | `KeychainSecureDataStore` | Persistent storage (iOS Keychain) |
| `RemoteDataProvider` | `RestAPI` | Network fetching of fingerprint lists |

Tests provide mock implementations (`TestingCryptoProvider`, `TestingSecureDataStore`, `TestingRemoteDataProvider`) in `Tests/Providers/`.

### Update scheduling

`UpdateScheduler` manages two modes:
- **Blocking mode** — first launch or expired fingerprints; the caller waits for the download
- **Silent mode** — background periodic updates controlled by `periodicUpdateInterval` and `expirationUpdateTreshold` in the configuration

### PowerAuth plugin (deprecated)

`Sources/WultraSSLPinning/Plugins/PowerAuth/` contains a legacy integration with [PowerAuth SDK](https://github.com/wultra/powerauth-mobile-sdk). This is deprecated since v1.8 — the README shows how to implement the integration manually instead.

## Key Conventions

- **Distribution**: Swift Package Manager (primary), CocoaPods (with subspecs `Lib` and `PowerAuthIntegration`), Carthage (experimental).
- **Thread safety**: `CertStore` uses a `DispatchSemaphore` for thread-safe access to cached data. All mutations go through `updateCachedData(updateClosure:)`.
- **Internal testing init**: `CertStore` has an `internal` initializer that accepts all dependencies directly (including `RemoteDataProvider`), used exclusively by tests.
- **Debug logging**: Controlled via `WultraDebug.verboseLevel` — keep it configurable but default to minimal output.
- **Minimum targets**: iOS 13.0+, tvOS 13.0+, Swift 5.9+.
- **CI runs on macOS 15** with Xcode version selected by `Scripts/xcodeselect.sh`.
