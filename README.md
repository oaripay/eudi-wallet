# Oari Wallet

Oari Wallet is a native SwiftUI iOS development wallet for EUDI and
W3C interoperability testing. The app display name is **Oari
Wallet**, the technical target is `OariWallet`, and the bundle identifier is
`io.oari.wallet`.

This repository is development and interoperability software. It does not claim
certification, eIDAS legal recognition, or production readiness.

## Requirements

- macOS with Xcode 26 or a compatible toolchain supporting Swift 6.2 packages.
- iOS 17 or later.
- XcodeGen when regenerating the Xcode project.
- A physical iPhone for camera scanning and device-specific secure-key behavior.

The simulator supports development fixtures and paste-based wallet URLs, but its
camera scanner reports that camera scanning is unavailable.

## Repository layout

```text
App/                 SwiftUI application and app composition
Tests/               Unit and iOS integration tests
UITests/             UI automation
Packages/Sources/    Domain, Wallet Kit, W3C, vault and design-system modules
Packages/Tests/      Package-level tests
Scripts/             Boundary, secret and verification checks
OariWallet.xcodeproj Generated Xcode project
```

The adjacent `workspace/` project is a separate issuer, verifier, and portal
counterpart. Wallet changes must not modify it unless a task explicitly includes
the workspace.

## Backends

### EUDI Wallet Kit

The pinned EUDI Wallet Kit owns EUDI wallet documents, secure keys, storage,
SD-JWT, mdoc, OpenID4VCI, OpenID4VP, DCQL, and BLE behavior. Oari owns consent,
application metadata, redacted audit, lifecycle UI, and recovery coordination.

### Development W3C backend

The development W3C backend speaks to Oari issuer and verifier services through
explicitly enabled profiles. It owns W3C credentials and stores them encrypted
locally. SpruceKit is not used by the app.

The W3C backend uses one persistent canonical holder `did:key`. DPoP,
credential-response encryption, attestation, and EUDI Wallet Kit keys remain
separate because they have different protocol and lifecycle responsibilities.

## Supported development flows

- EUDI mdoc and SD-JWT VC issuance and presentation through Wallet Kit.
- W3C VCDM 1.1 JWT VC formats advertised by issuer metadata.
- W3C VCDM 2.0 `application/vc+jwt` credentials.
- Native `dc+sd-jwt` presentations with a trailing Key Binding JWT.
- OpenID4VCI pre-authorized-code and authorization-code grants.
- OpenID4VCI 1.1 Interactive Authorization using
  `authorization_challenge_endpoint` and `ia_post`.
- OpenID4VP and DCQL consent with query-ID-based `vp_token` responses.
- OpenID4VC final and selected draft interaction profiles where an
  interoperability fixture requires them.

For final Interactive Authorization, the initial challenge request carries
`issuer_state` but not `auth_session`. Follow-up requests carry the server-issued
`auth_session` and `openid4vp_response`. A successful challenge response is
accepted with the standard `authorization_code` property and does not require an
OAuth redirect `state` value.

Unknown formats do not fall through as valid. Every enabled profile should have
positive and negative interoperability coverage.

## Security model

- Issuer, request-object, credential, and presentation signatures are verified.
- Credentials and holder-key references are encrypted or protected by the
  system keychain as appropriate.
- App Lock supports Face ID, Touch ID, and device-passcode fallback.
- Credential deletion requires local authentication.
- Missing persistent holder keys fail closed instead of silently rotating the
  holder DID.
- Malformed, expired, replayed, or unsupported protocol messages fail closed.

Missing signer accreditation can produce an explicit user warning. It never
disables cryptographic credential verification.

## Development configuration

The W3C backend uses the same pinned production registry and interoperability
profile in every build configuration. HTTPS issuer paths ending in `draft-13`,
`draft-17`, or `draft-18` select the corresponding compatibility contract;
other issuers use the final contract.

Supported launch arguments:

```text
--fixture production|empty|populated|storage-failure
--incoming-url <wallet-url>
--disable-animations
```

## QR scanner

The scanner uses VisionKit's `DataScannerViewController` for QR recognition. The
camera and scanner mask are edge-to-edge, while interactive controls remain
inside the device safe area. A paste fallback is available when camera scanning
is unsupported or unavailable.

VisionKit owns the active camera session and does not expose supported torch
control. iOS also disables the Control Center flashlight while an application is
using the camera. Closing the scanner releases the camera and makes the system
flashlight available again.

## Build and test

Run the package test loop from the repository root:

```sh
swift test
git diff --check
```

Build the application for a simulator:

```sh
xcodebuild \
  -project OariWallet.xcodeproj \
  -scheme OariWallet \
  -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' \
  -configuration Debug \
  build CODE_SIGNING_ALLOWED=NO
```

Use an installed simulator name and OS version if `iPhone 17` with iOS 26.5 is
not available.

Run the application model tests:

```sh
xcodebuild \
  -project OariWallet.xcodeproj \
  -scheme OariWallet \
  -configuration Debug \
  -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' \
  -only-testing:WalletTests/WalletAppModelTests \
  test
```

Regenerate the project after changing `project.yml`:

```sh
xcodegen generate
```

Run boundary and secret checks:

```sh
python3 Scripts/verify_wallet_kit_boundaries.py
python3 Scripts/check_tracked_secrets.py
```

`ReleaseTesting` is run once per completed milestone with a reused DerivedData
directory rather than after every edit.

## Xcode troubleshooting

An interrupted or overlapping build can leave Xcode's `XCBuildData/build.db`
inconsistent, especially while compiling the `CopyablePlugin` package macro.
Typical messages include `unexpected incomplete target` or a malformed macro
plugin response.

First ensure no other build is running, then clean the project:

```sh
xcodebuild -project OariWallet.xcodeproj -scheme OariWallet clean
```

If Xcode still reports the stale operation, close Xcode, remove only this
project's `OariWallet-*` DerivedData directory, reopen the project, and build
again. Do not run multiple builds against the same DerivedData database.

## Known limitations

- `ia_post.jwt` encrypted Interactive Authorization responses are unsupported.
- Full browser-based OAuth authorization is not implemented by the W3C backend.
- Selected draft compatibility remains for development counterpart profiles.
- Full multi-query DCQL and every optional claim-set combination are not yet
  implemented.
- Native SD-JWT verifiers must validate nonce and audience in the trailing Key
  Binding JWT rather than treating the issuer JWT as an ordinary JWT VP.
- Development trust warnings are not a substitute for a production trust and
  accreditation policy.
