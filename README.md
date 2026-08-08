# Oari Wallet

Oari Wallet is a native SwiftUI iOS development wallet for EUDI and workspace-backed
EBSI/W3C interoperability testing. The app display name is **Oari Wallet**; the
technical target is `OariWallet`; the bundle identifier remains `io.oari.wallet`.

This repository is development/interoperability software. It is not a certification,
eIDAS legal-recognition or production-readiness claim.

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

## Backends

### EUDI Wallet Kit

The pinned EUDI Wallet Kit owns EUDI wallet documents, secure keys, storage, SD-JWT,
mdoc, OpenID4VCI, OpenID4VP, DCQL and BLE behavior. OARI owns consent, application
metadata, redacted audit, lifecycle UI and recovery coordination.

### Workspace W3C/EBSI backend

The development W3C backend speaks to the OARI workspace issuer/verifier services and
supports the explicitly enabled workspace profiles. W3C credentials and holder keys
remain backend-owned and encrypted locally. SpruceKit is not used by the app.

## Development mode

Debug/testing builds enable the open development interoperability profile by default.
Valid issuers and verifiers do not need to be in a trust list. The app shows a warning
and requires explicit Continue/Cancel consent.

Invalid signatures, malformed requests, expired/replayed messages and unsupported
profiles still fail closed.

Disable the development profile explicitly with:

```text
--disable-ebsi-development
```

To use the local OARI authority:

```text
--enable-local-ebsi-authority
```

The local development authority offer is:

```text
http://127.0.0.1:4080/openid/offer/dev-lpid-offer
```

The local authority must be reachable from the simulator/device and must be started
with the workspace development signer enabled. A physical device cannot reach a Mac's
`127.0.0.1`; use an HTTPS development hostname or an explicitly configured LAN/tunnel
endpoint instead.

## Supported development profile families

- EUDI mdoc and SD-JWT VC through Wallet Kit.
- W3C VCDM 1.1 JWT VC formats where the issuer metadata advertises them.
- OARI VCDM 2.0 `application/vc+jwt` profile.
- OpenID4VCI pre-authorized and authorization-code transaction models.
- OpenID4VP/DCQL consent and development trust warnings.
- Workspace final/draft interaction profiles where a counterpart fixture is enabled.

The app does not treat unknown formats as valid. Every enabled profile requires a
positive and negative interoperability fixture.

## Build and test

Use Swift Package tests for the fast loop:

```sh
swift test
git diff --check
```

Regenerate the Xcode project after changing `project.yml`:

```sh
xcodegen generate
```

Run the renamed unit target:

```sh
xcodebuild \
  -project OariWallet.xcodeproj \
  -scheme OariWallet \
  -configuration Debug \
  -skipMacroValidation \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  -only-testing:WalletTests/WalletAppModelTests test
```

Run boundary and secret checks:

```sh
python3 Scripts/verify_wallet_kit_boundaries.py
python3 Scripts/check_tracked_secrets.py
```

ReleaseTesting is run once per completed milestone with a reused DerivedData directory;
it is not run after every edit.

## Security and release gates

Development trust warnings do not replace cryptographic validation. Production needs
separate approved trust anchors, attestation, issuer/verifier profiles, provisioning,
physical-device Secure Enclave/biometric/camera/BLE testing, AASA verification,
penetration testing, legal review, signing and certification evidence.

See:

- `AGENTS.md` — iterator execution contract;
- `docs/IMPLEMENTATION-PLAN.md` — ordered delivery loops;
- `docs/ITERATOR-EBSI-W3C-PLAN.md` — consolidated EBSI/W3C development milestone;
- `docs/EBSI_PROFILE_MATRIX.md` — explicit W3C/EBSI profile matrix;
- `docs/EVIDENCE.md` — verification ledger and remaining gates;
- `docs/WALLET_KIT_REVIEW.md` — pinned SDK and ownership review.
