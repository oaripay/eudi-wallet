# Implementation evidence ledger

## Observable acceptance criteria

1. The repository produces a native Swift 6.3 SwiftUI iOS application from a
   reproducible project definition, with no signing required for simulator tests.
2. Domain code is isolated from UI, networking and SDKs through explicit ports.
3. Credentials and redacted audit events persist locally with iOS data protection;
   device-bound key records are purpose-specific and deletion removes associated
   material.
4. Every trust decision returns a verdict plus evidence. Invalid, expired,
   unregistered or unsupported-profile inputs fail closed in regulated strict mode.
5. OpenID4VP requests are treated as untrusted input. Parsing, transport checks,
   requester evaluation, DCQL selection, review, one-time warning consent where
   policy permits, local authentication, signing, delivery and redacted recording
   follow the architecture state machine.
6. OpenID4VCI supports reviewed offers, authorization-code and pre-authorized-code
   profiles, proof binding, credential validation, deferred issuance, notifications
   and atomic storage without permissive version fallback.
7. The app uses OARI semantic design tokens, supports dark and light themes,
   Dynamic Type, VoiceOver and reduced motion, and never represents trust by color
   alone.
8. Credential/profile support is explicit for final OpenID4VCI 1.0, final
   OpenID4VP 1.0, selected DCQL/VCDM/EUDI/EBSI profiles and an isolated iGrant
   Draft 13/Draft 18 compatibility profile. Unsupported combinations are reported.
9. Private credential values, tokens, proofs, nonces and authorization headers are
   absent from logs and audit history. Secret and static-analysis checks pass.
10. Focused unit tests, simulator tests, architecture checks and a final independent
    review pass for every committed milestone.
11. Production release remains blocked until a Member State, national trust and RP
    registration sources, certification path, production endpoints and human
    security/legal approvals are recorded and verified on physical devices.

## Authoritative verification commands

```sh
swift test
xcodebuild -project OARIWallet.xcodeproj -scheme OARIWallet \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
xcodebuild -project OARIWallet.xcodeproj -scheme OARIWallet \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test
git diff --check
git diff --cached --check
```

Milestones add focused commands here before they are committed. CI is authoritative
for clean-environment checks after it exists.

## Baseline failures

Recorded before implementation on 2026-08-07:

| Command | Result |
|---|---|
| `xcodebuild -list` | Failed: repository contained no Xcode project, workspace or Swift package. |
| `swift test` | Failed: repository contained no `Package.swift`. |

These are absence-of-implementation failures, not regressions.

## Architecture and enterprise inputs inspected

- Architecture README, phases, component/security designs, version/profile rules,
  risk register and key/storage/SDK ADRs.
- OARI web design-system style guide, dark/light tokens and accessibility rules.
- Enterprise OpenID issuer/holder/DCQL implementation.
- `provisionalOariLPID`, EBSI onboarding, OARI agent and other schema families.
- `did:key` P-256/JWK JCS behavior and EBSI registry-backed DID resolution.
- Current enterprise issuer metadata advertises ES256, `did:key`, JWT VC and SD-JWT
  behavior and mixes final/current and documented draft compatibility. Mobile support
  must therefore remain profile-isolated.

## Current profile record

| Layer | Initial target | Status |
|---|---|---|
| Toolchain | Xcode 26.5, Swift 6.3.2, iOS 17 minimum | Verified locally |
| OpenID4VCI | Final 1.0 plus isolated iGrant Draft 13 | Planned |
| OpenID4VP | Final 1.0 plus isolated iGrant Draft 18 | Planned |
| VCDM | W3C VCDM 2.0, concrete JWT VC per OARI profile | Planned |
| Wallet Kit | `eudi-lib-ios-wallet-kit` 0.16.4 evaluation candidate | Exact source revision and API review required before adapter milestone |
| OARI LPID | `provisionalOariLPID`, development only | Backend implemented with provisional status index |
| EBSI onboarding | `ebsiOnboardingCredential`, development only | Backend recipient proof bypass is a security blocker |
| Business user/admin | `OariBusinessWalletUserCredential` | Blocked: schema and issuance path missing |

## Milestone evidence

### Milestone 0: baseline

- Review cycle: 2
- Changed paths: `.github/workflows/verify.yml`, `.gitignore`, `README.md`,
  `project.yml`, `OARIWallet.xcodeproj/**`, `OARIWallet/**`, `OARIWalletTests/**`,
  `Scripts/check_tracked_secrets.py`, `docs/EVIDENCE.md`, `docs/THREAT_MODEL.md`,
  `docs/RELEASE_POLICY.md`.
- Checks:
  - `xcodegen generate && git diff --exit-code -- OARIWallet.xcodeproj && git diff --check`: pass.
  - `xcodebuild -project OARIWallet.xcodeproj -scheme OARIWallet -derivedDataPath <temp>/oari-m0-build -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build`: pass.
  - `xcodebuild -project OARIWallet.xcodeproj -scheme OARIWallet -derivedDataPath <temp>/oari-m0-test -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test`: pass, one test.
  - `python3 Scripts/check_tracked_secrets.py`: pass, 18 repository files inspected.
- Implementation check note: an initial build attempt declared Wallet Kit 0.16.4
  directly and concurrent Xcode package resolution collided in shared DerivedData.
  No adapter uses the SDK yet, so the premature dependency declaration was removed.
  Future Xcode checks use separate DerivedData paths, and SDK addition remains gated
  on an exact reviewed source revision.
- Review findings: cycle 1 found a major gap in the CI private-material scan and a
  minor stale evidence record. Both were fixed and focused checks passed. Cycle 2
  returned PASS with one non-gating ignore-list alignment nit, which was applied.
- Commit: this milestone commit; exact SHA is recorded in the session ledger after creation.

Session ledger commit: `ec32eefe40760713bbef870ba95223deb3cbf050`.

### Milestone 1: domain contracts

- Acceptance:
  1. Credential metadata separates format, profile, cryptographic validity, issuer
     trust, status, legal classification, subject identity and holder binding.
  2. Key records are purpose-bound and declare algorithm and assurance without
     exposing private key material.
  3. Audit events are redacted by construction and cannot contain credential values,
     proofs, tokens or nonces.
  4. Async repository, audit and key-provider ports have no UI, network or SDK
     dependency.
  5. Swift Package tests and the consuming iOS app tests pass.
- Review cycle: 2
- Changed paths: `Package.swift`, `Packages/Sources/WalletDomain/**`,
  `Packages/Tests/WalletDomainTests/**`, `project.yml`, `OARIWallet.xcodeproj/**`,
  `OARIWallet/WalletHomeView.swift`, `OARIWalletTests/WalletHomeModelTests.swift`,
  `.github/workflows/verify.yml`, `docs/EVIDENCE.md`.
- Checks:
  - `swift test`: pass, four domain tests.
  - First simulator test attempt: failed because the app test omitted an explicit
    `Foundation` import for `Date`; fixed before review.
  - Simulator test after fix: pass, two app tests.
  - `xcodegen generate`: pass; generated project includes the local package product.
  - `git diff --check`: pass.
  - `python3 Scripts/check_tracked_secrets.py`: pass, 25 repository files inspected.
- Review findings: cycle 1 found that free-form audit strings could carry sensitive
  values despite redacted field names. Audit counterparties and claim identifiers
  are now SHA-256 digests, policy/reason metadata uses closed types, and custom digest
  decoding rejects non-canonical input. Cycle 2 passed with a minor Unicode-number
  validation issue; validation is now restricted to ASCII lowercase hexadecimal and
  has a negative Unicode-numeral test.
- Commit: this milestone commit; exact SHA is recorded in the session ledger after creation.

## Release blockers and assumptions

- No target Member State, national wallet-provider scheme, conformity assessor,
  production LoTE/trust list, RP register or WRP certificate source is selected.
- No production certification or legal-recognition claim is permitted.
- No production secrets or demo trust anchors may be committed.
- Recovery defaults to reissuance. Device-bound keys and credential data do not use
  cloud backup.
- Money transmission and A2A execution remain enterprise responsibilities. The app
  may present credentials or produce separately reviewed action-bound authorization,
  but identity presentation alone never executes an irreversible transfer.
