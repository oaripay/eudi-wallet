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

## Compact milestone map

The original architecture build loop and the initial delivery list are consolidated
into M0-M8. M0-M5 are completed implementation slices. M6 merges build-loop phases
3 and 4 (protocol engine); M7 maps to phase 5 (product UI); M8 maps to phases 6 and
7 (interoperability and release readiness). M6 is internally developed as 6a VP, 6b
VCI and 6c execution wiring, with one independent review and one final commit.

### M6: Protocol engine

- 6a OpenID4VP: untrusted input routing, request parsing, DCQL, replay and binding.
- 6b OpenID4VCI: offers, metadata, PKCE, proofs, validation, deferred issuance and
  notifications.
- 6c Execution: local-auth port, vault/key integration, delivery, audit and WUA.

### M7: Product UI

- OARI semantic design system, vault/scanner/review/warning/history/settings screens,
  app dependency wiring, themes and accessibility evidence.

#### M7 acceptance

1. Brand colors, spacing, radii, typography and motion are centralized in an
   `OariDesignSystem` SwiftUI product derived from the CSS source of truth.
2. Wallet, scanner, history and settings screens consume semantic tokens with dark
   and light themes and no color-only trust state.
3. App state loads credential metadata and redacted audit events through domain ports,
   never credential values, proofs, tokens or nonces.
4. Scanner input uses the M6 bounded classifier and cannot silently execute a request.
5. Dynamic Type, VoiceOver labels, reduced-motion token behavior and explicit
   development/not-certified copy are present.

- Review cycle: 2
- Changed paths: `Package.swift`, `project.yml`, `OARIWallet.xcodeproj/**`,
  `Packages/Sources/OariDesignSystem/**`, `OARIWallet/**`, `OARIWalletTests/**`,
  `docs/EVIDENCE.md`.
- Checks:
  - `xcodegen generate`: pass.
  - `swift test`: pass, 44 tests in 11 suites.
  - Simulator `xcodebuild ... test`: pass, three app-model tests after review fixes.
  - First final private-material scan found the scanner attempted to read tracked
    files deleted by this milestone. The scanner now skips deleted paths; rerun passed
    for 64 repository files.
- Review findings: cycle 1 found no concrete protected-repository composition/load,
  no scanner review/warning route, and a raw button foreground color. The app now
  composes encrypted credential/audit repositories, loads them with explicit failure
  state, links classified input to a non-executing Not verified review screen, and
  uses a semantic action-foreground token. Cycle 2 returned PASS with a non-gating
  stale simulator-test count, corrected above.
- Commit: `005f46f8689c4eed384616de85ea96ae8c5c70ca`.

### M8: Interoperability and release readiness

- DID/EBSI trust and status clients, reviewed Wallet Kit pin, iGrant fixtures, SBOM,
  SAST/privacy evidence, physical-device and certification matrix.

#### M8 acceptance

1. P-256 `did:key` is compatible with OARI multicodec behavior and fails closed for
   malformed/unsupported methods.
2. Replay claims persist encrypted across restart without storing plaintext nonces.
3. EBSI DID and credential-status clients enforce HTTPS/host/size/status boundaries
   and return evidence for trust policy evaluation; status tokens require a verifier.
4. iGrant Draft 13/18 behavior is isolated from final OpenID parsers and exercised by
   committed fixtures.
5. Secret scan, local SAST and SPDX SBOM commands run with recorded versions/results.
6. Wallet Kit, physical-device, Member-State, certification, production trust,
   privacy/legal and penetration-test gaps remain explicit blockers, never inferred
   as passed.

- Review cycle: 2
- Checks:
  - First `swift test` after persistent replay and `did:key`: pass, 47 tests in 13 suites.
  - `swift test` after EBSI/status and iGrant fixtures: pass, 51 tests in 15 suites.
  - `gitleaks 8.30.1`: pass, seven commits and approximately 220 KB scanned, no leaks.
  - First Semgrep run failed on an unquoted YAML pattern; fixed. `semgrep 1.172.0`
    then passed two local Swift rules over 40 source targets with zero findings.
  - First Syft run rejected an invalid exclusion pattern; fixed. `syft 1.50.0`
    generated `sbom.spdx.json` in SPDX 2.3 format.
  - Repository private-material scan: pass, 78 files at this checkpoint.
  - Direct execution of the TypeScript backend vector generator was unavailable
    because workspace `tsx` dependencies are not installed. A fixed P-256 generator
    vector independently confirms OARI `p256-pub` multicodec bytes and Base58BTC.
  - Final `swift test`: pass, 52 tests in 15 suites before the fixed-vector addition.
  - Simulator `xcodebuild ... test`: pass, three app-model tests.
  - `gitleaks dir`: pass, approximately 29.27 MB scanned, no leaks.
  - Final Semgrep: pass, two Swift rules and zero findings.
  - First final working-tree Gitleaks scan flagged two public `did:key` vectors. A
    narrow exact-vector allowlist was added; rerun passed with no leaks.
  - Final `swift test`: pass, 55 tests in 15 suites.
  - Final simulator `xcodebuild ... test`: pass, three app-model tests.
  - Final Gitleaks history and working-tree scans: pass, working tree approximately
    29.64 MB, no leaks.
  - Final Semgrep: pass, 41 Swift targets, two rules, zero findings.
  - Final repository private-material scan: pass, 81 files.
  - Syft 1.50.0 regenerated the committed SPDX 2.3 SBOM after final changes.
- Review findings: cycle 1 found off-curve/non-canonical `did:key` acceptance and
  redirect-following, post-buffer network limits. Derivation now validates the P-256
  point and canonical varint; negative tests cover both. EBSI/status clients now use
  a redirect-rejecting HTTPS transport that streams bytes and aborts at the cap,
  validates final origin, rejects userinfo, and invokes status verification only
  after a bounded successful response. CI pins scanner versions. Cycle 2 returned
  PASS with minor direct-transport test debt. Public `did:key` input is additionally
  length-bounded after review.
- Commit: this milestone commit; exact SHA is recorded in the session ledger after creation.
- Commit: pending.

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

- Review cycle: 4
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
- Commit: `ec32eefe40760713bbef870ba95223deb3cbf050`.

### Milestone 2: encrypted local vault

- Acceptance:
  1. Credential payload and metadata are AES-256-GCM encrypted at rest using a master
     key stored with `WhenUnlockedThisDeviceOnly` Keychain accessibility.
  2. Credential save, restart/read and deletion behavior is covered by tests.
  3. Ciphertext tampering fails closed and never returns a credential.
  4. Redacted audit events use the same protected encrypted-at-rest boundary and
     survive restart/deletion.
  5. Vault files use complete file protection, are excluded from backup and are
     written atomically.
- Review cycle: 3
- Changed paths: `Package.swift`, `Packages/Sources/WalletVault/**`,
  `Packages/Tests/WalletVaultTests/**`, `docs/EVIDENCE.md`.
- Checks:
  - First `swift test`: failed because a test-only URL helper was file-private to
    another test file; changed to module-internal.
  - `swift test` after all fixes: pass, 12 tests in 4 suites, including ciphertext
    substitution and locked-keychain error semantics.
  - `git diff --check`: pass.
  - `python3 Scripts/check_tracked_secrets.py`: pass, 32 repository files inspected.
  - Simulator `xcodebuild ... test`: pass, two app tests.
- Review findings: cycle 1 found that valid AES-GCM ciphertext could be substituted
  between credential files. Credential encryption now authenticates a versioned
  domain marker and credential ID as AAD, verifies decoded ID equality, and includes
  a substitution test. Audit ciphertext has a separate versioned AAD domain. Cycle 2
  returned PASS. Cycle 3 also returned PASS after the keychain error-semantics work.
  A non-gating stale test-count nit was corrected. Keychain duplicate
  creation races now reload the winning key, and keychain access failures remain
  distinguishable from corrupt ciphertext.
- Commit: `6348ccf24289050b9a732c9efb9496969c18ecf4`.

### Milestone 3: device-bound signing keys

- Acceptance:
  1. ES256 private keys are generated in Keychain, with explicit required/preferred
     Secure Enclave or lower-assurance software policy and no silent policy change.
  2. Secure Enclave keys use private-key-only operations and user-presence access
     controls when requested; software keys are explicitly labelled lower assurance.
  3. Signing supports profile-appropriate JOSE raw and X9.62 DER forms, while only
     public key material can be exported.
  4. Key deletion makes subsequent signing fail with key-not-found.
  5. Focused cryptographic lifecycle and malformed-signature tests pass.
- Review cycle: 2
- Changed paths: `Packages/Sources/WalletDomain/KeyModels.swift`,
  `Packages/Sources/WalletDomain/WalletPorts.swift`,
  `Packages/Sources/WalletVault/DeviceBoundKeyProvider.swift`,
  `Packages/Tests/WalletVaultTests/DeviceBoundKeyProviderTests.swift`,
  `docs/EVIDENCE.md`.
- Checks:
  - First `swift test`: failed because macOS command-line Keychain creation cannot
    use the access-control form without an application entitlement. Software keys
    that do not request user presence now use the equivalent
    `WhenUnlockedThisDeviceOnly` accessibility attribute directly; protected and
    Secure Enclave keys retain access-control flags.
  - Focused key-provider tests after strict-DER fix: pass, three tests.
  - Full `swift test` after strict-DER fix: pass, 15 tests in 5 suites.
  - Simulator `xcodebuild ... test`: pass, two app tests.
  - `git diff --check`: pass.
  - `python3 Scripts/check_tracked_secrets.py`: pass, 34 repository files inspected.
- Review findings: cycle 1 found that the DER converter did not enforce its outer
  sequence boundary or canonical positive INTEGER/length encodings. Strict boundary,
  minimal-length, positivity and coordinate-size checks plus negative and positive
  vectors were added. Cycle 2 returned PASS with a non-gating stale focused-test
  count nit, which is corrected above.
- Commit: `59275eac9a7ab64ed5248e16c45fcadc218436d7`.

### Milestone 4: explicit profiles and trust policy

- Acceptance:
  1. Final OpenID 1.0/OARI development behavior and iGrant Draft 13/18 behavior are
     separate immutable profiles with versions, source URLs, formats, identifiers,
     algorithms, key policy, trust sources and retirement rules.
  2. Unknown profiles and unsupported format/identifier/algorithm combinations fail
     explicitly with no permissive fallback.
  3. Trust uses evidence-bearing `trusted`, `untrusted`, `invalid` and
     `indeterminate` verdicts, never a Boolean.
  4. A trusted verdict requires fresh valid evidence for every profile-required
     source; missing or stale evidence becomes indeterminate and rejects.
  5. Strict and invalid states always reject. Permitted one-time consent preserves
     the untrusted verdict and never upgrades it to trusted.
- Review cycle: 2
- Changed paths: `Package.swift`, `Packages/Sources/ProfileDomain/**`,
  `Packages/Sources/TrustDomain/**`, `Packages/Tests/ProfileDomainTests/**`,
  `Packages/Tests/TrustDomainTests/**`, `docs/EVIDENCE.md`.
- Checks:
  - First `swift test`: failed on a shadowed initializer parameter in
    `StaticProfileRegistry`; fixed with explicit property assignment.
  - `swift test` after trust fixes: pass, 24 tests in 7 suites.
  - Simulator `xcodebuild ... test`: pass, two app tests.
  - `git diff --check`: pass.
  - `python3 Scripts/check_tracked_secrets.py`: pass, 41 repository files inspected.
- Review findings: cycle 1 found final-document URLs on the draft profile,
  contradictory evidence acceptance and no profile-owned maximum evidence age.
  Draft 13/18 now use revision-specific archived URLs; profiles define source-specific
  maximum age and validity; invalid/not-found/unavailable conflicts and malformed or
  stale timestamps fail closed with negative tests. Cycle 2 returned PASS with a
  non-gating stale evidence-ledger count, corrected above.
- Commit: this milestone commit; exact SHA is recorded in the session ledger after creation.

### Milestone 5: presentation authorization state machine

- Acceptance:
  1. Presentation follows received, parsed, transport-validated, requester-evaluated,
     candidate-evaluated, review, optional warning consent, authenticated, signed,
     delivered and recorded ordering.
  2. Signing is impossible before transaction review and local authentication.
  3. Warning continuation requires explicit one-time consent and preserves the
     existing untrusted trust decision.
  4. Rejected requesters and empty credential selection terminate fail closed.
  5. Terminal sessions cannot be resumed through normal transitions.
- Review cycle: 2
- Changed paths: `Package.swift`, `Packages/Sources/PresentationDomain/**`,
  `Packages/Tests/PresentationDomainTests/**`, `docs/EVIDENCE.md`.
- Checks:
  - `swift test` after trust-decision invariant fixes: pass, 29 tests in 8 suites.
  - Remaining milestone checks: pending.
- Review findings: cycle 1 found that a caller could pair an untrusted, invalid or
  indeterminate verdict with an allow action. Trust-decision construction is now
  package-scoped, its verdict/action invariant is explicit, and the presentation
  boundary defensively rejects inconsistent decisions. Negative and terminal-state
  tests were added. Cycle 2 returned PASS; this previously uncommitted slice is
  included in the compact M6 commit.
- Commit: included in M6.

### Milestone 6: compact protocol engine

- Acceptance:
  1. Bounded untrusted URL input routes only supported VP/VCI schemes and configured
     HTTPS hosts; malformed, oversized and unsupported input fails before I/O.
  2. VP requests require HTTPS response binding, nonce, requester identity and an
     explicit DCQL or presentation-definition query; nonce replay is rejected.
  3. VCI offers support authorization-code and pre-authorized-code grants; issuer and
     configuration metadata must match; PKCE uses RFC 7636 S256.
  4. Authentication precedes signing, signing precedes HTTPS delivery, and successful
     delivery precedes redacted audit recording through the M5 state machine.
  5. Issued credentials are validated before repository storage; empty or malformed
     responses fail closed and deferred issuance is explicit.
- Internal slices: 6a VP, 6b VCI, 6c execution wiring.
- Review cycle: 2
- Changed paths: `Package.swift`, `README.md`, `Packages/Sources/PresentationDomain/**`,
  `Packages/Sources/ProtocolEngine/**`, `Packages/Sources/TrustDomain/TrustModels.swift`,
  `Packages/Tests/PresentationDomainTests/**`, `Packages/Tests/ProtocolEngineTests/**`,
  `docs/EVIDENCE.md`.
- Checks:
  - M6a focused tests: pass, three tests.
  - M6a-M6b full `swift test`: pass, 36 tests in 10 suites.
  - M6a-M6c full `swift test`: pass, 39 tests in 11 suites.
  - After cycle-1 security fixes: pass, 42 tests in 11 suites.
  - After cycle-2 expiry and canonical-URL fixes: pass, 44 tests in 11 suites.
  - Final post-review `swift test`: pass, 44 tests in 11 suites.
  - Simulator `xcodebuild ... test`: pass, two app tests.
  - `git diff --check`: pass.
  - `python3 Scripts/check_tracked_secrets.py`: pass, 56 repository files inspected.
- Review findings: cycle 1 found permissive HTTPS routing, optional partial origin
  binding and disconnected replay, missing pre-authorized code/PKCE flow binding,
  and request/session substitution. HTTPS now requires a configured allowlist and
  canonical host; intake requires full registered origin and claims nonce; VCI keeps
  the sensitive pre-authorized code and binds S256/state at exchange; execution
  checks the exact reviewed request before authentication. Cycle 2 found that expiry
  was not rebound/rechecked and VCI accepted hostless HTTPS URLs. Expiry is now part
  of the reviewed session and checked before authentication; all offer and metadata
  endpoints require canonical absolute HTTPS URLs. Cycle 3 found execution expiry
  still depended on a caller-supplied timestamp. The coordinator now owns an injected
  trusted clock; no caller timestamp can influence authorization, and the expiry test
  proves authentication is not invoked. Cycle 4 returned PASS with a non-gating
  timing nit; expiry is now rechecked before signing and delivery as well.
- Commit: this milestone commit; exact SHA is recorded in the session ledger after creation.

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
- Commit: `0c6b8e43a18ba027442356f4dbae2870c9658f47`.

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
