# Implementation evidence ledger

## Observable acceptance criteria

1. The repository produces a native Swift 6.3 SwiftUI iOS application from a
   reproducible project definition, with no signing required for simulator tests.
2. Domain code is isolated from UI, networking and SDKs through explicit ports.
3. Wallet Kit owns raw credential documents and document-bound keys. OARI metadata
   and redacted audit events persist locally with iOS data protection; OARI
   device-bound key records are purpose-specific and deletion removes associated
   OARI material.
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

The original architecture build loop and initial delivery list are consolidated into
four production loops described in `docs/IMPLEMENTATION-PLAN.md`: A SDK foundation,
B operational wallet, C product/compatibility, and D release evidence. Existing M0-M8
commits are historical foundation evidence, not additional future loops. Each A-D
loop receives one independent review and one final local commit.

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

- Review cycle: 3
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
- Commit: `afb77756e71359093552c7be524010af52281f76`.

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
| EBSI VCDM 1.1 | Exact representation/proof/DID/schema/status profile not yet frozen | Blocked pending real EBSI profile matrix and backend selection |
| EBSI VCDM 2.0 | Separate named profiles only; must not be inferred from `jwt_vc_json` or JSON parsing | Blocked pending demonstrated issuer/verifier support |
| Wallet Kit | `eudi-lib-ios-wallet-kit` v0.39.1, commit `79005ab4bf0399238c1c9ebff9ee7d8a42c521f9` | Exact package resolved; adapter foundation under Loop A review |
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
- Implementation check note: an earlier build attempt declared Wallet Kit 0.16.4
  directly and concurrent Xcode package resolution collided in shared DerivedData.
  No adapter uses the SDK yet; the selected v0.39.1 baseline is recorded and SDK
  acquisition/package resolution is now Loop A.
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

### Loop A — SDK foundation

- Acceptance:
  1. Approved Wallet Kit tag/commit and Apache license/notice are verified.
  2. The application uses an exact package version and commits all resolved revisions.
  3. Only `EudiWalletKitAdapter` imports Wallet Kit; configuration defaults to user
     authentication, strict trust, signed metadata/WRPRC validation and no file log.
  4. Wallet Kit constructs behind the adapter only with explicit profile-bound,
     digest-pinned CA trust anchors and
     exposes OARI-neutral document summaries.
  5. Storage ownership and security no-go findings are documented before operational
     flows begin.
- Review cycle: 4
- Checks:
  - Vendor tag/SHA verification: pass.
  - Initial manifest resolution failed because `dependencies` preceded `products`;
    manifest order fixed.
  - Exact package resolution: pass, 24 locked revisions.
  - First trust-source implementation selected the unavailable optional ETSI path;
    compiler evidence led to the supported `SecTrust`/`rootIaca` mapping.
  - Focused adapter tests after cycle-2 fixes: pass, nine tests.
  - Full package suite after cycle-3 fixes: pass, 63 tests in 17 suites.
  - First Xcode build stopped for pinned `CopyablePlugin` macro approval; automated
    commands now use `-skipMacroValidation` only with the reviewed lockfile.
  - First iOS adapter compile exposed the optional ETSI trust initializer while
    macOS exposes `rootIaca`; conditional platform mapping now compiles both paths.
  - iPhone 17 Pro Debug build: pass with the exact SDK graph.
  - Final iPhone 17 Pro Debug app tests: pass, seven XCTest tests plus Swift Testing.
  - Final ReleaseTesting Wallet Kit iOS operation probe: pass.
  - Generic Release simulator build: pass.
  - First working-tree Gitleaks run scanned ignored `.build` package fixtures and
    reported upstream values; `.build/` alone is now excluded and the application
    working-tree scan passes.
  - Final Semgrep: pass, 46 application/adapter Swift targets, zero findings.
  - Syft SBOM: regenerated, 26 packages including ten EUDI components.
  - Statium license review: both malformed conflict sides and README identify
    Apache-2.0; legal source-hygiene confirmation remains a release gate.
  - Sensitive SDK Debug logging: operational adapter methods now fail in Debug and
    a regression test enforces the gate.
- Review findings: cycle 2 found that DER parsing alone allowed a syntactically valid
  leaf or unapproved CA to become an anchor, and that production app composition
  still selected the historical raw-byte credential vault. Trust sources are now
  profile-bound and digest-pinned, validate CA constraints, signing usage and dates,
  and reject valid leaf/unapproved anchors. Production composition now uses an
  encrypted metadata-only repository; a CI architecture check enforces both the sole
  SDK import and raw-document ownership boundary.
  Cycle 3 found that the historical raw-byte envelope/repository and validator still
  compiled in production modules despite not being composed by the app. Those APIs,
  storage implementation and tests are removed. Protocol issuance now accepts only
  Wallet Kit-validated `CredentialRecord` metadata and rebinds it to the reviewed
  issuer/configuration/profile before metadata persistence. The boundary verifier now
  rejects raw credential symbols across every production Swift source. Cycle-4 review
  returned PASS. It noted non-gating direct test debt for certificate validity and
  key-usage branches. A stale release-readiness row was corrected after review.
- Commit: `3f3850c1fee06d45d57c599744ab8a23c4d4d603`.

### Loop B — complete EUDI/eIDAS application

#### EUDI issuance and presentation UI milestone

- Added an app-specific `EudiWalletOperating` service boundary and live adapter
  implementation; Wallet Kit presentation results and redirect URLs remain inside the
  service while the model receives bounded completion states.
- Added explicit scanner resolution, issuance review/selection/transaction-code,
  ordinary VP claim consent, pending PID presentation, resumed issuance, working,
  configuration-required, success, redacted failure and recovery states using
  `OariDesignSystem` and native SwiftUI controls.
- Pending PID decline and transient failure preserve the pending credential. Consent
  sheets require explicit approve/decline, and a persistent scanner card restores a
  dismissed pending credential.
- Independent review cycle 3 returned `PASS` with no BLOCKER/MAJOR findings.
- Verification: full package tests pass 71 tests in 18 suites; Debug
  `WalletAppModelTests` pass 11 tests with warnings-as-errors app compilation. One
  transient simulator `No such process` launch was recorded separately; a subsequent
  complete test run passed.
- Commit: `9c20041` (`feat: add eudi wallet journeys`), including the explicitly
  approved AppIcon composition adjustment.

#### Credential lifecycle UI milestone

- Added accessible credential detail/status/trust/legal/date presentation using
  metadata and Wallet Kit document summaries only.
- Added destructive-confirmed Wallet Kit deletion with working/result acknowledgement,
  duplicate-action prevention and metadata/summary refresh.
- Added deferred issuance retry with exact issuer/document delegation and distinct
  issued versus still-deferred outcomes.
- Independent review cycle 2 returned `PASS`; Debug model tests pass 13 cases with
  warnings-as-errors app compilation. A still-deferred regression assertion was added
  after review to cover the remaining MINOR branch.
- Commit: `4316525` (`feat: add credential lifecycle ui`).

#### Onboarding and profile visibility milestone

- Added non-dismissible first-run onboarding covering consent, Wallet Kit ownership,
  device-bound keys and the requirement for approved operational profiles.
- Added settings/profile status, callback-domain/backend visibility and explicit
  development/not-certified messaging. Lifecycle controls are disabled with an
  accessible explanation whenever no approved EUDI service is active.
- Independent review cycle 2 returned `PASS`; Debug model tests pass 14 cases,
  including persisted onboarding and inconsistent service/profile fail-closed checks.
- Accessibility automation follow-up review cycle 2 returned `PASS`. Focused UI tests
  pass for disabled credential actions with an accessible explanation and for profile
  guidance in Scanner/Settings. All Wallet Kit entry points share the same operational
  availability predicate; inconsistent service-plus-disabled-profile tests invoke no
  service operation.

#### Presentation-during-issuance adapter milestone

- Acceptance: expose Wallet Kit pending issuance only through neutral handles; bind
  one pending transaction to its Wallet Kit OpenID4VP session/result; validate
  issuer/verifier origins; resume only accepted matching presentations through
  `EudiWallet.resumePendingIssuance`; preserve repeated pending results; update OARI
  metadata and durable audit/recovery without exporting raw documents or keys.
- Review cycle: 4 of 4, final verdict `FAIL` before the final replacement-ID crash
  fix. Cycles found and repaired public protocol-URL leakage, incorrect origin/audit
  ordering, non-issued completion audit, missing repeated-pending URL handling and
  replacement-handle drift.
- Post-cycle-4 repair: pre-metadata recovery now retains both original and replacement
  Wallet Kit document references when IDs differ, and reconciliation deletes both
  plus mapped metadata on rollback. The same neutral handle is retained for a valid
  replacement pending document. This repair is verified locally but cannot receive
  another review within the milestone's four-cycle limit.
- Changed paths: `Packages/Sources/EudiWalletKitAdapter/EudiWalletKitAdapter.swift`,
  `Packages/Sources/WalletDomain/WalletPorts.swift`,
  `Packages/Tests/EudiWalletKitAdapterTests/EudiWalletKitAdapterTests.swift`,
  `Packages/Tests/WalletVaultTests/EncryptedWalletOperationRecoveryStoreTests.swift`.
- Verification: `swift test` passes 71 tests in 18 suites; focused adapter passes 14
  tests; focused encrypted recovery passes 3 tests; `git diff --check`, Wallet Kit
  boundary verification and private-material scan pass.
- Baseline failures: none for package tests. Real staging PID presentation-during-
  issuance remains unavailable because no staging issuer/verifier/trust configuration
  has been supplied.
- Initial pending-issuance review was blocked after four cycles; the repair was then
  covered by an authorized narrow follow-up and consolidated-foundation review.
- Universal-link callback follow-up: `project.yml` and all three generated OARIWallet
  Debug/Release/ReleaseTesting configurations set
  `CODE_SIGN_ENTITLEMENTS = OARIWallet/OARIWallet.entitlements`; the file declares
  `applinks:oari.io`, matching the ReleaseTesting callback origin
  `https://oari.io/oauth/callback`. The incremental ReleaseTesting simulator integration
  command passed. Simulator ad-hoc signing produced an empty effective entitlement
  dictionary, so this is not device evidence: provisioning, hosted AASA verification,
  a signed physical-device build and universal-link callback behavior remain explicit
  external gates.
- Consolidated review cycle 4 found the ReleaseTesting callback used the
  `wallet.dev.oari.io` subdomain while the checked-in entitlement declared
  `applinks:oari.io`. The callback and allowed application redirect origin now use
  `https://oari.io/oauth/callback`, matching the entitlement.
- Authorized callback-alignment follow-up review cycle 1 returned `PASS`. A fresh
  post-repair incremental ReleaseTesting `WalletKitIOSIntegrationTests` run also
  completed with `TEST SUCCEEDED`. Final diff/staging/secrets inspection passed and
  the consolidated EUDI operational foundation was committed as `20361eb` (`feat:
  add eudi operational wallet`). Physical
  AASA/provisioning/universal-link behavior remains an external release gate.

- Acceptance:
  1. OpenID4VCI authorization-code and pre-authorized-code offers execute only for
     configured issuer hosts with PAR, PKCE/DPoP, proof binding, signed metadata,
     WRPRC validation, transaction-code rules and attestation hooks enabled.
  2. Batch and deferred issuance remain Wallet Kit-owned and expose only neutral
     summaries and stable document references to OARI metadata storage.
  3. OpenID4VP request/JAR and DCQL processing execute only for configured verifier
     hosts; requester evidence, requested claims, warnings and consent are exposed
     without exposing SDK types.
  4. Required claims cannot be deselected, rejection cannot disclose claims, and
     successful direct-post/direct-post-JWT delivery is recorded in redacted audit.
  5. mdoc QR engagement and BLE use the same one-time bounded presentation session,
     selection, authentication, trust and audit boundary.
  6. Operational state is bounded and expiring, unapproved network destinations and
     redirects fail closed, and every operational method remains blocked in Debug.
   7. ReleaseTesting must exercise the selected staging SDK-backed issuance and
      presentation journeys for SD-JWT and mdoc; malformed, expired, replayed,
      untrusted and unsupported cases must fail closed.
- Review cycle: 3
- Current checks:
  - Baseline `swift test`: pass, 66 tests in 17 suites.
  - After durable recovery and audit-outbox work, `swift test`: pass, 68 tests
    in 18 suites before final focused test additions.
  - Focused adapter tests: pass, 12 tests.
  - ReleaseTesting iOS operational probe: pass; Wallet Kit storage, malformed-input
    rejection and injected transport routing execute without external network.
  - Wallet Kit boundary, executable dependency and private-material checks: pass.
- Current implementation:
  - Strict VCI configuration, neutral offer/issuance/deferred models, transaction-code
    validation, attestation hooks, bounded one-time offer/session state and redacted
    issuance/presentation audit are implemented behind the adapter.
  - OpenID4VP/DCQL claim review, required-claim selection, direct response submission,
    mdoc BLE QR engagement and deferred retry are exposed as neutral adapter methods.
  - Issuer/verifier host allowlists, injected transport, redirect rejection and Debug
    operational containment are enforced.
- Review findings: cycle 1 found caller-controlled authorization redirects, a shared
  issuer/verifier host union, accepted 3xx responses, host-only rather than canonical
  origin policy, missing metadata/status lifecycle mapping, and incomplete end-to-end
  fixtures. The redirect override is removed; the configured app redirect is now the
  sole VCI callback. Task-local flow scope separates issuer and verifier network
  origins, canonical HTTPS origins preserve explicit non-default ports, and both
  injected and URLSession transports reject 3xx. Metadata now stores stable Wallet Kit
  document IDs, supports atomic replacement, rolls back issuance on mapping failure,
  updates deferred completion, deletes with the SDK document, and obtains status via
  an OARI status-provider port. Full positive/negative protocol fixtures remain open.
  Cycle 2 found ignored rollback failures and insufficient restart evidence. An
  encrypted recovery journal now records issuance, deferred issuance and deletion
  intent before crossing the Wallet Kit/OARI storage boundary, reconciles on restart,
  and retains failed work for retry; encrypted restart/tamper tests and a reconstructed
  metadata-replacement test pass. Cycle 3 found a delete-all bypass, concurrent
  baseline rollback risk, inline unverified JAR acceptance, unvalidated success
  redirects, and no durable post-delivery audit. Lifecycle mutations are now
  serialized, delete-all is journaled, inline JARs require the allowlisted request-URI
  path, success redirects require an allowlisted HTTPS verifier origin, and a redacted
  idempotent audit outbox is persisted before delivery. Complete SDK-backed fixtures
  remain the gating cycle-3 finding.
- Cleanup: the exploratory deterministic issuer/verifier target and duplicate iOS
  fixture test were removed. They were useful for diagnosing Wallet Kit boundaries
  but were not production infrastructure and could not prove EBSI or certification
  interoperability. The remaining 69 package tests in 18 suites cover the retained
  OARI policy, trust, storage, recovery, audit and Wallet Kit adapter boundaries.
- Current blocker: a real staging issuer/verifier is required to prove the Wallet Kit
  PID-to-new-credential presentation-during-issuance journey. No local mock is now
  counted as AC-B7 or as positive end-to-end evidence.
- Baseline/verification interruption: the focused ReleaseTesting Xcode test was
  interrupted by the command timeout at 120 seconds and again at 600 seconds while
  rebuilding transitive `swift-syntax`; neither run reached compilation of changed
  application sources or test execution and neither is recorded as a product failure.
- The prior incremental ReleaseTesting result remains evidence only for the retained
  malformed-input, redirect, storage, recovery and audit probes; references to the
  removed deterministic issuance fixture are no longer acceptance evidence.
- Remaining before exit: complete deterministic signed VCI/VP SD-JWT and mdoc
  journeys, stable Wallet Kit-document-to-OARI-metadata lifecycle mapping, status
  integration, full negative fixtures, independent review and final verification.
- Commit: pending.

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

### R1 production harness iteration

- Acceptance:
  1. Installed-app tests launch deterministic empty, populated and storage-failure
     states without production Keychain or network dependencies.
  2. XCUITest covers core tabs, credential/history rendering, scanner rejection,
     non-executing review and incoming URL routing.
  3. OpenID4VP and OpenID4VCI URL schemes route through the bounded classifier.
  4. Inactive/background lifecycle state obscures wallet content.
  5. Accessibility identifiers provide stable automation selectors.
- Review cycle: 2
- Checks:
  - First app build found a missing explicit `return` in fixture composition; fixed.
  - First UI compile found Swift 6 main-actor isolation requirements; test class now
    runs on `MainActor`.
  - First simulator launch encountered a CoreSimulator service crash before app
    launch; explicit named-device boot and retry succeeded.
  - Initial UI assertions used child text hidden by combined accessibility elements;
    stable semantic identifiers replaced element-type-dependent queries.
  - `swift test`: pass, 55 tests in 15 suites.
  - Hosted app model tests: pass, five tests.
  - XCUITest on booted iPhone 17 Pro: pass, five installed-app journeys.
  - Debug simulator builds: pass on iPhone 17e and iPad mini.
  - Release simulator build: pass; fixture parsing/repositories compile only in Debug.
  - Private-material scan and `git diff --check`: pass at pre-review checkpoint.
- Review findings: cycle 1 found incoming-URL UI tests used Debug launch injection
  rather than OS URL dispatch, and Release was not CI-enforced. XCUITest now opens
  both registered VP and VCI schemes through `XCUIApplication.open`; CI adds a
  generic Release simulator build. Both OS-dispatch tests pass on the booted iPhone
  17 Pro; the suite now contains six installed-app journeys. Cycle 2 returned PASS
  with one non-gating naming nit for the separate Debug-injected review fixture.
- Commit: `53a67fe`.

### R2 native device interaction iteration

- Acceptance:
  1. Production local authentication uses `deviceOwnerAuthentication`, requires a
     nonempty transaction-specific reason, and fails closed on denial/unavailability.
  2. Camera QR scanning uses the system VisionKit scanner and sends decoded text
     through the same bounded classifier as pasted/deep-link input.
  3. Simulator UI exposes a clear camera-unavailable fallback without weakening
     production camera behavior.
  4. Scanner delivery is one-shot per presented scanner session.
- Review cycle: 1
- Checks:
  - Focused local-auth tests: pass, three tests.
  - Full `swift test`: pass, 58 tests in 16 suites.
  - iPhone 17 Pro app build: pass under Swift 6 strict concurrency.
  - Simulator camera-fallback XCUITest: pass.
  - Camera and pasted-code model route test: included in hosted app suite.
  - Release simulator build: pass after composing the production authenticator.
  - Gitleaks and Semgrep: pass, zero findings.
- Review findings: cycle 1 returned PASS with one Release API hardening issue. The
  injectable authentication evaluator initializer is now internal and available to
  package tests only; production clients can construct only the system evaluator.
- Commit: this milestone commit; exact SHA is recorded in the session ledger after creation.
