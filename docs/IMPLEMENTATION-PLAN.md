# OARI Wallet implementation plan

This is the authoritative agent-readable execution plan. It supersedes the older
seven-phase micro-milestone list. SDK foundation is complete. Application delivery
is split into two strictly ordered implementation loops—first the complete EUDI
app, then EBSI/W3C support—followed by release evidence. Each loop ends in focused
tests, independent review, evidence and a local commit.

## Non-negotiable boundaries

- Never push or publish changes.
- Use the exact Wallet Kit baseline recorded in the architecture:
  `v0.39.1`, commit `79005ab4bf0399238c1c9ebff9ee7d8a42c521f9`.
- Wallet Kit owns OpenID4VCI/VP, DCQL, SD-JWT, mdoc/BLE and document mechanics.
- Wallet Kit is the sole EUDI credential backend. Do not reimplement its OpenID,
  SD-JWT, mdoc, BLE, storage, secure-area or holder-proof machinery.
- EBSI/W3C credentials use a separate selected backend. Never force unsupported
  W3C formats into Wallet Kit, transform signed credentials between backends, or
  duplicate backend-owned raw credentials/private keys.
- OARI owns routing, consent, trust/profile policy, normalized display metadata,
  audit, redaction, application lifecycle, recovery UX and release evidence.
- VCDM 1.1/2.0 are data-model versions, not synonyms for JSON-LD or JWT. Every W3C
  capability must name its representation, securing mechanism, DID methods,
  schema/status profile, OpenID revision and EBSI environment.
- Final OpenID profiles and iGrant Draft 13/18 behavior stay isolated.
- No certification, legal-recognition or verified iGrant claim without external
  evidence.

## Completed foundation

- M0-M5: baseline, domain contracts, encrypted vault, device keys, profiles/trust,
  presentation authorization state machine.
- M6: protocol-domain scaffolding and execution ports.
- M7: OARI UI, simulator harness, URL dispatch, camera/local-auth adapters.
- M8: interoperability boundaries, persistent replay, `did:key`, EBSI/status
  boundaries, fixtures and security evidence.

## Production loops

### Loop A — SDK foundation

1. Clone approved public SDKs into the approved vendor directory.
2. Pin Wallet Kit exactly and record its transitive package graph/licenses.
3. Add `EudiWalletKitAdapter` and compile `EudiWallet` with OARI trust/profile
   configuration.
4. Decide the single source of truth for raw document storage and document keys;
   do not duplicate Wallet Kit document bytes in the OARI vault.
5. Map Wallet Kit trust, storage, secure-area and error results to OARI ports.

Exit: SDK-backed adapter compiles, package/SBOM evidence is recorded, OARI tests
remain green, and no view imports Wallet Kit directly.

### Loop B — complete EUDI/eIDAS application

Use the pinned EUDI Wallet Kit as the complete EUDI backend and implement one
working product slice:

- OpenID4VCI authorization-code and pre-authorized-code issuance.
- PKCE, `tx_code`, DPoP, proof JWT, signed metadata and attestation hooks.
- Deferred and batch issuance.
- OpenID4VP request/JAR, client-ID, DCQL, trust and response handling.
- SD-JWT VC issuance/presentation through Wallet Kit. Legacy JWT VC is not a
  supported Wallet Kit format in the pinned baseline.
- mdoc, ISO 18013-5, QR engagement and BLE.
- Direct post and direct-post JWT delivery.
- Local authentication, consent, status and redacted audit integration.
- Wallet onboarding, home, credential list/detail/delete/reissue, issuance review,
  claim selection, presentation consent, pending/success/failure/recovery states,
  activity and settings UI using `OariDesignSystem`.
- Treat EUDI reference-app UI only as licensed design/reference material. Do not
  add it as a runtime dependency or copy assets/code without recorded approval.
- Implement Wallet Kit presentation during issuance exactly as documented:
  1. issue or load a PID in Wallet Kit;
  2. start OpenID4VCI for a second credential;
  3. detect the pending document and `authorizePresentationUrl`;
  4. begin Wallet Kit OpenID4VP;
  5. show verifier identity, requested PID claims and explicit consent;
  6. authenticate and send the Wallet Kit VP response;
  7. call Wallet Kit pending-issuance resume with the returned web URL;
  8. store/display the second credential and persist OARI metadata/status/audit.
- Production composition must use configured staging/production trust anchors,
  issuer/verifier origins, client ID, redirect URI and attestation provider. It may
  not silently ship with a nil wallet service or an embedded fake issuer.

Exit: the installed app completes the selected staging Wallet Kit PID-to-new-
credential presentation-during-issuance journey and all EUDI lifecycle UI states;
malformed, expired, replayed, untrusted and unsupported cases fail. Simulator tests
pass, and physical-device BLE/Secure Enclave evidence is recorded or explicitly
left as a release gate. Any local transport is test-only and is not staging proof.

### Loop C — EBSI W3C VCDM 1.1/2.0 support

Do not start this loop until Loop B is reviewed and committed. First freeze an
interoperability matrix from real EBSI issuer/verifier material. For every profile,
record VCDM version, representation, proof/cryptosuite, DID method, schema, status,
OpenID revision and network/API version.

- Select and review a maintained EBSI/W3C wallet SDK or service adapter before
  implementation. Prefer an on-device maintained SDK; if none passes a bake-off,
  use a service only for public DID/TIR/TSR/schema/status resolution while holder
  credentials and private keys remain on-device, or use an external wallet.
- Do not build custom JSON-LD canonicalization, Data Integrity/JAdES, generalized
  DID cryptography, or a second OpenID engine in OARI.
- Add a backend-neutral router only after the EBSI backend is selected. Every catalog
  entry stores `backendID`, exact profile/revision, VCDM version where applicable,
  representation/securing mechanism and an opaque backend document ID.
- Keep Wallet Kit responsible for EUDI mdoc/SD-JWT credentials and the EBSI backend
  responsible for its W3C raw credentials and keys.
- Implement the selected EBSI VCDM 1.1 profiles first. Add VCDM 2.0 only as separate
  named profiles demonstrated by actual EBSI counterpart fixtures; never infer 2.0
  from `jwt_vc_json`, JSON parsing success or an `@context` field.
- Validate `did:ebsi`/`did:key`, DID URL verification relationships and rotation,
  TIR accreditation/authorization, TSR schema integrity/dialect, holder binding,
  audience/domain/nonce/replay, and the selected EBSI status-list profile.
- Integrate issuance, presentation, deletion, restart/recovery and consent into the
  existing UI without converting credential formats or crossing backend key stores.
- Keep iGrant Draft 13/18 support isolated and enable it only for an explicitly named
  counterparty profile; it is never a generic EBSI fallback.

Exit: real selected EBSI issuer/verifier journeys pass for each explicitly supported
VCDM 1.1/2.0 profile, including DID/accreditation/schema/status and negative cases.
Both backends coexist in one catalog/consent UI, restart/delete/recovery pass, and
all unselected W3C representations or cryptosuites fail explicitly.

### Loop D — release evidence

- Full simulator/XCUITest matrix across supported devices and minimum iOS.
- Physical iPhone Secure Enclave, biometrics, camera, lock, mdoc and BLE evidence.
- Gitleaks, Semgrep, SBOM, dependency provenance and MASVS review.
- Privacy/DPIA, penetration test, incident/recovery and operational monitoring.
- Production signing, entitlements, associated domains and environment separation.
- EBSI interoperability evidence and certification/certification-gap report.

Exit: human legal/security/product approvals are recorded. Only then may a
production release claim be made.

## Required verification per loop

During implementation, use this fast loop after each coherent batch:

```sh
swift test
git diff --check
```

Do not run `xcodebuild` after every edit. Use one fixed DerivedData directory and
run the simulator/ReleaseTesting commands only after a batch is complete; this
avoids repeatedly rebuilding SwiftSyntax and reviewed macro dependencies. Run the
boundary, private-material, dependency and security scans at the same batch
checkpoint. Never run concurrent Xcode builds against the same DerivedData path.

```sh
swift test
xcodegen generate
xcodebuild -project OARIWallet.xcodeproj -scheme OARIWallet \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test
gitleaks detect --config .gitleaks.toml --redact --source .
gitleaks dir --config .gitleaks.toml --redact .
semgrep scan --config .semgrep.yml --error --no-git-ignore
syft dir:. --exclude './.build/**' -o spdx-json=sbom.spdx.json
git diff --check
```

## Current state

```text
Current loop: B — complete EUDI/eIDAS application
Current application commit after Loop A: 3f3850c
SDK integration: Loop A committed; exploratory local issuer fixtures removed
EBSI/W3C: Loop C blocked until an exact profile matrix and backend are selected
Production readiness: blocked until loops A-D and external gates pass
```
