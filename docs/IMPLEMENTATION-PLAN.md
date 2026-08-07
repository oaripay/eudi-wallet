# OARI Wallet implementation plan

This is the agent-readable execution plan. It supersedes the older seven-phase
micro-milestone list. Existing foundation work is complete; production work is
four cohesive loops, each ending in tests, one independent review, evidence and a
local commit.

## Non-negotiable boundaries

- Never push or publish changes.
- Use the exact Wallet Kit baseline recorded in the architecture:
  `v0.39.1`, commit `79005ab4bf0399238c1c9ebff9ee7d8a42c521f9`.
- Wallet Kit owns OpenID4VCI/VP, DCQL, SD-JWT, mdoc/BLE and document mechanics.
- OARI owns consent, trust policy, profiles, EBSI/enterprise policy, audit,
  redaction, application lifecycle and release evidence.
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

### Loop B — operational wallet

Implement as one operational slice:

- OpenID4VCI authorization-code and pre-authorized-code issuance.
- PKCE, `tx_code`, DPoP, proof JWT, signed metadata and attestation hooks.
- Deferred and batch issuance.
- OpenID4VP request/JAR, client-ID, DCQL, trust and response handling.
- JWT VC and SD-JWT issuance/presentation.
- mdoc, ISO 18013-5, QR engagement and BLE.
- Direct post and direct-post JWT delivery.
- Local authentication, consent, status and redacted audit integration.

Exit: deterministic local issuer/verifier fixtures complete JWT VC, SD-JWT and
mdoc journeys; malformed, expired, replayed, untrusted and unsupported cases fail.

### Loop C — product and compatibility

- Complete onboarding, credential review/detail/list/delete/reissue/deferred/status
  and notification UX.
- Complete presentation claim-selection and trust-warning UX.
- Implement WUA lifecycle against the selected provider.
- Configure production EBSI network, DID, accreditation and status services.
- Keep iGrant Draft 13/18 adapters and fixtures isolated from final OpenID paths.
- Use the EUDI UI repository only as a reference unless its exact license/reuse is
  approved; do not make it a runtime dependency.

Exit: all documented wallet lifecycle features have domain and UI journeys, and
unsupported profiles remain explicit failures.

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
Current loop: A — SDK foundation review
Current application commit before Loop A: 9348467
SDK integration: exact dependency and adapter foundation implemented; cycle-3 repairs under final review
Production readiness: blocked until loops A-D and external gates pass
```
