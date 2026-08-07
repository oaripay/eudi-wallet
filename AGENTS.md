# Agent execution rules

Read `docs/IMPLEMENTATION-PLAN.md`, `docs/ARCHITECTURE.md`,
`docs/WALLET_KIT_REVIEW.md` and `docs/EVIDENCE.md` before changing code.

## Ordered delivery loops

### 1. Complete EUDI/eIDAS app

- Use pinned `EudiWalletKit` as the sole EUDI backend.
- Do not reimplement OpenID4VCI, OpenID4VP, SD-JWT, mdoc, BLE, Wallet Kit
  storage, secure-area or holder-proof behavior.
- Finish the Wallet Kit PID presentation-during-issuance journey before EBSI work:
  pending issuance → `authorizePresentationUrl` → Wallet Kit OpenID4VP consent →
  response → pending issuance resume → second credential.
- Build all lifecycle UI with `OariDesignSystem`. EUDI reference UI is reference-only
  unless its exact code/assets and license are separately approved.
- Use real staging configuration for positive interoperability. Embedded issuer or
  verifier mocks are test-only and are not production evidence.

### 2. Add EBSI W3C support

- Start only after the EUDI loop passes review and is committed.
- Select a maintained EBSI/W3C backend before implementation; do not turn Wallet Kit
  or OARI into a general W3C cryptographic engine.
- Treat VCDM 1.1 and 2.0 as distinct profiles. For each profile pin representation,
  proof/cryptosuite, DID methods, schema/status rules, OpenID revision and EBSI
  environment/API version.
- Do not equate VCDM 2.0 with JSON-LD, `jwt_vc_json`, SD-JWT or successful JSON parsing.
- Each backend owns its raw credentials and private keys. OARI stores normalized
  display metadata, consent, lifecycle, trust evidence and redacted audit only.
- Validate real EBSI DIDR/TIR/TSR, schema, accreditation, status, holder binding,
  audience/domain/nonce/replay and issuer/verifier interoperability before claiming
  support.

## Scope controls

- Never mix both delivery loops in one milestone or commit.
- Do not add a generic credential/protocol abstraction until a second backend has
  been selected and its exact contract is known.
- Do not copy signed credentials or keys between backends or transform formats.
- Unsupported profiles fail explicitly.
- Never claim eIDAS/EBSI/W3C certification or production readiness from SDK or mock
  integration alone.

## Verification loop

Use after each coherent code batch:

```sh
swift test
git diff --check
```

Run Xcode simulator/ReleaseTesting once per complete milestone with a fixed
DerivedData directory. Physical iPhone Secure Enclave, biometrics, camera and BLE,
real staging interoperability, penetration testing, legal review, signing and
certification remain explicit release gates.
