# OARI EUDI Wallet

OARI EUDI Wallet is the native iOS holder wallet defined by the architecture in
`../eudi-wallet-achitecture`. It is separate from the enterprise services in
`../workspace` and consumes their published issuer, verifier, credential, status,
identity and trust contracts.

The product target is Swift 6.3, SwiftUI and iOS 17 or later. Certification and
production trust claims remain release gates. Development builds must not be
described as certified or legally recognised wallets.

## Historical foundation

M0-M8 are completed historical foundation commits covering the reproducible project,
domain contracts, encrypted vault, device-bound keys, profile/trust models, protocol
scaffolding, product UI, simulator harness and interoperability/security boundaries.
They are evidence of implemented foundations, not the production execution plan and
not a claim that SDK-backed issuance/presentation or release certification is done.

## Production execution

All future work is exactly four cohesive loops:

1. Loop A — SDK foundation.
2. Loop B — operational wallet.
3. Loop C — product and compatibility.
4. Loop D — release evidence.

See `docs/EVIDENCE.md` for evidence and `docs/IMPLEMENTATION-PLAN.md` for the
four-loop production execution plan. The current loop is SDK foundation; the
existing UI/protocol scaffolding is not a claim of SDK-backed production readiness.
