# OARI EUDI Wallet

OARI EUDI Wallet is the native iOS holder wallet defined by the architecture in
`../eudi-wallet-achitecture`. It is separate from the enterprise services in
`../workspace` and consumes their published issuer, verifier, credential, status,
identity and trust contracts.

The product target is Swift 6.3, SwiftUI and iOS 17 or later. Certification and
production trust claims remain release gates. Development builds must not be
described as certified or legally recognised wallets.

## Delivery milestones

1. Baseline: reproducible Xcode project, pinned toolchain/dependencies, CI,
   security and release assumptions.
2. Domain and vault: credential, profile, key and audit models with protected
   local persistence and lifecycle tests.
3. Trust: evidence-bearing trust verdicts, profile registry and negative tests.
4. Presentation: untrusted-input routing, OpenID4VP request handling, DCQL,
   consent, local authentication, replay protection and redacted history.
5. Issuance: OpenID4VCI offer handling, issuer review, proof binding, validation,
   deferred issuance and storage.
6. Product UI: OARI design system, credential vault, scanner, review, warning,
   history, settings and accessibility coverage.
7. Interoperability and release: pinned Wallet Kit adapter, selected EUDI/EBSI
   and iGrant fixtures, real-device evidence and human legal/security gates.

See `docs/EVIDENCE.md` for current acceptance and verification status.
