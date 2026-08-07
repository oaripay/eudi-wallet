# OARI EUDI Wallet

OARI EUDI Wallet is the native iOS holder wallet defined by the architecture in
`../eudi-wallet-achitecture`. It is separate from the enterprise services in
`../workspace` and consumes their published issuer, verifier, credential, status,
identity and trust contracts.

The product target is Swift 6.3, SwiftUI and iOS 17 or later. Certification and
production trust claims remain release gates. Development builds must not be
described as certified or legally recognised wallets.

## Compact delivery milestones

M0-M5 are complete and recorded in `docs/EVIDENCE.md`. The architecture build-loop
phases are intentionally consolidated into three larger delivery milestones:

0. Baseline: reproducible project, CI, threat model and release policy.
1. Domain contracts: credential/key/audit models and explicit ports.
2. Encrypted vault: protected credential and audit persistence.
3. Device-bound keys: Secure Enclave/software policy, ES256 signing and deletion.
4. Profiles and trust: final/draft profile registry and evidence-bearing verdicts.
5. Presentation authorization: review, consent, authentication and signing gates.
6. Protocol engine: OpenID4VP, OpenID4VCI and execution wiring, merging build-loop
   phases 3 and 4.
7. Product UI: OARI design system, vault, scanner, review, history, settings and
   accessibility, corresponding to build-loop phase 5.
8. Interoperability and release: DID/EBSI, Wallet Kit, iGrant fixtures, SBOM,
   security evidence, physical-device and certification gates, corresponding to
   build-loop phases 6 and 7.

M6 has internal slices 6a (VP), 6b (VCI), and 6c (execution wiring), but receives one
   independent review and one milestone commit after all three pass.

See `docs/EVIDENCE.md` for current acceptance and verification status.
