# Dependency and interoperability review

## Current build graph

The application builds only OARI-owned local Swift package products. Apple platform
frameworks in use are Foundation, SwiftUI, Security, LocalAuthentication and
CryptoKit. `syft` generates `sbom.spdx.json` from the committed workspace.

## EUDI Wallet Kit gate

`eudi-lib-ios-wallet-kit` 0.16.4 remains an evaluation candidate, not a build
dependency. No locally accessible source checkout or authoritative reviewed commit
SHA was available on 2026-08-07. A version label is not treated as a source pin.

Integration is blocked until a human reviewer records:

1. Exact source commit and immutable repository URL.
2. Tag-to-commit correspondence and source signature/provenance where available.
3. Transitive dependency and license inventory.
4. Supported OpenID4VCI, OpenID4VP, DCQL, mdoc and SD-JWT profile matrix.
5. Key-custody, logging, network and storage review.
6. Fixture and physical-device interoperability results.

No production or certification claim depends on the unintegrated candidate.

## iGrant compatibility

Draft behavior is isolated in `IGrantDraftCredentialOfferParser` and
`IGrantDraftPresentationRequestParser`, with Draft 13/18 fixtures under
`Packages/Tests/ProtocolEngineTests/Fixtures`. Final OpenID parsers do not silently
fall back to these adapters.
