# Third-party dependency license inventory

This inventory corresponds to the exact revisions in `Package.resolved`. The
machine-readable determinations are in `config/dependency-licenses.json` and are
applied to `sbom.spdx.json` by `Scripts/enrich_sbom_licenses.py`.

| Locked package | License determination |
|---|---|
| CryptoSwift | Zlib-style license; product documentation attribution required |
| EUDI data model, data transfer, security, OpenID4VCI, OpenID4VP, Statium, Wallet Kit, wallet storage, ETSI binary, SD-JWT | Apache-2.0 |
| jose-swift, JOSESwift | Apache-2.0 |
| SwiftCopyableMacro | Apache-2.0; executable macro source/revision independently gated |
| swift-asn1, swift-certificates, swift-collections, swift-crypto, swift-log, swift-syntax | Apache-2.0 |
| secp256k1.swift | MIT |
| SwiftyJSON | MIT |
| SwiftCBOR | Unlicense |
| swift-zlib | **NOASSERTION**: no license file in the locked checkout and GitHub license endpoint returned 404 |

## Explicit exceptions

- `eudi-lib-ios-statium-swift` 0.5.0 contains Git conflict markers around two
  complete copies of Apache-2.0. Its README also declares Apache-2.0. The intended
  license is unambiguous, but legal/source-hygiene confirmation remains mandatory.
- `swift-zlib` 1.0.2 has no discoverable license file. Production distribution is
  blocked until the upstream owner or legal review provides an acceptable license.

This file is an engineering inventory, not legal advice or legal approval.
