# EUDI Wallet Kit review

## Selected source

```text
Repository: https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit
Tag: v0.39.1
Commit: 79005ab4bf0399238c1c9ebff9ee7d8a42c521f9
Product: EudiWalletKit
License: Apache-2.0
Notice: EU Digital Identity Wallet, Copyright 2026 European Commission
```

The approved public source was cloned read-only into
`/Users/mika/Desktop/oaripay/vendor/eudi-lib-ios-wallet-kit`. The application uses
an exact SwiftPM version and commits its own `Package.resolved`; the vendor checkout
is review evidence, not the application build input.

## Resolved package graph

The OARI lockfile contains 24 exact revisions. Direct Wallet Kit dependencies are:

| Package | Version |
|---|---:|
| `eudi-lib-ios-iso18013-data-transfer` | 0.24.1 |
| `eudi-lib-ios-wallet-storage` | 0.23.2 |
| `eudi-lib-sdjwt-swift` | 0.14.6 |
| `eudi-lib-ios-openid4vp-swift` | 0.41.0 |
| `eudi-lib-ios-openid4vci-swift` | 0.53.0 |
| `eudi-lib-ios-statium-swift` | 0.5.0 |

`Package.resolved` is authoritative for all indirect commits. The application
resolver selected `swift-log` 1.15.0 and `swift-certificates` 1.19.4, newer than the
Wallet Kit repository's lockfile selections 1.13.2 and 1.19.1 because upstream
transitive manifests permit those versions. This variance requires regression tests
and must be reviewed on every lockfile change.

## Ownership decision

- Wallet Kit is the source of truth for raw documents and document-bound keys.
- OARI retains profile/trust evidence, consent, lifecycle state and redacted audit.
- OARI does not copy raw Wallet Kit documents into its encrypted metadata vault.
- Views never import `EudiWalletKit`; only `EudiWalletKitAdapter` does.
- Production app composition uses `EncryptedCredentialMetadataRepository`, whose
  API accepts only `CredentialRecord`. The former raw-byte repository, envelope,
  validator and issuance response path have been removed from production modules.
- `Scripts/verify_wallet_kit_boundaries.py` enforces the sole SDK import and rejects
  production composition or metadata storage that references raw credential bytes.

## Security findings and gates

1. `EudiWallet` attaches stdout logging in Debug builds even when `logFileName` is
   `nil`. Upstream issuance code logs access tokens and issued credential strings at
   info/notice level. SDK-backed issuance/presentation is a **no-go in Debug** until
   the dependency is patched, upgraded, or an upstream-supported redacting/disabled
   logger is available. Release builds do not attach this debug handler, but that
   does not make Debug leakage acceptable for fixtures or developer data.
   `EudiWalletKitAdapter.requireOperationalRuntime()` enforces containment:
   operational SDK methods fail in Debug, and only the adapter imports Wallet Kit.
   SDK-backed end-to-end fixtures must run in a Release test configuration until
   upstream logging is fixed.
2. The adapter sets `logFileName` to `nil`, strict trust policies, signed metadata,
   WRPRC validation and user authentication by default.
   Trust inputs are profile-bound and SHA-256 pinned; DER parsing, validity,
   `basicConstraints` CA status and certificate-signing key usage are checked before
   Wallet Kit construction. Valid leaf and unapproved CA certificates are rejected.
3. The current platform graph exposes Wallet Kit's `SecTrust`/`rootIaca` trust path;
   the optional ETSI binary trust-source initializer is not available to the adapter.
   Production EBSI/EUDI trust mapping therefore remains Loop C work.
4. Wallet Kit is explicitly described upstream as an initial development release;
   integration does not establish production readiness or certification.
5. `eudi-lib-ios-statium-swift` 0.5.0 has unresolved Git markers in its root
   `LICENSE`, but both conflict sides contain the complete Apache-2.0 text and its
   README independently declares Apache-2.0. This is malformed upstream source, not
   conflicting license terms; retain the Apache-2.0 notice and require human legal
   confirmation before distribution.

## Required follow-up before Loop B exits

- Obtain an upstream logging fix or retain the Release-only operational gate,
  source-level scan and regression test.
- Validate real signed issuer metadata, WRP certificates and status tokens.
- Validate storage deletion/key lifecycle on a physical device.
- Validate SD-JWT, mdoc, BLE and OpenID4VP with the pinned SDK tests plus real
  staging issuer/verifier interoperability; do not treat a local mock transport
  as production evidence.
- Update the SBOM and notices for every lockfile change.
