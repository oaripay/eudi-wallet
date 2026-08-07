# Release policy

## Build classes

- Development: simulator or registered development device, non-production endpoints,
  no certification claim.
- Interoperability: isolated sandbox profiles and redacted conformance evidence,
  no production trust anchors or secrets in the app bundle.
- Production candidate: selected Member State/profile, reviewed trust sources,
  physical-device matrix, privacy/security evidence and independent assessment.
- Production: requires human legal, security, privacy and release approval plus the
  applicable formal certification and national recognition evidence.

## Current state

Only development builds are permitted. Regulated strict mode must remain unavailable
until authoritative trust and RP registration sources are configured. A development
warning flow must never be represented as equivalent to regulated validation.

## Toolchain and dependency pins

- Xcode: 26.5 (build 17F42).
- Swift compiler: 6.3.2; project language mode: Swift 6.
- Minimum iOS: 17.0.
- EUDI Wallet Kit: exact version `v0.39.1`, commit
  `79005ab4bf0399238c1c9ebff9ee7d8a42c521f9` is selected but not yet a build
  dependency. It must not be used in a production adapter until its source,
  transitive dependencies, license, API and protocol profiles are reviewed and
  recorded. A version label alone is not adequate production evidence.
