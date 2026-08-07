# EBSI/W3C backend review

## Candidates

### Spruce DIDKit — rejected

- Repository: `https://github.com/spruceid/didkit`
- Reviewed commit: `57a3b45111f8b1003ef1a50cf7cf21c81cd59cb1`
- License: Apache-2.0
- Result: rejected. The repository's own README says its bindings repositories are
  archived and points consumers to SSI and SpruceKit Mobile.
- Historical key support includes P-256, secp256k1, Ed25519 and RSA, but that is not a
  basis for adding an archived iOS wallet backend.

### SpruceKit Mobile 0.20.0 — researched, not selected

- Repository: `https://github.com/spruceid/sprucekit-mobile`
- Tag: `0.20.0`
- Commit: `96efdc9f2958ca2811035cda86be7f5697c8a44b`
- License: Apache-2.0 OR MIT
- iOS delivery: Swift Package `SpruceIDMobileSdk`, backed by a checksummed released
  Rust/UniFFI XCFramework.
- Maintenance: active release line; 0.20.0 contains presentation-required issuance
  handling and mobile OID4VCI/OID4VP code.
- Security status: development only. Its README states it has not yet received the
  desired formal audit for production and is suitable for exploration/experimentation.

## Confirmed format surface in 0.20.0

- JWT VC JSON and JWT VC JSON-LD issuance/parsing/verification paths. Its `JwtVc`
  implementation reports VCDM version 1.
- LDP/Data Integrity JSON credentials are parsed version-agnostically as VCDM v1/v2.
- Dedicated VCDM2 SD-JWT and IETF `dc+sd-jwt` implementations.
- OID4VCI and OID4VP support, including a `presentation_required` issuance error that
  carries an authorization request.
- Credential status support exists, but exact EBSI status profile interoperability is
  not yet established.

## Confirmed key surface

- Mobile UniFFI `Algorithm` accepts ES256 and ES256K.
- Rust dependencies also contain Ed25519 and RSA support, but those algorithms are not
  exposed by the reviewed mobile `Algorithm` mapping and are not enabled for OARI.
- OARI must still verify DID verification relationships, holder binding and EBSI
  accreditation; recognizing an algorithm is not sufficient trust evidence.

## Current decision

SpruceKit Mobile is not used by the app. The selected development architecture is the
OARI workspace issuer/verifier/DIDR/TIR/TSR over bounded HTTPS plus an isolated native
Swift W3C backend for local keys, encrypted credential storage, JOSE validation and
presentation proofs. It must not replace EUDI Wallet Kit or own EUDI PID documents.

Notably, the reviewed `JwtVc` path is VCDM 1. A generic VCDM 2 JWT VC claim must not be
made. VCDM 2 support can only be enabled through a counterpart-tested representation
actually handled by the SDK, currently the Data Integrity JSON or VCDM2 SD-JWT paths.
