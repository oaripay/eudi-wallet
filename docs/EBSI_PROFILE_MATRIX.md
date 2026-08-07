# EBSI W3C profile matrix

This file is the gate for the development EBSI backend. A profile is not supported
until every column is pinned from an actual issuer/verifier interoperability fixture.

| Profile | VCDM | Representation | Securing mechanism | DID/key | Schema | Status | OpenID revision | State |
|---|---|---|---|---|---|---|---|---|
| EBSI 1.1 JWT VC | 1.1 | To be supplied | To be supplied | P-256/ES256 and secp256k1/ES256K candidates | To be supplied | To be supplied | To be supplied | Blocked |
| EBSI 2.0 JOSE VC | 2.0 | To be supplied | To be supplied | P-256/ES256 and secp256k1/ES256K candidates | To be supplied | To be supplied | To be supplied | Blocked |

## Key inventory

- Implemented locally today: P-256/ES256 and OARI P-256 `did:key`.
- Present only as a transitive dependency: secp256k1. No reviewed ES256K wallet-key
  provider, DID encoding or verifier integration exists yet.
- Not enabled without counterpart evidence: Ed25519/EdDSA, RSA/PS256, or other curves.
- A JWK `alg` or DID verification method is never accepted merely because its name is
  recognized; proof purpose, controller, relationship, algorithm and signature must
  all match the selected profile.

## Trust-chain endpoints

Development profiles may configure multiple explicit HTTPS DIDR/TIR/TSR endpoints.
`https://ebsi.oari.io` is the requested OARI development host, but exact service paths
still require confirmation. No official EBSI host is hard-coded yet: the suggested
`hub.ebsi.io`/`hub.ebsi.eu` location has not been verified from an approved immutable
source in this workspace. Production mode requires explicit approved endpoint IDs.

## Required interoperability inputs

For each row provide a credential offer, issuer metadata, credential, presentation
request, DID document, accreditation/TIR response, schema/TSR response, status data,
expected holder-binding key type and expected positive/negative outcomes.
