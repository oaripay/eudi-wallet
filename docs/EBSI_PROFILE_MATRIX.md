# EBSI W3C profile matrix

This file is the gate for the development EBSI backend. A profile is not supported
until every column is pinned from an actual issuer/verifier interoperability fixture.

| Profile | VCDM | Representation | Securing mechanism | DID/key | Schema | Status | OpenID revision | State |
|---|---|---|---|---|---|---|---|---|
| EBSI 1.1 JWT VC | 1.1 | `jwt_vc_json` or `jwt_vc_json-ld` candidate | Compact JWS candidate | P-256/ES256 or secp256k1/ES256K candidate | To be supplied | To be supplied | To be supplied | Blocked |
| EBSI 1.1/2.0 Data Integrity VC | Exact version per fixture | `ldp_vc` JSON candidate | Exact cryptosuite to be supplied | Exact verification method to be supplied | To be supplied | To be supplied | To be supplied | Blocked |
| EBSI 2.0 SD-JWT | 2.0 | SDK-specific VCDM2 SD-JWT candidate | SD-JWT/JWS candidate | P-256/ES256 or secp256k1/ES256K candidate | To be supplied | To be supplied | To be supplied | Blocked |
| OARI EBSI 2.0 JWT VC | 2.0 | top-level VCDM2 JSON in compact JWS, media type `application/vc+jwt`; VP uses `EnvelopedVerifiableCredential` data URL | JWS ES256 in current OARI issuer | `did:key` holder/issuer, P-256/ES256 in current OpenID metadata | `FullJsonSchemaValidator2021`, TSR v3 | `BitstringStatusListEntry` | OID4VCI final-style metadata plus interactive `urn:openid:dcp:ia:openid4vp_presentation`, `ia_post`, DCQL | Workspace-defined; selected SDK generic JwtVc is V1, so requires an isolated OARI VCDM2 adapter or SDK extension review |

## Key inventory

- Implemented locally today: P-256/ES256 and OARI P-256 `did:key`.
- Present only as a transitive dependency: secp256k1. No reviewed ES256K wallet-key
  provider, DID encoding or verifier integration exists yet.
- Native Swift support must be proven separately for ES256, ES256K and RS256 using
  workspace fixtures. Ed25519/RSA-PSS remain disabled without explicit profiles.
- A JWK `alg` or DID verification method is never accepted merely because its name is
  recognized; proof purpose, controller, relationship, algorithm and signature must
  all match the selected profile.

## Trust-chain endpoints

Development profiles may configure multiple explicit HTTPS DIDR/TIR/TSR endpoints.
`https://ebsi.oari.io` workspace configuration confirms DIDR v5, TIR v5 and TSR v3
service paths and root DID `did:ebsi:zyR8rBsunYRcXndvtxyZTmF`. No official EBSI host is hard-coded yet: the suggested
`hub.ebsi.io`/`hub.ebsi.eu` location has not been verified from an approved immutable
source in this workspace. Production mode requires explicit approved endpoint IDs.

## Required interoperability inputs

For each row provide a credential offer, issuer metadata, credential, presentation
request, DID document, accreditation/TIR response, schema/TSR response, status data,
expected holder-binding key type and expected positive/negative outcomes.
