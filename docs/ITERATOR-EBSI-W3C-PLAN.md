# Single milestone: development EUDI + EBSI/W3C wallet

## Objective

Deliver one reviewed, locally committed development app that resolves every explicitly
registered EUDI and workspace W3C/EBSI profile, supports issuance and presentation,
and permits cryptographically valid but unregistered development counterparties only
after a blocking one-time warning.

This is one milestone and one acceptance gate. The implementation steps below are not
separate commit/review milestones. Do not commit partial protocol scaffolding.

## Authoritative local sources

- `workspace/repos/identity/src/ebsi/config.ts`
- `workspace/repos/identity/src/ebsi/query.ts`
- `workspace/repos/identity/src/jwt.ts`
- `workspace/repos/identity/src/vp.ts`
- `workspace/repos/openid/src/issuer.ts`
- `workspace/repos/openid/src/holder.ts`
- `workspace/repos/schemas`
- `workspace/repos/wallet`

OARI development chain:

```text
DIDR: https://ebsi.oari.io/did-registry/v5/identifiers
TIR:  https://ebsi.oari.io/trusted-issuers-registry/v5/issuers
TSR:  https://ebsi.oari.io/trusted-schemas-registry/v3/schemas
Root: did:ebsi:zyR8rBsunYRcXndvtxyZTmF
```

Additional chains are explicit user-configured HTTPS endpoint sets. Do not guess an
official EBSI endpoint.

## Backend architecture

```text
SwiftUI consent/trust/catalog/audit
            |
 CredentialBackendRouter
      /             \
EUDI Wallet Kit   OariWorkspaceW3CBackend
```

- Wallet Kit owns PID, mdoc, SD-JWT, EUDI keys/storage and EUDI OpenID sessions.
- W3C backend owns W3C raw credentials, holder keys, nonces and W3C protocol state.
- OARI stores normalized metadata/audit only. Never copy credentials/keys between
  backends or transform one signed representation into another.
- Remove SpruceKit entirely. Use bounded HTTPS workspace services plus native Swift
  JOSE/DID/profile validation and encrypted local W3C storage.

## Consolidated implementation steps

1. Remove SpruceKit package/product/source/tests and stale evidence.
2. Freeze matrix profiles from local fixtures.
3. Implement `OariWorkspaceW3CBackend` with injected bounded HTTPS, no redirects,
   explicit endpoint origins and private transaction handles.
4. Implement W3C VCDM 1.1 `jwt_vc_json` issuance/verification/storage/presentation.
5. Implement OARI VCDM 2.0 top-level `application/vc+jwt` with context v2,
   FullJsonSchemaValidator2021, BitstringStatusListEntry, IssuanceCertificate and
   EnvelopedVerifiableCredential VP wrapping.
6. Implement ES256/P-256, ES256K/secp256k1 and fixture-required RS256 verification;
   unknown algorithms and ambiguous DID relationships reject.
7. Support `did:ebsi` DIDR v5 and `did:key`; enforce controller and
   authentication/assertionMethod relationships.
8. Resolve inline credential offers and `credential_offer_uri`; support
   pre-authorized-code, authorization-code, tx_code, metadata, PAR/PKCE/DPoP where
   advertised, proof nonce, batch, deferred, callback/cancel and replay protection.
9. Bridge `presentation_required` to the existing EUDI Wallet Kit PID consent flow,
   then resume W3C issuance without moving the PID out of Wallet Kit.
10. Implement W3C OpenID4VP request/request_uri, DCQL, nonce/state/audience/expiry,
    direct-post/direct-post-JWT, local proof signing and cancellation.
11. Implement trust evaluation against every configured chain. Development
    unregistered-but-valid issuer/verifier requires a blocking one-shot Continue or
    Cancel. Invalid/expired/replayed/malformed/indeterminate always reject. Production
    unregistered always rejects.
12. Wire catalog/detail/backend/profile/status/schema/trust warning/consent/pending/
    retry/recovery UI and redacted audit.
13. Add positive and negative workspace fixtures and full package, Debug,
    ReleaseTesting and UI automation.

## Registered profile matrix

Enable only counterpart-tested rows in `docs/EBSI_PROFILE_MATRIX.md`:

- EUDI mdoc and SD-JWT through Wallet Kit;
- VCDM 1.1 `jwt_vc_json` compact JWS;
- VCDM 1.1 `jwt_vc_json-ld` only with exact context fixture;
- VCDM 1.1/2.0 `ldp_vc` only with exact Data Integrity cryptosuite fixture;
- VCDM 2.0 SD-JWT only with exact fixture;
- OARI VCDM 2.0 `application/vc+jwt` workspace profile;
- no generic VCDM 2 JWT claim.

## Trust gate

```text
valid + trusted                  -> continue
valid + unregistered development -> blocking warning -> Continue or Cancel
invalid signature/proof          -> reject
expired/replayed/malformed       -> reject
indeterminate evidence           -> reject
production unregistered          -> reject
```

Continue consumes the transaction before any await/network call. Cancel destroys the
backend transaction. Warning must show role, identifier, evidence source/reasons and
that no data has yet been shared/stored.

## Single milestone acceptance criteria

1. No SpruceKit dependency/import/runtime claim remains.
2. Both backends own their respective raw documents/keys and route deterministically.
3. Every enabled matrix row has real workspace positive/negative fixtures.
4. All listed OpenID4VCI offer/grant/pending/deferred/presentation-required paths pass.
5. EUDI PID → W3C issuance passes end to end.
6. W3C virtual presentation passes end to end.
7. ES256, ES256K and fixture-required RS256 verification pass; unsupported algorithms
   fail explicitly.
8. DIDR/TIR/TSR/schema/status/holder-binding/nonce/audience/replay checks pass.
9. Development warnings are one-shot and cannot override invalid/indeterminate data.
10. Production remains fail-closed.
11. Raw credentials/private keys never enter OARI metadata/audit.
12. Package, app model, UI automation and ReleaseTesting pass.
13. Independent consolidated reviewer returns PASS with no BLOCKER/MAJOR.
14. One local conventional commit records the complete milestone; no push occurs.

If any criterion cannot be verified, report BLOCKED with the exact missing workspace
fixture/service/physical-device input. Do not claim partial scaffolding as support.
