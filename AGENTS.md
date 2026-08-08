# Iterator execution contract

Read these before changing code:

- `.agents/IMPLEMENTATION-PLAN.md`
- `.agents/EBSI_PROFILE_MATRIX.md`
- `.agents/EBSI_BACKEND_REVIEW.md`
- `.agents/WALLET_KIT_REVIEW.md`
- `.agents/EVIDENCE.md`

The goal is a development-capable wallet with two separate backends. “All possible”
means every explicitly registered profile in the matrix, not permissive parsing of
unknown credentials or protocol variants.

## Backend architecture

```text
OARI SwiftUI UI / consent / warnings / audit / metadata
                  |
          CredentialBackendRouter
             /                  \
    EudiWalletKitBackend       OariWorkspaceW3CBackend
       EudiWallet              HTTPS to workspace repos
```

### EUDI backend

Use the pinned EUDI Wallet Kit as the sole owner of:

- EUDI PID and mdoc documents;
- SD-JWT VC documents;
- document-bound private keys and secure storage;
- OpenID4VCI and OpenID4VP;
- DPoP, proofs, DCQL, deferred/batch issuance;
- mdoc QR/BLE and presentation sessions.

Do not copy EUDI credentials/keys into the W3C backend or reimplement these protocols.

### W3C/EBSI development backend

Do **not** use SpruceKit in the app. Remove its package/target/review code before
integration. Use the OARI workspace repositories as the development issuer/verifier
and public EBSI service backend.

The iOS adapter calls these services over bounded HTTPS. Raw W3C credentials and
holder private keys are encrypted on-device; private keys never go to the workspace.

## Explicit credential profile matrix

Implement and test profiles independently. Every profile needs a fixture and a
positive/negative interoperability test before it is enabled.

### EUDI profiles

- `mso_mdoc` / CBOR through Wallet Kit;
- SD-JWT VC through Wallet Kit;
- EUDI OpenID4VCI pre-authorized-code;
- EUDI OpenID4VCI authorization-code;
- EUDI batch/deferred issuance;
- EUDI OpenID4VP/DCQL/direct-post/direct-post-JWT;
- EUDI PID presentation during issuance;
- EUDI QR/BLE mdoc presentation.

### W3C/EBSI development profiles

- VCDM 1.1 `jwt_vc_json` with compact JWS;
- VCDM 1.1 `jwt_vc_json-ld` only where a workspace fixture proves its context/proof;
- VCDM 1.1/2.0 `ldp_vc` only with an exact Data Integrity cryptosuite fixture;
- VCDM 2.0 SD-JWT only with an exact workspace fixture;
- OARI VCDM 2.0 `application/vc+jwt` with the workspace-defined top-level VCDM2
  context/schema/status/IssuanceCertificate profile;
- no generic VCDM2 JWT VC claim until the workspace proves it independently.

## OpenID4VCI coverage

The W3C adapter must resolve and test:

1. `openid-credential-offer://` URI with inline `credential_offer`;
2. `credential_offer_uri` retrieval;
3. pre-authorized-code grant;
4. authorization-code grant;
5. transaction code (`tx_code`) with exact ASCII validation;
6. issuer metadata and authorization-server metadata;
7. PAR/PKCE where the issuer advertises them;
8. DPoP where advertised/required;
9. credential proof and nonce;
10. batch issuance;
11. deferred issuance;
12. `presentation_required` interactive authorization;
13. authorization callback and safe cancellation;
14. malformed, expired, replayed, unsupported and untrusted cases.

The local workspace OpenID implementation is the required protocol reference for
this development app. Its final/draft compatibility set is:

- final pre-authorized-code grant;
- final authorization-code grant;
- issuer-state authorization challenge;
- final `urn:openid:dcp:ia:openid4vp_presentation` interaction;
- draft bare `openid4vp_presentation` interaction;
- final `ia_post` response mode;
- draft `iar-post` response mode;
- final `openid4vp_response` containing `vp_token`;
- draft plain `vp_token` form response;
- inline and referenced credential offers;
- both credential-proof shapes accepted by the workspace;
- DCQL credential-query matching;
- authorization-code exchange after successful PID VP.

Draft 13/18 compatibility remains isolated behind named development profiles. Never
use a draft fallback when a final request is malformed. A profile is supported only
when an app test executes the actual workspace route and asserts its response shape.

For `presentation_required`:

```text
W3C issuer starts issuance
  -> issuer requests PID through OpenID4VP
  -> EUDI Wallet Kit presents PID
  -> workspace verifies PID VP
  -> workspace issues W3C VC
  -> iOS validates/stores W3C VC in its backend
```

## OpenID4VP coverage

Support only registered request profiles and test:

- signed and unsigned request behavior as the profile permits;
- `request_uri` and inline request handling;
- DCQL selection;
- required/optional claims;
- nonce, state, audience, response URI and expiry;
- direct-post and direct-post-JWT;
- verifier DID and trust evidence;
- EUDI PID presentation through Wallet Kit;
- W3C JWT VC/SD-JWT presentation through the W3C backend;
- malformed, expired, replayed, invalid-signature and untrusted verifier cases.

## DID and key coverage

Implement profile-bound verification, not algorithm-name recognition:

- `did:ebsi` resolution through configured DID Registry v5;
- `did:key` for development holder/issuer fixtures;
- P-256/ES256;
- secp256k1/ES256K;
- RSA/RS256 verification where workspace fixtures require it;
- Ed25519/EdDSA only if a pinned workspace fixture requires it;
- verification relationships: authentication, assertionMethod, capabilityInvocation
  and keyAgreement as appropriate;
- controller, key purpose, signature algorithm, expiry, nonce, audience and replay.

Unknown algorithms, unsupported DID methods and ambiguous verification relationships
fail explicitly.

## Development trust behavior

This is a development interoperability wallet. Registry and status membership are
diagnostic; cryptographic and protocol validity remain mandatory:

```text
valid + trusted                  -> continue normally
valid + unregistered              -> informational warning -> Continue or Cancel
invalid signature/proof          -> reject, no override
expired/replayed/malformed       -> reject, no override
unsupported profile/algorithm    -> reject, no override
```

The warning must say that this is development-only and display issuer/verifier, role,
trust-chain endpoint, reasons and what will happen next. Continue must consume the
interaction exactly once before any network continuation. Cancel must cancel backend
state and record no successful issuance/presentation. Production fail-closed policy is
outside this development acceptance gate.

## Storage and routing

```swift
struct CredentialCatalogEntry {
    let backendID: String
    let profileID: String
    let vcdmVersion: String?
    let representation: String
    let securingMechanism: String
    let opaqueBackendDocumentID: String
}
```

The catalog contains metadata only. Each backend owns raw credential payloads,
private keys, nonces, proof state and protocol handles.

## Single consolidated milestone

Execute every step in `.agents/ITERATOR-EBSI-W3C-PLAN.md` as one milestone. Internal
steps may use focused checks but must not be committed or declared complete
individually. Run one consolidated review loop over the complete implementation, fix
all BLOCKER/MAJOR findings (maximum four cycles), run the complete verification matrix
and create one local commit only after PASS.

Never mix EUDI and W3C backend ownership in one raw credential path, never silently
continue an untrusted request, and never claim support for an untested profile.
