# Initial threat model

## Protected assets

- Holder and device-binding private keys.
- Credential payloads and selectively disclosed claims.
- Authorization codes, access tokens, proofs, nonces and session state.
- Trust/profile configuration and cached status evidence.
- User consent and redacted audit integrity.

## Trust boundaries

- QR codes, deep links, pasteboard input and universal links are untrusted transport.
- Issuer, authorization-server and verifier metadata require profile and trust checks.
- The EUDI Wallet Kit is a pinned but independently reviewed adapter dependency, not
  a trust oracle or certification statement.
- OARI enterprise services are remote peers. Their response is not trusted merely
  because it uses an OARI hostname or credential type.
- Secure Enclave and Keychain protect keys but do not establish issuer, verifier or
  credential trust.

## Priority threats and controls

| Threat | Required control |
|---|---|
| Malicious QR or deep link | Size/scheme/host validation, no automatic execution, explicit review. |
| Requester impersonation | Signed request validation, RP registration evidence, origin and response URI binding. |
| Issuer metadata substitution | HTTPS, issuer identifier consistency, signed/profile trust evidence. |
| Replay or session swap | One-time state, nonce, audience, expiry and response URI checks plus replay cache. |
| Credential/token disclosure | Local encryption, data protection, redacted logs/history and no telemetry payloads. |
| Stolen unlocked device | Transaction-bound local authentication before signing or destructive operations. |
| Correlation | Purpose/profile-specific keys and selective disclosure. No universal DID assumption. |
| Stale status/trust data | Signed versioned cache with expiry; strict mode fails closed. |
| Dependency compromise | Exact pins, review, SBOM, secret/SAST/dependency checks and isolated adapters. |
| Agent-triggered transfer | Separate human-reviewed action-bound authorization; credential presentation alone is insufficient. |

## Recovery and deletion

Private keys and credential vault data are device-only by default. Recovery means
reissuance until a separately approved end-to-end encrypted design exists. Deleting
a credential must delete its local encrypted payload and dedicated keys where the
active profile does not permit shared use.
