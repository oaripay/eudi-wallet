# Privacy and security evidence

## Data minimisation

- Credential payloads are encrypted and excluded from backup.
- History stores operation metadata, credential IDs and SHA-256 digests, not claim
  values, tokens, proofs, nonces or authorization headers.
- Persistent replay storage hashes nonces before encrypting the record.
- Scanner classification performs no network or wallet action.
- No analytics or telemetry SDK is present in the current build graph.

## Network boundaries

- Protocol and registry URLs require absolute HTTPS URLs with canonical hosts.
- VP response origin binds scheme, host and effective port.
- EBSI and status clients reject cross-host final responses, oversized bodies and
  non-200 status codes.
- Credential status payloads require a separately supplied cryptographic verifier.

## Automated commands

```sh
python3 Scripts/check_tracked_secrets.py
gitleaks detect --config .gitleaks.toml --no-banner --redact --source .
gitleaks dir --config .gitleaks.toml --no-banner --redact .
semgrep scan --config .semgrep.yml --error
syft dir:. --exclude './.build/**' -o spdx-json=sbom.spdx.json
```

These checks do not replace independent source review, penetration testing, DPIA,
certification or physical-device testing.
