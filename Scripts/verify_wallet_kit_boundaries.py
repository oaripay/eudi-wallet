#!/usr/bin/env python3
"""Fail if Wallet Kit imports or raw-document storage escape their boundaries."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "Packages/Sources/EudiWalletKitAdapter/EudiWalletKitAdapter.swift"


def fail(message: str) -> None:
    print(f"Wallet Kit boundary verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    imports = []
    for source_root in (ROOT / "Packages/Sources", ROOT / "OARIWallet"):
        for source in source_root.rglob("*.swift"):
            if "import EudiWalletKit" in source.read_text().splitlines():
                imports.append(source.resolve())
    if imports != [ADAPTER.resolve()]:
        fail(f"production Wallet Kit imports differ from sole adapter: {imports}")

    composition = (ROOT / "App/WalletAppDependencies.swift").read_text()
    if "EncryptedCredentialRepository(" in composition or "encodedCredential" in composition:
        fail("production app composition can persist raw credential bytes")
    if "EncryptedCredentialMetadataRepository(" not in composition:
        fail("production app does not compose the metadata-only repository")

    metadata_store = (
        ROOT / "Packages/Sources/WalletVault/EncryptedCredentialMetadataRepository.swift"
    ).read_text()
    if "CredentialEnvelope" in metadata_store or "encodedCredential" in metadata_store:
        fail("metadata-only repository references a raw credential representation")

    forbidden = ("CredentialEnvelope", "encodedCredential", "EncryptedCredentialRepository")
    for source_root in (ROOT / "Packages/Sources", ROOT / "OARIWallet"):
        for source in source_root.rglob("*.swift"):
            text = source.read_text()
            if any(term in text for term in forbidden):
                fail(f"production source retains raw credential plumbing: {source}")

    print("Wallet Kit import and raw-document ownership boundaries verified.")


if __name__ == "__main__":
    main()
