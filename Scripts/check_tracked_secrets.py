#!/usr/bin/env python3
"""Reject private key material and secret-bearing files before commit or in CI."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys


FORBIDDEN_SUFFIXES = {
    ".cer",
    ".crt",
    ".der",
    ".jks",
    ".key",
    ".mobileprovision",
    ".p12",
    ".p8",
    ".pem",
    ".pfx",
}
FORBIDDEN_NAMES = {
    ".env",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
PRIVATE_KEY_PATTERN = re.compile(
    b"-" * 5 + b"BEGIN " + b"(?:[A-Z0-9]+ )*PRIVATE KEY" + b"-" * 5
)


def candidate_paths() -> list[pathlib.Path]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        check=True,
        capture_output=True,
    )
    return [
        pathlib.Path(raw.decode("utf-8"))
        for raw in result.stdout.split(b"\0")
        if raw
    ]


def main() -> int:
    violations: list[str] = []

    for path in candidate_paths():
        if not path.exists():
            continue
        normalized_name = path.name.lower()
        if normalized_name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            violations.append(f"forbidden private-material filename: {path}")
            continue

        try:
            contents = path.read_bytes()
        except OSError as error:
            violations.append(f"could not inspect {path}: {error}")
            continue

        if PRIVATE_KEY_PATTERN.search(contents):
            violations.append(f"private-key content marker: {path}")

    if violations:
        print("Private material check failed:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1

    print(f"Private material check passed for {len(candidate_paths())} repository files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
