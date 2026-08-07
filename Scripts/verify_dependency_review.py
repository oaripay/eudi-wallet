#!/usr/bin/env python3
"""Verify executable Swift package revisions and reviewed source hashes."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCKFILE = ROOT / "Package.resolved"
REVIEW_FILE = ROOT / "config" / "dependency-review.json"
CHECKOUTS = ROOT / ".build" / "checkouts"


def fail(message: str) -> None:
    print(f"Dependency review verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    lock = json.loads(LOCKFILE.read_text())
    reviews = json.loads(REVIEW_FILE.read_text())["executablePackages"]
    pins = {pin["identity"]: pin for pin in lock["pins"]}

    for identity, review in reviews.items():
        pin = pins.get(identity)
        if pin is None:
            fail(f"reviewed executable package {identity} is not locked")
        state = pin["state"]
        if state.get("version") != review["version"]:
            fail(f"{identity} version differs from reviewed record")
        if state["revision"] != review["revision"]:
            fail(f"{identity} revision differs from reviewed record")

        checkout = CHECKOUTS / "SwiftCopyableMacro"
        if not checkout.is_dir():
            fail(f"checkout missing for {identity}; run swift package resolve")
        revision = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if revision != review["revision"]:
            fail(f"{identity} checkout revision differs from reviewed record")

        for relative, expected_hash in review["sourceHashes"].items():
            source = checkout / relative
            if not source.is_file():
                fail(f"reviewed source is missing: {relative}")
            actual_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                fail(f"reviewed source changed: {relative}")

    print(f"Dependency review verification passed for {len(reviews)} executable package(s).")


if __name__ == "__main__":
    main()
