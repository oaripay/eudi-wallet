#!/usr/bin/env python3
"""Apply reviewed license determinations to the Syft SPDX document."""

from __future__ import annotations

import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCKFILE = ROOT / "Package.resolved"
LICENSES = ROOT / "config" / "dependency-licenses.json"
SBOM = ROOT / "sbom.spdx.json"


def fail(message: str) -> None:
    print(f"SBOM license enrichment failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    lock = json.loads(LOCKFILE.read_text())
    reviews = json.loads(LICENSES.read_text())
    document = json.loads(SBOM.read_text())
    pins = {pin["identity"]: pin for pin in lock["pins"]}

    if set(pins) != set(reviews):
        missing = sorted(set(pins) - set(reviews))
        stale = sorted(set(reviews) - set(pins))
        fail(f"license review mismatch; missing={missing}, stale={stale}")

    packages = {package["name"].lower(): package for package in document.get("packages", [])}
    for identity, pin in pins.items():
        package = packages.get(identity)
        if package is None:
            fail(f"locked package missing from SBOM: {identity}")
        expected_version = pin["state"].get("version")
        if package.get("versionInfo") != expected_version:
            fail(f"SBOM version mismatch for {identity}")
        review = reviews[identity]
        package["licenseDeclared"] = review["spdx"]
        package["licenseConcluded"] = review["spdx"]
        package["licenseComments"] = review["evidence"]

    document.setdefault("annotations", []).append({
        "annotationDate": document["creationInfo"]["created"],
        "annotationType": "OTHER",
        "annotator": "Tool: OARI Scripts/enrich_sbom_licenses.py",
        "comment": "License determinations correspond to config/dependency-licenses.json and Package.resolved."
    })
    SBOM.write_text(json.dumps(document, separators=(",", ":")) + "\n")
    print(f"SBOM license enrichment passed for {len(pins)} locked package(s).")


if __name__ == "__main__":
    main()
