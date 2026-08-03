#!/usr/bin/env python3
"""Generate the deterministic SPDX 2.3 inventory for vendored Rust inputs."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path
from typing import Any, Optional

from provenance_common import ROOT, UPSTREAM, VENDOR, canonical_json


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        return tomllib.load(source)


def package_manifests() -> dict[tuple[str, str], list[tuple[Path, dict[str, Any]]]]:
    result: dict[tuple[str, str], list[tuple[Path, dict[str, Any]]]] = {}
    for base in (UPSTREAM, VENDOR):
        for path in sorted(base.rglob("Cargo.toml")):
            value = load_toml(path)
            package = value.get("package")
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            version = package.get("version")
            if isinstance(name, str) and isinstance(version, str):
                result.setdefault((name, version), []).append((path, package))
    wrapper = load_toml(ROOT / "Cargo.toml")["package"]
    result.setdefault((wrapper["name"], wrapper["version"]), []).append(
        (ROOT / "Cargo.toml", wrapper)
    )
    return result


def spdx_id(name: str, version: str, index: int) -> str:
    clean = re.sub(r"[^A-Za-z0-9.-]", "-", f"{name}-{version}-{index}")
    return f"SPDXRef-Package-{clean}"


def select_manifest(
    manifests: dict[tuple[str, str], list[tuple[Path, dict[str, Any]]]],
    name: str,
    version: str,
    source: Optional[str],
) -> tuple[Path, dict[str, Any]]:
    candidates = manifests.get((name, version), [])
    if source:
        candidates = [item for item in candidates if VENDOR in item[0].parents]
    else:
        candidates = [item for item in candidates if VENDOR not in item[0].parents]
    if not candidates:
        raise RuntimeError(f"no Cargo.toml for {name} {version} ({source})")
    return sorted(candidates, key=lambda item: item[0].as_posix())[0]


def resolve_dependency(
    dependency: str,
    ids_by_name: dict[str, list[tuple[str, str]]],
) -> Optional[str]:
    parts = dependency.split()
    name = parts[0]
    choices = ids_by_name.get(name, [])
    if len(parts) > 1 and re.fullmatch(r"[0-9][^ ]*", parts[1]):
        version = parts[1]
        choices = [choice for choice in choices if choice[0] == version]
    if len(choices) == 1:
        return choices[0][1]
    return None


def build_sbom() -> dict[str, Any]:
    lock = load_toml(UPSTREAM / "Cargo.lock")
    manifests = package_manifests()
    wrapper_toml = load_toml(ROOT / "Cargo.toml")
    wrapper_manifest = wrapper_toml["package"]
    locked = sorted(
        lock["package"],
        key=lambda item: (item["name"], item["version"], item.get("source", "")),
    )
    records: list[dict[str, Any]] = [
        {
            "name": wrapper_manifest["name"],
            "version": wrapper_manifest["version"],
            "dependencies": sorted(wrapper_toml.get("dependencies", {})),
        }
    ] + locked

    packages: list[dict[str, Any]] = []
    package_ids: list[str] = []
    ids_by_name: dict[str, list[tuple[str, str]]] = {}
    for index, record in enumerate(records):
        name = record["name"]
        version = record["version"]
        source = record.get("source")
        manifest_path, manifest = select_manifest(
            manifests, name, version, source
        )
        identifier = spdx_id(name, version, index)
        package_ids.append(identifier)
        ids_by_name.setdefault(name, []).append((version, identifier))
        package: dict[str, Any] = {
            "SPDXID": identifier,
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": manifest.get("license", "NOASSERTION"),
            "copyrightText": "NOASSERTION",
            "comment": (
                "registry dependency vendored at "
                + manifest_path.parent.relative_to(ROOT).as_posix()
                if source
                else "source package at "
                + manifest_path.parent.relative_to(ROOT).as_posix()
            ),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:cargo/{name}@{version}",
                }
            ],
        }
        checksum = record.get("checksum")
        if checksum:
            package["checksums"] = [
                {"algorithm": "SHA256", "checksumValue": checksum}
            ]
        packages.append(package)

    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package_ids[0],
        }
    ]
    for record, identifier in zip(records, package_ids):
        for dependency in record.get("dependencies", []):
            target = resolve_dependency(dependency, ids_by_name)
            if target is not None:
                relationships.append(
                    {
                        "spdxElementId": identifier,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": target,
                    }
                )
    relationships.sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
        )
    )

    identity = hashlib.sha256(
        canonical_json(
            [(item["name"], item["versionInfo"]) for item in packages]
        )
    ).hexdigest()
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "innova-privacy-vnext-rust",
        "documentNamespace": (
            "https://innova.network/spdx/privacy-vnext/" + identity
        ),
        "creationInfo": {
            "created": "2026-07-09T09:05:47Z",
            "creators": [
                "Tool: src/privacy_vnext/rust/tools/generate_sbom.py"
            ],
            "licenseListVersion": "3.26",
        },
        "packages": packages,
        "relationships": relationships,
    }


def main() -> None:
    output = ROOT / "sbom.spdx.json"
    output.write_bytes(canonical_json(build_sbom()) + b"\n")
    print(f"wrote {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
