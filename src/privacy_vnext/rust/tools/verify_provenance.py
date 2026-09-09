#!/usr/bin/env python3
"""Fail unless all pinned privacy-vNext source inputs are exact and offline."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

from generate_provenance import (
    ROOT,
    TOOLCHAIN_SHA256,
    UPSTREAM,
    UPSTREAM_COMMIT,
    UPSTREAM_LOCK_SHA256,
    VENDOR,
    build_manifest,
    linked_consensus_active,
)
from generate_sbom import build_sbom
from provenance_common import canonical_json, sha256_file


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        return tomllib.load(source)


def package_key(package: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        package["name"],
        package["version"],
        package.get("source", ""),
        package.get("checksum", ""),
    )


def verify_locks_and_vendor() -> None:
    require(
        sha256_file(UPSTREAM / "Cargo.lock") == UPSTREAM_LOCK_SHA256,
        "upstream Cargo.lock differs from the pinned commit",
    )
    require(
        sha256_file(ROOT / "rust-toolchain.toml") == TOOLCHAIN_SHA256,
        "wrapper rust-toolchain.toml is not the exact pinned file",
    )
    require(
        sha256_file(UPSTREAM / "rust-toolchain.toml") == TOOLCHAIN_SHA256,
        "upstream rust-toolchain.toml differs from the pinned commit",
    )

    upstream = load_toml(UPSTREAM / "Cargo.lock")["package"]
    wrapper = load_toml(ROOT / "Cargo.lock")["package"]
    upstream_keys = {package_key(package) for package in upstream}
    for package in wrapper:
        if package["name"] == "innova-privacy-vnext":
            continue
        require(
            package_key(package) in upstream_keys,
            f"wrapper lock drifted from upstream resolution: {package_key(package)}",
        )

    registry_packages = [package for package in upstream if package.get("checksum")]
    expected_dirs = {f"{item['name']}-{item['version']}" for item in registry_packages}
    actual_dirs = {path.name for path in VENDOR.iterdir() if path.is_dir()}
    require(actual_dirs == expected_dirs, "vendored registry directory set is not exact")
    for package in registry_packages:
        checksum_path = (
            VENDOR
            / f"{package['name']}-{package['version']}"
            / ".cargo-checksum.json"
        )
        require(checksum_path.is_file(), f"missing {checksum_path.relative_to(ROOT)}")
        checksum = json.loads(checksum_path.read_text(encoding="utf-8"))
        require(
            checksum.get("package") == package["checksum"],
            f"archive checksum mismatch for {package['name']} {package['version']}",
        )


def verify_configuration_and_abi() -> None:
    config = load_toml(ROOT / ".cargo/config.toml")
    require(
        config.get("source", {}).get("crates-io", {}).get("replace-with")
        == "vendored-sources",
        "crates.io is not replaced with vendored sources",
    )
    directory = (
        config.get("source", {}).get("vendored-sources", {}).get("directory")
    )
    require(directory == "vendor", "vendor path must be repository-relative")
    require(config.get("net", {}).get("offline") is True, "Cargo offline mode missing")
    require(not (UPSTREAM / ".git").exists(), "upstream source must not be a submodule")

    cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    require('panic = "unwind"' in cargo, "wrapper must compile with panic unwinding")
    require(
        "monero-fcmp-plus-plus" in cargo,
        "wrapper does not compile the pinned FCMP++ source dependency",
    )
    header = (ROOT / "include/innova_privacy_vnext.h").read_text(encoding="utf-8")
    # Digits are part of an export name, so a letters-only class truncates one silently.
    exported = set(re.findall(r"innova_privacy_vnext_[a-z0-9_]+(?=\()", header))
    require(
        exported
        == {
            "innova_privacy_vnext_abi_version",
            "innova_privacy_vnext_abi_hash",
            "innova_privacy_vnext_provenance_digest",
            "innova_privacy_vnext_parameter_digest",
            "innova_privacy_vnext_accepted_parameter_digests",
            "innova_privacy_vnext_envelope_allows",
            "innova_privacy_vnext_contract_metadata",
            "innova_privacy_vnext_protocol_contract",
            "innova_privacy_vnext_fcmp_proof_size",
            "innova_privacy_vnext_fcmp_prove",
            "innova_privacy_vnext_fcmp_verify",
            "innova_privacy_vnext_fcmp_batch_verify",
            "innova_privacy_vnext_tree_update",
            "innova_privacy_vnext_tree_extend",
            "innova_privacy_vnext_tree_root",
            "innova_privacy_vnext_nullifier_update",
            "innova_privacy_vnext_nullifier_root",
            "innova_privacy_vnext_tree_witness",
            "innova_privacy_vnext_payload_signing_hash",
            "innova_privacy_vnext_payload_validate",
            "innova_privacy_vnext_payload_effects",
            "innova_privacy_vnext_payload_effects_assume_valid",
            "innova_privacy_vnext_payload_scan",
            "innova_privacy_vnext_address_encode",
            "innova_privacy_vnext_address_decode",
            "innova_privacy_vnext_key_derive",
            "innova_privacy_vnext_note_scan",
            "innova_privacy_vnext_note_encrypt",
            "innova_privacy_vnext_input_context",
            "innova_privacy_vnext_value_prove",
            "innova_privacy_vnext_receiver_disclosure_prove",
            "innova_privacy_vnext_amount_equality_prove",
            "innova_privacy_vnext_vote_membership_prove",
            "innova_privacy_vnext_vote_membership_verify",
            "innova_privacy_vnext_vote_sigma_prove",
            "innova_privacy_vnext_vote_sigma_verify",
            "innova_privacy_vnext_ed25519_combine",
            "innova_privacy_vnext_range_prove",
            "innova_privacy_vnext_range_verify",
        },
        "ABI differs from the caller-owned v2 contract",
    )


def verify_generated_files() -> None:
    actual_sbom = json.loads((ROOT / "sbom.spdx.json").read_text(encoding="utf-8"))
    require(actual_sbom == build_sbom(), "sbom.spdx.json is stale")
    actual_provenance = json.loads(
        (ROOT / "provenance.json").read_text(encoding="utf-8")
    )
    require(actual_provenance == build_manifest(), "provenance.json is stale")
    require(actual_provenance["upstream"]["commit"] == UPSTREAM_COMMIT, "wrong commit")
    # Was `is False`. The manifest and this check both hardcoded it, so the pair agreed
    # with each other while the archive became the consensus decoder underneath them.
    # Compare against the linked source instead, which is what the claim is about.
    linked_active = linked_consensus_active()
    require(
        actual_provenance["consensus_enabled"] == linked_active,
        "consensus_enabled disagrees with the linked contract metadata",
    )
    require(
        actual_provenance["parameter_digest"]["available"] is True,
        "fixed product contract digest must be available",
    )
    require(
        actual_provenance["product_contract"]["consensus_active"] == linked_active,
        "product metadata disagrees with the linked contract metadata",
    )
    require(
        actual_provenance["product_contract"]["prove_implemented"] is True
        and actual_provenance["product_contract"]["verify_implemented"] is True,
        "proof ABI implementation metadata is stale",
    )
    require(
        (ROOT / "sbom.spdx.json").read_bytes()
        == canonical_json(actual_sbom) + b"\n",
        "SBOM encoding is not canonical",
    )


def verify_consensus_header_binding() -> None:
    """The C++ constant must name the manifest the archive reports at runtime."""
    header = ROOT.parent / "iv5_protocol.h"
    text = header.read_text(encoding="utf-8")
    match = re.search(
        r"PROVENANCE_SHA256\[\]\s*=\s*\"([0-9a-f]{64})\"", text
    )
    require(match is not None, "iv5_protocol.h declares no PROVENANCE_SHA256")
    actual = sha256_file(ROOT / "provenance.json")
    require(
        match.group(1) == actual,
        "iv5_protocol.h PROVENANCE_SHA256 is stale: expected "
        f"{actual}, found {match.group(1)}",
    )


def main() -> int:
    try:
        verify_locks_and_vendor()
        verify_configuration_and_abi()
        verify_generated_files()
        verify_consensus_header_binding()
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError, VerificationError) as error:
        print(f"privacy-vNext provenance: ERROR: {error}", file=sys.stderr)
        return 1
    print(
        "privacy-vNext provenance: exact, vendored, offline, consensus %s"
        % ("active" if linked_consensus_active() else "disabled")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
