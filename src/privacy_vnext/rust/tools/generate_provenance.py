#!/usr/bin/env python3
"""Generate deterministic provenance for the pinned privacy-vNext sources."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

from provenance_common import (
    ROOT,
    UPSTREAM,
    VENDOR,
    license_files,
    sha256_file,
    tree_sha256,
)


UPSTREAM_COMMIT = "76399e58bfc7e652d900936f84b3785ea59ab4cd"
UPSTREAM_TREE = "18eb6a7f525e9413a8b7dcea28fd4c2b1180f9c7"
UPSTREAM_LOCK_SHA256 = (
    "ed36d0720d8f9edd9ebc479ad84adb0763b24d739ecce3271d35bc2ca59a0747"
)
TOOLCHAIN_SHA256 = (
    "f53198ae4fdecfd87da36fe431c771b54c51e975d01c0e99f653bc14d5d48211"
)
COMPONENT_GIT_TREES = {
    "crypto/fcmps": "4350e4a902093fcaa6e898324e419f01ac2c584f",
    "crypto/generalized-bulletproofs": "160793b98181d6c61d4ec5063a4afa4ad410eaf5",
    "crypto/helioselene": "89df10d4f04c760fc6f8b230872703b1f219d433",
    "crypto/divisors": "c18a9e59ec397738a6bf9c66e8ca2a1ad22d7851",
    "monero-oxide/ringct/fcmp++": "49e090270ba09bbc79c65718e5a002ca49bb0cd7",
}


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        return tomllib.load(source)


def component_records() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for relative, git_tree in COMPONENT_GIT_TREES.items():
        digest, count = tree_sha256(UPSTREAM / relative)
        result[relative] = {
            "git_tree": git_tree,
            "sha256_tree": digest,
            "file_count": count,
        }
    return result


def build_manifest() -> dict[str, Any]:
    upstream_digest, upstream_files = tree_sha256(UPSTREAM, ("target",))
    vendor_digest, vendor_files = tree_sha256(VENDOR, ("target",))
    root_lock = load_toml(ROOT / "Cargo.lock")
    upstream_lock = load_toml(UPSTREAM / "Cargo.lock")
    vendor_dirs = sorted(path.name for path in VENDOR.iterdir() if path.is_dir())
    upstream_licenses = license_files(UPSTREAM)
    vendor_licenses = license_files(VENDOR)
    protocol_contract = ROOT.parent / "contract" / "iv5_protocol_v1.json"
    return {
        "schema_version": 1,
        "status": "non_consensus_contract_and_fcmp_proof_abi",
        "consensus_enabled": False,
        "transaction_version_2008_enabled": False,
        "upstream": {
            "repository": "https://github.com/monero-oxide/monero-oxide.git",
            "commit": UPSTREAM_COMMIT,
            "git_tree": UPSTREAM_TREE,
            "commit_timestamp_utc": "2026-07-09T09:05:47Z",
            "source_directory": "upstream",
            "sha256_tree": upstream_digest,
            "file_count": upstream_files,
            "components": component_records(),
        },
        "rust_toolchain": {
            "channel": "1.94.1",
            "path": "rust-toolchain.toml",
            "sha256": sha256_file(ROOT / "rust-toolchain.toml"),
            "expected_sha256": TOOLCHAIN_SHA256,
        },
        "dependency_lock": {
            "upstream_path": "upstream/Cargo.lock",
            "upstream_sha256": sha256_file(UPSTREAM / "Cargo.lock"),
            "expected_upstream_sha256": UPSTREAM_LOCK_SHA256,
            "wrapper_path": "Cargo.lock",
            "wrapper_sha256": sha256_file(ROOT / "Cargo.lock"),
            "upstream_package_count": len(upstream_lock["package"]),
            "wrapper_package_count": len(root_lock["package"]),
        },
        "vendored_registry": {
            "directory": "vendor",
            "sha256_tree": vendor_digest,
            "file_count": vendor_files,
            "package_directory_count": len(vendor_dirs),
            "cargo_offline_required": True,
            "cargo_locked_required": True,
        },
        "licenses": {
            "upstream_file_count": len(upstream_licenses),
            "vendored_file_count": len(vendor_licenses),
            "upstream_files": upstream_licenses,
        },
        "sbom": {
            "format": "SPDX-2.3",
            "path": "sbom.spdx.json",
            "sha256": sha256_file(ROOT / "sbom.spdx.json"),
        },
        "abi": {
            "version": 2,
            "schema_path": "abi/innova_privacy_vnext_v2.txt",
            "schema_sha256": sha256_file(
                ROOT / "abi/innova_privacy_vnext_v2.txt"
            ),
            "panic_strategy": "unwind_and_catch_unwind",
            "ownership": "caller_owned_outputs_only",
        },
        "parameter_digest": {
            "available": True,
            "algorithm": "SHA-256",
            "scope": "normative inactive IV5 protocol contract; not activation",
            "contract_path": "../contract/iv5_protocol_v1.json",
            "contract_sha256": sha256_file(protocol_contract),
            "compatibility_summary_path": (
                "contract/innova_privacy_vnext_product_v1.txt"
            ),
            "compatibility_summary_sha256": sha256_file(
                ROOT / "contract/innova_privacy_vnext_product_v1.txt"
            ),
        },
        "product_contract": {
            "consensus_active": False,
            "transaction_version": 2008,
            "upstream_revision": UPSTREAM_COMMIT,
            "tree_layers": 8,
            "max_inputs": 16,
            "max_outputs": 16,
            "max_payload_bytes": 256 * 1024,
            "disclosure_modes": list(range(8)),
            "nullstake_generations": [1, 2, 3],
            "required_operations": [
                "shield",
                "unshield",
                "transfer",
                "nullsend",
                "delegation_create",
                "m_of_n_mint",
                "reclaim",
                "conditional_migration",
            ],
            "finality_profiles": [
                "none",
                "nullstake_v1",
                "nullstake_v2",
                "nullstake_v3",
            ],
            "authorization_modes": [
                "owner",
                "cold_staker",
                "m_of_n_public_signers",
                "m_of_n_hidden_signers",
            ],
            "finality_objects": [
                "none",
                "vote",
                "tally_share",
                "certificate",
                "committee_rotation",
            ],
            "proof_size_api": "upstream FcmpPlusPlus::proof_size",
            "prove_implemented": True,
            "verify_implemented": True,
        },
        "residual_risks": {
            "generalized_bulletproofs_fixed_protocol_audited": False,
            "innova_composition_reviewed": False,
            "proof_or_verification_abi_implemented": True,
        },
    }


def main() -> None:
    output = ROOT / "provenance.json"
    output.write_text(
        json.dumps(build_manifest(), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
