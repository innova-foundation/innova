#!/usr/bin/env python3
"""Fail release packaging unless external provenance, evidence, and reviews are pinned."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import tempfile
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from v5_release_evidence_schema import (
    MAINNET_ACTIVATION_BOUNDARY_B_BASE,
    MAINNET_ACTIVATION_FIRST_GATE_BASE,
    MAINNET_ACTIVATION_MAX_LEAD_BLOCKS,
    MAINNET_ACTIVATION_MIN_LEAD_BLOCKS,
    MAINNET_ACTIVATION_SHIFT_GRANULARITY,
    PREFLIGHT_SCHEMA_VERSION,
    REQUIRED_BOUNDARY_ORIGIN,
    REQUIRED_CHECKS,
    REQUIRED_EVIDENCE_FIELDS,
    REQUIRED_EPOCH_INTERVAL,
    REQUIRED_LEAD_BLOCKS,
    REQUIRED_NODE_FIELDS,
    REQUIRED_PRIVACY_VNEXT_DISCLOSURE_MODES,
    REQUIRED_PRIVACY_VNEXT_MEMBERSHIP_SCOPE,
    REQUIRED_PRIVACY_VNEXT_NULLSTAKE_GENERATION_IDS,
    REQUIRED_PRIVACY_VNEXT_OPERATIONS,
    REQUIRED_PRIVACY_VNEXT_POST_DAG_STAKING_ROLE,
    REQUIRED_PRIVACY_VNEXT_TREE_LAYERS,
    REQUIRED_SNAPSHOT_MANIFEST_FIELDS,
    REQUIRED_SNAPSHOT_NODE_FIELDS,
    SNAPSHOT_MANIFEST_SCHEMA_VERSION,
)


UNSET = 0x7FFFFFFF
MAX_EVIDENCE_AGE = dt.timedelta(hours=24)
MANIFEST_SCHEMA_VERSION = 5
RELEASE_GATE_EVIDENCE_SCHEMA_VERSION = 2
REVIEW_ATTESTATION_SCHEMA_VERSION = 2

PINNED_MONERO_OXIDE_COMMIT = "76399e58bfc7e652d900936f84b3785ea59ab4cd"
PINNED_RUST_VERSION = "1.94.1"
RELEASE_QT_VERSION = "6.8.3"
COMPAT_QT_VERSION = "5.15.17"

UNSIGNED_ARTIFACT_NAMES = frozenset({
    "ubuntu-22.04-x86_64",
    "ubuntu-24.04-x86_64",
    "ubuntu-26.04-x86_64",
    "debian-11-x86_64",
    "debian-12-x86_64",
    "fedora-40-x86_64",
    "fedora-41-x86_64",
    "archlinux-x86_64",
    "linux-arm64",
    "linux-arm64-qt",
    "linux-armhf",
    "macos-arm64",
    "windows-x86_64",
})
SIGNED_ARTIFACT_NAMES = frozenset({"macos-arm64", "windows-x86_64"})
UNSIGNED_ARTIFACT_DIRECTORIES = {
    "ubuntu-22.04-x86_64": "innova-ubuntu2204-x86_64",
    "ubuntu-24.04-x86_64": "innova-ubuntu2404-x86_64",
    "ubuntu-26.04-x86_64": "innova-ubuntu2604-x86_64",
    "debian-11-x86_64": "innova-debian11-x86_64",
    "debian-12-x86_64": "innova-debian12-x86_64",
    "fedora-40-x86_64": "innova-fedora40-x86_64",
    "fedora-41-x86_64": "innova-fedora41-x86_64",
    "archlinux-x86_64": "innova-archlinux-x86_64",
    "linux-arm64": "innova-linux-aarch64",
    "linux-arm64-qt": "innova-linux-aarch64-qt",
    "linux-armhf": "innova-linux-armhf",
    "macos-arm64": "innova-macOS-arm64",
    "windows-x86_64": "innova-win64",
}
SIGNED_ARTIFACT_DIRECTORIES = {
    "macos-arm64": "innova-macOS-arm64-signed",
    "windows-x86_64": "innova-win64-signed",
}
REQUIRED_PRIVACY_VNEXT_FIELDS = frozenset({
    "abi_sha256",
    "abi_version",
    "benchmark_evidence_sha256",
    "cargo_lock_sha256",
    "consensus_enabled",
    "disclosure_modes",
    "max_inputs",
    "max_outputs",
    "max_payload_bytes",
    "membership_scope",
    "nullstake_generation_ids",
    "parameter_digest",
    "post_dag_staking_role",
    "rust_toolchain_sha256",
    "rust_version",
    "supported_operations",
    "tree_layers",
    "upstream_commit",
    "upstream_gbp_external_audit",
    "upstream_gbp_risk_disclosed",
    "vendored_source_sha256",
})
REQUIRED_QT_FIELDS = frozenset({"compatibility_version", "release_version"})
REQUIRED_MAINNET_FIELDS = frozenset({
    "activation_shift",
    "boundary_b_slot",
    "first_v5_gate",
    "minimum_lead_blocks",
    "shift_granularity",
    "trusted_tip_evidence_sha256",
    "trusted_tip_hash",
    "trusted_tip_height",
})
REQUIRED_ARTIFACT_FIELDS = frozenset({"signed", "unsigned"})
REQUIRED_SIGNING_FIELDS = frozenset({
    "macos_codesign_verification_sha256",
    "macos_gatekeeper_verification_sha256",
    "macos_notarization_evidence_sha256",
    "windows_authenticode_verification_sha256",
    "windows_rfc3161_timestamp_verification_sha256",
})
REQUIRED_VERIFICATION_FIELDS = frozenset({
    "asan_lsan_sha256",
    "canary_24h_sha256",
    "crash_injection_sha256",
    "fuzz_corpora_sha256",
    "history_replay_sha256",
    "integration_sha256",
    "linux_clean_sha256",
    "linux_reproducible_sha256",
    "macos_clean_sha256",
    "performance_sha256",
    "qt5_compat_sha256",
    "qt6_release_sha256",
    "rust_audit_sha256",
    "ubsan_sha256",
})

SPECIFICATION_REVIEW_LANE = "specification_to_code"
ADVERSARIAL_REVIEW_LANE = "adversarial_innova_composition"


class PolicyError(RuntimeError):
    pass


REQUIRED_MANIFEST_FIELDS = frozenset({
    "schema_version",
    "generated_at",
    "source_commit",
    "candidate_commit",
    "source_build_sha256",
    "candidate_build_sha256",
    "lead_blocks",
    "epoch_interval",
    "boundary_origin",
    "fork_heights",
    "common_height",
    "common_hash",
    "evidence_bundle_sha256",
    "release_gate_evidence_sha256",
    "private_audit_sha256",
    "specification_to_code_attestation_sha256",
    "adversarial_composition_attestation_sha256",
    "privacy_vnext",
    "qt",
    "mainnet",
    "artifacts",
    "signing",
    "verification",
})

REQUIRED_RELEASE_GATE_EVIDENCE_FIELDS = frozenset({
    "schema_version",
    "generated_at",
    "source_commit",
    "candidate_commit",
    "privacy_vnext",
    "qt",
    "mainnet",
    "artifacts",
    "signing",
    "verification",
})

REQUIRED_REVIEW_ATTESTATION_FIELDS = frozenset({
    "schema_version",
    "review_lane",
    "verdict",
    "reviewer_identity_sha256",
    "source_commit",
    "candidate_commit",
    "source_build_sha256",
    "candidate_build_sha256",
    "privacy_parameter_digest",
    "privacy_abi_sha256",
    "upstream_gbp_external_audit",
    "upstream_gbp_risk_disclosed",
    "mainnet_activation_shift",
    "mainnet_trusted_tip_hash",
})

REQUIRED_MANIFEST_FORK_FIELDS = frozenset({
    "boundary_a_activation_height",
    "boundary_b_boundary_a_height",
    "boundary_b_candidate_freeze_height",
    "boundary_b_recommended_activation_height",
})


def int_literal(value: str, constants: Mapping[str, str], stack: Optional[set] = None) -> int:
    text = value.strip().strip("()")
    try:
        return int(text, 0)
    except ValueError:
        pass
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text) or text not in constants:
        raise PolicyError("cannot resolve activation expression %r" % value)
    seen = set() if stack is None else set(stack)
    if text in seen:
        raise PolicyError("activation constants contain a cycle at %s" % text)
    seen.add(text)
    return int_literal(constants[text], constants, seen)


def fork_function_body(text: str, name: str, source: Path) -> str:
    function = re.search(name + r"\s*\([^)]*\)\s*\{(?P<body>.*?)\n\}", text, re.DOTALL)
    if not function:
        raise PolicyError("%s() not found in %s" % (name, source))
    return function.group("body")


def testnet_fork_height(text: str, constants: Mapping[str, str], name: str,
                        source: Path) -> int:
    body = fork_function_body(text, name, source)
    match = re.search(r"if\s*\(\s*fTestNet\s*\)\s*return\s+([^;]+);", body)
    if not match:
        raise PolicyError("testnet return path not found in %s()" % name)
    return int_literal(match.group(1), constants)


def source_constants(text: str) -> Dict[str, str]:
    return {
        match.group(1): match.group(2).strip()
        for match in re.finditer(r"(?:static\s+)?const\s+int\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);", text)
    }


def configured_post_dag_epoch_interval(finality_h: Path) -> int:
    try:
        text = finality_h.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError("cannot read %s: %s" % (finality_h, exc)) from exc
    match = re.search(r"FINALITY_EPOCH_INTERVAL_POST_DAG\s*=\s*([0-9]+)\s*;", text)
    if not match:
        raise PolicyError("FINALITY_EPOCH_INTERVAL_POST_DAG is missing or non-literal")
    return int(match.group(1))


def configured_boundary_b_height(text: str, constants: Mapping[str, str],
                                 source: Path) -> int:
    body = fork_function_body(text, "GetForkHeightBoundaryB", source)
    match = re.search(r"return\s+fRegTest\s*\?[^:]+:\s*([^;]+);", body)
    if not match:
        match = re.search(r"return\s+([^;]+);", body)
    if not match:
        raise PolicyError("non-regtest return path not found in GetForkHeightBoundaryB()")
    return int_literal(match.group(1), constants)


def validate_testnet_activation_ladder(main_h: Path) -> Dict[str, int]:
    """Check the compiled testnet v5 ladder against the placement rules that still bind.

    The public testnet remines from genesis, so Boundary A is no longer scheduled from a
    rollout preflight over live history: there is no common height to lead and no running
    fleet to keep ahead of.  What stays load-bearing is the placement itself.  Boundary A
    (an alias of schema V3) must sit exactly one post-DAG epoch above the DAG fork, which
    is both an exact epoch boundary and the only offset that keeps every DAG-era epoch on
    the strict builder rather than the fBlue V2-compat one.

    Networks that do carry live history keep a lead rule: mainnet's is the trusted-tip
    calculation in validate_release_metadata(), and Boundary B -- scheduled later against
    a testnet that is running by then -- keeps required_boundary_b_activation_height().
    """
    try:
        text = main_h.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError("cannot read %s: %s" % (main_h, exc)) from exc
    constants = source_constants(text)

    interval = configured_post_dag_epoch_interval(main_h.with_name("finality.h"))
    if interval != REQUIRED_EPOCH_INTERVAL:
        raise PolicyError("post-DAG epoch interval is %d, not the fixed %d"
                          % (interval, REQUIRED_EPOCH_INTERVAL))

    finality = testnet_fork_height(text, constants, "GetForkHeightFinality", main_h)
    dag = testnet_fork_height(text, constants, "GetForkHeightDAG", main_h)
    boundary_a = testnet_fork_height(text, constants, "GetForkHeightEpochStateV3", main_h)
    boundary_b = configured_boundary_b_height(text, constants, main_h)

    alias = fork_function_body(text, "GetForkHeightBoundaryA", main_h)
    if not re.search(r"return\s+GetForkHeightEpochStateV3\s*\(\s*\)\s*;", alias):
        raise PolicyError("Boundary A is not an alias of the schema-V3 height")

    if not 0 < finality < dag:
        raise PolicyError("testnet fork ladder is out of order: finality %d, DAG %d"
                          % (finality, dag))
    if boundary_a != dag + interval:
        raise PolicyError(
            "testnet Boundary A (%d) is not exactly one post-DAG epoch above the DAG fork "
            "(%d + %d = %d)" % (boundary_a, dag, interval, dag + interval))
    if boundary_b < boundary_a:
        raise PolicyError("testnet Boundary B (%d) is below Boundary A (%d)"
                          % (boundary_b, boundary_a))

    return {
        "finality": finality,
        "dag": dag,
        "epoch_interval": interval,
        "boundary_a": boundary_a,
        "boundary_b": boundary_b,
    }


def configured_mainnet_v5_shift(source_root: Path) -> int:
    header = source_root / "src" / "v5activation.h"
    try:
        text = header.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError("cannot read %s: %s" % (header, exc)) from exc
    match = re.search(
        r"MAINNET_V5_ACTIVATION_SHIFT\s*=\s*([0-9]+)\s*;", text
    )
    if not match:
        raise PolicyError("MAINNET_V5_ACTIVATION_SHIFT is missing or non-literal")
    return int(match.group(1))


def load_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError("cannot read JSON %s: %s" % (path, exc)) from exc
    if not isinstance(value, dict):
        raise PolicyError("%s must be a JSON object" % path)
    return value


def load_evidence(path: Path) -> Tuple[Dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError("cannot read JSON %s: %s" % (path, exc)) from exc
    if not isinstance(value, dict):
        raise PolicyError("%s must be a JSON object" % path)
    return value, hashlib.sha256(raw).hexdigest()


def load_manifest(path: Path) -> Dict[str, Any]:
    return load_json(path)


def is_hex(value: Any, lengths: Sequence[int]) -> bool:
    text = str(value)
    return len(text) in lengths and all(ch in "0123456789abcdef" for ch in text.lower())


def is_obvious_placeholder_sha256(value: Any) -> bool:
    """Return true for synthetic 256-bit digests made from one nibble/byte."""
    text = str(value).lower()
    if not is_hex(text, (64,)):
        return False
    return len(set(text)) == 1 or len({text[offset:offset + 2] for offset in range(0, 64, 2)}) == 1


def reject_obvious_placeholder_sha256(value: Any, field: str) -> None:
    if is_obvious_placeholder_sha256(value):
        raise PolicyError("%s is an obvious placeholder SHA-256 digest" % field)


def validated_digest(value: Any, field: str) -> str:
    text = str(value or "").lower()
    if not is_hex(text, (64,)):
        raise PolicyError("%s must be a 64-character SHA-256 digest" % field)
    reject_obvious_placeholder_sha256(text, field)
    return text


def validate_digest_map(value: Any, expected: frozenset, field: str) -> Dict[str, str]:
    if not isinstance(value, dict) or set(value) != expected:
        present = set(value) if isinstance(value, dict) else set()
        raise PolicyError(
            "%s fields do not match schema (missing=%s extra=%s)" %
            (field, sorted(expected - present), sorted(present - expected))
        )
    return {
        name: validated_digest(value[name], "%s.%s" % (field, name))
        for name in sorted(expected)
    }


def validate_exact_int_list(value: Any, required: Tuple[int, ...], field: str) -> list:
    if (not isinstance(value, list) or
            any(isinstance(item, bool) or not isinstance(item, int) for item in value) or
            tuple(value) != required):
        raise PolicyError("%s must be exactly %s" % (field, list(required)))
    return list(value)


def validate_mainnet_activation_ladder(
    trusted_tip: int,
    shift: int,
    lead: int,
    granularity: int,
    first_gate: int,
    boundary_b_slot: int,
    field_prefix: str = "release",
) -> int:
    """Accept any ladder whose first gate leads the trusted tip by a policy-legal
    amount. Returns the actual lead in blocks.

    This is deliberately a BAND, not a derived exact value. The previous revision
    computed one required_shift from the tip and demanded equality, which pinned
    a tag to roughly a two-day window -- it rejected a long lead and a short one
    alike, so the deliberately short ladder the project now ships could not be
    tagged at all.

    Split out of validate_release_metadata so the predicate can be exercised
    against the real source tree without assembling a full signed release
    bundle; --selftest builds a synthetic main.h and proves nothing about it.
    """
    if trusted_tip < 0:
        raise PolicyError("%s mainnet trusted tip must be non-negative" % field_prefix)
    if (lead != MAINNET_ACTIVATION_MIN_LEAD_BLOCKS
            or granularity != MAINNET_ACTIVATION_SHIFT_GRANULARITY):
        raise PolicyError("%s mainnet activation inputs do not declare the %d/%d lead policy" %
                          (field_prefix, MAINNET_ACTIVATION_MIN_LEAD_BLOCKS,
                           MAINNET_ACTIVATION_SHIFT_GRANULARITY))
    # Structural consistency: the whole ladder is one shift off fixed bases.
    if shift < 0 or shift % granularity != 0:
        raise PolicyError("%s mainnet activation shift must be a non-negative multiple of %d" %
                          (field_prefix, granularity))
    if (first_gate != MAINNET_ACTIVATION_FIRST_GATE_BASE + shift
            or boundary_b_slot != MAINNET_ACTIVATION_BOUNDARY_B_BASE + shift):
        raise PolicyError("%s mainnet activation gates are not the fixed bases plus the shift" % field_prefix)

    actual_lead = first_gate - trusted_tip
    if actual_lead < MAINNET_ACTIVATION_MIN_LEAD_BLOCKS:
        raise PolicyError(
            "%s mainnet first gate %d leads trusted tip %d by only %d blocks; "
            "policy floor is %d (the network must be fully upgraded before the flag day)" %
            (field_prefix, first_gate, trusted_tip, actual_lead,
             MAINNET_ACTIVATION_MIN_LEAD_BLOCKS))
    if actual_lead > MAINNET_ACTIVATION_MAX_LEAD_BLOCKS:
        raise PolicyError(
            "%s mainnet first gate %d leads trusted tip %d by %d blocks, above the %d ceiling; "
            "the v5 ladder is required to activate swiftly" %
            (field_prefix, first_gate, trusted_tip, actual_lead,
             MAINNET_ACTIVATION_MAX_LEAD_BLOCKS))
    return actual_lead


def validate_release_metadata(container: Mapping[str, Any], field_prefix: str) -> Dict[str, Any]:
    privacy = container.get("privacy_vnext")
    if not isinstance(privacy, dict) or set(privacy) != REQUIRED_PRIVACY_VNEXT_FIELDS:
        present = set(privacy) if isinstance(privacy, dict) else set()
        raise PolicyError(
            "%s.privacy_vnext fields do not match schema (missing=%s extra=%s)" %
            (field_prefix, sorted(REQUIRED_PRIVACY_VNEXT_FIELDS - present),
             sorted(present - REQUIRED_PRIVACY_VNEXT_FIELDS))
        )
    if str(privacy.get("upstream_commit", "")).lower() != PINNED_MONERO_OXIDE_COMMIT:
        raise PolicyError("%s privacy upstream commit is not the pinned FCMP++ revision" % field_prefix)
    if str(privacy.get("rust_version", "")) != PINNED_RUST_VERSION:
        raise PolicyError("%s privacy Rust version is not pinned to %s" %
                          (field_prefix, PINNED_RUST_VERSION))
    if privacy.get("consensus_enabled") is not True:
        raise PolicyError("%s privacy vNext consensus implementation is not enabled" % field_prefix)
    if privacy.get("upstream_gbp_external_audit") is not False:
        raise PolicyError("%s must not claim an external audit for the upstream GBP fix" % field_prefix)
    if privacy.get("upstream_gbp_risk_disclosed") is not True:
        raise PolicyError("%s does not disclose the unaudited upstream GBP-fix risk" % field_prefix)
    abi_version = evidence_int(privacy.get("abi_version"), "%s.privacy_vnext.abi_version" % field_prefix)
    max_inputs = evidence_int(privacy.get("max_inputs"), "%s.privacy_vnext.max_inputs" % field_prefix)
    max_outputs = evidence_int(privacy.get("max_outputs"), "%s.privacy_vnext.max_outputs" % field_prefix)
    max_payload = evidence_int(
        privacy.get("max_payload_bytes"), "%s.privacy_vnext.max_payload_bytes" % field_prefix
    )
    if abi_version <= 0:
        raise PolicyError("%s privacy ABI version must be positive" % field_prefix)
    if max_inputs != max_outputs or max_inputs not in (1, 2, 4, 8, 16):
        raise PolicyError("%s privacy input/output caps must be one selected cap in 1/2/4/8/16" % field_prefix)
    if max_payload != 256 * 1024:
        raise PolicyError("%s privacy payload cap must be exactly 256 KiB" % field_prefix)
    disclosure_modes = validate_exact_int_list(
        privacy.get("disclosure_modes"), REQUIRED_PRIVACY_VNEXT_DISCLOSURE_MODES,
        "%s.privacy_vnext.disclosure_modes" % field_prefix,
    )
    nullstake_generation_ids = validate_exact_int_list(
        privacy.get("nullstake_generation_ids"), REQUIRED_PRIVACY_VNEXT_NULLSTAKE_GENERATION_IDS,
        "%s.privacy_vnext.nullstake_generation_ids" % field_prefix,
    )
    tree_layers = evidence_int(
        privacy.get("tree_layers"), "%s.privacy_vnext.tree_layers" % field_prefix
    )
    if tree_layers != REQUIRED_PRIVACY_VNEXT_TREE_LAYERS:
        raise PolicyError("%s privacy tree_layers must be exactly %d" %
                          (field_prefix, REQUIRED_PRIVACY_VNEXT_TREE_LAYERS))
    if privacy.get("membership_scope") != REQUIRED_PRIVACY_VNEXT_MEMBERSHIP_SCOPE:
        raise PolicyError("%s privacy membership_scope must be exactly %s" %
                          (field_prefix, REQUIRED_PRIVACY_VNEXT_MEMBERSHIP_SCOPE))
    if privacy.get("post_dag_staking_role") != REQUIRED_PRIVACY_VNEXT_POST_DAG_STAKING_ROLE:
        raise PolicyError("%s privacy post_dag_staking_role must be exactly %s" %
                          (field_prefix, REQUIRED_PRIVACY_VNEXT_POST_DAG_STAKING_ROLE))
    if privacy.get("supported_operations") != list(REQUIRED_PRIVACY_VNEXT_OPERATIONS):
        raise PolicyError("%s privacy supported_operations set is incomplete or noncanonical" %
                          field_prefix)
    digest_privacy = dict(privacy)
    digest_privacy["disclosure_modes"] = disclosure_modes
    digest_privacy["nullstake_generation_ids"] = nullstake_generation_ids
    for name in (
        "abi_sha256",
        "benchmark_evidence_sha256",
        "cargo_lock_sha256",
        "parameter_digest",
        "rust_toolchain_sha256",
        "vendored_source_sha256",
    ):
        digest_privacy[name] = validated_digest(
            privacy.get(name), "%s.privacy_vnext.%s" % (field_prefix, name)
        )

    qt = container.get("qt")
    if not isinstance(qt, dict) or set(qt) != REQUIRED_QT_FIELDS:
        raise PolicyError("%s.qt fields do not match schema" % field_prefix)
    if qt.get("release_version") != RELEASE_QT_VERSION or qt.get("compatibility_version") != COMPAT_QT_VERSION:
        raise PolicyError("%s Qt versions must be release=%s compatibility=%s" %
                          (field_prefix, RELEASE_QT_VERSION, COMPAT_QT_VERSION))

    mainnet = container.get("mainnet")
    if not isinstance(mainnet, dict) or set(mainnet) != REQUIRED_MAINNET_FIELDS:
        raise PolicyError("%s.mainnet fields do not match schema" % field_prefix)
    trusted_tip = evidence_int(
        mainnet.get("trusted_tip_height"), "%s.mainnet.trusted_tip_height" % field_prefix
    )
    shift = evidence_int(
        mainnet.get("activation_shift"), "%s.mainnet.activation_shift" % field_prefix
    )
    lead = evidence_int(
        mainnet.get("minimum_lead_blocks"), "%s.mainnet.minimum_lead_blocks" % field_prefix
    )
    granularity = evidence_int(
        mainnet.get("shift_granularity"), "%s.mainnet.shift_granularity" % field_prefix
    )
    first_gate = evidence_int(
        mainnet.get("first_v5_gate"), "%s.mainnet.first_v5_gate" % field_prefix
    )
    boundary_b_slot = evidence_int(
        mainnet.get("boundary_b_slot"), "%s.mainnet.boundary_b_slot" % field_prefix
    )
    validate_mainnet_activation_ladder(
        trusted_tip, shift, lead, granularity, first_gate, boundary_b_slot, field_prefix
    )
    digest_mainnet = dict(mainnet)
    digest_mainnet["trusted_tip_hash"] = validated_digest(
        mainnet.get("trusted_tip_hash"), "%s.mainnet.trusted_tip_hash" % field_prefix
    )
    digest_mainnet["trusted_tip_evidence_sha256"] = validated_digest(
        mainnet.get("trusted_tip_evidence_sha256"),
        "%s.mainnet.trusted_tip_evidence_sha256" % field_prefix,
    )

    artifacts = container.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != REQUIRED_ARTIFACT_FIELDS:
        raise PolicyError("%s.artifacts fields do not match schema" % field_prefix)
    unsigned = validate_digest_map(
        artifacts.get("unsigned"), UNSIGNED_ARTIFACT_NAMES,
        "%s.artifacts.unsigned" % field_prefix,
    )
    signed = validate_digest_map(
        artifacts.get("signed"), SIGNED_ARTIFACT_NAMES,
        "%s.artifacts.signed" % field_prefix,
    )
    if any(signed[name] == unsigned[name] for name in SIGNED_ARTIFACT_NAMES):
        raise PolicyError("%s signed package hashes must differ from unsigned package hashes" % field_prefix)

    signing = validate_digest_map(
        container.get("signing"), REQUIRED_SIGNING_FIELDS,
        "%s.signing" % field_prefix,
    )
    verification = validate_digest_map(
        container.get("verification"), REQUIRED_VERIFICATION_FIELDS,
        "%s.verification" % field_prefix,
    )
    return {
        "privacy_vnext": digest_privacy,
        "qt": dict(qt),
        "mainnet": digest_mainnet,
        "artifacts": {"unsigned": unsigned, "signed": signed},
        "signing": signing,
        "verification": verification,
    }


def canonical_digest(value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise PolicyError("cannot hash file %s: %s" % (path, exc)) from exc


def is_zero_amount(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    try:
        return Decimal(str(value)) == Decimal(0)
    except (InvalidOperation, ValueError):
        return False


def evidence_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise PolicyError("preflight field %s must be an integer" % field)
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyError("preflight field %s must be an integer" % field) from exc


def required_activation_height(common_height: int) -> int:
    target = common_height + REQUIRED_LEAD_BLOCKS
    if target <= REQUIRED_BOUNDARY_ORIGIN:
        return REQUIRED_BOUNDARY_ORIGIN
    steps = (target - REQUIRED_BOUNDARY_ORIGIN + REQUIRED_EPOCH_INTERVAL - 1) // REQUIRED_EPOCH_INTERVAL
    return REQUIRED_BOUNDARY_ORIGIN + steps * REQUIRED_EPOCH_INTERVAL


def required_boundary_b_activation_height(boundary_a_height: int, candidate_freeze_height: int) -> int:
    if boundary_a_height < 0 or candidate_freeze_height < 0:
        raise PolicyError("Boundary A and Boundary-B freeze heights must be non-negative")
    return required_activation_height(max(boundary_a_height, candidate_freeze_height))


def parse_generated_at(value: Any) -> dt.datetime:
    text = str(value or "")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise PolicyError("generated_at is missing or malformed") from exc
    if parsed.tzinfo is None:
        raise PolicyError("generated_at must include a UTC offset")
    return parsed.astimezone(dt.timezone.utc)


def git_output(source_root: Path, args: Sequence[str]) -> str:
    try:
        proc = subprocess.run(
            ["git"] + list(args), cwd=str(source_root), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError("cannot run git: %s" % exc) from exc
    if proc.returncode != 0:
        raise PolicyError("git %s: %s" % (" ".join(args), proc.stderr.strip() or "exit %d" % proc.returncode))
    return proc.stdout.strip()


def relative_to_root(path: Path, source_root: Path) -> str:
    try:
        return str(path.resolve().relative_to(source_root.resolve()))
    except ValueError as exc:
        raise PolicyError("policy path %s is outside source root %s" % (path, source_root)) from exc


def resolve_external_file(path: Optional[Path], source_root: Path, label: str) -> Path:
    if path is None:
        raise PolicyError("an explicit external %s path is required" % label)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = source_root / candidate
    supplied = candidate.parent.resolve() / candidate.name
    resolved = candidate.resolve()
    root = source_root.resolve()
    for location in (supplied, resolved):
        try:
            location.relative_to(root)
        except ValueError:
            continue
        raise PolicyError("release %s must be stored outside the source repository" % label)
    if not resolved.is_file():
        raise PolicyError("explicit %s path does not exist or is not a file: %s" % (label, resolved))
    return resolved


def resolve_external_evidence(path: Optional[Path], source_root: Path) -> Path:
    return resolve_external_file(path, source_root, "evidence")


def validate_artifact_directories(artifact_root: Optional[Path], source_root: Path,
                                  manifest: Dict[str, Any]) -> None:
    if artifact_root is None:
        raise PolicyError("an explicit external artifact directory is required")
    root = Path(artifact_root).resolve()
    try:
        root.relative_to(source_root.resolve())
    except ValueError:
        pass
    else:
        raise PolicyError("release artifact directory must be outside the source repository")
    if not root.is_dir():
        raise PolicyError("external artifact directory does not exist: %s" % root)

    def validate_set(directory_names: Mapping[str, str], digest_map: Mapping[str, str],
                     label: str) -> None:
        for artifact_name, directory_name in directory_names.items():
            directory = root / directory_name
            if not directory.is_dir():
                raise PolicyError("missing %s artifact directory %s" % (label, directory_name))
            files = [path for path in directory.rglob("*") if path.is_file()]
            if len(files) != 1:
                raise PolicyError("%s artifact %s must contain exactly one package" %
                                  (label, artifact_name))
            if file_digest(files[0]) != digest_map[artifact_name]:
                raise PolicyError("%s artifact %s digest does not match manifest" %
                                  (label, artifact_name))

    validate_set(
        UNSIGNED_ARTIFACT_DIRECTORIES, manifest["artifacts"]["unsigned"], "unsigned"
    )
    validate_set(
        SIGNED_ARTIFACT_DIRECTORIES, manifest["artifacts"]["signed"], "signed"
    )


def validate_source_binding(source_root: Path, candidate_commit: str,
                          source_commit: str) -> None:
    if git_output(source_root, ["status", "--porcelain", "--untracked-files=all"]):
        raise PolicyError("release source worktree is not clean")
    head = git_output(source_root, ["rev-parse", "HEAD"]).lower()
    if candidate_commit.lower() != head or source_commit.lower() != head:
        raise PolicyError("source and candidate commits must both equal the immutable checked-out HEAD")


def validate_manifest(manifest: Dict[str, Any], source_root: Path, now: dt.datetime) -> Dict[str, Any]:
    manifest_fields = set(manifest)
    if manifest_fields != REQUIRED_MANIFEST_FIELDS:
        missing = sorted(REQUIRED_MANIFEST_FIELDS - manifest_fields)
        extra = sorted(manifest_fields - REQUIRED_MANIFEST_FIELDS)
        raise PolicyError("release manifest fields do not match schema (missing=%s extra=%s)" % (missing, extra))
    if evidence_int(manifest.get("schema_version"), "manifest.schema_version") != MANIFEST_SCHEMA_VERSION:
        raise PolicyError("release manifest schema version is not supported")
    generated_at = parse_generated_at(manifest.get("generated_at", ""))
    age = now.astimezone(dt.timezone.utc) - generated_at
    if age < dt.timedelta(minutes=-5) or age > MAX_EVIDENCE_AGE:
        raise PolicyError("release manifest is stale or future-dated (age %s)" % age)

    source_commit = str(manifest.get("source_commit", "")).lower()
    candidate_commit = str(manifest.get("candidate_commit", "")).lower()
    if not is_hex(source_commit, (40, 64)):
        raise PolicyError("source_commit in manifest must be a valid commit hash")
    if not is_hex(candidate_commit, (40, 64)):
        raise PolicyError("candidate_commit in manifest must be a valid commit hash")

    for field in (
        "source_build_sha256",
        "candidate_build_sha256",
        "private_audit_sha256",
        "evidence_bundle_sha256",
        "release_gate_evidence_sha256",
        "specification_to_code_attestation_sha256",
        "adversarial_composition_attestation_sha256",
    ):
        if not is_hex(manifest.get(field), (64,)):
            raise PolicyError("manifest field %s must be a 64-char lowercase or mixed-case hex digest" % field)
        reject_obvious_placeholder_sha256(manifest.get(field), "manifest field %s" % field)
    if (str(manifest.get("specification_to_code_attestation_sha256")).lower() ==
            str(manifest.get("adversarial_composition_attestation_sha256")).lower()):
        raise PolicyError("manifest review attestation artifact digests must be distinct")

    release_metadata = validate_release_metadata(manifest, "manifest")
    compiled_shift = configured_mainnet_v5_shift(source_root)
    if release_metadata["mainnet"]["activation_shift"] != compiled_shift:
        raise PolicyError("manifest mainnet activation shift does not match the compiled ladder")

    lead = evidence_int(manifest.get("lead_blocks"), "lead_blocks")
    interval = evidence_int(manifest.get("epoch_interval"), "epoch_interval")
    origin = evidence_int(manifest.get("boundary_origin"), "boundary_origin")
    if (lead, interval, origin) != (REQUIRED_LEAD_BLOCKS, REQUIRED_EPOCH_INTERVAL, REQUIRED_BOUNDARY_ORIGIN):
        raise PolicyError("release manifest does not use fixed 900/300/60 activation policy")

    fork_heights = manifest.get("fork_heights")
    if not isinstance(fork_heights, dict) or set(fork_heights) != REQUIRED_MANIFEST_FORK_FIELDS:
        raise PolicyError("manifest fork-heights fields do not match schema")

    fork_values = {
        field: evidence_int(fork_heights.get(field), "fork_heights.%s" % field)
        for field in REQUIRED_MANIFEST_FORK_FIELDS
    }
    boundary_a_height = fork_values["boundary_a_activation_height"]
    boundary_b_values = (
        fork_values["boundary_b_boundary_a_height"],
        fork_values["boundary_b_candidate_freeze_height"],
        fork_values["boundary_b_recommended_activation_height"],
    )
    if boundary_a_height < 0:
        raise PolicyError("manifest Boundary-A height must be non-negative")
    if boundary_b_values != (-1, -1, -1):
        boundary_b_a, boundary_b_freeze, boundary_b_recommended = boundary_b_values
        if boundary_b_a != boundary_a_height:
            raise PolicyError("manifest Boundary-B arithmetic is not anchored to Boundary A")
        if boundary_b_recommended != required_boundary_b_activation_height(
                boundary_b_a, boundary_b_freeze):
            raise PolicyError("manifest Boundary-B activation is not the first fixed boundary with a 900-block lead")

    common_height = evidence_int(manifest.get("common_height"), "common_height")
    common_hash = str(manifest.get("common_hash", ""))
    if not is_hex(common_hash, (64,)):
        raise PolicyError("manifest common_hash must be a 64-char hex digest")
    reject_obvious_placeholder_sha256(common_hash, "manifest common_hash")

    return {
        "source_commit": source_commit,
        "candidate_commit": candidate_commit,
        "source_build_sha256": str(manifest.get("source_build_sha256")).lower(),
        "candidate_build_sha256": str(manifest.get("candidate_build_sha256")).lower(),
        "private_audit_sha256": str(manifest.get("private_audit_sha256")).lower(),
        "evidence_bundle_sha256": str(manifest.get("evidence_bundle_sha256")).lower(),
        "release_gate_evidence_sha256": str(
            manifest.get("release_gate_evidence_sha256")
        ).lower(),
        "specification_to_code_attestation_sha256": str(
            manifest.get("specification_to_code_attestation_sha256")
        ).lower(),
        "adversarial_composition_attestation_sha256": str(
            manifest.get("adversarial_composition_attestation_sha256")
        ).lower(),
        "fork_heights": fork_values,
        "common_height": common_height,
        "common_hash": common_hash,
        "generated_at": generated_at,
        **release_metadata,
    }


def validate_release_gate_evidence(evidence: Dict[str, Any], manifest: Dict[str, Any],
                                   now: dt.datetime) -> Dict[str, Any]:
    fields = set(evidence)
    if fields != REQUIRED_RELEASE_GATE_EVIDENCE_FIELDS:
        raise PolicyError(
            "release-gate evidence fields do not match schema (missing=%s extra=%s)" %
            (sorted(REQUIRED_RELEASE_GATE_EVIDENCE_FIELDS - fields),
             sorted(fields - REQUIRED_RELEASE_GATE_EVIDENCE_FIELDS))
        )
    if evidence_int(evidence.get("schema_version"), "release_gate.schema_version") != \
            RELEASE_GATE_EVIDENCE_SCHEMA_VERSION:
        raise PolicyError("release-gate evidence schema version is not supported")
    generated_at = parse_generated_at(evidence.get("generated_at"))
    age = now.astimezone(dt.timezone.utc) - generated_at
    if age < dt.timedelta(minutes=-5) or age > MAX_EVIDENCE_AGE:
        raise PolicyError("release-gate evidence is stale or future-dated (age %s)" % age)
    for field in ("source_commit", "candidate_commit"):
        value = str(evidence.get(field, "")).lower()
        if value != manifest[field]:
            raise PolicyError("release-gate evidence %s does not match manifest" % field)
    metadata = validate_release_metadata(evidence, "release_gate")
    for field in ("privacy_vnext", "qt", "mainnet", "artifacts", "signing", "verification"):
        if metadata[field] != manifest[field]:
            raise PolicyError("release-gate evidence %s does not match manifest" % field)
    return metadata


def validate_evidence(evidence: Dict[str, Any], manifest: Dict[str, Any],
                     common_height_expected: int, common_hash_expected: str, now: dt.datetime,
                     configured_height: int) -> Dict[str, Any]:
    evidence_fields = set(evidence)
    if evidence_fields != REQUIRED_EVIDENCE_FIELDS:
        missing_fields = sorted(REQUIRED_EVIDENCE_FIELDS - evidence_fields)
        extra_fields = sorted(evidence_fields - REQUIRED_EVIDENCE_FIELDS)
        raise PolicyError("preflight evidence fields do not match schema (missing=%s extra=%s)" % (missing_fields, extra_fields))

    if evidence.get("schema_version") != PREFLIGHT_SCHEMA_VERSION or evidence.get("passed") is not True:
        raise PolicyError("preflight evidence is absent, stale-schema, or failed")
    if evidence.get("failed_checks") != []:
        raise PolicyError("preflight evidence records failed checks")

    checks = evidence.get("checks")
    provided_checks = set(checks) if isinstance(checks, dict) else set()
    if not isinstance(checks, dict) or provided_checks != REQUIRED_CHECKS:
        missing = sorted(REQUIRED_CHECKS - provided_checks)
        extra = sorted(provided_checks - REQUIRED_CHECKS)
        raise PolicyError("preflight checks do not match schema (missing=%s extra=%s)" % (missing, extra))
    failed = sorted(name for name, value in checks.items() if value is not True)
    if failed:
        raise PolicyError("preflight evidence contains failed checks: %s" % ", ".join(failed))

    generated_at = parse_generated_at(evidence.get("generated_at"))
    age = now.astimezone(dt.timezone.utc) - generated_at
    if age < dt.timedelta(minutes=-5) or age > MAX_EVIDENCE_AGE:
        raise PolicyError("preflight evidence is stale or future-dated (age %s)" % age)

    nodes = evidence.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 4:
        raise PolicyError("preflight evidence must contain exactly four nodes")
    if not all(isinstance(node, dict) for node in nodes):
        raise PolicyError("preflight node entries must be objects")
    if any(set(node) != REQUIRED_NODE_FIELDS for node in nodes):
        raise PolicyError("preflight node fields do not match schema")

    common_height = evidence_int(evidence.get("common_height"), "common_height")
    common_hash = str(evidence.get("common_hash", ""))
    if common_height != common_height_expected or common_hash != common_hash_expected:
        raise PolicyError("preflight evidence is not anchored to manifest chain tip")
    if any(evidence_int(node.get("height"), "nodes.height") != common_height or
           str(node.get("best_hash", "")) != common_hash
           for node in nodes):
        raise PolicyError("four-node height/best-hash values do not match the preflight common tip")

    expected_binary_sha256 = str(evidence.get("expected_binary_sha256", "")).lower()
    node_binary_hashes = {str(node.get("binary_sha256", "")).lower() for node in nodes}
    if not is_hex(expected_binary_sha256, (64,)):
        raise PolicyError("preflight expected binary digest is missing or malformed")
    reject_obvious_placeholder_sha256(expected_binary_sha256, "preflight expected_binary_sha256")
    for index, node in enumerate(nodes):
        reject_obvious_placeholder_sha256(node.get("binary_sha256", ""), "preflight nodes[%d].binary_sha256" % index)
    if node_binary_hashes != {expected_binary_sha256}:
        raise PolicyError("four-node binary digests do not match the expected candidate")
    if expected_binary_sha256 != manifest["candidate_build_sha256"]:
        raise PolicyError("manifest candidate build digest does not match preflight evidence")

    labels = [str(node.get("label", "")) for node in nodes]
    if len(labels) != 4 or any(not label for label in labels) or len(set(labels)) != 4:
        raise PolicyError("preflight evidence node labels are missing or duplicated")
    identities = [str(node.get("node_identity", "")) for node in nodes]
    p2p_identities = [str(node.get("p2p_identity", "")) for node in nodes]
    if (any(not is_hex(value, (64,)) for value in identities + p2p_identities) or
            len(set(identities)) != 4 or len(set(p2p_identities)) != 4):
        raise PolicyError("preflight evidence does not identify four unique node/P2P identities")
    for index, value in enumerate(identities):
        reject_obvious_placeholder_sha256(value, "preflight nodes[%d].node_identity" % index)
    for index, value in enumerate(p2p_identities):
        reject_obvious_placeholder_sha256(value, "preflight nodes[%d].p2p_identity" % index)

    if any(str(node.get("network", "")) != "testnet" for node in nodes):
        raise PolicyError("preflight evidence includes non-testnet node")
    if any(not bool(node.get("p2p_identity_advertised", False)) for node in nodes):
        raise PolicyError("preflight evidence includes a non-advertised P2P identity")
    if any(node.get("height_hash_stable") is not True for node in nodes):
        raise PolicyError("preflight node height/hash snapshot was unstable")
    if any(node.get("initialblockdownload") is not False for node in nodes):
        raise PolicyError("preflight evidence includes a node in IBD")
    if any(bool(node.get("cpumining", False)) is True or bool(node.get("staking", False)) is True for node in nodes):
        raise PolicyError("preflight evidence does not prove controlled mining/staking is paused")
    if any(evidence_int(node.get("mempool_count"), "nodes.mempool_count") != 0 for node in nodes):
        raise PolicyError("preflight evidence includes node with non-empty mempool")
    if any(str(node.get("warnings", "")) for node in nodes):
        raise PolicyError("preflight evidence includes node warnings")
    if any(node.get("dag_active") is not True for node in nodes):
        raise PolicyError("preflight evidence includes an inactive DAG node")
    if any(str(node.get("epoch_state_health", "")) != "ok" for node in nodes):
        raise PolicyError("preflight evidence includes unhealthy epoch state")
    if any(str(node.get("migration_state", "")) != "recovery_idle" for node in nodes):
        raise PolicyError("preflight evidence includes pending/corrupt migration state")
    if any(str(node.get("legacy_anon_status", "")) != "historical_only" for node in nodes):
        raise PolicyError("preflight evidence does not prove legacy ANON is historical-only")
    if any(node.get("legacy_shielded_creation_enabled") is not False for node in nodes):
        raise PolicyError("preflight evidence does not prove legacy privacy creation is disabled")
    if any(node.get("legacy_shielded_consensus_active") is not False for node in nodes):
        raise PolicyError("preflight evidence does not prove legacy privacy is consensus-disabled")
    if any(node.get("legacy_privacy_retired") is not True for node in nodes):
        raise PolicyError("preflight evidence does not prove complete legacy privacy retirement")
    if any(node.get("privacy_vnext_consensus_ready") is not True for node in nodes):
        raise PolicyError("preflight evidence includes a node without reviewed privacy vNext consensus")
    privacy_manifest = manifest["privacy_vnext"]
    for index, node in enumerate(nodes):
        validate_exact_int_list(
            node.get("privacy_vnext_disclosure_modes"),
            REQUIRED_PRIVACY_VNEXT_DISCLOSURE_MODES,
            "nodes[%d].privacy_vnext_disclosure_modes" % index,
        )
        validate_exact_int_list(
            node.get("privacy_vnext_nullstake_generation_ids"),
            REQUIRED_PRIVACY_VNEXT_NULLSTAKE_GENERATION_IDS,
            "nodes[%d].privacy_vnext_nullstake_generation_ids" % index,
        )
    if any(
        evidence_int(node.get("privacy_vnext_abi_version"), "nodes.privacy_vnext_abi_version") !=
            privacy_manifest["abi_version"] or
        str(node.get("privacy_vnext_abi_sha256", "")).lower() != privacy_manifest["abi_sha256"] or
        str(node.get("privacy_vnext_parameter_digest", "")).lower() != privacy_manifest["parameter_digest"] or
        evidence_int(node.get("privacy_vnext_max_inputs"), "nodes.privacy_vnext_max_inputs") !=
            privacy_manifest["max_inputs"] or
        evidence_int(node.get("privacy_vnext_max_outputs"), "nodes.privacy_vnext_max_outputs") !=
            privacy_manifest["max_outputs"] or
        evidence_int(node.get("privacy_vnext_max_payload_bytes"), "nodes.privacy_vnext_max_payload_bytes") !=
            privacy_manifest["max_payload_bytes"] or
        node.get("privacy_vnext_disclosure_modes") != privacy_manifest["disclosure_modes"] or
        node.get("privacy_vnext_nullstake_generation_ids") != privacy_manifest["nullstake_generation_ids"] or
        evidence_int(node.get("privacy_vnext_tree_layers"), "nodes.privacy_vnext_tree_layers") !=
            privacy_manifest["tree_layers"] or
        node.get("privacy_vnext_membership_scope") != privacy_manifest["membership_scope"] or
        node.get("privacy_vnext_post_dag_staking_role") != privacy_manifest["post_dag_staking_role"]
        for node in nodes
    ):
        raise PolicyError("four-node privacy ABI, parameters, resource caps, or product contract differ from manifest")
    if any(node.get("privacy_vnext_supported_operations") !=
           privacy_manifest["supported_operations"] or
           tuple(node.get("privacy_vnext_supported_operations", [])) !=
           REQUIRED_PRIVACY_VNEXT_OPERATIONS for node in nodes):
        raise PolicyError("preflight privacy vNext operation set is incomplete or noncanonical")
    if any(str(node.get("privacy_vnext_wallet_migration_state", "")) != "ready" for node in nodes):
        raise PolicyError("preflight includes a wallet whose privacy vNext migration is not ready")
    vnext_tree_states = {
        (str(node.get("privacy_vnext_tree_root", "")).lower(),
         evidence_int(node.get("privacy_vnext_tree_size"), "nodes.privacy_vnext_tree_size"))
        for node in nodes
    }
    if len(vnext_tree_states) != 1:
        raise PolicyError("four-node privacy vNext tree root/size differs")
    vnext_root, vnext_size = next(iter(vnext_tree_states))
    if not is_hex(vnext_root, (64,)) or vnext_size < 0:
        raise PolicyError("privacy vNext tree root/size is missing or malformed")
    reject_obvious_placeholder_sha256(vnext_root, "preflight privacy_vnext_tree_root")
    if any(node.get("shielded_state_healthy") is not True for node in nodes):
        raise PolicyError("preflight evidence includes unhealthy legacy shielded state")
    if any(not is_zero_amount(node.get("shielded_pool_value")) for node in nodes):
        raise PolicyError("preflight evidence does not prove legacy shielded pool is zero")
    if any(evidence_int(node.get("unspent_notes"), "nodes.unspent_notes") != 0 for node in nodes):
        raise PolicyError("preflight evidence does not prove zero unspent legacy notes")
    if any(str(node.get("privacy_protocol_status", "")) != str(node.get("shielded_privacy_protocol_status", "")) for node in nodes):
        raise PolicyError("preflight privacy health RPCs disagree")

    for node in nodes:
        schema = evidence_int(node.get("schema_version"), "nodes.schema_version")
        required_schema = evidence_int(node.get("required_schema_version"), "nodes.required_schema_version")
        if schema not in (2, 3) or schema != required_schema:
            raise PolicyError("preflight evidence has inconsistent epoch-state schema")
    if any(node.get("schema_marker_present") is not True for node in nodes):
        raise PolicyError("preflight evidence is missing an epoch-state schema marker")
    if any(node.get("deterministic_finalized_height_available") is not True for node in nodes):
        raise PolicyError("preflight evidence lacks deterministic finalized height")

    for node in nodes:
        if (evidence_int(node.get("connected_fleet_peer_count"), "nodes.connected_fleet_peer_count") != 3 or
                evidence_int(node.get("missing_fleet_peer_count"), "nodes.missing_fleet_peer_count") != 0 or
                evidence_int(node.get("banned_fleet_peer_count"), "nodes.banned_fleet_peer_count") != 0):
            raise PolicyError("preflight evidence does not prove a connected, unbanned four-node mesh")

    consensus_health = {
        (str(node.get("dag_best_tip", "")), str(node.get("finality_tier", "")),
         evidence_int(node.get("finalized_height"), "nodes.finalized_height"),
         str(node.get("committee_set_hash", "")))
        for node in nodes
    }
    if len(consensus_health) != 1:
        raise PolicyError("four-node DAG/finality/committee health differs")
    for index, node in enumerate(nodes):
        reject_obvious_placeholder_sha256(node.get("best_hash", ""), "preflight nodes[%d].best_hash" % index)
        reject_obvious_placeholder_sha256(node.get("dag_best_tip", ""), "preflight nodes[%d].dag_best_tip" % index)
        reject_obvious_placeholder_sha256(node.get("committee_set_hash", ""), "preflight nodes[%d].committee_set_hash" % index)

    digest_health = {
        (str(node.get("epoch_state_digest", "")), str(node.get("epoch_curve_root", "")),
         str(node.get("epoch_nullifier_root", "")), str(node.get("epoch_vote_set_root", "")))
        for node in nodes
    }
    if len(digest_health) != 1 or any(
            not is_hex(value, (64,)) for values in digest_health for value in values):
        raise PolicyError("four-node epoch/root digests are missing or differ")
    for index, node in enumerate(nodes):
        for field in ("epoch_state_digest", "epoch_curve_root", "epoch_nullifier_root", "epoch_vote_set_root"):
            reject_obvious_placeholder_sha256(node.get(field, ""), "preflight nodes[%d].%s" % (index, field))

    expected_serializer = str(evidence.get("expected_serializer_schema", ""))
    expected_serializer_version = evidence_int(
        evidence.get("expected_serializer_schema_version"),
        "expected_serializer_schema_version",
    )
    if not expected_serializer or expected_serializer == "legacy_v5_decode" or expected_serializer_version <= 0:
        raise PolicyError("expected canonical serializer schema is missing")
    if any(str(node.get("serializer_schema", "")) != expected_serializer or
           evidence_int(node.get("serializer_schema_version"), "nodes.serializer_schema_version") != expected_serializer_version
           for node in nodes):
        raise PolicyError("four-node serializer schema does not match the expected candidate")

    activation = evidence_int(evidence.get("activation_height"), "activation_height")
    lead = evidence_int(evidence.get("lead_blocks"), "lead_blocks")
    interval = evidence_int(evidence.get("epoch_interval"), "epoch_interval")
    origin = evidence_int(evidence.get("boundary_origin"), "boundary_origin")
    if (lead, interval, origin) != (
            REQUIRED_LEAD_BLOCKS, REQUIRED_EPOCH_INTERVAL, REQUIRED_BOUNDARY_ORIGIN):
        raise PolicyError("preflight release parameters are not the fixed 900/300/60 policy")
    if activation != configured_height:
        raise PolicyError("source activation %d does not match configured height %d" % (activation, configured_height))
    # Boundary A is checked in validate_testnet_activation_ladder(). A remined testnet
    # needs no 900-block lead over the tip; Boundary B still does, below.
    if common_height < 0:
        raise PolicyError("preflight common height must be non-negative")

    if any(node.get("boundary_a_configured") is not True or
           evidence_int(node.get("boundary_a_activation_height"), "nodes.boundary_a_activation_height") != activation or
           node.get("boundary_a_active") is not (common_height >= activation)
           for node in nodes):
        raise PolicyError("four-node Boundary A status does not match the scheduled activation")

    fork = manifest["fork_heights"]
    boundary_b_available_value = evidence.get("boundary_b_calculation_available")
    if boundary_b_available_value is not True and boundary_b_available_value is not False:
        raise PolicyError("preflight Boundary-B calculation availability must be boolean")
    boundary_b_available = boundary_b_available_value is True
    boundary_b_values = (
        evidence_int(evidence.get("boundary_b_boundary_a_height"), "evidence.boundary_b_boundary_a_height"),
        evidence_int(evidence.get("boundary_b_candidate_freeze_height"), "evidence.boundary_b_candidate_freeze_height"),
        evidence_int(evidence.get("boundary_b_recommended_activation_height"), "evidence.boundary_b_recommended_activation_height"),
    )
    manifested_boundary_b_values = (
        fork["boundary_b_boundary_a_height"],
        fork["boundary_b_candidate_freeze_height"],
        fork["boundary_b_recommended_activation_height"],
    )
    if boundary_b_values != manifested_boundary_b_values:
        raise PolicyError("manifest Boundary-B heights do not match preflight evidence")
    if boundary_b_available:
        boundary_b_a, boundary_b_freeze, boundary_b_recommended = boundary_b_values
        if boundary_b_a != activation:
            raise PolicyError("preflight Boundary-B calculation is not anchored to Boundary A")
        if boundary_b_recommended != required_boundary_b_activation_height(
                boundary_b_a, boundary_b_freeze):
            raise PolicyError("preflight Boundary-B activation is not the first fixed boundary with a 900-block lead")
    elif boundary_b_values != (-1, -1, -1):
        raise PolicyError("preflight marks Boundary-B arithmetic unavailable but supplies heights")

    boundary_b_configured = [node.get("boundary_b_configured") for node in nodes]
    if boundary_b_available:
        if not all(value is True for value in boundary_b_configured):
            raise PolicyError("final Boundary-B arithmetic requires all four nodes to report it configured")
        boundary_b_recommended = boundary_b_values[2]
        if any(evidence_int(node.get("boundary_b_activation_height"), "nodes.boundary_b_activation_height") !=
               boundary_b_recommended or
               node.get("boundary_b_active") is not (common_height >= boundary_b_recommended)
               for node in nodes):
            raise PolicyError("four-node Boundary-B status does not match the recomputed activation")
    else:
        if not all(value is False for value in boundary_b_configured):
            raise PolicyError("Boundary B without final arithmetic must remain unconfigured on all four nodes")
        if any(node.get("boundary_b_active") is not False or
               evidence_int(node.get("boundary_b_activation_height"), "nodes.boundary_b_activation_height") != UNSET
               for node in nodes):
            raise PolicyError("unconfigured Boundary B must remain inactive at the unset sentinel")

    snapshot = evidence.get("snapshot_manifest")
    if not isinstance(snapshot, dict) or set(snapshot) != REQUIRED_SNAPSHOT_MANIFEST_FIELDS or \
            evidence_int(snapshot.get("schema_version"), "snapshot_manifest.schema_version") != SNAPSHOT_MANIFEST_SCHEMA_VERSION:
        raise PolicyError("snapshot completion manifest is missing or malformed")
    snapshot_nodes = snapshot.get("nodes")
    if not isinstance(snapshot_nodes, list) or len(snapshot_nodes) != 4 or \
            any(not isinstance(node, dict) or set(node) != REQUIRED_SNAPSHOT_NODE_FIELDS for node in snapshot_nodes):
        raise PolicyError("snapshot manifest must contain four exact node records")

    snapshot_by_label = {str(node.get("label", "")): node for node in snapshot_nodes}
    if set(snapshot_by_label) != set(labels):
        raise PolicyError("snapshot manifest labels do not match the four-node preflight")

    reject_obvious_placeholder_sha256(snapshot.get("common_hash", ""), "snapshot_manifest.common_hash")

    if evidence_int(snapshot.get("common_height"), "snapshot.common_height") != common_height or \
            str(snapshot.get("common_hash", "")) != common_hash_expected:
        raise PolicyError("snapshot manifest is not anchored to the preflight chain tip")

    for label in labels:
        snap = snapshot_by_label[label]
        reject_obvious_placeholder_sha256(snap.get("best_hash", ""), "snapshot_manifest.nodes[%s].best_hash" % label)
        reject_obvious_placeholder_sha256(
            snap.get("chain_snapshot_sha256", ""),
            "snapshot_manifest.nodes[%s].chain_snapshot_sha256" % label,
        )
        reject_obvious_placeholder_sha256(
            snap.get("wallet_snapshot_sha256", ""),
            "snapshot_manifest.nodes[%s].wallet_snapshot_sha256" % label,
        )
        if (snap.get("chain_snapshot_complete") is not True or
                snap.get("wallet_snapshot_complete") is not True or
                not is_hex(snap.get("chain_snapshot_sha256", ""), (64,)) or
                not is_hex(snap.get("wallet_snapshot_sha256", ""), (64,)) or
                evidence_int(snap.get("height"), "snapshot.nodes.height") != common_height or
                str(snap.get("best_hash", "")) != common_hash_expected):
            raise PolicyError("snapshot manifest contains incomplete/unbound node backups")

    snapshot_digest = str(evidence.get("snapshot_manifest_sha256", ""))
    if not is_hex(snapshot_digest, (64,)) or snapshot_digest != canonical_digest(snapshot):
        raise PolicyError("snapshot manifest digest is missing or incorrect")
    reject_obvious_placeholder_sha256(snapshot_digest, "preflight snapshot_manifest_sha256")

    snapshot_time = parse_generated_at(snapshot.get("completed_at"))
    if snapshot_time > generated_at + dt.timedelta(minutes=5) or generated_at - snapshot_time > MAX_EVIDENCE_AGE:
        raise PolicyError("snapshot manifest is stale or post-dates preflight evidence")

    source_commit = str(evidence.get("source_commit", "")).lower()
    artifact_source_commit = str(evidence.get("artifact_source_commit", "")).lower()
    if (not is_hex(source_commit, (40, 64)) or artifact_source_commit != source_commit):
        raise PolicyError("preflight does not bind build to one valid source commit")
    if source_commit != manifest["source_commit"]:
        raise PolicyError("preflight source commit does not match manifest source_commit")

    expected_build = str(evidence.get("expected_candidate_build_identifier", ""))
    build_ids = {str(node.get("candidate_build_identifier", "")) for node in nodes}
    if (not expected_build or build_ids != {expected_build} or
            source_commit not in expected_build.lower() or
            "dirty" in expected_build.lower()):
        raise PolicyError("candidate build identifier is not exactly bound to the source commit")

    if fork["boundary_a_activation_height"] != activation:
        raise PolicyError("manifest Boundary-A height does not match preflight recommendation")

    return {
        "activation_height": activation,
        "common_height": common_height,
        "common_hash": common_hash_expected,
        "source_commit": source_commit,
    }


def validate_review_attestation(attestation: Dict[str, Any], expected_lane: str,
                                manifest: Dict[str, Any]) -> str:
    fields = set(attestation)
    if fields != REQUIRED_REVIEW_ATTESTATION_FIELDS:
        missing = sorted(REQUIRED_REVIEW_ATTESTATION_FIELDS - fields)
        extra = sorted(fields - REQUIRED_REVIEW_ATTESTATION_FIELDS)
        raise PolicyError("%s review attestation fields do not match schema (missing=%s extra=%s)" %
                          (expected_lane, missing, extra))
    schema_version = attestation.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != REVIEW_ATTESTATION_SCHEMA_VERSION:
        raise PolicyError("%s review attestation schema version is not supported" % expected_lane)
    if str(attestation.get("review_lane", "")) != expected_lane:
        raise PolicyError("review attestation lane does not match %s" % expected_lane)
    if str(attestation.get("verdict", "")) != "GO":
        raise PolicyError("%s review attestation does not contain an exact GO verdict" % expected_lane)

    reviewer_identity = str(attestation.get("reviewer_identity_sha256", "")).lower()
    if not is_hex(reviewer_identity, (64,)):
        raise PolicyError("%s review attestation has a malformed reviewer identity digest" % expected_lane)
    reject_obvious_placeholder_sha256(
        reviewer_identity, "%s reviewer identity" % expected_lane
    )

    for field in ("source_commit", "candidate_commit"):
        value = str(attestation.get(field, "")).lower()
        if not is_hex(value, (40, 64)) or value != manifest[field]:
            raise PolicyError("%s review attestation %s does not match the manifest" %
                              (expected_lane, field))
    for field in ("source_build_sha256", "candidate_build_sha256"):
        value = str(attestation.get(field, "")).lower()
        if not is_hex(value, (64,)):
            raise PolicyError("%s review attestation %s is malformed" % (expected_lane, field))
        reject_obvious_placeholder_sha256(value, "%s review attestation %s" % (expected_lane, field))
        if value != manifest[field]:
            raise PolicyError("%s review attestation %s does not match the manifest" %
                              (expected_lane, field))
    parameter_digest = validated_digest(
        attestation.get("privacy_parameter_digest"),
        "%s review attestation privacy_parameter_digest" % expected_lane,
    )
    abi_digest = validated_digest(
        attestation.get("privacy_abi_sha256"),
        "%s review attestation privacy_abi_sha256" % expected_lane,
    )
    if parameter_digest != manifest["privacy_vnext"]["parameter_digest"]:
        raise PolicyError("%s review attestation parameter digest does not match the manifest" % expected_lane)
    if abi_digest != manifest["privacy_vnext"]["abi_sha256"]:
        raise PolicyError("%s review attestation ABI digest does not match the manifest" % expected_lane)
    if attestation.get("upstream_gbp_external_audit") is not False or \
            attestation.get("upstream_gbp_risk_disclosed") is not True:
        raise PolicyError("%s review attestation does not preserve the upstream GBP risk disclosure" % expected_lane)
    review_shift = evidence_int(
        attestation.get("mainnet_activation_shift"),
        "%s review attestation mainnet_activation_shift" % expected_lane,
    )
    if review_shift != manifest["mainnet"]["activation_shift"]:
        raise PolicyError("%s review attestation mainnet shift does not match the manifest" % expected_lane)
    trusted_tip_hash = validated_digest(
        attestation.get("mainnet_trusted_tip_hash"),
        "%s review attestation mainnet_trusted_tip_hash" % expected_lane,
    )
    if trusted_tip_hash != manifest["mainnet"]["trusted_tip_hash"]:
        raise PolicyError("%s review attestation mainnet tip does not match the manifest" % expected_lane)
    return reviewer_identity


def validate(main_h: Path,
             manifest_path: Optional[Path] = None,
             evidence_path: Optional[Path] = None,
             release_gate_evidence_path: Optional[Path] = None,
             artifact_directory: Optional[Path] = None,
             source_artifact_path: Optional[Path] = None,
             specification_attestation_path: Optional[Path] = None,
             adversarial_attestation_path: Optional[Path] = None,
             private_audit_sha256: Optional[str] = None,
             source_root: Path = Path("."),
             now: Optional[dt.datetime] = None) -> Dict[str, Any]:
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)

    external_manifest = resolve_external_file(manifest_path, source_root, "candidate manifest")
    manifest = validate_manifest(load_manifest(external_manifest), source_root, now)

    release_gate_evidence_file = resolve_external_file(
        release_gate_evidence_path, source_root, "release-gate evidence"
    )
    release_gate_evidence, release_gate_evidence_digest = load_evidence(
        release_gate_evidence_file
    )
    if release_gate_evidence_digest != manifest["release_gate_evidence_sha256"]:
        raise PolicyError("release-gate evidence digest does not match manifest")
    validate_release_gate_evidence(release_gate_evidence, manifest, now)
    validate_artifact_directories(artifact_directory, source_root, manifest)

    supplied_audit_sha256 = str(private_audit_sha256 or "").lower()
    if not is_hex(supplied_audit_sha256, (64,)):
        raise PolicyError("an explicit private-audit SHA-256 digest is required")
    reject_obvious_placeholder_sha256(supplied_audit_sha256, "supplied private-audit digest")
    if supplied_audit_sha256 != manifest["private_audit_sha256"]:
        raise PolicyError("supplied private-audit digest does not match manifest")

    source_artifact = resolve_external_file(source_artifact_path, source_root, "source artifact")
    try:
        if source_artifact.stat().st_size <= 0:
            raise PolicyError("external source artifact must be non-empty")
    except OSError as exc:
        raise PolicyError("cannot inspect external source artifact: %s" % exc) from exc
    source_artifact_digest = file_digest(source_artifact)
    if source_artifact_digest != manifest["source_build_sha256"]:
        raise PolicyError("external source artifact digest does not match manifest source_build_sha256")

    specification_attestation = resolve_external_file(
        specification_attestation_path, source_root, "specification-to-code review attestation"
    )
    adversarial_attestation = resolve_external_file(
        adversarial_attestation_path, source_root, "adversarial-composition review attestation"
    )
    specification_review, specification_digest = load_evidence(specification_attestation)
    adversarial_review, adversarial_digest = load_evidence(adversarial_attestation)
    if specification_digest != manifest["specification_to_code_attestation_sha256"]:
        raise PolicyError("specification-to-code review artifact digest does not match manifest")
    if adversarial_digest != manifest["adversarial_composition_attestation_sha256"]:
        raise PolicyError("adversarial-composition review artifact digest does not match manifest")
    if len({source_artifact_digest, specification_digest, adversarial_digest}) != 3:
        raise PolicyError("source and review artifacts must have three distinct digests")

    specification_reviewer = validate_review_attestation(
        specification_review, SPECIFICATION_REVIEW_LANE, manifest
    )
    adversarial_reviewer = validate_review_attestation(
        adversarial_review, ADVERSARIAL_REVIEW_LANE, manifest
    )
    if specification_reviewer == adversarial_reviewer:
        raise PolicyError("the two internal GO attestations must name distinct reviewer identities")

    evidence_path = resolve_external_evidence(evidence_path, source_root)

    ladder = validate_testnet_activation_ladder(main_h)
    height = ladder["boundary_a"]
    if height == UNSET:
        raise PolicyError("public-testnet schema-V3 activation is unset (0x7fffffff)")

    evidence, evidence_digest = load_evidence(evidence_path)
    if evidence_digest != manifest["evidence_bundle_sha256"]:
        raise PolicyError("evidence bundle digest does not match manifest")
    result = validate_evidence(
        evidence,
        manifest,
        manifest["common_height"],
        manifest["common_hash"],
        now,
        height,
    )

    validate_source_binding(source_root, manifest["candidate_commit"], result["source_commit"])
    return {
        "activation_height": result["activation_height"],
        "common_height": result["common_height"],
        "common_hash": result["common_hash"],
    }


def selftest() -> int:
    with tempfile.TemporaryDirectory(prefix="innova-release-policy-") as tmp:
        workspace = Path(tmp)
        root = workspace / "source"
        private_dir = workspace / "private"
        artifact_dir = workspace / "artifacts"
        now = dt.datetime.now(dt.timezone.utc)
        main_h = root / "src" / "main.h"
        finality_h = root / "src" / "finality.h"
        activation_h = root / "src" / "v5activation.h"
        evidence = private_dir / "v5-testnet-v3-preflight.json"
        release_gate_evidence = private_dir / "v5-release-gate-evidence.json"
        source_artifact = private_dir / "innova-v5-source.tar"
        specification_attestation = private_dir / "specification-to-code-review.json"
        adversarial_attestation = private_dir / "adversarial-composition-review.json"
        manifest = private_dir / "v5-release-candidate-manifest.json"

        main_h.parent.mkdir(parents=True, exist_ok=True)
        private_dir.mkdir(parents=True, exist_ok=True)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        manifest.parent.mkdir(parents=True, exist_ok=True)

        def fixture_sha256(label: str) -> str:
            return hashlib.sha256(("v5-release-policy-selftest:" + label).encode("utf-8")).hexdigest()

        common_hash = fixture_sha256("common-chain-tip")
        binary_sha256 = fixture_sha256("candidate-binary")
        audit_sha256 = fixture_sha256("private-audit")
        specification_reviewer = fixture_sha256("specification-reviewer-identity")
        adversarial_reviewer = fixture_sha256("adversarial-reviewer-identity")

        source_artifact.write_bytes(b"fixture immutable source artifact\n")

        # Fixture ladder: Boundary A one post-DAG epoch above the DAG fork, aliased to V3.
        main_h.write_text(
            "static const int TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET = 0x7fffffff;\n"
            "static const int TESTNET_EPOCH_STATE_V3_HEIGHT = 1260;\n"
            "static const int PRIVACY_VNEXT_HEIGHT_UNSET = 0x7fffffff;\n"
            "inline int GetForkHeightFinality()\n{\n if (fTestNet) return 955;\n return 7945000;\n}\n"
            "inline int GetForkHeightDAG()\n{\n if (fTestNet) return 960;\n return 7950000;\n}\n"
            "inline int GetForkHeightEpochStateV3()\n"
            "{\n if (fTestNet) return TESTNET_EPOCH_STATE_V3_HEIGHT;\n"
            " return GetForkHeightDAG() + 300;\n}\n"
            "inline int GetForkHeightBoundaryA()\n{\n return GetForkHeightEpochStateV3();\n}\n"
            "inline int GetForkHeightBoundaryB()\n"
            "{\n return fRegTest ? nRegtestBoundaryBHeight : PRIVACY_VNEXT_HEIGHT_UNSET;\n}\n",
            encoding="utf-8",
        )
        finality_h.write_text(
            "static const int FINALITY_EPOCH_INTERVAL_POST_DAG = 300;\n",
            encoding="utf-8",
        )
        activation_h.write_text(
            "static const int MAINNET_V5_ACTIVATION_SHIFT = 0;\n",
            encoding="utf-8",
        )

        snapshot = {
            "schema_version": SNAPSHOT_MANIFEST_SCHEMA_VERSION,
            "completed_at": (now - dt.timedelta(minutes=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "common_height": 360,
            "common_hash": common_hash,
            "nodes": [
                {
                    "label": "n%d" % idx,
                    "height": 360,
                    "best_hash": common_hash,
                    "chain_snapshot_complete": True,
                    "chain_snapshot_sha256": fixture_sha256("chain-snapshot-%d" % idx),
                    "wallet_snapshot_complete": True,
                    "wallet_snapshot_sha256": fixture_sha256("wallet-snapshot-%d" % idx),
                }
                for idx in range(4)
            ],
        }

        payload = {
            "schema_version": PREFLIGHT_SCHEMA_VERSION,
            "generated_at": (now - dt.timedelta(minutes=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "source_commit": "",  # filled after source commit known
            "artifact_source_commit": "",
            "expected_binary_sha256": binary_sha256,
            "expected_candidate_build_identifier": "innova-v5-gplaceholder",
            "expected_serializer_schema": "boundary_a_canonical_v1",
            "expected_serializer_schema_version": 1,
            "passed": True,
            "failed_checks": [],
            "checks": {name: True for name in REQUIRED_CHECKS},
            "common_height": 360,
            "common_hash": common_hash,
            "activation_height": 1260,
            "lead_blocks": REQUIRED_LEAD_BLOCKS,
            "epoch_interval": REQUIRED_EPOCH_INTERVAL,
            "boundary_origin": REQUIRED_BOUNDARY_ORIGIN,
            "boundary_b_calculation_available": False,
            "boundary_b_boundary_a_height": -1,
            "boundary_b_candidate_freeze_height": -1,
            "boundary_b_recommended_activation_height": -1,
            "snapshot_manifest": snapshot,
            "snapshot_manifest_sha256": canonical_digest(snapshot),
            "nodes": [
                {
                    "label": "n%d" % idx,
                    "network": "testnet",
                    "node_identity": fixture_sha256("node-identity-%d" % idx),
                    "p2p_identity": fixture_sha256("p2p-identity-%d" % idx),
                    "p2p_identity_advertised": True,
                    "height": 360,
                    "height_hash_stable": True,
                    "best_hash": common_hash,
                    "initialblockdownload": False,
                    "cpumining": False,
                    "staking": False,
                    "warnings": "",
                    "dag_active": True,
                    "dag_best_tip": fixture_sha256("dag-best-tip"),
                    "finality_tier": "hard",
                    "finalized_height": 300,
                    "epoch_state_health": "ok",
                    "schema_version": 3,
                    "required_schema_version": 3,
                    "schema_marker_present": True,
                    "deterministic_finalized_height_available": True,
                    "committee_set_hash": fixture_sha256("committee-set"),
                    "epoch_state_digest": fixture_sha256("epoch-state"),
                    "epoch_curve_root": fixture_sha256("epoch-curve-root"),
                    "epoch_nullifier_root": fixture_sha256("epoch-nullifier-root"),
                    "epoch_vote_set_root": fixture_sha256("epoch-vote-set-root"),
                    "boundary_a_activation_height": 1260,
                    "boundary_a_configured": True,
                    "boundary_a_active": False,
                    "boundary_b_activation_height": 0x7fffffff,
                    "boundary_b_configured": False,
                    "boundary_b_active": False,
                    "candidate_build_identifier": "innova-v5-gplaceholder",
                    "serializer_schema": "boundary_a_canonical_v1",
                    "serializer_schema_version": 1,
                    "migration_state": "recovery_idle",
                    "legacy_anon_status": "historical_only",
                    "privacy_protocol_status": "legacy_creation_disabled",
                    "shielded_privacy_protocol_status": "legacy_creation_disabled",
                    "legacy_shielded_creation_enabled": False,
                    "legacy_shielded_consensus_active": False,
                    "legacy_privacy_retired": True,
                    "privacy_vnext_consensus_ready": True,
                    "privacy_vnext_abi_version": 1,
                    "privacy_vnext_abi_sha256": fixture_sha256("privacy-abi"),
                    "privacy_vnext_disclosure_modes": list(REQUIRED_PRIVACY_VNEXT_DISCLOSURE_MODES),
                    "privacy_vnext_parameter_digest": fixture_sha256("privacy-parameters"),
                    "privacy_vnext_tree_root": fixture_sha256("privacy-vnext-tree-root"),
                    "privacy_vnext_tree_size": 0,
                    "privacy_vnext_tree_layers": REQUIRED_PRIVACY_VNEXT_TREE_LAYERS,
                    "privacy_vnext_max_inputs": 16,
                    "privacy_vnext_max_outputs": 16,
                    "privacy_vnext_max_payload_bytes": 256 * 1024,
                    "privacy_vnext_membership_scope": REQUIRED_PRIVACY_VNEXT_MEMBERSHIP_SCOPE,
                    "privacy_vnext_nullstake_generation_ids": list(
                        REQUIRED_PRIVACY_VNEXT_NULLSTAKE_GENERATION_IDS
                    ),
                    "privacy_vnext_post_dag_staking_role": REQUIRED_PRIVACY_VNEXT_POST_DAG_STAKING_ROLE,
                    "privacy_vnext_supported_operations": list(REQUIRED_PRIVACY_VNEXT_OPERATIONS),
                    "privacy_vnext_wallet_migration_state": "ready",
                    "shielded_state_healthy": True,
                    "shielded_pool_value": "0.00000000",
                    "commitment_tree_size": 0,
                    "unspent_notes": 0,
                    "mempool_count": 0,
                    "peer_count": 3,
                    "binary_sha256": binary_sha256,
                    "connected_fleet_peer_count": 3,
                    "missing_fleet_peer_count": 0,
                    "banned_fleet_peer_count": 0,
                }
                for idx in range(4)
            ],
        }

        git_output(root, ["init", "-q"])
        git_output(root, ["config", "user.email", "release-policy@example.invalid"])
        git_output(root, ["config", "user.name", "Release Policy Selftest"])
        git_output(root, ["add", "src/main.h", "src/finality.h", "src/v5activation.h"])
        git_output(root, ["commit", "-q", "-m", "fixture source"])
        source_commit = git_output(root, ["rev-parse", "HEAD"])

        payload["source_commit"] = source_commit
        payload["artifact_source_commit"] = source_commit
        payload["expected_binary_sha256"] = binary_sha256
        build_id = "innova-v5-g%s" % source_commit
        payload["expected_candidate_build_identifier"] = build_id
        for node in payload["nodes"]:
            node["candidate_build_identifier"] = build_id

        source_artifact_sha256 = file_digest(source_artifact)
        unsigned_artifact_hashes: Dict[str, str] = {}
        for name, directory_name in UNSIGNED_ARTIFACT_DIRECTORIES.items():
            package_dir = artifact_dir / directory_name
            package_dir.mkdir()
            package = package_dir / (name + ".package")
            package.write_bytes(("unsigned:" + name).encode("utf-8"))
            unsigned_artifact_hashes[name] = file_digest(package)
        signed_artifact_hashes: Dict[str, str] = {}
        for name, directory_name in SIGNED_ARTIFACT_DIRECTORIES.items():
            package_dir = artifact_dir / directory_name
            package_dir.mkdir()
            package = package_dir / (name + ".signed.package")
            package.write_bytes(("signed:" + name).encode("utf-8"))
            signed_artifact_hashes[name] = file_digest(package)
        release_metadata = {
            "privacy_vnext": {
                "abi_sha256": fixture_sha256("privacy-abi"),
                "abi_version": 1,
                "benchmark_evidence_sha256": fixture_sha256("privacy-benchmark"),
                "cargo_lock_sha256": fixture_sha256("cargo-lock"),
                "consensus_enabled": True,
                "disclosure_modes": list(REQUIRED_PRIVACY_VNEXT_DISCLOSURE_MODES),
                "max_inputs": 16,
                "max_outputs": 16,
                "max_payload_bytes": 256 * 1024,
                "membership_scope": REQUIRED_PRIVACY_VNEXT_MEMBERSHIP_SCOPE,
                "nullstake_generation_ids": list(REQUIRED_PRIVACY_VNEXT_NULLSTAKE_GENERATION_IDS),
                "parameter_digest": fixture_sha256("privacy-parameters"),
                "post_dag_staking_role": REQUIRED_PRIVACY_VNEXT_POST_DAG_STAKING_ROLE,
                "rust_toolchain_sha256": fixture_sha256("rust-toolchain"),
                "rust_version": PINNED_RUST_VERSION,
                "supported_operations": list(REQUIRED_PRIVACY_VNEXT_OPERATIONS),
                "tree_layers": REQUIRED_PRIVACY_VNEXT_TREE_LAYERS,
                "upstream_commit": PINNED_MONERO_OXIDE_COMMIT,
                "upstream_gbp_external_audit": False,
                "upstream_gbp_risk_disclosed": True,
                "vendored_source_sha256": fixture_sha256("vendored-source"),
            },
            "qt": {
                "release_version": RELEASE_QT_VERSION,
                "compatibility_version": COMPAT_QT_VERSION,
            },
            "mainnet": {
                "trusted_tip_height": 7_700_000,
                "trusted_tip_hash": fixture_sha256("mainnet-trusted-tip"),
                "trusted_tip_evidence_sha256": fixture_sha256("mainnet-tip-evidence"),
                "minimum_lead_blocks": MAINNET_ACTIVATION_MIN_LEAD_BLOCKS,
                "shift_granularity": MAINNET_ACTIVATION_SHIFT_GRANULARITY,
                "activation_shift": 0,
                "first_v5_gate": 7_800_000,
                "boundary_b_slot": 8_060_000,
            },
            "artifacts": {
                "unsigned": {
                    name: unsigned_artifact_hashes[name]
                    for name in UNSIGNED_ARTIFACT_NAMES
                },
                "signed": {
                    name: signed_artifact_hashes[name]
                    for name in SIGNED_ARTIFACT_NAMES
                },
            },
            "signing": {
                name: fixture_sha256("signing:" + name)
                for name in REQUIRED_SIGNING_FIELDS
            },
            "verification": {
                name: fixture_sha256("verification:" + name)
                for name in REQUIRED_VERIFICATION_FIELDS
            },
        }
        release_gate_payload = {
            "schema_version": RELEASE_GATE_EVIDENCE_SCHEMA_VERSION,
            "generated_at": (now - dt.timedelta(minutes=1)).replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z"),
            "source_commit": source_commit,
            "candidate_commit": source_commit,
            **release_metadata,
        }
        release_gate_evidence.write_text(
            json.dumps(release_gate_payload), encoding="utf-8"
        )
        specification_review = {
            "schema_version": REVIEW_ATTESTATION_SCHEMA_VERSION,
            "review_lane": SPECIFICATION_REVIEW_LANE,
            "verdict": "GO",
            "reviewer_identity_sha256": specification_reviewer,
            "source_commit": source_commit,
            "candidate_commit": source_commit,
            "source_build_sha256": source_artifact_sha256,
            "candidate_build_sha256": binary_sha256,
            "privacy_parameter_digest": release_metadata["privacy_vnext"]["parameter_digest"],
            "privacy_abi_sha256": release_metadata["privacy_vnext"]["abi_sha256"],
            "upstream_gbp_external_audit": False,
            "upstream_gbp_risk_disclosed": True,
            "mainnet_activation_shift": release_metadata["mainnet"]["activation_shift"],
            "mainnet_trusted_tip_hash": release_metadata["mainnet"]["trusted_tip_hash"],
        }
        adversarial_review = dict(specification_review)
        adversarial_review["review_lane"] = ADVERSARIAL_REVIEW_LANE
        adversarial_review["reviewer_identity_sha256"] = adversarial_reviewer
        specification_attestation.write_text(json.dumps(specification_review), encoding="utf-8")
        adversarial_attestation.write_text(json.dumps(adversarial_review), encoding="utf-8")
        evidence.write_text(json.dumps(payload), encoding="utf-8")

        manifest_payload = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "generated_at": (now - dt.timedelta(minutes=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "source_commit": source_commit,
            "candidate_commit": source_commit,
            "source_build_sha256": source_artifact_sha256,
            "candidate_build_sha256": binary_sha256,
            "lead_blocks": REQUIRED_LEAD_BLOCKS,
            "epoch_interval": REQUIRED_EPOCH_INTERVAL,
            "boundary_origin": REQUIRED_BOUNDARY_ORIGIN,
            "fork_heights": {
                "boundary_a_activation_height": 1260,
                "boundary_b_candidate_freeze_height": -1,
                "boundary_b_recommended_activation_height": -1,
                "boundary_b_boundary_a_height": -1,
            },
            "common_height": 360,
            "common_hash": common_hash,
            "evidence_bundle_sha256": file_digest(evidence),
            "release_gate_evidence_sha256": file_digest(release_gate_evidence),
            "private_audit_sha256": audit_sha256,
            "specification_to_code_attestation_sha256": file_digest(specification_attestation),
            "adversarial_composition_attestation_sha256": file_digest(adversarial_attestation),
            **release_metadata,
        }
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        assert validate(
            main_h,
            manifest_path=manifest,
            evidence_path=evidence,
            release_gate_evidence_path=release_gate_evidence,
            artifact_directory=artifact_dir,
            source_artifact_path=source_artifact,
            specification_attestation_path=specification_attestation,
            adversarial_attestation_path=adversarial_attestation,
            private_audit_sha256=audit_sha256,
            source_root=root,
        )["activation_height"] == 1260

        def expect_failure(message: str,
                           evidence_override: Optional[Path] = evidence,
                           release_gate_evidence_override: Optional[Path] = release_gate_evidence,
                           artifact_directory_override: Optional[Path] = artifact_dir,
                           source_artifact_override: Optional[Path] = source_artifact,
                           specification_override: Optional[Path] = specification_attestation,
                           adversarial_override: Optional[Path] = adversarial_attestation,
                           audit_override: Optional[str] = audit_sha256,
                           expected_error: Optional[str] = None) -> None:
            try:
                validate(
                    main_h,
                    manifest_path=manifest,
                    evidence_path=evidence_override,
                    release_gate_evidence_path=release_gate_evidence_override,
                    artifact_directory=artifact_directory_override,
                    source_artifact_path=source_artifact_override,
                    specification_attestation_path=specification_override,
                    adversarial_attestation_path=adversarial_override,
                    private_audit_sha256=audit_override,
                    source_root=root,
                )
            except PolicyError as exc:
                if expected_error is not None and expected_error not in str(exc):
                    raise AssertionError("%s (unexpected error: %s)" % (message, exc))
                return
            raise AssertionError(message)

        # The structural placement rules read the tree, so mutate the tree to prove them.
        clean_main_h = main_h.read_text(encoding="utf-8")
        try:
            main_h.write_text(
                clean_main_h.replace("TESTNET_EPOCH_STATE_V3_HEIGHT = 1260;",
                                     "TESTNET_EPOCH_STATE_V3_HEIGHT = 1560;"),
                encoding="utf-8")
            expect_failure("Boundary A off the first post-DAG epoch passed release policy",
                           expected_error="one post-DAG epoch above the DAG fork")
            main_h.write_text(
                clean_main_h.replace(" return GetForkHeightEpochStateV3();",
                                     " return TESTNET_EPOCH_STATE_V3_HEIGHT;"),
                encoding="utf-8")
            expect_failure("Boundary A detached from schema V3 passed release policy",
                           expected_error="not an alias of the schema-V3 height")
            main_h.write_text(
                clean_main_h.replace("if (fTestNet) return 955;",
                                     "if (fTestNet) return 1000;"),
                encoding="utf-8")
            expect_failure("out-of-order testnet fork ladder passed release policy",
                           expected_error="fork ladder is out of order")
        finally:
            main_h.write_text(clean_main_h, encoding="utf-8")

        clean_finality_h = finality_h.read_text(encoding="utf-8")
        try:
            finality_h.write_text(
                clean_finality_h.replace("= 300;", "= 600;"), encoding="utf-8")
            expect_failure("non-fixed post-DAG epoch interval passed release policy",
                           expected_error="post-DAG epoch interval")
        finally:
            finality_h.write_text(clean_finality_h, encoding="utf-8")

        expect_failure("missing evidence passed release policy", evidence_override=None,
                       expected_error="explicit external evidence path")
        expect_failure("missing release-gate evidence passed release policy",
                       release_gate_evidence_override=None,
                       expected_error="explicit external release-gate evidence path")
        expect_failure("missing artifact directory passed release policy",
                       artifact_directory_override=None,
                       expected_error="explicit external artifact directory")
        expect_failure("missing private-audit digest passed release policy", audit_override=None,
                       expected_error="explicit private-audit SHA-256")
        expect_failure("mismatched private-audit digest passed release policy",
                       audit_override=fixture_sha256("different-private-audit"),
                       expected_error="does not match manifest")
        expect_failure("placeholder supplied private-audit digest passed release policy",
                       audit_override="a5" * 32,
                       expected_error="obvious placeholder SHA-256")
        expect_failure("missing source artifact passed release policy",
                       source_artifact_override=None,
                       expected_error="explicit external source artifact path")
        expect_failure("missing specification review passed release policy",
                       specification_override=None,
                       expected_error="explicit external specification-to-code review attestation path")
        expect_failure("missing adversarial review passed release policy",
                       adversarial_override=None,
                       expected_error="explicit external adversarial-composition review attestation path")

        narrowed_contracts = (
            ("disclosure_modes", list(range(7)), "disclosure_modes must be exactly"),
            ("nullstake_generation_ids", [1, 2], "nullstake_generation_ids must be exactly"),
            ("tree_layers", 7, "tree_layers must be exactly"),
            ("membership_scope", "current_epoch", "membership_scope must be exactly"),
            ("post_dag_staking_role", "block_production", "post_dag_staking_role must be exactly"),
            ("supported_operations", list(REQUIRED_PRIVACY_VNEXT_OPERATIONS[:-1]),
             "supported_operations set is incomplete or noncanonical"),
        )
        for contract_field, narrowed_value, expected_error in narrowed_contracts:
            narrowed_manifest = json.loads(json.dumps(manifest_payload))
            narrowed_manifest["privacy_vnext"][contract_field] = narrowed_value
            manifest.write_text(json.dumps(narrowed_manifest), encoding="utf-8")
            expect_failure(
                "narrowed privacy product contract field %s passed release policy" % contract_field,
                expected_error=expected_error,
            )
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        in_repo_source_artifact = root / "source-artifact.tar"
        in_repo_source_artifact.write_bytes(source_artifact.read_bytes())
        expect_failure("repository-local source artifact passed release policy",
                       source_artifact_override=in_repo_source_artifact,
                       expected_error="outside the source repository")
        in_repo_source_artifact.unlink()

        source_artifact.write_bytes(b"different source artifact\n")
        expect_failure("mismatched source artifact passed release policy",
                       expected_error="source artifact digest does not match")
        source_artifact.write_bytes(b"fixture immutable source artifact\n")

        placeholder_manifest = dict(manifest_payload)
        placeholder_manifest["source_build_sha256"] = "0" * 64
        manifest.write_text(json.dumps(placeholder_manifest), encoding="utf-8")
        expect_failure("repeated-nibble manifest digest passed release policy",
                       expected_error="obvious placeholder SHA-256")
        placeholder_manifest["source_build_sha256"] = manifest_payload["source_build_sha256"]
        placeholder_manifest["candidate_build_sha256"] = "a5" * 32
        manifest.write_text(json.dumps(placeholder_manifest), encoding="utf-8")
        expect_failure("repeated-byte manifest digest passed release policy",
                       expected_error="obvious placeholder SHA-256")
        placeholder_manifest["candidate_build_sha256"] = manifest_payload["candidate_build_sha256"]
        placeholder_manifest["specification_to_code_attestation_sha256"] = "3" * 64
        manifest.write_text(json.dumps(placeholder_manifest), encoding="utf-8")
        expect_failure("placeholder review artifact digest passed release policy",
                       expected_error="obvious placeholder SHA-256")
        duplicate_review_artifacts = dict(manifest_payload)
        duplicate_review_artifacts["specification_to_code_attestation_sha256"] = \
            duplicate_review_artifacts["adversarial_composition_attestation_sha256"]
        manifest.write_text(json.dumps(duplicate_review_artifacts), encoding="utf-8")
        expect_failure("duplicate review artifact digests passed release policy",
                       expected_error="artifact digests must be distinct")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        in_repo_review = root / "specification-review.json"
        in_repo_review.write_bytes(specification_attestation.read_bytes())
        expect_failure("repository-local review attestation passed release policy",
                       specification_override=in_repo_review,
                       expected_error="outside the source repository")
        in_repo_review.unlink()

        specification_attestation.write_text(json.dumps(specification_review, indent=2), encoding="utf-8")
        expect_failure("unmanifested review artifact bytes passed release policy",
                       expected_error="review artifact digest does not match manifest")
        specification_attestation.write_text(json.dumps(specification_review), encoding="utf-8")

        def expect_review_failure(review_path: Path, review_value: Dict[str, Any],
                                  manifest_digest_field: str, message: str,
                                  expected_error: str) -> None:
            review_path.write_text(json.dumps(review_value), encoding="utf-8")
            review_manifest = dict(manifest_payload)
            review_manifest[manifest_digest_field] = file_digest(review_path)
            manifest.write_text(json.dumps(review_manifest), encoding="utf-8")
            expect_failure(message, expected_error=expected_error)
            original = specification_review if review_path == specification_attestation else adversarial_review
            review_path.write_text(json.dumps(original), encoding="utf-8")
            manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        no_go_review = dict(specification_review)
        no_go_review["verdict"] = "NO-GO"
        expect_review_failure(
            specification_attestation, no_go_review,
            "specification_to_code_attestation_sha256",
            "non-GO specification review passed release policy", "exact GO verdict",
        )

        duplicate_reviewer = dict(adversarial_review)
        duplicate_reviewer["reviewer_identity_sha256"] = specification_reviewer
        expect_review_failure(
            adversarial_attestation, duplicate_reviewer,
            "adversarial_composition_attestation_sha256",
            "duplicate reviewer identities passed release policy", "distinct reviewer identities",
        )

        placeholder_reviewer = dict(specification_review)
        placeholder_reviewer["reviewer_identity_sha256"] = "6b" * 32
        expect_review_failure(
            specification_attestation, placeholder_reviewer,
            "specification_to_code_attestation_sha256",
            "placeholder reviewer identity passed release policy", "obvious placeholder SHA-256",
        )

        wrong_review_source = dict(specification_review)
        wrong_review_source["source_commit"] = "f" * 40
        expect_review_failure(
            specification_attestation, wrong_review_source,
            "specification_to_code_attestation_sha256",
            "review bound to a different source commit passed release policy", "source_commit does not match",
        )

        wrong_review_candidate = dict(adversarial_review)
        wrong_review_candidate["candidate_commit"] = "e" * 40
        expect_review_failure(
            adversarial_attestation, wrong_review_candidate,
            "adversarial_composition_attestation_sha256",
            "review bound to a different candidate commit passed release policy", "candidate_commit does not match",
        )

        in_repo_evidence = root / "repo-evidence.json"
        in_repo_evidence.write_text(json.dumps(payload), encoding="utf-8")
        expect_failure("repository-local evidence passed release policy", evidence_override=in_repo_evidence,
                       expected_error="outside the source repository")
        evidence_symlink = private_dir / "repo-evidence-link.json"
        evidence_symlink.symlink_to(in_repo_evidence)
        expect_failure("external symlink to repository evidence passed release policy",
                       evidence_override=evidence_symlink,
                       expected_error="outside the source repository")
        evidence_symlink.unlink()
        in_repo_evidence.unlink()

        outward_symlink = root / "external-evidence-link.json"
        outward_symlink.symlink_to(evidence)
        expect_failure("repository symlink to external evidence passed release policy",
                       evidence_override=outward_symlink,
                       expected_error="outside the source repository")
        outward_symlink.unlink()

        manifest_with_path = dict(manifest_payload)
        manifest_with_path["evidence_bundle_path"] = str(evidence)
        manifest.write_text(json.dumps(manifest_with_path), encoding="utf-8")
        expect_failure("manifest evidence path passed schema validation",
                       expected_error="fields do not match schema")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        evidence.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        expect_failure("evidence digest mismatch passed release policy",
                       expected_error="evidence bundle digest does not match")
        evidence.write_text(json.dumps(payload), encoding="utf-8")

        malformed = dict(payload)
        malformed["checks"] = {"fixture": True}
        evidence.write_text(json.dumps(malformed), encoding="utf-8")
        malformed_manifest = dict(manifest_payload)
        malformed_manifest["evidence_bundle_sha256"] = file_digest(evidence)
        manifest.write_text(json.dumps(malformed_manifest), encoding="utf-8")
        expect_failure("arbitrary check dictionary passed release policy",
                       expected_error="checks do not match schema")
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        wrong_height = json.loads(json.dumps(payload))
        wrong_height["nodes"][0]["height"] = 361
        evidence.write_text(json.dumps(wrong_height), encoding="utf-8")
        wrong_height_manifest = dict(manifest_payload)
        wrong_height_manifest["evidence_bundle_sha256"] = file_digest(evidence)
        manifest.write_text(json.dumps(wrong_height_manifest), encoding="utf-8")
        expect_failure("node height differing from common height passed release policy",
                       expected_error="height/best-hash values")
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        wrong_best_hash = json.loads(json.dumps(payload))
        wrong_best_hash["nodes"][0]["best_hash"] = fixture_sha256("wrong-node-best-hash")
        evidence.write_text(json.dumps(wrong_best_hash), encoding="utf-8")
        wrong_best_hash_manifest = dict(manifest_payload)
        wrong_best_hash_manifest["evidence_bundle_sha256"] = file_digest(evidence)
        manifest.write_text(json.dumps(wrong_best_hash_manifest), encoding="utf-8")
        expect_failure("node best hash differing from common hash passed release policy",
                       expected_error="height/best-hash values")
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        placeholder_binary = json.loads(json.dumps(payload))
        placeholder_binary["nodes"][0]["binary_sha256"] = "a5" * 32
        evidence.write_text(json.dumps(placeholder_binary), encoding="utf-8")
        placeholder_binary_manifest = dict(manifest_payload)
        placeholder_binary_manifest["evidence_bundle_sha256"] = file_digest(evidence)
        manifest.write_text(json.dumps(placeholder_binary_manifest), encoding="utf-8")
        expect_failure("placeholder node binary digest passed release policy",
                       expected_error="obvious placeholder SHA-256")
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        placeholder_root = json.loads(json.dumps(payload))
        for node in placeholder_root["nodes"]:
            node["epoch_curve_root"] = "7" * 64
        evidence.write_text(json.dumps(placeholder_root), encoding="utf-8")
        placeholder_root_manifest = dict(manifest_payload)
        placeholder_root_manifest["evidence_bundle_sha256"] = file_digest(evidence)
        manifest.write_text(json.dumps(placeholder_root_manifest), encoding="utf-8")
        expect_failure("placeholder epoch root passed release policy",
                       expected_error="obvious placeholder SHA-256")
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        wrong_binary = json.loads(json.dumps(payload))
        wrong_binary["nodes"][0]["binary_sha256"] = fixture_sha256("wrong-node-binary")
        evidence.write_text(json.dumps(wrong_binary), encoding="utf-8")
        wrong_binary_manifest = dict(manifest_payload)
        wrong_binary_manifest["evidence_bundle_sha256"] = file_digest(evidence)
        manifest.write_text(json.dumps(wrong_binary_manifest), encoding="utf-8")
        expect_failure("mismatched node binary digest passed release policy",
                       expected_error="four-node binary digests")
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        wrong_candidate = dict(manifest_payload)
        wrong_candidate_sha256 = fixture_sha256("wrong-candidate-binary")
        wrong_candidate["candidate_build_sha256"] = wrong_candidate_sha256
        wrong_candidate_specification_review = dict(specification_review)
        wrong_candidate_adversarial_review = dict(adversarial_review)
        wrong_candidate_specification_review["candidate_build_sha256"] = wrong_candidate_sha256
        wrong_candidate_adversarial_review["candidate_build_sha256"] = wrong_candidate_sha256
        specification_attestation.write_text(
            json.dumps(wrong_candidate_specification_review), encoding="utf-8"
        )
        adversarial_attestation.write_text(
            json.dumps(wrong_candidate_adversarial_review), encoding="utf-8"
        )
        wrong_candidate["specification_to_code_attestation_sha256"] = file_digest(
            specification_attestation
        )
        wrong_candidate["adversarial_composition_attestation_sha256"] = file_digest(
            adversarial_attestation
        )
        manifest.write_text(json.dumps(wrong_candidate), encoding="utf-8")
        expect_failure("mismatched manifest candidate digest passed release policy",
                       expected_error="manifest candidate build digest")
        specification_attestation.write_text(json.dumps(specification_review), encoding="utf-8")
        adversarial_attestation.write_text(json.dumps(adversarial_review), encoding="utf-8")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        boundary_b_height = required_boundary_b_activation_height(1260, 1260)
        wrong_boundary_b = json.loads(json.dumps(payload))
        wrong_boundary_b["boundary_b_calculation_available"] = True
        wrong_boundary_b["boundary_b_boundary_a_height"] = 1260
        wrong_boundary_b["boundary_b_candidate_freeze_height"] = 1260
        wrong_boundary_b["boundary_b_recommended_activation_height"] = boundary_b_height + 300
        wrong_boundary_b_manifest = json.loads(json.dumps(manifest_payload))
        wrong_boundary_b_manifest["fork_heights"].update({
            "boundary_b_boundary_a_height": 1260,
            "boundary_b_candidate_freeze_height": 1260,
            "boundary_b_recommended_activation_height": boundary_b_height + 300,
        })
        evidence.write_text(json.dumps(wrong_boundary_b), encoding="utf-8")
        wrong_boundary_b_manifest["evidence_bundle_sha256"] = file_digest(evidence)
        manifest.write_text(json.dumps(wrong_boundary_b_manifest), encoding="utf-8")
        expect_failure("copied but arithmetically invalid Boundary-B heights passed release policy",
                       expected_error="first fixed boundary with a 900-block lead")
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        unconfigured_final_b = json.loads(json.dumps(payload))
        unconfigured_final_b["boundary_b_calculation_available"] = True
        unconfigured_final_b["boundary_b_boundary_a_height"] = 1260
        unconfigured_final_b["boundary_b_candidate_freeze_height"] = 1260
        unconfigured_final_b["boundary_b_recommended_activation_height"] = boundary_b_height
        unconfigured_final_b_manifest = json.loads(json.dumps(manifest_payload))
        unconfigured_final_b_manifest["fork_heights"].update({
            "boundary_b_boundary_a_height": 1260,
            "boundary_b_candidate_freeze_height": 1260,
            "boundary_b_recommended_activation_height": boundary_b_height,
        })
        evidence.write_text(json.dumps(unconfigured_final_b), encoding="utf-8")
        unconfigured_final_b_manifest["evidence_bundle_sha256"] = file_digest(evidence)
        manifest.write_text(json.dumps(unconfigured_final_b_manifest), encoding="utf-8")
        expect_failure("final Boundary-B arithmetic passed with unconfigured nodes",
                       expected_error="requires all four nodes")
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        configured_without_arithmetic = json.loads(json.dumps(payload))
        for node in configured_without_arithmetic["nodes"]:
            node["boundary_b_activation_height"] = boundary_b_height
            node["boundary_b_configured"] = True
        evidence.write_text(json.dumps(configured_without_arithmetic), encoding="utf-8")
        configured_without_arithmetic_manifest = dict(manifest_payload)
        configured_without_arithmetic_manifest["evidence_bundle_sha256"] = file_digest(evidence)
        manifest.write_text(json.dumps(configured_without_arithmetic_manifest), encoding="utf-8")
        expect_failure("configured Boundary B without final arithmetic passed release policy",
                       expected_error="must remain unconfigured")
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        stale = dict(manifest_payload)
        stale["generated_at"] = "2020-01-01T00:00:00Z"
        manifest.write_text(json.dumps(stale), encoding="utf-8")
        expect_failure("stale manifest passed release policy", expected_error="stale or future-dated")
        manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")

        wrong_source = dict(manifest_payload)
        wrong_source["source_commit"] = "f" * 40
        manifest.write_text(json.dumps(wrong_source), encoding="utf-8")
        expect_failure("manifested source commit mismatch passed release policy",
                       expected_error="release-gate evidence source_commit")

        final_boundary_b = json.loads(json.dumps(payload))
        final_boundary_b["boundary_b_calculation_available"] = True
        final_boundary_b["boundary_b_boundary_a_height"] = 1260
        final_boundary_b["boundary_b_candidate_freeze_height"] = 1260
        final_boundary_b["boundary_b_recommended_activation_height"] = boundary_b_height
        for node in final_boundary_b["nodes"]:
            node["boundary_b_activation_height"] = boundary_b_height
            node["boundary_b_configured"] = True
            node["boundary_b_active"] = False
        evidence.write_text(json.dumps(final_boundary_b), encoding="utf-8")
        final_boundary_b_manifest = json.loads(json.dumps(manifest_payload))
        final_boundary_b_manifest["fork_heights"].update({
            "boundary_b_boundary_a_height": 1260,
            "boundary_b_candidate_freeze_height": 1260,
            "boundary_b_recommended_activation_height": boundary_b_height,
        })
        final_boundary_b_manifest["evidence_bundle_sha256"] = file_digest(evidence)
        manifest.write_text(json.dumps(final_boundary_b_manifest), encoding="utf-8")
        validated_final_boundary_b_manifest = validate_manifest(
            final_boundary_b_manifest, root, now
        )
        assert validate_evidence(
            final_boundary_b,
            validated_final_boundary_b_manifest,
            final_boundary_b_manifest["common_height"],
            final_boundary_b_manifest["common_hash"],
            now,
            1260,
        )["activation_height"] == 1260

        print("v5 release policy selftest passed")
        return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--main-h", type=Path, default=Path("src/main.h"))
    parser.add_argument("--manifest", type=Path,
                        help="Explicit candidate manifest outside the source repository")
    parser.add_argument("--evidence", type=Path,
                        help="Explicit preflight evidence file outside the source repository")
    parser.add_argument("--release-gate-evidence", type=Path,
                        help="External signed/artifact/test-gate evidence JSON")
    parser.add_argument("--artifact-directory", type=Path,
                        help="Downloaded unsigned and signed package artifact directories")
    parser.add_argument("--source-artifact", type=Path,
                        help="Immutable source artifact outside the source repository")
    parser.add_argument("--specification-to-code-attestation", type=Path,
                        help="External specification-to-code GO attestation JSON")
    parser.add_argument("--adversarial-composition-attestation", type=Path,
                        help="External adversarial-composition GO attestation JSON")
    parser.add_argument("--private-audit-sha256",
                        help="SHA-256 of the independently reviewed private audit")
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.evidence is None:
        parser.error("--evidence is required and must name a file outside --source-root")
    if args.manifest is None:
        parser.error("--manifest is required and must name a file outside --source-root")
    if args.release_gate_evidence is None:
        parser.error("--release-gate-evidence is required and must be outside --source-root")
    if args.artifact_directory is None:
        parser.error("--artifact-directory is required and must be outside --source-root")
    if args.source_artifact is None:
        parser.error("--source-artifact is required and must name a file outside --source-root")
    if args.specification_to_code_attestation is None:
        parser.error("--specification-to-code-attestation is required and must be outside --source-root")
    if args.adversarial_composition_attestation is None:
        parser.error("--adversarial-composition-attestation is required and must be outside --source-root")
    if args.private_audit_sha256 is None:
        parser.error("--private-audit-sha256 is required")
    result = validate(
        args.main_h,
        manifest_path=args.manifest,
        evidence_path=args.evidence,
        release_gate_evidence_path=args.release_gate_evidence,
        artifact_directory=args.artifact_directory,
        source_artifact_path=args.source_artifact,
        specification_attestation_path=args.specification_to_code_attestation,
        adversarial_attestation_path=args.adversarial_composition_attestation,
        private_audit_sha256=args.private_audit_sha256,
        source_root=args.source_root,
    )
    print("release policy passed: activation={activation_height} preflight_height={common_height} hash={common_hash}".format(**result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
