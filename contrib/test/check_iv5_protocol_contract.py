#!/usr/bin/env python3
"""Check that every current IV5 consumer names one normative contract."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "src/privacy_vnext/contract/iv5_protocol_v1.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("iv5-contract: " + message)


def numeric_constant(text: str, name: str) -> int:
    match = re.search(r"\b" + re.escape(name) + r"\s*(?::[^=]+)?=\s*([0-9]+)", text)
    require(match is not None, "missing constant " + name)
    return int(match.group(1))


raw = CONTRACT_PATH.read_bytes()
contract = json.loads(raw)
require(contract["contract"] == "Innova/IV5/Protocol/v1", "wrong contract name")
require(contract["status"] == "normative-inactive", "contract must remain inactive")
require(contract["consensus_ready"] is False, "contract cannot claim consensus readiness")
require(contract["envelope"]["marker_hex"] == "ff49563550", "wrong envelope marker")
require(contract["limits"]["tree_layers"] == 8, "tree must have eight layers")
require(contract["limits"]["selected_maximum_inputs"] is None, "input cap was not benchmark-frozen")
require(contract["limits"]["selected_maximum_outputs"] is None, "output cap was not benchmark-frozen")
require(contract["limits"]["benchmark_sha256"] is None, "benchmark hash must be absent before cap freeze")

expected_note = {
    "shield": 0,
    "unshield": 1,
    "transfer": 2,
    "nullsend": 3,
    "delegation_create": 4,
    "m_of_n_mint": 5,
    "reclaim": 6,
    "conditional_migration": 7,
    "collateral_register": 8,
    "finality_member_register": 9,
    "finality_vote": 10,
    "none": 255,
}
# Consensus-defined but not surfaced to callers yet, so the RPC/release-schema checks
# below skip them. Registration cannot go live while the attestation tag is the note's
# own key image; the note vote has no connect path, producer or RPC yet. Remove an
# entry here when its operation is exposed, and this set must be empty before release.
not_yet_surfaced = {"collateral_register", "finality_member_register", "finality_vote"}
expected_profiles = {"none": 0, "nullstake_v1": 1, "nullstake_v2": 2, "nullstake_v3": 3}
expected_auth = {"owner": 0, "cold_staker": 1, "m_of_n_public_signers": 2, "m_of_n_hidden_signers": 3}
expected_objects = {"none": 0, "vote": 1, "tally_share": 2, "certificate": 3, "committee_rotation": 4}
require(contract["note_operations"] == expected_note, "note-operation mapping changed")
require(contract["finality_profiles"] == expected_profiles, "finality-profile mapping changed")
require(contract["authorization_modes"] == expected_auth, "authorization mapping changed")
require(contract["finality_objects"] == expected_objects, "finality-object mapping changed")
require(sorted(map(int, contract["envelope_capabilities"])) == list(range(2000, 2009)), "wire versions must be exactly 2000..2008")

cpp = (ROOT / "src/privacy_vnext/iv5_protocol.h").read_text(encoding="utf-8")
rust = (ROOT / "src/privacy_vnext/rust/src/lib.rs").read_text(encoding="utf-8")
mapping = {
    "NOTE_SHIELD": 0,
    "NOTE_UNSHIELD": 1,
    "NOTE_TRANSFER": 2,
    "NOTE_NULLSEND": 3,
    "NOTE_DELEGATION_CREATE": 4,
    "NOTE_M_OF_N_MINT": 5,
    "NOTE_RECLAIM": 6,
    "NOTE_CONDITIONAL_MIGRATION": 7,
    "NOTE_COLLATERAL_REGISTER": 8,
    "NOTE_FINALITY_MEMBER_REGISTER": 9,
    "NOTE_FINALITY_VOTE": 10,
    "NOTE_OPERATION_NONE": 255,
    "FINALITY_NONE": 0,
    "FINALITY_NULLSTAKE_V1": 1,
    "FINALITY_NULLSTAKE_V2": 2,
    "FINALITY_NULLSTAKE_V3": 3,
    "AUTH_OWNER": 0,
    "AUTH_COLD_STAKER": 1,
    "AUTH_M_OF_N_PUBLIC_SIGNERS": 2,
    "AUTH_M_OF_N_HIDDEN_SIGNERS": 3,
    "FINALITY_OBJECT_NONE": 0,
    "FINALITY_OBJECT_VOTE": 1,
    "FINALITY_OBJECT_TALLY_SHARE": 2,
    "FINALITY_OBJECT_CERTIFICATE": 3,
    "FINALITY_OBJECT_COMMITTEE_ROTATION": 4,
}
for name, value in mapping.items():
    require(numeric_constant(cpp, name) == value, "C++ mismatch for " + name)
    require(numeric_constant(rust, name) == value, "Rust mismatch for " + name)

abi_path = ROOT / "src/privacy_vnext/rust/abi/innova_privacy_vnext_v2.txt"
abi_sha256 = hashlib.sha256(abi_path.read_bytes()).hexdigest()
require(
    contract["fcmp_abi"]["abi_schema_sha256"] == abi_sha256,
    "contract records a stale ABI digest; the ABI text is " + abi_sha256,
)

contract_sha256 = hashlib.sha256(raw).hexdigest()
require(
    'PROTOCOL_CONTRACT_SHA256[] =\n    "' + contract_sha256 + '"' in cpp,
    "C++ contract digest is stale",
)
require('include_bytes!("../../contract/iv5_protocol_v1.json")' in rust, "Rust does not hash canonical contract bytes")
rpc = (ROOT / "src/rpcshielded.cpp").read_text(encoding="utf-8")
for name in expected_note:
    if name != "none" and name not in not_yet_surfaced:
        require('"' + name + '"' in rpc, "RPC omits note operation " + name)
for name in ("nullstake_v1", "nullstake_v2", "nullstake_v3"):
    require('"' + name + '"' in rpc, "RPC omits finality profile " + name)

evidence = (ROOT / "contrib/test/v5_release_evidence_schema.py").read_text(encoding="utf-8")
for name in expected_note:
    if name != "none" and name not in not_yet_surfaced:
        require('"' + name + '"' in evidence, "release schema omits note operation " + name)

docs = (ROOT / "docs/architecture/IV5-PROTOCOL.md").read_text(encoding="utf-8")
require("iv5_protocol_v1.json" in docs, "protocol documentation does not identify source bytes")
print("iv5-contract: ok sha256=" + contract_sha256)
