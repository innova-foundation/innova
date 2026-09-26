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
# Consensus-defined but not yet exposed; the RPC/release-schema checks skip them.
# Remove an entry when its operation is exposed; must be empty before release.
not_yet_surfaced = {"collateral_register"}
# Refused by consensus at every height; never surfaced.
refused_by_consensus = {"finality_member_register"}
# Produced by the node, not built by a caller: surfaced through the finality RPCs
# rather than the operation lists.
surfaced_by_finality_rpc = {"finality_vote": ("note_votes", "note_votes_counted", "note_vote_tags")}
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


def product_constant(text: str, name: str) -> int:
    """Read a constant written as INN x atomic units on either side."""
    match = re.search(
        r"\b" + re.escape(name) + r"\s*(?::[^=]+)?=\s*([0-9_]+)(?:LL|L|u64)?\s*\*\s*([0-9_]+)(?:LL|L|u64)?",
        text,
    )
    require(match is not None, "missing product constant " + name)
    return int(match.group(1).replace("_", "")) * int(match.group(2).replace("_", ""))


def scalar_constant(text: str, name: str) -> int:
    """Read a constant written as a plain integer on either side."""
    match = re.search(
        r"\b" + re.escape(name) + r"\s*(?::[^=]+)?=\s*([0-9_]+)(?:LL|L|u64|usize)?\s*;",
        text,
    )
    require(match is not None, "missing scalar constant " + name)
    return int(match.group(1).replace("_", ""))


# The stake floor a note vote proves. The Rust decoder proves it as a range statement and
# has no height to key on, while the C++ side keys the same figure by height; the one rung
# reads this constant, so a rung that moves has to move both.
floor_atomic = contract["note_finality_vote"]["minimum_vote_weight_atomic"]
require(
    product_constant(cpp, "NOTE_VOTE_MIN_WEIGHT") == floor_atomic,
    "C++ mismatch for NOTE_VOTE_MIN_WEIGHT",
)
require(
    product_constant(rust, "NOTE_VOTE_MIN_WEIGHT") == floor_atomic,
    "Rust mismatch for NOTE_VOTE_MIN_WEIGHT",
)

# Participants a mix may carry. One proof per input under a fixed section cap fixes this,
# and it is written down in both languages -- so the contract is what the two must agree
# with, rather than each other. A bound that drifts builds payloads no verifier can read.
mix_max = contract["nullsend"]["maximum_participants"]
require(
    scalar_constant(cpp, "MAX_NULLSEND_INPUTS") == mix_max,
    "C++ mismatch for MAX_NULLSEND_INPUTS",
)
require(
    scalar_constant(rust, "MAX_NULLSEND_INPUTS") == mix_max,
    "Rust mismatch for MAX_NULLSEND_INPUTS",
)

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
skip_operation_lists = not_yet_surfaced | refused_by_consensus | set(surfaced_by_finality_rpc)
require(not (not_yet_surfaced & refused_by_consensus), "an operation is both pending and refused")
for name in expected_note:
    if name != "none" and name not in skip_operation_lists:
        require('"' + name + '"' in rpc, "RPC omits note operation " + name)
for name in refused_by_consensus:
    require('"' + name + '"' not in rpc, "RPC surfaces refused note operation " + name)
main_cpp = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
require("NOTE_FINALITY_MEMBER_REGISTER" in main_cpp and
        "IV5 finality member registration is not a valid operation" in main_cpp,
        "consensus no longer refuses finality_member_register")
finality_rpc = (ROOT / "src/rpcblockchain.cpp").read_text(encoding="utf-8")
for name, fields in surfaced_by_finality_rpc.items():
    for field in fields:
        require('"' + field + '"' in finality_rpc, "finality RPC omits " + field + " for " + name)
for name in ("nullstake_v1", "nullstake_v2", "nullstake_v3"):
    require('"' + name + '"' in rpc, "RPC omits finality profile " + name)

evidence = (ROOT / "contrib/test/v5_release_evidence_schema.py").read_text(encoding="utf-8")
for name in expected_note:
    if name != "none" and name not in skip_operation_lists:
        require('"' + name + '"' in evidence, "release schema omits note operation " + name)

docs = (ROOT / "docs/architecture/IV5-PROTOCOL.md").read_text(encoding="utf-8")
require("iv5_protocol_v1.json" in docs, "protocol documentation does not identify source bytes")
print("iv5-contract: ok sha256=" + contract_sha256)
