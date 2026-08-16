#!/usr/bin/env python3
"""Versioned constants shared by v5 preflight generation and release policy."""

from __future__ import annotations


PREFLIGHT_SCHEMA_VERSION = 6
SNAPSHOT_MANIFEST_SCHEMA_VERSION = 1
REQUIRED_LEAD_BLOCKS = 900
REQUIRED_EPOCH_INTERVAL = 300
REQUIRED_BOUNDARY_ORIGIN = 60

# Mainnet v5 activation ladder: gates must lead a trusted tip by MIN <= lead <= MAX.
# MIN is the upgrade window; MAX keeps activation prompt.
MAINNET_ACTIVATION_MIN_LEAD_BLOCKS = 50_000
MAINNET_ACTIVATION_MAX_LEAD_BLOCKS = 250_000
MAINNET_ACTIVATION_SHIFT_GRANULARITY = 10_000
MAINNET_ACTIVATION_FIRST_GATE_BASE = 7_800_000
MAINNET_ACTIVATION_DAG_GATE_BASE = 7_950_000
MAINNET_ACTIVATION_BOUNDARY_B_BASE = 8_060_000

# The DAG gate must be a pre-DAG epoch boundary (FINALITY_EPOCH_INTERVAL_PRE_DAG), so the
# shift must be a multiple of lcm(10_000, 60) = 30_000.
MAINNET_PRE_DAG_EPOCH_INTERVAL = 60
MAINNET_ACTIVATION_SHIFT_STEP = 30_000

REQUIRED_PRIVACY_VNEXT_DISCLOSURE_MODES = tuple(range(8))
REQUIRED_PRIVACY_VNEXT_NULLSTAKE_GENERATION_IDS = (1, 2, 3)
REQUIRED_PRIVACY_VNEXT_TREE_LAYERS = 8
REQUIRED_PRIVACY_VNEXT_MEMBERSHIP_SCOPE = "full_chain_finalized_root"
REQUIRED_PRIVACY_VNEXT_POST_DAG_STAKING_ROLE = "finality"
REQUIRED_PRIVACY_VNEXT_OPERATIONS = (
    "shield",
    "unshield",
    "transfer",
    "nullsend",
    "delegation_create",
    "m_of_n_mint",
    "reclaim",
    "conditional_migration",
    "nullstake_v1",
    "nullstake_v2",
    "nullstake_v3",
    "m_of_n_public_signers",
    "m_of_n_hidden_signers",
    "private_finality",
)

REQUIRED_EVIDENCE_FIELDS = frozenset({
    "activation_height",
    "artifact_source_commit",
    "boundary_origin",
    "boundary_b_calculation_available",
    "boundary_b_boundary_a_height",
    "boundary_b_candidate_freeze_height",
    "boundary_b_recommended_activation_height",
    "checks",
    "common_hash",
    "common_height",
    "epoch_interval",
    "expected_binary_sha256",
    "expected_candidate_build_identifier",
    "expected_serializer_schema",
    "expected_serializer_schema_version",
    "failed_checks",
    "generated_at",
    "lead_blocks",
    "nodes",
    "passed",
    "schema_version",
    "snapshot_manifest",
    "snapshot_manifest_sha256",
    "source_commit",
})

REQUIRED_NODE_FIELDS = frozenset({
    "banned_fleet_peer_count",
    "best_hash",
    "binary_sha256",
    "boundary_a_activation_height",
    "boundary_a_active",
    "boundary_a_configured",
    "boundary_b_activation_height",
    "boundary_b_active",
    "boundary_b_configured",
    "candidate_build_identifier",
    "committee_set_hash",
    "commitment_tree_size",
    "connected_fleet_peer_count",
    "cpumining",
    "dag_active",
    "dag_best_tip",
    "deterministic_finalized_height_available",
    "epoch_curve_root",
    "epoch_nullifier_root",
    "epoch_state_digest",
    "epoch_state_health",
    "epoch_vote_set_root",
    "finality_tier",
    "finalized_height",
    "height",
    "height_hash_stable",
    "initialblockdownload",
    "label",
    "legacy_anon_status",
    "legacy_shielded_consensus_active",
    "legacy_shielded_creation_enabled",
    "mempool_count",
    "migration_state",
    "missing_fleet_peer_count",
    "network",
    "node_identity",
    "p2p_identity",
    "p2p_identity_advertised",
    "peer_count",
    "privacy_protocol_status",
    "privacy_vnext_abi_sha256",
    "privacy_vnext_abi_version",
    "privacy_vnext_consensus_ready",
    "privacy_vnext_disclosure_modes",
    "privacy_vnext_max_inputs",
    "privacy_vnext_max_outputs",
    "privacy_vnext_max_payload_bytes",
    "privacy_vnext_membership_scope",
    "privacy_vnext_nullstake_generation_ids",
    "privacy_vnext_parameter_digest",
    "privacy_vnext_post_dag_staking_role",
    "privacy_vnext_supported_operations",
    "privacy_vnext_tree_layers",
    "privacy_vnext_tree_root",
    "privacy_vnext_tree_size",
    "privacy_vnext_wallet_migration_state",
    "legacy_privacy_retired",
    "required_schema_version",
    "schema_marker_present",
    "schema_version",
    "serializer_schema",
    "serializer_schema_version",
    "shielded_pool_value",
    "shielded_privacy_protocol_status",
    "shielded_state_healthy",
    "staking",
    "unspent_notes",
    "warnings",
})

REQUIRED_SNAPSHOT_MANIFEST_FIELDS = frozenset({
    "common_hash",
    "common_height",
    "completed_at",
    "nodes",
    "schema_version",
})

REQUIRED_SNAPSHOT_NODE_FIELDS = frozenset({
    "best_hash",
    "chain_snapshot_complete",
    "chain_snapshot_sha256",
    "height",
    "label",
    "wallet_snapshot_complete",
    "wallet_snapshot_sha256",
})

REQUIRED_CHECKS = frozenset({
    "artifact_source_commit_matches",
    "binary_hashes_match",
    "boundary_a_matches_recommendation",
    "boundary_b_calculation_consistent",
    "boundary_b_status_consistent",
    "candidate_build_bound_to_source",
    "candidate_build_identifiers_match",
    "common_best_hash",
    "common_height",
    "consensus_health_matches",
    "controlled_mining_paused",
    "controlled_staking_paused",
    "dag_active",
    "deterministic_finalized_height_available",
    "epoch_state_healthy",
    "exactly_four_nodes",
    "expected_binary_matches",
    "expected_binary_supplied",
    "expected_candidate_build_identifier_supplied",
    "expected_serializer_schema_supplied",
    "four_node_peer_mesh",
    "height_and_hash_stable",
    "health_digests_match",
    "legacy_anon_historical",
    "legacy_privacy_consensus_retired",
    "legacy_pool_empty",
    "mempools_empty",
    "migration_ready",
    "no_fleet_bans",
    "no_warnings",
    "out_of_ibd",
    "p2p_identities_advertised",
    "privacy_health_consistent",
    "privacy_vnext_ready",
    "privacy_vnext_product_contract",
    "privacy_vnext_state_consistent",
    "release_parameters_fixed",
    "serializer_schema_matches",
    "schema_consistent",
    "schema_marker_present",
    "shielded_state_healthy",
    "snapshot_manifest_matches_chain",
    "snapshot_manifest_supplied",
    "snapshots_complete",
    "source_commit_present",
    "source_tree_clean",
    "testnet_only",
    "unique_node_identities",
    "zero_unspent_legacy_notes",
})
