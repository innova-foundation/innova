#ifndef INNOVA_PRIVACY_VNEXT_H
#define INNOVA_PRIVACY_VNEXT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INNOVA_PRIVACY_VNEXT_ABI_VERSION 2u
#define INNOVA_PRIVACY_VNEXT_DIGEST_SIZE 32u
#define INNOVA_PRIVACY_VNEXT_UPSTREAM_REVISION_SIZE 40u
#define INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION 2008u
#define INNOVA_PRIVACY_VNEXT_TREE_LAYERS 8u
#define INNOVA_PRIVACY_VNEXT_MAX_INPUTS 16u
#define INNOVA_PRIVACY_VNEXT_MAX_OUTPUTS 16u
#define INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES 262144u
#define INNOVA_PRIVACY_VNEXT_DISCLOSURE_MODE_MIN 0u
#define INNOVA_PRIVACY_VNEXT_DISCLOSURE_MODE_MAX 7u
#define INNOVA_PRIVACY_VNEXT_NULLSTAKE_GENERATION_MIN 1u
#define INNOVA_PRIVACY_VNEXT_NULLSTAKE_GENERATION_MAX 3u
#define INNOVA_PRIVACY_VNEXT_PAYLOAD_SCHEMA 1u
#define INNOVA_PRIVACY_VNEXT_ADDRESS_FORMAT 1u
#define INNOVA_PRIVACY_VNEXT_ADDRESS_COMPONENT_SIZE 70u
#define INNOVA_PRIVACY_VNEXT_KEY_DERIVATION_REQUEST_SIZE 72u
#define INNOVA_PRIVACY_VNEXT_KEY_DERIVATION_OUTPUT_SIZE 232u
#define INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE 300u
#define INNOVA_PRIVACY_VNEXT_TREE_ROOT_SIZE 44u
#define INNOVA_PRIVACY_VNEXT_NOTE_SCAN_PREFIX_SIZE 268u
#define INNOVA_PRIVACY_VNEXT_NOTE_SCAN_RESULT_SIZE 212u
#define INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE 177u
#define INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE 241u
#define INNOVA_PRIVACY_VNEXT_NOTE_ENCRYPT_REQUEST_SIZE 304u
/* Per-payload value every output's one-time key and note tag are derived under. */
#define INNOVA_PRIVACY_VNEXT_INPUT_CONTEXT_SIZE 32u
/* schema_u16 || operation_u8 || key_image_count_u8 || transparent_binding_32, then the
 * key images, 32 each, in payload order. */
#define INNOVA_PRIVACY_VNEXT_INPUT_CONTEXT_REQUEST_HEADER_SIZE 36u
#define INNOVA_PRIVACY_VNEXT_NOTE_ENCRYPT_RESULT_SIZE 586u
#define INNOVA_PRIVACY_VNEXT_FCMP_PROVE_RESPONSE_HEADER_SIZE 4u
#define INNOVA_PRIVACY_VNEXT_FCMP_PROVE_RESPONSE_RECORD_SIZE 256u
#define INNOVA_PRIVACY_VNEXT_FCMP_PROVE_MASK_DELTA_OFFSET 64u
#define INNOVA_PRIVACY_VNEXT_FCMP_PROVE_SENDER_AUTHORITY_OFFSET 96u
#define INNOVA_PRIVACY_VNEXT_FCMP_PROVE_SENDER_PROOF_OFFSET 128u
#define INNOVA_PRIVACY_VNEXT_SENDER_DISCLOSURE_PROOF_SIZE 128u
#define INNOVA_PRIVACY_VNEXT_RECEIVER_DISCLOSURE_PROOF_SIZE 160u
#define INNOVA_PRIVACY_VNEXT_RECEIVER_DISCLOSURE_REQUEST_SIZE 296u
#define INNOVA_PRIVACY_VNEXT_AMOUNT_EQUALITY_REQUEST_SIZE 140u
#define INNOVA_PRIVACY_VNEXT_VALUE_PROVE_HEADER_SIZE 116u
#define INNOVA_PRIVACY_VNEXT_PAYLOAD_EFFECTS_HEADER_SIZE 124u
/* Compressed secp256k1 tally-encryption key of one finality-committee member. */
#define INNOVA_PRIVACY_VNEXT_FINALITY_MEMBER_KEY_SIZE 33u
/* Boundary block hash (32) and u32 LE boundary height a note finality vote names. */
#define INNOVA_PRIVACY_VNEXT_FINALITY_VOTE_CONTEXT_SIZE 36u
/* Attestation count, registration context, member key and vote boundary, after the key
 * images and output leaves. Fixed width and always present. */
#define INNOVA_PRIVACY_VNEXT_PAYLOAD_EFFECTS_TRAILER_SIZE 102u
/* Atomic units one collateralnode attests to; proved, never published. */
#define INNOVA_PRIVACY_VNEXT_COLLATERAL_ATTESTATION_AMOUNT 2500000000000ull
#define INNOVA_PRIVACY_VNEXT_AMOUNT_EQUALITY_PROOF_SIZE 64u
#define INNOVA_PRIVACY_VNEXT_NULLIFIER_STATE_SIZE 44u
#define INNOVA_PRIVACY_VNEXT_NULLIFIER_ROOT_SIZE 44u

#define INNOVA_PRIVACY_VNEXT_CAP_PROTOCOL_CONTRACT (1u << 0)
#define INNOVA_PRIVACY_VNEXT_CAP_FCMP_PROOF_SIZE (1u << 1)
#define INNOVA_PRIVACY_VNEXT_CAP_FCMP_PROVE (1u << 2)
#define INNOVA_PRIVACY_VNEXT_CAP_FCMP_VERIFY (1u << 3)
#define INNOVA_PRIVACY_VNEXT_CAP_FCMP_BATCH_VERIFY (1u << 4)
#define INNOVA_PRIVACY_VNEXT_CAP_TREE_UPDATE (1u << 5)
#define INNOVA_PRIVACY_VNEXT_CAP_TREE_ROOT (1u << 6)
#define INNOVA_PRIVACY_VNEXT_CAP_TREE_WITNESS (1u << 7)
#define INNOVA_PRIVACY_VNEXT_CAP_PAYLOAD_VALIDATE (1u << 8)
#define INNOVA_PRIVACY_VNEXT_CAP_ADDRESS_CODEC (1u << 9)
#define INNOVA_PRIVACY_VNEXT_CAP_KEY_DERIVATION (1u << 10)
#define INNOVA_PRIVACY_VNEXT_CAP_NOTE_SCAN (1u << 11)
#define INNOVA_PRIVACY_VNEXT_CAP_NOTE_ENCRYPT (1u << 12)
#define INNOVA_PRIVACY_VNEXT_CAP_VALUE_PROVE (1u << 13)
#define INNOVA_PRIVACY_VNEXT_CAP_PAYLOAD_EFFECTS (1u << 14)
#define INNOVA_PRIVACY_VNEXT_CAP_NULLIFIER_ACCUMULATOR (1u << 15)
#define INNOVA_PRIVACY_VNEXT_CAP_PAYLOAD_SCAN (1u << 16)
#define INNOVA_PRIVACY_VNEXT_CAP_TREE_EXTEND (1u << 17)
#define INNOVA_PRIVACY_VNEXT_CAP_PAYLOAD_SIGNING_HASH (1u << 18)
#define INNOVA_PRIVACY_VNEXT_CAP_RECEIVER_DISCLOSURE_PROVE (1u << 19)
#define INNOVA_PRIVACY_VNEXT_CAP_AMOUNT_EQUALITY_PROVE (1u << 20)
#define INNOVA_PRIVACY_VNEXT_CAP_VOTE_MEMBERSHIP (1u << 21)
#define INNOVA_PRIVACY_VNEXT_CAP_VOTE_SIGMA (1u << 22)
#define INNOVA_PRIVACY_VNEXT_CAP_ED25519_COMBINE (1u << 23)
#define INNOVA_PRIVACY_VNEXT_CAP_RANGE_PROOF (1u << 24)
#define INNOVA_PRIVACY_VNEXT_CAP_FCMP_SPLIT_PROVE (1u << 25)
#define INNOVA_PRIVACY_VNEXT_CAP_MIX_BALANCE (1u << 26)
#define INNOVA_PRIVACY_VNEXT_IMPLEMENTED_CAPABILITIES \
    (INNOVA_PRIVACY_VNEXT_CAP_PROTOCOL_CONTRACT | \
     INNOVA_PRIVACY_VNEXT_CAP_FCMP_PROOF_SIZE | \
     INNOVA_PRIVACY_VNEXT_CAP_FCMP_PROVE | \
     INNOVA_PRIVACY_VNEXT_CAP_FCMP_VERIFY | \
     INNOVA_PRIVACY_VNEXT_CAP_FCMP_BATCH_VERIFY | \
     INNOVA_PRIVACY_VNEXT_CAP_TREE_UPDATE | \
     INNOVA_PRIVACY_VNEXT_CAP_TREE_ROOT | \
     INNOVA_PRIVACY_VNEXT_CAP_TREE_WITNESS | \
     INNOVA_PRIVACY_VNEXT_CAP_PAYLOAD_VALIDATE | \
     INNOVA_PRIVACY_VNEXT_CAP_ADDRESS_CODEC | \
     INNOVA_PRIVACY_VNEXT_CAP_KEY_DERIVATION | \
     INNOVA_PRIVACY_VNEXT_CAP_NOTE_SCAN | \
     INNOVA_PRIVACY_VNEXT_CAP_NOTE_ENCRYPT | \
     INNOVA_PRIVACY_VNEXT_CAP_VALUE_PROVE | \
     INNOVA_PRIVACY_VNEXT_CAP_PAYLOAD_EFFECTS | \
     INNOVA_PRIVACY_VNEXT_CAP_NULLIFIER_ACCUMULATOR | \
     INNOVA_PRIVACY_VNEXT_CAP_TREE_EXTEND | \
     INNOVA_PRIVACY_VNEXT_CAP_PAYLOAD_SIGNING_HASH | \
     INNOVA_PRIVACY_VNEXT_CAP_RECEIVER_DISCLOSURE_PROVE | \
     INNOVA_PRIVACY_VNEXT_CAP_AMOUNT_EQUALITY_PROVE | \
     INNOVA_PRIVACY_VNEXT_CAP_VOTE_MEMBERSHIP | \
     INNOVA_PRIVACY_VNEXT_CAP_VOTE_SIGMA | \
     INNOVA_PRIVACY_VNEXT_CAP_ED25519_COMBINE | \
     INNOVA_PRIVACY_VNEXT_CAP_RANGE_PROOF | \
     INNOVA_PRIVACY_VNEXT_CAP_FCMP_SPLIT_PROVE | \
     INNOVA_PRIVACY_VNEXT_CAP_MIX_BALANCE | \
     INNOVA_PRIVACY_VNEXT_CAP_PAYLOAD_SCAN)

#define INNOVA_PRIVACY_VNEXT_OP_SHIELD (1u << 0)
#define INNOVA_PRIVACY_VNEXT_OP_UNSHIELD (1u << 1)
#define INNOVA_PRIVACY_VNEXT_OP_TRANSFER (1u << 2)
#define INNOVA_PRIVACY_VNEXT_OP_NULLSEND (1u << 3)
#define INNOVA_PRIVACY_VNEXT_OP_NULLSTAKE_V1 (1u << 4)
#define INNOVA_PRIVACY_VNEXT_OP_NULLSTAKE_V2 (1u << 5)
#define INNOVA_PRIVACY_VNEXT_OP_NULLSTAKE_V3_PRIVATE_COLD (1u << 6)
#define INNOVA_PRIVACY_VNEXT_OP_M_OF_N_PUBLIC_SIGNER (1u << 7)
#define INNOVA_PRIVACY_VNEXT_OP_M_OF_N_HIDDEN_SIGNER (1u << 8)
#define INNOVA_PRIVACY_VNEXT_OP_RECLAIM (1u << 9)
#define INNOVA_PRIVACY_VNEXT_OP_PRIVATE_FINALITY (1u << 10)
#define INNOVA_PRIVACY_VNEXT_REQUIRED_OPERATIONS ((1u << 11) - 1u)

typedef enum innova_privacy_vnext_result {
    INNOVA_PRIVACY_VNEXT_VALID = 0,
    INNOVA_PRIVACY_VNEXT_CONSENSUS_INVALID = 1,
    INNOVA_PRIVACY_VNEXT_BAD_LENGTH = 2,
    INNOVA_PRIVACY_VNEXT_UNSUPPORTED_FORMAT = 3,
    INNOVA_PRIVACY_VNEXT_RESOURCE_LIMIT = 4,
    INNOVA_PRIVACY_VNEXT_CONTAINED_PANIC = 5,
    INNOVA_PRIVACY_VNEXT_INTERNAL_LOCAL_STATE_FAILURE = 6
} innova_privacy_vnext_result;

/* Fixed product intent. consensus_active stays zero until a reviewed activation.
 * upstream_revision is 40 lowercase hex bytes without a terminator. */
typedef struct innova_privacy_vnext_contract {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t transaction_version;
    uint32_t consensus_active;
    uint32_t tree_layers;
    uint32_t max_inputs;
    uint32_t max_outputs;
    uint32_t max_payload_bytes;
    uint32_t disclosure_mode_min;
    uint32_t disclosure_mode_max;
    uint32_t nullstake_generation_min;
    uint32_t nullstake_generation_max;
    uint32_t required_operations;
    uint32_t payload_schema;
    uint32_t implemented_capabilities;
    uint32_t consensus_capabilities;
    uint8_t upstream_revision[INNOVA_PRIVACY_VNEXT_UPSTREAM_REVISION_SIZE];
} innova_privacy_vnext_contract;

/* Every function contains Rust panics and returns one deterministic result. */
int32_t innova_privacy_vnext_abi_version(uint32_t *out_version);
int32_t innova_privacy_vnext_abi_hash(uint8_t *out, size_t out_len);
int32_t innova_privacy_vnext_provenance_digest(uint8_t *out, size_t out_len);

/* SHA-256 of the fixed, explicitly non-consensus product contract. */
int32_t innova_privacy_vnext_parameter_digest(uint8_t *out, size_t out_len);
/* Accepted parameter digests as "count_u8 || 32 bytes each", own digest first.
 * A NULL out with zero capacity is a size query. */
int32_t innova_privacy_vnext_accepted_parameter_digests(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
/* Whether the envelope table admits one typed contract. Decodes nothing. */
int32_t innova_privacy_vnext_envelope_allows(
    uint32_t wire_version,
    uint8_t operation,
    uint8_t profile,
    uint8_t authorization,
    uint8_t finality_object,
    uint8_t disclosure_mask);
int32_t innova_privacy_vnext_contract_metadata(
    innova_privacy_vnext_contract *out,
    size_t out_len);
int32_t innova_privacy_vnext_protocol_contract(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);

/* Upstream FcmpPlusPlus::proof_size for 1..16 inputs and eight layers. No consensus
 * effect. */
int32_t innova_privacy_vnext_fcmp_proof_size(
    uint32_t inputs,
    uint32_t layers,
    size_t *out_size);

/* Each response input record is 256 bytes: pseudo-output, key image, mask delta,
 * sender authority, sender disclosure proof. Zeroize the mask delta after use. */
int32_t innova_privacy_vnext_fcmp_prove(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_fcmp_verify(
    const uint8_t *request,
    size_t request_len);
int32_t innova_privacy_vnext_fcmp_batch_verify(
    const uint8_t *request,
    size_t request_len,
    uint32_t request_count);

/*
 * The split prover. fcmp_membership_prove takes the spend proving request
 * with its signable-hash slot removed and returns schema_u16 || layers_u8 ||
 * count_u8 || count * (pseudo_out_32 || key_image_32 || mask_delta_32 ||
 * sender_authority_32) || instance_len_u32_le || instance, the instance being
 * a canonical membership verification request. fcmp_sal_prove takes
 * schema_u16 || layers_u8 || reserved_u8_zero || signable_hash_32 ||
 * proving_len_u32_le || that proving request || that instance, both verbatim,
 * and returns the fcmp_prove response. The mask delta is caller-secret. A
 * retry under a new hash reuses the membership half.
 */
int32_t innova_privacy_vnext_fcmp_membership_prove(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_fcmp_sal_prove(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);

/* Framing is fixed by abi/innova_privacy_vnext_v2.txt: schema 1, eight layers, Helios
 * root, at most 16 inputs. Proving self-verifies; consensus_capabilities stays zero. */

int32_t innova_privacy_vnext_tree_update(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_tree_extend(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_tree_root(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_nullifier_update(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_nullifier_root(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_tree_witness(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
/* Request: outer-wire-version-u32-le followed by one canonical payload. */
int32_t innova_privacy_vnext_payload_signing_hash(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_len);
/* Request: outer-wire-version-u32-le, network-id-u8, three zero bytes, the caller's
 * genesis hash, then one canonical payload. The payload's own network and genesis are
 * checked against the caller's. */
int32_t innova_privacy_vnext_payload_validate(
    const uint8_t *request,
    size_t request_len);
int32_t innova_privacy_vnext_payload_scan(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
/* Same request framing as innova_privacy_vnext_payload_validate. */
int32_t innova_privacy_vnext_payload_effects(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
/* Effects with the proof gates skipped. Structure is still enforced and the bytes are
   identical to innova_privacy_vnext_payload_effects for anything that accepts. The CALLER
   owns the assume-valid gate: this checks no height and no chain. */
int32_t innova_privacy_vnext_payload_effects_assume_valid(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_address_encode(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_address_decode(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_key_derive(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_note_scan(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_note_encrypt(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
/* Derive a payload's input context (INPUT_CONTEXT_SIZE bytes) from its operation,
 * transparent binding and key images. Feeds note_encrypt, note_scan and
 * receiver_disclosure_prove. */
int32_t innova_privacy_vnext_input_context(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_len);
int32_t innova_privacy_vnext_value_prove(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);

/* Prove one output's receiver disclosure (the sender side comes from fcmp_prove).
 * Self-verifies before returning. */
int32_t innova_privacy_vnext_receiver_disclosure_prove(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);

/* Prove one commitment opens to a fixed amount, without publishing its opening.
 * Request: schema_u16 || reserved_u16_zero || amount_u64_le || commitment_32 ||
 * mask_32 || signable_hash_32 || entropy_32. */
int32_t innova_privacy_vnext_amount_equality_prove(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);

/* A mix's joint balance proof. Facts: schema_u16 || output_count_u8 ||
 * input_count_u8 || transparent_value_balance_i64_le || fee_u64_le ||
 * signable_hash_32 || input_count * pseudo_out_32 || output_count * output_32.
 * Share: input_index_u8 || output_index_u8 || reserved_u16_zero ||
 * fee_share_u64_le || mask_32 || output_mask_32 || entropy_32.
 * The mask is the pseudo-output mask and is what the seat signs with; the
 * output mask is its own output's opening, checked against the declared pair
 * and never signed over, so a response names no output. The combiner folds the
 * output openings in, which are public because a mix discloses amounts.
 * nonce:   facts || share                              -> nonce point (32)
 * sign:    facts || share || input_count * nonce_32    -> response (32)
 * combine: facts || input_count * (nonce_32) || input_count * (response_32)
 *                || output_count * (output_mask_32)    -> proof (64)
 * One nonce signs under one aggregate per process; another aggregate returns
 * INTERNAL_LOCAL_STATE_FAILURE. Draw the entropy fresh per signing. */
int32_t innova_privacy_vnext_mix_balance_nonce(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_mix_balance_sign(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_mix_balance_combine(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);

/* Prove a membership-only instance for a note vote and report the per-input
 * sigma witnesses, which depend on blinds the prover draws internally.
 * Response: schema_u16 || input_count_u8 || reserved_u8_zero || input_count *
 * (o_tilde_32 || c_tilde_32 || rerandomized_y_32 || mask_delta_32) ||
 * request_len_u32_le || request. The two scalars are caller-secret. */
int32_t innova_privacy_vnext_vote_membership_prove(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);

/* Verify one membership-only instance. No key image and no signable hash take
 * part, so nothing here binds the proof to a message. */
int32_t innova_privacy_vnext_vote_membership_verify(
    const uint8_t *request,
    size_t request_len);

/* Prove the note-vote authorization sigma and derive its epoch tag.
 * Request: schema_u16 || reserved_u16_zero || epoch_u64_le || o_tilde_32 ||
 * c_tilde_32 || binding_32 || x_32 || rerandomized_y_32 || entropy_32.
 * Response: tag_32 || proof_128. */
int32_t innova_privacy_vnext_vote_sigma_prove(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);

/* Verify the note-vote authorization sigma against a caller-rebuilt statement.
 * Request: schema_u16 || reserved_u16_zero || epoch_u64_le || o_tilde_32 ||
 * c_tilde_32 || binding_32 || tag_32 || proof_128. */
int32_t innova_privacy_vnext_vote_sigma_verify(
    const uint8_t *request,
    size_t request_len);

/* Sum caller-named scalar*point terms over ed25519.
 * Request: schema_u16 || reserved_u16_zero || term_count_u16_le ||
 * reserved_u16_zero || term_count * (source_u8 || reserved_u8_zero_3 ||
 * scalar_32 || point_32). Source 0 supplied, 1 Monero H, 2 ed25519 basepoint;
 * a generator term must carry a zero point. Output may be the identity. */
int32_t innova_privacy_vnext_ed25519_combine(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);

/* Range-prove one commitment opening.
 * Request: schema_u16 || reserved_u16_zero || amount_u64_le || mask_32 ||
 * entropy_32. Response: commitment_32 || proof_len_u32_le || proof. */
int32_t innova_privacy_vnext_range_prove(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);

/* Verify a single-commitment range proof over a caller-derived point.
 * Request: schema_u16 || reserved_u16_zero || commitment_32 ||
 * signable_hash_32 || proof. */
int32_t innova_privacy_vnext_range_verify(
    const uint8_t *request,
    size_t request_len);

#ifdef __cplusplus
}
#endif

#endif /* INNOVA_PRIVACY_VNEXT_H */
