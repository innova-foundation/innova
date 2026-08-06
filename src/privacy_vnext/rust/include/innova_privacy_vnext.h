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
#define INNOVA_PRIVACY_VNEXT_NOTE_SCAN_PREFIX_SIZE 236u
#define INNOVA_PRIVACY_VNEXT_NOTE_SCAN_RESULT_SIZE 212u
#define INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE 177u
#define INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE 209u
#define INNOVA_PRIVACY_VNEXT_NOTE_ENCRYPT_REQUEST_SIZE 272u
#define INNOVA_PRIVACY_VNEXT_NOTE_ENCRYPT_RESULT_SIZE 522u
#define INNOVA_PRIVACY_VNEXT_FCMP_PROVE_RESPONSE_HEADER_SIZE 4u
#define INNOVA_PRIVACY_VNEXT_FCMP_PROVE_RESPONSE_RECORD_SIZE 256u
#define INNOVA_PRIVACY_VNEXT_FCMP_PROVE_MASK_DELTA_OFFSET 64u
#define INNOVA_PRIVACY_VNEXT_FCMP_PROVE_SENDER_AUTHORITY_OFFSET 96u
#define INNOVA_PRIVACY_VNEXT_FCMP_PROVE_SENDER_PROOF_OFFSET 128u
#define INNOVA_PRIVACY_VNEXT_SENDER_DISCLOSURE_PROOF_SIZE 128u
#define INNOVA_PRIVACY_VNEXT_VALUE_PROVE_HEADER_SIZE 116u
#define INNOVA_PRIVACY_VNEXT_PAYLOAD_EFFECTS_HEADER_SIZE 92u
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
int32_t innova_privacy_vnext_payload_validate(
    const uint8_t *request,
    size_t request_len);
int32_t innova_privacy_vnext_payload_scan(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);
int32_t innova_privacy_vnext_payload_effects(
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
int32_t innova_privacy_vnext_value_prove(
    const uint8_t *request,
    size_t request_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_written);

#ifdef __cplusplus
}
#endif

#endif /* INNOVA_PRIVACY_VNEXT_H */
