#include "innova_privacy_vnext.h"

_Static_assert(INNOVA_PRIVACY_VNEXT_ABI_VERSION == 2u, "ABI version changed");
_Static_assert(INNOVA_PRIVACY_VNEXT_DIGEST_SIZE == 32u, "digest size changed");
_Static_assert(INNOVA_PRIVACY_VNEXT_TREE_LAYERS == 8u, "tree depth changed");
_Static_assert(INNOVA_PRIVACY_VNEXT_MAX_INPUTS == 16u, "input cap changed");
_Static_assert(INNOVA_PRIVACY_VNEXT_MAX_OUTPUTS == 16u, "output cap changed");
_Static_assert(INNOVA_PRIVACY_VNEXT_DISCLOSURE_MODE_MAX == 7u,
               "disclosure modes changed");
_Static_assert(INNOVA_PRIVACY_VNEXT_NULLSTAKE_GENERATION_MAX == 3u,
               "NullStake generations changed");
_Static_assert(INNOVA_PRIVACY_VNEXT_REQUIRED_OPERATIONS == 0x7ffu,
               "required operations changed");
_Static_assert(sizeof(innova_privacy_vnext_contract) == 104u,
               "contract metadata layout changed");
_Static_assert(INNOVA_PRIVACY_VNEXT_IMPLEMENTED_CAPABILITIES == 131071u,
               "implemented capabilities changed");
_Static_assert(INNOVA_PRIVACY_VNEXT_VALID == 0, "valid result changed");
_Static_assert(INNOVA_PRIVACY_VNEXT_INTERNAL_LOCAL_STATE_FAILURE == 6,
               "result taxonomy changed");

int main(void)
{
    uint32_t version = 0;
    size_t proof_size = 0;
    uint8_t digest[INNOVA_PRIVACY_VNEXT_DIGEST_SIZE] = {0};
    innova_privacy_vnext_contract metadata = {0};
    const uint8_t request[1] = {0};
    (void)innova_privacy_vnext_abi_version(&version);
    (void)innova_privacy_vnext_abi_hash(digest, sizeof(digest));
    (void)innova_privacy_vnext_provenance_digest(digest, sizeof(digest));
    (void)innova_privacy_vnext_parameter_digest(digest, sizeof(digest));
    (void)innova_privacy_vnext_contract_metadata(&metadata, sizeof(metadata));
    (void)innova_privacy_vnext_protocol_contract(NULL, 0, &proof_size);
    (void)innova_privacy_vnext_fcmp_proof_size(
        INNOVA_PRIVACY_VNEXT_MAX_INPUTS,
        INNOVA_PRIVACY_VNEXT_TREE_LAYERS,
        &proof_size);
    (void)innova_privacy_vnext_fcmp_prove(
        request, sizeof(request), NULL, 0, &proof_size);
    (void)innova_privacy_vnext_fcmp_verify(request, sizeof(request));
    (void)innova_privacy_vnext_fcmp_batch_verify(request, sizeof(request), 1);
    (void)innova_privacy_vnext_tree_update(request, sizeof(request), NULL, 0, &proof_size);
    (void)innova_privacy_vnext_tree_root(request, sizeof(request), NULL, 0, &proof_size);
    (void)innova_privacy_vnext_tree_witness(request, sizeof(request), NULL, 0, &proof_size);
    (void)innova_privacy_vnext_payload_validate(request, sizeof(request));
    (void)innova_privacy_vnext_address_encode(request, sizeof(request), NULL, 0, &proof_size);
    (void)innova_privacy_vnext_address_decode(request, sizeof(request), NULL, 0, &proof_size);
    (void)innova_privacy_vnext_key_derive(request, sizeof(request), NULL, 0, &proof_size);
    (void)innova_privacy_vnext_note_scan(request, sizeof(request), NULL, 0, &proof_size);
    return 0;
}
