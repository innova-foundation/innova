#include "nyx_pq.h"

_Static_assert(NYX_MLKEM768_SEED == 64u, "ML-KEM-768 seed size changed");
_Static_assert(NYX_MLKEM768_EK == 1184u, "ML-KEM-768 encapsulation key size changed");
_Static_assert(NYX_MLKEM768_DK == 2400u, "ML-KEM-768 decapsulation key size changed");
_Static_assert(NYX_MLKEM768_CT == 1088u, "ML-KEM-768 ciphertext size changed");
_Static_assert(NYX_MLDSA65_PK == 1952u, "ML-DSA-65 public key size changed");
_Static_assert(NYX_MLDSA65_SK == 4032u, "ML-DSA-65 expanded key size changed");
_Static_assert(NYX_MLDSA65_SIG == 3309u, "ML-DSA-65 signature size changed");
_Static_assert(NYX_AEAD_NONCE == 12u && NYX_AEAD_TAG == 16u, "AEAD sizes changed");
_Static_assert(NYX_PQ_SIZE_COUNT == 13u, "size list changed");

int main(void)
{
    uint32_t sizes[NYX_PQ_SIZE_COUNT];
    return nyx_pq_sizes(sizes, NYX_PQ_SIZE_COUNT);
}
