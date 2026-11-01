#ifndef INNOVA_NYX_PQ_H
#define INNOVA_NYX_PQ_H

/* Nyx messenger primitives (not a consensus input). Every function returns 0 on success. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NYX_MLKEM768_SEED 64u
#define NYX_MLKEM768_EK 1184u
#define NYX_MLKEM768_DK 2400u
#define NYX_MLKEM768_CT 1088u
#define NYX_MLKEM768_SS 32u
#define NYX_MLDSA65_SEED 32u
#define NYX_MLDSA65_PK 1952u
#define NYX_MLDSA65_SK 4032u
#define NYX_MLDSA65_SIG 3309u
#define NYX_X25519 32u
#define NYX_AEAD_KEY 32u
#define NYX_AEAD_NONCE 12u
#define NYX_AEAD_TAG 16u
#define NYX_PQ_SIZE_COUNT 13u

int nyx_random(uint8_t* out, size_t len);
/* Fills NYX_PQ_SIZE_COUNT sizes in the order of the defines above. */
int nyx_pq_sizes(uint32_t* out, size_t n);

int nyx_mlkem768_keygen(uint8_t* out_seed64, uint8_t* out_ek);
int nyx_mlkem768_ek_from_seed(const uint8_t* seed64, uint8_t* out_ek);
int nyx_mlkem768_encaps(const uint8_t* ek, uint8_t* out_ct, uint8_t* out_ss);
int nyx_mlkem768_decaps(const uint8_t* seed64, const uint8_t* ct, uint8_t* out_ss);

int nyx_mldsa65_keygen(uint8_t* out_seed32, uint8_t* out_pk);
int nyx_mldsa65_pk_from_seed(const uint8_t* seed32, uint8_t* out_pk);
int nyx_mldsa65_sign(const uint8_t* seed32, const uint8_t* msg, size_t len, uint8_t* out_sig);
int nyx_mldsa65_verify(const uint8_t* pk, const uint8_t* msg, size_t len, const uint8_t* sig);

int nyx_x25519_keygen(uint8_t* out_secret, uint8_t* out_public);
int nyx_x25519(const uint8_t* sk, const uint8_t* pk, uint8_t* out);

/* out may equal pt (in place); no other overlap. */
int nyx_aead_seal(const uint8_t* key, const uint8_t* nonce, const uint8_t* ad, size_t ad_len,
                  const uint8_t* pt, size_t pt_len, uint8_t* out);
int nyx_aead_open(const uint8_t* key, const uint8_t* nonce, const uint8_t* ad, size_t ad_len,
                  const uint8_t* ct, size_t ct_len, uint8_t* out);

int nyx_hkdf_sha256(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len,
                    const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len);

/* Known-answer test entry points; never used for live keys. */
int nyx_kat_mlkem768_encaps(const uint8_t* ek, const uint8_t* m32, uint8_t* out_ct, uint8_t* out_ss);
int nyx_kat_mlkem768_decaps(const uint8_t* dk2400, const uint8_t* ct, uint8_t* out_ss);
int nyx_kat_mldsa65_sign_internal(const uint8_t* sk4032, const uint8_t* mp, size_t len,
                                  const uint8_t* rnd32, uint8_t* out_sig);
int nyx_kat_mldsa65_verify_internal(const uint8_t* pk, const uint8_t* mp, size_t len, const uint8_t* sig);

#ifdef __cplusplus
}
#endif

#endif
