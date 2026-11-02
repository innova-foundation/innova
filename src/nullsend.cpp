// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "nullsend.h"
#include "hash.h"
#include "util.h"

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

static std::vector<unsigned char> NS_BNToVec(const BIGNUM* bn, int nPadLen = 0)
{
    int nLen = BN_num_bytes(bn);
    int nOutLen = (nPadLen > 0 && nLen <= nPadLen) ? nPadLen : nLen;
    std::vector<unsigned char> vch(nOutLen, 0);
    BN_bn2bin(bn, vch.data() + (nOutLen - nLen));
    return vch;
}

static BIGNUM* NS_VecToBN(const std::vector<unsigned char>& vch)
{
    return BN_bin2bn(vch.data(), (int)vch.size(), NULL);
}

// Full-domain hash for the RSA blind-credential message (fixes M-3). A bare
// SHA256 representative occupies only 256 of the modulus' ~2048 bits, which makes
// the textbook-RSA blind signature multiplicatively malleable and not
// one-more-unforgeable. NS_FullDomainHash expands the message to a near-uniform
// integer in [2, n-1] via MGF1-SHA256 over a domain-separated seed, so forging a
// credential reduces to a full RSA inversion. The reduction into [2, n-1] also
// excludes the trivial 0/1 message representatives. Signer and verifier MUST both
// route the message through this function so the round-trip is preserved.
static bool NS_FullDomainHash(const std::vector<unsigned char>& vchMsg,
                              const BIGNUM* n, BIGNUM* out, BN_CTX* ctx)
{
    if (!n || !out || !ctx)
        return false;
    int nLen = BN_num_bytes(n);
    if (nLen <= 0)
        return false;

    // Domain-separated seed = TAG || SHA256(msg).
    static const char NS_FDH_TAG[] = "Innova/NullSend/FDH/v1";
    unsigned char seed[SHA256_DIGEST_LENGTH];
    {
        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, NS_FDH_TAG, sizeof(NS_FDH_TAG) - 1);
        SHA256_Update(&sha, vchMsg.data(), vchMsg.size());
        SHA256_Final(seed, &sha);
    }

    // MGF1-SHA256: produce > modulus-size bytes so the mod reduction bias < 2^-256.
    std::vector<unsigned char> vchExpand;
    vchExpand.reserve(nLen + SHA256_DIGEST_LENGTH);
    uint32_t counter = 0;
    while ((int)vchExpand.size() < nLen + SHA256_DIGEST_LENGTH)
    {
        unsigned char cbe[4] = {
            (unsigned char)(counter >> 24), (unsigned char)(counter >> 16),
            (unsigned char)(counter >> 8),  (unsigned char)(counter) };
        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, seed, SHA256_DIGEST_LENGTH);
        SHA256_Update(&sha, cbe, sizeof(cbe));
        unsigned char blk[SHA256_DIGEST_LENGTH];
        SHA256_Final(blk, &sha);
        vchExpand.insert(vchExpand.end(), blk, blk + SHA256_DIGEST_LENGTH);
        counter++;
    }

    BIGNUM* t = BN_bin2bn(vchExpand.data(), (int)vchExpand.size(), NULL);
    BIGNUM* nm2 = BN_new();
    bool fOk = false;
    // out = (t mod (n-2)) + 2  ->  out in [2, n-1]
    if (t && nm2 && BN_copy(nm2, n) && BN_sub_word(nm2, 2) &&
        BN_mod(out, t, nm2, ctx) && BN_add_word(out, 2))
        fOk = true;
    if (t) BN_free(t);
    if (nm2) BN_free(nm2);
    return fOk;
}

bool CNullSendSession::GenerateSessionRSAKey()
{
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* phi = BN_new();
    BIGNUM* p1 = BN_new();
    BIGNUM* q1 = BN_new();

    if (!ctx || !p || !q || !n || !e || !d || !phi || !p1 || !q1)
    {
        BN_CTX_free(ctx); BN_free(p); BN_free(q); BN_free(n);
        BN_free(e); BN_free(d); BN_free(phi); BN_free(p1); BN_free(q1);
        return false;
    }

    bool fOk = false;

    if (!BN_generate_prime_ex(p, NULLSEND_RSA_BITS / 2, 0, NULL, NULL, NULL))
        goto ns_rsa_cleanup;
    if (!BN_generate_prime_ex(q, NULLSEND_RSA_BITS / 2, 0, NULL, NULL, NULL))
        goto ns_rsa_cleanup;
    if (BN_cmp(p, q) == 0)
        goto ns_rsa_cleanup;
    if (!BN_mul(n, p, q, ctx))
        goto ns_rsa_cleanup;
    if (!BN_set_word(e, 65537))
        goto ns_rsa_cleanup;
    if (!BN_sub(p1, p, BN_value_one()))
        goto ns_rsa_cleanup;
    if (!BN_sub(q1, q, BN_value_one()))
        goto ns_rsa_cleanup;
    if (!BN_mul(phi, p1, q1, ctx))
        goto ns_rsa_cleanup;
    if (!BN_mod_inverse(d, e, phi, ctx))
        goto ns_rsa_cleanup;

    {
        int nKeyBytes = NULLSEND_RSA_BITS / 8;
        vchRSA_N = NS_BNToVec(n, nKeyBytes);
        vchRSA_E = NS_BNToVec(e);
        vchRSA_D = NS_BNToVec(d, nKeyBytes);
    }

    fOk = true;

ns_rsa_cleanup:
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(d);
    BN_clear_free(phi);
    BN_clear_free(p1);
    BN_clear_free(q1);
    BN_free(n);
    BN_free(e);
    BN_CTX_free(ctx);

    if (fOk && fDebug)
        printf("NullSend session %d: RSA-%d key generated\n", nSessionID, NULLSEND_RSA_BITS);

    return fOk;
}

bool CNullSendSession::BlindSign(const std::vector<unsigned char>& vchBlinded,
                                  std::vector<unsigned char>& vchSignatureOut)
{
    if (vchRSA_D.empty() || vchRSA_N.empty())
        return false;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* m = NS_VecToBN(vchBlinded);
    BIGNUM* d_bn = NS_VecToBN(vchRSA_D);
    BIGNUM* n_bn = NS_VecToBN(vchRSA_N);
    BIGNUM* s = BN_new();

    if (!ctx || !m || !d_bn || !n_bn || !s)
    {
        BN_CTX_free(ctx); BN_free(m); BN_clear_free(d_bn); BN_free(n_bn); BN_free(s);
        return false;
    }

    // Reject degenerate blinded values (0, 1, n-1) that produce trivial signatures.
    bool fRange = false;
    {
        BIGNUM* nm1 = BN_new();
        if (nm1 && BN_copy(nm1, n_bn) && BN_sub_word(nm1, 1))
            fRange = (BN_cmp(m, BN_value_one()) > 0) && (BN_cmp(m, nm1) < 0);
        if (nm1) BN_free(nm1);
    }
    if (!fRange)
    {
        BN_free(m); BN_clear_free(d_bn); BN_free(n_bn); BN_free(s);
        BN_CTX_free(ctx);
        return false;
    }

    bool fOk = BN_mod_exp_mont_consttime(s, m, d_bn, n_bn, ctx, NULL) == 1;

    if (fOk)
        vchSignatureOut = NS_BNToVec(s, NULLSEND_RSA_BITS / 8);

    BN_free(m);
    BN_clear_free(d_bn);
    BN_free(n_bn);
    BN_free(s);
    BN_CTX_free(ctx);

    return fOk;
}

// Shape fence against a grossly malformed round key. Pinning e = 65537 does not make
// x -> x^e a permutation of Z_N*; unlinkability rests on the participant verifying its
// own token (UnblindSignature), not on this check.
bool IsMixRoundKeyWellFormed(const std::vector<unsigned char>& vchRSA_N,
                             const std::vector<unsigned char>& vchRSA_E)
{
    if (vchRSA_N.size() != (size_t)(NULLSEND_RSA_BITS / 8))
        return false;
    if ((vchRSA_N[0] & 0x80) == 0)          // full-width modulus
        return false;
    if ((vchRSA_N.back() & 0x01) == 0)      // a product of odd primes is odd
        return false;
    // 65537, byte-exact, which is what the generator encodes and what the commitment
    // is taken over.
    static const unsigned char vchE65537[3] = { 0x01, 0x00, 0x01 };
    return vchRSA_E.size() == sizeof(vchE65537) &&
           memcmp(&vchRSA_E[0], vchE65537, sizeof(vchE65537)) == 0;
}

// Extracted so the v2008 round can check a token with the same code the legacy
// session does, rather than a second copy of the BN arithmetic.
bool VerifyMixCredential(const std::vector<unsigned char>& vchRSA_N,
                         const std::vector<unsigned char>& vchRSA_E,
                         const std::vector<unsigned char>& vchCredential,
                         const std::vector<unsigned char>& vchSignature)
{
    if (vchRSA_N.empty() || vchRSA_E.empty())
        return false;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* s_bn = NS_VecToBN(vchSignature);
    BIGNUM* e_bn = NS_VecToBN(vchRSA_E);
    BIGNUM* n_bn = NS_VecToBN(vchRSA_N);
    BIGNUM* result = BN_new();

    if (!ctx || !s_bn || !e_bn || !n_bn || !result)
    {
        BN_CTX_free(ctx); BN_free(s_bn); BN_free(e_bn); BN_free(n_bn); BN_free(result);
        return false;
    }

    // Reject trivial signature fixed points (0, 1, n-1) before verifying.
    bool fSigRange = false;
    {
        BIGNUM* nm1 = BN_new();
        if (nm1 && BN_copy(nm1, n_bn) && BN_sub_word(nm1, 1))
            fSigRange = (BN_cmp(s_bn, BN_value_one()) > 0) && (BN_cmp(s_bn, nm1) < 0);
        if (nm1) BN_free(nm1);
    }

    bool fOk = fSigRange && (BN_mod_exp(result, s_bn, e_bn, n_bn, ctx) == 1);

    if (fOk)
    {
        // Full-domain-hash representative; must match the signer's NS_FullDomainHash.
        BIGNUM* expected = BN_new();
        if (expected && NS_FullDomainHash(vchCredential, n_bn, expected, ctx))
            fOk = (BN_cmp(result, expected) == 0);
        else
            fOk = false;
        if (expected) BN_free(expected);
    }

    BN_free(s_bn);
    BN_free(e_bn);
    BN_free(n_bn);
    BN_free(result);
    BN_CTX_free(ctx);

    return fOk;
}

bool CNullSendSession::VerifyCredential(const std::vector<unsigned char>& vchCredential,
                                         const std::vector<unsigned char>& vchSignature)
{
    return VerifyMixCredential(vchRSA_N, vchRSA_E, vchCredential, vchSignature);
}

void CNullSendClient::Reset()
{
    if (!vchBlindingFactor.empty())
        OPENSSL_cleanse(vchBlindingFactor.data(), vchBlindingFactor.size());
    vchBlindingFactor.clear();
    vchCredentialHash.clear();
    vchBlindedCredential.clear();
    vchUnblindedSig.clear();
    vchSessionRSA_N.clear();
    vchSessionRSA_E.clear();
    vMyOutputsDeferred.clear();
    nMyOutputValue = 0;
}

bool CNullSendClient::BlindOutputCredential(const std::vector<unsigned char>& vchN,
                                              const std::vector<unsigned char>& vchE)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const CShieldedOutputDescription& output : vMyOutputsDeferred)
        ss << output;
    ss << nMyOutputValue;
    return BlindCredentialMessage(vchN, vchE, ss.GetHash());
}

bool CNullSendClient::BlindCredentialMessage(const std::vector<unsigned char>& vchN,
                                             const std::vector<unsigned char>& vchE,
                                             const uint256& hashMessage)
{
    if (!IsMixRoundKeyWellFormed(vchN, vchE))
        return false;

    vchSessionRSA_N = vchN;
    vchSessionRSA_E = vchE;
    vchCredentialHash.assign(hashMessage.begin(), hashMessage.end());

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* n_bn = NS_VecToBN(vchN);
    BIGNUM* e_bn = NS_VecToBN(vchE);
    BIGNUM* r = BN_new();
    BIGNUM* r_e = BN_new();
    BIGNUM* blinded = BN_new();
    BIGNUM* m_mod = BN_new();

    if (!ctx || !n_bn || !e_bn || !r || !r_e || !blinded || !m_mod)
    {
        BN_CTX_free(ctx); BN_free(n_bn); BN_free(e_bn);
        BN_free(r); BN_free(r_e); BN_free(blinded); BN_free(m_mod);
        return false;
    }

    bool fOk = false;

    // Full-domain-hash representative (must match VerifyCredential's NS_FullDomainHash).
    if (!NS_FullDomainHash(vchCredentialHash, n_bn, m_mod, ctx))
        goto ns_blind_cleanup;

    {
        // r must be uniform over Z_N*; a fixed-width BN_rand with the top bit set
        // lands in a sub-interval the signer could test against.
        for (int tries = 0; tries < 100; tries++)
        {
            if (!BN_priv_rand_range(r, n_bn))
                goto ns_blind_cleanup;
            if (BN_cmp(r, BN_value_one()) <= 0)
                continue;   // 0 and 1 blind nothing

            BIGNUM* gcd = BN_new();
            if (!gcd) goto ns_blind_cleanup;
            BN_gcd(gcd, r, n_bn, ctx);
            bool fCoprime = BN_is_one(gcd);
            BN_free(gcd);
            if (fCoprime)
                break;
            if (tries == 99)
                goto ns_blind_cleanup;
        }
    }

    vchBlindingFactor = NS_BNToVec(r, (int)vchN.size());

    if (!BN_mod_exp(r_e, r, e_bn, n_bn, ctx))
        goto ns_blind_cleanup;

    if (!BN_mod_mul(blinded, m_mod, r_e, n_bn, ctx))
        goto ns_blind_cleanup;

    vchBlindedCredential = NS_BNToVec(blinded, (int)vchN.size());
    fOk = true;

ns_blind_cleanup:
    BN_free(m_mod);
    BN_free(n_bn);
    BN_free(e_bn);
    BN_clear_free(r);
    BN_free(r_e);
    BN_free(blinded);
    BN_CTX_free(ctx);

    return fOk;
}

bool CNullSendClient::UnblindSignature(const std::vector<unsigned char>& vchBlindSig)
{
    if (vchBlindingFactor.empty() || vchSessionRSA_N.empty())
        return false;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* s_prime = NS_VecToBN(vchBlindSig);
    BIGNUM* r_bn = NS_VecToBN(vchBlindingFactor);
    BIGNUM* n_bn = NS_VecToBN(vchSessionRSA_N);
    BIGNUM* r_inv = BN_new();
    BIGNUM* s = BN_new();

    if (!ctx || !s_prime || !r_bn || !n_bn || !r_inv || !s)
    {
        BN_CTX_free(ctx); BN_free(s_prime); BN_clear_free(r_bn);
        BN_free(n_bn); BN_free(r_inv); BN_free(s);
        return false;
    }

    bool fOk = false;

    if (!BN_mod_inverse(r_inv, r_bn, n_bn, ctx))
        goto ns_unblind_cleanup;

    if (!BN_mod_mul(s, s_prime, r_inv, n_bn, ctx))
        goto ns_unblind_cleanup;

    {
        // Only the participant can verify its token (the payload does not carry it); a
        // per-seat value in place of a signature would link seat to output.
        const std::vector<unsigned char> vchCandidate =
            NS_BNToVec(s, (int)vchSessionRSA_N.size());
        if (!VerifyMixCredential(vchSessionRSA_N, vchSessionRSA_E, vchCredentialHash,
                                 vchCandidate))
            goto ns_unblind_cleanup;
        vchUnblindedSig = vchCandidate;
        fOk = true;
    }

ns_unblind_cleanup:
    BN_free(s_prime);
    BN_clear_free(r_bn);
    BN_free(n_bn);
    BN_clear_free(r_inv);
    BN_clear_free(s);
    BN_CTX_free(ctx);

    if (!vchBlindingFactor.empty())
        OPENSSL_cleanse(vchBlindingFactor.data(), vchBlindingFactor.size());
    vchBlindingFactor.clear();

    return fOk;
}
