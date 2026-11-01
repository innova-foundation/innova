// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Known-answer tests for the Nyx PQ primitives, through the C FFI the node uses.

#include <boost/test/unit_test.hpp>

#include "../privacy_vnext/rust/include/nyx_pq.h"
#include "../nyxcert.h"
#include "../nyxpo.h"
#include "../util.h"
#include "data/nyx_pq_kat.h"

static_assert(NYX_MLDSA65_PK == NYX_MLDSA_PK, "ML-DSA-65 pk");
static_assert(NYX_MLDSA65_SIG == NYX_MLDSA_SIG, "ML-DSA-65 sig");
static_assert(NYX_MLKEM768_EK == NYX_MLKEM_EK, "ML-KEM-768 ek");

static std::vector<unsigned char> H(const char* s)
{
    return ParseHex(s);
}

static std::string Hx(const std::vector<unsigned char>& v)
{
    return HexStr(v.begin(), v.end());
}

static std::string Lower(const char* s)
{
    std::string r(s);
    for (size_t i = 0; i < r.size(); ++i)
        r[i] = tolower(r[i]);
    return r;
}

BOOST_AUTO_TEST_SUITE(nyx_pq_kat_tests)

BOOST_AUTO_TEST_CASE(sizes_match_header)
{
    uint32_t v[NYX_PQ_SIZE_COUNT];
    BOOST_REQUIRE_EQUAL(nyx_pq_sizes(v, NYX_PQ_SIZE_COUNT), 0);
    const uint32_t want[NYX_PQ_SIZE_COUNT] = {NYX_MLKEM768_SEED, NYX_MLKEM768_EK, NYX_MLKEM768_DK, NYX_MLKEM768_CT,
                                              NYX_MLKEM768_SS, NYX_MLDSA65_SEED, NYX_MLDSA65_PK, NYX_MLDSA65_SK,
                                              NYX_MLDSA65_SIG, NYX_X25519, NYX_AEAD_KEY, NYX_AEAD_NONCE, NYX_AEAD_TAG};
    for (unsigned int i = 0; i < NYX_PQ_SIZE_COUNT; ++i)
        BOOST_CHECK_EQUAL(v[i], want[i]);
    BOOST_CHECK(nyx_pq_sizes(v, NYX_PQ_SIZE_COUNT - 1) != 0);
}

BOOST_AUTO_TEST_CASE(mlkem768_keygen_acvp)
{
    for (size_t i = 0; i < sizeof(nyxKemKeyGen) / sizeof(nyxKemKeyGen[0]); ++i)
    {
        std::vector<unsigned char> seed = H(nyxKemKeyGen[i].d), z = H(nyxKemKeyGen[i].z);
        seed.insert(seed.end(), z.begin(), z.end());
        BOOST_REQUIRE_EQUAL(seed.size(), NYX_MLKEM768_SEED);
        std::vector<unsigned char> ek(NYX_MLKEM768_EK);
        BOOST_REQUIRE_EQUAL(nyx_mlkem768_ek_from_seed(&seed[0], &ek[0]), 0);
        BOOST_CHECK_MESSAGE(Hx(ek) == Lower(nyxKemKeyGen[i].ek), "tcId " << nyxKemKeyGen[i].tcId);
    }
}

BOOST_AUTO_TEST_CASE(mlkem768_encaps_acvp)
{
    for (size_t i = 0; i < sizeof(nyxKemEncap) / sizeof(nyxKemEncap[0]); ++i)
    {
        const std::vector<unsigned char> ek = H(nyxKemEncap[i].ek), m = H(nyxKemEncap[i].m);
        std::vector<unsigned char> ct(NYX_MLKEM768_CT), ss(NYX_MLKEM768_SS);
        BOOST_REQUIRE_EQUAL(nyx_kat_mlkem768_encaps(&ek[0], &m[0], &ct[0], &ss[0]), 0);
        BOOST_CHECK_MESSAGE(Hx(ct) == Lower(nyxKemEncap[i].c), "tcId " << nyxKemEncap[i].tcId);
        BOOST_CHECK_MESSAGE(Hx(ss) == Lower(nyxKemEncap[i].k), "tcId " << nyxKemEncap[i].tcId);
    }
}

BOOST_AUTO_TEST_CASE(mlkem768_decaps_acvp)
{
    // One valid ciphertext and one modified ciphertext (implicit rejection value).
    for (size_t i = 0; i < sizeof(nyxKemDecap) / sizeof(nyxKemDecap[0]); ++i)
    {
        const std::vector<unsigned char> dk = H(nyxKemDecap[i].dk), c = H(nyxKemDecap[i].c);
        std::vector<unsigned char> ss(NYX_MLKEM768_SS);
        BOOST_REQUIRE_EQUAL(nyx_kat_mlkem768_decaps(&dk[0], &c[0], &ss[0]), 0);
        BOOST_CHECK_MESSAGE(Hx(ss) == Lower(nyxKemDecap[i].k), "tcId " << nyxKemDecap[i].tcId);
    }
}

BOOST_AUTO_TEST_CASE(mlkem768_seed_round_trip)
{
    std::vector<unsigned char> seed(NYX_MLKEM768_SEED), ek(NYX_MLKEM768_EK), ct(NYX_MLKEM768_CT);
    std::vector<unsigned char> a(32), b(32);
    BOOST_REQUIRE_EQUAL(nyx_mlkem768_keygen(&seed[0], &ek[0]), 0);
    BOOST_REQUIRE_EQUAL(nyx_mlkem768_encaps(&ek[0], &ct[0], &a[0]), 0);
    BOOST_REQUIRE_EQUAL(nyx_mlkem768_decaps(&seed[0], &ct[0], &b[0]), 0);
    BOOST_CHECK(a == b);
    ct[5] ^= 1;
    BOOST_REQUIRE_EQUAL(nyx_mlkem768_decaps(&seed[0], &ct[0], &b[0]), 0);
    BOOST_CHECK(a != b);
}

BOOST_AUTO_TEST_CASE(mldsa65_keygen_acvp)
{
    for (size_t i = 0; i < sizeof(nyxDsaKeyGen) / sizeof(nyxDsaKeyGen[0]); ++i)
    {
        const std::vector<unsigned char> seed = H(nyxDsaKeyGen[i].seed);
        std::vector<unsigned char> pk(NYX_MLDSA65_PK);
        BOOST_REQUIRE_EQUAL(nyx_mldsa65_pk_from_seed(&seed[0], &pk[0]), 0);
        BOOST_CHECK_MESSAGE(Hx(pk) == Lower(nyxDsaKeyGen[i].pk), "tcId " << nyxDsaKeyGen[i].tcId);
    }
}

static std::vector<unsigned char> MPrime(bool fExternal, const char* msg, const char* ctx)
{
    const std::vector<unsigned char> m = H(msg), c = H(ctx);
    if (!fExternal)
        return m;
    std::vector<unsigned char> r;
    r.push_back(0);
    r.push_back((unsigned char)c.size());
    r.insert(r.end(), c.begin(), c.end());
    r.insert(r.end(), m.begin(), m.end());
    return r;
}

BOOST_AUTO_TEST_CASE(mldsa65_siggen_acvp)
{
    for (size_t i = 0; i < sizeof(nyxDsaSigGen) / sizeof(nyxDsaSigGen[0]); ++i)
    {
        const NyxDsaSigGenKat& t = nyxDsaSigGen[i];
        const std::vector<unsigned char> sk = H(t.sk), rnd = H(t.rnd), mp = MPrime(t.fExternal, t.msg, t.ctx);
        BOOST_REQUIRE_EQUAL(sk.size(), NYX_MLDSA65_SK);
        BOOST_REQUIRE_EQUAL(rnd.size(), 32U);
        std::vector<unsigned char> sig(NYX_MLDSA65_SIG);
        BOOST_REQUIRE_EQUAL(nyx_kat_mldsa65_sign_internal(&sk[0], mp.empty() ? NULL : &mp[0], mp.size(), &rnd[0], &sig[0]), 0);
        BOOST_CHECK_MESSAGE(Hx(sig) == Lower(t.sig), "tcId " << t.tcId);
    }
}

BOOST_AUTO_TEST_CASE(mldsa65_sigver_acvp)
{
    for (size_t i = 0; i < sizeof(nyxDsaSigVer) / sizeof(nyxDsaSigVer[0]); ++i)
    {
        const NyxDsaSigVerKat& t = nyxDsaSigVer[i];
        const std::vector<unsigned char> pk = H(t.pk), sig = H(t.sig), mp = MPrime(t.fExternal, t.msg, t.ctx);
        BOOST_REQUIRE_EQUAL(sig.size(), NYX_MLDSA65_SIG);
        const int r = nyx_kat_mldsa65_verify_internal(&pk[0], mp.empty() ? NULL : &mp[0], mp.size(), &sig[0]);
        BOOST_CHECK_MESSAGE((r == 0) == t.fPass, "tcId " << t.tcId);
        // The node's pure empty-context verify agrees with the internal form for empty contexts.
        if (t.fExternal && H(t.ctx).empty())
        {
            const std::vector<unsigned char> m = H(t.msg);
            BOOST_CHECK_EQUAL(nyx_mldsa65_verify(&pk[0], m.empty() ? NULL : &m[0], m.size(), &sig[0]) == 0, t.fPass);
        }
    }
}

BOOST_AUTO_TEST_CASE(mldsa65_sign_verify_and_tamper)
{
    std::vector<unsigned char> seed(32), pk(NYX_MLDSA65_PK), pk2(NYX_MLDSA65_PK), sig(NYX_MLDSA65_SIG), sig2(NYX_MLDSA65_SIG);
    const std::string msg = "nyx keyring";
    BOOST_REQUIRE_EQUAL(nyx_mldsa65_keygen(&seed[0], &pk[0]), 0);
    BOOST_REQUIRE_EQUAL(nyx_mldsa65_pk_from_seed(&seed[0], &pk2[0]), 0);
    BOOST_CHECK(pk == pk2);
    BOOST_REQUIRE_EQUAL(nyx_mldsa65_sign(&seed[0], (const uint8_t*)msg.data(), msg.size(), &sig[0]), 0);
    BOOST_REQUIRE_EQUAL(nyx_mldsa65_sign(&seed[0], (const uint8_t*)msg.data(), msg.size(), &sig2[0]), 0);
    BOOST_CHECK(sig != sig2);   // hedged
    BOOST_CHECK_EQUAL(nyx_mldsa65_verify(&pk[0], (const uint8_t*)msg.data(), msg.size(), &sig[0]), 0);
    BOOST_CHECK_EQUAL(nyx_mldsa65_verify(&pk[0], (const uint8_t*)msg.data(), msg.size(), &sig2[0]), 0);
    BOOST_CHECK(nyx_mldsa65_verify(&pk[0], (const uint8_t*)msg.data(), msg.size() - 1, &sig[0]) != 0);
    sig[100] ^= 0x10;
    BOOST_CHECK(nyx_mldsa65_verify(&pk[0], (const uint8_t*)msg.data(), msg.size(), &sig[0]) != 0);
}

BOOST_AUTO_TEST_CASE(x25519_rfc7748)
{
    struct { const char *k, *u, *out; } v[] = {
        {"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
         "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"},
        {"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
         "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
         "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"},
        // Section 6.1: public keys from the base point, then the shared secret both ways.
        {"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
         "0900000000000000000000000000000000000000000000000000000000000000",
         "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"},
        {"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
         "0900000000000000000000000000000000000000000000000000000000000000",
         "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"},
        {"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
         "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
         "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"},
        {"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
         "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
         "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"},
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); ++i)
    {
        const std::vector<unsigned char> k = H(v[i].k), u = H(v[i].u);
        std::vector<unsigned char> out(32);
        BOOST_REQUIRE_EQUAL(nyx_x25519(&k[0], &u[0], &out[0]), 0);
        BOOST_CHECK_EQUAL(Hx(out), v[i].out);
    }
    // Small-order input: all-zero output is refused.
    const std::vector<unsigned char> k = H(v[0].k);
    std::vector<unsigned char> zero(32, 0), out(32);
    BOOST_CHECK(nyx_x25519(&k[0], &zero[0], &out[0]) != 0);
}

BOOST_AUTO_TEST_CASE(hkdf_rfc5869)
{
    struct { const char *ikm, *salt, *info, *okm; } v[] = {
        {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
         "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
         "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
         "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
         "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
         "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
         "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09"
         "da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"},
        {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "",
         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"},
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); ++i)
    {
        const std::vector<unsigned char> ikm = H(v[i].ikm), salt = H(v[i].salt), info = H(v[i].info), want = H(v[i].okm);
        std::vector<unsigned char> okm(want.size());
        BOOST_REQUIRE_EQUAL(nyx_hkdf_sha256(salt.empty() ? NULL : &salt[0], salt.size(), &ikm[0], ikm.size(),
                                            info.empty() ? NULL : &info[0], info.size(), &okm[0], okm.size()), 0);
        BOOST_CHECK_EQUAL(Hx(okm), v[i].okm);
    }
    std::vector<unsigned char> big(255 * 32 + 1);
    const unsigned char ikm[1] = {1};
    BOOST_CHECK(nyx_hkdf_sha256(NULL, 0, ikm, 1, NULL, 0, &big[0], big.size()) != 0);
}

BOOST_AUTO_TEST_CASE(aead_rfc8439)
{
    const std::string pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
                           "sunscreen would be it.";
    const std::vector<unsigned char> key = H("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const std::vector<unsigned char> nonce = H("070000004041424344454647");
    const std::vector<unsigned char> aad = H("50515253c0c1c2c3c4c5c6c7");
    const std::string want =
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
        "1ae10b594f09e26a7e902ecbd0600691";
    std::vector<unsigned char> ct(pt.size() + 16);
    BOOST_REQUIRE_EQUAL(nyx_aead_seal(&key[0], &nonce[0], &aad[0], aad.size(), (const uint8_t*)pt.data(), pt.size(), &ct[0]), 0);
    BOOST_CHECK_EQUAL(Hx(ct), want);
    std::vector<unsigned char> back(pt.size());
    BOOST_REQUIRE_EQUAL(nyx_aead_open(&key[0], &nonce[0], &aad[0], aad.size(), &ct[0], ct.size(), &back[0]), 0);
    BOOST_CHECK(std::string(back.begin(), back.end()) == pt);
    ct[3] ^= 1;
    BOOST_CHECK(nyx_aead_open(&key[0], &nonce[0], &aad[0], aad.size(), &ct[0], ct.size(), &back[0]) != 0);
    ct[3] ^= 1;
    BOOST_CHECK(nyx_aead_open(&key[0], &nonce[0], &aad[0], aad.size() - 1, &ct[0], ct.size(), &back[0]) != 0);
    BOOST_CHECK(nyx_aead_open(&key[0], &nonce[0], NULL, 0, &ct[0], 15, &back[0]) != 0);
}

BOOST_AUTO_TEST_SUITE_END()
