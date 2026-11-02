// Tests for the NullSend blind credential.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../nullsend.h"
#include "../shielded.h"
#include "../zkproof.h"

#include <openssl/bn.h>
#include <vector>

namespace {

// A session holding a fresh ephemeral RSA key, for blind-credential tests (M-3).
CNullSendSession MakeKeyedSession()
{
    CNullSendSession session;
    session.nSessionID = 7;
    BOOST_REQUIRE(session.GenerateSessionRSAKey());
    return session;
}

// A client that has blinded a credential over one output and the given value.
CNullSendClient MakeCredentialClient(const std::vector<unsigned char>& vchN,
                                     const std::vector<unsigned char>& vchE,
                                     int64_t value)
{
    CNullSendClient client;
    client.vMyOutputsDeferred.push_back(CShieldedOutputDescription());
    client.nMyOutputValue = value;
    BOOST_REQUIRE(client.BlindOutputCredential(vchN, vchE));
    return client;
}

} // namespace

BOOST_AUTO_TEST_SUITE(nullsend_binding_tests)

// M-3: the full-domain-hash blind credential round-trips end to end.
BOOST_AUTO_TEST_CASE(fdh_blind_credential_round_trips)
{
    CNullSendSession server = MakeKeyedSession();
    CNullSendClient client = MakeCredentialClient(server.vchRSA_N, server.vchRSA_E, 1000);
    std::vector<unsigned char> blindSig;
    BOOST_REQUIRE(server.BlindSign(client.vchBlindedCredential, blindSig));
    BOOST_REQUIRE(client.UnblindSignature(blindSig));
    BOOST_CHECK(server.VerifyCredential(client.vchCredentialHash, client.vchUnblindedSig));
}

// A valid signature must not verify against a different credential message.
BOOST_AUTO_TEST_CASE(fdh_credential_rejects_wrong_message)
{
    CNullSendSession server = MakeKeyedSession();
    CNullSendClient client = MakeCredentialClient(server.vchRSA_N, server.vchRSA_E, 1000);
    std::vector<unsigned char> blindSig;
    BOOST_REQUIRE(server.BlindSign(client.vchBlindedCredential, blindSig));
    BOOST_REQUIRE(client.UnblindSignature(blindSig));
    std::vector<unsigned char> wrong = client.vchCredentialHash;
    wrong[0] ^= 0x01;
    BOOST_CHECK(!server.VerifyCredential(wrong, client.vchUnblindedSig));
}

// Trivial signature fixed points (0, 1, n-1) must be rejected by the range check.
BOOST_AUTO_TEST_CASE(fdh_credential_rejects_degenerate_signatures)
{
    CNullSendSession server = MakeKeyedSession();
    std::vector<unsigned char> msg(32, 0x07);
    std::vector<unsigned char> sig0(1, 0x00);
    std::vector<unsigned char> sig1(1, 0x01);
    std::vector<unsigned char> sigNm1 = server.vchRSA_N; // N is odd => N-1 = drop low bit
    sigNm1.back() -= 1;
    BOOST_CHECK(!server.VerifyCredential(msg, sig0));
    BOOST_CHECK(!server.VerifyCredential(msg, sig1));
    BOOST_CHECK(!server.VerifyCredential(msg, sigNm1));
}

// Multiplicative malleability: s_C = s_A * s_B mod n must not verify for either
// original message. (Textbook-RSA one-more forgeability is closed by the FDH.)
BOOST_AUTO_TEST_CASE(fdh_credential_resists_multiplicative_malleability)
{
    CNullSendSession server = MakeKeyedSession();
    CNullSendClient ca = MakeCredentialClient(server.vchRSA_N, server.vchRSA_E, 111);
    CNullSendClient cb = MakeCredentialClient(server.vchRSA_N, server.vchRSA_E, 222);
    std::vector<unsigned char> bsA, bsB;
    BOOST_REQUIRE(server.BlindSign(ca.vchBlindedCredential, bsA));
    BOOST_REQUIRE(server.BlindSign(cb.vchBlindedCredential, bsB));
    BOOST_REQUIRE(ca.UnblindSignature(bsA));
    BOOST_REQUIRE(cb.UnblindSignature(bsB));

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* sA = BN_bin2bn(ca.vchUnblindedSig.data(), (int)ca.vchUnblindedSig.size(), NULL);
    BIGNUM* sB = BN_bin2bn(cb.vchUnblindedSig.data(), (int)cb.vchUnblindedSig.size(), NULL);
    BIGNUM* n  = BN_bin2bn(server.vchRSA_N.data(), (int)server.vchRSA_N.size(), NULL);
    BIGNUM* sC = BN_new();
    BOOST_REQUIRE(ctx && sA && sB && n && sC);
    BOOST_REQUIRE(BN_mod_mul(sC, sA, sB, n, ctx));
    int len = (int)server.vchRSA_N.size();
    std::vector<unsigned char> vchSC(len, 0);
    int nb = BN_num_bytes(sC);
    BN_bn2bin(sC, vchSC.data() + (len - nb));
    BN_free(sA); BN_free(sB); BN_free(n); BN_free(sC); BN_CTX_free(ctx);

    BOOST_CHECK(!server.VerifyCredential(ca.vchCredentialHash, vchSC));
    BOOST_CHECK(!server.VerifyCredential(cb.vchCredentialHash, vchSC));
}

// Only the holder verifies the token, so the participant must check it is a valid
// signature under the committed key; otherwise per-seat values would link seats to outputs.
BOOST_AUTO_TEST_CASE(a_token_the_round_key_did_not_sign_is_never_presented)
{
    CNullSendSession server = MakeKeyedSession();
    CNullSendClient client = MakeCredentialClient(server.vchRSA_N, server.vchRSA_E, 4242);

    // The control: a real blind signature unblinds and is kept.
    {
        CNullSendClient honest = MakeCredentialClient(server.vchRSA_N, server.vchRSA_E, 4243);
        std::vector<unsigned char> blindSig;
        BOOST_REQUIRE(server.BlindSign(honest.vchBlindedCredential, blindSig));
        BOOST_REQUIRE(honest.UnblindSignature(blindSig));
        BOOST_CHECK(!honest.vchUnblindedSig.empty());
        BOOST_CHECK(server.VerifyCredential(honest.vchCredentialHash, honest.vchUnblindedSig));
    }

    // A non-signature return must leave the participant with nothing to present.
    std::vector<unsigned char> vchNotASignature(server.vchRSA_N.size(), 0);
    vchNotASignature[vchNotASignature.size() - 1] = 0x2a;
    vchNotASignature[0] = 0x01;
    BOOST_CHECK_MESSAGE(!client.UnblindSignature(vchNotASignature),
                        "a value that is not a signature under the round key was accepted");
    BOOST_CHECK_MESSAGE(client.vchUnblindedSig.empty(),
                        "an unverified token was kept, so it can still be presented and the "
                        "coordinator can recognise it");
}

// Refuses malformed key shapes only; e = 65537 does not imply gcd(e, phi(N)) = 1, so
// unlinkability rests on the local token check above.
BOOST_AUTO_TEST_CASE(a_round_key_of_the_wrong_shape_is_refused)
{
    CNullSendSession server = MakeKeyedSession();
    BOOST_REQUIRE(IsMixRoundKeyWellFormed(server.vchRSA_N, server.vchRSA_E));

    std::vector<unsigned char> vchE3;
    vchE3.push_back(0x03);
    BOOST_CHECK_MESSAGE(!IsMixRoundKeyWellFormed(server.vchRSA_N, vchE3),
                        "an exponent other than 65537 was accepted");

    std::vector<unsigned char> vchEven = server.vchRSA_N;
    vchEven[vchEven.size() - 1] &= 0xFE;
    BOOST_CHECK_MESSAGE(!IsMixRoundKeyWellFormed(vchEven, server.vchRSA_E),
                        "an even modulus was accepted");

    std::vector<unsigned char> vchNarrow = server.vchRSA_N;
    vchNarrow[0] &= 0x7F;
    BOOST_CHECK(!IsMixRoundKeyWellFormed(vchNarrow, server.vchRSA_E));

    std::vector<unsigned char> vchShort(server.vchRSA_N.begin(), server.vchRSA_N.end() - 1);
    BOOST_CHECK(!IsMixRoundKeyWellFormed(vchShort, server.vchRSA_E));

    // And a participant refuses to blind under one.
    CNullSendClient client;
    client.vMyOutputsDeferred.push_back(CShieldedOutputDescription());
    client.nMyOutputValue = 7;
    BOOST_CHECK_MESSAGE(!client.BlindOutputCredential(server.vchRSA_N, vchE3),
                        "a participant blinded under a key of the wrong shape");
}

// Blinding hides the credential only when r is uniform on Z_N*.
BOOST_AUTO_TEST_CASE(the_blinding_factor_spans_the_whole_modulus)
{
    CNullSendSession server = MakeKeyedSession();
    const size_t nBytes = server.vchRSA_N.size();

    // Over many draws, r's leading byte must fall both below and at/above 0x80.
    bool fSawTopBitClear = false;
    bool fSawTopBitSet = false;
    for (int i = 0; i < 48 && !(fSawTopBitClear && fSawTopBitSet); i++)
    {
        CNullSendClient client = MakeCredentialClient(server.vchRSA_N, server.vchRSA_E,
                                                      1000 + i);
        BOOST_REQUIRE_EQUAL(client.vchBlindingFactor.size(), nBytes);
        if (client.vchBlindingFactor[0] & 0x80)
            fSawTopBitSet = true;
        else
            fSawTopBitClear = true;
    }
    BOOST_CHECK_MESSAGE(fSawTopBitClear,
                        "every blinding factor had its top bit set, so r is drawn from a "
                        "fixed sub-interval of Z_N rather than uniformly");
    BOOST_CHECK(fSawTopBitSet);
}

BOOST_AUTO_TEST_SUITE_END()
