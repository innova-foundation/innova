// Tests for NullSend/coinjoin nullifier binding transport: post-fork entries
// must declare note-bound nullifiers up front (AcceptEntry/AcceptInputReg),
// and the partial-sig message carries each participant's per-spend binding
// proofs (made over the session sighash) so FinalizeTransaction can attach
// them to the assembled transaction. ConnectInputs rejects post-fork shielded
// spends without a valid binding proof.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../nullsend.h"
#include "../shielded.h"
#include "../zkproof.h"

#include <openssl/bn.h>
#include <vector>

// Global-scope decls (defined in util.cpp / main); declaring `extern` inside the
// anonymous namespace below would bind to a namespace-local symbol the linker
// cannot resolve.
extern bool fRegTest;

namespace {

// Force the nullifier-binding fork active (regtest fork height is 8) for the
// scope of a test, restoring prior globals even on assertion unwind.
struct BindingForkGuard
{
    bool fRegTestSaved;
    int nBestHeightSaved;
    BindingForkGuard(bool fActive)
    {
        fRegTestSaved = fRegTest;
        nBestHeightSaved = nBestHeight;
        fRegTest = true;
        nBestHeight = fActive ? 100 : 2; // 2+1 < 8 keeps binding inactive
    }
    ~BindingForkGuard()
    {
        fRegTest = fRegTestSaved;
        nBestHeight = nBestHeightSaved;
    }
};

CShieldedSpendDescription MakeBoundSpend(int64_t value)
{
    CShieldedSpendDescription spend;
    std::vector<unsigned char> blind;
    BOOST_REQUIRE(GenerateBlindingFactor(blind));
    BOOST_REQUIRE(CreatePedersenCommitment(value, blind, spend.cv));
    BOOST_REQUIRE(ComputeNullifierPoint(blind, spend.vchNullifierPoint));
    spend.nullifier = NullifierTagFromPoint(spend.vchNullifierPoint);
    return spend;
}

CShieldedSpendDescription MakeUnboundSpend(int64_t value)
{
    CShieldedSpendDescription spend;
    std::vector<unsigned char> blind;
    BOOST_REQUIRE(GenerateBlindingFactor(blind));
    BOOST_REQUIRE(CreatePedersenCommitment(value, blind, spend.cv));
    spend.nullifier = uint256(0xF00D); // legacy free-field nullifier
    return spend;
}

CNullSendEntry MakeEntry(const CShieldedSpendDescription& spend)
{
    CNullSendEntry entry;
    entry.nSessionID = 7;
    entry.vMySpends.push_back(spend);
    entry.vMyOutputs.push_back(CShieldedOutputDescription());
    entry.nMyValueBalance = NULLSEND_FEE;
    return entry;
}

CNullSendSession MakeAcceptingSession()
{
    CNullSendSession session;
    session.nSessionID = 7;
    session.nTargetParticipants = 16; // never auto-advance during the test
    session.nState = NULLSEND_STATE_ACCEPTING;
    return session;
}

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

// The znsps wire message round-trips the per-spend binding proofs.
BOOST_AUTO_TEST_CASE(partial_sig_message_round_trips_binding_proofs)
{
    CNullSendPartialSig msg;
    msg.nSessionID = 42;
    msg.nParticipantID = 3;
    msg.vchPartialSig.assign(32, 0xAB);
    msg.vSpendAuthSigs.push_back(std::vector<unsigned char>(65, 0x01));
    msg.vSpendRks.push_back(std::vector<unsigned char>(33, 0x02));
    msg.vNullifierBindingProofs.push_back(
        std::vector<unsigned char>(NULLIFIER_BINDING_PROOF_SIZE, 0x03));

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << msg;
    CNullSendPartialSig decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.nSessionID, 42);
    BOOST_CHECK_EQUAL(decoded.nParticipantID, 3);
    BOOST_CHECK(decoded.vchPartialSig == msg.vchPartialSig);
    BOOST_CHECK(decoded.vSpendAuthSigs == msg.vSpendAuthSigs);
    BOOST_CHECK(decoded.vSpendRks == msg.vSpendRks);
    BOOST_CHECK(decoded.vNullifierBindingProofs == msg.vNullifierBindingProofs);
}

// Post-fork, an entry whose spends do not declare a bound nullifier point can
// never connect; the session must refuse it up front.
BOOST_AUTO_TEST_CASE(accept_entry_requires_bound_nullifiers_post_fork)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    BindingForkGuard fork(true);

    CNullSendSession session = MakeAcceptingSession();
    BOOST_CHECK(!session.AcceptEntry(MakeEntry(MakeUnboundSpend(100000000)), NULL));
    BOOST_CHECK_EQUAL((int)session.vParticipants.size(), 0);

    BOOST_CHECK(session.AcceptEntry(MakeEntry(MakeBoundSpend(100000000)), NULL));
    BOOST_CHECK_EQUAL((int)session.vParticipants.size(), 1);
}

// Post-fork, a declared nullifier that is not the tag of the declared point
// is malformed (CheckVote-equivalent of the spend rule) and refused.
BOOST_AUTO_TEST_CASE(accept_entry_rejects_mismatched_tag_post_fork)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    BindingForkGuard fork(true);

    CShieldedSpendDescription spend = MakeBoundSpend(100000000);
    spend.nullifier = uint256(0xBADBADBAD); // tag no longer matches the point

    CNullSendSession session = MakeAcceptingSession();
    BOOST_CHECK(!session.AcceptEntry(MakeEntry(spend), NULL));
    BOOST_CHECK_EQUAL((int)session.vParticipants.size(), 0);
}

// Before the fork, legacy unbound entries remain acceptable (no premature
// enforcement on the live pre-fork chain).
BOOST_AUTO_TEST_CASE(accept_entry_allows_unbound_pre_fork)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    BindingForkGuard fork(false);

    CNullSendSession session = MakeAcceptingSession();
    BOOST_CHECK(session.AcceptEntry(MakeEntry(MakeUnboundSpend(100000000)), NULL));
    BOOST_CHECK_EQUAL((int)session.vParticipants.size(), 1);
}

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

BOOST_AUTO_TEST_SUITE_END()
