// A tally certificate's cert.hashBlock must be on the carrier's own ancestor chain
// (as CheckVote requires for votes); ConnectBlock derives the carrier from the block
// hash; callers with no carrier are unchanged. Linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

#include "../finality.h"
#include "../hash.h"
#include "../key.h"
#include "../main.h"
#include "../txdb.h"
#include "../uint256.h"
#include "synthetic_chain.h"

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(finality_cert_ancestry_tests)

namespace {

const char* const kNotAncestor =
    "tally certificate block is not an ancestor of the including block";

struct CertAncestryRegtest
{
    bool fSavedRegTest;
    bool fSavedTestNet;

    CertAncestryRegtest() : fSavedRegTest(fRegTest), fSavedTestNet(fTestNet)
    {
        fRegTest = true;
        fTestNet = false;
    }

    ~CertAncestryRegtest()
    {
        fRegTest = fSavedRegTest;
        fTestNet = fSavedTestNet;
    }
};

// Two branches sharing no block: each opens the epoch with its own boundary block and
// runs to the first height a certificate for that epoch may be carried at.
struct TwoBranchEpoch
{
    CertAncestryRegtest network;
    int nEpoch;
    int nBoundary;
    int nCarrierHeight;
    CSyntheticChain chainA;
    CSyntheticChain chainB;
    CBlockIndex* pBoundaryA;
    CBlockIndex* pBoundaryB;
    CBlockIndex* pCarrierA;
    CBlockIndex* pCarrierB;

    TwoBranchEpoch() : chainA(0xCA000001), chainB(0xCB000001)
    {
        nBoundary = FORK_HEIGHT_BOUNDARY_A;
        nEpoch = GetEpochForHeight(nBoundary);
        BOOST_REQUIRE_EQUAL(GetEpochBoundaryHeight(nEpoch, nBoundary), nBoundary);
        nCarrierHeight = nBoundary + FINALITY_VOTE_INCLUSION_WINDOW;

        pBoundaryA = chainA.Add(NULL, nBoundary);
        pBoundaryB = chainB.Add(NULL, nBoundary);
        BOOST_REQUIRE(pBoundaryA != NULL && pBoundaryB != NULL);
        pCarrierA = chainA.Extend(pBoundaryA, FINALITY_VOTE_INCLUSION_WINDOW);
        pCarrierB = chainB.Extend(pBoundaryB, FINALITY_VOTE_INCLUSION_WINDOW);
        BOOST_REQUIRE(pCarrierA != NULL && pCarrierB != NULL);
        BOOST_REQUIRE_EQUAL(pCarrierA->nHeight, nCarrierHeight);
        BOOST_REQUIRE_EQUAL(pCarrierB->nHeight, nCarrierHeight);

        // Each carrier reaches its own boundary through its parents and never the other's.
        BOOST_REQUIRE(GetFinalityAncestorOnChain(pCarrierA, nBoundary,
                                                 FINALITY_ANCESTOR_MAX_WALK) == pBoundaryA);
        BOOST_REQUIRE(GetFinalityAncestorOnChain(pCarrierB, nBoundary,
                                                 FINALITY_ANCESTOR_MAX_WALK) == pBoundaryB);
    }

    uint256 HashA() const { return pBoundaryA->GetBlockHash(); }
    uint256 HashB() const { return pBoundaryB->GetBlockHash(); }
};

CFinalityVote MakeVote(const CKey& key, int nEpoch, int nHeight, const uint256& hashBlock)
{
    CPubKey pubkey = key.GetPubKey();
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    vote.nEpoch = nEpoch;
    vote.nHeight = nHeight;
    vote.hashBlock = hashBlock;
    vote.nTime = 1000;
    vote.nVoteWeight = 1000 * COIN;
    vote.nReward = 0;
    vote.vchPubKey.assign(pubkey.begin(), pubkey.end());
    vote.vStakeProof.push_back(COutPoint(uint256(0xCA5E0001), 0));
    CHashWriter ss(SER_GETHASH, 0);
    ss << vote.vchPubKey;
    ss << vote.nEpoch;
    vote.nullifier = ss.GetHash();
    vote.MarkCanonicalEnvelope();
    return vote;
}

// FINALITY_MIN_VOTERS connected transparent votes, all naming hashNamed.
std::vector<CFinalityVote> ConnectVotesNaming(CFinalityTracker& tracker, int nEpoch,
                                              int nHeight, const uint256& hashNamed)
{
    std::vector<CFinalityVote> votes;
    for (int i = 0; i < FINALITY_MIN_VOTERS; i++)
    {
        CKey key;
        key.MakeNewKey(true);
        CFinalityVote vote = MakeVote(key, nEpoch, nHeight, hashNamed);
        BOOST_REQUIRE(tracker.AddVote(vote, false, true));
        votes.push_back(vote);
    }
    return votes;
}

CFinalityTallyCertificate CanonicalCertificate(const std::vector<CFinalityVote>& votes)
{
    CFinalityTallyCertificate cert;
    std::string error;
    BOOST_REQUIRE_MESSAGE(BuildCanonicalTransparentFinalityCertificate(votes, cert, &error),
                          error);
    return cert;
}

// A pre-Boundary-A envelope with FINALITY_NONE: no threshold applies, so its named block is
// constrained only by the index lookup. The covered votes name another block.
CFinalityTallyCertificate LegacyNoneTierCertificate(const std::vector<CFinalityVote>& votes,
                                                    const uint256& hashNamed)
{
    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = votes[0].nEpoch;
    cert.hashBlock = hashNamed;
    cert.nHeight = votes[0].nHeight;
    cert.nTier = FINALITY_NONE;
    for (size_t i = 0; i < votes.size(); i++)
    {
        BOOST_REQUIRE(votes[i].hashBlock != hashNamed);
        cert.nTransparentActiveWeight += votes[i].nVoteWeight;
        cert.nTransparentRewardBudget += votes[i].nReward;
        cert.vVoteNullifiers.push_back(votes[i].nullifier);
    }
    cert.nTransparentWinningWeight = 0;
    return cert;
}

struct Verdict
{
    bool fOk;
    FinalityResult result;
    std::string error;
};

Verdict Judge(const CFinalityTracker& tracker, const CFinalityTallyCertificate& cert,
              CTxDB& txdb, int nContextHeight, const CBlockIndex* pindexAnchor)
{
    Verdict v;
    v.result = FINALITY_RESULT_OK;
    v.fOk = tracker.CheckTallyCertificate(cert, txdb, &v.error, NULL, false, nContextHeight,
                                          false, &v.result, pindexAnchor);
    return v;
}

} // namespace

// The covered votes and the certificate agree on branch B's boundary, so every weight
// re-derivation matches; only the carrier's ancestry separates the two verdicts.
BOOST_AUTO_TEST_CASE(a_certificate_naming_a_sibling_boundary_block_is_refused_at_connect)
{
    TwoBranchEpoch f;
    CFinalityTracker tracker;
    CTxDB txdb("r");

    const std::vector<CFinalityVote> votes =
        ConnectVotesNaming(tracker, f.nEpoch, f.nBoundary, f.HashB());
    const CFinalityTallyCertificate cert = CanonicalCertificate(votes);
    BOOST_REQUIRE(cert.hashBlock == f.HashB());
    BOOST_REQUIRE_EQUAL(cert.nTier, (int)FINALITY_HARD);

    // Control: carried on the branch whose boundary it names.
    const Verdict same = Judge(tracker, cert, txdb, f.nCarrierHeight, f.pCarrierB);
    BOOST_REQUIRE_MESSAGE(same.fOk, "same-chain certificate refused: " << same.error);
    BOOST_CHECK_EQUAL(same.result, FINALITY_RESULT_OK);

    // Carried on branch A, whose boundary is a different block at the same height.
    const Verdict cross = Judge(tracker, cert, txdb, f.nCarrierHeight, f.pCarrierA);
    BOOST_CHECK(!cross.fOk);
    BOOST_CHECK_EQUAL(cross.result, FINALITY_RESULT_INVALID);
    BOOST_CHECK_EQUAL(cross.error, kNotAncestor);
}

// The one envelope the weight re-derivation does not constrain. Without the binding,
// this certificate is accepted on branch B while naming branch A's boundary.
BOOST_AUTO_TEST_CASE(a_legacy_no_tier_envelope_naming_a_sibling_boundary_is_refused_too)
{
    TwoBranchEpoch f;
    CFinalityTracker tracker;
    CTxDB txdb("r");

    const std::vector<CFinalityVote> votes =
        ConnectVotesNaming(tracker, f.nEpoch, f.nBoundary, f.HashB());
    const CFinalityTallyCertificate cert = LegacyNoneTierCertificate(votes, f.HashA());
    BOOST_REQUIRE(!cert.IsCanonicalEnvelope());

    const Verdict cross = Judge(tracker, cert, txdb, f.nCarrierHeight, f.pCarrierB);
    BOOST_CHECK(!cross.fOk);
    BOOST_CHECK_EQUAL(cross.result, FINALITY_RESULT_INVALID);
    BOOST_CHECK_EQUAL(cross.error, kNotAncestor);
}

// Relay, signature collection and the regtest RPC hold no carrier and pass none; the
// binding must not reach them, or a certificate gossiped ahead of its block is lost.
BOOST_AUTO_TEST_CASE(a_caller_without_a_carrier_is_not_bound)
{
    TwoBranchEpoch f;
    CFinalityTracker tracker;
    CTxDB txdb("r");

    const std::vector<CFinalityVote> votes =
        ConnectVotesNaming(tracker, f.nEpoch, f.nBoundary, f.HashB());
    const CFinalityTallyCertificate cert = CanonicalCertificate(votes);

    const Verdict unbound = Judge(tracker, cert, txdb, f.nCarrierHeight, NULL);
    BOOST_CHECK_MESSAGE(unbound.fOk, "anchorless check refused: " << unbound.error);
    BOOST_CHECK_EQUAL(unbound.result, FINALITY_RESULT_OK);

    const Verdict relay = Judge(tracker, cert, txdb, -1, NULL);
    BOOST_CHECK_MESSAGE(relay.fOk, "relay check refused: " << relay.error);
}

// ConnectBlock passes the carrier's hash, not its index. The carrier is always indexed
// by then, so the binding must be derived from the hash: refused on the wrong branch
// before anything is written, accepted and persisted on the right one.
BOOST_AUTO_TEST_CASE(connect_derives_the_carrier_from_the_block_hash_it_is_given)
{
    TwoBranchEpoch f;
    CFinalityTracker tracker;
    CTxDB txdb;

    const std::vector<CFinalityVote> votes =
        ConnectVotesNaming(tracker, f.nEpoch, f.nBoundary, f.HashB());
    const CFinalityTallyCertificate cert = CanonicalCertificate(votes);
    std::vector<CFinalityTallyCertificate> vCert(1, cert);

    const uint256 hashCarrierA = f.pCarrierA->GetBlockHash();
    const uint256 hashCarrierB = f.pCarrierB->GetBlockHash();
    txdb.EraseFinalityTallyCertificate(cert.GetHash());
    txdb.EraseFinalityConnectedCertBlock(hashCarrierA);
    txdb.EraseFinalityConnectedCertBlock(hashCarrierB);

    FinalityResult result = FINALITY_RESULT_OK;
    BOOST_CHECK(!tracker.ConnectBlockTallyCertificates(txdb, hashCarrierA, vCert,
                                                       f.nCarrierHeight, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_INVALID);
    BOOST_CHECK(tracker.GetEpochTallyCertificates(f.nEpoch).empty());
    CFinalityTallyCertificate persisted;
    BOOST_CHECK(!txdb.ReadFinalityTallyCertificate(cert.GetHash(), persisted));

    BOOST_REQUIRE(txdb.TxnBegin());
    result = FINALITY_RESULT_INVALID;
    BOOST_CHECK_MESSAGE(tracker.ConnectBlockTallyCertificates(txdb, hashCarrierB, vCert,
                                                              f.nCarrierHeight, &result),
                        "same-chain carrier refused");
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_OK);
    BOOST_CHECK_EQUAL(tracker.GetEpochTallyCertificates(f.nEpoch).size(), 1U);
    BOOST_CHECK(tracker.DisconnectBlockTallyCertificates(txdb, hashCarrierB, vCert));
    txdb.TxnAbort();
    txdb.EraseFinalityTallyCertificate(cert.GetHash());
    txdb.EraseFinalityConnectedCertBlock(hashCarrierB);
}

BOOST_AUTO_TEST_SUITE_END()
