// A tally certificate's cert.hashBlock must be on the carrier's own ancestor chain
// (as CheckVote requires for votes); ConnectBlock derives the carrier from the block
// hash; callers with no carrier are unchanged. Linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../finality.h"
#include "../hash.h"
#include "../init.h"
#include "../innovarpc.h"
#include "../key.h"
#include "../main.h"
#include "../miner.h"
#include "../txdb.h"
#include "../uint256.h"
#include "../wallet.h"
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

namespace {

bool SolveBlock(CBlock* pblock)
{
    CBigNum target;
    target.SetCompact(pblock->nBits);
    const uint256 hashTarget = target.getuint256();
    unsigned int nHashes = 0;
    while (pblock->GetPoWHash() > hashTarget)
    {
        ++pblock->nNonce;
        if (pblock->nNonce == 0)
            ++pblock->nTime;
        if (++nHashes > 4000000U)
            return false;
    }
    return true;
}

CBlockIndex* TemplateParent(const CBlock& block)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
    BOOST_REQUIRE(mi != mapBlockIndex.end());
    return mi->second;
}

void MineOnTemplate()
{
    unsigned int nExtraNonce = 0;
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    IncrementExtraNonce(pblock.get(), TemplateParent(*pblock), nExtraNonce);
    BOOST_REQUIRE(SolveBlock(pblock.get()));
    BOOST_REQUIRE(ProcessBlock(NULL, pblock.get()));
}

bool CoinbaseCarries(const CBlock& block, const CScript& script)
{
    const std::vector<CTxOut>& vout = block.vtx[0].vout;
    for (size_t i = 0; i < vout.size(); i++)
        if (vout[i].scriptPubKey == script)
            return true;
    return false;
}

// Discards the in-memory votes and pending certificates a case injected.
struct GlobalFinalityRestore
{
    int nFinalizedBefore;
    GlobalFinalityRestore() : nFinalizedBefore(g_finalityTracker.GetFinalizedHeight()) {}
    ~GlobalFinalityRestore()
    {
        BOOST_CHECK(g_finalityTracker.RestoreCommittedStateAfterAbort());
        BOOST_CHECK_EQUAL(g_finalityTracker.GetFinalizedHeight(), nFinalizedBefore);
    }
};


struct ScopedNoteVoteHeight
{
    int nSaved;
    explicit ScopedNoteVoteHeight(int nNew) : nSaved(nRegtestIV5NoteVoteHeight)
    {
        nRegtestIV5NoteVoteHeight = nNew;
    }
    ~ScopedNoteVoteHeight() { nRegtestIV5NoteVoteHeight = nSaved; }
};

// Note votes counted on g_finalityTracker under a synthetic carrier; disconnected on exit.
struct CountedNoteVotes
{
    CTxDB txdb;
    uint256 hashCarrier;
    std::vector<CNoteFinalityVote> vVotes;
    bool fConnected;

    CountedNoteVotes(const uint256& hashCarrierIn, int nEpoch, int nBoundary,
                     const uint256& hashNamed, int nCount, unsigned char nTagSeed)
        : hashCarrier(hashCarrierIn), fConnected(false)
    {
        for (int i = 0; i < nCount; i++)
        {
            CNoteFinalityVote vote;
            vote.nEpoch = nEpoch;
            vote.nHeight = nBoundary;
            vote.hashBlock = hashNamed;
            vote.vchTag.assign(FINALITY_NOTE_POINT_SIZE, (unsigned char)(nTagSeed + i));
            vVotes.push_back(vote);
        }
        fConnected = g_finalityTracker.ConnectBlockNoteVotes(
            txdb, hashCarrier, vVotes, CFinalityVoteContext::ChainHeight(nBoundary + 1),
            NULL, false);
        BOOST_REQUIRE(fConnected);
        BOOST_REQUIRE_EQUAL(g_finalityTracker.GetCountedEpochNoteVotes(nEpoch).size(),
                            (size_t)nCount);
    }

    ~CountedNoteVotes()
    {
        if (fConnected)
            g_finalityTracker.DisconnectBlockNoteVotes(txdb, hashCarrier, vVotes);
    }
};

CFinalityTallyCertificate NoteCertificate(int nEpoch, const std::vector<CFinalityVote>& votes)
{
    CFinalityTallyCertificate cert;
    std::string error;
    BOOST_REQUIRE_MESSAGE(BuildNoteTallyCertificate(
                              nEpoch, votes, g_finalityTracker.GetCountedEpochNoteVotes(nEpoch),
                              cert, &error),
                          error);
    return cert;
}

// Mines until the next template height satisfies fAccept; returns the template parent.
template <typename F>
CBlockIndex* MineUntil(F fAccept)
{
    for (int nMined = 0;; nMined++)
    {
        BOOST_REQUIRE(nMined < 3000);
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        BOOST_REQUIRE(pblock.get() != NULL);
        CBlockIndex* pindexPrev = TemplateParent(*pblock);
        if (fAccept(pindexPrev->nHeight + 1))
            return pindexPrev;
        MineOnTemplate();
    }
}

} // namespace

// The template's certificate filter must apply the same binding as connect. Two pending
// certificates for consecutive epochs differ only in whether the named boundary block is
// an ancestor of the template parent; only that one may be embedded.
BOOST_AUTO_TEST_CASE(the_miner_does_not_embed_a_certificate_naming_a_sibling_boundary_block)
{
    // Two post-Boundary-A epochs whose vote-inclusion windows have closed at the
    // template height.
    CBlockIndex* pindexPrev = NULL;
    int nHeight = 0;
    int nEpochSibling = 0;
    for (int nMined = 0;; nMined++)
    {
        BOOST_REQUIRE(nMined < 2000);
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        BOOST_REQUIRE(pblock.get() != NULL);
        pindexPrev = TemplateParent(*pblock);
        nHeight = pindexPrev->nHeight + 1;
        int nEpochClosed = GetEpochForHeight(nHeight);
        if (nHeight < GetEpochBoundaryHeight(nEpochClosed, nHeight) + FINALITY_VOTE_INCLUSION_WINDOW)
            nEpochClosed--;
        nEpochSibling = nEpochClosed - 1;
        if (IsBoundaryAActiveAtHeight(nHeight) &&
            GetEpochBoundaryHeight(nEpochSibling, nHeight) >= FORK_HEIGHT_BOUNDARY_A)
            break;
        MineOnTemplate();
    }
    const int nEpochCanonical = nEpochSibling + 1;
    const int nBoundarySibling = GetEpochBoundaryHeight(nEpochSibling, nHeight);
    const int nBoundaryCanonical = GetEpochBoundaryHeight(nEpochCanonical, nHeight);

    const CBlockIndex* pCanonical =
        GetFinalityAncestorOnChain(pindexPrev, nBoundaryCanonical, FINALITY_ANCESTOR_MAX_WALK);
    const CBlockIndex* pOwnSiblingEpoch =
        GetFinalityAncestorOnChain(pindexPrev, nBoundarySibling, FINALITY_ANCESTOR_MAX_WALK);
    BOOST_REQUIRE(pCanonical != NULL && pCanonical->IsProofOfWork());
    BOOST_REQUIRE(pOwnSiblingEpoch != NULL);
    BOOST_REQUIRE_EQUAL(g_finalityTracker.GetEpochVoteCount(nEpochSibling), 0);
    BOOST_REQUIRE_EQUAL(g_finalityTracker.GetEpochVoteCount(nEpochCanonical), 0);
    BOOST_REQUIRE(g_finalityTracker.GetEpochTallyCertificates(nEpochSibling).empty());
    BOOST_REQUIRE(g_finalityTracker.GetEpochTallyCertificates(nEpochCanonical).empty());

    CertAncestryRegtest network;
    CSyntheticChain branch(0xCC000001);
    CBlockIndex* pSibling = branch.Add(NULL, nBoundarySibling);
    BOOST_REQUIRE(pSibling != NULL && pSibling->IsProofOfWork());
    BOOST_REQUIRE(pSibling != pOwnSiblingEpoch);

    GlobalFinalityRestore restore;
    const CFinalityTallyCertificate certSibling = CanonicalCertificate(
        ConnectVotesNaming(g_finalityTracker, nEpochSibling, nBoundarySibling,
                           pSibling->GetBlockHash()));
    const CFinalityTallyCertificate certCanonical = CanonicalCertificate(
        ConnectVotesNaming(g_finalityTracker, nEpochCanonical, nBoundaryCanonical,
                           pCanonical->GetBlockHash()));
    BOOST_REQUIRE_EQUAL(certSibling.nTier, (int)FINALITY_HARD);
    BOOST_REQUIRE_EQUAL(certCanonical.nTier, (int)FINALITY_HARD);

    // Both pass every check that holds no carrier.
    {
        CTxDB txdb("r");
        BOOST_REQUIRE(Judge(g_finalityTracker, certSibling, txdb, nHeight, NULL).fOk);
        BOOST_REQUIRE(Judge(g_finalityTracker, certCanonical, txdb, nHeight, NULL).fOk);
    }
    BOOST_REQUIRE(g_finalityTracker.AddTallyCertificate(certSibling, false));
    BOOST_REQUIRE(g_finalityTracker.AddTallyCertificate(certCanonical, false));
    BOOST_REQUIRE_EQUAL(g_finalityTracker.GetPendingTallyCertificatesForBlock(nHeight).size(), 2U);

    CScript scriptSibling;
    CScript scriptCanonical;
    BOOST_REQUIRE(BuildFinalityTallyCertificateScriptForHeight(certSibling, nHeight, scriptSibling));
    BOOST_REQUIRE(BuildFinalityTallyCertificateScriptForHeight(certCanonical, nHeight,
                                                               scriptCanonical));

    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    BOOST_REQUIRE(TemplateParent(*pblock) == pindexPrev);
    BOOST_CHECK_MESSAGE(CoinbaseCarries(*pblock, scriptCanonical),
                        "canonical-boundary certificate not embedded");
    BOOST_CHECK_MESSAGE(!CoinbaseCarries(*pblock, scriptSibling),
                        "sibling-boundary certificate embedded");
}

// Relay-valid subset certificates with lower hashes must not crowd the covering
// certificate out of the template or the per-epoch pending bound.
BOOST_AUTO_TEST_CASE(non_covering_certificates_do_not_starve_the_covering_one)
{
    CBlockIndex* pindexPrev = NULL;
    int nHeight = 0;
    int nEpoch = 0;
    for (int nMined = 0;; nMined++)
    {
        BOOST_REQUIRE(nMined < 3000);
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        BOOST_REQUIRE(pblock.get() != NULL);
        pindexPrev = TemplateParent(*pblock);
        nHeight = pindexPrev->nHeight + 1;
        nEpoch = GetEpochForHeight(nHeight);
        if (IsBoundaryAActiveAtHeight(nHeight) &&
            nHeight >= GetEpochBoundaryHeight(nEpoch, nHeight) + FINALITY_VOTE_INCLUSION_WINDOW &&
            GetEpochBoundaryHeight(nEpoch - FINALITY_CONFIRMATION_EPOCHS, nHeight) >=
                FORK_HEIGHT_BOUNDARY_A)
            break;
        MineOnTemplate();
    }
    BOOST_REQUIRE(pindexPrev == pindexBest);
    const int nFirstEpoch = nEpoch - FINALITY_CONFIRMATION_EPOCHS;

    CertAncestryRegtest network;
    GlobalFinalityRestore restore;
    CTxDB txdb("r");

    const int kVoters = 5;
    std::map<int, std::vector<CFinalityVote> > mapVotes;
    for (int e = nFirstEpoch; e <= nEpoch; e++)
    {
        BOOST_REQUIRE_EQUAL(g_finalityTracker.GetEpochVoteCount(e), 0);
        BOOST_REQUIRE_EQUAL(g_finalityTracker.GetPendingTallyCertificateCount(e), 0U);
        const int nBoundary = GetEpochBoundaryHeight(e, nHeight);
        const CBlockIndex* pBoundary =
            GetFinalityAncestorOnChain(pindexPrev, nBoundary, FINALITY_ANCESTOR_MAX_WALK);
        BOOST_REQUIRE(pBoundary != NULL && pBoundary->IsProofOfWork());
        // The covering certificate's hash is drawn from the upper half, so the other
        // epochs' subset certificates supply at least four lower hashes.
        for (int nTry = 0;; nTry++)
        {
            BOOST_REQUIRE(nTry < 256);
            std::vector<CFinalityVote> votes;
            for (int i = 0; i < kVoters; i++)
            {
                CKey key;
                key.MakeNewKey(true);
                votes.push_back(MakeVote(key, e, nBoundary, pBoundary->GetBlockHash()));
            }
            if (e == nEpoch && !(CanonicalCertificate(votes).GetHash() > (uint256(1) << 255)))
                continue;
            mapVotes[e] = votes;
            break;
        }
        for (const CFinalityVote& vote : mapVotes[e])
            BOOST_REQUIRE(g_finalityTracker.AddVote(vote, false, true));
    }

    const CFinalityTallyCertificate honest = CanonicalCertificate(mapVotes[nEpoch]);
    BOOST_REQUIRE_EQUAL(honest.nTier, (int)FINALITY_HARD);
    {
        const Verdict v = Judge(g_finalityTracker, honest, txdb, nHeight, pindexPrev);
        BOOST_REQUIRE_MESSAGE(v.fOk, "covering certificate refused: " << v.error);
    }

    // Every subset of two to four voters, per epoch.
    std::map<int, std::vector<CFinalityTallyCertificate> > mapJunk;
    for (int e = nFirstEpoch; e <= nEpoch; e++)
    {
        for (unsigned int mask = 1; mask < (1U << kVoters); mask++)
        {
            std::vector<CFinalityVote> subset;
            for (int i = 0; i < kVoters; i++)
                if (mask & (1U << i))
                    subset.push_back(mapVotes[e][i]);
            if (subset.size() < (size_t)FINALITY_MIN_VOTERS || subset.size() == (size_t)kVoters)
                continue;
            const CFinalityTallyCertificate junk = CanonicalCertificate(subset);
            const Verdict relay = Judge(g_finalityTracker, junk, txdb, -1, NULL);
            BOOST_REQUIRE_MESSAGE(relay.fOk, "subset certificate not relay-valid: " << relay.error);
            const Verdict block = Judge(g_finalityTracker, junk, txdb, nHeight, pindexPrev);
            BOOST_REQUIRE(!block.fOk);
            BOOST_REQUIRE_EQUAL(block.error,
                                "tally certificate does not cover the full connected epoch vote set");
            mapJunk[e].push_back(junk);
        }
    }

    // Past the window, relay refuses a non-covering certificate outright.
    BOOST_CHECK(!g_finalityTracker.AddTallyCertificate(mapJunk[nEpoch][0]));
    BOOST_CHECK_EQUAL(g_finalityTracker.GetPendingTallyCertificateCount(nEpoch), 0U);

    // The regtest submit RPC applies the same judgement. MUTATION: submit with
    // AddTallyCertificate(cert, false) and no judgement, and it is stored.
    {
        CCanonicalFinalityTallyCertificateEnvelope envelope;
        BOOST_REQUIRE(envelope.FromLogical(mapJunk[nEpoch][0]));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << envelope;
        json_spirit::Array params;
        params.push_back(HexStr(ss.begin(), ss.end()));
        BOOST_CHECK_THROW(submitfinalitytallycert(params, false), json_spirit::Object);
        BOOST_CHECK_EQUAL(g_finalityTracker.GetPendingTallyCertificateCount(nEpoch), 0U);
    }

    // Forced in without the relay check (fCheck=false). Past the window each is judged
    // INVALID and ranks below the covering certificate; the pre-window order is pinned by
    // undecided_certificates_rank_by_coverage_before_the_window_closes.
    std::vector<CFinalityTallyCertificate> vLowJunk;
    size_t nLowOlderEpochs = 0;
    for (int e = nFirstEpoch; e <= nEpoch; e++)
    {
        size_t nAdded = 0;
        for (const CFinalityTallyCertificate& junk : mapJunk[e])
        {
            if (!(junk.GetHash() < honest.GetHash()) ||
                nAdded + 1 >= FINALITY_PENDING_CERTS_PER_EPOCH)
                continue;
            BOOST_REQUIRE(g_finalityTracker.AddTallyCertificate(junk, false));
            vLowJunk.push_back(junk);
            nAdded++;
            if (e != nEpoch)
                nLowOlderEpochs++;
        }
    }
    BOOST_REQUIRE_GE(nLowOlderEpochs, 4U);
    BOOST_REQUIRE(g_finalityTracker.AddTallyCertificate(honest));

    // Every other subset for the epoch: the pending set stays bounded and keeps the
    // covering certificate.
    for (const CFinalityTallyCertificate& junk : mapJunk[nEpoch])
        g_finalityTracker.AddTallyCertificate(junk, false);
    BOOST_CHECK_LE(g_finalityTracker.GetPendingTallyCertificateCount(nEpoch),
                   (size_t)FINALITY_PENDING_CERTS_PER_EPOCH);
    for (int e = nFirstEpoch; e <= nEpoch; e++)
        BOOST_CHECK_LE(g_finalityTracker.GetPendingTallyCertificateCount(e),
                       (size_t)FINALITY_PENDING_CERTS_PER_EPOCH);
    bool fHonestPending = false;
    const std::vector<CFinalityTallyCertificate> vPending =
        g_finalityTracker.GetPendingTallyCertificatesForBlock(
            nHeight, std::numeric_limits<unsigned int>::max());
    for (const CFinalityTallyCertificate& cert : vPending)
        if (cert.GetHash() == honest.GetHash())
            fHonestPending = true;
    BOOST_CHECK_MESSAGE(fHonestPending, "covering certificate was evicted");

    // The unvalidated cap would hand the template only non-covering certificates.
    {
        const std::vector<CFinalityTallyCertificate> vFirstByHash =
            g_finalityTracker.GetPendingTallyCertificatesForBlock(nHeight);
        BOOST_REQUIRE_EQUAL(vFirstByHash.size(), 4U);
        for (const CFinalityTallyCertificate& cert : vFirstByHash)
            BOOST_REQUIRE(cert.GetHash() != honest.GetHash());
    }

    const std::vector<CFinalityTallyCertificate> vSelected =
        g_finalityTracker.SelectTallyCertificatesForBlock(txdb, nHeight, NULL, pindexPrev);
    BOOST_REQUIRE_EQUAL(vSelected.size(), 1U);
    BOOST_CHECK(vSelected[0].GetHash() == honest.GetHash());

    CScript scriptHonest;
    BOOST_REQUIRE(BuildFinalityTallyCertificateScriptForHeight(honest, nHeight, scriptHonest));
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    BOOST_REQUIRE(TemplateParent(*pblock) == pindexPrev);
    BOOST_CHECK_MESSAGE(CoinbaseCarries(*pblock, scriptHonest),
                        "covering certificate not embedded");
    for (const CFinalityTallyCertificate& junk : vLowJunk)
    {
        CScript scriptJunk;
        BOOST_REQUIRE(BuildFinalityTallyCertificateScriptForHeight(junk, nHeight, scriptJunk));
        BOOST_CHECK(!CoinbaseCarries(*pblock, scriptJunk));
    }

    // Pruned on every node once no later block may carry them.
    const int nNextEpochStart =
        GetEpochBoundaryHeight(nEpoch, nHeight) + GetEpochInterval(nHeight);
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(nNextEpochStart), nEpoch + 1);
    g_finalityTracker.PrunePendingTallyCertificates(nNextEpochStart);
    BOOST_CHECK_EQUAL(g_finalityTracker.GetPendingTallyCertificateCount(nFirstEpoch), 0U);
    BOOST_CHECK(g_finalityTracker.GetPendingTallyCertificateCount(nEpoch) > 0U);
}

// Before the window closes, the pending bound evicts by coverage first, so junk
// certificates that outrank the covering one by record ranking cannot displace it.
BOOST_AUTO_TEST_CASE(undecided_certificates_rank_by_coverage_before_the_window_closes)
{
    CBlockIndex* pindexPrev = MineUntil([](int nHeight) {
        const int nEpoch = GetEpochForHeight(nHeight);
        const int nBoundary = GetEpochBoundaryHeight(nEpoch, nHeight);
        return IsBoundaryAActiveAtHeight(nHeight) && nBoundary >= FORK_HEIGHT_BOUNDARY_A &&
               nHeight > nBoundary + 1 &&
               nHeight < nBoundary + FINALITY_VOTE_INCLUSION_WINDOW;
    });
    BOOST_REQUIRE(pindexPrev == pindexBest);
    const int nHeight = pindexPrev->nHeight + 1;
    const int nEpoch = GetEpochForHeight(nHeight);
    const int nBoundary = GetEpochBoundaryHeight(nEpoch, nHeight);
    BOOST_REQUIRE(!IsFinalityVoteWindowClosedForTip(nEpoch, pindexPrev->nHeight));
    const CBlockIndex* pBoundary =
        GetFinalityAncestorOnChain(pindexPrev, nBoundary, FINALITY_ANCESTOR_MAX_WALK);
    BOOST_REQUIRE(pBoundary != NULL);

    CertAncestryRegtest network;
    GlobalFinalityRestore restore;
    ScopedNoteVoteHeight noteVoteHeight(1);
    BOOST_REQUIRE_EQUAL(g_finalityTracker.GetEpochVoteCount(nEpoch), 0);
    BOOST_REQUIRE_EQUAL(g_finalityTracker.GetPendingTallyCertificateCount(nEpoch), 0U);
    CountedNoteVotes notes(uint256(0xCE000001), nEpoch, nBoundary, pBoundary->GetBlockHash(),
                           2, 0x61);
    CTxDB txdb("r");

    const int kVoters = 5;
    std::vector<CFinalityVote> votes;
    CFinalityTallyCertificate honest;
    std::vector<CFinalityTallyCertificate> vJunk;
    for (int nTry = 0;; nTry++)
    {
        BOOST_REQUIRE(nTry < 64);
        votes.clear();
        vJunk.clear();
        for (int i = 0; i < kVoters; i++)
        {
            CKey key;
            key.MakeNewKey(true);
            votes.push_back(MakeVote(key, nEpoch, nBoundary, pBoundary->GetBlockHash()));
        }
        honest = NoteCertificate(nEpoch, votes);
        size_t nOutrank = 0;
        for (unsigned int mask = 1; mask < (1U << kVoters); mask++)
        {
            std::vector<CFinalityVote> subset;
            for (int i = 0; i < kVoters; i++)
                if (mask & (1U << i))
                    subset.push_back(votes[i]);
            if (subset.size() < (size_t)FINALITY_MIN_VOTERS || subset.size() == (size_t)kVoters)
                continue;
            vJunk.push_back(CanonicalCertificate(subset));
            vJunk.push_back(NoteCertificate(nEpoch, subset));
            if (FinalityCertificateOutranks(vJunk.back(), honest))
                nOutrank++;
        }
        if (nOutrank >= FINALITY_PENDING_CERTS_PER_EPOCH)
            break;
    }
    for (const CFinalityVote& vote : votes)
        BOOST_REQUIRE(g_finalityTracker.AddVote(vote, false, true));
    BOOST_REQUIRE(honest.HasNoteWeight());
    BOOST_REQUIRE_EQUAL(honest.nTier, (int)FINALITY_HARD);
    BOOST_REQUIRE(Judge(g_finalityTracker, honest, txdb, -1, NULL).fOk);
    for (const CFinalityTallyCertificate& junk : vJunk)
    {
        const Verdict relay = Judge(g_finalityTracker, junk, txdb, -1, NULL);
        BOOST_REQUIRE_MESSAGE(relay.fOk, "subset certificate not relay-valid: " << relay.error);
        BOOST_REQUIRE(!IsTallyCertificateInvalidForNextBlock(junk));
    }

    for (const CFinalityTallyCertificate& junk : vJunk)
        g_finalityTracker.AddTallyCertificate(junk);
    BOOST_REQUIRE_EQUAL(g_finalityTracker.GetPendingTallyCertificateCount(nEpoch),
                        (size_t)FINALITY_PENDING_CERTS_PER_EPOCH);
    BOOST_REQUIRE_MESSAGE(g_finalityTracker.AddTallyCertificate(honest),
                          "covering certificate refused at a full pending set");
    for (const CFinalityTallyCertificate& junk : vJunk)
        g_finalityTracker.AddTallyCertificate(junk);

    BOOST_CHECK_LE(g_finalityTracker.GetPendingTallyCertificateCount(nEpoch),
                   (size_t)FINALITY_PENDING_CERTS_PER_EPOCH);
    bool fHonestPending = false;
    const std::vector<CFinalityTallyCertificate> vPending =
        g_finalityTracker.GetPendingTallyCertificatesForBlock(
            nBoundary + FINALITY_VOTE_INCLUSION_WINDOW, std::numeric_limits<unsigned int>::max());
    for (const CFinalityTallyCertificate& cert : vPending)
        if (cert.GetHash() == honest.GetHash())
            fHonestPending = true;
    BOOST_CHECK_MESSAGE(fHonestPending, "covering certificate was evicted");
}

// A template builder holding no certificate embeds the one it builds from its connected
// view: one transparent voter and two note votes, HARD only through the note leg.
// MUTATION: return nothing from GetSelfBuiltTallyCertificatesForBlock and the template
// carries no certificate.
BOOST_AUTO_TEST_CASE(a_template_with_no_received_certificate_embeds_the_self_built_one)
{
    CBlockIndex* pindexPrev = MineUntil([](int nHeight) {
        const int nEpoch = GetEpochForHeight(nHeight);
        const int nBoundary = GetEpochBoundaryHeight(nEpoch, nHeight);
        return IsBoundaryAActiveAtHeight(nHeight) && nBoundary >= FORK_HEIGHT_BOUNDARY_A &&
               nHeight >= nBoundary + FINALITY_VOTE_INCLUSION_WINDOW;
    });
    BOOST_REQUIRE(pindexPrev == pindexBest);
    const int nHeight = pindexPrev->nHeight + 1;
    const int nEpoch = GetEpochForHeight(nHeight);
    const int nBoundary = GetEpochBoundaryHeight(nEpoch, nHeight);
    const CBlockIndex* pBoundary =
        GetFinalityAncestorOnChain(pindexPrev, nBoundary, FINALITY_ANCESTOR_MAX_WALK);
    BOOST_REQUIRE(pBoundary != NULL);

    CertAncestryRegtest network;
    GlobalFinalityRestore restore;
    ScopedNoteVoteHeight noteVoteHeight(1);
    BOOST_REQUIRE_EQUAL(g_finalityTracker.GetEpochVoteCount(nEpoch), 0);
    CountedNoteVotes notes(uint256(0xCE000002), nEpoch, nBoundary, pBoundary->GetBlockHash(),
                           2, 0x71);
    CKey key;
    key.MakeNewKey(true);
    BOOST_REQUIRE(g_finalityTracker.AddVote(
        MakeVote(key, nEpoch, nBoundary, pBoundary->GetBlockHash()), false, true));
    BOOST_REQUIRE_EQUAL(g_finalityTracker.GetPendingTallyCertificateCount(nEpoch), 0U);

    const std::vector<CFinalityTallyCertificate> vProduced =
        BuildConnectedTallyCertificates(g_finalityTracker, nEpoch, pindexPrev->nHeight);
    BOOST_REQUIRE_EQUAL(vProduced.size(), 1U);
    BOOST_REQUIRE(vProduced[0].HasNoteWeight());
    BOOST_REQUIRE_EQUAL(vProduced[0].nTier, (int)FINALITY_HARD);
    CScript scriptProduced;
    BOOST_REQUIRE(BuildFinalityTallyCertificateScriptForHeight(vProduced[0], nHeight,
                                                               scriptProduced));

    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    BOOST_REQUIRE(TemplateParent(*pblock) == pindexPrev);
    BOOST_CHECK_MESSAGE(CoinbaseCarries(*pblock, scriptProduced),
                        "self-built certificate not embedded");
    BOOST_CHECK_EQUAL(g_finalityTracker.GetPendingTallyCertificateCount(nEpoch), 0U);
}

// A template whose parent is not pindexBest carries no certificate (the tracker holds
// pindexBest's branch).
BOOST_AUTO_TEST_CASE(a_template_off_the_tip_carries_no_certificate)
{
    CBlockIndex* pindexPrev = MineUntil([](int nHeight) {
        const int nEpoch = GetEpochForHeight(nHeight);
        const int nBoundary = GetEpochBoundaryHeight(nEpoch, nHeight);
        return IsBoundaryAActiveAtHeight(nHeight) && nBoundary >= FORK_HEIGHT_BOUNDARY_A &&
               nHeight >= nBoundary + FINALITY_VOTE_INCLUSION_WINDOW;
    });
    BOOST_REQUIRE(pindexPrev == pindexBest);
    const int nHeight = pindexPrev->nHeight + 1;
    const int nEpoch = GetEpochForHeight(nHeight);
    const int nBoundary = GetEpochBoundaryHeight(nEpoch, nHeight);
    const CBlockIndex* pBoundary =
        GetFinalityAncestorOnChain(pindexPrev, nBoundary, FINALITY_ANCESTOR_MAX_WALK);
    BOOST_REQUIRE(pBoundary != NULL);

    CertAncestryRegtest network;
    GlobalFinalityRestore restore;
    ScopedNoteVoteHeight noteVoteHeight(1);
    BOOST_REQUIRE_EQUAL(g_finalityTracker.GetEpochVoteCount(nEpoch), 0);
    CountedNoteVotes notes(uint256(0xCE000003), nEpoch, nBoundary, pBoundary->GetBlockHash(),
                           2, 0x81);
    BOOST_REQUIRE_EQUAL(g_finalityTracker.GetPendingTallyCertificateCount(nEpoch), 0U);

    const std::vector<CFinalityTallyCertificate> vProduced =
        BuildConnectedTallyCertificates(g_finalityTracker, nEpoch, pindexPrev->nHeight);
    BOOST_REQUIRE_EQUAL(vProduced.size(), 1U);
    CScript scriptProduced;
    BOOST_REQUIRE(BuildFinalityTallyCertificateScriptForHeight(vProduced[0], nHeight,
                                                               scriptProduced));

    // On the tip the template carries it.
    {
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        BOOST_REQUIRE(pblock.get() != NULL);
        BOOST_REQUIRE(TemplateParent(*pblock) == pindexPrev);
        BOOST_REQUIRE_MESSAGE(CoinbaseCarries(*pblock, scriptProduced),
                              "on-tip template did not carry the certificate");
    }

    std::unique_ptr<CBlock> pblock;
    {
        struct HoldBest
        {
            CBlockIndex* pSaved;
            explicit HoldBest(CBlockIndex* p)
            {
                LOCK(cs_main);
                pSaved = pindexBest;
                pindexBest = p;
            }
            ~HoldBest()
            {
                LOCK(cs_main);
                pindexBest = pSaved;
            }
        } hold(pindexPrev->pprev);
        pblock.reset(CreateNewBlock(pwalletMain));
    }
    BOOST_REQUIRE(pindexBest == pindexPrev);
    BOOST_REQUIRE(pblock.get() != NULL);
    BOOST_REQUIRE_MESSAGE(TemplateParent(*pblock) == pindexPrev,
                          "parent selection did not pick the block above pindexBest");
    BOOST_CHECK_MESSAGE(!CoinbaseCarries(*pblock, scriptProduced),
                        "off-tip template carried the certificate");
    const std::vector<CTxOut>& vout = pblock->vtx[0].vout;
    for (size_t i = 0; i < vout.size(); i++)
    {
        CFinalityTallyCertificate carried;
        BOOST_CHECK(ExtractFinalityTallyCertificateForHeight(vout[i].scriptPubKey, nHeight,
                                                             carried) !=
                    FINALITY_ENVELOPE_VALID);
    }
}

BOOST_AUTO_TEST_SUITE_END()
