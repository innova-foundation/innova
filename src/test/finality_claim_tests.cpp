// The finalized height is the epoch boundary the votes named, not the epoch end.
// Linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <map>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../dag.h"
#include "../finality.h"
#include "../key.h"
#include "../main.h"
#include "../txdb.h"
#include "../uint256.h"
#include "synthetic_chain.h"

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(finality_claim_tests)

namespace {

// Post-DAG PoW blocks wired into mapBlockIndex and the DAG manager, torn down on exit.
// Regtest (DAG fork 11, schema V3 at 311) with Boundary B at the V3 height, so the
// builder also derives the IV5 finalized anchor.
struct ClaimHarness
{
    std::vector<uint256> hashes;
    std::vector<CBlockIndex*> blocks;
    CBlockIndex* oldBest;
    bool oldRegTest;
    bool oldTestNet;
    int oldBoundaryB;
    CBigNum oldProofOfWorkLimit;

    ClaimHarness()
    {
        oldRegTest = fRegTest;
        oldTestNet = fTestNet;
        fRegTest = true;
        fTestNet = false;
        oldProofOfWorkLimit = bnProofOfWorkLimit;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        oldBest = pindexBest;
        oldBoundaryB = nRegtestBoundaryBHeight;
        nRegtestBoundaryBHeight = FORK_HEIGHT_EPOCH_STATE_V3;
    }

    ~ClaimHarness() { cleanup(); }

    CBlockIndex* add(unsigned int seed, int height, const std::vector<uint256>& parents,
                     CBlockIndex* pprev, const std::vector<CTransaction>* pvtx = NULL)
    {
        CBlock block;
        block.nVersion = 1;
        block.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
        block.nTime = (unsigned int)(1700000000 + height);
        block.nBits = bnProofOfWorkLimit.GetCompact();
        block.nNonce = seed;
        if (pvtx && !pvtx->empty())
        {
            block.vtx = *pvtx;
            block.hashMerkleRoot = block.BuildMerkleTree();
        }
        else
            block.hashMerkleRoot = uint256(seed);
        while (!CheckProofOfWork(block.GetHash(), block.nBits))
            ++block.nNonce;

        unsigned int nFile = 0;
        unsigned int nBlockPos = 0;
        BOOST_REQUIRE(block.WriteToDisk(nFile, nBlockPos));

        const uint256 h = block.GetHash();
        CBlockIndex* idx = new CBlockIndex(nFile, nBlockPos, block);
        idx->nHeight = height;
        idx->pprev = pprev;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(h, idx));
        BOOST_REQUIRE(ins.second);
        idx->phashBlock = &ins.first->first;
        g_dagManager.InitBlockDAGData(idx, parents);
        if (height >= FORK_HEIGHT_DAGKNIGHT)
            BOOST_REQUIRE(g_dagManager.ColorBlockDAGKnight(idx));
        else
            g_dagManager.ColorBlock(idx);
        idx->nChainTrust = g_dagManager.ComputeDAGScore(idx);
        hashes.push_back(h);
        blocks.push_back(idx);
        return idx;
    }

    CBlockIndex* addChild(unsigned int seed, CBlockIndex* pprev,
                          const std::vector<CTransaction>* pvtx = NULL)
    {
        std::vector<uint256> parents(1, pprev->GetBlockHash());
        return add(seed, pprev->nHeight + 1, parents, pprev, pvtx);
    }

    void cleanup()
    {
        for (size_t i = 0; i < hashes.size(); i++)
        {
            g_dagManager.RemoveBlockDAGData(hashes[i]);
            mapBlockIndex.erase(hashes[i]);
            delete blocks[i];
        }
        hashes.clear();
        blocks.clear();
        pindexBest = oldBest;
        nRegtestBoundaryBHeight = oldBoundaryB;
        bnProofOfWorkLimit = oldProofOfWorkLimit;
        fRegTest = oldRegTest;
        fTestNet = oldTestNet;
    }
};

int EpochStart(int nEpoch) { return GetEpochBoundaryHeight(nEpoch, 0); }
int EpochEnd(int nEpoch)   { return GetEpochBoundaryHeight(nEpoch + 1, 0) - 1; }

CFinalityVote VoteFor(int nEpoch, const CBlockIndex* pNamed, const CKey& key, int nSeed)
{
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    vote.nEpoch = nEpoch;
    vote.hashBlock = pNamed->GetBlockHash();
    vote.nHeight = pNamed->nHeight;
    vote.nTime = 1700000000 + nSeed;
    vote.nVoteWeight = 100 * COIN;
    vote.nReward = 0;
    vote.nullifier = uint256(0x5000 + nSeed);
    const CPubKey pubkey = key.GetPubKey();
    vote.vchPubKey.assign(pubkey.begin(), pubkey.end());
    return vote;
}

std::vector<CTransaction> Carrier(const std::vector<CScript>& vScripts, unsigned int nTime)
{
    CTransaction tx;
    tx.nTime = nTime;
    for (size_t i = 0; i < vScripts.size(); i++)
        tx.vout.push_back(CTxOut(0, vScripts[i]));
    return std::vector<CTransaction>(1, tx);
}

// One full epoch on top of pPrevEnd. Every voter names the block nNamedOffset above the
// boundary (0 is the boundary itself, or pNameInstead when given); the votes ride in the
// block after the named one, inside the inclusion window. Returns the epoch's end block.
CBlockIndex* BuildEpoch(ClaimHarness& h, unsigned int seedBase, int nEpoch,
                        CBlockIndex* pPrevEnd, const std::vector<CKey>& vVoters,
                        int nNamedOffset, CBlockIndex** ppBoundaryOut,
                        std::vector<CFinalityVote>* pvVotesOut,
                        CBlockIndex* pNameInstead = NULL)
{
    const int hStart = EpochStart(nEpoch);
    const int hEnd = EpochEnd(nEpoch);
    BOOST_REQUIRE_EQUAL(pPrevEnd->nHeight, hStart - 1);

    CBlockIndex* pBoundary = h.addChild(seedBase, pPrevEnd);
    if (ppBoundaryOut)
        *ppBoundaryOut = pBoundary;
    CBlockIndex* pNamed = pNameInstead ? pNameInstead : pBoundary;
    CBlockIndex* pMain = pBoundary;
    for (int nHeight = hStart + 1; nHeight <= hEnd; ++nHeight)
    {
        std::vector<CTransaction> vtx;
        if (!vVoters.empty() && nHeight == pNamed->nHeight + 1 &&
            pNamed->nHeight == hStart + nNamedOffset)
        {
            std::vector<CScript> vScripts;
            for (size_t i = 0; i < vVoters.size(); i++)
            {
                CFinalityVote vote =
                    VoteFor(nEpoch, pNamed, vVoters[i], nEpoch * 100 + (int)i);
                if (IsBoundaryAActiveAtHeight(nHeight))
                    vote.MarkCanonicalEnvelope();
                CScript script;
                BOOST_REQUIRE(BuildFinalityVoteScriptForHeight(vote, nHeight, script));
                vScripts.push_back(script);
                if (pvVotesOut)
                    pvVotesOut->push_back(vote);
            }
            vtx = Carrier(vScripts, (unsigned int)(1700000000 + nHeight));
        }
        pMain = h.addChild(seedBase + (unsigned int)(nHeight - hStart), pMain,
                           vtx.empty() ? NULL : &vtx);
        if (nHeight == hStart + nNamedOffset)
            pNamed = pMain;
    }
    return pMain;
}

// The predecessor of the first V3 epoch. Its finalized height is the block before the
// epoch so the IV5 anchor walk has somewhere to land on a harness chain.
CEpochState PredecessorFor(int nEpoch, const CBlockIndex* pBefore)
{
    CEpochState prev;
    prev.nEpoch = nEpoch - 1;
    prev.hashBoundaryBlock = pBefore->GetBlockHash();
    prev.nHeightStart = EpochStart(nEpoch - 1);
    prev.nHeightEnd = EpochStart(nEpoch) - 1;
    prev.hashCurveRoot = 0;
    prev.nFinalizedHeightAsOf = pBefore->nHeight;
    return prev;
}

bool BuildV3(int nEpoch, CBlockIndex* pEnd, const CEpochState& prev, const CCurveTree& prevTree,
             CEpochState& stateOut, CCurveTree& treeOut, std::string& strError)
{
    pindexBest = pEnd;
    return g_dagManager.BuildEpochState(nEpoch, EpochEnd(nEpoch) - EpochStart(nEpoch) + 1,
                                        pEnd, stateOut, treeOut, strError, &prev, &prevTree);
}

std::vector<CKey> Voters(size_t n)
{
    std::vector<CKey> v(n);
    for (size_t i = 0; i < n; i++)
        v[i].MakeNewKey(true);
    return v;
}

} // namespace

// Three consecutive HARD epochs finalize the third epoch's boundary, not its end; the
// IV5 anchor and the live tracker agree on height and hash.
BOOST_AUTO_TEST_CASE(the_streak_finalizes_the_attested_boundary_not_the_epoch_end)
{
    ClaimHarness h;
    const int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    BOOST_REQUIRE_EQUAL(FINALITY_CONFIRMATION_EPOCHS, 3);
    const std::vector<CKey> voters = Voters(FINALITY_MIN_VOTERS);

    std::vector<uint256> none;
    CBlockIndex* pBefore = h.add(0xF1A00000, EpochStart(E) - 1, none, NULL);

    CBlockIndex* pBoundary[3] = {NULL, NULL, NULL};
    std::vector<CFinalityVote> vVotes[3];
    CBlockIndex* pEnd = pBefore;
    CEpochState states[3];
    CCurveTree trees[3];
    CEpochState prev = PredecessorFor(E, pBefore);
    CCurveTree prevTree;
    for (int i = 0; i < 3; i++)
    {
        pEnd = BuildEpoch(h, 0xF1A10000U + (unsigned int)i * 0x1000U, E + i, pEnd, voters,
                          0, &pBoundary[i], &vVotes[i]);
        std::string strError;
        BOOST_REQUIRE_MESSAGE(BuildV3(E + i, pEnd, prev, prevTree, states[i], trees[i], strError),
                              strError);
        prev = states[i];
        prevTree = trees[i];
    }

    // Premise: each epoch is HARD on its own votes and the streak is complete.
    for (int i = 0; i < 3; i++)
    {
        BOOST_CHECK_EQUAL(states[i].nFinalityTier, FINALITY_HARD);
        BOOST_CHECK_EQUAL(states[i].nConsecutiveHardCount, i + 1);
    }

    // Before the streak completes the height carries forward untouched, and so does
    // the block it names.
    BOOST_CHECK_EQUAL(states[0].nFinalizedHeightAsOf, pBefore->nHeight);
    BOOST_CHECK_EQUAL(states[1].nFinalizedHeightAsOf, pBefore->nHeight);
    BOOST_CHECK(states[0].hashVNextFinalizedAnchor == pBefore->GetBlockHash());
    BOOST_CHECK(states[1].hashVNextFinalizedAnchor == pBefore->GetBlockHash());

    // The claim: the boundary the votes named, and nothing above it.
    const CEpochState& last = states[2];
    BOOST_CHECK_MESSAGE(last.nFinalizedHeightAsOf == last.nHeightStart,
                        "finalized height " << last.nFinalizedHeightAsOf
                        << " is not the attested boundary " << last.nHeightStart);
    BOOST_CHECK_MESSAGE(last.nFinalizedHeightAsOf != last.nHeightEnd,
                        "finalized height landed on the unattested epoch end "
                        << last.nHeightEnd);
    BOOST_CHECK_EQUAL(last.nFinalizedHeightAsOf, pBoundary[2]->nHeight);
    BOOST_CHECK_MESSAGE(!last.fFinalized,
                        "the record claims its own unattested tail as finalized");

    // The record's anchor is the block the votes named: the boundary block on the
    // epoch's own chain, which the builder requires the winner to be. MUTATION: leave
    // the anchor at the predecessor's and the checks against the vote fail.
    BOOST_CHECK_EQUAL(last.nVNextFinalizedHeight, last.nHeightStart);
    BOOST_CHECK_MESSAGE(last.hashVNextFinalizedAnchor == vVotes[2][0].hashBlock,
                        "the record does not name the block the votes named");
    BOOST_CHECK(last.hashVNextFinalizedAnchor == pBoundary[2]->GetBlockHash());
    BOOST_CHECK(last.hashVNextFinalizedAnchor != pBefore->GetBlockHash());
    BOOST_CHECK(last.FinalizedAnchorHash() == last.hashVNextFinalizedAnchor);

    // The two numbers a node reports agree: the live tracker fed the same votes.
    CFinalityTracker tracker;
    for (int i = 0; i < 3; i++)
    {
        for (size_t v = 0; v < vVotes[i].size(); v++)
            BOOST_REQUIRE(tracker.AddVote(vVotes[i][v], false, true));
        tracker.CheckFinalityThreshold(E + i, false);
    }
    BOOST_CHECK_MESSAGE(tracker.GetFinalizedHeight() == last.nFinalizedHeightAsOf,
                        "live tracker reports " << tracker.GetFinalizedHeight()
                        << " but the epoch state reports " << last.nFinalizedHeightAsOf);
    BOOST_CHECK_MESSAGE(tracker.GetFinalizedHash() == last.hashVNextFinalizedAnchor,
                        "live tracker and epoch state name different finalized blocks");
}

// The builder refuses to complete a streak on a winner that is not the epoch boundary.
// Consensus already rejects such a vote at connect; this pins that the claim can only
// ever be the boundary even if one got through.
BOOST_AUTO_TEST_CASE(a_streak_completing_on_a_non_boundary_winner_fails_the_build)
{
    ClaimHarness h;
    const int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    const std::vector<CKey> voters = Voters(FINALITY_MIN_VOTERS);

    std::vector<uint256> none;
    CBlockIndex* pBefore = h.add(0xF1B00000, EpochStart(E) - 1, none, NULL);

    CBlockIndex* pEnd = pBefore;
    CEpochState prev = PredecessorFor(E, pBefore);
    CCurveTree prevTree;
    for (int i = 0; i < 2; i++)
    {
        pEnd = BuildEpoch(h, 0xF1B10000U + (unsigned int)i * 0x1000U, E + i, pEnd, voters,
                          0, NULL, NULL);
        CEpochState state;
        CCurveTree tree;
        std::string strError;
        BOOST_REQUIRE_MESSAGE(BuildV3(E + i, pEnd, prev, prevTree, state, tree, strError),
                              strError);
        BOOST_REQUIRE_EQUAL(state.nConsecutiveHardCount, i + 1);
        prev = state;
        prevTree = tree;
    }

    // The third epoch's voters name the block after the boundary.
    pEnd = BuildEpoch(h, 0xF1B13000U, E + 2, pEnd, voters, 1, NULL, NULL);
    CEpochState state;
    CCurveTree tree;
    std::string strError;
    BOOST_CHECK_MESSAGE(!BuildV3(E + 2, pEnd, prev, prevTree, state, tree, strError),
                        "a streak completed on a winner that is not the epoch boundary");
    BOOST_CHECK_MESSAGE(strError.find("is not the epoch boundary") != std::string::npos,
                        "unexpected error: " << strError);
}

// The builder refuses a winner at the boundary height that is not the block on its
// own pprev chain.
BOOST_AUTO_TEST_CASE(a_streak_completing_on_a_sibling_of_the_boundary_block_fails_the_build)
{
    ClaimHarness h;
    const int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    const std::vector<CKey> voters = Voters(FINALITY_MIN_VOTERS);

    std::vector<uint256> none;
    CBlockIndex* pBefore = h.add(0xF1E00000, EpochStart(E) - 1, none, NULL);

    CBlockIndex* pEnd = pBefore;
    CEpochState prev = PredecessorFor(E, pBefore);
    CCurveTree prevTree;
    for (int i = 0; i < 2; i++)
    {
        pEnd = BuildEpoch(h, 0xF1E10000U + (unsigned int)i * 0x1000U, E + i, pEnd, voters,
                          0, NULL, NULL);
        CEpochState state;
        CCurveTree tree;
        std::string strError;
        BOOST_REQUIRE_MESSAGE(BuildV3(E + i, pEnd, prev, prevTree, state, tree, strError),
                              strError);
        BOOST_REQUIRE_EQUAL(state.nConsecutiveHardCount, i + 1);
        prev = state;
        prevTree = tree;
    }

    // A second block at the third epoch's boundary height, off the chain the epoch is
    // built on. The voters name it, at the boundary height.
    CBlockIndex* pSibling = h.addChild(0xF1E1F000U, pEnd);
    CBlockIndex* pBoundary = NULL;
    std::vector<CFinalityVote> vVotes;
    pEnd = BuildEpoch(h, 0xF1E13000U, E + 2, pEnd, voters, 0, &pBoundary, &vVotes, pSibling);
    BOOST_REQUIRE(pBoundary->pprev == pSibling->pprev);
    BOOST_REQUIRE(pBoundary->GetBlockHash() != pSibling->GetBlockHash());
    BOOST_REQUIRE(!vVotes.empty());
    BOOST_REQUIRE_EQUAL(vVotes[0].nHeight, EpochStart(E + 2));
    BOOST_REQUIRE(vVotes[0].hashBlock == pSibling->GetBlockHash());

    CEpochState state;
    CCurveTree tree;
    std::string strError;
    BOOST_CHECK_MESSAGE(!BuildV3(E + 2, pEnd, prev, prevTree, state, tree, strError),
                        "a streak completed on a winner the epoch's own chain does not carry");
    BOOST_CHECK_MESSAGE(strError.find("is not the epoch's boundary block") != std::string::npos,
                        "unexpected error: " << strError);
}

// Pre-V3 epoch with one streak-completing HARD cert naming the block nNamedOffset from
// the boundary, or a sibling with fNameSibling. Returns the V2 builder's verdict.
bool BuildV2StreakWithCert(ClaimHarness& h, int nNamedOffset, CEpochState& stateOut,
                           std::string& strError, int& hStartOut, int& hEndOut,
                           bool fNameSibling = false)
{
    const int nCarrierFork = FORK_HEIGHT_CONNECTED_FINALITY_CARRIER;
    const int E = GetEpochForHeight(nCarrierFork);
    hStartOut = EpochStart(E);
    hEndOut = EpochEnd(E);
    const int hCarrier = nCarrierFork - 1;
    BOOST_REQUIRE(nNamedOffset <= 0 || hCarrier > hStartOut + nNamedOffset);
    BOOST_REQUIRE(hEndOut < FORK_HEIGHT_EPOCH_STATE_V3);

    std::vector<uint256> none;
    CBlockIndex* pBefore = h.add(0xF1C00000, hStartOut - 1, none, NULL);
    CBlockIndex* pBoundary = h.addChild(0xF1C00001, pBefore);
    CBlockIndex* pNamed = (nNamedOffset < 0) ? pBefore : pBoundary;
    if (fNameSibling)
        pNamed = h.addChild(0xF1C00002, pBefore);
    CBlockIndex* pMain = pBoundary;
    std::vector<CScript> vScripts;
    for (int nHeight = hStartOut + 1; nHeight <= hEndOut; ++nHeight)
    {
        std::vector<CTransaction> vtx;
        if (nHeight == hCarrier)
        {
            CFinalityTallyCertificate cert;
            cert.nVersion = 2;
            cert.nEpoch = E;
            cert.hashBlock = pNamed->GetBlockHash();
            cert.nHeight = pNamed->nHeight;
            cert.nTier = FINALITY_HARD;
            cert.nConsecutiveHardCount = FINALITY_CONFIRMATION_EPOCHS;
            cert.nTransparentActiveWeight = 1000;
            cert.nTransparentWinningWeight = 1000;
            cert.vVoteNullifiers.push_back(uint256(0xF1C0AAAA));
            vScripts.push_back(BuildFinalityTallyCertificateScript(cert));
            vtx = Carrier(vScripts, (unsigned int)(1700000000 + nHeight));
        }
        pMain = h.addChild(0xF1C10000U + (unsigned int)(nHeight - hStartOut), pMain,
                           vtx.empty() ? NULL : &vtx);
        if (nHeight == hStartOut + nNamedOffset)
            pNamed = pMain;
    }
    CBlockIndex* pCrossing = h.addChild(0xF1C1FFFF, pMain);

    // Two HARD epochs behind it, so this one completes the streak.
    CEpochState prev;
    prev.nEpoch = E - 1;
    prev.hashBoundaryBlock = pBefore->GetBlockHash();
    prev.nHeightStart = EpochStart(E - 1);
    prev.nHeightEnd = hStartOut - 1;
    prev.nFinalityTier = FINALITY_HARD;
    prev.nConsecutiveHardCount = FINALITY_CONFIRMATION_EPOCHS - 1;
    prev.nFinalizedHeightAsOf = 0;
    CCurveTree prevTree;
    CCurveTree tree;
    return g_dagManager.BuildEpochStateV2Compat(E, hEndOut - hStartOut + 1, pCrossing,
                                                stateOut, tree, strError, &prev, &prevTree);
}

// The legacy V2 builder makes the same claim: a HARD certificate naming the boundary
// completes a streak at the boundary height, not the epoch end.
BOOST_AUTO_TEST_CASE(the_v2_builder_finalizes_the_attested_boundary_too)
{
    ClaimHarness h;
    CEpochState state;
    std::string strError;
    int hStart = 0, hEnd = 0;
    BOOST_REQUIRE_MESSAGE(BuildV2StreakWithCert(h, 0, state, strError, hStart, hEnd), strError);

    BOOST_CHECK_EQUAL(state.nFinalityTier, FINALITY_HARD);
    BOOST_CHECK_EQUAL(state.nConsecutiveHardCount, FINALITY_CONFIRMATION_EPOCHS);
    BOOST_CHECK_MESSAGE(state.nFinalizedHeightAsOf == hStart,
                        "V2 finalized height " << state.nFinalizedHeightAsOf
                        << " is not the attested boundary " << hStart);
    BOOST_CHECK_MESSAGE(state.nFinalizedHeightAsOf != hEnd,
                        "V2 finalized height landed on the unattested epoch end");
    BOOST_CHECK(!state.fFinalized);
    // The certificate named the boundary block, h.blocks[1]; the record's anchor is it.
    BOOST_REQUIRE_EQUAL(h.blocks[1]->nHeight, hStart);
    BOOST_CHECK_MESSAGE(state.hashVNextFinalizedAnchor == h.blocks[1]->GetBlockHash(),
                        "V2 record does not name the block the certificate named");
    BOOST_CHECK(state.FinalizedAnchorHash() == h.blocks[1]->GetBlockHash());
}

// And refuses to complete a streak on a certificate naming a non-boundary block.
BOOST_AUTO_TEST_CASE(the_v2_builder_refuses_a_streak_on_a_non_boundary_winner)
{
    ClaimHarness h;
    CEpochState state;
    std::string strError;
    int hStart = 0, hEnd = 0;
    BOOST_CHECK_MESSAGE(!BuildV2StreakWithCert(h, -1, state, strError, hStart, hEnd),
                        "V2 completed a streak on a winner that is not the epoch boundary");
    BOOST_CHECK_MESSAGE(strError.find("is not the epoch boundary") != std::string::npos,
                        "unexpected error: " << strError);
}

// And on a certificate naming a block at the boundary height that is not the boundary
// block on the epoch's own chain.
BOOST_AUTO_TEST_CASE(the_v2_builder_refuses_a_streak_on_a_sibling_winner)
{
    ClaimHarness h;
    CEpochState state;
    std::string strError;
    int hStart = 0, hEnd = 0;
    BOOST_CHECK_MESSAGE(!BuildV2StreakWithCert(h, 0, state, strError, hStart, hEnd, true),
                        "V2 completed a streak on a winner the epoch's own chain does not carry");
    BOOST_CHECK_MESSAGE(strError.find("is not the epoch's boundary block") != std::string::npos,
                        "unexpected error: " << strError);
}

// The finalized epoch is the last one ending at or below the finalized height; legacy
// end-height records resolve the same way.
BOOST_AUTO_TEST_CASE(the_finalized_epoch_is_the_last_one_ending_at_or_below_the_height)
{
    ClaimHarness h;
    const int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);

    BOOST_CHECK_EQUAL(GetFinalizedEpochForHeight(EpochStart(E + 2)), E + 1);
    BOOST_CHECK_EQUAL(GetFinalizedEpochForHeight(EpochEnd(E + 2)), E + 2);
    BOOST_CHECK_EQUAL(GetFinalizedEpochForHeight(EpochStart(E) - 1), E - 1);
    BOOST_CHECK_EQUAL(GetFinalizedEpochForHeight(0), -1);

    // As of epoch E+2 the boundary H_{E+2} is finalized: the finalized epoch is E+1.
    {
        CDAGManager dag;
        std::map<int, CEpochState> states;
        std::map<int, CCurveTree> trees;
        for (int e = E - 1; e <= E + 2; e++)
        {
            CEpochState state;
            state.nEpoch = e;
            state.nHeightStart = EpochStart(e);
            state.nHeightEnd = EpochEnd(e);
            state.hashCurveRoot = 0;
            state.nFinalizedHeightAsOf = (e == E + 2) ? EpochStart(E + 2) : 0;
            states[e] = state;
            trees[e] = CCurveTree();
        }
        BOOST_REQUIRE(dag.InstallEpochStateBatch(E - 1, states, trees));

        CEpochState anchor;
        BOOST_REQUIRE(dag.GetFinalizedEpochStateAsOf(EpochStart(E + 3) + 5, anchor));
        BOOST_CHECK_MESSAGE(anchor.nEpoch == E + 1,
                            "finalized epoch resolved to " << anchor.nEpoch
                            << ", whose blocks above the boundary no vote attested");
        BOOST_CHECK(anchor.nHeightEnd <= EpochStart(E + 2));
    }

    // A record that still carries an end height resolves to the epoch ending there.
    {
        CDAGManager dag;
        std::map<int, CEpochState> states;
        std::map<int, CCurveTree> trees;
        for (int e = E - 1; e <= E + 2; e++)
        {
            CEpochState state;
            state.nEpoch = e;
            state.nHeightStart = EpochStart(e);
            state.nHeightEnd = EpochEnd(e);
            state.hashCurveRoot = 0;
            state.nFinalizedHeightAsOf = (e == E + 2) ? EpochEnd(E + 2) : 0;
            states[e] = state;
            trees[e] = CCurveTree();
        }
        BOOST_REQUIRE(dag.InstallEpochStateBatch(E - 1, states, trees));

        CEpochState anchor;
        BOOST_REQUIRE(dag.GetFinalizedEpochStateAsOf(EpochStart(E + 3) + 5, anchor));
        BOOST_CHECK_EQUAL(anchor.nEpoch, E + 2);
    }
}

// Whether an epoch's root is final is derived from the finalized height in force, not
// read from the record: the record of the epoch before a completed streak was written
// before that streak finished and says false of itself.
BOOST_AUTO_TEST_CASE(root_finality_is_derived_from_the_finalized_height_not_the_record)
{
    ClaimHarness h;
    const int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    const int nFinalized = EpochStart(E + 2);

    CEpochState before;
    before.nEpoch = E + 1;
    before.nHeightStart = EpochStart(E + 1);
    before.nHeightEnd = EpochEnd(E + 1);
    before.fFinalized = false;

    CEpochState opening;
    opening.nEpoch = E + 2;
    opening.nHeightStart = EpochStart(E + 2);
    opening.nHeightEnd = EpochEnd(E + 2);
    opening.fFinalized = false;

    BOOST_CHECK(EpochStateIsFinalizedAsOf(before, nFinalized));
    BOOST_CHECK(!EpochStateIsFinalizedAsOf(opening, nFinalized));

    // A shallow context: the epoch that ends below the finalized boundary anchors on
    // finality alone, the one that opens at it does not.
    const int nShallow = EpochStart(E + 2) + 5;
    BOOST_CHECK_MESSAGE(EpochStateMayAnchorAt(before, nFinalized, nShallow),
                        "an epoch whose every block is below the finalized boundary "
                        "was refused as an anchor");
    BOOST_CHECK(!EpochStateMayAnchorAt(opening, nFinalized, nShallow));

    // Depth still stands in for finality, exactly as before.
    BOOST_CHECK(EpochStateMayAnchorAt(
        opening, nFinalized,
        opening.nHeightEnd + EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH));
    BOOST_CHECK(!EpochStateMayAnchorAt(
        opening, nFinalized,
        opening.nHeightEnd + EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH - 1));
}

// The reorg guard admits a sibling fork at the epoch end and still refuses a fork
// replacing the boundary block.
BOOST_AUTO_TEST_CASE(the_reorg_guard_admits_an_epoch_end_sibling_and_defends_the_boundary)
{
    ClaimHarness h;
    const int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    const int nBest = EpochStart(E + 3) + 5; // completed epoch E + 2
    BOOST_REQUIRE(nBest >= FORK_HEIGHT_EPOCH_STATE_V3);

    CSyntheticChain chain(0xF1D00000U);
    CBlockIndex* pTip = chain.Linear(nBest);
    BOOST_REQUIRE(pTip != NULL);
    // A block whose selected parent is the chain block at nFork.
    struct Fork
    {
        static CBlockIndex* At(CSyntheticChain& c, CBlockIndex* pTip, int nFork)
        {
            CBlockIndex* p = c.Add(pTip->GetAncestor(nFork), nFork + 1);
            BOOST_REQUIRE(p != NULL);
            return p;
        }
    };

    for (int pass = 0; pass < 2; pass++)
    {
        const bool fBoundaryClaim = (pass == 0);
        const int nClaim = fBoundaryClaim ? EpochStart(E + 2) : EpochEnd(E + 2);
        CDAGManager dag;
        std::map<int, CEpochState> states;
        std::map<int, CCurveTree> trees;
        for (int e = E - 1; e <= E + 2; e++)
        {
            CEpochState state;
            state.nEpoch = e;
            state.nHeightStart = EpochStart(e);
            state.nHeightEnd = EpochEnd(e);
            state.nFinalizedHeightAsOf = (e == E + 2) ? nClaim : 0;
            state.hashVNextFinalizedAnchor =
                (e == E + 2) ? pTip->GetAncestor(nClaim)->GetBlockHash() : uint256(0);
            states[e] = state;
            trees[e] = CCurveTree();
        }
        BOOST_REQUIRE(dag.InstallEpochStateBatch(E - 1, states, trees));

        int nCur = 0, nLatch = 0, nAsOf = 0;
        const ReorgFinalityVerdict endSibling = CheckReorgAgainstFinality(
            dag, nBest, Fork::At(chain, pTip, EpochEnd(E + 2) - 1), nCur, nLatch, nAsOf);
        BOOST_CHECK_EQUAL(nCur, nClaim);
        if (fBoundaryClaim)
            BOOST_CHECK_MESSAGE(endSibling == REORG_FINALITY_ALLOW,
                                "a reorg among siblings at the epoch end was refused "
                                "although no vote attested that block");
        else
            BOOST_CHECK(endSibling != REORG_FINALITY_ALLOW);

        const ReorgFinalityVerdict belowBoundary = CheckReorgAgainstFinality(
            dag, nBest, Fork::At(chain, pTip, EpochStart(E + 2) - 1), nCur, nLatch, nAsOf);
        BOOST_CHECK_MESSAGE(belowBoundary != REORG_FINALITY_ALLOW,
                            "a reorg replacing the attested boundary block was admitted");
        if (fBoundaryClaim)
        {
            const ReorgFinalityVerdict keepsBoundary = CheckReorgAgainstFinality(
                dag, nBest, Fork::At(chain, pTip, EpochStart(E + 2)), nCur, nLatch, nAsOf);
            BOOST_CHECK_MESSAGE(keepsBoundary == REORG_FINALITY_ALLOW,
                                "a reorg that keeps the attested boundary block was refused");
        }
    }
}


// Persisted-record migration: EPOCHSTATE_SCHEMA_V5 marks boundary-claim records.

namespace {

class SchemaTestDB : public CTxDB
{
public:
    SchemaTestDB() : CTxDB("r+") {}
    bool EraseEpochStateSchema() { return Erase(std::string("epochstateschema")); }
};

// Hides other suites' epoch records for the case and restores them on exit.
struct HiddenEpochRecords
{
    CTxDB& txdb;
    std::map<int, CEpochState> states;
    std::map<int, CCurveTree> trees;

    explicit HiddenEpochRecords(CTxDB& db) : txdb(db)
    {
        BOOST_REQUIRE(txdb.IterateEpochStates(states));
        BOOST_REQUIRE(txdb.IterateCurveTreeEpochs(trees));
        BOOST_REQUIRE(txdb.TxnBegin());
        for (std::map<int, CEpochState>::const_iterator it = states.begin(); it != states.end(); ++it)
            BOOST_REQUIRE(txdb.EraseEpochState(it->first));
        for (std::map<int, CCurveTree>::const_iterator it = trees.begin(); it != trees.end(); ++it)
            BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(it->first));
        BOOST_REQUIRE(txdb.TxnCommit());
    }

    ~HiddenEpochRecords()
    {
        std::map<int, CEpochState> left;
        std::map<int, CCurveTree> leftTrees;
        txdb.IterateEpochStates(left);
        txdb.IterateCurveTreeEpochs(leftTrees);
        bool fOK = txdb.TxnBegin();
        for (std::map<int, CEpochState>::const_iterator it = left.begin(); it != left.end(); ++it)
            fOK = txdb.EraseEpochState(it->first) && fOK;
        for (std::map<int, CCurveTree>::const_iterator it = leftTrees.begin(); it != leftTrees.end(); ++it)
            fOK = txdb.EraseCurveTreeAtEpoch(it->first) && fOK;
        for (std::map<int, CEpochState>::const_iterator it = states.begin(); it != states.end(); ++it)
            fOK = txdb.WriteEpochState(it->first, it->second) && fOK;
        for (std::map<int, CCurveTree>::const_iterator it = trees.begin(); it != trees.end(); ++it)
            fOK = txdb.WriteCurveTreeAtEpoch(it->first, it->second) && fOK;
        fOK = txdb.TxnCommit() && fOK;
        BOOST_CHECK_MESSAGE(fOK, "could not put the hidden epoch records back");
    }
};

// Regtest geometry: the epoch before the V3 fork is the migration base, and the fork
// block opens the next one. Boundary B is left unset so the record carries no IV5 fields.
struct SchemaFixture
{
    ClaimHarness h;
    int nEpoch;
    CBlockIndex* pStart;
    CBlockIndex* pEnd;
    CBlockIndex* pTip;

    SchemaFixture()
    {
        nRegtestBoundaryBHeight = PRIVACY_VNEXT_HEIGHT_UNSET;
        nEpoch = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3) - 1;
        std::vector<uint256> none;
        // The boundary block the epoch's records name, so a record naming the epoch
        // start has an ancestor the loader's anchor walk can land on.
        pStart = h.add(0xF5A00002, EpochStart(nEpoch), none, NULL);
        pEnd = h.add(0xF5A00000, EpochEnd(nEpoch), none, pStart);
        pTip = h.addChild(0xF5A00001, pEnd);
        BOOST_REQUIRE_EQUAL(pTip->nHeight, FORK_HEIGHT_EPOCH_STATE_V3);
    }

    CEpochState Record(int nFinalizedHeight) const
    {
        CEpochState state;
        state.nEpoch = nEpoch;
        state.nHeightStart = EpochStart(nEpoch);
        state.nHeightEnd = EpochEnd(nEpoch);
        state.hashBoundaryBlock = pEnd->GetBlockHash();
        state.vBlockHashes.push_back(state.hashBoundaryBlock);
        state.nBlockCount = 1;
        state.nTxCount = -1;
        state.nFinalizedHeightAsOf = nFinalizedHeight;
        return state;
    }

    void Install(CDAGManager& dag, const CEpochState& record) const
    {
        std::map<int, CEpochState> states;
        std::map<int, CCurveTree> trees;
        states[nEpoch] = record;
        trees[nEpoch] = CCurveTree();
        BOOST_REQUIRE(dag.InstallEpochStateBatch(nEpoch, states, trees));
    }
};

} // namespace

// The finalized height a record may carry is an epoch boundary or nothing. An epoch's
// end is neither, on either side of the DAG fork.
BOOST_AUTO_TEST_CASE(an_epoch_end_is_not_a_boundary_height)
{
    SchemaFixture f;
    const int E = f.nEpoch + 1;
    BOOST_CHECK(IsEpochBoundaryHeight(0));
    BOOST_CHECK(IsEpochBoundaryHeight(FORK_HEIGHT_DAG));
    BOOST_CHECK(IsEpochBoundaryHeight(EpochStart(E)));
    BOOST_CHECK(IsEpochBoundaryHeight(EpochStart(E + 1)));
    BOOST_CHECK(!IsEpochBoundaryHeight(FORK_HEIGHT_DAG - 1));
    BOOST_CHECK(!IsEpochBoundaryHeight(EpochEnd(E)));
    BOOST_CHECK(!IsEpochBoundaryHeight(EpochStart(E) + 1));
    BOOST_CHECK(!IsEpochBoundaryHeight(-1));

    CDAGManager dag;
    int nBadEpoch = 0;
    int nBadHeight = 0;
    f.Install(dag, f.Record(EpochStart(f.nEpoch)));
    BOOST_CHECK(dag.EpochStatesNameOnlyBoundaries(nBadEpoch, nBadHeight));
    f.Install(dag, f.Record(0));
    BOOST_CHECK(dag.EpochStatesNameOnlyBoundaries(nBadEpoch, nBadHeight));
    f.Install(dag, f.Record(EpochEnd(f.nEpoch)));
    BOOST_CHECK_MESSAGE(!dag.EpochStatesNameOnlyBoundaries(nBadEpoch, nBadHeight),
                        "a record naming the epoch end passed as a boundary record");
    BOOST_CHECK_EQUAL(nBadEpoch, f.nEpoch);
    BOOST_CHECK_EQUAL(nBadHeight, EpochEnd(f.nEpoch));
}

// A set whose record places the finalized height at an epoch end was built under the
// old rule. Past the V3 fork it is refused under every marker, the message names the
// record and the recovery, and -acceptepochstate does not admit it.
BOOST_AUTO_TEST_CASE(an_end_height_database_is_refused_and_the_flag_does_not_admit_it)
{
    SchemaFixture f;
    CDAGManager dag;
    f.Install(dag, f.Record(EpochEnd(f.nEpoch)));

    const int markers[3] = {EPOCHSTATE_SCHEMA_V3, EPOCHSTATE_SCHEMA_V4, EPOCHSTATE_SCHEMA_V5};
    for (int i = 0; i < 3; i++)
    {
        for (int flag = 0; flag < 2; flag++)
        {
            bool fStamp = true;
            std::string strError;
            BOOST_CHECK_MESSAGE(!dag.CheckEpochStateSchemaAtTip(true, markers[i], f.pTip,
                                                                flag != 0, fStamp, strError),
                                "an end-height record was admitted under marker "
                                << markers[i] << " with flag=" << flag);
            BOOST_CHECK(!fStamp);
            BOOST_CHECK_MESSAGE(strError.find("is not an epoch boundary") != std::string::npos,
                                strError);
            BOOST_CHECK_MESSAGE(strError.find(strprintf("epoch %d names finalized height %d",
                                                        f.nEpoch, EpochEnd(f.nEpoch))) !=
                                    std::string::npos, strError);
            BOOST_CHECK_MESSAGE(strError.find("resync") != std::string::npos, strError);
        }
    }
}

// Boundary-only records under a V3/V4 marker load only with -acceptepochstate; a V5
// marker needs no flag; older or unread markers are refused.
BOOST_AUTO_TEST_CASE(a_boundary_database_needs_the_flag_under_an_old_marker_and_none_under_v5)
{
    SchemaFixture f;
    CDAGManager dag;
    f.Install(dag, f.Record(EpochStart(f.nEpoch)));

    bool fStamp = true;
    std::string strError;
    BOOST_CHECK_MESSAGE(!dag.CheckEpochStateSchemaAtTip(true, EPOCHSTATE_SCHEMA_V4, f.pTip,
                                                        false, fStamp, strError),
                        "a V4 database ran without the flag");
    BOOST_CHECK(!fStamp);
    BOOST_CHECK_MESSAGE(strError.find("-acceptepochstate") != std::string::npos, strError);
    BOOST_CHECK_MESSAGE(strError.find("before the finalized height moved") != std::string::npos,
                        strError);

    fStamp = false;
    BOOST_CHECK_MESSAGE(dag.CheckEpochStateSchemaAtTip(true, EPOCHSTATE_SCHEMA_V4, f.pTip,
                                                       true, fStamp, strError), strError);
    BOOST_CHECK_MESSAGE(fStamp, "an admitted V4 database was not asked to be stamped V5");

    fStamp = false;
    BOOST_CHECK_MESSAGE(dag.CheckEpochStateSchemaAtTip(true, EPOCHSTATE_SCHEMA_V3, f.pTip,
                                                       true, fStamp, strError), strError);
    BOOST_CHECK(fStamp);

    fStamp = true;
    BOOST_CHECK_MESSAGE(dag.CheckEpochStateSchemaAtTip(true, EPOCHSTATE_SCHEMA_V5, f.pTip,
                                                       false, fStamp, strError), strError);
    BOOST_CHECK_MESSAGE(!fStamp, "a V5 database was asked to be stamped again");

    fStamp = true;
    BOOST_CHECK(!dag.CheckEpochStateSchemaAtTip(true, EPOCHSTATE_SCHEMA_V2, f.pTip, true,
                                                fStamp, strError));
    BOOST_CHECK(!fStamp);
    BOOST_CHECK(!dag.CheckEpochStateSchemaAtTip(false, 0, f.pTip, true, fStamp, strError));
    BOOST_CHECK(!fStamp);
    BOOST_CHECK(!dag.CheckEpochStateSchemaAtTip(true, EPOCHSTATE_SCHEMA_V5 + 1, f.pTip, true,
                                                fStamp, strError));
    BOOST_CHECK(!fStamp);

    // Nothing is stamped when the set fails the tip check, and the message reports the
    // marker the database has, not the one the flag would have written.
    CDAGManager torn;
    CEpochState wrong = f.Record(EpochStart(f.nEpoch));
    wrong.hashBoundaryBlock = uint256(0xF5A0BAD0);
    f.Install(torn, wrong);
    fStamp = true;
    BOOST_CHECK(!torn.CheckEpochStateSchemaAtTip(true, EPOCHSTATE_SCHEMA_V4, f.pTip, true,
                                                 fStamp, strError));
    BOOST_CHECK(!fStamp);
    BOOST_CHECK_MESSAGE(strError.find("schema marker 4") != std::string::npos, strError);
}

// Below the V3 fork nothing is judged: a node that has never reached the fork keeps the
// marker it has, and so does an empty set.
BOOST_AUTO_TEST_CASE(a_tip_below_the_v3_fork_is_not_judged)
{
    SchemaFixture f;
    CDAGManager dag;
    f.Install(dag, f.Record(EpochEnd(f.nEpoch)));
    bool fStamp = true;
    std::string strError;
    BOOST_REQUIRE(f.pEnd->nHeight < FORK_HEIGHT_EPOCH_STATE_V3);
    BOOST_CHECK(dag.CheckEpochStateSchemaAtTip(true, EPOCHSTATE_SCHEMA_V4, f.pEnd, false,
                                               fStamp, strError));
    BOOST_CHECK(!fStamp);
    BOOST_CHECK(strError.empty());

    CDAGManager empty;
    BOOST_CHECK(empty.CheckEpochStateSchemaAtTip(false, 0, f.pEnd, false, fStamp, strError));
    BOOST_CHECK(empty.CheckEpochStateSchemaAtTip(false, 0, NULL, false, fStamp, strError));
}

// The restart path. Under the V5 marker a persisted record naming an epoch end fails the
// load outright; the same record under the V4 marker loads, so init can judge it and
// name the recovery. Boundary and empty claims load under V5.
BOOST_AUTO_TEST_CASE(load_refuses_an_end_height_record_under_the_v5_marker)
{
    SchemaFixture f;
    SchemaTestDB txdb;
    int nOldSchema = 0;
    const bool fHadOldSchema = txdb.ReadEpochStateSchema(nOldSchema);
    // The loader sees this case's record and nothing else.
    HiddenEpochRecords hidden(txdb);
    CEpochState unused;
    BOOST_REQUIRE(!txdb.ReadEpochState(f.nEpoch, unused));

    struct Trial { int nSchema; int nFinalized; bool fLoads; };
    const Trial trials[] = {
        {EPOCHSTATE_SCHEMA_V5, EpochEnd(f.nEpoch), false},
        {EPOCHSTATE_SCHEMA_V4, EpochEnd(f.nEpoch), true},
        {EPOCHSTATE_SCHEMA_V5, EpochStart(f.nEpoch), true},
        {EPOCHSTATE_SCHEMA_V5, 0, true},
    };
    for (size_t i = 0; i < sizeof(trials) / sizeof(trials[0]); i++)
    {
        BOOST_REQUIRE(txdb.TxnBegin());
        BOOST_REQUIRE(txdb.WriteEpochState(f.nEpoch, f.Record(trials[i].nFinalized)));
        BOOST_REQUIRE(txdb.WriteCurveTreeAtEpoch(f.nEpoch, CCurveTree()));
        BOOST_REQUIRE(txdb.WriteEpochStateSchema(trials[i].nSchema));
        BOOST_REQUIRE(txdb.TxnCommit());

        CDAGManager loader;
        std::vector<uint256> none;
        BOOST_REQUIRE(loader.InitBlockDAGData(f.pEnd, none));
        BOOST_CHECK_MESSAGE(loader.LoadEpochStates(txdb) == trials[i].fLoads,
                            "trial " << i << ": schema " << trials[i].nSchema
                            << " with finalized height " << trials[i].nFinalized
                            << (trials[i].fLoads ? " failed to load" : " loaded"));
    }

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.EraseEpochState(f.nEpoch));
    BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(f.nEpoch));
    if (fHadOldSchema)
        BOOST_REQUIRE(txdb.WriteEpochStateSchema(nOldSchema));
    else
        BOOST_REQUIRE(txdb.EraseEpochStateSchema());
    BOOST_REQUIRE(txdb.TxnCommit());
}

BOOST_AUTO_TEST_SUITE_END()
