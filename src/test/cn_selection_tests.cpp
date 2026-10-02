// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Collateralnode selection: payee scoring width, protocol-version floor on the ranking,
// and payment-count exclusion from the average.

#include <boost/test/unit_test.hpp>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "../collateralnode.h"
#include "../key.h"
#include "../main.h"
#include "../miner.h"
#include "../util.h"
#include "../version.h"
#include "../wallet.h"

extern CWallet* pwalletMain;

// Both have external linkage but no declaration in the header.
extern std::vector<CCollateralNode> vecCollateralnodeScoresList;
extern std::map<uint256, std::vector<CCollateralNode> > mapCollateralnodeScoresCache;

BOOST_AUTO_TEST_SUITE(cn_selection_tests)

namespace {

// Restores the gossiped list, rank cache and score list. GetCollateralnodeRanks answers
// from the cache per block hash, so a stale entry would hide an edit.
struct CollateralnodeViewGuard
{
    std::vector<CCollateralNode> vSaved;
    std::vector<CCollateralNode> vSavedList;
    std::map<uint256, std::vector<CCollateralNode> > mapSavedCache;
    std::map<int64_t, uint256> mapSavedBlockHashes;
    bool fSavedReorg;

    CollateralnodeViewGuard()
    {
        LOCK(cs_collateralnodes);
        vSaved = vecCollateralnodes;
        vSavedList = vecCollateralnodeScoresList;
        mapSavedCache = mapCollateralnodeScoresCache;
        mapSavedBlockHashes = mapCacheBlockHashes;
        fSavedReorg = CollateralNReorgBlock;
        vecCollateralnodes.clear();
        vecCollateralnodeScores.clear();
        vecCollateralnodeScoresList.clear();
        mapCollateralnodeScoresCache.clear();
    }
    ~CollateralnodeViewGuard()
    {
        LOCK(cs_collateralnodes);
        vecCollateralnodes = vSaved;
        vecCollateralnodeScores.clear();
        vecCollateralnodeScoresList = vSavedList;
        mapCollateralnodeScoresCache = mapSavedCache;
        mapCacheBlockHashes = mapSavedBlockHashes;
        CollateralNReorgBlock = fSavedReorg;
    }
    void DropRankCache()
    {
        LOCK(cs_collateralnodes);
        mapCollateralnodeScoresCache.clear();
        vecCollateralnodeScores.clear();
        vecCollateralnodeScoresList.clear();
    }
};

// Restores the cold-staking rehearsal height on scope exit.
struct ColdStakingGateGuard
{
    int nSaved;
    ColdStakingGateGuard() : nSaved(nRegtestColdStakingHeight) {}
    ~ColdStakingGateGuard() { nRegtestColdStakingHeight = nSaved; }
};

// A live node: unitTest suppresses the collateral scan and a fresh lastTimeSeen keeps
// Check from disabling it.
CCollateralNode MakeNode(const uint256& hashPrev, unsigned int nOut,
                         int nProtocolVersion)
{
    CKey key;
    key.MakeNewKey(true);
    CService addr;
    CTxIn vin(COutPoint(hashPrev, nOut), CScript());
    std::vector<unsigned char> sig;
    CCollateralNode mn(addr, vin, key.GetPubKey(), sig, GetTime(),
                       key.GetPubKey(), nProtocolVersion);
    mn.unitTest = true;
    mn.enabled = 1;
    mn.UpdateLastSeen();
    return mn;
}

// Detaches the wallet while mining so coinbases do not move counters other suites pin.
struct DetachedWalletGuard
{
    DetachedWalletGuard() { UnregisterWallet(pwalletMain); }
    ~DetachedWalletGuard() { RegisterWallet(pwalletMain); }
};

bool EnsureChainHeight(int nWanted)
{
    if (pindexBest != NULL && pindexBest->nHeight >= nWanted)
        return true;
    BOOST_REQUIRE_MESSAGE(nWanted < FORK_HEIGHT_DAG,
                          "mining to height " << nWanted << " would cross the "
                          "regtest DAG fork at " << FORK_HEIGHT_DAG);
    DetachedWalletGuard walletGuard;
    while (pindexBest != NULL && pindexBest->nHeight < nWanted)
    {
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        if (pblock.get() == NULL)
            return false;
        CBlockIndex* pindexParent = NULL;
        {
            LOCK(cs_main);
            std::map<uint256, CBlockIndex*>::const_iterator mi =
                mapBlockIndex.find(pblock->hashPrevBlock);
            if (mi == mapBlockIndex.end())
                return false;
            pindexParent = mi->second;
        }
        unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock.get(), pindexParent, nExtraNonce);
        CBigNum target;
        target.SetCompact(pblock->nBits);
        const uint256 hashTarget = target.getuint256();
        unsigned int nHashes = 0;
        while (pblock->GetPoWHash() > hashTarget)
        {
            ++pblock->nNonce;
            if (pblock->nNonce == 0)
                ++pblock->nTime;
            if (++nHashes > 2000000U)
                return false;
        }
        if (!ProcessBlock(NULL, pblock.get()))
            return false;
    }
    return pindexBest != NULL && pindexBest->nHeight >= nWanted;
}

uint256 CountedHash(int n)
{
    uint256 h = 0;
    h = Hash(BEGIN(n), END(n));
    return h;
}

// Low 32 bits of a score, as the pre-gate comparison reads them. Used only to find a
// pair the two widths order differently.
unsigned int LowWord(const uint256& n)
{
    unsigned int n2 = 0;
    memcpy(&n2, &n, sizeof(n2));
    return n2;
}

} // namespace

// The score mixes the block hash with the candidate's outpoint. The vectors are the
// deployed (gcc) answers, pinned so the well-defined range matches on every compiler.
BOOST_AUTO_TEST_CASE(the_score_mix_matches_its_pinned_vectors)
{
    struct { const char* pszBlock; const char* pszAux; const char* pszScore; } vec[] = {
        { "00000000000000000000000000000000000000000000000000000000000000ff",
          "0000000000000000000000000000000000000000000000000000000000000001",
          "02bbad5d3261bd83afd91313b2f2559ca4803147e9b99413f37f751f67b31ce9" },
        // A zero outpoint term against a non-zero block hash: a mix that dropped
        // the outpoint would answer this and the next vector the same.
        { "a3f1c09b2e7d4856190bacde3f2718650d9c8b7a6f5e4d3c2b1a09f8e7d6c5b4",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "5904bfe9308d1deb946ec1818f924e2cb9e72c1040b40db74f19bf93ed578f92" },
        { "a3f1c09b2e7d4856190bacde3f2718650d9c8b7a6f5e4d3c2b1a09f8e7d6c5b4",
          "5c4b3a29180716f5e4d3c2b1a09f8e7d6c5b4a39281706fedcba9876543210ff",
          "03e5b60e0408349287ecff861e95f28e57211c0779d51cbea74e04c356b64e5b" },
    };

    for (size_t i = 0; i < sizeof(vec) / sizeof(vec[0]); i++)
    {
        const uint256 hashBlock(std::string(vec[i].pszBlock));
        const uint256 aux(std::string(vec[i].pszAux));
        BOOST_CHECK_MESSAGE(
            CollateralnodeScoreMix(hashBlock, aux).ToString() == std::string(vec[i].pszScore),
            "vector " << i << ": expected " << vec[i].pszScore << ", got "
                      << CollateralnodeScoreMix(hashBlock, aux).ToString());
    }

    // The two operands enter the hashed range in a fixed order, so they are not
    // interchangeable; a mix that concatenated them the other way round would
    // still be well defined but would move every score on the live network.
    const uint256 hashBlock(std::string(vec[2].pszBlock));
    const uint256 aux(std::string(vec[2].pszAux));
    BOOST_CHECK_MESSAGE(CollateralnodeScoreMix(aux, hashBlock) != CollateralnodeScoreMix(hashBlock, aux),
                        "the block hash and the outpoint term are hashed in a "
                        "fixed order; swapping them must not answer the same");
}

// What the undefined range cost in practice: a build that dropped the outpoint
// from it scored every candidate off the block hash alone, so the election
// returned the first enabled entry whatever the block and was not a lottery.
BOOST_AUTO_TEST_CASE(the_payee_score_varies_with_the_candidate)
{
    CollateralnodeViewGuard guard;

    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_REQUIRE_MESSAGE(!IsInitialBlockDownload(),
                          "CalculateScore is not reached during initial download");
    BOOST_REQUIRE(EnsureChainHeight(4));
    const int64_t nBlockHeight = pindexBest->nHeight;

    const int nCandidates = 32;
    std::vector<uint256> vScores;
    for (int i = 0; i < nCandidates; i++)
    {
        CCollateralNode mn = MakeNode(CountedHash(i), 0, PROTOCOL_VERSION);
        vScores.push_back(mn.CalculateScore(1, nBlockHeight));
    }

    // Positive control: an unanswerable height scores every candidate zero.
    BOOST_REQUIRE_MESSAGE(vScores[0] != uint256(0),
                          "the block-hash lookup did not answer at height "
                          << nBlockHeight << ", so every score is zero and the "
                          "distinctness below would prove nothing");

    std::set<uint256> setDistinct(vScores.begin(), vScores.end());
    BOOST_CHECK_MESSAGE(setDistinct.size() == (size_t)nCandidates,
                        "candidates differing only in their outpoint must score "
                        "differently; got " << setDistinct.size()
                        << " distinct scores across " << nCandidates
                        << " candidates");
}

// From FORK_HEIGHT_COLD_STAKING the payee election compares full 256-bit
// scores; below it, the low 32 bits. The case requires a pair the two widths order
// differently, then moves only the height.
BOOST_AUTO_TEST_CASE(the_payee_election_widens_from_the_cold_staking_gate)
{
    CollateralnodeViewGuard guard;
    ColdStakingGateGuard gateGuard;

    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_REQUIRE_MESSAGE(!IsInitialBlockDownload(),
                          "GetCurrentCollateralNode returns 0 during initial "
                          "download, which is indistinguishable from candidate 0 "
                          "winning");

    // GetBlockHash cannot answer the first heights, so score against the tip's height.
    BOOST_REQUIRE(EnsureChainHeight(4));
    const int64_t nBlockHeight = pindexBest->nHeight;
    BOOST_REQUIRE_MESSAGE(nBlockHeight > 1,
                          "the chain is too short for the score lookup to answer "
                          "at all, so every candidate would score zero");

    // Score enough candidates to find a discriminating pair.
    const int nCandidates = 96;
    std::vector<CCollateralNode> vAll;
    std::vector<uint256> vScores;
    for (int i = 0; i < nCandidates; i++)
    {
        CCollateralNode mn = MakeNode(CountedHash(i), 0, PROTOCOL_VERSION);
        vScores.push_back(mn.CalculateScore(1, nBlockHeight));
        vAll.push_back(mn);
    }

    // How much the score actually varies, reported whether or not a pair is
    // found: a degenerate election is a bigger finding than an untested gate.
    std::set<uint256> setDistinct;
    std::set<unsigned int> setDistinctLow;
    for (int i = 0; i < nCandidates; i++)
    {
        setDistinct.insert(vScores[i]);
        setDistinctLow.insert(LowWord(vScores[i]));
    }
    BOOST_TEST_MESSAGE("collateralnode scores at height " << nBlockHeight << ": "
                       << setDistinct.size() << " distinct of " << nCandidates
                       << " candidates, " << setDistinctLow.size()
                       << " distinct low words; first score "
                       << vScores[0].ToString());
    BOOST_REQUIRE_MESSAGE(setDistinct.size() > 1,
                          "every candidate scores the same, so the payee election "
                          "returns the first enabled entry whatever the block: "
                          "the width the gate selects cannot change the answer and "
                          "the election is not a lottery at all");

    int nFull = -1, nTrunc = -1;
    for (int a = 0; a < nCandidates && nFull < 0; a++)
        for (int b = 0; b < nCandidates; b++)
        {
            if (a == b)
                continue;
            if (vScores[a] > vScores[b] && LowWord(vScores[a]) < LowWord(vScores[b]))
            {
                nFull = a;
                nTrunc = b;
                break;
            }
        }
    BOOST_REQUIRE_MESSAGE(nFull >= 0,
                          "no candidate pair the two widths order differently was "
                          "found in " << nCandidates << " tries; either the "
                          "scores no longer vary with the candidate -- in which "
                          "case the election is degenerate and this rule is the "
                          "least of it -- or the search needs widening");

    // The list holds exactly the two, so the returned index names one of them.
    {
        LOCK(cs_collateralnodes);
        vecCollateralnodes.clear();
        vecCollateralnodes.push_back(vAll[nFull]);   // index 0
        vecCollateralnodes.push_back(vAll[nTrunc]);  // index 1
    }
    BOOST_REQUIRE_EQUAL(vecCollateralnodes.size(), 2u);

    // At or above the gate: the whole score decides, so the full-score maximum
    // wins.
    nRegtestColdStakingHeight = 0;
    BOOST_REQUIRE_MESSAGE(nBlockHeight >= FORK_HEIGHT_COLD_STAKING,
                          "the gate is above the scored height; the arm would be "
                          "the pre-gate one twice");
    const int nWide = GetCurrentCollateralNode(1, nBlockHeight, PROTOCOL_VERSION);
    BOOST_CHECK_MESSAGE(nWide == 0,
                        "at or above the gate the candidate with the greater "
                        "256-bit score must win; got index " << nWide);

    // Below it: only the low word is compared, and the other candidate wins.
    // Nothing about the candidates has changed.
    nRegtestColdStakingHeight = (int)nBlockHeight + 1;
    BOOST_REQUIRE(nBlockHeight < FORK_HEIGHT_COLD_STAKING);
    const int nNarrow = GetCurrentCollateralNode(1, nBlockHeight, PROTOCOL_VERSION);
    BOOST_CHECK_MESSAGE(nNarrow == 1,
                        "below the gate the truncated comparison must pick the "
                        "other candidate; got index " << nNarrow);
    BOOST_CHECK_MESSAGE(nWide != nNarrow,
                        "the gate changed nothing, so the two widths are not "
                        "distinguished at all");
}

// From FORK_HEIGHT_CN_PAYMENT_VALIDATION a collateralnode must advertise at
// least FORK_MIN_CN_PROTO_VERSION to be ranked. Control: same nodes before the drop.
BOOST_AUTO_TEST_CASE(the_ranking_excludes_a_collateralnode_below_the_protocol_floor)
{
    CollateralnodeViewGuard guard;

    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_REQUIRE(EnsureChainHeight(4));
    BOOST_REQUIRE_MESSAGE(pindexBest->pprev != NULL,
                          "GetCollateralnodeRanks returns early on a chain with "
                          "only a genesis block");
    BOOST_REQUIRE(!IsInitialBlockDownload());
    BOOST_REQUIRE_MESSAGE(pindexBest->nHeight >= FORK_HEIGHT_CN_PAYMENT_VALIDATION,
                          "the tip is below the gate, so the floor under test is "
                          "not the one the ranking would apply");
    BOOST_REQUIRE_MESSAGE(PROTOCOL_VERSION >= FORK_MIN_CN_PROTO_VERSION,
                          "this build's own protocol version is below the floor "
                          "it enforces; the control node would be dropped too");

    const uint256 hashA = CountedHash(1001);
    const uint256 hashB = CountedHash(1002);

    // Control: both advertise a version the floor admits, and both rank.
    {
        LOCK(cs_collateralnodes);
        vecCollateralnodes.clear();
        vecCollateralnodes.push_back(MakeNode(hashA, 0, PROTOCOL_VERSION));
        vecCollateralnodes.push_back(MakeNode(hashB, 0, PROTOCOL_VERSION));
    }
    guard.DropRankCache();
    BOOST_REQUIRE(GetCollateralnodeRanks(pindexBest));
    BOOST_CHECK_MESSAGE(vecCollateralnodeScores.size() == 2,
                        "two admissible collateralnodes must both rank; got "
                        << vecCollateralnodeScores.size());

    // Same two vins, same block, one version below the floor.
    {
        LOCK(cs_collateralnodes);
        vecCollateralnodes.clear();
        vecCollateralnodes.push_back(MakeNode(hashA, 0, PROTOCOL_VERSION));
        vecCollateralnodes.push_back(MakeNode(hashB, 0,
                                              FORK_MIN_CN_PROTO_VERSION - 1));
    }
    guard.DropRankCache();
    BOOST_REQUIRE(GetCollateralnodeRanks(pindexBest));
    BOOST_REQUIRE_MESSAGE(vecCollateralnodeScores.size() == 1,
                          "exactly one collateralnode must rank; got "
                          << vecCollateralnodeScores.size());
    BOOST_CHECK_MESSAGE(vecCollateralnodeScores[0].second->vin.prevout.hash == hashA,
                        "the ranked collateralnode is not the one that met the "
                        "protocol floor");
    BOOST_CHECK_MESSAGE(
        vecCollateralnodeScores[0].second->protocolVersion >= FORK_MIN_CN_PROTO_VERSION,
        "a collateralnode below FORK_MIN_CN_PROTO_VERSION entered the ranking");
}

// From FORK_HEIGHT_CN_PAYMENT_VALIDATION a collateralnode with more than 100
// payments is excluded from the average-income mean. Regtest gate is 1: heights 0 and 1
// give the two answers.
BOOST_AUTO_TEST_CASE(the_income_average_excludes_an_over_paid_collateralnode)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE_EQUAL(FORK_HEIGHT_CN_PAYMENT_VALIDATION, 1);

    std::vector<CCollateralNode> v;
    v.push_back(MakeNode(CountedHash(2001), 0, PROTOCOL_VERSION));
    v.push_back(MakeNode(CountedHash(2002), 0, PROTOCOL_VERSION));
    v.push_back(MakeNode(CountedHash(2003), 0, PROTOCOL_VERSION));
    v.push_back(MakeNode(CountedHash(2004), 0, PROTOCOL_VERSION));
    v[0].payCount = 2;
    v[1].payCount = 4;
    v[2].payCount = 200;   // above the exclusion threshold
    v[3].payCount = 0;     // never paid, excluded at every height

    // Below the gate the over-paid node is counted, so it drags the mean up.
    const int64_t nBelow = avgCount(v, 0);
    // At the gate it is dropped, and the mean is the two admissible counts.
    const int64_t nAt = avgCount(v, 1);

    BOOST_CHECK_MESSAGE(nBelow > nAt,
                        "the over-paid node did not move the pre-gate mean, so "
                        "the arm cannot show it being excluded (below=" << nBelow
                        << " at=" << nAt << ")");
    BOOST_CHECK_MESSAGE(nAt == 3,
                        "the mean over payment counts 2 and 4 is 3; got " << nAt);

    // The threshold itself: exactly 100 is admitted, 101 is not.
    std::vector<CCollateralNode> vEdge;
    vEdge.push_back(MakeNode(CountedHash(2101), 0, PROTOCOL_VERSION));
    vEdge[0].payCount = 100;
    BOOST_CHECK_MESSAGE(avgCount(vEdge, 1) == 100,
                        "a collateralnode with exactly 100 payments must still "
                        "count; got " << avgCount(vEdge, 1));
    vEdge[0].payCount = 101;
    BOOST_CHECK_MESSAGE(avgCount(vEdge, 1) == 0,
                        "a collateralnode with 101 payments must be excluded, "
                        "leaving no sample; got " << avgCount(vEdge, 1));
    BOOST_CHECK_MESSAGE(avgCount(vEdge, 0) == 101,
                        "below the gate 101 payments must still count; got "
                        << avgCount(vEdge, 0));
}

BOOST_AUTO_TEST_SUITE_END()
