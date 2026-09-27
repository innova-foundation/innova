// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Settlement payout clamp (R-RSV-004); the headroom is read from the block's parent.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../finality.h"
#include "../key.h"
#include "../main.h"
#include "../miner.h"
#include "../subsidy.h"
#include "../txdb.h"
#include "../wallet.h"

extern CWallet* pwalletMain;

BOOST_AUTO_TEST_SUITE(settlement_headroom_clamp_tests)

namespace {

// The cap is MAX_MONEY everywhere except regtest, where these two knobs lower
// it far enough for a fixture to sit on the boundary.
struct SupplyCapGuard
{
    int nHeightSaved;
    int64_t nAmountSaved;
    SupplyCapGuard(int nHeight, int64_t nAmount)
        : nHeightSaved(nRegtestSupplyCapHeight), nAmountSaved(nRegtestSupplyCapAmount)
    {
        nRegtestSupplyCapHeight = nHeight;
        nRegtestSupplyCapAmount = nAmount;
    }
    ~SupplyCapGuard()
    {
        nRegtestSupplyCapHeight = nHeightSaved;
        nRegtestSupplyCapAmount = nAmountSaved;
    }
};

// A settlement epoch whose budget is non-zero. A zero budget makes every arm
// below vacuous: the clamp returns 0 before it ever reads the headroom.
bool FindFundedSettlementEpoch(int& nEpochOut, int& nSettlementHeightOut,
                               int64_t& nBudgetOut)
{
    const int nFirstEpoch = GetEpochForHeight(GetForkHeightDAG());
    for (int i = 0; i < 8; i++)
    {
        const int nEpoch = nFirstEpoch + i;
        const int64_t nBudget = GetFinalityEpochBudget(nEpoch);
        if (nBudget <= 0)
            continue;
        const int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
        nEpochOut = nEpoch;
        nSettlementHeightOut = GetFinalitySettlementHeight(nEpoch, nBoundary);
        nBudgetOut = nBudget;
        return true;
    }
    return false;
}

// A bare index carrying only what the clamp reads: its height and the money
// supply folded over its ancestors.
CBlockIndex MakeIndex(int nHeight, int64_t nMoneySupply)
{
    CBlockIndex index;
    index.nHeight = nHeight;
    index.nMoneySupply = nMoneySupply;
    return index;
}

} // namespace

// Headroom above the budget pays the budget; headroom below it pays the
// headroom; no headroom pays nothing.
BOOST_AUTO_TEST_CASE(the_settlement_budget_is_clamped_to_the_issuance_headroom)
{
    BOOST_REQUIRE(fRegTest);

    int nEpoch = 0, nSettlementHeight = 0;
    int64_t nBudget = 0;
    BOOST_REQUIRE_MESSAGE(FindFundedSettlementEpoch(nEpoch, nSettlementHeight, nBudget),
                          "no post-DAG epoch in the first eight carries a non-zero "
                          "finality budget, so the clamp has nothing to clamp");
    BOOST_TEST_MESSAGE("settlement epoch " << nEpoch << " at height " << nSettlementHeight
                       << " with budget " << nBudget);

    const int64_t nCap = nBudget * 1000;
    SupplyCapGuard capGuard(0, nCap);
    BOOST_REQUIRE_EQUAL(GetSupplyCapAmount(), nCap);
    BOOST_REQUIRE(IsSupplyCapActiveAtHeight(nSettlementHeight));

    // Room to spare: the whole budget is payable.
    CBlockIndex idxRoomy = MakeIndex(nSettlementHeight - 1, 0);
    BOOST_CHECK_EQUAL(GetClampedFinalitySettlementBudget(&idxRoomy, nEpoch, 0), nBudget);

    // Less headroom than budget: the headroom is the answer, and the block's own
    // subsidy then has nothing left to take, which is what keeps the total inside
    // the cap.
    const int64_t nTight = nBudget / 3;
    BOOST_REQUIRE(nTight > 0);
    CBlockIndex idxTight = MakeIndex(nSettlementHeight - 1, nCap - nTight);
    BOOST_CHECK_EQUAL(GetClampedFinalitySettlementBudget(&idxTight, nEpoch, 0), nTight);

    // At the cap: nothing is payable and nothing is minted.
    CBlockIndex idxFull = MakeIndex(nSettlementHeight - 1, nCap);
    BOOST_CHECK_EQUAL(GetClampedFinalitySettlementBudget(&idxFull, nEpoch, 0), 0);

    // Past the cap, which a historical chain can be after the cap is lowered.
    CBlockIndex idxOver = MakeIndex(nSettlementHeight - 1, nCap + nBudget);
    BOOST_CHECK_EQUAL(GetClampedFinalitySettlementBudget(&idxOver, nEpoch, 0), 0);
}

// The clamp is not inert: the amount it returns is what each counted voter is
// paid, so clamping the budget clamps the settlement outputs the block must
// carry exactly.
BOOST_AUTO_TEST_CASE(the_clamped_budget_is_what_the_settlement_outputs_pay)
{
    BOOST_REQUIRE(fRegTest);

    int nEpoch = 0, nSettlementHeight = 0;
    int64_t nBudget = 0;
    BOOST_REQUIRE(FindFundedSettlementEpoch(nEpoch, nSettlementHeight, nBudget));

    const int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
    std::vector<CFinalityVote> vVotes;
    for (int i = 0; i < 2; i++)
    {
        CKey key;
        key.MakeNewKey(true);
        CPubKey pubkey = key.GetPubKey();

        CFinalityVote vote;
        vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
        vote.nEpoch = nEpoch;
        vote.nHeight = nBoundary;
        vote.nVoteWeight = 100000 * COIN;
        vote.nReward = GetFinalityVoteRewardAtHeight(vote.nVoteWeight, nBoundary);
        vote.vchPubKey = std::vector<unsigned char>(pubkey.begin(), pubkey.end());
        CHashWriter nf(SER_GETHASH, 0);
        nf << vote.vchPubKey;
        nf << nEpoch;
        vote.nullifier = nf.GetHash();
        BOOST_REQUIRE_MESSAGE(vote.nReward > 0,
                              "a zero-entitlement voter is not a payee, so the split "
                              "below would have nothing to divide");
        vVotes.push_back(vote);
    }

    const int64_t nCap = nBudget * 1000;
    SupplyCapGuard capGuard(0, nCap);

    CBlockIndex idxRoomy = MakeIndex(nSettlementHeight - 1, 0);
    const int64_t nTight = nBudget / 3;
    BOOST_REQUIRE(nTight > 0);
    CBlockIndex idxTight = MakeIndex(nSettlementHeight - 1, nCap - nTight);

    std::vector<CTxOut> vRoomy, vTight;
    int64_t nRoomyTotal = 0, nTightTotal = 0;
    std::string strError;
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(
        vVotes, GetClampedFinalitySettlementBudget(&idxRoomy, nEpoch, 0),
        vRoomy, nRoomyTotal, &strError));
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(
        vVotes, GetClampedFinalitySettlementBudget(&idxTight, nEpoch, 0),
        vTight, nTightTotal, &strError));

    BOOST_CHECK_EQUAL(vRoomy.size(), vVotes.size());
    BOOST_CHECK_EQUAL(nRoomyTotal, (nBudget / 2) * 2);
    BOOST_CHECK_EQUAL(nTightTotal, (nTight / 2) * 2);
    BOOST_CHECK_MESSAGE(nTightTotal < nRoomyTotal,
                        "the clamped budget paid the same as the unclamped one ("
                        << nTightTotal << "), so the clamp moved no money and the "
                        "arms above cannot see it");
}

// Which index the headroom is read from. The parent and the settlement block
// itself carry different money supplies, so the two answers differ: this is the
// assertion a caller that read the block's own index would fail.
BOOST_AUTO_TEST_CASE(the_headroom_is_read_from_the_settlement_block_parent)
{
    BOOST_REQUIRE(fRegTest);

    int nEpoch = 0, nSettlementHeight = 0;
    int64_t nBudget = 0;
    BOOST_REQUIRE(FindFundedSettlementEpoch(nEpoch, nSettlementHeight, nBudget));

    const int64_t nCap = nBudget * 1000;
    SupplyCapGuard capGuard(0, nCap);

    // The parent is near the cap; the settlement block's own index carries the
    // supply a block still being connected carries, which is not yet its own.
    const int64_t nTight = nBudget / 4;
    BOOST_REQUIRE(nTight > 0);
    CBlockIndex idxParent = MakeIndex(nSettlementHeight - 1, nCap - nTight);
    CBlockIndex idxSelf = MakeIndex(nSettlementHeight, 0);

    const int64_t nFromParent = GetClampedFinalitySettlementBudget(&idxParent, nEpoch, 0);
    const int64_t nFromSelf = GetClampedFinalitySettlementBudget(&idxSelf, nEpoch, 0);

    BOOST_CHECK_EQUAL(nFromParent, nTight);
    BOOST_CHECK_EQUAL(nFromSelf, nBudget);
    BOOST_CHECK_MESSAGE(nFromParent != nFromSelf,
                        "the parent and the settlement block answer the same, so this "
                        "case cannot tell which index the clamp reads");
}

namespace {

// The connect case mines real blocks. A registered wallet would record their coinbases,
// moving the ordering counters other suites pin.
struct DetachedWalletGuard
{
    DetachedWalletGuard() { UnregisterWallet(pwalletMain); }
    ~DetachedWalletGuard() { RegisterWallet(pwalletMain); }
};

CBlockIndex* BestIndex()
{
    LOCK(cs_main);
    return pindexBest;
}

CBlockIndex* IndexOf(const uint256& hash)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::const_iterator mi = mapBlockIndex.find(hash);
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

bool GrindHeader(CBlock* pblock)
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

bool MineOne(CBlock& blockOut)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexParent = IndexOf(pblock->hashPrevBlock);
    if (pindexParent == NULL)
        return false;
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexParent, nExtraNonce);
    if (!GrindHeader(pblock.get()))
        return false;
    if (!ProcessBlock(NULL, pblock.get()))
        return false;
    blockOut = *pblock;
    return true;
}

void MineTo(int nTarget)
{
    while (BestIndex()->nHeight < nTarget)
    {
        CBlock block;
        BOOST_REQUIRE_MESSAGE(MineOne(block), "could not extend the chain to " << nTarget);
    }
}

// A transparent vote for the epoch whose boundary is pEpochBlock, staking the unspent
// wallet-owned coinbase outputs at or below the boundary, as ProduceFinalityVote builds it.
bool BuildWalletVote(const CBlockIndex* pEpochBlock, int nEpoch, bool fCanonical,
                     CFinalityVote& voteOut)
{
    CTxDB txdb("r");
    CKey key;
    CKeyID keyVoter;
    bool fHaveKey = false;
    int64_t nWeight = 0;
    std::vector<COutPoint> vProof;
    for (const CBlockIndex* pindex = pEpochBlock;
         pindex && vProof.size() < (size_t)FINALITY_MAX_STAKE_PROOFS; pindex = pindex->pprev)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex, true) || block.vtx.empty())
            continue;
        const CTransaction& coinbase = block.vtx[0];
        for (unsigned int n = 0; n < coinbase.vout.size(); n++)
        {
            const CTxOut& out = coinbase.vout[n];
            CKeyID keyID;
            if (out.nValue <= 0 || !ExtractFinalityStakeKeyID(out.scriptPubKey, keyID))
                continue;
            if (fHaveKey ? !(keyID == keyVoter) : !pwalletMain->GetKey(keyID, key))
                continue;
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(coinbase.GetHash(), txindex) ||
                n >= txindex.vSpent.size() || !txindex.vSpent[n].IsNull())
                continue;
            fHaveKey = true;
            keyVoter = keyID;
            vProof.push_back(COutPoint(coinbase.GetHash(), n));
            nWeight += out.nValue;
            if (vProof.size() >= (size_t)FINALITY_MAX_STAKE_PROOFS)
                break;
        }
    }
    if (!fHaveKey || vProof.empty())
        return false;

    CHashWriter nullifierHash(SER_GETHASH, 0);
    const CPubKey pubkey = key.GetPubKey();
    nullifierHash << std::vector<unsigned char>(pubkey.begin(), pubkey.end());
    nullifierHash << nEpoch;

    CFinalityVote vote;
    vote.nEpoch = nEpoch;
    vote.hashBlock = pEpochBlock->GetBlockHash();
    vote.nHeight = pEpochBlock->nHeight;
    vote.nTime = GetAdjustedTime();
    vote.nVoteWeight = nWeight;
    vote.nReward = GetFinalityVoteRewardAtHeight(nWeight, pEpochBlock->nHeight);
    vote.nullifier = nullifierHash.GetHash();
    vote.vStakeProof = vProof;
    if (fCanonical)
        vote.MarkCanonicalEnvelope();
    if (!vote.Sign(key))
        return false;
    voteOut = vote;
    return true;
}

} // namespace

// ConnectBlock must read the settlement headroom from the parent, as the producer does,
// or the exact-match settlement check refuses the block.
BOOST_AUTO_TEST_CASE(connect_reads_the_settlement_headroom_from_the_parent)
{
    BOOST_REQUIRE(fRegTest);
    DetachedWalletGuard wallet;

    MineTo(GetForkHeightDAG() + 2);
    int nEpoch = GetEpochForHeight(BestIndex()->nHeight) + 1;
    int nBoundary = 0;
    for (;; nEpoch++)
    {
        nBoundary = GetEpochBoundaryHeight(nEpoch, BestIndex()->nHeight);
        const int nSettle = GetFinalitySettlementHeight(nEpoch, nBoundary);
        if (GetFinalityEpochBudget(nEpoch) > 0 &&
            IsBoundaryAActiveAtHeight(nBoundary) == IsBoundaryAActiveAtHeight(nSettle))
            break;
        BOOST_REQUIRE(nEpoch < GetEpochForHeight(BestIndex()->nHeight) + 16);
    }
    const int nSettlementHeight = GetFinalitySettlementHeight(nEpoch, nBoundary);
    BOOST_REQUIRE_EQUAL(nSettlementHeight, nBoundary + FINALITY_VOTE_INCLUSION_WINDOW);

    MineTo(nBoundary);
    const CBlockIndex* pEpochBlock = BestIndex();
    BOOST_REQUIRE_EQUAL(pEpochBlock->nHeight, nBoundary);
    BOOST_REQUIRE(pEpochBlock->IsProofOfWork());

    CFinalityVote vote;
    BOOST_REQUIRE(BuildWalletVote(pEpochBlock, nEpoch,
                                  IsBoundaryAActiveAtHeight(nBoundary + 1), vote));
    BOOST_REQUIRE_MESSAGE(g_finalityTracker.AddVote(vote), "the wallet vote was refused");

    // The window: the vote is carried in one of these.
    MineTo(nSettlementHeight - 1);
    std::vector<CFinalityVote> vSettlementVotes;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(GatherFinalitySettlementVotes(BestIndex(), nEpoch, vSettlementVotes,
                                                        &strError, NULL),
                          strError);
    BOOST_REQUIRE_EQUAL(vSettlementVotes.size(), 1U);

    // The parent sits half an epoch budget under the cap.
    const CBlockIndex* pParent = BestIndex();
    const int64_t nBudget = GetFinalityEpochBudget(nEpoch);
    const int64_t nHeadroom = nBudget / 2;
    BOOST_REQUIRE(nHeadroom > 0);
    {
        SupplyCapGuard capGuard(0, pParent->nMoneySupply + nHeadroom);
        BOOST_REQUIRE_EQUAL(GetClampedFinalitySettlementBudget(pParent, nEpoch, 0), nHeadroom);

        CBlock settlement;
        BOOST_REQUIRE_MESSAGE(MineOne(settlement),
                              "the settlement block the producer built from the parent's "
                              "headroom was refused at connect");
        BOOST_CHECK_EQUAL(BestIndex()->nHeight, nSettlementHeight);
        BOOST_CHECK(BestIndex()->nMoneySupply <= pParent->nMoneySupply + nHeadroom);
    }

    // Later suites on this chain take the epochs within FINALITY_CONFIRMATION_EPOCHS of
    // their tip to hold no votes; move the tip past the voted epoch's reach.
    const int nClearEpoch = nEpoch + FINALITY_CONFIRMATION_EPOCHS + 2;
    MineTo(GetEpochBoundaryHeight(nClearEpoch, BestIndex()->nHeight) +
           FINALITY_VOTE_INCLUSION_WINDOW);
}

BOOST_AUTO_TEST_SUITE_END()
