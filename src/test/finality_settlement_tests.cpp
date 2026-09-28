// Per-epoch finality-reward settlement: votes are paid once, at H_E +
// FINALITY_VOTE_INCLUSION_WINDOW, from the window's frozen vote set.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../bignum.h"
#include "../finality.h"
#include "../subsidy.h"
#include "../key.h"

#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace {

const int64_t VOTE_WEIGHT = 100000 * COIN;

struct Voter
{
    CKey key;
    CFinalityVote vote;
};

// A structurally valid transparent vote for nEpoch. Mirrors the consensus binding
// CFinalityTracker::CheckVote enforces: nullifier == H(pubkey || epoch) and
// nReward == GetFinalityVoteReward(nVoteWeight, epoch interval).
Voter MakeVoter(int nEpoch, int nHeightBoundary, int64_t nWeight = VOTE_WEIGHT)
{
    Voter v;
    v.key.MakeNewKey(true);
    CPubKey pubkey = v.key.GetPubKey();

    v.vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    v.vote.nEpoch = nEpoch;
    v.vote.nHeight = nHeightBoundary;
    v.vote.nVoteWeight = nWeight;
    v.vote.nReward = GetFinalityVoteRewardAtHeight(nWeight, nHeightBoundary);
    v.vote.vchPubKey = std::vector<unsigned char>(pubkey.begin(), pubkey.end());

    CHashWriter nf(SER_GETHASH, 0);
    nf << v.vote.vchPubKey;
    nf << nEpoch;
    v.vote.nullifier = nf.GetHash();
    return v;
}

CScript PayeeScript(const CFinalityVote& vote)
{
    CPubKey pubkey(vote.vchPubKey);
    return GetScriptForDestination(pubkey.GetID());
}

// A settlement-block coinbase: the block subsidy plus the settlement leg.
CBlock MakeSettlementBlock(int64_t nSubsidy, const CScript& scriptMiner,
                           const std::vector<CTxOut>& vSettlement)
{
    CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.push_back(CTxOut(nSubsidy, scriptMiner));
    for (const CTxOut& out : vSettlement)
        coinbase.vout.push_back(out);

    CBlock block;
    block.vtx.push_back(coinbase);
    return block;
}

int PostDAGEpoch(int nOffsetEpochs)
{
    return GetEpochForHeight(GetForkHeightDAG()) + nOffsetEpochs;
}

// A fixed epoch budget for the settlement leg. Divisible by every voter count
// used below so the equal split is exact and the assertions stay arithmetic.
static const int64_t TEST_EPOCH_BUDGET = 12 * COIN;
static int64_t PerVoter(size_t nVoters)
{
    return nVoters ? TEST_EPOCH_BUDGET / (int64_t)nVoters : 0;
}

} // namespace

BOOST_AUTO_TEST_SUITE(finality_settlement_tests)

// Exactly one settlement height per epoch, and it is none of the K carrier heights.
BOOST_AUTO_TEST_CASE(settlement_height_is_unique_per_epoch)
{
    for (int nOffset = 0; nOffset < 4; nOffset++)
    {
        int nEpoch = PostDAGEpoch(nOffset);
        int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
        int nSettlement = GetFinalitySettlementHeight(nEpoch, nBoundary);

        BOOST_CHECK_EQUAL(nSettlement, nBoundary + FINALITY_VOTE_INCLUSION_WINDOW);

        int nEpochInterval = GetEpochInterval(nBoundary);
        int nFound = 0;
        for (int h = nBoundary; h < nBoundary + nEpochInterval; h++)
        {
            int nSettledEpoch = -1;
            bool fSettles = IsFinalitySettlementHeight(h, &nSettledEpoch);
            if (fSettles)
            {
                nFound++;
                BOOST_CHECK_EQUAL(h, nSettlement);
                BOOST_CHECK_EQUAL(nSettledEpoch, nEpoch);
            }
            // Every height that can carry an epoch-E vote must NOT be a payout height.
            if (h < nBoundary + FINALITY_VOTE_INCLUSION_WINDOW)
                BOOST_CHECK(!fSettles);
        }
        BOOST_CHECK_EQUAL(nFound, 1);
    }
}

// The settlement height is inside its own epoch (so it is a real canonical block of
// that epoch) and coincides with the height at which a tally certificate for the
// epoch becomes block-valid -- the point at which the vote set is frozen.
BOOST_AUTO_TEST_CASE(settlement_height_is_inside_the_epoch_at_the_freeze_point)
{
    int nEpoch = PostDAGEpoch(2);
    int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
    int nSettlement = GetFinalitySettlementHeight(nEpoch, nBoundary);

    BOOST_CHECK(FINALITY_VOTE_INCLUSION_WINDOW < GetEpochInterval(nBoundary));
    BOOST_CHECK_EQUAL(GetEpochForHeight(nSettlement), nEpoch);
    // R2 (CheckTallyCertificate): a cert for E is valid only at >= H_E + K.
    BOOST_CHECK_EQUAL(nSettlement, nBoundary + FINALITY_VOTE_INCLUSION_WINDOW);
    // Pre-DAG heights have no finality reward at all.
    BOOST_CHECK(!IsFinalitySettlementHeight(GetForkHeightDAG() - 1));
}

// End-to-end over the pure settlement path: three voters, each carried by one window
// block, are paid once each and the settled total is the sum of their bound rewards.
BOOST_AUTO_TEST_CASE(settlement_pays_each_counted_vote_once)
{
    int nEpoch = PostDAGEpoch(1);
    int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());

    Voter a = MakeVoter(nEpoch, nBoundary);
    Voter b = MakeVoter(nEpoch, nBoundary, VOTE_WEIGHT * 2);
    Voter c = MakeVoter(nEpoch, nBoundary, VOTE_WEIGHT * 3);
    BOOST_REQUIRE(a.vote.nReward > 0 && b.vote.nReward > 0 && c.vote.nReward > 0);

    std::vector<std::vector<CFinalityVote> > vWindow(FINALITY_VOTE_INCLUSION_WINDOW);
    vWindow[0].push_back(a.vote);
    vWindow[7].push_back(b.vote);
    vWindow[FINALITY_VOTE_INCLUSION_WINDOW - 1].push_back(c.vote);

    std::vector<CFinalityVote> vCounted;
    CollectFinalitySettlementVotes(vWindow, nEpoch, vCounted);
    BOOST_CHECK_EQUAL(vCounted.size(), 3u);

    std::vector<CTxOut> vSettlement;
    int64_t nTotal = 0;
    std::string strError;
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, TEST_EPOCH_BUDGET, vSettlement, nTotal, &strError));
    BOOST_CHECK_EQUAL(vSettlement.size(), 3u);
    BOOST_CHECK_EQUAL(nTotal, TEST_EPOCH_BUDGET);

    // One output per voter, at that voter's own bound reward.
    for (const Voter* p : { &a, &b, &c })
    {
        int nHits = 0;
        for (const CTxOut& out : vSettlement)
        {
            if (out.scriptPubKey == PayeeScript(p->vote))
            {
                nHits++;
                BOOST_CHECK_EQUAL(out.nValue, PerVoter(3));
            }
        }
        BOOST_CHECK_EQUAL(nHits, 1);
    }

    CKey minerKey;
    minerKey.MakeNewKey(true);
    CScript scriptMiner = GetScriptForDestination(minerKey.GetPubKey().GetID());
    CBlock block = MakeSettlementBlock(5 * COIN, scriptMiner, vSettlement);

    int64_t nChecked = -1;
    BOOST_CHECK(CheckFinalitySettlementOutputs(block, vCounted, TEST_EPOCH_BUDGET, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, nTotal);
    // The extra coinbase allowance is exactly the settled total: coinbase value out
    // minus the subsidy leaves nothing unaccounted for.
    BOOST_CHECK_EQUAL(block.vtx[0].GetValueOut() - nChecked, 5 * COIN);
}

// A vote re-carried in all K window blocks is paid exactly once and does not grow the
// coinbase allowance.
BOOST_AUTO_TEST_CASE(settlement_pays_a_recarried_vote_exactly_once)
{
    int nEpoch = PostDAGEpoch(1);
    int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());

    Voter attacker = MakeVoter(nEpoch, nBoundary);
    Voter honest = MakeVoter(nEpoch, nBoundary, VOTE_WEIGHT * 2);
    BOOST_REQUIRE(attacker.vote.nReward > 0 && honest.vote.nReward > 0);

    // The identical vote in every one of the K canonical window blocks.
    std::vector<std::vector<CFinalityVote> > vWindow(FINALITY_VOTE_INCLUSION_WINDOW);
    for (int i = 0; i < FINALITY_VOTE_INCLUSION_WINDOW; i++)
        vWindow[i].push_back(attacker.vote);
    vWindow[3].push_back(honest.vote);

    std::vector<CFinalityVote> vCounted;
    CollectFinalitySettlementVotes(vWindow, nEpoch, vCounted);
    BOOST_CHECK_EQUAL(vCounted.size(), 2u);

    std::vector<CTxOut> vSettlement;
    int64_t nTotal = 0;
    std::string strError;
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, TEST_EPOCH_BUDGET, vSettlement, nTotal, &strError));

    BOOST_CHECK_EQUAL(vSettlement.size(), 2u);
    BOOST_CHECK_EQUAL(nTotal, TEST_EPOCH_BUDGET);

    // Under a fixed budget the re-carry cannot inflate the mint at all: the total
    // is the budget regardless of how many window blocks embedded the vote, and the
    // attacker's own share is diluted by the honest voter rather than multiplied.
    BOOST_CHECK_EQUAL(nTotal, TEST_EPOCH_BUDGET);
    for (const CTxOut& out : vSettlement)
        BOOST_CHECK_EQUAL(out.nValue, PerVoter(2));

    int nAttackerOutputs = 0;
    for (const CTxOut& out : vSettlement)
    {
        if (out.scriptPubKey == PayeeScript(attacker.vote))
            nAttackerOutputs++;
    }
    BOOST_CHECK_EQUAL(nAttackerOutputs, 1);

    // A settlement block that pays the re-carried voter K times does not get a bigger
    // allowance for it: the allowance stays at the settled total, so the surplus is
    // value the block cannot cover and ConnectBlock's coinbase check rejects it.
    CKey minerKey;
    minerKey.MakeNewKey(true);
    CScript scriptMiner = GetScriptForDestination(minerKey.GetPubKey().GetID());
    std::vector<CTxOut> vGreedy = vSettlement;
    for (int i = 1; i < FINALITY_VOTE_INCLUSION_WINDOW; i++)
        vGreedy.push_back(CTxOut(PerVoter(2), PayeeScript(attacker.vote)));

    const int64_t nSubsidy = 5 * COIN;
    CBlock greedyBlock = MakeSettlementBlock(nSubsidy, scriptMiner, vGreedy);
    int64_t nAllowedExtra = -1;
    BOOST_REQUIRE(CheckFinalitySettlementOutputs(greedyBlock, vCounted, TEST_EPOCH_BUDGET, nAllowedExtra, &strError));
    BOOST_CHECK_EQUAL(nAllowedExtra, nTotal);
    // ConnectBlock: vtx[0].GetValueOut() > nReward + nFinalityRewardOut  =>  rejected.
    BOOST_CHECK(greedyBlock.vtx[0].GetValueOut() > nSubsidy + nAllowedExtra);
}

// A settlement block must actually carry the whole leg. Dropping a payee, short-paying
// one, or omitting the leg entirely is rejected.
BOOST_AUTO_TEST_CASE(settlement_rejects_missing_or_short_payout)
{
    int nEpoch = PostDAGEpoch(1);
    int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());

    Voter a = MakeVoter(nEpoch, nBoundary);
    Voter b = MakeVoter(nEpoch, nBoundary, VOTE_WEIGHT * 2);

    std::vector<std::vector<CFinalityVote> > vWindow(FINALITY_VOTE_INCLUSION_WINDOW);
    vWindow[0].push_back(a.vote);
    vWindow[1].push_back(b.vote);

    std::vector<CFinalityVote> vCounted;
    CollectFinalitySettlementVotes(vWindow, nEpoch, vCounted);

    std::vector<CTxOut> vSettlement;
    int64_t nTotal = 0;
    std::string strError;
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, TEST_EPOCH_BUDGET, vSettlement, nTotal, &strError));
    BOOST_REQUIRE_EQUAL(vSettlement.size(), 2u);

    CKey minerKey;
    minerKey.MakeNewKey(true);
    CScript scriptMiner = GetScriptForDestination(minerKey.GetPubKey().GetID());
    int64_t nChecked = -1;

    // Whole leg omitted.
    CBlock empty = MakeSettlementBlock(5 * COIN, scriptMiner, std::vector<CTxOut>());
    BOOST_CHECK(!CheckFinalitySettlementOutputs(empty, vCounted, TEST_EPOCH_BUDGET, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, 0);

    // One payee dropped.
    std::vector<CTxOut> vShortSet(vSettlement.begin(), vSettlement.begin() + 1);
    CBlock dropped = MakeSettlementBlock(5 * COIN, scriptMiner, vShortSet);
    BOOST_CHECK(!CheckFinalitySettlementOutputs(dropped, vCounted, TEST_EPOCH_BUDGET, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, 0);

    // One payee short-paid by a single innovai.
    std::vector<CTxOut> vShortPay = vSettlement;
    vShortPay[0].nValue -= 1;
    CBlock shortPaid = MakeSettlementBlock(5 * COIN, scriptMiner, vShortPay);
    BOOST_CHECK(!CheckFinalitySettlementOutputs(shortPaid, vCounted, TEST_EPOCH_BUDGET, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, 0);

    // Redirected to the miner instead of the voter.
    std::vector<CTxOut> vRedirected = vSettlement;
    vRedirected[1].scriptPubKey = scriptMiner;
    CBlock redirected = MakeSettlementBlock(5 * COIN, scriptMiner, vRedirected);
    BOOST_CHECK(!CheckFinalitySettlementOutputs(redirected, vCounted, TEST_EPOCH_BUDGET, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, 0);

    // The correct leg is accepted in any output order.
    std::vector<CTxOut> vReordered(vSettlement.rbegin(), vSettlement.rend());
    CBlock reordered = MakeSettlementBlock(5 * COIN, scriptMiner, vReordered);
    BOOST_CHECK(CheckFinalitySettlementOutputs(reordered, vCounted, TEST_EPOCH_BUDGET, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, nTotal);
}

// Settlement is a pure function of the window ancestors: a sibling over the same window
// re-derives the same leg; a changed window re-derives from the new ancestors.
BOOST_AUTO_TEST_CASE(settlement_re_derives_across_a_reorg)
{
    int nEpoch = PostDAGEpoch(1);
    int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());

    Voter a = MakeVoter(nEpoch, nBoundary);
    Voter b = MakeVoter(nEpoch, nBoundary, VOTE_WEIGHT * 2);
    Voter c = MakeVoter(nEpoch, nBoundary, VOTE_WEIGHT * 3);

    // Branch A: a carried at window index 0, b at 2.
    std::vector<std::vector<CFinalityVote> > vWindowA(FINALITY_VOTE_INCLUSION_WINDOW);
    vWindowA[0].push_back(a.vote);
    vWindowA[2].push_back(b.vote);

    // Branch B: same epoch, a re-carried at a different index, b censored, c added.
    std::vector<std::vector<CFinalityVote> > vWindowB(FINALITY_VOTE_INCLUSION_WINDOW);
    vWindowB[5].push_back(a.vote);
    vWindowB[5].push_back(c.vote);
    vWindowB[9].push_back(a.vote);

    std::string strError;
    std::vector<CFinalityVote> vCountedA, vCountedB;
    std::vector<CTxOut> vLegA, vLegB;
    int64_t nTotalA = 0, nTotalB = 0;

    CollectFinalitySettlementVotes(vWindowA, nEpoch, vCountedA);
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCountedA, TEST_EPOCH_BUDGET, vLegA, nTotalA, &strError));
    CollectFinalitySettlementVotes(vWindowB, nEpoch, vCountedB);
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCountedB, TEST_EPOCH_BUDGET, vLegB, nTotalB, &strError));

    BOOST_CHECK_EQUAL(nTotalA, TEST_EPOCH_BUDGET);
    BOOST_CHECK_EQUAL(nTotalB, TEST_EPOCH_BUDGET);
    BOOST_CHECK_EQUAL(vLegA.size(), 2u);
    BOOST_CHECK_EQUAL(vLegB.size(), 2u);

    // Same-window re-derivation is byte-identical, so any block that becomes canonical
    // at the settlement height over branch A owes exactly branch A's leg.
    std::vector<CFinalityVote> vCountedARepeat;
    std::vector<CTxOut> vLegARepeat;
    int64_t nTotalARepeat = 0;
    CollectFinalitySettlementVotes(vWindowA, nEpoch, vCountedARepeat);
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCountedARepeat, TEST_EPOCH_BUDGET, vLegARepeat, nTotalARepeat, &strError));
    BOOST_CHECK_EQUAL(nTotalARepeat, nTotalA);
    BOOST_REQUIRE_EQUAL(vLegARepeat.size(), vLegA.size());
    for (size_t i = 0; i < vLegA.size(); i++)
    {
        BOOST_CHECK_EQUAL(vLegARepeat[i].nValue, vLegA[i].nValue);
        BOOST_CHECK(vLegARepeat[i].scriptPubKey == vLegA[i].scriptPubKey);
    }

    // A block carrying branch A's leg is not a valid settlement over branch B.
    CKey minerKey;
    minerKey.MakeNewKey(true);
    CScript scriptMiner = GetScriptForDestination(minerKey.GetPubKey().GetID());
    CBlock blockA = MakeSettlementBlock(5 * COIN, scriptMiner, vLegA);
    int64_t nChecked = -1;
    BOOST_CHECK(CheckFinalitySettlementOutputs(blockA, vCountedA, TEST_EPOCH_BUDGET, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, nTotalA);
    BOOST_CHECK(!CheckFinalitySettlementOutputs(blockA, vCountedB, TEST_EPOCH_BUDGET, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, 0);

    // a is still paid exactly once on branch B even though branch B carries it twice.
    int nAOutputs = 0;
    for (const CTxOut& out : vLegB)
    {
        if (out.scriptPubKey == PayeeScript(a.vote))
            nAOutputs++;
    }
    BOOST_CHECK_EQUAL(nAOutputs, 1);
}

// The settlement coinbase is reproducible: the frozen set determines the leg
// regardless of the order votes appeared in within the window blocks.
BOOST_AUTO_TEST_CASE(settlement_leg_is_canonically_ordered)
{
    int nEpoch = PostDAGEpoch(3);
    int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());

    std::vector<Voter> vVoters;
    for (int i = 0; i < 6; i++)
        vVoters.push_back(MakeVoter(nEpoch, nBoundary, VOTE_WEIGHT * (i + 1)));

    std::vector<std::vector<CFinalityVote> > vWindowFwd(FINALITY_VOTE_INCLUSION_WINDOW);
    std::vector<std::vector<CFinalityVote> > vWindowRev(FINALITY_VOTE_INCLUSION_WINDOW);
    for (size_t i = 0; i < vVoters.size(); i++)
    {
        vWindowFwd[i].push_back(vVoters[i].vote);
        vWindowRev[vVoters.size() - 1 - i].push_back(vVoters[i].vote);
    }

    std::string strError;
    std::vector<CFinalityVote> vFwd, vRev;
    std::vector<CTxOut> vLegFwd, vLegRev;
    int64_t nTotalFwd = 0, nTotalRev = 0;
    CollectFinalitySettlementVotes(vWindowFwd, nEpoch, vFwd);
    CollectFinalitySettlementVotes(vWindowRev, nEpoch, vRev);
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vFwd, TEST_EPOCH_BUDGET, vLegFwd, nTotalFwd, &strError));
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vRev, TEST_EPOCH_BUDGET, vLegRev, nTotalRev, &strError));

    BOOST_CHECK_EQUAL(nTotalFwd, nTotalRev);
    BOOST_REQUIRE_EQUAL(vLegFwd.size(), vLegRev.size());
    for (size_t i = 0; i < vLegFwd.size(); i++)
    {
        BOOST_CHECK_EQUAL(vLegFwd[i].nValue, vLegRev[i].nValue);
        BOOST_CHECK(vLegFwd[i].scriptPubKey == vLegRev[i].scriptPubKey);
    }
}

// Private votes are part of the frozen set (so the private leg can be added at the
// same freeze point) but the transparent leg mints nothing for them today.
BOOST_AUTO_TEST_CASE(settlement_transparent_leg_skips_private_votes)
{
    int nEpoch = PostDAGEpoch(1);
    int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());

    Voter t = MakeVoter(nEpoch, nBoundary);

    CFinalityVote priv;
    priv.nProofMode = FINALITY_PROOF_NULLSTAKE_V2;
    priv.nEpoch = nEpoch;
    priv.nHeight = nBoundary;
    priv.nVoteWeight = 0;   // CheckVote forbids clear weight/reward on a private vote
    priv.nReward = 0;
    priv.nullifier = uint256(0xBEEF);
    BOOST_REQUIRE(priv.IsPrivate());

    std::vector<std::vector<CFinalityVote> > vWindow(FINALITY_VOTE_INCLUSION_WINDOW);
    vWindow[0].push_back(t.vote);
    vWindow[1].push_back(priv);

    std::vector<CFinalityVote> vCounted;
    CollectFinalitySettlementVotes(vWindow, nEpoch, vCounted);
    BOOST_CHECK_EQUAL(vCounted.size(), 2u);   // both tiers are frozen together

    std::vector<CTxOut> vLeg;
    int64_t nTotal = 0;
    std::string strError;
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, TEST_EPOCH_BUDGET, vLeg, nTotal, &strError));
    BOOST_CHECK_EQUAL(vLeg.size(), 1u);       // transparent leg only
    BOOST_CHECK_EQUAL(nTotal, TEST_EPOCH_BUDGET);   // the sole payee takes the whole budget
}

// Votes belonging to another epoch never enter this epoch's settlement.
BOOST_AUTO_TEST_CASE(settlement_ignores_votes_from_another_epoch)
{
    int nEpoch = PostDAGEpoch(1);
    int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
    int nOtherEpoch = nEpoch + 1;

    Voter mine = MakeVoter(nEpoch, nBoundary);
    Voter theirs = MakeVoter(nOtherEpoch, GetEpochBoundaryHeight(nOtherEpoch, GetForkHeightDAG()));

    std::vector<std::vector<CFinalityVote> > vWindow(FINALITY_VOTE_INCLUSION_WINDOW);
    vWindow[0].push_back(mine.vote);
    vWindow[0].push_back(theirs.vote);

    std::vector<CFinalityVote> vCounted;
    CollectFinalitySettlementVotes(vWindow, nEpoch, vCounted);
    BOOST_REQUIRE_EQUAL(vCounted.size(), 1u);
    BOOST_CHECK(vCounted[0].nullifier == mine.vote.nullifier);

    std::vector<CTxOut> vLeg;
    int64_t nTotal = 0;
    std::string strError;
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, TEST_EPOCH_BUDGET, vLeg, nTotal, &strError));
    BOOST_CHECK_EQUAL(nTotal, TEST_EPOCH_BUDGET);
}

// Carrying a vote is a commitment, not a payment: the carrier check validates shape
// only and reports no reward, so a carrying block's coinbase allowance is the subsidy
// alone no matter how many votes it carries.
BOOST_AUTO_TEST_CASE(vote_commitments_are_shape_only)
{
    int nEpoch = PostDAGEpoch(1);
    int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());

    Voter a = MakeVoter(nEpoch, nBoundary);
    Voter b = MakeVoter(nEpoch, nBoundary, VOTE_WEIGHT * 2);

    CKey minerKey;
    minerKey.MakeNewKey(true);
    CScript scriptMiner = GetScriptForDestination(minerKey.GetPubKey().GetID());
    CBlock carrier = MakeSettlementBlock(5 * COIN, scriptMiner, std::vector<CTxOut>());

    std::vector<CFinalityVote> vVotes;
    vVotes.push_back(a.vote);
    vVotes.push_back(b.vote);

    std::string strError;
    // No reward output in the coinbase, and the carrier is still valid.
    BOOST_CHECK(CheckFinalityVoteCommitments(carrier, vVotes, &strError));

    // The same nullifier twice inside one block is still rejected.
    vVotes.push_back(a.vote);
    BOOST_CHECK(!CheckFinalityVoteCommitments(carrier, vVotes, &strError));

    // Per-block cap still enforced.
    std::vector<CFinalityVote> vTooMany;
    for (int i = 0; i < FINALITY_MAX_BLOCK_VOTES + 1; i++)
        vTooMany.push_back(MakeVoter(nEpoch, nBoundary).vote);
    BOOST_CHECK(!CheckFinalityVoteCommitments(carrier, vTooMany, &strError));

    // An invalid payee key is rejected up front rather than at settlement.
    std::vector<CFinalityVote> vBadKey;
    CFinalityVote bad = a.vote;
    bad.vchPubKey.assign(33, 0x00);
    vBadKey.push_back(bad);
    BOOST_CHECK(!CheckFinalityVoteCommitments(carrier, vBadKey, &strError));
}

// The collateralnode payment base excludes the settlement's pass-through finality value
// (vtx[0].GetValueOut() - nFinalityRewardOut).
BOOST_AUTO_TEST_CASE(collateralnode_payment_base_excludes_settlement)
{
    int nEpoch = PostDAGEpoch(1);
    int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
    int nSettlementHeight = GetFinalitySettlementHeight(nEpoch, nBoundary);

    Voter a = MakeVoter(nEpoch, nBoundary);
    Voter b = MakeVoter(nEpoch, nBoundary, VOTE_WEIGHT * 2);

    std::vector<std::vector<CFinalityVote> > vWindow(FINALITY_VOTE_INCLUSION_WINDOW);
    vWindow[0].push_back(a.vote);
    vWindow[1].push_back(b.vote);

    std::vector<CFinalityVote> vCounted;
    CollectFinalitySettlementVotes(vWindow, nEpoch, vCounted);

    std::vector<CTxOut> vLeg;
    int64_t nSettled = 0;
    std::string strError;
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, TEST_EPOCH_BUDGET, vLeg, nSettled, &strError));
    BOOST_REQUIRE(nSettled > 0);

    // Producer's base: the subsidy, split between the miner and the collateralnode.
    const int64_t nBlockValue = 5 * COIN;
    int64_t nCNPayment = CBlockSubsidySplit::CollateralnodeShareOfBase(nBlockValue);

    CKey minerKey, cnKey;
    minerKey.MakeNewKey(true);
    cnKey.MakeNewKey(true);
    std::vector<CTxOut> vExtra;
    vExtra.push_back(CTxOut(nCNPayment, GetScriptForDestination(cnKey.GetPubKey().GetID())));
    for (const CTxOut& out : vLeg)
        vExtra.push_back(out);
    CBlock block = MakeSettlementBlock(nBlockValue - nCNPayment,
                                       GetScriptForDestination(minerKey.GetPubKey().GetID()),
                                       vExtra);

    int64_t nFinalityRewardOut = -1;
    BOOST_REQUIRE(CheckFinalitySettlementOutputs(block, vCounted, TEST_EPOCH_BUDGET, nFinalityRewardOut, &strError));
    BOOST_CHECK_EQUAL(nFinalityRewardOut, nSettled);

    // ConnectBlock's base (the same helper it calls) reproduces the producer's exactly.
    int64_t nValidatorBase =
        FinalityCollateralnodePaymentBase(block.vtx[0].GetValueOut(), nFinalityRewardOut);
    BOOST_CHECK_EQUAL(nValidatorBase, nBlockValue);
    BOOST_CHECK_EQUAL(CBlockSubsidySplit::CollateralnodeShareOfBase(nValidatorBase), nCNPayment);

    // Without the subtraction the validator would demand more than the producer paid,
    // so every settlement block would be rejected for a bad collateralnode payment.
    BOOST_CHECK(CBlockSubsidySplit::CollateralnodeShareOfBase(block.vtx[0].GetValueOut()) > nCNPayment);

    // On every non-settlement block nFinalityRewardOut is 0, so the base is untouched.
    BOOST_CHECK(!IsFinalitySettlementHeight(nSettlementHeight - 1));
    BOOST_CHECK_EQUAL(FinalityCollateralnodePaymentBase(nBlockValue, 0), nBlockValue);
    // Underflow-safe.
    BOOST_CHECK_EQUAL(FinalityCollateralnodePaymentBase(1 * COIN, 5 * COIN), 0);
}


// R-SETTLE-002: the settlement vote set is walked off the settlement block's own
// ancestors; blocks are written to disk and reread so every window block is decoded.

namespace {

// A linked run of on-disk blocks and their indexes, removed again when the case
// ends so the shared mapBlockIndex is unchanged.
struct SettlementWindowChain
{
    std::vector<uint256> vHashes;
    std::vector<CBlockIndex*> vIndex;
    CBigNum bnSavedLimit;

    SettlementWindowChain(unsigned int nSeed, int nFirstHeight, int nCount)
        : bnSavedLimit(bnProofOfWorkLimit)
    {
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        CBlockIndex* pprev = NULL;
        for (int i = 0; i < nCount; i++)
            pprev = Add(nSeed + (unsigned int)i, nFirstHeight + i, pprev);
    }

    ~SettlementWindowChain()
    {
        for (size_t i = vHashes.size(); i-- > 0; )
        {
            mapBlockIndex.erase(vHashes[i]);
            delete vIndex[i];
        }
        bnProofOfWorkLimit = bnSavedLimit;
    }

    CBlockIndex* Tip() const { return vIndex.back(); }
    CBlockIndex* At(int i) const { return vIndex[i]; }

private:
    CBlockIndex* Add(unsigned int nSeed, int nHeight, CBlockIndex* pprev)
    {
        CBlock block;
        block.nVersion = 1;
        block.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
        block.nTime = (unsigned int)(1700000000 + nHeight);
        block.nBits = bnProofOfWorkLimit.GetCompact();
        block.nNonce = nSeed;

        // A coinbase carrying no vote commitment: the walk has to decode it, and
        // an empty vote set is the honest answer for a window nobody voted in.
        CTransaction coinbase;
        coinbase.nTime = block.nTime;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript() << nHeight;
        coinbase.vout.push_back(CTxOut(0, CScript() << OP_TRUE));
        block.vtx.push_back(coinbase);
        block.hashMerkleRoot = block.BuildMerkleTree();
        while (!CheckProofOfWork(block.GetHash(), block.nBits))
            ++block.nNonce;

        unsigned int nFile = 0;
        unsigned int nBlockPos = 0;
        BOOST_REQUIRE(block.WriteToDisk(nFile, nBlockPos));

        const uint256 hash = block.GetHash();
        CBlockIndex* pindex = new CBlockIndex(nFile, nBlockPos, block);
        pindex->nHeight = nHeight;
        pindex->pprev = pprev;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(hash, pindex));
        BOOST_REQUIRE(ins.second);
        pindex->phashBlock = &ins.first->first;

        vHashes.push_back(hash);
        vIndex.push_back(pindex);
        return pindex;
    }
};

} // namespace

// Pending sets are memory-only, so a voter re-relays its own uncarried vote at a
// bounded rate while the inclusion window is open.
BOOST_AUTO_TEST_CASE(an_uncarried_vote_is_relayed_again_only_inside_its_window)
{
    CFinalityVote vote;
    vote.nEpoch = 5;
    vote.nHeight = 1211;
    const int64_t nT0 = 1000000;
    // Open window, not carried, interval passed: relay again.
    BOOST_CHECK(OwnVoteNeedsRebroadcast(vote, 1214, false, nT0 + FINALITY_VOTE_REBROADCAST_MS, nT0));
    BOOST_CHECK(OwnVoteNeedsRebroadcast(vote, 1211 + FINALITY_VOTE_INCLUSION_WINDOW - 1, false,
                                        nT0 + FINALITY_VOTE_REBROADCAST_MS, nT0));
    // Carried by a connected block: done.
    BOOST_CHECK(!OwnVoteNeedsRebroadcast(vote, 1214, true, nT0 + FINALITY_VOTE_REBROADCAST_MS, nT0));
    // Too soon since the last relay.
    BOOST_CHECK(!OwnVoteNeedsRebroadcast(vote, 1214, false, nT0 + FINALITY_VOTE_REBROADCAST_MS - 1, nT0));
    // Window closed: a vote outside [H_E, H_E + K) is not block-valid, so relaying it is noise.
    BOOST_CHECK(!OwnVoteNeedsRebroadcast(vote, 1211 + FINALITY_VOTE_INCLUSION_WINDOW, false,
                                         nT0 + FINALITY_VOTE_REBROADCAST_MS, nT0));
    // Before the boundary (a vote for a boundary the tip has not reached): not yet.
    BOOST_CHECK(!OwnVoteNeedsRebroadcast(vote, 1210, false, nT0 + FINALITY_VOTE_REBROADCAST_MS, nT0));
}

BOOST_AUTO_TEST_CASE(the_settlement_vote_set_is_walked_off_the_whole_window)
{
    const bool fSavedRegTest = fRegTest;
    const bool fSavedTestNet = fTestNet;
    fRegTest = true;
    fTestNet = false;

    const int nEpoch = PostDAGEpoch(1);
    const int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
    const int nWindowTop = nBoundary + FINALITY_VOTE_INCLUSION_WINDOW - 1;
    BOOST_REQUIRE_EQUAL(nBoundary + FINALITY_VOTE_INCLUSION_WINDOW,
                        GetFinalitySettlementHeight(nEpoch, nBoundary));

    std::vector<CFinalityVote> vVotes;
    std::string strError;

    {
        // The whole window, on disk. The walk reaches the boundary and every block
        // decodes, so the set is derived rather than refused.
        SettlementWindowChain full(0xFA5E0001, nBoundary,
                                   FINALITY_VOTE_INCLUSION_WINDOW);
        BOOST_REQUIRE_EQUAL(full.Tip()->nHeight, nWindowTop);
        strError.clear();
        BOOST_CHECK_MESSAGE(GatherFinalitySettlementVotes(full.Tip(), nEpoch, vVotes,
                                                          &strError),
                            "the complete window was refused: " << strError);
        BOOST_CHECK(vVotes.empty());

        // The parent has to be the top of the window exactly. One block either side
        // is a different settlement height's parent, and paying from it would settle
        // an epoch twice or from a set still open.
        strError.clear();
        BOOST_CHECK(!GatherFinalitySettlementVotes(
            full.At(FINALITY_VOTE_INCLUSION_WINDOW - 2), nEpoch, vVotes, &strError));
        BOOST_CHECK_EQUAL(strError,
                          "settlement parent is not the top of the epoch "
                          "vote-inclusion window");
        BOOST_CHECK(vVotes.empty());

        strError.clear();
        BOOST_CHECK(!GatherFinalitySettlementVotes(NULL, nEpoch, vVotes, &strError));
        BOOST_CHECK_EQUAL(strError, "settlement has no parent block");

        // The refusals above are properties of the ancestor chain; a window block this
        // node cannot read is not, and says so, so ConnectBlock refuses it transiently
        // instead of condemning the settlement block.
        bool fLocalFailure = true;
        strError.clear();
        BOOST_CHECK(!GatherFinalitySettlementVotes(
            full.At(FINALITY_VOTE_INCLUSION_WINDOW - 2), nEpoch, vVotes, &strError,
            &fLocalFailure));
        BOOST_CHECK(!fLocalFailure);
        CBlockIndex* pDamaged = full.At(3);
        const unsigned int nSavedFile = pDamaged->nFile;
        const unsigned int nSavedPos = pDamaged->nBlockPos;
        pDamaged->nFile = 9999;
        pDamaged->nBlockPos = 0;
        fLocalFailure = false;
        strError.clear();
        BOOST_CHECK(!GatherFinalitySettlementVotes(full.Tip(), nEpoch, vVotes, &strError,
                                                   &fLocalFailure));
        BOOST_CHECK_EQUAL(strError, "settlement window block not readable");
        BOOST_CHECK_MESSAGE(fLocalFailure, "an unreadable block file was reported as a chain property");
        BOOST_CHECK(vVotes.empty());
        pDamaged->nFile = nSavedFile;
        pDamaged->nBlockPos = nSavedPos;
        fLocalFailure = true;
        BOOST_CHECK(GatherFinalitySettlementVotes(full.Tip(), nEpoch, vVotes, &strError,
                                                  &fLocalFailure));
        BOOST_CHECK(!fLocalFailure);
    }

    {
        // The same top block, one ancestor short of the boundary. Nothing about the
        // settlement height has changed; only the ancestry is incomplete, and a
        // partial window is a smaller vote set than the epoch actually connected.
        SettlementWindowChain gapped(0xFA5E1001, nBoundary + 1,
                                     FINALITY_VOTE_INCLUSION_WINDOW - 1);
        BOOST_REQUIRE_EQUAL(gapped.Tip()->nHeight, nWindowTop);
        BOOST_REQUIRE(gapped.At(0)->pprev == NULL);
        strError.clear();
        BOOST_CHECK(!GatherFinalitySettlementVotes(gapped.Tip(), nEpoch, vVotes,
                                                   &strError));
        BOOST_CHECK_EQUAL(strError, "settlement vote-inclusion window is incomplete");
        BOOST_CHECK(vVotes.empty());
    }

    fRegTest = fSavedRegTest;
    fTestNet = fSavedTestNet;
}

// With the note lane active the epoch settles once the note-vote window closes, so the
// note mint total the budget subtracts covers every note vote the epoch can carry.
// Transparent votes still sit only in the first FINALITY_VOTE_INCLUSION_WINDOW blocks.
BOOST_AUTO_TEST_CASE(the_settlement_waits_for_the_note_vote_window)
{
    const bool fSavedRegTest = fRegTest;
    const bool fSavedTestNet = fTestNet;
    const int nSavedNoteVote = nRegtestIV5NoteVoteHeight;
    fRegTest = true;
    fTestNet = false;
    nRegtestIV5NoteVoteHeight = 1;

    const int nEpoch = PostDAGEpoch(1);
    const int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
    BOOST_CHECK_EQUAL(GetFinalityVoteSetCloseOffset(nBoundary),
                      FINALITY_NOTE_VOTE_INCLUSION_WINDOW);
    BOOST_CHECK_EQUAL(GetFinalitySettlementHeight(nEpoch, nBoundary),
                      nBoundary + FINALITY_NOTE_VOTE_INCLUSION_WINDOW);
    BOOST_CHECK(IsFinalitySettlementHeight(nBoundary + FINALITY_NOTE_VOTE_INCLUSION_WINDOW));
    BOOST_CHECK(!IsFinalitySettlementHeight(nBoundary + FINALITY_VOTE_INCLUSION_WINDOW));

    std::vector<CFinalityVote> vVotes;
    std::string strError;
    {
        SettlementWindowChain full(0xFA5E2001, nBoundary, FINALITY_NOTE_VOTE_INCLUSION_WINDOW);
        BOOST_REQUIRE_EQUAL(full.Tip()->nHeight,
                            nBoundary + FINALITY_NOTE_VOTE_INCLUSION_WINDOW - 1);
        BOOST_CHECK_MESSAGE(GatherFinalitySettlementVotes(full.Tip(), nEpoch, vVotes,
                                                          &strError),
                            strError);
        strError.clear();
        BOOST_CHECK(!GatherFinalitySettlementVotes(
            full.At(FINALITY_VOTE_INCLUSION_WINDOW - 1), nEpoch, vVotes, &strError));
        BOOST_CHECK_EQUAL(strError,
                          "settlement parent is not the top of the epoch "
                          "vote-inclusion window");
    }

    nRegtestIV5NoteVoteHeight = nSavedNoteVote;
    fRegTest = fSavedRegTest;
    fTestNet = fSavedTestNet;
}

BOOST_AUTO_TEST_SUITE_END()
