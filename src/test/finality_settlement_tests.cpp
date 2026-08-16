// Per-epoch finality-reward settlement: votes are paid once, at H_E +
// FINALITY_VOTE_INCLUSION_WINDOW, from the window's frozen vote set.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../finality.h"
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
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, vSettlement, nTotal, &strError));
    BOOST_CHECK_EQUAL(vSettlement.size(), 3u);
    BOOST_CHECK_EQUAL(nTotal, a.vote.nReward + b.vote.nReward + c.vote.nReward);

    // One output per voter, at that voter's own bound reward.
    for (const Voter* p : { &a, &b, &c })
    {
        int nHits = 0;
        for (const CTxOut& out : vSettlement)
        {
            if (out.scriptPubKey == PayeeScript(p->vote))
            {
                nHits++;
                BOOST_CHECK_EQUAL(out.nValue, p->vote.nReward);
            }
        }
        BOOST_CHECK_EQUAL(nHits, 1);
    }

    CKey minerKey;
    minerKey.MakeNewKey(true);
    CScript scriptMiner = GetScriptForDestination(minerKey.GetPubKey().GetID());
    CBlock block = MakeSettlementBlock(5 * COIN, scriptMiner, vSettlement);

    int64_t nChecked = -1;
    BOOST_CHECK(CheckFinalitySettlementOutputs(block, vCounted, nChecked, &strError));
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
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, vSettlement, nTotal, &strError));

    BOOST_CHECK_EQUAL(vSettlement.size(), 2u);
    BOOST_CHECK_EQUAL(nTotal, attacker.vote.nReward + honest.vote.nReward);

    // What the old per-carrier rule would have minted for the same window.
    int64_t nLegacyPerCarrierTotal =
        (int64_t)FINALITY_VOTE_INCLUSION_WINDOW * attacker.vote.nReward + honest.vote.nReward;
    BOOST_CHECK(nLegacyPerCarrierTotal > nTotal);
    BOOST_CHECK_EQUAL(nLegacyPerCarrierTotal - nTotal,
                      (int64_t)(FINALITY_VOTE_INCLUSION_WINDOW - 1) * attacker.vote.nReward);

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
        vGreedy.push_back(CTxOut(attacker.vote.nReward, PayeeScript(attacker.vote)));

    const int64_t nSubsidy = 5 * COIN;
    CBlock greedyBlock = MakeSettlementBlock(nSubsidy, scriptMiner, vGreedy);
    int64_t nAllowedExtra = -1;
    BOOST_REQUIRE(CheckFinalitySettlementOutputs(greedyBlock, vCounted, nAllowedExtra, &strError));
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
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, vSettlement, nTotal, &strError));
    BOOST_REQUIRE_EQUAL(vSettlement.size(), 2u);

    CKey minerKey;
    minerKey.MakeNewKey(true);
    CScript scriptMiner = GetScriptForDestination(minerKey.GetPubKey().GetID());
    int64_t nChecked = -1;

    // Whole leg omitted.
    CBlock empty = MakeSettlementBlock(5 * COIN, scriptMiner, std::vector<CTxOut>());
    BOOST_CHECK(!CheckFinalitySettlementOutputs(empty, vCounted, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, 0);

    // One payee dropped.
    std::vector<CTxOut> vShortSet(vSettlement.begin(), vSettlement.begin() + 1);
    CBlock dropped = MakeSettlementBlock(5 * COIN, scriptMiner, vShortSet);
    BOOST_CHECK(!CheckFinalitySettlementOutputs(dropped, vCounted, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, 0);

    // One payee short-paid by a single innovai.
    std::vector<CTxOut> vShortPay = vSettlement;
    vShortPay[0].nValue -= 1;
    CBlock shortPaid = MakeSettlementBlock(5 * COIN, scriptMiner, vShortPay);
    BOOST_CHECK(!CheckFinalitySettlementOutputs(shortPaid, vCounted, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, 0);

    // Redirected to the miner instead of the voter.
    std::vector<CTxOut> vRedirected = vSettlement;
    vRedirected[1].scriptPubKey = scriptMiner;
    CBlock redirected = MakeSettlementBlock(5 * COIN, scriptMiner, vRedirected);
    BOOST_CHECK(!CheckFinalitySettlementOutputs(redirected, vCounted, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, 0);

    // The correct leg is accepted in any output order.
    std::vector<CTxOut> vReordered(vSettlement.rbegin(), vSettlement.rend());
    CBlock reordered = MakeSettlementBlock(5 * COIN, scriptMiner, vReordered);
    BOOST_CHECK(CheckFinalitySettlementOutputs(reordered, vCounted, nChecked, &strError));
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
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCountedA, vLegA, nTotalA, &strError));
    CollectFinalitySettlementVotes(vWindowB, nEpoch, vCountedB);
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCountedB, vLegB, nTotalB, &strError));

    BOOST_CHECK_EQUAL(nTotalA, a.vote.nReward + b.vote.nReward);
    BOOST_CHECK_EQUAL(nTotalB, a.vote.nReward + c.vote.nReward);
    BOOST_CHECK_EQUAL(vLegA.size(), 2u);
    BOOST_CHECK_EQUAL(vLegB.size(), 2u);

    // Same-window re-derivation is byte-identical, so any block that becomes canonical
    // at the settlement height over branch A owes exactly branch A's leg.
    std::vector<CFinalityVote> vCountedARepeat;
    std::vector<CTxOut> vLegARepeat;
    int64_t nTotalARepeat = 0;
    CollectFinalitySettlementVotes(vWindowA, nEpoch, vCountedARepeat);
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCountedARepeat, vLegARepeat, nTotalARepeat, &strError));
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
    BOOST_CHECK(CheckFinalitySettlementOutputs(blockA, vCountedA, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, nTotalA);
    BOOST_CHECK(!CheckFinalitySettlementOutputs(blockA, vCountedB, nChecked, &strError));
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
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vFwd, vLegFwd, nTotalFwd, &strError));
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vRev, vLegRev, nTotalRev, &strError));

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
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, vLeg, nTotal, &strError));
    BOOST_CHECK_EQUAL(vLeg.size(), 1u);       // transparent leg only
    BOOST_CHECK_EQUAL(nTotal, t.vote.nReward);
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
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, vLeg, nTotal, &strError));
    BOOST_CHECK_EQUAL(nTotal, mine.vote.nReward);
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
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vCounted, vLeg, nSettled, &strError));
    BOOST_REQUIRE(nSettled > 0);

    // Producer's base: the subsidy, split between the miner and the collateralnode.
    const int64_t nBlockValue = 5 * COIN;
    int64_t nCNPayment = GetCollateralnodePayment(nSettlementHeight, nBlockValue);

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
    BOOST_REQUIRE(CheckFinalitySettlementOutputs(block, vCounted, nFinalityRewardOut, &strError));
    BOOST_CHECK_EQUAL(nFinalityRewardOut, nSettled);

    // ConnectBlock's base (the same helper it calls) reproduces the producer's exactly.
    int64_t nValidatorBase =
        FinalityCollateralnodePaymentBase(block.vtx[0].GetValueOut(), nFinalityRewardOut);
    BOOST_CHECK_EQUAL(nValidatorBase, nBlockValue);
    BOOST_CHECK_EQUAL(GetCollateralnodePayment(nSettlementHeight, nValidatorBase), nCNPayment);

    // Without the subtraction the validator would demand more than the producer paid,
    // so every settlement block would be rejected for a bad collateralnode payment.
    BOOST_CHECK(GetCollateralnodePayment(nSettlementHeight, block.vtx[0].GetValueOut()) > nCNPayment);

    // On every non-settlement block nFinalityRewardOut is 0, so the base is untouched.
    BOOST_CHECK(!IsFinalitySettlementHeight(nSettlementHeight - 1));
    BOOST_CHECK_EQUAL(FinalityCollateralnodePaymentBase(nBlockValue, 0), nBlockValue);
    // Underflow-safe.
    BOOST_CHECK_EQUAL(FinalityCollateralnodePaymentBase(1 * COIN, 5 * COIN), 0);
}

BOOST_AUTO_TEST_SUITE_END()
