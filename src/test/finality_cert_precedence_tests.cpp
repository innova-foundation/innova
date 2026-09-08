// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Precedence between an epoch's own-block tally certificate and its votes when
// deriving the epoch tier, and the transparent-lane equivocation counter.

#include <boost/test/unit_test.hpp>

#include <vector>

#include "../finality.h"
#include "../key.h"
#include "../uint256.h"

namespace {

CFinalityVote MakeVote(int nEpoch, const uint256& hashBlock, int nHeight,
                       int64_t nWeight, const CKey& key, int nSeed)
{
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    vote.nEpoch = nEpoch;
    vote.hashBlock = hashBlock;
    vote.nHeight = nHeight;
    vote.nTime = 1700000000 + nSeed;
    vote.nVoteWeight = nWeight;
    vote.nReward = 0;
    vote.nullifier = uint256(500000 + nSeed);
    const CPubKey pubkey = key.GetPubKey();
    vote.vchPubKey.assign(pubkey.begin(), pubkey.end());
    return vote;
}

CFinalityTallyCertificate MakeCert(int nEpoch, int nTier, const uint256& hashBlock,
                                   int nHeight, size_t nNullifiers)
{
    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = nEpoch;
    cert.nHeight = nHeight;
    cert.hashBlock = hashBlock;
    cert.nTier = nTier;
    for (size_t i = 0; i < nNullifiers; i++)
        cert.vVoteNullifiers.push_back(uint256(900000 + nEpoch * 100 + (int)i + 1));
    return cert;
}

// Two voters of equal weight on hashA: the whole epoch weight, so HARD.
struct HardEpoch
{
    CKey keyA;
    CKey keyB;
    uint256 hashA;
    uint256 hashB;
    int nHeightA;
    int nHeightB;

    explicit HardEpoch(int nSeed)
        : hashA(uint256(700000 + nSeed)), hashB(uint256(800000 + nSeed)),
          nHeightA(90000 + nSeed), nHeightB(90001 + nSeed)
    {
        keyA.MakeNewKey(true);
        keyB.MakeNewKey(true);
    }

    void Populate(CFinalityTracker& tracker, int nEpoch, int nSeed) const
    {
        BOOST_REQUIRE(tracker.AddVote(
            MakeVote(nEpoch, hashA, nHeightA, 2000, keyA, nSeed), false, true));
        BOOST_REQUIRE(tracker.AddVote(
            MakeVote(nEpoch, hashA, nHeightA, 2000, keyB, nSeed + 1), false, true));
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(finality_cert_precedence_tests)

// A legacy NONE-tier certificate passes every connect-time threshold check at any
// weights. As the epoch's only certificate it must not replace the vote-derived tier.
BOOST_AUTO_TEST_CASE(none_tier_certificate_yields_to_vote_tier)
{
    const int nEpoch = 501;
    HardEpoch epoch(1);
    CFinalityTracker tracker;
    epoch.Populate(tracker, nEpoch, 10);

    const CFinalityTallyCertificate noneCert =
        MakeCert(nEpoch, FINALITY_NONE, epoch.hashB, epoch.nHeightB, 2);

    int nTier = FINALITY_HARD;
    uint256 hashWinner = 0;
    int nWinnerHeight = 0, nVoterCount = 0;
    BOOST_CHECK(tracker.ComputeDeterministicEpochTier(nEpoch, true, noneCert, nTier,
                                                      hashWinner, nWinnerHeight, nVoterCount));
    BOOST_CHECK_EQUAL(nTier, (int)FINALITY_HARD);
    BOOST_CHECK(hashWinner == epoch.hashA);
    BOOST_CHECK_EQUAL(nWinnerHeight, epoch.nHeightA);
    BOOST_CHECK_EQUAL(nVoterCount, 2);

    // Identical to the no-certificate result.
    const CFinalityTallyCertificate noCert;
    int nTier2 = FINALITY_NONE;
    uint256 hashWinner2 = 0;
    int nWinnerHeight2 = 0, nVoterCount2 = 0;
    BOOST_REQUIRE(tracker.ComputeDeterministicEpochTier(nEpoch, false, noCert, nTier2,
                                                        hashWinner2, nWinnerHeight2, nVoterCount2));
    BOOST_CHECK_EQUAL(nTier, nTier2);
    BOOST_CHECK(hashWinner == hashWinner2);
    BOOST_CHECK_EQUAL(nWinnerHeight, nWinnerHeight2);
    BOOST_CHECK_EQUAL(nVoterCount, nVoterCount2);
}

// A certificate asserting any tier keeps precedence: tier, winner, height and voter
// count all come from the certificate, including a tier below the vote-derived one.
BOOST_AUTO_TEST_CASE(asserting_certificate_keeps_precedence_over_votes)
{
    const int nEpoch = 502;
    HardEpoch epoch(2);
    CFinalityTracker tracker;
    epoch.Populate(tracker, nEpoch, 20);

    const int vTiers[3] = { FINALITY_TENTATIVE, FINALITY_SOFT, FINALITY_HARD };
    for (int i = 0; i < 3; i++)
    {
        const CFinalityTallyCertificate cert =
            MakeCert(nEpoch, vTiers[i], epoch.hashB, epoch.nHeightB, 3);
        int nTier = FINALITY_NONE;
        uint256 hashWinner = 0;
        int nWinnerHeight = 0, nVoterCount = 0;
        BOOST_CHECK(tracker.ComputeDeterministicEpochTier(nEpoch, true, cert, nTier,
                                                          hashWinner, nWinnerHeight, nVoterCount));
        BOOST_CHECK_EQUAL(nTier, vTiers[i]);
        BOOST_CHECK(hashWinner == epoch.hashB);
        BOOST_CHECK_EQUAL(nWinnerHeight, epoch.nHeightB);
        BOOST_CHECK_EQUAL(nVoterCount, 3);
    }

    // Another epoch's certificate is not this epoch's certificate (unchanged rule).
    const CFinalityTallyCertificate otherEpoch =
        MakeCert(nEpoch + 1, FINALITY_HARD, epoch.hashB, epoch.nHeightB, 3);
    int nTier = FINALITY_NONE;
    uint256 hashWinner = 0;
    int nWinnerHeight = 0, nVoterCount = 0;
    BOOST_REQUIRE(tracker.ComputeDeterministicEpochTier(nEpoch, true, otherEpoch, nTier,
                                                        hashWinner, nWinnerHeight, nVoterCount));
    BOOST_CHECK_EQUAL(nTier, (int)FINALITY_HARD);
    BOOST_CHECK(hashWinner == epoch.hashA);
    BOOST_CHECK_EQUAL(nVoterCount, 2);
}

// The fallback reads only the votes: a NONE-tier certificate supplies no winner,
// height or voter count when the votes cannot.
BOOST_AUTO_TEST_CASE(none_tier_certificate_cannot_supply_a_winner)
{
    const int nEpoch = 503;
    HardEpoch epoch(3);
    const CFinalityTallyCertificate noneCert =
        MakeCert(nEpoch, FINALITY_NONE, epoch.hashB, epoch.nHeightB, 2);

    {
        CFinalityTracker tracker;
        int nTier = FINALITY_HARD;
        uint256 hashWinner = epoch.hashB;
        int nWinnerHeight = 1, nVoterCount = 1;
        BOOST_CHECK(!tracker.ComputeDeterministicEpochTier(nEpoch, true, noneCert, nTier,
                                                           hashWinner, nWinnerHeight, nVoterCount));
        BOOST_CHECK_EQUAL(nTier, (int)FINALITY_NONE);
        BOOST_CHECK(hashWinner == 0);
        BOOST_CHECK_EQUAL(nWinnerHeight, 0);
        BOOST_CHECK_EQUAL(nVoterCount, 0);
    }
    {
        // One voter is below FINALITY_MIN_VOTERS.
        CFinalityTracker tracker;
        BOOST_REQUIRE(tracker.AddVote(
            MakeVote(nEpoch, epoch.hashA, epoch.nHeightA, 2000, epoch.keyA, 30), false, true));
        int nTier = FINALITY_HARD;
        uint256 hashWinner = epoch.hashB;
        int nWinnerHeight = 1, nVoterCount = 0;
        BOOST_CHECK(!tracker.ComputeDeterministicEpochTier(nEpoch, true, noneCert, nTier,
                                                           hashWinner, nWinnerHeight, nVoterCount));
        BOOST_CHECK_EQUAL(nTier, (int)FINALITY_NONE);
        BOOST_CHECK(hashWinner == 0);
        BOOST_CHECK_EQUAL(nWinnerHeight, 0);
        BOOST_CHECK_EQUAL(nVoterCount, 1);
    }
}

// The node-local streak takes the same rule: a NONE-tier certificate connected for
// the middle epoch of a HARD run must not break the run.
BOOST_AUTO_TEST_CASE(none_tier_certificate_does_not_reset_live_streak)
{
    const int nFirst = 601;
    HardEpoch epoch(4);
    CFinalityTracker tracker;
    for (int i = 0; i < FINALITY_CONFIRMATION_EPOCHS; i++)
        epoch.Populate(tracker, nFirst + i, 40 + 2 * i);
    BOOST_REQUIRE(tracker.AddTallyCertificate(
        MakeCert(nFirst + 1, FINALITY_NONE, epoch.hashB, epoch.nHeightB, 2), false, true));

    {
        LOCK(tracker.cs_finality);
        for (int i = 0; i < FINALITY_CONFIRMATION_EPOCHS; i++)
            tracker.CheckFinalityThreshold(nFirst + i, false);
    }
    BOOST_CHECK_EQUAL(tracker.GetFinalizedHeight(), epoch.nHeightA);
    BOOST_CHECK(tracker.GetFinalizedHash() == epoch.hashA);
}

// Same nullifier, different block: dropped as before, and now counted once per
// nullifier. A re-encoding of the same choice is not counted. No verdict changes.
BOOST_AUTO_TEST_CASE(conflicting_nullifier_vote_is_counted)
{
    // Relay-path votes must sit within the tip+2 epoch admission bound.
    const int nEpoch = 1;
    const uint256 hashA(11), hashB(12), hashC(13);
    CKey key;
    key.MakeNewKey(true);
    CFinalityTracker tracker;
    BOOST_CHECK_EQUAL(tracker.GetEpochEquivocatedVoteCount(nEpoch), 0);

    BOOST_REQUIRE(tracker.AddVote(MakeVote(nEpoch, hashA, 100, 1000, key, 50), false, false));

    BOOST_CHECK(!tracker.AddVote(MakeVote(nEpoch, hashB, 100, 1000, key, 50), false, false));
    BOOST_CHECK_EQUAL(tracker.GetEpochEquivocatedVoteCount(nEpoch), 1);

    CFinalityVote reencoded = MakeVote(nEpoch, hashA, 100, 1000, key, 50);
    reencoded.nTime += 1;
    reencoded.nReward = 7;
    BOOST_REQUIRE(reencoded.GetHash() != MakeVote(nEpoch, hashA, 100, 1000, key, 50).GetHash());
    BOOST_CHECK(!tracker.AddVote(reencoded, false, false));
    BOOST_CHECK_EQUAL(tracker.GetEpochEquivocatedVoteCount(nEpoch), 1);

    BOOST_CHECK(!tracker.AddVote(MakeVote(nEpoch, hashC, 100, 1000, key, 50), false, false));
    BOOST_CHECK_EQUAL(tracker.GetEpochEquivocatedVoteCount(nEpoch), 1);

    CKey key2;
    key2.MakeNewKey(true);
    BOOST_REQUIRE(tracker.AddVote(MakeVote(nEpoch, hashA, 100, 1000, key2, 51), false, false));
    BOOST_CHECK(!tracker.AddVote(MakeVote(nEpoch, hashB, 100, 1000, key2, 51), false, false));
    BOOST_CHECK_EQUAL(tracker.GetEpochEquivocatedVoteCount(nEpoch), 2);
    BOOST_CHECK_EQUAL(tracker.GetEpochEquivocatedVoteCount(nEpoch + 1), 0);

    // Block-connect path: a connected vote replacing a pending one for another block
    // is still accepted, and counted; a conflict with a connected vote is still refused.
    CKey key3;
    key3.MakeNewKey(true);
    BOOST_REQUIRE(tracker.AddVote(MakeVote(nEpoch, hashA, 100, 1000, key3, 52), false, false));
    BOOST_CHECK(tracker.AddVote(MakeVote(nEpoch, hashB, 100, 1000, key3, 52), false, true));
    BOOST_CHECK_EQUAL(tracker.GetEpochEquivocatedVoteCount(nEpoch), 3);
    BOOST_CHECK(!tracker.AddVote(MakeVote(nEpoch, hashC, 100, 1000, key3, 52), false, true));
    BOOST_CHECK_EQUAL(tracker.GetEpochEquivocatedVoteCount(nEpoch), 3);
    BOOST_CHECK_EQUAL(tracker.GetEpochVoteCount(nEpoch), 1);
}

BOOST_AUTO_TEST_SUITE_END()
