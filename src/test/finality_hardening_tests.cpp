// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Mergeset-fork finality hardening: inclusion window, equivocation evidence and
// settlement exclusion, stake quorum, voter clusters. Each rule on both sides of the fork.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../finality.h"
#include "../key.h"
#include "../txdb.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

struct MergesetAt
{
    int nSaved;
    explicit MergesetAt(int nHeight) : nSaved(::nRegtestMergesetHeight) { ::nRegtestMergesetHeight = nHeight; }
    ~MergesetAt() { ::nRegtestMergesetHeight = nSaved; }
};

int Epoch(int nOffset) { return GetEpochForHeight(GetForkHeightDAG()) + nOffset; }
int Boundary(int nEpoch) { return GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG()); }

CFinalityVote SignedVote(const CKey& keyIn, int nEpoch, const uint256& hashBlock,
                         int nHeight, int64_t nWeight = 1000 * COIN,
                         const COutPoint* pStake = NULL)
{
    CKey key = keyIn;
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    vote.nEpoch = nEpoch;
    vote.hashBlock = hashBlock;
    vote.nHeight = nHeight;
    vote.nTime = 1700000000;
    vote.nVoteWeight = nWeight;
    vote.nReward = 0;
    const CPubKey pubkey = key.GetPubKey();
    vote.vchPubKey.assign(pubkey.begin(), pubkey.end());
    CHashWriter nf(SER_GETHASH, 0);
    nf << vote.vchPubKey;
    nf << nEpoch;
    vote.nullifier = nf.GetHash();
    if (pStake)
        vote.vStakeProof.push_back(*pStake);
    vote.MarkCanonicalEnvelope();
    BOOST_REQUIRE(vote.Sign(key));
    return vote;
}

CKey NewKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key;
}

CKeyID KeyIDOf(const CFinalityVote& vote) { return CPubKey(vote.vchPubKey).GetID(); }

} // namespace

BOOST_AUTO_TEST_SUITE(finality_hardening_tests)

BOOST_AUTO_TEST_CASE(inclusion_window_widens_only_from_the_fork)
{
    const int nEpoch = Epoch(4);
    const int nBoundary = Boundary(nEpoch);
    {
        MergesetAt unset(PRIVACY_VNEXT_HEIGHT_UNSET);
        BOOST_CHECK_EQUAL(GetFinalityVoteInclusionWindow(nBoundary), FINALITY_VOTE_INCLUSION_WINDOW);
        BOOST_CHECK(!IsFinalityHardeningActiveForEpoch(nEpoch));
    }
    {
        MergesetAt fork(nBoundary);
        BOOST_CHECK_EQUAL(GetFinalityVoteInclusionWindow(nBoundary), FINALITY_VOTE_INCLUSION_WINDOW_HARDENED);
        BOOST_CHECK_EQUAL(GetFinalityVoteInclusionWindow(Boundary(nEpoch - 1)), FINALITY_VOTE_INCLUSION_WINDOW);
        BOOST_CHECK(IsFinalityHardeningActiveForEpoch(nEpoch));
        BOOST_CHECK(!IsFinalityHardeningActiveForEpoch(nEpoch - 1));
        // Settlement and certificate floor follow the window, and stay inside the epoch.
        const int nClose = GetFinalityVoteSetCloseOffset(nBoundary);
        BOOST_CHECK_GE(nClose, FINALITY_VOTE_INCLUSION_WINDOW_HARDENED);
        BOOST_CHECK_LT(nClose, GetEpochInterval(nBoundary));
        BOOST_CHECK_EQUAL(GetFinalitySettlementHeight(nEpoch, nBoundary), nBoundary + nClose);
        // A fork inside an epoch leaves that epoch on the old rules.
        MergesetAt mid(nBoundary + 1);
        BOOST_CHECK_EQUAL(GetFinalityVoteInclusionWindow(nBoundary), FINALITY_VOTE_INCLUSION_WINDOW);
        BOOST_CHECK(!IsFinalityHardeningActiveForEpoch(nEpoch));
    }
}

BOOST_AUTO_TEST_CASE(stake_quorum_downgrades_only_hard)
{
    BOOST_CHECK_EQUAL(ApplyFinalityStakeQuorum(FINALITY_HARD, 49, 100), FINALITY_SOFT);
    BOOST_CHECK_EQUAL(ApplyFinalityStakeQuorum(FINALITY_HARD, 50, 100), FINALITY_HARD);
    BOOST_CHECK_EQUAL(ApplyFinalityStakeQuorum(FINALITY_HARD, 1, 0), FINALITY_HARD);
    BOOST_CHECK_EQUAL(ApplyFinalityStakeQuorum(FINALITY_SOFT, 1, 100), FINALITY_SOFT);
    BOOST_CHECK_EQUAL(ApplyFinalityStakeQuorum(FINALITY_TENTATIVE, 1, 100), FINALITY_TENTATIVE);
    BOOST_CHECK_EQUAL(ApplyFinalityStakeQuorum(FINALITY_HARD, MAX_MONEY / 2, MAX_MONEY), FINALITY_HARD);
}

BOOST_AUTO_TEST_CASE(voter_clusters_merge_on_shared_controlling_key)
{
    const int nEpoch = Epoch(3);
    const uint256 hashA(1), hashB(2);
    CKey a = NewKey(), b = NewKey(), c = NewKey(), owner = NewKey();
    std::vector<CFinalityVote> votes;
    votes.push_back(SignedVote(a, nEpoch, hashA, Boundary(nEpoch)));
    votes.push_back(SignedVote(b, nEpoch, hashB, Boundary(nEpoch)));
    votes.push_back(SignedVote(c, nEpoch, hashA, Boundary(nEpoch)));

    std::map<uint256, std::vector<CKeyID> > noKeys;
    int nWinners = -1;
    BOOST_CHECK_EQUAL(CountFinalityVoterClusters(votes, noKeys, &hashA, &nWinners), 3);
    BOOST_CHECK_EQUAL(nWinners, 2);

    std::map<uint256, std::vector<CKeyID> > keys;
    keys[votes[0].nullifier].push_back(owner.GetPubKey().GetID());
    keys[votes[1].nullifier].push_back(owner.GetPubKey().GetID());
    BOOST_CHECK_EQUAL(CountFinalityVoterClusters(votes, keys, &hashA, &nWinners), 2);
    // The a+b cluster split its vote, so only c counts as a winner.
    BOOST_CHECK_EQUAL(nWinners, 1);

    // Transitive: c linked to b's own key joins the same cluster.
    keys[votes[2].nullifier].push_back(KeyIDOf(votes[1]));
    BOOST_CHECK_EQUAL(CountFinalityVoterClusters(votes, keys), 1);
}

BOOST_AUTO_TEST_CASE(split_stake_is_one_voter_after_the_fork)
{
    const int nEpoch = Epoch(5);
    const int nBoundary = Boundary(nEpoch);
    const uint256 hashA(11);
    CKey a = NewKey(), b = NewKey(), owner = NewKey();
    const CFinalityVote va = SignedVote(a, nEpoch, hashA, nBoundary);
    const CFinalityVote vb = SignedVote(b, nEpoch, hashA, nBoundary);
    std::vector<CKeyID> vOwner(1, owner.GetPubKey().GetID());

    for (int fFork = 0; fFork < 2; fFork++)
    {
        MergesetAt fork(fFork ? nBoundary : PRIVACY_VNEXT_HEIGHT_UNSET);
        CFinalityTracker tracker;
        tracker.SetVoteControlKeys(va.nullifier, vOwner);
        tracker.SetVoteControlKeys(vb.nullifier, vOwner);
        BOOST_REQUIRE(tracker.AddVote(va, false, true));
        BOOST_REQUIRE(tracker.AddVote(vb, false, true));
        std::vector<CFinalityVote> votes;
        votes.push_back(va);
        votes.push_back(vb);
        BOOST_CHECK_EQUAL(tracker.GetTransparentVoterUnits(nEpoch, votes), fFork ? 1 : 2);

        int nTier = 0, nHeight = 0, nVoters = 0;
        uint256 hashWinner;
        CFinalityTallyCertificate noCert;
        const bool fTier = tracker.ComputeDeterministicEpochTier(nEpoch, false, noCert, nTier,
                                                                 hashWinner, nHeight, nVoters);
        BOOST_CHECK_EQUAL(fTier, !fFork);
        if (!fFork)
            BOOST_CHECK_EQUAL(nTier, FINALITY_HARD);

        // The canonical certificate floor counts the same units.
        CFinalityTallyCertificate cert;
        std::string strError;
        const bool fCert = BuildCanonicalTransparentFinalityCertificate(
            votes, cert, &strError, 0, 0,
            tracker.GetTransparentVoterUnits(nEpoch, votes));
        BOOST_CHECK_EQUAL(fCert, !fFork);
    }
}

BOOST_AUTO_TEST_CASE(abort_restore_keeps_voter_clusters)
{
    const int nEpoch = Epoch(6);
    const int nBoundary = Boundary(nEpoch);
    MergesetAt fork(nBoundary);
    const uint256 hashA(31);
    CKey a = NewKey(), b = NewKey(), owner = NewKey();
    const CKeyID ownerID = owner.GetPubKey().GetID();

    CTransaction txFund;
    txFund.nTime = 1700000000;
    txFund.vin.resize(1);
    txFund.vin[0].prevout = COutPoint(uint256(0xC1u), 0);
    txFund.vout.push_back(CTxOut(1000 * COIN, GetScriptForColdStaking(a.GetPubKey().GetID(), ownerID)));
    txFund.vout.push_back(CTxOut(1000 * COIN, GetScriptForColdStaking(b.GetPubKey().GetID(), ownerID)));
    CBlock block;
    block.nTime = 1700000000;
    block.vtx.push_back(txFund);
    block.hashMerkleRoot = block.BuildMerkleTree();
    unsigned int nFile = 0, nBlockPos = 0;
    BOOST_REQUIRE(block.WriteToDisk(nFile, nBlockPos));
    const unsigned int nTxPos = nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) -
                                (2 * GetSizeOfCompactSize(0)) + GetSizeOfCompactSize(block.vtx.size());
    const uint256 hashFund = txFund.GetHash();
    CTxDB txdb("r+");
    BOOST_REQUIRE(txdb.UpdateTxIndex(hashFund, CTxIndex(CDiskTxPos(nFile, nBlockPos, nTxPos), 2)));

    const COutPoint stakeA(hashFund, 0), stakeB(hashFund, 1);
    const CFinalityVote va = SignedVote(a, nEpoch, hashA, nBoundary, 1000 * COIN, &stakeA);
    const CFinalityVote vb = SignedVote(b, nEpoch, hashA, nBoundary, 1000 * COIN, &stakeB);
    std::map<uint256, CFinalityVote> mapVotes;
    mapVotes[va.nullifier] = va;
    mapVotes[vb.nullifier] = vb;
    std::vector<CFinalityVote> votes;
    votes.push_back(va);
    votes.push_back(vb);

    std::vector<CKeyID> vKeys;
    BOOST_REQUIRE(CFinalityTracker::ResolveVoteControlKeys(va, txdb, vKeys));
    BOOST_REQUIRE_EQUAL(vKeys.size(), 1u);
    BOOST_CHECK(vKeys[0] == ownerID);

    CFinalityTracker reference;
    for (const CFinalityVote& v : votes)
    {
        BOOST_REQUIRE(CFinalityTracker::ResolveVoteControlKeys(v, txdb, vKeys));
        reference.SetVoteControlKeys(v.nullifier, vKeys);
        BOOST_REQUIRE(reference.AddVote(v, false, true));
    }
    BOOST_CHECK_EQUAL(reference.GetTransparentVoterUnits(nEpoch, votes), 1);

    CFinalityTracker aborted;
    BOOST_REQUIRE(aborted.ResolveMissingVoteControlKeys(mapVotes, txdb));
    for (const CFinalityVote& v : votes)
        BOOST_REQUIRE(aborted.AddVote(v, false, true));
    BOOST_REQUIRE(aborted.RestoreCommittedStateAfterAbort());
    BOOST_CHECK_EQUAL(aborted.GetTransparentVoterUnits(nEpoch, votes), 2);
    BOOST_REQUIRE(aborted.ResolveMissingVoteControlKeys(mapVotes, txdb));
    for (const CFinalityVote& v : votes)
        BOOST_REQUIRE(aborted.AddVote(v, false, true));
    BOOST_CHECK_EQUAL(aborted.GetTransparentVoterUnits(nEpoch, votes),
                      reference.GetTransparentVoterUnits(nEpoch, votes));

    CFinalityVote vMissing = SignedVote(NewKey(), nEpoch, hashA, nBoundary, 1000 * COIN, &stakeA);
    vMissing.vStakeProof[0] = COutPoint(uint256(0xC2u), 0);
    std::map<uint256, CFinalityVote> mapMissing;
    mapMissing[vMissing.nullifier] = vMissing;
    BOOST_CHECK(!aborted.ResolveMissingVoteControlKeys(mapMissing, txdb));

    BOOST_REQUIRE(txdb.EraseTxIndex(txFund));
}

BOOST_AUTO_TEST_CASE(hard_needs_quorum_of_trailing_turnout_after_the_fork)
{
    const int nEpoch = Epoch(20);
    const int nBoundary = Boundary(nEpoch);
    const uint256 hashA(21), hashPrev(22);

    for (int nCase = 0; nCase < 3; nCase++)
    {
        // 0: pre-fork; 1: post-fork with a heavy prior epoch; 2: heavy epoch outside lookback.
        MergesetAt fork(nCase == 0 ? PRIVACY_VNEXT_HEIGHT_UNSET : Boundary(nEpoch - 15));
        const int nHeavyEpoch = nCase == 2 ? nEpoch - FINALITY_QUORUM_LOOKBACK_EPOCHS - 1 : nEpoch - 1;
        CFinalityTracker tracker;
        BOOST_REQUIRE(tracker.AddVote(SignedVote(NewKey(), nHeavyEpoch, hashPrev,
                                                 Boundary(nHeavyEpoch), 5000 * COIN), false, true));
        BOOST_REQUIRE(tracker.AddVote(SignedVote(NewKey(), nHeavyEpoch, hashPrev,
                                                 Boundary(nHeavyEpoch), 5000 * COIN), false, true));
        std::vector<CFinalityVote> votes;
        votes.push_back(SignedVote(NewKey(), nEpoch, hashA, nBoundary, 2000 * COIN));
        votes.push_back(SignedVote(NewKey(), nEpoch, hashA, nBoundary, 2000 * COIN));
        for (const CFinalityVote& v : votes)
            BOOST_REQUIRE(tracker.AddVote(v, false, true));

        const int64_t nRef = tracker.GetFinalityQuorumReference(nEpoch, false);
        BOOST_CHECK_EQUAL(nRef, nCase == 1 ? 10000 * COIN : 0);

        int nTier = 0, nHeight = 0, nVoters = 0;
        uint256 hashWinner;
        CFinalityTallyCertificate noCert;
        BOOST_REQUIRE(tracker.ComputeDeterministicEpochTier(nEpoch, false, noCert, nTier,
                                                            hashWinner, nHeight, nVoters));
        BOOST_CHECK_EQUAL(nTier, nCase == 1 ? FINALITY_SOFT : FINALITY_HARD);

        CFinalityTallyCertificate cert;
        std::string strError;
        BOOST_REQUIRE_MESSAGE(BuildCanonicalTransparentFinalityCertificate(
                                  votes, cert, &strError, 0, nRef,
                                  tracker.GetTransparentVoterUnits(nEpoch, votes)), strError);
        BOOST_CHECK_EQUAL(cert.nTier, nCase == 1 ? FINALITY_SOFT : FINALITY_HARD);
    }
}

BOOST_AUTO_TEST_CASE(equivocation_evidence_is_self_proving)
{
    const int nEpoch = Epoch(6);
    const int nBoundary = Boundary(nEpoch);
    MergesetAt fork(nBoundary);
    CKey key = NewKey(), other = NewKey();
    const CFinalityVote v1 = SignedVote(key, nEpoch, uint256(31), nBoundary);
    const CFinalityVote v2 = SignedVote(key, nEpoch, uint256(32), nBoundary);

    CFinalityEquivocationEvidence ev;
    BOOST_REQUIRE(ev.FromVotes(v2, v1));
    BOOST_CHECK(ev.voteA.hashBlock < ev.voteB.hashBlock);
    CKeyID keyID;
    BOOST_REQUIRE(ev.GetKeyID(keyID));
    BOOST_CHECK(keyID == key.GetPubKey().GetID());

    CFinalityEquivocationEvidence same;
    BOOST_CHECK(!same.FromVotes(v1, v1));
    CFinalityEquivocationEvidence twoKeys;
    BOOST_CHECK(!twoKeys.FromVotes(v1, SignedVote(other, nEpoch, uint256(32), nBoundary)));
    CFinalityEquivocationEvidence offBoundary;
    BOOST_CHECK(!offBoundary.FromVotes(v1, SignedVote(key, nEpoch, uint256(32), nBoundary + 1)));

    CFinalityEquivocationEvidence badSig = ev;
    badSig.voteB.nTime++;
    BOOST_CHECK(!badSig.IsValid());

    // Script round trip through a coinbase.
    CScript script;
    BOOST_REQUIRE(BuildFinalityEquivocationScript(ev, script));
    CBlock block;
    CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.push_back(CTxOut(0, script));
    block.vtx.push_back(coinbase);
    std::vector<CFinalityEquivocationEvidence> vOut;
    BOOST_REQUIRE(ExtractFinalityEquivocationEvidenceFromBlockForHeight(block, nBoundary + 1, vOut));
    BOOST_REQUIRE_EQUAL(vOut.size(), 1u);
    BOOST_CHECK(vOut[0].IsValid());
    // Pre-fork the carrier is plain data.
    BOOST_REQUIRE(ExtractFinalityEquivocationEvidenceFromBlockForHeight(block, nBoundary - 1, vOut));
    BOOST_CHECK(vOut.empty());
    // Post-fork a malformed carrier invalidates the block.
    CScript junk;
    std::vector<unsigned char> vch(FINALITY_EQUIVOCATION_TAG, FINALITY_EQUIVOCATION_TAG + 4);
    vch.push_back(0x01);
    junk << OP_RETURN << vch;
    block.vtx[0].vout.push_back(CTxOut(0, junk));
    BOOST_CHECK(!ExtractFinalityEquivocationEvidenceFromBlockForHeight(block, nBoundary + 1, vOut));
}

BOOST_AUTO_TEST_CASE(equivocation_evidence_block_rule)
{
    const int nEpoch = Epoch(7);
    const int nBoundary = Boundary(nEpoch);
    CKey key = NewKey();
    CFinalityEquivocationEvidence ev;
    {
        MergesetAt fork(nBoundary);
        BOOST_REQUIRE(ev.FromVotes(SignedVote(key, nEpoch, uint256(41), nBoundary),
                                   SignedVote(key, nEpoch, uint256(42), nBoundary)));
        std::vector<CFinalityEquivocationEvidence> v(1, ev);
        std::string strError;
        BOOST_CHECK_MESSAGE(CheckFinalityEquivocationEvidenceForBlock(v, nBoundary, &strError), strError);
        const int nClose = GetFinalityVoteSetCloseOffset(nBoundary);
        BOOST_CHECK(CheckFinalityEquivocationEvidenceForBlock(v, nBoundary + nClose - 1));
        BOOST_CHECK(!CheckFinalityEquivocationEvidenceForBlock(v, nBoundary + nClose));
        BOOST_CHECK(!CheckFinalityEquivocationEvidenceForBlock(v, nBoundary - 1));
        v.push_back(ev);
        BOOST_CHECK(!CheckFinalityEquivocationEvidenceForBlock(v, nBoundary));
    }
    {
        // Evidence about an epoch that predates the fork is never valid.
        MergesetAt fork(nBoundary + 1);
        std::vector<CFinalityEquivocationEvidence> v(1, ev);
        BOOST_CHECK(!CheckFinalityEquivocationEvidenceForBlock(v, nBoundary + 2));
    }
}

BOOST_AUTO_TEST_CASE(excluded_equivocator_forfeits_its_settlement_share)
{
    const int nEpoch = Epoch(8);
    const int nBoundary = Boundary(nEpoch);
    MergesetAt fork(nBoundary);
    CFinalityVote honest = SignedVote(NewKey(), nEpoch, uint256(51), nBoundary);
    CFinalityVote cheat = SignedVote(NewKey(), nEpoch, uint256(51), nBoundary);
    honest.nReward = cheat.nReward = 1;
    std::vector<CFinalityVote> votes;
    votes.push_back(honest);
    votes.push_back(cheat);
    std::set<CKeyID> setExcluded;
    setExcluded.insert(KeyIDOf(cheat));
    FilterFinalitySettlementVotes(votes, setExcluded);
    BOOST_REQUIRE_EQUAL(votes.size(), 1u);
    BOOST_CHECK(votes[0].nullifier == honest.nullifier);

    std::vector<CTxOut> vOut;
    int64_t nTotal = 0;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(BuildFinalitySettlementOutputs(votes, 10 * COIN, vOut, nTotal, &strError), strError);
    BOOST_REQUIRE_EQUAL(vOut.size(), 1u);
    BOOST_CHECK(vOut[0].scriptPubKey == GetScriptForDestination(KeyIDOf(honest)));
    BOOST_CHECK_EQUAL(nTotal, 10 * COIN);

    // An empty exclusion set changes nothing.
    std::vector<CFinalityVote> both;
    both.push_back(honest);
    both.push_back(cheat);
    FilterFinalitySettlementVotes(both, std::set<CKeyID>());
    BOOST_CHECK_EQUAL(both.size(), 2u);
}

BOOST_AUTO_TEST_CASE(conflicting_relay_vote_becomes_pending_evidence)
{
    const int nEpoch = Epoch(9);
    const int nBoundary = Boundary(nEpoch);
    CKey key = NewKey();
    const CFinalityVote v1 = SignedVote(key, nEpoch, uint256(61), nBoundary);
    const CFinalityVote v2 = SignedVote(key, nEpoch, uint256(62), nBoundary);
    for (int fFork = 0; fFork < 2; fFork++)
    {
        MergesetAt fork(fFork ? nBoundary : PRIVACY_VNEXT_HEIGHT_UNSET);
        CFinalityTracker tracker;
        BOOST_REQUIRE(tracker.AddVote(v1, false, true));
        BOOST_CHECK(!tracker.AddVote(v2, false, false));
        std::vector<CFinalityEquivocationEvidence> vEv =
            tracker.GetPendingEquivocationEvidenceForBlock(nBoundary + 3);
        BOOST_CHECK_EQUAL(vEv.size(), fFork ? 1u : 0u);
        if (fFork)
        {
            BOOST_CHECK(tracker.GetPendingEquivocationEvidenceForBlock(
                nBoundary + GetFinalityVoteSetCloseOffset(nBoundary)).empty());
            tracker.MarkEquivocationEvidenceCarried(vEv);
            BOOST_CHECK(tracker.GetPendingEquivocationEvidenceForBlock(nBoundary + 3).empty());
        }
    }
}

namespace {
CFinalityEquivocationEvidence EvidenceFor(const CKey& key, int nEpoch, uint32_t nSalt)
{
    CFinalityEquivocationEvidence ev;
    const int nBoundary = Boundary(nEpoch);
    BOOST_REQUIRE(ev.FromVotes(SignedVote(key, nEpoch, uint256(nSalt), nBoundary),
                               SignedVote(key, nEpoch, uint256(nSalt + 1), nBoundary)));
    return ev;
}
size_t PendingCount(const CFinalityTracker& t) { size_t p, c; t.GetEquivocationEvidenceCounts(p, c); return p; }
size_t CarriedCount(const CFinalityTracker& t) { size_t p, c; t.GetEquivocationEvidenceCounts(p, c); return c; }
}

BOOST_AUTO_TEST_CASE(carried_evidence_returns_to_pending_on_disconnect)
{
    const int nEpoch = Epoch(11);
    const int nBoundary = Boundary(nEpoch);
    MergesetAt fork(nBoundary);
    const int nClose = GetFinalityVoteSetCloseOffset(nBoundary);
    CFinalityTracker tracker;
    const CFinalityEquivocationEvidence ev = EvidenceFor(NewKey(), nEpoch, 71);
    tracker.AddPendingEquivocationEvidence(ev);
    std::vector<CFinalityEquivocationEvidence> vEv = tracker.GetPendingEquivocationEvidenceForBlock(nBoundary + 2);
    BOOST_REQUIRE_EQUAL(vEv.size(), 1u);

    const uint256 hashA(0xA1u), hashB(0xB1u);
    tracker.MarkEquivocationEvidenceCarried(vEv, hashA);
    BOOST_CHECK(tracker.GetPendingEquivocationEvidenceForBlock(nBoundary + 2).empty());
    tracker.AddPendingEquivocationEvidence(ev);   // relay re-offer of carried evidence
    BOOST_CHECK_EQUAL(PendingCount(tracker), 0u);

    // Another block's disconnect leaves it carried.
    tracker.ReturnCarriedEquivocationEvidence(hashB, nBoundary + 2);
    BOOST_CHECK_EQUAL(CarriedCount(tracker), 1u);

    // Its carrier disconnects inside the window: minable again on the new branch.
    tracker.ReturnCarriedEquivocationEvidence(hashA, nBoundary + 2);
    BOOST_CHECK_EQUAL(CarriedCount(tracker), 0u);
    BOOST_CHECK_EQUAL(tracker.GetPendingEquivocationEvidenceForBlock(nBoundary + 2).size(), 1u);

    // Carrier disconnects after the window closed: nothing left to mine.
    tracker.MarkEquivocationEvidenceCarried(vEv, hashB);
    tracker.ReturnCarriedEquivocationEvidence(hashB, nBoundary + nClose);
    BOOST_CHECK_EQUAL(PendingCount(tracker), 0u);
    BOOST_CHECK_EQUAL(CarriedCount(tracker), 0u);
}

BOOST_AUTO_TEST_CASE(abort_restore_reoffers_carried_evidence)
{
    const int nEpoch = Epoch(12);
    const int nBoundary = Boundary(nEpoch);
    MergesetAt fork(nBoundary);
    CFinalityTracker tracker;
    tracker.AddPendingEquivocationEvidence(EvidenceFor(NewKey(), nEpoch, 81));
    tracker.MarkEquivocationEvidenceCarried(tracker.GetPendingEquivocationEvidenceForBlock(nBoundary + 1),
                                            uint256(0xC3u));
    BOOST_REQUIRE_EQUAL(CarriedCount(tracker), 1u);
    BOOST_REQUIRE(tracker.RestoreCommittedStateAfterAbort());
    BOOST_CHECK_EQUAL(CarriedCount(tracker), 0u);
    BOOST_CHECK_EQUAL(tracker.GetPendingEquivocationEvidenceForBlock(nBoundary + 1).size(), 1u);
}

BOOST_AUTO_TEST_CASE(pending_evidence_prunes_and_evicts_oldest)
{
    const int nEpoch = Epoch(13);
    MergesetAt fork(Boundary(nEpoch));
    CFinalityTracker tracker;
    tracker.SetMaxPendingEquivocationEvidence(2);
    CKey key = NewKey();
    const CFinalityEquivocationEvidence ev0 = EvidenceFor(key, nEpoch, 91);
    const CFinalityEquivocationEvidence ev1 = EvidenceFor(key, nEpoch + 1, 93);
    const CFinalityEquivocationEvidence ev2 = EvidenceFor(key, nEpoch + 2, 95);
    tracker.AddPendingEquivocationEvidence(ev0);
    tracker.AddPendingEquivocationEvidence(ev1);
    tracker.AddPendingEquivocationEvidence(ev2);   // full: evicts epoch nEpoch
    BOOST_CHECK_EQUAL(PendingCount(tracker), 2u);
    BOOST_CHECK(tracker.GetPendingEquivocationEvidenceForBlock(Boundary(nEpoch) + 1).empty());
    BOOST_CHECK_EQUAL(tracker.GetPendingEquivocationEvidenceForBlock(Boundary(nEpoch + 2) + 1).size(), 1u);
    tracker.AddPendingEquivocationEvidence(ev0);   // older than everything held: refused
    BOOST_CHECK(tracker.GetPendingEquivocationEvidenceForBlock(Boundary(nEpoch) + 1).empty());

    tracker.MarkEquivocationEvidenceCarried(std::vector<CFinalityEquivocationEvidence>(1, ev1), uint256(1));
    BOOST_CHECK_EQUAL(PendingCount(tracker), 1u);
    BOOST_CHECK_EQUAL(CarriedCount(tracker), 1u);

    // Epoch rollover prunes both maps below the window.
    tracker.PruneOldEpochs(nEpoch + 2 + 10);
    BOOST_CHECK_EQUAL(PendingCount(tracker), 1u);
    BOOST_CHECK_EQUAL(CarriedCount(tracker), 0u);
    tracker.PruneOldEpochs(nEpoch + 3 + 10);
    BOOST_CHECK_EQUAL(PendingCount(tracker), 0u);
}

BOOST_AUTO_TEST_CASE(side_block_evidence_is_not_canonical)
{
    // Evidence in a merged side block never reaches the extractor: ConnectBlock reads the
    // canonical block only, so the evidence stays pending for a canonical carrier.
    const int nEpoch = Epoch(14);
    const int nBoundary = Boundary(nEpoch);
    for (int fFork = 0; fFork < 2; fFork++)
    {
        MergesetAt fork(fFork ? nBoundary : PRIVACY_VNEXT_HEIGHT_UNSET);
        CKey key = NewKey();
        CFinalityEquivocationEvidence ev;
        BOOST_REQUIRE(ev.FromVotes(SignedVote(key, nEpoch, uint256(101), nBoundary),
                                   SignedVote(key, nEpoch, uint256(102), nBoundary)));
        CScript script;
        BOOST_REQUIRE(BuildFinalityEquivocationScript(ev, script));
        CTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        CBlock canonical, side;
        canonical.vtx.push_back(coinbase);
        coinbase.vout.push_back(CTxOut(0, script));
        side.vtx.push_back(coinbase);

        std::vector<CFinalityEquivocationEvidence> vCanon, vSide;
        BOOST_REQUIRE(ExtractFinalityEquivocationEvidenceFromBlockForHeight(canonical, nBoundary + 1, vCanon));
        BOOST_REQUIRE(ExtractFinalityEquivocationEvidenceFromBlockForHeight(side, nBoundary + 1, vSide));
        BOOST_CHECK(vCanon.empty());
        BOOST_CHECK_EQUAL(vSide.size(), fFork ? 1u : 0u);

        CFinalityTracker tracker;
        tracker.AddPendingEquivocationEvidence(ev);
        tracker.MarkEquivocationEvidenceCarried(vCanon, uint256(0xD1u));
        BOOST_CHECK_EQUAL(tracker.GetPendingEquivocationEvidenceForBlock(nBoundary + 1).size(),
                          fFork ? 1u : 0u);
    }
}

BOOST_AUTO_TEST_CASE(quorum_reference_and_exclusion_are_order_independent)
{
    const int nEpoch = Epoch(30);
    MergesetAt fork(Boundary(nEpoch - 12));
    std::vector<CFinalityVote> votes;
    for (int e = nEpoch - 4; e < nEpoch; e++)
        for (int i = 0; i < 3; i++)
            votes.push_back(SignedVote(NewKey(), e, uint256(200 + e), Boundary(e), (1000 + 500 * i) * COIN));
    CFinalityTracker a, b;
    for (size_t i = 0; i < votes.size(); i++)
        BOOST_REQUIRE(a.AddVote(votes[i], false, true));
    for (size_t i = votes.size(); i-- > 0; )
        BOOST_REQUIRE(b.AddVote(votes[i], false, true));
    BOOST_CHECK_EQUAL(a.GetFinalityQuorumReference(nEpoch, false), 4500 * COIN);
    BOOST_CHECK_EQUAL(a.GetFinalityQuorumReference(nEpoch, false), b.GetFinalityQuorumReference(nEpoch, false));
    BOOST_CHECK_EQUAL(a.GetFinalityQuorumReference(nEpoch, true), b.GetFinalityQuorumReference(nEpoch, true));

    std::set<CKeyID> setExcluded;
    setExcluded.insert(KeyIDOf(votes[1]));
    std::vector<CFinalityVote> fwd(votes.begin(), votes.begin() + 3), rev(fwd.rbegin(), fwd.rend());
    FilterFinalitySettlementVotes(fwd, setExcluded);
    FilterFinalitySettlementVotes(rev, setExcluded);
    BOOST_REQUIRE_EQUAL(fwd.size(), 2u);
    BOOST_REQUIRE_EQUAL(rev.size(), 2u);
    std::set<uint256> sf, sr;
    for (size_t i = 0; i < 2; i++) { sf.insert(fwd[i].nullifier); sr.insert(rev[i].nullifier); }
    BOOST_CHECK(sf == sr);
}

BOOST_AUTO_TEST_CASE(quorum_reference_collapses_after_lookback)
{
    // A turnout drop holds HARD back for at most FINALITY_QUORUM_LOOKBACK_EPOCHS epochs.
    const int nEpoch = Epoch(40);
    const int nBoundary = Boundary(nEpoch);
    MergesetAt fork(Boundary(nEpoch - 15));
    for (int nAgo = 1; nAgo <= FINALITY_QUORUM_LOOKBACK_EPOCHS + 1; nAgo++)
    {
        CFinalityTracker tracker;
        const int nHeavy = nEpoch - nAgo;
        for (int i = 0; i < 2; i++)
            BOOST_REQUIRE(tracker.AddVote(SignedVote(NewKey(), nHeavy, uint256(300), Boundary(nHeavy), 5000 * COIN),
                                          false, true));
        for (int i = 0; i < 2; i++)
            BOOST_REQUIRE(tracker.AddVote(SignedVote(NewKey(), nEpoch, uint256(301), nBoundary, 2000 * COIN),
                                          false, true));
        const bool fInLookback = nAgo <= FINALITY_QUORUM_LOOKBACK_EPOCHS;
        BOOST_CHECK_EQUAL(tracker.GetFinalityQuorumReference(nEpoch, false), fInLookback ? 10000 * COIN : 0);
        int nTier = 0, nHeight = 0, nVoters = 0;
        uint256 hashWinner;
        CFinalityTallyCertificate noCert;
        BOOST_REQUIRE(tracker.ComputeDeterministicEpochTier(nEpoch, false, noCert, nTier,
                                                            hashWinner, nHeight, nVoters));
        BOOST_CHECK_EQUAL(nTier, fInLookback ? FINALITY_SOFT : FINALITY_HARD);
    }
}

BOOST_AUTO_TEST_SUITE_END()
