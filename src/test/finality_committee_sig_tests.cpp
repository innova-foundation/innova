// Tests for the shared M-of-N committee signature helper (used by the finality
// certificate signer-set / D1.2) and the aggregate-partial content digest (D1.1).
// These are the consensus-critical building blocks of the self-governing finality
// committee: distinct in-range threshold signatures over a domain-separated digest.

#include <boost/test/unit_test.hpp>

#include "../finality.h"
#include "../key.h"
#include "../txdb.h"

#include <algorithm>
#include <vector>

namespace {

// N independent committee keypairs; pubkeys in committee-index order.
struct Committee
{
    std::vector<CKey> keys;
    std::vector<CPubKey> pubs;
    explicit Committee(int n)
    {
        for (int i = 0; i < n; i++)
        {
            CKey k;
            k.MakeNewKey(true); // compressed
            keys.push_back(k);
            pubs.push_back(k.GetPubKey());
        }
    }
};

uint256 SomeDigest(const char* s)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string(s);
    return ss.GetHash();
}

struct ScopedCommitteeBlockIndex
{
    uint256 hashBlock;
    CBlockIndex index;
    CBlockIndex* pOld;
    bool fHadOld;

    ScopedCommitteeBlockIndex(const uint256& hashBlockIn, int nHeight)
        : hashBlock(hashBlockIn), pOld(NULL), fHadOld(false)
    {
        std::map<uint256, CBlockIndex*>::iterator old =
            mapBlockIndex.find(hashBlock);
        if (old != mapBlockIndex.end())
        {
            fHadOld = true;
            pOld = old->second;
        }
        index.nHeight = nHeight;
        index.nFlags = 0;
        mapBlockIndex[hashBlock] = &index;
        index.phashBlock = &mapBlockIndex.find(hashBlock)->first;
    }

    ~ScopedCommitteeBlockIndex()
    {
        if (fHadOld)
            mapBlockIndex[hashBlock] = pOld;
        else
            mapBlockIndex.erase(hashBlock);
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(finality_committee_sig_tests)

BOOST_AUTO_TEST_CASE(accepts_exactly_m_distinct_valid_signatures)
{
    Committee c(5);
    const int M = 3;
    uint256 digest = SomeDigest("tally-cert-digest");

    // Members 0,2,4 sign (ascending, distinct).
    std::vector<uint16_t> idx = {0, 2, 4};
    std::vector<std::vector<unsigned char> > sigs(idx.size());
    for (size_t k = 0; k < idx.size(); k++)
        BOOST_REQUIRE(c.keys[idx[k]].Sign(digest, sigs[k]));

    std::string err;
    BOOST_CHECK(VerifyMofNCommitteeSignatures(c.pubs, M, idx, sigs, digest, &err));
}

BOOST_AUTO_TEST_CASE(rejects_sub_threshold)
{
    Committee c(5);
    const int M = 3;
    uint256 digest = SomeDigest("d");
    std::vector<uint16_t> idx = {0, 1};            // only 2 < M=3
    std::vector<std::vector<unsigned char> > sigs(idx.size());
    for (size_t k = 0; k < idx.size(); k++)
        BOOST_REQUIRE(c.keys[idx[k]].Sign(digest, sigs[k]));
    BOOST_CHECK(!VerifyMofNCommitteeSignatures(c.pubs, M, idx, sigs, digest, NULL));
}

BOOST_AUTO_TEST_CASE(rejects_duplicate_or_unsorted_index)
{
    Committee c(5);
    const int M = 3;
    uint256 digest = SomeDigest("d");

    // duplicate index 1,1,2
    {
        std::vector<uint16_t> idx = {1, 1, 2};
        std::vector<std::vector<unsigned char> > sigs(idx.size());
        for (size_t k = 0; k < idx.size(); k++)
            BOOST_REQUIRE(c.keys[idx[k]].Sign(digest, sigs[k]));
        BOOST_CHECK(!VerifyMofNCommitteeSignatures(c.pubs, M, idx, sigs, digest, NULL));
    }
    // descending / non-ascending 2,1,0
    {
        std::vector<uint16_t> idx = {2, 1, 0};
        std::vector<std::vector<unsigned char> > sigs(idx.size());
        for (size_t k = 0; k < idx.size(); k++)
            BOOST_REQUIRE(c.keys[idx[k]].Sign(digest, sigs[k]));
        BOOST_CHECK(!VerifyMofNCommitteeSignatures(c.pubs, M, idx, sigs, digest, NULL));
    }
}

BOOST_AUTO_TEST_CASE(rejects_out_of_range_index)
{
    Committee c(5);
    uint256 digest = SomeDigest("d");
    std::vector<uint16_t> idx = {0, 2, 5};         // 5 >= N=5
    std::vector<std::vector<unsigned char> > sigs(idx.size());
    BOOST_REQUIRE(c.keys[0].Sign(digest, sigs[0]));
    BOOST_REQUIRE(c.keys[2].Sign(digest, sigs[1]));
    BOOST_REQUIRE(c.keys[0].Sign(digest, sigs[2])); // signer for the bad index
    BOOST_CHECK(!VerifyMofNCommitteeSignatures(c.pubs, 3, idx, sigs, digest, NULL));
}

BOOST_AUTO_TEST_CASE(rejects_wrong_key_or_tampered_digest)
{
    Committee c(5);
    const int M = 3;
    uint256 digest = SomeDigest("d");
    std::vector<uint16_t> idx = {0, 1, 2};
    std::vector<std::vector<unsigned char> > sigs(idx.size());
    // Sign with the WRONG keys (shifted): index 0 carries member 1's signature.
    BOOST_REQUIRE(c.keys[1].Sign(digest, sigs[0]));
    BOOST_REQUIRE(c.keys[1].Sign(digest, sigs[1]));
    BOOST_REQUIRE(c.keys[2].Sign(digest, sigs[2]));
    BOOST_CHECK(!VerifyMofNCommitteeSignatures(c.pubs, M, idx, sigs, digest, NULL));

    // Correct signatures, but verify against a different digest.
    std::vector<std::vector<unsigned char> > good(3);
    BOOST_REQUIRE(c.keys[0].Sign(digest, good[0]));
    BOOST_REQUIRE(c.keys[1].Sign(digest, good[1]));
    BOOST_REQUIRE(c.keys[2].Sign(digest, good[2]));
    BOOST_CHECK(VerifyMofNCommitteeSignatures(c.pubs, M, idx, good, digest, NULL));
    BOOST_CHECK(!VerifyMofNCommitteeSignatures(c.pubs, M, idx, good, SomeDigest("other"), NULL));
}

BOOST_AUTO_TEST_CASE(partial_content_digest_excludes_signature)
{
    // GetContentDigest() (what the source signs) must be independent of
    // vchSourceSig, so signing can't affect the digest it commits to.
    CFinalityTallyAggregatePartial p;
    p.nVersion = 3;
    p.nEpoch = 7;
    p.hashBlock = SomeDigest("blk");
    p.hashCurveRoot = SomeDigest("cr");
    p.hashNullifierRoot = SomeDigest("nr");
    p.committeeSetHash = SomeDigest("cs");
    p.nSourceIndex = 2;
    p.vTallyShareHashes.push_back(SomeDigest("share0"));
    p.vEncryptedRecipientPartials.push_back(std::vector<unsigned char>(8, 0xAB));

    uint256 d1 = p.GetContentDigest();
    p.vchSourceSig = std::vector<unsigned char>(70, 0x11);
    uint256 d2 = p.GetContentDigest();
    BOOST_CHECK(d1 == d2);

    // But GetHash() (full identity) DOES change with the signature for v3.
    uint256 h1;
    {
        CFinalityTallyAggregatePartial q = p;
        q.vchSourceSig.clear();
        h1 = q.GetHash();
    }
    BOOST_CHECK(h1 != p.GetHash());

    // Changing content changes the signed digest.
    CFinalityTallyAggregatePartial p2 = p;
    p2.nSourceIndex = 3;
    BOOST_CHECK(p2.GetContentDigest() != d1);
}

// --- D2 certificate signer-set (CheckTallyCertificateCommitteeSignatures) ---

namespace {
CFinalityTallyCertificate MakeSignedCert(const Committee& c, int M,
                                         const std::vector<uint16_t>& signers,
                                         const uint256& setHash)
{
    CFinalityTallyCertificate cert;
    cert.nVersion = 3;
    cert.nEpoch = 2;
    cert.nHeight = 600;
    cert.hashBlock = SomeDigest("winblk");
    cert.nTier = FINALITY_HARD;
    cert.hashCurveRoot = SomeDigest("cr");
    cert.hashNullifierRoot = SomeDigest("nr");
    cert.committeeSetHash = setHash;
    cert.vVoteNullifiers.push_back(SomeDigest("vn"));
    cert.vTallyShareHashes.push_back(SomeDigest("sh"));
    cert.vSignerIndexes = signers;
    uint256 digest = cert.GetSignatureDigest();
    for (size_t k = 0; k < signers.size(); k++)
    {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(c.keys[signers[k]].Sign(digest, sig));
        cert.vSignerSigs.push_back(sig);
    }
    (void)M;
    return cert;
}
} // namespace

BOOST_AUTO_TEST_CASE(cert_signer_set_accepts_threshold_and_rejects_tamper)
{
    Committee c(5);
    const int M = 3;
    uint256 setHash = ComputeFinalityTallyCommitteeHash(M, c.pubs);

    CFinalityTallyCertificate cert = MakeSignedCert(c, M, {0, 2, 4}, setHash);
    std::string err;
    BOOST_CHECK(CheckTallyCertificateCommitteeSignatures(cert, c.pubs, M, setHash, &err));

    // Tamper a signed field after signing -> digest changes -> rejected.
    CFinalityTallyCertificate tampered = cert;
    tampered.nTransparentActiveWeight += 1;
    BOOST_CHECK(!CheckTallyCertificateCommitteeSignatures(tampered, c.pubs, M, setHash, NULL));

    // Wrong committee-set hash -> rejected.
    BOOST_CHECK(!CheckTallyCertificateCommitteeSignatures(cert, c.pubs, M, SomeDigest("wrong"), NULL));
}

BOOST_AUTO_TEST_CASE(cert_signer_set_rejects_sub_threshold_and_pre_v3)
{
    Committee c(5);
    const int M = 3;
    uint256 setHash = ComputeFinalityTallyCommitteeHash(M, c.pubs);

    // Only 2 signers for M=3.
    CFinalityTallyCertificate sub = MakeSignedCert(c, M, {0, 1}, setHash);
    BOOST_CHECK(!CheckTallyCertificateCommitteeSignatures(sub, c.pubs, M, setHash, NULL));

    // A pre-v3 certificate must be rejected by the committee check.
    CFinalityTallyCertificate cert = MakeSignedCert(c, M, {0, 2, 4}, setHash);
    cert.nVersion = 2;
    BOOST_CHECK(!CheckTallyCertificateCommitteeSignatures(cert, c.pubs, M, setHash, NULL));
}

// --- D2 self-governing committee: rotation + canonical-set state (2c) ---

namespace {
CFinalityCommitteeRotation MakeRotation(const Committee& prev, const uint256& prevSetHash,
                                        int effEpoch, const Committee& next, int nextM,
                                        const std::vector<uint16_t>& signers)
{
    CFinalityCommitteeRotation rot;
    rot.nVersion = 1;
    rot.nEffectiveEpoch = effEpoch;
    rot.hashPrevCommitteeSet = prevSetHash;
    rot.nNewThresholdM = (uint8_t)nextM;
    for (size_t i = 0; i < next.pubs.size(); i++)
        rot.vNewPubKeys.push_back(std::vector<unsigned char>(next.pubs[i].begin(), next.pubs[i].end()));
    rot.vSignerIndexes = signers;
    uint256 digest = rot.GetSignatureDigest();
    for (size_t k = 0; k < signers.size(); k++)
    {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(prev.keys[signers[k]].Sign(digest, sig));
        rot.vSignerSigs.push_back(sig);
    }
    return rot;
}
} // namespace

BOOST_AUTO_TEST_CASE(rotation_advances_canonical_committee)
{
    Committee initial(5);
    Committee next(3);
    const int M0 = 3, M1 = 2;
    uint256 set0 = ComputeFinalityTallyCommitteeHash(M0, initial.pubs);
    uint256 set1 = ComputeFinalityTallyCommitteeHash(M1, next.pubs);

    CFinalityTracker tracker;
    tracker.SetInitialFinalityCommittee(initial.pubs, M0);

    // Before any rotation, every epoch resolves to the initial set.
    std::vector<CPubKey> v; int m; uint256 sh;
    BOOST_REQUIRE(tracker.GetCommitteeForEpoch(9, v, m, sh));
    BOOST_CHECK(sh == set0 && m == M0 && v.size() == 5);

    CFinalityCommitteeRotation rot = MakeRotation(initial, set0, 10, next, M1, {0, 2, 4});
    std::string err;
    BOOST_CHECK_MESSAGE(tracker.ConnectCommitteeRotation(rot, &err), err);

    // Before the effective epoch: still the initial set; at/after: the new set.
    BOOST_REQUIRE(tracker.GetCommitteeForEpoch(9, v, m, sh));
    BOOST_CHECK(sh == set0);
    BOOST_REQUIRE(tracker.GetCommitteeForEpoch(10, v, m, sh));
    BOOST_CHECK(sh == set1 && m == M1 && v.size() == 3);
    BOOST_REQUIRE(tracker.GetCommitteeForEpoch(50, v, m, sh));
    BOOST_CHECK(sh == set1);
}

BOOST_AUTO_TEST_CASE(rotation_rejects_sub_threshold_and_wrong_prev_set)
{
    Committee initial(5);
    Committee next(3);
    const int M0 = 3;
    uint256 set0 = ComputeFinalityTallyCommitteeHash(M0, initial.pubs);

    CFinalityTracker tracker;
    tracker.SetInitialFinalityCommittee(initial.pubs, M0);

    // Sub-threshold (2 signers for M0=3).
    CFinalityCommitteeRotation sub = MakeRotation(initial, set0, 10, next, 2, {0, 1});
    BOOST_CHECK(!tracker.ConnectCommitteeRotation(sub, NULL));

    // Wrong prev-set hash (does not chain).
    CFinalityCommitteeRotation badPrev = MakeRotation(initial, SomeDigest("wrong"), 10, next, 2, {0, 2, 4});
    BOOST_CHECK(!tracker.ConnectCommitteeRotation(badPrev, NULL));

    // Correct one still applies.
    CFinalityCommitteeRotation good = MakeRotation(initial, set0, 10, next, 2, {0, 2, 4});
    BOOST_CHECK(tracker.ConnectCommitteeRotation(good, NULL));
}

BOOST_AUTO_TEST_CASE(rotation_a2_lowest_hash_wins_at_same_epoch)
{
    Committee initial(5);
    Committee nextA(3);
    Committee nextB(4);
    const int M0 = 3;
    uint256 set0 = ComputeFinalityTallyCommitteeHash(M0, initial.pubs);

    CFinalityTracker tracker;
    tracker.SetInitialFinalityCommittee(initial.pubs, M0);

    CFinalityCommitteeRotation a = MakeRotation(initial, set0, 10, nextA, 2, {0, 1, 2});
    CFinalityCommitteeRotation b = MakeRotation(initial, set0, 10, nextB, 3, {0, 1, 2});
    // Determine which has the lower SIGNATURE DIGEST (the malleability-free signed content, not GetHash
    // which folds in third-party-malleable signatures) — that one must win the A2 tie-break regardless of
    // connect order. Keyed on GetSignatureDigest so a re-signed variant cannot grind the outcome.
    bool aLower = (a.GetSignatureDigest() < b.GetSignatureDigest());
    uint256 winnerSet = aLower
        ? ComputeFinalityTallyCommitteeHash(2, nextA.pubs)
        : ComputeFinalityTallyCommitteeHash(3, nextB.pubs);

    // Connect the higher-hash one first, then the lower-hash one.
    if (aLower) { BOOST_CHECK(tracker.ConnectCommitteeRotation(b, NULL)); BOOST_CHECK(tracker.ConnectCommitteeRotation(a, NULL)); }
    else        { BOOST_CHECK(tracker.ConnectCommitteeRotation(a, NULL)); BOOST_CHECK(tracker.ConnectCommitteeRotation(b, NULL)); }

    std::vector<CPubKey> v; int m; uint256 sh;
    BOOST_REQUIRE(tracker.GetCommitteeForEpoch(10, v, m, sh));
    BOOST_CHECK(sh == winnerSet);

    // Disconnect removes the rotation -> back to the initial set.
    tracker.DisconnectCommitteeRotation(10);
    BOOST_REQUIRE(tracker.GetCommitteeForEpoch(10, v, m, sh));
    BOOST_CHECK(sh == set0);
}

BOOST_AUTO_TEST_CASE(rotation_v3_uses_canonical_carrier_order_without_reinterpreting_legacy)
{
    Committee initial(5);
    Committee nextA(3);
    Committee nextB(4);
    const uint256 set0 = ComputeFinalityTallyCommitteeHash(3, initial.pubs);
    const CFinalityCommitteeRotation a =
        MakeRotation(initial, set0, 10, nextA, 2, {0, 1, 2});
    const CFinalityCommitteeRotation b =
        MakeRotation(initial, set0, 10, nextB, 3, {0, 1, 2});
    const CFinalityCommitteeRotation lower =
        a.GetSignatureDigest() < b.GetSignatureDigest() ? a : b;
    const CFinalityCommitteeRotation higher =
        a.GetSignatureDigest() < b.GetSignatureDigest() ? b : a;
    const int nV3Height = 1000;

    // With V3-only carriers, canonical block position wins even when the first
    // carrier advertises the higher content digest. Input vector order is not
    // part of the result.
    std::vector<CFinalityCommitteeRotationCarrier> vV3;
    vV3.push_back(CFinalityCommitteeRotationCarrier(
        nV3Height + 2, uint256(0xB002), lower));
    vV3.push_back(CFinalityCommitteeRotationCarrier(
        nV3Height + 1, uint256(0xB001), higher));
    CFinalityCommitteeRotation winner;
    uint256 hashCarrier;
    BOOST_REQUIRE(SelectCanonicalFinalityCommitteeRotation(
        vV3, nV3Height, winner, &hashCarrier));
    BOOST_CHECK(winner.GetSignatureDigest() == higher.GetSignatureDigest());
    BOOST_CHECK(hashCarrier == uint256(0xB001));
    std::reverse(vV3.begin(), vV3.end());
    BOOST_REQUIRE(SelectCanonicalFinalityCommitteeRotation(
        vV3, nV3Height, winner, &hashCarrier));
    BOOST_CHECK(winner.GetSignatureDigest() == higher.GetSignatureDigest());

    // Crossing V3 must not reinterpret a winner already carried under the
    // historical rule. A legacy carrier remains authoritative over a later V3
    // competitor, while two legacy carriers still resolve by lowest digest.
    std::vector<CFinalityCommitteeRotationCarrier> vMixed;
    vMixed.push_back(CFinalityCommitteeRotationCarrier(
        nV3Height - 1, uint256(0xA001), higher));
    vMixed.push_back(CFinalityCommitteeRotationCarrier(
        nV3Height + 1, uint256(0xA002), lower));
    BOOST_REQUIRE(SelectCanonicalFinalityCommitteeRotation(
        vMixed, nV3Height, winner, NULL));
    BOOST_CHECK(winner.GetSignatureDigest() == higher.GetSignatureDigest());

    vMixed.push_back(CFinalityCommitteeRotationCarrier(
        nV3Height - 2, uint256(0xA000), lower));
    BOOST_REQUIRE(SelectCanonicalFinalityCommitteeRotation(
        vMixed, nV3Height, winner, NULL));
    BOOST_CHECK(winner.GetSignatureDigest() == lower.GetSignatureDigest());
}

BOOST_AUTO_TEST_CASE(block_rotation_v3_later_lower_digest_is_retained_as_noop)
{
    Committee initial(5);
    Committee nextA(3);
    Committee nextB(4);
    const uint256 set0 = ComputeFinalityTallyCommitteeHash(3, initial.pubs);
    const int nFirstHeight = FORK_HEIGHT_EPOCH_STATE_V3;
    BOOST_REQUIRE(nFirstHeight < TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET);
    const int nSecondHeight = nFirstHeight + 1;
    const int nEffectiveEpoch =
        std::max(GetEpochForHeight(nFirstHeight),
                 GetEpochForHeight(nSecondHeight)) + 1;
    const CFinalityCommitteeRotation a =
        MakeRotation(initial, set0, nEffectiveEpoch, nextA, 2, {0, 1, 2});
    const CFinalityCommitteeRotation b =
        MakeRotation(initial, set0, nEffectiveEpoch, nextB, 3, {0, 1, 2});
    const CFinalityCommitteeRotation lower =
        a.GetSignatureDigest() < b.GetSignatureDigest() ? a : b;
    const CFinalityCommitteeRotation higher =
        a.GetSignatureDigest() < b.GetSignatureDigest() ? b : a;

    CFinalityTracker tracker;
    tracker.SetInitialFinalityCommittee(initial.pubs, 3);
    CTxDB txdb("rw");
    BOOST_REQUIRE(txdb.TxnBegin());
    ScopedCommitteeBlockIndex firstCarrier(uint256(0xC001),
                                            nFirstHeight);
    BOOST_REQUIRE(tracker.ConnectBlockCommitteeRotations(
        txdb, uint256(0xC001),
        std::vector<CFinalityCommitteeRotation>(1, higher), nFirstHeight));

    FinalityResult sameHeightResult = FINALITY_RESULT_OK;
    BOOST_CHECK(!tracker.ConnectBlockCommitteeRotations(
        txdb, uint256(0xC000),
        std::vector<CFinalityCommitteeRotation>(1, lower), nFirstHeight,
        &sameHeightResult));
    BOOST_CHECK_EQUAL(sameHeightResult, FINALITY_RESULT_LOCAL_STATE);
    std::map<int, CFinalityCommitteeRotation> afterRejectedCarrier =
        tracker.GetConnectedRotations();
    BOOST_REQUIRE_EQUAL(afterRejectedCarrier.size(), 1U);
    BOOST_CHECK(afterRejectedCarrier.begin()->second.GetSignatureDigest() ==
                higher.GetSignatureDigest());

    BOOST_REQUIRE(tracker.ConnectBlockCommitteeRotations(
        txdb, uint256(0xC002),
        std::vector<CFinalityCommitteeRotation>(1, lower), nSecondHeight));

    const std::map<int, CFinalityCommitteeRotation> connected =
        tracker.GetConnectedRotations();
    BOOST_REQUIRE_EQUAL(connected.size(), 1U);
    BOOST_CHECK(connected.begin()->second.GetSignatureDigest() ==
                higher.GetSignatureDigest());
    txdb.TxnAbort();
}

BOOST_AUTO_TEST_CASE(block_rotations_apply_in_effective_epoch_order)
{
    Committee initial(5);
    Committee middle(4);
    Committee finalSet(3);
    const int M0 = 3, M1 = 3, M2 = 2;
    const uint256 set0 = ComputeFinalityTallyCommitteeHash(M0, initial.pubs);
    const uint256 set1 = ComputeFinalityTallyCommitteeHash(M1, middle.pubs);
    const uint256 set2 = ComputeFinalityTallyCommitteeHash(M2, finalSet.pubs);
    CFinalityCommitteeRotation first =
        MakeRotation(initial, set0, 10, middle, M1, {0, 2, 4});
    CFinalityCommitteeRotation second =
        MakeRotation(middle, set1, 11, finalSet, M2, {0, 1, 3});

    CFinalityTracker tracker;
    tracker.SetInitialFinalityCommittee(initial.pubs, M0);
    CTxDB txdb("rw");
    BOOST_REQUIRE(txdb.TxnBegin());
    std::vector<CFinalityCommitteeRotation> reversed;
    reversed.push_back(second);
    reversed.push_back(first);
    BOOST_REQUIRE(tracker.ConnectBlockCommitteeRotations(
        txdb, uint256(0xA001), reversed, GetEpochBoundaryHeight(8, FORK_HEIGHT_DAG)));

    std::vector<CPubKey> v;
    int m = 0;
    uint256 hashSet;
    BOOST_REQUIRE(tracker.GetCommitteeForEpoch(11, v, m, hashSet));
    BOOST_CHECK(hashSet == set2);
    txdb.TxnAbort();
}

BOOST_AUTO_TEST_CASE(disconnecting_predecessor_recursively_drops_rotation_orphans)
{
    Committee initial(5);
    Committee middle(4);
    Committee finalSet(3);
    const int M0 = 3, M1 = 3, M2 = 2;
    const uint256 set0 = ComputeFinalityTallyCommitteeHash(M0, initial.pubs);
    const uint256 set1 = ComputeFinalityTallyCommitteeHash(M1, middle.pubs);
    CFinalityCommitteeRotation first =
        MakeRotation(initial, set0, 10, middle, M1, {0, 2, 4});
    CFinalityCommitteeRotation dependent =
        MakeRotation(middle, set1, 11, finalSet, M2, {0, 1, 3});

    CFinalityTracker tracker;
    tracker.SetInitialFinalityCommittee(initial.pubs, M0);
    CTxDB txdb("rw");
    BOOST_REQUIRE(txdb.TxnBegin());
    std::vector<CFinalityCommitteeRotation> vFirst(1, first);
    std::vector<CFinalityCommitteeRotation> vDependent(1, dependent);
    BOOST_REQUIRE(tracker.ConnectBlockCommitteeRotations(
        txdb, uint256(0xB001), vFirst, GetEpochBoundaryHeight(8, FORK_HEIGHT_DAG)));
    BOOST_REQUIRE(tracker.ConnectBlockCommitteeRotations(
        txdb, uint256(0xB002), vDependent, GetEpochBoundaryHeight(8, FORK_HEIGHT_DAG)));
    BOOST_REQUIRE(tracker.DisconnectBlockCommitteeRotations(
        txdb, uint256(0xB001), vFirst));
    BOOST_CHECK(tracker.GetConnectedRotations().empty());
    txdb.TxnAbort();
}

BOOST_AUTO_TEST_CASE(rotation_opreturn_roundtrip)
{
    Committee initial(5);
    Committee next(3);
    uint256 set0 = ComputeFinalityTallyCommitteeHash(3, initial.pubs);
    CFinalityCommitteeRotation rot = MakeRotation(initial, set0, 12, next, 2, {0, 2, 4});

    CScript script = BuildFinalityCommitteeRotationScript(rot);
    CFinalityCommitteeRotation parsed;
    BOOST_REQUIRE(ExtractFinalityCommitteeRotation(script, parsed));
    BOOST_CHECK(parsed.GetHash() == rot.GetHash());
    BOOST_CHECK(parsed.nEffectiveEpoch == 12);
    BOOST_CHECK(parsed.hashPrevCommitteeSet == set0);

    // A non-rotation OP_RETURN must not parse as a rotation.
    CScript other;
    other << OP_RETURN << std::vector<unsigned char>{0x00, 0x01, 0x02};
    CFinalityCommitteeRotation none;
    BOOST_CHECK(!ExtractFinalityCommitteeRotation(other, none));
}

BOOST_AUTO_TEST_CASE(recovery_window_predicate_and_committee_auth)
{
    // Recovery window opens only once HARD finality lags the cert epoch by more
    // than the gap. With finalizedHeight=0 (epoch 0): window = certEpoch > GAP.
    BOOST_CHECK(!FinalityCertInRecoveryWindow(FINALITY_RECOVERY_GAP_EPOCHS, 0));
    BOOST_CHECK(!FinalityCertInRecoveryWindow(FINALITY_RECOVERY_GAP_EPOCHS - 1, 0));
    BOOST_CHECK(FinalityCertInRecoveryWindow(FINALITY_RECOVERY_GAP_EPOCHS + 1, 0));

    // A recovery committee authorizes a cert with M-of-N exactly like the
    // canonical one (same verification primitive, different pinned set).
    Committee recovery(5);
    const int M = 3;
    uint256 recSet = ComputeFinalityTallyCommitteeHash(M, recovery.pubs);
    CFinalityTallyCertificate cert = MakeSignedCert(recovery, M, {1, 2, 3}, recSet);
    BOOST_CHECK(CheckTallyCertificateCommitteeSignatures(cert, recovery.pubs, M, recSet, NULL));

    // SetRecoveryFinalityCommittee round-trips through the tracker.
    CFinalityTracker tracker;
    tracker.SetRecoveryFinalityCommittee(recovery.pubs, M);
    std::vector<CPubKey> v; int m; uint256 sh;
    BOOST_REQUIRE(tracker.GetRecoveryCommittee(v, m, sh));
    BOOST_CHECK(sh == recSet && m == M && v.size() == 5);
}

BOOST_AUTO_TEST_CASE(block_rotation_results_distinguish_invalid_and_local_state)
{
    Committee initial(5);
    Committee next(3);
    const int M0 = 3;
    const uint256 set0 = ComputeFinalityTallyCommitteeHash(M0, initial.pubs);
    const int nBlockHeight = GetEpochBoundaryHeight(8, FORK_HEIGHT_DAG);
    const CFinalityCommitteeRotation valid =
        MakeRotation(initial, set0, 10, next, 2, {0, 2, 4});
    const uint256 hashCarrier(0xFC010001);
    CTxDB txdbReadOnly("r");

    // A deterministic A2 window violation is peer-invalid even before any
    // committee state or database write is consulted.
    CFinalityCommitteeRotation outOfWindow = valid;
    outOfWindow.nEffectiveEpoch = 8;
    CFinalityTracker trackerWindow;
    FinalityResult result = FINALITY_RESULT_OK;
    BOOST_CHECK(!trackerWindow.ConnectBlockCommitteeRotations(
        txdbReadOnly, hashCarrier,
        std::vector<CFinalityCommitteeRotation>(1, outOfWindow),
        nBlockHeight, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_INVALID);

    // A valid candidate cannot be judged without the locally pinned committee.
    CFinalityTracker trackerMissing;
    result = FINALITY_RESULT_INVALID;
    BOOST_CHECK(!trackerMissing.ConnectBlockCommitteeRotations(
        txdbReadOnly, hashCarrier,
        std::vector<CFinalityCommitteeRotation>(1, valid),
        nBlockHeight, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_LOCAL_STATE);

    // Once the committee is available, a bad signature is deterministically
    // invalid, while a write failure after successful validation is local.
    CFinalityCommitteeRotation badSignature = valid;
    BOOST_REQUIRE(!badSignature.vSignerSigs.empty());
    BOOST_REQUIRE(!badSignature.vSignerSigs[0].empty());
    badSignature.vSignerSigs[0][0] ^= 0x01;
    CFinalityTracker trackerBadSig;
    trackerBadSig.SetInitialFinalityCommittee(initial.pubs, M0);
    result = FINALITY_RESULT_OK;
    BOOST_CHECK(!trackerBadSig.ConnectBlockCommitteeRotations(
        txdbReadOnly, hashCarrier,
        std::vector<CFinalityCommitteeRotation>(1, badSignature),
        nBlockHeight, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_INVALID);

    CFinalityTracker trackerWrite;
    trackerWrite.SetInitialFinalityCommittee(initial.pubs, M0);
    result = FINALITY_RESULT_INVALID;
    BOOST_CHECK(!trackerWrite.ConnectBlockCommitteeRotations(
        txdbReadOnly, hashCarrier,
        std::vector<CFinalityCommitteeRotation>(1, valid),
        nBlockHeight, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_LOCAL_STATE);
    BOOST_CHECK(trackerWrite.GetConnectedRotations().empty());
}

BOOST_AUTO_TEST_CASE(cert_signature_collection_assembles_at_threshold)
{
    // 2c-4b: M members independently sign one builder's candidate; the collected
    // signatures assemble into a complete, valid signer-set.
    Committee c(5);
    const int M = 3;
    uint256 setHash = ComputeFinalityTallyCommitteeHash(M, c.pubs);

    // Candidate cert (content fixed; signer-set empty), at the version/sethash
    // the signers will commit to.
    CFinalityTallyCertificate cand;
    cand.nVersion = 3;
    cand.nEpoch = 4;
    cand.nHeight = 1200;
    cand.hashBlock = SomeDigest("cand-blk");
    cand.nTier = FINALITY_HARD;
    cand.hashCurveRoot = SomeDigest("cr");
    cand.hashNullifierRoot = SomeDigest("nr");
    cand.committeeSetHash = setHash;
    cand.vVoteNullifiers.push_back(SomeDigest("vn"));
    cand.vTallyShareHashes.push_back(SomeDigest("sh"));
    uint256 digest = cand.GetSignatureDigest();

    // Members 4, 1, 3 sign (out of order on purpose).
    std::map<uint16_t, std::vector<unsigned char> > collected;
    for (uint16_t idx : {uint16_t(4), uint16_t(1), uint16_t(3)})
    {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(c.keys[idx].Sign(digest, sig));
        collected[idx] = sig;
    }

    CFinalityTallyCertificate assembled = cand;
    BOOST_CHECK(AssembleCertificateFromSignatures(assembled, collected, c.pubs, M, setHash));
    // Ascending order, M sigs, and verifies as a full committee cert.
    BOOST_REQUIRE_EQUAL(assembled.vSignerIndexes.size(), 3u);
    BOOST_CHECK(assembled.vSignerIndexes[0] < assembled.vSignerIndexes[1] &&
                assembled.vSignerIndexes[1] < assembled.vSignerIndexes[2]);
    BOOST_CHECK(CheckTallyCertificateCommitteeSignatures(assembled, c.pubs, M, setHash, NULL));

    // Below threshold: 2 collected -> assembly fails.
    std::map<uint16_t, std::vector<unsigned char> > two;
    two[1] = collected[1]; two[3] = collected[3];
    CFinalityTallyCertificate sub = cand;
    BOOST_CHECK(!AssembleCertificateFromSignatures(sub, two, c.pubs, M, setHash));

    // A garbage signature is filtered out (not counted toward threshold).
    std::map<uint16_t, std::vector<unsigned char> > withBad = two;
    withBad[2] = std::vector<unsigned char>(70, 0x00); // invalid sig for member 2
    CFinalityTallyCertificate badAssembled = cand;
    BOOST_CHECK(!AssembleCertificateFromSignatures(badAssembled, withBad, c.pubs, M, setHash));
}

BOOST_AUTO_TEST_SUITE_END()
