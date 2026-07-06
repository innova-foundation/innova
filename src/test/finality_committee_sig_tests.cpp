// Tests for the shared M-of-N committee signature helper (used by the finality
// certificate signer-set / D1.2) and the aggregate-partial content digest (D1.1).
// These are the consensus-critical building blocks of the self-governing finality
// committee: distinct in-range threshold signatures over a domain-separated digest.

#include <boost/test/unit_test.hpp>

#include "../finality.h"
#include "../key.h"

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
