// Tests for the shared M-of-N committee signature helper (used by the finality
// certificate signer-set / D1.2) and the aggregate-partial content digest (D1.1).
// These are the consensus-critical building blocks of the self-governing finality
// committee: distinct in-range threshold signatures over a domain-separated digest.

#include <boost/test/unit_test.hpp>

#include "../finality.h"
#include "../key.h"
#include "../script.h"
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

// The canonical-encoding rule assumes this wallet's own signer emits low-S DER.
// If that ever stops being true, certificates this node signs would be rejected
// by the rule at the fork height, so pin it here rather than discover it live.
BOOST_AUTO_TEST_CASE(committee_signatures_this_node_produces_are_canonical)
{
    for (int i = 0; i < 64; i++)
    {
        CKey key;
        key.MakeNewKey(true);
        uint256 digest;
        for (int b = 0; b < 32; b++)
            *(digest.begin() + b) = (unsigned char)((i * 31) + b);

        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(key.Sign(digest, vchSig));
        BOOST_REQUIRE(!vchSig.empty());
        BOOST_CHECK_MESSAGE(IsDERSignature(vchSig, false),
                            "signer produced a non-DER committee signature");

        const unsigned int nLenR = vchSig[3];
        BOOST_REQUIRE(vchSig.size() >= (size_t)6 + nLenR);
        const unsigned int nLenS = vchSig[5 + nLenR];
        BOOST_REQUIRE(vchSig.size() >= (size_t)6 + nLenR + nLenS);
        BOOST_CHECK_MESSAGE(CKey::CheckSignatureElement(&vchSig[6 + nLenR], nLenS, true),
                            "signer produced a high-S committee signature");

        BOOST_CHECK(key.GetPubKey().Verify(digest, vchSig));
    }
}

BOOST_AUTO_TEST_SUITE_END()
