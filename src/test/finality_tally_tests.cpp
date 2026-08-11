#include <boost/test/unit_test.hpp>

#include "../finality.h"
#include "../txdb-leveldb.h"
#include "../util.h"
#include "../zkproof.h"

#include <algorithm>
#include <string.h>

namespace
{

struct ScopedTallyArgs
{
    std::map<std::string, std::string> mapArgsSaved;
    std::map<std::string, std::vector<std::string> > mapMultiArgsSaved;

    ScopedTallyArgs()
        : mapArgsSaved(mapArgs),
          mapMultiArgsSaved(mapMultiArgs)
    {
    }

    ~ScopedTallyArgs()
    {
        mapArgs = mapArgsSaved;
        mapMultiArgs = mapMultiArgsSaved;
    }
};

struct ScopedFinalityTestnet
{
    bool fSavedRegTest;
    bool fSavedTestNet;

    ScopedFinalityTestnet()
        : fSavedRegTest(fRegTest), fSavedTestNet(fTestNet)
    {
        fRegTest = false;
        fTestNet = true;
    }

    ~ScopedFinalityTestnet()
    {
        fRegTest = fSavedRegTest;
        fTestNet = fSavedTestNet;
    }
};

struct ScopedFinalityRegtest
{
    bool fSavedRegTest;
    bool fSavedTestNet;

    ScopedFinalityRegtest()
        : fSavedRegTest(fRegTest), fSavedTestNet(fTestNet)
    {
        fRegTest = true;
        fTestNet = false;
    }

    ~ScopedFinalityRegtest()
    {
        fRegTest = fSavedRegTest;
        fTestNet = fSavedTestNet;
    }
};

std::string PubKeyHex(const CPubKey& pubkey)
{
    return HexStr(pubkey.begin(), pubkey.end());
}

uint256 TestScalarFromBytesBE(const std::vector<unsigned char>& vch)
{
    uint256 out = 0;
    unsigned char be[32];
    memset(be, 0, sizeof(be));
    size_t nCopy = std::min(vch.size(), sizeof(be));
    if (nCopy > 0)
        memcpy(be + sizeof(be) - nCopy, &vch[vch.size() - nCopy], nCopy);
    unsigned char* le = out.begin();
    for (int i = 0; i < 32; i++)
        le[i] = be[31 - i];
    return FieldReduce(out);
}

CFinalityTallyConfig BuildTestTallyConfig(std::vector<CKey>& vKeys,
                                          int nThreshold)
{
    CFinalityTallyConfig config;
    config.strMode = "committee";
    config.fModeValid = true;
    config.fEnabled = true;
    config.fThresholdValid = true;
    config.fPubKeyConfigured = true;
    config.fCommitteeValid = true;
    config.fEncryptedTallyReady = true;
    config.nThresholdM = nThreshold;
    config.nThresholdN = (int)vKeys.size();
    config.nLocalCommitteeIndex = 0;

    for (CKey& key : vKeys)
        config.vCommitteePubKeys.push_back(key.GetPubKey());
    config.committeeSetHash = ComputeFinalityTallyCommitteeHash(nThreshold,
                                                                config.vCommitteePubKeys);
    return config;
}

CFinalityTallyShare BuildEncryptedShare(const CFinalityTallyConfig& config,
                                        int64_t nWeight,
                                        int64_t nReward,
                                        const std::vector<unsigned char>& vchWeightBlind,
                                        const std::vector<unsigned char>& vchRewardBlind,
                                        int nEpoch = 101)
{
    CFinalityTallyShare share;
    share.nVersion = 2;
    share.nEpoch = nEpoch;
    share.voteNullifier = uint256(10101);
    share.hashBlock = uint256(20202);
    share.hashCurveRoot = uint256(30303);
    share.hashNullifierRoot = uint256(40404);
    share.committeeSetHash = config.committeeSetHash;
    BOOST_REQUIRE(CreatePedersenCommitment(nWeight, vchWeightBlind,
                                           share.stakeWeightCommitment));
    BOOST_REQUIRE(CreatePedersenCommitment(nReward, vchRewardBlind,
                                           share.rewardCommitment));
    CBindingSignature bindingSig;
    bindingSig.vchSignature.assign(BINDING_SIGNATURE_SIZE, 0x51);
    CDataStream ssBinding(SER_NETWORK, PROTOCOL_VERSION);
    ssBinding << bindingSig;
    share.vchShareProof.assign(ssBinding.begin(), ssBinding.end());
    BOOST_REQUIRE(BuildEncryptedFinalityTallyShares(share,
                                                    nWeight,
                                                    nReward,
                                                    vchWeightBlind,
                                                    vchRewardBlind,
                                                    config));
    return share;
}

CFinalityVote BuildPrivateVoteForShare(const CFinalityTallyShare& share)
{
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_NULLSTAKE_V2;
    vote.nEpoch = share.nEpoch;
    vote.hashBlock = share.hashBlock;
    vote.nullifier = share.voteNullifier;
    vote.privateProof.nVersion = 1;
    vote.privateProof.nProofMode = vote.nProofMode;
    vote.privateProof.nEpoch = vote.nEpoch;
    vote.privateProof.hashEpochBlock = vote.hashBlock;
    vote.privateProof.hashCurveRoot = share.hashCurveRoot;
    vote.privateProof.hashNullifierRoot = share.hashNullifierRoot;
    vote.privateProof.nullifier = vote.nullifier;
    vote.privateProof.stakeWeightCommitment = share.stakeWeightCommitment;
    vote.privateProof.rewardCommitment = share.rewardCommitment;
    vote.privateProof.vchBindingProof = share.vchShareProof;
    return vote;
}

CFinalityTallyAggregatePartial BuildEncryptedPartial(const CFinalityTallyConfig& config,
                                                     const CFinalityTallyPlainShare& aggregate,
                                                     const CKey& keySource,
                                                     const CFinalityTallyShare& share1,
                                                     const CFinalityTallyShare& share2)
{
    CFinalityTallyAggregatePartial partial;
    partial.nVersion = 2;
    partial.nEpoch = share1.nEpoch;
    partial.hashBlock = share1.hashBlock;
    partial.hashCurveRoot = share1.hashCurveRoot;
    partial.hashNullifierRoot = share1.hashNullifierRoot;
    partial.committeeSetHash = config.committeeSetHash;
    partial.vTallyShareHashes.push_back(share1.GetHash());
    partial.vTallyShareHashes.push_back(share2.GetHash());
    BOOST_REQUIRE(BuildEncryptedFinalityTallyAggregatePartial(partial,
                                                              aggregate,
                                                              config,
                                                              keySource));
    return partial;
}

std::vector<unsigned char> SerializeLegacyProofBlob()
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << (uint32_t)1;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

bool ContainsBytes(const std::vector<unsigned char>& haystack,
                   const std::vector<unsigned char>& needle)
{
    if (needle.empty())
        return true;
    return std::search(haystack.begin(), haystack.end(),
                       needle.begin(), needle.end()) != haystack.end();
}

std::vector<unsigned char> EncodeLE64(uint64_t nValue)
{
    std::vector<unsigned char> out(8, 0);
    for (int i = 0; i < 8; i++)
        out[i] = (unsigned char)((nValue >> (8 * i)) & 0xff);
    return out;
}

uint32_t ReadProofEnvelopeVersion(const std::vector<unsigned char>& vchProof)
{
    CDataStream ss(vchProof, SER_NETWORK, PROTOCOL_VERSION);
    uint32_t nVersion = 0;
    ss >> nVersion;
    return nVersion;
}

template <typename K, typename V>
bool PutRawLevelDBRecord(CTxDB& txdb, const K& key, const V& value)
{
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    ssKey << key;
    ssValue << value;
    leveldb::DB* db = txdb.GetInstance();
    return db && db->Put(leveldb::WriteOptions(), ssKey.str(),
                         ssValue.str()).ok();
}

template <typename K>
bool DeleteRawLevelDBRecord(CTxDB& txdb, const K& key)
{
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey << key;
    leveldb::DB* db = txdb.GetInstance();
    if (!db)
        return false;
    const leveldb::Status status = db->Delete(leveldb::WriteOptions(),
                                               ssKey.str());
    return status.ok() || status.IsNotFound();
}

template <typename K>
bool GetRawLevelDBRecord(CTxDB& txdb, const K& key,
                         std::string& valueOut)
{
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey << key;
    leveldb::DB* db = txdb.GetInstance();
    if (!db)
        return false;
    return db->Get(leveldb::ReadOptions(), ssKey.str(), &valueOut).ok();
}

CFinalityVote BuildTransparentVoteForTrackerTest(const CKey& key,
                                                 int64_t nTime,
                                                 int64_t nWeight)
{
    CPubKey pubkey = key.GetPubKey();
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    vote.nEpoch = 0;
    vote.nHeight = 0;
    vote.hashBlock = uint256(70707);
    vote.nTime = nTime;
    vote.nVoteWeight = nWeight;
    vote.nReward = 0;
    vote.vchPubKey.assign(pubkey.begin(), pubkey.end());
    vote.vStakeProof.push_back(COutPoint(uint256(80808), 0));

    CHashWriter ss(SER_GETHASH, 0);
    ss << vote.vchPubKey;
    ss << vote.nEpoch;
    vote.nullifier = ss.GetHash();
    return vote;
}

struct ScopedBlockIndexEntry
{
    uint256 hashBlock;
    CBlockIndex index;
    CBlockIndex* pOld;
    bool fHadOld;

    ScopedBlockIndexEntry(const uint256& hashBlockIn, int nHeight)
        : hashBlock(hashBlockIn), pOld(NULL), fHadOld(false)
    {
        std::map<uint256, CBlockIndex*>::iterator itOld = mapBlockIndex.find(hashBlock);
        if (itOld != mapBlockIndex.end())
        {
            fHadOld = true;
            pOld = itOld->second;
        }

        index.nHeight = nHeight;
        index.nFlags = 0; // PoW
        mapBlockIndex[hashBlock] = &index;
        index.phashBlock = &mapBlockIndex.find(hashBlock)->first;
    }

    ~ScopedBlockIndexEntry()
    {
        if (fHadOld)
            mapBlockIndex[hashBlock] = pOld;
        else
            mapBlockIndex.erase(hashBlock);
    }
};

struct ScopedEpochStateOverride
{
    CTxDB& txdb;
    int nEpoch;
    bool fHadOriginal;
    CEpochState original;

    ScopedEpochStateOverride(CTxDB& txdbIn, int nEpochIn)
        : txdb(txdbIn), nEpoch(nEpochIn), fHadOriginal(false)
    {
        fHadOriginal = txdb.ReadEpochState(nEpoch, original);
        txdb.EraseEpochState(nEpoch);
    }

    ~ScopedEpochStateOverride()
    {
        if (fHadOriginal)
            txdb.WriteEpochState(nEpoch, original);
        else
            txdb.EraseEpochState(nEpoch);
    }
};

struct ScopedRawTxIndexCleanup
{
    CTxDB& txdb;
    uint256 hashTx;

    ScopedRawTxIndexCleanup(CTxDB& txdbIn, const uint256& hashTxIn)
        : txdb(txdbIn), hashTx(hashTxIn)
    {
        DeleteRawLevelDBRecord(
            txdb, std::make_pair(std::string("tx"), hashTx));
    }

    ~ScopedRawTxIndexCleanup()
    {
        DeleteRawLevelDBRecord(
            txdb, std::make_pair(std::string("tx"), hashTx));
    }
};

struct ScopedFinalityCertDbCleanup
{
    CTxDB& txdb;
    std::vector<uint256> vCertHashes;
    std::vector<uint256> vBlockHashes;

    explicit ScopedFinalityCertDbCleanup(CTxDB& txdbIn)
        : txdb(txdbIn)
    {
    }

    ~ScopedFinalityCertDbCleanup()
    {
        for (const uint256& hashCert : vCertHashes)
            txdb.EraseFinalityTallyCertificate(hashCert);
        for (const uint256& hashBlock : vBlockHashes)
            txdb.EraseFinalityConnectedCertBlock(hashBlock);
    }

    void TrackCert(const uint256& hashCert)
    {
        vCertHashes.push_back(hashCert);
        txdb.EraseFinalityTallyCertificate(hashCert);
    }

    void TrackBlock(const uint256& hashBlock)
    {
        vBlockHashes.push_back(hashBlock);
        txdb.EraseFinalityConnectedCertBlock(hashBlock);
    }
};

struct ScopedFinalityDiskMigrationCleanup
{
    CTxDB& txdb;
    std::vector<uint256> vVoteNullifiers;
    std::vector<uint256> vCertHashes;

    explicit ScopedFinalityDiskMigrationCleanup(CTxDB& txdbIn)
        : txdb(txdbIn)
    {
    }

    ~ScopedFinalityDiskMigrationCleanup()
    {
        for (std::vector<uint256>::const_iterator it = vVoteNullifiers.begin();
             it != vVoteNullifiers.end(); ++it)
            txdb.EraseFinalityVote(*it);
        for (std::vector<uint256>::const_iterator it = vCertHashes.begin();
             it != vCertHashes.end(); ++it)
            txdb.EraseFinalityTallyCertificate(*it);

        int nGeneration = 0;
        if (!txdb.ReadFinalityDiskEnvelopeGeneration(nGeneration) ||
            nGeneration != FINALITY_DISK_ENVELOPE_GENERATION)
            PutRawLevelDBRecord(txdb, std::string("finalitydiskschema"),
                                FINALITY_DISK_ENVELOPE_GENERATION);
    }
};

CFinalityVote BuildTransparentVoteForCertificateCarrierTest(const CKey& key,
                                                            int nEpoch,
                                                            int nHeight,
                                                            const uint256& hashBlock)
{
    CPubKey pubkey = key.GetPubKey();
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    vote.nEpoch = nEpoch;
    vote.nHeight = nHeight;
    vote.hashBlock = hashBlock;
    vote.nTime = 1000;
    vote.nVoteWeight = 1000 * COIN;
    vote.nReward = 0;
    vote.vchPubKey.assign(pubkey.begin(), pubkey.end());
    vote.vStakeProof.push_back(COutPoint(uint256(9180808), 0));

    CHashWriter ss(SER_GETHASH, 0);
    ss << vote.vchPubKey;
    ss << vote.nEpoch;
    vote.nullifier = ss.GetHash();
    return vote;
}

CFinalityTallyCertificate BuildTransparentCertificateForCarrierTest(const CFinalityVote& vote)
{
    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = vote.nEpoch;
    cert.hashBlock = vote.hashBlock;
    cert.nHeight = vote.nHeight;
    cert.nTier = FINALITY_HARD;
    cert.nTransparentActiveWeight = vote.nVoteWeight;
    cert.nTransparentWinningWeight = vote.nVoteWeight;
    cert.nTransparentRewardBudget = vote.nReward;
    cert.vVoteNullifiers.push_back(vote.nullifier);
    return cert;
}

} // namespace

BOOST_AUTO_TEST_SUITE(finality_tally_tests)

BOOST_AUTO_TEST_CASE(block_connected_vote_replaces_conflicting_pending_nullifier)
{
    CKey key;
    key.MakeNewKey(true);

    CFinalityVote pending = BuildTransparentVoteForTrackerTest(key, 1000, 50);
    CFinalityVote connected = BuildTransparentVoteForTrackerTest(key, 1001, 80);

    BOOST_REQUIRE(pending.nullifier == connected.nullifier);
    BOOST_REQUIRE(pending.GetHash() != connected.GetHash());

    CFinalityTracker tracker;
    BOOST_REQUIRE(tracker.AddVote(pending, false, false));
    BOOST_CHECK_EQUAL(tracker.GetPendingVoteCount(), 1);
    BOOST_CHECK(!tracker.AddVote(pending, false, false));
    BOOST_CHECK_EQUAL(tracker.GetPendingVoteCount(), 1);
    BOOST_CHECK(!tracker.AddVote(connected, false, false));

    BOOST_CHECK(tracker.AddVote(connected, false, true));
    BOOST_CHECK_EQUAL(tracker.GetPendingVoteCount(), 0);
    BOOST_CHECK_EQUAL(tracker.GetEpochVoteCount(connected.nEpoch), 1);
    BOOST_CHECK_EQUAL(tracker.GetEpochVoterCount(connected.nEpoch), 1);
    BOOST_CHECK_EQUAL(tracker.GetEpochVoteWeight(connected.nEpoch), connected.nVoteWeight);

    CFinalityVote conflictingConnected = BuildTransparentVoteForTrackerTest(key, 1002, 90);
    BOOST_REQUIRE(conflictingConnected.nullifier == connected.nullifier);
    BOOST_CHECK(!tracker.AddVote(conflictingConnected, false, true));
}

BOOST_AUTO_TEST_CASE(pending_tally_certificate_duplicate_is_not_rebroadcast)
{
    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = 7;
    cert.hashBlock = uint256(70707);
    cert.nHeight = 70;
    cert.nTier = FINALITY_HARD;
    cert.hashCurveRoot = uint256(80808);
    cert.hashNullifierRoot = uint256(90909);
    cert.committeeSetHash = uint256(100100);
    cert.nTransparentActiveWeight = 1000 * COIN;
    cert.nTransparentWinningWeight = 800 * COIN;
    cert.vVoteNullifiers.push_back(uint256(111111));
    cert.vTallyShareHashes.push_back(uint256(222222));

    CFinalityTracker tracker;
    BOOST_REQUIRE(tracker.AddTallyCertificate(cert, false, false));
    BOOST_CHECK(!tracker.AddTallyCertificate(cert, false, false));

    CFinalityTallyCertificate sameContext = cert;
    sameContext.vchAggregateThresholdProof.push_back(1);
    sameContext.vchRewardBudgetProof.push_back(2);
    BOOST_REQUIRE(sameContext.GetHash() != cert.GetHash());
    BOOST_CHECK(!tracker.AddTallyCertificate(sameContext, false, false));
}

BOOST_AUTO_TEST_CASE(tally_certificate_context_separates_envelope_and_version_domains)
{
    CFinalityTallyCertificate legacyV2;
    legacyV2.nVersion = 2;
    legacyV2.nEpoch = 9;
    legacyV2.hashBlock = uint256(0xD001);
    legacyV2.nHeight = 90;
    legacyV2.nTier = FINALITY_HARD;
    legacyV2.nTransparentActiveWeight = 1000 * COIN;
    legacyV2.nTransparentWinningWeight = 800 * COIN;
    legacyV2.vVoteNullifiers.push_back(uint256(0xD002));
    legacyV2.vVoteNullifiers.push_back(uint256(0xD003));

    CFinalityTallyCertificate canonicalV2 = legacyV2;
    canonicalV2.MarkCanonicalEnvelope();
    CFinalityTallyCertificate legacyV1 = legacyV2;
    legacyV1.nVersion = 1;

    BOOST_REQUIRE(legacyV2.GetHash() != canonicalV2.GetHash());
    BOOST_REQUIRE(legacyV2.GetHash() != legacyV1.GetHash());

    CFinalityTracker tracker;
    BOOST_CHECK(tracker.AddTallyCertificate(legacyV2, false, false));
    BOOST_CHECK(tracker.AddTallyCertificate(canonicalV2, false, false));
    BOOST_CHECK(tracker.AddTallyCertificate(legacyV1, false, false));
    BOOST_CHECK(!tracker.AddTallyCertificate(legacyV2, false, false));
    BOOST_CHECK(!tracker.AddTallyCertificate(canonicalV2, false, false));
    BOOST_CHECK(!tracker.AddTallyCertificate(legacyV1, false, false));
}

BOOST_AUTO_TEST_CASE(canonical_certificate_validation_requires_exact_rebuild)
{
    ScopedFinalityRegtest network;
    const int nTargetHeight = FORK_HEIGHT_BOUNDARY_A;
    const int nEpoch = GetEpochForHeight(nTargetHeight);
    BOOST_REQUIRE_EQUAL(GetEpochBoundaryHeight(nEpoch, nTargetHeight),
                        nTargetHeight);
    const int nContextHeight =
        nTargetHeight + FINALITY_VOTE_INCLUSION_WINDOW;
    const uint256 hashTarget(0xD101);
    ScopedBlockIndexEntry targetIndex(hashTarget, nTargetHeight);

    CFinalityTracker tracker;
    std::vector<CFinalityVote> votes;
    for (int i = 0; i < FINALITY_MIN_VOTERS; ++i)
    {
        CKey key;
        key.MakeNewKey(true);
        CFinalityVote vote = BuildTransparentVoteForCertificateCarrierTest(
            key, nEpoch, nTargetHeight, hashTarget);
        vote.MarkCanonicalEnvelope();
        BOOST_REQUIRE(tracker.AddVote(vote, false, true));
        votes.push_back(vote);
    }

    CFinalityTallyCertificate canonical;
    std::string error;
    BOOST_REQUIRE_MESSAGE(BuildCanonicalTransparentFinalityCertificate(
                              votes, canonical, &error), error);
    CTxDB txdb("r");
    FinalityResult result = FINALITY_RESULT_INVALID;
    BOOST_REQUIRE_MESSAGE(tracker.CheckTallyCertificate(
                              canonical, txdb, &error, NULL,
                              false, nContextHeight, false, &result), error);
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_OK);

    const auto rejected = [&](const CFinalityTallyCertificate& candidate) {
        FinalityResult candidateResult = FINALITY_RESULT_OK;
        std::string candidateError;
        BOOST_CHECK(!tracker.CheckTallyCertificate(
            candidate, txdb, &candidateError, NULL, false,
            nContextHeight, false, &candidateResult));
        BOOST_CHECK_EQUAL(candidateResult, FINALITY_RESULT_INVALID);
    };

    CFinalityTallyCertificate downgraded = canonical;
    downgraded.nTier = FINALITY_SOFT;
    rejected(downgraded);

    CFinalityTallyCertificate arbitraryRoot = canonical;
    arbitraryRoot.hashCurveRoot = uint256(0xD102);
    rejected(arbitraryRoot);

    CFinalityTallyCertificate arbitraryStreak = canonical;
    arbitraryStreak.nConsecutiveHardCount = 1;
    rejected(arbitraryStreak);

    CFinalityTallyCertificate permuted = canonical;
    std::reverse(permuted.vVoteNullifiers.begin(),
                 permuted.vVoteNullifiers.end());
    rejected(permuted);
}

BOOST_AUTO_TEST_CASE(connected_tally_certificate_context_duplicate_is_not_reindexed)
{
    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = 8;
    cert.hashBlock = uint256(80707);
    cert.nHeight = 80;
    cert.nTier = FINALITY_HARD;
    cert.hashCurveRoot = uint256(90808);
    cert.hashNullifierRoot = uint256(100909);
    cert.committeeSetHash = uint256(110100);
    cert.nTransparentActiveWeight = 1000 * COIN;
    cert.nTransparentWinningWeight = 800 * COIN;
    cert.vVoteNullifiers.push_back(uint256(121111));
    cert.vTallyShareHashes.push_back(uint256(132222));

    CFinalityTallyCertificate sameContext = cert;
    sameContext.vchAggregateThresholdProof.push_back(3);
    sameContext.vchRewardBudgetProof.push_back(4);
    BOOST_REQUIRE(sameContext.GetHash() != cert.GetHash());

    CFinalityTracker tracker;
    BOOST_REQUIRE(tracker.AddTallyCertificate(cert, false, true));
    BOOST_REQUIRE(tracker.AddTallyCertificate(sameContext, false, true));
    BOOST_CHECK_EQUAL(tracker.GetEpochTallyCertificates(cert.nEpoch).size(), 1U);
    BOOST_CHECK(!tracker.AddTallyCertificate(sameContext, false, false));
}

BOOST_AUTO_TEST_CASE(connected_tally_certificate_carriers_survive_partial_disconnect)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    const uint256 hashEpochBlock(9107001);
    const uint256 hashCarrierA(9107002);
    const uint256 hashCarrierB(9107003);
    const uint256 hashCarrierC(9107004);
    const uint256 hashCarrierD(9107005);

    int nEpoch = GetEpochForHeight(FORK_HEIGHT_DAG);
    int nEpochHeight = GetEpochBoundaryHeight(nEpoch, FORK_HEIGHT_DAG);
    int nCertBlockHeight = nEpochHeight + FINALITY_VOTE_INCLUSION_WINDOW;
    ScopedBlockIndexEntry scopedEpochBlock(hashEpochBlock, nEpochHeight);

    CKey key;
    key.MakeNewKey(true);
    BOOST_REQUIRE(key.GetPubKey().IsValid());

    CFinalityVote vote = BuildTransparentVoteForCertificateCarrierTest(key, nEpoch, nEpochHeight, hashEpochBlock);
    CFinalityTallyCertificate cert = BuildTransparentCertificateForCarrierTest(vote);
    CFinalityTallyCertificate sameContext = cert;
    sameContext.vchAggregateThresholdProof.push_back(0x42);
    sameContext.vchRewardBudgetProof.push_back(0x24);
    BOOST_REQUIRE(sameContext.GetHash() != cert.GetHash());

    CTxDB txdb;
    ScopedFinalityCertDbCleanup cleanup(txdb);
    cleanup.TrackCert(cert.GetHash());
    cleanup.TrackCert(sameContext.GetHash());
    cleanup.TrackBlock(hashCarrierA);
    cleanup.TrackBlock(hashCarrierB);
    cleanup.TrackBlock(hashCarrierC);
    cleanup.TrackBlock(hashCarrierD);

    std::vector<CFinalityTallyCertificate> vCert;
    vCert.push_back(cert);
    std::vector<CFinalityTallyCertificate> vSameContext;
    vSameContext.push_back(sameContext);

    CFinalityTracker trackerSameHash;
    BOOST_REQUIRE(trackerSameHash.AddVote(vote, false, true));
    BOOST_REQUIRE(trackerSameHash.ConnectBlockTallyCertificates(txdb, hashCarrierA, vCert, nCertBlockHeight));
    BOOST_CHECK_EQUAL(trackerSameHash.GetFinalityTier(), FINALITY_HARD);
    BOOST_CHECK_EQUAL(trackerSameHash.GetConsecutiveHardEpochCount(), 1);
    BOOST_REQUIRE(trackerSameHash.ConnectBlockTallyCertificates(txdb, hashCarrierB, vCert, nCertBlockHeight));
    BOOST_REQUIRE_EQUAL(trackerSameHash.GetEpochTallyCertificates(nEpoch).size(), 1U);
    BOOST_REQUIRE(trackerSameHash.DisconnectBlockTallyCertificates(txdb, hashCarrierA, vCert));
    BOOST_CHECK_EQUAL(trackerSameHash.GetEpochTallyCertificates(nEpoch).size(), 1U);
    BOOST_CHECK_EQUAL(trackerSameHash.GetFinalityTier(), FINALITY_HARD);
    BOOST_CHECK_EQUAL(trackerSameHash.GetConsecutiveHardEpochCount(), 1);
    CFinalityTallyCertificate persisted;
    BOOST_CHECK(txdb.ReadFinalityTallyCertificate(cert.GetHash(), persisted));
    BOOST_REQUIRE(trackerSameHash.DisconnectBlockTallyCertificates(txdb, hashCarrierB, vCert));
    BOOST_CHECK(trackerSameHash.GetEpochTallyCertificates(nEpoch).empty());
    BOOST_CHECK(!txdb.ReadFinalityTallyCertificate(cert.GetHash(), persisted));
    BOOST_CHECK_EQUAL(trackerSameHash.GetFinalityTier(), FINALITY_NONE);
    BOOST_CHECK_EQUAL(trackerSameHash.GetConsecutiveHardEpochCount(), 0);
    BOOST_CHECK_EQUAL(trackerSameHash.GetFinalizedHeight(), 0);

    CFinalityTracker trackerSameContext;
    BOOST_REQUIRE(trackerSameContext.AddVote(vote, false, true));
    BOOST_REQUIRE(trackerSameContext.ConnectBlockTallyCertificates(txdb, hashCarrierC, vCert, nCertBlockHeight));
    BOOST_REQUIRE(trackerSameContext.ConnectBlockTallyCertificates(txdb, hashCarrierD, vSameContext, nCertBlockHeight));
    std::vector<CFinalityTallyCertificate> vSelected =
        trackerSameContext.GetEpochTallyCertificates(nEpoch);
    BOOST_REQUIRE_EQUAL(vSelected.size(), 1U);
    const uint256 hashExpectedWinner =
        sameContext.GetHash() < cert.GetHash()
            ? sameContext.GetHash() : cert.GetHash();
    BOOST_CHECK(vSelected[0].GetHash() == hashExpectedWinner);
    BOOST_REQUIRE(trackerSameContext.DisconnectBlockTallyCertificates(txdb, hashCarrierC, vCert));
    std::vector<CFinalityTallyCertificate> vRemaining = trackerSameContext.GetEpochTallyCertificates(nEpoch);
    BOOST_REQUIRE_EQUAL(vRemaining.size(), 1U);
    BOOST_CHECK(vRemaining[0].GetHash() == sameContext.GetHash());
    BOOST_CHECK(!txdb.ReadFinalityTallyCertificate(cert.GetHash(), persisted));
    BOOST_CHECK(txdb.ReadFinalityTallyCertificate(sameContext.GetHash(), persisted));
    BOOST_REQUIRE(trackerSameContext.DisconnectBlockTallyCertificates(txdb, hashCarrierD, vSameContext));
    BOOST_CHECK(trackerSameContext.GetEpochTallyCertificates(nEpoch).empty());
    BOOST_CHECK(!txdb.ReadFinalityTallyCertificate(sameContext.GetHash(), persisted));
}

BOOST_AUTO_TEST_CASE(finality_live_summary_replays_late_certificates_in_epoch_order)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    const int nEpoch = GetEpochForHeight(FORK_HEIGHT_DAG);
    const int nNextEpoch = nEpoch + 1;
    const int nThirdEpoch = nEpoch + 2;
    const int nEpochHeight = GetEpochBoundaryHeight(nEpoch, FORK_HEIGHT_DAG);
    const int nNextEpochHeight =
        GetEpochBoundaryHeight(nNextEpoch, FORK_HEIGHT_DAG);
    const int nThirdEpochHeight =
        GetEpochBoundaryHeight(nThirdEpoch, FORK_HEIGHT_DAG);
    const int nFirstCarrierHeight =
        nNextEpochHeight + FINALITY_VOTE_INCLUSION_WINDOW;
    const uint256 hashEpochBlock(9107101);
    const uint256 hashNextEpochBlock(9107102);
    const uint256 hashNextCertCarrier(9107103);
    const uint256 hashLateCertCarrier(9107104);
    const uint256 hashThirdEpochBlock(9107105);
    const uint256 hashThirdCertCarrier(9107106);
    ScopedBlockIndexEntry scopedEpochBlock(hashEpochBlock, nEpochHeight);
    ScopedBlockIndexEntry scopedNextEpochBlock(hashNextEpochBlock,
                                                nNextEpochHeight);
    ScopedBlockIndexEntry scopedThirdEpochBlock(hashThirdEpochBlock,
                                                 nThirdEpochHeight);

    CKey keyEpoch;
    CKey keyNextEpoch;
    CKey keyThirdEpoch;
    keyEpoch.MakeNewKey(true);
    keyNextEpoch.MakeNewKey(true);
    keyThirdEpoch.MakeNewKey(true);
    CFinalityVote voteEpoch = BuildTransparentVoteForCertificateCarrierTest(
        keyEpoch, nEpoch, nEpochHeight, hashEpochBlock);
    CFinalityVote voteNextEpoch =
        BuildTransparentVoteForCertificateCarrierTest(
            keyNextEpoch, nNextEpoch, nNextEpochHeight,
            hashNextEpochBlock);
    CFinalityVote voteThirdEpoch =
        BuildTransparentVoteForCertificateCarrierTest(
            keyThirdEpoch, nThirdEpoch, nThirdEpochHeight,
            hashThirdEpochBlock);
    CFinalityTallyCertificate certEpoch =
        BuildTransparentCertificateForCarrierTest(voteEpoch);
    CFinalityTallyCertificate certNextEpoch =
        BuildTransparentCertificateForCarrierTest(voteNextEpoch);
    CFinalityTallyCertificate certThirdEpoch =
        BuildTransparentCertificateForCarrierTest(voteThirdEpoch);

    CTxDB txdb;
    ScopedFinalityCertDbCleanup cleanup(txdb);
    cleanup.TrackCert(certEpoch.GetHash());
    cleanup.TrackCert(certNextEpoch.GetHash());
    cleanup.TrackCert(certThirdEpoch.GetHash());
    cleanup.TrackBlock(hashNextCertCarrier);
    cleanup.TrackBlock(hashLateCertCarrier);
    cleanup.TrackBlock(hashThirdCertCarrier);
    BOOST_REQUIRE(txdb.TxnBegin());

    CFinalityTracker tracker;
    BOOST_REQUIRE(tracker.AddVote(voteEpoch, false, true));
    BOOST_REQUIRE(tracker.AddVote(voteNextEpoch, false, true));

    // Connect E+1 first, then a still-valid late certificate for E. Canonical replay
    // must derive E,E+1 regardless of carrier arrival order.
    std::vector<CFinalityTallyCertificate> vNext(1, certNextEpoch);
    BOOST_REQUIRE(tracker.ConnectBlockTallyCertificates(
        txdb, hashNextCertCarrier, vNext, nFirstCarrierHeight));
    BOOST_CHECK_EQUAL(tracker.GetConsecutiveHardEpochCount(), 1);

    std::vector<CFinalityTallyCertificate> vLate(1, certEpoch);
    BOOST_REQUIRE(tracker.ConnectBlockTallyCertificates(
        txdb, hashLateCertCarrier, vLate, nFirstCarrierHeight + 1));
    BOOST_CHECK_EQUAL(tracker.GetFinalityTier(), FINALITY_HARD);
    BOOST_CHECK_EQUAL(tracker.GetConsecutiveHardEpochCount(), 2);
    BOOST_CHECK_EQUAL(tracker.GetFinalizedHeight(), 0);

    // This maintenance call is scheduled only on local voters, so it must never
    // remove carrier-backed validation state. All following connect/disconnect
    // mutations still run inside the active WriteBatch and are aborted below.
    tracker.PruneOldEpochs(nNextEpoch + 20);
    BOOST_CHECK_EQUAL(tracker.GetEpochTallyCertificates(nEpoch).size(), 1U);
    BOOST_CHECK_EQUAL(tracker.GetEpochTallyCertificates(nNextEpoch).size(), 1U);
    BOOST_CHECK_EQUAL(tracker.GetConsecutiveHardEpochCount(), 2);

    std::vector<CFinalityTallyCertificate> vThird(1, certThirdEpoch);
    BOOST_REQUIRE(tracker.AddVote(voteThirdEpoch, false, true));
    BOOST_REQUIRE(tracker.ConnectBlockTallyCertificates(
        txdb, hashThirdCertCarrier, vThird,
        nThirdEpochHeight + FINALITY_VOTE_INCLUSION_WINDOW));
    BOOST_CHECK_EQUAL(tracker.GetConsecutiveHardEpochCount(), 3);
    BOOST_CHECK_EQUAL(tracker.GetFinalizedHeight(), nThirdEpochHeight);
    BOOST_REQUIRE(tracker.DisconnectBlockTallyCertificates(
        txdb, hashThirdCertCarrier, vThird));
    BOOST_CHECK_EQUAL(tracker.GetConsecutiveHardEpochCount(), 2);
    BOOST_CHECK_EQUAL(tracker.GetFinalizedHeight(), 0);

    // Removing the late E carrier must immediately recompute from the surviving
    // E+1 carrier instead of retaining the stale two-epoch streak until restart.
    BOOST_REQUIRE(tracker.DisconnectBlockTallyCertificates(
        txdb, hashLateCertCarrier, vLate));
    BOOST_CHECK_EQUAL(tracker.GetEpochTallyCertificates(nNextEpoch).size(), 1U);
    // The still-connected E+2 vote has too few voters after its cert is gone,
    // so the latest tier is NONE even though the surviving hard streak is one.
    BOOST_CHECK_EQUAL(tracker.GetFinalityTier(), FINALITY_NONE);
    BOOST_CHECK_EQUAL(tracker.GetConsecutiveHardEpochCount(), 1);
    BOOST_REQUIRE(tracker.DisconnectBlockTallyCertificates(
        txdb, hashNextCertCarrier, vNext));
    BOOST_CHECK_EQUAL(tracker.GetFinalityTier(), FINALITY_NONE);
    BOOST_CHECK_EQUAL(tracker.GetConsecutiveHardEpochCount(), 0);
    txdb.TxnAbort();
}

BOOST_AUTO_TEST_CASE(tally_config_parses_ordered_committee_and_rejects_invalid_sets)
{
    ScopedTallyArgs scopedArgs;

    std::vector<CKey> vKeys(3);
    for (CKey& key : vKeys)
        key.MakeNewKey(true);

    std::vector<std::string> vPubKeyHex;
    for (const CKey& key : vKeys)
        vPubKeyHex.push_back(PubKeyHex(key.GetPubKey()));

    mapArgs["-finalitytallymode"] = "committee";
    mapArgs["-finalitytallythreshold"] = "2-of-3";
    mapArgs["-finalitytallypubkey"] = "not-used-when-mapMultiArgs-is-populated";
    mapMultiArgs["-finalitytallypubkey"] = vPubKeyHex;

    CFinalityTallyConfig config = GetFinalityTallyConfig();
    BOOST_CHECK(config.fModeValid);
    BOOST_CHECK(config.fEnabled);
    BOOST_CHECK(config.fPubKeyConfigured);
    BOOST_CHECK(config.fThresholdValid);
    BOOST_CHECK(config.fCommitteeValid);
    BOOST_CHECK(config.CanRelayPrivateVotes());
    BOOST_CHECK_EQUAL(config.nThresholdM, 2);
    BOOST_CHECK_EQUAL(config.nThresholdN, 3);
    BOOST_REQUIRE_EQUAL(config.vCommitteePubKeys.size(), vKeys.size());
    for (size_t i = 0; i < vKeys.size(); i++)
        BOOST_CHECK(config.vCommitteePubKeys[i] == vKeys[i].GetPubKey());
    BOOST_CHECK(config.committeeSetHash ==
                ComputeFinalityTallyCommitteeHash(2, config.vCommitteePubKeys));

    std::vector<CPubKey> vReorderedPubKeys = config.vCommitteePubKeys;
    std::reverse(vReorderedPubKeys.begin(), vReorderedPubKeys.end());
    BOOST_CHECK(config.committeeSetHash !=
                ComputeFinalityTallyCommitteeHash(2, vReorderedPubKeys));

    mapMultiArgs["-finalitytallypubkey"][2] = vPubKeyHex[1];
    CFinalityTallyConfig duplicateConfig = GetFinalityTallyConfig();
    BOOST_CHECK(!duplicateConfig.fCommitteeValid);
    BOOST_CHECK(!duplicateConfig.CanRelayPrivateVotes());

    mapMultiArgs["-finalitytallypubkey"] = vPubKeyHex;
    mapArgs["-finalitytallythreshold"] = "2-of-4";
    CFinalityTallyConfig mismatchedConfig = GetFinalityTallyConfig();
    BOOST_CHECK(mismatchedConfig.fThresholdValid);
    BOOST_CHECK(!mismatchedConfig.fCommitteeValid);

    mapArgs["-finalitytallythreshold"] = "2-of-3";
    mapMultiArgs["-finalitytallypubkey"][1] = "abcd";
    CFinalityTallyConfig badPubKeyConfig = GetFinalityTallyConfig();
    BOOST_CHECK(!badPubKeyConfig.fCommitteeValid);

    int nM = 0;
    int nN = 0;
    BOOST_CHECK(ParseFinalityTallyThreshold("2-of-3", nM, nN));
    BOOST_CHECK_EQUAL(nM, 2);
    BOOST_CHECK_EQUAL(nN, 3);
    BOOST_CHECK(!ParseFinalityTallyThreshold("0-of-3", nM, nN));
    BOOST_CHECK(!ParseFinalityTallyThreshold("3-of-2", nM, nN));
    BOOST_CHECK(!ParseFinalityTallyThreshold("2/3", nM, nN));

    mapMultiArgs.erase("-finalitytallypubkey");
    mapArgs["-finalitytallypubkey"] = vPubKeyHex[0];
    mapArgs["-finalitytallythreshold"] = "1-of-1";
    CFinalityTallyConfig singleKeyFallbackConfig = GetFinalityTallyConfig();
    BOOST_CHECK(singleKeyFallbackConfig.fCommitteeValid);
    BOOST_REQUIRE_EQUAL(singleKeyFallbackConfig.vCommitteePubKeys.size(), 1U);
    BOOST_CHECK(singleKeyFallbackConfig.vCommitteePubKeys[0] == vKeys[0].GetPubKey());
}

BOOST_AUTO_TEST_CASE(threshold_share_decrypt_tamper_and_recover)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    std::vector<CKey> vKeys(3);
    for (CKey& key : vKeys)
        key.MakeNewKey(true);
    CFinalityTallyConfig config = BuildTestTallyConfig(vKeys, 2);

    std::vector<unsigned char> vchWeightBlind;
    std::vector<unsigned char> vchRewardBlind;
    BOOST_REQUIRE(GenerateBlindingFactor(vchWeightBlind));
    BOOST_REQUIRE(GenerateBlindingFactor(vchRewardBlind));

    CFinalityTallyShare share = BuildEncryptedShare(config, 1234, 17,
                                                    vchWeightBlind,
                                                    vchRewardBlind);

    CFinalityTallyShare missingRootShare = share;
    missingRootShare.vEncryptedRecipientShares.clear();
    missingRootShare.hashCurveRoot = uint256(0);
    BOOST_CHECK(!BuildEncryptedFinalityTallyShares(missingRootShare,
                                                   1234,
                                                   17,
                                                   vchWeightBlind,
                                                   vchRewardBlind,
                                                   config));

    CFinalityTallyShare wrongCommitteeShare = share;
    wrongCommitteeShare.vEncryptedRecipientShares.clear();
    wrongCommitteeShare.committeeSetHash = uint256(999);
    BOOST_CHECK(!BuildEncryptedFinalityTallyShares(wrongCommitteeShare,
                                                   1234,
                                                   17,
                                                   vchWeightBlind,
                                                   vchRewardBlind,
                                                   config));

    CFinalityTallyPlainShare plain0, plain1, plain2;
    BOOST_REQUIRE(DecryptFinalityTallyShareForRecipient(share, config,
                                                        vKeys[0], 0, plain0));
    BOOST_REQUIRE(DecryptFinalityTallyShareForRecipient(share, config,
                                                        vKeys[1], 1, plain1));
    BOOST_REQUIRE(DecryptFinalityTallyShareForRecipient(share, config,
                                                        vKeys[2], 2, plain2));

    CFinalityTallyPlainShare wrongRecipient;
    BOOST_CHECK(!DecryptFinalityTallyShareForRecipient(share, config,
                                                       vKeys[1], 0,
                                                       wrongRecipient));

    CFinalityTallyShare tampered = share;
    tampered.hashBlock = uint256(99999);
    BOOST_CHECK(!DecryptFinalityTallyShareForRecipient(tampered, config,
                                                       vKeys[0], 0,
                                                       wrongRecipient));

    CFinalityTallyShare legacyShare = share;
    legacyShare.nVersion = 1;
    BOOST_CHECK(!DecryptFinalityTallyShareForRecipient(legacyShare, config,
                                                       vKeys[0], 0,
                                                       wrongRecipient));

    uint256 recoveredWeight, recoveredReward, recoveredWeightBlind, recoveredRewardBlind;
    std::vector<CFinalityTallyPlainShare> vOneShare;
    vOneShare.push_back(plain0);
    BOOST_CHECK(!RecoverFinalityTallySecrets(vOneShare, config.nThresholdM,
                                             recoveredWeight,
                                             recoveredReward,
                                             recoveredWeightBlind,
                                             recoveredRewardBlind));

    std::vector<CFinalityTallyPlainShare> vEnoughShares;
    vEnoughShares.push_back(plain0);
    vEnoughShares.push_back(plain2);
    BOOST_REQUIRE(RecoverFinalityTallySecrets(vEnoughShares, config.nThresholdM,
                                              recoveredWeight,
                                              recoveredReward,
                                              recoveredWeightBlind,
                                              recoveredRewardBlind));
    BOOST_CHECK(recoveredWeight == FieldFromUint64(1234));
    BOOST_CHECK(recoveredReward == FieldFromUint64(17));
    BOOST_CHECK(recoveredWeightBlind == TestScalarFromBytesBE(vchWeightBlind));
    BOOST_CHECK(recoveredRewardBlind == TestScalarFromBytesBE(vchRewardBlind));
}

BOOST_AUTO_TEST_CASE(aggregate_evaluations_recover_only_at_threshold)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    std::vector<CKey> vKeys(3);
    for (CKey& key : vKeys)
        key.MakeNewKey(true);
    CFinalityTallyConfig config = BuildTestTallyConfig(vKeys, 2);

    std::vector<unsigned char> vchWeightBlind1, vchRewardBlind1;
    std::vector<unsigned char> vchWeightBlind2, vchRewardBlind2;
    BOOST_REQUIRE(GenerateBlindingFactor(vchWeightBlind1));
    BOOST_REQUIRE(GenerateBlindingFactor(vchRewardBlind1));
    BOOST_REQUIRE(GenerateBlindingFactor(vchWeightBlind2));
    BOOST_REQUIRE(GenerateBlindingFactor(vchRewardBlind2));

    CFinalityTallyShare share1 = BuildEncryptedShare(config, 111, 7,
                                                     vchWeightBlind1,
                                                     vchRewardBlind1);
    CFinalityTallyShare share2 = BuildEncryptedShare(config, 222, 9,
                                                     vchWeightBlind2,
                                                     vchRewardBlind2);

    CFinalityTallyPlainShare share1Plain0, share1Plain1;
    CFinalityTallyPlainShare share2Plain0, share2Plain1;
    BOOST_REQUIRE(DecryptFinalityTallyShareForRecipient(share1, config,
                                                        vKeys[0], 0, share1Plain0));
    BOOST_REQUIRE(DecryptFinalityTallyShareForRecipient(share1, config,
                                                        vKeys[1], 1, share1Plain1));
    BOOST_REQUIRE(DecryptFinalityTallyShareForRecipient(share2, config,
                                                        vKeys[0], 0, share2Plain0));
    BOOST_REQUIRE(DecryptFinalityTallyShareForRecipient(share2, config,
                                                        vKeys[1], 1, share2Plain1));

    CFinalityTallyPlainShare aggregate0, aggregate1;
    std::vector<CFinalityTallyPlainShare> vRecipient0;
    vRecipient0.push_back(share1Plain0);
    vRecipient0.push_back(share2Plain0);
    BOOST_REQUIRE(AggregateFinalityTallyPlainShares(vRecipient0, aggregate0));

    std::vector<CFinalityTallyPlainShare> vRecipient1;
    vRecipient1.push_back(share1Plain1);
    vRecipient1.push_back(share2Plain1);
    BOOST_REQUIRE(AggregateFinalityTallyPlainShares(vRecipient1, aggregate1));

    uint256 recoveredWeight, recoveredReward, recoveredWeightBlind, recoveredRewardBlind;
    std::vector<CFinalityTallyPlainShare> vAggregateOneShare;
    vAggregateOneShare.push_back(aggregate0);
    BOOST_CHECK(!RecoverFinalityTallySecrets(vAggregateOneShare, config.nThresholdM,
                                             recoveredWeight,
                                             recoveredReward,
                                             recoveredWeightBlind,
                                             recoveredRewardBlind));

    std::vector<CFinalityTallyPlainShare> vAggregateEnoughShares;
    vAggregateEnoughShares.push_back(aggregate0);
    vAggregateEnoughShares.push_back(aggregate1);
    BOOST_REQUIRE(RecoverFinalityTallySecrets(vAggregateEnoughShares, config.nThresholdM,
                                              recoveredWeight,
                                              recoveredReward,
                                              recoveredWeightBlind,
                                              recoveredRewardBlind));
    BOOST_CHECK(recoveredWeight == FieldFromUint64(333));
    BOOST_CHECK(recoveredReward == FieldFromUint64(16));
    BOOST_CHECK(recoveredWeightBlind == FieldAdd(TestScalarFromBytesBE(vchWeightBlind1),
                                                 TestScalarFromBytesBE(vchWeightBlind2)));
    BOOST_CHECK(recoveredRewardBlind == FieldAdd(TestScalarFromBytesBE(vchRewardBlind1),
                                                 TestScalarFromBytesBE(vchRewardBlind2)));

    CFinalityTallyAggregatePartial partial0 = BuildEncryptedPartial(config,
                                                                    aggregate0,
                                                                    vKeys[0],
                                                                    share1,
                                                                    share2);
    CFinalityTallyAggregatePartial partial1 = BuildEncryptedPartial(config,
                                                                    aggregate1,
                                                                    vKeys[1],
                                                                    share1,
                                                                    share2);
    BOOST_CHECK(partial0.IsValidBasic());
    BOOST_CHECK(partial1.IsValidBasic());

    CFinalityTallyAggregatePartial noHashesPartial = partial0;
    noHashesPartial.vEncryptedRecipientPartials.clear();
    noHashesPartial.vTallyShareHashes.clear();
    BOOST_CHECK(!BuildEncryptedFinalityTallyAggregatePartial(noHashesPartial,
                                                             aggregate0,
                                                             config,
                                                             vKeys[0]));

    CFinalityTallyAggregatePartial duplicateHashPartial = partial0;
    duplicateHashPartial.vEncryptedRecipientPartials.clear();
    duplicateHashPartial.vTallyShareHashes[1] =
        duplicateHashPartial.vTallyShareHashes[0];
    BOOST_CHECK(!BuildEncryptedFinalityTallyAggregatePartial(duplicateHashPartial,
                                                             aggregate0,
                                                             config,
                                                             vKeys[0]));

    CFinalityTallyPlainShare decrypted0, decrypted1;
    BOOST_REQUIRE(DecryptFinalityTallyAggregatePartialForRecipient(partial0,
                                                                   config,
                                                                   vKeys[2],
                                                                   2,
                                                                   decrypted0));
    BOOST_REQUIRE(DecryptFinalityTallyAggregatePartialForRecipient(partial1,
                                                                   config,
                                                                   vKeys[0],
                                                                   0,
                                                                   decrypted1));
    BOOST_CHECK(decrypted0.nRecipientIndex == aggregate0.nRecipientIndex);
    BOOST_CHECK(decrypted0.nX == aggregate0.nX);
    BOOST_CHECK(decrypted1.nRecipientIndex == aggregate1.nRecipientIndex);
    BOOST_CHECK(decrypted1.nX == aggregate1.nX);

    CFinalityTallyPlainShare wrongAggregateRecipient;
    BOOST_CHECK(!DecryptFinalityTallyAggregatePartialForRecipient(partial0,
                                                                  config,
                                                                  vKeys[1],
                                                                  2,
                                                                  wrongAggregateRecipient));

    CFinalityTallyAggregatePartial tamperedPartial = partial0;
    tamperedPartial.hashBlock = uint256(99999);
    BOOST_CHECK(!DecryptFinalityTallyAggregatePartialForRecipient(tamperedPartial,
                                                                  config,
                                                                  vKeys[2],
                                                                  2,
                                                                  wrongAggregateRecipient));

    CFinalityTallyAggregatePartial legacyPartial = partial0;
    legacyPartial.nVersion = 1;
    BOOST_CHECK(!DecryptFinalityTallyAggregatePartialForRecipient(legacyPartial,
                                                                  config,
                                                                  vKeys[2],
                                                                  2,
                                                                  wrongAggregateRecipient));

    std::vector<CFinalityTallyPlainShare> vEncryptedAggregateEnoughShares;
    vEncryptedAggregateEnoughShares.push_back(decrypted0);
    vEncryptedAggregateEnoughShares.push_back(decrypted1);
    BOOST_REQUIRE(RecoverFinalityTallySecrets(vEncryptedAggregateEnoughShares,
                                              config.nThresholdM,
                                              recoveredWeight,
                                              recoveredReward,
                                              recoveredWeightBlind,
                                              recoveredRewardBlind));
    BOOST_CHECK(recoveredWeight == FieldFromUint64(333));
    BOOST_CHECK(recoveredReward == FieldFromUint64(16));
}

BOOST_AUTO_TEST_CASE(v2_tally_share_opreturn_extracts_and_persists)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    std::vector<CKey> vKeys(3);
    for (CKey& key : vKeys)
        key.MakeNewKey(true);
    CFinalityTallyConfig config = BuildTestTallyConfig(vKeys, 2);

    std::vector<unsigned char> vchWeightBlind;
    std::vector<unsigned char> vchRewardBlind;
    BOOST_REQUIRE(GenerateBlindingFactor(vchWeightBlind));
    BOOST_REQUIRE(GenerateBlindingFactor(vchRewardBlind));

    CFinalityTallyShare share = BuildEncryptedShare(config, 777, 19,
                                                    vchWeightBlind,
                                                    vchRewardBlind,
                                                    0);
    CScript shareScript = BuildFinalityTallyShareScript(share);
    BOOST_REQUIRE(!shareScript.empty());
    BOOST_CHECK_EQUAL((int)shareScript[0], (int)OP_RETURN);
    BOOST_CHECK_LT(shareScript.size(), (size_t)MAX_SCRIPT_SIZE);

    CFinalityTallyShare extracted;
    BOOST_REQUIRE(ExtractFinalityTallyShare(shareScript, extracted));
    BOOST_CHECK(extracted.GetHash() == share.GetHash());
    BOOST_CHECK_EQUAL(extracted.nVersion, 2);
    BOOST_CHECK_EQUAL(extracted.nEpoch, 0);
    BOOST_CHECK(extracted.committeeSetHash == config.committeeSetHash);
    BOOST_REQUIRE_EQUAL(extracted.vEncryptedRecipientShares.size(),
                        config.vCommitteePubKeys.size());

    CBlock block;
    CTransaction coinbase;
    coinbase.vin.push_back(CTxIn());
    coinbase.vout.push_back(CTxOut(0, CScript()));
    coinbase.vout.push_back(CTxOut(0, shareScript));
    block.vtx.push_back(coinbase);

    std::vector<CFinalityTallyShare> vExtracted =
        ExtractFinalityTallySharesFromBlock(block);
    BOOST_REQUIRE_EQUAL(vExtracted.size(), 1U);
    BOOST_CHECK(vExtracted[0].GetHash() == share.GetHash());

    CFinalityVote vote = BuildPrivateVoteForShare(share);
    CFinalityTracker tracker;
    BOOST_REQUIRE(tracker.AddVote(vote, false));
    BOOST_REQUIRE(tracker.AddTallyShare(share, false));

    int nBlockHeight = GetEpochBoundaryHeight(share.nEpoch, 0);

    // A share whose vote exists only in pending relay state must not be
    // offered for block inclusion: other nodes may not have the vote and
    // would reject the block.
    BOOST_CHECK(tracker.GetPendingTallySharesForBlock(nBlockHeight).empty());

    // It becomes includable when the vote rides in the same block...
    std::vector<CFinalityVote> vBlockVotes;
    vBlockVotes.push_back(vote);
    std::vector<CFinalityTallyShare> vPendingWithVote =
        tracker.GetPendingTallySharesForBlock(nBlockHeight, 16, &vBlockVotes);
    BOOST_REQUIRE_EQUAL(vPendingWithVote.size(), 1U);
    BOOST_CHECK(vPendingWithVote[0].GetHash() == share.GetHash());

    // ...or once the vote is connected.
    BOOST_REQUIRE(tracker.AddVote(vote, false, true));
    std::vector<CFinalityTallyShare> vPendingBefore =
        tracker.GetPendingTallySharesForBlock(nBlockHeight);
    BOOST_REQUIRE_EQUAL(vPendingBefore.size(), 1U);
    BOOST_CHECK(vPendingBefore[0].GetHash() == share.GetHash());

    CTxDB txdb;
    uint256 hashShare = share.GetHash();
    CFinalityTallyShare staleShare;
    if (txdb.ReadFinalityTallyShare(hashShare, staleShare))
        txdb.EraseFinalityTallyShare(hashShare);

    const uint256 hashContainingBlock(606060);
    BOOST_REQUIRE(tracker.ConnectBlockTallyShares(txdb,
                                                  hashContainingBlock,
                                                  vExtracted,
                                                  nBlockHeight));
    BOOST_CHECK_EQUAL(tracker.GetEpochTallyShareCount(share.nEpoch), 1);
    BOOST_CHECK(tracker.GetPendingTallySharesForBlock(nBlockHeight).empty());

    CFinalityTallyShare persisted;
    BOOST_REQUIRE(txdb.ReadFinalityTallyShare(hashShare, persisted));
    BOOST_CHECK(persisted.GetHash() == hashShare);

    BOOST_REQUIRE(tracker.DisconnectBlockTallyShares(txdb,
                                                     hashContainingBlock,
                                                     vExtracted));
    BOOST_CHECK_EQUAL(tracker.GetEpochTallyShareCount(share.nEpoch), 0);
    BOOST_CHECK(!txdb.ReadFinalityTallyShare(hashShare, persisted));
}

// Regression: a persisted relayed share can outlive its pending vote across
// a restart (pending votes are memory-only). Such an orphan must never be
// offered for block inclusion, must fail block-context validation, and must
// be purged from the pool and LevelDB at startup.
BOOST_AUTO_TEST_CASE(v2_tally_share_orphaned_vote_excluded_and_purged)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    std::vector<CKey> vKeys(3);
    for (CKey& key : vKeys)
        key.MakeNewKey(true);
    CFinalityTallyConfig config = BuildTestTallyConfig(vKeys, 2);

    std::vector<unsigned char> vchWeightBlind;
    std::vector<unsigned char> vchRewardBlind;
    BOOST_REQUIRE(GenerateBlindingFactor(vchWeightBlind));
    BOOST_REQUIRE(GenerateBlindingFactor(vchRewardBlind));

    CFinalityTallyShare share = BuildEncryptedShare(config, 555, 13,
                                                    vchWeightBlind,
                                                    vchRewardBlind,
                                                    0);
    uint256 hashShare = share.GetHash();

    // Simulate the post-restart state: the share was reloaded from disk but
    // the pending vote it references was lost with the process.
    CFinalityTracker tracker;
    BOOST_REQUIRE(tracker.AddTallyShare(share, false));

    int nBlockHeight = GetEpochBoundaryHeight(share.nEpoch, 0);

    // The miner must not be offered the orphan, with or without unrelated
    // block votes.
    BOOST_CHECK(tracker.GetPendingTallySharesForBlock(nBlockHeight).empty());
    std::vector<CFinalityVote> vNoMatchingVotes;
    BOOST_CHECK(tracker.GetPendingTallySharesForBlock(nBlockHeight, 16, &vNoMatchingVotes).empty());

    // Block-context validation must reject it deterministically; permissive
    // (relay) validation may still resolve it once the vote shows up pending.
    std::string strError;
    BOOST_CHECK(!tracker.CheckTallyShare(share, &strError, NULL, false, nBlockHeight));
    BOOST_CHECK_EQUAL(strError, "tally share references unknown vote");

    CFinalityVote vote = BuildPrivateVoteForShare(share);
    BOOST_REQUIRE(tracker.AddVote(vote, false));
    BOOST_CHECK(tracker.CheckTallyShare(share, &strError, NULL, true, nBlockHeight));
    BOOST_CHECK(!tracker.CheckTallyShare(share, &strError, NULL, false, nBlockHeight));

    // But it is includable when the pending vote is embedded in the block.
    std::vector<CFinalityVote> vBlockVotes;
    vBlockVotes.push_back(vote);
    BOOST_REQUIRE_EQUAL(tracker.GetPendingTallySharesForBlock(nBlockHeight, 16, &vBlockVotes).size(), 1U);

    // Startup purge: with the vote unresolvable again, the share must be
    // dropped from both the pool and the database.
    CFinalityTracker trackerRestarted;
    BOOST_REQUIRE(trackerRestarted.AddTallyShare(share, false));
    CTxDB txdb;
    BOOST_REQUIRE(txdb.WriteFinalityTallyShare(hashShare, share));

    BOOST_REQUIRE(trackerRestarted.PurgeUnresolvableTallyShares(txdb));

    BOOST_CHECK(trackerRestarted.GetPendingTallySharesForBlock(nBlockHeight).empty());
    CFinalityTallyShare reloaded;
    BOOST_CHECK(!txdb.ReadFinalityTallyShare(hashShare, reloaded));
}

BOOST_AUTO_TEST_CASE(private_tally_certificate_v2_bpac_proofs_reject_opening_blobs)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    const int64_t nTransparentActive = 1000 * COIN;
    const int64_t nTransparentWinning = 500 * COIN;
    const int64_t nPrivateActive = 5000 * COIN;
    const int64_t nPrivateWinning = 4000 * COIN;
    const int nHeight = 9000000;
    const int64_t nPrivateReward =
        GetFinalityVoteReward(nPrivateActive, FINALITY_EPOCH_INTERVAL_POST_DAG);
    BOOST_REQUIRE_GT(nPrivateReward, 0);

    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = 77;
    cert.hashBlock = uint256(70707);
    cert.nHeight = nHeight;
    cert.nTier = FINALITY_HARD;
    cert.hashCurveRoot = uint256(80808);
    cert.hashNullifierRoot = uint256(90909);
    cert.committeeSetHash = uint256(100100);
    cert.nTransparentActiveWeight = nTransparentActive;
    cert.nTransparentWinningWeight = nTransparentWinning;
    cert.nTransparentRewardBudget = 0;
    cert.vVoteNullifiers.push_back(uint256(111111));
    cert.vTallyShareHashes.push_back(uint256(222222));

    std::vector<unsigned char> vchActiveBlind;
    std::vector<unsigned char> vchWinningBlind;
    std::vector<unsigned char> vchRewardBlind;
    BOOST_REQUIRE(GenerateBlindingFactor(vchActiveBlind));
    BOOST_REQUIRE(GenerateBlindingFactor(vchWinningBlind));
    BOOST_REQUIRE(GenerateBlindingFactor(vchRewardBlind));
    BOOST_REQUIRE(CreatePedersenCommitment(nPrivateActive, vchActiveBlind,
                                           cert.activeWeightCommitment));
    BOOST_REQUIRE(CreatePedersenCommitment(nPrivateWinning, vchWinningBlind,
                                           cert.winningWeightCommitment));
    BOOST_REQUIRE(CreatePedersenCommitment(nPrivateReward, vchRewardBlind,
                                           cert.rewardBudgetCommitment));

    BOOST_REQUIRE(CreateFinalityAggregateThresholdProofV2(cert,
                                                          nPrivateActive,
                                                          nPrivateWinning,
                                                          vchActiveBlind,
                                                          vchWinningBlind,
                                                          false,
                                                          cert.vchAggregateThresholdProof));
    BOOST_REQUIRE(CreateFinalityRewardBudgetProofV2(cert,
                                                    nPrivateActive,
                                                    nPrivateReward,
                                                    vchActiveBlind,
                                                    vchRewardBlind,
                                                    cert.vchRewardBudgetProof));

    std::string strError;
    BOOST_CHECK(cert.IsValidBasic(&strError));
    BOOST_CHECK_EQUAL(ReadProofEnvelopeVersion(cert.vchAggregateThresholdProof), 2U);
    BOOST_CHECK_EQUAL(ReadProofEnvelopeVersion(cert.vchRewardBudgetProof), 2U);
    BOOST_CHECK(VerifyFinalityAggregateThresholdProofV2(cert,
                                                        nTransparentActive,
                                                        nTransparentWinning,
                                                        false,
                                                        &strError));
    BOOST_CHECK(VerifyFinalityRewardBudgetProofV2(cert, 0, &strError));
    BOOST_CHECK(!VerifyFinalityAggregateThresholdProofV2(cert,
                                                         nTransparentActive + COIN,
                                                         nTransparentWinning,
                                                         false,
                                                         &strError));

    CFinalityTallyCertificate wrongContext = cert;
    wrongContext.committeeSetHash = uint256(333333);
    BOOST_CHECK(wrongContext.IsValidBasic(&strError));
    BOOST_CHECK(!VerifyFinalityAggregateThresholdProofV2(wrongContext,
                                                         nTransparentActive,
                                                         nTransparentWinning,
                                                         false,
                                                         &strError));
    BOOST_CHECK(!VerifyFinalityRewardBudgetProofV2(wrongContext, 0, &strError));

    BOOST_CHECK(!ContainsBytes(cert.vchAggregateThresholdProof, vchActiveBlind));
    BOOST_CHECK(!ContainsBytes(cert.vchAggregateThresholdProof, vchWinningBlind));
    BOOST_CHECK(!ContainsBytes(cert.vchRewardBudgetProof, vchActiveBlind));
    BOOST_CHECK(!ContainsBytes(cert.vchRewardBudgetProof, vchRewardBlind));
    BOOST_CHECK(!ContainsBytes(cert.vchAggregateThresholdProof,
                               EncodeLE64((uint64_t)nPrivateActive)));
    BOOST_CHECK(!ContainsBytes(cert.vchAggregateThresholdProof,
                               EncodeLE64((uint64_t)nPrivateWinning)));
    BOOST_CHECK(!ContainsBytes(cert.vchRewardBudgetProof,
                               EncodeLE64((uint64_t)nPrivateReward)));

    CFinalityTallyCertificate tampered = cert;
    BOOST_REQUIRE_GT(tampered.vchAggregateThresholdProof.size(), 10U);
    tampered.vchAggregateThresholdProof[9] ^= 0x01;
    BOOST_CHECK(!VerifyFinalityAggregateThresholdProofV2(tampered,
                                                         nTransparentActive,
                                                         nTransparentWinning,
                                                         false,
                                                         &strError));
    tampered = cert;
    BOOST_REQUIRE_GT(tampered.vchRewardBudgetProof.size(), 10U);
    tampered.vchRewardBudgetProof[9] ^= 0x01;
    BOOST_CHECK(!VerifyFinalityRewardBudgetProofV2(tampered, 0, &strError));

    CFinalityTallyCertificate legacy = cert;
    legacy.vchAggregateThresholdProof = SerializeLegacyProofBlob();
    BOOST_CHECK(!VerifyFinalityAggregateThresholdProofV2(legacy,
                                                         nTransparentActive,
                                                         nTransparentWinning,
                                                         false,
                                                         &strError));
    legacy = cert;
    legacy.vchRewardBudgetProof = SerializeLegacyProofBlob();
    BOOST_CHECK(!VerifyFinalityRewardBudgetProofV2(legacy, 0, &strError));

    CFinalityTallyCertificate zeroWinning = cert;
    zeroWinning.nTier = FINALITY_HARD;
    zeroWinning.nTransparentActiveWeight = 100 * COIN;
    zeroWinning.nTransparentWinningWeight = 100 * COIN;
    BOOST_REQUIRE(CreatePedersenCommitment(0, vchActiveBlind,
                                           zeroWinning.activeWeightCommitment));
    BOOST_REQUIRE(CreatePedersenCommitment(0, vchWinningBlind,
                                           zeroWinning.winningWeightCommitment));
    BOOST_REQUIRE(CreateFinalityAggregateThresholdProofV2(zeroWinning,
                                                          0,
                                                          0,
                                                          vchActiveBlind,
                                                          vchWinningBlind,
                                                          true,
                                                          zeroWinning.vchAggregateThresholdProof));
    BOOST_CHECK(VerifyFinalityAggregateThresholdProofV2(zeroWinning,
                                                        zeroWinning.nTransparentActiveWeight,
                                                        zeroWinning.nTransparentWinningWeight,
                                                        true,
                                                        &strError));
    BOOST_CHECK(!CreateFinalityAggregateThresholdProofV2(zeroWinning,
                                                         COIN,
                                                         COIN,
                                                         vchActiveBlind,
                                                         vchWinningBlind,
                                                         true,
                                                         zeroWinning.vchAggregateThresholdProof));
}

BOOST_AUTO_TEST_CASE(finality_deserializers_enforce_consensus_vector_maxima_before_allocation)
{
    CFinalityVote voteAtMax;
    voteAtMax.vStakeProof.resize(FINALITY_MAX_STAKE_PROOFS);
    CDataStream ssVoteAtMax(SER_NETWORK, PROTOCOL_VERSION);
    ssVoteAtMax << voteAtMax;
    CFinalityVote decodedVote;
    BOOST_CHECK_NO_THROW(ssVoteAtMax >> decodedVote);
    BOOST_CHECK_EQUAL(decodedVote.vStakeProof.size(),
                      (size_t)FINALITY_MAX_STAKE_PROOFS);

    CFinalityVote voteTooLarge;
    voteTooLarge.vStakeProof.resize(FINALITY_MAX_STAKE_PROOFS + 1);
    CDataStream ssVoteTooLarge(SER_NETWORK, PROTOCOL_VERSION);
    ssVoteTooLarge << voteTooLarge;
    BOOST_CHECK_THROW(ssVoteTooLarge >> decodedVote, std::ios_base::failure);

    CFinalityTallyShare shareAtMax;
    shareAtMax.vEncryptedRecipientShares.assign(
        FINALITY_MAX_TALLY_COMMITTEE, std::vector<unsigned char>(1, 0x01));
    shareAtMax.vchShareProof.assign(BPAC_V3_MAX_PROOF_SIZE, 0x02);
    CDataStream ssShareAtMax(SER_NETWORK, PROTOCOL_VERSION);
    ssShareAtMax << shareAtMax;
    CFinalityTallyShare decodedShare;
    BOOST_CHECK_NO_THROW(ssShareAtMax >> decodedShare);
    BOOST_CHECK_EQUAL(decodedShare.vEncryptedRecipientShares.size(),
                      (size_t)FINALITY_MAX_TALLY_COMMITTEE);
    BOOST_CHECK_EQUAL(decodedShare.vchShareProof.size(),
                      (size_t)BPAC_V3_MAX_PROOF_SIZE);

    CFinalityTallyShare shareTooLarge = shareAtMax;
    shareTooLarge.vEncryptedRecipientShares.push_back(
        std::vector<unsigned char>(1, 0x03));
    CDataStream ssShareTooLarge(SER_NETWORK, PROTOCOL_VERSION);
    ssShareTooLarge << shareTooLarge;
    BOOST_CHECK_THROW(ssShareTooLarge >> decodedShare, std::ios_base::failure);

    CFinalityTallyCertificate certAtMax;
    certAtMax.vVoteNullifiers.resize(FINALITY_MAX_VOTES, uint256(1));
    certAtMax.vTallyShareHashes.resize(FINALITY_MAX_VOTES, uint256(2));
    certAtMax.vchAggregateThresholdProof.assign(BPAC_V3_MAX_PROOF_SIZE, 0x04);
    certAtMax.vchRewardBudgetProof.assign(BPAC_V3_MAX_PROOF_SIZE, 0x05);
    CDataStream ssCertAtMax(SER_NETWORK, PROTOCOL_VERSION);
    ssCertAtMax << certAtMax;
    CFinalityTallyCertificate decodedCert;
    BOOST_CHECK_NO_THROW(ssCertAtMax >> decodedCert);
    BOOST_CHECK_EQUAL(decodedCert.vVoteNullifiers.size(),
                      (size_t)FINALITY_MAX_VOTES);

    CFinalityTallyCertificate certTooLarge = certAtMax;
    certTooLarge.vVoteNullifiers.push_back(uint256(3));
    CDataStream ssCertTooLarge(SER_NETWORK, PROTOCOL_VERSION);
    ssCertTooLarge << certTooLarge;
    BOOST_CHECK_THROW(ssCertTooLarge >> decodedCert, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(finality_abort_restores_only_committed_state)
{
    const uint256 nullifier(0xFA110001);
    const uint256 hashCarrier(0xFA110002);
    CTxDB txdb("r+");
    BOOST_REQUIRE(txdb.EraseFinalityVote(nullifier));
    BOOST_REQUIRE(txdb.EraseFinalityConnectedVoteBlock(hashCarrier));

    CKey key;
    key.MakeNewKey(true);
    CFinalityVote vote;
    vote.nEpoch = 777;
    vote.hashBlock = uint256(0xFA110003);
    vote.nHeight = 777;
    vote.nTime = GetTime();
    vote.nVoteWeight = COIN;
    vote.nullifier = nullifier;
    vote.vStakeProof.push_back(COutPoint(uint256(0xFA120004), 0));
    CPubKey pubkey = key.GetPubKey();
    vote.vchPubKey.assign(pubkey.begin(), pubkey.end());

    CFinalityTracker tracker;
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.WriteFinalityVote(nullifier, vote));
    BOOST_REQUIRE(txdb.WriteFinalityConnectedVoteBlock(
        hashCarrier, std::vector<uint256>(1, nullifier)));
    BOOST_REQUIRE(tracker.AddVote(vote, false, true));
    BOOST_REQUIRE(tracker.HasVoteNullifier(nullifier));
    txdb.TxnAbort();

    BOOST_REQUIRE(tracker.RestoreCommittedStateAfterAbort());
    BOOST_CHECK(!tracker.HasVoteNullifier(nullifier));
    CFinalityVote persisted;
    BOOST_CHECK(!txdb.ReadFinalityVote(nullifier, persisted));
}

BOOST_AUTO_TEST_CASE(canonical_finality_disk_envelopes_survive_restart_decode)
{
    CTxDB txdb("r+");
    int nGeneration = 0;
    BOOST_REQUIRE(txdb.ReadFinalityDiskEnvelopeGeneration(nGeneration));
    BOOST_REQUIRE_EQUAL(nGeneration, FINALITY_DISK_ENVELOPE_GENERATION);

    CKey key;
    key.MakeNewKey(true);
    CFinalityVote vote = BuildTransparentVoteForTrackerTest(key, 2000, 75 * COIN);
    vote.nEpoch = 811;
    vote.nHeight = 811;
    vote.hashBlock = uint256(0xFA210001);
    vote.nullifier = uint256(0xFA210002);
    vote.MarkCanonicalEnvelope();
    BOOST_REQUIRE(vote.Sign(key));
    BOOST_REQUIRE(vote.IsValid());
    const uint256 hashVote = vote.GetHash();
    const uint256 hashVoteSig = vote.GetSignatureHash();

    CFinalityTallyCertificate cert =
        BuildTransparentCertificateForCarrierTest(vote);
    cert.MarkCanonicalEnvelope();
    cert.vVoteNullifiers.push_back(uint256(0xFA210003));
    BOOST_REQUIRE(cert.IsValidBasic());
    const uint256 hashCert = cert.GetHash();
    const uint256 hashCertSig = cert.GetSignatureDigest();

    ScopedFinalityDiskMigrationCleanup cleanup(txdb);
    cleanup.vVoteNullifiers.push_back(vote.nullifier);
    cleanup.vCertHashes.push_back(hashCert);

    BOOST_REQUIRE(txdb.EraseFinalityVote(vote.nullifier));
    BOOST_REQUIRE(txdb.EraseFinalityTallyCertificate(hashCert));
    BOOST_REQUIRE(txdb.WriteFinalityVote(vote.nullifier, vote));
    BOOST_REQUIRE(txdb.WriteFinalityTallyCertificate(hashCert, cert));

    // A new cheap wrapper exercises the on-disk decoder used after process
    // restart; runtime provenance must not be borrowed from the original object.
    CTxDB restarted("r");
    CFinalityVote loadedVote;
    CFinalityTallyCertificate loadedCert;
    BOOST_REQUIRE(restarted.ReadFinalityVote(vote.nullifier, loadedVote));
    BOOST_REQUIRE(restarted.ReadFinalityTallyCertificate(hashCert, loadedCert));
    BOOST_CHECK(loadedVote.IsCanonicalEnvelope());
    BOOST_CHECK(loadedCert.IsCanonicalEnvelope());
    BOOST_CHECK(loadedVote.GetHash() == hashVote);
    BOOST_CHECK(loadedVote.GetSignatureHash() == hashVoteSig);
    BOOST_CHECK(loadedVote.CheckSignature());
    BOOST_CHECK(loadedCert.GetHash() == hashCert);
    BOOST_CHECK(loadedCert.GetSignatureDigest() == hashCertSig);

    std::map<uint256, CFinalityVote> mapVotes;
    std::map<uint256, CFinalityTallyCertificate> mapCerts;
    BOOST_REQUIRE(restarted.IterateFinalityVotes(mapVotes));
    BOOST_REQUIRE(restarted.IterateFinalityTallyCertificates(mapCerts));
    BOOST_REQUIRE(mapVotes.count(vote.nullifier));
    BOOST_REQUIRE(mapCerts.count(hashCert));
    BOOST_CHECK(mapVotes[vote.nullifier].IsCanonicalEnvelope());
    BOOST_CHECK(mapCerts[hashCert].IsCanonicalEnvelope());

    BOOST_REQUIRE(txdb.EraseFinalityVote(vote.nullifier));
    BOOST_REQUIRE(txdb.EraseFinalityTallyCertificate(hashCert));
}

BOOST_AUTO_TEST_CASE(legacy_finality_disk_records_migrate_atomically_with_provenance)
{
    CTxDB txdb("r+");
    int nGeneration = 0;
    BOOST_REQUIRE(txdb.ReadFinalityDiskEnvelopeGeneration(nGeneration));
    BOOST_REQUIRE_EQUAL(nGeneration, FINALITY_DISK_ENVELOPE_GENERATION);

    CKey key;
    key.MakeNewKey(true);

    CFinalityVote legacyVote =
        BuildTransparentVoteForTrackerTest(key, 2100, 60 * COIN);
    legacyVote.nEpoch = 812;
    legacyVote.nHeight = 812;
    legacyVote.hashBlock = uint256(0xFA220001);
    legacyVote.nullifier = uint256(0xFA220002);
    BOOST_REQUIRE(legacyVote.Sign(key));
    BOOST_REQUIRE(legacyVote.IsValid());

    CFinalityVote canonicalVote =
        BuildTransparentVoteForTrackerTest(key, 2200, 70 * COIN);
    canonicalVote.nEpoch = 813;
    canonicalVote.nHeight = 813;
    canonicalVote.hashBlock = uint256(0xFA220003);
    canonicalVote.nullifier = uint256(0xFA220004);
    canonicalVote.MarkCanonicalEnvelope();
    BOOST_REQUIRE(canonicalVote.Sign(key));
    BOOST_REQUIRE(canonicalVote.IsValid());
    const uint256 hashCanonicalVote = canonicalVote.GetHash();

    CFinalityTallyCertificate canonicalCert =
        BuildTransparentCertificateForCarrierTest(canonicalVote);
    canonicalCert.MarkCanonicalEnvelope();
    canonicalCert.vVoteNullifiers.push_back(uint256(0xFA220005));
    BOOST_REQUIRE(canonicalCert.IsValidBasic());
    const uint256 hashCanonicalCert = canonicalCert.GetHash();
    CFinalityTallyCertificate legacyCert =
        BuildTransparentCertificateForCarrierTest(legacyVote);
    BOOST_REQUIRE(legacyCert.IsValidBasic());
    const uint256 hashLegacyCert = legacyCert.GetHash();

    ScopedFinalityDiskMigrationCleanup cleanup(txdb);
    cleanup.vVoteNullifiers.push_back(legacyVote.nullifier);
    cleanup.vVoteNullifiers.push_back(canonicalVote.nullifier);
    cleanup.vCertHashes.push_back(hashCanonicalCert);
    cleanup.vCertHashes.push_back(hashLegacyCert);

    BOOST_REQUIRE(txdb.EraseFinalityVote(legacyVote.nullifier));
    BOOST_REQUIRE(txdb.EraseFinalityVote(canonicalVote.nullifier));
    BOOST_REQUIRE(txdb.EraseFinalityTallyCertificate(hashCanonicalCert));
    BOOST_REQUIRE(txdb.EraseFinalityTallyCertificate(hashLegacyCert));

    // Recreate the pre-envelope database: the old serializers omit the runtime
    // marker even for canonical logical objects.  Removing the schema marker
    // makes the three raw writes one coherent legacy generation for migration.
    BOOST_REQUIRE(DeleteRawLevelDBRecord(
        txdb, std::string("finalitydiskschema")));
    BOOST_REQUIRE(PutRawLevelDBRecord(
        txdb, std::make_pair(std::string("finalityvote"), legacyVote.nullifier),
        legacyVote));
    BOOST_REQUIRE(PutRawLevelDBRecord(
        txdb, std::make_pair(std::string("finalityvote"), canonicalVote.nullifier),
        canonicalVote));
    BOOST_REQUIRE(PutRawLevelDBRecord(
        txdb, std::make_pair(std::string("finalitycert"), hashCanonicalCert),
        canonicalCert));
    BOOST_REQUIRE(PutRawLevelDBRecord(
        txdb, std::make_pair(std::string("finalitycert"), hashLegacyCert),
        legacyCert));

    std::string strMigrationError;
    BOOST_REQUIRE_MESSAGE(txdb.MigrateFinalityDiskRecords(strMigrationError),
                          strMigrationError);
    BOOST_REQUIRE(txdb.ReadFinalityDiskEnvelopeGeneration(nGeneration));
    BOOST_CHECK_EQUAL(nGeneration, FINALITY_DISK_ENVELOPE_GENERATION);

    CFinalityVote loadedLegacy;
    CFinalityVote loadedCanonical;
    CFinalityTallyCertificate loadedCert;
    CFinalityTallyCertificate loadedLegacyCert;
    BOOST_REQUIRE(txdb.ReadFinalityVote(legacyVote.nullifier, loadedLegacy));
    BOOST_REQUIRE(txdb.ReadFinalityVote(canonicalVote.nullifier,
                                       loadedCanonical));
    BOOST_REQUIRE(txdb.ReadFinalityTallyCertificate(hashCanonicalCert,
                                                    loadedCert));
    BOOST_REQUIRE(txdb.ReadFinalityTallyCertificate(hashLegacyCert,
                                                    loadedLegacyCert));
    BOOST_CHECK(!loadedLegacy.IsCanonicalEnvelope());
    BOOST_CHECK(loadedLegacy.CheckSignature());
    BOOST_CHECK(loadedCanonical.IsCanonicalEnvelope());
    BOOST_CHECK(loadedCanonical.CheckSignature());
    BOOST_CHECK(loadedCanonical.GetHash() == hashCanonicalVote);
    BOOST_CHECK(loadedCert.IsCanonicalEnvelope());
    BOOST_CHECK(loadedCert.GetHash() == hashCanonicalCert);
    BOOST_CHECK(!loadedLegacyCert.IsCanonicalEnvelope());
    BOOST_CHECK(loadedLegacyCert.GetHash() == hashLegacyCert);

    BOOST_REQUIRE(txdb.EraseFinalityVote(legacyVote.nullifier));
    BOOST_REQUIRE(txdb.EraseFinalityVote(canonicalVote.nullifier));
    BOOST_REQUIRE(txdb.EraseFinalityTallyCertificate(hashCanonicalCert));
    BOOST_REQUIRE(txdb.EraseFinalityTallyCertificate(hashLegacyCert));
}

BOOST_AUTO_TEST_CASE(finality_disk_migration_rejects_lossy_provenance_without_writes)
{
    CTxDB txdb("r+");
    CKey key;
    key.MakeNewKey(true);
    CFinalityVote corruptCanonical =
        BuildTransparentVoteForTrackerTest(key, 2300, 80 * COIN);
    corruptCanonical.nEpoch = 814;
    corruptCanonical.nHeight = 814;
    corruptCanonical.hashBlock = uint256(0xFA230001);
    corruptCanonical.nullifier = uint256(0xFA230002);
    corruptCanonical.MarkCanonicalEnvelope();
    BOOST_REQUIRE(corruptCanonical.Sign(key));
    // These bytes are omitted by the canonical envelope.  A migration must
    // fail rather than authenticate the canonical signature and silently drop
    // the non-default legacy payload.
    corruptCanonical.privateProof.hashCurveRoot = uint256(0xFA230003);

    ScopedFinalityDiskMigrationCleanup cleanup(txdb);
    cleanup.vVoteNullifiers.push_back(corruptCanonical.nullifier);
    BOOST_REQUIRE(txdb.EraseFinalityVote(corruptCanonical.nullifier));
    BOOST_REQUIRE(DeleteRawLevelDBRecord(
        txdb, std::string("finalitydiskschema")));
    const std::pair<std::string, uint256> keyVote(
        std::string("finalityvote"), corruptCanonical.nullifier);
    BOOST_REQUIRE(PutRawLevelDBRecord(txdb, keyVote, corruptCanonical));

    std::string bytesBefore;
    BOOST_REQUIRE(GetRawLevelDBRecord(txdb, keyVote, bytesBefore));
    std::string strMigrationError;
    BOOST_CHECK(!txdb.MigrateFinalityDiskRecords(strMigrationError));
    BOOST_CHECK(!strMigrationError.empty());
    int nGeneration = 0;
    BOOST_CHECK(!txdb.ReadFinalityDiskEnvelopeGeneration(nGeneration));
    std::string bytesAfter;
    BOOST_REQUIRE(GetRawLevelDBRecord(txdb, keyVote, bytesAfter));
    BOOST_CHECK(bytesAfter == bytesBefore);

    BOOST_REQUIRE(txdb.EraseFinalityVote(corruptCanonical.nullifier));
    BOOST_REQUIRE(PutRawLevelDBRecord(
        txdb, std::string("finalitydiskschema"),
        FINALITY_DISK_ENVELOPE_GENERATION));
}

BOOST_AUTO_TEST_CASE(finality_restart_rejects_unpaired_persistence_records)
{
    const uint256 nullifier(0xFA120001);
    const uint256 hashCarrier(0xFA120002);
    CTxDB txdb("r+");
    BOOST_REQUIRE(txdb.EraseFinalityVote(nullifier));
    BOOST_REQUIRE(txdb.EraseFinalityConnectedVoteBlock(hashCarrier));

    CKey key;
    key.MakeNewKey(true);
    CFinalityVote vote;
    vote.nEpoch = 778;
    vote.hashBlock = uint256(0xFA120003);
    vote.nHeight = 778;
    vote.nTime = GetTime();
    vote.nVoteWeight = COIN;
    vote.nullifier = nullifier;
    vote.vStakeProof.push_back(COutPoint(uint256(0xFA120004), 0));
    CPubKey pubkey = key.GetPubKey();
    vote.vchPubKey.assign(pubkey.begin(), pubkey.end());
    BOOST_REQUIRE(vote.Sign(key));
    BOOST_REQUIRE(txdb.WriteFinalityVote(nullifier, vote));

    CFinalityTracker tracker;
    BOOST_CHECK(!tracker.RestoreCommittedStateAfterAbort());

    BOOST_REQUIRE(txdb.EraseFinalityVote(nullifier));
    BOOST_REQUIRE(txdb.EraseFinalityConnectedVoteBlock(hashCarrier));

    // A syntactically paired index is still corrupt when the claimed carrier
    // cannot be resolved to an active block containing the exact vote.
    BOOST_REQUIRE(txdb.WriteFinalityVote(nullifier, vote));
    BOOST_REQUIRE(txdb.WriteFinalityConnectedVoteBlock(
        hashCarrier, std::vector<uint256>(1, nullifier)));
    CFinalityTracker pairedWrongCarrier;
    BOOST_CHECK(!pairedWrongCarrier.RestoreCommittedStateAfterAbort());

    BOOST_REQUIRE(txdb.EraseFinalityVote(nullifier));
    BOOST_REQUIRE(txdb.EraseFinalityConnectedVoteBlock(hashCarrier));
}

BOOST_AUTO_TEST_CASE(finality_validation_distinguishes_invalid_from_local_state)
{
    // Historical private-finality validation is regtest-only, so this test uses a
    // pre-Boundary-A regtest epoch.
    ScopedFinalityRegtest network;
    CFinalityTracker tracker;
    CTxDB txdb("r+");
    std::string error;

    CFinalityVote malformedVote;
    FinalityResult result = FINALITY_RESULT_OK;
    BOOST_CHECK(!tracker.CheckVote(malformedVote, txdb, &error, -1, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_INVALID);

    const int voteEpoch = GetEpochForHeight(FORK_HEIGHT_DAG);
    const int voteHeight = GetEpochBoundaryHeight(voteEpoch, FORK_HEIGHT_DAG);
    CKey key;
    key.MakeNewKey(true);
    CFinalityVote unavailableVote;
    unavailableVote.nEpoch = voteEpoch;
    unavailableVote.nHeight = voteHeight;
    unavailableVote.hashBlock = uint256(0xFA130001);
    unavailableVote.nTime = GetTime();
    unavailableVote.nVoteWeight = COIN;
    unavailableVote.nReward = GetFinalityVoteReward(
        unavailableVote.nVoteWeight, GetEpochInterval(voteHeight));
    unavailableVote.vStakeProof.push_back(COutPoint(uint256(0xFA130002), 0));
    CPubKey pubkey = key.GetPubKey();
    unavailableVote.vchPubKey.assign(pubkey.begin(), pubkey.end());
    CHashWriter nullifierHash(SER_GETHASH, 0);
    nullifierHash << unavailableVote.vchPubKey;
    nullifierHash << unavailableVote.nEpoch;
    unavailableVote.nullifier = nullifierHash.GetHash();
    BOOST_REQUIRE(unavailableVote.Sign(key));

    result = FINALITY_RESULT_INVALID;
    error.clear();
    BOOST_CHECK(!tracker.CheckVote(unavailableVote, txdb, &error,
                                   voteHeight, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_INVALID);

    // Once the claimed epoch block is known, an absent transaction index is
    // still peer-invalid: the outpoint simply does not exist.  An existing
    // index whose block/transaction body cannot be read is local corruption.
    ScopedBlockIndexEntry knownVoteTarget(unavailableVote.hashBlock,
                                           voteHeight);
    result = FINALITY_RESULT_LOCAL_STATE;
    error.clear();
    BOOST_CHECK(!tracker.CheckVote(unavailableVote, txdb, &error,
                                   voteHeight, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_INVALID);

    ScopedRawTxIndexCleanup txIndexCleanup(
        txdb, unavailableVote.vStakeProof[0].hash);
    CTxIndex unreadableIndex(CDiskTxPos(999999, 1, 1), 1);
    BOOST_REQUIRE(PutRawLevelDBRecord(
        txdb,
        std::make_pair(std::string("tx"),
                       unavailableVote.vStakeProof[0].hash),
        unreadableIndex));
    result = FINALITY_RESULT_INVALID;
    error.clear();
    BOOST_CHECK(!tracker.CheckVote(unavailableVote, txdb, &error,
                                   voteHeight, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_LOCAL_STATE);

    CFinalityTallyCertificate malformedCert;
    result = FINALITY_RESULT_OK;
    error.clear();
    BOOST_CHECK(!tracker.CheckTallyCertificate(
        malformedCert, txdb, &error, NULL, false, -1, false, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_INVALID);

    CFinalityTallyCertificate unavailableCert;
    unavailableCert.nVersion = 2;
    unavailableCert.nEpoch = voteEpoch;
    unavailableCert.nHeight = voteHeight;
    unavailableCert.hashBlock = uint256(0xFA130003);
    unavailableCert.nTier = FINALITY_NONE;
    unavailableCert.vVoteNullifiers.push_back(uint256(0xFA130004));
    result = FINALITY_RESULT_INVALID;
    error.clear();
    BOOST_CHECK(!tracker.CheckTallyCertificate(
        unavailableCert, txdb, &error, NULL, false,
        voteHeight + FINALITY_VOTE_INCLUSION_WINDOW, false, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_INVALID);

    // A private certificate before any epoch has finalized is invalid, not a
    // recoverable storage failure.  Missing progress for an epoch that should
    // already be persisted remains LOCAL_STATE.
    const int certContextHeight =
        voteHeight + FINALITY_VOTE_INCLUSION_WINDOW;
    BOOST_REQUIRE(!IsBoundaryAActiveAtHeight(certContextHeight));
    const uint256 hashPrivateTarget(0xFA130005);
    ScopedBlockIndexEntry knownPrivateTarget(hashPrivateTarget, voteHeight);
    const int nAsOfEpoch = GetEpochForHeight(certContextHeight) - 1;
    ScopedEpochStateOverride epochStateOverride(txdb, nAsOfEpoch);

    CFinalityTallyCertificate privateCert;
    privateCert.nVersion = 2;
    privateCert.nEpoch = voteEpoch;
    privateCert.nHeight = voteHeight;
    privateCert.hashBlock = hashPrivateTarget;
    privateCert.nTier = FINALITY_HARD;
    privateCert.hashCurveRoot = uint256(0xFA130006);
    privateCert.hashNullifierRoot = uint256(0xFA130007);
    privateCert.committeeSetHash = uint256(0xFA130008);
    privateCert.activeWeightCommitment.vchCommitment[0] = 1;
    privateCert.winningWeightCommitment.vchCommitment[0] = 2;
    privateCert.rewardBudgetCommitment.vchCommitment[0] = 3;
    privateCert.vVoteNullifiers.push_back(uint256(0xFA130009));
    privateCert.vTallyShareHashes.push_back(uint256(0xFA13000A));
    privateCert.vchAggregateThresholdProof.push_back(1);
    privateCert.vchRewardBudgetProof.push_back(1);
    BOOST_REQUIRE(privateCert.IsValidBasic(&error));

    result = FINALITY_RESULT_INVALID;
    error.clear();
    BOOST_CHECK(!tracker.CheckTallyCertificate(
        privateCert, txdb, &error, NULL, false, certContextHeight,
        true, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_LOCAL_STATE);

    CEpochState zeroFinalityState;
    zeroFinalityState.nEpoch = nAsOfEpoch;
    zeroFinalityState.nFinalizedHeightAsOf = 0;
    BOOST_REQUIRE(txdb.WriteEpochState(nAsOfEpoch, zeroFinalityState));
    result = FINALITY_RESULT_LOCAL_STATE;
    error.clear();
    BOOST_CHECK(!tracker.CheckTallyCertificate(
        privateCert, txdb, &error, NULL, false, certContextHeight,
        true, &result));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_INVALID);
}

BOOST_AUTO_TEST_SUITE_END()
