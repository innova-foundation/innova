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
    BOOST_REQUIRE(trackerSameHash.ConnectBlockTallyCertificates(txdb, hashCarrierB, vCert, nCertBlockHeight));
    BOOST_REQUIRE_EQUAL(trackerSameHash.GetEpochTallyCertificates(nEpoch).size(), 1U);
    BOOST_REQUIRE(trackerSameHash.DisconnectBlockTallyCertificates(txdb, hashCarrierA, vCert));
    BOOST_CHECK_EQUAL(trackerSameHash.GetEpochTallyCertificates(nEpoch).size(), 1U);
    CFinalityTallyCertificate persisted;
    BOOST_CHECK(txdb.ReadFinalityTallyCertificate(cert.GetHash(), persisted));
    BOOST_REQUIRE(trackerSameHash.DisconnectBlockTallyCertificates(txdb, hashCarrierB, vCert));
    BOOST_CHECK(trackerSameHash.GetEpochTallyCertificates(nEpoch).empty());
    BOOST_CHECK(!txdb.ReadFinalityTallyCertificate(cert.GetHash(), persisted));

    CFinalityTracker trackerSameContext;
    BOOST_REQUIRE(trackerSameContext.AddVote(vote, false, true));
    BOOST_REQUIRE(trackerSameContext.ConnectBlockTallyCertificates(txdb, hashCarrierC, vCert, nCertBlockHeight));
    BOOST_REQUIRE(trackerSameContext.ConnectBlockTallyCertificates(txdb, hashCarrierD, vSameContext, nCertBlockHeight));
    BOOST_REQUIRE_EQUAL(trackerSameContext.GetEpochTallyCertificates(nEpoch).size(), 1U);
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
                                                  vExtracted));
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

    trackerRestarted.PurgeUnresolvableTallyShares(txdb);

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

BOOST_AUTO_TEST_SUITE_END()
