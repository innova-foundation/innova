#include <boost/test/unit_test.hpp>

#include "../bulletproof_ac.h"
#include "../curvetree.h"
#include "../finality.h"
#include "../init.h"
#include "../lelantus.h"
#include "../main.h"
#include "../nullstake.h"
#include "../serialize.h"
#include "../v5activation.h"
#include "../shielded.h"
#include "../txdb.h"
#include "../util.h"
#include "../walletdb.h"
#include "../zkproof.h"

#include <algorithm>
#include <limits>
#include <set>
#include <vector>

namespace
{

template <typename T>
std::vector<unsigned char> SerializeEnvelope(const T& value)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << value;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

template <typename T>
bool TryDeserializeEnvelope(const std::vector<unsigned char>& bytes, T& value)
{
    try
    {
        CDataStream ss(bytes, SER_NETWORK, PROTOCOL_VERSION);
        ss >> value;
        // Active v5 envelopes do not uniformly require exact consumption.
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
    catch (...)
    {
        return false;
    }
}

template <typename T>
bool RoundTripsAtLimit(const T& value)
{
    const std::vector<unsigned char> encoded = SerializeEnvelope(value);
    T decoded;
    return TryDeserializeEnvelope(encoded, decoded) &&
           SerializeEnvelope(decoded) == encoded;
}

template <typename T>
bool RejectsWithoutThrow(const T& value)
{
    const std::vector<unsigned char> encoded = SerializeEnvelope(value);
    T decoded;
    return !TryDeserializeEnvelope(encoded, decoded);
}

template <typename T>
void CheckLegacyShadowedVersionContext(T value,
                                       int nLogicalDefault,
                                       int nType,
                                       int nStreamVersion)
{
    static const int SENTINEL_LOGICAL_VERSION = 0x12345678;

    T defaultVersionValue = value;
    value.nVersion = SENTINEL_LOGICAL_VERSION;
    defaultVersionValue.nVersion = nLogicalDefault;

    CDataStream sentinelStream(nType, nStreamVersion);
    sentinelStream << value;
    const std::vector<unsigned char> sentinelBytes(sentinelStream.begin(),
                                                    sentinelStream.end());

    CDataStream defaultStream(nType, nStreamVersion);
    defaultStream << defaultVersionValue;
    const std::vector<unsigned char> defaultBytes(defaultStream.begin(),
                                                  defaultStream.end());

    // The logical sentinel is absent from the legacy bytes: the first word is
    // exactly the serialization stream's context version, and changing only
    // the object member does not change any encoded byte.
    BOOST_REQUIRE_EQUAL_COLLECTIONS(sentinelBytes.begin(), sentinelBytes.end(),
                                    defaultBytes.begin(), defaultBytes.end());
    BOOST_REQUIRE(sentinelBytes.size() >= sizeof(int));
    CDataStream wordStream(sentinelBytes, nType, nStreamVersion);
    int nEncodedWord = -1;
    wordStream >> nEncodedWord;
    BOOST_CHECK_EQUAL(nEncodedWord, nStreamVersion);

    T decoded;
    CDataStream decodeStream(sentinelBytes, nType, nStreamVersion);
    decodeStream >> decoded;
    BOOST_CHECK(decodeStream.empty());
    // Reading the first word overwrites only IMPLEMENT_SERIALIZE's local
    // parameter.  The object retains its constructor's logical default.
    BOOST_CHECK_EQUAL((uint64_t)decoded.nVersion,
                      (uint64_t)nLogicalDefault);
}

std::vector<unsigned char> SerializeShieldedSpendWithOrdinaryVectors(
    const CShieldedSpendDescription& spend)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << spend.cv;
    ss << spend.anchor;
    ss << spend.nullifier;
    ss << spend.vchRk;
    ss << spend.rangeProof;
    ss << spend.vchSpendAuthSig;
    ss << spend.vchLelantusProof;
    ss << spend.vAnonSet;
    ss << spend.lelantusSerial;

    const unsigned char fHasFCMP = spend.fcmpProof.IsNull() ? 0 : 1;
    ss << fHasFCMP;
    if (fHasFCMP)
    {
        ss << spend.fcmpProof;
        ss << spend.curveTreeRoot;
    }

    const unsigned char fHasNfBind =
        (spend.vchNullifierPoint.empty() &&
         spend.vchNullifierBindingProof.empty()) ? 0 : 1;
    ss << fHasNfBind;
    if (fHasNfBind)
    {
        ss << spend.vchNullifierPoint;
        ss << spend.vchNullifierBindingProof;
    }
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

std::vector<unsigned char> SerializeShieldedOutputWithOrdinaryVectors(
    const CShieldedOutputDescription& output)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << output.cv;
    ss << output.cmu;
    ss << output.vchEphemeralKey;
    ss << output.vchEncCiphertext;
    ss << output.vchOutCiphertext;
    ss << output.rangeProof;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

std::vector<unsigned char> SerializeMofNMintTxWithOrdinaryVectors(
    const CTransaction& tx)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx.nVersion;
    ss << tx.nTime;
    ss << tx.vin;
    ss << tx.vout;
    ss << tx.nLockTime;
    ss << tx.vShieldedSpend;
    ss << tx.vShieldedOutput;
    ss << tx.nValueBalance;
    ss << tx.nPrivacyMode;
    for (size_t i = 0; i < tx.vShieldedSpend.size(); ++i)
    {
        ss << tx.vShieldedSpend[i].nPlaintextValue;
        ss << tx.vShieldedSpend[i].vchPlaintextBlind;
    }
    for (size_t i = 0; i < tx.vShieldedOutput.size(); ++i)
    {
        ss << tx.vShieldedOutput[i].nPlaintextValue;
        ss << tx.vShieldedOutput[i].vchPlaintextBlind;
        ss << tx.vShieldedOutput[i].vchRecipientScript;
    }
    for (size_t i = 0; i < tx.vShieldedOutput.size(); ++i)
    {
        ss << tx.vShieldedOutput[i].nMofNType;
        if (tx.vShieldedOutput[i].nMofNType == 1)
        {
            ss << tx.vShieldedOutput[i].valueCommitmentVv;
            ss << tx.vShieldedOutput[i].vchMofNLink;
        }
    }
    ss << tx.bindingSig;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

CShieldedSpendDescription ShieldedSpendAtWireLimits()
{
    CShieldedSpendDescription spend;
    spend.nullifier = uint256(1);
    spend.vchRk.assign(SHIELDED_SPEND_AUTH_KEY_MAX_SIZE, 0xb1);
    spend.vchSpendAuthSig.assign(SHIELDED_SPEND_AUTH_SIG_SIZE, 0xb2);
    spend.vchLelantusProof.assign(
        SHIELDED_TX_FIELD_MAX_WIRE_SIZE, 0xb3);
    spend.vAnonSet.assign(LELANTUS_MAX_SET_SIZE, CPedersenCommitment());
    spend.vchNullifierPoint.assign(NULLIFIER_POINT_SIZE, 0xb4);
    spend.vchNullifierBindingProof.assign(
        NULLIFIER_BINDING_PROOF_SIZE, 0xb5);
    return spend;
}

class ShieldedGenesisMigrationTestGuard
{
public:
    CTxDB txdb;
    CBlockIndex activeTip;
    CBlockIndex* savedBest;
    std::vector<CPedersenCommitment> commitments;

    ShieldedGenesisMigrationTestGuard()
        : txdb("r+"), savedBest(pindexBest)
    {
        activeTip.nHeight = FORK_HEIGHT_SHIELDED - 1;
        pindexBest = &activeTip;
    }

    ~ShieldedGenesisMigrationTestGuard()
    {
        for (int i = 0; i < LELANTUS_GENESIS_SEED_COUNT; ++i)
        {
            CPedersenCommitment commitment;
            if (txdb.ReadShieldedCommitment((uint64_t)i, commitment))
                txdb.EraseShieldedCommitmentIndex(
                    commitment.vchCommitment);
            txdb.EraseShieldedCommitmentHeight((uint64_t)i);
            txdb.EraseShieldedCommitment((uint64_t)i);
        }
        txdb.EraseShieldedCommitmentCount();
        pindexBest = savedBest;
    }
};

class BoundedLelantusSampleTestGuard
{
public:
    CTxDB txdb;
    uint64_t count;

    BoundedLelantusSampleTestGuard()
        : txdb("r+"), count(0)
    {
    }

    ~BoundedLelantusSampleTestGuard()
    {
        for (uint64_t i = 0; i < count; ++i)
        {
            CPedersenCommitment commitment;
            if (txdb.ReadShieldedCommitment(i, commitment))
                txdb.EraseShieldedCommitmentIndex(
                    commitment.vchCommitment);
            txdb.EraseShieldedCommitment(i);
        }
        txdb.EraseShieldedCommitmentCount();
    }
};

class ShieldedTreeDiskTestDB : public CTxDB
{
public:
    ShieldedTreeDiskTestDB() : CTxDB("r+") {}

    template <typename T>
    bool WriteRawTreeAtBlock(const uint256& blockHash, const T& value)
    {
        return Write(std::make_pair(std::string("sb"), blockHash), value);
    }
};

class AnonExactDiskTestDB : public CTxDB
{
public:
    AnonExactDiskTestDB() : CTxDB("r+") {}

    template <typename T>
    bool WriteRawKeyImage(const ec_point& keyImage, const T& value)
    {
        return Write(std::make_pair(std::string("ki"), keyImage), value);
    }

    template <typename T>
    bool WriteRawAnonOutput(const CPubKey& pubkey, const T& value)
    {
        return Write(std::make_pair(std::string("ao"), pubkey), value);
    }
};

class AnonMainnetModeGuard
{
public:
    const bool fSavedRegTest;
    const bool fSavedTestNet;

    AnonMainnetModeGuard()
        : fSavedRegTest(fRegTest), fSavedTestNet(fTestNet)
    {
        fRegTest = false;
        fTestNet = false;
    }

    ~AnonMainnetModeGuard()
    {
        fRegTest = fSavedRegTest;
        fTestNet = fSavedTestNet;
    }
};

class ShieldedWalletRecoveryDiskTestDB : public CTxDB
{
public:
    ShieldedWalletRecoveryDiskTestDB() : CTxDB("r+")
    {
        EraseShieldedWalletRecovery();
    }

    ~ShieldedWalletRecoveryDiskTestDB()
    {
        TxnAbort();
        EraseShieldedWalletRecovery();
    }

    template <typename T>
    bool WriteRawRecovery(const T& value)
    {
        return Write(std::string("shieldedWalletRecovery"), value);
    }
};

class ShieldedWalletRecoveryWithTrailingByte
{
public:
    CShieldedWalletRecoveryRecord record;
    unsigned char trailing;

    ShieldedWalletRecoveryWithTrailingByte() : trailing(0xa5) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(record);
        READWRITE(trailing);
    )
};

class KeyImageSpentWithTrailingByte
{
public:
    CKeyImageSpent spent;
    unsigned char trailing;

    KeyImageSpentWithTrailingByte() : trailing(0xa5) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(spent);
        READWRITE(trailing);
    )
};

class AnonOutputWithTrailingByte
{
public:
    CAnonOutput output;
    unsigned char trailing;

    AnonOutputWithTrailingByte() : trailing(0xa5) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(output);
        READWRITE(trailing);
    )
};

class ShieldedV3IndexTestGuard : public CTxDB
{
public:
    std::vector<CPedersenCommitment> commitments;

    ShieldedV3IndexTestGuard() : CTxDB("r+") {}

    bool WriteCorruptV3MarkerForTest()
    {
        return Write(std::string("siv3"), 3);
    }

    ~ShieldedV3IndexTestGuard()
    {
        // Clear every generation-tagged key, including generations created by
        // the abandoned-branch regression below.
        TxnAbort();
        std::string ignored;
        if (TxnBegin())
        {
            ClearShieldedCommitmentIndexV3(ignored);
            TxnCommit();
        }
        for (uint64_t i = 0; i < 8; ++i)
        {
            EraseShieldedCommitmentHeight(i);
            EraseShieldedCommitment(i);
        }
        for (size_t i = 0; i < commitments.size(); ++i)
        {
            EraseShieldedCommitmentIndex(
                commitments[i].vchCommitment);
        }
        Erase(std::string("scc"));
        Erase(std::string("st"));
    }
};

class ShieldedTreeWithTrailingByte
{
public:
    CIncrementalMerkleTree tree;
    unsigned char trailing;

    ShieldedTreeWithTrailingByte() : trailing(0xa5) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(tree);
        READWRITE(trailing);
    )
};

CPedersenCommitment IndexedTestCommitment(uint64_t index)
{
    CPedersenCommitment commitment;
    commitment.vchCommitment.assign(PEDERSEN_COMMITMENT_SIZE, 0);
    commitment.vchCommitment[0] = 0x02;
    for (int i = 0; i < 8; ++i)
        commitment.vchCommitment[PEDERSEN_COMMITMENT_SIZE - 1 - i] =
            (unsigned char)(index >> (8 * i));
    return commitment;
}

class CAdrenalineWalletDBTestAccess : public CWalletDB
{
public:
    typedef std::pair<std::vector<unsigned char>,
                      std::vector<unsigned char> > RawRecord;

    explicit CAdrenalineWalletDBTestAccess(
        const std::string& strFilename,
        const char* pszMode = "r+")
        : CWalletDB(strFilename, pszMode)
    {
    }

    template <typename K>
    bool PutRawValue(const K& key, const std::vector<unsigned char>& value)
    {
        if (!pdb || value.empty())
            return false;
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());
        Dbt datValue((void*)&value[0], value.size());
        return pdb->put(NULL, &datKey, &datValue, 0) == 0;
    }

    template <typename K>
    bool GetRawValue(const K& key, std::vector<unsigned char>& value)
    {
        value.clear();
        if (!pdb)
            return false;
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());
        Dbt datValue;
        datValue.set_flags(DB_DBT_MALLOC);
        const int ret = pdb->get(NULL, &datKey, &datValue, 0);
        if (ret != 0 || datValue.get_data() == NULL)
        {
            if (datValue.get_data() != NULL)
            {
                memset(datValue.get_data(), 0, datValue.get_size());
                free(datValue.get_data());
            }
            return false;
        }
        const unsigned char* p =
            (const unsigned char*)datValue.get_data();
        value.assign(p, p + datValue.get_size());
        memset(datValue.get_data(), 0, datValue.get_size());
        free(datValue.get_data());
        return true;
    }

    template <typename K>
    bool DeleteRawValue(const K& key)
    {
        if (!pdb)
            return false;
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());
        const int ret = pdb->del(NULL, &datKey, 0);
        return ret == 0 || ret == DB_NOTFOUND;
    }

    bool SnapshotAdrenalineRecords(std::vector<RawRecord>& records)
    {
        records.clear();
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;
        bool ok = true;
        while (ok)
        {
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            const int ret = ReadAtCursor(pcursor, ssKey, ssValue, DB_NEXT);
            if (ret == DB_NOTFOUND)
                break;
            if (ret != 0)
            {
                ok = false;
                break;
            }
            CDataStream ssType = ssKey;
            try
            {
                std::string strType;
                ssType >> strType;
                if (strType == "adrenaline" ||
                    strType == "adrenalinecfg" ||
                    strType == "adrenalinecfgschema")
                {
                    const std::vector<unsigned char> keyBytes(
                        ssKey.begin(), ssKey.end());
                    const std::vector<unsigned char> valueBytes(
                        ssValue.begin(), ssValue.end());
                    records.push_back(std::make_pair(keyBytes, valueBytes));
                }
            }
            catch (...)
            {
                ok = false;
            }
        }
        if (pcursor->close() != 0)
            ok = false;
        return ok;
    }

    bool ReplaceAdrenalineRecords(const std::vector<RawRecord>& records)
    {
        std::vector<RawRecord> current;
        if (!SnapshotAdrenalineRecords(current))
            return false;
        if (!TxnBegin())
            return false;
        for (std::vector<RawRecord>::const_iterator it = current.begin();
             it != current.end(); ++it)
        {
            Dbt datKey((void*)&it->first[0], it->first.size());
            const int ret = pdb->del(activeTxn, &datKey, 0);
            if (ret != 0 && ret != DB_NOTFOUND)
            {
                TxnAbort();
                return false;
            }
        }
        for (std::vector<RawRecord>::const_iterator it = records.begin();
             it != records.end(); ++it)
        {
            if (it->first.empty() || it->second.empty())
            {
                TxnAbort();
                return false;
            }
            Dbt datKey((void*)&it->first[0], it->first.size());
            Dbt datValue((void*)&it->second[0], it->second.size());
            if (pdb->put(activeTxn, &datKey, &datValue, 0) != 0)
            {
                TxnAbort();
                return false;
            }
        }
        return TxnCommit(true);
    }
};

class CScopedAdrenalineWalletDBRecords
{
public:
    CAdrenalineWalletDBTestAccess& walletdb;
    std::vector<CAdrenalineWalletDBTestAccess::RawRecord> original;
    bool fArmed;

    explicit CScopedAdrenalineWalletDBRecords(
        CAdrenalineWalletDBTestAccess& walletdbIn)
        : walletdb(walletdbIn), fArmed(false)
    {
    }

    ~CScopedAdrenalineWalletDBRecords()
    {
        if (fArmed)
            walletdb.ReplaceAdrenalineRecords(original);
    }
};

std::vector<unsigned char> AdrenalineValueBytes(const CDataStream& ss)
{
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

std::pair<std::string, std::string> AdrenalineLegacyTestKey(
    const std::string& strStorageKey)
{
    return std::make_pair(std::string("adrenaline"), strStorageKey);
}

std::pair<std::string, std::pair<int, std::string> >
AdrenalineCanonicalTestKey(const std::string& strStorageKey)
{
    return std::make_pair(
        std::string("adrenalinecfg"),
        std::make_pair(ADRENALINE_NODE_CONFIG_DISK_GENERATION,
                       strStorageKey));
}

std::vector<unsigned char> AdrenalineGenerationBytes(int nGeneration)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << nGeneration;
    return AdrenalineValueBytes(ss);
}

} // namespace

BOOST_AUTO_TEST_SUITE(fuzz_deserialize_tests)

BOOST_AUTO_TEST_CASE(consensus_proof_versions_preserve_legacy_stream_shadowing)
{
    struct SerializationContext
    {
        int nType;
        int nVersion;
    };
    const SerializationContext contexts[] = {
        { SER_GETHASH, 0 },
        { SER_NETWORK, PROTOCOL_VERSION },
        { SER_DISK, CLIENT_VERSION }
    };

    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i)
    {
        const SerializationContext& context = contexts[i];
        CheckLegacyShadowedVersionContext(
            CBulletproofACProof(), BPAC_PROOF_VERSION,
            context.nType, context.nVersion);
        CheckLegacyShadowedVersionContext(
            CPrivateFinalityVoteProof(), 1,
            context.nType, context.nVersion);
        CheckLegacyShadowedVersionContext(
            CFinalityTallyShare(), 2,
            context.nType, context.nVersion);
        CheckLegacyShadowedVersionContext(
            CFinalityCommitteeRotation(), 1,
            context.nType, context.nVersion);
        CheckLegacyShadowedVersionContext(
            CFinalityCertSignature(), 1,
            context.nType, context.nVersion);
        CheckLegacyShadowedVersionContext(
            CNullStakeMofNHiddenAuthProof(),
            NULLSTAKE_B2C_HIDDEN_AUTH_VERSION,
            context.nType, context.nVersion);
    }

    // CTransaction encodes nested proof objects under its own transaction version:
    // in the 2005 context the BPAC and hidden-auth members do not reach the bytes,
    // and decode restores defaults.
    CTransaction nestedSentinel;
    nestedSentinel.nVersion = SHIELDED_TX_VERSION_NULLSTAKE_COLD;
    nestedSentinel.nullstakeProofV3.nThresholdM = 1;
    nestedSentinel.nullstakeProofV3.nAuthMode = NULLSTAKE_AUTHMODE_B2C_HIDDEN;
    nestedSentinel.nullstakeProofV3.acProof.nVersion = 0x12345678;
    nestedSentinel.nullstakeProofV3.hiddenAuth.nVersion = 0x12345678;

    CTransaction nestedDefaults = nestedSentinel;
    nestedDefaults.nullstakeProofV3.acProof.nVersion = BPAC_PROOF_VERSION;
    nestedDefaults.nullstakeProofV3.hiddenAuth.nVersion =
        NULLSTAKE_B2C_HIDDEN_AUTH_VERSION;

    const std::vector<unsigned char> nestedSentinelBytes =
        SerializeEnvelope(nestedSentinel);
    const std::vector<unsigned char> nestedDefaultBytes =
        SerializeEnvelope(nestedDefaults);
    BOOST_REQUIRE_EQUAL_COLLECTIONS(
        nestedSentinelBytes.begin(), nestedSentinelBytes.end(),
        nestedDefaultBytes.begin(), nestedDefaultBytes.end());

    CTransaction nestedDecoded;
    CDataStream nestedDecode(nestedSentinelBytes, SER_NETWORK,
                             PROTOCOL_VERSION);
    nestedDecode >> nestedDecoded;
    BOOST_REQUIRE(nestedDecode.empty());
    BOOST_CHECK_EQUAL(nestedDecoded.nullstakeProofV3.acProof.nVersion,
                      BPAC_PROOF_VERSION);
    BOOST_CHECK_EQUAL(
        nestedDecoded.nullstakeProofV3.hiddenAuth.nVersion,
        (unsigned int)NULLSTAKE_B2C_HIDDEN_AUTH_VERSION);
}

BOOST_AUTO_TEST_CASE(adrenaline_wallet_disk_migration_is_lossless_and_fail_closed)
{
    CAdrenalineWalletDBTestAccess walletdb(pwalletMain->strWalletFile);
    CScopedAdrenalineWalletDBRecords restore(walletdb);
    BOOST_REQUIRE(walletdb.SnapshotAdrenalineRecords(restore.original));
    restore.fArmed = true;
    const std::vector<CAdrenalineWalletDBTestAccess::RawRecord> emptyRecords;
    BOOST_REQUIRE(walletdb.ReplaceAdrenalineRecords(emptyRecords));

    const std::string strStorageKey = "storage-key";
    const std::pair<std::string, std::string> legacyKey =
        AdrenalineLegacyTestKey(strStorageKey);
    const std::pair<std::string, std::pair<int, std::string> > canonicalKey =
        AdrenalineCanonicalTestKey(strStorageKey);
    const std::string schemaKey = "adrenalinecfgschema";
    const int nHistoricalSerializerVersion = 4010203;

    CDataStream ssLegacyKeyGolden(SER_DISK, CLIENT_VERSION);
    ssLegacyKeyGolden << legacyKey;
    BOOST_REQUIRE(AdrenalineValueBytes(ssLegacyKeyGolden) == ParseHex(
        "0a616472656e616c696e650b73746f726167652d6b6579"));
    CDataStream ssCanonicalKeyGolden(SER_DISK, CLIENT_VERSION);
    ssCanonicalKeyGolden << canonicalKey;
    BOOST_REQUIRE(AdrenalineValueBytes(ssCanonicalKeyGolden) == ParseHex(
        "0d616472656e616c696e65636667010000000b73746f726167652d6b6579"));

    CAdrenalineNodeConfig legacyConfig(
        "a", "payload-address", "p", "t", "3");
    legacyConfig.nVersion = 77; // never represented by generation 0
    CDataStream ssLegacy(SER_DISK, nHistoricalSerializerVersion);
    std::string strCodecError;
    BOOST_REQUIRE_MESSAGE(EncodeLegacyAdrenalineNodeConfigValue(
        legacyConfig, nHistoricalSerializerVersion, ssLegacy,
        strCodecError), strCodecError);
    const std::vector<unsigned char> legacyBytes =
        AdrenalineValueBytes(ssLegacy);
    const std::vector<unsigned char> legacyGolden = ParseHex(
        "db303d0001610f7061796c6f61642d61646472657373017001740133");
    BOOST_REQUIRE(legacyBytes == legacyGolden);
    CDataStream ssFutureLegacy(SER_DISK, CLIENT_VERSION + 1);
    BOOST_CHECK(!EncodeLegacyAdrenalineNodeConfigValue(
        legacyConfig, CLIENT_VERSION + 1, ssFutureLegacy,
        strCodecError));
    BOOST_REQUIRE(walletdb.PutRawValue(legacyKey, legacyBytes));

    // Golden generation-0 semantics: the first word is provenance, and the
    // lost logical member is restored to its historical constructor value.
    CDataStream ssLegacyGolden(legacyBytes, SER_DISK, CLIENT_VERSION);
    CAdrenalineNodeConfig decodedLegacy;
    int nDecodedSerializerVersion = 0;
    BOOST_REQUIRE_MESSAGE(DecodeLegacyAdrenalineNodeConfigValue(
        ssLegacyGolden, decodedLegacy, nDecodedSerializerVersion,
        strCodecError), strCodecError);
    BOOST_CHECK_EQUAL(nDecodedSerializerVersion,
                      nHistoricalSerializerVersion);
    BOOST_CHECK_EQUAL(decodedLegacy.nVersion, 0);
    BOOST_CHECK_EQUAL(decodedLegacy.sAlias, legacyConfig.sAlias);
    BOOST_CHECK_EQUAL(decodedLegacy.sAddress, legacyConfig.sAddress);
    BOOST_CHECK_EQUAL(decodedLegacy.sCollateralnodePrivKey,
                      legacyConfig.sCollateralnodePrivKey);
    BOOST_CHECK(decodedLegacy.sAddress != strStorageKey);

    // The logical serializer does not shadow the member; legacy BDB compatibility
    // is only the explicit generation-0 codec.
    CDataStream ssLogical(SER_DISK, CLIENT_VERSION);
    ssLogical << legacyConfig;
    CAdrenalineNodeConfig logicalRoundTrip;
    ssLogical >> logicalRoundTrip;
    BOOST_REQUIRE(ssLogical.empty());
    BOOST_CHECK_EQUAL(logicalRoundTrip.nVersion, legacyConfig.nVersion);

    CAdrenalineNodeConfig preMigrationRead;
    BOOST_REQUIRE(walletdb.ReadAdrenalineNodeConfig(
        strStorageKey, preMigrationRead));
    BOOST_CHECK_EQUAL(preMigrationRead.nVersion, 0);

    std::vector<unsigned char> malformedLegacy = legacyBytes;
    malformedLegacy.push_back(0x5a);
    BOOST_REQUIRE(walletdb.PutRawValue(legacyKey, malformedLegacy));
    std::string strMigrationError;
    BOOST_CHECK(!walletdb.MigrateAdrenalineNodeConfigRecords(
        strMigrationError));
    int nGeneration = 0;
    BOOST_CHECK(!walletdb.ReadAdrenalineNodeConfigGeneration(nGeneration));
    std::vector<unsigned char> absentCanonical;
    BOOST_CHECK(!walletdb.GetRawValue(canonicalKey, absentCanonical));
    std::vector<unsigned char> malformedLegacyAfterFailure;
    BOOST_REQUIRE(walletdb.GetRawValue(legacyKey,
                                       malformedLegacyAfterFailure));
    BOOST_CHECK(malformedLegacyAfterFailure == malformedLegacy);
    BOOST_REQUIRE(walletdb.PutRawValue(legacyKey, legacyBytes));

    // Read-only startup validates the same bounded snapshot transactionally,
    // but cannot publish a partial generation or schema marker.
    {
        CAdrenalineWalletDBTestAccess readOnly(
            pwalletMain->strWalletFile, "r");
        BOOST_REQUIRE_MESSAGE(readOnly.MigrateAdrenalineNodeConfigRecords(
            strMigrationError), strMigrationError);
    }
    BOOST_CHECK(!walletdb.ReadAdrenalineNodeConfigGeneration(nGeneration));
    BOOST_CHECK(!walletdb.GetRawValue(canonicalKey, absentCanonical));
    std::vector<unsigned char> legacyAfterReadOnlyValidation;
    BOOST_REQUIRE(walletdb.GetRawValue(
        legacyKey, legacyAfterReadOnlyValidation));
    BOOST_CHECK(legacyAfterReadOnlyValidation == legacyBytes);

    // Fresh migration writes the distinct canonical record and marker while
    // leaving the complete legacy value byte-for-byte unchanged.
    BOOST_REQUIRE_MESSAGE(walletdb.MigrateAdrenalineNodeConfigRecords(
        strMigrationError), strMigrationError);
    BOOST_REQUIRE(walletdb.ReadAdrenalineNodeConfigGeneration(nGeneration));
    BOOST_CHECK_EQUAL(nGeneration,
                      ADRENALINE_NODE_CONFIG_DISK_GENERATION);
    std::vector<unsigned char> legacyAfterMigration;
    std::vector<unsigned char> canonicalAfterMigration;
    std::vector<unsigned char> markerAfterMigration;
    BOOST_REQUIRE(walletdb.GetRawValue(legacyKey, legacyAfterMigration));
    BOOST_REQUIRE(walletdb.GetRawValue(canonicalKey,
                                       canonicalAfterMigration));
    BOOST_REQUIRE(walletdb.GetRawValue(schemaKey, markerAfterMigration));
    BOOST_CHECK(legacyAfterMigration == legacyBytes);
    BOOST_CHECK(markerAfterMigration == ParseHex("01000000"));

    CAdrenalineNodeConfig migratedConfig;
    BOOST_REQUIRE(walletdb.ReadAdrenalineNodeConfig(
        strStorageKey, migratedConfig));
    BOOST_CHECK_EQUAL(migratedConfig.nVersion, 0);
    BOOST_CHECK_EQUAL(migratedConfig.sTxHash, legacyConfig.sTxHash);
    BOOST_CHECK_EQUAL(migratedConfig.sAddress, legacyConfig.sAddress);

    // A newly opened wallet-DB wrapper performs an idempotent startup pass and
    // rewrites neither generation. Process-death durability remains an
    // integration/failpoint concern outside the in-memory unit fixture.
    {
        CAdrenalineWalletDBTestAccess reopened(pwalletMain->strWalletFile);
        BOOST_REQUIRE_MESSAGE(reopened.MigrateAdrenalineNodeConfigRecords(
            strMigrationError), strMigrationError);
    }
    std::vector<unsigned char> idempotentLegacy;
    std::vector<unsigned char> idempotentCanonical;
    std::vector<unsigned char> idempotentMarker;
    BOOST_REQUIRE(walletdb.GetRawValue(legacyKey, idempotentLegacy));
    BOOST_REQUIRE(walletdb.GetRawValue(canonicalKey,
                                       idempotentCanonical));
    BOOST_REQUIRE(walletdb.GetRawValue(schemaKey, idempotentMarker));
    BOOST_CHECK(idempotentLegacy == legacyAfterMigration);
    BOOST_CHECK(idempotentCanonical == canonicalAfterMigration);
    BOOST_CHECK(idempotentMarker == markerAfterMigration);

    // New writes are one synchronous transaction over the downgrade-readable
    // legacy value, canonical logical value, and active-generation marker.
    CAdrenalineNodeConfig currentConfig(
        "b", "payload-2", "q", "u", "5");
    currentConfig.nVersion = 7;
    BOOST_REQUIRE(walletdb.WriteAdrenalineNodeConfig(
        strStorageKey, currentConfig));
    CAdrenalineNodeConfig currentRead;
    BOOST_REQUIRE(walletdb.ReadAdrenalineNodeConfig(
        strStorageKey, currentRead));
    BOOST_CHECK_EQUAL(currentRead.nVersion, currentConfig.nVersion);
    BOOST_CHECK_EQUAL(currentRead.sAlias, currentConfig.sAlias);

    std::vector<unsigned char> downgradeReadableBytes;
    std::vector<unsigned char> currentCanonicalBytes;
    BOOST_REQUIRE(walletdb.GetRawValue(legacyKey,
                                       downgradeReadableBytes));
    BOOST_REQUIRE(walletdb.GetRawValue(canonicalKey,
                                       currentCanonicalBytes));
    CDataStream ssExpectedCanonical(SER_DISK, CLIENT_VERSION);
    BOOST_REQUIRE_MESSAGE(EncodeCanonicalAdrenalineNodeConfigValue(
        strStorageKey, currentConfig, ssExpectedCanonical,
        strCodecError), strCodecError);
    BOOST_CHECK(currentCanonicalBytes ==
                AdrenalineValueBytes(ssExpectedCanonical));
    const std::vector<unsigned char> canonicalGolden = ParseHex(
        "494e4331010000000b73746f726167652d6b6579070000000162097061796c6f61642d32017101750135");
    BOOST_CHECK(currentCanonicalBytes == canonicalGolden);
    CDataStream ssDowngradeRead(downgradeReadableBytes,
                                SER_DISK, CLIENT_VERSION);
    CAdrenalineNodeConfig downgradeRead;
    BOOST_REQUIRE_MESSAGE(DecodeLegacyAdrenalineNodeConfigValue(
        ssDowngradeRead, downgradeRead, nDecodedSerializerVersion,
        strCodecError), strCodecError);
    BOOST_CHECK_EQUAL(nDecodedSerializerVersion, CLIENT_VERSION);
    BOOST_CHECK_EQUAL(downgradeRead.nVersion, 0);
    BOOST_CHECK_EQUAL(downgradeRead.sAlias, currentConfig.sAlias);
    BOOST_CHECK_EQUAL(downgradeRead.sTxHash, currentConfig.sTxHash);

    // Simulate an old binary changing only the generation-0 value. The next
    // generation-1 reader and restart both reject the mismatch rather than
    // guessing which private-key-bearing record is authoritative.
    CAdrenalineNodeConfig oldWriterConfig = currentConfig;
    oldWriterConfig.sTxHash = "v";
    CDataStream ssOldWriter(SER_DISK, nHistoricalSerializerVersion);
    BOOST_REQUIRE_MESSAGE(EncodeLegacyAdrenalineNodeConfigValue(
        oldWriterConfig, nHistoricalSerializerVersion, ssOldWriter,
        strCodecError), strCodecError);
    BOOST_REQUIRE(walletdb.PutRawValue(
        legacyKey, AdrenalineValueBytes(ssOldWriter)));
    CAdrenalineNodeConfig rejectedMismatch;
    BOOST_CHECK(!walletdb.ReadAdrenalineNodeConfig(
        strStorageKey, rejectedMismatch));
    BOOST_CHECK(!walletdb.MigrateAdrenalineNodeConfigRecords(
        strMigrationError));
    BOOST_CHECK(strMigrationError.find("differ") != std::string::npos);
    BOOST_CHECK(!walletdb.WriteAdrenalineNodeConfig(
        strStorageKey, currentConfig));
    std::vector<unsigned char> canonicalAfterMismatch;
    BOOST_REQUIRE(walletdb.GetRawValue(canonicalKey,
                                       canonicalAfterMismatch));
    BOOST_CHECK(canonicalAfterMismatch == currentCanonicalBytes);
    BOOST_REQUIRE(walletdb.PutRawValue(legacyKey,
                                       downgradeReadableBytes));

    // Exact canonical decoding rejects trailing corruption and identity swaps.
    std::vector<unsigned char> trailingCanonical = currentCanonicalBytes;
    trailingCanonical.push_back(0xa5);
    BOOST_REQUIRE(walletdb.PutRawValue(canonicalKey, trailingCanonical));
    BOOST_CHECK(!walletdb.ReadAdrenalineNodeConfig(
        strStorageKey, rejectedMismatch));
    BOOST_CHECK(!walletdb.MigrateAdrenalineNodeConfigRecords(
        strMigrationError));
    BOOST_REQUIRE(walletdb.PutRawValue(canonicalKey,
                                       currentCanonicalBytes));
    CDataStream ssWrongIdentity(currentCanonicalBytes,
                                SER_DISK, CLIENT_VERSION);
    BOOST_CHECK(!DecodeCanonicalAdrenalineNodeConfigValue(
        ssWrongIdentity, "different-storage-key", rejectedMismatch,
        strCodecError));

    // Schema transitions are forward-only. Unknown generations, and a
    // canonical record whose marker disappeared, both fail without rewriting
    // either representation.
    std::vector<unsigned char> trailingMarker = markerAfterMigration;
    trailingMarker.push_back(0x01);
    BOOST_REQUIRE(walletdb.PutRawValue(schemaKey, trailingMarker));
    BOOST_CHECK(!walletdb.MigrateAdrenalineNodeConfigRecords(
        strMigrationError));
    BOOST_REQUIRE(walletdb.PutRawValue(schemaKey, markerAfterMigration));
    BOOST_REQUIRE(walletdb.PutRawValue(
        schemaKey,
        AdrenalineGenerationBytes(
            ADRENALINE_NODE_CONFIG_DISK_GENERATION + 1)));
    BOOST_CHECK(!walletdb.MigrateAdrenalineNodeConfigRecords(
        strMigrationError));
    BOOST_CHECK(!walletdb.ReadAdrenalineNodeConfig(
        strStorageKey, rejectedMismatch));
    BOOST_REQUIRE(walletdb.PutRawValue(schemaKey, markerAfterMigration));
    BOOST_REQUIRE(walletdb.DeleteRawValue(schemaKey));
    BOOST_CHECK(!walletdb.MigrateAdrenalineNodeConfigRecords(
        strMigrationError));
    BOOST_CHECK(strMigrationError.find("without a schema marker") !=
                std::string::npos);
    std::vector<unsigned char> finalLegacy;
    std::vector<unsigned char> finalCanonical;
    BOOST_REQUIRE(walletdb.GetRawValue(legacyKey, finalLegacy));
    BOOST_REQUIRE(walletdb.GetRawValue(canonicalKey, finalCanonical));
    BOOST_CHECK(finalLegacy == downgradeReadableBytes);
    BOOST_CHECK(finalCanonical == currentCanonicalBytes);
    BOOST_REQUIRE(walletdb.PutRawValue(schemaKey, markerAfterMigration));
    BOOST_REQUIRE(walletdb.ReplaceAdrenalineRecords(restore.original));
    restore.fArmed = false;
}

BOOST_AUTO_TEST_CASE(shielded_sender_recovery_ciphertext_matches_legacy_wire_size)
{
    CShieldedNote note;
    note.nValue = 42;

    CDataStream plaintext(SER_NETWORK, 0);
    plaintext << note.addr;
    plaintext << note.nValue;
    BOOST_REQUIRE_EQUAL(plaintext.size(), 54U);

    uint256 ovk(1);
    uint256 cv(2);
    uint256 cmu(3);
    std::vector<unsigned char> ephemeralKey(
        SHIELDED_EPHEMERAL_KEY_SIZE, 0x02);
    std::vector<unsigned char> ciphertext;
    BOOST_REQUIRE(EncryptShieldedNoteForSender(
        note, ovk, cv, cmu, ephemeralKey, ciphertext));

    const size_t nProducedSize = 12 + plaintext.size() + 16;
    BOOST_CHECK_EQUAL(nProducedSize, 82U);
    BOOST_CHECK_EQUAL(ciphertext.size(), nProducedSize);
    BOOST_CHECK_EQUAL(SHIELDED_OUT_CIPHERTEXT_SIZE, 82U);
    BOOST_CHECK_EQUAL(ciphertext.size(), SHIELDED_OUT_CIPHERTEXT_SIZE);
}

BOOST_AUTO_TEST_CASE(shielded_recipient_payload_decoding_is_exact_and_versioned)
{
    CShieldedPaymentAddress address;
    std::fill(address.vchDiversifier.begin(), address.vchDiversifier.end(),
              0x11);
    std::fill(address.vchPkD.begin(), address.vchPkD.end(), 0x22);

    CDataStream addressStream(SER_NETWORK, 0);
    addressStream << address;
    const std::vector<unsigned char> addressBytes(
        addressStream.begin(), addressStream.end());
    BOOST_REQUIRE_EQUAL(addressBytes.size(), 46U);

    ShieldedRecipientPayloadKind kind = SHIELDED_RECIPIENT_NONE;
    CShieldedPaymentAddress decodedAddress;
    CShieldedNote decodedNote;
    BOOST_REQUIRE(DecodeShieldedRecipientPayload(
        SHIELDED_TX_VERSION_DSP, addressBytes, kind,
        decodedAddress, decodedNote));
    BOOST_CHECK_EQUAL(kind, SHIELDED_RECIPIENT_ADDRESS);
    BOOST_CHECK(decodedAddress == address);

    CShieldedNote legacyNote;
    legacyNote.addr = address;
    legacyNote.nValue = 42;
    legacyNote.rho = uint256(0x1234);
    legacyNote.rcm = uint256(0x5678);
    legacyNote.vchBlind.resize(BLINDING_FACTOR_SIZE, 0x33);
    CDataStream noteStream(SER_NETWORK, 0);
    noteStream << legacyNote;
    const std::vector<unsigned char> noteBytes(
        noteStream.begin(), noteStream.end());
    BOOST_REQUIRE_EQUAL(noteBytes.size(), 151U);

    BOOST_REQUIRE(DecodeShieldedRecipientPayload(
        SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM, noteBytes, kind,
        decodedAddress, decodedNote));
    BOOST_CHECK_EQUAL(kind, SHIELDED_RECIPIENT_LEGACY_NOTE);
    BOOST_CHECK(decodedAddress == address);
    BOOST_CHECK_EQUAL(decodedNote.nValue, legacyNote.nValue);
    BOOST_CHECK(decodedNote.rho == legacyNote.rho);
    BOOST_CHECK(decodedNote.rcm == legacyNote.rcm);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        decodedNote.vchBlind.begin(), decodedNote.vchBlind.end(),
        legacyNote.vchBlind.begin(), legacyNote.vchBlind.end());

    std::vector<unsigned char> trailingAddress = addressBytes;
    trailingAddress.push_back(0x00);
    BOOST_CHECK(!DecodeShieldedRecipientPayload(
        SHIELDED_TX_VERSION_DSP, trailingAddress, kind,
        decodedAddress, decodedNote));
    std::vector<unsigned char> shortNote = noteBytes;
    shortNote.pop_back();
    BOOST_CHECK(!DecodeShieldedRecipientPayload(
        SHIELDED_TX_VERSION_DSP, shortNote, kind,
        decodedAddress, decodedNote));

    BOOST_CHECK(!DecodeShieldedRecipientPayload(
        SHIELDED_TX_VERSION, addressBytes, kind,
        decodedAddress, decodedNote));
    BOOST_CHECK(!DecodeShieldedRecipientPayload(
        SHIELDED_TX_VERSION_VNEXT, addressBytes, kind,
        decodedAddress, decodedNote));

    const std::vector<unsigned char> empty;
    BOOST_REQUIRE(DecodeShieldedRecipientPayload(
        SHIELDED_TX_VERSION, empty, kind, decodedAddress, decodedNote));
    BOOST_CHECK_EQUAL(kind, SHIELDED_RECIPIENT_NONE);
}

BOOST_AUTO_TEST_CASE(shielded_wallet_recovery_record_is_fixed_exact_and_bound)
{
    ShieldedWalletRecoveryDiskTestDB txdb;
    CShieldedWalletRecoveryRecord record;
    record.nSchema = SHIELDED_WALLET_RECOVERY_SCHEMA;
    record.hashOldTip = uint256(1);
    record.hashFork = uint256(1);
    record.hashNewTip = uint256(2);
    record.nDisconnect = 0;
    record.nConnect = 1;
    record.hashEffectPlan = uint256(3);
    BOOST_REQUIRE(record.IsValid());
    BOOST_CHECK_LE(::GetSerializeSize(record, SER_DISK, CLIENT_VERSION),
                   256U);

    BOOST_REQUIRE(txdb.WriteShieldedWalletRecovery(record));
    CShieldedWalletRecoveryRecord decoded;
    BOOST_CHECK_EQUAL(txdb.ReadShieldedWalletRecoveryStatus(decoded),
                      TXDB_READ_FOUND);
    BOOST_CHECK(decoded.hashOldTip == record.hashOldTip);
    BOOST_CHECK(decoded.hashNewTip == record.hashNewTip);
    BOOST_CHECK(decoded.hashEffectPlan == record.hashEffectPlan);

    // A stale/different recovery attempt must never acknowledge the current
    // outbox.  Only the exact record returned by successful replay may clear
    // it, and the clear itself is a synchronous LevelDB batch.
    CShieldedWalletRecoveryRecord mismatched = record;
    mismatched.hashNewTip = uint256(4);
    BOOST_REQUIRE(mismatched.IsValid());
    BOOST_CHECK(!txdb.AcknowledgeShieldedWalletRecovery(mismatched));
    BOOST_CHECK_EQUAL(txdb.ReadShieldedWalletRecoveryStatus(decoded),
                      TXDB_READ_FOUND);
    BOOST_CHECK(decoded.hashNewTip == record.hashNewTip);
    BOOST_REQUIRE(txdb.AcknowledgeShieldedWalletRecovery(record));
    BOOST_CHECK_EQUAL(txdb.ReadShieldedWalletRecoveryStatus(decoded),
                      TXDB_READ_NOT_FOUND);

    CShieldedWalletRecoveryRecord rollback = record;
    rollback.hashOldTip = uint256(4);
    rollback.hashFork = rollback.hashNewTip;
    rollback.nDisconnect = 1;
    rollback.nConnect = 0;
    BOOST_REQUIRE(rollback.IsValid());
    BOOST_REQUIRE(txdb.WriteShieldedWalletRecovery(rollback));
    BOOST_CHECK_EQUAL(txdb.ReadShieldedWalletRecoveryStatus(decoded),
                      TXDB_READ_FOUND);
    BOOST_CHECK_EQUAL(decoded.nDisconnect, 1U);
    BOOST_CHECK_EQUAL(decoded.nConnect, 0U);

    ShieldedWalletRecoveryWithTrailingByte trailing;
    trailing.record = record;
    BOOST_REQUIRE(txdb.WriteRawRecovery(trailing));
    BOOST_CHECK_EQUAL(txdb.ReadShieldedWalletRecoveryStatus(decoded),
                      TXDB_READ_ERROR);

    BOOST_REQUIRE(txdb.WriteRawRecovery((unsigned char)1));
    BOOST_CHECK_EQUAL(txdb.ReadShieldedWalletRecoveryStatus(decoded),
                      TXDB_READ_ERROR);
    BOOST_REQUIRE(txdb.EraseShieldedWalletRecovery());
    BOOST_CHECK_EQUAL(txdb.ReadShieldedWalletRecoveryStatus(decoded),
                      TXDB_READ_NOT_FOUND);

    std::set<uint256> skipped;
    skipped.insert(uint256(9));
    std::vector<CShieldedWalletEffectDigestEntry> plan;
    plan.push_back(CShieldedWalletEffectDigestEntry(
        false, uint256(10), skipped));
    const uint256 digest = ComputeShieldedWalletEffectPlanDigest(plan);
    BOOST_CHECK(digest != 0);
    plan[0].fConnect = true;
    BOOST_CHECK(ComputeShieldedWalletEffectPlanDigest(plan) != digest);
}

BOOST_AUTO_TEST_CASE(anonymous_consensus_records_use_exact_tristate_reads)
{
    AnonExactDiskTestDB txdb;

    ec_point keyImage(ec_compressed_size, 0x11);
    KeyImageSpentWithTrailingByte trailingKeyImage;
    trailingKeyImage.spent.txnHash = uint256(0xa001);
    trailingKeyImage.spent.inputNo = 2;
    trailingKeyImage.spent.nValue = 3;
    BOOST_REQUIRE(txdb.WriteRawKeyImage(keyImage, trailingKeyImage));
    CKeyImageSpent decodedSpent;
    BOOST_CHECK_EQUAL(txdb.ReadKeyImageStatus(keyImage, decodedSpent),
                      TXDB_READ_ERROR);
    BOOST_REQUIRE(txdb.EraseKeyImage(keyImage));
    BOOST_CHECK_EQUAL(txdb.ReadKeyImageStatus(keyImage, decodedSpent),
                      TXDB_READ_NOT_FOUND);

    std::vector<unsigned char> pubkeyBytes(ec_compressed_size, 0x22);
    pubkeyBytes[0] = 0x02;
    CPubKey pubkey(pubkeyBytes);
    COutPoint outpoint(uint256(0xa002), 1);
    AnonOutputWithTrailingByte trailingOutput;
    trailingOutput.output = CAnonOutput(outpoint, 4, 5, 0);
    BOOST_REQUIRE(txdb.WriteRawAnonOutput(pubkey, trailingOutput));
    CAnonOutput decodedOutput;
    BOOST_CHECK_EQUAL(txdb.ReadAnonOutputStatus(pubkey, decodedOutput),
                      TXDB_READ_ERROR);
    BOOST_REQUIRE(txdb.EraseAnonOutput(pubkey));
    BOOST_CHECK_EQUAL(txdb.ReadAnonOutputStatus(pubkey, decodedOutput),
                      TXDB_READ_NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(anonymous_chain_effects_are_outer_batch_atomic_and_fail_closed)
{
    AnonMainnetModeGuard networkGuard;
    AnonExactDiskTestDB txdb;
    const int nBlockHeight = 100;

    std::vector<unsigned char> pubkeyBytes(ec_compressed_size, 0x22);
    pubkeyBytes[0] = 0x02;
    CScript anonScript;
    anonScript.resize(MIN_ANON_OUT_SIZE, 0);
    anonScript[0] = OP_RETURN;
    anonScript[1] = OP_ANON_MARKER;
    anonScript[2] = ec_compressed_size;
    std::copy(pubkeyBytes.begin(), pubkeyBytes.end(),
              anonScript.begin() + 3);
    anonScript[3 + ec_compressed_size] = ec_compressed_size;
    std::copy(pubkeyBytes.begin(), pubkeyBytes.end(),
              anonScript.begin() + 4 + ec_compressed_size);

    CTransaction tx;
    tx.nVersion = ANON_TXN_VERSION;
    tx.nTime = 123;
    tx.vout.push_back(CTxOut(7, anonScript));
    const CPubKey pkCoin = tx.vout[0].ExtractAnonPk();

    // Effect application is deliberately unavailable outside the enclosing
    // chain transaction.
    CLegacyAnonEffectPlan plan;
    std::string error;
    BOOST_CHECK(!ApplyLegacyAnonEffectPlan(txdb, plan, error));
    BOOST_CHECK(error.find("outer chain transaction") != std::string::npos);

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.EraseAnonOutput(pkCoin));
    {
        LOCK(cs_main);
        std::set<ec_point> blockKeyImages;
        bool invalid = false;
        BOOST_REQUIRE(tx.BuildLegacyAnonEffectPlan(
            txdb, nBlockHeight, blockKeyImages, plan, invalid));
        BOOST_CHECK(!invalid);
    }
    BOOST_REQUIRE_EQUAL(plan.vOutputs.size(), 1U);

    COutPoint conflictingOutpoint(uint256(0xa200), 0);
    CAnonOutput conflictingOutput(conflictingOutpoint, 7,
                                  nBlockHeight, 0);
    BOOST_REQUIRE(txdb.WriteAnonOutput(pkCoin, conflictingOutput));
    BOOST_CHECK(!ApplyLegacyAnonEffectPlan(txdb, plan, error));
    BOOST_CHECK(error.find("changed after validation") !=
                std::string::npos);
    BOOST_REQUIRE(txdb.EraseAnonOutput(pkCoin));

    BOOST_REQUIRE(ApplyLegacyAnonEffectPlan(txdb, plan, error));
    // Replaying the exact plan in the same batch is idempotent.
    BOOST_REQUIRE(ApplyLegacyAnonEffectPlan(txdb, plan, error));

    CAnonOutput stored;
    BOOST_REQUIRE_EQUAL(txdb.ReadAnonOutputStatus(pkCoin, stored),
                        TXDB_READ_FOUND);
    BOOST_CHECK_EQUAL(stored.nBlockHeight, nBlockHeight);
    BOOST_CHECK_EQUAL(stored.nValue, 7);

    BOOST_REQUIRE(DisconnectLegacyAnonChainState(
        txdb, tx, nBlockHeight, error));
    BOOST_CHECK_EQUAL(txdb.ReadAnonOutputStatus(pkCoin, stored),
                      TXDB_READ_NOT_FOUND);
    // Missing exact state on a duplicate rollback is corruption, not a no-op.
    BOOST_CHECK(!DisconnectLegacyAnonChainState(
        txdb, tx, nBlockHeight, error));
    BOOST_CHECK(error.find("missing/corrupt/mismatched") !=
                std::string::npos);
    BOOST_REQUIRE(txdb.TxnAbort());

    // The consensus builder owns post-deprecation rejection as well as the
    // earlier AcceptBlock defense.
    {
        LOCK(cs_main);
        std::set<ec_point> blockKeyImages;
        bool invalid = false;
        BOOST_CHECK(!tx.BuildLegacyAnonEffectPlan(
            txdb, FORK_HEIGHT_RINGSIG_DEPRECATION,
            blockKeyImages, plan, invalid));
        BOOST_CHECK(invalid);
    }
}

BOOST_AUTO_TEST_CASE(anonymous_block_key_image_duplicates_are_candidate_local)
{
    AnonMainnetModeGuard networkGuard;
    AnonExactDiskTestDB txdb;

    CTransaction tx;
    tx.nVersion = ANON_TXN_VERSION;
    tx.nTime = 456;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = uint256(0xa100);
    tx.vin[0].prevout.n = ((uint32_t)MIN_RING_SIZE << 16) | 1;
    tx.vin[0].scriptSig.resize(
        2 + (size_t)MIN_RING_SIZE * ec_compressed_size, 0x42);
    tx.vin[0].scriptSig[0] = OP_RETURN;
    tx.vin[0].scriptSig[1] = OP_ANON_MARKER;
    tx.vout.push_back(CTxOut(1, CScript() << OP_TRUE));

    ec_point keyImage;
    tx.vin[0].ExtractKeyImage(keyImage);
    std::set<ec_point> blockKeyImages;
    BOOST_REQUIRE(blockKeyImages.insert(keyImage).second);

    int64_t valueIn = 0;
    bool invalid = false;
    std::vector<std::pair<ec_point, CKeyImageSpent> > effects;
    {
        LOCK(cs_main);
        BOOST_CHECK(!tx.CheckAnonInputs(
            txdb, 100, valueIn, invalid, false,
            &blockKeyImages, &effects));
    }
    BOOST_CHECK(invalid);
    BOOST_CHECK(effects.empty());
}

BOOST_AUTO_TEST_CASE(finality_envelopes_accept_maxima_and_reject_max_plus_one)
{
    CFinalityVote vote;
    vote.vStakeProof.resize(FINALITY_MAX_STAKE_PROOFS);
    BOOST_CHECK(RoundTripsAtLimit(vote));
    vote.vStakeProof.push_back(COutPoint());
    BOOST_CHECK(RejectsWithoutThrow(vote));

    CFinalityTallyShare share;
    share.nVersion = 2;
    share.vEncryptedRecipientShares.assign(
        FINALITY_MAX_TALLY_COMMITTEE, std::vector<unsigned char>(1, 0x11));
    share.vchShareProof.assign(BPAC_V3_MAX_PROOF_SIZE, 0x12);
    BOOST_CHECK(RoundTripsAtLimit(share));

    CFinalityTallyShare oversizedShare = share;
    oversizedShare.vEncryptedRecipientShares.push_back(
        std::vector<unsigned char>(1, 0x13));
    BOOST_CHECK(RejectsWithoutThrow(oversizedShare));
    oversizedShare = CFinalityTallyShare();
    oversizedShare.vEncryptedRecipientShares.push_back(
        std::vector<unsigned char>(BPAC_V3_MAX_PROOF_SIZE + 1, 0x14));
    BOOST_CHECK(RejectsWithoutThrow(oversizedShare));

    CFinalityTallyAggregatePartial partial;
    partial.nVersion = 3;
    partial.vTallyShareHashes.assign(FINALITY_MAX_VOTES, uint256(1));
    partial.vEncryptedRecipientPartials.assign(
        FINALITY_MAX_TALLY_COMMITTEE, std::vector<unsigned char>(1, 0x21));
    partial.vchSourceSig.assign(80, 0x22);
    BOOST_CHECK(RoundTripsAtLimit(partial));

    CFinalityTallyAggregatePartial oversizedPartial = partial;
    oversizedPartial.vTallyShareHashes.push_back(uint256(2));
    BOOST_CHECK(RejectsWithoutThrow(oversizedPartial));

    CFinalityTallyCertificate certificate;
    certificate.nVersion = 3;
    certificate.vVoteNullifiers.assign(FINALITY_MAX_VOTES, uint256(3));
    certificate.vchAggregateThresholdProof.assign(BPAC_V3_MAX_PROOF_SIZE, 0x31);
    certificate.vchRewardBudgetProof.assign(BPAC_V3_MAX_PROOF_SIZE, 0x32);
    certificate.vSignerIndexes.resize(FINALITY_MAX_TALLY_COMMITTEE);
    certificate.vSignerSigs.assign(
        FINALITY_MAX_TALLY_COMMITTEE, std::vector<unsigned char>(80, 0x33));
    BOOST_CHECK(RoundTripsAtLimit(certificate));

    CFinalityTallyCertificate oversizedCertificate = certificate;
    oversizedCertificate.vVoteNullifiers.push_back(uint256(4));
    BOOST_CHECK(RejectsWithoutThrow(oversizedCertificate));

    CFinalityCommitteeRotation rotation;
    rotation.vNewPubKeys.assign(
        FINALITY_MAX_TALLY_COMMITTEE, std::vector<unsigned char>(33, 0x41));
    rotation.vSignerIndexes.resize(FINALITY_MAX_TALLY_COMMITTEE);
    rotation.vSignerSigs.assign(
        FINALITY_MAX_TALLY_COMMITTEE, std::vector<unsigned char>(80, 0x42));
    BOOST_CHECK(RoundTripsAtLimit(rotation));

    CFinalityCommitteeRotation oversizedRotation = rotation;
    oversizedRotation.vNewPubKeys.push_back(std::vector<unsigned char>(33, 0x43));
    BOOST_CHECK(RejectsWithoutThrow(oversizedRotation));
}

BOOST_AUTO_TEST_CASE(proof_envelopes_accept_maxima_and_reject_max_plus_one)
{
    CFCMPProof fcmp;
    fcmp.vchProof.assign(FCMP_PROOF_MAX_SIZE, 0x51);
    BOOST_CHECK(RoundTripsAtLimit(fcmp));
    fcmp.vchProof.push_back(0x52);
    BOOST_CHECK(RejectsWithoutThrow(fcmp));

    CBulletproofRangeProof rangeProof;
    rangeProof.vchProof.assign(MAX_BULLETPROOF_PROOF_SIZE, 0x61);
    BOOST_CHECK(RoundTripsAtLimit(rangeProof));
    rangeProof.vchProof.push_back(0x62);
    BOOST_CHECK(RejectsWithoutThrow(rangeProof));

    CBulletproofACProof acProof;
    acProof.vchAI.assign(33, 0x71);
    acProof.vchAO.assign(33, 0x72);
    acProof.vchS.assign(33, 0x73);
    acProof.vchT1.assign(33, 0x74);
    acProof.vchT3.assign(33, 0x75);
    acProof.vchT4.assign(33, 0x76);
    acProof.vchT5.assign(33, 0x77);
    acProof.vchT6.assign(33, 0x78);
    acProof.ipaProof.vL.assign(
        IPA_MAX_ROUNDS, std::vector<unsigned char>(IPA_SECP256K1_POINT, 0x02));
    acProof.ipaProof.vR.assign(
        IPA_MAX_ROUNDS, std::vector<unsigned char>(IPA_SECP256K1_POINT, 0x03));
    acProof.ipaProof.vchAFinal.assign(IPA_SCALAR_SIZE, 0x04);
    acProof.ipaProof.vchBFinal.assign(IPA_SCALAR_SIZE, 0x05);
    BOOST_CHECK(RoundTripsAtLimit(acProof));

    CBulletproofACProof oversizedAC = acProof;
    oversizedAC.vchAI.push_back(0x79);
    BOOST_CHECK(RejectsWithoutThrow(oversizedAC));

    CNullStakeKernelProof nullStakeV1;
    nullStakeV1.vchProof.assign(NULLSTAKE_PROOF_MAX_SIZE, 0x81);
    BOOST_CHECK(RoundTripsAtLimit(nullStakeV1));
    nullStakeV1.vchProof.push_back(0x82);
    BOOST_CHECK(RejectsWithoutThrow(nullStakeV1));

    CNullStakeKernelProofV2 nullStakeV2;
    nullStakeV2.vchLinkProof.assign(65, 0x83);
    BOOST_CHECK(RoundTripsAtLimit(nullStakeV2));
    nullStakeV2.vchLinkProof.push_back(0x84);
    BOOST_CHECK(RejectsWithoutThrow(nullStakeV2));

    CNullStakeKernelProofV3 nullStakeV3;
    nullStakeV3.nThresholdM = 1;
    nullStakeV3.nAuthMode = NULLSTAKE_AUTHMODE_HALFAGG;
    nullStakeV3.vStakerSet.assign(
        MAX_NULLSTAKE_MOFN_MEMBERS, std::vector<unsigned char>(33, 0x85));
    nullStakeV3.vSignerPubKeys.assign(
        MAX_NULLSTAKE_MOFN_SIGNERS, std::vector<unsigned char>(33, 0x86));
    nullStakeV3.vSignerRPoints.assign(
        MAX_NULLSTAKE_MOFN_SIGNERS, std::vector<unsigned char>(33, 0x87));
    nullStakeV3.vchAggregatedSScalar.assign(32, 0x88);
    BOOST_CHECK(RoundTripsAtLimit(nullStakeV3));

    CNullStakeKernelProofV3 oversizedV3 = nullStakeV3;
    oversizedV3.vStakerSet.push_back(std::vector<unsigned char>(33, 0x89));
    BOOST_CHECK(RejectsWithoutThrow(oversizedV3));

    CNullStakeReclaimAuth reclaim;
    reclaim.vStakerSet.assign(
        MAX_NULLSTAKE_MOFN_MEMBERS, std::vector<unsigned char>(33, 0x91));
    reclaim.vchPkOwner.assign(33, 0x92);
    BOOST_CHECK(RoundTripsAtLimit(reclaim));
    reclaim.vStakerSet.push_back(std::vector<unsigned char>(33, 0x93));
    BOOST_CHECK(RejectsWithoutThrow(reclaim));

    CNullStakeMofNHiddenAuthProof hiddenAuth;
    hiddenAuth.vchResearchProof.assign(NULLSTAKE_B2C_MAX_AUTH_SIZE, 0xa1);
    BOOST_CHECK(RoundTripsAtLimit(hiddenAuth));
    hiddenAuth.vchResearchProof.push_back(0xa2);
    BOOST_CHECK(RejectsWithoutThrow(hiddenAuth));
}

BOOST_AUTO_TEST_CASE(shielded_spend_vectors_accept_exact_maxima_and_reject_max_plus_one)
{
    const CShieldedSpendDescription atLimit = ShieldedSpendAtWireLimits();
    BOOST_CHECK(RoundTripsAtLimit(atLimit));
    BOOST_CHECK(SerializeEnvelope(atLimit) ==
                SerializeShieldedSpendWithOrdinaryVectors(atLimit));

    CShieldedSpendDescription oversized = atLimit;
    oversized.vchRk.push_back(0xc1);
    BOOST_CHECK(RejectsWithoutThrow(oversized));

    oversized = atLimit;
    oversized.vchSpendAuthSig.push_back(0xc2);
    BOOST_CHECK(RejectsWithoutThrow(oversized));

    oversized = atLimit;
    oversized.vchLelantusProof.push_back(0xc3);
    BOOST_CHECK(RejectsWithoutThrow(oversized));

    oversized = atLimit;
    oversized.vAnonSet.push_back(CPedersenCommitment());
    BOOST_CHECK(RejectsWithoutThrow(oversized));

    oversized = atLimit;
    oversized.vchNullifierPoint.push_back(0xc4);
    BOOST_CHECK(RejectsWithoutThrow(oversized));

    oversized = atLimit;
    oversized.vchNullifierBindingProof.push_back(0xc5);
    BOOST_CHECK(RejectsWithoutThrow(oversized));
}

BOOST_AUTO_TEST_CASE(shielded_output_vectors_accept_transaction_ceiling_and_reject_plus_one)
{
    CShieldedOutputDescription atLimit;
    atLimit.vchEphemeralKey.assign(
        SHIELDED_TX_FIELD_MAX_WIRE_SIZE, 0xd1);
    atLimit.vchEncCiphertext.assign(
        SHIELDED_TX_FIELD_MAX_WIRE_SIZE, 0xd2);
    atLimit.vchOutCiphertext.assign(
        SHIELDED_TX_FIELD_MAX_WIRE_SIZE, 0xd3);
    BOOST_CHECK(RoundTripsAtLimit(atLimit));
    BOOST_CHECK(SerializeEnvelope(atLimit) ==
                SerializeShieldedOutputWithOrdinaryVectors(atLimit));

    CShieldedOutputDescription oversized = atLimit;
    oversized.vchEphemeralKey.push_back(0xe1);
    BOOST_CHECK(RejectsWithoutThrow(oversized));

    oversized = atLimit;
    oversized.vchEncCiphertext.push_back(0xe2);
    BOOST_CHECK(RejectsWithoutThrow(oversized));

    oversized = atLimit;
    oversized.vchOutCiphertext.push_back(0xe3);
    BOOST_CHECK(RejectsWithoutThrow(oversized));
}

BOOST_AUTO_TEST_CASE(shielded_transaction_vectors_accept_exact_consensus_maxima)
{
    CTransaction atLimit;
    atLimit.nVersion = SHIELDED_TX_VERSION;
    for (int i = 0; i < MAX_SHIELDED_INPUTS; ++i)
    {
        CShieldedSpendDescription spend;
        spend.nullifier = uint256(i + 1);
        atLimit.vShieldedSpend.push_back(spend);
    }
    atLimit.vShieldedOutput.resize(MAX_SHIELDED_OUTPUTS);
    BOOST_CHECK(RoundTripsAtLimit(atLimit));
    BOOST_CHECK(atLimit.CheckTransaction());

    CTransaction oversized = atLimit;
    CShieldedSpendDescription extraSpend;
    extraSpend.nullifier = uint256(MAX_SHIELDED_INPUTS + 1);
    oversized.vShieldedSpend.push_back(extraSpend);
    BOOST_CHECK(RejectsWithoutThrow(oversized));
    BOOST_CHECK(!oversized.CheckTransaction());

    oversized = atLimit;
    oversized.vShieldedOutput.push_back(CShieldedOutputDescription());
    BOOST_CHECK(RejectsWithoutThrow(oversized));
    BOOST_CHECK(!oversized.CheckTransaction());
}

BOOST_AUTO_TEST_CASE(shielded_transaction_optional_vectors_preserve_wire_and_reject_plus_one)
{
    CTransaction dsp;
    dsp.nVersion = SHIELDED_TX_VERSION_DSP;
    CShieldedSpendDescription dspSpend;
    dspSpend.nullifier = uint256(1);
    dspSpend.vchPlaintextBlind.assign(BLINDING_FACTOR_SIZE, 0xf1);
    dsp.vShieldedSpend.push_back(dspSpend);
    CShieldedOutputDescription dspOutput;
    dspOutput.vchPlaintextBlind.assign(BLINDING_FACTOR_SIZE, 0xf2);
    dspOutput.vchRecipientScript.assign(
        SHIELDED_TX_FIELD_MAX_WIRE_SIZE, 0xf3);
    dsp.vShieldedOutput.push_back(dspOutput);
    BOOST_CHECK(RoundTripsAtLimit(dsp));

    CTransaction oversized = dsp;
    oversized.vShieldedSpend[0].vchPlaintextBlind.push_back(0xf4);
    BOOST_CHECK(RejectsWithoutThrow(oversized));

    oversized = dsp;
    oversized.vShieldedOutput[0].vchPlaintextBlind.push_back(0xf5);
    BOOST_CHECK(RejectsWithoutThrow(oversized));

    oversized = dsp;
    oversized.vShieldedOutput[0].vchRecipientScript.push_back(0xf6);
    BOOST_CHECK(RejectsWithoutThrow(oversized));

    CTransaction mofn;
    mofn.nVersion = SHIELDED_TX_VERSION_MOFN_MINT;
    CShieldedOutputDescription mofnOutput;
    mofnOutput.nMofNType = 1;
    mofnOutput.vchMofNLink.assign(NULLSTAKE_MOFN_MINTLINK_SIZE, 0xa6);
    mofn.vShieldedOutput.push_back(mofnOutput);
    BOOST_CHECK(RoundTripsAtLimit(mofn));
    BOOST_CHECK(SerializeEnvelope(mofn) ==
                SerializeMofNMintTxWithOrdinaryVectors(mofn));

    oversized = mofn;
    oversized.vShieldedOutput[0].vchMofNLink.push_back(0xa7);
    BOOST_CHECK(RejectsWithoutThrow(oversized));

    // CheckTransaction's size gate is context-free; exercise it with a legacy
    // in-memory shape so the test does not depend on the global DSP fork height.
    CTransaction linkShape;
    linkShape.nVersion = SHIELDED_TX_VERSION;
    CShieldedOutputDescription linkOutput;
    linkOutput.vchMofNLink.assign(NULLSTAKE_MOFN_MINTLINK_SIZE, 0xa8);
    linkShape.vShieldedOutput.push_back(linkOutput);
    BOOST_CHECK(linkShape.CheckTransaction());
    linkShape.vShieldedOutput[0].vchMofNLink.push_back(0xa9);
    BOOST_CHECK(!linkShape.CheckTransaction());
}

BOOST_AUTO_TEST_CASE(shielded_genesis_index_migration_is_bounded_atomic_and_idempotent)
{
    ShieldedGenesisMigrationTestGuard guard;
    std::string error;

    // A pre-fork empty database is not mutated.
    BOOST_CHECK(ValidateAndMigrateShieldedGenesisCommitmentIndexes(
        guard.txdb, error));
    uint64_t count = 0;
    BOOST_CHECK(!guard.txdb.ReadShieldedCommitmentCount(count));

    // Once active, an empty/partial set is corruption: never synthesize sc.
    guard.activeTip.nHeight = FORK_HEIGHT_SHIELDED;
    BOOST_CHECK(!ValidateAndMigrateShieldedGenesisCommitmentIndexes(
        guard.txdb, error));
    BOOST_CHECK(error.find("commitment count") != std::string::npos);

    BOOST_REQUIRE(CZKContext::Initialize());
    CIncrementalMerkleTree tree;
    BOOST_REQUIRE(SeedGenesisCommitments(guard.txdb, tree, NULL));
    BOOST_REQUIRE_EQUAL(tree.Size(),
                        (uint64_t)LELANTUS_GENESIS_SEED_COUNT);
    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitmentCount(tree.Size()));

    for (int i = 0; i < LELANTUS_GENESIS_SEED_COUNT; ++i)
    {
        CPedersenCommitment commitment;
        BOOST_REQUIRE(guard.txdb.ReadShieldedCommitment(
            (uint64_t)i, commitment));
        guard.commitments.push_back(commitment);
        BOOST_REQUIRE(guard.txdb.EraseShieldedCommitmentIndex(
            commitment.vchCommitment));
        BOOST_REQUIRE(guard.txdb.EraseShieldedCommitmentHeight((uint64_t)i));
    }

    // A later conflict aborts the batch, including an earlier staged fill.
    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitmentIndex(
        guard.commitments[1].vchCommitment, 99));
    BOOST_CHECK(!ValidateAndMigrateShieldedGenesisCommitmentIndexes(
        guard.txdb, error));
    BOOST_CHECK(error.find("conflicting") != std::string::npos);
    BOOST_CHECK(!guard.txdb.HasShieldedCommitmentIndex(
        guard.commitments[0].vchCommitment));
    BOOST_REQUIRE(guard.txdb.EraseShieldedCommitmentIndex(
        guard.commitments[1].vchCommitment));

    BOOST_REQUIRE(ValidateAndMigrateShieldedGenesisCommitmentIndexes(
        guard.txdb, error));
    for (int i = 0; i < LELANTUS_GENESIS_SEED_COUNT; ++i)
    {
        uint64_t storedIndex = 0;
        int storedHeight = -1;
        BOOST_CHECK(guard.txdb.ReadShieldedCommitmentIndex(
            guard.commitments[i].vchCommitment, storedIndex));
        BOOST_CHECK_EQUAL(storedIndex, (uint64_t)i);
        BOOST_CHECK(guard.txdb.ReadShieldedCommitmentHeight(
            (uint64_t)i, storedHeight));
        BOOST_CHECK_EQUAL(storedHeight, FORK_HEIGHT_SHIELDED);
    }

    // Local proof construction reads a bounded uniform sample that includes the real
    // commitment; the 16-entry genesis pool comes back whole, exactly once.
    std::vector<CPedersenCommitment> sampled;
    uint64_t realGlobalIndex = 0;
    BOOST_REQUIRE(guard.txdb.ReadBoundedLelantusCommitments(
        guard.commitments[7], sampled, realGlobalIndex, error));
    BOOST_CHECK_EQUAL(realGlobalIndex, (uint64_t)7);
    BOOST_CHECK_EQUAL(sampled.size(),
                      (size_t)LELANTUS_GENESIS_SEED_COUNT);
    size_t realOccurrences = 0;
    std::set<std::vector<unsigned char> > uniqueSample;
    for (std::vector<CPedersenCommitment>::const_iterator it = sampled.begin();
         it != sampled.end(); ++it)
    {
        uniqueSample.insert(it->vchCommitment);
        if (it->vchCommitment == guard.commitments[7].vchCommitment)
            ++realOccurrences;
    }
    BOOST_CHECK_EQUAL(realOccurrences, (size_t)1);
    BOOST_CHECK_EQUAL(uniqueSample.size(), sampled.size());

    // A second run is a read-only success.
    BOOST_CHECK(ValidateAndMigrateShieldedGenesisCommitmentIndexes(
        guard.txdb, error));

    // Missing canonical sc remains missing and fails closed.
    BOOST_REQUIRE(guard.txdb.EraseShieldedCommitment(2));
    BOOST_CHECK(!ValidateAndMigrateShieldedGenesisCommitmentIndexes(
        guard.txdb, error));
    BOOST_CHECK(error.find("value 2 is missing") != std::string::npos);
    CPedersenCommitment absent;
    BOOST_CHECK(!guard.txdb.ReadShieldedCommitment(2, absent));
    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitment(
        2, guard.commitments[2]));

    // Existing heights are validated, never overwritten.
    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitmentHeight(
        3, FORK_HEIGHT_SHIELDED + 1));
    BOOST_CHECK(!ValidateAndMigrateShieldedGenesisCommitmentIndexes(
        guard.txdb, error));
    BOOST_CHECK(error.find("height 3") != std::string::npos);
    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitmentHeight(
        3, FORK_HEIGHT_SHIELDED));
}

BOOST_AUTO_TEST_CASE(lelantus_commitment_sampler_is_bounded_and_includes_exact_real_index)
{
    BoundedLelantusSampleTestGuard guard;
    guard.count = (uint64_t)LELANTUS_MAX_SET_SIZE + 100;
    const uint64_t realIndex = guard.count - 1;
    const CPedersenCommitment realCommitment =
        IndexedTestCommitment(realIndex);

    BOOST_REQUIRE(guard.txdb.TxnBegin());
    for (uint64_t i = 0; i < guard.count; ++i)
        BOOST_REQUIRE(guard.txdb.WriteShieldedCommitment(
            i, IndexedTestCommitment(i)));
    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitmentCount(guard.count));
    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitmentIndex(
        realCommitment.vchCommitment, realIndex));
    BOOST_REQUIRE(guard.txdb.TxnCommit());

    std::vector<CPedersenCommitment> sample;
    uint64_t sampledRealIndex = 0;
    std::string error;
    BOOST_REQUIRE(guard.txdb.ReadBoundedLelantusCommitments(
        realCommitment, sample, sampledRealIndex, error));
    BOOST_CHECK_EQUAL(sampledRealIndex, realIndex);
    BOOST_CHECK_EQUAL(sample.size(), (size_t)LELANTUS_MAX_SET_SIZE);

    std::set<std::vector<unsigned char> > uniqueCommitments;
    for (size_t i = 0; i < sample.size(); ++i)
        uniqueCommitments.insert(sample[i].vchCommitment);
    BOOST_CHECK_EQUAL(uniqueCommitments.size(), sample.size());
    BOOST_CHECK(uniqueCommitments.count(realCommitment.vchCommitment) == 1);

    CAnonymitySet anonSet;
    BOOST_REQUIRE(BuildAnonymitySet(realCommitment, sample, uint256(123),
                                    FORK_HEIGHT_SHIELDED, anonSet));
    BOOST_CHECK_EQUAL(anonSet.Size(), LELANTUS_SET_SIZE);
    BOOST_CHECK(anonSet.FindIndex(realCommitment) >= 0);

    BOOST_REQUIRE(guard.txdb.EraseShieldedCommitmentIndex(
        realCommitment.vchCommitment));
    BOOST_CHECK(!guard.txdb.ReadBoundedLelantusCommitments(
        realCommitment, sample, sampledRealIndex, error));
    BOOST_CHECK(error.find("reverse index") != std::string::npos);

    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitmentIndex(
        realCommitment.vchCommitment, 0));
    BOOST_CHECK(!guard.txdb.ReadBoundedLelantusCommitments(
        realCommitment, sample, sampledRealIndex, error));
    BOOST_CHECK(error.find("mismatch") != std::string::npos);
    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitmentIndex(
        realCommitment.vchCommitment, realIndex));

    BOOST_REQUIRE(guard.txdb.EraseShieldedCommitment(realIndex));
    BOOST_CHECK(!guard.txdb.ReadBoundedLelantusCommitments(
        realCommitment, sample, sampledRealIndex, error));
    BOOST_CHECK(error.find("value missing") != std::string::npos);
    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitment(
        realIndex, realCommitment));

    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitmentCount(
        LELANTUS_MIN_SET_SIZE - 1));
    BOOST_CHECK(!guard.txdb.ReadBoundedLelantusCommitments(
        realCommitment, sample, sampledRealIndex, error));
    BOOST_CHECK(error.find("too small") != std::string::npos);
    BOOST_REQUIRE(guard.txdb.WriteShieldedCommitmentCount(guard.count));
}

BOOST_AUTO_TEST_CASE(txdb_exists_honors_active_batch_deletes)
{
    CTxDB txdb("r+");
    const uint64_t index = std::numeric_limits<uint64_t>::max() - 17;
    const uint256 anchor(std::numeric_limits<uint64_t>::max() - 18);

    BOOST_REQUIRE(txdb.WriteShieldedCommitmentHeight(index, 123));
    BOOST_REQUIRE(txdb.HasShieldedCommitmentHeight(index));

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.EraseShieldedCommitmentHeight(index));
    BOOST_CHECK(!txdb.HasShieldedCommitmentHeight(index));
    BOOST_REQUIRE(txdb.TxnAbort());

    // Aborting the batch must expose the original disk value again.
    BOOST_CHECK(txdb.HasShieldedCommitmentHeight(index));
    BOOST_REQUIRE(txdb.EraseShieldedCommitmentHeight(index));
    BOOST_CHECK(!txdb.HasShieldedCommitmentHeight(index));

    BOOST_REQUIRE(txdb.WriteShieldedAnchorHeight(anchor, 456));
    BOOST_REQUIRE(txdb.HasShieldedAnchorHeight(anchor));
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.EraseShieldedAnchorHeight(anchor));
    BOOST_CHECK(!txdb.HasShieldedAnchorHeight(anchor));
    BOOST_REQUIRE(txdb.TxnAbort());
    int anchorHeight = 0;
    BOOST_REQUIRE(txdb.ReadShieldedAnchorHeight(anchor, anchorHeight));
    BOOST_CHECK_EQUAL(anchorHeight, 456);
    BOOST_REQUIRE(txdb.EraseShieldedAnchorHeight(anchor));
    BOOST_CHECK(!txdb.HasShieldedAnchorHeight(anchor));
}

BOOST_AUTO_TEST_CASE(shielded_merkle_tree_rejects_corrupt_disk_shape_without_indexing)
{
    CIncrementalMerkleTree malformed;
    malformed.vLeft.clear();
    malformed.nSize = 1;

    std::vector<uint256> witness;
    BOOST_CHECK(!malformed.IsValidStructure());
    BOOST_CHECK(!malformed.Append(uint256(1)));
    BOOST_CHECK(malformed.Root() == uint256(0));
    BOOST_CHECK(!malformed.GetWitness(0, witness));
    BOOST_CHECK(witness.empty());

    ShieldedTreeDiskTestDB txdb;
    BOOST_CHECK(!txdb.WriteShieldedTree(malformed));
    BOOST_CHECK(!txdb.WriteShieldedTreeAtBlock(uint256(9), malformed));

    // Bypass the checked writer to model corrupt on-disk records.  The
    // bounded decoder rejects an oversized frontier before allocating it.
    CIncrementalMerkleTree oversizedFrontier;
    oversizedFrontier.vLeft.push_back(uint256(2));
    const uint256 oversizedHash(0xf101);
    BOOST_REQUIRE(txdb.WriteRawTreeAtBlock(oversizedHash,
                                           oversizedFrontier));
    CIncrementalMerkleTree decoded;
    BOOST_CHECK(!txdb.ReadShieldedTreeAtBlock(oversizedHash, decoded));
    BOOST_REQUIRE(txdb.EraseShieldedTreeAtBlock(oversizedHash));

    // Exact vector lengths with an impossible leaf count are also rejected.
    CIncrementalMerkleTree impossibleSize;
    impossibleSize.nSize = ((uint64_t)1 << SHIELDED_MERKLE_DEPTH) + 1;
    const uint256 impossibleHash(0xf102);
    BOOST_REQUIRE(txdb.WriteRawTreeAtBlock(impossibleHash,
                                           impossibleSize));
    BOOST_CHECK(!txdb.ReadShieldedTreeAtBlock(impossibleHash, decoded));
    BOOST_REQUIRE(txdb.EraseShieldedTreeAtBlock(impossibleHash));

    // Consensus snapshots are exact records: a valid tree prefix followed by
    // bytes from a corrupt/newer value must not be silently accepted.
    ShieldedTreeWithTrailingByte withTrailing;
    BOOST_REQUIRE(withTrailing.tree.Append(uint256(3)));
    const uint256 trailingHash(0xf103);
    BOOST_REQUIRE(txdb.WriteRawTreeAtBlock(trailingHash, withTrailing));
    BOOST_CHECK(!txdb.ReadShieldedTreeAtBlock(trailingHash, decoded));
    BOOST_REQUIRE(txdb.EraseShieldedTreeAtBlock(trailingHash));
}

BOOST_AUTO_TEST_CASE(shielded_v3_mode_selection_handles_activation_crossing_reconnects)
{
    ShieldedV3IndexTestGuard guard;
    const int nActivationHeight = 100;
    std::string error;
    bool fUseV3 = true;

    // With no siv3 marker, a reconnect below activation stays on the legacy index so
    // it can reach the activation block. Abort leaves the shared test database unchanged.
    BOOST_REQUIRE(guard.TxnBegin());
    BOOST_REQUIRE(guard.ClearShieldedCommitmentIndexV3(error));
    BOOST_REQUIRE(guard.WriteEpochStateSchema(EPOCHSTATE_SCHEMA_V3));
    BOOST_REQUIRE_MESSAGE(guard.ResolveShieldedCommitmentIndexV3Mode(
                              nActivationHeight - 1, nActivationHeight,
                              fUseV3, error),
                          error);
    BOOST_CHECK(!fUseV3);

    // At activation, height alone selects V3 and therefore requires the
    // marker to have been initialized first.
    BOOST_CHECK(!guard.ResolveShieldedCommitmentIndexV3Mode(
        nActivationHeight, nActivationHeight, fUseV3, error));
    BOOST_CHECK(error.find("missing") != std::string::npos);

    CIncrementalMerkleTree emptyTree;
    BOOST_REQUIRE(guard.WriteShieldedTree(emptyTree));
    BOOST_REQUIRE(guard.WriteShieldedCommitmentCount(0));
    BOOST_REQUIRE(guard.InitializeShieldedCommitmentIndexV3(
        uint256(0xd100), error));
    BOOST_REQUIRE_MESSAGE(guard.ResolveShieldedCommitmentIndexV3Mode(
                              nActivationHeight, nActivationHeight,
                              fUseV3, error),
                          error);
    BOOST_CHECK(fUseV3);

    // A valid marker from the branch being disconnected keeps V3 active for
    // below-activation disconnects/reconnects until the new activation block
    // atomically rebuilds it under a new generation.
    BOOST_REQUIRE_MESSAGE(guard.ResolveShieldedCommitmentIndexV3Mode(
                              nActivationHeight - 1, nActivationHeight,
                              fUseV3, error),
                          error);
    BOOST_CHECK(fUseV3);
    BOOST_REQUIRE(guard.TxnAbort());

    // Corruption is distinct from absence and fails closed even below the
    // activation boundary.
    BOOST_REQUIRE(guard.TxnBegin());
    BOOST_REQUIRE(guard.ClearShieldedCommitmentIndexV3(error));
    BOOST_REQUIRE(guard.WriteCorruptV3MarkerForTest());
    BOOST_CHECK(!guard.ResolveShieldedCommitmentIndexV3Mode(
        nActivationHeight - 1, nActivationHeight, fUseV3, error));
    BOOST_CHECK(error.find("corrupt") != std::string::npos);
    BOOST_REQUIRE(guard.TxnAbort());
}

BOOST_AUTO_TEST_CASE(shielded_v3_duplicate_commitment_index_rolls_back_to_predecessor)
{
    ShieldedV3IndexTestGuard guard;
    const CPedersenCommitment commitmentA = IndexedTestCommitment(0xa1);
    const CPedersenCommitment commitmentB = IndexedTestCommitment(0xb2);
    const CPedersenCommitment commitmentC = IndexedTestCommitment(0xc3);
    guard.commitments.push_back(commitmentA);
    guard.commitments.push_back(commitmentB);
    guard.commitments.push_back(commitmentC);

    CIncrementalMerkleTree tree;
    BOOST_REQUIRE(tree.Append(uint256(0x11)));
    BOOST_REQUIRE(tree.Append(uint256(0x12)));
    BOOST_REQUIRE(tree.Append(uint256(0x13)));
    BOOST_REQUIRE(guard.WriteShieldedTree(tree));
    BOOST_REQUIRE(guard.WriteShieldedCommitment(0, commitmentA));
    BOOST_REQUIRE(guard.WriteShieldedCommitment(1, commitmentB));
    BOOST_REQUIRE(guard.WriteShieldedCommitment(2, commitmentA));
    BOOST_REQUIRE(guard.WriteShieldedCommitmentCount(3));

    std::string error;
    const uint256 generationA(0xd001);
    const uint256 generationB(0xd002);
    BOOST_REQUIRE(guard.TxnBegin());
    BOOST_REQUIRE(guard.InitializeShieldedCommitmentIndexV3(
        generationA, error));
    // Validation must read through the active batch, including the duplicate
    // predecessor journal staged above.
    BOOST_REQUIRE_MESSAGE(guard.ValidateShieldedCommitmentIndexV3(error),
                          error);
    BOOST_REQUIRE(guard.TxnCommit());

    uint64_t index = 0;
    BOOST_REQUIRE(guard.ReadShieldedCommitmentIndexV3(
        commitmentA.vchCommitment, index));
    BOOST_CHECK_EQUAL(index, (uint64_t)2);

    // Disconnect the duplicate leaf.  Pop runs before the forward leaf is
    // erased, then the predecessor tree/count are installed in the same batch.
    CIncrementalMerkleTree predecessorTree;
    BOOST_REQUIRE(predecessorTree.Append(uint256(0x11)));
    BOOST_REQUIRE(predecessorTree.Append(uint256(0x12)));
    BOOST_REQUIRE(guard.TxnBegin());
    BOOST_REQUIRE(guard.PopShieldedCommitmentIndexV3(
        2, commitmentA, error));
    BOOST_REQUIRE(guard.EraseShieldedCommitment(2));
    BOOST_REQUIRE(guard.WriteShieldedCommitmentCount(2));
    BOOST_REQUIRE(guard.WriteShieldedTree(predecessorTree));
    BOOST_REQUIRE(guard.ValidateShieldedCommitmentIndexV3(error));
    BOOST_REQUIRE(guard.TxnCommit());
    BOOST_REQUIRE(guard.ReadShieldedCommitmentIndexV3(
        commitmentA.vchCommitment, index));
    BOOST_CHECK_EQUAL(index, (uint64_t)0);

    // Reusing the same index on a competing branch overwrites the stale
    // predecessor metadata deterministically without disturbing A's head.
    BOOST_REQUIRE(guard.TxnBegin());
    BOOST_REQUIRE(guard.WriteShieldedCommitment(2, commitmentC));
    BOOST_REQUIRE(guard.PushShieldedCommitmentIndexV3(
        2, commitmentC, error));
    BOOST_REQUIRE(guard.WriteShieldedCommitmentCount(3));
    BOOST_REQUIRE(guard.WriteShieldedTree(tree));
    BOOST_REQUIRE(guard.ValidateShieldedCommitmentIndexV3(error));
    BOOST_REQUIRE(guard.TxnCommit());
    BOOST_REQUIRE(guard.ReadShieldedCommitmentIndexV3(
        commitmentA.vchCommitment, index));
    BOOST_CHECK_EQUAL(index, (uint64_t)0);
    BOOST_REQUIRE(guard.ReadShieldedCommitmentIndexV3(
        commitmentC.vchCommitment, index));
    BOOST_CHECK_EQUAL(index, (uint64_t)2);

    // An aborted disconnect must leave the committed head untouched.
    BOOST_REQUIRE(guard.TxnBegin());
    BOOST_REQUIRE(guard.PopShieldedCommitmentIndexV3(
        2, commitmentC, error));
    BOOST_REQUIRE(guard.TxnAbort());
    BOOST_REQUIRE(guard.ReadShieldedCommitmentIndexV3(
        commitmentC.vchCommitment, index));
    BOOST_CHECK_EQUAL(index, (uint64_t)2);
    BOOST_REQUIRE(guard.ValidateShieldedCommitmentIndexV3(error));

    // Reorg across activation onto a generation where C is absent. Prefix
    // clearing rebuilds both V3 and legacy heads from A,B only, so no public
    // lookup can observe the abandoned C@2 head.
    BOOST_REQUIRE(guard.TxnBegin());
    BOOST_REQUIRE(guard.EraseShieldedCommitment(2));
    BOOST_REQUIRE(guard.WriteShieldedCommitmentCount(2));
    BOOST_REQUIRE(guard.WriteShieldedTree(predecessorTree));
    BOOST_REQUIRE(guard.InitializeShieldedCommitmentIndexV3(
        generationB, error));
    BOOST_REQUIRE(guard.ValidateShieldedCommitmentIndexV3(error));
    BOOST_REQUIRE(guard.TxnCommit());
    BOOST_CHECK(!guard.ReadShieldedCommitmentIndexV3(
        commitmentC.vchCommitment, index));
    BOOST_CHECK(!guard.ReadShieldedCommitmentIndex(
        commitmentC.vchCommitment, index));
    BOOST_REQUIRE(guard.ReadShieldedCommitmentIndexV3(
        commitmentA.vchCommitment, index));
    BOOST_CHECK_EQUAL(index, (uint64_t)0);

    // A malformed existing marker is corruption, not an absent marker that an
    // activation rebuild may silently overwrite.
    BOOST_REQUIRE(guard.WriteCorruptV3MarkerForTest());
    BOOST_REQUIRE(guard.TxnBegin());
    BOOST_CHECK(!guard.InitializeShieldedCommitmentIndexV3(
        uint256(0xd003), error));
    BOOST_CHECK(error.find("marker is corrupt") != std::string::npos);
    BOOST_REQUIRE(guard.TxnAbort());
}

BOOST_AUTO_TEST_CASE(active_v5_envelope_trailing_bytes_remain_accepted)
{
    CFCMPProof fcmp;
    fcmp.vchProof.push_back((unsigned char)(FCMP_PROOF_VERSION_IPA >> 0));
    fcmp.vchProof.push_back((unsigned char)(FCMP_PROOF_VERSION_IPA >> 8));
    fcmp.vchProof.push_back((unsigned char)(FCMP_PROOF_VERSION_IPA >> 16));
    fcmp.vchProof.push_back((unsigned char)(FCMP_PROOF_VERSION_IPA >> 24));
    std::vector<unsigned char> encoded = SerializeEnvelope(fcmp);
    encoded.push_back(0xa5);
    encoded.push_back(0x5a);

    CFCMPProof decoded;
    bool accepted = false;
    BOOST_CHECK_NO_THROW(accepted = TryDeserializeEnvelope(encoded, decoded));
    BOOST_CHECK(accepted);
    BOOST_CHECK(decoded.vchProof == fcmp.vchProof);
}

BOOST_AUTO_TEST_CASE(reserved_vnext_is_not_a_legacy_privacy_envelope)
{
    CTransaction emptyVNext;
    emptyVNext.nVersion = SHIELDED_TX_VERSION_VNEXT;

    BOOST_CHECK(!emptyVNext.IsShielded());
    BOOST_CHECK(!emptyVNext.IsDSP());
    BOOST_CHECK(!emptyVNext.IsFCMP());
    BOOST_CHECK(!IsLegacyShieldedTransactionVersion(emptyVNext.nVersion));

    // A vNext transaction must not accidentally serialize legacy shielded
    // fields. Its dedicated payload is the only privacy data in this envelope.
    CTransaction populatedVNext = emptyVNext;
    populatedVNext.vShieldedSpend.push_back(CShieldedSpendDescription());
    populatedVNext.vShieldedOutput.push_back(CShieldedOutputDescription());
    populatedVNext.nValueBalance = 1;
    populatedVNext.nPrivacyMode = PRIVACY_MODE_TRANSPARENT;

    BOOST_CHECK(SerializeEnvelope(emptyVNext) ==
                SerializeEnvelope(populatedVNext));
    BOOST_CHECK(emptyVNext.GetBindingSigHash() ==
                populatedVNext.GetBindingSigHash());

    CTransaction payloadVNext = emptyVNext;
    payloadVNext.privacyVNext.vchPayload.push_back(0x01);
    BOOST_CHECK(SerializeEnvelope(emptyVNext) !=
                SerializeEnvelope(payloadVNext));
    BOOST_CHECK(emptyVNext.GetHash() != payloadVNext.GetHash());

    // Context-free validation is the first admission boundary and must remain
    // fail closed until the independent vNext implementation is complete.
    BOOST_CHECK(!populatedVNext.CheckTransaction());
    BOOST_CHECK_EQUAL(populatedVNext.nDoS, 100);
}

BOOST_AUTO_TEST_CASE(vnext_envelope_marker_schema_and_length_are_strict)
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_VNEXT;
    tx.privacyVNext.vchPayload.push_back(0x01);
    tx.privacyVNext.vchPayload.push_back(0x02);
    tx.privacyVNext.vchPayload.push_back(0x03);

    const std::vector<unsigned char> encoded = SerializeEnvelope(tx);
    CDataStream framed(encoded, SER_NETWORK, PROTOCOL_VERSION);
    int wireVersion = 0;
    unsigned int wireTime = 0;
    std::vector<CTxIn> wireInputs;
    std::vector<CTxOut> wireOutputs;
    unsigned int wireLockTime = 0;
    framed >> wireVersion >> wireTime >> wireInputs >> wireOutputs >> wireLockTime;
    const size_t markerOffset = encoded.size() - framed.size();

    unsigned char marker[5] = {0, 0, 0, 0, 0};
    framed.read(reinterpret_cast<char*>(marker), sizeof(marker));
    BOOST_CHECK_EQUAL(marker[0], 0xff);
    BOOST_CHECK_EQUAL(marker[1], 'I');
    BOOST_CHECK_EQUAL(marker[2], 'V');
    BOOST_CHECK_EQUAL(marker[3], '5');
    BOOST_CHECK_EQUAL(marker[4], 'P');

    uint16_t schema = 0;
    std::vector<unsigned char> payload;
    framed >> schema >> payload;
    BOOST_CHECK_EQUAL(wireVersion, SHIELDED_TX_VERSION_VNEXT);
    BOOST_CHECK_EQUAL(schema, static_cast<uint16_t>(iv5::PROTOCOL_SCHEMA));
    BOOST_CHECK(payload == tx.privacyVNext.vchPayload);
    BOOST_CHECK(framed.empty());

    CTransaction roundTrip;
    BOOST_CHECK(TryDeserializeEnvelope(encoded, roundTrip));
    BOOST_CHECK(roundTrip.privacyVNext.vchPayload ==
                tx.privacyVNext.vchPayload);

    std::vector<unsigned char> badMarker = encoded;
    badMarker[markerOffset + 1] = 'X';
    CTransaction rejectedMarker;
    BOOST_CHECK(!TryDeserializeEnvelope(badMarker, rejectedMarker));

    std::vector<unsigned char> badSchema = encoded;
    badSchema[markerOffset + sizeof(marker)] = 0x02;
    badSchema[markerOffset + sizeof(marker) + 1] = 0x00;
    CTransaction rejectedSchema;
    BOOST_CHECK(!TryDeserializeEnvelope(badSchema, rejectedSchema));

    CDataStream oversized(SER_NETWORK, PROTOCOL_VERSION);
    oversized << tx.nVersion << tx.nTime << tx.vin << tx.vout << tx.nLockTime;
    const unsigned char canonicalMarker[5] = {0xff, 'I', 'V', '5', 'P'};
    oversized.write(reinterpret_cast<const char*>(canonicalMarker),
                    sizeof(canonicalMarker));
    const uint16_t canonicalSchema =
        static_cast<uint16_t>(iv5::PROTOCOL_SCHEMA);
    oversized << canonicalSchema;
    WriteCompactSize(oversized, SHIELDED_VNEXT_MAX_PAYLOAD_SIZE + 1);
    const std::vector<unsigned char> oversizedBytes(oversized.begin(),
                                                     oversized.end());
    CTransaction rejectedOversized;
    BOOST_CHECK(!TryDeserializeEnvelope(oversizedBytes,
                                        rejectedOversized));
}

BOOST_AUTO_TEST_CASE(vnext_compatibility_envelopes_are_disjoint_from_history)
{
    for (int version = SHIELDED_TX_VERSION;
         version <= SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM; ++version)
    {
        CTransaction historical;
        historical.nVersion = version;
        const std::vector<unsigned char> historicalBytes =
            SerializeEnvelope(historical);

        CTransaction historicalRoundTrip;
        BOOST_REQUIRE(TryDeserializeEnvelope(historicalBytes,
                                             historicalRoundTrip));
        BOOST_CHECK(historicalRoundTrip.privacyVNext.IsNull());
        BOOST_CHECK(SerializeEnvelope(historicalRoundTrip) == historicalBytes);

        CTransaction compatibility;
        compatibility.nVersion = version;
        compatibility.privacyVNext.SetPresent();
        compatibility.privacyVNext.vchPayload.push_back(0x01);
        compatibility.privacyVNext.vchPayload.push_back(
            static_cast<unsigned char>(version & 0xff));
        const std::vector<unsigned char> compatibilityBytes =
            SerializeEnvelope(compatibility);
        BOOST_CHECK(compatibilityBytes != historicalBytes);

        CTransaction compatibilityRoundTrip;
        BOOST_REQUIRE(TryDeserializeEnvelope(compatibilityBytes,
                                             compatibilityRoundTrip));
        BOOST_CHECK(!compatibilityRoundTrip.IsShielded());
        BOOST_CHECK(compatibilityRoundTrip.IsPrivacyVNext());
        BOOST_CHECK(!compatibilityRoundTrip.IsDSP());
        BOOST_CHECK(!compatibilityRoundTrip.IsFCMP());
        BOOST_CHECK(compatibilityRoundTrip.privacyVNext.IsPresent());
        BOOST_CHECK(compatibilityRoundTrip.privacyVNext.vchPayload ==
                    compatibility.privacyVNext.vchPayload);
        BOOST_CHECK(compatibilityRoundTrip.vShieldedSpend.empty());
        BOOST_CHECK(compatibilityRoundTrip.vShieldedOutput.empty());
        BOOST_CHECK(SerializeEnvelope(compatibilityRoundTrip) ==
                    compatibilityBytes);
    }
}

BOOST_AUTO_TEST_CASE(public_networks_consensus_reject_all_legacy_shielded_versions)
{
    AnonMainnetModeGuard publicNetwork;
    BOOST_REQUIRE(IsLegacyPrivacyPolicyDisabled());

    for (int nVersion = SHIELDED_TX_VERSION;
         nVersion <= SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM;
         ++nVersion)
    {
        CTransaction tx;
        tx.nVersion = nVersion;
        BOOST_REQUIRE(IsLegacyShieldedTransactionVersion(tx.nVersion));
        BOOST_CHECK(!tx.CheckTransaction());
        BOOST_CHECK_EQUAL(tx.nDoS, 100);
    }
}

BOOST_AUTO_TEST_CASE(future_versions_do_not_inherit_legacy_privacy_predicates)
{
    const int futureVersions[] = {
        SHIELDED_TX_VERSION_VNEXT,
        SHIELDED_TX_VERSION_VNEXT + 1,
        std::numeric_limits<int>::max()
    };

    for (size_t i = 0; i < sizeof(futureVersions) / sizeof(futureVersions[0]); ++i)
    {
        CTransaction tx;
        tx.nVersion = futureVersions[i];
        BOOST_CHECK(!tx.IsShielded());
        BOOST_CHECK(!tx.IsDSP());
        BOOST_CHECK(!tx.IsFCMP());
        BOOST_CHECK(!IsLegacyShieldedTransactionVersion(tx.nVersion));
    }

    // The active verifier remains v5.  Dormant cross-curve/v6 code must not
    // become consensus-active as an incidental consequence of reserving 2008.
    BOOST_CHECK_EQUAL(FCMP_PROOF_VERSION_CURRENT, FCMP_PROOF_VERSION_IPA);
    BOOST_CHECK(FCMP_PROOF_VERSION_CROSSCURVE > FCMP_PROOF_VERSION_CURRENT);
}


namespace {
struct NetFlagGuard {
    bool fStoredRegTest, fStoredTestNet;
    NetFlagGuard() : fStoredRegTest(fRegTest), fStoredTestNet(fTestNet) {}
    ~NetFlagGuard() { fRegTest = fStoredRegTest; fTestNet = fStoredTestNet; }
};

bool VarIntReadThrows(const std::vector<unsigned char>& vch)
{
    try {
        CDataStream ss(vch, SER_DISK, CLIENT_VERSION);
        int64_t n = 0;
        ss >> VARINT(n);
        return false;
    } catch (const std::ios_base::failure&) {
        return true;
    }
}
} // namespace

// VARINT encodes consensus fields that arrive from the network. A signed
// accumulator made an over-wide encoding undefined rather than a decode error,
// so a peer could steer the decoded value.
BOOST_AUTO_TEST_CASE(varint_rejects_out_of_range_rather_than_wrapping)
{
    BOOST_CHECK(VarIntReadThrows(std::vector<unsigned char>(10, 0xFF)));
    BOOST_CHECK(VarIntReadThrows(std::vector<unsigned char>(64, 0xFF)));

    std::vector<unsigned char> vchWide(9, 0xFF);
    vchWide.push_back(0x00);
    BOOST_CHECK(VarIntReadThrows(vchWide));

    // A truncated encoding is a stream error, never a silent value.
    BOOST_CHECK(VarIntReadThrows(std::vector<unsigned char>(1, 0x80)));

    // Valid values must still round trip, including the widest one.
    const int64_t vTest[] = { 0, 1, 127, 128, 16383, 16384, 0xFFFFFFFFLL,
                              std::numeric_limits<int64_t>::max() };
    for (unsigned int i = 0; i < sizeof(vTest) / sizeof(vTest[0]); i++) {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        int64_t nIn = vTest[i];
        ss << VARINT(nIn);
        int64_t nOut = -1;
        ss >> VARINT(nOut);
        BOOST_CHECK_EQUAL(nOut, nIn);
    }
}

// The shift moves every mainnet gate by one constant. If it ever scaled or
// applied unevenly the ladder would reorder and stages would activate before
// what they depend on.
BOOST_AUTO_TEST_CASE(v5_activation_shift_is_uniform)
{
    BOOST_CHECK_EQUAL(ShiftMainnetV5Activation(7810000) - ShiftMainnetV5Activation(7800000), 10000);
    BOOST_CHECK_EQUAL(ShiftMainnetV5Activation(8060000) - ShiftMainnetV5Activation(7800000), 260000);
    BOOST_CHECK_EQUAL(ShiftMainnetV5Activation(MAINNET_V5_ACTIVATION_BASE),
                      MAINNET_V5_ACTIVATION_BASE + MAINNET_V5_ACTIVATION_SHIFT);
}

// Each gate depends on the stage below it being live. These orderings are the
// reason a re-base may only move the shift, never an individual base.
BOOST_AUTO_TEST_CASE(v5_activation_ladder_preserves_stage_dependencies)
{
    NetFlagGuard guard;
    fRegTest = false;
    fTestNet = false;

    const int nFirst = ShiftMainnetV5Activation(MAINNET_V5_ACTIVATION_BASE);

    BOOST_CHECK_EQUAL(GetForkHeightTighterDrift(), nFirst);
    BOOST_CHECK_EQUAL(GetForkHeightCNPaymentValidation(), nFirst);
    BOOST_CHECK_EQUAL(GetForkHeightColdStaking(), nFirst);
    BOOST_CHECK_EQUAL(GetForkHeightIDNSReset(), nFirst);

    // Shielded output support precedes anything that spends or proves over it.
    BOOST_CHECK(GetForkHeightShielded() > nFirst);
    BOOST_CHECK(GetForkHeightShieldedHardening() >= GetForkHeightShielded());
    BOOST_CHECK(GetForkHeightRingSigDeprecation() > GetForkHeightShielded());
    BOOST_CHECK(GetForkHeightDSP() > GetForkHeightShielded());
    BOOST_CHECK(GetForkHeightFCMP() > GetForkHeightShielded());
    BOOST_CHECK(GetForkHeightNullSend() > GetForkHeightShielded());

    // Private staking builds on FCMP membership, and each tier on the last.
    BOOST_CHECK(GetForkHeightNullStake() > GetForkHeightFCMP());
    BOOST_CHECK(GetForkHeightNullStakeV2() > GetForkHeightNullStake());
    BOOST_CHECK(GetForkHeightNullStakeV3() > GetForkHeightNullStakeV2());
    BOOST_CHECK(GetForkHeightNullStakeB2C() > GetForkHeightNullStakeV3());
    BOOST_CHECK(GetForkHeightNullStakeReclaim() >= GetForkHeightNullStakeV3());
    BOOST_CHECK(GetForkHeightNullStakeDelegSet() >= GetForkHeightNullStakeV3());

    // Finality certifies DAG order, so it must be live before the DAG turns on.
    BOOST_CHECK(GetForkHeightFinality() > GetForkHeightPoem());
    BOOST_CHECK(GetForkHeightDAG() > GetForkHeightFinality());
    BOOST_CHECK(GetForkHeightDAGKnight() > GetForkHeightDAG());

    // Boundary B stays unset on mainnet until privacy vNext is scheduled.
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), PRIVACY_VNEXT_HEIGHT_UNSET);
}

BOOST_AUTO_TEST_SUITE_END()
