// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletdb.h"
#include "wallet.h"
#include "key.h"
#include <algorithm>
#include <limits>
#include <boost/version.hpp>
#include <boost/filesystem.hpp>

using namespace std;
namespace fs = boost::filesystem;


static uint64_t nAccountingEntryNumber = 0;
extern bool fWalletUnlockStakingOnly;

//
// CWalletDB
//

bool CWalletDB::WriteName(const string& strAddress, const string& strName)
{
    nWalletDBUpdated++;
    return Write(make_pair(string("name"), strAddress), strName);
}

bool CWalletDB::EraseName(const string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    nWalletDBUpdated++;
    return Erase(make_pair(string("name"), strAddress));
}

bool CWalletDB::WritePurpose(const string& strAddress, const string& strPurpose)
{
    nWalletDBUpdated++;
    return Write(make_pair(string("purpose"), strAddress), strPurpose);
}

bool CWalletDB::ErasePurpose(const string& strPurpose)
{
    nWalletDBUpdated++;
    return Erase(make_pair(string("purpose"), strPurpose));
}

bool CWalletDB::ReadAccount(const string& strAccount, CAccount& account)
{
    account.SetNull();
    return Read(make_pair(string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccount(const string& strAccount, const CAccount& account)
{
    return Write(make_pair(string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry)
{
    return Write(boost::make_tuple(string("acentry"), acentry.strAccount, nAccEntryNum), acentry);
}

bool CWalletDB::WriteAccountingEntry(const CAccountingEntry& acentry)
{
    return WriteAccountingEntry(++nAccountingEntryNumber, acentry);
}

namespace
{
static const uint32_t ADRENALINE_NODE_CONFIG_DISK_MAGIC = 0x31434e49; // "INC1"
static const size_t ADRENALINE_NODE_CONFIG_MAX_VALUE_BYTES = 64 * 1024;
static const size_t ADRENALINE_NODE_CONFIG_MAX_FIELD_BYTES = 4 * 1024;
static const size_t ADRENALINE_NODE_CONFIG_MAX_KEY_BYTES = 8 * 1024;
static const size_t ADRENALINE_NODE_CONFIG_MAX_RECORDS = 2048;
static const char* ADRENALINE_NODE_CONFIG_LEGACY_KEY = "adrenaline";
static const char* ADRENALINE_NODE_CONFIG_CANONICAL_KEY = "adrenalinecfg";
static const char* ADRENALINE_NODE_CONFIG_SCHEMA_KEY = "adrenalinecfgschema";

typedef std::pair<std::string, std::string> CAdrenalineLegacyKey;
typedef std::pair<std::string, std::pair<int, std::string> >
    CAdrenalineCanonicalKey;

CAdrenalineLegacyKey AdrenalineLegacyKey(const std::string& strStorageKey)
{
    return std::make_pair(std::string(ADRENALINE_NODE_CONFIG_LEGACY_KEY),
                          strStorageKey);
}

CAdrenalineCanonicalKey AdrenalineCanonicalKey(
    const std::string& strStorageKey)
{
    return std::make_pair(
        std::string(ADRENALINE_NODE_CONFIG_CANONICAL_KEY),
        std::make_pair(ADRENALINE_NODE_CONFIG_DISK_GENERATION,
                       strStorageKey));
}

bool IsAdrenalineNodeConfigStructurallyValid(
    const CAdrenalineNodeConfig& nodeConfig)
{
    return nodeConfig.nVersion >= 0 &&
           nodeConfig.sAlias.size() <= ADRENALINE_NODE_CONFIG_MAX_FIELD_BYTES &&
           nodeConfig.sAddress.size() <= ADRENALINE_NODE_CONFIG_MAX_FIELD_BYTES &&
           nodeConfig.sCollateralnodePrivKey.size() <=
               ADRENALINE_NODE_CONFIG_MAX_FIELD_BYTES &&
           nodeConfig.sTxHash.size() <= ADRENALINE_NODE_CONFIG_MAX_FIELD_BYTES &&
           nodeConfig.sOutputIndex.size() <=
               ADRENALINE_NODE_CONFIG_MAX_FIELD_BYTES;
}

bool ReadAdrenalineNodeConfigString(CDataStream& ssValue,
                                    std::string& strValue)
{
    uint64_t nSize = 0;
    if (!ReadCompactSizeLimited(
            ssValue, nSize, ADRENALINE_NODE_CONFIG_MAX_FIELD_BYTES) ||
        nSize > ssValue.size())
        return false;
    strValue.assign((size_t)nSize, '\0');
    if (nSize > 0)
        ssValue.read(&strValue[0], (size_t)nSize);
    return true;
}

bool WalletKeyHasSerializedType(const CDataStream& ssKey,
                                const std::string& strType)
{
    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << strType;
    return ssKey.size() >= ssPrefix.size() &&
           std::equal(ssPrefix.begin(), ssPrefix.end(), ssKey.begin());
}

int ReadBoundedWalletCursor(Dbc* pcursor,
                            const CDataStream* pSeekKey,
                            CDataStream& ssKeyOut,
                            CDataStream& ssValueOut,
                            u_int32_t fFlags)
{
    if (!pcursor ||
        (pSeekKey &&
         pSeekKey->size() > ADRENALINE_NODE_CONFIG_MAX_KEY_BYTES))
        return DB_BUFFER_SMALL;

    CSerializeData vchKey(ADRENALINE_NODE_CONFIG_MAX_KEY_BYTES, 0);
    CSerializeData vchValue(ADRENALINE_NODE_CONFIG_MAX_VALUE_BYTES, 0);
    size_t nSeekSize = 0;
    if (pSeekKey)
    {
        nSeekSize = pSeekKey->size();
        std::copy(pSeekKey->begin(), pSeekKey->end(), vchKey.begin());
    }

    Dbt datKey;
    datKey.set_data(&vchKey[0]);
    datKey.set_size((u_int32_t)nSeekSize);
    datKey.set_ulen((u_int32_t)vchKey.size());
    datKey.set_flags(DB_DBT_USERMEM);
    Dbt datValue;
    datValue.set_data(&vchValue[0]);
    datValue.set_ulen((u_int32_t)vchValue.size());
    datValue.set_flags(DB_DBT_USERMEM);

    const int ret = pcursor->get(&datKey, &datValue, fFlags);
    if (ret == 0)
    {
        if (datKey.get_size() == 0 ||
            datKey.get_size() > vchKey.size() ||
            datValue.get_size() == 0 ||
            datValue.get_size() > vchValue.size())
        {
            memset(&vchKey[0], 0, vchKey.size());
            memset(&vchValue[0], 0, vchValue.size());
            return DB_BUFFER_SMALL;
        }
        try
        {
            ssKeyOut.clear();
            ssKeyOut.SetType(SER_DISK);
            ssKeyOut.SetVersion(CLIENT_VERSION);
            ssKeyOut.write(&vchKey[0], datKey.get_size());
            ssValueOut.clear();
            ssValueOut.SetType(SER_DISK);
            ssValueOut.SetVersion(CLIENT_VERSION);
            ssValueOut.write(&vchValue[0], datValue.get_size());
        }
        catch (...)
        {
            memset(&vchKey[0], 0, vchKey.size());
            memset(&vchValue[0], 0, vchValue.size());
            ssKeyOut.clear();
            ssValueOut.clear();
            return DB_BUFFER_SMALL;
        }
    }
    memset(&vchKey[0], 0, vchKey.size());
    memset(&vchValue[0], 0, vchValue.size());
    return ret;
}

bool EqualLegacyRepresentableAdrenalineNodeConfig(
    const CAdrenalineNodeConfig& a,
    const CAdrenalineNodeConfig& b)
{
    // Generation 0 never persisted the logical member version. All five
    // strings must still agree exactly; the canonical generation is the sole
    // source of truth for nVersion.
    return a.sAlias == b.sAlias &&
           a.sAddress == b.sAddress &&
           a.sCollateralnodePrivKey == b.sCollateralnodePrivKey &&
           a.sTxHash == b.sTxHash &&
           a.sOutputIndex == b.sOutputIndex;
}

class CAdrenalineNodeConfigLegacyDiskRecord
{
public:
    int nSerializerContextVersion;
    std::string sAlias;
    std::string sAddress;
    std::string sCollateralnodePrivKey;
    std::string sTxHash;
    std::string sOutputIndex;

    CAdrenalineNodeConfigLegacyDiskRecord()
        : nSerializerContextVersion(0)
    {
    }

    bool FromLogical(const CAdrenalineNodeConfig& nodeConfig,
                     int nSerializerContextVersionIn)
    {
        if (nSerializerContextVersionIn < 0 ||
            nSerializerContextVersionIn > CLIENT_VERSION ||
            !IsAdrenalineNodeConfigStructurallyValid(nodeConfig))
            return false;
        nSerializerContextVersion = nSerializerContextVersionIn;
        sAlias = nodeConfig.sAlias;
        sAddress = nodeConfig.sAddress;
        sCollateralnodePrivKey = nodeConfig.sCollateralnodePrivKey;
        sTxHash = nodeConfig.sTxHash;
        sOutputIndex = nodeConfig.sOutputIndex;
        return true;
    }

    bool ToLogical(CAdrenalineNodeConfig& nodeConfig) const
    {
        if (nSerializerContextVersion < 0 ||
            nSerializerContextVersion > CLIENT_VERSION)
            return false;
        CAdrenalineNodeConfig decoded;
        // The shadow bug never stored the logical member. Generation 0
        // constructors always supplied zero, so migration restores zero
        // explicitly instead of reinterpreting the historical context word.
        decoded.nVersion = 0;
        decoded.sAlias = sAlias;
        decoded.sAddress = sAddress;
        decoded.sCollateralnodePrivKey = sCollateralnodePrivKey;
        decoded.sTxHash = sTxHash;
        decoded.sOutputIndex = sOutputIndex;
        if (!IsAdrenalineNodeConfigStructurallyValid(decoded))
            return false;
        nodeConfig = decoded;
        return true;
    }

    IMPLEMENT_SERIALIZE
    (
        CAdrenalineNodeConfigLegacyDiskRecord* pthis =
            const_cast<CAdrenalineNodeConfigLegacyDiskRecord*>(this);
        READWRITE(pthis->nSerializerContextVersion);
        READWRITE(pthis->sAlias);
        READWRITE(pthis->sAddress);
        READWRITE(pthis->sCollateralnodePrivKey);
        READWRITE(pthis->sTxHash);
        READWRITE(pthis->sOutputIndex);
    )
};

class CAdrenalineNodeConfigCanonicalDiskRecord
{
public:
    uint32_t nMagic;
    int nGeneration;
    std::string strStorageKey;
    CAdrenalineNodeConfig nodeConfig;

    CAdrenalineNodeConfigCanonicalDiskRecord()
        : nMagic(ADRENALINE_NODE_CONFIG_DISK_MAGIC),
          nGeneration(ADRENALINE_NODE_CONFIG_DISK_GENERATION)
    {
    }

    bool FromLogical(const std::string& strStorageKeyIn,
                     const CAdrenalineNodeConfig& nodeConfigIn)
    {
        // The BDB key is the identity; old records may not match sAddress. Never re-key from
        // nodeConfigIn.sAddress during migration.
        if (strStorageKeyIn.size() > ADRENALINE_NODE_CONFIG_MAX_FIELD_BYTES ||
            !IsAdrenalineNodeConfigStructurallyValid(nodeConfigIn))
            return false;
        nMagic = ADRENALINE_NODE_CONFIG_DISK_MAGIC;
        nGeneration = ADRENALINE_NODE_CONFIG_DISK_GENERATION;
        strStorageKey = strStorageKeyIn;
        nodeConfig = nodeConfigIn;
        return true;
    }

    bool ToLogical(const std::string& strExpectedStorageKey,
                   CAdrenalineNodeConfig& nodeConfigOut) const
    {
        if (nMagic != ADRENALINE_NODE_CONFIG_DISK_MAGIC ||
            nGeneration != ADRENALINE_NODE_CONFIG_DISK_GENERATION ||
            strStorageKey != strExpectedStorageKey ||
            !IsAdrenalineNodeConfigStructurallyValid(nodeConfig))
            return false;
        nodeConfigOut = nodeConfig;
        return true;
    }

    IMPLEMENT_SERIALIZE
    (
        CAdrenalineNodeConfigCanonicalDiskRecord* pthis =
            const_cast<CAdrenalineNodeConfigCanonicalDiskRecord*>(this);
        READWRITE(pthis->nMagic);
        READWRITE(pthis->nGeneration);
        if (fRead &&
            (pthis->nMagic != ADRENALINE_NODE_CONFIG_DISK_MAGIC ||
             pthis->nGeneration != ADRENALINE_NODE_CONFIG_DISK_GENERATION))
            throw std::ios_base::failure(
                "unsupported adrenaline config disk envelope");
        READWRITE(pthis->strStorageKey);
        READWRITE(pthis->nodeConfig.nVersion);
        READWRITE(pthis->nodeConfig.sAlias);
        READWRITE(pthis->nodeConfig.sAddress);
        READWRITE(pthis->nodeConfig.sCollateralnodePrivKey);
        READWRITE(pthis->nodeConfig.sTxHash);
        READWRITE(pthis->nodeConfig.sOutputIndex);
    )
};

} // namespace

bool EncodeLegacyAdrenalineNodeConfigValue(
    const CAdrenalineNodeConfig& nodeConfig,
    int nSerializerContextVersion,
    CDataStream& ssValue,
    std::string& strError)
{
    strError.clear();
    ssValue.clear();
    try
    {
        CAdrenalineNodeConfigLegacyDiskRecord record;
        if (!record.FromLogical(nodeConfig, nSerializerContextVersion))
            throw std::ios_base::failure(
                "invalid legacy adrenaline config fields");
        // Match the historical serializer exactly: the shadow word and the
        // context used for the following strings are the writer's version.
        ssValue.SetType(SER_DISK);
        ssValue.SetVersion(nSerializerContextVersion);
        ssValue << record.nSerializerContextVersion;
        ssValue << record.sAlias;
        ssValue << record.sAddress;
        ssValue << record.sCollateralnodePrivKey;
        ssValue << record.sTxHash;
        ssValue << record.sOutputIndex;
        return true;
    }
    catch (const std::exception& e)
    {
        ssValue.clear();
        strError = e.what();
        return false;
    }
}

bool DecodeLegacyAdrenalineNodeConfigValue(
    CDataStream& ssValue,
    CAdrenalineNodeConfig& nodeConfig,
    int& nSerializerContextVersion,
    std::string& strError)
{
    strError.clear();
    nSerializerContextVersion = 0;
    try
    {
        CAdrenalineNodeConfigLegacyDiskRecord record;
        // Reproduce the shadowed decoder rather than feeding old bytes to the
        // repaired logical serializer: the first word replaced the legacy
        // function's context for every remaining field.
        ssValue >> record.nSerializerContextVersion;
        if (record.nSerializerContextVersion < 0 ||
            record.nSerializerContextVersion > CLIENT_VERSION)
            throw std::ios_base::failure(
                "unsupported legacy serializer context version");
        ssValue.SetVersion(record.nSerializerContextVersion);
        if (!ReadAdrenalineNodeConfigString(ssValue, record.sAlias) ||
            !ReadAdrenalineNodeConfigString(ssValue, record.sAddress) ||
            !ReadAdrenalineNodeConfigString(
                ssValue, record.sCollateralnodePrivKey) ||
            !ReadAdrenalineNodeConfigString(ssValue, record.sTxHash) ||
            !ReadAdrenalineNodeConfigString(ssValue, record.sOutputIndex))
            throw std::ios_base::failure(
                "invalid bounded legacy adrenaline config string");
        if (!ssValue.empty() || !record.ToLogical(nodeConfig))
            throw std::ios_base::failure(
                "invalid or trailing legacy adrenaline config bytes");
        nSerializerContextVersion = record.nSerializerContextVersion;
        return true;
    }
    catch (const std::exception& e)
    {
        strError = e.what();
        return false;
    }
}

bool EncodeCanonicalAdrenalineNodeConfigValue(
    const std::string& strStorageKey,
    const CAdrenalineNodeConfig& nodeConfig,
    CDataStream& ssValue,
    std::string& strError)
{
    strError.clear();
    ssValue.clear();
    try
    {
        CAdrenalineNodeConfigCanonicalDiskRecord record;
        if (!record.FromLogical(strStorageKey, nodeConfig))
            throw std::ios_base::failure(
                "invalid canonical adrenaline config fields");
        ssValue.SetType(SER_DISK);
        ssValue.SetVersion(CLIENT_VERSION);
        ssValue << record;
        return true;
    }
    catch (const std::exception& e)
    {
        ssValue.clear();
        strError = e.what();
        return false;
    }
}

bool DecodeCanonicalAdrenalineNodeConfigValue(
    CDataStream& ssValue,
    const std::string& strExpectedStorageKey,
    CAdrenalineNodeConfig& nodeConfig,
    std::string& strError)
{
    strError.clear();
    try
    {
        CAdrenalineNodeConfigCanonicalDiskRecord record;
        ssValue >> record.nMagic;
        ssValue >> record.nGeneration;
        if (record.nMagic != ADRENALINE_NODE_CONFIG_DISK_MAGIC ||
            record.nGeneration !=
                ADRENALINE_NODE_CONFIG_DISK_GENERATION)
            throw std::ios_base::failure(
                "unsupported adrenaline config disk envelope");
        if (!ReadAdrenalineNodeConfigString(
                ssValue, record.strStorageKey))
            throw std::ios_base::failure(
                "invalid canonical adrenaline storage key");
        ssValue >> record.nodeConfig.nVersion;
        if (!ReadAdrenalineNodeConfigString(
                ssValue, record.nodeConfig.sAlias) ||
            !ReadAdrenalineNodeConfigString(
                ssValue, record.nodeConfig.sAddress) ||
            !ReadAdrenalineNodeConfigString(
                ssValue, record.nodeConfig.sCollateralnodePrivKey) ||
            !ReadAdrenalineNodeConfigString(
                ssValue, record.nodeConfig.sTxHash) ||
            !ReadAdrenalineNodeConfigString(
                ssValue, record.nodeConfig.sOutputIndex))
            throw std::ios_base::failure(
                "invalid bounded canonical adrenaline config string");
        if (!ssValue.empty() ||
            !record.ToLogical(strExpectedStorageKey, nodeConfig))
            throw std::ios_base::failure(
                "invalid, mismatched, or trailing canonical adrenaline config bytes");
        return true;
    }
    catch (const std::exception& e)
    {
        strError = e.what();
        return false;
    }
}

CWalletDB::WalletDBRawReadStatus CWalletDB::ReadRawValueStatus(
    CDataStream& ssKey,
    CDataStream& ssValue,
    size_t nMaxValueSize)
{
    if (!pdb || ssKey.empty())
        return WALLET_DB_READ_ERROR;

    Dbt datKey(&ssKey[0], ssKey.size());
    if (nMaxValueSize == 0 ||
        nMaxValueSize > std::numeric_limits<u_int32_t>::max())
        return WALLET_DB_READ_ERROR;
    CSerializeData vchValue(nMaxValueSize, 0);
    Dbt datValue;
    datValue.set_data(&vchValue[0]);
    datValue.set_ulen((u_int32_t)vchValue.size());
    datValue.set_flags(DB_DBT_USERMEM);
    const int ret = pdb->get(activeTxn, &datKey, &datValue, 0);
    memset(datKey.get_data(), 0, datKey.get_size());
    ssKey.clear();

    if (ret == DB_NOTFOUND)
    {
        memset(&vchValue[0], 0, vchValue.size());
        return WALLET_DB_READ_NOT_FOUND;
    }
    if (ret != 0 ||
        datValue.get_size() == 0 || datValue.get_size() > nMaxValueSize)
    {
        memset(&vchValue[0], 0, vchValue.size());
        return WALLET_DB_READ_ERROR;
    }

    ssValue.clear();
    ssValue.SetType(SER_DISK);
    ssValue.SetVersion(CLIENT_VERSION);
    try
    {
        ssValue.write((const char*)datValue.get_data(), datValue.get_size());
    }
    catch (...)
    {
        memset(&vchValue[0], 0, vchValue.size());
        ssValue.clear();
        return WALLET_DB_READ_ERROR;
    }
    memset(&vchValue[0], 0, vchValue.size());
    return WALLET_DB_READ_FOUND;
}

CWalletDB::WalletDBRawReadStatus
CWalletDB::ReadAdrenalineNodeConfigSchemaStatus(int& nGeneration)
{
    nGeneration = 0;
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey << std::string(ADRENALINE_NODE_CONFIG_SCHEMA_KEY);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    const WalletDBRawReadStatus status = ReadRawValueStatus(
        ssKey, ssValue, 32);
    if (status != WALLET_DB_READ_FOUND)
        return status;
    try
    {
        ssValue >> nGeneration;
        if (!ssValue.empty())
            return WALLET_DB_READ_ERROR;
    }
    catch (...)
    {
        return WALLET_DB_READ_ERROR;
    }
    return WALLET_DB_READ_FOUND;
}

bool CWalletDB::ReadAdrenalineNodeConfigGeneration(int& nGeneration)
{
    return ReadAdrenalineNodeConfigSchemaStatus(nGeneration) ==
           WALLET_DB_READ_FOUND;
}

bool CWalletDB::EnsureAdrenalineNodeConfigSchema(std::string& strError)
{
    int nGeneration = 0;
    const WalletDBRawReadStatus status =
        ReadAdrenalineNodeConfigSchemaStatus(nGeneration);
    if (status == WALLET_DB_READ_ERROR)
    {
        strError = "adrenaline config schema marker is corrupt";
        return false;
    }
    if (status == WALLET_DB_READ_FOUND)
    {
        if (nGeneration != ADRENALINE_NODE_CONFIG_DISK_GENERATION)
        {
            strError = strprintf(
                "unsupported adrenaline config disk generation %d",
                nGeneration);
            return false;
        }
        // Do not let a direct writer repair over an old-client mutation or a
        // partially damaged generation. Validate the complete paired record
        // set before beginning a new mutation transaction.
        return MigrateAdrenalineNodeConfigRecords(strError);
    }
    return MigrateAdrenalineNodeConfigRecords(strError);
}

bool CWalletDB::MigrateAdrenalineNodeConfigRecords(std::string& strError)
{
    strError.clear();
    if (activeTxn)
    {
        strError = "adrenaline config migration cannot join an active transaction";
        return false;
    }

    if (!TxnBegin())
    {
        strError = "could not begin atomic adrenaline config migration";
        return false;
    }

    int nGeneration = 0;
    const WalletDBRawReadStatus schemaStatus =
        ReadAdrenalineNodeConfigSchemaStatus(nGeneration);
    if (schemaStatus == WALLET_DB_READ_ERROR)
    {
        TxnAbort();
        strError = "adrenaline config schema marker is corrupt";
        return false;
    }
    if (schemaStatus == WALLET_DB_READ_FOUND &&
        nGeneration != ADRENALINE_NODE_CONFIG_DISK_GENERATION)
    {
        TxnAbort();
        strError = strprintf(
            "unsupported adrenaline config disk generation %d", nGeneration);
        return false;
    }

    std::map<std::string, CAdrenalineNodeConfig> mapLegacy;
    std::map<std::string, CAdrenalineNodeConfig> mapCanonical;
    Dbc* pcursor = GetTxnCursor();
    if (!pcursor)
    {
        TxnAbort();
        strError = "could not create wallet cursor for adrenaline config migration";
        return false;
    }

    bool fScanOk = true;
    const char* const ppszRecordTypes[] = {
        ADRENALINE_NODE_CONFIG_LEGACY_KEY,
        ADRENALINE_NODE_CONFIG_CANONICAL_KEY
    };
    for (size_t nPrefix = 0;
         fScanOk && nPrefix < sizeof(ppszRecordTypes) /
                                  sizeof(ppszRecordTypes[0]);
         ++nPrefix)
    {
        const std::string strRecordType(ppszRecordTypes[nPrefix]);
        u_int32_t fFlags = DB_SET_RANGE;
        while (fScanOk)
        {
            CDataStream ssSeek(SER_DISK, CLIENT_VERSION);
            const CDataStream* pSeek = NULL;
            if (fFlags == DB_SET_RANGE)
            {
                ssSeek << strRecordType;
                pSeek = &ssSeek;
            }
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            const int ret = ReadBoundedWalletCursor(
                pcursor, pSeek, ssKey, ssValue, fFlags);
            fFlags = DB_NEXT;
            if (ret == DB_NOTFOUND)
                break;
            if (ret != 0)
            {
                strError = "bounded wallet cursor failed during adrenaline config migration";
                fScanOk = false;
                break;
            }
            if (!WalletKeyHasSerializedType(ssKey, strRecordType))
                break;

            try
            {
                std::string strType;
                ssKey >> strType;
                if (strType != strRecordType)
                    throw std::ios_base::failure(
                        "adrenaline config cursor prefix mismatch");
                if (nPrefix == 0)
                {
                    std::string strStorageKey;
                    if (!ReadAdrenalineNodeConfigString(
                            ssKey, strStorageKey) || !ssKey.empty())
                        throw std::ios_base::failure(
                            "trailing legacy adrenaline config key bytes");
                    CAdrenalineNodeConfig nodeConfig;
                    int nSerializerContextVersion = 0;
                    std::string strDecodeError;
                    if (!DecodeLegacyAdrenalineNodeConfigValue(
                            ssValue, nodeConfig, nSerializerContextVersion,
                            strDecodeError))
                        throw std::ios_base::failure(strDecodeError);
                    if (!mapLegacy.insert(
                            std::make_pair(strStorageKey,
                                           nodeConfig)).second)
                        throw std::ios_base::failure(
                            "duplicate legacy adrenaline config key");
                    if (mapLegacy.size() >
                        ADRENALINE_NODE_CONFIG_MAX_RECORDS)
                        throw std::ios_base::failure(
                            "too many legacy adrenaline config records");
                }
                else
                {
                    int nRecordGeneration = 0;
                    std::string strStorageKey;
                    ssKey >> nRecordGeneration;
                    if (!ReadAdrenalineNodeConfigString(
                            ssKey, strStorageKey) || !ssKey.empty() ||
                        nRecordGeneration !=
                            ADRENALINE_NODE_CONFIG_DISK_GENERATION)
                        throw std::ios_base::failure(
                            "unsupported or trailing canonical adrenaline config key");
                    CAdrenalineNodeConfig nodeConfig;
                    std::string strDecodeError;
                    if (!DecodeCanonicalAdrenalineNodeConfigValue(
                            ssValue, strStorageKey, nodeConfig,
                            strDecodeError))
                        throw std::ios_base::failure(strDecodeError);
                    if (!mapCanonical.insert(
                            std::make_pair(strStorageKey,
                                           nodeConfig)).second)
                        throw std::ios_base::failure(
                            "duplicate canonical adrenaline config key");
                    if (mapCanonical.size() >
                        ADRENALINE_NODE_CONFIG_MAX_RECORDS)
                        throw std::ios_base::failure(
                            "too many canonical adrenaline config records");
                }
            }
            catch (const std::exception& e)
            {
                strError = strprintf(
                    "invalid adrenaline config wallet record: %s", e.what());
                fScanOk = false;
            }
        }
    }
    if (pcursor->close() != 0 && fScanOk)
    {
        strError = "could not close wallet cursor after adrenaline config scan";
        fScanOk = false;
    }
    if (!fScanOk)
    {
        TxnAbort();
        return false;
    }

    if (schemaStatus == WALLET_DB_READ_FOUND)
    {
        if (mapLegacy.size() != mapCanonical.size())
        {
            TxnAbort();
            strError = "legacy/canonical adrenaline config record sets differ";
            return false;
        }
        for (std::map<std::string, CAdrenalineNodeConfig>::const_iterator it =
                 mapLegacy.begin(); it != mapLegacy.end(); ++it)
        {
            std::map<std::string, CAdrenalineNodeConfig>::const_iterator jt =
                mapCanonical.find(it->first);
            if (jt == mapCanonical.end() ||
                !EqualLegacyRepresentableAdrenalineNodeConfig(
                    it->second, jt->second))
            {
                TxnAbort();
                strError = "legacy/canonical adrenaline config values differ";
                return false;
            }
        }
        if (!TxnAbort())
        {
            strError = "could not close validated adrenaline config transaction";
            return false;
        }
        return true;
    }

    if (!mapCanonical.empty())
    {
        TxnAbort();
        strError = "canonical adrenaline config records exist without a schema marker";
        return false;
    }
    if (fReadOnly)
    {
        if (!TxnAbort())
        {
            strError = "could not close read-only adrenaline config transaction";
            return false;
        }
        printf("Wallet: validated %d legacy adrenaline config records in "
               "read-only mode (migration deferred)\n", (int)mapLegacy.size());
        return true;
    }
    for (std::map<std::string, CAdrenalineNodeConfig>::const_iterator it =
             mapLegacy.begin(); it != mapLegacy.end(); ++it)
    {
        CAdrenalineNodeConfigCanonicalDiskRecord record;
        if (!record.FromLogical(it->first, it->second) ||
            !Write(AdrenalineCanonicalKey(it->first), record, true))
        {
            TxnAbort();
            strError = "failed to stage canonical adrenaline config record";
            return false;
        }
    }
    if (!Write(std::string(ADRENALINE_NODE_CONFIG_SCHEMA_KEY),
               ADRENALINE_NODE_CONFIG_DISK_GENERATION, true))
    {
        TxnAbort();
        strError = "failed to stage adrenaline config schema marker";
        return false;
    }
    if (!TxnCommit(true))
    {
        strError = "failed to commit atomic adrenaline config migration";
        return false;
    }
    nWalletDBUpdated++;
    printf("Wallet: migrated %d adrenaline config records to disk generation %d\n",
           (int)mapLegacy.size(), ADRENALINE_NODE_CONFIG_DISK_GENERATION);
    return true;
}

bool CWalletDB::WriteAdrenalineNodeConfig(std::string sAlias, const CAdrenalineNodeConfig& nodeConfig)
{
    if (activeTxn)
        return error("WriteAdrenalineNodeConfig: active transaction is unsupported");
    std::string strError;
    if (!EnsureAdrenalineNodeConfigSchema(strError))
        return error("WriteAdrenalineNodeConfig: %s", strError.c_str());

    CAdrenalineNodeConfigLegacyDiskRecord legacyRecord;
    CAdrenalineNodeConfigCanonicalDiskRecord canonicalRecord;
    if (!legacyRecord.FromLogical(nodeConfig, CLIENT_VERSION) ||
        !canonicalRecord.FromLogical(sAlias, nodeConfig))
        return error("WriteAdrenalineNodeConfig: invalid config record");
    if (!TxnBegin())
        return error("WriteAdrenalineNodeConfig: transaction begin failed");
    if (!Write(AdrenalineLegacyKey(sAlias), legacyRecord, true) ||
        !Write(AdrenalineCanonicalKey(sAlias), canonicalRecord, true) ||
        !Write(std::string(ADRENALINE_NODE_CONFIG_SCHEMA_KEY),
               ADRENALINE_NODE_CONFIG_DISK_GENERATION, true))
    {
        TxnAbort();
        return error("WriteAdrenalineNodeConfig: transaction staging failed");
    }
    if (!TxnCommit(true))
        return error("WriteAdrenalineNodeConfig: transaction commit failed");
    nWalletDBUpdated++;
    return true;
}

bool CWalletDB::ReadAdrenalineNodeConfig(std::string sAlias, CAdrenalineNodeConfig& nodeConfig)
{
    const bool fOwnReadTxn = activeTxn == NULL;
    if (fOwnReadTxn && !TxnBegin())
        return false;

    bool fReadOk = false;
    do
    {
        int nGeneration = 0;
        const WalletDBRawReadStatus schemaStatus =
            ReadAdrenalineNodeConfigSchemaStatus(nGeneration);
        if (schemaStatus == WALLET_DB_READ_ERROR ||
            (schemaStatus == WALLET_DB_READ_FOUND &&
             nGeneration != ADRENALINE_NODE_CONFIG_DISK_GENERATION))
            break;

        CDataStream ssLegacyKey(SER_DISK, CLIENT_VERSION);
        ssLegacyKey << AdrenalineLegacyKey(sAlias);
        CDataStream ssLegacyValue(SER_DISK, CLIENT_VERSION);
        const WalletDBRawReadStatus legacyStatus = ReadRawValueStatus(
            ssLegacyKey, ssLegacyValue,
            ADRENALINE_NODE_CONFIG_MAX_VALUE_BYTES);

        CDataStream ssCanonicalKey(SER_DISK, CLIENT_VERSION);
        ssCanonicalKey << AdrenalineCanonicalKey(sAlias);
        CDataStream ssCanonicalValue(SER_DISK, CLIENT_VERSION);
        const WalletDBRawReadStatus canonicalStatus = ReadRawValueStatus(
            ssCanonicalKey, ssCanonicalValue,
            ADRENALINE_NODE_CONFIG_MAX_VALUE_BYTES);

        if (schemaStatus == WALLET_DB_READ_NOT_FOUND)
        {
            if (canonicalStatus != WALLET_DB_READ_NOT_FOUND ||
                legacyStatus != WALLET_DB_READ_FOUND)
                break;
            CAdrenalineNodeConfig decoded;
            int nSerializerContextVersion = 0;
            std::string strDecodeError;
            if (!DecodeLegacyAdrenalineNodeConfigValue(
                    ssLegacyValue, decoded, nSerializerContextVersion,
                    strDecodeError))
                break;
            nodeConfig = decoded;
            fReadOk = true;
            break;
        }

        if (legacyStatus != WALLET_DB_READ_FOUND ||
            canonicalStatus != WALLET_DB_READ_FOUND)
            break;
        CAdrenalineNodeConfig legacyConfig;
        CAdrenalineNodeConfig canonicalConfig;
        int nSerializerContextVersion = 0;
        std::string strDecodeError;
        if (!DecodeLegacyAdrenalineNodeConfigValue(
                ssLegacyValue, legacyConfig, nSerializerContextVersion,
                strDecodeError) ||
            !DecodeCanonicalAdrenalineNodeConfigValue(
                ssCanonicalValue, sAlias, canonicalConfig,
                strDecodeError) ||
            !EqualLegacyRepresentableAdrenalineNodeConfig(
                legacyConfig, canonicalConfig))
            break;
        nodeConfig = canonicalConfig;
        fReadOk = true;
    } while (false);

    if (fOwnReadTxn && !TxnAbort())
        return false;
    return fReadOk;
}

bool CWalletDB::EraseAdrenalineNodeConfig(std::string sAlias)
{
    if (activeTxn)
        return error("EraseAdrenalineNodeConfig: active transaction is unsupported");
    std::string strError;
    if (!EnsureAdrenalineNodeConfigSchema(strError))
        return error("EraseAdrenalineNodeConfig: %s", strError.c_str());
    if (!TxnBegin())
        return error("EraseAdrenalineNodeConfig: transaction begin failed");
    if (!Erase(AdrenalineLegacyKey(sAlias)) ||
        !Erase(AdrenalineCanonicalKey(sAlias)) ||
        !Write(std::string(ADRENALINE_NODE_CONFIG_SCHEMA_KEY),
               ADRENALINE_NODE_CONFIG_DISK_GENERATION, true))
    {
        TxnAbort();
        return error("EraseAdrenalineNodeConfig: transaction staging failed");
    }
    if (!TxnCommit(true))
        return error("EraseAdrenalineNodeConfig: transaction commit failed");
    nWalletDBUpdated++;
    return true;
}

bool CWalletDB::WriteWatchOnly(const CScript &dest)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("watchs"), dest), '1');
}

bool CWalletDB::EraseWatchOnly(const CScript &dest)
{
    nWalletDBUpdated++;
    return Erase(std::make_pair(std::string("watchs"), dest));
}

int64_t CWalletDB::GetAccountCreditDebit(const string& strAccount)
{
    list<CAccountingEntry> entries;
    ListAccountCreditDebit(strAccount, entries);

    int64_t nCreditDebit = 0;
    BOOST_FOREACH (const CAccountingEntry& entry, entries)
        nCreditDebit += entry.nCreditDebit;

    return nCreditDebit;
}

void CWalletDB::ListAccountCreditDebit(const string& strAccount, list<CAccountingEntry>& entries)
{
    bool fAllAccounts = (strAccount == "*");

    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error("CWalletDB::ListAccountCreditDebit() : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    while (true)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << boost::make_tuple(string("acentry"), (fAllAccounts? string("") : strAccount), uint64_t(0));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error("CWalletDB::ListAccountCreditDebit() : error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "acentry")
            break;
        CAccountingEntry acentry;
        ssKey >> acentry.strAccount;
        if (!fAllAccounts && acentry.strAccount != strAccount)
            break;

        ssValue >> acentry;
        ssKey >> acentry.nEntryNo;
        entries.push_back(acentry);
    }

    pcursor->close();
}


DBErrors
CWalletDB::ReorderTransactions(CWallet* pwallet)
{
    LOCK(pwallet->cs_wallet);
    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
    typedef pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef multimap<int64_t, TxPair > TxItems;
    TxItems txByTime;

    for (map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txByTime.insert(make_pair(wtx->nTimeReceived, TxPair(wtx, (CAccountingEntry*)0)));
    }
    list<CAccountingEntry> acentries;
    ListAccountCreditDebit("", acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
    }

    int64_t& nOrderPosNext = pwallet->nOrderPosNext;
    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        CAccountingEntry *const pacentry = (*it).second.second;
        int64_t& nOrderPos = (pwtx != 0) ? pwtx->nOrderPos : pacentry->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (pacentry)
                // Have to write accounting regardless, since we don't keep it in memory
                if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            BOOST_FOREACH(const int64_t& nOffsetStart, nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (pwtx)
            {
                if (!WriteTx(pwtx->GetHash(), *pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
    }

    return DB_LOAD_OK;
}

class CWalletScanState {
public:
    unsigned int nKeys;
    unsigned int nCKeys;
    unsigned int nKeyMeta;
    bool fIsEncrypted;
    bool fAnyUnordered;
    int nFileVersion;
    vector<uint256> vWalletUpgrade;

    CWalletScanState() {
        nKeys = nCKeys = nKeyMeta = 0;
        fIsEncrypted = false;
        fAnyUnordered = false;
        nFileVersion = 0;
    }
};

bool
ReadKeyValue(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue,
             CWalletScanState &wss, string& strType, string& strErr)
{
    try {
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        ssKey >> strType;
        if (strType == "name")
        {
            string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CBitcoinAddress(strAddress).Get()];
        }
        else if (strType == "tx")
        {
            uint256 hash;
            ssKey >> hash;
            CWalletTx& wtx = pwallet->mapWallet[hash];
            ssValue >> wtx;
            if (wtx.CheckTransaction() && (wtx.GetHash() == hash))
                wtx.BindWallet(pwallet);
            else
            {
                pwallet->mapWallet.erase(hash);
                return false;
            }

            // Undo serialize changes in 31600
            if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703)
            {
                if (!ssValue.empty())
                {
                    char fTmp;
                    char fUnused;
                    ssValue >> fTmp >> fUnused >> wtx.strFromAccount;
                    strErr = strprintf("LoadWallet() upgrading tx ver=%d %d '%s' %s",
                                       wtx.fTimeReceivedIsTxTime, fTmp, wtx.strFromAccount.c_str(), hash.ToString().c_str());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                }
                else
                {
                    strErr = strprintf("LoadWallet() repairing tx ver=%d %s", wtx.fTimeReceivedIsTxTime, hash.ToString().c_str());
                    wtx.fTimeReceivedIsTxTime = 0;
                }
                wss.vWalletUpgrade.push_back(hash);
            }

            if (wtx.nOrderPos == -1)
                wss.fAnyUnordered = true;

            //// debug print
            //printf("LoadWallet  %s\n", wtx.GetHash().ToString().c_str());
            //printf(" %12" PRId64"  %s  %s  %s\n",
            //    wtx.vout[0].nValue,
            //    DateTimeStrFormat("%x %H:%M:%S", wtx.GetBlockTime()).c_str(),
            //    wtx.hashBlock.ToString().substr(0,20).c_str(),
            //    wtx.mapValue["message"].c_str());
        } else
        if (strType == "sxAddr")
        {
            if (fDebug)
                printf("WalletDB ReadKeyValue sxAddr\n");

            CStealthAddress sxAddr;
            ssValue >> sxAddr;

            pwallet->stealthAddresses.insert(sxAddr);
        } else if (strType == "acentry")
        {
            string strAccount;
            ssKey >> strAccount;
            uint64_t nNumber;
            ssKey >> nNumber;
            if (nNumber > nAccountingEntryNumber)
                nAccountingEntryNumber = nNumber;

            if (!wss.fAnyUnordered)
            {
                CAccountingEntry acentry;
                ssValue >> acentry;
                if (acentry.nOrderPos == -1)
                    wss.fAnyUnordered = true;
            }
        }
        else if (strType == "watchs")
        {
            CScript script;
            ssKey >> script;
            char fYes;
            ssValue >> fYes;
            if (fYes == '1')
                pwallet->LoadWatchOnly(script);

            // Watch-only addresses have no birthday information for now,
            // so set the wallet birthday to the beginning of time.
            pwallet->nTimeFirstKey = 1;
        }
        else if (strType == "key" || strType == "wkey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash = 0;

            if (strType == "key")
            {
                wss.nKeys++;
                ssValue >> pkey;
            } else {
                CWalletKey wkey;
                ssValue >> wkey;
                pkey = wkey.vchPrivKey;
            }

            // Old wallets store keys as "key" [pubkey] => [privkey]
            // ... which was slow for wallets with lots of keys, because the public key is re-derived from the private key
            // using EC operations as a checksum.
            // Newer wallets store keys as "key"[pubkey] => [privkey][hash(pubkey,privkey)], which is much faster while
            // remaining backwards-compatible.
            try
            {
                ssValue >> hash;
            }
            catch(...){}

            bool fSkipCheck = false;

            if (hash != 0)
            {
                // hash pubkey/privkey to accelerate wallet load
                std::vector<unsigned char> vchKey;
                vchKey.reserve(vchPubKey.size() + pkey.size());
                vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
                vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

                if (Hash(vchKey.begin(), vchKey.end()) != hash)
                {
                    strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                    return false;
                }

                fSkipCheck = true;
            }

            if (!key.Load(pkey, vchPubKey, fSkipCheck))
            {
                strErr = "Error reading wallet database: CPrivKey corrupt";
                return false;
            }
            if (!pwallet->LoadKey(key, vchPubKey))
            {
                strErr = "Error reading wallet database: LoadKey failed";
                return false;
            }
        }
        else if (strType == "mkey")
        {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if(pwallet->mapMasterKeys.count(nID) != 0)
            {
                strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
                return false;
            }
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
        }
        else if (strType == "ckey")
        {
            wss.nCKeys++;
            vector<unsigned char> vchPubKey;
            ssKey >> vchPubKey;
            vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;
            if (!pwallet->LoadCryptedKey(vchPubKey, vchPrivKey))
            {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        }
        else if (strType == "keymeta")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;

            pwallet->LoadKeyMetadata(vchPubKey, keyMeta);

            // find earliest key creation time, as wallet birthday
            if (!pwallet->nTimeFirstKey ||
                (keyMeta.nCreateTime < pwallet->nTimeFirstKey))
                pwallet->nTimeFirstKey = keyMeta.nCreateTime;
        }
        else if (strType == "sxKeyMeta")
        {
            if (fDebug)
                printf("WalletDB ReadKeyValue sxKeyMeta\n");

            CKeyID keyId;
            ssKey >> keyId;
            CStealthKeyMetadata sxKeyMeta;
            ssValue >> sxKeyMeta;

            pwallet->mapStealthKeyMeta[keyId] = sxKeyMeta;
        }
        else if (strType == "defaultkey")
        {
            ssValue >> pwallet->vchDefaultKey;
        }
        else if (strType == "pool")
        {
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPool keypool;
            ssValue >> keypool;
            pwallet->setKeyPool.insert(nIndex);

            // If no metadata exists yet, create a default with the pool key's
            // creation time. Note that this may be overwritten by actually
            // stored metadata for that key later, which is fine.
            CKeyID keyid = keypool.vchPubKey.GetID();
            if (pwallet->mapKeyMetadata.count(keyid) == 0)
                pwallet->mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);

        }
        else if (strType == "version")
        {
            ssValue >> wss.nFileVersion;
            if (wss.nFileVersion == 10300)
                wss.nFileVersion = 300;
        }
        else if (strType == "cscript")
        {
            uint160 hash;
            ssKey >> hash;
            CScript script;
            ssValue >> script;
            if (!pwallet->LoadCScript(script))
            {
                strErr = "Error reading wallet database: LoadCScript failed";
                return false;
            }
        }
        else if (strType == "orderposnext")
        {
            ssValue >> pwallet->nOrderPosNext;
        }
        else if (strType == "iv5seed")
        {
            CPrivacyVNextSeedRecord record;
            ssValue >> record;
            if (!ssValue.empty())
            {
                strErr = "Error reading wallet database: trailing IV5 seed bytes";
                return false;
            }
            std::string strSeedError;
            if (!pwallet->LoadPrivacyVNextSeedRecord(record, strSeedError))
            {
                strErr = "Error reading wallet database: " + strSeedError;
                return false;
            }
            wss.fIsEncrypted = true;
        }
        else if (strType == "shkey")
        {
            CShieldedPaymentAddress addr;
            ssKey >> addr;
            CShieldedSpendingKey key;
            ssValue >> key;

            LOCK(pwallet->cs_shielded);
            pwallet->mapShieldedSpendingKeys[addr] = key;

            CShieldedFullViewingKey fvk;
            DeriveShieldedFullViewingKey(key, fvk);
            CShieldedIncomingViewingKey ivk;
            DeriveShieldedIncomingViewingKey(fvk, ivk);
            pwallet->mapShieldedViewingKeys[addr] = ivk;
        }
        else if (strType == "shvk")
        {
            CShieldedPaymentAddress addr;
            ssKey >> addr;
            CShieldedIncomingViewingKey ivk;
            ssValue >> ivk;

            LOCK(pwallet->cs_shielded);
            if (pwallet->mapShieldedSpendingKeys.count(addr) == 0)
                pwallet->mapShieldedViewingKeys[addr] = ivk;
        }
        else if (strType == "shnote")
        {
            uint256 txhash;
            uint32_t nPosition;
            ssKey >> txhash;
            ssKey >> nPosition;
            CShieldedNoteData data;
            ssValue >> data;

            LOCK(pwallet->cs_shielded);
            bool fDuplicate = false;
            for (const auto& existing : pwallet->vShieldedNotes)
            {
                if (existing.txhash == txhash && existing.nPosition == nPosition)
                {
                    fDuplicate = true;
                    break;
                }
            }
            if (!fDuplicate)
            {
                CWallet::CShieldedWalletNote wnote;
                wnote.note = data.note;
                wnote.txhash = txhash;
                wnote.nPosition = nPosition;
                wnote.fSpent = data.fSpent;
                wnote.nHeight = data.nHeight;
                pwallet->vShieldedNotes.push_back(wnote);
            }
        }
        else if (strType == "iv5idxcount")
        {
            uint32_t nCount = 0;
            ssValue >> nCount;
            if (nCount == 0)
            {
                strErr = "Error reading wallet database: IV5 index count is zero";
                return false;
            }
            LOCK(pwallet->cs_shielded);
            pwallet->nPrivacyVNextIndexCount = nCount;
        }
        else if (strType == "iv5scangap")
        {
            int nHeight = -1;
            ssValue >> nHeight;
            LOCK(pwallet->cs_shielded);
            pwallet->nPrivacyVNextScanGapHeight = nHeight < 0 ? -1 : nHeight;
        }
        else if (strType == "iv5note")
        {
            uint256 txhash;
            uint32_t nOutputIndex;
            ssKey >> txhash;
            ssKey >> nOutputIndex;
            CPrivacyVNextWalletNote note;
            ssValue >> note;
            if (note.txhash != txhash || note.nOutputIndex != nOutputIndex ||
                !note.IsComplete())
            {
                strErr = "Error reading wallet database: malformed IV5 note record";
                return false;
            }

            LOCK(pwallet->cs_shielded);
            bool fDuplicate = false;
            for (const auto& existing : pwallet->vPrivacyVNextNotes)
            {
                if (existing.txhash == txhash &&
                    existing.nOutputIndex == nOutputIndex)
                {
                    fDuplicate = true;
                    break;
                }
            }
            if (!fDuplicate)
                pwallet->vPrivacyVNextNotes.push_back(note);
        }
        else if (strType == "iv5coll")
        {
            uint256 keyImage;
            ssKey >> keyImage;
            CPrivacyVNextCollateralRegistration record;
            ssValue >> record;
            if (record.keyImage != keyImage || !record.IsValid())
            {
                strErr = "Error reading wallet database: malformed IV5 collateral record";
                return false;
            }

            LOCK(pwallet->cs_shielded);
            pwallet->mapPrivacyVNextCollateral[keyImage] = record;
        }
        else if (strType == "csdeleg")
        {
            uint256 hashOwner;
            ssKey >> hashOwner;
            CColdStakeDelegation deleg;
            ssValue >> deleg;

            LOCK(pwallet->cs_shielded);
            pwallet->mapColdStakeDelegations[hashOwner] = deleg;
        }
        else if (strType == "mofndeleg")
        {
            uint256 delegationHash;
            ssKey >> delegationHash;
            CMofNDelegation deleg;
            ssValue >> deleg;

            LOCK(pwallet->cs_shielded);
            pwallet->mapMofNDelegations[delegationHash] = deleg;
        }
        else if (strType == "mofnmkey")
        {
            std::vector<unsigned char> vchPubKey;
            ssKey >> vchPubKey;
            uint256 secret;
            ssValue >> secret;

            LOCK(pwallet->cs_shielded);
            pwallet->mapMofNMemberKeys[vchPubKey] = secret;
        }
        else if (strType == "adrenaline")
        {
            if (ssValue.size() >
                ADRENALINE_NODE_CONFIG_MAX_VALUE_BYTES)
                throw std::ios_base::failure(
                    "oversized legacy adrenaline config value");
            std::string sStorageKey;
            if (!ReadAdrenalineNodeConfigString(
                    ssKey, sStorageKey) || !ssKey.empty())
                throw std::ios_base::failure(
                    "trailing legacy adrenaline config key bytes");
            CAdrenalineNodeConfig adrenalineNodeConfig;
            int nSerializerContextVersion = 0;
            std::string strDecodeError;
            if (!DecodeLegacyAdrenalineNodeConfigValue(
                    ssValue, adrenalineNodeConfig,
                    nSerializerContextVersion, strDecodeError))
                throw std::ios_base::failure(strDecodeError);
            // Keep a compatibility view only until a canonical record for the
            // same storage identity is encountered. Canonical assignment below
            // wins regardless of Berkeley DB cursor ordering.
            pwallet->mapMyAdrenalineNodes.insert(
                make_pair(sStorageKey, adrenalineNodeConfig));
        }
        else if (strType == "adrenalinecfg")
        {
            if (ssValue.size() >
                ADRENALINE_NODE_CONFIG_MAX_VALUE_BYTES)
                throw std::ios_base::failure(
                    "oversized canonical adrenaline config value");
            int nGeneration = 0;
            std::string sStorageKey;
            ssKey >> nGeneration;
            if (!ReadAdrenalineNodeConfigString(
                    ssKey, sStorageKey) || !ssKey.empty() ||
                nGeneration != ADRENALINE_NODE_CONFIG_DISK_GENERATION)
                throw std::ios_base::failure(
                    "unsupported canonical adrenaline config key");
            CAdrenalineNodeConfig adrenalineNodeConfig;
            std::string strDecodeError;
            if (!DecodeCanonicalAdrenalineNodeConfigValue(
                    ssValue, sStorageKey, adrenalineNodeConfig,
                    strDecodeError))
                throw std::ios_base::failure(strDecodeError);
            pwallet->mapMyAdrenalineNodes[sStorageKey] =
                adrenalineNodeConfig;
        }
    } catch (...)
    {
        return false;
    }
    return true;
}

bool CWalletDB::WritePrivacyVNextSeed(
    const CPrivacyVNextSeedRecord& record)
{
    if (activeTxn)
        return error("WritePrivacyVNextSeed: active transaction is unsupported");
    if (!TxnBegin())
        return error("WritePrivacyVNextSeed: transaction begin failed");
    if (!Write(std::string("iv5seed"), record, false))
    {
        TxnAbort();
        return error("WritePrivacyVNextSeed: transaction staging failed");
    }
    if (!TxnCommit(true))
        return error("WritePrivacyVNextSeed: transaction commit failed");
    nWalletDBUpdated++;
    return true;
}

bool CWalletDB::AdvancePrivacyVNextSeedIndex(
    const CPrivacyVNextSeedRecord& expected,
    uint32_t nextAddressIndex)
{
    if (activeTxn)
        return error("AdvancePrivacyVNextSeedIndex: active transaction is unsupported");
    if (expected.nNextAddressIndex == 0xffffffffU ||
        nextAddressIndex != expected.nNextAddressIndex + 1)
        return error("AdvancePrivacyVNextSeedIndex: non-sequential index");
    if (!TxnBegin())
        return error("AdvancePrivacyVNextSeedIndex: transaction begin failed");

    CPrivacyVNextSeedRecord current;
    if (!Read(std::string("iv5seed"), current) ||
        current.nGeneration != expected.nGeneration ||
        current.vchCryptedSeed != expected.vchCryptedSeed ||
        current.hashSeedCommitment != expected.hashSeedCommitment ||
        current.nNextAddressIndex != expected.nNextAddressIndex)
    {
        TxnAbort();
        return error("AdvancePrivacyVNextSeedIndex: persisted record mismatch");
    }
    current.nNextAddressIndex = nextAddressIndex;
    if (!Write(std::string("iv5seed"), current, true))
    {
        TxnAbort();
        return error("AdvancePrivacyVNextSeedIndex: transaction staging failed");
    }
    if (!TxnCommit(true))
        return error("AdvancePrivacyVNextSeedIndex: transaction commit failed");
    nWalletDBUpdated++;
    return true;
}

bool CWalletDB::RaisePrivacyVNextSeedIndex(
    const CPrivacyVNextSeedRecord& expected,
    uint32_t nMinNextAddressIndex)
{
    if (activeTxn)
        return error("RaisePrivacyVNextSeedIndex: active transaction is unsupported");
    if (nMinNextAddressIndex <= expected.nNextAddressIndex)
        return error("RaisePrivacyVNextSeedIndex: index does not raise");
    if (nMinNextAddressIndex > PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES)
        return error("RaisePrivacyVNextSeedIndex: index is outside the issuable bound");
    if (!TxnBegin())
        return error("RaisePrivacyVNextSeedIndex: transaction begin failed");

    // The same compare-and-swap the sequential advance makes: a record that moved under
    // us is a concurrent issue or a reload, and raising over it would overwrite a count
    // this wallet arrived at by handing an address out.
    CPrivacyVNextSeedRecord current;
    if (!Read(std::string("iv5seed"), current) ||
        current.nGeneration != expected.nGeneration ||
        current.vchCryptedSeed != expected.vchCryptedSeed ||
        current.hashSeedCommitment != expected.hashSeedCommitment ||
        current.nNextAddressIndex != expected.nNextAddressIndex)
    {
        TxnAbort();
        return error("RaisePrivacyVNextSeedIndex: persisted record mismatch");
    }
    current.nNextAddressIndex = nMinNextAddressIndex;
    if (!Write(std::string("iv5seed"), current, true))
    {
        TxnAbort();
        return error("RaisePrivacyVNextSeedIndex: transaction staging failed");
    }
    if (!TxnCommit(true))
        return error("RaisePrivacyVNextSeedIndex: transaction commit failed");
    nWalletDBUpdated++;
    return true;
}

static bool IsKeyType(string strType)
{
    return (strType== "key" || strType == "wkey" ||
            strType == "mkey" || strType == "ckey" ||
            strType == "iv5seed");
}

DBErrors CWalletDB::LoadWallet(CWallet* pwallet)
{
    pwallet->vchDefaultKey = CPubKey();
    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try {
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read((string)"minversion", nMinVersion))
        {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        std::string strAdrenalineMigrationError;
        if (!MigrateAdrenalineNodeConfigRecords(
                strAdrenalineMigrationError))
        {
            printf("Error migrating wallet adrenaline config records: %s\n",
                   strAdrenalineMigrationError.c_str());
            return DB_CORRUPT;
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            printf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                printf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            // Try to be tolerant of single corrupt records:
            string strType, strErr;
            if (!ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr))
            {
                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with:
                if (IsKeyType(strType))
                    result = DB_CORRUPT;
                else
                {
                    // Leave other errors alone, if we try to fix them we might make things worse.
                    fNoncriticalErrors = true; // ... but do warn the user there is something wrong.
                    if (strType == "tx")
                        // Rescan if there is a bad transaction record:
                        SoftSetBoolArg("-rescan", true);
                }
            }
            if (!strErr.empty())
                printf("%s\n", strErr.c_str());
        }
        pcursor->close();
    }
    catch (...)
    {
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    // Any wallet corruption at all: skip any rewriting or
    // upgrading, we don't want to make it worse.
    if (result != DB_LOAD_OK)
        return result;

    printf("nFileVersion = %d\n", wss.nFileVersion);

    printf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total\n",
           wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys);

    // nTimeFirstKey is only reliable if all keys have metadata
    if ((wss.nKeys + wss.nCKeys) != wss.nKeyMeta)
        pwallet->nTimeFirstKey = 1; // 0 would be considered 'no value'


    BOOST_FOREACH(uint256 hash, wss.vWalletUpgrade)
        WriteTx(hash, pwallet->mapWallet[hash]);

    // Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc:
    if (wss.fIsEncrypted && (wss.nFileVersion == 40000 || wss.nFileVersion == 50000))
        return DB_NEED_REWRITE;

    if (wss.nFileVersion < CLIENT_VERSION) // Update
        WriteVersion(CLIENT_VERSION);

    if (wss.fAnyUnordered)
        result = ReorderTransactions(pwallet);

    return result;
}

DBErrors CWalletDB::FindWalletTx(CWallet* pwallet, vector<uint256>& vTxHash)
{
    pwallet->vchDefaultKey = CPubKey();
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try {
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read((string)"minversion", nMinVersion))
        {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            printf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                printf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            string strType;
            ssKey >> strType;
            if (strType == "tx") {
                uint256 hash;
                ssKey >> hash;

                vTxHash.push_back(hash);
            }
        }
        pcursor->close();
    }
    catch (boost::thread_interrupted) {
        throw;
    }
    catch (...) {
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    return result;
}

DBErrors CWalletDB::ZapWalletTx(CWallet* pwallet)
{
    // build list of wallet TXs
    vector<uint256> vTxHash;
    DBErrors err = FindWalletTx(pwallet, vTxHash);
    if (err != DB_LOAD_OK)
        return err;

    // erase each wallet TX
    BOOST_FOREACH (uint256& hash, vTxHash) {
        if (!EraseTx(hash))
            return DB_CORRUPT;
    }

    return DB_LOAD_OK;
}

namespace
{
CCriticalSection cs_walletDBFlushThread;
boost::thread* pWalletDBFlushThread = NULL;
std::string strWalletDBFlushFile;
}

bool StartWalletDBFlushThread(const std::string& strFile)
{
    if (!GetBoolArg("-flushwallet", true))
        return true;

    LOCK(cs_walletDBFlushThread);
    if (pWalletDBFlushThread)
        return true;
    strWalletDBFlushFile = strFile;
    try
    {
        pWalletDBFlushThread = new boost::thread(
            ThreadFlushWalletDB, &strWalletDBFlushFile);
    }
    catch (const boost::thread_resource_error& e)
    {
        pWalletDBFlushThread = NULL;
        strWalletDBFlushFile.clear();
        return error("StartWalletDBFlushThread() : %s", e.what());
    }
    return true;
}

void StopWalletDBFlushThread()
{
    LOCK(cs_walletDBFlushThread);
    if (!pWalletDBFlushThread)
        return;

    // Only the lifecycle owner may stop this worker. Keeping the lifecycle
    // lock through join prevents a concurrent LoadWallet from replacing the
    // immutable filename state before the old thread has exited.
    if (pWalletDBFlushThread->get_id() == boost::this_thread::get_id())
    {
        error("StopWalletDBFlushThread() : worker attempted to join itself");
        return;
    }
    pWalletDBFlushThread->interrupt();
    pWalletDBFlushThread->join();
    delete pWalletDBFlushThread;
    pWalletDBFlushThread = NULL;
    strWalletDBFlushFile.clear();
}

void ThreadFlushWalletDB(void* parg)
{
    // Make this thread recognisable as the wallet flushing thread
    RenameThread("innova-wallet");

    // Copy the owned launch argument before entering the loop. The controller
    // retains its storage until this thread has joined.
    const string strFile = ((const string*)parg)[0];
    if (!GetBoolArg("-flushwallet", true))
        return;

    unsigned int nLastSeen = nWalletDBUpdated;
    unsigned int nLastFlushed = nWalletDBUpdated;
    int64_t nLastWalletUpdate = GetTime();
    try
    {
        while (!fShutdown)
        {
            MilliSleep(500);

            if (!IsInitialBlockDownload())
            {
                LOCK(cs_vNodes);
                for (CNode* pnode : vNodes)
                {
                    bool fPeerCatchingUp = nBestHeight >= 0 && pnode->nChainHeight >= 0 &&
                                            pnode->nChainHeight + 24 < nBestHeight;
                    int64_t nMaxPeerSendBytesArg = GetArg("-maxpp", 0);
                    uint64_t nMaxPeerSendBytes = (uint64_t)std::max<int64_t>(0, nMaxPeerSendBytesArg);
                    if (!fPeerCatchingUp &&
                        nMaxPeerSendBytes > 0 &&
                        pnode->nSendBytes >= nMaxPeerSendBytes &&
                        GetTime() - pnode->nTimeConnected < GetArg("-maxpptime", 10*60))
                    {
                        printf("Disconnecting Node: %s, send byte limit exceeded = %llu\n",
                               pnode->addr.ToString().c_str(),
                               (unsigned long long)pnode->nSendBytes);
                        pnode->fDisconnect = true;
                        if (GetBoolArg("-maxppban", false))
                        {
                            int bantime = 60*60*24;
                            CNode::Ban(pnode->addr, BanReasonNodeMisbehaving, bantime);
                        }
                        pnode->CloseSocketDisconnect();
                    }
                }
            }

            if (nLastSeen != nWalletDBUpdated)
            {
                nLastSeen = nWalletDBUpdated;
                nLastWalletUpdate = GetTime();
            }

            if (nLastFlushed != nWalletDBUpdated && GetTime() - nLastWalletUpdate >= 2)
            {
                TRY_LOCK(bitdb.cs_db,lockDb);
                if (lockDb)
                {
                    // Don't do this if any databases are in use
                    int nRefCount = 0;
                    map<string, int>::iterator mi = bitdb.mapFileUseCount.begin();
                    while (mi != bitdb.mapFileUseCount.end())
                    {
                        nRefCount += (*mi).second;
                        mi++;
                    }

                    if (nRefCount == 0 && !fShutdown)
                    {
                        map<string, int>::iterator mi = bitdb.mapFileUseCount.find(strFile);
                        if (mi != bitdb.mapFileUseCount.end())
                        {
                            printf("Flushing wallet.dat\n");
                            nLastFlushed = nWalletDBUpdated;
                            int64_t nStart = GetTimeMillis();

                            // Flush wallet.dat so it's self contained
                            bitdb.CloseDb(strFile);
                            bitdb.CheckpointLSN(strFile);

                            bitdb.mapFileUseCount.erase(mi++);
                            printf("Flushed wallet.dat %" PRId64"ms\n", GetTimeMillis() - nStart);
                        }
                    }
                }
            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        // StopWalletDBFlushThread() owns and joins this cooperative exit.
    }
}

bool BackupWallet(const CWallet& wallet, const string& strDest)
{
    if (!wallet.fFileBacked)
        return false;
    while (!fShutdown)
    {
        {
            LOCK(bitdb.cs_db);
            if (!bitdb.mapFileUseCount.count(wallet.strWalletFile) || bitdb.mapFileUseCount[wallet.strWalletFile] == 0)
            {
                // Flush log data to the dat file
                bitdb.CloseDb(wallet.strWalletFile);
                bitdb.CheckpointLSN(wallet.strWalletFile);
                bitdb.mapFileUseCount.erase(wallet.strWalletFile);

                // Copy wallet.dat
                fs::path pathSrc = GetDataDir() / wallet.strWalletFile;
                fs::path pathDest(strDest);
                if (fs::is_directory(pathDest))
                    pathDest /= wallet.strWalletFile;

                try {
#if BOOST_VERSION >= 107800
                    fs::copy_file(pathSrc, pathDest, fs::copy_options::overwrite_existing);
#elif BOOST_VERSION >= 104000
                    fs::copy_file(pathSrc, pathDest, fs::copy_option::overwrite_if_exists);
#else
                    fs::copy_file(pathSrc, pathDest);
#endif
                    printf("copied wallet.dat to %s\n", pathDest.string().c_str());
                    return true;
                } catch(const fs::filesystem_error &e) {
                    printf("error copying wallet.dat to %s - %s\n", pathDest.string().c_str(), e.what());
                    return false;
                }
            }
        }
        MilliSleep(100);
    }
    return false;
}

//
// Try to (very carefully!) recover wallet.dat if there is a problem.
//
bool CWalletDB::Recover(CDBEnv& dbenv, std::string filename, bool fOnlyKeys)
{
    // Recovery procedure:
    // move wallet.dat to wallet.timestamp.bak
    // Call Salvage with fAggressive=true to
    // get as much data as possible.
    // Rewrite salvaged data to wallet.dat
    // Set -rescan so any missing transactions will be
    // found.
    int64_t now = GetTime();
    std::string newFilename = strprintf("wallet.%" PRId64".bak", now);

    int result = dbenv.dbenv.dbrename(NULL, filename.c_str(), NULL,
                                      newFilename.c_str(), DB_AUTO_COMMIT);
    if (result == 0)
        printf("Renamed %s to %s\n", filename.c_str(), newFilename.c_str());
    else
    {
        printf("Failed to rename %s to %s\n", filename.c_str(), newFilename.c_str());
        return false;
    }

    std::vector<CDBEnv::KeyValPair> salvagedData;
    bool allOK = dbenv.Salvage(newFilename, true, salvagedData);
    if (salvagedData.empty())
    {
        printf("Salvage(aggressive) found no records in %s.\n", newFilename.c_str());
        return false;
    }
    printf("Salvage(aggressive) found %" PRIszu" records\n", salvagedData.size());

    bool fSuccess = allOK;
    Db* pdbCopy = new Db(&dbenv.dbenv, 0);
    int ret = pdbCopy->open(NULL,                 // Txn pointer
                            filename.c_str(),   // Filename
                            "main",    // Logical db name
                            DB_BTREE,  // Database type
                            DB_CREATE,    // Flags
                            0);
    if (ret > 0)
    {
        printf("Cannot create database file %s\n", filename.c_str());
        return false;
    }
    CWallet dummyWallet;
    CWalletScanState wss;

    DbTxn* ptxn = dbenv.TxnBegin();
    BOOST_FOREACH(CDBEnv::KeyValPair& row, salvagedData)
    {
        if (fOnlyKeys)
        {
            CDataStream ssKey(row.first, SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(row.second, SER_DISK, CLIENT_VERSION);
            string strType, strErr;
            bool fReadOK = ReadKeyValue(&dummyWallet, ssKey, ssValue,
                                        wss, strType, strErr);
            if (!IsKeyType(strType))
                continue;
            if (!fReadOK)
            {
                printf("WARNING: CWalletDB::Recover skipping %s: %s\n", strType.c_str(), strErr.c_str());
                continue;
            }
        }
        Dbt datKey(&row.first[0], row.first.size());
        Dbt datValue(&row.second[0], row.second.size());
        int ret2 = pdbCopy->put(ptxn, &datKey, &datValue, DB_NOOVERWRITE);
        if (ret2 > 0)
            fSuccess = false;
    }
    ptxn->commit(0);
    pdbCopy->close(0);
    delete pdbCopy;

    return fSuccess;
}

bool CWalletDB::Recover(CDBEnv& dbenv, std::string filename)
{
    return CWalletDB::Recover(dbenv, filename, false);
}
