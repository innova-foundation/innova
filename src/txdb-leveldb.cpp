// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <map>
#include <set>
#include <limits>

#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <leveldb/env.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#include <memenv/memenv.h>

#include "kernel.h"
#include "checkpoints.h"
#include "txdb.h"
#include "util.h"
#include "main.h"

using namespace std;
namespace fs = boost::filesystem;

leveldb::DB *txdb; // global pointer for LevelDB object instance

static CCriticalSection cs_txdb;
// LevelDB does not own Options::block_cache or filter_policy. Keep their
// lifetime with the shared DB rather than with whichever cheap CTxDB wrapper
// happened to open it, so a later wrapper can release them during Close().
static leveldb::Cache* txdbBlockCache = NULL;
static const leveldb::FilterPolicy* txdbFilterPolicy = NULL;

static void ReleaseLevelDBSharedResources()
{
    // DB uses the cache/filter during its destructor, so release it first.
    delete txdb;
    txdb = NULL;
    delete txdbFilterPolicy;
    txdbFilterPolicy = NULL;
    delete txdbBlockCache;
    txdbBlockCache = NULL;
}

namespace
{
// Every consensus-valid transaction is larger than one uint256 on disk, so a
// block cannot contain more hashes than this without exceeding the adaptive
// hard ceiling.  The bound is intentionally checked before allocating.
static const uint64_t DAG_ACTIVE_SET_MAX_TXS =
    (uint64_t)ADAPTIVE_BLOCK_CEILING / 32 + 1;
// A minimally encoded transparent output is nine bytes.  This bounds the
// CTxIndex spent-position vector for every transaction admitted by an adaptive
// block while retaining all historical records.
static const uint64_t TXINDEX_MAX_OUTPUTS =
    (uint64_t)ADAPTIVE_BLOCK_CEILING / 9 + 1;

uint256 ComputeDAGSkippedTxDigest(
    const uint256& hashBlock, const uint256& hashMerkleRoot,
    uint32_t nBlockTxCount, const std::vector<uint256>& vSkipped)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/IDAG/ActiveSet/v1");
    ss << hashBlock << hashMerkleRoot << nBlockTxCount;
    ss << (uint64_t)vSkipped.size();
    for (std::vector<uint256>::const_iterator it = vSkipped.begin();
         it != vSkipped.end(); ++it)
        ss << *it;
    return ss.GetHash();
}

class CDAGSkippedTxDiskRecord
{
public:
    int nSchema;
    uint32_t nBlockTxCount;
    uint256 hashMerkleRoot;
    std::vector<uint256> vSkipped;
    uint256 hashDigest;

    CDAGSkippedTxDiskRecord()
        : nSchema(0), nBlockTxCount(0) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSchema);
        READWRITE(nBlockTxCount);
        READWRITE(hashMerkleRoot);
        READWRITE(vSkipped);
        READWRITE(hashDigest);
    )
};

class CDAGActiveSetBestRecord
{
public:
    int nSchema;
    uint256 hashBest;
    uint256 hashDigest;

    CDAGActiveSetBestRecord() : nSchema(0) {}

    uint256 GetDigest() const
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("Innova/IDAG/ActiveSetBest/v1");
        ss << nSchema << hashBest;
        return ss.GetHash();
    }

    bool IsValid() const
    {
        return nSchema == DAG_ACTIVE_SET_SCHEMA && hashBest != 0 &&
               hashDigest == GetDigest();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSchema);
        READWRITE(hashBest);
        READWRITE(hashDigest);
    )
};

TxDBReadStatus ParseDAGSkippedTxValue(
    const char* pData, size_t nDataSize, const uint256& hashBlock,
    const uint256& hashExpectedMerkleRoot, uint32_t& nBlockTxCount,
    std::set<uint256>* pSkipped, std::string& strError)
{
    if (pSkipped)
        pSkipped->clear();
    strError.clear();

    // schema + tx count + merkle root + one-byte empty vector + digest
    static const size_t MIN_RECORD_SIZE = 4 + 4 + 32 + 1 + 32;
    if (!pData || nDataSize < MIN_RECORD_SIZE ||
        nDataSize > 4 + 4 + 32 + 9 +
                        (size_t)DAG_ACTIVE_SET_MAX_TXS * 32 + 32)
    {
        strError = "DAG active-set record has an invalid bounded size";
        return TXDB_READ_ERROR;
    }

    try
    {
        CDataStream ssValue(pData, pData + nDataSize,
                            SER_DISK, CLIENT_VERSION);
        int nSchema = 0;
        uint256 hashMerkleRoot;
        ssValue >> nSchema;
        ssValue >> nBlockTxCount;
        ssValue >> hashMerkleRoot;
        const uint64_t nSkipped = ReadCompactSize(ssValue);
        if (nSchema != DAG_ACTIVE_SET_SCHEMA ||
            nBlockTxCount > DAG_ACTIVE_SET_MAX_TXS ||
            nSkipped > nBlockTxCount ||
            nSkipped > DAG_ACTIVE_SET_MAX_TXS ||
            nSkipped > (uint64_t)ssValue.size() / 32 ||
            ssValue.size() != (size_t)nSkipped * 32 + 32)
            throw std::ios_base::failure("invalid/truncated DAG active-set fields");
        if (hashExpectedMerkleRoot != 0 &&
            hashMerkleRoot != hashExpectedMerkleRoot)
            throw std::ios_base::failure("DAG active-set merkle-root mismatch");

        std::vector<uint256> vSkipped;
        if (pSkipped)
            vSkipped.reserve((size_t)nSkipped);

        CHashWriter digestWriter(SER_GETHASH, 0);
        digestWriter << std::string("Innova/IDAG/ActiveSet/v1");
        digestWriter << hashBlock << hashMerkleRoot << nBlockTxCount;
        digestWriter << nSkipped;
        uint256 hashPrevious;
        bool fHavePrevious = false;
        for (uint64_t i = 0; i < nSkipped; ++i)
        {
            uint256 hashTx;
            ssValue >> hashTx;
            if (hashTx == 0 || (fHavePrevious && !(hashPrevious < hashTx)))
                throw std::ios_base::failure("non-canonical DAG active-set ordering");
            digestWriter << hashTx;
            if (pSkipped)
                vSkipped.push_back(hashTx);
            hashPrevious = hashTx;
            fHavePrevious = true;
        }
        uint256 hashStoredDigest;
        ssValue >> hashStoredDigest;
        if (!ssValue.empty() || hashStoredDigest != digestWriter.GetHash())
            throw std::ios_base::failure("DAG active-set digest/trailing-byte mismatch");
        if (pSkipped)
            pSkipped->insert(vSkipped.begin(), vSkipped.end());
        return TXDB_READ_FOUND;
    }
    catch (const std::exception& e)
    {
        if (pSkipped)
            pSkipped->clear();
        strError = e.what();
        return TXDB_READ_ERROR;
    }
}

TxDBReadStatus ParseTxIndexValue(const char* pData, size_t nDataSize,
                                 CTxIndex& txindex)
{
    txindex.SetNull();
    const size_t nPosSize = ::GetSerializeSize(
        CDiskTxPos(), SER_DISK, CLIENT_VERSION);
    const size_t nMaxSize = 4 + nPosSize + 9 +
                            (size_t)TXINDEX_MAX_OUTPUTS * nPosSize;
    if (!pData || nDataSize < 4 + nPosSize + 1 || nDataSize > nMaxSize)
        return TXDB_READ_ERROR;
    try
    {
        CDataStream ssValue(pData, pData + nDataSize,
                            SER_DISK, CLIENT_VERSION);
        int nDiskVersion = 0;
        ssValue >> nDiskVersion;
        ssValue >> txindex.pos;
        const uint64_t nSpent = ReadCompactSize(ssValue);
        if (nSpent > TXINDEX_MAX_OUTPUTS ||
            nSpent > (uint64_t)ssValue.size() / nPosSize ||
            ssValue.size() != (size_t)nSpent * nPosSize)
            throw std::ios_base::failure("invalid/truncated transaction-index spent vector");
        txindex.vSpent.reserve((size_t)nSpent);
        for (uint64_t i = 0; i < nSpent; ++i)
        {
            CDiskTxPos spent;
            ssValue >> spent;
            txindex.vSpent.push_back(spent);
        }
        if (!ssValue.empty())
            throw std::ios_base::failure("trailing transaction-index bytes");
        return TXDB_READ_FOUND;
    }
    catch (const std::exception&)
    {
        txindex.SetNull();
        return TXDB_READ_ERROR;
    }
}
} // namespace

static int nIBDBatchSize = 0;
static int nIBDBatchCount = 0;
static bool fIBDBatchPending = false;
static CCriticalSection cs_IBDBatch;

void InitIBDBatching()
{
    nIBDBatchSize = GetArg("-ibdbatchsize", 50);
    if (nIBDBatchSize < 0) nIBDBatchSize = 0;
    if (nIBDBatchSize > 1000) nIBDBatchSize = 1000;
    if (nIBDBatchSize > 0)
        printf("IBD batching enabled: committing every %d blocks\n", nIBDBatchSize);
}

void FlushIBDBatch()
{
    LOCK(cs_IBDBatch);
    if (fIBDBatchPending && txdb)
    {
        printf("Flushing pending IBD batch (%d blocks)...\n", nIBDBatchCount);
        CTxDB txdbFlush;
        txdbFlush.TxnBegin();
        txdbFlush.TxnCommit();
        fIBDBatchPending = false;
        nIBDBatchCount = 0;
    }
}

static leveldb::Options GetOptions() {
    leveldb::Options options;
    int nCacheSizeMB = GetArg("-dbcache", 300);
    if (txdbBlockCache || txdbFilterPolicy)
        ReleaseLevelDBSharedResources();
    try
    {
        txdbBlockCache = leveldb::NewLRUCache(
            nCacheSizeMB * 1048576);
        txdbFilterPolicy = leveldb::NewBloomFilterPolicy(10);
    }
    catch (...)
    {
        ReleaseLevelDBSharedResources();
        throw;
    }
    options.block_cache = txdbBlockCache;
    options.filter_policy = txdbFilterPolicy;
    options.write_buffer_size = 64 * 1048576; // 64MB write buffer (default 4MB) for smoother IBD
    options.max_open_files = 1000;
    options.compression = leveldb::kSnappyCompression;
    return options;
}

void init_blockindex(leveldb::Options& options, bool fRemoveOld = false) {
    // First time init.
    fs::path directory = GetDataDir() / "txleveldb";

    if (fRemoveOld) {
        fs::remove_all(directory);
        unsigned int nFile = 1;

        while (true)
        {
            fs::path strBlockFile = GetDataDir() / strprintf("blk%04u.dat", nFile);

            // Break if no such file
            if( !fs::exists( strBlockFile ) )
                break;

            fs::remove(strBlockFile);

            nFile++;
        }
    }

    fs::create_directory(directory);
    printf("Opening LevelDB in %s\n", directory.string().c_str());
    leveldb::Status status = leveldb::DB::Open(options, directory.string(), &txdb);
    if (!status.ok()) {
        throw runtime_error(strprintf("init_blockindex(): error opening database environment %s", status.ToString().c_str()));
    }
}

// CDB subclasses are created and destroyed VERY OFTEN. That's why
// we shouldn't treat this as a free operations.
CTxDB::CTxDB(const char* pszMode)
{
    assert(pszMode);
    activeBatch = NULL;
    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));

    LOCK(cs_txdb);

    if (txdb) {
        pdb = txdb;
        return;
    }

    bool fCreate = strchr(pszMode, 'c');

    options = GetOptions();
    options.create_if_missing = true; //fCreate

    try
    {
        init_blockindex(options); // Init directory
    }
    catch (...)
    {
        ReleaseLevelDBSharedResources();
        options.filter_policy = NULL;
        options.block_cache = NULL;
        throw;
    }
    pdb = txdb;

    if (Exists(string("version")))
    {
        ReadVersion(nVersion);
        printf("Transaction index version is %d\n", nVersion);

        if (nVersion < DATABASE_VERSION)
        {
            printf("CTxDB() : database version %d is older than expected %d, creating backup\n",
                   nVersion, DATABASE_VERSION);
            bool fBackupOk = false;
            try {
                boost::filesystem::path backupPath = GetDataDir() / "txleveldb_backup";
                if (boost::filesystem::exists(backupPath))
                    boost::filesystem::remove_all(backupPath);
                boost::filesystem::rename(GetDataDir() / "txleveldb", backupPath);
                printf("CTxDB() : backed up old database to %s\n", backupPath.filename().string().c_str());
                fBackupOk = true;
            } catch (const boost::filesystem::filesystem_error& e) {
                printf("CTxDB() : CRITICAL - failed to backup database: %s\n", e.what());
                printf("CTxDB() : Database reset aborted. Please manually backup txleveldb and restart.\n");
            }

            if (!fBackupOk)
            {
                printf("CTxDB() : Continuing with old database version %d\n", nVersion);
            }
            else
            {

            printf("Required index version is %d, removing old database\n", DATABASE_VERSION);

            // Leveldb instance destruction
            delete txdb;
            txdb = pdb = NULL;
            delete activeBatch;
            activeBatch = NULL;

            try
            {
                init_blockindex(options, true); // Remove directory and create new database
            }
            catch (...)
            {
                ReleaseLevelDBSharedResources();
                options.filter_policy = NULL;
                options.block_cache = NULL;
                throw;
            }
            pdb = txdb;

            bool fTmp = fReadOnly;
            fReadOnly = false;
            WriteVersion(DATABASE_VERSION); // Save transaction index version
            fReadOnly = fTmp;
            } // end fBackupOk else block
        }
    }
    else if (fCreate)
    {
        bool fTmp = fReadOnly;
        fReadOnly = false;
        WriteVersion(DATABASE_VERSION);
        fReadOnly = fTmp;
    }

    printf("Opened LevelDB successfully\n");
}

void CTxDB::Close()
{
    LOCK(cs_txdb);
    ReleaseLevelDBSharedResources();
    pdb = NULL;
    options.filter_policy = NULL;
    options.block_cache = NULL;
    delete activeBatch;
    activeBatch = NULL;
}

bool CTxDB::TxnBegin()
{
    if (activeBatch)
        return false;
    activeBatch = new leveldb::WriteBatch();
    return true;
}

bool CTxDB::TxnCommit(bool fSync)
{
    if (!activeBatch)
        return false;

    leveldb::WriteOptions writeOptions;
    writeOptions.sync = fSync;
    if (!fSync && IsInitialBlockDownload() && nIBDBatchSize > 0)
    {
        LOCK(cs_IBDBatch);
        fIBDBatchPending = true;
        nIBDBatchCount++;
    }

    leveldb::Status status = pdb->Write(writeOptions, activeBatch);
    delete activeBatch;
    activeBatch = NULL;
    if (!status.ok()) {
        printf("LevelDB batch commit failure: %s\n", status.ToString().c_str());
        return false;
    }
    return true;
}

bool CTxDB::WriteKeyImage(const ec_point& keyImage,
                          const CKeyImageSpent& keyImageSpent)
{
    return Write(make_pair(string("ki"), keyImage), keyImageSpent);
};

bool CTxDB::ReadKeyImage(ec_point& keyImage, CKeyImageSpent& keyImageSpent)
{
    return Read(make_pair(string("ki"), keyImage), keyImageSpent);
};

TxDBReadStatus CTxDB::ReadKeyImageStatus(
    const ec_point& keyImage, CKeyImageSpent& keyImageSpent)
{
    return ReadExactStatus(make_pair(string("ki"), keyImage), keyImageSpent);
}

bool CTxDB::EraseKeyImage(const ec_point& keyImage)
{
    return Erase(make_pair(string("ki"), keyImage));
}

bool CTxDB::WriteAnonOutput(const CPubKey& pkCoin, const CAnonOutput& ao)
{
    return Write(make_pair(string("ao"), pkCoin), ao);
};

bool CTxDB::ReadAnonOutput(CPubKey& pkCoin, CAnonOutput& ao)
{
    return Read(make_pair(string("ao"), pkCoin), ao);
};

TxDBReadStatus CTxDB::ReadAnonOutputStatus(const CPubKey& pkCoin,
                                           CAnonOutput& ao)
{
    return ReadExactStatus(make_pair(string("ao"), pkCoin), ao);
}

bool CTxDB::EraseAnonOutput(const CPubKey& pkCoin)
{
    return Erase(make_pair(string("ao"), pkCoin));
}

bool CTxDB::WriteShieldedNullifier(const uint256& nullifier, const CShieldedNullifierSpent& nfs)
{
    return Write(make_pair(string("sn"), nullifier), nfs);
}

bool CTxDB::ReadShieldedNullifier(const uint256& nullifier, CShieldedNullifierSpent& nfs)
{
    return Read(make_pair(string("sn"), nullifier), nfs);
}

TxDBReadStatus CTxDB::ReadShieldedNullifierStatus(
    const uint256& nullifier, CShieldedNullifierSpent& nfs)
{
    const TxDBReadStatus status = ReadExactStatus(
        make_pair(string("sn"), nullifier), nfs);
    if (status == TXDB_READ_FOUND && nfs.txnHash == 0)
        return TXDB_READ_ERROR;
    return status;
}

bool CTxDB::EraseShieldedNullifier(const uint256& nullifier)
{
    return Erase(make_pair(string("sn"), nullifier));
}

bool CTxDB::WritePrivacyVNextNullifier(
    const uint256& keyImage, const CShieldedNullifierSpent& spent)
{
    return Write(make_pair(string("iv5nf"), keyImage), spent);
}

TxDBReadStatus CTxDB::ReadPrivacyVNextNullifierStatus(
    const uint256& keyImage, CShieldedNullifierSpent& spent)
{
    const TxDBReadStatus status = ReadExactStatus(
        make_pair(string("iv5nf"), keyImage), spent);
    if (status == TXDB_READ_FOUND && spent.txnHash == 0)
        return TXDB_READ_ERROR;
    return status;
}

bool CTxDB::ErasePrivacyVNextNullifier(const uint256& keyImage)
{
    return Erase(make_pair(string("iv5nf"), keyImage));
}

bool CTxDB::CountPrivacyVNextNullifiers(
    uint64_t& nCount, std::string& strError)
{
    nCount = 0;
    strError.clear();
    if (activeBatch)
    {
        strError = "cannot audit the IV5 spent-key index inside an active batch";
        return false;
    }

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("iv5nf");
    const std::string strPrefix = ssPrefix.str();
    leveldb::Iterator* it = pdb->NewIterator(leveldb::ReadOptions());
    it->Seek(strPrefix);
    while (it->Valid())
    {
        const std::string strKey = it->key().ToString();
        if (strKey.compare(0, strPrefix.size(), strPrefix) != 0)
            break;
        try
        {
            CDataStream ssKey(strKey.data(), strKey.data() + strKey.size(),
                              SER_DISK, CLIENT_VERSION);
            std::pair<std::string, uint256> key;
            ssKey >> key;
            if (key.first != "iv5nf" || ssKey.size() != 0 || key.second == 0)
                throw std::ios_base::failure("non-canonical IV5 spent-key record key");

            const leveldb::Slice value = it->value();
            CDataStream ssValue(value.data(), value.data() + value.size(),
                                SER_DISK, CLIENT_VERSION);
            CShieldedNullifierSpent spent;
            ssValue >> spent;
            if (ssValue.size() != 0 || spent.txnHash == 0)
                throw std::ios_base::failure("non-canonical IV5 spent-key record value");
            if (nCount == std::numeric_limits<uint64_t>::max())
                throw std::ios_base::failure("IV5 spent-key record count overflow");
            ++nCount;
        }
        catch (const std::exception& e)
        {
            strError = strprintf("invalid IV5 spent-key index record: %s",
                                 e.what());
            delete it;
            return false;
        }
        it->Next();
    }

    const leveldb::Status status = it->status();
    delete it;
    if (!status.ok())
    {
        strError = "IV5 spent-key iterator failure: " + status.ToString();
        return false;
    }
    return true;
}

bool CTxDB::WriteShieldedAnchor(const uint256& anchor)
{
    return Write(make_pair(string("sa"), anchor), true);
}

bool CTxDB::ReadShieldedAnchor(const uint256& anchor)
{
    bool fValid = false;
    if (!Read(make_pair(string("sa"), anchor), fValid))
        return false;
    return fValid;
}

TxDBReadStatus CTxDB::ReadShieldedAnchorStatus(const uint256& anchor)
{
    bool fValid = false;
    const TxDBReadStatus status = ReadExactStatus(
        make_pair(string("sa"), anchor), fValid);
    if (status == TXDB_READ_FOUND && !fValid)
        return TXDB_READ_ERROR;
    return status;
}

bool CTxDB::EraseShieldedAnchor(const uint256& anchor)
{
    return Erase(make_pair(string("sa"), anchor));
}

bool CTxDB::WriteShieldedAnchorHeight(const uint256& anchor, int nHeight)
{
    return Write(make_pair(string("sah"), anchor), nHeight);
}

bool CTxDB::ReadShieldedAnchorHeight(const uint256& anchor, int& nHeight)
{
    return Read(make_pair(string("sah"), anchor), nHeight);
}

TxDBReadStatus CTxDB::ReadShieldedAnchorHeightStatus(
    const uint256& anchor,
    int& nHeight)
{
    return ReadExactStatus(make_pair(string("sah"), anchor), nHeight);
}

bool CTxDB::HasShieldedAnchorHeight(const uint256& anchor)
{
    return Exists(make_pair(string("sah"), anchor));
}

bool CTxDB::EraseShieldedAnchorHeight(const uint256& anchor)
{
    return Erase(make_pair(string("sah"), anchor));
}

bool CTxDB::WriteShieldedTree(const CIncrementalMerkleTree& tree)
{
    if (!tree.IsValidStructure())
        return false;
    return Write(string("st"), tree);
}

bool CTxDB::ReadShieldedTree(CIncrementalMerkleTree& tree)
{
    return ReadExact(string("st"), tree) && tree.IsValidStructure();
}

bool CTxDB::WriteShieldedTreeAtBlock(const uint256& blockHash, const CIncrementalMerkleTree& tree)
{
    if (!tree.IsValidStructure())
        return false;
    return Write(make_pair(string("sb"), blockHash), tree);
}

bool CTxDB::ReadShieldedTreeAtBlock(const uint256& blockHash, CIncrementalMerkleTree& tree)
{
    return ReadExact(make_pair(string("sb"), blockHash), tree) &&
           tree.IsValidStructure();
}

bool CTxDB::EraseShieldedTreeAtBlock(const uint256& blockHash)
{
    return Erase(make_pair(string("sb"), blockHash));
}

bool CTxDB::WriteShieldedPoolValue(int64_t nValue)
{
    return Write(string("sv"), nValue);
}

bool CTxDB::ReadShieldedPoolValue(int64_t& nValue)
{
    return Read(string("sv"), nValue);
};

bool CTxDB::WriteShieldedCommitment(uint64_t nIndex, const CPedersenCommitment& commit)
{
    return Write(make_pair(string("sc"), nIndex), commit);
}

bool CTxDB::ReadShieldedCommitment(uint64_t nIndex, CPedersenCommitment& commit)
{
    return Read(make_pair(string("sc"), nIndex), commit);
}

bool CTxDB::EraseShieldedCommitment(uint64_t nIndex)
{
    return Erase(make_pair(string("sc"), nIndex));
}

bool CTxDB::WriteShieldedCommitmentCount(uint64_t nCount)
{
    return Write(string("scc"), nCount);
}

bool CTxDB::ReadShieldedCommitmentCount(uint64_t& nCount)
{
    return Read(string("scc"), nCount);
}

bool CTxDB::EraseShieldedCommitmentCount()
{
    return Erase(string("scc"));
}

bool CTxDB::WriteShieldedCommitmentHeight(uint64_t nIndex, int nHeight)
{
    return Write(make_pair(string("sch"), nIndex), nHeight);
}

bool CTxDB::ReadShieldedCommitmentHeight(uint64_t nIndex, int& nHeight)
{
    return Read(make_pair(string("sch"), nIndex), nHeight);
}

bool CTxDB::HasShieldedCommitmentHeight(uint64_t nIndex)
{
    return Exists(make_pair(string("sch"), nIndex));
}

bool CTxDB::WriteShieldedCommitmentIndex(const std::vector<unsigned char>& vchCommitment, uint64_t nIndex)
{
    return Write(make_pair(string("sci"), vchCommitment), nIndex);
}

bool CTxDB::ReadShieldedCommitmentIndex(const std::vector<unsigned char>& vchCommitment, uint64_t& nIndex)
{
    return Read(make_pair(string("sci"), vchCommitment), nIndex);
}

bool CTxDB::HasShieldedCommitmentIndex(const std::vector<unsigned char>& vchCommitment)
{
    return Exists(make_pair(string("sci"), vchCommitment));
}

namespace
{

static const uint64_t SHIELDED_COMMITMENT_INDEX_NONE =
    std::numeric_limits<uint64_t>::max();
static const int SHIELDED_COMMITMENT_INDEX_SCHEMA_V3 = 3;

class CShieldedCommitmentIndexV3Marker
{
public:
    int nSchema;
    uint256 hashGeneration;

    CShieldedCommitmentIndexV3Marker()
        : nSchema(0), hashGeneration(0) {}

    CShieldedCommitmentIndexV3Marker(int nSchemaIn,
                                     const uint256& hashGenerationIn)
        : nSchema(nSchemaIn), hashGeneration(hashGenerationIn) {}

    bool IsValid() const
    {
        return nSchema == SHIELDED_COMMITMENT_INDEX_SCHEMA_V3 &&
               hashGeneration != 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSchema);
        READWRITE(hashGeneration);
    )
};

typedef std::pair<std::string, uint256> CShieldedIndexGenerationKey;

static std::pair<CShieldedIndexGenerationKey, std::vector<unsigned char> >
ShieldedCommitmentIndexV3Key(
    const uint256& hashGeneration,
    const std::vector<unsigned char>& vchCommitment)
{
    return std::make_pair(
        std::make_pair(std::string("sci3"), hashGeneration),
        vchCommitment);
}

static std::pair<CShieldedIndexGenerationKey, uint64_t>
ShieldedCommitmentPreviousV3Key(const uint256& hashGeneration,
                                uint64_t nIndex)
{
    return std::make_pair(
        std::make_pair(std::string("scp3"), hashGeneration), nIndex);
}

} // namespace

bool CTxDB::EraseSerializedStringKeyPrefix(const std::string& strPrefix,
                                           std::string& strError)
{
    if (!activeBatch)
    {
        strError = "shielded index prefix reset requires an active DB transaction";
        return false;
    }

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << strPrefix;
    const std::string encodedPrefix = ssPrefix.str();
    leveldb::Iterator* it = pdb->NewIterator(leveldb::ReadOptions());
    for (it->Seek(encodedPrefix); it->Valid(); it->Next())
    {
        const std::string key = it->key().ToString();
        if (key.size() < encodedPrefix.size() ||
            key.compare(0, encodedPrefix.size(), encodedPrefix) != 0)
            break;
        activeBatch->Delete(key);
    }
    const leveldb::Status status = it->status();
    delete it;
    if (!status.ok())
    {
        strError = strprintf("LevelDB iterator failed while clearing %s: %s",
                             strPrefix.c_str(),
                             status.ToString().c_str());
        return false;
    }
    return true;
}

bool CTxDB::ReadShieldedCommitmentIndexV3(
    const std::vector<unsigned char>& vchCommitment,
    uint64_t& nIndex)
{
    CShieldedCommitmentIndexV3Marker marker;
    if (!ReadExact(string("siv3"), marker) || !marker.IsValid())
        return false;
    return ReadExact(ShieldedCommitmentIndexV3Key(
                         marker.hashGeneration, vchCommitment),
                     nIndex);
}

bool CTxDB::HasShieldedCommitmentIndexV3Schema()
{
    CShieldedCommitmentIndexV3Marker marker;
    return ReadExact(string("siv3"), marker) && marker.IsValid();
}

bool CTxDB::ResolveShieldedCommitmentIndexV3Mode(
    int nCandidateHeight,
    int nActivationHeight,
    bool& fUseV3,
    std::string& strError)
{
    fUseV3 = false;
    strError.clear();

    CShieldedCommitmentIndexV3Marker marker;
    const TxDBReadStatus markerStatus =
        ReadExactStatus(string("siv3"), marker);
    if (markerStatus == TXDB_READ_ERROR ||
        (markerStatus == TXDB_READ_FOUND && !marker.IsValid()))
    {
        strError = "shielded V3 reverse-index marker is corrupt";
        return false;
    }

    const bool fHaveValidMarker = markerStatus == TXDB_READ_FOUND;
    fUseV3 = nCandidateHeight >= nActivationHeight || fHaveValidMarker;
    if (fUseV3 && !fHaveValidMarker)
    {
        strError = "shielded V3 reverse-index marker is missing at or after activation";
        return false;
    }
    return true;
}

bool CTxDB::ClearShieldedCommitmentIndexV3(std::string& strError)
{
    strError.clear();
    if (!EraseSerializedStringKeyPrefix("sci3", strError) ||
        !EraseSerializedStringKeyPrefix("scp3", strError) ||
        !Erase(string("siv3")))
    {
        if (strError.empty())
            strError = "failed to clear shielded V3 reverse-index marker";
        return false;
    }
    return true;
}

bool CTxDB::InitializeShieldedCommitmentIndexV3(
    const uint256& hashGeneration,
    std::string& strError)
{
    strError.clear();
    if (hashGeneration == 0)
    {
        strError = "shielded V3 reverse-index generation is zero";
        return false;
    }

    CShieldedCommitmentIndexV3Marker existingMarker;
    const TxDBReadStatus markerStatus =
        ReadExactStatus(string("siv3"), existingMarker);
    if (markerStatus == TXDB_READ_ERROR ||
        (markerStatus == TXDB_READ_FOUND && !existingMarker.IsValid()))
    {
        strError = "existing shielded V3 reverse-index marker is corrupt";
        return false;
    }

    CIncrementalMerkleTree tree;
    uint64_t nCount = 0;
    if (!ReadShieldedTree(tree))
    {
        strError = "shielded Merkle tree missing, malformed, or unreadable";
        return false;
    }
    if (!ReadExact(string("scc"), nCount))
    {
        strError = "shielded commitment count missing or unreadable";
        return false;
    }
    if (nCount != tree.Size())
    {
        strError = strprintf("shielded tree/count mismatch (%" PRIu64
                             " != %" PRIu64 ")", tree.Size(), nCount);
        return false;
    }

    // O(active shielded leaves) at the one-time V3 activation or a reorg across it. Prefix
    // clearing plus full rebuild drops abandoned-branch heads and repairs legacy `sci` atomically.
    if (!EraseSerializedStringKeyPrefix("sci3", strError) ||
        !EraseSerializedStringKeyPrefix("scp3", strError) ||
        !EraseSerializedStringKeyPrefix("sci", strError))
        return false;

    std::map<std::vector<unsigned char>, uint64_t> mapLatest;
    for (uint64_t i = 0; i < nCount; ++i)
    {
        CPedersenCommitment commitment;
        if (!ReadExact(make_pair(string("sc"), i), commitment) ||
            commitment.vchCommitment.size() != PEDERSEN_COMMITMENT_SIZE)
        {
            strError = strprintf("shielded commitment %" PRIu64
                                 " missing, malformed, or unreadable", i);
            return false;
        }

        const std::map<std::vector<unsigned char>, uint64_t>::const_iterator
            previous = mapLatest.find(commitment.vchCommitment);
        const uint64_t nPrevious =
            previous == mapLatest.end() ? SHIELDED_COMMITMENT_INDEX_NONE
                                        : previous->second;

        if (!Write(ShieldedCommitmentPreviousV3Key(hashGeneration, i),
                   nPrevious) ||
            !Write(ShieldedCommitmentIndexV3Key(
                       hashGeneration, commitment.vchCommitment), i) ||
            !WriteShieldedCommitmentIndex(commitment.vchCommitment, i))
        {
            strError = strprintf("failed to stage shielded V3 index leaf %" PRIu64,
                                 i);
            return false;
        }
        mapLatest[commitment.vchCommitment] = i;
    }

    const CShieldedCommitmentIndexV3Marker marker(
        SHIELDED_COMMITMENT_INDEX_SCHEMA_V3, hashGeneration);
    if (!Write(string("siv3"), marker))
    {
        strError = "failed to stage shielded V3 reverse-index schema marker";
        return false;
    }
    return true;
}

bool CTxDB::ValidateShieldedCommitmentIndexV3(std::string& strError)
{
    strError.clear();
    CShieldedCommitmentIndexV3Marker marker;
    if (!ReadExact(string("siv3"), marker) || !marker.IsValid())
    {
        strError = "shielded V3 reverse-index schema marker missing or invalid";
        return false;
    }

    CIncrementalMerkleTree tree;
    uint64_t nCount = 0;
    if (!ReadShieldedTree(tree) || !ReadExact(string("scc"), nCount))
    {
        strError = "shielded tree/count missing, malformed, or unreadable";
        return false;
    }
    if (nCount != tree.Size())
    {
        strError = strprintf("shielded tree/count mismatch (%" PRIu64
                             " != %" PRIu64 ")", tree.Size(), nCount);
        return false;
    }

    std::map<std::vector<unsigned char>, uint64_t> mapLatest;
    for (uint64_t i = 0; i < nCount; ++i)
    {
        CPedersenCommitment commitment;
        if (!ReadExact(make_pair(string("sc"), i), commitment) ||
            commitment.vchCommitment.size() != PEDERSEN_COMMITMENT_SIZE)
        {
            strError = strprintf("shielded commitment %" PRIu64
                                 " missing, malformed, or unreadable", i);
            return false;
        }

        const std::map<std::vector<unsigned char>, uint64_t>::const_iterator
            previous = mapLatest.find(commitment.vchCommitment);
        const uint64_t nExpectedPrevious =
            previous == mapLatest.end() ? SHIELDED_COMMITMENT_INDEX_NONE
                                        : previous->second;
        uint64_t nStoredPrevious = 0;
        if (!ReadExact(ShieldedCommitmentPreviousV3Key(
                           marker.hashGeneration, i),
                       nStoredPrevious) ||
            nStoredPrevious != nExpectedPrevious)
        {
            strError = strprintf("shielded V3 predecessor mismatch at leaf %" PRIu64,
                                 i);
            return false;
        }
        mapLatest[commitment.vchCommitment] = i;
    }

    for (std::map<std::vector<unsigned char>, uint64_t>::const_iterator it =
             mapLatest.begin(); it != mapLatest.end(); ++it)
    {
        uint64_t nV3Index = 0;
        uint64_t nLegacyIndex = 0;
        if (!ReadExact(ShieldedCommitmentIndexV3Key(
                           marker.hashGeneration, it->first),
                       nV3Index) ||
            nV3Index != it->second ||
            !ReadExact(make_pair(string("sci"), it->first), nLegacyIndex) ||
            nLegacyIndex != it->second)
        {
            strError = "shielded V3 reverse-index head mismatch";
            return false;
        }
    }
    return true;
}

bool CTxDB::PushShieldedCommitmentIndexV3(
    uint64_t nIndex,
    const CPedersenCommitment& commitment,
    std::string& strError)
{
    strError.clear();
    CShieldedCommitmentIndexV3Marker marker;
    if (!ReadExact(string("siv3"), marker) || !marker.IsValid())
    {
        strError = "shielded V3 reverse-index schema marker missing or invalid";
        return false;
    }
    if (commitment.vchCommitment.size() != PEDERSEN_COMMITMENT_SIZE)
    {
        strError = "shielded commitment has invalid encoded size";
        return false;
    }

    CPedersenCommitment stored;
    if (!ReadExact(make_pair(string("sc"), nIndex), stored) ||
        stored.vchCommitment != commitment.vchCommitment)
    {
        strError = "shielded commitment forward value missing or mismatched";
        return false;
    }

    uint64_t nPrevious = SHIELDED_COMMITMENT_INDEX_NONE;
    uint64_t nCandidate = 0;
    const TxDBReadStatus status = ReadExactStatus(
        ShieldedCommitmentIndexV3Key(marker.hashGeneration,
                                     commitment.vchCommitment),
        nCandidate);
    if (status == TXDB_READ_ERROR)
    {
        strError = "shielded V3 reverse-index head is malformed or unreadable";
        return false;
    }
    if (status == TXDB_READ_FOUND && nCandidate < nIndex)
    {
        CPedersenCommitment candidate;
        if (ReadExact(make_pair(string("sc"), nCandidate), candidate) &&
            candidate.vchCommitment == commitment.vchCommitment)
            nPrevious = nCandidate;
    }

    if (!Write(ShieldedCommitmentPreviousV3Key(marker.hashGeneration,
                                               nIndex),
               nPrevious) ||
        !Write(ShieldedCommitmentIndexV3Key(
                   marker.hashGeneration, commitment.vchCommitment),
               nIndex) ||
        !WriteShieldedCommitmentIndex(commitment.vchCommitment, nIndex))
    {
        strError = "failed to stage shielded V3 reverse-index push";
        return false;
    }
    return true;
}

bool CTxDB::PopShieldedCommitmentIndexV3(
    uint64_t nIndex,
    const CPedersenCommitment& commitment,
    std::string& strError)
{
    strError.clear();
    CShieldedCommitmentIndexV3Marker marker;
    if (!ReadExact(string("siv3"), marker) || !marker.IsValid())
    {
        strError = "shielded V3 reverse-index schema marker missing or invalid";
        return false;
    }
    if (commitment.vchCommitment.size() != PEDERSEN_COMMITMENT_SIZE)
    {
        strError = "shielded commitment has invalid encoded size";
        return false;
    }

    uint64_t nHead = 0;
    uint64_t nPrevious = 0;
    if (!ReadExact(ShieldedCommitmentIndexV3Key(
                       marker.hashGeneration, commitment.vchCommitment),
                   nHead) ||
        nHead != nIndex ||
        !ReadExact(ShieldedCommitmentPreviousV3Key(
                       marker.hashGeneration, nIndex),
                   nPrevious))
    {
        strError = "shielded V3 reverse-index pop order/state mismatch";
        return false;
    }

    if (nPrevious == SHIELDED_COMMITMENT_INDEX_NONE)
    {
        if (!Erase(ShieldedCommitmentIndexV3Key(
                       marker.hashGeneration, commitment.vchCommitment)) ||
            !EraseShieldedCommitmentIndex(commitment.vchCommitment))
        {
            strError = "failed to erase final shielded V3 reverse-index head";
            return false;
        }
    }
    else
    {
        CPedersenCommitment previous;
        if (nPrevious >= nIndex ||
            !ReadExact(make_pair(string("sc"), nPrevious), previous) ||
            previous.vchCommitment != commitment.vchCommitment)
        {
            strError = "shielded V3 predecessor is invalid or unreadable";
            return false;
        }
        if (!Write(ShieldedCommitmentIndexV3Key(
                       marker.hashGeneration, commitment.vchCommitment),
                   nPrevious) ||
            !WriteShieldedCommitmentIndex(commitment.vchCommitment,
                                           nPrevious))
        {
            strError = "failed to restore shielded V3 reverse-index predecessor";
            return false;
        }
    }

    if (!Erase(ShieldedCommitmentPreviousV3Key(marker.hashGeneration,
                                               nIndex)))
    {
        strError = "failed to erase shielded V3 predecessor journal entry";
        return false;
    }
    return true;
}

bool CTxDB::EraseShieldedCommitmentHeight(uint64_t nIndex)
{
    return Erase(make_pair(string("sch"), nIndex));
}

bool CTxDB::EraseShieldedCommitmentIndex(const std::vector<unsigned char>& vchCommitment)
{
    return Erase(make_pair(string("sci"), vchCommitment));
}

bool CTxDB::ReadAllShieldedCommitments(std::vector<CPedersenCommitment>& vCommitments)
{
    vCommitments.clear();
    uint64_t nCount = 0;
    if (!ReadShieldedCommitmentCount(nCount))
        return false;
    vCommitments.reserve(nCount);
    for (uint64_t i = 0; i < nCount; i++)
    {
        CPedersenCommitment commit;
        if (!ReadShieldedCommitment(i, commit))
        {
            vCommitments.clear();
            return false;
        }
        vCommitments.push_back(commit);
    }
    return true;
}

bool CTxDB::ReadBoundedLelantusCommitments(
    const CPedersenCommitment& realCommit,
    std::vector<CPedersenCommitment>& vCommitments,
    uint64_t& nRealIndex,
    std::string& strError)
{
    vCommitments.clear();
    nRealIndex = 0;
    strError.clear();

    uint64_t nCount = 0;
    if (!ReadShieldedCommitmentCount(nCount))
    {
        strError = "shielded commitment count missing or unreadable";
        return false;
    }
    if (nCount < (uint64_t)LELANTUS_MIN_SET_SIZE)
    {
        strError = strprintf("shielded commitment pool too small (%" PRIu64
                             " < %d)", nCount, LELANTUS_MIN_SET_SIZE);
        return false;
    }
    if (!ReadShieldedCommitmentIndex(realCommit.vchCommitment,
                                     nRealIndex))
    {
        strError = "real shielded commitment reverse index missing or unreadable";
        return false;
    }
    if (nRealIndex >= nCount)
    {
        strError = strprintf("real shielded commitment index %" PRIu64
                             " is outside count %" PRIu64,
                             nRealIndex, nCount);
        return false;
    }

    CPedersenCommitment indexedRealCommitment;
    if (!ReadShieldedCommitment(nRealIndex, indexedRealCommitment))
    {
        strError = "real shielded commitment value missing or unreadable";
        return false;
    }
    if (indexedRealCommitment.vchCommitment != realCommit.vchCommitment)
    {
        strError = "real shielded commitment reverse-index/value mismatch";
        return false;
    }

    const uint64_t nDecoyPopulation = nCount - 1;
    const uint64_t nDecoyCount = std::min<uint64_t>(
        nDecoyPopulation, (uint64_t)LELANTUS_MAX_SET_SIZE - 1);

    // Floyd's algorithm chooses a uniform k-subset without replacement using
    // O(k) memory and random draws. Work over a virtual population that omits
    // nRealIndex, then map virtual indices at/after it up by one.
    std::set<uint64_t> setVirtualIndices;
    try
    {
        for (uint64_t j = nDecoyPopulation - nDecoyCount;
             j < nDecoyPopulation; ++j)
        {
            const uint64_t nCandidate = GetRand(j + 1);
            if (!setVirtualIndices.insert(nCandidate).second)
                setVirtualIndices.insert(j);
        }
    }
    catch (const std::exception& e)
    {
        strError = strprintf("secure Lelantus sampling failed: %s", e.what());
        return false;
    }

    vCommitments.reserve((size_t)nDecoyCount + 1);
    vCommitments.push_back(indexedRealCommitment);
    for (std::set<uint64_t>::const_iterator it = setVirtualIndices.begin();
         it != setVirtualIndices.end(); ++it)
    {
        const uint64_t nIndex = *it >= nRealIndex ? *it + 1 : *it;
        CPedersenCommitment commitment;
        if (!ReadShieldedCommitment(nIndex, commitment))
        {
            vCommitments.clear();
            strError = strprintf("sampled shielded commitment %" PRIu64
                                 " missing or unreadable", nIndex);
            return false;
        }
        vCommitments.push_back(commitment);
    }

    if (vCommitments.size() != (size_t)nDecoyCount + 1 ||
        vCommitments.size() > (size_t)LELANTUS_MAX_SET_SIZE)
    {
        vCommitments.clear();
        strError = "bounded Lelantus sampler produced an invalid sample size";
        return false;
    }
    return true;
}

bool CTxDB::WriteCurveTree(const CCurveTree& tree)
{
    return Write(string("ct"), tree);
}

bool CTxDB::ReadCurveTree(CCurveTree& tree)
{
    return Read(string("ct"), tree);
}

bool CTxDB::WriteCurveTreeAtBlock(const uint256& blockHash, const CCurveTree& tree)
{
    return Write(make_pair(string("cb"), blockHash), tree);
}

bool CTxDB::ReadCurveTreeAtBlock(const uint256& blockHash, CCurveTree& tree)
{
    return Read(make_pair(string("cb"), blockHash), tree);
}

bool CTxDB::WriteCurveTreeAtEpoch(int nEpoch, const CCurveTree& tree)
{
    return Write(make_pair(string("ce"), nEpoch), tree);
}

bool CTxDB::ReadCurveTreeAtEpoch(int nEpoch, CCurveTree& tree)
{
    return Read(make_pair(string("ce"), nEpoch), tree);
}

bool CTxDB::EraseCurveTreeAtEpoch(int nEpoch)
{
    return Erase(make_pair(string("ce"), nEpoch));
}

bool CTxDB::EraseCurveTreeAtBlock(const uint256& blockHash)
{
    return Erase(make_pair(string("cb"), blockHash));
}

// DAG link persistence
bool CTxDB::WriteDAGLinks(const uint256& hash, const CBlockDAGData& data)
{
    return Write(make_pair(string("daglinks"), hash), data);
}

bool CTxDB::ReadDAGLinks(const uint256& hash, CBlockDAGData& data)
{
    return Read(make_pair(string("daglinks"), hash), data);
}

bool CTxDB::EraseDAGLinks(const uint256& hash)
{
    return Erase(make_pair(string("daglinks"), hash));
}

// Epoch state persistence
bool CTxDB::WriteEpochState(int nEpoch, const CEpochState& state)
{
    return Write(make_pair(string("epochstate"), nEpoch), state);
}

// Requires the trailing nSerVersion byte and throws on legacy records. No callers; the
// runtime path is IterateEpochStates. Migrate to V2 records before using this.
bool CTxDB::ReadEpochState(int nEpoch, CEpochState& state)
{
    return Read(make_pair(string("epochstate"), nEpoch), state);
}

TxDBReadStatus CTxDB::ProbeEpochState(int nEpoch)
{
    string strValue;
    return ReadRawValueStatus(make_pair(string("epochstate"), nEpoch), strValue);
}

bool CTxDB::EraseEpochState(int nEpoch)
{
    return Erase(make_pair(string("epochstate"), nEpoch));
}

bool CTxDB::WritePrivacyVNextTreeLeaf(uint64_t nIndex,
                                      const std::vector<unsigned char>& vchLeaf)
{
    return Write(make_pair(string("iv5treeleaf"), nIndex), vchLeaf);
}

bool CTxDB::ReadPrivacyVNextTreeLeaf(uint64_t nIndex,
                                     std::vector<unsigned char>& vchLeaf)
{
    return Read(make_pair(string("iv5treeleaf"), nIndex), vchLeaf);
}

bool CTxDB::ErasePrivacyVNextTreeLeaf(uint64_t nIndex)
{
    return Erase(make_pair(string("iv5treeleaf"), nIndex));
}

bool CTxDB::WritePrivacyVNextTreeNode(int nLevel, uint64_t nIndex,
                                      const std::vector<unsigned char>& vchPoint)
{
    return Write(make_pair(string("iv5treenode"), make_pair(nLevel, nIndex)),
                 vchPoint);
}

bool CTxDB::ReadPrivacyVNextTreeNode(int nLevel, uint64_t nIndex,
                                     std::vector<unsigned char>& vchPoint)
{
    return Read(make_pair(string("iv5treenode"), make_pair(nLevel, nIndex)),
                vchPoint);
}

bool CTxDB::ErasePrivacyVNextTreeNode(int nLevel, uint64_t nIndex)
{
    return Erase(make_pair(string("iv5treenode"), make_pair(nLevel, nIndex)));
}

bool CTxDB::WritePrivacyVNextTreeStoreSize(uint64_t nSize)
{
    return Write(string("iv5treestoresize"), nSize);
}

bool CTxDB::ReadPrivacyVNextTreeStoreSize(uint64_t& nSize)
{
    nSize = 0;
    return Read(string("iv5treestoresize"), nSize);
}

bool CTxDB::WritePrivacyVNextPoolValue(int64_t nValue)
{
    return Write(string("iv5pool"), nValue);
}

TxDBReadStatus CTxDB::ReadPrivacyVNextPoolValueStatus(int64_t& nValue)
{
    nValue = 0;
    return ReadExactStatus(string("iv5pool"), nValue);
}

bool CTxDB::IterateEpochStates(std::map<int, CEpochState>& mapOut)
{
    mapOut.clear();
    leveldb::DB* db = GetInstance();
    if (!db)
        return false;

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("epochstate");
    std::string strPrefix = ssPrefix.str();

    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    it->Seek(strPrefix);

    while (it->Valid())
    {
        std::string strKey = it->key().ToString();
        if (strKey.compare(0, strPrefix.size(), strPrefix) != 0)
            break;

        try {
            CDataStream ssKey(strKey.data(), strKey.data() + strKey.size(), SER_DISK, CLIENT_VERSION);
            std::pair<std::string, int> keyPair;
            ssKey >> keyPair;
            if (keyPair.first != "epochstate" || ssKey.size() != 0)
                throw std::ios_base::failure("non-canonical epoch-state key");

            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            CEpochState state;
            // Read the known fields explicitly, in EXACT CEpochState::IMPLEMENT_SERIALIZE order
            // (dag.h) -- do NOT use `ssValue >> state`, because the whole-struct read now requires the
            // trailing nSerVersion byte and would THROW on legacy (pre-byte) records. This mirrors the
            // CBlockDAGData nInferredK tolerant-read pattern in LoadDAGLinks. Keep this list in sync
            // with CEpochState on any future field add, or every epoch silently misparses.
            ssValue >> state.nEpoch;
            ssValue >> state.hashBoundaryBlock;
            ssValue >> state.nHeightStart;
            ssValue >> state.nHeightEnd;
            ssValue >> state.vBlockHashes;
            ssValue >> state.hashCurveRoot;
            ssValue >> state.hashNullifierRoot;
            ssValue >> state.hashVoteSetRoot;
            ssValue >> state.hashFinalityCertificate;
            ssValue >> state.nTotalTrust;
            ssValue >> state.nBlockCount;
            ssValue >> state.nTxCount;
            ssValue >> state.nFinalityTier;
            ssValue >> state.nConsecutiveHardCount;
            ssValue >> state.fFinalized;
            ssValue >> state.nFinalizedHeightAsOf;
            // Trailing version byte: present on V2+ records, absent (implicit 0) on legacy records.
            if (ssValue.size() > 0)
            {
                ssValue >> state.nSerVersion;
            }
            else
                state.nSerVersion = 0;
            if (state.nSerVersion > EPOCHSTATE_SER_VERSION)
                throw std::ios_base::failure("unsupported epoch-state record version");
            if (state.nSerVersion >= EPOCHSTATE_SER_VERSION_V4)
            {
                ssValue >> state.vchVNextTreeState;
                ssValue >> state.vchVNextRoot;
                ssValue >> state.nVNextTreeSize;
                ssValue >> state.vchVNextNullifierState;
                ssValue >> state.hashVNextNullifierRoot;
                ssValue >> state.nVNextNullifierCount;
                ssValue >> state.vVNextEpochNullifiers;
                ssValue >> state.vchVNextParameterDigest;
                ssValue >> state.hashVNextFinalizedAnchor;
                ssValue >> state.nVNextFinalizedHeight;
                ssValue >> state.vVNextActiveBlockTxCounts;
                // Field order must track CEpochState's serializer exactly: this reader
                // decodes by hand, so a field added there and missed here is read as the
                // next field's length.
                if (state.nSerVersion >= EPOCHSTATE_SER_VERSION_V5)
                    ssValue >> state.nVNextPoolBalance;
                ssValue >> state.vVNextActiveTxIds;
                ssValue >> state.hashVNextActiveTxSet;
                if (state.vchVNextTreeState.size() !=
                        EPOCHSTATE_VNEXT_TREE_STATE_SIZE ||
                    state.vchVNextRoot.size() !=
                        EPOCHSTATE_VNEXT_DIGEST_SIZE ||
                    state.vchVNextNullifierState.size() !=
                        EPOCHSTATE_VNEXT_NULLIFIER_STATE_SIZE ||
                    state.vVNextEpochNullifiers.size() >
                        EPOCHSTATE_VNEXT_MAX_NULLIFIERS ||
                    state.vVNextActiveBlockTxCounts.size() >
                        EPOCHSTATE_VNEXT_MAX_ACTIVE_TXS ||
                    state.vVNextActiveTxIds.size() >
                        EPOCHSTATE_VNEXT_MAX_ACTIVE_TXS ||
                    state.vchVNextParameterDigest.size() !=
                        EPOCHSTATE_VNEXT_DIGEST_SIZE)
                    throw std::ios_base::failure("invalid IV5 epoch-state field length");
            }
            if (ssValue.size() != 0)
                throw std::ios_base::failure("trailing epoch-state bytes");
            if (state.nEpoch != keyPair.second)
                throw std::ios_base::failure("epoch-state key/value epoch mismatch");
            if (mapOut.count(keyPair.second))
                throw std::ios_base::failure("duplicate epoch-state key");
            mapOut[keyPair.second] = state;
        }
        catch (const std::exception& e)
        {
            // Fail closed: a dropped epoch-state record reads as not-yet-computed and diverges
            // GetDeterministicFinalizedHeight from the network. Abort the load so the caller
            // refuses to start and forces a -reindex. Legacy pre-V2 records parse above.
            printf("IterateEpochStates: FATAL epoch-state record failed to deserialize "
                   "(rawkeylen=%d): %s -- refusing to load a partial epoch-state set (would diverge "
                   "the deterministic finalized-height anchor); -reindex required\n",
                   (int)strKey.size(), e.what());
            delete it;
            return false;
        }

        it->Next();
    }

    leveldb::Status status = it->status();
    delete it;
    if (!status.ok())
    {
        printf("IterateEpochStates: FATAL LevelDB iterator failure: %s -- -reindex/resync required\n",
               status.ToString().c_str());
        return false;
    }
    return true;
}

bool CTxDB::IterateCurveTreeEpochs(std::map<int, CCurveTree>& mapOut)
{
    mapOut.clear();
    leveldb::DB* db = GetInstance();
    if (!db)
        return false;

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("ce");
    std::string strPrefix = ssPrefix.str();

    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    it->Seek(strPrefix);

    while (it->Valid())
    {
        std::string strKey = it->key().ToString();
        if (strKey.compare(0, strPrefix.size(), strPrefix) != 0)
            break;

        try {
            CDataStream ssKey(strKey.data(), strKey.data() + strKey.size(), SER_DISK, CLIENT_VERSION);
            std::pair<std::string, int> keyPair;
            ssKey >> keyPair;
            if (keyPair.first != "ce" || ssKey.size() != 0)
                throw std::ios_base::failure("non-canonical curve-tree epoch key");

            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            CCurveTree tree;
            ssValue >> tree;
            if (ssValue.size() != 0)
                throw std::ios_base::failure("trailing curve-tree epoch bytes");
            if (mapOut.count(keyPair.second))
                throw std::ios_base::failure("duplicate curve-tree epoch key");
            mapOut[keyPair.second] = tree;
        }
        catch (const std::exception& e)
        {
            printf("IterateCurveTreeEpochs: FATAL curve-tree snapshot failed to deserialize "
                   "(rawkeylen=%d): %s -- refusing to load a partial epoch snapshot set; "
                   "-reindex/resync required\n", (int)strKey.size(), e.what());
            delete it;
            return false;
        }

        it->Next();
    }

    leveldb::Status status = it->status();
    delete it;
    if (!status.ok())
    {
        printf("IterateCurveTreeEpochs: FATAL LevelDB iterator failure: %s -- "
               "-reindex/resync required\n", status.ToString().c_str());
        return false;
    }
    return true;
}

bool CTxDB::WriteDAGCleanHeight(int nHeight)
{
    return Write(string("dagcleanheight"), nHeight);
}

bool CTxDB::ReadDAGCleanHeight(int& nHeight)
{
    return Read(string("dagcleanheight"), nHeight);
}

// DB-wide epoch-state schema marker (see EPOCHSTATE_SCHEMA_V2 in dag.h). Absent -> nVersion left 0,
// which classifies the DB as pre-deterministic-anchor (needs the upgrade guard in AppInit2).
bool CTxDB::WriteEpochStateSchema(int nVersion)
{
    return Write(string("epochstateschema"), nVersion);
}

bool CTxDB::ReadEpochStateSchema(int& nVersion)
{
    nVersion = 0;
    return Read(string("epochstateschema"), nVersion);
}

bool CTxDB::HasEpochStateSchema()
{
    return Exists(string("epochstateschema"));
}

namespace
{
static const uint32_t FINALITY_DISK_ENVELOPE_MAGIC = 0x31444649; // "IFD1"
static const unsigned char FINALITY_DISK_ENCODING_LEGACY = 0;
static const unsigned char FINALITY_DISK_ENCODING_CANONICAL = 1;

class CFinalityVoteDiskRecord
{
public:
    uint32_t nMagic;
    int nGeneration;
    unsigned char nEncoding;
    CFinalityVote legacyVote;
    CCanonicalFinalityVoteEnvelope canonicalVote;

    CFinalityVoteDiskRecord()
        : nMagic(FINALITY_DISK_ENVELOPE_MAGIC),
          nGeneration(FINALITY_DISK_ENVELOPE_GENERATION),
          nEncoding(FINALITY_DISK_ENCODING_LEGACY)
    {
    }

    bool FromLogical(const CFinalityVote& vote)
    {
        nMagic = FINALITY_DISK_ENVELOPE_MAGIC;
        nGeneration = FINALITY_DISK_ENVELOPE_GENERATION;
        if (vote.IsCanonicalEnvelope())
        {
            nEncoding = FINALITY_DISK_ENCODING_CANONICAL;
            canonicalVote = CCanonicalFinalityVoteEnvelope();
            return canonicalVote.FromLogical(vote);
        }
        nEncoding = FINALITY_DISK_ENCODING_LEGACY;
        legacyVote = vote;
        legacyVote.fCanonicalEnvelope = false;
        return true;
    }

    bool ToLogical(CFinalityVote& voteOut) const
    {
        if (nMagic != FINALITY_DISK_ENVELOPE_MAGIC ||
            nGeneration != FINALITY_DISK_ENVELOPE_GENERATION)
            return false;
        if (nEncoding == FINALITY_DISK_ENCODING_CANONICAL)
            return canonicalVote.ToLogical(voteOut);
        if (nEncoding != FINALITY_DISK_ENCODING_LEGACY)
            return false;
        voteOut = legacyVote;
        voteOut.fCanonicalEnvelope = false;
        return true;
    }

    IMPLEMENT_SERIALIZE
    (
        CFinalityVoteDiskRecord* pthis =
            const_cast<CFinalityVoteDiskRecord*>(this);
        READWRITE(pthis->nMagic);
        READWRITE(pthis->nGeneration);
        READWRITE(pthis->nEncoding);
        if (fRead &&
            (pthis->nMagic != FINALITY_DISK_ENVELOPE_MAGIC ||
             pthis->nGeneration != FINALITY_DISK_ENVELOPE_GENERATION ||
             (pthis->nEncoding != FINALITY_DISK_ENCODING_LEGACY &&
              pthis->nEncoding != FINALITY_DISK_ENCODING_CANONICAL)))
            throw std::ios_base::failure("invalid finality-vote disk envelope header");
        if (pthis->nEncoding == FINALITY_DISK_ENCODING_CANONICAL)
            READWRITE(pthis->canonicalVote);
        else
            READWRITE(pthis->legacyVote);
    )
};

class CFinalityCertificateDiskRecord
{
public:
    uint32_t nMagic;
    int nGeneration;
    unsigned char nEncoding;
    CFinalityTallyCertificate legacyCert;
    CCanonicalFinalityTallyCertificateEnvelope canonicalCert;

    CFinalityCertificateDiskRecord()
        : nMagic(FINALITY_DISK_ENVELOPE_MAGIC),
          nGeneration(FINALITY_DISK_ENVELOPE_GENERATION),
          nEncoding(FINALITY_DISK_ENCODING_LEGACY)
    {
    }

    bool FromLogical(const CFinalityTallyCertificate& cert)
    {
        nMagic = FINALITY_DISK_ENVELOPE_MAGIC;
        nGeneration = FINALITY_DISK_ENVELOPE_GENERATION;
        if (cert.IsCanonicalEnvelope())
        {
            nEncoding = FINALITY_DISK_ENCODING_CANONICAL;
            canonicalCert = CCanonicalFinalityTallyCertificateEnvelope();
            return canonicalCert.FromLogical(cert);
        }
        nEncoding = FINALITY_DISK_ENCODING_LEGACY;
        legacyCert = cert;
        legacyCert.fCanonicalEnvelope = false;
        return true;
    }

    bool ToLogical(CFinalityTallyCertificate& certOut) const
    {
        if (nMagic != FINALITY_DISK_ENVELOPE_MAGIC ||
            nGeneration != FINALITY_DISK_ENVELOPE_GENERATION)
            return false;
        if (nEncoding == FINALITY_DISK_ENCODING_CANONICAL)
            return canonicalCert.ToLogical(certOut);
        if (nEncoding != FINALITY_DISK_ENCODING_LEGACY)
            return false;
        certOut = legacyCert;
        certOut.fCanonicalEnvelope = false;
        return true;
    }

    IMPLEMENT_SERIALIZE
    (
        CFinalityCertificateDiskRecord* pthis =
            const_cast<CFinalityCertificateDiskRecord*>(this);
        READWRITE(pthis->nMagic);
        READWRITE(pthis->nGeneration);
        READWRITE(pthis->nEncoding);
        if (fRead &&
            (pthis->nMagic != FINALITY_DISK_ENVELOPE_MAGIC ||
             pthis->nGeneration != FINALITY_DISK_ENVELOPE_GENERATION ||
             (pthis->nEncoding != FINALITY_DISK_ENCODING_LEGACY &&
              pthis->nEncoding != FINALITY_DISK_ENCODING_CANONICAL)))
            throw std::ios_base::failure("invalid finality-certificate disk envelope header");
        if (pthis->nEncoding == FINALITY_DISK_ENCODING_CANONICAL)
            READWRITE(pthis->canonicalCert);
        else
            READWRITE(pthis->legacyCert);
    )
};

bool FinalityDiskValueHasEnvelopeMagic(const std::string& strValue)
{
    if (strValue.size() < sizeof(uint32_t))
        return false;
    try
    {
        CDataStream ss(strValue.data(), strValue.data() + strValue.size(),
                       SER_DISK, CLIENT_VERSION);
        uint32_t nMagic = 0;
        ss >> nMagic;
        return nMagic == FINALITY_DISK_ENVELOPE_MAGIC;
    }
    catch (const std::exception&)
    {
        return false;
    }
}

bool DecodeFinalityVoteDiskValue(const std::string& strValue,
                                 CFinalityVote& voteOut,
                                 bool& fEnvelopeOut,
                                 std::string& strError)
{
    fEnvelopeOut = FinalityDiskValueHasEnvelopeMagic(strValue);
    strError.clear();
    try
    {
        CDataStream ss(strValue.data(), strValue.data() + strValue.size(),
                       SER_DISK, CLIENT_VERSION);
        if (fEnvelopeOut)
        {
            CFinalityVoteDiskRecord record;
            ss >> record;
            if (!ss.empty() || !record.ToLogical(voteOut))
                throw std::ios_base::failure("invalid/trailing finality-vote disk envelope");
            return true;
        }

        CFinalityVote rawVote;
        ss >> rawVote;
        if (!ss.empty())
            throw std::ios_base::failure("trailing legacy finality-vote bytes");

        // The old serializer omitted fCanonicalEnvelope. Transparent vote signatures authenticate
        // exactly one of the legacy and canonical domains; private votes cannot be canonical.
        CFinalityVote legacyVote = rawVote;
        legacyVote.fCanonicalEnvelope = false;
        CFinalityVote canonicalVote = rawVote;
        canonicalVote.MarkCanonicalEnvelope();
        CCanonicalFinalityVoteEnvelope canonicalShape;
        const bool fLegacyValid = legacyVote.IsValid();
        const bool fCanonicalValid =
            canonicalShape.FromLogical(canonicalVote) && canonicalVote.IsValid();
        if (fLegacyValid == fCanonicalValid)
            throw std::ios_base::failure(
                "legacy finality-vote provenance is invalid or ambiguous");
        voteOut = fCanonicalValid ? canonicalVote : legacyVote;
        return true;
    }
    catch (const std::exception& e)
    {
        strError = e.what();
        return false;
    }
}

bool DecodeFinalityCertificateDiskValue(
    const std::string& strValue, const uint256& hashKey,
    CFinalityTallyCertificate& certOut, bool& fEnvelopeOut,
    std::string& strError)
{
    fEnvelopeOut = FinalityDiskValueHasEnvelopeMagic(strValue);
    strError.clear();
    try
    {
        CDataStream ss(strValue.data(), strValue.data() + strValue.size(),
                       SER_DISK, CLIENT_VERSION);
        if (fEnvelopeOut)
        {
            CFinalityCertificateDiskRecord record;
            ss >> record;
            if (!ss.empty() || !record.ToLogical(certOut))
                throw std::ios_base::failure(
                    "invalid/trailing finality-certificate disk envelope");
            return true;
        }

        CFinalityTallyCertificate rawCert;
        ss >> rawCert;
        if (!ss.empty())
            throw std::ios_base::failure(
                "trailing legacy finality-certificate bytes");

        // Certificates do not always carry a signature, but their LevelDB key
        // is their identity hash.  Exactly one domain must reproduce that key.
        CFinalityTallyCertificate legacyCert = rawCert;
        legacyCert.fCanonicalEnvelope = false;
        CFinalityTallyCertificate canonicalCert = rawCert;
        canonicalCert.MarkCanonicalEnvelope();
        CCanonicalFinalityTallyCertificateEnvelope canonicalShape;
        const bool fLegacyValid = legacyCert.IsValidBasic() &&
                                  legacyCert.GetHash() == hashKey;
        const bool fCanonicalValid = canonicalShape.FromLogical(canonicalCert) &&
                                     canonicalCert.IsValidBasic() &&
                                     canonicalCert.GetHash() == hashKey;
        if (fLegacyValid == fCanonicalValid)
            throw std::ios_base::failure(
                "legacy finality-certificate provenance is invalid or ambiguous");
        certOut = fCanonicalValid ? canonicalCert : legacyCert;
        return true;
    }
    catch (const std::exception& e)
    {
        strError = e.what();
        return false;
    }
}
} // namespace

bool CTxDB::ReadFinalityDiskEnvelopeGeneration(int& nGeneration)
{
    nGeneration = 0;
    return ReadFixedExactStatusBounded(
               string("finalitydiskschema"), nGeneration) ==
           TXDB_READ_FOUND;
}

bool CTxDB::WriteFinalityVote(const uint256& nullifier, const CFinalityVote& vote)
{
    int nGeneration = 0;
    if (!ReadFinalityDiskEnvelopeGeneration(nGeneration) ||
        nGeneration != FINALITY_DISK_ENVELOPE_GENERATION)
        return error("WriteFinalityVote: finality disk envelope schema is unavailable");
    CFinalityVoteDiskRecord record;
    if (!record.FromLogical(vote))
        return false;
    return Write(make_pair(string("finalityvote"), nullifier), record);
}

bool CTxDB::ReadFinalityVote(const uint256& nullifier, CFinalityVote& vote)
{
    int nGeneration = 0;
    const TxDBReadStatus schemaStatus = ReadFixedExactStatusBounded(
        string("finalitydiskschema"), nGeneration);
    if (schemaStatus == TXDB_READ_ERROR ||
        (schemaStatus == TXDB_READ_FOUND &&
         nGeneration != FINALITY_DISK_ENVELOPE_GENERATION))
        return false;

    std::string strValue;
    if (ReadRawValueStatus(make_pair(string("finalityvote"), nullifier),
                           strValue) != TXDB_READ_FOUND)
        return false;
    bool fEnvelope = false;
    std::string strError;
    if (!DecodeFinalityVoteDiskValue(strValue, vote, fEnvelope, strError))
        return false;
    if (schemaStatus == TXDB_READ_FOUND && !fEnvelope)
        return false;
    return vote.nullifier == nullifier && vote.IsValid();
}

bool CTxDB::EraseFinalityVote(const uint256& nullifier)
{
    return Erase(make_pair(string("finalityvote"), nullifier));
}

bool CTxDB::IterateFinalityVotes(std::map<uint256, CFinalityVote>& mapOut)
{
    mapOut.clear();
    int nGeneration = 0;
    const TxDBReadStatus schemaStatus = ReadFixedExactStatusBounded(
        string("finalitydiskschema"), nGeneration);
    if (schemaStatus == TXDB_READ_ERROR ||
        (schemaStatus == TXDB_READ_FOUND &&
         nGeneration != FINALITY_DISK_ENVELOPE_GENERATION))
        return false;
    const bool fRequireEnvelope = schemaStatus == TXDB_READ_FOUND;

    leveldb::DB* db = GetInstance();
    if (!db)
        return false;

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("finalityvote");
    std::string strPrefix = ssPrefix.str();

    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    it->Seek(strPrefix);

    while (it->Valid())
    {
        std::string strKey = it->key().ToString();
        if (strKey.compare(0, strPrefix.size(), strPrefix) != 0)
            break;

        try {
            CDataStream ssKey(strKey.data(), strKey.data() + strKey.size(), SER_DISK, CLIENT_VERSION);
            std::pair<std::string, uint256> keyPair;
            ssKey >> keyPair;
            if (keyPair.first != "finalityvote" || keyPair.second == 0 || ssKey.size() != 0)
                throw std::ios_base::failure("non-canonical finality-vote key");

            CFinalityVote vote;
            const leveldb::Slice rawValue = it->value();
            const std::string strValue(rawValue.data(), rawValue.size());
            bool fEnvelope = false;
            std::string strDecodeError;
            if (!DecodeFinalityVoteDiskValue(
                    strValue, vote, fEnvelope, strDecodeError))
                throw std::ios_base::failure(strDecodeError);
            if (fRequireEnvelope && !fEnvelope)
                throw std::ios_base::failure(
                    "legacy finality-vote value under envelope schema marker");
            if (vote.nullifier == 0 || vote.nullifier != keyPair.second)
                throw std::ios_base::failure("finality-vote key/value nullifier mismatch");
            if (!vote.IsValid())
                throw std::ios_base::failure("persisted finality vote is structurally invalid");
            if (mapOut.count(keyPair.second))
                throw std::ios_base::failure("duplicate finality-vote key");
            mapOut[keyPair.second] = vote;
        }
        catch (const std::exception& e)
        {
            printf("IterateFinalityVotes: FATAL finality-vote record failed to deserialize: %s -- "
                   "-reindex/resync required\n", e.what());
            delete it;
            mapOut.clear();
            return false;
        }

        it->Next();
    }

    leveldb::Status status = it->status();
    delete it;
    if (!status.ok())
    {
        printf("IterateFinalityVotes: FATAL LevelDB iterator failure: %s -- "
               "-reindex/resync required\n", status.ToString().c_str());
        mapOut.clear();
        return false;
    }
    return true;
}

bool CTxDB::WriteFinalityTallyShare(const uint256& hashShare, const CFinalityTallyShare& share)
{
    return Write(make_pair(string("finalityshare"), hashShare), share);
}

bool CTxDB::ReadFinalityTallyShare(const uint256& hashShare, CFinalityTallyShare& share)
{
    return Read(make_pair(string("finalityshare"), hashShare), share);
}

bool CTxDB::EraseFinalityTallyShare(const uint256& hashShare)
{
    return Erase(make_pair(string("finalityshare"), hashShare));
}

template <typename Key, typename Value>
static bool IterateFinalityRecords(leveldb::DB* db,
                                   const char* pszPrefix,
                                   std::map<Key, Value>& mapOut)
{
    mapOut.clear();
    if (!db)
        return false;

    const std::string strType(pszPrefix);
    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << strType;
    const std::string strPrefix = ssPrefix.str();

    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    it->Seek(strPrefix);
    while (it->Valid())
    {
        const std::string strKey = it->key().ToString();
        if (strKey.compare(0, strPrefix.size(), strPrefix) != 0)
            break;
        try
        {
            CDataStream ssKey(strKey.data(), strKey.data() + strKey.size(),
                              SER_DISK, CLIENT_VERSION);
            std::pair<std::string, Key> keyPair;
            ssKey >> keyPair;
            if (keyPair.first != strType || ssKey.size() != 0 ||
                mapOut.count(keyPair.second))
                throw std::ios_base::failure("non-canonical or duplicate finality key");

            CDataStream ssValue(it->value().data(),
                                it->value().data() + it->value().size(),
                                SER_DISK, CLIENT_VERSION);
            Value value;
            ssValue >> value;
            if (ssValue.size() != 0)
                throw std::ios_base::failure("trailing finality record bytes");
            mapOut[keyPair.second] = value;
        }
        catch (const std::exception& e)
        {
            printf("IterateFinalityRecords(%s): FATAL record decode failure: %s -- "
                   "-reindex/resync required\n", pszPrefix, e.what());
            delete it;
            mapOut.clear();
            return false;
        }
        it->Next();
    }

    const leveldb::Status status = it->status();
    delete it;
    if (!status.ok())
    {
        printf("IterateFinalityRecords(%s): FATAL iterator failure: %s -- "
               "-reindex/resync required\n", pszPrefix, status.ToString().c_str());
        mapOut.clear();
        return false;
    }
    return true;
}

template <typename Key, typename Element>
static bool IterateFinalityVectorRecords(
    leveldb::DB* db,
    const char* pszPrefix,
    uint64_t nMaxElements,
    std::map<Key, std::vector<Element> >& mapOut)
{
    mapOut.clear();
    if (!db)
        return false;

    const std::string strType(pszPrefix);
    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << strType;
    const std::string strPrefix = ssPrefix.str();

    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    it->Seek(strPrefix);
    while (it->Valid())
    {
        const std::string strKey = it->key().ToString();
        if (strKey.compare(0, strPrefix.size(), strPrefix) != 0)
            break;
        try
        {
            CDataStream ssKey(strKey.data(), strKey.data() + strKey.size(),
                              SER_DISK, CLIENT_VERSION);
            std::pair<std::string, Key> keyPair;
            ssKey >> keyPair;
            if (keyPair.first != strType || ssKey.size() != 0 ||
                mapOut.count(keyPair.second))
                throw std::ios_base::failure("non-canonical or duplicate finality key");

            CDataStream ssValue(it->value().data(),
                                it->value().data() + it->value().size(),
                                SER_DISK, CLIENT_VERSION);
            std::vector<Element> value;
            SerReadWriteLimitedVector(ssValue, value, nMaxElements,
                                      SER_DISK, CLIENT_VERSION,
                                      CSerActionUnserialize());
            if (ssValue.size() != 0)
                throw std::ios_base::failure("trailing finality vector record bytes");
            mapOut[keyPair.second] = value;
        }
        catch (const std::exception& e)
        {
            printf("IterateFinalityVectorRecords(%s): FATAL record decode failure: %s -- "
                   "-reindex/resync required\n", pszPrefix, e.what());
            delete it;
            mapOut.clear();
            return false;
        }
        it->Next();
    }

    const leveldb::Status status = it->status();
    delete it;
    if (!status.ok())
    {
        printf("IterateFinalityVectorRecords(%s): FATAL iterator failure: %s -- "
               "-reindex/resync required\n", pszPrefix, status.ToString().c_str());
        mapOut.clear();
        return false;
    }
    return true;
}

bool CTxDB::IterateFinalityTallyShares(std::map<uint256, CFinalityTallyShare>& mapOut)
{
    if (!IterateFinalityRecords(GetInstance(), "finalityshare", mapOut))
        return false;
    for (std::map<uint256, CFinalityTallyShare>::const_iterator it = mapOut.begin();
         it != mapOut.end(); ++it)
        if (it->first == 0 || it->second.GetHash() != it->first ||
            !it->second.IsValidBasic())
        {
            printf("IterateFinalityTallyShares: FATAL key/value or structural mismatch; "
                   "-reindex/resync required\n");
            mapOut.clear();
            return false;
        }
    return true;
}

bool CTxDB::WriteFinalityTallyCertificate(const uint256& hashCert, const CFinalityTallyCertificate& cert)
{
    int nGeneration = 0;
    if (!ReadFinalityDiskEnvelopeGeneration(nGeneration) ||
        nGeneration != FINALITY_DISK_ENVELOPE_GENERATION)
        return error("WriteFinalityTallyCertificate: finality disk envelope schema is unavailable");
    CFinalityCertificateDiskRecord record;
    if (!record.FromLogical(cert))
        return false;
    return Write(make_pair(string("finalitycert"), hashCert), record);
}

bool CTxDB::ReadFinalityTallyCertificate(const uint256& hashCert, CFinalityTallyCertificate& cert)
{
    int nGeneration = 0;
    const TxDBReadStatus schemaStatus = ReadFixedExactStatusBounded(
        string("finalitydiskschema"), nGeneration);
    if (schemaStatus == TXDB_READ_ERROR ||
        (schemaStatus == TXDB_READ_FOUND &&
         nGeneration != FINALITY_DISK_ENVELOPE_GENERATION))
        return false;

    std::string strValue;
    if (ReadRawValueStatus(make_pair(string("finalitycert"), hashCert),
                           strValue) != TXDB_READ_FOUND)
        return false;
    bool fEnvelope = false;
    std::string strError;
    if (!DecodeFinalityCertificateDiskValue(
            strValue, hashCert, cert, fEnvelope, strError))
        return false;
    if (schemaStatus == TXDB_READ_FOUND && !fEnvelope)
        return false;
    return cert.GetHash() == hashCert && cert.IsValidBasic();
}

bool CTxDB::EraseFinalityTallyCertificate(const uint256& hashCert)
{
    return Erase(make_pair(string("finalitycert"), hashCert));
}

bool CTxDB::IterateFinalityTallyCertificates(std::map<uint256, CFinalityTallyCertificate>& mapOut)
{
    mapOut.clear();
    int nGeneration = 0;
    const TxDBReadStatus schemaStatus = ReadFixedExactStatusBounded(
        string("finalitydiskschema"), nGeneration);
    if (schemaStatus == TXDB_READ_ERROR ||
        (schemaStatus == TXDB_READ_FOUND &&
         nGeneration != FINALITY_DISK_ENVELOPE_GENERATION))
        return false;
    const bool fRequireEnvelope = schemaStatus == TXDB_READ_FOUND;

    leveldb::DB* db = GetInstance();
    if (!db)
        return false;
    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("finalitycert");
    const std::string strPrefix = ssPrefix.str();
    leveldb::Iterator* iter = db->NewIterator(leveldb::ReadOptions());
    iter->Seek(strPrefix);
    while (iter->Valid())
    {
        const std::string strKey = iter->key().ToString();
        if (strKey.compare(0, strPrefix.size(), strPrefix) != 0)
            break;
        try
        {
            CDataStream ssKey(strKey.data(), strKey.data() + strKey.size(),
                              SER_DISK, CLIENT_VERSION);
            std::pair<std::string, uint256> keyPair;
            ssKey >> keyPair;
            if (keyPair.first != "finalitycert" || keyPair.second == 0 ||
                !ssKey.empty() || mapOut.count(keyPair.second))
                throw std::ios_base::failure(
                    "non-canonical or duplicate finality-certificate key");

            const leveldb::Slice rawValue = iter->value();
            const std::string strValue(rawValue.data(), rawValue.size());
            CFinalityTallyCertificate cert;
            bool fEnvelope = false;
            std::string strDecodeError;
            if (!DecodeFinalityCertificateDiskValue(
                    strValue, keyPair.second, cert, fEnvelope,
                    strDecodeError))
                throw std::ios_base::failure(strDecodeError);
            if (fRequireEnvelope && !fEnvelope)
                throw std::ios_base::failure(
                    "legacy finality-certificate value under envelope schema marker");
            if (cert.GetHash() != keyPair.second || !cert.IsValidBasic())
                throw std::ios_base::failure(
                    "finality-certificate key/value or structural mismatch");
            mapOut[keyPair.second] = cert;
        }
        catch (const std::exception& e)
        {
            printf("IterateFinalityTallyCertificates: FATAL record decode failure: %s -- "
                   "-reindex/resync required\n", e.what());
            delete iter;
            mapOut.clear();
            return false;
        }
        iter->Next();
    }

    const leveldb::Status status = iter->status();
    delete iter;
    if (!status.ok())
    {
        printf("IterateFinalityTallyCertificates: FATAL iterator failure: %s -- "
               "-reindex/resync required\n", status.ToString().c_str());
        mapOut.clear();
        return false;
    }
    return true;
}

bool CTxDB::MigrateFinalityDiskRecords(std::string& strError)
{
    strError.clear();
    if (IsTxnActive())
    {
        strError = "finality disk migration cannot join an existing transaction";
        return false;
    }

    int nGeneration = 0;
    const TxDBReadStatus schemaStatus = ReadFixedExactStatusBounded(
        string("finalitydiskschema"), nGeneration);
    if (schemaStatus == TXDB_READ_ERROR)
    {
        strError = "finality disk envelope schema marker is corrupt";
        return false;
    }
    if (schemaStatus == TXDB_READ_FOUND)
    {
        if (nGeneration != FINALITY_DISK_ENVELOPE_GENERATION)
        {
            strError = strprintf("unsupported finality disk envelope generation %d",
                                 nGeneration);
            return false;
        }
        return true;
    }

    // No marker means the legacy generation. The strict dual decoder recovers canonical
    // provenance from the vote domain or certificate key, and fails if both or neither match.
    std::map<uint256, CFinalityVote> mapVotes;
    if (!IterateFinalityVotes(mapVotes))
    {
        strError = "legacy finality-vote records cannot be classified safely";
        return false;
    }
    std::map<uint256, CFinalityTallyCertificate> mapCerts;
    if (!IterateFinalityTallyCertificates(mapCerts))
    {
        strError = "legacy finality-certificate records cannot be classified safely";
        return false;
    }

    // Read-only loads run the full legacy classification but cannot stamp the marker; a
    // writable startup commits records and marker in one synchronous batch.
    if (fReadOnly)
    {
        printf("Finality: validated %d legacy votes and %d legacy certificates "
               "in read-only mode (migration deferred)\n",
               (int)mapVotes.size(), (int)mapCerts.size());
        return true;
    }

    if (!TxnBegin())
    {
        strError = "could not begin atomic finality disk migration";
        return false;
    }

    for (std::map<uint256, CFinalityVote>::const_iterator it = mapVotes.begin();
         it != mapVotes.end(); ++it)
    {
        CFinalityVoteDiskRecord record;
        if (!record.FromLogical(it->second) ||
            !Write(make_pair(string("finalityvote"), it->first), record))
        {
            TxnAbort();
            strError = "failed to stage generation-tagged finality-vote record";
            return false;
        }
    }
    for (std::map<uint256, CFinalityTallyCertificate>::const_iterator it =
             mapCerts.begin(); it != mapCerts.end(); ++it)
    {
        CFinalityCertificateDiskRecord record;
        if (!record.FromLogical(it->second) ||
            !Write(make_pair(string("finalitycert"), it->first), record))
        {
            TxnAbort();
            strError = "failed to stage generation-tagged finality-certificate record";
            return false;
        }
    }
    if (!Write(string("finalitydiskschema"),
               FINALITY_DISK_ENVELOPE_GENERATION))
    {
        TxnAbort();
        strError = "failed to stage finality disk envelope schema marker";
        return false;
    }
    if (!TxnCommit(true))
    {
        strError = "failed to commit atomic finality disk migration";
        return false;
    }

    printf("Finality: migrated %d votes and %d certificates to disk envelope generation %d\n",
           (int)mapVotes.size(), (int)mapCerts.size(),
           FINALITY_DISK_ENVELOPE_GENERATION);
    return true;
}

bool CTxDB::WriteFinalityConnectedVoteBlock(const uint256& hashBlock, const std::vector<uint256>& vNullifiers)
{
    return Write(make_pair(string("finalityconnvb"), hashBlock), vNullifiers);
}

bool CTxDB::EraseFinalityConnectedVoteBlock(const uint256& hashBlock)
{
    return Erase(make_pair(string("finalityconnvb"), hashBlock));
}

bool CTxDB::IterateFinalityConnectedVoteBlocks(std::map<uint256, std::vector<uint256> >& mapOut)
{
    if (!IterateFinalityVectorRecords(GetInstance(), "finalityconnvb",
                                      FINALITY_MAX_BLOCK_VOTES, mapOut))
        return false;
    for (std::map<uint256, std::vector<uint256> >::const_iterator it = mapOut.begin();
         it != mapOut.end(); ++it)
    {
        const std::set<uint256> unique(it->second.begin(), it->second.end());
        if (it->first == 0 || it->second.size() > FINALITY_MAX_BLOCK_VOTES ||
            unique.size() != it->second.size() || unique.count(uint256(0)))
            return false;
    }
    return true;
}

bool CTxDB::WriteFinalityConnectedShareBlock(const uint256& hashBlock, const std::vector<uint256>& vShareHashes)
{
    return Write(make_pair(string("finalityconnsb"), hashBlock), vShareHashes);
}

bool CTxDB::EraseFinalityConnectedShareBlock(const uint256& hashBlock)
{
    return Erase(make_pair(string("finalityconnsb"), hashBlock));
}

bool CTxDB::IterateFinalityConnectedShareBlocks(std::map<uint256, std::vector<uint256> >& mapOut)
{
    if (!IterateFinalityVectorRecords(GetInstance(), "finalityconnsb",
                                      FINALITY_MAX_VOTES, mapOut))
        return false;
    for (std::map<uint256, std::vector<uint256> >::const_iterator it = mapOut.begin();
         it != mapOut.end(); ++it)
    {
        const std::set<uint256> unique(it->second.begin(), it->second.end());
        if (it->first == 0 || it->second.size() > FINALITY_MAX_VOTES ||
            unique.size() != it->second.size() || unique.count(uint256(0)))
            return false;
    }
    return true;
}

bool CTxDB::WriteFinalityConnectedCertBlock(const uint256& hashBlock, const std::vector<uint256>& vCertHashes)
{
    return Write(make_pair(string("finalityconncb"), hashBlock), vCertHashes);
}

bool CTxDB::EraseFinalityConnectedCertBlock(const uint256& hashBlock)
{
    return Erase(make_pair(string("finalityconncb"), hashBlock));
}

bool CTxDB::IterateFinalityConnectedCertBlocks(std::map<uint256, std::vector<uint256> >& mapOut)
{
    if (!IterateFinalityVectorRecords(GetInstance(), "finalityconncb",
                                      FINALITY_MAX_VOTES, mapOut))
        return false;
    for (std::map<uint256, std::vector<uint256> >::const_iterator it = mapOut.begin();
         it != mapOut.end(); ++it)
    {
        const std::set<uint256> unique(it->second.begin(), it->second.end());
        if (it->first == 0 || it->second.size() > FINALITY_MAX_VOTES ||
            unique.size() != it->second.size() || unique.count(uint256(0)))
            return false;
    }
    return true;
}

bool CTxDB::WriteFinalityCommitteeRotation(int nEffectiveEpoch, const CFinalityCommitteeRotation& rot)
{
    return Write(make_pair(string("finalityrot"), nEffectiveEpoch), rot);
}

bool CTxDB::ReadFinalityCommitteeRotation(int nEffectiveEpoch, CFinalityCommitteeRotation& rot)
{
    return Read(make_pair(string("finalityrot"), nEffectiveEpoch), rot);
}

bool CTxDB::EraseFinalityCommitteeRotation(int nEffectiveEpoch)
{
    return Erase(make_pair(string("finalityrot"), nEffectiveEpoch));
}

bool CTxDB::IterateFinalityCommitteeRotations(std::map<int, CFinalityCommitteeRotation>& mapOut)
{
    if (!IterateFinalityRecords(GetInstance(), "finalityrot", mapOut))
        return false;
    for (std::map<int, CFinalityCommitteeRotation>::const_iterator it = mapOut.begin();
         it != mapOut.end(); ++it)
        if (it->first <= 0 || it->second.nEffectiveEpoch != it->first ||
            !it->second.IsValidBasic())
        {
            printf("IterateFinalityCommitteeRotations: FATAL key/value or structural "
                   "mismatch; -reindex/resync required\n");
            mapOut.clear();
            return false;
        }
    return true;
}

bool CTxDB::WriteFinalityConnectedRotationBlock(const uint256& hashBlock, const std::vector<int>& vEffEpochs)
{
    return Write(make_pair(string("finalityconnrot"), hashBlock), vEffEpochs);
}

bool CTxDB::EraseFinalityConnectedRotationBlock(const uint256& hashBlock)
{
    return Erase(make_pair(string("finalityconnrot"), hashBlock));
}

bool CTxDB::IterateFinalityConnectedRotationBlocks(std::map<uint256, std::vector<int> >& mapOut)
{
    if (!IterateFinalityVectorRecords(GetInstance(), "finalityconnrot",
                                      FINALITY_MAX_VOTES, mapOut))
        return false;
    for (std::map<uint256, std::vector<int> >::const_iterator it = mapOut.begin();
         it != mapOut.end(); ++it)
    {
        const std::set<int> unique(it->second.begin(), it->second.end());
        if (it->first == 0 || it->second.size() > FINALITY_MAX_VOTES ||
            unique.size() != it->second.size() ||
            (!unique.empty() && *unique.begin() <= 0))
            return false;
    }
    return true;
}

bool CTxDB::IterateDAGLinks(std::map<uint256, CBlockDAGData>& mapOut)
{
    mapOut.clear();
    leveldb::DB* db = GetInstance();
    if (!db)
        return false;

    // Build the serialized prefix for "daglinks" key type
    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("daglinks");
    std::string strPrefix = ssPrefix.str();

    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    it->Seek(strPrefix);

    while (it->Valid())
    {
        std::string strKey = it->key().ToString();
        if (strKey.compare(0, strPrefix.size(), strPrefix) != 0)
            break;

        try {
            CDataStream ssKey(strKey.data(), strKey.data() + strKey.size(), SER_DISK, CLIENT_VERSION);
            std::pair<std::string, uint256> keyPair;
            ssKey >> keyPair;
            if (keyPair.first != "daglinks" || keyPair.second == 0 || ssKey.size() != 0)
                throw std::ios_base::failure("non-canonical DAG-link key");
            if (mapOut.count(keyPair.second))
                throw std::ios_base::failure("duplicate DAG-link key");

            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            CBlockDAGData data;

            // Parents are deserialized manually so a corrupt record cannot allocate past the consensus
            // maximum. Children are rebuilt by RebuildPendingChildIndex(), so this copy is discarded.
            const uint64_t nParentCount = ReadCompactSize(ssValue);
            if (nParentCount > MAX_DAG_PARENTS)
                throw std::ios_base::failure("oversized DAG parent set");
            data.vDAGParents.reserve((size_t)nParentCount);
            for (uint64_t i = 0; i < nParentCount; ++i)
            {
                uint256 hashParent;
                ssValue >> hashParent;
                data.vDAGParents.push_back(hashParent);
            }
            const uint64_t nChildCount = ReadCompactSize(ssValue);
            if (nChildCount > (uint64_t)ssValue.size() / 32)
                throw std::ios_base::failure("truncated/oversized DAG child set");
            for (uint64_t i = 0; i < nChildCount; ++i)
            {
                uint256 hashIgnoredChild;
                ssValue >> hashIgnoredChild;
            }

            // DAGKNIGHT compatibility: deserialize core fields first, then try nInferredK.
            ssValue >> data.fBlue;
            ssValue >> data.nDAGScore;
            ssValue >> data.nDAGOrder;

            // nInferredK may not exist in legacy entries
            if (ssValue.size() > 0)
            {
                ssValue >> data.nInferredK;
            }
            else
            {
                data.nInferredK = -1;
            }

            if (ssValue.size() != 0)
                throw std::ios_base::failure("trailing DAG-link bytes");
            std::set<uint256> setParents;
            for (std::vector<uint256>::const_iterator pit = data.vDAGParents.begin();
                 pit != data.vDAGParents.end(); ++pit)
            {
                if (*pit == 0 || *pit == keyPair.second || !setParents.insert(*pit).second)
                    throw std::ios_base::failure("invalid DAG parent set");
            }

            mapOut[keyPair.second] = data;
        }
        catch (const std::exception& e)
        {
            printf("IterateDAGLinks: FATAL DAG-link record failed to deserialize: %s -- "
                   "-reindex/resync required\n", e.what());
            delete it;
            mapOut.clear();
            return false;
        }

        it->Next();
    }

    leveldb::Status status = it->status();
    delete it;
    if (!status.ok())
    {
        printf("IterateDAGLinks: FATAL LevelDB iterator failure: %s -- "
               "-reindex/resync required\n", status.ToString().c_str());
        mapOut.clear();
        return false;
    }
    return true;
}

class CBatchScanner : public leveldb::WriteBatch::Handler {
public:
    std::string needle;
    bool *deleted;
    std::string *foundValue;
    bool foundEntry;

    CBatchScanner() : foundEntry(false) {}

    virtual void Put(const leveldb::Slice& key, const leveldb::Slice& value) {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = false;
            *foundValue = value.ToString();
        }
    }

    virtual void Delete(const leveldb::Slice& key) {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = true;
        }
    }
};

// When performing a read, if we have an active batch we need to check it first
// before reading from the database, as the rest of the code assumes that once
// a database transaction begins reads are consistent with it. It would be good
// to change that assumption in future and avoid the performance hit, though in
// practice it does not appear to be large.
bool CTxDB::ScanBatch(const CDataStream &key, string *value, bool *deleted) const {
    assert(activeBatch);
    *deleted = false;
    CBatchScanner scanner;
    scanner.needle = key.str();
    scanner.deleted = deleted;
    scanner.foundValue = value;
    leveldb::Status status = activeBatch->Iterate(&scanner);
    if (!status.ok()) {
        throw runtime_error(status.ToString());
    }
    return scanner.foundEntry;
}

bool CTxDB::WriteAddrIndex(uint160 addrHash, uint256 txHash)
{
    std::vector<uint256> txHashes;
    if(!ReadAddrIndex(addrHash, txHashes))
    {
	txHashes.push_back(txHash);
        return Write(make_pair(string("adr"), addrHash), txHashes);
    }
    else
    {
	if(std::find(txHashes.begin(), txHashes.end(), txHash) == txHashes.end())
    	{
    	    txHashes.push_back(txHash);
            return Write(make_pair(string("adr"), addrHash), txHashes);
	}
	else
	{
	    return true; // already have this tx hash
	}
    }
}

bool CTxDB::ReadAddrIndex(uint160 addrHash, std::vector<uint256>& txHashes)
{
    return Read(make_pair(string("adr"), addrHash), txHashes);
}

bool CTxDB::ReadTxIndex(uint256 hash, CTxIndex& txindex)
{
    return ReadTxIndexStatus(hash, txindex) == TXDB_READ_FOUND;
}

TxDBReadStatus CTxDB::ReadTxIndexStatus(const uint256& hash,
                                        CTxIndex& txindex)
{
    txindex.SetNull();
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey << make_pair(string("tx"), hash);

    std::string strBatchValue;
    if (activeBatch)
    {
        try
        {
            bool fDeleted = false;
            if (ScanBatch(ssKey, &strBatchValue, &fDeleted))
            {
                if (fDeleted)
                    return TXDB_READ_NOT_FOUND;
                return ParseTxIndexValue(strBatchValue.data(),
                                         strBatchValue.size(), txindex);
            }
        }
        catch (const std::exception&)
        {
            return TXDB_READ_ERROR;
        }
    }

    leveldb::Iterator* it = pdb->NewIterator(leveldb::ReadOptions());
    if (!it)
        return TXDB_READ_ERROR;
    const std::string strKey = ssKey.str();
    it->Seek(strKey);
    if (!it->Valid())
    {
        const bool fOk = it->status().ok();
        delete it;
        return fOk ? TXDB_READ_NOT_FOUND : TXDB_READ_ERROR;
    }
    if (it->key().compare(leveldb::Slice(strKey)) != 0)
    {
        delete it;
        return TXDB_READ_NOT_FOUND;
    }
    const leveldb::Slice value = it->value();
    const TxDBReadStatus status = ParseTxIndexValue(
        value.data(), value.size(), txindex);
    delete it;
    return status;
}

bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex& txindex)
{
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight)
{
    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction& tx)
{
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}

bool CTxDB::ContainsTx(uint256 hash)
{
    return Exists(make_pair(string("tx"), hash));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex))
        return false;
    return (tx.ReadFromDisk(txindex.pos));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

bool CTxDB::EraseBlockIndex(const uint256& blockhash)
{
    return Erase(make_pair(string("blockindex"), blockhash));
}

bool CTxDB::ReadHashBestChain(uint256& hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}

TxDBReadStatus CTxDB::ReadShieldedWalletRecoveryStatus(
    CShieldedWalletRecoveryRecord& record)
{
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey << string("shieldedWalletRecovery");
    const size_t nExpectedSize = ::GetSerializeSize(
        CShieldedWalletRecoveryRecord(), SER_DISK, CLIENT_VERSION);

    std::string strBatchValue;
    if (activeBatch)
    {
        bool fDeleted = false;
        if (ScanBatch(ssKey, &strBatchValue, &fDeleted))
        {
            if (fDeleted)
                return TXDB_READ_NOT_FOUND;
            if (strBatchValue.size() != nExpectedSize)
                return TXDB_READ_ERROR;
            try
            {
                CDataStream ssValue(strBatchValue.data(),
                                    strBatchValue.data() +
                                        strBatchValue.size(),
                                    SER_DISK, CLIENT_VERSION);
                ssValue >> record;
                if (!ssValue.empty() || !record.IsValid())
                    return TXDB_READ_ERROR;
                return TXDB_READ_FOUND;
            }
            catch (const std::exception&)
            {
                return TXDB_READ_ERROR;
            }
        }
    }

    // Iterator values are borrowed slices.  Inspect the exact fixed size
    // before copying or deserializing, so a corrupt local record cannot force
    // an attacker-sized allocation during startup.
    leveldb::Iterator* it = pdb->NewIterator(leveldb::ReadOptions());
    if (!it)
        return TXDB_READ_ERROR;
    const std::string strKey = ssKey.str();
    it->Seek(strKey);
    if (!it->Valid())
    {
        const bool fOk = it->status().ok();
        delete it;
        return fOk ? TXDB_READ_NOT_FOUND : TXDB_READ_ERROR;
    }
    if (it->key().compare(leveldb::Slice(strKey)) != 0)
    {
        delete it;
        return TXDB_READ_NOT_FOUND;
    }
    const leveldb::Slice value = it->value();
    if (value.size() != nExpectedSize)
    {
        delete it;
        return TXDB_READ_ERROR;
    }
    try
    {
        CDataStream ssValue(value.data(), value.data() + value.size(),
                            SER_DISK, CLIENT_VERSION);
        ssValue >> record;
        if (!ssValue.empty() || !record.IsValid())
        {
            delete it;
            return TXDB_READ_ERROR;
        }
    }
    catch (const std::exception&)
    {
        delete it;
        return TXDB_READ_ERROR;
    }
    delete it;
    return TXDB_READ_FOUND;
}

bool CTxDB::WriteShieldedWalletRecovery(
    const CShieldedWalletRecoveryRecord& record)
{
    return record.IsValid() &&
           Write(string("shieldedWalletRecovery"), record);
}

bool CTxDB::AcknowledgeShieldedWalletRecovery(
    const CShieldedWalletRecoveryRecord& expected)
{
    if (!expected.IsValid() || IsTxnActive() || !TxnBegin())
        return false;

    CShieldedWalletRecoveryRecord current;
    const TxDBReadStatus status =
        ReadShieldedWalletRecoveryStatus(current);
    const bool fMatches =
        status == TXDB_READ_FOUND &&
        current.nSchema == expected.nSchema &&
        current.hashOldTip == expected.hashOldTip &&
        current.hashFork == expected.hashFork &&
        current.hashNewTip == expected.hashNewTip &&
        current.nDisconnect == expected.nDisconnect &&
        current.nConnect == expected.nConnect &&
        current.hashEffectPlan == expected.hashEffectPlan;
    if (!fMatches || !EraseShieldedWalletRecovery())
    {
        TxnAbort();
        return false;
    }
    return TxnCommit(true);
}

bool CTxDB::EraseShieldedWalletRecovery()
{
    return Erase(string("shieldedWalletRecovery"));
}

TxDBReadStatus CTxDB::ReadDAGSkippedTxMetadataStatus(
    const uint256& hashBlock, const uint256& hashMerkleRoot,
    uint32_t& nBlockTxCount, std::string& strError)
{
    nBlockTxCount = 0;
    strError.clear();
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey << make_pair(string("dagactiveset"), hashBlock);

    std::string strBatchValue;
    if (activeBatch)
    {
        try
        {
            bool fDeleted = false;
            if (ScanBatch(ssKey, &strBatchValue, &fDeleted))
            {
                if (fDeleted)
                    return TXDB_READ_NOT_FOUND;
                return ParseDAGSkippedTxValue(
                    strBatchValue.data(), strBatchValue.size(), hashBlock,
                    hashMerkleRoot, nBlockTxCount, NULL, strError);
            }
        }
        catch (const std::exception& e)
        {
            strError = e.what();
            return TXDB_READ_ERROR;
        }
    }

    leveldb::Iterator* it = pdb->NewIterator(leveldb::ReadOptions());
    if (!it)
    {
        strError = "could not create DAG active-set iterator";
        return TXDB_READ_ERROR;
    }
    const std::string strKey = ssKey.str();
    it->Seek(strKey);
    if (!it->Valid())
    {
        const bool fOk = it->status().ok();
        if (!fOk)
            strError = it->status().ToString();
        delete it;
        return fOk ? TXDB_READ_NOT_FOUND : TXDB_READ_ERROR;
    }
    if (it->key().compare(leveldb::Slice(strKey)) != 0)
    {
        delete it;
        return TXDB_READ_NOT_FOUND;
    }
    const leveldb::Slice value = it->value();
    const TxDBReadStatus status = ParseDAGSkippedTxValue(
        value.data(), value.size(), hashBlock, hashMerkleRoot,
        nBlockTxCount, NULL, strError);
    delete it;
    return status;
}

TxDBReadStatus CTxDB::ReadDAGSkippedTxsStatus(
    const CBlock& block, std::set<uint256>& setSkipped,
    std::string& strError)
{
    setSkipped.clear();
    strError.clear();
    if (block.vtx.empty() || block.hashMerkleRoot == 0 ||
        block.BuildMerkleTree() != block.hashMerkleRoot ||
        block.vtx.size() > DAG_ACTIVE_SET_MAX_TXS)
    {
        strError = "block data is invalid while reading its DAG active set";
        return TXDB_READ_ERROR;
    }

    const uint256 hashBlock = block.GetHash();
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey << make_pair(string("dagactiveset"), hashBlock);
    uint32_t nBlockTxCount = 0;
    TxDBReadStatus status = TXDB_READ_ERROR;
    std::string strBatchValue;
    if (activeBatch)
    {
        try
        {
            bool fDeleted = false;
            if (ScanBatch(ssKey, &strBatchValue, &fDeleted))
            {
                if (fDeleted)
                    return TXDB_READ_NOT_FOUND;
                status = ParseDAGSkippedTxValue(
                    strBatchValue.data(), strBatchValue.size(), hashBlock,
                    block.hashMerkleRoot, nBlockTxCount, &setSkipped,
                    strError);
            }
        }
        catch (const std::exception& e)
        {
            strError = e.what();
            return TXDB_READ_ERROR;
        }
    }
    if (status == TXDB_READ_ERROR && strBatchValue.empty())
    {
        leveldb::Iterator* it = pdb->NewIterator(leveldb::ReadOptions());
        if (!it)
        {
            strError = "could not create DAG active-set iterator";
            return TXDB_READ_ERROR;
        }
        const std::string strKey = ssKey.str();
        it->Seek(strKey);
        if (!it->Valid())
        {
            const bool fOk = it->status().ok();
            if (!fOk)
                strError = it->status().ToString();
            delete it;
            return fOk ? TXDB_READ_NOT_FOUND : TXDB_READ_ERROR;
        }
        if (it->key().compare(leveldb::Slice(strKey)) != 0)
        {
            delete it;
            return TXDB_READ_NOT_FOUND;
        }
        const leveldb::Slice value = it->value();
        status = ParseDAGSkippedTxValue(
            value.data(), value.size(), hashBlock, block.hashMerkleRoot,
            nBlockTxCount, &setSkipped, strError);
        delete it;
    }
    if (status != TXDB_READ_FOUND)
        return status;
    if (nBlockTxCount != block.vtx.size())
    {
        setSkipped.clear();
        strError = "DAG active-set block transaction count mismatch";
        return TXDB_READ_ERROR;
    }

    std::map<uint256, const CTransaction*> mapBlockTx;
    for (std::vector<CTransaction>::const_iterator it = block.vtx.begin();
         it != block.vtx.end(); ++it)
    {
        const uint256 hashTx = it->GetHash();
        if (!mapBlockTx.insert(std::make_pair(hashTx, &*it)).second)
        {
            setSkipped.clear();
            strError = "DAG active-set block contains duplicate transaction hashes";
            return TXDB_READ_ERROR;
        }
    }
    for (std::set<uint256>::const_iterator it = setSkipped.begin();
         it != setSkipped.end(); ++it)
    {
        std::map<uint256, const CTransaction*>::const_iterator mi =
            mapBlockTx.find(*it);
        if (mi == mapBlockTx.end() || mi->second->IsCoinBase() ||
            mi->second->IsCoinStake())
        {
            setSkipped.clear();
            strError = "DAG active set names an absent or mandatory transaction";
            return TXDB_READ_ERROR;
        }
    }
    return TXDB_READ_FOUND;
}

bool CTxDB::WriteDAGSkippedTxs(
    const CBlock& block, const std::set<uint256>& setSkipped,
    std::string& strError)
{
    strError.clear();
    if (block.vtx.empty() || block.hashMerkleRoot == 0 ||
        block.BuildMerkleTree() != block.hashMerkleRoot ||
        block.vtx.size() > DAG_ACTIVE_SET_MAX_TXS ||
        setSkipped.size() > block.vtx.size())
    {
        strError = "cannot persist an invalid/unbounded DAG active set";
        return false;
    }

    std::map<uint256, const CTransaction*> mapBlockTx;
    for (std::vector<CTransaction>::const_iterator it = block.vtx.begin();
         it != block.vtx.end(); ++it)
    {
        const uint256 hashTx = it->GetHash();
        if (!mapBlockTx.insert(std::make_pair(hashTx, &*it)).second)
        {
            strError = "cannot persist a DAG active set for duplicate transaction hashes";
            return false;
        }
    }
    for (std::set<uint256>::const_iterator it = setSkipped.begin();
         it != setSkipped.end(); ++it)
    {
        std::map<uint256, const CTransaction*>::const_iterator mi =
            mapBlockTx.find(*it);
        if (mi == mapBlockTx.end() || mi->second->IsCoinBase() ||
            mi->second->IsCoinStake())
        {
            strError = "cannot persist an absent/mandatory skipped transaction";
            return false;
        }
    }

    CDAGSkippedTxDiskRecord record;
    record.nSchema = DAG_ACTIVE_SET_SCHEMA;
    record.nBlockTxCount = (uint32_t)block.vtx.size();
    record.hashMerkleRoot = block.hashMerkleRoot;
    record.vSkipped.assign(setSkipped.begin(), setSkipped.end());
    record.hashDigest = ComputeDAGSkippedTxDigest(
        block.GetHash(), record.hashMerkleRoot, record.nBlockTxCount,
        record.vSkipped);
    return Write(make_pair(string("dagactiveset"), block.GetHash()),
                 record);
}

TxDBReadStatus CTxDB::ReadDAGActiveSetBest(uint256& hashBest)
{
    hashBest = 0;
    CDAGActiveSetBestRecord record;
    const TxDBReadStatus status = ReadFixedExactStatusBounded(
        string("dagactivesetbest"), record);
    if (status != TXDB_READ_FOUND)
        return status;
    if (!record.IsValid())
        return TXDB_READ_ERROR;
    hashBest = record.hashBest;
    return TXDB_READ_FOUND;
}

bool CTxDB::WriteDAGActiveSetBest(const uint256& hashBest)
{
    if (hashBest == 0)
        return false;
    CDAGActiveSetBestRecord record;
    record.nSchema = DAG_ACTIVE_SET_SCHEMA;
    record.hashBest = hashBest;
    record.hashDigest = record.GetDigest();
    return Write(string("dagactivesetbest"), record);
}

TxDBReadStatus CTxDB::ReadDAGActiveSetBuild(
    CDAGActiveSetBuildRecord& record)
{
    record = CDAGActiveSetBuildRecord();
    const TxDBReadStatus status = ReadFixedExactStatusBounded(
        string("dagactivesetbuild"), record);
    if (status != TXDB_READ_FOUND)
        return status;
    return record.IsValid() ? TXDB_READ_FOUND : TXDB_READ_ERROR;
}

bool CTxDB::WriteDAGActiveSetBuild(CDAGActiveSetBuildRecord record)
{
    record.nSchema = DAG_ACTIVE_SET_SCHEMA;
    record.hashDigest = record.GetDigest();
    return record.IsValid() &&
           Write(string("dagactivesetbuild"), record);
}

bool CTxDB::EraseDAGActiveSetBuild()
{
    return Erase(string("dagactivesetbuild"));
}

bool CTxDB::ReadBestInvalidTrust(CBigNum& bnBestInvalidTrust)
{
    return Read(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CTxDB::WriteBestInvalidTrust(CBigNum bnBestInvalidTrust)
{
    return Write(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CTxDB::ReadSyncCheckpoint(uint256& hashCheckpoint)
{
    return Read(string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CTxDB::WriteSyncCheckpoint(uint256 hashCheckpoint)
{
    return Write(string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CTxDB::ReadCheckpointPubKey(string& strPubKey)
{
    return Read(string("strCheckpointPubKey"), strPubKey);
}

bool CTxDB::WriteCheckpointPubKey(const string& strPubKey)
{
    return Write(string("strCheckpointPubKey"), strPubKey);
}

static CBlockIndex *InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
        return NULL;

    // Return existing
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool CTxDB::LoadBlockIndex()
{
    {
        // Runs even when an earlier BDB-import pass populated mapBlockIndex, so legacy finality
        // values are stamped whichever loader ran first.
        std::string strFinalityMigrationError;
        if (!MigrateFinalityDiskRecords(strFinalityMigrationError))
            return error("CTxDB::LoadBlockIndex() : FATAL -- finality disk envelope "
                         "migration failed: %s. Recover with -reindex/resync.",
                         strFinalityMigrationError.c_str());
    }
    if (mapBlockIndex.size() > 0) {
        // Already loaded once in this session. It can happen during migration
        // from BDB.
        return true;
    }
    // The block index is an in-memory structure that maps hashes to on-disk
    // locations where the contents of the block can be found. Here, we scan it
    // out of the DB and into mapBlockIndex.
    leveldb::Iterator *iterator = pdb->NewIterator(leveldb::ReadOptions());
    // Seek to start key.
    CDataStream ssStartKey(SER_DISK, CLIENT_VERSION);
    ssStartKey << make_pair(string("blockindex"), uint256(0));
    iterator->Seek(ssStartKey.str());
    // Now read each entry.
    while (iterator->Valid())
    {
        // Unpack keys and values.
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.write(iterator->key().data(), iterator->key().size());
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.write(iterator->value().data(), iterator->value().size());
        string strType;
        ssKey >> strType;
        // Did we reach the end of the data to read?
        if (fRequestShutdown || strType != "blockindex")
            break;
        CDiskBlockIndex diskindex;
        ssValue >> diskindex;

        uint256 blockHash = diskindex.GetBlockHash();

        // Construct block index object
        CBlockIndex* pindexNew    = InsertBlockIndex(blockHash);
        pindexNew->pprev          = InsertBlockIndex(diskindex.hashPrev);
        pindexNew->pnext          = InsertBlockIndex(diskindex.hashNext);
        pindexNew->nFile          = diskindex.nFile;
        pindexNew->nBlockPos      = diskindex.nBlockPos;
        pindexNew->nHeight        = diskindex.nHeight;
        pindexNew->nMint          = diskindex.nMint;
        pindexNew->nMoneySupply   = diskindex.nMoneySupply;
        pindexNew->nFlags         = diskindex.nFlags;
        pindexNew->nStakeModifier = diskindex.nStakeModifier;
        pindexNew->prevoutStake   = diskindex.prevoutStake;
        pindexNew->nStakeTime     = diskindex.nStakeTime;
        pindexNew->hashProof      = diskindex.hashProof;
        pindexNew->nVersion       = diskindex.nVersion;
        pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
        pindexNew->nTime          = diskindex.nTime;
        pindexNew->nBits          = diskindex.nBits;
        pindexNew->nNonce         = diskindex.nNonce;
        // nSize populated later during chain trust calculation pass (not serialized for backward compat)

        // Watch for genesis block
        if (pindexGenesisBlock == NULL && blockHash == GetGenesisBlockHash())
            pindexGenesisBlock = pindexNew;

        if (!pindexNew->CheckIndex()) {
            delete iterator;
            return error("LoadBlockIndex() : CheckIndex failed at %d", pindexNew->nHeight);
        }

        // NovaCoin: build setStakeSeen
        if (pindexNew->IsProofOfStake())
            setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));

        iterator->Next();
    }
    delete iterator;

    if (fRequestShutdown)
        return true;

    // Calculate nChainTrust
    vector<pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    for (const PAIRTYPE(uint256, CBlockIndex*)& item : mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for (const PAIRTYPE(int, CBlockIndex*)& item : vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;
        pindex->nChainTrust = (pindex->pprev ? pindex->pprev->nChainTrust : 0) + pindex->GetBlockTrust();
        // NovaCoin: calculate stake modifier checksum
        pindex->nStakeModifierChecksum = GetStakeModifierChecksum(pindex);
        if (!CheckStakeModifierCheckpoints(pindex->nHeight, pindex->nStakeModifierChecksum))
            return error("CTxDB::LoadBlockIndex() : Failed stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindex->nHeight, pindex->nStakeModifier);
    }

    // Load DAG links; ordering is deferred to init.cpp for incremental support
    if (!g_dagManager.LoadDAGLinks(*this))
        return error("CTxDB::LoadBlockIndex() : FATAL -- DAG-link load failed (corrupt or "
                     "incomplete DAG persistence). Recover with -reindex/resync.");
    // Fail closed: a corrupt or holed epoch-state set would diverge the finalized-height
    // anchor from the network.
    if (!g_dagManager.LoadEpochStates(*this))
        return error("CTxDB::LoadBlockIndex() : FATAL -- epoch-state load failed (corrupt or holed "
                     "epoch-state records -> divergent deterministic finalized-height anchor). "
                     "Recover by removing the chain database (keep wallet.dat) and resyncing, or -reindex.");
    PinFinalityCommitteeConstants(); // before rotations load
    {
        // Release gate (defense-in-depth): a mainnet node must never run with an empty finality
        // committee. If it did, private tally certificates would be accepted with NO M-of-N committee
        // authorization from FORK_HEIGHT_TALLY_GOVERNANCE onward (GetCommitteeForEpoch returns false ->
        // the signature check is skipped -> accept-all). Refuse to start rather than run unpinned; the
        // mainnet committee is pinned from constants in PinFinalityCommitteeConstants, so this only fires
        // if a build ships with an empty/invalid committee.
        extern bool fRegTest;
        extern bool fTestNet;
        std::vector<CPubKey> vChk; int nChkM = 0; uint256 hashChk;
        if (!fRegTest && !fTestNet &&
            !g_finalityTracker.GetCommitteeForEpoch(0, vChk, nChkM, hashChk))
            return error("LoadBlockIndex : FATAL -- mainnet finality committee is UNPINNED; refusing to "
                         "start (the M-of-N governance trust root would be absent). Pin the launch "
                         "committee in PinFinalityCommitteeConstants before shipping mainnet.");
    }
    if (!g_finalityTracker.LoadVotes(*this) ||
        !g_finalityTracker.LoadTallyShares(*this) ||
        !g_finalityTracker.LoadTallyCertificates(*this) ||
        !g_finalityTracker.LoadCommitteeRotations(*this))
        return error("CTxDB::LoadBlockIndex() : FATAL -- persisted finality vote/share/"
                     "certificate/rotation state is corrupt or incomplete. Recover with "
                     "-reindex/resync.");

    // Load hashBestChain pointer to end of best chain
    if (!ReadHashBestChain(hashBestChain))
    {
        if (pindexGenesisBlock == NULL)
            return true;
        return error("CTxDB::LoadBlockIndex() : hashBestChain not loaded");
    }
    if (!mapBlockIndex.count(hashBestChain))
        return error("CTxDB::LoadBlockIndex() : hashBestChain not found in the block index");
    pindexBest = mapBlockIndex[hashBestChain];
    nBestHeight = pindexBest->nHeight;
    nBestChainTrust = pindexBest->nChainTrust;

    printf("LoadBlockIndex(): hashBestChain=%s  height=%d  trust=%s  date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), nBestHeight, CBigNum(nBestChainTrust).ToString().c_str(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    // NovaCoin: load hashSyncCheckpoint
    if (!ReadSyncCheckpoint(Checkpoints::hashSyncCheckpoint))
        return error("CTxDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");
    printf("LoadBlockIndex(): synchronized checkpoint %s\n", Checkpoints::hashSyncCheckpoint.ToString().c_str());

    // Load bnBestInvalidTrust, OK if it doesn't exist
    CBigNum bnBestInvalidTrust;
    ReadBestInvalidTrust(bnBestInvalidTrust);
    nBestInvalidTrust = bnBestInvalidTrust.getuint256();

    // Verify blocks in the best chain
    int nCheckLevel = GetArg("-checklevel", 1);
    int nCheckDepth = GetArg( "-checkblocks", 2500);
    if (nCheckDepth == 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > nBestHeight)
        nCheckDepth = nBestHeight;
    printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CBlockIndex* pindexFork = NULL;
    map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
    for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
    {
        if (fRequestShutdown || pindex->nHeight < nBestHeight-nCheckDepth)
            break;
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("LoadBlockIndex() : block.ReadFromDisk failed");
        // check level 1: verify block validity
        // check level 7: verify block signature too
        if (nCheckLevel>0 && !block.CheckBlock(true, true, (nCheckLevel>6)))
        {
            printf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pindex->pprev;
        }
        // check level 2: verify transaction index validity
        if (nCheckLevel>1)
        {
            pair<unsigned int, unsigned int> pos = make_pair(pindex->nFile, pindex->nBlockPos);
            mapBlockPos[pos] = pindex;
            for (const CTransaction &tx : block.vtx)
            {
                uint256 hashTx = tx.GetHash();
                CTxIndex txindex;
                if (ReadTxIndex(hashTx, txindex))
                {
                    // check level 3: checker transaction hashes
                    if (nCheckLevel>2 || pindex->nFile != txindex.pos.nFile || pindex->nBlockPos != txindex.pos.nBlockPos)
                    {
                        // either an error or a duplicate transaction
                        CTransaction txFound;
                        if (!txFound.ReadFromDisk(txindex.pos))
                        {
                            printf("LoadBlockIndex() : *** cannot read mislocated transaction %s\n", hashTx.ToString().c_str());
                            pindexFork = pindex->pprev;
                        }
                        else
                            if (txFound.GetHash() != hashTx) // not a duplicate tx
                            {
                                printf("LoadBlockIndex(): *** invalid tx position for %s\n", hashTx.ToString().c_str());
                                pindexFork = pindex->pprev;
                            }
                    }
                    // check level 4: check whether spent txouts were spent within the main chain
                    unsigned int nOutput = 0;
                    if (nCheckLevel>3)
                    {
                        for (const CDiskTxPos &txpos : txindex.vSpent)
                        {
                            if (!txpos.IsNull())
                            {
                                pair<unsigned int, unsigned int> posFind = make_pair(txpos.nFile, txpos.nBlockPos);
                                if (!mapBlockPos.count(posFind))
                                {
                                    printf("LoadBlockIndex(): *** found bad spend at %d, hashBlock=%s, hashTx=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str(), hashTx.ToString().c_str());
                                    pindexFork = pindex->pprev;
                                }
                                // check level 6: check whether spent txouts were spent by a valid transaction that consume them
                                if (nCheckLevel>5)
                                {
                                    CTransaction txSpend;
                                    if (!txSpend.ReadFromDisk(txpos))
                                    {
                                        printf("LoadBlockIndex(): *** cannot read spending transaction of %s:%i from disk\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    }
                                    else if (!txSpend.CheckTransaction())
                                    {
                                        printf("LoadBlockIndex(): *** spending transaction of %s:%i is invalid\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    }
                                    else
                                    {
                                        bool fFound = false;
                                        for (const CTxIn &txin : txSpend.vin)
                                            if (txin.prevout.hash == hashTx && txin.prevout.n == nOutput)
                                                fFound = true;
                                        if (!fFound)
                                        {
                                            printf("LoadBlockIndex(): *** spending transaction of %s:%i does not spend it\n", hashTx.ToString().c_str(), nOutput);
                                            pindexFork = pindex->pprev;
                                        }
                                    }
                                }
                            }
                            nOutput++;
                        }
                    }
                }
                // check level 5: check whether all prevouts are marked spent
                if (nCheckLevel>4)
                {
                     for (const CTxIn &txin : tx.vin)
                     {
                          CTxIndex txindex;
                          if (ReadTxIndex(txin.prevout.hash, txindex))
                              if (txindex.vSpent.size()-1 < txin.prevout.n || txindex.vSpent[txin.prevout.n].IsNull())
                              {
                                  printf("LoadBlockIndex(): *** found unspent prevout %s:%i in %s\n", txin.prevout.hash.ToString().c_str(), txin.prevout.n, hashTx.ToString().c_str());
                                  pindexFork = pindex->pprev;
                              }
                     }
                }
            }
        }
    }
    if (pindexFork && !fRequestShutdown)
    {
        // Reorg back to the fork
        printf("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->nHeight);
        CBlock block;
        if (!block.ReadFromDisk(pindexFork))
            return error("LoadBlockIndex() : block.ReadFromDisk failed");
        CTxDB txdb;
        block.SetBestChain(txdb, pindexFork);
    }

    return true;
}
