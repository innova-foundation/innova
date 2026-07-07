// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <map>

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
    options.block_cache = leveldb::NewLRUCache(nCacheSizeMB * 1048576);
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
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
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);

    init_blockindex(options); // Init directory
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

            init_blockindex(options, true); // Remove directory and create new database
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
    delete txdb;
    txdb = pdb = NULL;
    delete options.filter_policy;
    options.filter_policy = NULL;
    delete options.block_cache;
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

bool CTxDB::TxnCommit()
{
    if (!activeBatch)
        return false;

    leveldb::WriteOptions writeOptions;
    if (IsInitialBlockDownload() && nIBDBatchSize > 0)
    {
        writeOptions.sync = false;
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

bool CTxDB::WriteKeyImage(ec_point& keyImage, CKeyImageSpent& keyImageSpent)
{
    return Write(make_pair(string("ki"), keyImage), keyImageSpent);
};

bool CTxDB::ReadKeyImage(ec_point& keyImage, CKeyImageSpent& keyImageSpent)
{
    return Read(make_pair(string("ki"), keyImage), keyImageSpent);
};

bool CTxDB::EraseKeyImage(ec_point& keyImage)
{
    return Erase(make_pair(string("ki"), keyImage));
}

bool CTxDB::WriteAnonOutput(CPubKey& pkCoin, CAnonOutput& ao)
{
    return Write(make_pair(string("ao"), pkCoin), ao);
};

bool CTxDB::ReadAnonOutput(CPubKey& pkCoin, CAnonOutput& ao)
{
    return Read(make_pair(string("ao"), pkCoin), ao);
};

bool CTxDB::EraseAnonOutput(CPubKey& pkCoin)
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

bool CTxDB::EraseShieldedNullifier(const uint256& nullifier)
{
    return Erase(make_pair(string("sn"), nullifier));
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

bool CTxDB::WriteShieldedTree(const CIncrementalMerkleTree& tree)
{
    return Write(string("st"), tree);
}

bool CTxDB::ReadShieldedTree(CIncrementalMerkleTree& tree)
{
    return Read(string("st"), tree);
}

bool CTxDB::WriteShieldedTreeAtBlock(const uint256& blockHash, const CIncrementalMerkleTree& tree)
{
    return Write(make_pair(string("sb"), blockHash), tree);
}

bool CTxDB::ReadShieldedTreeAtBlock(const uint256& blockHash, CIncrementalMerkleTree& tree)
{
    return Read(make_pair(string("sb"), blockHash), tree);
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

bool CTxDB::WriteShieldedCommitmentCount(uint64_t nCount)
{
    return Write(string("scc"), nCount);
}

bool CTxDB::ReadShieldedCommitmentCount(uint64_t& nCount)
{
    return Read(string("scc"), nCount);
}

bool CTxDB::WriteShieldedCommitmentHeight(uint64_t nIndex, int nHeight)
{
    return Write(make_pair(string("sch"), nIndex), nHeight);
}

bool CTxDB::ReadShieldedCommitmentHeight(uint64_t nIndex, int& nHeight)
{
    return Read(make_pair(string("sch"), nIndex), nHeight);
}

bool CTxDB::WriteShieldedCommitmentIndex(const std::vector<unsigned char>& vchCommitment, uint64_t nIndex)
{
    return Write(make_pair(string("sci"), vchCommitment), nIndex);
}

bool CTxDB::ReadShieldedCommitmentIndex(const std::vector<unsigned char>& vchCommitment, uint64_t& nIndex)
{
    return Read(make_pair(string("sci"), vchCommitment), nIndex);
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
        if (ReadShieldedCommitment(i, commit))
            vCommitments.push_back(commit);
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

// NOTE: this whole-struct Read requires the trailing nSerVersion byte (CEpochState serialization),
// so it MUST NOT be called on pre-versioning (legacy) records -- it would throw. It currently has
// zero callers; the sole runtime read path is IterateEpochStates, which reads tolerantly. If you wire
// this up, guarantee the DB has been migrated to V2 records first (see the epochstateschema marker).
bool CTxDB::ReadEpochState(int nEpoch, CEpochState& state)
{
    return Read(make_pair(string("epochstate"), nEpoch), state);
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
                try { ssValue >> state.nSerVersion; }
                catch (const std::exception&) { state.nSerVersion = 0; }
            }
            else
                state.nSerVersion = 0;
            mapOut[keyPair.second] = state;
        }
        catch (const std::exception& e)
        {
            // A persisted epoch-state record that fails to deserialize is a CONSENSUS ANCHOR silently
            // going missing -> a wrong GetDeterministicFinalizedHeight with nothing in the log. Never
            // swallow it quietly: this is especially important across a binary upgrade that changes the
            // CEpochState record format or activates the epoch-state fork on a node holding records
            // written under the old regime. Callers treat a missing epoch as not-yet-computed, so a
            // dropped record can diverge this node from the fleet; surface it so a reindex is triggered.
            printf("IterateEpochStates: WARNING dropped an epoch-state record that failed to deserialize "
                   "(rawkeylen=%d): %s -- deterministic finalized-height anchor may be INCOMPLETE; a "
                   "-reindex is recommended after any format/fork-regime change\n",
                   (int)strKey.size(), e.what());
        }

        it->Next();
    }

    delete it;
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

            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            CCurveTree tree;
            ssValue >> tree;
            mapOut[keyPair.second] = tree;
        }
        catch (const std::exception&)
        {
        }

        it->Next();
    }

    delete it;
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

bool CTxDB::WriteFinalityVote(const uint256& nullifier, const CFinalityVote& vote)
{
    return Write(make_pair(string("finalityvote"), nullifier), vote);
}

bool CTxDB::ReadFinalityVote(const uint256& nullifier, CFinalityVote& vote)
{
    return Read(make_pair(string("finalityvote"), nullifier), vote);
}

bool CTxDB::EraseFinalityVote(const uint256& nullifier)
{
    return Erase(make_pair(string("finalityvote"), nullifier));
}

bool CTxDB::IterateFinalityVotes(std::map<uint256, CFinalityVote>& mapOut)
{
    mapOut.clear();
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

            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            CFinalityVote vote;
            ssValue >> vote;
            mapOut[keyPair.second] = vote;
        }
        catch (const std::exception&)
        {
            // Skip malformed entries.
        }

        it->Next();
    }

    delete it;
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

bool CTxDB::IterateFinalityTallyShares(std::map<uint256, CFinalityTallyShare>& mapOut)
{
    mapOut.clear();
    leveldb::DB* db = GetInstance();
    if (!db)
        return false;

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("finalityshare");
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

            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            CFinalityTallyShare share;
            ssValue >> share;
            mapOut[keyPair.second] = share;
        }
        catch (const std::exception&)
        {
            // Skip malformed entries.
        }

        it->Next();
    }

    delete it;
    return true;
}

bool CTxDB::WriteFinalityTallyCertificate(const uint256& hashCert, const CFinalityTallyCertificate& cert)
{
    return Write(make_pair(string("finalitycert"), hashCert), cert);
}

bool CTxDB::ReadFinalityTallyCertificate(const uint256& hashCert, CFinalityTallyCertificate& cert)
{
    return Read(make_pair(string("finalitycert"), hashCert), cert);
}

bool CTxDB::EraseFinalityTallyCertificate(const uint256& hashCert)
{
    return Erase(make_pair(string("finalitycert"), hashCert));
}

bool CTxDB::IterateFinalityTallyCertificates(std::map<uint256, CFinalityTallyCertificate>& mapOut)
{
    mapOut.clear();
    leveldb::DB* db = GetInstance();
    if (!db)
        return false;

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("finalitycert");
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

            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            CFinalityTallyCertificate cert;
            ssValue >> cert;
            mapOut[keyPair.second] = cert;
        }
        catch (const std::exception&)
        {
            // Skip malformed entries.
        }

        it->Next();
    }

    delete it;
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
    mapOut.clear();
    leveldb::DB* db = GetInstance();
    if (!db)
        return false;

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("finalityconnvb");
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

            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            std::vector<uint256> vNullifiers;
            ssValue >> vNullifiers;
            mapOut[keyPair.second] = vNullifiers;
        }
        catch (const std::exception&)
        {
            // Skip malformed entries.
        }

        it->Next();
    }

    delete it;
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
    mapOut.clear();
    leveldb::DB* db = GetInstance();
    if (!db)
        return false;

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("finalityconnsb");
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

            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            std::vector<uint256> vShareHashes;
            ssValue >> vShareHashes;
            mapOut[keyPair.second] = vShareHashes;
        }
        catch (const std::exception&)
        {
            // Skip malformed entries.
        }

        it->Next();
    }

    delete it;
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
    mapOut.clear();
    leveldb::DB* db = GetInstance();
    if (!db)
        return false;

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("finalityconncb");
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

            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            std::vector<uint256> vCertHashes;
            ssValue >> vCertHashes;
            mapOut[keyPair.second] = vCertHashes;
        }
        catch (const std::exception&)
        {
            // Skip malformed entries.
        }

        it->Next();
    }

    delete it;
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
    mapOut.clear();
    leveldb::DB* db = GetInstance();
    if (!db)
        return false;

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("finalityrot");
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
            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            CFinalityCommitteeRotation rot;
            ssValue >> rot;
            mapOut[keyPair.second] = rot;
        }
        catch (const std::exception&) { /* skip malformed */ }
        it->Next();
    }
    delete it;
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
    mapOut.clear();
    leveldb::DB* db = GetInstance();
    if (!db)
        return false;

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("finalityconnrot");
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
            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            std::vector<int> vEffEpochs;
            ssValue >> vEffEpochs;
            mapOut[keyPair.second] = vEffEpochs;
        }
        catch (const std::exception&) { /* skip malformed */ }
        it->Next();
    }
    delete it;
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

            CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
            CBlockDAGData data;

            // DAGKNIGHT compatibility: deserialize core fields first, then try nInferredK
            ssValue >> data.vDAGParents;
            ssValue >> data.vDAGChildren;
            ssValue >> data.fBlue;
            ssValue >> data.nDAGScore;
            ssValue >> data.nDAGOrder;

            // nInferredK may not exist in legacy entries
            if (ssValue.size() > 0)
            {
                try { ssValue >> data.nInferredK; }
                catch (const std::exception&) { data.nInferredK = -1; }
            }
            else
            {
                data.nInferredK = -1;
            }

            mapOut[keyPair.second] = data;
        }
        catch (const std::exception&)
        {
            // Skip malformed entries
        }

        it->Next();
    }

    delete it;
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
    txindex.SetNull();
    return Read(make_pair(string("tx"), hash), txindex);
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
    g_dagManager.LoadDAGLinks(*this);
    g_dagManager.LoadEpochStates(*this);
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
    g_finalityTracker.LoadVotes(*this);
    g_finalityTracker.LoadTallyShares(*this);
    g_finalityTracker.LoadTallyCertificates(*this);
    g_finalityTracker.LoadCommitteeRotations(*this);

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
