// Copyright (c) 2009-2012 The Bitcoin Developers.
// Authored by Google, Inc.
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LEVELDB_H
#define BITCOIN_LEVELDB_H

#include "main.h"
#include "dag.h"
#include "finality.h"
#include "ringsig.h"
#include "curvetree.h"

#include <map>
#include <set>
#include <string>
#include <vector>

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

enum TxDBReadStatus
{
    TXDB_READ_FOUND = 0,
    TXDB_READ_NOT_FOUND,
    TXDB_READ_ERROR
};

static const int SHIELDED_WALLET_RECOVERY_SCHEMA = 1;
static const int DAG_ACTIVE_SET_SCHEMA = 1;
static const int DAG_ACTIVE_SET_BUILD_REBUILD_SUFFIX = 1;
static const int DAG_ACTIVE_SET_BUILD_REPAIR_CANONICAL = 2;

// Crash-recovery outbox for the auxiliary shielded wallet.  This fixed-size
// record is written in the same LevelDB batch as the canonical best-chain
// transition.  No transaction or wire encoding depends on it.
class CShieldedWalletRecoveryRecord
{
public:
    int nSchema;
    uint256 hashOldTip;
    uint256 hashFork;
    uint256 hashNewTip;
    uint32_t nDisconnect;
    uint32_t nConnect;
    uint256 hashEffectPlan;

    CShieldedWalletRecoveryRecord()
        : nSchema(0), nDisconnect(0), nConnect(0) {}

    bool IsValid() const
    {
        if (nSchema != SHIELDED_WALLET_RECOVERY_SCHEMA ||
            hashNewTip == 0 || hashEffectPlan == 0 ||
            (nDisconnect == 0 && nConnect == 0))
            return false;
        if (nDisconnect == 0 && hashOldTip != hashFork)
            return false;
        if (nDisconnect > 0 && hashOldTip == 0)
            return false;
        if (hashOldTip == 0 && hashFork != 0)
            return false;
        if (nConnect == 0 && hashNewTip != hashFork)
            return false;
        return true;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSchema);
        READWRITE(hashOldTip);
        READWRITE(hashFork);
        READWRITE(hashNewTip);
        READWRITE(nDisconnect);
        READWRITE(nConnect);
        READWRITE(hashEffectPlan);
    )
};

// Durable progress of the chunked legacy active-set recovery: the marker advances in each
// chunk's batch, and the best-tip marker is written only once every DAG block is covered.
class CDAGActiveSetBuildRecord
{
public:
    int nSchema;
    int nMode;
    uint256 hashTargetBest;
    int nTargetHeight;
    uint256 hashTrustedBase;
    int nTrustedBaseHeight;
    uint256 hashNextBlock;
    int nNextHeight;
    uint256 hashDigest;

    CDAGActiveSetBuildRecord()
        : nSchema(0), nMode(0), nTargetHeight(-1),
          nTrustedBaseHeight(-1), nNextHeight(-1) {}

    uint256 GetDigest() const
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("Innova/IDAG/ActiveSetBuild/v1");
        ss << nSchema << nMode << hashTargetBest << nTargetHeight;
        ss << hashTrustedBase << nTrustedBaseHeight;
        ss << hashNextBlock << nNextHeight;
        return ss.GetHash();
    }

    bool IsValid() const
    {
        if (nSchema != DAG_ACTIVE_SET_SCHEMA ||
            (nMode != DAG_ACTIVE_SET_BUILD_REBUILD_SUFFIX &&
             nMode != DAG_ACTIVE_SET_BUILD_REPAIR_CANONICAL) ||
            hashTargetBest == 0 || nTargetHeight < 0 ||
            nTrustedBaseHeight < -1 ||
            nNextHeight < nTrustedBaseHeight ||
            nNextHeight > nTargetHeight)
            return false;
        if ((nTrustedBaseHeight < 0) != (hashTrustedBase == 0) ||
            (nNextHeight < 0) != (hashNextBlock == 0))
            return false;
        return hashDigest == GetDigest();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSchema);
        READWRITE(nMode);
        READWRITE(hashTargetBest);
        READWRITE(nTargetHeight);
        READWRITE(hashTrustedBase);
        READWRITE(nTrustedBaseHeight);
        READWRITE(hashNextBlock);
        READWRITE(nNextHeight);
        READWRITE(hashDigest);
    )
};

// Class that provides access to a LevelDB. Note that this class is frequently
// instantiated on the stack and then destroyed again, so instantiation has to
// be very cheap. Unfortunately that means, a CTxDB instance is actually just a
// wrapper around some global state.
//
// A LevelDB is a key/value store that is optimized for fast usage on hard
// disks. It prefers long read/writes to seeks and is based on a series of
// sorted key/value mapping files that are stacked on top of each other, with
// newer files overriding older files. A background thread compacts them
// together when too many files stack up.
//
// Learn more: http://code.google.com/p/leveldb/
class CTxDB
{
public:
    CTxDB(const char* pszMode="r+");
    ~CTxDB() {
        // Note that this is not the same as Close() because it deletes only
        // data scoped to this TxDB object.
        if (activeBatch)
            delete activeBatch;
    }

    // Destroys the underlying shared global state accessed by this TxDB.
    void Close();

private:
    leveldb::DB *pdb;  // Points to the global instance.

    // A batch stores up writes and deletes for atomic application. When this
    // field is non-NULL, writes/deletes go there instead of directly to disk.
    leveldb::WriteBatch *activeBatch;
    leveldb::Options options;
    bool fReadOnly;
    int nVersion;

    // Stage deletion of every raw key whose serialized leading string equals strPrefix.
    // Schema migrations only, inside an existing DB transaction.
    bool EraseSerializedStringKeyPrefix(const std::string& strPrefix,
                                        std::string& strError);

protected:
    // Returns true and sets (value,false) if activeBatch contains the given key
    // or leaves value alone and sets deleted = true if activeBatch contains a
    // delete for it.
    bool ScanBatch(const CDataStream &key, std::string *value, bool *deleted) const;

    // Fetch one raw value without choosing its decoder, so migrated records pick the
    // envelope or legacy decoder before consuming untrusted bytes.
    template<typename K>
    TxDBReadStatus ReadRawValueStatus(const K& key, std::string& strValue)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        strValue.clear();

        bool fReadFromDb = true;
        if (activeBatch)
        {
            bool fDeleted = false;
            fReadFromDb = !ScanBatch(ssKey, &strValue, &fDeleted);
            if (fDeleted)
                return TXDB_READ_NOT_FOUND;
        }
        if (fReadFromDb)
        {
            const leveldb::Status status = pdb->Get(
                leveldb::ReadOptions(), ssKey.str(), &strValue);
            if (!status.ok())
            {
                if (status.IsNotFound())
                    return TXDB_READ_NOT_FOUND;
                printf("LevelDB raw-read failure: %s\n",
                       status.ToString().c_str());
                return TXDB_READ_ERROR;
            }
        }
        return TXDB_READ_FOUND;
    }

    template<typename K, typename T>
    bool Read(const K& key, T& value)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        std::string strValue;

        bool readFromDb = true;
        if (activeBatch) {
            // First we must search for it in the currently pending set of
            // changes to the db. If not found in the batch, go on to read disk.
            bool deleted = false;
            readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
            if (deleted) {
                return false;
            }
        }
        if (readFromDb) {
            leveldb::Status status = pdb->Get(leveldb::ReadOptions(),
                                              ssKey.str(), &strValue);
            if (!status.ok()) {
                if (status.IsNotFound())
                    return false;
                // Some unexpected error.
                printf("LevelDB read failure: %s\n", status.ToString().c_str());
                return false;
            }
        }
        // Unserialize value
        try {
            CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(),
                                SER_DISK, CLIENT_VERSION);
            ssValue >> value;
        }
        catch (std::exception &e) {
            printf("LevelDB deserialization failure: %s (value size=%zu)\n",
                   e.what(), strValue.size());
            return false;
        }
        return true;
    }

    // Persistence records used as consensus inputs must not accept a valid
    // prefix followed by unparsed bytes.  Keep the legacy Read() behavior for
    // older database records, and opt strict records into this exact decoder.
    template<typename K, typename T>
    TxDBReadStatus ReadExactStatus(const K& key, T& value)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        std::string strValue;

        bool readFromDb = true;
        if (activeBatch) {
            bool deleted = false;
            readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
            if (deleted)
                return TXDB_READ_NOT_FOUND;
        }
        if (readFromDb) {
            leveldb::Status status = pdb->Get(leveldb::ReadOptions(),
                                              ssKey.str(), &strValue);
            if (!status.ok()) {
                if (status.IsNotFound())
                    return TXDB_READ_NOT_FOUND;
                printf("LevelDB exact-read failure: %s\n",
                       status.ToString().c_str());
                return TXDB_READ_ERROR;
            }
        }

        try {
            CDataStream ssValue(strValue.data(),
                                strValue.data() + strValue.size(),
                                SER_DISK, CLIENT_VERSION);
            ssValue >> value;
            if (ssValue.size() != 0) {
                printf("LevelDB exact-read failure: trailing bytes "
                       "(value size=%zu, trailing=%zu)\n",
                       strValue.size(), ssValue.size());
                return TXDB_READ_ERROR;
            }
        }
        catch (std::exception &e) {
            printf("LevelDB exact deserialization failure: %s "
                   "(value size=%zu)\n", e.what(), strValue.size());
            return TXDB_READ_ERROR;
        }
        return TXDB_READ_FOUND;
    }

    template<typename K, typename T>
    bool ReadExact(const K& key, T& value)
    {
        return ReadExactStatus(key, value) == TXDB_READ_FOUND;
    }

    // Fixed-size markers are read through a borrowed iterator slice so a
    // corrupt local value cannot force an attacker-sized std::string copy.
    template<typename K, typename T>
    TxDBReadStatus ReadFixedExactStatusBounded(const K& key, T& value)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey << key;
        const size_t nExpected = ::GetSerializeSize(
            T(), SER_DISK, CLIENT_VERSION);
        std::string strBatchValue;
        if (activeBatch)
        {
            bool fDeleted = false;
            try
            {
                if (ScanBatch(ssKey, &strBatchValue, &fDeleted))
                {
                    if (fDeleted)
                        return TXDB_READ_NOT_FOUND;
                    if (strBatchValue.size() != nExpected)
                        return TXDB_READ_ERROR;
                    CDataStream ssValue(strBatchValue.data(),
                                        strBatchValue.data() +
                                            strBatchValue.size(),
                                        SER_DISK, CLIENT_VERSION);
                    ssValue >> value;
                    return ssValue.empty() ? TXDB_READ_FOUND
                                           : TXDB_READ_ERROR;
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
        const leveldb::Slice raw = it->value();
        if (raw.size() != nExpected)
        {
            delete it;
            return TXDB_READ_ERROR;
        }
        try
        {
            CDataStream ssValue(raw.data(), raw.data() + raw.size(),
                                SER_DISK, CLIENT_VERSION);
            ssValue >> value;
            if (!ssValue.empty())
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

    template<typename K, typename T>
    bool Write(const K& key, const T& value)
    {
        if (fReadOnly)
        {
            printf("ERROR: Write called on database in read-only mode\n");
            return false;
        }

        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.reserve(10000);
        ssValue << value;

        if (activeBatch) {
            activeBatch->Put(ssKey.str(), ssValue.str());
            return true;
        }
        leveldb::Status status = pdb->Put(leveldb::WriteOptions(), ssKey.str(), ssValue.str());
        if (!status.ok()) {
            printf("LevelDB write failure: %s\n", status.ToString().c_str());
            return false;
        }
        return true;
    }

    template<typename K>
    bool Erase(const K& key)
    {
        if (!pdb)
            return false;
        if (fReadOnly)
        {
            printf("ERROR: Erase called on database in read-only mode\n");
            return false;
        }

        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        if (activeBatch) {
            activeBatch->Delete(ssKey.str());
            return true;
        }
        leveldb::Status status = pdb->Delete(leveldb::WriteOptions(), ssKey.str());
        return (status.ok() || status.IsNotFound());
    }

    template<typename K>
    bool Exists(const K& key)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        std::string unused;

        if (activeBatch) {
            bool deleted = false;
            // The newest op in the active batch wins; never fall through to disk after a
            // staged delete.
            if (ScanBatch(ssKey, &unused, &deleted))
                return !deleted;
        }

        leveldb::Status status = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &unused);
        if (status.ok())
            return true;
        if (!status.IsNotFound())
            printf("LevelDB exists failure: %s\n", status.ToString().c_str());
        return false;
    }


public:
    bool TxnBegin();
    bool TxnCommit(bool fSync = false);
    bool IsTxnActive() const { return activeBatch != NULL; }
    bool TxnAbort()
    {
        delete activeBatch;
        activeBatch = NULL;
        return true;
    }

    leveldb::DB* GetInstance()
    {
        return pdb;
    }

    bool ReadVersion(int& nVersion)
    {
        nVersion = 0;
        return Read(std::string("version"), nVersion);
    }

    bool WriteVersion(int nVersion)
    {
        return Write(std::string("version"), nVersion);
    }

    bool WriteKeyImage(const ec_point& keyImage,
                       const CKeyImageSpent& keyImageSpent);
    bool ReadKeyImage(ec_point& keyImage, CKeyImageSpent& keyImageSpent);
    TxDBReadStatus ReadKeyImageStatus(const ec_point& keyImage,
                                      CKeyImageSpent& keyImageSpent);
    bool EraseKeyImage(const ec_point& keyImage);

    bool WriteAnonOutput(const CPubKey& pkCoin, const CAnonOutput& ao);
    bool ReadAnonOutput(CPubKey& pkCoin, CAnonOutput& ao);
    TxDBReadStatus ReadAnonOutputStatus(const CPubKey& pkCoin,
                                        CAnonOutput& ao);
    bool EraseAnonOutput(const CPubKey& pkCoin);

    bool WriteShieldedNullifier(const uint256& nullifier, const CShieldedNullifierSpent& nfs);
    bool ReadShieldedNullifier(const uint256& nullifier, CShieldedNullifierSpent& nfs);
    TxDBReadStatus ReadShieldedNullifierStatus(
        const uint256& nullifier, CShieldedNullifierSpent& nfs);
    bool EraseShieldedNullifier(const uint256& nullifier);

    // Full-chain IV5 spent-key membership in its own namespace, with the consuming height
    // so a reader anchored to a settled height can ask about that height.
    bool WritePrivacyVNextNullifier(const uint256& keyImage,
                                    const CPrivacyVNextNullifierSpent& spent);
    TxDBReadStatus ReadPrivacyVNextNullifierStatus(
        const uint256& keyImage, CPrivacyVNextNullifierSpent& spent);
    bool ErasePrivacyVNextNullifier(const uint256& keyImage);
    bool CountPrivacyVNextNullifiers(uint64_t& nCount,
                                    std::string& strError);

    // Exact full-chain membership of every IV5 output's nullifier base I = Hp(O).
    // Two leaves that share an owner key O share I, hence share the key image any
    // spend of either publishes: spending one marks both, so the second is value
    // that can never be moved again. Value never leaves the pool, so that value is
    // destroyed. A payload already refuses a repeated owner among its own outputs
    // and a proof refuses a repeated key image among its own inputs; this index is
    // what makes the same statement across transactions.
    bool WritePrivacyVNextOutputBase(const uint256& base,
                                     const CShieldedNullifierSpent& created);
    TxDBReadStatus ReadPrivacyVNextOutputBaseStatus(
        const uint256& base, CShieldedNullifierSpent& created);
    bool ErasePrivacyVNextOutputBase(const uint256& base);
    bool CountPrivacyVNextOutputBases(uint64_t& nCount,
                                      std::string& strError);

    // Collateralnode attestations, keyed on the key image the attestation published.
    //
    // Deliberately a separate namespace from the spent-key index: an attestation consumes
    // nothing, and a key image recorded as spent is a note that can never move again.
    // Registration is the derived predicate "watched and not yet spent", so a later spend
    // deregisters by itself and neither index ever has to be edited to undo the other.
    bool WritePrivacyVNextCollateral(
        const uint256& keyImage,
        const CPrivacyVNextCollateralAttestation& attested);
    TxDBReadStatus ReadPrivacyVNextCollateralStatus(
        const uint256& keyImage,
        CPrivacyVNextCollateralAttestation& attested);
    bool ErasePrivacyVNextCollateral(const uint256& keyImage);
    bool CountPrivacyVNextCollateral(uint64_t& nCount, std::string& strError);
    // Every stored attestation with the key image it was recorded under. Storage only:
    // which of these are still active at a height is a consensus predicate and lives with
    // the caller that knows the height.
    bool EnumeratePrivacyVNextCollateral(
        std::vector<std::pair<uint256, CPrivacyVNextCollateralAttestation> >& vOut,
        std::string& strError);

    bool WriteShieldedAnchor(const uint256& anchor);
    bool ReadShieldedAnchor(const uint256& anchor);
    TxDBReadStatus ReadShieldedAnchorStatus(const uint256& anchor);
    bool EraseShieldedAnchor(const uint256& anchor);
    bool WriteShieldedAnchorHeight(const uint256& anchor, int nHeight);
    bool ReadShieldedAnchorHeight(const uint256& anchor, int& nHeight);
    TxDBReadStatus ReadShieldedAnchorHeightStatus(const uint256& anchor,
                                                  int& nHeight);
    bool HasShieldedAnchorHeight(const uint256& anchor);
    bool EraseShieldedAnchorHeight(const uint256& anchor);

    bool WriteShieldedTree(const CIncrementalMerkleTree& tree);
    bool ReadShieldedTree(CIncrementalMerkleTree& tree);

    bool WriteShieldedTreeAtBlock(const uint256& blockHash, const CIncrementalMerkleTree& tree);
    bool ReadShieldedTreeAtBlock(const uint256& blockHash, CIncrementalMerkleTree& tree);
    bool EraseShieldedTreeAtBlock(const uint256& blockHash);

    bool WriteShieldedPoolValue(int64_t nValue);
    bool ReadShieldedPoolValue(int64_t& nValue);

    bool WriteShieldedCommitment(uint64_t nIndex, const CPedersenCommitment& commit);
    bool ReadShieldedCommitment(uint64_t nIndex, CPedersenCommitment& commit);
    bool EraseShieldedCommitment(uint64_t nIndex);
    bool ReadAllShieldedCommitments(std::vector<CPedersenCommitment>& vCommitments);
    // Proof construction only: include realCommit via its reverse index, then sample
    // the rest uniformly without replacement, up to LELANTUS_MAX_SET_SIZE.
    bool ReadBoundedLelantusCommitments(
        const CPedersenCommitment& realCommit,
        std::vector<CPedersenCommitment>& vCommitments,
        uint64_t& nRealIndex,
        std::string& strError);
    bool ReadShieldedCommitmentCount(uint64_t& nCount);
    bool WriteShieldedCommitmentCount(uint64_t nCount);
    bool EraseShieldedCommitmentCount();

    bool WriteShieldedCommitmentHeight(uint64_t nIndex, int nHeight);
    bool ReadShieldedCommitmentHeight(uint64_t nIndex, int& nHeight);
    bool HasShieldedCommitmentHeight(uint64_t nIndex);
    bool WriteShieldedCommitmentIndex(const std::vector<unsigned char>& vchCommitment, uint64_t nIndex);
    bool ReadShieldedCommitmentIndex(const std::vector<unsigned char>& vchCommitment, uint64_t& nIndex);
    bool HasShieldedCommitmentIndex(const std::vector<unsigned char>& vchCommitment);
    // Schema-V3 reverse-index journal.  Every active leaf has a predecessor
    // record, allowing duplicate Pedersen commitments to be disconnected
    // without erasing the older leaf's canonical lookup.
    bool InitializeShieldedCommitmentIndexV3(const uint256& hashGeneration,
                                              std::string& strError);
    bool ValidateShieldedCommitmentIndexV3(std::string& strError);
    bool PushShieldedCommitmentIndexV3(uint64_t nIndex,
                                       const CPedersenCommitment& commitment,
                                       std::string& strError);
    bool PopShieldedCommitmentIndexV3(uint64_t nIndex,
                                      const CPedersenCommitment& commitment,
                                      std::string& strError);
    bool ReadShieldedCommitmentIndexV3(const std::vector<unsigned char>& vchCommitment,
                                       uint64_t& nIndex);
    bool HasShieldedCommitmentIndexV3Schema();
    // Reverse-index persistence mode for a block transition: a valid marker keeps V3 across
    // reorgs below activation; missing markers at/after activation and malformed ones fail closed.
    bool ResolveShieldedCommitmentIndexV3Mode(int nCandidateHeight,
                                               int nActivationHeight,
                                               bool& fUseV3,
                                               std::string& strError);
    bool ClearShieldedCommitmentIndexV3(std::string& strError);
    // B2-e Phase 3c.4: erase the per-leaf height ('sch') + cv->index ('sci') entries on reorg, so a
    // disconnected block's leaves cannot leave stale data that mis-dates the owner-reclaim timelock.
    bool EraseShieldedCommitmentHeight(uint64_t nIndex);
    bool EraseShieldedCommitmentIndex(const std::vector<unsigned char>& vchCommitment);

    bool WriteCurveTree(const CCurveTree& tree);
    bool ReadCurveTree(CCurveTree& tree);
    bool WriteCurveTreeAtBlock(const uint256& blockHash, const CCurveTree& tree);
    bool ReadCurveTreeAtBlock(const uint256& blockHash, CCurveTree& tree);
    bool EraseCurveTreeAtBlock(const uint256& blockHash);
    bool WriteCurveTreeAtEpoch(int nEpoch, const CCurveTree& tree);
    bool ReadCurveTreeAtEpoch(int nEpoch, CCurveTree& tree);
    bool EraseCurveTreeAtEpoch(int nEpoch);

	bool ReadAddrIndex(uint160 addrHash, std::vector<uint256>& txHashes);
    bool WriteAddrIndex(uint160 addrHash, uint256 txHash);
    bool ReadTxIndex(uint256 hash, CTxIndex& txindex);
    TxDBReadStatus ReadTxIndexStatus(const uint256& hash,
                                     CTxIndex& txindex);
    bool UpdateTxIndex(uint256 hash, const CTxIndex& txindex);
    bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight);
    bool EraseTxIndex(const CTransaction& tx);
    bool ContainsTx(uint256 hash);
    bool ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(uint256 hash, CTransaction& tx);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx);
    bool WriteBlockIndex(const CDiskBlockIndex& blockindex);
    bool EraseBlockIndex(const uint256& blockhash);
    bool ReadHashBestChain(uint256& hashBestChain);
    bool WriteHashBestChain(uint256 hashBestChain);
    TxDBReadStatus ReadShieldedWalletRecoveryStatus(
        CShieldedWalletRecoveryRecord& record);
    bool WriteShieldedWalletRecovery(
        const CShieldedWalletRecoveryRecord& record);
    // Atomically erase the recovery outbox only when its exact fixed record
    // still matches the caller's successfully replayed transition.  The
    // caller must make auxiliary Berkeley DB effects durable first.
    bool AcknowledgeShieldedWalletRecovery(
        const CShieldedWalletRecoveryRecord& expected);
    bool EraseShieldedWalletRecovery();
    TxDBReadStatus ReadDAGSkippedTxsStatus(
        const CBlock& block, std::set<uint256>& setSkipped,
        std::string& strError);
    TxDBReadStatus ReadDAGSkippedTxMetadataStatus(
        const uint256& hashBlock, const uint256& hashMerkleRoot,
        uint32_t& nBlockTxCount, std::string& strError);
    bool WriteDAGSkippedTxs(const CBlock& block,
                            const std::set<uint256>& setSkipped,
                            std::string& strError);
    TxDBReadStatus ReadDAGActiveSetBest(uint256& hashBest);
    bool WriteDAGActiveSetBest(const uint256& hashBest);
    TxDBReadStatus ReadDAGActiveSetBuild(
        CDAGActiveSetBuildRecord& record);
    bool WriteDAGActiveSetBuild(CDAGActiveSetBuildRecord record);
    bool EraseDAGActiveSetBuild();
    bool ReadHashBestHeaderChain(uint256& hashBestChain);
    bool WriteHashBestHeaderChain(uint256 hashBestChain);
    bool ReadBestInvalidTrust(CBigNum& bnBestInvalidTrust);
    bool WriteBestInvalidTrust(CBigNum bnBestInvalidTrust);
    bool ReadSyncCheckpoint(uint256& hashCheckpoint);
    bool WriteSyncCheckpoint(uint256 hashCheckpoint);
    bool ReadCheckpointPubKey(std::string& strPubKey);
    bool WriteCheckpointPubKey(const std::string& strPubKey);
    bool LoadBlockIndex();

    // DAG link persistence
    bool WriteDAGLinks(const uint256& hash, const CBlockDAGData& data);
    bool ReadDAGLinks(const uint256& hash, CBlockDAGData& data);
    bool EraseDAGLinks(const uint256& hash);
    bool IterateDAGLinks(std::map<uint256, CBlockDAGData>& mapOut);

    // Epoch state persistence
    bool WriteEpochState(int nEpoch, const CEpochState& state);
    bool ReadEpochState(int nEpoch, CEpochState& state);
    // Whether the record exists at all, without decoding it: separates a record the
    // chain has not written from one this node cannot read.
    TxDBReadStatus ProbeEpochState(int nEpoch);
    bool EraseEpochState(int nEpoch);
    bool IterateEpochStates(std::map<int, CEpochState>& mapOut);
    bool IterateCurveTreeEpochs(std::map<int, CCurveTree>& mapOut);
    bool WriteDAGCleanHeight(int nHeight);
    bool ReadDAGCleanHeight(int& nHeight);
    /** Exclusive lower bound of retained DAG vertices; records below it are absent by design. */
    bool WriteDAGPruneBoundary(int nHeight);
    bool ReadDAGPruneBoundary(int& nHeight);
    bool IsReadOnly() const { return fReadOnly; }
    bool WriteEpochStateSchema(int nVersion);
    bool ReadEpochStateSchema(int& nVersion);
    bool HasEpochStateSchema();

    // IV5 tree store. A derived index of the finalized IV5 tree, rebuildable from the
    // chain, held so a membership witness can be read by leaf index instead of replaying
    // every leaf. Not consensus state: the epoch state's root remains the authority.
    bool WritePrivacyVNextTreeLeaf(uint64_t nIndex,
                                   const std::vector<unsigned char>& vchLeaf);
    bool ReadPrivacyVNextTreeLeaf(uint64_t nIndex, std::vector<unsigned char>& vchLeaf);
    bool ErasePrivacyVNextTreeLeaf(uint64_t nIndex);
    bool WritePrivacyVNextTreeNode(int nLevel, uint64_t nIndex,
                                   const std::vector<unsigned char>& vchPoint);
    bool ReadPrivacyVNextTreeNode(int nLevel, uint64_t nIndex,
                                  std::vector<unsigned char>& vchPoint);
    bool ErasePrivacyVNextTreeNode(int nLevel, uint64_t nIndex);
    bool WritePrivacyVNextTreeStoreSize(uint64_t nSize);
    bool ReadPrivacyVNextTreeStoreSize(uint64_t& nSize);

    bool WritePrivacyVNextPoolValue(int64_t nValue);
    TxDBReadStatus ReadPrivacyVNextPoolValueStatus(int64_t& nValue);

    // IDAG finality vote persistence
    bool WriteFinalityVote(const uint256& nullifier, const CFinalityVote& vote);
    bool ReadFinalityVote(const uint256& nullifier, CFinalityVote& vote);
    bool EraseFinalityVote(const uint256& nullifier);
    bool IterateFinalityVotes(std::map<uint256, CFinalityVote>& mapOut);
    bool ReadFinalityDiskEnvelopeGeneration(int& nGeneration);
    bool MigrateFinalityDiskRecords(std::string& strError);
    bool WriteFinalityTallyShare(const uint256& hashShare, const CFinalityTallyShare& share);
    bool ReadFinalityTallyShare(const uint256& hashShare, CFinalityTallyShare& share);
    bool EraseFinalityTallyShare(const uint256& hashShare);
    bool IterateFinalityTallyShares(std::map<uint256, CFinalityTallyShare>& mapOut);
    bool WriteFinalityTallyCertificate(const uint256& hashCert, const CFinalityTallyCertificate& cert);
    bool ReadFinalityTallyCertificate(const uint256& hashCert, CFinalityTallyCertificate& cert);
    bool EraseFinalityTallyCertificate(const uint256& hashCert);
    bool IterateFinalityTallyCertificates(std::map<uint256, CFinalityTallyCertificate>& mapOut);
    // Per-block connected-carrier indexes (block hash -> carried vote-nullifier /
    // tally-share-hash / tally-certificate-hash lists). Written on connect, erased
    // on disconnect; reloaded at startup so the finality connected-set bookkeeping
    // is restart-deterministic.
    bool WriteFinalityConnectedVoteBlock(const uint256& hashBlock, const std::vector<uint256>& vNullifiers);
    bool EraseFinalityConnectedVoteBlock(const uint256& hashBlock);
    bool IterateFinalityConnectedVoteBlocks(std::map<uint256, std::vector<uint256> >& mapOut);
    // F2 note votes, keyed by vote hash, plus their per-block carrier index. A tag can
    // legitimately name two distinct objects (an equivocation), so the vote hash rather
    // than the tag is what identifies a stored record.
    bool WriteNoteFinalityVote(const uint256& hashVote, const CNoteFinalityVote& vote);
    bool ReadNoteFinalityVote(const uint256& hashVote, CNoteFinalityVote& vote);
    bool EraseNoteFinalityVote(const uint256& hashVote);
    bool IterateNoteFinalityVotes(std::map<uint256, CNoteFinalityVote>& mapOut);
    bool WriteFinalityConnectedNoteVoteBlock(const uint256& hashBlock, const std::vector<uint256>& vVoteHashes);
    bool EraseFinalityConnectedNoteVoteBlock(const uint256& hashBlock);
    bool IterateFinalityConnectedNoteVoteBlocks(std::map<uint256, std::vector<uint256> >& mapOut);
    bool WriteFinalityConnectedShareBlock(const uint256& hashBlock, const std::vector<uint256>& vShareHashes);
    bool EraseFinalityConnectedShareBlock(const uint256& hashBlock);
    bool IterateFinalityConnectedShareBlocks(std::map<uint256, std::vector<uint256> >& mapOut);
    bool WriteFinalityConnectedCertBlock(const uint256& hashBlock, const std::vector<uint256>& vCertHashes);
    bool EraseFinalityConnectedCertBlock(const uint256& hashBlock);
    bool IterateFinalityConnectedCertBlocks(std::map<uint256, std::vector<uint256> >& mapOut);

private:
    bool LoadBlockIndexGuts();
};

void InitIBDBatching();
void FlushIBDBatch();

#endif // BITCOIN_DB_H
