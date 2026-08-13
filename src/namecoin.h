#include "db.h"
#include "txdb-leveldb.h"
#include "innovarpc.h"
#include "base58.h"
#include "main.h"
#include "hooks.h"

class CBitcoinAddress;
class CKeyStore;
struct NameIndexStats;

static const int NAMECOIN_TX_VERSION = 0x0333; //0x0333 is initial version
static const unsigned int MAX_NAME_LENGTH = 512;
static const unsigned int MAX_VALUE_LENGTH = 20*1024;
// Maximum rental term for a name operation, in days. Six months.
static const int MAX_RENTAL_DAYS = 180;
// Term bound before the v5 gate. Kept so historical name txs re-index to the same
// records; otherwise rebuilt and upgraded-in-place nodes would disagree on name state.
static const int MAX_RENTAL_DAYS_PRE_V5 = 100*365;
static const int OP_NAME_NEW = 0x01;
static const int OP_NAME_UPDATE = 0x02;
static const int OP_NAME_DELETE = 0x03;
static const unsigned int NAMEINDEX_CHAIN_SIZE = 1000;
// Bumped for the piecewise day->block conversion: stored nExpiresAt values from
// the flat 5760-blocks-per-day formula are not comparable with the new ones, so
// every node rebuilds rather than carrying a stale expiry across the upgrade.
static const int NAMEINDEX_CURSOR_SCHEMA = 2;
static const int NAMEINDEX_EFFECT_PROGRESS_SCHEMA = 1;
static const uint32_t NAMEINDEX_MAX_TRANSITION_EFFECTS = 1000000;
static const size_t NAMEINDEX_MAX_EFFECT_RECORD_ENTRIES = 1000000;

// Height at which IDNS name operations become active.
// Regtest/Testnet: active from genesis for easy testing.
// Mainnet: 1,200,000 (original Innova DNS launch height).
inline int GetIDNSReleaseHeight() {
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest || fTestNet) return 0;
    return 1200000;
}
#define RELEASE_HEIGHT (GetIDNSReleaseHeight())

// Term bound in force for a name op mined at nHeight. The v5 gate is the IDNS
// reset height, which is 0 off mainnet so clean chains carry the 180-day bound
// from genesis.
inline int GetMaxRentalDays(int nHeight)
{
    return nHeight >= FORK_HEIGHT_IDNS_RESET ? MAX_RENTAL_DAYS
                                             : MAX_RENTAL_DAYS_PRE_V5;
}

// Blocks a rental of nRentalDays buys starting at nStartHeight. Spacing changes at the
// DAG gate (15s -> 1s), so a term spanning the gate is converted piecewise.
int64_t NameRentalBlocks(int64_t nStartHeight, int64_t nRentalDays);

// Wall-clock seconds between two heights under the same piecewise spacing.
// Inverse of NameRentalBlocks; negative when nToHeight < nFromHeight.
int64_t NameBlocksToSeconds(int64_t nFromHeight, int64_t nToHeight);

class CNameIndex
{
public:
    CDiskTxPos txPos;
    int nHeight;
    int op;
    std::vector<unsigned char> vchValue;

    CNameIndex() : nHeight(0), op(0) {}

    CNameIndex(CDiskTxPos txPos, int nHeight, std::vector<unsigned char> vchValue) :
        txPos(txPos), nHeight(nHeight), vchValue(vchValue) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(txPos);
        READWRITE(nHeight);
        READWRITE(op);
        READWRITE(vchValue);
    )
};

// CNameRecord is all the data that is saved (in nameindex.dat) with associated name
class CNameRecord
{
public:
    std::vector<CNameIndex> vtxPos;
    int nExpiresAt;
    int nLastActiveChainIndex;  // position in vtxPos of first tx in last active chain of name_new -> name_update -> name_update -> ....

    CNameRecord() : nExpiresAt(0), nLastActiveChainIndex(0) {}
    bool deleted()
    {
        if (!vtxPos.empty())
            return vtxPos.back().op == OP_NAME_DELETE;
        else return true;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vtxPos);
        READWRITE(nExpiresAt);
        READWRITE(nLastActiveChainIndex);
    )
};

// True when the IDNS reset has expired this record as of nAtHeight.
// The reset is a chain event: it expires names registered before its height,
// but only from that height onward.
bool NameResetExpired(const CNameRecord& nameRec, int nAtHeight);

// Recomputes nExpiresAt from the record's rental chain.
bool CalculateExpiresAt(CNameRecord& nameRec);

/**
 * Recovery cursor for the auxiliary name index.
 *
 * The name index lives in a separate Berkeley DB and therefore cannot share
 * the chain LevelDB transaction.  Callers update this cursor only after every
 * name mutation for a committed block succeeds.  A missing or non-matching
 * cursor means that the index may be partially applied and must be rebuilt
 * from the canonical chain before it is used.
 */
class CNameIndexCursor
{
public:
    int nSchema;
    int nResetHeight;
    int nHeight;
    uint256 hashBlock;

    CNameIndexCursor()
        : nSchema(0), nResetHeight(-1), nHeight(-1), hashBlock(0) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSchema);
        READWRITE(nResetHeight);
        READWRITE(nHeight);
        READWRITE(hashBlock);
    )
};

/**
 * Durable progress for an exact, caller-supplied name-index transition.
 *
 * This is intentionally a new auxiliary key rather than an extension of
 * CNameIndexCursor: deployed cursor bytes remain unchanged.  The progress
 * record is written in the same Berkeley DB transaction as the corresponding
 * name mutation and cursor, so an ambiguous commit can be retried safely.
 */
class CNameIndexEffectProgress
{
public:
    int nSchema;
    uint256 hashTransition;
    uint32_t nEffectCount;
    uint32_t nNextEffect;
    uint256 hashLastEffect;

    CNameIndexEffectProgress()
        : nSchema(0), nEffectCount(0), nNextEffect(0) {}

    bool IsValid() const
    {
        if (nSchema != NAMEINDEX_EFFECT_PROGRESS_SCHEMA ||
            hashTransition == 0 ||
            nEffectCount > NAMEINDEX_MAX_TRANSITION_EFFECTS ||
            nNextEffect > nEffectCount)
            return false;
        if (nEffectCount == 0)
            return nNextEffect == 0 && hashLastEffect == 0;
        return nNextEffect == 0 ? hashLastEffect == 0
                                : hashLastEffect != 0;
    }

    bool IsComplete() const
    {
        return IsValid() && nNextEffect == nEffectCount;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSchema);
        READWRITE(hashTransition);
        READWRITE(nEffectCount);
        READWRITE(nNextEffect);
        READWRITE(hashLastEffect);
    )
};

/**
 * One exact compare-and-swap mutation in a name transition.
 *
 * Both states are carried so connect and disconnect retries can distinguish
 * "not applied" from "already applied" without guessing from a transaction
 * tail.  The source transaction hash and direction are part of the effect
 * identity even when the before/after records happen to serialize similarly.
 */
class CNameIndexTransitionEffect
{
public:
    bool fConnect;
    uint256 hashSourceTx;
    std::vector<unsigned char> vchName;
    bool fBeforeExists;
    CNameRecord before;
    bool fAfterExists;
    CNameRecord after;

    CNameIndexTransitionEffect()
        : fConnect(false), fBeforeExists(false), fAfterExists(false) {}
};

/** Fully prepared effects for one block-level name-index transition. */
class CPreparedNameIndexTransition
{
public:
    bool fConnect;
    uint256 hashBlock;
    uint256 hashTransition;
    CNameIndexCursor cursorAfter;
    std::set<uint256> setDAGSkippedTxs;
    std::vector<CNameIndexTransitionEffect> vEffects;
    std::vector<std::pair<std::vector<unsigned char>, uint256> >
        vPendingCleanup;
    bool fAlreadyComplete;

    CPreparedNameIndexTransition()
        : fConnect(false), fAlreadyComplete(false) {}
};

// Deterministic, test-only fault locations inside the staging primitive.  They
// cannot be selected from RPC/configuration and have no production caller.
enum NameIndexEffectFault
{
    NAMEINDEX_EFFECT_FAULT_NONE = 0,
    NAMEINDEX_EFFECT_FAULT_AFTER_MUTATION,
    NAMEINDEX_EFFECT_FAULT_AFTER_CURSOR,
    NAMEINDEX_EFFECT_FAULT_AFTER_PROGRESS
};

class CNameDB : public CDB
{
public:
    CNameDB(const char* pszMode="r+") : CDB("innovanamesindex.dat", pszMode) {}

    bool WriteName(const std::vector<unsigned char>& name, const CNameRecord &rec)
    {
        return Write(make_pair(std::string("namei"), name), rec);
    }

    bool ReadName(const std::vector<unsigned char>& name, CNameRecord &rec)
    {
        bool ret = Read(make_pair(std::string("namei"), name), rec);
        if (!ret)
            return false;
        const int s = rec.vtxPos.size();
        if (s > 0 &&
            (rec.nLastActiveChainIndex < 0 ||
             rec.nLastActiveChainIndex >= s))
            return false;
        return true;
    }

    bool ExistsName(const std::vector<unsigned char>& name)
    {
        return Exists(make_pair(std::string("namei"), name));
    }

    bool EraseName(const std::vector<unsigned char>& name)
    {
        return Erase(make_pair(std::string("namei"), name));
    }

    bool WriteCursor(const CNameIndexCursor& cursor)
    {
        return Write(std::string("nameindex-cursor"), cursor);
    }

    bool ReadCursor(CNameIndexCursor& cursor);

    bool EraseCursor()
    {
        return Erase(std::string("nameindex-cursor"));
    }

    bool WriteEffectProgress(const CNameIndexEffectProgress& progress)
    {
        return progress.IsValid() &&
               Write(std::string("nameindex-effect-progress"), progress);
    }

    bool ReadEffectProgress(CNameIndexEffectProgress& progress);

    bool HasEffectProgress()
    {
        return Exists(std::string("nameindex-effect-progress"));
    }

    bool EraseEffectProgress()
    {
        return Erase(std::string("nameindex-effect-progress"));
    }

    bool HasActiveTxn() const
    {
        return activeTxn != NULL;
    }

    bool ScanNames(
            const std::vector<unsigned char>& vchName,
            unsigned int nMax,
            std::vector<
                std::pair<
                    std::vector<unsigned char>,
                    std::pair<CNameIndex, int>
                >
            >& nameScan
            );
    bool DumpToTextFile();
};

uint256 ComputeNameIndexTransitionEffectIdentity(
    const uint256& hashTransition, uint32_t nEffect,
    uint32_t nEffectCount, const CNameIndexTransitionEffect& effect,
    const CNameIndexCursor& cursorAfter);

uint256 ComputeNameIndexBlockTransitionIdentity(
    bool fConnect, const uint256& hashBlock,
    const CNameIndexCursor& cursorAfter,
    const std::set<uint256>& setDAGSkippedTxs = std::set<uint256>());

/**
 * Stage one exact name mutation, its compatible legacy cursor, and durable
 * progress in the caller's already-active CNameDB transaction.
 *
 * The caller must abort its transaction on false and commit it on true.  A
 * retry after a successful/ambiguous commit returns true with
 * fAlreadyAppliedOut set and does not append/pop the record again.
 */
bool StageNameIndexTransitionEffect(
    CNameDB& dbName, const uint256& hashTransition,
    uint32_t nEffect, uint32_t nEffectCount,
    const CNameIndexTransitionEffect& effect,
    const CNameIndexCursor& cursorAfter,
    bool& fAlreadyAppliedOut, std::string& strError,
    NameIndexEffectFault fault = NAMEINDEX_EFFECT_FAULT_NONE);

// True when connect would index this name tx at pindexBlock.  Block templates
// use it so they do not carry a name tx ConnectBlock will refuse to index.
// Non-name transactions are not judged and always return true.
bool NameTxWouldIndex(CTxDB& txdb, std::map<uint256, CTxIndex>& mapTestPool,
                      const CTransaction& tx, MapPrevTx& mapInputs,
                      const CBlockIndex* pindexBlock);

// Prepare exact connect effects in block order using the same historical
// validation/indexing semantics as CNamecoinHooks::ConnectBlock.
bool PrepareNameIndexConnectTransition(
    CTxDB& txdb, CBlockIndex* pindex,
    const std::set<uint256>& setDAGSkippedTxs,
    CPreparedNameIndexTransition& preparedOut,
    std::string& strError);

// Prepare exact disconnect effects in reverse transaction order.  The block
// index must name the block being disconnected; the cursor target is pprev.
bool PrepareNameIndexDisconnectTransition(
    const CBlock& block, const CBlockIndex* pindex,
    const std::set<uint256>& setDAGSkippedTxs,
    CPreparedNameIndexTransition& preparedOut,
    std::string& strError);

// Compatibility overloads for callers whose block has no DAG-skipped
// transactions.  Best-chain journal replay must use the explicit-set forms.
bool PrepareNameIndexConnectTransition(
    CTxDB& txdb, CBlockIndex* pindex,
    CPreparedNameIndexTransition& preparedOut,
    std::string& strError);
bool PrepareNameIndexDisconnectTransition(
    const CBlock& block, const CBlockIndex* pindex,
    CPreparedNameIndexTransition& preparedOut,
    std::string& strError);

// Commit all prepared effects, the compatible cursor and final progress in one
// Berkeley DB transaction.  nFaultEffect/fault are deterministic test-only
// injection controls; production callers use their defaults.
bool ApplyPreparedNameIndexTransition(
    const CPreparedNameIndexTransition& prepared,
    bool& fAlreadyAppliedOut, std::string& strError,
    uint32_t nFaultEffect = (uint32_t)-1,
    NameIndexEffectFault fault = NAMEINDEX_EFFECT_FAULT_NONE);

// Ready-to-call block-level disconnect entry point for best-chain replay.
bool ApplyNameIndexConnectBlock(
    CTxDB& txdb, CBlockIndex* pindex,
    const std::set<uint256>& setDAGSkippedTxs,
    std::string& strError);
bool ApplyNameIndexDisconnectBlock(
    const CBlock& block, const CBlockIndex* pindex,
    const std::set<uint256>& setDAGSkippedTxs,
    std::string& strError);

// Compatibility entry points for non-DAG callers.
bool ApplyNameIndexConnectBlock(
    CTxDB& txdb, CBlockIndex* pindex, std::string& strError);
bool ApplyNameIndexDisconnectBlock(
    const CBlock& block, const CBlockIndex* pindex,
    std::string& strError);

// Rebuild one canonical block using the exact connect-time DAG active set.
// Post-DAG callers fail closed when that persisted record is absent or corrupt;
// pre-DAG blocks retain the historical empty-skip-set behavior.
bool ApplyNameIndexRebuildBlock(
    CTxDB& txdb, const CBlock& block, CBlockIndex* pindex,
    std::string& strError);

// Marker-last API used by best-chain post-commit replay.  Pass NULL only for
// an empty chain; disconnect callers pass the newly committed predecessor.
bool CommitNameIndexTip(const CBlockIndex* pindexTip, std::string& strError);

// Strictly checks schema/reset era and exact canonical tip equality.
bool ValidateNameIndexTip(const CBlockIndex* pindexTip, std::string& strError);

// Recreates the index from canonical block data and writes the cursor last.
bool createNameIndexFile();

extern std::map<std::vector<unsigned char>, uint256> mapMyNames;
extern std::map<std::vector<unsigned char>, std::set<uint256> > mapNamePending;

int IndexOfNameOutput(const CTransaction& tx);
bool GetNameCurrentAddress(const std::vector<unsigned char> &vchName, CBitcoinAddress &address, std::string &error);
std::string stringFromVch(const std::vector<unsigned char> &vch);
std::vector<unsigned char> vchFromString(const std::string &str);
std::string nameFromOp(int op);

int64_t GetNameOpFee(const CBlockIndex* pindexBlock, const int nRentalDays, int op, const std::vector<unsigned char> &vchName, const std::vector<unsigned char> &vchValue);
CAmount GetNameOpFee2(const CBlockIndex* pindexBlock, const int nRentalDays, int op, const std::vector<unsigned char> &vchName, const std::vector<unsigned char> &vchValue);

struct NameTxInfo
{
    std::vector<unsigned char> vchName;
    std::vector<unsigned char> vchValue;
    int nRentalDays;
    int op;
    int nOut;
    std::string err_msg; //in case function that takes this as argument have something to say about it

    //used only by DecodeNameScript()
    std::string strAddress;
    bool fIsMine;

    //used only by GetNameList()
    int nExpiresAt;

    NameTxInfo(): nRentalDays(-1), op(-1), nOut(-1), fIsMine(false), nExpiresAt(-1) {}
    NameTxInfo(std::vector<unsigned char> vchName1, std::vector<unsigned char> vchValue1, int nRentalDays1, int op1, int nOut1, std::string err_msg1):
        vchName(vchName1), vchValue(vchValue1), nRentalDays(nRentalDays1), op(op1), nOut(nOut1), err_msg(err_msg1), fIsMine(false), nExpiresAt(-1) {}
};

bool DecodeNameScript(const CScript& script, NameTxInfo& ret, bool checkValuesCorrectness = true, bool checkAddressAndIfIsMine = false);
bool DecodeNameScript(const CScript& script, NameTxInfo& ret, CScript::const_iterator& pc, bool checkValuesCorrectness = true, bool checkAddressAndIfIsMine = false);
bool DecodeNameTx(const CTransaction& tx, NameTxInfo& nti, bool checkValuesCorrectness = true, bool checkAddressAndIfIsMine = false);
void GetNameList(const std::vector<unsigned char> &vchNameUniq, std::map<std::vector<unsigned char>, NameTxInfo> &mapNames, std::map<std::vector<unsigned char>, NameTxInfo> &mapPending);
bool GetNameValue(const std::vector<unsigned char> &vchName, std::vector<unsigned char> &vchValue, bool checkPending);

bool SignNameSignatureINN(const CKeyStore& keystore, const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL);
struct NameTxReturn
{
     bool ok;
     std::string err_msg;
     RPCErrorCode err_code;
     std::string address;
     uint256 hex;   // Transaction hash in hex
};
NameTxReturn name_new(const std::vector<unsigned char> &vchName,
              const std::vector<unsigned char> &vchValue,
              const int nRentalDays, std::string strAddress);
NameTxReturn name_update(const std::vector<unsigned char> &vchName,
              const std::vector<unsigned char> &vchValue,
              const int nRentalDays, std::string strAddress = "");
NameTxReturn name_delete(const std::vector<unsigned char> &vchName);


struct nameTempProxy
{
    unsigned int nTime;
    std::vector<unsigned char> vchName;
    int op;
    uint256 hash;
    CNameIndex ind;
};
