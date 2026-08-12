#include <boost/test/unit_test.hpp>

#include "namecoin.h"

BOOST_AUTO_TEST_SUITE(name_index_recovery_tests)

class CNameDBCursorTest : public CNameDB
{
public:
    CNameDBCursorTest(const char* pszMode="cr+") : CNameDB(pszMode) {}

    template<typename T>
    bool WriteCursorValueForTest(const T& value)
    {
        return Write(std::string("nameindex-cursor"), value);
    }

    template<typename T>
    bool WriteEffectProgressValueForTest(const T& value)
    {
        return Write(std::string("nameindex-effect-progress"), value);
    }
};

class CNameIndexRebuildTestDB : public CTxDB
{
public:
    CNameIndexRebuildTestDB(const char* pszMode = "r+") : CTxDB(pszMode) {}

    template <typename T>
    bool WriteRawActiveSet(const uint256& hashBlock, const T& value)
    {
        return Write(std::make_pair(std::string("dagactiveset"), hashBlock),
                     value);
    }

    bool EraseActiveSet(const uint256& hashBlock)
    {
        return Erase(std::make_pair(std::string("dagactiveset"), hashBlock));
    }

    bool EraseTestTxIndex(const uint256& hashTx)
    {
        return Erase(std::make_pair(std::string("tx"), hashTx));
    }
};

class CCursorWithTrailingByte
{
public:
    CNameIndexCursor cursor;
    unsigned char trailing;

    CCursorWithTrailingByte() : trailing(0xa5) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(cursor);
        READWRITE(trailing);
    )
};

class COversizedCursorValue
{
public:
    CNameIndexCursor cursor;
    std::vector<unsigned char> padding;

    COversizedCursorValue() : padding(1024, 0x5a) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(cursor);
        READWRITE(padding);
    )
};

class CEffectProgressWithTrailingByte
{
public:
    CNameIndexEffectProgress progress;
    unsigned char trailing;

    CEffectProgressWithTrailingByte() : trailing(0xa5) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(progress);
        READWRITE(trailing);
    )
};

static void WriteCursorForTest(const CNameIndexCursor& cursor)
{
    CNameDB dbName("cr+");
    BOOST_REQUIRE(dbName.TxnBegin());
    if (!dbName.WriteCursor(cursor))
    {
        dbName.TxnAbort();
        BOOST_FAIL("failed to stage name-index cursor");
    }
    BOOST_REQUIRE(dbName.TxnCommit());
}

template<typename T>
static void WriteCursorValueForTest(const T& value)
{
    CNameDBCursorTest dbName;
    BOOST_REQUIRE(dbName.TxnBegin());
    if (!dbName.WriteCursorValueForTest(value))
    {
        dbName.TxnAbort();
        BOOST_FAIL("failed to stage malformed name-index cursor");
    }
    BOOST_REQUIRE(dbName.TxnCommit());
}

static CBlockIndex MakeTestTip(uint256& hash, int nHeight, uint64_t nHashValue)
{
    hash = uint256(nHashValue);
    CBlockIndex tip;
    tip.phashBlock = &hash;
    tip.nHeight = nHeight;
    return tip;
}

static CNameIndexCursor MakeCursor(int nHeight, uint64_t nHashValue)
{
    CNameIndexCursor cursor;
    cursor.nSchema = NAMEINDEX_CURSOR_SCHEMA;
    cursor.nResetHeight = FORK_HEIGHT_IDNS_RESET;
    cursor.nHeight = nHeight;
    cursor.hashBlock = uint256(nHashValue);
    return cursor;
}

static CNameRecord MakeRecord(int nHeight, int op, unsigned int nTxPos,
                              unsigned char value)
{
    CNameRecord record;
    CNameIndex entry;
    entry.txPos = CDiskTxPos(1, 2, nTxPos);
    entry.nHeight = nHeight;
    entry.op = op;
    entry.vchValue.push_back(value);
    record.vtxPos.push_back(entry);
    record.nLastActiveChainIndex = 0;
    record.nExpiresAt = nHeight + 100;
    return record;
}

static CNameRecord AppendRecord(const CNameRecord& before, int nHeight,
                                int op, unsigned int nTxPos,
                                unsigned char value)
{
    CNameRecord after = before;
    CNameIndex entry;
    entry.txPos = CDiskTxPos(1, 2, nTxPos);
    entry.nHeight = nHeight;
    entry.op = op;
    entry.vchValue.push_back(value);
    after.vtxPos.push_back(entry);
    if (op == OP_NAME_NEW)
        after.nLastActiveChainIndex = after.vtxPos.size() - 1;
    after.nExpiresAt = nHeight + 100;
    return after;
}

static void ResetEffectState(const std::vector<unsigned char>& vchName,
                             const CNameIndexCursor& cursor,
                             const CNameRecord* pRecord = NULL)
{
    CNameDB dbName("cr+");
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE(dbName.EraseName(vchName));
    BOOST_REQUIRE(dbName.EraseEffectProgress());
    if (pRecord)
        BOOST_REQUIRE(dbName.WriteName(vchName, *pRecord));
    BOOST_REQUIRE(dbName.WriteCursor(cursor));
    BOOST_REQUIRE(dbName.TxnCommit());
}

static void CheckCursorEquals(const CNameIndexCursor& expected)
{
    CNameDB dbName("r");
    CNameIndexCursor actual;
    BOOST_REQUIRE(dbName.ReadCursor(actual));
    BOOST_CHECK_EQUAL(actual.nSchema, expected.nSchema);
    BOOST_CHECK_EQUAL(actual.nResetHeight, expected.nResetHeight);
    BOOST_CHECK_EQUAL(actual.nHeight, expected.nHeight);
    BOOST_CHECK(actual.hashBlock == expected.hashBlock);
}

static void BuildNameIndexRebuildBlock(
    CBlock& block, CTransaction& skippedNameTx,
    CBlockIndex& previous, CBlockIndex& current,
    uint256& hashPrevious, uint256& hashCurrent)
{
    CTransaction coinbase;
    coinbase.nTime = 0xdab100;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.push_back(CTxOut(1, CScript() << OP_TRUE));

    // Make the block proof-of-stake-shaped so the disk round trip does not
    // depend on a test-specific proof-of-work limit.  The name transaction is
    // a separate, non-mandatory transaction and is the only skipped entry.
    CTransaction coinstake;
    coinstake.nTime = 0xdab101;
    coinstake.vin.push_back(CTxIn(COutPoint(uint256(0xdab102), 0)));
    coinstake.vout.push_back(CTxOut(0, CScript()));
    coinstake.vout.push_back(CTxOut(1, CScript() << OP_TRUE));
    BOOST_REQUIRE(coinstake.IsCoinStake());

    skippedNameTx = CTransaction();
    skippedNameTx.nVersion = NAMECOIN_TX_VERSION;
    skippedNameTx.nTime = 0xdab103;
    skippedNameTx.vin.push_back(
        CTxIn(COutPoint(uint256(0xdab104), 0)));
    skippedNameTx.vout.push_back(CTxOut(1, CScript() << OP_TRUE));
    BOOST_REQUIRE(!skippedNameTx.IsCoinBase());
    BOOST_REQUIRE(!skippedNameTx.IsCoinStake());

    block = CBlock();
    hashPrevious = uint256(0xdab105);
    block.hashPrevBlock = hashPrevious;
    block.nTime = 0xdab106;
    block.vtx.push_back(coinbase);
    block.vtx.push_back(coinstake);
    block.vtx.push_back(skippedNameTx);
    block.hashMerkleRoot = block.BuildMerkleTree();
    hashCurrent = block.GetHash();

    unsigned int nFile = 0;
    unsigned int nBlockPos = 0;
    BOOST_REQUIRE(block.WriteToDisk(nFile, nBlockPos));

    previous = CBlockIndex();
    previous.phashBlock = &hashPrevious;
    previous.nHeight = FORK_HEIGHT_DAG + 4;
    current = CBlockIndex(nFile, nBlockPos, block);
    current.phashBlock = &hashCurrent;
    current.pprev = &previous;
    current.nHeight = previous.nHeight + 1;

    CBlock reread;
    BOOST_REQUIRE(reread.ReadFromDisk(&current, true));
    BOOST_REQUIRE(reread.GetHash() == hashCurrent);
}

BOOST_AUTO_TEST_CASE(cursor_requires_exact_tip)
{
    uint256 hashTip;
    CBlockIndex tip = MakeTestTip(hashTip, 321, 0x321);
    std::string strError;

    BOOST_REQUIRE_MESSAGE(CommitNameIndexTip(&tip, strError), strError);
    BOOST_CHECK_MESSAGE(ValidateNameIndexTip(&tip, strError), strError);

    uint256 hashOther;
    CBlockIndex other = MakeTestTip(hashOther, 322, 0x322);
    BOOST_CHECK(!ValidateNameIndexTip(&other, strError));
    BOOST_CHECK(strError.find("does not match canonical tip") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(cursor_rejects_missing_schema_and_wrong_era)
{
    uint256 hashTip;
    CBlockIndex tip = MakeTestTip(hashTip, 400, 0x400);
    std::string strError;

    {
        CNameDB dbName("cr+");
        BOOST_REQUIRE(dbName.TxnBegin());
        BOOST_REQUIRE(dbName.EraseCursor());
        BOOST_REQUIRE(dbName.TxnCommit());
    }
    BOOST_CHECK(!ValidateNameIndexTip(&tip, strError));
    BOOST_CHECK(strError.find("missing or unreadable") != std::string::npos);

    CNameIndexCursor cursor;
    cursor.nSchema = NAMEINDEX_CURSOR_SCHEMA + 1;
    cursor.nResetHeight = FORK_HEIGHT_IDNS_RESET;
    cursor.nHeight = tip.nHeight;
    cursor.hashBlock = hashTip;
    WriteCursorForTest(cursor);
    BOOST_CHECK(!ValidateNameIndexTip(&tip, strError));
    BOOST_CHECK(strError.find("schema") != std::string::npos);

    cursor.nSchema = NAMEINDEX_CURSOR_SCHEMA;
    cursor.nResetHeight = FORK_HEIGHT_IDNS_RESET + 1;
    WriteCursorForTest(cursor);
    BOOST_CHECK(!ValidateNameIndexTip(&tip, strError));
    BOOST_CHECK(strError.find("reset era") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(cursor_read_is_exact_and_bounded)
{
    uint256 hashTip;
    CBlockIndex tip = MakeTestTip(hashTip, 450, 0x450);
    std::string strError;

    CNameIndexCursor valid;
    valid.nSchema = NAMEINDEX_CURSOR_SCHEMA;
    valid.nResetHeight = FORK_HEIGHT_IDNS_RESET;
    valid.nHeight = tip.nHeight;
    valid.hashBlock = hashTip;

    CCursorWithTrailingByte trailing;
    trailing.cursor = valid;
    WriteCursorValueForTest(trailing);
    BOOST_CHECK(!ValidateNameIndexTip(&tip, strError));
    BOOST_CHECK(strError.find("missing or unreadable") != std::string::npos);

    WriteCursorValueForTest((unsigned char)0x01);
    BOOST_CHECK(!ValidateNameIndexTip(&tip, strError));
    BOOST_CHECK(strError.find("missing or unreadable") != std::string::npos);

    COversizedCursorValue oversized;
    oversized.cursor = valid;
    WriteCursorValueForTest(oversized);
    BOOST_CHECK(!ValidateNameIndexTip(&tip, strError));
    BOOST_CHECK(strError.find("missing or unreadable") != std::string::npos);

    WriteCursorForTest(valid);
    BOOST_CHECK_MESSAGE(ValidateNameIndexTip(&tip, strError), strError);
}

BOOST_AUTO_TEST_CASE(name_record_transaction_abort_and_commit_are_atomic)
{
    const std::vector<unsigned char> vchName =
        std::vector<unsigned char>({'c', 'u', 'r', 's', 'o', 'r', '-', 't', 'x'});

    CNameRecord record;
    CNameIndex entry;
    entry.op = OP_NAME_NEW;
    entry.nHeight = 7;
    record.vtxPos.push_back(entry);
    record.nLastActiveChainIndex = 0;

    CNameDB dbName("cr+");
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE(dbName.EraseName(vchName));
    BOOST_REQUIRE(dbName.TxnCommit());

    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE(dbName.WriteName(vchName, record));
    BOOST_REQUIRE(dbName.TxnAbort());
    BOOST_CHECK(!dbName.ExistsName(vchName));

    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE(dbName.WriteName(vchName, record));
    BOOST_REQUIRE(dbName.TxnCommit());

    CNameRecord loaded;
    BOOST_REQUIRE(dbName.ReadName(vchName, loaded));
    BOOST_REQUIRE_EQUAL(loaded.vtxPos.size(), 1U);
    BOOST_CHECK_EQUAL(loaded.vtxPos[0].op, OP_NAME_NEW);

    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE(dbName.EraseName(vchName));
    BOOST_REQUIRE(dbName.TxnCommit());
    BOOST_CHECK(!dbName.ExistsName(vchName));
}

BOOST_AUTO_TEST_CASE(connect_effect_commit_and_retry_are_idempotent)
{
    const std::vector<unsigned char> vchName =
        std::vector<unsigned char>({'e', 'f', 'f', 'e', 'c', 't', '-', 'c'});
    const CNameIndexCursor cursorBefore = MakeCursor(20, 0x2000);
    const CNameIndexCursor cursorAfter = MakeCursor(21, 0x2100);
    ResetEffectState(vchName, cursorBefore);

    CNameIndexTransitionEffect effect;
    effect.fConnect = true;
    effect.hashSourceTx = uint256(0xc001);
    effect.vchName = vchName;
    effect.fAfterExists = true;
    effect.after = MakeRecord(21, OP_NAME_NEW, 101, 0x41);

    CNameDB dbName("cr+");
    std::string strError;
    bool fAlreadyApplied = false;
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE_MESSAGE(StageNameIndexTransitionEffect(
        dbName, uint256(0xc100), 0, 1, effect, cursorAfter,
        fAlreadyApplied, strError), strError);
    BOOST_CHECK(!fAlreadyApplied);
    BOOST_REQUIRE(dbName.TxnCommit());

    CNameRecord loaded;
    BOOST_REQUIRE(dbName.ReadName(vchName, loaded));
    BOOST_REQUIRE_EQUAL(loaded.vtxPos.size(), 1U);
    BOOST_CHECK(loaded.vtxPos[0].txPos == effect.after.vtxPos[0].txPos);

    CNameIndexEffectProgress progress;
    BOOST_REQUIRE(dbName.ReadEffectProgress(progress));
    BOOST_CHECK(progress.IsComplete());
    BOOST_CHECK_EQUAL(progress.nNextEffect, 1U);
    CheckCursorEquals(cursorAfter);

    // An ambiguous successful commit is retried with the exact same effect.
    // Progress makes this a no-op rather than appending a duplicate record.
    fAlreadyApplied = false;
    strError.clear();
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE_MESSAGE(StageNameIndexTransitionEffect(
        dbName, uint256(0xc100), 0, 1, effect, cursorAfter,
        fAlreadyApplied, strError), strError);
    BOOST_CHECK(fAlreadyApplied);
    BOOST_REQUIRE(dbName.TxnCommit());
    BOOST_REQUIRE(dbName.ReadName(vchName, loaded));
    BOOST_CHECK_EQUAL(loaded.vtxPos.size(), 1U);
}

BOOST_AUTO_TEST_CASE(disconnect_effect_commit_and_retry_are_idempotent)
{
    const std::vector<unsigned char> vchName =
        std::vector<unsigned char>({'e', 'f', 'f', 'e', 'c', 't', '-', 'd'});
    const CNameIndexCursor cursorBefore = MakeCursor(31, 0x3100);
    const CNameIndexCursor cursorAfter = MakeCursor(30, 0x3000);
    const CNameRecord record = MakeRecord(31, OP_NAME_NEW, 201, 0x51);
    ResetEffectState(vchName, cursorBefore, &record);

    CNameIndexTransitionEffect effect;
    effect.fConnect = false;
    effect.hashSourceTx = uint256(0xd001);
    effect.vchName = vchName;
    effect.fBeforeExists = true;
    effect.before = record;

    CNameDB dbName("cr+");
    std::string strError;
    bool fAlreadyApplied = false;
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE_MESSAGE(StageNameIndexTransitionEffect(
        dbName, uint256(0xd100), 0, 1, effect, cursorAfter,
        fAlreadyApplied, strError), strError);
    BOOST_CHECK(!fAlreadyApplied);
    BOOST_REQUIRE(dbName.TxnCommit());
    BOOST_CHECK(!dbName.ExistsName(vchName));
    CheckCursorEquals(cursorAfter);

    fAlreadyApplied = false;
    strError.clear();
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE_MESSAGE(StageNameIndexTransitionEffect(
        dbName, uint256(0xd100), 0, 1, effect, cursorAfter,
        fAlreadyApplied, strError), strError);
    BOOST_CHECK(fAlreadyApplied);
    BOOST_REQUIRE(dbName.TxnCommit());
    BOOST_CHECK(!dbName.ExistsName(vchName));
}

BOOST_AUTO_TEST_CASE(effect_phase_failures_abort_atomically_and_retry)
{
    const std::vector<unsigned char> vchName =
        std::vector<unsigned char>({'e', 'f', 'f', 'e', 'c', 't', '-', 'f'});
    const CNameIndexCursor cursorBefore = MakeCursor(40, 0x4000);
    const CNameIndexCursor cursorAfter = MakeCursor(41, 0x4100);

    CNameIndexTransitionEffect effect;
    effect.fConnect = true;
    effect.hashSourceTx = uint256(0xf001);
    effect.vchName = vchName;
    effect.fAfterExists = true;
    effect.after = MakeRecord(41, OP_NAME_NEW, 301, 0x61);

    for (int injected = NAMEINDEX_EFFECT_FAULT_AFTER_MUTATION;
         injected <= NAMEINDEX_EFFECT_FAULT_AFTER_PROGRESS; ++injected)
    {
        ResetEffectState(vchName, cursorBefore);
        CNameDB dbName("cr+");
        std::string strError;
        bool fAlreadyApplied = false;
        BOOST_REQUIRE(dbName.TxnBegin());
        BOOST_CHECK(!StageNameIndexTransitionEffect(
            dbName, uint256(0xf100 + injected), 0, 1, effect,
            cursorAfter, fAlreadyApplied, strError,
            (NameIndexEffectFault)injected));
        BOOST_CHECK(!strError.empty());
        BOOST_REQUIRE(dbName.TxnAbort());

        BOOST_CHECK(!dbName.ExistsName(vchName));
        BOOST_CHECK(!dbName.HasEffectProgress());
        CheckCursorEquals(cursorBefore);

        strError.clear();
        fAlreadyApplied = false;
        BOOST_REQUIRE(dbName.TxnBegin());
        BOOST_REQUIRE_MESSAGE(StageNameIndexTransitionEffect(
            dbName, uint256(0xf100 + injected), 0, 1, effect,
            cursorAfter, fAlreadyApplied, strError), strError);
        BOOST_REQUIRE(dbName.TxnCommit());
        BOOST_REQUIRE(dbName.ExistsName(vchName));
        CheckCursorEquals(cursorAfter);
    }
}

BOOST_AUTO_TEST_CASE(effect_progress_rejects_conflicts_and_out_of_order_replay)
{
    const std::vector<unsigned char> vchName =
        std::vector<unsigned char>({'e', 'f', 'f', 'e', 'c', 't', '-', 'o'});
    const CNameIndexCursor cursor0 = MakeCursor(50, 0x5000);
    const CNameIndexCursor cursor1 = MakeCursor(51, 0x5100);
    const CNameIndexCursor cursor2 = MakeCursor(52, 0x5200);
    ResetEffectState(vchName, cursor0);

    CNameIndexTransitionEffect first;
    first.fConnect = true;
    first.hashSourceTx = uint256(0xa001);
    first.vchName = vchName;
    first.fAfterExists = true;
    first.after = MakeRecord(51, OP_NAME_NEW, 401, 0x71);

    CNameIndexTransitionEffect second;
    second.fConnect = true;
    second.hashSourceTx = uint256(0xa002);
    second.vchName = vchName;
    second.fBeforeExists = true;
    second.before = first.after;
    second.fAfterExists = true;
    second.after = AppendRecord(first.after, 52, OP_NAME_UPDATE,
                                402, 0x72);

    const uint256 hashTransition(0xa100);
    CNameDB dbName("cr+");
    std::string strError;
    bool fAlreadyApplied = false;
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE_MESSAGE(StageNameIndexTransitionEffect(
        dbName, hashTransition, 0, 2, first, cursor1,
        fAlreadyApplied, strError), strError);
    BOOST_REQUIRE(dbName.TxnCommit());

    CNameIndexTransitionEffect conflicting = first;
    conflicting.hashSourceTx = uint256(0xafff);
    strError.clear();
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_CHECK(!StageNameIndexTransitionEffect(
        dbName, hashTransition, 0, 2, conflicting, cursor1,
        fAlreadyApplied, strError));
    BOOST_CHECK(strError.find("conflicting effect identity") !=
                std::string::npos);
    BOOST_REQUIRE(dbName.TxnAbort());

    strError.clear();
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_CHECK(!StageNameIndexTransitionEffect(
        dbName, uint256(0xa200), 0, 1, second, cursor2,
        fAlreadyApplied, strError));
    BOOST_CHECK(strError.find("still incomplete") != std::string::npos);
    BOOST_REQUIRE(dbName.TxnAbort());

    strError.clear();
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE_MESSAGE(StageNameIndexTransitionEffect(
        dbName, hashTransition, 1, 2, second, cursor2,
        fAlreadyApplied, strError), strError);
    BOOST_REQUIRE(dbName.TxnCommit());
    CNameRecord loaded;
    BOOST_REQUIRE(dbName.ReadName(vchName, loaded));
    BOOST_CHECK_EQUAL(loaded.vtxPos.size(), 2U);
    CNameIndexEffectProgress progress;
    BOOST_REQUIRE(dbName.ReadEffectProgress(progress));
    BOOST_CHECK(progress.IsComplete());
}

BOOST_AUTO_TEST_CASE(prepared_block_effects_commit_atomically_and_retry)
{
    const std::vector<unsigned char> firstName =
        std::vector<unsigned char>({'b', 'l', 'o', 'c', 'k', '-', '1'});
    const std::vector<unsigned char> secondName =
        std::vector<unsigned char>({'b', 'l', 'o', 'c', 'k', '-', '2'});
    const CNameIndexCursor cursorBefore = MakeCursor(60, 0x6000);
    const CNameIndexCursor cursorAfter = MakeCursor(61, 0x6100);
    ResetEffectState(firstName, cursorBefore);
    {
        CNameDB dbName("cr+");
        BOOST_REQUIRE(dbName.TxnBegin());
        BOOST_REQUIRE(dbName.EraseName(secondName));
        BOOST_REQUIRE(dbName.TxnCommit());
    }

    CPreparedNameIndexTransition prepared;
    prepared.fConnect = true;
    prepared.hashBlock = uint256(0x6111);
    prepared.cursorAfter = cursorAfter;
    prepared.hashTransition = ComputeNameIndexBlockTransitionIdentity(
        true, prepared.hashBlock, cursorAfter);

    CNameIndexTransitionEffect first;
    first.fConnect = true;
    first.hashSourceTx = uint256(0x6112);
    first.vchName = firstName;
    first.fAfterExists = true;
    first.after = MakeRecord(61, OP_NAME_NEW, 501, 0x81);
    prepared.vEffects.push_back(first);

    CNameIndexTransitionEffect second;
    second.fConnect = true;
    second.hashSourceTx = uint256(0x6113);
    second.vchName = secondName;
    second.fAfterExists = true;
    second.after = MakeRecord(61, OP_NAME_NEW, 502, 0x82);
    prepared.vEffects.push_back(second);

    std::string strError;
    bool fAlreadyApplied = false;
    BOOST_CHECK(!ApplyPreparedNameIndexTransition(
        prepared, fAlreadyApplied, strError, 1,
        NAMEINDEX_EFFECT_FAULT_AFTER_MUTATION));
    BOOST_CHECK(!strError.empty());
    {
        CNameDB dbName("r");
        BOOST_CHECK(!dbName.ExistsName(firstName));
        BOOST_CHECK(!dbName.ExistsName(secondName));
        BOOST_CHECK(!dbName.HasEffectProgress());
    }
    CheckCursorEquals(cursorBefore);

    strError.clear();
    BOOST_REQUIRE_MESSAGE(ApplyPreparedNameIndexTransition(
        prepared, fAlreadyApplied, strError), strError);
    BOOST_CHECK(!fAlreadyApplied);
    {
        CNameDB dbName("r");
        BOOST_CHECK(dbName.ExistsName(firstName));
        BOOST_CHECK(dbName.ExistsName(secondName));
        CNameIndexEffectProgress progress;
        BOOST_REQUIRE(dbName.ReadEffectProgress(progress));
        BOOST_CHECK(progress.IsComplete());
        BOOST_CHECK_EQUAL(progress.nEffectCount, 2U);
    }
    CheckCursorEquals(cursorAfter);

    fAlreadyApplied = false;
    strError.clear();
    BOOST_REQUIRE_MESSAGE(ApplyPreparedNameIndexTransition(
        prepared, fAlreadyApplied, strError), strError);
    BOOST_CHECK(fAlreadyApplied);
    CNameDB dbName("r");
    CNameRecord loaded;
    BOOST_REQUIRE(dbName.ReadName(firstName, loaded));
    BOOST_CHECK_EQUAL(loaded.vtxPos.size(), 1U);
    BOOST_REQUIRE(dbName.ReadName(secondName, loaded));
    BOOST_CHECK_EQUAL(loaded.vtxPos.size(), 1U);
}

BOOST_AUTO_TEST_CASE(reverse_block_noop_progress_targets_predecessor_cursor)
{
    CBlock block;
    block.nTime = 12345;
    uint256 hashBlock = block.GetHash();
    uint256 hashPrev(0x7000);
    CBlockIndex prev;
    prev.phashBlock = &hashPrev;
    prev.nHeight = 70;
    CBlockIndex current;
    current.phashBlock = &hashBlock;
    current.nHeight = 71;
    current.pprev = &prev;

    const std::vector<unsigned char> cleanupName =
        std::vector<unsigned char>({'b', 'l', 'o', 'c', 'k', '-', '0'});
    ResetEffectState(cleanupName, MakeCursor(71, 0x7100));

    CPreparedNameIndexTransition prepared;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(PrepareNameIndexDisconnectTransition(
        block, &current, prepared, strError), strError);
    BOOST_CHECK(!prepared.fConnect);
    BOOST_CHECK(prepared.vEffects.empty());
    BOOST_CHECK_EQUAL(prepared.cursorAfter.nHeight, prev.nHeight);
    BOOST_CHECK(prepared.cursorAfter.hashBlock == hashPrev);

    bool fAlreadyApplied = false;
    BOOST_REQUIRE_MESSAGE(ApplyPreparedNameIndexTransition(
        prepared, fAlreadyApplied, strError), strError);
    BOOST_CHECK(!fAlreadyApplied);
    CheckCursorEquals(prepared.cursorAfter);
    {
        CNameDB dbName("r");
        CNameIndexEffectProgress progress;
        BOOST_REQUIRE(dbName.ReadEffectProgress(progress));
        BOOST_CHECK(progress.IsComplete());
        BOOST_CHECK_EQUAL(progress.nEffectCount, 0U);
    }

    CPreparedNameIndexTransition retry;
    strError.clear();
    BOOST_REQUIRE_MESSAGE(PrepareNameIndexDisconnectTransition(
        block, &current, retry, strError), strError);
    BOOST_CHECK(retry.fAlreadyComplete);
    fAlreadyApplied = false;
    BOOST_REQUIRE_MESSAGE(ApplyPreparedNameIndexTransition(
        retry, fAlreadyApplied, strError), strError);
    BOOST_CHECK(fAlreadyApplied);

    const uint256 connectIdentity = ComputeNameIndexBlockTransitionIdentity(
        true, hashBlock, retry.cursorAfter);
    BOOST_CHECK(connectIdentity != retry.hashTransition);
}

BOOST_AUTO_TEST_CASE(dag_skipped_name_tx_is_excluded_and_identity_bound)
{
    CTransaction skippedNameTx;
    skippedNameTx.nVersion = NAMECOIN_TX_VERSION;
    skippedNameTx.nTime = 23456;

    CBlock block;
    block.nTime = 23457;
    block.vtx.push_back(skippedNameTx);
    uint256 hashBlock = block.GetHash();
    uint256 hashPrev(0x7200);
    CBlockIndex prev;
    prev.phashBlock = &hashPrev;
    prev.nHeight = 72;
    CBlockIndex current;
    current.phashBlock = &hashBlock;
    current.nHeight = 73;
    current.pprev = &prev;

    CNameIndexCursor cursorCurrent = MakeCursor(73, 0x7300);
    cursorCurrent.hashBlock = hashBlock;
    const std::vector<unsigned char> cleanupName =
        std::vector<unsigned char>({'d', 'a', 'g', '-', 's', 'k', 'i', 'p'});
    ResetEffectState(cleanupName, cursorCurrent);

    // Undecodable is a connect-skip reason, so disconnect must undo nothing
    // rather than fail, but the active set still binds the identity.
    CPreparedNameIndexTransition activePrepared;
    std::string strError;
    const std::set<uint256> setNoSkippedTxs;
    BOOST_REQUIRE_MESSAGE(PrepareNameIndexDisconnectTransition(
        block, &current, setNoSkippedTxs, activePrepared, strError), strError);
    BOOST_CHECK(activePrepared.vEffects.empty());

    std::set<uint256> setSkippedTxs;
    setSkippedTxs.insert(skippedNameTx.GetHash());
    CPreparedNameIndexTransition skippedPrepared;
    strError.clear();
    BOOST_REQUIRE_MESSAGE(PrepareNameIndexDisconnectTransition(
        block, &current, setSkippedTxs, skippedPrepared, strError), strError);
    BOOST_CHECK(skippedPrepared.vEffects.empty());
    BOOST_CHECK(skippedPrepared.setDAGSkippedTxs == setSkippedTxs);
    BOOST_CHECK(skippedPrepared.hashTransition !=
        ComputeNameIndexBlockTransitionIdentity(
            false, hashBlock, skippedPrepared.cursorAfter,
            setNoSkippedTxs));

    std::set<uint256> setNotInBlock;
    setNotInBlock.insert(uint256(0x72ff));
    CPreparedNameIndexTransition invalidPrepared;
    strError.clear();
    BOOST_CHECK(!PrepareNameIndexDisconnectTransition(
        block, &current, setNotInBlock, invalidPrepared, strError));
    BOOST_CHECK(strError.find("not in its block") != std::string::npos);

    bool fAlreadyApplied = false;
    strError.clear();
    BOOST_REQUIRE_MESSAGE(ApplyPreparedNameIndexTransition(
        skippedPrepared, fAlreadyApplied, strError), strError);
    BOOST_CHECK(!fAlreadyApplied);
    CheckCursorEquals(skippedPrepared.cursorAfter);

    // Replaying the same block/cursor with a different active set must fail
    // closed rather than reinterpret the already-committed no-op transition.
    strError.clear();
    BOOST_CHECK(!PrepareNameIndexDisconnectTransition(
        block, &current, setNoSkippedTxs, activePrepared, strError));
    BOOST_CHECK(strError.find("conflicting completed") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(restart_rebuild_uses_persisted_dag_skip_set)
{
    CBlock block;
    CTransaction skippedNameTx;
    CBlockIndex previous;
    CBlockIndex current;
    uint256 hashPrevious;
    uint256 hashCurrent;
    BuildNameIndexRebuildBlock(
        block, skippedNameTx, previous, current,
        hashPrevious, hashCurrent);

    const uint256 hashSkipped = skippedNameTx.GetHash();
    std::set<uint256> setSkippedTxs;
    setSkippedTxs.insert(hashSkipped);
    {
        CNameIndexRebuildTestDB writer;
        BOOST_REQUIRE(writer.EraseActiveSet(hashCurrent));
        // If rebuild drops the persisted skip set, the missing tx index makes
        // the malformed/non-indexable name transaction fail preparation.
        BOOST_REQUIRE(writer.EraseTestTxIndex(hashSkipped));
        std::string strWriteError;
        BOOST_REQUIRE_MESSAGE(writer.WriteDAGSkippedTxs(
            block, setSkippedTxs, strWriteError), strWriteError);
    }

    const std::vector<unsigned char> cleanupName =
        std::vector<unsigned char>({'r', 'e', 'b', 'u', 'i', 'l', 'd', '-', 's'});
    CNameIndexCursor cursorPrevious = MakeCursor(
        previous.nHeight, 0xdab105);
    cursorPrevious.hashBlock = hashPrevious;
    ResetEffectState(cleanupName, cursorPrevious);

    // A fresh LevelDB wrapper models startup after the active-set record was
    // durably committed by the original connect.
    CNameIndexRebuildTestDB restarted("r");
    std::string strError;
    BOOST_REQUIRE_MESSAGE(ApplyNameIndexRebuildBlock(
        restarted, block, &current, strError), strError);

    CNameIndexCursor cursorCurrent = MakeCursor(current.nHeight, 0);
    cursorCurrent.hashBlock = hashCurrent;
    CheckCursorEquals(cursorCurrent);
    CNameDB dbName("r");
    CNameIndexEffectProgress progress;
    BOOST_REQUIRE(dbName.ReadEffectProgress(progress));
    BOOST_CHECK(progress.IsComplete());
    BOOST_CHECK_EQUAL(progress.nEffectCount, 0U);
    BOOST_CHECK(progress.hashTransition ==
        ComputeNameIndexBlockTransitionIdentity(
            true, hashCurrent, cursorCurrent, setSkippedTxs));

    CNameIndexRebuildTestDB cleanup;
    BOOST_REQUIRE(cleanup.EraseActiveSet(hashCurrent));
    BOOST_REQUIRE(cleanup.EraseTestTxIndex(hashSkipped));
}

BOOST_AUTO_TEST_CASE(restart_rebuild_rejects_missing_or_corrupt_dag_skip_set)
{
    CBlock block;
    CTransaction skippedNameTx;
    CBlockIndex previous;
    CBlockIndex current;
    uint256 hashPrevious;
    uint256 hashCurrent;
    BuildNameIndexRebuildBlock(
        block, skippedNameTx, previous, current,
        hashPrevious, hashCurrent);

    CNameIndexRebuildTestDB db;
    BOOST_REQUIRE(db.EraseActiveSet(hashCurrent));
    std::string strError;
    BOOST_CHECK(!ApplyNameIndexRebuildBlock(
        db, block, &current, strError));
    BOOST_CHECK(strError.find("missing") != std::string::npos);

    BOOST_REQUIRE(db.WriteRawActiveSet(hashCurrent, (unsigned char)0x01));
    strError.clear();
    BOOST_CHECK(!ApplyNameIndexRebuildBlock(
        db, block, &current, strError));
    BOOST_CHECK(strError.find("corrupt") != std::string::npos);
    BOOST_REQUIRE(db.EraseActiveSet(hashCurrent));
    BOOST_REQUIRE(db.EraseTestTxIndex(skippedNameTx.GetHash()));
}

BOOST_AUTO_TEST_CASE(effect_progress_read_is_exact_and_bounded)
{
    CNameIndexEffectProgress valid;
    valid.nSchema = NAMEINDEX_EFFECT_PROGRESS_SCHEMA;
    valid.hashTransition = uint256(0xb100);
    valid.nEffectCount = 1;
    valid.nNextEffect = 1;
    valid.hashLastEffect = uint256(0xb101);
    BOOST_REQUIRE(valid.IsValid());

    CNameDBCursorTest dbName;
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE(dbName.WriteEffectProgress(valid));
    BOOST_REQUIRE(dbName.TxnCommit());
    CNameIndexEffectProgress decoded;
    BOOST_REQUIRE(dbName.ReadEffectProgress(decoded));
    BOOST_CHECK(decoded.hashTransition == valid.hashTransition);

    CEffectProgressWithTrailingByte trailing;
    trailing.progress = valid;
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE(dbName.WriteEffectProgressValueForTest(trailing));
    BOOST_REQUIRE(dbName.TxnCommit());
    BOOST_CHECK(!dbName.ReadEffectProgress(decoded));

    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE(dbName.WriteEffectProgressValueForTest((unsigned char)1));
    BOOST_REQUIRE(dbName.TxnCommit());
    BOOST_CHECK(!dbName.ReadEffectProgress(decoded));

    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE(dbName.EraseEffectProgress());
    BOOST_REQUIRE(dbName.TxnCommit());
}

BOOST_AUTO_TEST_SUITE_END()
