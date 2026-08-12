#include <boost/test/unit_test.hpp>

#include "bignum.h"
#include "main.h"
#include "namecoin.h"
#include "txdb.h"

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(name_rental_tests)

namespace
{
// The rental conversion and the reset gate read fRegTest/fTestNet through the
// fork-height accessors, so exercising mainnet heights means flipping the
// network for the duration of a test.
class CNetworkOverride
{
public:
    CNetworkOverride(bool fRegTestIn, bool fTestNetIn)
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet)
    {
        fRegTest = fRegTestIn;
        fTestNet = fTestNetIn;
    }
    ~CNetworkOverride()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
    }
private:
    bool fRegTestSaved;
    bool fTestNetSaved;
};

const int64_t SECONDS_PER_DAY = 86400;

// A name script built without the creation-side term bound, so a term connect
// will refuse can still be placed in a block.
CScript MakeNameScript(const std::string& strName, int nRentalDays, int op,
                       const std::string& strValue)
{
    const std::vector<unsigned char> vchName(strName.begin(), strName.end());
    const std::vector<unsigned char> vchValue(strValue.begin(), strValue.end());
    CScript script;
    script << op << OP_DROP << vchName << CBigNum(nRentalDays).getvch()
           << OP_2DROP << vchValue << OP_DROP;
    script << OP_TRUE;
    return script;
}

CTransaction MakeNameTx(const std::string& strName, int nRentalDays, int op,
                        const std::string& strValue, const COutPoint& prevout,
                        int64_t nValueOut, unsigned int nTime)
{
    CTransaction tx;
    tx.nVersion = NAMECOIN_TX_VERSION;
    tx.nTime = nTime;
    tx.vin.push_back(CTxIn(prevout));
    tx.vout.push_back(CTxOut(nValueOut,
                             MakeNameScript(strName, nRentalDays, op, strValue)));
    return tx;
}

// Proof-of-stake shaped so the disk round trip does not depend on a test
// proof-of-work limit.
void AddCoinbaseAndCoinstake(CBlock& block, unsigned int nSeed)
{
    CTransaction coinbase;
    coinbase.nTime = nSeed;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.push_back(CTxOut(1, CScript() << OP_TRUE));

    CTransaction coinstake;
    coinstake.nTime = nSeed + 1;
    coinstake.vin.push_back(CTxIn(COutPoint(uint256(nSeed + 2), 0)));
    coinstake.vout.push_back(CTxOut(0, CScript()));
    coinstake.vout.push_back(CTxOut(1, CScript() << OP_TRUE));
    BOOST_REQUIRE(coinstake.IsCoinStake());

    block.vtx.push_back(coinbase);
    block.vtx.push_back(coinstake);
}

// Writes the block and the tx-index entries ConnectBlock would have written,
// at the positions ConnectBlock computes.
void StoreBlock(CBlock& block, int nHeight, unsigned int& nFileOut,
                unsigned int& nBlockPosOut)
{
    block.hashMerkleRoot = block.BuildMerkleTree();
    nFileOut = 0;
    nBlockPosOut = 0;
    BOOST_REQUIRE(block.WriteToDisk(nFileOut, nBlockPosOut));

    const uint64_t nHeaderBytes =
        ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION);
    uint64_t nTxPos = (uint64_t)nBlockPosOut + nHeaderBytes -
                      2 * GetSizeOfCompactSize(0) +
                      GetSizeOfCompactSize(block.vtx.size());

    CTxDB txdb("r+");
    for (std::vector<CTransaction>::const_iterator it = block.vtx.begin();
         it != block.vtx.end(); ++it)
    {
        BOOST_REQUIRE(txdb.AddTxIndex(
            *it, CDiskTxPos(nFileOut, nBlockPosOut, (unsigned int)nTxPos),
            nHeight));
        nTxPos += ::GetSerializeSize(*it, SER_DISK, CLIENT_VERSION);
    }
}

CNameIndexCursor MakeChainCursor(int nHeight, const uint256& hashBlock)
{
    CNameIndexCursor cursor;
    cursor.nSchema = NAMEINDEX_CURSOR_SCHEMA;
    cursor.nResetHeight = FORK_HEIGHT_IDNS_RESET;
    cursor.nHeight = nHeight;
    cursor.hashBlock = hashBlock;
    return cursor;
}

void SeedIndexAt(const std::string& strName, const CNameIndexCursor& cursor)
{
    const std::vector<unsigned char> vchName(strName.begin(), strName.end());
    CNameDB dbName("cr+");
    BOOST_REQUIRE(dbName.TxnBegin());
    BOOST_REQUIRE(dbName.EraseName(vchName));
    BOOST_REQUIRE(dbName.EraseEffectProgress());
    BOOST_REQUIRE(dbName.WriteCursor(cursor));
    BOOST_REQUIRE(dbName.TxnCommit());
}

bool NameIsIndexed(const std::string& strName)
{
    const std::vector<unsigned char> vchName(strName.begin(), strName.end());
    CNameDB dbName("r");
    CNameRecord rec;
    return dbName.ExistsName(vchName) && dbName.ReadName(vchName, rec) &&
           !rec.vtxPos.empty();
}

// Connects a block holding one name tx spending a funding output, then
// disconnects it.  Returns whether the disconnect preparation succeeded; a
// false return is what drives ReplayBestChainEffects into FailClosed/shutdown.
bool ConnectThenDisconnectNameTx(const std::string& strName, int nRentalDays,
                                 int op, unsigned int nSeed,
                                 bool fFundWithNameOutput,
                                 bool& fIndexedAfterConnect,
                                 bool& fIndexedAfterDisconnect)
{
    CBlock fundBlock;
    AddCoinbaseAndCoinstake(fundBlock, nSeed);
    CTransaction fundTx;
    fundTx.nTime = nSeed + 3;
    fundTx.vin.push_back(CTxIn(COutPoint(uint256(nSeed + 4), 0)));
    fundTx.vout.push_back(CTxOut(
        100 * COIN,
        fFundWithNameOutput
            ? MakeNameScript(strName, 30, OP_NAME_NEW, "prior")
            : CScript() << OP_TRUE));
    fundBlock.vtx.push_back(fundTx);
    fundBlock.hashPrevBlock = uint256(nSeed + 5);
    fundBlock.nTime = nSeed + 6;

    unsigned int nFundFile = 0;
    unsigned int nFundPos = 0;
    StoreBlock(fundBlock, 10, nFundFile, nFundPos);

    const CTransaction nameTx = MakeNameTx(
        strName, nRentalDays, op, "value", COutPoint(fundTx.GetHash(), 0),
        1 * COIN, nSeed + 7);

    CBlock nameBlock;
    AddCoinbaseAndCoinstake(nameBlock, nSeed + 8);
    nameBlock.vtx.push_back(nameTx);
    nameBlock.hashPrevBlock = fundBlock.GetHash();
    nameBlock.nTime = nSeed + 12;

    unsigned int nNameFile = 0;
    unsigned int nNamePos = 0;
    StoreBlock(nameBlock, 11, nNameFile, nNamePos);

    uint256 hashPrevious = fundBlock.GetHash();
    uint256 hashCurrent = nameBlock.GetHash();
    CBlockIndex previous;
    previous.phashBlock = &hashPrevious;
    previous.nHeight = 10;
    CBlockIndex current(nNameFile, nNamePos, nameBlock);
    current.phashBlock = &hashCurrent;
    current.pprev = &previous;
    current.nHeight = 11;

    const CNameIndexCursor cursorPrevious =
        MakeChainCursor(previous.nHeight, hashPrevious);
    SeedIndexAt(strName, cursorPrevious);

    std::string strError;
    {
        CTxDB txdb("r+");
        BOOST_REQUIRE_MESSAGE(
            ApplyNameIndexConnectBlock(txdb, &current, strError), strError);
    }
    fIndexedAfterConnect = NameIsIndexed(strName);

    strError.clear();
    const bool fDisconnected =
        ApplyNameIndexDisconnectBlock(nameBlock, &current, strError);
    fIndexedAfterDisconnect = NameIsIndexed(strName);
    if (!fDisconnected)
        BOOST_TEST_MESSAGE("disconnect failed: " + strError);
    return fDisconnected;
}

CNameRecord MakeRecord(int nRegistrationHeight)
{
    CNameRecord rec;
    CNameIndex ind;
    ind.nHeight = nRegistrationHeight;
    ind.op = OP_NAME_NEW;
    rec.vtxPos.push_back(ind);
    rec.nLastActiveChainIndex = 0;
    return rec;
}
} // namespace

// A term bought and spent entirely below the DAG gate must convert at exactly
// the legacy 5760 blocks/day, so no already-indexed pre-DAG name moves.
BOOST_AUTO_TEST_CASE(pre_dag_conversion_matches_legacy_constant)
{
    CNetworkOverride mainnet(false, false);
    const int64_t nDag = FORK_HEIGHT_DAG;
    const int64_t nStart = nDag - 400000; // 400k blocks of headroom at 15s

    for (int nDays = 1; nDays <= 60; ++nDays)
        BOOST_CHECK_EQUAL(NameRentalBlocks(nStart, nDays),
                          (int64_t)nDays * 5760);
}

// The same term bought after the gate must convert at 86,400 blocks/day.
BOOST_AUTO_TEST_CASE(post_dag_conversion_is_one_second_blocks)
{
    CNetworkOverride mainnet(false, false);
    const int64_t nStart = (int64_t)FORK_HEIGHT_DAG + 1;

    BOOST_CHECK_EQUAL(NameRentalBlocks(nStart, 1), 86400);
    BOOST_CHECK_EQUAL(NameRentalBlocks(nStart, MAX_RENTAL_DAYS),
                      (int64_t)MAX_RENTAL_DAYS * 86400);
}

// A term that starts before the gate and ends after it is the case the flat
// constant got wrong: 180 days at 5760 blocks/day lands ~36 wall-clock days
// after the gate, not 180.
BOOST_AUTO_TEST_CASE(term_spanning_the_dag_gate_is_six_real_months)
{
    CNetworkOverride mainnet(false, false);
    const int64_t nDag = FORK_HEIGHT_DAG;
    const int64_t nStart = FORK_HEIGHT_IDNS_RESET; // first height a name can live at
    BOOST_REQUIRE(nStart < nDag);

    const int64_t nBlocks = NameRentalBlocks(nStart, MAX_RENTAL_DAYS);
    const int64_t nSeconds = NameBlocksToSeconds(nStart, nStart + nBlocks);
    BOOST_CHECK_EQUAL(nSeconds, (int64_t)MAX_RENTAL_DAYS * SECONDS_PER_DAY);

    // The reset sits between the v5 first gate and the DAG gate, so the very
    // first registrations really do straddle the spacing change: the term must
    // be converted at 15s up to the gate and 1s after it.
    BOOST_REQUIRE(nStart + nBlocks > nDag);
    const int64_t nPreGate = nDag - nStart;
    BOOST_CHECK_EQUAL(NameBlocksToSeconds(nStart, nDag),
                      nPreGate * PRE_DAG_TARGET_SPACING);
    BOOST_CHECK_EQUAL(NameBlocksToSeconds(nDag, nStart + nBlocks),
                      (nStart + nBlocks - nDag) * POST_DAG_TARGET_SPACING);

    // Registering one block later buys the same wall clock, one 15s block of
    // pre-gate room less.
    BOOST_CHECK_EQUAL(
        NameBlocksToSeconds(nStart + 1,
                            nStart + 1 + NameRentalBlocks(nStart + 1,
                                                          MAX_RENTAL_DAYS)),
        nSeconds);

    // The legacy constant would have been short by the spacing ratio.
    const int64_t nLegacyBlocks = (int64_t)MAX_RENTAL_DAYS * 5760;
    const int64_t nLegacySeconds =
        NameBlocksToSeconds(nStart, nStart + nLegacyBlocks);
    BOOST_CHECK(nLegacySeconds < nSeconds);
    BOOST_CHECK(nLegacySeconds / SECONDS_PER_DAY < 40);
}

// Conversion is exact in both directions at every position relative to the gate.
BOOST_AUTO_TEST_CASE(blocks_and_seconds_round_trip_across_the_gate)
{
    CNetworkOverride mainnet(false, false);
    const int64_t nDag = FORK_HEIGHT_DAG;
    const int64_t vStarts[] = { nDag - 1000000, nDag - 150000, nDag - 1,
                                nDag, nDag + 1, nDag + 5000000 };

    for (size_t i = 0; i < sizeof(vStarts) / sizeof(vStarts[0]); ++i)
    {
        for (int nDays = 1; nDays <= MAX_RENTAL_DAYS; nDays += 17)
        {
            const int64_t nStart = vStarts[i];
            const int64_t nBlocks = NameRentalBlocks(nStart, nDays);
            BOOST_CHECK_EQUAL(NameBlocksToSeconds(nStart, nStart + nBlocks),
                              (int64_t)nDays * SECONDS_PER_DAY);
        }
    }
}

// Wall-clock length must not depend on which side of the gate you buy from.
BOOST_AUTO_TEST_CASE(term_length_is_spacing_independent)
{
    CNetworkOverride mainnet(false, false);
    const int64_t nDag = FORK_HEIGHT_DAG;
    const int64_t nBefore = nDag - 90000;
    const int64_t nAfter = nDag + 90000;

    const int64_t nBlocksBefore = NameRentalBlocks(nBefore, MAX_RENTAL_DAYS);
    const int64_t nBlocksAfter = NameRentalBlocks(nAfter, MAX_RENTAL_DAYS);

    BOOST_CHECK_EQUAL(NameBlocksToSeconds(nBefore, nBefore + nBlocksBefore),
                      NameBlocksToSeconds(nAfter, nAfter + nBlocksAfter));
    // Same wall clock, different block counts: the pre-gate term spends its
    // first stretch at 15s.
    BOOST_CHECK(nBlocksBefore < nBlocksAfter);
}

BOOST_AUTO_TEST_CASE(conversion_rejects_and_clamps_degenerate_terms)
{
    CNetworkOverride mainnet(false, false);
    const int64_t nStart = FORK_HEIGHT_DAG + 10;

    BOOST_CHECK_EQUAL(NameRentalBlocks(nStart, 0), 0);
    BOOST_CHECK_EQUAL(NameRentalBlocks(nStart, -5), 0);
    // Clamped to the widest decodable term; must not overflow into a negative.
    BOOST_CHECK(NameRentalBlocks(nStart, (int64_t)MAX_RENTAL_DAYS_PRE_V5 * 100) > 0);
    BOOST_CHECK_EQUAL(NameRentalBlocks(nStart, (int64_t)MAX_RENTAL_DAYS_PRE_V5 * 100),
                      NameRentalBlocks(nStart, MAX_RENTAL_DAYS_PRE_V5));
}

// Regtest collapses both spacings to 1s, so the conversion must be flat there.
BOOST_AUTO_TEST_CASE(regtest_conversion_is_flat)
{
    CNetworkOverride regtest(true, false);
    BOOST_CHECK_EQUAL(NameRentalBlocks(0, 1), 86400);
    BOOST_CHECK_EQUAL(NameRentalBlocks(FORK_HEIGHT_DAG + 100, 1), 86400);
}

// The reset is a chain event. Before its height nothing is reset; a binary that
// merely carries the constant must not expire live names.
BOOST_AUTO_TEST_CASE(reset_does_not_apply_below_its_height)
{
    CNetworkOverride mainnet(false, false);
    const int nReset = FORK_HEIGHT_IDNS_RESET;
    BOOST_REQUIRE(nReset > 0);

    CNameRecord old = MakeRecord(nReset - 500000);
    BOOST_CHECK(!NameResetExpired(old, nReset - 1));
    BOOST_CHECK(NameResetExpired(old, nReset));
    BOOST_CHECK(NameResetExpired(old, nReset + 1));
}

// A name registered after the upgrade but before the gate stayed live until the
// gate; the ungated check killed it on arrival and let it be sniped.
BOOST_AUTO_TEST_CASE(pre_gate_registration_survives_until_the_gate)
{
    CNetworkOverride mainnet(false, false);
    const int nReset = FORK_HEIGHT_IDNS_RESET;
    CNameRecord fresh = MakeRecord(nReset - 10);

    BOOST_CHECK(!NameResetExpired(fresh, nReset - 10));
    BOOST_CHECK(!NameResetExpired(fresh, nReset - 1));
    BOOST_CHECK(NameResetExpired(fresh, nReset));
}

BOOST_AUTO_TEST_CASE(registration_at_or_after_the_gate_is_never_reset)
{
    CNetworkOverride mainnet(false, false);
    const int nReset = FORK_HEIGHT_IDNS_RESET;
    CNameRecord rec = MakeRecord(nReset);

    BOOST_CHECK(!NameResetExpired(rec, nReset));
    BOOST_CHECK(!NameResetExpired(rec, nReset + 1000000));
}

// Reset is off on clean chains, at every height.
BOOST_AUTO_TEST_CASE(reset_is_inert_off_mainnet)
{
    CNetworkOverride regtest(true, false);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_IDNS_RESET, 0);
    CNameRecord rec = MakeRecord(0);
    BOOST_CHECK(!NameResetExpired(rec, 0));
    BOOST_CHECK(!NameResetExpired(rec, 1000000));
}

BOOST_AUTO_TEST_CASE(reset_ignores_a_malformed_active_chain_index)
{
    CNetworkOverride mainnet(false, false);
    CNameRecord rec;
    BOOST_CHECK(!NameResetExpired(rec, FORK_HEIGHT_IDNS_RESET + 1));

    rec = MakeRecord(FORK_HEIGHT_IDNS_RESET - 1);
    rec.nLastActiveChainIndex = 5; // out of range
    BOOST_CHECK(!NameResetExpired(rec, FORK_HEIGHT_IDNS_RESET + 1));
}

// The term bound is gated on the mined height so pre-gate history keeps the
// bound it was indexed under.
BOOST_AUTO_TEST_CASE(term_bound_is_height_gated_on_mainnet)
{
    CNetworkOverride mainnet(false, false);
    const int nReset = FORK_HEIGHT_IDNS_RESET;

    BOOST_CHECK_EQUAL(GetMaxRentalDays(nReset), MAX_RENTAL_DAYS);
    BOOST_CHECK_EQUAL(GetMaxRentalDays(nReset + 1), MAX_RENTAL_DAYS);
    BOOST_CHECK_EQUAL(GetMaxRentalDays(nReset - 1), MAX_RENTAL_DAYS_PRE_V5);
    BOOST_CHECK_EQUAL(GetMaxRentalDays(RELEASE_HEIGHT), MAX_RENTAL_DAYS_PRE_V5);
    BOOST_CHECK_EQUAL(MAX_RENTAL_DAYS, 180);
}

// Clean chains have no pre-gate era, so the six-month bound holds from genesis.
BOOST_AUTO_TEST_CASE(term_bound_is_six_months_off_mainnet)
{
    CNetworkOverride regtest(true, false);
    BOOST_CHECK_EQUAL(GetMaxRentalDays(0), MAX_RENTAL_DAYS);
    BOOST_CHECK_EQUAL(GetMaxRentalDays(1000000), MAX_RENTAL_DAYS);
}

// Stacked rentals extend the running expiry, so a chain of updates that crosses
// the gate is converted piecewise rather than at the rate of its first tx.
BOOST_AUTO_TEST_CASE(stacked_rentals_extend_from_the_running_expiry)
{
    CNetworkOverride mainnet(false, false);
    const int64_t nDag = FORK_HEIGHT_DAG;
    const int64_t nStart = nDag - 5760 * 10; // 10 days of pre-gate room

    // 30 + 30 days stacked equals 60 days bought at once.
    int64_t nExpires = nStart;
    nExpires += NameRentalBlocks(nExpires, 30);
    nExpires += NameRentalBlocks(nExpires, 30);

    const int64_t nAtOnce = nStart + NameRentalBlocks(nStart, 60);
    BOOST_CHECK_EQUAL(nExpires, nAtOnce);
    BOOST_CHECK_EQUAL(NameBlocksToSeconds(nStart, nExpires),
                      60 * SECONDS_PER_DAY);
}

// Control: an indexable name op must still be applied at connect and undone at
// disconnect, so the skip path below cannot be satisfied by never undoing
// anything.
BOOST_AUTO_TEST_CASE(indexable_name_op_connects_and_disconnects)
{
    bool fAfterConnect = false;
    bool fAfterDisconnect = true;
    BOOST_CHECK(ConnectThenDisconnectNameTx(
        "control.inn", 30, OP_NAME_NEW, 0x51000, false,
        fAfterConnect, fAfterDisconnect));
    BOOST_CHECK(fAfterConnect);
    BOOST_CHECK(!fAfterDisconnect);
}

// Connect skips a name op it will not index; Disconnect must treat the missing
// index entry as expected, not corruption, or the first reorg over it halts the node.
BOOST_AUTO_TEST_CASE(over_term_name_op_survives_a_reorg)
{
    BOOST_REQUIRE(GetMaxRentalDays(11) == MAX_RENTAL_DAYS);
    bool fAfterConnect = true;
    bool fAfterDisconnect = true;
    BOOST_CHECK(ConnectThenDisconnectNameTx(
        "overterm.inn", MAX_RENTAL_DAYS + 1, OP_NAME_NEW, 0x52000, false,
        fAfterConnect, fAfterDisconnect));
    BOOST_CHECK(!fAfterConnect);
    BOOST_CHECK(!fAfterDisconnect);
}

// The same hazard predates the term bound: every connect-skip reason lands in
// the same state. name_update against a name the index does not hold is one of
// the original ones.
BOOST_AUTO_TEST_CASE(update_of_an_absent_name_survives_a_reorg)
{
    bool fAfterConnect = true;
    bool fAfterDisconnect = true;
    BOOST_CHECK(ConnectThenDisconnectNameTx(
        "absent.inn", 30, OP_NAME_UPDATE, 0x53000, true,
        fAfterConnect, fAfterDisconnect));
    BOOST_CHECK(!fAfterConnect);
    BOOST_CHECK(!fAfterDisconnect);
}

// A name tx that does not decode is skipped at connect for the same reason, so
// disconnect must not read it as corruption either.
BOOST_AUTO_TEST_CASE(undecodable_name_tx_survives_a_reorg)
{
    CTransaction bogus;
    bogus.nVersion = NAMECOIN_TX_VERSION;
    bogus.nTime = 0x54000;
    bogus.vin.push_back(CTxIn(COutPoint(uint256(0x54001), 0)));
    bogus.vout.push_back(CTxOut(1, CScript() << OP_TRUE));

    CBlock block;
    AddCoinbaseAndCoinstake(block, 0x54002);
    block.vtx.push_back(bogus);
    block.hashPrevBlock = uint256(0x54006);
    block.nTime = 0x54007;
    block.hashMerkleRoot = block.BuildMerkleTree();

    uint256 hashPrevious = block.hashPrevBlock;
    uint256 hashCurrent = block.GetHash();
    CBlockIndex previous;
    previous.phashBlock = &hashPrevious;
    previous.nHeight = 20;
    CBlockIndex current;
    current.phashBlock = &hashCurrent;
    current.pprev = &previous;
    current.nHeight = 21;

    SeedIndexAt("undecodable.inn",
                MakeChainCursor(current.nHeight, hashCurrent));

    CPreparedNameIndexTransition prepared;
    std::string strError;
    BOOST_CHECK_MESSAGE(PrepareNameIndexDisconnectTransition(
        block, &current, prepared, strError), strError);
    BOOST_CHECK(prepared.vEffects.empty());
}

BOOST_AUTO_TEST_SUITE_END()
