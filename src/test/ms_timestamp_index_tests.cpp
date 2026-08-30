// CBlockIndex::nTimeMs storage: the on-disk record, the record generations a node can
// meet, and the cache agreeing with its coinbase. The field is a trailing optional after
// nSize, told apart by the bytes remaining; the wire and block hash are unchanged.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../init.h"
#include "../main.h"
#include "../miner.h"
#include "../mstimestamp.h"
#include "../txdb.h"
#include "../wallet.h"

extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(ms_timestamp_index_tests)

namespace
{

// A padded proof-of-work block, the shape CBlockIndex(nFile, nPos, block)
// measures.
CBlock MakeBlock(unsigned int nSeed, uint16_t nTimeMs, bool fCommit)
{
    CBlock block;
    CTransaction tx;
    tx.nTime = 1296688602 + nSeed;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << (int64_t)nSeed;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    if (fCommit)
    {
        CTxOut msOut;
        msOut.nValue = 0;
        msOut.scriptPubKey = BuildMsTimestampScript(nTimeMs);
        tx.vout.push_back(msOut);
    }
    block.vtx.push_back(tx);

    block.nVersion = 1;
    block.hashPrevBlock = 0;
    block.nTime = 1296688602 + nSeed;
    block.nBits = 0x207fffff;
    block.nNonce = nSeed;
    block.hashMerkleRoot = block.BuildMerkleTree();
    return block;
}

// Serialize a record the way CTxDB::WriteBlockIndex does.
std::string EncodeRecord(CBlockIndex* pindex)
{
    CDiskBlockIndex diskindex(pindex);
    diskindex.GetBlockHash();
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << diskindex;
    return ss.str();
}

CDiskBlockIndex DecodeRecord(const std::string& strValue)
{
    CDataStream ss(strValue.data(), strValue.data() + strValue.size(),
                   SER_DISK, CLIENT_VERSION);
    CDiskBlockIndex diskindex;
    ss >> diskindex;
    return diskindex;
}

bool SolveBlock(CBlock* pblock)
{
    CBigNum target;
    target.SetCompact(pblock->nBits);
    const uint256 hashTarget = target.getuint256();
    unsigned int nHashes = 0;
    while (pblock->GetPoWHash() > hashTarget)
    {
        ++pblock->nNonce;
        if (pblock->nNonce == 0)
            ++pblock->nTime;
        if (++nHashes > 4000000U)
            return false;
    }
    return true;
}

CBlockIndex* BestIndex()
{
    LOCK(cs_main);
    return pindexBest;
}

struct MsGateGuard
{
    int nSaved;
    explicit MsGateGuard(int nHeight) : nSaved(nRegtestMsTimestampHeight)
    {
        nRegtestMsTimestampHeight = nHeight;
    }
    ~MsGateGuard() { nRegtestMsTimestampHeight = nSaved; }
};

std::unique_ptr<CBlock> MineOne()
{
    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (!pblock.get())
        return pblock;
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    if (!SolveBlock(pblock.get()))
        return std::unique_ptr<CBlock>();
    const uint256 hash = pblock->GetHash();
    if (!ProcessBlock(NULL, pblock.get()))
        return std::unique_ptr<CBlock>();
    LOCK(cs_main);
    if (!mapBlockIndex.count(hash))
        return std::unique_ptr<CBlock>();
    return pblock;
}

CBlockIndex* IndexFor(const uint256& hash)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

// The offset a block's own coinbase commits to, or 0 when it carries none.
uint16_t CommittedOffset(const CBlock& block, bool& fPresent)
{
    std::vector<CScript> vScripts;
    for (unsigned int i = 0; i < block.vtx[0].vout.size(); ++i)
        vScripts.push_back(block.vtx[0].vout[i].scriptPubKey);
    uint16_t nMs = 0;
    std::string strError;
    fPresent = ExtractCanonicalMsTimestampCommitment(vScripts, nMs, strError);
    return fPresent ? nMs : (uint16_t)0;
}

} // namespace


// Positive control for every storage case: a record carrying the field survives
// the restart round trip, and ApplyDiskBlockIndexFields copies it onto the rebuilt
// index (a CDiskBlockIndex field missing from that copy diverges state).
BOOST_AUTO_TEST_CASE(a_record_with_the_field_round_trips)
{
    const unsigned int nOffsets[] = { 0, 1, 255, 256, 999 };
    for (size_t i = 0; i < sizeof(nOffsets) / sizeof(nOffsets[0]); ++i)
    {
        CBlock block = MakeBlock(4000 + (unsigned int)i,
                                 (uint16_t)nOffsets[i], true);
        CBlockIndex index(7, 11, block);
        index.nHeight = 100 + (int)i;
        index.nTimeMs = (uint16_t)nOffsets[i];
        const uint256 hash = block.GetHash();
        index.phashBlock = &hash;

        const CDiskBlockIndex reloaded = DecodeRecord(EncodeRecord(&index));
        BOOST_CHECK_EQUAL(reloaded.nTimeMs, (uint16_t)nOffsets[i]);
        BOOST_CHECK_EQUAL(reloaded.nSize, index.nSize);

        CBlockIndex applied;
        ApplyDiskBlockIndexFields(reloaded, &applied);
        BOOST_CHECK_MESSAGE(applied.nTimeMs == (uint16_t)nOffsets[i],
                            "offset " << nOffsets[i]
                                      << " was not copied onto the rebuilt index");
        BOOST_CHECK_EQUAL(applied.nSize, index.nSize);
        BOOST_CHECK_EQUAL(applied.nTime, index.nTime);
        BOOST_CHECK_EQUAL(applied.GetBlockTimeMs(),
                          MsTimestampCombine(index.nTime,
                                             (uint16_t)nOffsets[i]));
    }
}

// The field is appended, so a different offset changes only the last two bytes, and
// truncating there yields the record an older binary wrote (downgrade-safe).
BOOST_AUTO_TEST_CASE(the_field_is_appended_and_changes_only_the_tail)
{
    CBlock block = MakeBlock(4100, 0, true);
    CBlockIndex index(3, 5, block);
    index.nHeight = 200;
    const uint256 hash = block.GetHash();
    index.phashBlock = &hash;

    index.nTimeMs = 0;
    const std::string strZero = EncodeRecord(&index);
    index.nTimeMs = 999;
    const std::string strMax = EncodeRecord(&index);

    BOOST_REQUIRE_EQUAL(strZero.size(), strMax.size());
    BOOST_REQUIRE_GT(strZero.size(), sizeof(uint16_t));
    const size_t nPrefix = strZero.size() - sizeof(uint16_t);
    BOOST_CHECK_EQUAL(strZero.compare(0, nPrefix, strMax, 0, nPrefix), 0);
    BOOST_CHECK(strZero.compare(nPrefix, sizeof(uint16_t),
                                strMax, nPrefix, sizeof(uint16_t)) != 0);

    // Little-endian, so the two payload bytes are the offset itself.
    BOOST_CHECK_EQUAL((unsigned char)strMax[nPrefix], (unsigned char)(999 & 0xff));
    BOOST_CHECK_EQUAL((unsigned char)strMax[nPrefix + 1], (unsigned char)(999 >> 8));
}

// The three on-disk generations are separated by the bytes remaining. A pre-field record
// must not read as offset garbage, and a pre-nSize one must not read size bytes as offset.
BOOST_AUTO_TEST_CASE(three_record_generations_are_separated_by_remaining_bytes)
{
    CBlock block = MakeBlock(4200, 777, true);
    CBlockIndex index(2, 9, block);
    index.nHeight = 300;
    index.nTimeMs = 777;
    const uint256 hash = block.GetHash();
    index.phashBlock = &hash;

    const std::string strCurrent = EncodeRecord(&index);
    BOOST_REQUIRE_GT(strCurrent.size(), sizeof(uint16_t) + sizeof(unsigned int));

    // Generation 3: both trailing fields present.
    const CDiskBlockIndex current = DecodeRecord(strCurrent);
    BOOST_CHECK_EQUAL(current.nTimeMs, 777);
    BOOST_CHECK_EQUAL(current.nSize, index.nSize);

    // Generation 2: written after nSize, before nTimeMs.
    const std::string strNoMs =
        strCurrent.substr(0, strCurrent.size() - sizeof(uint16_t));
    const CDiskBlockIndex noMs = DecodeRecord(strNoMs);
    BOOST_CHECK_EQUAL(noMs.nTimeMs, 0);
    BOOST_CHECK_EQUAL(noMs.nSize, index.nSize);

    // Generation 1: written before either field.
    const std::string strNeither = strCurrent.substr(
        0, strCurrent.size() - sizeof(uint16_t) - sizeof(unsigned int));
    const CDiskBlockIndex neither = DecodeRecord(strNeither);
    BOOST_CHECK_EQUAL(neither.nTimeMs, 0);
    BOOST_CHECK_EQUAL(neither.nSize, 0U);

    // The generation-1 record must not have consumed the size bytes as the
    // offset, which is what a reader that checked only "any bytes remain"
    // would do.
    BOOST_CHECK_MESSAGE(neither.nTimeMs != (uint16_t)(index.nSize & 0xffff),
                        "the size bytes were read back as the offset");

    // Copying a record that predates the field leaves the rebuilt index at the
    // unknown value rather than at whatever the object already held.
    CBlockIndex applied;
    applied.nTimeMs = 4242;
    ApplyDiskBlockIndexFields(noMs, &applied);
    BOOST_CHECK_EQUAL(applied.nTimeMs, 0);
}

// A block that carries no commitment caches a zero offset, and its record is
// indistinguishable in the field from a block that committed to zero. The two
// are separated by height, not by the record.
BOOST_AUTO_TEST_CASE(an_uncommitted_block_caches_a_zero_offset)
{
    CBlock block = MakeBlock(4300, 0, false);
    bool fPresent = true;
    BOOST_CHECK_EQUAL(CommittedOffset(block, fPresent), 0);
    BOOST_CHECK(!fPresent);

    CBlockIndex index(1, 1, block);
    index.nHeight = 5;
    const uint256 hash = block.GetHash();
    index.phashBlock = &hash;
    BOOST_CHECK_EQUAL(index.nTimeMs, 0);
    BOOST_CHECK_EQUAL(index.GetBlockTimeMs(), index.GetBlockTime() * 1000);

    const CDiskBlockIndex reloaded = DecodeRecord(EncodeRecord(&index));
    BOOST_CHECK_EQUAL(reloaded.nTimeMs, 0);
}

// For every block from the gate on, the cached offset equals the one its coinbase commits
// to, in the re-read block and in the record a restart reloads.
BOOST_AUTO_TEST_CASE(the_index_cache_agrees_with_the_coinbase_after_a_reindex)
{
    BOOST_REQUIRE(fRegTest);
    const int nBase = BestIndex()->nHeight;
    MsGateGuard guard(nBase + 2);

    std::vector<uint256> vHashes;
    for (int i = 0; i < 5; ++i)
    {
        std::unique_ptr<CBlock> pblock(MineOne());
        BOOST_REQUIRE(pblock.get() != NULL);
        vHashes.push_back(pblock->GetHash());
    }

    int nChecked = 0;
    int nWithCommitment = 0;
    for (size_t i = 0; i < vHashes.size(); ++i)
    {
        CBlockIndex* pindex = IndexFor(vHashes[i]);
        BOOST_REQUIRE(pindex != NULL);

        // The block as it was persisted, not the in-memory template.
        CBlock onDisk;
        BOOST_REQUIRE_MESSAGE(onDisk.ReadFromDisk(pindex, true),
                              "block at height " << pindex->nHeight
                                                 << " could not be re-read");
        bool fPresent = false;
        const uint16_t nCommitted = CommittedOffset(onDisk, fPresent);

        BOOST_CHECK_MESSAGE(fPresent == (pindex->nHeight >= FORK_HEIGHT_MS_TIMESTAMP),
                            "height " << pindex->nHeight
                                      << " commitment present=" << fPresent);
        BOOST_CHECK_MESSAGE(pindex->nTimeMs == nCommitted,
                            "height " << pindex->nHeight << ": cache "
                                      << pindex->nTimeMs << " != coinbase "
                                      << nCommitted);
        BOOST_CHECK_EQUAL(pindex->GetBlockTimeMs(),
                          MsTimestampCombine(onDisk.nTime, nCommitted));

        // What a restart rebuilds from the record.
        const CDiskBlockIndex reloaded = DecodeRecord(EncodeRecord(pindex));
        CBlockIndex applied;
        ApplyDiskBlockIndexFields(reloaded, &applied);
        BOOST_CHECK_MESSAGE(applied.nTimeMs == nCommitted,
                            "height " << pindex->nHeight
                                      << ": reloaded index disagrees with the coinbase");
        BOOST_CHECK_EQUAL(applied.nTime, onDisk.nTime);

        nChecked++;
        if (fPresent)
            nWithCommitment++;
    }
    BOOST_CHECK_EQUAL(nChecked, 5);
    // Both eras were reached, so neither half of the comparison was vacuous.
    BOOST_CHECK_GT(nWithCommitment, 0);
    BOOST_CHECK_LT(nWithCommitment, nChecked);
}

BOOST_AUTO_TEST_SUITE_END()
