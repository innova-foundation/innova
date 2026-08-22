// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// CBlockIndex::nSize feeds consensus size limits; an index rebuilt from disk must recover
// the same value a freshly synced node computes.

#include <boost/test/unit_test.hpp>

#include "main.h"

#include <algorithm>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(blockindex_nsize_tests)

namespace {

// A padded proof-of-work block of approximately nTargetBytes.
CBlock MakeSizedBlock(unsigned int nTargetBytes, unsigned int nSeed)
{
    CBlock block;
    CTransaction tx;
    tx.nTime = 1296688602 + nSeed;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << (int64_t)nSeed;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;
    block.vtx.push_back(tx);

    block.nVersion = 1;
    block.hashPrevBlock = 0;
    block.nTime = 1296688602 + nSeed;
    block.nBits = 0x207fffff;
    block.nNonce = nSeed;

    // Grow the coinbase output script until the block reaches the target.
    unsigned int nPad = nTargetBytes;
    for (int i = 0; i < 8; i++)
    {
        block.vtx[0].vout[0].scriptPubKey = CScript();
        block.vtx[0].vout[0].scriptPubKey.resize(nPad, 0x51);
        block.hashMerkleRoot = block.BuildMerkleTree();
        const unsigned int nHave = ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
        if (nHave == nTargetBytes)
            break;
        if (nHave > nTargetBytes)
            nPad -= (nHave - nTargetBytes);
        else
            nPad += (nTargetBytes - nHave);
    }
    block.hashMerkleRoot = block.BuildMerkleTree();
    return block;
}

// Twenty-one post-DAG blocks whose median is comfortably above
// ADAPTIVE_BLOCK_FLOOR, so a lost nSize changes the computed limit.
const int CHAIN_LEN = 21;

unsigned int TargetSizeAt(int i)
{
    return 310000 + (unsigned int)i * 20000;
}

// Owns an in-process index chain plus the block files it was built from.
struct WrittenChain
{
    std::vector<uint256> vHashes;
    std::vector<CBlockIndex*> vIndex;
    std::vector<unsigned int> vFile;
    std::vector<unsigned int> vPos;

    WrittenChain()
    {
        vHashes.reserve(CHAIN_LEN);
        for (int i = 0; i < CHAIN_LEN; i++)
        {
            CBlock block = MakeSizedBlock(TargetSizeAt(i), 1000 + i);
            unsigned int nFile = 0;
            unsigned int nPos = 0;
            BOOST_REQUIRE(block.WriteToDisk(nFile, nPos));
            vFile.push_back(nFile);
            vPos.push_back(nPos);

            CBlockIndex* pindex = new CBlockIndex(nFile, nPos, block);
            pindex->nHeight = FORK_HEIGHT_DAG + i;
            pindex->pprev = vIndex.empty() ? NULL : vIndex.back();
            vHashes.push_back(block.GetHash());
            pindex->phashBlock = &vHashes.back();
            vIndex.push_back(pindex);
        }
    }

    ~WrittenChain()
    {
        for (size_t i = 0; i < vIndex.size(); i++)
            delete vIndex[i];
    }

    CBlockIndex* Tip() const { return vIndex.back(); }
};

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

// Rebuild an index chain from encoded records, exactly as CTxDB::LoadBlockIndex
// does: decode, copy the persisted fields, relink.
struct ReloadedChain
{
    std::vector<uint256> vHashes;
    std::vector<CBlockIndex*> vIndex;

    explicit ReloadedChain(const std::vector<std::string>& vRecords)
    {
        vHashes.reserve(vRecords.size());
        for (size_t i = 0; i < vRecords.size(); i++)
        {
            const CDiskBlockIndex diskindex = DecodeRecord(vRecords[i]);
            CBlockIndex* pindex = new CBlockIndex();
            ApplyDiskBlockIndexFields(diskindex, pindex);
            pindex->pprev = vIndex.empty() ? NULL : vIndex.back();
            vHashes.push_back(diskindex.GetBlockHash());
            pindex->phashBlock = &vHashes.back();
            vIndex.push_back(pindex);
        }
    }

    ~ReloadedChain()
    {
        for (size_t i = 0; i < vIndex.size(); i++)
            delete vIndex[i];
    }

    CBlockIndex* Tip() const { return vIndex.back(); }
    const std::vector<CBlockIndex*>& All() const { return vIndex; }
};


// Write a block carrying an eight-byte decoy inside its coinbase padding and
// return the offset just past the decoy -- the position an index would hold if
// those eight bytes were a real magic-and-size prefix.
unsigned int WriteBlockWithDecoy(const unsigned char* pchDecoy, unsigned int nSeed,
                                 unsigned int& nFileRet)
{
    CBlock block = MakeSizedBlock(340000, nSeed);
    CScript& script = block.vtx[0].vout[0].scriptPubKey;
    BOOST_REQUIRE(script.size() > 32);
    memcpy(&script[8], pchDecoy, 8);
    block.hashMerkleRoot = block.BuildMerkleTree();

    unsigned int nPos = 0;
    nFileRet = 0;
    BOOST_REQUIRE(block.WriteToDisk(nFileRet, nPos));

    const unsigned int nBytes = ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
    std::vector<unsigned char> vBytes(nBytes);
    FILE* file = OpenBlockFile(nFileRet, 0, "rb");
    BOOST_REQUIRE(file != NULL);
    BOOST_REQUIRE_EQUAL(fseek(file, (long)nPos, SEEK_SET), 0);
    const size_t nRead = fread(&vBytes[0], 1, vBytes.size(), file);
    fclose(file);
    BOOST_REQUIRE_EQUAL(nRead, (size_t)nBytes);

    std::vector<unsigned char>::iterator it =
        std::search(vBytes.begin(), vBytes.end(), pchDecoy, pchDecoy + 8);
    BOOST_REQUIRE(it != vBytes.end());
    return nPos + (unsigned int)(it - vBytes.begin()) + 8;
}

} // namespace

// The size prefix CBlock::WriteToDisk lays down ahead of every block is the
// only on-disk record of the block's size, and it has to agree with the measure
// CBlockIndex and both adaptive-size consumers use.
BOOST_AUTO_TEST_CASE(disk_size_prefix_equals_index_size)
{
    CBlock block = MakeSizedBlock(400000, 77);
    unsigned int nFile = 0, nPos = 0;
    BOOST_REQUIRE(block.WriteToDisk(nFile, nPos));

    CBlockIndex index(nFile, nPos, block);
    BOOST_CHECK_EQUAL(index.nSize,
                      ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION));
    BOOST_CHECK_EQUAL(index.nSize,
                      ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION));

    FILE* file = OpenBlockFile(nFile, 0, "rb");
    BOOST_REQUIRE(file != NULL);
    unsigned char pchHeader[8];
    BOOST_REQUIRE_EQUAL(fseek(file, (long)nPos - 8, SEEK_SET), 0);
    BOOST_REQUIRE_EQUAL(fread(pchHeader, 1, 8, file), (size_t)8);
    fclose(file);
    BOOST_CHECK_EQUAL(memcmp(pchHeader, pchMessageStart, 4), 0);
    unsigned int nPrefix = 0;
    memcpy(&nPrefix, pchHeader + 4, 4);
    BOOST_CHECK_EQUAL(nPrefix, index.nSize);
}

// A persisted record carries nSize, so a normal restart needs no file reads.
BOOST_AUTO_TEST_CASE(record_roundtrip_preserves_nsize)
{
    CBlock block = MakeSizedBlock(415000, 78);
    unsigned int nFile = 0, nPos = 0;
    BOOST_REQUIRE(block.WriteToDisk(nFile, nPos));
    CBlockIndex index(nFile, nPos, block);
    index.nHeight = FORK_HEIGHT_DAG + 5;
    uint256 hash = block.GetHash();
    index.phashBlock = &hash;

    const CDiskBlockIndex decoded = DecodeRecord(EncodeRecord(&index));
    BOOST_CHECK_EQUAL(decoded.nSize, index.nSize);
    BOOST_CHECK(decoded.nSize != 0);

    CBlockIndex reloaded;
    ApplyDiskBlockIndexFields(decoded, &reloaded);
    BOOST_CHECK_EQUAL(reloaded.nSize, index.nSize);
    BOOST_CHECK_EQUAL(reloaded.nHeight, index.nHeight);
    BOOST_CHECK_EQUAL(reloaded.nBlockPos, index.nBlockPos);
}

// Records written before nSize existed end at blockHash. Reading one must
// report "unknown" rather than throw or invent a value.
BOOST_AUTO_TEST_CASE(legacy_record_without_nsize_reads_unknown)
{
    CBlock block = MakeSizedBlock(420000, 79);
    unsigned int nFile = 0, nPos = 0;
    BOOST_REQUIRE(block.WriteToDisk(nFile, nPos));
    CBlockIndex index(nFile, nPos, block);
    index.nHeight = FORK_HEIGHT_DAG + 6;
    uint256 hash = block.GetHash();
    index.phashBlock = &hash;

    const std::string strFull = EncodeRecord(&index);
    const std::string strLegacy = strFull.substr(0, strFull.size() - sizeof(unsigned int));
    BOOST_REQUIRE_EQUAL(strFull.size() - strLegacy.size(), sizeof(unsigned int));

    const CDiskBlockIndex decoded = DecodeRecord(strLegacy);
    BOOST_CHECK_EQUAL(decoded.nSize, 0u);
    // Every field ahead of the optional tail still decodes.
    BOOST_CHECK_EQUAL(decoded.nHeight, index.nHeight);
    BOOST_CHECK_EQUAL(decoded.nBlockPos, index.nBlockPos);
    BOOST_CHECK_EQUAL(decoded.nFile, index.nFile);
    BOOST_CHECK(decoded.nBits == index.nBits);
}

// An index rebuilt from pre-nSize records must compute the same limit as the
// in-process index.
BOOST_AUTO_TEST_CASE(reloaded_legacy_index_matches_in_process_limit)
{
    WrittenChain live;
    const unsigned int nLiveLimit = GetAdaptiveBlockSizeLimit(live.Tip());
    BOOST_REQUIRE(nLiveLimit > 2 * ADAPTIVE_BLOCK_FLOOR);

    std::vector<std::string> vRecords;
    for (int i = 0; i < CHAIN_LEN; i++)
    {
        const std::string strFull = EncodeRecord(live.vIndex[i]);
        vRecords.push_back(strFull.substr(0, strFull.size() - sizeof(unsigned int)));
    }

    ReloadedChain stale(vRecords);
    for (int i = 0; i < CHAIN_LEN; i++)
        BOOST_REQUIRE_EQUAL(stale.vIndex[i]->nSize, 0u);

    // Negative control: without the restore the limits genuinely diverge, so
    // the equality asserted below is not vacuous.
    BOOST_CHECK(GetAdaptiveBlockSizeLimit(stale.Tip()) != nLiveLimit);

    int nRestored = 0;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(BackfillBlockIndexSizes(stale.All(), nRestored, strError), strError);
    BOOST_CHECK_EQUAL(nRestored, CHAIN_LEN);
    for (int i = 0; i < CHAIN_LEN; i++)
        BOOST_CHECK_EQUAL(stale.vIndex[i]->nSize, live.vIndex[i]->nSize);
    BOOST_CHECK_EQUAL(GetAdaptiveBlockSizeLimit(stale.Tip()), nLiveLimit);
}

// The same equality through the current record format, with no file reads.
BOOST_AUTO_TEST_CASE(reloaded_current_index_matches_without_restore)
{
    WrittenChain live;
    std::vector<std::string> vRecords;
    for (int i = 0; i < CHAIN_LEN; i++)
        vRecords.push_back(EncodeRecord(live.vIndex[i]));

    ReloadedChain fresh(vRecords);
    for (int i = 0; i < CHAIN_LEN; i++)
        BOOST_REQUIRE_EQUAL(fresh.vIndex[i]->nSize, live.vIndex[i]->nSize);

    int nRestored = 0;
    std::string strError;
    BOOST_REQUIRE(BackfillBlockIndexSizes(fresh.All(), nRestored, strError));
    BOOST_CHECK_EQUAL(nRestored, 0);
    BOOST_CHECK_EQUAL(GetAdaptiveBlockSizeLimit(fresh.Tip()),
                      GetAdaptiveBlockSizeLimit(live.Tip()));
}

// The restore reads consensus input from a file, so it must authenticate the
// location instead of trusting whatever four bytes sit there.
BOOST_AUTO_TEST_CASE(restore_rejects_prefix_that_is_not_a_block_header)
{
    CBlock block = MakeSizedBlock(430000, 80);
    unsigned int nFile = 0, nPos = 0;
    BOOST_REQUIRE(block.WriteToDisk(nFile, nPos));

    CBlockIndex bogus;
    bogus.nFile = nFile;
    bogus.nBlockPos = nPos + 100000;   // inside the padding, not a block start
    bogus.nHeight = FORK_HEIGHT_DAG + 1;
    std::vector<CBlockIndex*> v;
    v.push_back(&bogus);

    int nRestored = 0;
    std::string strError;
    BOOST_CHECK(!BackfillBlockIndexSizes(v, nRestored, strError));
    BOOST_CHECK(!strError.empty());
    BOOST_CHECK_EQUAL(bogus.nSize, 0u);
}

// The range check alone is not enough: four bytes at a wrong offset can easily
// look like a legal size. Only the magic ahead of them proves the offset is a
// block start, so removing that check must break a test.
BOOST_AUTO_TEST_CASE(restore_rejects_plausible_size_behind_wrong_magic)
{
    // Four bytes that are not the network magic, then 0x00030d40 == 200000,
    // a size comfortably inside the accepted range.
    const unsigned char pchDecoy[8] = { 0xde, 0xad, 0xbe, 0xef, 0x40, 0x0d, 0x03, 0x00 };
    BOOST_REQUIRE(memcmp(pchDecoy, pchMessageStart, 4) != 0);
    unsigned int nSizeInDecoy = 0;
    memcpy(&nSizeInDecoy, pchDecoy + 4, 4);
    BOOST_REQUIRE(nSizeInDecoy > 0 && nSizeInDecoy <= ADAPTIVE_BLOCK_CEILING);

    unsigned int nFile = 0;
    const unsigned int nDecoyEnd = WriteBlockWithDecoy(pchDecoy, 81, nFile);

    CBlockIndex bogus;
    bogus.nFile = nFile;
    bogus.nBlockPos = nDecoyEnd;
    bogus.nHeight = FORK_HEIGHT_DAG + 3;
    std::vector<CBlockIndex*> v;
    v.push_back(&bogus);

    int nRestored = 0;
    std::string strError;
    BOOST_CHECK(!BackfillBlockIndexSizes(v, nRestored, strError));
    BOOST_CHECK(strError.find("magic") != std::string::npos);
    BOOST_CHECK_EQUAL(nRestored, 0);
    BOOST_CHECK_EQUAL(bogus.nSize, 0u);
}

// And the magic alone is not enough either: block payloads can contain it, so
// the recovered value still has to be a size a block could have.
BOOST_AUTO_TEST_CASE(restore_rejects_out_of_range_size_behind_valid_magic)
{
    unsigned char pchDecoy[8];
    memcpy(pchDecoy, pchMessageStart, 4);
    memset(pchDecoy + 4, 0xff, 4);          // 4294967295, far above the ceiling

    unsigned int nFile = 0;
    const unsigned int nDecoyEnd = WriteBlockWithDecoy(pchDecoy, 82, nFile);

    CBlockIndex bogus;
    bogus.nFile = nFile;
    bogus.nBlockPos = nDecoyEnd;
    bogus.nHeight = FORK_HEIGHT_DAG + 4;
    std::vector<CBlockIndex*> v;
    v.push_back(&bogus);

    int nRestored = 0;
    std::string strError;
    BOOST_CHECK(!BackfillBlockIndexSizes(v, nRestored, strError));
    BOOST_CHECK(strError.find("out of range") != std::string::npos);
    BOOST_CHECK_EQUAL(nRestored, 0);
    BOOST_CHECK_EQUAL(bogus.nSize, 0u);
}

// Header-only entries have no stored block and must be skipped, not failed.
BOOST_AUTO_TEST_CASE(restore_skips_entries_with_no_stored_block)
{
    CBlockIndex headerOnly;
    headerOnly.nFile = 0;
    headerOnly.nBlockPos = 0;
    headerOnly.nHeight = FORK_HEIGHT_DAG + 2;
    std::vector<CBlockIndex*> v;
    v.push_back(&headerOnly);

    int nRestored = 0;
    std::string strError;
    BOOST_CHECK(BackfillBlockIndexSizes(v, nRestored, strError));
    BOOST_CHECK_EQUAL(nRestored, 0);
    BOOST_CHECK_EQUAL(headerOnly.nSize, 0u);
}

// A restarted node must pay for the restore once. After it writes the recovered
// sizes back, the next start reads them straight out of the records.
BOOST_AUTO_TEST_CASE(restore_persists_so_the_next_start_does_no_file_reads)
{
    WrittenChain live;
    const unsigned int nLiveLimit = GetAdaptiveBlockSizeLimit(live.Tip());

    std::vector<std::string> vLegacy;
    for (int i = 0; i < CHAIN_LEN; i++)
    {
        const std::string strFull = EncodeRecord(live.vIndex[i]);
        vLegacy.push_back(strFull.substr(0, strFull.size() - sizeof(unsigned int)));
    }

    // First start: restore, then write the records back.
    ReloadedChain first(vLegacy);
    int nRestored = 0;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(BackfillBlockIndexSizes(first.All(), nRestored, strError), strError);
    BOOST_CHECK_EQUAL(nRestored, CHAIN_LEN);
    std::vector<std::string> vRewritten;
    for (int i = 0; i < CHAIN_LEN; i++)
        vRewritten.push_back(EncodeRecord(first.vIndex[i]));

    // Second start: the sizes arrive with the records.
    ReloadedChain second(vRewritten);
    for (int i = 0; i < CHAIN_LEN; i++)
        BOOST_CHECK_EQUAL(second.vIndex[i]->nSize, live.vIndex[i]->nSize);
    BOOST_CHECK_EQUAL(GetAdaptiveBlockSizeLimit(second.Tip()), nLiveLimit);

    int nRestoredAgain = 0;
    BOOST_REQUIRE(BackfillBlockIndexSizes(second.All(), nRestoredAgain, strError));
    BOOST_CHECK_EQUAL(nRestoredAgain, 0);
}

// The startup pass reads a block file per selected entry, so it selects only
// entries that are missing a size and shallow enough to matter.
BOOST_AUTO_TEST_CASE(restore_selects_only_indexes_a_window_can_reach)
{
    const int nFloor = GetBlockIndexSizeBackfillFloor();

    CBlockIndex missingAtFloor;
    missingAtFloor.nHeight = nFloor;
    BOOST_CHECK(BlockIndexNeedsSizeRestore(&missingAtFloor, nFloor));

    CBlockIndex missingAboveFloor;
    missingAboveFloor.nHeight = nFloor + 1;
    BOOST_CHECK(BlockIndexNeedsSizeRestore(&missingAboveFloor, nFloor));

    // Below the floor no window can reach it, so its size is never consulted.
    CBlockIndex missingBelowFloor;
    missingBelowFloor.nHeight = nFloor - 1;
    BOOST_CHECK(!BlockIndexNeedsSizeRestore(&missingBelowFloor, nFloor));

    // Already known: reading the file again would be pure cost.
    CBlockIndex known;
    known.nHeight = nFloor + 1;
    known.nSize = 400000;
    BOOST_CHECK(!BlockIndexNeedsSizeRestore(&known, nFloor));

    BOOST_CHECK(!BlockIndexNeedsSizeRestore(NULL, nFloor));
}

// The restore is bounded, so the bound has to cover every index an adaptive
// window can reach.
BOOST_AUTO_TEST_CASE(restore_depth_covers_every_adaptive_window)
{
    // ApplyBlockSizePenalty evaluates the parent, so the reach is one block
    // deeper than the two windows themselves.
    const int nNeeded = (int)ADAPTIVE_MEDIAN_WINDOW
                      + (int)ADAPTIVE_LONG_MEDIAN_EFFECTIVE_WINDOW + 1;
    BOOST_CHECK_GE(GetBlockIndexSizeBackfillDepth(), nNeeded);

    const int nFloor = GetBlockIndexSizeBackfillFloor();
    BOOST_CHECK(nFloor >= 0);
    BOOST_CHECK_EQUAL(nFloor,
                      std::max(0, FORK_HEIGHT_DAG - GetBlockIndexSizeBackfillDepth()));
    // The clamp the depth is derived from must not silently widen.
    BOOST_CHECK_EQUAL(std::min(ADAPTIVE_LONG_MEDIAN_WINDOW,
                               ADAPTIVE_LONG_MEDIAN_EFFECTIVE_WINDOW),
                      ADAPTIVE_LONG_MEDIAN_EFFECTIVE_WINDOW);
}

BOOST_AUTO_TEST_SUITE_END()
