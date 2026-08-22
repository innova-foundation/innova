// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// CBlockIndex::nSize feeds consensus size limits; an index rebuilt from disk must recover
// the same value a freshly synced node computes.

#include <boost/test/unit_test.hpp>

#include "checkpoints.h"
#include "main.h"
#include "txdb.h"

#include <algorithm>
#include <map>
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

    explicit WrittenChain(unsigned int nSeedBase = 1000)
    {
        vHashes.reserve(CHAIN_LEN);
        for (int i = 0; i < CHAIN_LEN; i++)
        {
            CBlock block = MakeSizedBlock(TargetSizeAt(i), nSeedBase + i);
            // A fixed-width field, so linking the chain does not resize it.
            block.hashPrevBlock = vHashes.empty() ? 0 : vHashes.back();
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
        for (size_t i = 0; i + 1 < vIndex.size(); i++)
            vIndex[i]->pnext = vIndex[i + 1];
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

// The WriteToDisk size prefix must equal the SER_NETWORK size CBlockIndex and
// both adaptive-size consumers use.
BOOST_AUTO_TEST_CASE(disk_size_prefix_equals_index_size)
{
    std::vector<CBlock> vShapes;
    vShapes.push_back(MakeSizedBlock(400000, 77));

    // More than one transaction and a block signature, so the equality is not
    // asserted only over a single-transaction body.
    CBlock blockSigned = MakeSizedBlock(320000, 76);
    blockSigned.vtx.push_back(blockSigned.vtx[0]);
    blockSigned.vtx.back().nTime += 1;
    blockSigned.vchBlockSig.assign(72, 0x30);
    blockSigned.hashMerkleRoot = blockSigned.BuildMerkleTree();
    vShapes.push_back(blockSigned);

    for (size_t nShape = 0; nShape < vShapes.size(); nShape++)
    {
        CBlock& block = vShapes[nShape];
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
                      + (int)ADAPTIVE_LONG_MEDIAN_WINDOW + 1;
    BOOST_CHECK_GE(GetBlockIndexSizeBackfillDepth(), nNeeded);

    const int nFloor = GetBlockIndexSizeBackfillFloor();
    BOOST_CHECK(nFloor >= 0);
    BOOST_CHECK_EQUAL(nFloor,
                      std::max(0, FORK_HEIGHT_DAG - GetBlockIndexSizeBackfillDepth()));
}

// Pins the window constants and the depth derived from them.
BOOST_AUTO_TEST_CASE(adaptive_window_constants_are_pinned)
{
    BOOST_CHECK_EQUAL(ADAPTIVE_MEDIAN_WINDOW, 1000u);
    BOOST_CHECK_EQUAL(ADAPTIVE_LONG_MEDIAN_WINDOW, 50000u);
    BOOST_CHECK_EQUAL(GetBlockIndexSizeBackfillDepth(), 52001);
}

// Pins the short-term window's sample count behaviourally. The long-term width
// is not observable: FLOOR * LONG_MEDIAN_CAP exceeds the ceiling, so its cap never binds.
BOOST_AUTO_TEST_CASE(short_median_window_takes_exactly_its_sample_count)
{
    const unsigned int nSmall = 350000;
    const unsigned int nLarge = 450000;
    const size_t nCount = ADAPTIVE_MEDIAN_WINDOW + 1;

    std::vector<CBlockIndex> vChain(nCount);
    for (size_t i = 0; i < nCount; i++)
    {
        // Index 0 is the tip. The window is [0, ADAPTIVE_MEDIAN_WINDOW), split
        // evenly between the two sizes; the one entry past it is small.
        vChain[i].nHeight = (int)(FORK_HEIGHT_DAG + nCount - 1 - i);
        vChain[i].nSize = (i >= ADAPTIVE_MEDIAN_WINDOW || i % 2 == 0) ? nSmall : nLarge;
        vChain[i].pprev = (i + 1 < nCount) ? &vChain[i + 1] : NULL;
    }

    // 1000 samples sort to 500 small then 500 large and the median is large.
    // One more sample makes it 501 small and the median flips to small.
    BOOST_CHECK_EQUAL(GetAdaptiveBlockSizeLimit(&vChain[0]), 2 * nLarge);
    BOOST_CHECK(2 * nSmall != 2 * nLarge);
}

namespace {

// Reads and writes raw block-index records the way CTxDB::LoadBlockIndex sees
// them, so a record can be stored in the pre-nSize format.
class CBlockIndexRecordDB : public CTxDB
{
public:
    CBlockIndexRecordDB() : CTxDB("r+") {}

    bool WriteRaw(const uint256& hash, const std::string& strValue)
    {
        CDataStream ss(strValue.data(), strValue.data() + strValue.size(),
                       SER_DISK, CLIENT_VERSION);
        return Write(std::make_pair(std::string("blockindex"), hash), ss);
    }

    bool ReadRecord(const uint256& hash, CDiskBlockIndex& diskindex)
    {
        return Read(std::make_pair(std::string("blockindex"), hash), diskindex);
    }
};

// LoadBlockIndex refuses a populated map: swap in an empty one and restore afterwards.
// std::map::swap moves nodes, so saved phashBlock pointers stay valid.
struct ChainStateGuard
{
    std::map<uint256, CBlockIndex*> mapSaved;
    CBlockIndex* pindexGenesisSaved;
    CBlockIndex* pindexBestSaved;
    uint256 hashBestChainSaved;
    uint256 hashSyncCheckpointSaved;
    uint256 nBestChainTrustSaved;
    uint256 nBestInvalidTrustSaved;
    int nBestHeightSaved;
    std::map<std::string, std::string> mapArgsSaved;
    std::vector<uint256> vEraseOnExit;

    // GetArg keys off presence, so a restore has to remove a key that was not
    // there rather than leave it set to the empty string.
    void SetArg(const char* pszKey, const char* pszValue)
    {
        if (mapArgs.count(pszKey))
            mapArgsSaved[pszKey] = mapArgs[pszKey];
        mapArgs[pszKey] = pszValue;
    }

    void RestoreArg(const char* pszKey)
    {
        if (mapArgsSaved.count(pszKey))
            mapArgs[pszKey] = mapArgsSaved[pszKey];
        else
            mapArgs.erase(pszKey);
    }

    ChainStateGuard()
    {
        pindexGenesisSaved = pindexGenesisBlock;
        pindexBestSaved = pindexBest;
        hashBestChainSaved = hashBestChain;
        hashSyncCheckpointSaved = Checkpoints::hashSyncCheckpoint;
        nBestChainTrustSaved = nBestChainTrust;
        nBestInvalidTrustSaved = nBestInvalidTrust;
        nBestHeightSaved = nBestHeight;
        // The re-verification pass is not what is under test here.
        SetArg("-checklevel", "0");
        SetArg("-checkblocks", "1");
        mapSaved.swap(mapBlockIndex);
    }

    ~ChainStateGuard()
    {
        for (std::map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.begin();
             it != mapBlockIndex.end(); ++it)
            delete it->second;
        mapBlockIndex.clear();
        mapBlockIndex.swap(mapSaved);
        pindexGenesisBlock = pindexGenesisSaved;
        pindexBest = pindexBestSaved;
        hashBestChain = hashBestChainSaved;
        Checkpoints::hashSyncCheckpoint = hashSyncCheckpointSaved;
        nBestChainTrust = nBestChainTrustSaved;
        nBestInvalidTrust = nBestInvalidTrustSaved;
        nBestHeight = nBestHeightSaved;
        RestoreArg("-checklevel");
        RestoreArg("-checkblocks");

        CBlockIndexRecordDB txdb;
        for (size_t i = 0; i < vEraseOnExit.size(); i++)
            txdb.EraseBlockIndex(vEraseOnExit[i]);
    }
};

} // namespace

// Pre-nSize records through the real database and CTxDB::LoadBlockIndex must
// rebuild a chain that computes the in-process limit.
BOOST_AUTO_TEST_CASE(load_block_index_restores_nsize_from_the_database)
{
    LOCK(cs_main);

    WrittenChain live(3000);
    const unsigned int nLiveLimit = GetAdaptiveBlockSizeLimit(live.Tip());
    // Non-vacuous: an index that lost every size computes 2 * the floor.
    BOOST_REQUIRE(nLiveLimit != 2 * ADAPTIVE_BLOCK_FLOOR);

    std::vector<std::string> vLegacy;
    for (int i = 0; i < CHAIN_LEN; i++)
    {
        const std::string strFull = EncodeRecord(live.vIndex[i]);
        vLegacy.push_back(strFull.substr(0, strFull.size() - sizeof(unsigned int)));
    }

    ChainStateGuard guard;
    guard.vEraseOnExit = live.vHashes;

    {
        CBlockIndexRecordDB txdb;
        for (int i = 0; i < CHAIN_LEN; i++)
            BOOST_REQUIRE(txdb.WriteRaw(live.vHashes[i], vLegacy[i]));
    }

    {
        CTxDB txdb;
        BOOST_REQUIRE(txdb.LoadBlockIndex());
    }

    for (int i = 0; i < CHAIN_LEN; i++)
    {
        std::map<uint256, CBlockIndex*>::const_iterator mi =
            mapBlockIndex.find(live.vHashes[i]);
        BOOST_REQUIRE(mi != mapBlockIndex.end());
        BOOST_REQUIRE(mi->second != NULL);
        BOOST_CHECK_EQUAL(mi->second->nSize, live.vIndex[i]->nSize);
        BOOST_CHECK_EQUAL(mi->second->nHeight, live.vIndex[i]->nHeight);
    }

    CBlockIndex* pindexReloadedTip = mapBlockIndex[live.vHashes[CHAIN_LEN - 1]];
    BOOST_CHECK_EQUAL(GetAdaptiveBlockSizeLimit(pindexReloadedTip), nLiveLimit);

    // The recovered sizes are written back, so the next start reads them out of
    // the records instead of the block files.
    CBlockIndexRecordDB txdb;
    for (int i = 0; i < CHAIN_LEN; i++)
    {
        CDiskBlockIndex diskindex;
        BOOST_REQUIRE(txdb.ReadRecord(live.vHashes[i], diskindex));
        BOOST_CHECK_EQUAL(diskindex.nSize, live.vIndex[i]->nSize);
    }
}

// Records already carrying nSize load through the same path unchanged.
BOOST_AUTO_TEST_CASE(load_block_index_keeps_recorded_nsize)
{
    LOCK(cs_main);

    WrittenChain live(4000);
    const unsigned int nLiveLimit = GetAdaptiveBlockSizeLimit(live.Tip());

    std::vector<std::string> vRecords;
    for (int i = 0; i < CHAIN_LEN; i++)
        vRecords.push_back(EncodeRecord(live.vIndex[i]));

    ChainStateGuard guard;
    guard.vEraseOnExit = live.vHashes;

    {
        CBlockIndexRecordDB txdb;
        for (int i = 0; i < CHAIN_LEN; i++)
            BOOST_REQUIRE(txdb.WriteRaw(live.vHashes[i], vRecords[i]));
    }

    {
        CTxDB txdb;
        BOOST_REQUIRE(txdb.LoadBlockIndex());
    }

    for (int i = 0; i < CHAIN_LEN; i++)
        BOOST_CHECK_EQUAL(mapBlockIndex[live.vHashes[i]]->nSize, live.vIndex[i]->nSize);
    BOOST_CHECK_EQUAL(GetAdaptiveBlockSizeLimit(mapBlockIndex[live.vHashes[CHAIN_LEN - 1]]),
                      nLiveLimit);
}

// The restore re-measures the block and refuses a prefix that disagrees with it.
BOOST_AUTO_TEST_CASE(restore_rejects_prefix_that_disagrees_with_the_block)
{
    CBlock block = MakeSizedBlock(360000, 90);
    unsigned int nFile = 0, nPos = 0;
    BOOST_REQUIRE(block.WriteToDisk(nFile, nPos));
    const unsigned int nTrueSize =
        ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
    BOOST_REQUIRE(nTrueSize > 1000);

    // A size that passes every range check but is not this block's size.
    const unsigned int nWrongSize = nTrueSize - 1000;
    FILE* file = OpenBlockFile(nFile, 0, "r+b");
    BOOST_REQUIRE(file != NULL);
    BOOST_REQUIRE_EQUAL(fseek(file, (long)nPos - 4, SEEK_SET), 0);
    BOOST_REQUIRE_EQUAL(fwrite(&nWrongSize, 1, 4, file), (size_t)4);
    fclose(file);

    CBlockIndex stale;
    stale.nFile = nFile;
    stale.nBlockPos = nPos;
    stale.nHeight = FORK_HEIGHT_DAG + 7;
    std::vector<CBlockIndex*> v;
    v.push_back(&stale);

    int nRestored = 0;
    std::string strError;
    BOOST_CHECK(!BackfillBlockIndexSizes(v, nRestored, strError));
    BOOST_CHECK(strError.find("measures") != std::string::npos);
    BOOST_CHECK_EQUAL(nRestored, 0);
    BOOST_CHECK_EQUAL(stale.nSize, 0u);

    // Put the block file back; the same entry then restores cleanly.
    file = OpenBlockFile(nFile, 0, "r+b");
    BOOST_REQUIRE(file != NULL);
    BOOST_REQUIRE_EQUAL(fseek(file, (long)nPos - 4, SEEK_SET), 0);
    BOOST_REQUIRE_EQUAL(fwrite(&nTrueSize, 1, 4, file), (size_t)4);
    fclose(file);

    BOOST_REQUIRE(BackfillBlockIndexSizes(v, nRestored, strError));
    BOOST_CHECK_EQUAL(nRestored, 1);
    BOOST_CHECK_EQUAL(stale.nSize, nTrueSize);
}

BOOST_AUTO_TEST_SUITE_END()
