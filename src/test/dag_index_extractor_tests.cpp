// AcceptBlock (validates DAG parents) and AddToBlockIndex (records them) must use
// the same coinbase decoder from Boundary A; a decoy OP_PUSHDATA4 payload must not
// reach the index. Mines past Boundary A, so linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../dag.h"
#include "../init.h"
#include "../main.h"
#include "../miner.h"
#include "../script.h"
#include "../uint256.h"
#include "../wallet.h"

extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(dag_index_extractor_tests)

namespace
{

// The one push shape the two decoders disagree about: a well-formed IDAG
// payload behind OP_PUSHDATA4.
CScript MakeWideDecoy(const std::vector<uint256>& vParents)
{
    std::vector<unsigned char> vchData(DAG_PARENT_TAG, DAG_PARENT_TAG + 4);
    vchData.push_back((unsigned char)vParents.size());
    for (unsigned int i = 0; i < vParents.size(); ++i)
        vchData.insert(vchData.end(), vParents[i].begin(), vParents[i].end());

    CScript script;
    script.push_back(OP_RETURN);
    script.push_back(OP_PUSHDATA4);
    const unsigned int nSize = (unsigned int)vchData.size();
    for (int i = 0; i < 4; ++i)
        script.push_back((unsigned char)((nSize >> (8 * i)) & 0xff));
    script.insert(script.end(), vchData.begin(), vchData.end());
    return script;
}

int FindCanonicalOutput(const CTransaction& txCoinbase)
{
    for (unsigned int i = 0; i < txCoinbase.vout.size(); ++i)
    {
        std::vector<uint256> vDecoded;
        std::string strError;
        if (DecodeCanonicalDAGParentScript(txCoinbase.vout[i].scriptPubKey,
                                           vDecoded, strError) ==
            DAG_PARENT_VALID)
            return (int)i;
    }
    return -1;
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

// Mines one block on the current tip and returns it.
CBlockIndex* MineOne()
{
    unsigned int nExtraNonce = 0;
    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    BOOST_REQUIRE(SolveBlock(pblock.get()));
    const uint256 hash = pblock->GetHash();
    BOOST_REQUIRE(ProcessBlock(NULL, pblock.get()));
    LOCK(cs_main);
    BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
    return mapBlockIndex[hash];
}

void MineTo(int nTarget)
{
    while (BestIndex()->nHeight < nTarget)
        MineOne();
}

} // namespace

// Identifies which arm coloured the block: DAGKnight writes k clamped to
// [DAGKNIGHT_K_FLOOR, DAGKNIGHT_K_CEILING]; GHOSTDAG leaves -1. The read must be passive
// (GetDAGData), since InferLocalK would compute k on either arm.
BOOST_AUTO_TEST_CASE(the_dagknight_arm_is_the_one_that_colours_a_post_fork_block)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(FORK_HEIGHT_DAGKNIGHT > FORK_HEIGHT_DAG);

    MineTo(FORK_HEIGHT_DAGKNIGHT);
    CBlockIndex* pindexNew = MineOne();
    BOOST_REQUIRE(pindexNew->nHeight > FORK_HEIGHT_DAGKNIGHT);

    CBlockDAGData data;
    BOOST_REQUIRE(g_dagManager.GetDAGData(pindexNew->GetBlockHash(), data));
    BOOST_CHECK_MESSAGE(data.nInferredK >= DAGKNIGHT_K_FLOOR,
                        "a block above the DAGKnight height carries the GHOSTDAG "
                        "sentinel, so the index writer coloured it with the wrong arm");
    BOOST_CHECK_LE(data.nInferredK, DAGKNIGHT_K_CEILING);

    // Control: a GHOSTDAG-window block keeps the -1 sentinel.
    const CBlockIndex* pindexPre = pindexNew;
    while (pindexPre && pindexPre->nHeight >= FORK_HEIGHT_DAGKNIGHT)
        pindexPre = pindexPre->pprev;
    BOOST_REQUIRE(pindexPre != NULL);
    BOOST_REQUIRE_GE(pindexPre->nHeight, FORK_HEIGHT_DAG);
    CBlockDAGData ghostdag;
    BOOST_REQUIRE(g_dagManager.GetDAGData(pindexPre->GetBlockHash(), ghostdag));
    BOOST_CHECK_MESSAGE(ghostdag.nInferredK == -1,
                        "a pre-DAGKnight block reports an inferred k, so the read "
                        "is not passive");
}

// The canonical decoder returns NOT_FOUND (skip, not reject) for an OP_PUSHDATA4 payload.
BOOST_AUTO_TEST_CASE(a_pushdata4_payload_is_read_by_one_decoder_only)
{
    std::vector<uint256> vDecoy(1, uint256(0xdec0de));
    const CScript decoy = MakeWideDecoy(vDecoy);

    BOOST_CHECK(ExtractDAGParents(decoy) == vDecoy);

    std::vector<uint256> vCanonical;
    std::string strError;
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(decoy, vCanonical, strError),
        DAG_PARENT_NOT_FOUND);
    BOOST_CHECK(vCanonical.empty());
    BOOST_CHECK(strError.empty());

    // Skipped, so a later well-formed commitment still satisfies the gate.
    std::vector<CScript> vScripts;
    vScripts.push_back(decoy);
    std::vector<uint256> vReal(1, uint256(0xfeed));
    vScripts.push_back(BuildDAGParentScript(vReal));
    BOOST_CHECK(ExtractCanonicalDAGParentCommitment(vScripts, vCanonical,
                                                    strError));
    BOOST_CHECK(vCanonical == vReal);
}

// One reader, and the height picks the decoder.
BOOST_AUTO_TEST_CASE(the_block_height_selects_the_parent_decoder)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(IsBoundaryAConfigured());

    std::vector<uint256> vDecoy(1, uint256(0xdec0de));
    std::vector<uint256> vReal(1, uint256(0xfeed));

    std::vector<CScript> vScripts;
    vScripts.push_back(CScript() << OP_RETURN
                                 << std::vector<unsigned char>(1, 0x42));
    vScripts.push_back(MakeWideDecoy(vDecoy));
    vScripts.push_back(BuildDAGParentScript(vReal));

    std::vector<uint256> vParents;
    std::string strError;

    BOOST_CHECK(ReadDAGParentCommitmentAtHeight(
        vScripts, FORK_HEIGHT_BOUNDARY_A, vParents, strError));
    BOOST_CHECK_MESSAGE(vParents == vReal,
                        "at Boundary A the reader took the decoy");
    BOOST_CHECK(!(vParents == vDecoy));

    BOOST_CHECK(ReadDAGParentCommitmentAtHeight(
        vScripts, FORK_HEIGHT_BOUNDARY_A + 1, vParents, strError));
    BOOST_CHECK(vParents == vReal);

    // Below Boundary A the historical first-match shape is retained so already
    // connected blocks replay byte for byte.
    BOOST_CHECK(ReadDAGParentCommitmentAtHeight(
        vScripts, FORK_HEIGHT_BOUNDARY_A - 1, vParents, strError));
    BOOST_CHECK(vParents == vDecoy);

    BOOST_CHECK(ReadDAGParentCommitmentAtHeight(vScripts, FORK_HEIGHT_DAG,
                                                vParents, strError));
    BOOST_CHECK(vParents == vDecoy);

    // No commitment at all fails on both branches, with a reason.
    std::vector<CScript> vNone;
    vNone.push_back(CScript() << OP_RETURN
                              << std::vector<unsigned char>(1, 0x42));
    BOOST_CHECK(!ReadDAGParentCommitmentAtHeight(
        vNone, FORK_HEIGHT_BOUNDARY_A, vParents, strError));
    BOOST_CHECK(vParents.empty());
    BOOST_CHECK(!strError.empty());
    BOOST_CHECK(!ReadDAGParentCommitmentAtHeight(vNone, FORK_HEIGHT_DAG,
                                                 vParents, strError));
    BOOST_CHECK(vParents.empty());
    BOOST_CHECK(!strError.empty());

    // A malformed canonical commitment is a rejection at Boundary A, not a
    // fall-through to whatever the permissive reader can find.
    std::vector<CScript> vBoth;
    vBoth.push_back(MakeWideDecoy(vDecoy));
    std::vector<unsigned char> vchShort(DAG_PARENT_TAG, DAG_PARENT_TAG + 4);
    vchShort.push_back(2);
    vchShort.insert(vchShort.end(), vReal[0].begin(), vReal[0].end());
    CScript malformed;
    malformed << OP_RETURN << vchShort;
    vBoth.push_back(malformed);
    BOOST_CHECK(!ReadDAGParentCommitmentAtHeight(
        vBoth, FORK_HEIGHT_BOUNDARY_A, vParents, strError));
    BOOST_CHECK(vParents.empty());
}

// End to end: a block with a decoy commitment ahead of its real one is
// accepted and indexed against the canonical parents (checked in the DAG store).
BOOST_AUTO_TEST_CASE(a_decoy_commitment_never_reaches_the_dag_record)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(IsBoundaryAConfigured());
    MineTo(FORK_HEIGHT_BOUNDARY_A + 4);

    CBlockIndex* pindexPrev = BestIndex();
    BOOST_REQUIRE(pindexPrev->pprev != NULL);
    BOOST_REQUIRE(IsBoundaryAActiveAtHeight(pindexPrev->nHeight + 1));

    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);

    const int nOut = FindCanonicalOutput(pblock->vtx[0]);
    BOOST_REQUIRE(nOut >= 0);
    std::vector<uint256> vCanonical;
    std::string strError;
    BOOST_REQUIRE_EQUAL(
        DecodeCanonicalDAGParentScript(pblock->vtx[0].vout[nOut].scriptPubKey,
                                       vCanonical, strError),
        DAG_PARENT_VALID);
    BOOST_REQUIRE(!vCanonical.empty());
    BOOST_REQUIRE(vCanonical[0] == pblock->hashPrevBlock);

    // Decoy parent: a real lower block that is not this block's predecessor.
    std::vector<uint256> vDecoy(1, pindexPrev->pprev->GetBlockHash());
    BOOST_REQUIRE(!(vDecoy == vCanonical));

    CTxOut decoyOut;
    decoyOut.nValue = 0;
    decoyOut.scriptPubKey = MakeWideDecoy(vDecoy);
    pblock->vtx[0].vout.insert(pblock->vtx[0].vout.begin() + nOut, decoyOut);

    // The decoy sits ahead of the real commitment and only the permissive
    // decoder can see it.
    BOOST_REQUIRE(ExtractDAGParents(pblock->vtx[0].vout[nOut].scriptPubKey) ==
                  vDecoy);
    BOOST_REQUIRE_EQUAL(FindCanonicalOutput(pblock->vtx[0]), nOut + 1);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pblock.get()));
    const uint256 hash = pblock->GetHash();

    pblock->nDoS = 0;
    BOOST_REQUIRE_MESSAGE(ProcessBlock(NULL, pblock.get()),
                          "the decoy-carrying block was not accepted, so the "
                          "index writer was never reached");
    BOOST_CHECK_EQUAL(pblock->nDoS, 0);

    CBlockIndex* pindexNew = NULL;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
        pindexNew = mapBlockIndex[hash];
    }
    BOOST_REQUIRE(pindexNew->pprev != NULL);

    CBlockDAGData data;
    BOOST_REQUIRE(g_dagManager.GetDAGData(hash, data));
    BOOST_CHECK_MESSAGE(data.vDAGParents == vCanonical,
                        "the DAG record holds a parent set the validity gate "
                        "never read");
    BOOST_CHECK_MESSAGE(!(data.vDAGParents == vDecoy),
                        "the DAG record holds the decoy parents");

    // The exact binding LoadDAGLinks re-checks for a V3 vertex.
    BOOST_REQUIRE(!data.vDAGParents.empty());
    BOOST_CHECK_LE(data.vDAGParents.size(), (size_t)MAX_DAG_PARENTS);
    BOOST_CHECK(data.vDAGParents[0] == pindexNew->pprev->GetBlockHash());
}

// GetMissingDAGMergeParents (in ProcessBlock) must use the canonical decoder,
// or a decoy naming an unknown merge parent parks a valid block as a DAG orphan.
// ProcessBlock returns true when parking, so assert index membership instead.
BOOST_AUTO_TEST_CASE(a_decoy_merge_parent_never_diverts_the_parent_fetch)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(IsBoundaryAConfigured());
    MineTo(FORK_HEIGHT_BOUNDARY_A + 4);

    CBlockIndex* pindexPrev = BestIndex();
    BOOST_REQUIRE(IsBoundaryAActiveAtHeight(pindexPrev->nHeight + 1));

    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);

    const int nOut = FindCanonicalOutput(pblock->vtx[0]);
    BOOST_REQUIRE(nOut >= 0);
    std::vector<uint256> vCanonical;
    std::string strError;
    BOOST_REQUIRE_EQUAL(
        DecodeCanonicalDAGParentScript(pblock->vtx[0].vout[nOut].scriptPubKey,
                                       vCanonical, strError),
        DAG_PARENT_VALID);
    BOOST_REQUIRE(!vCanonical.empty());
    BOOST_REQUIRE(vCanonical[0] == pblock->hashPrevBlock);
    BOOST_REQUIRE(vCanonical.size() < (size_t)MAX_DAG_PARENTS);

    // Decoy = the real commitment plus one merge parent nobody holds.
    const uint256 hashAbsent(std::string(
        "00000000000000000000000000000000000000000000000000000000000ba012"));
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.count(hashAbsent) == 0);
    }
    std::vector<uint256> vDecoy = vCanonical;
    vDecoy.push_back(hashAbsent);

    CTxOut decoyOut;
    decoyOut.nValue = 0;
    decoyOut.scriptPubKey = MakeWideDecoy(vDecoy);
    pblock->vtx[0].vout.insert(pblock->vtx[0].vout.begin() + nOut, decoyOut);
    BOOST_REQUIRE(ExtractDAGParents(pblock->vtx[0].vout[nOut].scriptPubKey) ==
                  vDecoy);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pblock.get()));
    const uint256 hash = pblock->GetHash();

    BOOST_REQUIRE(ProcessBlock(NULL, pblock.get()));

    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hash) == 0,
                            "a valid block was parked as a DAG orphan against a "
                            "merge parent only the decoy names");
        BOOST_REQUIRE_MESSAGE(mapBlockIndex.count(hash) != 0,
                              "the block never reached the index");
    }

    CBlockDAGData data;
    BOOST_REQUIRE(g_dagManager.GetDAGData(hash, data));
    BOOST_CHECK(data.vDAGParents == vCanonical);
}

BOOST_AUTO_TEST_SUITE_END()
