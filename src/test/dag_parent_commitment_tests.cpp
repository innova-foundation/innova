// IDAG parent-commitment codec: strict Boundary-A and permissive pre-A decoders agree up
// to MAX_DAG_PARENTS (a 1,029-byte push). Linked after miner_tests, last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../dag.h"
#include "../finality.h"
#include "../init.h"
#include "../main.h"
#include "../miner.h"
#include "../script.h"
#include "../subsidy.h"
#include "../txdb.h"
#include "../uint256.h"
#include "../wallet.h"

extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(dag_parent_commitment_tests)

namespace
{

std::vector<uint256> MakeParents(unsigned int nCount, unsigned int nSeed = 1)
{
    std::vector<uint256> vParents;
    for (unsigned int i = 0; i < nCount; ++i)
        vParents.push_back(uint256(nSeed + i));
    return vParents;
}

// Payload with an independently chosen count byte, so a declared count can be
// made to contradict the hashes that follow it.
std::vector<unsigned char> MakePayload(const std::vector<uint256>& vParents,
                                       unsigned int nDeclared)
{
    std::vector<unsigned char> vch(DAG_PARENT_TAG, DAG_PARENT_TAG + 4);
    vch.push_back((unsigned char)nDeclared);
    for (unsigned int i = 0; i < vParents.size(); ++i)
        vch.insert(vch.end(), vParents[i].begin(), vParents[i].end());
    return vch;
}

CScript WrapPayload(const std::vector<unsigned char>& vchPayload)
{
    CScript script;
    script << OP_RETURN << vchPayload;
    return script;
}

// Same payload, deliberately non-minimal push opcode.
CScript WrapPayloadWithOpcode(const std::vector<unsigned char>& vchPayload,
                              opcodetype pushOpcode)
{
    CScript script;
    script.push_back(OP_RETURN);
    script.push_back(pushOpcode);
    const unsigned int nSize = (unsigned int)vchPayload.size();
    if (pushOpcode == OP_PUSHDATA1)
        script.push_back((unsigned char)nSize);
    else if (pushOpcode == OP_PUSHDATA2)
        for (int i = 0; i < 2; ++i)
            script.push_back((unsigned char)((nSize >> (8 * i)) & 0xff));
    else if (pushOpcode == OP_PUSHDATA4)
        for (int i = 0; i < 4; ++i)
            script.push_back((unsigned char)((nSize >> (8 * i)) & 0xff));
    script.insert(script.end(), vchPayload.begin(), vchPayload.end());
    return script;
}

// Does the generic script reader accept this element? Pins that the fix is in
// the IDAG decoder and not a raised global element cap.
bool GenericReaderAcceptsPush(const CScript& script)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    if (!script.GetOp(pc, opcode, vch) || opcode != OP_RETURN)
        return false;
    return script.GetOp(pc, opcode, vch);
}

int FindCommitmentOutput(const CBlock& block)
{
    if (block.vtx.empty())
        return -1;
    for (unsigned int i = 0; i < block.vtx[0].vout.size(); ++i)
    {
        std::vector<uint256> vDecoded;
        std::string strError;
        if (DecodeCanonicalDAGParentScript(block.vtx[0].vout[i].scriptPubKey,
                                           vDecoded, strError) !=
            DAG_PARENT_NOT_FOUND)
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

// Extend the chain to nTarget, which must be at or above FORK_HEIGHT_DAG for
// merge parents to be permitted at all.
void MineTo(int nTarget)
{
    unsigned int nExtraNonce = 0;
    while (BestIndex()->nHeight < nTarget)
    {
        CBlockIndex* pindexPrev = BestIndex();
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        BOOST_REQUIRE(pblock.get() != NULL);
        IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
        BOOST_REQUIRE(SolveBlock(pblock.get()));
        const uint256 hash = pblock->GetHash();
        BOOST_REQUIRE(ProcessBlock(NULL, pblock.get()));
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
    }
}

void MineToPostDAG()
{
    MineTo(FORK_HEIGHT_DAG + 1);
}

// Merge-eligible ancestors of pindexPrev, newest first: post-DAG proof-of-work
// blocks within DAG_MERGE_DEPTH of the primary parent.
std::vector<uint256> CollectMergeParents(CBlockIndex* pindexPrev,
                                         unsigned int nWanted)
{
    LOCK(cs_main);
    std::vector<uint256> vMerge;
    for (CBlockIndex* p = pindexPrev->pprev;
         p != NULL && vMerge.size() < nWanted; p = p->pprev)
    {
        if (p->nHeight < FORK_HEIGHT_DAG || !p->IsProofOfWork())
            break;
        if (pindexPrev->nHeight - p->nHeight > DAG_MERGE_DEPTH)
            break;
        vMerge.push_back(p->GetBlockHash());
    }
    return vMerge;
}

} // namespace

// Every count the consensus maximum permits must decode identically through
// both decoders.
BOOST_AUTO_TEST_CASE(both_decoders_agree_across_the_permitted_parent_range)
{
    for (unsigned int n = 1; n <= (unsigned int)MAX_DAG_PARENTS; ++n)
    {
        const std::vector<uint256> vParents = MakeParents(n);
        const CScript script = BuildDAGParentScript(vParents);
        BOOST_REQUIRE_MESSAGE(script.size() > 0,
                              "encoder refused " << n << " parents");

        std::vector<uint256> vCanonical;
        std::string strError;
        BOOST_CHECK_MESSAGE(
            DecodeCanonicalDAGParentScript(script, vCanonical, strError) ==
                DAG_PARENT_VALID,
            "canonical decoder rejected " << n << " parents: " << strError);
        BOOST_CHECK_MESSAGE(vCanonical == vParents,
                            "canonical payload mismatch at n=" << n);

        const std::vector<uint256> vPermissive = ExtractDAGParents(script);
        BOOST_CHECK_MESSAGE(vPermissive.size() == n,
                            "permissive decoder returned "
                                << vPermissive.size() << " for n=" << n);
        BOOST_CHECK_MESSAGE(vPermissive == vParents,
                            "permissive payload mismatch at n=" << n);
        BOOST_CHECK_MESSAGE(vPermissive == vCanonical,
                            "decoders disagree at n=" << n);
    }
}

// The 16/17 parent step crosses the 520-byte element cap. GetOp has no element cap,
// as in v4.3.9.5; EvalScript enforces it.
BOOST_AUTO_TEST_CASE(the_sixteen_to_seventeen_parent_boundary_decodes)
{
    BOOST_CHECK_EQUAL(MAX_SCRIPT_ELEMENT_SIZE, 520U);
    BOOST_CHECK_EQUAL(MAX_DAG_PARENTS, 32);

    const unsigned int nCounts[3] = { 16, 17, 32 };
    const unsigned int nPayloads[3] = { 517, 549, 1029 };
    for (int i = 0; i < 3; ++i)
    {
        const std::vector<uint256> vParents = MakeParents(nCounts[i]);
        const CScript script = BuildDAGParentScript(vParents);
        BOOST_CHECK_EQUAL(5 + nCounts[i] * 32, nPayloads[i]);
        // OP_RETURN + OP_PUSHDATA2 + 2 length bytes.
        BOOST_CHECK_EQUAL(script.size(), nPayloads[i] + 4);

        BOOST_CHECK_MESSAGE(
            GenericReaderAcceptsPush(script),
            "generic reader refused the push at n=" << nCounts[i]);

        const std::vector<uint256> vPermissive = ExtractDAGParents(script);
        BOOST_CHECK_MESSAGE(vPermissive == vParents,
                            "permissive decode failed at n=" << nCounts[i]);

        std::vector<uint256> vCanonical;
        std::string strError;
        BOOST_CHECK_EQUAL(
            DecodeCanonicalDAGParentScript(script, vCanonical, strError),
            DAG_PARENT_VALID);
        BOOST_CHECK(vCanonical == vParents);
    }
}

// The permissive decoder is a strict superset of the canonical one, and must
// stay that way: the pre-Boundary-A window replays against its exact shape.
BOOST_AUTO_TEST_CASE(canonical_rejects_encodings_the_permissive_reader_keeps)
{
    std::vector<uint256> vDecoded;
    std::string strError;

    // Non-minimal push that the canonical parser still structurally reads:
    // it reaches the re-encode comparison and fails there.
    const std::vector<uint256> vOne = MakeParents(1);
    const CScript nonMinimal =
        WrapPayloadWithOpcode(MakePayload(vOne, 1), OP_PUSHDATA1);
    BOOST_CHECK(ExtractDAGParents(nonMinimal) == vOne);
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(nonMinimal, vDecoded, strError),
        DAG_PARENT_MALFORMED);
    BOOST_CHECK_EQUAL(strError,
                      "IDAG commitment uses a non-canonical push encoding");
    BOOST_CHECK(vDecoded.empty());

    // 32 parents carried by OP_PUSHDATA4 instead of the canonical
    // OP_PUSHDATA2. The permissive reader accepts it; the canonical parser
    // does not treat it as a commitment at all.
    const std::vector<uint256> vThirtyTwo = MakeParents(32);
    const CScript wideOpcode =
        WrapPayloadWithOpcode(MakePayload(vThirtyTwo, 32), OP_PUSHDATA4);
    BOOST_CHECK(ExtractDAGParents(wideOpcode) == vThirtyTwo);
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(wideOpcode, vDecoded, strError),
        DAG_PARENT_NOT_FOUND);

    // Trailing payload beyond the counted hashes: tolerated by the permissive
    // decoder, a length mismatch to the canonical one.
    std::vector<unsigned char> vchTrailing = MakePayload(vThirtyTwo, 32);
    vchTrailing.push_back(0x7f);
    const CScript trailing = WrapPayload(vchTrailing);
    BOOST_CHECK(ExtractDAGParents(trailing) == vThirtyTwo);
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(trailing, vDecoded, strError),
        DAG_PARENT_MALFORMED);

    // Zero and duplicate parents: permissive keeps them, canonical rejects.
    std::vector<uint256> vZero = MakeParents(2);
    vZero[1] = uint256(0);
    const CScript zeroScript = WrapPayload(MakePayload(vZero, 2));
    BOOST_CHECK(ExtractDAGParents(zeroScript) == vZero);
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(zeroScript, vDecoded, strError),
        DAG_PARENT_MALFORMED);
}

BOOST_AUTO_TEST_CASE(contradictory_and_out_of_range_counts_are_rejected)
{
    std::vector<uint256> vDecoded;
    std::string strError;

    // Declares 32 parents, carries 20. Payload is 645 bytes, so only the
    // fixed reader gets far enough to see the contradiction at all.
    const CScript tooFew = WrapPayload(MakePayload(MakeParents(20), 32));
    BOOST_CHECK_EQUAL(tooFew.size(), 645U + 4U);
    BOOST_CHECK(ExtractDAGParents(tooFew).empty());
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(tooFew, vDecoded, strError),
        DAG_PARENT_MALFORMED);
    BOOST_CHECK_EQUAL(strError,
                      "IDAG payload length 645 does not match count 32");

    // Declares 20, carries 32: the declared count governs the permissive
    // decoder and the surplus is trailing data.
    const CScript tooMany = WrapPayload(MakePayload(MakeParents(32), 20));
    BOOST_CHECK_EQUAL(ExtractDAGParents(tooMany).size(), 20U);
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(tooMany, vDecoded, strError),
        DAG_PARENT_MALFORMED);

    // Zero.
    const CScript zeroCount =
        WrapPayload(MakePayload(std::vector<uint256>(), 0));
    BOOST_CHECK(ExtractDAGParents(zeroCount).empty());
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(zeroCount, vDecoded, strError),
        DAG_PARENT_MALFORMED);

    // One past the consensus maximum, fully formed. The count bound now does
    // this work; before the decoder fix the element cap masked it.
    const CScript thirtyThree = WrapPayload(MakePayload(MakeParents(33), 33));
    BOOST_CHECK(ExtractDAGParents(thirtyThree).empty());
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(thirtyThree, vDecoded, strError),
        DAG_PARENT_MALFORMED);
    BOOST_CHECK_EQUAL(strError, "IDAG parent count 33 is outside 1..32");

    // Largest payload a count byte can describe, and one hash beyond it.
    const CScript maxCount = WrapPayload(MakePayload(MakeParents(255), 255));
    BOOST_CHECK_EQUAL(maxCount.size(), 8165U + 4U);
    BOOST_CHECK(ExtractDAGParents(maxCount).empty());
    const CScript pastMaxCount =
        WrapPayload(MakePayload(MakeParents(256), 255));
    BOOST_CHECK(ExtractDAGParents(pastMaxCount).empty());
}

// Nothing the permissive decoder already refused may start decoding.
BOOST_AUTO_TEST_CASE(permissive_decoder_rejections_are_unchanged)
{
    BOOST_CHECK(ExtractDAGParents(CScript()).empty());

    CScript noReturn;
    noReturn << MakePayload(MakeParents(32), 32);
    BOOST_CHECK(ExtractDAGParents(noReturn).empty());

    std::vector<unsigned char> vchWrongTag = MakePayload(MakeParents(32), 32);
    vchWrongTag[3] = 0x00;
    BOOST_CHECK(ExtractDAGParents(WrapPayload(vchWrongTag)).empty());

    CScript nonPush;
    nonPush.push_back(OP_RETURN);
    nonPush.push_back(OP_TRUE);
    BOOST_CHECK(ExtractDAGParents(nonPush).empty());

    CScript bareReturn;
    bareReturn.push_back(OP_RETURN);
    BOOST_CHECK(ExtractDAGParents(bareReturn).empty());

    // Truncated OP_PUSHDATA2 length, and a length longer than the script.
    CScript truncatedLength;
    truncatedLength.push_back(OP_RETURN);
    truncatedLength.push_back(OP_PUSHDATA2);
    truncatedLength.push_back(0x05);
    BOOST_CHECK(ExtractDAGParents(truncatedLength).empty());

    // Declares 2,000 bytes, carries 1,029.
    CScript overrunLength;
    overrunLength.push_back(OP_RETURN);
    overrunLength.push_back(OP_PUSHDATA2);
    overrunLength.push_back(0xd0);
    overrunLength.push_back(0x07);
    const std::vector<unsigned char> vchShort =
        MakePayload(MakeParents(32), 32);
    BOOST_REQUIRE_EQUAL(vchShort.size(), 1029U);
    overrunLength.insert(overrunLength.end(), vchShort.begin(), vchShort.end());
    BOOST_CHECK(ExtractDAGParents(overrunLength).empty());
}

// AcceptBlock's pre-Boundary-A path uses the permissive decoder. A commitment
// it cannot read is scored as misbehaviour, so the score -- not merely the
// rejection -- is what separates "read and deferred" from "unreadable".
BOOST_AUTO_TEST_CASE(accept_block_reads_a_seventeen_parent_commitment)
{
    BOOST_REQUIRE(fRegTest);
    MineToPostDAG();
    BOOST_REQUIRE(!IsBoundaryAActiveAtHeight(BestIndex()->nHeight + 1));

    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);

    const int nOut = FindCommitmentOutput(*pblock);
    BOOST_REQUIRE(nOut >= 0);

    std::vector<uint256> vParents(1, pblock->hashPrevBlock);
    for (unsigned int i = 1; i < 17; ++i)
        vParents.push_back(uint256(0xd0d0000 + i));
    pblock->vtx[0].vout[nOut].scriptPubKey = BuildDAGParentScript(vParents);
    BOOST_REQUIRE_EQUAL(pblock->vtx[0].vout[nOut].scriptPubKey.size(),
                        549U + 4U);
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pblock.get()));

    pblock->nDoS = 0;
    BOOST_CHECK(!pblock->AcceptBlock());
    // Decoded, then deferred because merge parents are absent -- that path
    // carries no DoS score. An unreadable commitment scores 100.
    BOOST_CHECK_EQUAL(pblock->nDoS, 0);

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(mapBlockIndex.count(pblock->GetHash()), 0U);
}

// The producer's own commitment must round-trip through both decoders.
BOOST_AUTO_TEST_CASE(the_producer_commitment_round_trips)
{
    BOOST_REQUIRE(fRegTest);
    MineToPostDAG();

    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);

    const int nOut = FindCommitmentOutput(*pblock);
    BOOST_REQUIRE(nOut >= 0);
    const CScript commitment = pblock->vtx[0].vout[nOut].scriptPubKey;

    const std::vector<uint256> vPermissive = ExtractDAGParents(commitment);
    BOOST_REQUIRE(!vPermissive.empty());
    BOOST_CHECK_LE(vPermissive.size(), (unsigned int)MAX_DAG_PARENTS);
    BOOST_CHECK(vPermissive[0] == pblock->hashPrevBlock);

    std::vector<uint256> vCanonical;
    std::string strError;
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(commitment, vCanonical, strError),
        DAG_PARENT_VALID);
    BOOST_CHECK(vCanonical == vPermissive);
}

// End to end: a block committing to the full MAX_DAG_PARENTS set is accepted,
// indexed and carries all 32 links in DAG state.
BOOST_AUTO_TEST_CASE(a_full_parent_set_is_accepted_and_indexed)
{
    BOOST_REQUIRE(fRegTest);
    // Enough post-DAG ancestors inside DAG_MERGE_DEPTH to name 31 of them.
    MineTo(FORK_HEIGHT_DAG + MAX_DAG_PARENTS + 1);

    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    BOOST_REQUIRE(!IsBoundaryAActiveAtHeight(pindexPrev->nHeight + 1));

    std::vector<uint256> vParents(1, pblock->hashPrevBlock);
    const std::vector<uint256> vMerge =
        CollectMergeParents(pindexPrev, MAX_DAG_PARENTS - 1);
    vParents.insert(vParents.end(), vMerge.begin(), vMerge.end());
    BOOST_REQUIRE_EQUAL(vParents.size(), (unsigned int)MAX_DAG_PARENTS);

    const int nOut = FindCommitmentOutput(*pblock);
    BOOST_REQUIRE(nOut >= 0);
    pblock->vtx[0].vout[nOut].scriptPubKey = BuildDAGParentScript(vParents);
    const CScript commitment = pblock->vtx[0].vout[nOut].scriptPubKey;
    BOOST_REQUIRE_EQUAL(commitment.size(), 1029U + 4U);

    // Both decoders read the same 32 parents out of the block as built.
    const std::vector<uint256> vPermissive = ExtractDAGParents(commitment);
    BOOST_CHECK_EQUAL(vPermissive.size(), (unsigned int)MAX_DAG_PARENTS);
    BOOST_CHECK(vPermissive == vParents);
    std::vector<uint256> vCanonical;
    std::string strError;
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(commitment, vCanonical, strError),
        DAG_PARENT_VALID);
    BOOST_CHECK(vCanonical == vParents);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pblock.get()));
    BOOST_REQUIRE(pblock->CheckBlock(true, true, true));
    const uint256 hash = pblock->GetHash();

    pblock->nDoS = 0;
    BOOST_CHECK(ProcessBlock(NULL, pblock.get()));
    BOOST_CHECK_EQUAL(pblock->nDoS, 0);

    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
        BOOST_CHECK_EQUAL(mapBlockIndex[hash]->nHeight,
                          pindexPrev->nHeight + 1);
    }

    // AddToBlockIndex reads the commitment with the permissive decoder and
    // records the links; all 32 must survive into DAG state.
    CBlockDAGData data;
    BOOST_REQUIRE(g_dagManager.GetDAGData(hash, data));
    BOOST_CHECK_EQUAL(data.vDAGParents.size(), (unsigned int)MAX_DAG_PARENTS);
    BOOST_CHECK(data.vDAGParents == vParents);
}


// Post-DAG the coinbase may pay subsidy minus the withheld reserve plus the
// settlement leg, never the reserve. Arithmetic is in subsidy_split_tests.

namespace {

CBlockIndex* ParentIndexOf(const CBlock& block)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::const_iterator mi =
        mapBlockIndex.find(block.hashPrevBlock);
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

// A template on the tip with the stack index ConnectBlock is handed. Edit the
// coinbase, then Seal: the merkle root and the work are recomputed there, so an
// arm's edit rides a block that is otherwise what the producer emitted.
struct AllowanceCandidate
{
    CBlock block;
    uint256 hash;
    CBlockIndex index;
    CBlockIndex* pparent;

    AllowanceCandidate() : pparent(NULL) {}
    CBlockIndex* Index() { return &index; }
    int Height() const { return pparent->nHeight + 1; }
    CTransaction& Coinbase() { return block.vtx[0]; }
};

bool BuildAllowanceCandidate(AllowanceCandidate& out)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexParent = ParentIndexOf(*pblock);
    if (pindexParent == NULL)
        return false;
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexParent, nExtraNonce);
    out.block = *pblock;
    out.pparent = pindexParent;
    return true;
}

bool SealCandidate(AllowanceCandidate& out)
{
    out.block.hashMerkleRoot = out.block.BuildMerkleTree();
    if (!SolveBlock(&out.block))
        return false;
    out.hash = out.block.GetHash();
    out.index = CBlockIndex(0, 0, out.block);
    out.index.pprev = out.pparent;
    out.index.nHeight = out.pparent->nHeight + 1;
    out.index.phashBlock = &out.hash;
    return true;
}

// Connect and discard every write. Without the abort an accepted arm would spend
// this chain's outputs for the rest of the binary.
CBlock::ConnectResult ConnectAndRollBack(AllowanceCandidate& cb)
{
    LOCK(cs_main);
    CTxDB txdb;
    CBlock::ConnectResult result = CBlock::CONNECT_RESULT_INVALID;
    BOOST_REQUIRE(txdb.TxnBegin());
    const bool fConnected = cb.block.ConnectBlock(txdb, cb.Index(), false, false, &result);
    BOOST_REQUIRE(txdb.TxnAbort());
    BOOST_CHECK_EQUAL(fConnected, result == CBlock::CONNECT_RESULT_OK);
    return result;
}

// The coinbase output carrying the producer's payout. Chosen by value rather
// than by position: the IDAG commitment is a zero-value OP_RETURN and its index
// is the producer's to choose.
unsigned int LargestCoinbaseOutput(const CTransaction& coinbase)
{
    unsigned int nBest = 0;
    for (unsigned int i = 1; i < coinbase.vout.size(); i++)
        if (coinbase.vout[i].nValue > coinbase.vout[nBest].nValue)
            nBest = i;
    return nBest;
}

// Past the DAG fork, and past any settlement height: on a settlement block the
// allowance carries a settlement leg as well, so the reserve arm below would no
// longer name a single quantity.
void MineToNonSettlementPostDAG()
{
    MineToPostDAG();
    while (IsFinalitySettlementHeight(BestIndex()->nHeight + 1))
        MineTo(BestIndex()->nHeight + 1);
}

// Every condition that makes the arms below adversarial rather than vacuous.
void RequireAllowanceWindow(AllowanceCandidate& cb)
{
    BOOST_TEST_MESSAGE("coinbase allowance at height " << cb.Height()
                       << " (DAG fork " << FORK_HEIGHT_DAG << ", reserve "
                       << GetFinalityReservePerBlock(cb.Height()) << ")");
    BOOST_REQUIRE_MESSAGE(cb.Height() >= FORK_HEIGHT_DAG,
                          "below the DAG fork the reserve is zero and the arms "
                          "prove nothing");
    BOOST_REQUIRE_MESSAGE(GetFinalityReservePerBlock(cb.Height()) > 0,
                          "the reserve is zero at height " << cb.Height());
    BOOST_REQUIRE_MESSAGE(cb.block.IsProofOfWork(),
                          "the allowance branch under test is the proof-of-work one");
    int nSettlementEpoch = -1;
    BOOST_REQUIRE_MESSAGE(!IsFinalitySettlementHeight(cb.Height(), &nSettlementEpoch),
                          "height " << cb.Height() << " is a settlement height, so "
                          "the allowance carries a settlement leg as well and the "
                          "reserve arm no longer names one quantity");
    BOOST_REQUIRE_MESSAGE(pindexBest != NULL &&
                              pindexBest->GetBlockHash() == cb.block.hashPrevBlock,
                          "the candidate does not extend this node's own tip");
}

} // namespace

// The producer's block connects and one satoshi more does not, so the producer pays
// exactly the validator's allowance.
BOOST_AUTO_TEST_CASE(the_coinbase_allowance_is_exactly_what_the_producer_pays)
{
    MineToNonSettlementPostDAG();

    AllowanceCandidate control;
    BOOST_REQUIRE(BuildAllowanceCandidate(control));
    BOOST_REQUIRE(SealCandidate(control));
    RequireAllowanceWindow(control);
    BOOST_REQUIRE_MESSAGE(ConnectAndRollBack(control) == CBlock::CONNECT_RESULT_OK,
                          "the producer's own block was refused; every arm below "
                          "would then pass for the wrong reason");

    AllowanceCandidate over;
    BOOST_REQUIRE(BuildAllowanceCandidate(over));
    const unsigned int nOut = LargestCoinbaseOutput(over.Coinbase());
    BOOST_REQUIRE(over.Coinbase().vout[nOut].nValue > 0);
    const int64_t nPaid = over.Coinbase().GetValueOut();
    over.Coinbase().vout[nOut].nValue += 1;
    BOOST_REQUIRE_EQUAL(over.Coinbase().GetValueOut(), nPaid + 1);
    BOOST_REQUIRE(SealCandidate(over));
    RequireAllowanceWindow(over);
    BOOST_CHECK_MESSAGE(ConnectAndRollBack(over) == CBlock::CONNECT_RESULT_INVALID,
                        "a coinbase paying one satoshi above the producer's own "
                        "figure was accepted, so the cap is not the allowance");
}

// A coinbase taking the withheld reserve too (allowance sized by Total() instead of
// PaidToBlock()) would mint the settlement budget twice.
BOOST_AUTO_TEST_CASE(a_coinbase_may_not_pay_out_the_withheld_finality_reserve)
{
    MineToNonSettlementPostDAG();

    AllowanceCandidate cb;
    BOOST_REQUIRE(BuildAllowanceCandidate(cb));
    const int64_t nReserve = GetFinalityReservePerBlock(cb.pparent->nHeight + 1);
    BOOST_REQUIRE_MESSAGE(nReserve > 0, "no reserve is withheld at this height");

    const unsigned int nOut = LargestCoinbaseOutput(cb.Coinbase());
    const int64_t nPaid = cb.Coinbase().GetValueOut();
    cb.Coinbase().vout[nOut].nValue += nReserve;
    BOOST_REQUIRE_EQUAL(cb.Coinbase().GetValueOut(), nPaid + nReserve);
    BOOST_REQUIRE(SealCandidate(cb));
    RequireAllowanceWindow(cb);

    BOOST_CHECK_MESSAGE(ConnectAndRollBack(cb) == CBlock::CONNECT_RESULT_INVALID,
                        "a coinbase carrying the withheld reserve was accepted; the "
                        "epoch settlement would then be minted twice");

    // And the reserve is the whole of what separates the two: the producer's own
    // figure plus the reserve is the un-netted subsidy the pre-split code paid.
    const CBlockSubsidySplit split = CBlockSubsidySplit::ForBlock(
        cb.Height(), GetBlockSubsidySchedule(cb.Height()), 0,
        CollateralnodeShare::Paid);
    BOOST_CHECK_EQUAL(split.PaidToBlock() + split.FinalityReserve(), split.Total());
    BOOST_CHECK_EQUAL(split.FinalityReserve(), nReserve);
}

BOOST_AUTO_TEST_SUITE_END()
