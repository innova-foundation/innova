// getdagheaders entries: the coinbase merkle branch and the DAG parent commitment are checked
// against the header, and the skeleton opens the assume-valid gate by ancestry only.

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

#include "../dag.h"
#include "../dagheaders.h"
#include "../main.h"
#include "../protocol.h"
#include "../script.h"
#include "../uint256.h"
#include "synthetic_chain.h"

extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(dagheaders_tests)

namespace {

std::vector<uint256> MakeParents(const uint256& hashPrev, unsigned int nMerge)
{
    std::vector<uint256> vParents(1, hashPrev);
    for (unsigned int i = 0; i < nMerge; i++)
        vParents.push_back(uint256(0x5000 + i));
    return vParents;
}

CTransaction MakeCoinbase(int nHeight, const CScript& scriptCommit)
{
    CTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    if (!scriptCommit.empty())
        tx.vout.push_back(CTxOut(0, scriptCommit));
    tx.vout.push_back(CTxOut(50 * COIN, CScript() << OP_TRUE));
    return tx;
}

CTransaction MakeSpend(unsigned int n)
{
    CTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256(0x9000 + n), n);
    tx.vin[0].scriptSig = CScript() << OP_TRUE;
    tx.vout.push_back(CTxOut(COIN + n, CScript() << OP_TRUE));
    return tx;
}

CBlock MakeBlock(const CTransaction& txCoinbase, const uint256& hashPrev, unsigned int nSpends)
{
    CBlock block;
    block.nVersion = CBlock::CURRENT_VERSION;
    block.hashPrevBlock = hashPrev;
    block.nTime = 1700000000;
    block.nBits = 0x207fffff;
    block.nNonce = 7;
    block.vtx.push_back(txCoinbase);
    for (unsigned int i = 0; i < nSpends; i++)
        block.vtx.push_back(MakeSpend(i));
    block.hashMerkleRoot = block.BuildMerkleTree();
    return block;
}

CDAGHeaderEntry EntryFor(const CBlock& block)
{
    CDAGHeaderEntry entry;
    entry.header.nVersion = block.nVersion;
    entry.header.hashPrevBlock = block.hashPrevBlock;
    entry.header.hashMerkleRoot = block.hashMerkleRoot;
    entry.header.nTime = block.nTime;
    entry.header.nBits = block.nBits;
    entry.header.nNonce = block.nNonce;
    entry.txCoinbase = block.vtx[0];
    entry.vMerkleBranch = block.GetMerkleBranch(0);
    return entry;
}

int DagHeight() { return FORK_HEIGHT_DAG + 10; }

} // namespace

// A command longer than the header field arrives truncated and is never dispatched.
BOOST_AUTO_TEST_CASE(the_commands_survive_the_message_header)
{
    BOOST_CHECK_EQUAL(CMessageHeader(DAGHEADERS_GETCMD, 0).GetCommand(), std::string(DAGHEADERS_GETCMD));
    BOOST_CHECK_EQUAL(CMessageHeader(DAGHEADERS_CMD, 0).GetCommand(), std::string(DAGHEADERS_CMD));
}

BOOST_AUTO_TEST_CASE(a_served_entry_proves_its_coinbase_and_parents)
{
    BOOST_REQUIRE(fRegTest);
    const uint256 hashPrev(0x1234);
    const std::vector<uint256> vParents = MakeParents(hashPrev, 3);
    const unsigned int vSpends[] = { 0, 1, 2, 4, 7, 12 };
    for (size_t i = 0; i < sizeof(vSpends) / sizeof(vSpends[0]); i++)
    {
        const CBlock block = MakeBlock(MakeCoinbase(DagHeight(), BuildDAGParentScript(vParents)),
                                       hashPrev, vSpends[i]);
        CDAGHeaderEntry entry = EntryFor(block);

        // Through the wire format, as a peer would receive it.
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << entry;
        CDAGHeaderEntry received;
        ss >> received;
        BOOST_CHECK(received.header.GetHash() == block.GetHash());

        std::vector<uint256> vOut;
        std::string strError;
        BOOST_CHECK_MESSAGE(CheckDAGHeaderEntry(received, DagHeight(), vOut, strError),
                            vSpends[i] << " spends: " << strError);
        BOOST_CHECK(vOut == vParents);
    }
}

BOOST_AUTO_TEST_CASE(a_branch_that_misses_the_merkle_root_is_refused)
{
    const uint256 hashPrev(0x2345);
    const CBlock block = MakeBlock(
        MakeCoinbase(DagHeight(), BuildDAGParentScript(MakeParents(hashPrev, 1))), hashPrev, 5);
    std::vector<uint256> vOut;
    std::string strError;

    CDAGHeaderEntry entry = EntryFor(block);
    BOOST_REQUIRE(!entry.vMerkleBranch.empty());
    entry.vMerkleBranch[1] = uint256(0xbad);
    BOOST_CHECK(!CheckDAGHeaderEntry(entry, DagHeight(), vOut, strError));

    entry = EntryFor(block);
    entry.vMerkleBranch.pop_back();
    BOOST_CHECK(!CheckDAGHeaderEntry(entry, DagHeight(), vOut, strError));

    entry = EntryFor(block);
    entry.header.hashMerkleRoot = uint256(0xbad);
    BOOST_CHECK(!CheckDAGHeaderEntry(entry, DagHeight(), vOut, strError));

    // A coinbase other than the committed one: same branch, different leaf.
    entry = EntryFor(block);
    entry.txCoinbase.vout.push_back(CTxOut(1, CScript() << OP_TRUE));
    BOOST_CHECK(!CheckDAGHeaderEntry(entry, DagHeight(), vOut, strError));

    entry = EntryFor(block);
    entry.vMerkleBranch.resize(MAX_DAGHEADERS_BRANCH + 1);
    BOOST_CHECK(!CheckDAGHeaderEntry(entry, DagHeight(), vOut, strError));
    BOOST_CHECK(vOut.empty());
}

BOOST_AUTO_TEST_CASE(only_a_coinbase_at_index_zero_is_accepted)
{
    const uint256 hashPrev(0x3456);
    const CBlock block = MakeBlock(
        MakeCoinbase(DagHeight(), BuildDAGParentScript(MakeParents(hashPrev, 0))), hashPrev, 3);
    std::vector<uint256> vOut;
    std::string strError;

    // The second transaction with its own valid branch is not a coinbase.
    CDAGHeaderEntry entry = EntryFor(block);
    entry.txCoinbase = block.vtx[1];
    entry.vMerkleBranch = block.GetMerkleBranch(1);
    BOOST_REQUIRE(CBlock::CheckMerkleBranch(block.vtx[1].GetHash(), entry.vMerkleBranch, 1) ==
                  block.hashMerkleRoot);
    BOOST_CHECK(!CheckDAGHeaderEntry(entry, DagHeight(), vOut, strError));

    // A one-transaction block has an empty branch and the coinbase hash as its root.
    const CBlock single = MakeBlock(
        MakeCoinbase(DagHeight(), BuildDAGParentScript(MakeParents(hashPrev, 0))), hashPrev, 0);
    entry = EntryFor(single);
    BOOST_CHECK(entry.vMerkleBranch.empty());
    BOOST_CHECK_MESSAGE(CheckDAGHeaderEntry(entry, DagHeight(), vOut, strError), strError);
}

BOOST_AUTO_TEST_CASE(the_commitment_must_decode_and_name_the_primary_parent)
{
    const uint256 hashPrev(0x4567);
    std::vector<uint256> vOut;
    std::string strError;

    // First parent is not hashPrevBlock.
    const CBlock wrongPrimary = MakeBlock(
        MakeCoinbase(DagHeight(), BuildDAGParentScript(MakeParents(uint256(0x7777), 2))), hashPrev, 2);
    BOOST_CHECK(!CheckDAGHeaderEntry(EntryFor(wrongPrimary), DagHeight(), vOut, strError));

    // No commitment from the DAG fork on.
    const CBlock missing = MakeBlock(MakeCoinbase(DagHeight(), CScript()), hashPrev, 2);
    BOOST_CHECK(!CheckDAGHeaderEntry(EntryFor(missing), DagHeight(), vOut, strError));

    // Below the fork no commitment exists, and none is read.
    BOOST_CHECK_MESSAGE(CheckDAGHeaderEntry(EntryFor(missing), FORK_HEIGHT_DAG - 1, vOut, strError),
                        strError);
    BOOST_CHECK(vOut.empty());

    // Two commitments are refused where the strict decoder applies.
    if (IsBoundaryAActiveAtHeight(DagHeight()))
    {
        CTransaction txTwo = MakeCoinbase(DagHeight(), BuildDAGParentScript(MakeParents(hashPrev, 1)));
        txTwo.vout.push_back(CTxOut(0, BuildDAGParentScript(MakeParents(hashPrev, 2))));
        const CBlock two = MakeBlock(txTwo, hashPrev, 1);
        BOOST_CHECK(!CheckDAGHeaderEntry(EntryFor(two), DagHeight(), vOut, strError));
    }
}

BOOST_AUTO_TEST_CASE(the_skeleton_is_bounded_and_prunes_by_height)
{
    CDAGHeaderSkeleton skeleton(3);
    CDAGSkeletonNode node;
    uint256 hashPrev(0xa0);
    for (int i = 1; i <= 4; i++)
    {
        node.hashPrev = hashPrev;
        node.nHeight = 100 + i;
        const bool fAdded = skeleton.Add(uint256(0xa0 + i), node);
        BOOST_CHECK_EQUAL(fAdded, i <= 3);
        hashPrev = uint256(0xa0 + i);
    }
    BOOST_CHECK_EQUAL(skeleton.Size(), 3u);
    BOOST_CHECK_EQUAL(skeleton.Room(), 0u);
    BOOST_CHECK_EQUAL(skeleton.TopHeight(), 103);

    uint256 hashRoot;
    int nRootHeight = -1;
    std::vector<uint256> vChain;
    BOOST_REQUIRE(skeleton.CollectChain(uint256(0xa3), hashRoot, nRootHeight, vChain));
    BOOST_CHECK(hashRoot == uint256(0xa0));
    BOOST_CHECK_EQUAL(nRootHeight, 100);
    BOOST_REQUIRE_EQUAL(vChain.size(), 3u);
    BOOST_CHECK(vChain.front() == uint256(0xa1) && vChain.back() == uint256(0xa3));

    skeleton.PruneAtOrBelow(102);
    BOOST_CHECK_EQUAL(skeleton.Size(), 1u);
    BOOST_CHECK(skeleton.Have(uint256(0xa3)));
    BOOST_CHECK(!skeleton.Have(uint256(0xa2)));
    BOOST_CHECK_EQUAL(skeleton.Room(), 2u);
}

// The anchor answers for blocks whose bodies arrive before the assume-valid block is indexed,
// and only along the hash-linked run to it.
BOOST_AUTO_TEST_CASE(headers_open_the_assume_valid_gate_by_ancestry_only)
{
    LOCK(cs_main);
    CSyntheticChain chain(0xD4E40001U);
    CBlockIndex* pBase = chain.Linear(20);
    BOOST_REQUIRE(pBase != NULL);

    // Header-only run above the indexed base; the last one is the assume-valid block.
    CDAGHeaderSkeleton skeleton(100);
    std::vector<uint256> vRun;
    uint256 hashPrev = pBase->GetBlockHash();
    for (int i = 1; i <= 10; i++)
    {
        CDAGSkeletonNode node;
        node.hashPrev = hashPrev;
        node.nHeight = pBase->nHeight + i;
        const uint256 hash = uint256(0xD4E40000ULL + (uint64_t)i);
        BOOST_REQUIRE(skeleton.Add(hash, node));
        vRun.push_back(hash);
        hashPrev = hash;
    }
    const uint256 hashAssumeValid = vRun.back();
    BOOST_CHECK(!IsPrivacyVNextAssumeValidAncestorOf(hashAssumeValid, pBase));

    uint256 hashRoot;
    int nRootHeight = -1;
    std::vector<uint256> vChain;
    BOOST_REQUIRE(skeleton.CollectChain(hashAssumeValid, hashRoot, nRootHeight, vChain));
    BOOST_REQUIRE(hashRoot == pBase->GetBlockHash());
    DAGHeadersSetAssumeValidAnchor(hashAssumeValid, hashRoot, nRootHeight, vChain);

    // Bodies for the first five arrive; a sibling at the same heights does not qualify.
    std::vector<CBlockIndex*> vOwned;
    std::vector<uint256> vOwnedHashes;
    CBlockIndex* pPrev = pBase;
    CBlockIndex* pSiblingPrev = pBase;
    for (int i = 0; i < 5; i++)
    {
        CBlockIndex* p = new CBlockIndex();
        p->nHeight = pPrev->nHeight + 1;
        p->pprev = pPrev;
        p->phashBlock = &mapBlockIndex.insert(std::make_pair(vRun[i], p)).first->first;
        p->BuildSkip();
        vOwned.push_back(p);
        vOwnedHashes.push_back(vRun[i]);
        pPrev = p;

        const uint256 hashSibling = uint256(0xD4E50000ULL + (uint64_t)i);
        CBlockIndex* s = new CBlockIndex();
        s->nHeight = pSiblingPrev->nHeight + 1;
        s->pprev = pSiblingPrev;
        s->phashBlock = &mapBlockIndex.insert(std::make_pair(hashSibling, s)).first->first;
        s->BuildSkip();
        vOwned.push_back(s);
        vOwnedHashes.push_back(hashSibling);
        pSiblingPrev = s;

        BOOST_CHECK_MESSAGE(IsPrivacyVNextAssumeValidAncestorOf(hashAssumeValid, p),
                            "run block at height " << p->nHeight << " must qualify");
        BOOST_CHECK_MESSAGE(!IsPrivacyVNextAssumeValidAncestorOf(hashAssumeValid, s),
                            "sibling at height " << s->nHeight << " must not qualify");
    }
    // Below the run, the indexed ancestry of the root answers.
    BOOST_CHECK(IsPrivacyVNextAssumeValidAncestorOf(hashAssumeValid, pBase));
    BOOST_CHECK(IsPrivacyVNextAssumeValidAncestorOf(hashAssumeValid, pBase->GetAncestor(3)));
    // Another hash gets nothing from this anchor.
    BOOST_CHECK(!IsPrivacyVNextAssumeValidAncestorOf(vRun[8], vOwned[0]));

    DAGHeadersClearAssumeValidAnchor();
    BOOST_CHECK(!IsPrivacyVNextAssumeValidAncestorOf(hashAssumeValid, vOwned[0]));
    for (size_t i = 0; i < vOwned.size(); i++)
    {
        mapBlockIndex.erase(vOwnedHashes[i]);
        delete vOwned[i];
    }
}

BOOST_AUTO_TEST_SUITE_END()
