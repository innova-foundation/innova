// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// DisconnectBlock undoes everything ConnectBlock wrote for a block with
// shielded outputs, for both the legacy and the V3 index.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../key.h"
#include "../main.h"
#include "../miner.h"
#include "../script.h"
#include "../shielded.h"
#include "../txdb.h"
#include "../util.h"
#include "../wallet.h"
#include "../zkproof.h"

extern CWallet* pwalletMain;

BOOST_AUTO_TEST_SUITE(shielded_pool_reorg_tests)

namespace {

// The suite mines real blocks. A registered wallet would record their coinbases
// and the shielding transaction, moving the ordering counters other suites pin.
struct DetachedWalletGuard
{
    DetachedWalletGuard() { UnregisterWallet(pwalletMain); }
    ~DetachedWalletGuard() { RegisterWallet(pwalletMain); }
};

CBlockIndex* ParentOf(const CBlock& block)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::const_iterator mi =
        mapBlockIndex.find(block.hashPrevBlock);
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

// ConnectBlock re-runs CheckBlock with the proof-of-work check on, so a block it
// is handed has to carry real work even when it never reaches the chain.
bool GrindHeader(CBlock* pblock)
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
        if (++nHashes > 2000000U)
            return false;
    }
    return true;
}

// Seal a template the caller has already filled and put it on the chain.
// IncrementExtraNonce rebuilds the merkle tree, so it runs last.
bool SealAndProcess(CBlock* pblock, CBlockIndex* pindexParent)
{
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock, pindexParent, nExtraNonce);
    return GrindHeader(pblock) && ProcessBlock(NULL, pblock);
}

// One empty proof-of-work block on the tip, returned so the caller can spend its
// coinbase later.
bool MineOneBlock(CBlock& blockOut)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexParent = ParentOf(*pblock);
    if (pindexParent == NULL)
        return false;
    if (!SealAndProcess(pblock.get(), pindexParent))
        return false;
    blockOut = *pblock;
    return true;
}

// Both cases spend the same coinbase: each aborts its batch, so the output is
// still unspent for the next one. The chain therefore grows by exactly one block
// however many cases are added, which keeps every case inside the window below.
const CTransaction* FundingCoinbase()
{
    static CBlock blockFunding;
    static bool fMined = false;
    if (!fMined)
    {
        DetachedWalletGuard walletGuard;
        if (!MineOneBlock(blockFunding))
            return NULL;
        fMined = true;
    }
    return &blockFunding.vtx[0];
}

// Everything DisconnectBlock has to put back. Read straight from the database so
// a case compares stored state, not a cached copy of it.
struct ShieldedState
{
    int64_t nPool;
    uint256 treeRoot;
    uint64_t nTreeSize;
    uint64_t nCommitCount;

    ShieldedState() : nPool(0), treeRoot(0), nTreeSize(0), nCommitCount(0) {}

    bool operator==(const ShieldedState& o) const
    {
        return nPool == o.nPool && treeRoot == o.treeRoot &&
               nTreeSize == o.nTreeSize && nCommitCount == o.nCommitCount;
    }
};

bool ReadShieldedState(CTxDB& txdb, ShieldedState& out)
{
    CIncrementalMerkleTree tree;
    if (!txdb.ReadShieldedTree(tree))
        return false;
    if (!txdb.ReadShieldedPoolValue(out.nPool))
        return false;
    if (!txdb.ReadShieldedCommitmentCount(out.nCommitCount))
        return false;
    out.treeRoot = tree.Root();
    out.nTreeSize = tree.Size();
    return true;
}

// A v2000 shielding transaction: transparent value in, one shielded note out,
// negative nValueBalance. Built the way rpcshielded builds one -- the transparent
// input is signed first, because GetBindingSigHash covers vin.
bool BuildShieldingTx(const CTransaction& txFunding, unsigned int nOut,
                      int64_t nShieldAmount, unsigned int nTime,
                      unsigned char nSeed, CTransaction& txOut,
                      CPedersenCommitment& cvOut)
{
    CShieldedPaymentAddress zAddr = pwalletMain->GenerateNewShieldedAddress();

    CShieldedNote note;
    note.addr = zAddr;
    note.nValue = nShieldAmount;
    for (int i = 0; i < 32; i++)
    {
        note.rho.begin()[i] = (unsigned char)(nSeed + i);
        note.rcm.begin()[i] = (unsigned char)(nSeed + 64 + i);
    }
    if (!note.GenerateBlindingFactor())
        return false;

    CPedersenCommitment cv;
    if (!note.GetPedersenCommitment(cv))
        return false;

    CShieldedOutputDescription output;
    output.cv = cv;
    output.cmu = note.GetCommitment();
    if (!CreateBulletproofRangeProof(note.nValue, note.vchBlind, cv,
                                     output.rangeProof))
        return false;
    if (!EncryptShieldedNote(note, zAddr, output.vchEphemeralKey,
                             output.vchEncCiphertext))
        return false;

    const int64_t nIn = txFunding.vout[nOut].nValue;
    const int64_t nFee = MIN_TX_FEE_SHIELDED;
    if (nIn <= nShieldAmount + nFee)
        return false;

    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION;
    tx.nTime = nTime;
    tx.nValueBalance = -nShieldAmount;
    tx.vShieldedOutput.push_back(output);
    tx.vin.push_back(CTxIn(txFunding.GetHash(), nOut));
    tx.vout.push_back(CTxOut(nIn - nShieldAmount - nFee,
                             txFunding.vout[nOut].scriptPubKey));
    if (!SignSignature(*pwalletMain, txFunding, tx, 0, SIGHASH_ALL))
        return false;

    std::vector<std::vector<unsigned char> > vInputBlinds, vOutputBlinds;
    vOutputBlinds.push_back(note.vchBlind);
    vInputBlinds.push_back(std::vector<unsigned char>(32, 0));
    CBindingSignature bindingSig;
    if (!CreateBindingSignature(vInputBlinds, vOutputBlinds,
                                tx.GetBindingSigHash(), bindingSig))
        return false;
    tx.bindingSig.bindingSig = bindingSig;

    txOut = tx;
    cvOut = cv;
    return true;
}

// A block on the tip carrying one shielded transaction, with the stack block
// index ConnectBlock and DisconnectBlock are handed. It is never put on the
// chain: both halves run inside a batch the caller aborts.
struct ShieldedBlock
{
    CBlock block;
    uint256 hash;
    CBlockIndex index;
    CPedersenCommitment cv;

    CBlockIndex* Index() { return &index; }
};

bool BuildShieldedBlock(const CTransaction& txFunding, unsigned int nOut,
                        int64_t nShieldAmount, unsigned char nSeed,
                        ShieldedBlock& out)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexParent = ParentOf(*pblock);
    if (pindexParent == NULL)
        return false;

    CTransaction txShield;
    if (!BuildShieldingTx(txFunding, nOut, nShieldAmount, pblock->nTime, nSeed,
                          txShield, out.cv))
        return false;
    pblock->vtx.push_back(txShield);

    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexParent, nExtraNonce);
    if (!GrindHeader(pblock.get()))
        return false;

    out.block = *pblock;
    out.hash = out.block.GetHash();
    out.index = CBlockIndex(0, 0, out.block);
    out.index.pprev = pindexParent;
    out.index.nHeight = pindexParent->nHeight + 1;
    out.index.phashBlock = &out.hash;
    return true;
}

// Requires shielded rules live and the block below the DAG gate. A tripwire, not a
// skip: a prior suite leaving the chain past the gate must be visible.
void RequireShieldedWindow(int nBlockHeight)
{
    BOOST_REQUIRE_MESSAGE(nBlockHeight >= FORK_HEIGHT_SHIELDED,
                          "block height " << nBlockHeight
                          << " is below FORK_HEIGHT_SHIELDED "
                          << FORK_HEIGHT_SHIELDED);
    BOOST_REQUIRE_MESSAGE(nBlockHeight < FORK_HEIGHT_DAG,
                          "block height " << nBlockHeight
                          << " is at or past FORK_HEIGHT_DAG " << FORK_HEIGHT_DAG
                          << "; a preceding suite advanced the chain");
}

} // namespace

// The reversal, on the legacy reverse index. Connect writes a pool delta, a leaf,
// a commitment record and a new anchor; disconnect must undo all four and leave
// the predecessor's anchor alone.
BOOST_AUTO_TEST_CASE(disconnect_reverses_the_shielded_pool_tree_and_anchor)
{
    DetachedWalletGuard walletGuard;
    LOCK(cs_main);

    const CTransaction* ptxFunding = FundingCoinbase();
    BOOST_REQUIRE(ptxFunding != NULL);

    const int64_t nShieldAmount = 5 * CENT;
    ShieldedBlock sb;
    BOOST_REQUIRE(BuildShieldedBlock(*ptxFunding, 0, nShieldAmount, 0x11, sb));
    RequireShieldedWindow(sb.index.nHeight);

    CTxDB txdb;
    BOOST_REQUIRE(txdb.TxnBegin());

    ShieldedState before;
    BOOST_REQUIRE(ReadShieldedState(txdb, before));
    const uint256 rootBefore = before.treeRoot;

    CBlock::ConnectResult result = CBlock::CONNECT_RESULT_INVALID;
    const bool fConnected = sb.block.ConnectBlock(txdb, sb.Index(), false, false, &result);
    BOOST_CHECK_EQUAL(result, CBlock::CONNECT_RESULT_OK);
    BOOST_REQUIRE(fConnected);

    // Positive control: the connect has to have moved every quantity the
    // disconnect is about, or the comparison below is vacuous.
    ShieldedState connected;
    BOOST_REQUIRE(ReadShieldedState(txdb, connected));
    BOOST_CHECK_EQUAL(connected.nPool, before.nPool + nShieldAmount);
    BOOST_CHECK_EQUAL(connected.nTreeSize, before.nTreeSize + 1);
    BOOST_CHECK_EQUAL(connected.nCommitCount, before.nCommitCount + 1);
    BOOST_CHECK(connected.treeRoot != rootBefore);
    BOOST_CHECK(txdb.ReadShieldedAnchor(connected.treeRoot));

    const uint64_t nLeaf = before.nTreeSize;
    CPedersenCommitment commitStored;
    BOOST_CHECK(txdb.ReadShieldedCommitment(nLeaf, commitStored));
    BOOST_CHECK(commitStored.vchCommitment == sb.cv.vchCommitment);
    BOOST_CHECK(txdb.HasShieldedCommitmentHeight(nLeaf));
    BOOST_CHECK(txdb.HasShieldedCommitmentIndex(sb.cv.vchCommitment));
    CIncrementalMerkleTree snapshot;
    BOOST_CHECK(txdb.ReadShieldedTreeAtBlock(sb.hash, snapshot));

    BOOST_REQUIRE(sb.block.DisconnectBlock(txdb, sb.Index(), false));

    ShieldedState after;
    BOOST_REQUIRE(ReadShieldedState(txdb, after));
    BOOST_CHECK_EQUAL(after.nPool, before.nPool);
    BOOST_CHECK_EQUAL(after.nTreeSize, before.nTreeSize);
    BOOST_CHECK_EQUAL(after.nCommitCount, before.nCommitCount);
    BOOST_CHECK(after.treeRoot == rootBefore);
    BOOST_CHECK(after == before);

    // The anchor the block created is gone; the predecessor's still resolves, so
    // a spend anchored before the reorg is not collaterally invalidated.
    BOOST_CHECK(!txdb.ReadShieldedAnchor(connected.treeRoot));
    BOOST_CHECK(txdb.ReadShieldedAnchor(rootBefore));

    // The leaf's own records are gone, not merely orphaned past the count.
    CPedersenCommitment commitGone;
    BOOST_CHECK(!txdb.ReadShieldedCommitment(nLeaf, commitGone));
    BOOST_CHECK(!txdb.HasShieldedCommitmentHeight(nLeaf));
    BOOST_CHECK(!txdb.HasShieldedCommitmentIndex(sb.cv.vchCommitment));

    // The per-block snapshot the disconnect consumed is not left behind.
    CIncrementalMerkleTree snapshotGone;
    BOOST_CHECK(!txdb.ReadShieldedTreeAtBlock(sb.hash, snapshotGone));

    BOOST_REQUIRE(txdb.TxnAbort());
}

// The same reversal with the V3 reverse index active. The mode is resolved from
// the height OR the stored marker, so installing the marker reaches the V3 arm
// -- the arm that runs on mainnet from Boundary A on -- at a testable height.
BOOST_AUTO_TEST_CASE(disconnect_reverses_the_shielded_state_under_v3_persistence)
{
    DetachedWalletGuard walletGuard;
    LOCK(cs_main);

    const CTransaction* ptxFunding = FundingCoinbase();
    BOOST_REQUIRE(ptxFunding != NULL);

    const int64_t nShieldAmount = 7 * CENT;
    ShieldedBlock sb;
    BOOST_REQUIRE(BuildShieldedBlock(*ptxFunding, 0, nShieldAmount, 0x37, sb));
    RequireShieldedWindow(sb.index.nHeight);

    CTxDB txdb;
    BOOST_REQUIRE(txdb.TxnBegin());

    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        txdb.InitializeShieldedCommitmentIndexV3(sb.index.pprev->GetBlockHash(), strError),
        strError);
    bool fUseV3 = false;
    BOOST_REQUIRE(txdb.ResolveShieldedCommitmentIndexV3Mode(
        sb.index.nHeight, FORK_HEIGHT_EPOCH_STATE_V3, fUseV3, strError));
    BOOST_REQUIRE_MESSAGE(fUseV3, "V3 reverse index did not activate");

    ShieldedState before;
    BOOST_REQUIRE(ReadShieldedState(txdb, before));
    const uint256 rootBefore = before.treeRoot;
    // The V3 arm reads the predecessor root's height, so it must be recorded.
    BOOST_REQUIRE(txdb.ReadShieldedAnchor(rootBefore));
    BOOST_REQUIRE(txdb.HasShieldedAnchorHeight(rootBefore));

    CBlock::ConnectResult result = CBlock::CONNECT_RESULT_INVALID;
    const bool fConnected = sb.block.ConnectBlock(txdb, sb.Index(), false, false, &result);
    BOOST_CHECK_EQUAL(result, CBlock::CONNECT_RESULT_OK);
    BOOST_REQUIRE(fConnected);

    ShieldedState connected;
    BOOST_REQUIRE(ReadShieldedState(txdb, connected));
    BOOST_CHECK_EQUAL(connected.nPool, before.nPool + nShieldAmount);
    BOOST_CHECK_EQUAL(connected.nTreeSize, before.nTreeSize + 1);
    BOOST_CHECK(connected.treeRoot != rootBefore);

    // The V3 arm records the height an anchor first became active; the reversal
    // keys on it to decide whether the anchor belongs to this block.
    int nAnchorHeight = -1;
    BOOST_REQUIRE(txdb.ReadShieldedAnchorHeight(connected.treeRoot, nAnchorHeight));
    BOOST_CHECK_EQUAL(nAnchorHeight, sb.index.nHeight);

    const uint64_t nLeaf = before.nTreeSize;
    uint64_t nIndexed = 0;
    BOOST_CHECK(txdb.ReadShieldedCommitmentIndex(sb.cv.vchCommitment, nIndexed));
    BOOST_CHECK_EQUAL(nIndexed, nLeaf);

    BOOST_REQUIRE(sb.block.DisconnectBlock(txdb, sb.Index(), false));

    ShieldedState after;
    BOOST_REQUIRE(ReadShieldedState(txdb, after));
    BOOST_CHECK(after == before);
    BOOST_CHECK_EQUAL(after.nPool, before.nPool);
    BOOST_CHECK_EQUAL(after.nCommitCount, before.nCommitCount);

    // Anchor and its height are erased as a pair; leaving the height behind would
    // age a re-created anchor from the wrong block.
    BOOST_CHECK(!txdb.ReadShieldedAnchor(connected.treeRoot));
    BOOST_CHECK(!txdb.HasShieldedAnchorHeight(connected.treeRoot));
    BOOST_CHECK(txdb.ReadShieldedAnchor(rootBefore));
    BOOST_CHECK(txdb.HasShieldedAnchorHeight(rootBefore));

    // The V3 reverse index is popped, not merely overwritten, and what it leaves
    // behind still validates.
    BOOST_CHECK(!txdb.HasShieldedCommitmentIndex(sb.cv.vchCommitment));
    BOOST_CHECK_MESSAGE(txdb.ValidateShieldedCommitmentIndexV3(strError), strError);

    BOOST_REQUIRE(txdb.TxnAbort());
}

BOOST_AUTO_TEST_SUITE_END()
