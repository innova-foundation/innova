// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The four DAG-and-privacy interactions, checked against CDAGManager::BuildEpochState
// (merge blocks, determinism, reorg, out-of-order arrival).

#include <boost/test/unit_test.hpp>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../dag.h"
#include "../finality.h"
#include "../main.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../shielded.h"
#include "../txdb.h"

#include <cstring>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(dag_privacy_interaction_tests)

namespace {

PrivacyVNextDigest FillDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

PrivacyVNextDigest LocalGenesis()
{
    PrivacyVNextDigest d;
    PrivacyVNextLocalGenesis(d.data());
    return d;
}

// Read at use: the fixture sets fRegTest after this translation unit's globals are
// constructed, so a captured value would be mainnet's while validation compares regtest's.
uint8_t LocalNetwork()
{
    return PrivacyVNextLocalNetworkId();
}

// Every payload here rides a transaction with no transparent side at all, so the binding
// it commits to is the one an empty transaction produces.
PrivacyVNextDigest NoTransparentSide()
{
    PrivacyVNextDigest d;
    const uint256 binding = GetPrivacyVNextTransparentBinding(CTransaction());
    std::memcpy(d.data(), binding.begin(), 32);
    return d;
}

// One note and the two independent spends of it that the sibling race needs, plus a second
// shield for the merge block that carries no conflict at all. Proving is the expensive part
// and none of it depends on the DAG, so it is built once and reused by every case.
struct PayloadSet
{
    bool fLoaded;
    std::vector<unsigned char> vchShield;      // creates the note both spends consume
    std::vector<unsigned char> vchShieldTwo;   // an unrelated note, for a merge block
    std::vector<unsigned char> vchSpendA;      // spends the note, paying destination A
    std::vector<unsigned char> vchSpendB;      // spends the SAME note, paying destination B
    uint256 keyImage;                          // the key image both spends publish

    PayloadSet() : fLoaded(false) {}
};

bool BuildPayloadSet(PayloadSet& out, std::string& error)
{
    CTxDB txdb("r+");

    const PrivacyVNextDigest genesis = LocalGenesis();
    const PrivacyVNextDigest binding = NoTransparentSide();
    const uint8_t nNetwork = LocalNetwork();

    PrivacyVNextDerivedKeys owner;
    PrivacyVNextDerivedKeys destA;
    PrivacyVNextDerivedKeys destB;
    if (!DerivePrivacyVNextKeys(FillDigest(0x71), genesis, 0, nNetwork, 0, owner, error) ||
        !DerivePrivacyVNextKeys(FillDigest(0x71), genesis, 0, nNetwork, 1, destA, error) ||
        !DerivePrivacyVNextKeys(FillDigest(0x71), genesis, 0, nNetwork, 2, destB, error))
        return false;

    PrivacyVNextEpochSeed epochSeed;
    if (!LoadPrivacyVNextEpochSeed(epochSeed, error))
        return false;
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    if (!TrimPrivacyVNextTreeStore(txdb, 0, treeState, error))
        return false;
    std::vector<unsigned char> vchRoot;
    uint64_t nTreeSize = 0;
    if (!DecodePrivacyVNextTreeState(treeState, vchRoot, nTreeSize, error))
        return false;
    if (nTreeSize != 0 || vchRoot.size() < 32)
    {
        error = "IV5 tree store did not reset to an empty pool";
        return false;
    }
    PrivacyVNextDigest emptyRoot;
    std::memcpy(emptyRoot.data(), &vchRoot[0], 32);

    const uint64_t nShieldIn = 20000;
    const uint64_t nFee = 100;
    std::vector<PrivacyVNextNewOutput> vShieldOut;
    vShieldOut.resize(1);
    vShieldOut[0].recipient.nNetwork = nNetwork;
    vShieldOut[0].recipient.nAddressType = 0;
    vShieldOut[0].recipient.spendPublic = owner.spendPublic;
    vShieldOut[0].recipient.viewPublic = owner.viewPublic;
    vShieldOut[0].nAmount = nShieldIn - nFee;
    if (!BuildPrivacyVNextShieldPayload(nNetwork, 7, genesis, owner.outgoingViewSecret,
                                        emptyRoot, nTreeSize, binding, nShieldIn, nFee,
                                        vShieldOut, out.vchShield, error))
        return false;

    // A second, unrelated shield. It rides a merge block, so its leaf must never reach the
    // epoch tree -- which is what tells a broken fence apart from a duplicate key image.
    std::vector<PrivacyVNextNewOutput> vShieldTwoOut;
    vShieldTwoOut.resize(1);
    vShieldTwoOut[0].recipient.nNetwork = nNetwork;
    vShieldTwoOut[0].recipient.nAddressType = 0;
    vShieldTwoOut[0].recipient.spendPublic = destB.spendPublic;
    vShieldTwoOut[0].recipient.viewPublic = destB.viewPublic;
    vShieldTwoOut[0].nAmount = 5000 - nFee;
    if (!BuildPrivacyVNextShieldPayload(nNetwork, 7, genesis, destB.outgoingViewSecret,
                                        emptyRoot, nTreeSize, binding, 5000, nFee,
                                        vShieldTwoOut, out.vchShieldTwo, error))
        return false;

    PrivacyVNextStateEffects shieldEffects;
    const PrivacyVNextPayloadValidation shieldValid =
        ExtractPrivacyVNextPayloadEffects(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                          out.vchShield, shieldEffects);
    if (!shieldValid.IsValid())
    {
        error = shieldValid.strError;
        return false;
    }
    if (shieldEffects.outputLeaves.size() != 1)
    {
        error = "the shield did not create exactly one note";
        return false;
    }

    // Place the note so a membership proof can be produced against it.
    if (!GrowPrivacyVNextTreeStore(txdb, shieldEffects.outputLeaves, treeState, error) ||
        !DecodePrivacyVNextTreeState(treeState, vchRoot, nTreeSize, error))
        return false;

    std::vector<PrivacyVNextScanKey> vKeys(1);
    vKeys[0].scanSecret = owner.viewSecret;
    vKeys[0].spendMaterial = owner.spendSecret;
    std::vector<PrivacyVNextScanMatch> vMatches;
    std::vector<PrivacyVNextDigest> vScannedKeyImages;
    uint8_t nOutputCount = 0;
    if (!ScanPrivacyVNextPayload(PRIVACY_VNEXT_SCAN_FULL, nNetwork, 0,
                                 INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, out.vchShield,
                                 vKeys, vMatches, vScannedKeyImages, nOutputCount, error))
        return false;
    if (vMatches.size() != 1)
    {
        error = "the shielded note did not reopen under its own keys";
        return false;
    }

    std::vector<uint64_t> vTargets(1, 0);
    std::vector<unsigned char> vchPaths;
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    if (!ReadPrivacyVNextTreePaths(txdb, nTreeSize, treeState, vTargets, vchPaths, error) ||
        !BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths, vWitnesses,
                                             treeRoot, error))
        return false;

    std::vector<PrivacyVNextSpendNote> vSpends;
    vSpends.resize(1);
    vSpends[0].spendSecret = vMatches[0].spendSecret;
    vSpends[0].y = vMatches[0].y;
    vSpends[0].mask = vMatches[0].mask;
    vSpends[0].nAmount = vMatches[0].nAmount;
    vSpends[0].leaf = shieldEffects.outputLeaves[0];
    vSpends[0].vchWitnessRecord = vWitnesses[0].vchRecord;

    // Two spends of one note, differing only in who they pay. Independently built, so they
    // are two transactions rather than one transaction restamped -- and they publish the
    // same key image, which is the whole conflict.
    std::vector<PrivacyVNextNewOutput> vToA;
    vToA.resize(1);
    vToA[0].recipient.nNetwork = nNetwork;
    vToA[0].recipient.nAddressType = 0;
    vToA[0].recipient.spendPublic = destA.spendPublic;
    vToA[0].recipient.viewPublic = destA.viewPublic;
    vToA[0].nAmount = vMatches[0].nAmount - nFee;

    std::vector<PrivacyVNextNewOutput> vToB = vToA;
    vToB[0].recipient.spendPublic = destB.spendPublic;
    vToB[0].recipient.viewPublic = destB.viewPublic;

    if (!BuildPrivacyVNextTransferPayload(nNetwork, 7, genesis, owner.outgoingViewSecret,
                                          treeRoot, nTreeSize, binding, nFee, vSpends, vToA,
                                          out.vchSpendA, error) ||
        !BuildPrivacyVNextTransferPayload(nNetwork, 7, genesis, owner.outgoingViewSecret,
                                          treeRoot, nTreeSize, binding, nFee, vSpends, vToB,
                                          out.vchSpendB, error))
        return false;

    PrivacyVNextStateEffects effectsA;
    PrivacyVNextStateEffects effectsB;
    const PrivacyVNextPayloadValidation validA =
        ExtractPrivacyVNextPayloadEffects(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                          out.vchSpendA, effectsA);
    const PrivacyVNextPayloadValidation validB =
        ExtractPrivacyVNextPayloadEffects(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                          out.vchSpendB, effectsB);
    if (!validA.IsValid()) { error = validA.strError; return false; }
    if (!validB.IsValid()) { error = validB.strError; return false; }
    if (effectsA.keyImages.size() != 1 || effectsB.keyImages.size() != 1)
    {
        error = "a spend of one note did not publish exactly one key image";
        return false;
    }
    if (effectsA.keyImages[0] != effectsB.keyImages[0])
    {
        error = "the two spends do not name the same note";
        return false;
    }
    if (out.vchSpendA == out.vchSpendB)
    {
        error = "the two spends are the same payload, not two builds";
        return false;
    }
    out.keyImage = uint256(std::vector<unsigned char>(effectsA.keyImages[0].begin(),
                                                      effectsA.keyImages[0].end()));
    out.fLoaded = true;
    return true;
}

const PayloadSet& Payloads()
{
    static PayloadSet set;
    if (!set.fLoaded)
    {
        std::string error;
        BOOST_REQUIRE_MESSAGE(BuildPayloadSet(set, error), "IV5 payload setup: " << error);
    }
    return set;
}

// A transaction whose only content is an IV5 payload. No transparent input and no
// transparent output, which is exactly what the payloads above bind to.
CTransaction IV5Tx(const std::vector<unsigned char>& vchPayload)
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_DSP;
    tx.nTime = 1700000000;
    tx.nLockTime = 0;
    tx.privacyVNext.vchPayload = vchPayload;
    return tx;
}

// Post-DAG PoW block indexes wired into mapBlockIndex and the DAG manager, torn down with
// the globals they moved. Boundary B is placed at the epoch-state V3 height so the epoch
// under test is the chain's first IV5 epoch.
struct EpochShapeHarness
{
    std::vector<uint256>      hashes;
    std::vector<CBlockIndex*> blocks;
    CBlockIndex*              oldBest;
    bool                      oldRegTest;
    bool                      oldTestNet;
    int                       oldBoundaryB;
    CBigNum                   oldProofOfWorkLimit;

    EpochShapeHarness()
    {
        oldRegTest = fRegTest;
        oldTestNet = fTestNet;
        fRegTest = true;
        fTestNet = false;
        oldProofOfWorkLimit = bnProofOfWorkLimit;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        oldBest = pindexBest;
        oldBoundaryB = nRegtestBoundaryBHeight;
        nRegtestBoundaryBHeight = FORK_HEIGHT_EPOCH_STATE_V3;
    }

    ~EpochShapeHarness() { cleanup(); }

    CBlockIndex* add(unsigned int seed, int height, const std::vector<uint256>& parents,
                     CBlockIndex* pprev, const std::vector<CTransaction>* pvtx = NULL)
    {
        CBlock block;
        block.nVersion = 1;
        block.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
        block.nTime = (unsigned int)(1700000000 + height);
        block.nBits = bnProofOfWorkLimit.GetCompact();
        block.nNonce = seed;
        if (pvtx && !pvtx->empty())
        {
            block.vtx = *pvtx;
            block.hashMerkleRoot = block.BuildMerkleTree();
        }
        else
        {
            block.hashMerkleRoot = uint256(seed);
        }
        while (!CheckProofOfWork(block.GetHash(), block.nBits))
            ++block.nNonce;

        unsigned int nFile = 0;
        unsigned int nBlockPos = 0;
        BOOST_REQUIRE(block.WriteToDisk(nFile, nBlockPos));

        const uint256 h = block.GetHash();
        CBlockIndex* idx = new CBlockIndex(nFile, nBlockPos, block);
        idx->nHeight = height;
        idx->pprev = pprev;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(h, idx));
        BOOST_REQUIRE(ins.second);
        idx->phashBlock = &ins.first->first;
        CBlock check;
        BOOST_REQUIRE(check.ReadFromDisk(idx));
        g_dagManager.InitBlockDAGData(idx, parents);
        if (height >= FORK_HEIGHT_DAGKNIGHT)
            BOOST_REQUIRE(g_dagManager.ColorBlockDAGKnight(idx));
        else
            g_dagManager.ColorBlock(idx);
        idx->nChainTrust = g_dagManager.ComputeDAGScore(idx);
        hashes.push_back(h);
        blocks.push_back(idx);
        return idx;
    }

    CBlockIndex* addChild(unsigned int seed, CBlockIndex* pprev,
                          const std::vector<CTransaction>* pvtx = NULL)
    {
        std::vector<uint256> parents(1, pprev->GetBlockHash());
        return add(seed, pprev->nHeight + 1, parents, pprev, pvtx);
    }

    // Detach a block, the way a reorg that disconnected it would leave the DAG.
    void remove(const uint256& h)
    {
        g_dagManager.RemoveBlockDAGData(h);
        mapBlockIndex.erase(h);
        for (size_t i = 0; i < hashes.size(); i++)
            if (hashes[i] == h && blocks[i]) { delete blocks[i]; blocks[i] = NULL; }
    }

    void cleanup()
    {
        for (size_t i = 0; i < hashes.size(); i++)
        {
            g_dagManager.RemoveBlockDAGData(hashes[i]);
            mapBlockIndex.erase(hashes[i]);
            delete blocks[i];
        }
        hashes.clear();
        blocks.clear();
        pindexBest = oldBest;
        nRegtestBoundaryBHeight = oldBoundaryB;
        bnProofOfWorkLimit = oldProofOfWorkLimit;
        fRegTest = oldRegTest;
        fTestNet = oldTestNet;
    }
};

int EpochUnderTest()      { return GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3); }
int EpochStartHeight()    { return GetEpochBoundaryHeight(EpochUnderTest(),
                                                          FORK_HEIGHT_EPOCH_STATE_V3); }
int EpochEndHeight()      { return GetEpochBoundaryHeight(EpochUnderTest() + 1,
                                                          FORK_HEIGHT_EPOCH_STATE_V3) - 1; }

// The predecessor the epoch under test needs. Its finalized height is the block before the
// epoch, which is what gives the IV5 finalized anchor somewhere to land: the walk from the
// boundary stops there instead of running off the bottom of a harness chain.
CEpochState PredecessorFor(const CBlockIndex* pBefore)
{
    CEpochState prev;
    prev.nEpoch = EpochUnderTest() - 1;
    prev.hashBoundaryBlock = pBefore->GetBlockHash();
    prev.nHeightStart = GetEpochBoundaryHeight(EpochUnderTest() - 1, EpochStartHeight());
    prev.nHeightEnd = EpochStartHeight() - 1;
    prev.hashCurveRoot = 0;
    prev.nFinalizedHeightAsOf = EpochStartHeight() - 1;
    return prev;
}

// One chain carries the shield and a spend; one merged sibling carries the competing
// spend and another an unrelated shield.
struct RaceShape
{
    CBlockIndex* pBefore;
    CBlockIndex* pBase;      // carries the shield
    CBlockIndex* pCanon;     // carries spend A
    CBlockIndex* pSibling;   // carries spend B, merged, never connected
    CBlockIndex* pSibShield; // carries the second shield, merged, never connected
    CBlockIndex* pEnd;       // the epoch boundary block
    uint256      hashShieldTx;
    uint256      hashSpendATx;
    uint256      hashSpendBTx;
    uint256      hashSibShieldTx;
};

RaceShape BuildRaceShape(EpochShapeHarness& h, unsigned int nSeedBase)
{
    const PayloadSet& p = Payloads();
    const int hStart = EpochStartHeight();
    const int hEnd = EpochEndHeight();

    std::vector<CTransaction> vShield(1, IV5Tx(p.vchShield));
    std::vector<CTransaction> vSpendA(1, IV5Tx(p.vchSpendA));
    std::vector<CTransaction> vSpendB(1, IV5Tx(p.vchSpendB));
    std::vector<CTransaction> vShieldTwo(1, IV5Tx(p.vchShieldTwo));

    RaceShape s;
    s.hashShieldTx = vShield[0].GetHash();
    s.hashSpendATx = vSpendA[0].GetHash();
    s.hashSpendBTx = vSpendB[0].GetHash();
    s.hashSibShieldTx = vShieldTwo[0].GetHash();

    std::vector<uint256> none;
    s.pBefore = h.add(nSeedBase + 0, hStart - 1, none, NULL);
    s.pBase = h.addChild(nSeedBase + 1, s.pBefore, &vShield);

    s.pCanon = h.addChild(nSeedBase + 2, s.pBase, &vSpendA);
    s.pSibling = h.addChild(nSeedBase + 3, s.pBase, &vSpendB);

    std::vector<uint256> mergeOne;
    mergeOne.push_back(s.pCanon->GetBlockHash());
    mergeOne.push_back(s.pSibling->GetBlockHash());
    CBlockIndex* pMerge = h.add(nSeedBase + 4, hStart + 2, mergeOne, s.pCanon);

    CBlockIndex* pCanonThree = h.addChild(nSeedBase + 5, pMerge);
    s.pSibShield = h.addChild(nSeedBase + 6, pMerge, &vShieldTwo);
    std::vector<uint256> mergeTwo;
    mergeTwo.push_back(pCanonThree->GetBlockHash());
    mergeTwo.push_back(s.pSibShield->GetBlockHash());
    CBlockIndex* pMain = h.add(nSeedBase + 7, hStart + 4, mergeTwo, pCanonThree);

    for (int nHeight = hStart + 5; nHeight <= hEnd; ++nHeight)
        pMain = h.addChild(nSeedBase + 8 + (unsigned int)(nHeight - hStart), pMain);
    s.pEnd = pMain;
    return s;
}

// A chain of the same length that never saw a payload, for the races that replace one
// whole chain with another.
CBlockIndex* BuildPlainChain(EpochShapeHarness& h, CBlockIndex* pBefore,
                             unsigned int nSeedBase)
{
    CBlockIndex* p = pBefore;
    for (int nHeight = EpochStartHeight(); nHeight <= EpochEndHeight(); ++nHeight)
        p = h.addChild(nSeedBase + (unsigned int)(nHeight - EpochStartHeight()), p);
    return p;
}

size_t IndexOf(const std::vector<uint256>& v, const uint256& h)
{
    for (size_t i = 0; i < v.size(); i++)
        if (v[i] == h) return i;
    return (size_t)-1;
}

bool Contains(const std::vector<uint256>& v, const uint256& h)
{
    return IndexOf(v, h) != (size_t)-1;
}

uint256 ExpectedActiveTxSetHash(const CEpochState& s)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/IV5/ActiveDAGTransactionSet/v1");
    ss << s.hashBoundaryBlock << s.vBlockHashes;
    ss << s.vVNextActiveBlockTxCounts;
    ss << s.vVNextActiveTxIds;
    return ss.GetHash();
}

} // namespace

// 1. NULLIFIER / KEY-IMAGE CONFLICT ACROSS SIBLINGS.
//
// Two blocks at one height each carry a different spend of the same note. Both are in the
// epoch's DAG order; only one is on the chain ConnectBlock ran along. The epoch must take
// the connected one's key image and none of the merged one's -- and must take nothing at
// all from the second merged sibling, whose shield conflicts with nothing.
BOOST_AUTO_TEST_CASE(a_merged_sibling_contributes_no_transaction_to_the_iv5_active_set)
{
    EpochShapeHarness h;
    const RaceShape s = BuildRaceShape(h, 0xC0110000);

    CEpochState prev = PredecessorFor(s.pBefore);
    CCurveTree prevTree;
    CEpochState state;
    CCurveTree tree;
    std::string strError;
    pindexBest = s.pEnd;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(EpochUnderTest(),
                                                       EpochEndHeight() - EpochStartHeight() + 1,
                                                       s.pEnd, state, tree, strError,
                                                       &prev, &prevTree), strError);

    // Premise: both siblings really are in the epoch, or there is no conflict to resolve.
    BOOST_REQUIRE_MESSAGE(Contains(state.vBlockHashes, s.pSibling->GetBlockHash()),
                          "the competing sibling is not in the epoch's DAG order");
    BOOST_REQUIRE_MESSAGE(Contains(state.vBlockHashes, s.pSibShield->GetBlockHash()),
                          "the merged shield sibling is not in the epoch's DAG order");
    BOOST_REQUIRE_MESSAGE(Contains(state.vBlockHashes, s.pCanon->GetBlockHash()),
                          "the canonical sibling is not in the epoch's DAG order");

    // The active id list names exactly the transactions the canonical chain connected.
    BOOST_CHECK(Contains(state.vVNextActiveTxIds, s.hashShieldTx));
    BOOST_CHECK(Contains(state.vVNextActiveTxIds, s.hashSpendATx));
    BOOST_CHECK_MESSAGE(!Contains(state.vVNextActiveTxIds, s.hashSpendBTx),
                        "a merged sibling's spend reached the IV5 active set");
    BOOST_CHECK_MESSAGE(!Contains(state.vVNextActiveTxIds, s.hashSibShieldTx),
                        "a merged sibling's shield reached the IV5 active set");
    BOOST_CHECK_EQUAL(state.vVNextActiveTxIds.size(), 2U);

    // Per-block counts, which is what both replayers walk.
    BOOST_REQUIRE_EQUAL(state.vVNextActiveBlockTxCounts.size(), state.vBlockHashes.size());
    BOOST_CHECK_EQUAL(state.vVNextActiveBlockTxCounts[
                          IndexOf(state.vBlockHashes, s.pSibling->GetBlockHash())], 0U);
    BOOST_CHECK_EQUAL(state.vVNextActiveBlockTxCounts[
                          IndexOf(state.vBlockHashes, s.pSibShield->GetBlockHash())], 0U);
    BOOST_CHECK_EQUAL(state.vVNextActiveBlockTxCounts[
                          IndexOf(state.vBlockHashes, s.pCanon->GetBlockHash())], 1U);
    BOOST_CHECK_EQUAL(state.vVNextActiveBlockTxCounts[
                          IndexOf(state.vBlockHashes, s.pBase->GetBlockHash())], 1U);

    // The decisive count: one note was spent once.
    BOOST_REQUIRE_EQUAL(state.vVNextEpochNullifiers.size(), 1U);
    BOOST_CHECK(state.vVNextEpochNullifiers[0] == Payloads().keyImage);
    BOOST_CHECK_EQUAL(state.nVNextNullifierCount, 1U);

    // Two leaves: the shield the chain connected and the surviving spend's output. The
    // merged shield's leaf is the third one that must not be there.
    BOOST_CHECK_EQUAL(state.nVNextTreeSize, 2U);
}

// 2. Epoch digest determinism: the whole commitment is a function of the anchor, and the
// active-transaction digest commits its inputs in one order.
BOOST_AUTO_TEST_CASE(the_epoch_digest_over_privacy_payloads_is_a_function_of_its_anchor)
{
    EpochShapeHarness h;
    const RaceShape s = BuildRaceShape(h, 0xD1220000);

    CEpochState prev = PredecessorFor(s.pBefore);
    CCurveTree prevTree;
    std::string strError;

    CEpochState first;
    CCurveTree firstTree;
    pindexBest = s.pEnd;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(EpochUnderTest(),
                                                       EpochEndHeight() - EpochStartHeight() + 1,
                                                       s.pEnd, first, firstTree, strError,
                                                       &prev, &prevTree), strError);

    // Premise: this epoch actually carries privacy state, or determinism over it is vacuous.
    BOOST_REQUIRE_MESSAGE(first.nVNextTreeSize > 0 && !first.vVNextEpochNullifiers.empty(),
                          "the epoch under test committed no IV5 state");

    // The digest commits its inputs in a fixed order. Recomputed here rather than compared
    // to itself, so swapping two fields in the hasher changes one side and not the other.
    BOOST_CHECK_MESSAGE(first.hashVNextActiveTxSet == ExpectedActiveTxSetHash(first),
                        "the active-transaction digest does not commit boundary, blocks, "
                        "counts and ids in that order");

    // A competing branch, and a run above the boundary, both arrive afterwards. Neither is
    // reachable from the anchor, so neither may move a single field.
    CBlockIndex* pFork = h.addChild(0xD1330000, s.pBase);
    for (int i = 0; i < 6; i++)
        pFork = h.addChild(0xD1330001 + (unsigned int)i, pFork);
    CBlockIndex* pAfter = h.addChild(0xD1340000, s.pEnd);
    pAfter = h.addChild(0xD1340001, pAfter);
    pindexBest = pFork;

    CEpochState second;
    CCurveTree secondTree;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(EpochUnderTest(),
                                                       EpochEndHeight() - EpochStartHeight() + 1,
                                                       s.pEnd, second, secondTree, strError,
                                                       &prev, &prevTree), strError);

    BOOST_CHECK_EQUAL(first.GetDigest().GetHex(), second.GetDigest().GetHex());
    BOOST_CHECK(!Contains(second.vBlockHashes, pFork->GetBlockHash()));
    BOOST_CHECK(!Contains(second.vBlockHashes, pAfter->GetBlockHash()));
    BOOST_CHECK(first.vVNextActiveTxIds == second.vVNextActiveTxIds);
    BOOST_CHECK(first.vVNextActiveBlockTxCounts == second.vVNextActiveBlockTxCounts);
    BOOST_CHECK(first.hashVNextActiveTxSet == second.hashVNextActiveTxSet);
    BOOST_CHECK(first.vchVNextRoot == second.vchVNextRoot);
    BOOST_CHECK_EQUAL(first.nVNextTreeSize, second.nVNextTreeSize);
    BOOST_CHECK(first.hashVNextNullifierRoot == second.hashVNextNullifierRoot);
    BOOST_CHECK_EQUAL(first.nVNextPoolBalance, second.nVNextPoolBalance);

    // And the serialized form round-trips to the same digest, which is what a restart reads.
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << first;
    CEpochState restarted;
    ss >> restarted;
    BOOST_CHECK_EQUAL(first.GetDigest().GetHex(), restarted.GetDigest().GetHex());
    BOOST_CHECK(restarted.vVNextActiveTxIds == first.vVNextActiveTxIds);
}

// 3. Reorg across a v2008 block: the winning epoch holds nothing of the loser and is
// byte-identical before and after the loser disconnects.
BOOST_AUTO_TEST_CASE(an_epoch_rebuilt_over_the_winning_chain_keeps_none_of_the_payload)
{
    EpochShapeHarness h;
    const RaceShape s = BuildRaceShape(h, 0xE2440000);
    CBlockIndex* pPlainEnd = BuildPlainChain(h, s.pBefore, 0xE2550000);

    CEpochState prev = PredecessorFor(s.pBefore);
    CCurveTree prevTree;
    std::string strError;
    const int nInterval = EpochEndHeight() - EpochStartHeight() + 1;

    CEpochState loser;
    CCurveTree loserTree;
    pindexBest = s.pEnd;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(EpochUnderTest(), nInterval, s.pEnd,
                                                       loser, loserTree, strError, &prev,
                                                       &prevTree), strError);

    // Derived while the losing chain is still present, and with the node-local best tip
    // deliberately pointed at it.
    CEpochState winnerBefore;
    CCurveTree winnerBeforeTree;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(EpochUnderTest(), nInterval, pPlainEnd,
                                                       winnerBefore, winnerBeforeTree,
                                                       strError, &prev, &prevTree), strError);

    // Anti-vacuity: the two chains really did close this epoch differently.
    BOOST_REQUIRE_MESSAGE(loser.GetDigest() != winnerBefore.GetDigest(),
                          "both chains closed the epoch on the same state; nothing was undone");
    BOOST_REQUIRE_MESSAGE(loser.nVNextTreeSize > winnerBefore.nVNextTreeSize,
                          "the losing chain committed no leaf the winner has to drop");
    BOOST_CHECK_EQUAL(winnerBefore.nVNextTreeSize, 0U);
    BOOST_CHECK(winnerBefore.vVNextActiveTxIds.empty());
    BOOST_CHECK(winnerBefore.vVNextEpochNullifiers.empty());
    BOOST_CHECK_EQUAL(winnerBefore.nVNextPoolBalance, 0);

    // Now disconnect the losing chain, the way a reorg leaves the DAG, and derive again.
    std::vector<uint256> vLosing;
    for (const CBlockIndex* p = s.pEnd; p && p->nHeight >= EpochStartHeight(); p = p->pprev)
        vLosing.push_back(p->GetBlockHash());
    vLosing.push_back(s.pSibling->GetBlockHash());
    vLosing.push_back(s.pSibShield->GetBlockHash());
    pindexBest = pPlainEnd;
    for (size_t i = 0; i < vLosing.size(); i++)
        h.remove(vLosing[i]);

    CEpochState winnerAfter;
    CCurveTree winnerAfterTree;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(EpochUnderTest(), nInterval, pPlainEnd,
                                                       winnerAfter, winnerAfterTree,
                                                       strError, &prev, &prevTree), strError);
    BOOST_CHECK_EQUAL(winnerBefore.GetDigest().GetHex(), winnerAfter.GetDigest().GetHex());
    BOOST_CHECK(winnerAfter.vVNextActiveTxIds.empty());
    BOOST_CHECK_EQUAL(winnerAfter.nVNextTreeSize, 0U);
    BOOST_CHECK(winnerAfter.vchVNextRoot == winnerBefore.vchVNextRoot);
}

// 4. Out-of-order arrival: blocks received after the boundary do not change its epoch.
BOOST_AUTO_TEST_CASE(late_arriving_blocks_cannot_move_the_epoch_the_boundary_names)
{
    EpochShapeHarness h;
    const RaceShape s = BuildRaceShape(h, 0xF3660000);

    CEpochState prev = PredecessorFor(s.pBefore);
    CCurveTree prevTree;
    std::string strError;
    const int nInterval = EpochEndHeight() - EpochStartHeight() + 1;

    CEpochState atBoundary;
    CCurveTree atBoundaryTree;
    pindexBest = s.pEnd;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(EpochUnderTest(), nInterval, s.pEnd,
                                                       atBoundary, atBoundaryTree, strError,
                                                       &prev, &prevTree), strError);
    BOOST_REQUIRE_MESSAGE(atBoundary.nVNextTreeSize > 0,
                          "the epoch under test committed no IV5 state");

    // A sibling of an in-epoch block, arriving now, carrying a payload of its own. It is
    // inside the epoch's height range and it is not reachable from the anchor.
    std::vector<CTransaction> vLate(1, IV5Tx(Payloads().vchShieldTwo));
    CBlockIndex* pLateSibling = h.addChild(0xF3770000, s.pBase, &vLate);
    BOOST_REQUIRE(pLateSibling->nHeight >= EpochStartHeight() &&
                  pLateSibling->nHeight <= EpochEndHeight());

    // A competing branch, then a longer run above the boundary, then the node-local best
    // tip moved onto them.
    CBlockIndex* pFork = pLateSibling;
    for (int i = 0; i < 8; i++)
        pFork = h.addChild(0xF3780000 + (unsigned int)i, pFork);
    CBlockIndex* pAbove = s.pEnd;
    for (int i = 0; i < 8; i++)
        pAbove = h.addChild(0xF3790000 + (unsigned int)i, pAbove);
    pindexBest = pAbove;

    CEpochState afterArrivals;
    CCurveTree afterArrivalsTree;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(EpochUnderTest(), nInterval, s.pEnd,
                                                       afterArrivals, afterArrivalsTree,
                                                       strError, &prev, &prevTree), strError);

    BOOST_CHECK_EQUAL(atBoundary.GetDigest().GetHex(), afterArrivals.GetDigest().GetHex());
    BOOST_CHECK(atBoundary.vBlockHashes == afterArrivals.vBlockHashes);
    BOOST_CHECK(atBoundary.vVNextActiveTxIds == afterArrivals.vVNextActiveTxIds);
    BOOST_CHECK(atBoundary.vVNextActiveBlockTxCounts ==
                afterArrivals.vVNextActiveBlockTxCounts);
    BOOST_CHECK(atBoundary.vchVNextRoot == afterArrivals.vchVNextRoot);
    BOOST_CHECK_EQUAL(atBoundary.nVNextTreeSize, afterArrivals.nVNextTreeSize);
    BOOST_CHECK(atBoundary.hashVNextNullifierRoot == afterArrivals.hashVNextNullifierRoot);

    // The late sibling's payload is the specific thing that must not have been absorbed.
    BOOST_CHECK_MESSAGE(!Contains(afterArrivals.vVNextActiveTxIds, vLate[0].GetHash()),
                        "a block that arrived after the boundary reached the epoch's tree");
    BOOST_CHECK(!Contains(afterArrivals.vBlockHashes, pLateSibling->GetBlockHash()));
    BOOST_CHECK(!Contains(afterArrivals.vBlockHashes, pFork->GetBlockHash()));
    BOOST_CHECK(!Contains(afterArrivals.vBlockHashes, pAbove->GetBlockHash()));
}

BOOST_AUTO_TEST_SUITE_END()
