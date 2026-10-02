// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Post-DAG rules in CBlock::AcceptBlock and the two DAG parent decoders, driven through
// AcceptBlock over a synthetic post-DAG index, asserting the accumulated DoS score.

#include <boost/test/unit_test.hpp>

#include "../dag.h"
#include "../finality.h"
#include "../main.h"
#include "../mstimestamp.h"

#include <string>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(idag_rule_coverage_tests)

namespace {

// Synthetic chain on the regtest genesis index with only the fields AcceptBlock reads.
// The destructor removes every inserted index from mapBlockIndex.
struct PostDagChain
{
    std::vector<uint256>      vHashes;
    std::vector<CBlockIndex*> vIndex;
    bool         fOldRegTest;
    bool         fOldTestNet;
    CBlockIndex* pOldBest;
    int64_t      nBaseTime;

    explicit PostDagChain(int nTop) : nBaseTime(1750000000)
    {
        // Before any global moves: a throw here would skip the destructor that
        // puts them back.
        BOOST_REQUIRE(pindexGenesisBlock != NULL);

        fOldRegTest = fRegTest;
        fOldTestNet = fTestNet;
        pOldBest = pindexBest;
        fRegTest = true;
        fTestNet = false;
        // AcceptBlock reads pindexBest only through the checkpoint helpers; a
        // null tip puts them on the genesis path, which every chain built here
        // descends from.
        pindexBest = NULL;

        for (int nHeight = 1; nHeight <= nTop; nHeight++)
            Add(nHeight, nHeight == 1 ? pindexGenesisBlock : vIndex.back(), false);
    }

    ~PostDagChain()
    {
        for (size_t i = vHashes.size(); i-- > 0; )
        {
            mapBlockIndex.erase(vHashes[i]);
            delete vIndex[i];
        }
        pindexBest = pOldBest;
        fRegTest = fOldRegTest;
        fTestNet = fOldTestNet;
    }

    // A side vertex: same shape, an explicit parent, not appended to the trunk.
    uint256 AddSide(int nHeight, CBlockIndex* pprev, bool fProofOfStake)
    {
        const size_t nBefore = vHashes.size();
        Add(nHeight, pprev, fProofOfStake);
        return vHashes[nBefore];
    }

    CBlockIndex* Tip() const { return vIndex.back(); }
    const uint256& TipHash() const { return vHashes.back(); }

    CBlockIndex* At(int nHeight) const
    {
        for (size_t i = 0; i < vIndex.size(); i++)
            if (vIndex[i]->nHeight == nHeight)
                return vIndex[i];
        return NULL;
    }

private:
    void Add(int nHeight, CBlockIndex* pprev, bool fProofOfStake)
    {
        CBlock header;
        header.nVersion = CBlock::CURRENT_VERSION;
        header.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
        header.nTime = (unsigned int)(nBaseTime + nHeight);
        header.nBits = bnProofOfWorkLimit.GetCompact();
        header.nNonce = (unsigned int)(vHashes.size() + 1);
        header.hashMerkleRoot = uint256((unsigned int)(vHashes.size() + 1));

        const uint256 hash = header.GetHash();
        CBlockIndex* pindex = new CBlockIndex(0, 0, header);
        pindex->nHeight = nHeight;
        pindex->pprev = pprev;
        if (fProofOfStake)
            pindex->SetProofOfStake();
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(hash, pindex));
        BOOST_REQUIRE(ins.second);
        pindex->phashBlock = &ins.first->first;

        vHashes.push_back(hash);
        vIndex.push_back(pindex);
    }
};

// A candidate block on top of pindexPrev. vParents becomes the coinbase IDAG
// commitment; an empty vector leaves the block without one.
CBlock CandidateBlock(const CBlockIndex* pindexPrev,
                      const std::vector<uint256>& vParents,
                      bool fProofOfStake = false)
{
    const int nHeight = pindexPrev->nHeight + 1;

    CTransaction coinbase;
    coinbase.nTime = (unsigned int)(pindexPrev->GetBlockTime() + 1);
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << nHeight;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = 0;
    if (!vParents.empty())
        coinbase.vout[0].scriptPubKey = BuildDAGParentScript(vParents);
    // From FORK_HEIGHT_MS_TIMESTAMP a coinbase must also carry a millisecond
    // commitment, and AcceptBlock checks it ahead of the parent set. The
    // candidate carries a valid one so a rejection here is the parent rule's.
    if (nHeight >= FORK_HEIGHT_MS_TIMESTAMP)
    {
        CTxOut msOut;
        msOut.nValue = 0;
        msOut.scriptPubKey = BuildMsTimestampScript(0);
        coinbase.vout.push_back(msOut);
    }

    CBlock block;
    block.nVersion = CBlock::CURRENT_VERSION;
    block.hashPrevBlock = pindexPrev->GetBlockHash();
    block.nTime = (unsigned int)(pindexPrev->GetBlockTime() + 1);
    block.nNonce = 12345;
    block.vtx.push_back(coinbase);

    if (fProofOfStake)
    {
        CTransaction coinstake;
        coinstake.nTime = coinbase.nTime;
        coinstake.vin.resize(1);
        coinstake.vin[0].prevout = COutPoint(uint256(517), 0);
        coinstake.vout.resize(2);
        coinstake.vout[0].nValue = 0;              // empty: the coinstake marker
        coinstake.vout[1].nValue = 1;
        coinstake.vout[1].scriptPubKey = CScript() << OP_TRUE;
        block.vtx.push_back(coinstake);
        BOOST_REQUIRE(block.IsProofOfStake());
    }

    block.nBits = GetNextTargetRequired(pindexPrev, fProofOfStake);
    block.hashMerkleRoot = block.BuildMerkleTree();
    block.nDoS = 0;
    return block;
}

// A raw IDAG payload with a declared parent count, so a count the builder
// refuses to encode can still be presented to the decoders.
CScript RawParentScript(unsigned int nCount)
{
    std::vector<unsigned char> vchData(DAG_PARENT_TAG, DAG_PARENT_TAG + 4);
    vchData.push_back((unsigned char)nCount);
    for (unsigned int i = 1; i <= nCount; i++)
    {
        uint256 hash(i);
        vchData.insert(vchData.end(), hash.begin(), hash.end());
    }
    CScript script;
    script << OP_RETURN << vchData;
    return script;
}

} // namespace

// Below POEM the inverse-target work, at or above it the entropy weight (hashProof
// for pre-DAG stake, else block hash); a post-DAG stake index contributes nothing.
BOOST_AUTO_TEST_CASE(post_poem_chain_trust_is_entropy_and_not_inverse_target)
{
    const bool fOldRegTest = fRegTest;
    const bool fOldTestNet = fTestNet;
    fRegTest = true;
    fTestNet = false;

    CBlock header;
    header.nVersion = CBlock::CURRENT_VERSION;
    header.nTime = 1750000000;
    header.nBits = bnProofOfWorkLimit.GetCompact();
    header.nNonce = 9;
    header.hashMerkleRoot = uint256(7);
    const uint256 hash = header.GetHash();

    CBigNum bnTarget;
    bnTarget.SetCompact(header.nBits);
    const uint256 inverseTarget = ((CBigNum(1) << 256) / (bnTarget + 1)).getuint256();

    CBlockIndex index(0, 0, header);
    index.phashBlock = &hash;

    index.nHeight = FORK_HEIGHT_POEM - 1;
    BOOST_CHECK(index.GetBlockTrust() == inverseTarget);

    index.nHeight = FORK_HEIGHT_POEM;
    BOOST_CHECK(index.GetBlockTrust() == GetBlockEntropy(hash));
    BOOST_CHECK(index.GetBlockTrust() != inverseTarget);

    // A stake block below the DAG height weighs its hashProof, not its hash.
    BOOST_REQUIRE(FORK_HEIGHT_POEM < FORK_HEIGHT_DAG);
    index.SetProofOfStake();
    index.hashProof = uint256(0xf00dfaceULL);
    BOOST_CHECK(index.GetBlockTrust() == GetBlockEntropy(index.hashProof));
    BOOST_CHECK(index.GetBlockTrust() != GetBlockEntropy(hash));

    // At or above the DAG height a stake index carries no weight at all, so a
    // case that measured one there would be measuring the wrong regime.
    index.nHeight = FORK_HEIGHT_DAG;
    BOOST_CHECK(index.GetBlockTrust() == 0);

    fRegTest = fOldRegTest;
    fTestNet = fOldTestNet;
}

// Both decoders refuse more than MAX_DAG_PARENTS parents; in the permissive
// decoder the count check is the only enforcement.
BOOST_AUTO_TEST_CASE(a_parent_count_over_the_bound_is_refused_by_both_decoders)
{
    BOOST_CHECK_EQUAL(MAX_DAG_PARENTS, 32);

    std::vector<uint256> vAtBound;
    for (int i = 1; i <= MAX_DAG_PARENTS; i++)
        vAtBound.push_back(uint256(i));
    std::vector<uint256> vDecoded;
    std::string strError;
    BOOST_CHECK_EQUAL(DecodeCanonicalDAGParentScript(
                          BuildDAGParentScript(vAtBound), vDecoded, strError),
                      DAG_PARENT_VALID);
    BOOST_CHECK(vDecoded.size() == (size_t)MAX_DAG_PARENTS);

    const CScript overBound = RawParentScript(MAX_DAG_PARENTS + 1);
    BOOST_CHECK_EQUAL(DecodeCanonicalDAGParentScript(overBound, vDecoded, strError),
                      DAG_PARENT_MALFORMED);
    BOOST_CHECK(vDecoded.empty());
    BOOST_CHECK(ExtractDAGParents(overBound).empty());

    // 255 is what the one-byte count can state; the bound is what is enforced.
    BOOST_CHECK(ExtractDAGParents(RawParentScript(255)).empty());
}

// Both decoders must admit exactly what the encoder produces, up to MAX_DAG_PARENTS;
// AddToBlockIndex reads every post-DAG block with the permissive decoder.
BOOST_AUTO_TEST_CASE(the_permissive_decoder_reaches_the_declared_bound)
{
    const size_t nElementCeiling = (MAX_SCRIPT_ELEMENT_SIZE - 5) / 32;
    BOOST_CHECK_EQUAL(nElementCeiling, (size_t)16);
    BOOST_CHECK(nElementCeiling < (size_t)MAX_DAG_PARENTS);

    std::vector<uint256> vParents;
    for (int n = 1; n <= MAX_DAG_PARENTS; n++)
    {
        vParents.push_back(uint256(n));
        const CScript script = BuildDAGParentScript(vParents);
        BOOST_REQUIRE(script.size() > 0);

        std::vector<uint256> vCanonical;
        std::string strError;
        BOOST_CHECK_EQUAL(DecodeCanonicalDAGParentScript(script, vCanonical, strError),
                          DAG_PARENT_VALID);
        BOOST_CHECK(vCanonical.size() == (size_t)n);

        const std::vector<uint256> vPermissive = ExtractDAGParents(script);
        BOOST_CHECK_MESSAGE(vPermissive.size() == (size_t)n,
                            "the permissive decoder read " << vPermissive.size()
                                << " of " << n << " committed parents");
        BOOST_CHECK_MESSAGE(vPermissive == vCanonical,
                            "the decoders disagree at " << n << " parents");
    }
}

// At or above the DAG height the limit is the adaptive one from the parent,
// flooring at ADAPTIVE_BLOCK_FLOOR, far below ADAPTIVE_BLOCK_CEILING.
BOOST_AUTO_TEST_CASE(post_dag_block_size_limit_is_the_adaptive_limit)
{
    PostDagChain chain(FORK_HEIGHT_DAG + 20);

    const CBlockIndex* pPreDag = chain.At(FORK_HEIGHT_DAG - 1);
    BOOST_REQUIRE(pPreDag != NULL);
    BOOST_CHECK_EQUAL(GetAdaptiveBlockSizeLimit(pPreDag), MAX_BLOCK_SIZE_LEGACY);

    const unsigned int nLimit = GetAdaptiveBlockSizeLimit(chain.Tip());
    BOOST_CHECK_EQUAL(nLimit, ADAPTIVE_BLOCK_FLOOR * 2);
    BOOST_CHECK(nLimit != MAX_BLOCK_SIZE_LEGACY);
    BOOST_CHECK(nLimit != ADAPTIVE_BLOCK_CEILING);

    // AcceptBlock has to read that limit rather than a constant. The oversize
    // block also carries no parent commitment, so if the size check stops
    // rejecting it the next rule does, at a different score.
    LOCK(cs_main);
    CBlock block = CandidateBlock(chain.Tip(), std::vector<uint256>());
    block.vtx[0].vout.resize(2);
    block.vtx[0].vout[1].nValue = 0;
    block.vtx[0].vout[1].scriptPubKey = CScript() << OP_RETURN
        << std::vector<unsigned char>(nLimit, 0x5a);
    block.hashMerkleRoot = block.BuildMerkleTree();
    BOOST_REQUIRE(::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION) > nLimit);

    BOOST_CHECK(!block.AcceptBlock());
    BOOST_CHECK_MESSAGE(block.nDoS == 50,
                        "an oversize post-DAG block scored " << block.nDoS
                            << ", so the adaptive size check is not what "
                               "rejected it");
}

// A stake block is invalid from the DAG height up. Its nBits are the
// stake target, so the rule under test is the only thing wrong with it.
BOOST_AUTO_TEST_CASE(a_post_dag_proof_of_stake_block_is_refused)
{
    PostDagChain chain(FORK_HEIGHT_DAG + 20);
    LOCK(cs_main);

    std::vector<uint256> vParents(1, chain.TipHash());
    CBlock block = CandidateBlock(chain.Tip(), vParents, true);
    BOOST_REQUIRE(block.IsProofOfStake());
    BOOST_REQUIRE(chain.Tip()->nHeight + 1 >= FORK_HEIGHT_DAG);

    BOOST_CHECK(!block.AcceptBlock());
    BOOST_CHECK_MESSAGE(block.nDoS == 100,
                        "a post-DAG proof-of-stake block scored " << block.nDoS
                            << " instead of being refused for its type");
}

// A post-DAG block must carry a parent commitment, and its first
// entry must be the block's own predecessor.
BOOST_AUTO_TEST_CASE(a_post_dag_block_commits_its_predecessor_first)
{
    PostDagChain chain(FORK_HEIGHT_DAG + 20);
    LOCK(cs_main);

    CBlock missing = CandidateBlock(chain.Tip(), std::vector<uint256>());
    BOOST_CHECK(!missing.AcceptBlock());
    BOOST_CHECK_MESSAGE(missing.nDoS == 100,
                        "a post-DAG block with no parent commitment scored "
                            << missing.nDoS);

    // A commitment naming a real, in-index block that is not the predecessor.
    CBlockIndex* pOther = chain.At(chain.Tip()->nHeight - 1);
    BOOST_REQUIRE(pOther != NULL);
    std::vector<uint256> vWrong(1, pOther->GetBlockHash());
    CBlock wrong = CandidateBlock(chain.Tip(), vWrong);
    BOOST_CHECK(!wrong.AcceptBlock());
    BOOST_CHECK_MESSAGE(wrong.nDoS == 100,
                        "a post-DAG block whose first committed parent is not "
                           "its predecessor scored " << wrong.nDoS);
}

// Merge parents must be lower, not post-DAG stake, within DAG_MERGE_DEPTH and
// unique. Depth scores 50 and the rest 100, so the score names the leg.
BOOST_AUTO_TEST_CASE(merge_parents_must_be_lower_recent_and_distinct)
{
    PostDagChain chain(FORK_HEIGHT_DAG + 2 * DAG_MERGE_DEPTH);
    LOCK(cs_main);
    CBlockIndex* pTip = chain.Tip();
    const int nHeight = pTip->nHeight + 1;

    const uint256 hashAbove = chain.AddSide(nHeight + 5, pTip, false);
    const uint256 hashStake = chain.AddSide(pTip->nHeight - 1, pTip->pprev, true);
    CBlockIndex* pDeep = chain.At(FORK_HEIGHT_DAG);
    BOOST_REQUIRE(pDeep != NULL);
    BOOST_REQUIRE(pTip->nHeight - pDeep->nHeight > DAG_MERGE_DEPTH);
    CBlockIndex* pNear = chain.At(pTip->nHeight - 1);
    BOOST_REQUIRE(pNear != NULL);

    std::vector<uint256> vAbove;
    vAbove.push_back(pTip->GetBlockHash());
    vAbove.push_back(hashAbove);
    CBlock above = CandidateBlock(pTip, vAbove);
    BOOST_CHECK(!above.AcceptBlock());
    BOOST_CHECK_MESSAGE(above.nDoS == 100,
                        "a merge parent at or above the block's height scored "
                            << above.nDoS);

    std::vector<uint256> vStake;
    vStake.push_back(pTip->GetBlockHash());
    vStake.push_back(hashStake);
    CBlock stake = CandidateBlock(pTip, vStake);
    BOOST_CHECK(!stake.AcceptBlock());
    BOOST_CHECK_MESSAGE(stake.nDoS == 100,
                        "a post-DAG proof-of-stake merge parent scored "
                            << stake.nDoS);

    std::vector<uint256> vDeep;
    vDeep.push_back(pTip->GetBlockHash());
    vDeep.push_back(pDeep->GetBlockHash());
    CBlock deep = CandidateBlock(pTip, vDeep);
    BOOST_CHECK(!deep.AcceptBlock());
    BOOST_CHECK_MESSAGE(deep.nDoS == 50,
                        "a merge parent beyond DAG_MERGE_DEPTH scored "
                            << deep.nDoS << ", not the depth rule's 50");

    std::vector<uint256> vRepeat;
    vRepeat.push_back(pTip->GetBlockHash());
    vRepeat.push_back(pNear->GetBlockHash());
    vRepeat.push_back(pNear->GetBlockHash());
    CBlock repeat = CandidateBlock(pTip, vRepeat);
    BOOST_CHECK(!repeat.AcceptBlock());
    BOOST_CHECK_MESSAGE(repeat.nDoS == 100,
                        "a repeated merge parent scored " << repeat.nDoS);
}

// A committed merge parent that has not arrived defers the child. It
// is the one rejection in the parent loop that must not score the peer, so the
// assertion is on the score staying at zero rather than on the false return.
BOOST_AUTO_TEST_CASE(an_unavailable_merge_parent_defers_without_scoring)
{
    PostDagChain chain(FORK_HEIGHT_DAG + 20);
    LOCK(cs_main);

    const uint256 hashAbsent(0xabce77ULL);
    BOOST_REQUIRE(!mapBlockIndex.count(hashAbsent));

    std::vector<uint256> vParents;
    vParents.push_back(chain.TipHash());
    vParents.push_back(hashAbsent);
    CBlock block = CandidateBlock(chain.Tip(), vParents);

    BOOST_CHECK(!block.AcceptBlock());
    BOOST_CHECK_MESSAGE(block.nDoS == 0,
                        "an unavailable merge parent scored " << block.nDoS
                            << "; a parent still in flight is normal, and "
                               "scoring it makes every deferring peer look "
                               "like a misbehaving one");
}

// From Boundary A the parent set must also have a DAGKnight selected parent and a
// resolvable merge history.
BOOST_AUTO_TEST_CASE(a_committed_parent_set_must_satisfy_dagknight_selection)
{
    PostDagChain chain(FORK_HEIGHT_DAG + 20);
    const int nAnchorHeight = chain.Tip()->nHeight + 1;
    std::string strError;

    BOOST_CHECK(!g_dagManager.CheckDAGKnightParentSet(
        std::vector<uint256>(), nAnchorHeight, strError));

    std::vector<uint256> vPrimaryOnly(1, chain.TipHash());
    BOOST_CHECK(g_dagManager.CheckDAGKnightParentSet(
        vPrimaryOnly, nAnchorHeight, strError));

    std::vector<uint256> vUnresolvable;
    vUnresolvable.push_back(chain.TipHash());
    vUnresolvable.push_back(uint256(0xdeadbeefULL));
    BOOST_CHECK_MESSAGE(!g_dagManager.CheckDAGKnightParentSet(
                            vUnresolvable, nAnchorHeight, strError),
                        "a parent set naming merge history this node does not "
                        "hold was collected anyway");
}

BOOST_AUTO_TEST_SUITE_END()
