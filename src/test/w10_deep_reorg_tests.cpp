#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../txdb.h"

namespace {

class W10TestTxDB : public CTxDB
{
public:
    using CTxDB::Read;
};

class W10Chain
{
    std::vector<uint256> hashes;
    unsigned int nonce = 0;

public:
    ~W10Chain()
    {
        for (size_t i = 0; i < hashes.size(); ++i)
        {
            delete mapBlockIndex[hashes[i]];
            mapBlockIndex.erase(hashes[i]);
        }
    }

    CBlockIndex* Add(CBlockIndex* prev, int height)
    {
        CBlock block;
        block.hashPrevBlock = prev ? prev->GetBlockHash() : 0;
        block.hashMerkleRoot = uint256(0xB5100000U);
        block.nNonce = ++nonce;
        block.nTime = 1;
        block.nBits = 0x207fffff;
        const uint256 hash = block.GetHash();
        BOOST_REQUIRE(mapBlockIndex.count(hash) == 0);
        CBlockIndex* index = new CBlockIndex(0, 0, block);
        index->pprev = prev;
        index->nHeight = height;
        mapBlockIndex[hash] = index;
        index->phashBlock = &mapBlockIndex.find(hash)->first;
        index->BuildSkip();
        hashes.push_back(hash);
        return index;
    }

    CBlockIndex* Extend(CBlockIndex* prev, int count)
    {
        for (int i = 0; i < count; ++i)
            prev = Add(prev, prev ? prev->nHeight + 1 : 0);
        return prev;
    }

    CBlockIndex* Linear(int height) { return Extend(Add(NULL, 0), height); }
};

struct W10Fixture
{
    bool oldRegTest = fRegTest;
    bool oldTestNet = fTestNet;
    bool oldImporting = fImporting;
    bool oldReindex = fReindex;
    int oldBestHeight = nBestHeight;
    int oldHeaderHeight = nBestHeaderHeight;
    CBlockIndex* oldBest = pindexBest;
    bool hadMaxDepth = mapArgs.count("-maxreorgdepth") != 0;
    std::string oldMaxDepth = hadMaxDepth ? mapArgs["-maxreorgdepth"] : "";
    W10Chain chain;
    std::vector<uint256> persisted;

    W10Fixture()
    {
        fRegTest = true;
        fTestNet = false;
        fImporting = false;
        fReindex = false;
        nBestHeaderHeight = -1;
        mapArgs.erase("-maxreorgdepth");
    }

    ~W10Fixture()
    {
        CTxDB txdb;
        for (size_t i = 0; i < persisted.size(); ++i)
            txdb.EraseBlockIndex(persisted[i]);
        pindexBest = oldBest;
        nBestHeight = oldBestHeight;
        nBestHeaderHeight = oldHeaderHeight;
        fRegTest = oldRegTest;
        fTestNet = oldTestNet;
        fImporting = oldImporting;
        fReindex = oldReindex;
        if (hadMaxDepth)
            mapArgs["-maxreorgdepth"] = oldMaxDepth;
        else
            mapArgs.erase("-maxreorgdepth");
    }

    CBlockIndex* Tip(int nHeight)
    {
        CBlockIndex* p = chain.Linear(nHeight);
        BOOST_REQUIRE(p);
        pindexBest = p;
        nBestHeight = nHeight;
        return p;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(w10_deep_reorg_tests, W10Fixture)

BOOST_AUTO_TEST_CASE(option_is_local_and_has_no_activation_height)
{
    LOCK(cs_main);
    BOOST_CHECK_EQUAL(GetMaxReorgDepth(), 1440);
    CBlockIndex* fork = chain.Add(NULL, FORK_HEIGHT_DAG);
    CBlockIndex* tip = chain.Extend(fork, MAX_REORG_DEPTH + 1);
    CBlockIndex* candidate = chain.Extend(fork, MAX_REORG_DEPTH + 2);
    BOOST_REQUIRE(tip && candidate);
    pindexBest = tip;
    nBestHeight = tip->nHeight;
    BOOST_CHECK(!AllowReorgByDepthPolicy(tip, candidate));
    mapArgs["-maxreorgdepth"] = "0";
    BOOST_CHECK_EQUAL(GetMaxReorgDepth(), 0);
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, candidate));
    fRegTest = false;
    BOOST_CHECK_EQUAL(GetMaxReorgDepth(), 0);
    fTestNet = true;
    BOOST_CHECK_EQUAL(GetMaxReorgDepth(), 0);
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, candidate));
}

BOOST_AUTO_TEST_CASE(refusal_preserves_validity_and_stored_indexes)
{
    LOCK(cs_main);
    CBlockIndex* tip = Tip(FORK_HEIGHT_DAG + MAX_REORG_DEPTH + 1);
    CBlockIndex* fork = tip->GetAncestor(FORK_HEIGHT_DAG);
    CBlockIndex* candidate = chain.Extend(fork, MAX_REORG_DEPTH + 2);
    BOOST_REQUIRE(candidate);
    CBlockIndex* root = candidate->GetAncestor(fork->nHeight + 1);
    CBlockIndex* sibling = chain.Extend(root, 2);
    BOOST_REQUIRE(sibling);
    const unsigned int flags = candidate->nFlags;
    const uint256 invalidTrust = nBestInvalidTrust;
    CTxDB txdb;
    BOOST_REQUIRE(txdb.WriteBlockIndex(CDiskBlockIndex(candidate)));
    persisted.push_back(candidate->GetBlockHash());

    CBlock block;
    bool permanent = true, policy = false;
    CBlockFailReason reason;
    BOOST_CHECK(!block.SetBestChain(txdb, candidate, &permanent, &reason, &policy));
    BOOST_CHECK(!permanent);
    BOOST_CHECK(policy);
    BOOST_CHECK(pindexBest == tip);
    BOOST_CHECK(nBestInvalidTrust == invalidTrust);
    BOOST_CHECK(mapBlockIndex.count(candidate->GetBlockHash()) == 1);
    BOOST_CHECK(!root->IsInvalid());
    BOOST_CHECK(!candidate->IsInvalid());
    BOOST_CHECK(!sibling->IsInvalid());
    BOOST_CHECK_EQUAL(candidate->nFlags, flags);
    BOOST_CHECK(!txdb.ReadBlockFailReason(root->GetBlockHash(), reason));
    BOOST_CHECK(!txdb.ReadBlockFailReason(candidate->GetBlockHash(), reason));

    W10TestTxDB reopened;
    CDiskBlockIndex disk;
    BOOST_REQUIRE(reopened.Read(std::make_pair(std::string("blockindex"), candidate->GetBlockHash()), disk));
    BOOST_CHECK(disk.GetBlockHash() == candidate->GetBlockHash());
    BOOST_CHECK_EQUAL(disk.nFlags, flags);
    BOOST_CHECK(!disk.IsInvalid());
    BOOST_CHECK(!AllowReorgByDepthPolicy(tip, candidate));

    // A later tip or a disabled limit immediately permits another attempt.
    BOOST_CHECK(AllowReorgByDepthPolicy(tip->pprev, candidate));
    mapArgs["-maxreorgdepth"] = "0";
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, candidate));
}

BOOST_AUTO_TEST_CASE(shallow_exact_limit_and_custom_limit)
{
    LOCK(cs_main);
    CBlockIndex* tip = Tip(FORK_HEIGHT_DAG + MAX_REORG_DEPTH + 10);
    const int depths[] = {1, MAX_REORG_DEPTH};
    for (size_t i = 0; i < sizeof(depths) / sizeof(depths[0]); ++i)
    {
        CBlockIndex* fork = tip->GetAncestor(tip->nHeight - depths[i]);
        CBlockIndex* candidate = chain.Extend(fork, depths[i] + 1);
        BOOST_REQUIRE(candidate);
        BOOST_CHECK(AllowReorgByDepthPolicy(tip, candidate));
    }
    CBlockIndex* fork = tip->GetAncestor(tip->nHeight - 3);
    CBlockIndex* candidate = chain.Extend(fork, 4);
    BOOST_REQUIRE(candidate);
    mapArgs["-maxreorgdepth"] = "2";
    BOOST_CHECK(!AllowReorgByDepthPolicy(tip, candidate));
    mapArgs["-maxreorgdepth"] = "3";
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, candidate));
    mapArgs["-maxreorgdepth"] = "2147483647";
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, candidate));
}

BOOST_AUTO_TEST_CASE(pre_dag_fork_extensions_rollbacks_and_genesis)
{
    LOCK(cs_main);
    CBlockIndex* tip = Tip(FORK_HEIGHT_DAG + MAX_REORG_DEPTH + 1);
    CBlockIndex* preDAG = chain.Extend(tip->GetAncestor(FORK_HEIGHT_DAG - 1), MAX_REORG_DEPTH + 3);
    CBlockIndex* extension = chain.Extend(tip, MAX_REORG_DEPTH + 2);
    BOOST_REQUIRE(preDAG && extension);
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, preDAG));
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, tip));
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, extension));
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, tip->GetAncestor(FORK_HEIGHT_DAG)));
    BOOST_CHECK(AllowReorgByDepthPolicy(NULL, extension));
    for (int h = 0; h < extension->nHeight; ++h)
        BOOST_CHECK(AllowReorgByDepthPolicy(extension->GetAncestor(h), extension->GetAncestor(h + 1)));
}

BOOST_AUTO_TEST_CASE(sync_import_and_reindex_are_exempt)
{
    LOCK(cs_main);
    CBlockIndex* tip = Tip(FORK_HEIGHT_DAG + MAX_REORG_DEPTH + 1);
    CBlockIndex* candidate = chain.Extend(tip->GetAncestor(FORK_HEIGHT_DAG), MAX_REORG_DEPTH + 2);
    BOOST_REQUIRE(candidate);
    BOOST_CHECK(!AllowReorgByDepthPolicy(tip, candidate));
    fImporting = true;
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, candidate));
    fImporting = false;
    fReindex = true;
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, candidate));
    fReindex = false;

    // Mainnet IBD also exempts a nonempty selected chain below the checkpoints.
    fRegTest = false;
    BOOST_REQUIRE(IsInitialBlockDownload());
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, candidate));
}

BOOST_AUTO_TEST_CASE(checked_header_lag_exempts_a_nonempty_regtest_node)
{
    LOCK(cs_main);
    CBlockIndex* tip = Tip(FORK_HEIGHT_DAG + MAX_REORG_DEPTH + 1);
    CBlockIndex* candidate = chain.Extend(tip->GetAncestor(FORK_HEIGHT_DAG), MAX_REORG_DEPTH + 2);
    BOOST_REQUIRE(candidate);
    BOOST_REQUIRE(!IsInitialBlockDownload());
    nBestHeaderHeight = tip->nHeight + MAX_REORG_DEPTH;
    BOOST_CHECK(!AllowReorgByDepthPolicy(tip, candidate));
    nBestHeaderHeight++;
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, candidate));
    nBestHeaderHeight = tip->nHeight;
    BOOST_CHECK(!AllowReorgByDepthPolicy(tip, candidate));
    BOOST_CHECK(!candidate->IsInvalid());
}

BOOST_AUTO_TEST_CASE(a_far_ahead_body_also_proves_header_lag)
{
    LOCK(cs_main);
    CBlockIndex* tip = Tip(FORK_HEIGHT_DAG + MAX_REORG_DEPTH + 1);
    CBlockIndex* candidate = chain.Extend(tip->GetAncestor(FORK_HEIGHT_DAG),
                                         2 * MAX_REORG_DEPTH + 2);
    BOOST_REQUIRE(candidate);
    BOOST_CHECK(AllowReorgByDepthPolicy(tip, candidate));
    BOOST_CHECK(!candidate->IsInvalid());
}

BOOST_AUTO_TEST_CASE(arrival_order_does_not_change_branch_validity)
{
    LOCK(cs_main);
    CBlockIndex* fork = chain.Add(NULL, FORK_HEIGHT_DAG);
    CBlockIndex* first = chain.Extend(fork, MAX_REORG_DEPTH + 1);
    CBlockIndex* second = chain.Extend(fork, MAX_REORG_DEPTH + 2);
    BOOST_REQUIRE(first && second);
    pindexBest = first;
    nBestHeight = first->nHeight;
    BOOST_CHECK(!AllowReorgByDepthPolicy(first, second));
    pindexBest = second;
    nBestHeight = second->nHeight;
    BOOST_CHECK(!AllowReorgByDepthPolicy(second, first));
    for (const CBlockIndex* p = first; p; p = p->pprev)
        BOOST_CHECK(!p->IsInvalid());
    for (const CBlockIndex* p = second; p; p = p->pprev)
        BOOST_CHECK(!p->IsInvalid());
}

BOOST_AUTO_TEST_SUITE_END()
