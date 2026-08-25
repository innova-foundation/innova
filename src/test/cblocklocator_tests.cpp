#include <boost/test/unit_test.hpp>
#include "../main.h"
#include <vector>

BOOST_AUTO_TEST_SUITE(cblocklocator_tests)

namespace {

struct ExposedLocator : public CBlockLocator
{
    explicit ExposedLocator(const CBlockIndex* pindex) : CBlockLocator(pindex) {}
    const std::vector<uint256>& Hashes() const { return vHave; }
};

struct Chain
{
    std::vector<uint256> hashes;
    std::vector<CBlockIndex*> nodes;
    ~Chain() { for (size_t i = 0; i < nodes.size(); ++i) delete nodes[i]; }
};

Chain BuildLinear(int n)
{
    Chain c;
    c.hashes.reserve(n);
    c.nodes.reserve(n);
    CBlockIndex* prev = NULL;
    for (int i = 0; i < n; ++i)
    {
        c.hashes.push_back(uint256((uint64_t)(0x100000 + i)));
        CBlockIndex* p = new CBlockIndex();
        p->phashBlock = &c.hashes.back();
        p->pprev = prev;
        p->nHeight = i;
        p->BuildSkip();
        if (prev)
            prev->pnext = p;
        c.nodes.push_back(p);
        prev = p;
    }
    return c;
}

std::vector<uint256> LegacyLocatorReference(const CBlockIndex* pindex)
{
    std::vector<uint256> out;
    int step = 1;
    while (pindex)
    {
        out.push_back(pindex->GetBlockHash());
        for (int i = 0; pindex && i < step; ++i)
            pindex = pindex->pprev;
        if (out.size() > 10)
            step *= 2;
    }
    out.push_back(GetGenesisBlockHash());
    return out;
}

void CheckExact(const CBlockIndex* pindex)
{
    std::vector<uint256> legacy = LegacyLocatorReference(pindex);
    ExposedLocator loc(pindex);
    BOOST_CHECK(loc.Hashes() == legacy);
}

} // namespace

BOOST_AUTO_TEST_CASE(genesis_exact_equality_and_duplicate_genesis)
{
    Chain c = BuildLinear(1);
    std::vector<uint256> legacy = LegacyLocatorReference(c.nodes[0]);
    ExposedLocator loc(c.nodes[0]);
    BOOST_CHECK_EQUAL(legacy.size(), (size_t)2);
    BOOST_CHECK(loc.Hashes() == legacy);
    BOOST_CHECK(legacy[0] == c.nodes[0]->GetBlockHash());
    BOOST_CHECK(legacy[1] == GetGenesisBlockHash());
}

BOOST_AUTO_TEST_CASE(active_chain_threshold_cases_exact)
{
    CheckExact(BuildLinear(2).nodes.back());
    CheckExact(BuildLinear(10).nodes.back());
    CheckExact(BuildLinear(11).nodes.back());
    CheckExact(BuildLinear(12).nodes.back());
    CheckExact(BuildLinear(32).nodes.back());
    CheckExact(BuildLinear(257).nodes.back());
}

BOOST_AUTO_TEST_CASE(intermediate_and_tip_exact)
{
    Chain c = BuildLinear(200);
    CheckExact(c.nodes[37]);
    CheckExact(c.nodes[100]);
    CheckExact(c.nodes[101]);
    CheckExact(c.nodes[102]);
    CheckExact(c.nodes[199]);
}

BOOST_AUTO_TEST_CASE(rebuild_forward_links_main_chain_only)
{
    Chain c = BuildLinear(20);
    pindexGenesisBlock = c.nodes[0];
    pindexBest = c.nodes[19];
    for (size_t i = 0; i < c.nodes.size(); ++i)
        c.nodes[i]->pnext = NULL;
    BOOST_REQUIRE(RebuildMainChainForwardLinks());
    for (int i = 0; i < 19; ++i)
        BOOST_CHECK(c.nodes[i]->pnext == c.nodes[i+1]);
    BOOST_CHECK(c.nodes[19]->pnext == NULL);
}

BOOST_AUTO_TEST_SUITE_END()
