#include <boost/test/unit_test.hpp>
#include "../checkpoints.h"
#include "../main.h"
#include <vector>

BOOST_AUTO_TEST_SUITE(Checkpoints_tests)

namespace {
struct Chain {
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
        c.hashes.push_back(uint256((uint64_t)(0x900000 + i)));
        CBlockIndex* p = new CBlockIndex();
        p->phashBlock = &c.hashes.back();
        p->pprev = prev;
        p->nHeight = i;
        if (prev)
            prev->pnext = p;
        c.nodes.push_back(p);
        prev = p;
    }
    return c;
}
}

BOOST_AUTO_TEST_CASE(hardened_checkpoint_sanity)
{
    uint256 p2000("0x000000007e4fbd38a6072a2725273901d2eafdadbe9ce2e28f22882db6e76817");
    uint256 p5000("0x0000000090efedc86969fcd821ee8fdde179796547a4bd07c643800d75c1ddbd");
    BOOST_CHECK(Checkpoints::CheckHardened(2000, p2000));
    BOOST_CHECK(Checkpoints::CheckHardened(5000, p5000));
    BOOST_CHECK(!Checkpoints::CheckHardened(2000, p5000));
    BOOST_CHECK(!Checkpoints::CheckHardened(5000, p2000));
    BOOST_CHECK(Checkpoints::CheckHardened(2001, p5000));
    BOOST_CHECK(Checkpoints::GetTotalBlocksEstimate() >= 5000);
}

BOOST_AUTO_TEST_CASE(ibd_check_sync_accepts_competing_branch)
{
    Chain c = BuildLinear(6);
    pindexBest = c.nodes[5];
    pindexGenesisBlock = c.nodes[0];

    const uint256 candidateHash((uint64_t)0xabcdef01ULL);
    BOOST_CHECK(Checkpoints::CheckSync(candidateHash, c.nodes[2]));
}

BOOST_AUTO_TEST_SUITE_END()
