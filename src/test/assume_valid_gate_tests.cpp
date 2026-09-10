// The assume-valid gate lets a block's payloads skip proof verification. It must answer by
// ancestry (selected-parent path to the compiled-in hash), never by height.
// Linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include "../checkpoints.h"
#include "../main.h"
#include "../uint256.h"
#include "../v5activation.h"
#include "synthetic_chain.h"

BOOST_AUTO_TEST_SUITE(assume_valid_gate_tests)

namespace {

// Two branches from one shared base, so every height above the fork exists on both.
struct ForkedChain
{
    CSyntheticChain chain;
    CBlockIndex* pBase;      // tip of the shared segment
    CBlockIndex* pMainTip;   // branch A
    CBlockIndex* pForkTip;   // branch B, same heights as A

    explicit ForkedChain(unsigned int nTag)
        : chain(nTag), pBase(NULL), pMainTip(NULL), pForkTip(NULL)
    {
        CBlockIndex* pRoot = chain.Add(NULL, 0);
        BOOST_REQUIRE(pRoot != NULL);
        pBase = chain.Extend(pRoot, 20);
        BOOST_REQUIRE(pBase != NULL);
        pMainTip = chain.Extend(pBase, 10);
        pForkTip = chain.Extend(pBase, 10);
        BOOST_REQUIRE(pMainTip != NULL);
        BOOST_REQUIRE(pForkTip != NULL);
        BOOST_REQUIRE_EQUAL(pMainTip->nHeight, pForkTip->nHeight);
    }

    static uint256 HashOf(const CBlockIndex* pindex)
    {
        return pindex->GetBlockHash();
    }
};

const CBlockIndex* AncestorAt(const CBlockIndex* pTip, int nHeight)
{
    const CBlockIndex* p = pTip;
    while (p != NULL && p->nHeight > nHeight)
        p = p->pprev;
    return p;
}

} // namespace

// Both branches have a block at every height above the fork; only ancestry separates them.
BOOST_AUTO_TEST_CASE(a_block_on_another_branch_at_the_same_height_never_qualifies)
{
    ForkedChain fork(0xA5000001U);
    const uint256 hashAssumeValid = ForkedChain::HashOf(fork.pMainTip);

    for (int nHeight = fork.pBase->nHeight + 1; nHeight <= fork.pMainTip->nHeight; ++nHeight)
    {
        const CBlockIndex* pOnMain = AncestorAt(fork.pMainTip, nHeight);
        const CBlockIndex* pOnFork = AncestorAt(fork.pForkTip, nHeight);
        BOOST_REQUIRE(pOnMain != NULL && pOnFork != NULL);
        BOOST_REQUIRE(pOnMain != pOnFork);
        BOOST_REQUIRE_EQUAL(pOnMain->nHeight, pOnFork->nHeight);

        BOOST_CHECK_MESSAGE(
            IsPrivacyVNextAssumeValidAncestorOf(hashAssumeValid, pOnMain),
            "the named chain's own block at height " << nHeight << " must qualify");
        BOOST_CHECK_MESSAGE(
            !IsPrivacyVNextAssumeValidAncestorOf(hashAssumeValid, pOnFork),
            "a sibling branch's block at height " << nHeight << " must NOT qualify");
    }
}

// The shared segment is an ancestor of both tips, so it qualifies on either branch.
BOOST_AUTO_TEST_CASE(the_shared_segment_below_the_fork_qualifies_from_either_branch)
{
    ForkedChain fork(0xA5000002U);
    for (int nHeight = 0; nHeight <= fork.pBase->nHeight; ++nHeight)
    {
        const CBlockIndex* pShared = AncestorAt(fork.pBase, nHeight);
        BOOST_REQUIRE(pShared != NULL);
        BOOST_CHECK(IsPrivacyVNextAssumeValidAncestorOf(
            ForkedChain::HashOf(fork.pMainTip), pShared));
        BOOST_CHECK(IsPrivacyVNextAssumeValidAncestorOf(
            ForkedChain::HashOf(fork.pForkTip), pShared));
    }
}

// Blocks above the named block are never assumed valid.
BOOST_AUTO_TEST_CASE(nothing_above_the_named_block_qualifies)
{
    ForkedChain fork(0xA5000003U);
    const CBlockIndex* pNamed = AncestorAt(fork.pMainTip, fork.pBase->nHeight + 4);
    BOOST_REQUIRE(pNamed != NULL);
    const uint256 hashAssumeValid = ForkedChain::HashOf(pNamed);

    BOOST_CHECK(IsPrivacyVNextAssumeValidAncestorOf(hashAssumeValid, pNamed));
    for (int nHeight = pNamed->nHeight + 1; nHeight <= fork.pMainTip->nHeight; ++nHeight)
    {
        const CBlockIndex* pAbove = AncestorAt(fork.pMainTip, nHeight);
        BOOST_REQUIRE(pAbove != NULL);
        BOOST_CHECK_MESSAGE(
            !IsPrivacyVNextAssumeValidAncestorOf(hashAssumeValid, pAbove),
            "height " << nHeight << " is above the named block and must verify in full");
    }
}

// An unindexed hash, the disabled sentinel, and a null block all keep the gate shut.
BOOST_AUTO_TEST_CASE(an_unknown_or_disabled_hash_keeps_the_gate_shut)
{
    ForkedChain fork(0xA5000004U);
    uint256 hashUnknown;
    hashUnknown.SetHex(
        "0x00000000000000000000000000000000000000000000000000000000deadbeef");

    BOOST_CHECK(!IsPrivacyVNextAssumeValidAncestorOf(hashUnknown, fork.pMainTip));
    BOOST_CHECK(!IsPrivacyVNextAssumeValidAncestorOf(0, fork.pMainTip));
    BOOST_CHECK(!IsPrivacyVNextAssumeValidAncestorOf(
        ForkedChain::HashOf(fork.pMainTip), NULL));
}

// Post-DAG a height holds several valid blocks, so a checkpoint there would reject valid
// siblings. AcceptBlock does not gate CheckHardened on the fork, so no checkpoint may sit
// at or above FORK_HEIGHT_DAG on any network.
BOOST_AUTO_TEST_CASE(no_checkpoint_sits_at_or_above_the_dag_fork)
{
    // Both sides read mainnet on purpose. GetTotalBlocksEstimate() takes the mainnet map
    // unless fTestNet, and the suite runs under regtest, whose own DAG fork is height 11 --
    // comparing against that would assert nothing about the list this ships with.
    const int nMainnetDagFork = ShiftMainnetV5Activation(7950000);
    const int nLastCheckpoint = Checkpoints::GetTotalBlocksEstimate();
    BOOST_REQUIRE(nMainnetDagFork > 0);
    BOOST_REQUIRE(nLastCheckpoint > 0);
    BOOST_CHECK_MESSAGE(
        nLastCheckpoint < nMainnetDagFork,
        "a checkpoint at or above the DAG fork ("
            << nLastCheckpoint << " >= " << nMainnetDagFork
            << ") would reject every sibling block at that height");
}

BOOST_AUTO_TEST_SUITE_END()
