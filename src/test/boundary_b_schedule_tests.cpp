#include <boost/test/unit_test.hpp>

#include "../finality.h"
#include "../main.h"
#include "../shielded.h"
#include "../util.h"
#include "../v5activation.h"

#include <vector>

// Boundary B is an alias of Boundary A on every network; the regtest knob still
// overrides it, and scheduling the height does not enable the v2008 verifier.

namespace
{

struct NetFlagGuard
{
    bool fStoredRegTest, fStoredTestNet;
    NetFlagGuard() : fStoredRegTest(fRegTest), fStoredTestNet(fTestNet) {}
    ~NetFlagGuard() { fRegTest = fStoredRegTest; fTestNet = fStoredTestNet; }
};

struct RegtestBoundaryBGuard
{
    int nStored;
    RegtestBoundaryBGuard() : nStored(nRegtestBoundaryBHeight) {}
    ~RegtestBoundaryBGuard() { nRegtestBoundaryBHeight = nStored; }
};

void SetMainnet() { fRegTest = false; fTestNet = false; }
void SetTestnet() { fRegTest = false; fTestNet = true; }

// Heights around a boundary and far from it, so a drift of even one block shows.
std::vector<int> ProbeHeights(int nBoundary)
{
    std::vector<int> v;
    v.push_back(0);
    v.push_back(1);
    for (int nOffset = -3; nOffset <= 3; ++nOffset)
    {
        const int nHeight = nBoundary + nOffset;
        if (nHeight >= 0)
            v.push_back(nHeight);
    }
    v.push_back(nBoundary + 300);
    v.push_back(nBoundary + 100000);
    return v;
}

} // namespace

BOOST_AUTO_TEST_SUITE(boundary_b_schedule_tests)

// Off regtest, B must not sit on the sentinel height.
BOOST_AUTO_TEST_CASE(boundary_b_is_configured_on_mainnet_and_testnet)
{
    NetFlagGuard guard;

    SetMainnet();
    BOOST_CHECK(IsBoundaryBConfigured());
    BOOST_CHECK(GetForkHeightBoundaryB() != PRIVACY_VNEXT_HEIGHT_UNSET);

    SetTestnet();
    BOOST_CHECK(IsBoundaryBConfigured());
    BOOST_CHECK(GetForkHeightBoundaryB() != PRIVACY_VNEXT_HEIGHT_UNSET);
}

BOOST_AUTO_TEST_CASE(boundary_b_equals_boundary_a_on_every_network)
{
    NetFlagGuard guard;
    RegtestBoundaryBGuard boundaryGuard;

    SetMainnet();
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), GetForkHeightBoundaryA());
    BOOST_CHECK_EQUAL(FORK_HEIGHT_BOUNDARY_B, FORK_HEIGHT_BOUNDARY_A);

    SetTestnet();
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), GetForkHeightBoundaryA());
    BOOST_CHECK_EQUAL(FORK_HEIGHT_BOUNDARY_B, FORK_HEIGHT_BOUNDARY_A);

    // Regtest reaches the same shape when the knob is pointed at A, which is what
    // every IV5 harness does.
    fRegTest = true; fTestNet = false;
    nRegtestBoundaryBHeight = GetForkHeightBoundaryA();
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), GetForkHeightBoundaryA());
}

// B is derived from A rather than restated, so it moves with a re-base instead of
// being left behind by one. The derivation, not a literal, is what is pinned.
BOOST_AUTO_TEST_CASE(boundary_b_derives_from_the_ladder)
{
    NetFlagGuard guard;

    SetMainnet();
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), GetForkHeightEpochStateV3());
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), GetForkHeightDAG() + 300);
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(),
                      ShiftMainnetV5Activation(7950000) + 300);

    SetTestnet();
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), GetForkHeightEpochStateV3());
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), TESTNET_EPOCH_STATE_V3_HEIGHT);
}

// The anti-drift assertion. Every consumer asks IsBoundaryBActiveAtHeight, so
// agreement height by height is the property that matters, not just equal ints.
BOOST_AUTO_TEST_CASE(boundary_b_cannot_drift_from_boundary_a)
{
    NetFlagGuard guard;

    for (int nNet = 0; nNet < 2; ++nNet)
    {
        if (nNet == 0) SetMainnet(); else SetTestnet();

        const int nA = GetForkHeightBoundaryA();
        BOOST_CHECK_EQUAL(IsBoundaryBConfigured(), IsBoundaryAConfigured());

        const std::vector<int> vHeights = ProbeHeights(nA);
        for (size_t i = 0; i < vHeights.size(); ++i)
        {
            const int nHeight = vHeights[i];
            BOOST_CHECK_MESSAGE(
                IsBoundaryBActiveAtHeight(nHeight) ==
                    IsBoundaryAActiveAtHeight(nHeight),
                "boundary A/B disagree at height " << nHeight
                    << " (testnet=" << (int)fTestNet << ")");
        }

        // The pair a one-block drift would break.
        BOOST_CHECK(!IsBoundaryBActiveAtHeight(nA - 1));
        BOOST_CHECK(IsBoundaryBActiveAtHeight(nA));

        // No height runs a restored encoding outside the quarantine.
        BOOST_CHECK(BoundaryOrderingHolds());
        BOOST_CHECK(PrivateStakeIsFinalityOnly());
    }
}

// Regtest keeps its own knob so one chain can hold blocks on both sides of the
// boundary. Deriving the public value must not have taken that away.
BOOST_AUTO_TEST_CASE(boundary_b_regtest_override_is_unchanged)
{
    NetFlagGuard guard;
    RegtestBoundaryBGuard boundaryGuard;

    fRegTest = true; fTestNet = false;

    // Default: unset, and unset means unconfigured.
    nRegtestBoundaryBHeight = PRIVACY_VNEXT_HEIGHT_UNSET;
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), PRIVACY_VNEXT_HEIGHT_UNSET);
    BOOST_CHECK(!IsBoundaryBConfigured());
    BOOST_CHECK(!IsBoundaryBActiveAtHeight(GetForkHeightBoundaryA()));
    BOOST_CHECK(!IsBoundaryBActiveAtHeight(PRIVACY_VNEXT_HEIGHT_UNSET - 1));

    // The knob is returned verbatim, including the rehearsal height every IV5
    // harness uses and values above A.
    const int nA = GetForkHeightBoundaryA();
    const int vKnob[] = { nA, nA + 1, nA + 49 };
    for (size_t i = 0; i < sizeof(vKnob) / sizeof(vKnob[0]); ++i)
    {
        nRegtestBoundaryBHeight = vKnob[i];
        BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), vKnob[i]);
        BOOST_CHECK(IsBoundaryBConfigured());
        BOOST_CHECK(!IsBoundaryBActiveAtHeight(vKnob[i] - 1));
        BOOST_CHECK(IsBoundaryBActiveAtHeight(vKnob[i]));
        BOOST_CHECK(BoundaryOrderingHolds());
    }

    // Setting the regtest knob must not reach the public networks.
    nRegtestBoundaryBHeight = nA + 7;
    SetMainnet();
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), GetForkHeightBoundaryA());
    SetTestnet();
    BOOST_CHECK_EQUAL(GetForkHeightBoundaryB(), GetForkHeightBoundaryA());
}

// A scheduled height turns on the pool's state machinery, not the verifier. If
// this ever fails, a release shipped mainnet privacy consensus by moving a gate.
BOOST_AUTO_TEST_CASE(scheduling_boundary_b_does_not_activate_privacy)
{
    NetFlagGuard guard;

    for (int nNet = 0; nNet < 2; ++nNet)
    {
        if (nNet == 0) SetMainnet(); else SetTestnet();

        BOOST_CHECK(!IsShieldedVNextConsensusReady());

        const std::vector<int> vHeights = ProbeHeights(GetForkHeightBoundaryB());
        for (size_t i = 0; i < vHeights.size(); ++i)
            BOOST_CHECK(!IsPrivacyVNextCoinStakeReachableAtHeight(vHeights[i]));

        // Legacy privacy stays retired by policy on both public networks, so the
        // boundary does not hand it back either.
        BOOST_CHECK(IsLegacyPrivacyPolicyDisabled());
        BOOST_CHECK(!IsNullStakeBlockProductionReachableAtHeight(
            GetForkHeightBoundaryB()));
    }
}

// The window the ladder leaves for B, checked from B's side.
BOOST_AUTO_TEST_CASE(boundary_b_lands_inside_the_ladder_window)
{
    NetFlagGuard guard;
    SetMainnet();

    const int nB = GetForkHeightBoundaryB();
    BOOST_CHECK(nB > ShiftMainnetV5Activation(MAINNET_V5_ACTIVATION_BASE));
    BOOST_CHECK(nB > GetForkHeightDAG());
    BOOST_CHECK(nB > GetForkHeightIDNSReset());
    BOOST_CHECK(nB < ShiftMainnetV5Activation(8060000));
    BOOST_CHECK(nB < GetForkHeightNullStakeDelegSet());
    BOOST_CHECK(nB < GetForkHeightNullStakeB2C());

    // Schema V4 is expected of an epoch by its END height, so an epoch must not
    // straddle the boundary. B == A == DAG + one post-DAG epoch puts the
    // boundary exactly on an epoch start; an arbitrary later B would not.
    BOOST_CHECK_EQUAL(GetEpochBoundaryHeight(GetEpochForHeight(nB), nB), nB);
    BOOST_CHECK_EQUAL(GetEpochForHeight(nB), GetEpochForHeight(GetForkHeightDAG()) + 1);
}

BOOST_AUTO_TEST_SUITE_END()
