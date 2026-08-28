// Post-IDAG, a coinstake carrying a privacy encoding (legacy 2003-2005 or vNext 2008)
// must be unreachable on every public network at every height: the legacy policy refuses
// one, and every privacy height sits above the gate refusing proof-of-stake blocks.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../shielded.h"

#include <limits>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

namespace {

struct NetworkGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    int nRegtestBoundaryBSaved;
    bool fRehearsalSaved;
    int nBestHeightSaved;

    NetworkGuard()
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet),
          nRegtestBoundaryBSaved(nRegtestBoundaryBHeight),
          fRehearsalSaved(fRegtestShieldedVNextRehearsal),
          nBestHeightSaved(nBestHeight) {}

    ~NetworkGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
        nRegtestBoundaryBHeight = nRegtestBoundaryBSaved;
        fRegtestShieldedVNextRehearsal = fRehearsalSaved;
        nBestHeight = nBestHeightSaved;
    }
};

void SelectMainnet() { fRegTest = false; fTestNet = false; }
void SelectTestnet() { fRegTest = false; fTestNet = true; }
void SelectRegtest() { fRegTest = true;  fTestNet = false; }

// CheckTransaction reads nBestHeight for the DSP gate, so park the tip above
// every legacy privacy gate on whichever network is selected. Otherwise a
// public network rejects for the wrong reason and the test proves nothing.
void ParkTipAboveLegacyPrivacyGates() { nBestHeight = FORK_HEIGHT_NULLSTAKE_V3 + 1; }

// Every height a gate change could plausibly move the answer at: each gate on
// the ladder and its immediate neighbours, plus the ends of the range. A dense
// sweep of 8,000,000 heights would prove no more than the boundaries do.
std::vector<int> LadderProbeHeights()
{
    const int nGates[] = {
        FORK_HEIGHT_TIGHTER_DRIFT, FORK_HEIGHT_COLD_STAKING, FORK_HEIGHT_SHIELDED,
        FORK_HEIGHT_DSP, FORK_HEIGHT_NULLSEND,
        FORK_HEIGHT_NULLSTAKE, FORK_HEIGHT_NULLSTAKE_V2, FORK_HEIGHT_NULLSTAKE_V3,
        FORK_HEIGHT_CHAUMIAN_CJ, FORK_HEIGHT_POEM, FORK_HEIGHT_FINALITY,
        FORK_HEIGHT_DAG, FORK_HEIGHT_BOUNDARY_A, FORK_HEIGHT_DAGKNIGHT,
        FORK_HEIGHT_NULLSTAKE_DELEGSET, FORK_HEIGHT_NULLSTAKE_RECLAIM,
        FORK_HEIGHT_NULLSTAKE_B2C
    };

    std::vector<int> vHeights;
    vHeights.push_back(0);
    vHeights.push_back(1);
    for (size_t i = 0; i < sizeof(nGates) / sizeof(nGates[0]); i++)
    {
        const int nGate = nGates[i];
        if (nGate > 0)
            vHeights.push_back(nGate - 1);
        vHeights.push_back(nGate);
        if (nGate < std::numeric_limits<int>::max())
            vHeights.push_back(nGate + 1);
    }
    vHeights.push_back(std::numeric_limits<int>::max() - 1);
    vHeights.push_back(std::numeric_limits<int>::max());
    return vHeights;
}

// NullStake coinstake shape: a shielded spend, an empty vout[0], reward paid
// into the pool. Enough for IsCoinStake() and IsShielded() to both hold.
CTransaction MakeNullStakeCoinStake(int nTxVersion)
{
    CTransaction tx;
    tx.nVersion = nTxVersion;
    tx.nTime = GetAdjustedTime();
    tx.vShieldedSpend.resize(1);
    tx.vShieldedSpend[0].nullifier = uint256(0xBEEF);
    tx.vout.resize(1);
    tx.vout[0].SetEmpty();
    tx.nValueBalance = -1;
    return tx;
}

} // namespace

BOOST_AUTO_TEST_SUITE(nullstake_finality_only_tests)

// The deliverable. If a future gate change opens a height where a NullStake
// coinstake could connect on a public network, this fails.
BOOST_AUTO_TEST_CASE(nullstake_block_production_unreachable_on_public_networks)
{
    NetworkGuard guard;

    SelectMainnet();
    std::vector<int> vMainnet = LadderProbeHeights();
    for (size_t i = 0; i < vMainnet.size(); i++)
        BOOST_CHECK_MESSAGE(
            !IsNullStakeBlockProductionReachableAtHeight(vMainnet[i]),
            "mainnet height " << vMainnet[i] << " admits a NullStake coinstake");

    SelectTestnet();
    std::vector<int> vTestnet = LadderProbeHeights();
    for (size_t i = 0; i < vTestnet.size(); i++)
        BOOST_CHECK_MESSAGE(
            !IsNullStakeBlockProductionReachableAtHeight(vTestnet[i]),
            "testnet height " << vTestnet[i] << " admits a NullStake coinstake");
}

// Same for the canonical envelope, which is where the three NullStake
// generations come back as finality voting.
BOOST_AUTO_TEST_CASE(privacy_vnext_coinstake_unreachable_on_public_networks)
{
    NetworkGuard guard;

    SelectMainnet();
    std::vector<int> vMainnet = LadderProbeHeights();
    for (size_t i = 0; i < vMainnet.size(); i++)
        BOOST_CHECK_MESSAGE(
            !IsPrivacyVNextCoinStakeReachableAtHeight(vMainnet[i]),
            "mainnet height " << vMainnet[i] << " admits a v2008 coinstake");

    SelectTestnet();
    std::vector<int> vTestnet = LadderProbeHeights();
    for (size_t i = 0; i < vTestnet.size(); i++)
        BOOST_CHECK_MESSAGE(
            !IsPrivacyVNextCoinStakeReachableAtHeight(vTestnet[i]),
            "testnet height " << vTestnet[i] << " admits a v2008 coinstake");
}

// The predicate above is only worth anything if it can say yes. Regtest keeps
// the legacy block-production rehearsal reachable in a window below the DAG
// gate, and that is the window the harnesses use.
BOOST_AUTO_TEST_CASE(regtest_still_reaches_the_block_production_rehearsal)
{
    NetworkGuard guard;
    SelectRegtest();

    BOOST_REQUIRE(FORK_HEIGHT_NULLSTAKE < FORK_HEIGHT_DAG);
    BOOST_CHECK(!IsNullStakeBlockProductionReachableAtHeight(FORK_HEIGHT_NULLSTAKE - 1));
    BOOST_CHECK(IsNullStakeBlockProductionReachableAtHeight(FORK_HEIGHT_NULLSTAKE));
    BOOST_CHECK(IsNullStakeBlockProductionReachableAtHeight(FORK_HEIGHT_DAG - 1));

    // Retired at the DAG gate on regtest too: stake stops producing blocks
    // there on every network.
    BOOST_CHECK(!IsNullStakeBlockProductionReachableAtHeight(FORK_HEIGHT_DAG));
    BOOST_CHECK(!IsNullStakeBlockProductionReachableAtHeight(FORK_HEIGHT_BOUNDARY_A));
}

// The ordering the vNext argument rests on, stated as an assertion rather than
// left to be re-derived from three gate accessors.
BOOST_AUTO_TEST_CASE(boundaries_stay_above_the_gate_that_retires_stake_blocks)
{
    NetworkGuard guard;

    SelectMainnet();
    BOOST_CHECK_EQUAL(FORK_HEIGHT_BOUNDARY_A, FORK_HEIGHT_DAG + 300);
    BOOST_CHECK(BoundaryOrderingHolds());
    BOOST_CHECK(PrivateStakeIsFinalityOnly());

    SelectTestnet();
    BOOST_CHECK_EQUAL(FORK_HEIGHT_BOUNDARY_A, FORK_HEIGHT_DAG + 300);
    BOOST_CHECK(BoundaryOrderingHolds());
    BOOST_CHECK(PrivateStakeIsFinalityOnly());

    SelectRegtest();
    BOOST_CHECK_EQUAL(FORK_HEIGHT_BOUNDARY_A, FORK_HEIGHT_DAG + 300);
    BOOST_CHECK(BoundaryOrderingHolds());
    BOOST_CHECK(PrivateStakeIsFinalityOnly());
}

// PrivateStakeIsFinalityOnly() is the startup backstop, so it has to reject the
// configuration it exists to reject. A Boundary B under the DAG gate reopens
// v2008 block production, and the node must refuse to start rather than serve it.
BOOST_AUTO_TEST_CASE(boundary_b_below_the_dag_gate_is_refused)
{
    NetworkGuard guard;
    SelectRegtest();
    fRegtestShieldedVNextRehearsal = true;

    // The rehearsal placement every IV5 harness uses: B == A, above the gate.
    nRegtestBoundaryBHeight = FORK_HEIGHT_BOUNDARY_A;
    BOOST_CHECK(PrivateStakeIsFinalityOnly());
    BOOST_CHECK(!IsPrivacyVNextCoinStakeReachableAtHeight(FORK_HEIGHT_BOUNDARY_A));
    BOOST_CHECK(!IsPrivacyVNextCoinStakeReachableAtHeight(FORK_HEIGHT_BOUNDARY_A + 1));

    // Dropped under the DAG gate, a v2008 coinstake becomes reachable again --
    // and the startup guard is what stops that configuration from running.
    nRegtestBoundaryBHeight = FORK_HEIGHT_DAG - 2;
    BOOST_REQUIRE(IsPrivacyVNextCoinStakeReachableAtHeight(FORK_HEIGHT_DAG - 1));
    BOOST_CHECK(!PrivateStakeIsFinalityOnly());
}

// Which rule covers the range below the DAG gate. Written as a disjunction so it
// survives either answer: today the policy covers it because the NullStake gates
// sit under the gate, and moving them above it would be the other way.
BOOST_AUTO_TEST_CASE(pre_dag_window_is_covered_by_a_named_rule)
{
    NetworkGuard guard;
    SelectMainnet();

    const bool fOrderingCovers = (FORK_HEIGHT_NULLSTAKE >= FORK_HEIGHT_DAG);
    const bool fPolicyCovers = IsLegacyPrivacyPolicyDisabled();
    BOOST_CHECK_MESSAGE(fOrderingCovers || fPolicyCovers,
        "nothing covers [FORK_HEIGHT_NULLSTAKE, FORK_HEIGHT_DAG) on mainnet");

    SelectTestnet();
    BOOST_CHECK((FORK_HEIGHT_NULLSTAKE >= FORK_HEIGHT_DAG) ||
                IsLegacyPrivacyPolicyDisabled());
}

// The predicate arithmetic above says the encoding is unreachable; this executes
// the rule that makes it so. All three legacy generations, in coinstake shape.
BOOST_AUTO_TEST_CASE(checktransaction_refuses_every_nullstake_generation_publicly)
{
    NetworkGuard guard;

    const int nVersions[] = { SHIELDED_TX_VERSION_NULLSTAKE,
                              SHIELDED_TX_VERSION_NULLSTAKE_V2,
                              SHIELDED_TX_VERSION_NULLSTAKE_COLD };

    for (size_t i = 0; i < sizeof(nVersions) / sizeof(nVersions[0]); i++)
    {
        CTransaction tx = MakeNullStakeCoinStake(nVersions[i]);
        BOOST_REQUIRE(tx.IsCoinStake());
        BOOST_REQUIRE(tx.IsShielded());

        SelectMainnet();
        ParkTipAboveLegacyPrivacyGates();
        BOOST_CHECK_MESSAGE(!tx.CheckTransaction(),
            "mainnet accepted a version " << nVersions[i] << " coinstake");

        SelectTestnet();
        ParkTipAboveLegacyPrivacyGates();
        BOOST_CHECK_MESSAGE(!tx.CheckTransaction(),
            "testnet accepted a version " << nVersions[i] << " coinstake");

        // Regtest keeps the decoder and the rehearsal, which is why the public
        // rejection has to be a policy rather than a deletion. This is the
        // positive control: without it the two checks above pass vacuously.
        SelectRegtest();
        ParkTipAboveLegacyPrivacyGates();
        BOOST_CHECK_MESSAGE(tx.CheckTransaction(),
            "regtest lost the version " << nVersions[i] << " rehearsal");
    }
}

// The B2-c hidden-signer bound is reachable only in [FORK_HEIGHT_NULLSTAKE_DELEGSET,
// FORK_HEIGHT_NULLSTAKE_B2C), above the DAG gate; on mainnet the window is empty.
BOOST_AUTO_TEST_CASE(the_b2c_hidden_coinstake_bound_has_no_height_to_decide_at)
{
    NetworkGuard guard;

    for (int nPass = 0; nPass < 3; nPass++)
    {
        if (nPass == 0)
            SelectMainnet();
        else if (nPass == 1)
            SelectTestnet();
        else
            SelectRegtest();

        const std::string strNet = nPass == 0 ? "mainnet"
                                 : nPass == 1 ? "testnet" : "regtest";

        BOOST_CHECK_MESSAGE(FORK_HEIGHT_NULLSTAKE_B2C >= FORK_HEIGHT_NULLSTAKE_DELEGSET,
            strNet + ": the B2C gate moved below DELEGSET, which opens a window where "
            "the hidden-signer bound decides and so needs its own case");
        BOOST_CHECK_MESSAGE(FORK_HEIGHT_NULLSTAKE_DELEGSET >= FORK_HEIGHT_DAG,
            strNet + ": the DELEGSET gate moved below the DAG gate, so a proof-of-stake "
            "block now reaches the coinstake dispatch inside the hidden-signer window");
    }

    // Which mechanism carries which network. Without this the ordering check above
    // would pass on a ladder that had collapsed every window to empty, and nothing
    // would say the DAG ordering is what does the work.
    SelectMainnet();
    BOOST_CHECK_MESSAGE(FORK_HEIGHT_NULLSTAKE_DELEGSET == FORK_HEIGHT_NULLSTAKE_B2C,
        "mainnet no longer co-activates DELEGSET and B2C, so the window is no longer "
        "empty and only the DAG ordering closes it");

    SelectTestnet();
    BOOST_CHECK_MESSAGE(FORK_HEIGHT_NULLSTAKE_B2C > FORK_HEIGHT_NULLSTAKE_DELEGSET,
        "testnet lost its non-empty hidden-signer window, so the DAG ordering check "
        "above passes vacuously there");

    SelectRegtest();
    BOOST_CHECK_MESSAGE(FORK_HEIGHT_NULLSTAKE_B2C > FORK_HEIGHT_NULLSTAKE_DELEGSET,
        "regtest lost its non-empty hidden-signer window, so the DAG ordering check "
        "above passes vacuously there");
}

// No public-network height may have Boundary B live and the fee-note fork not yet live:
// that gap is a full-value exit for a self-mining producer.
BOOST_AUTO_TEST_CASE(pool_never_opens_while_unshield_is_still_permitted)
{
    NetworkGuard guard;

    const char* const vNames[] = { "mainnet", "testnet" };
    for (size_t nNet = 0; nNet < 2; nNet++)
    {
        if (nNet == 0)
            SelectMainnet();
        else
            SelectTestnet();
        const std::string strNet(vNames[nNet]);

        // The derivation itself, read at heights these networks do not carry yet;
        // comparing the two accessors proves nothing while both sit at the sentinel.
        const int vHypothetical[] = { 1, 60, 360, 8220300, 8330000,
                                      PRIVACY_VNEXT_HEIGHT_UNSET };
        for (size_t j = 0; j < sizeof(vHypothetical) / sizeof(vHypothetical[0]); j++)
            BOOST_CHECK_MESSAGE(
                DeriveIV5FeeNoteHeight(vHypothetical[j]) == vHypothetical[j],
                strNet + ": a Boundary B at " << vHypothetical[j] <<
                    " does not carry the fee-note fork with it, so scheduling B "
                    "would open the pool with unshield still permitted");

        BOOST_CHECK_MESSAGE(
            GetForkHeightIV5FeeNote() == GetForkHeightBoundaryB(),
            strNet + ": the fee-note fork is not derived from Boundary B");

        std::vector<int> vHeights = LadderProbeHeights();
        vHeights.push_back(FORK_HEIGHT_BOUNDARY_B);
        for (size_t i = 0; i < vHeights.size(); i++)
            BOOST_CHECK_MESSAGE(
                !IsBoundaryBActiveAtHeight(vHeights[i]) ||
                    IsIV5FeeNoteActiveAtHeight(vHeights[i]),
                strNet + " height " << vHeights[i] << " runs the IV5 pool while "
                    "unshield is still permitted and pool fees still pay out "
                    "transparently");
    }
}

// Regtest keeps an independent fee-note knob so both sides of the boundary stay
// reachable against a rehearsal B; there the two heights can differ.
BOOST_AUTO_TEST_CASE(regtest_still_separates_the_fee_note_from_boundary_b)
{
    NetworkGuard guard;
    SelectRegtest();

    const int nSavedB = nRegtestBoundaryBHeight;
    const int nSavedFee = nRegtestIV5FeeNoteHeight;

    nRegtestBoundaryBHeight = 311;
    nRegtestIV5FeeNoteHeight = 611;

    BOOST_CHECK_EQUAL(FORK_HEIGHT_BOUNDARY_B, 311);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_IV5_FEE_NOTE, 611);
    BOOST_CHECK(IsBoundaryBActiveAtHeight(400));
    BOOST_CHECK(!IsIV5FeeNoteActiveAtHeight(400));

    nRegtestBoundaryBHeight = nSavedB;
    nRegtestIV5FeeNoteHeight = nSavedFee;
}

BOOST_AUTO_TEST_SUITE_END()
