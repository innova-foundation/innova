// Difficulty retarget controller tests. Post-DAG spacing is 1s, the timestamp
// resolution, so the observation spans POST_DAG_RETARGET_WINDOW blocks.
// Pre-DAG results must stay bit-identical.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../bignum.h"

#include <cmath>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

namespace {

// nTargetTimespan is file-static in main.cpp; mirrored here for the reference
// transcription below.
static const int64_t kTargetTimespan = 30;

// Verbatim transcription of the retarget arithmetic as it stood BEFORE the
// window fix. The bit-identity test below pins the new code against this.
unsigned int LegacyRetarget(unsigned int nPrevBits, int64_t nActualSpacing,
                            unsigned int nEffectiveSpacing, bool fTighterDrift,
                            const CBigNum& bnTargetLimit)
{
    if (!fTighterDrift)
    {
        if (nActualSpacing < 0)
            nActualSpacing = nEffectiveSpacing;
    }
    else
    {
        int nClampFactor = 4;
        int64_t nMinSpacing = (int64_t)nEffectiveSpacing / nClampFactor;
        if (nMinSpacing < 1) nMinSpacing = 1;
        int64_t nMaxSpacing = (int64_t)nEffectiveSpacing * nClampFactor;

        if (nActualSpacing < nMinSpacing)
            nActualSpacing = nMinSpacing;
        if (nActualSpacing > nMaxSpacing)
            nActualSpacing = nMaxSpacing;
    }

    CBigNum bnNew;
    bnNew.SetCompact(nPrevBits);
    int64_t nSmoothTimespan = fTighterDrift ? 180 : kTargetTimespan;
    int64_t nInterval = nSmoothTimespan / nEffectiveSpacing;
    bnNew *= ((nInterval - 1) * nEffectiveSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nEffectiveSpacing);

    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

// Independent transcription of the retarget rule: interval 180/spacing, observation
// clamped to [1/4, 4x], update prev * ((I-1)*T + 2A) / ((I+1)*T). Literal constants,
// so an edit to main.cpp alone fails the sweep.
unsigned int ReferenceRetarget(unsigned int nPrevBits, int64_t nActualSpan,
                               unsigned int nEffectiveSpacing, int nWindow,
                               const CBigNum& bnTargetLimit)
{
    if (nWindow < 1) nWindow = 1;
    const int64_t nTargetSpan = (int64_t)nEffectiveSpacing * nWindow;

    int64_t nMinSpan = nTargetSpan / 4;
    if (nMinSpan < 1) nMinSpan = 1;
    const int64_t nMaxSpan = nTargetSpan * 4;
    if (nActualSpan < nMinSpan) nActualSpan = nMinSpan;
    if (nActualSpan > nMaxSpan) nActualSpan = nMaxSpan;

    const int64_t nInterval = 180 / (int64_t)nEffectiveSpacing;

    CBigNum bnNew;
    bnNew.SetCompact(nPrevBits);
    bnNew *= ((nInterval - 1) * nTargetSpan + nActualSpan + nActualSpan);
    bnNew /= ((nInterval + 1) * nTargetSpan);

    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

CBigNum TargetOf(unsigned int nBits)
{
    CBigNum bn;
    bn.SetCompact(nBits);
    return bn;
}

// Deterministic LCG + inverse-CDF exponential, so the convergence simulations
// below are reproducible and independent of the platform RNG.
struct Rng
{
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed) {}
    double Next()
    {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return (double)((s >> 11) & ((1ULL << 53) - 1)) / (double)(1ULL << 53);
    }
    double Exponential(double mean)
    {
        double u = Next();
        if (u <= 1e-12) u = 1e-12;
        return -mean * std::log(u);
    }
};

// Closed-loop mining at a fixed hashrate with whole-second timestamps bumped past
// MTP(11). Returns mean real spacing over the back half of the run.
double SimulateSpacing(int nWindow, unsigned int nEffectiveSpacing, int nBlocks,
                       double dTargetSpacing, uint64_t seed, double dHashrateMul = 1.0)
{
    const CBigNum bnLimit = CBigNum(~uint256(0) >> 20);
    unsigned int nBits = (bnLimit / 5000).GetCompact();

    // Calibrate a hashrate that yields exactly dTargetSpacing at the start.
    double dWork0 = TargetOf(nBits).getuint256().getdouble();
    double dHashrate = (std::pow(2.0, 256.0) / dWork0) / dTargetSpacing * dHashrateMul;

    Rng rng(seed);
    double dNow = 1000000.0;
    std::vector<int64_t> vTimes;
    std::vector<double> vGaps;

    for (int i = 0; i < nBlocks; i++)
    {
        double dWork = TargetOf(nBits).getuint256().getdouble();
        double dMean = (std::pow(2.0, 256.0) / dWork) / dHashrate;
        double dGap = rng.Exponential(dMean);
        dNow += dGap;

        int64_t nStamp = (int64_t)dNow;
        if (!vTimes.empty())
        {
            std::vector<int64_t> vRecent(vTimes.end() - std::min<size_t>(11, vTimes.size()),
                                         vTimes.end());
            std::sort(vRecent.begin(), vRecent.end());
            int64_t nMedian = vRecent[vRecent.size() / 2];
            if (nStamp <= nMedian) nStamp = nMedian + 1;
        }
        vTimes.push_back(nStamp);
        vGaps.push_back(dGap);

        if ((int)vTimes.size() > nWindow)
        {
            int64_t nSpan = vTimes.back() - vTimes[vTimes.size() - 1 - nWindow];
            nBits = ComputeRetargetedBits(nBits, nSpan, nEffectiveSpacing, nWindow,
                                          true, bnLimit);
        }
    }

    double dSum = 0.0;
    size_t nHalf = vGaps.size() / 2;
    for (size_t i = nHalf; i < vGaps.size(); i++) dSum += vGaps[i];
    return dSum / (double)(vGaps.size() - nHalf);
}

} // namespace

BOOST_AUTO_TEST_SUITE(retarget_tests)

// The defect itself: at the post-DAG 1s target with a single-gap observation,
// EVERY reachable observation leaves the target the same or larger. There is no
// input to the controller that raises difficulty.
BOOST_AUTO_TEST_CASE(postdag_single_gap_has_no_tightening_force)
{
    const CBigNum bnLimit = CBigNum(~uint256(0) >> 20);
    const unsigned int nBits = (bnLimit / 5000).GetCompact();
    const CBigNum bnPrev = TargetOf(nBits);

    bool fAnyTightened = false;
    // -5..+600 covers every gap a block can present, clamped or not.
    for (int64_t nGap = -5; nGap <= 600; nGap++)
    {
        unsigned int nNext = ComputeRetargetedBits(nBits, nGap, 1, 1, true, bnLimit);
        CBigNum bnNext = TargetOf(nNext);
        BOOST_CHECK_MESSAGE(bnNext >= bnPrev,
                            "single-gap observation " << nGap << " unexpectedly tightened");
        if (bnNext < bnPrev) fAnyTightened = true;
    }
    BOOST_CHECK_MESSAGE(!fAnyTightened,
                        "expected the single-gap controller to have no tightening force at T=1");

    // Concretely: the only observations that survive the clamp are 1..4, and the
    // smallest of them is exactly neutral rather than tightening.
    BOOST_CHECK(TargetOf(ComputeRetargetedBits(nBits, 0, 1, 1, true, bnLimit)) == bnPrev);
    BOOST_CHECK(TargetOf(ComputeRetargetedBits(nBits, 1, 1, 1, true, bnLimit)) == bnPrev);
    BOOST_CHECK(TargetOf(ComputeRetargetedBits(nBits, 2, 1, 1, true, bnLimit)) > bnPrev);
}

// With a window the controller can tighten: spans below the window's target span
// raise difficulty, the exact span is neutral, above it eases.
BOOST_AUTO_TEST_CASE(postdag_window_restores_tightening_force)
{
    const CBigNum bnLimit = CBigNum(~uint256(0) >> 20);
    const unsigned int nBits = (bnLimit / 5000).GetCompact();
    const CBigNum bnPrev = TargetOf(nBits);
    const int N = POST_DAG_RETARGET_WINDOW;

    // Blocks arriving faster than 1s => span < N => difficulty must rise.
    for (int64_t nSpan = N / 4; nSpan < N; nSpan++)
    {
        CBigNum bnNext = TargetOf(ComputeRetargetedBits(nBits, nSpan, 1, N, true, bnLimit));
        BOOST_CHECK_MESSAGE(bnNext < bnPrev,
                            "span " << nSpan << " over " << N << " blocks should tighten");
    }

    // Exactly on target => neutral.
    BOOST_CHECK(TargetOf(ComputeRetargetedBits(nBits, N, 1, N, true, bnLimit)) == bnPrev);

    // Slower than target => eases.
    for (int64_t nSpan = N + 1; nSpan <= (int64_t)N * 4; nSpan++)
    {
        CBigNum bnNext = TargetOf(ComputeRetargetedBits(nBits, nSpan, 1, N, true, bnLimit));
        BOOST_CHECK_MESSAGE(bnNext > bnPrev,
                            "span " << nSpan << " over " << N << " blocks should ease");
    }

    // The clamp floor sits strictly below the target span.
    BOOST_CHECK(((int64_t)N / 4) < (int64_t)N);
}

// Scope rule: with a window of 1 the new arithmetic must reproduce the old
// function bit for bit, across the whole pre-DAG parameter space.
BOOST_AUTO_TEST_CASE(predag_retarget_is_bit_identical)
{
    const CBigNum bnPowLimit = CBigNum(~uint256(0) >> 20);
    const CBigNum bnPosLimit = CBigNum(~uint256(0) >> 20);

    const unsigned int vBits[] = {
        bnPowLimit.GetCompact(),
        (bnPowLimit / 3).GetCompact(),
        (bnPowLimit / 1000).GetCompact(),
        (bnPowLimit / 1000000).GetCompact(),
        0x1d00ffff, 0x1c0ae23f, 0x1b04864c, 0x1e0fffff,
    };
    const unsigned int vSpacing[] = { 15, 30, 60, 64, 90 };

    size_t nChecked = 0;
    for (size_t b = 0; b < sizeof(vBits) / sizeof(vBits[0]); b++)
    {
        for (size_t s = 0; s < sizeof(vSpacing) / sizeof(vSpacing[0]); s++)
        {
            for (int d = 0; d < 2; d++)
            {
                bool fTighterDrift = (d == 1);
                for (int64_t nGap = -300; nGap <= 1200; nGap++)
                {
                    const CBigNum& bnLimit = (b % 2) ? bnPosLimit : bnPowLimit;
                    unsigned int nOld = LegacyRetarget(vBits[b], nGap, vSpacing[s],
                                                       fTighterDrift, bnLimit);
                    unsigned int nNew = ComputeRetargetedBits(vBits[b], nGap, vSpacing[s],
                                                              1, fTighterDrift, bnLimit);
                    BOOST_CHECK_MESSAGE(nOld == nNew,
                        "pre-DAG divergence: bits=" << vBits[b] << " spacing=" << vSpacing[s]
                        << " drift=" << fTighterDrift << " gap=" << nGap
                        << " old=" << nOld << " new=" << nNew);
                    nChecked++;
                }
            }
        }
    }
    BOOST_CHECK(nChecked > 100000);
}

// Same bit-identity claim over a wide pseudorandom spread of nBits, a superset of real
// pre-DAG history.
BOOST_AUTO_TEST_CASE(predag_retarget_bit_identical_over_random_targets)
{
    const CBigNum bnLimit = CBigNum(~uint256(0) >> 20);
    const unsigned int nLimitBits = bnLimit.GetCompact();
    Rng rng(0xC0FFEEULL);

    size_t nChecked = 0;
    for (int i = 0; i < 60000; i++)
    {
        // Spread targets across the whole representable range below the limit,
        // then hand both implementations the identical compact encoding.
        int nShift = (int)(rng.Next() * 60.0);
        CBigNum bnTarget = bnLimit >> nShift;
        if (bnTarget <= 0) continue;
        unsigned int nBits = bnTarget.GetCompact();
        if (nBits == 0) continue;

        // Real pre-DAG spacing is 15; keep a little variety around it.
        static const unsigned int kSpacings[] = { 15, 30, 60, 90 };
        unsigned int nSpacing = kSpacings[(int)(rng.Next() * 4.0) & 3];

        // Gaps spanning stalls, backwards timestamps and normal operation.
        int64_t nGap = (int64_t)(rng.Next() * 2000.0) - 500;
        bool fTighterDrift = (rng.Next() < 0.5);

        unsigned int nOld = LegacyRetarget(nBits, nGap, nSpacing, fTighterDrift, bnLimit);
        unsigned int nNew = ComputeRetargetedBits(nBits, nGap, nSpacing, 1, fTighterDrift, bnLimit);
        BOOST_CHECK_MESSAGE(nOld == nNew,
            "pre-DAG divergence: bits=" << nBits << " spacing=" << nSpacing
            << " drift=" << fTighterDrift << " gap=" << nGap
            << " old=" << nOld << " new=" << nNew);
        nChecked++;
    }
    BOOST_CHECK(nChecked > 50000);
    BOOST_CHECK(nLimitBits != 0);
}

// The window must never apply pre-DAG. The guard is the `- FORK_HEIGHT_DAG`
// subtraction in nAvailable; the height gate is a redundant fast path.
BOOST_AUTO_TEST_CASE(window_would_change_predag_results)
{
    const CBigNum bnLimit = CBigNum(~uint256(0) >> 20);
    const unsigned int nBits = (bnLimit / 1000).GetCompact();

    // On an on-target 15s chain a 60-block window is neutral only with the matching 900s span;
    // fed the single gap it hits the clamp floor. Hence the gate.
    unsigned int nSingle = ComputeRetargetedBits(nBits, 15, 15, 1, true, bnLimit);
    unsigned int nWindowed = ComputeRetargetedBits(nBits, 15, 15, 60, true, bnLimit);
    BOOST_CHECK(nSingle != nWindowed);
    BOOST_CHECK(TargetOf(nSingle) == TargetOf(nBits));
    BOOST_CHECK(TargetOf(nWindowed) < TargetOf(nBits));
}

// Golden post-DAG targets computed from the rule outside this codebase; they pin the
// smoothing interval and clamp, which the fixed point cannot (it is neutral for any I).
BOOST_AUTO_TEST_CASE(postdag_gain_matches_hardcoded_golden_targets)
{
    const CBigNum bnLimit = CBigNum(~uint256(0) >> 1);
    const unsigned int nPrev = 0x1d00ffffu;
    BOOST_REQUIRE_EQUAL(TargetOf(nPrev).GetCompact(), nPrev); // canonical input

    struct Golden { int64_t nSpan; unsigned int nSpacing; int nWindow; unsigned int nExpect; };
    static const Golden kGolden[] = {
        // Post-DAG: 1s spacing, full 60-block window.
        { 240, 1, 60, 0x1d01087bu }, // 4x slow, at the max clamp => max ease
        { 200, 1, 60, 0x1d010698u }, // slow, inside the clamp
        {  60, 1, 60, 0x1d00ffffu }, // on target => exactly neutral
        {  45, 1, 60, 0x1d00ff49u }, // fast => tightens (impossible pre-fix)
        {  30, 1, 60, 0x1d00fe94u },
        {  15, 1, 60, 0x1d00fddfu }, // 4x fast, at the min clamp => max tighten
        // Partial windows during the fork transition.
        {   7, 1, 12, 0x1d00fed1u },
        {  12, 1, 12, 0x1d00ffffu },
        {  30, 1, 12, 0x1d01043du },
        // Window 1 at 1s spacing: the defect itself. The clamp floor rounds up
        // to the target, so no observation tightens and 0s and 1s gaps are both
        // neutral while anything slower eases.
        {   0, 1,  1, 0x1d00ffffu },
        {   1, 1,  1, 0x1d00ffffu },
        {   4, 1,  1, 0x1d01087bu },
    };

    for (size_t i = 0; i < sizeof(kGolden) / sizeof(kGolden[0]); i++)
    {
        const Golden& g = kGolden[i];
        unsigned int nGot = ComputeRetargetedBits(nPrev, g.nSpan, g.nSpacing,
                                                  g.nWindow, true, bnLimit);
        BOOST_CHECK_MESSAGE(nGot == g.nExpect,
            "span " << g.nSpan << " spacing " << g.nSpacing << " window "
            << g.nWindow << ": expected nBits " << g.nExpect << " got " << nGot);
    }
}

// Breadth behind the golden points: sweep the post-DAG operating range against
// the independent transcription above, which carries the interval and clamp
// constants as literals of its own.
BOOST_AUTO_TEST_CASE(postdag_gain_matches_independent_reference)
{
    const CBigNum bnLimit = CBigNum(~uint256(0) >> 1);
    const unsigned int nPrev = 0x1d00ffffu;

    size_t nChecked = 0, nOffTarget = 0;
    for (int nWindow = 1; nWindow <= POST_DAG_RETARGET_WINDOW; nWindow++)
    {
        for (int64_t nSpan = 0; nSpan <= 5 * nWindow + 8; nSpan++)
        {
            unsigned int nGot = ComputeRetargetedBits(nPrev, nSpan, 1, nWindow, true, bnLimit);
            unsigned int nWant = ReferenceRetarget(nPrev, nSpan, 1, nWindow, bnLimit);
            BOOST_CHECK_MESSAGE(nGot == nWant,
                "post-DAG span " << nSpan << " window " << nWindow << " diverged");
            if (nGot != nPrev)
                nOffTarget++;
            nChecked++;
        }
    }
    BOOST_CHECK(nChecked > 5000);
    // Guard the guard: a sweep that only ever lands on the neutral fixed point
    // would agree with any smoothing interval and prove nothing.
    BOOST_CHECK_MESSAGE(nOffTarget > 1000,
        "post-DAG sweep never moved the target -- it cannot pin the gain");
}

// End to end: the old observation runs away from the 1s target, the new one
// converges to it. Same simulator, same seed, same hashrate.
BOOST_AUTO_TEST_CASE(postdag_controller_converges_only_with_window)
{
    const int nBlocks = 20000;

    double dOld = SimulateSpacing(1, 1, nBlocks, 1.0, 20260814ULL);
    double dNew = SimulateSpacing(POST_DAG_RETARGET_WINDOW, 1, nBlocks, 1.0, 20260814ULL);

    BOOST_TEST_MESSAGE("post-DAG mean spacing: single-gap = " << dOld
                       << "s, window(" << POST_DAG_RETARGET_WINDOW << ") = " << dNew << "s");

    // Old: blocks arrive far faster than the 1s target and difficulty never
    // recovers. Anything at or under half the target is already a failed chain.
    BOOST_CHECK_MESSAGE(dOld < 0.5,
        "expected the single-gap controller to run away below 0.5s, got " << dOld);

    // New: converges on the target.
    BOOST_CHECK_MESSAGE(dNew > 0.9 && dNew < 1.1,
        "expected the windowed controller to hold ~1s, got " << dNew);
}

// The windowed controller must also recover from a hashrate step rather than
// merely sitting still at a lucky starting difficulty.
BOOST_AUTO_TEST_CASE(postdag_window_recovers_from_hashrate_step)
{
    // Start 4x over-powered for the starting difficulty: without a working
    // controller spacing would sit at 0.25s forever.
    double dNew = SimulateSpacing(POST_DAG_RETARGET_WINDOW, 1, 20000, 1.0,
                                  99001ULL, 4.0);
    BOOST_TEST_MESSAGE("post-DAG mean spacing after 4x hashrate step: " << dNew << "s");
    BOOST_CHECK_MESSAGE(dNew > 0.9 && dNew < 1.1,
        "windowed controller failed to absorb a 4x hashrate step, got " << dNew);

    double dOld = SimulateSpacing(1, 1, 20000, 1.0, 99001ULL, 4.0);
    BOOST_CHECK_MESSAGE(dOld < 0.5,
        "expected single-gap to stay run away under the same step, got " << dOld);
}

// Pre-DAG spacing is unaffected by the same simulator: the 15s controller was
// always healthy and must stay that way.
BOOST_AUTO_TEST_CASE(predag_controller_remains_stable)
{
    double d = SimulateSpacing(1, 15, 8000, 15.0, 4242ULL);
    BOOST_TEST_MESSAGE("pre-DAG mean spacing (single gap, T=15): " << d << "s");
    BOOST_CHECK_MESSAGE(d > 13.0 && d < 18.0,
        "pre-DAG controller should hold near 15s, got " << d);
}

// Chain-level coverage of GetNextTargetRequired, using testnet params (DAG fork at 60) so
// a synthetic index chain reaches the fork.
namespace {

struct TestNetGuard
{
    bool fOldRegTest, fOldTestNet;
    unsigned int nOldSpacing;
    TestNetGuard() : fOldRegTest(fRegTest), fOldTestNet(fTestNet), nOldSpacing(nTargetSpacing)
    {
        fRegTest = false;
        fTestNet = true;
        // Restore the pre-DAG 15s spacing (regtest pins 1), or the fixture saturates the 4x clamp
        // and cannot tell a single gap from a window.
        nTargetSpacing = 15;
    }
    ~TestNetGuard()
    {
        fRegTest = fOldRegTest;
        fTestNet = fOldTestNet;
        nTargetSpacing = nOldSpacing;
    }
};

// Build a PoW index chain whose blocks are nSpacing seconds apart.
void BuildChain(std::vector<CBlockIndex>& vChain, int nBlocks, int nSpacing,
                unsigned int nBits)
{
    vChain.clear();
    vChain.resize(nBlocks);
    for (int i = 0; i < nBlocks; i++)
    {
        vChain[i].nHeight = i;
        vChain[i].nTime = 1700000000u + (unsigned int)(i * nSpacing);
        vChain[i].nBits = nBits;
        vChain[i].nFlags = 0; // proof-of-work
        vChain[i].pprev = (i == 0) ? NULL : &vChain[i - 1];
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(gate_applies_window_only_at_and_after_the_dag_fork)
{
    TestNetGuard guard;
    const int nDAG = FORK_HEIGHT_DAG;
    BOOST_REQUIRE(nDAG > 2 && nDAG < 1000); // testnet fork must be reachable

    const CBigNum bnLimit = bnProofOfWorkLimit;
    const unsigned int nBits = (bnLimit / 1000).GetCompact();

    // A chain running at 1 block/second. Post-DAG that is exactly on target, so
    // once the window is wide the controller must hold difficulty steady.
    std::vector<CBlockIndex> vChain;
    BuildChain(vChain, nDAG + POST_DAG_RETARGET_WINDOW + 40, 1, nBits);

    // Well past the fork with a full window: 1s blocks are on target => neutral.
    const CBlockIndex* pTip = &vChain[nDAG + POST_DAG_RETARGET_WINDOW + 20];
    unsigned int nOnTarget = GetNextTargetRequired(pTip, false);
    BOOST_CHECK_MESSAGE(TargetOf(nOnTarget) == TargetOf(nBits),
        "1s blocks past the DAG fork should be neutral, got a target change");

    // Blocks at twice the 1s target must raise difficulty.
    std::vector<CBlockIndex> vFast;
    BuildChain(vFast, nDAG + POST_DAG_RETARGET_WINDOW + 40, 1, nBits);
    for (size_t i = 1; i < vFast.size(); i++)
    {
        // Post-DAG: two blocks per second, i.e. the timestamp advances only on
        // every second block. Pre-DAG: one per second, as built.
        bool fPostDag = ((int)i > nDAG);
        unsigned int nAdvance = (fPostDag && (i % 2) == 1) ? 0u : 1u;
        vFast[i].nTime = vFast[i - 1].nTime + nAdvance;
    }
    const CBlockIndex* pFastTip = &vFast[nDAG + POST_DAG_RETARGET_WINDOW + 20];
    unsigned int nFast = GetNextTargetRequired(pFastTip, false);
    BOOST_CHECK_MESSAGE(TargetOf(nFast) < TargetOf(nBits),
        "post-DAG blocks arriving faster than target must tighten difficulty");

    // Alternating 5s/25s spacing (mean 15s): a single gap is off target but any
    // window >= 2 is on target, so the results differ.
    std::vector<CBlockIndex> vPre;
    BuildChain(vPre, nDAG, 15, nBits);
    for (size_t i = 1; i < vPre.size(); i++)
        vPre[i].nTime = vPre[i - 1].nTime + ((i % 2) ? 5u : 25u);

    size_t nNonNeutral = 0;
    for (int h = 3; h < nDAG - 1; h++)
    {
        const CBlockIndex* p = &vPre[h];
        unsigned int nGot = GetNextTargetRequired(p, false);
        unsigned int nWant = LegacyRetarget(p->nBits,
                                            (int64_t)p->nTime - (int64_t)p->pprev->nTime,
                                            GetTargetSpacingForHeight(p->nHeight + 1),
                                            (p->nHeight + 1) >= FORK_HEIGHT_TIGHTER_DRIFT,
                                            bnLimit);
        BOOST_CHECK_MESSAGE(nGot == nWant,
            "pre-DAG height " << (p->nHeight + 1) << " diverged from the legacy decision");
        // Discrimination check: feed the arithmetic the REAL elapsed span this
        // fixture would present over an 8-block window and confirm it lands
        // somewhere different. If it does not, the equality above proves nothing.
        if (h >= 10)
        {
            unsigned int nSpacing = GetTargetSpacingForHeight(p->nHeight + 1);
            bool fDrift = (p->nHeight + 1) >= FORK_HEIGHT_TIGHTER_DRIFT;
            int64_t nSpan8 = (int64_t)p->nTime - (int64_t)vPre[h - 8].nTime;
            unsigned int nWindowed = ComputeRetargetedBits(p->nBits, nSpan8, nSpacing, 8,
                                                           fDrift, bnLimit);
            if (nWindowed != nWant)
                nNonNeutral++;
        }
    }

    // Guard the guard: if a window and a single gap agree everywhere on this
    // fixture (e.g. both saturating the clamp), the equality above passes
    // vacuously and would not notice the gate being removed.
    BOOST_CHECK_MESSAGE(nNonNeutral > 0,
        "pre-DAG fixture cannot distinguish a window from a single gap -- "
        "it would not detect a window applied pre-DAG");
}

// For the first WINDOW blocks after the fork, the walk stays post-DAG. Without the
// subtraction it would read 15s pre-DAG gaps and max-ease exactly when difficulty
// must drop 15x. Fixture: 15s blocks to the fork, 1s after.
BOOST_AUTO_TEST_CASE(window_at_the_dag_fork_never_spans_predag_history)
{
    TestNetGuard guard;
    const int nDAG = FORK_HEIGHT_DAG;
    const int nWin = POST_DAG_RETARGET_WINDOW;
    BOOST_REQUIRE(nDAG > 2 && nDAG < 1000);

    const CBigNum bnLimit = bnProofOfWorkLimit;
    const unsigned int nBits = (bnLimit / 1000).GetCompact();

    const int nBlocks = nDAG + nWin + 10;
    std::vector<CBlockIndex> vChain;
    BuildChain(vChain, nBlocks, 15, nBits); // pre-DAG cadence everywhere...
    for (int i = nDAG; i < nBlocks; i++)    // ...then 1s from the fork block on
        vChain[i].nTime = vChain[i - 1].nTime + 1;

    // The very first post-DAG retarget (tip nDAG-1) legitimately reads the last
    // 15s gap against the 1s target: there is no post-DAG history yet. It must
    // ease, and it is the ONLY retarget allowed to see a pre-DAG gap.
    unsigned int nFirst = GetNextTargetRequired(&vChain[nDAG - 1], false);
    BOOST_CHECK_MESSAGE(TargetOf(nFirst) > TargetOf(nBits),
        "the first post-DAG retarget should ease off the 15s cadence");

    // From the fork block onward every observation is exactly on target.
    size_t nDiscriminating = 0;
    for (int h = nDAG; h < nBlocks - 1; h++)
    {
        const CBlockIndex* p = &vChain[h];
        unsigned int nGot = GetNextTargetRequired(p, false);
        BOOST_CHECK_MESSAGE(nGot == nBits,
            "tip " << h << " (" << (h - nDAG) << " blocks past the fork): 1s "
            "blocks are on target and must be neutral -- a window reaching into "
            "15s history is the only way to move here");

        // Confirm the pre-DAG prefix is visible to this fixture, so the neutrality above does not
        // hold merely because every reachable window agrees.
        int nCross = std::min(nWin, h);
        int64_t nCrossSpan = (int64_t)p->nTime - (int64_t)vChain[h - nCross].nTime;
        unsigned int nCrossed = ComputeRetargetedBits(nBits, nCrossSpan, 1, nCross,
                                                      true, bnLimit);
        if (nCrossed != nGot)
            nDiscriminating++;
    }

    BOOST_CHECK_MESSAGE(nDiscriminating > (size_t)(nWin / 2),
        "fork-transition fixture cannot tell a post-DAG-confined window from one "
        "that reaches into pre-DAG history -- the neutrality checks above would "
        "pass vacuously (got " << nDiscriminating << ")");
}

// Pin the window width: uneven post-DAG gaps make the result depend on the exact width and
// span, which neutrality alone cannot detect.
BOOST_AUTO_TEST_CASE(window_width_tracks_postdag_depth)
{
    TestNetGuard guard;
    const int nDAG = FORK_HEIGHT_DAG;
    const int nWin = POST_DAG_RETARGET_WINDOW;

    const CBigNum bnLimit = bnProofOfWorkLimit;
    const unsigned int nBits = (bnLimit / 1000).GetCompact();

    const int nBlocks = nDAG + nWin + 20;
    std::vector<CBlockIndex> vChain;
    BuildChain(vChain, nBlocks, 15, nBits);
    // Post-DAG gaps cycle 0/1/2 seconds: mean 1s (so the clamp stays off the
    // rails) but no two window widths see the same average.
    for (int i = nDAG; i < nBlocks; i++)
        vChain[i].nTime = vChain[i - 1].nTime + (unsigned int)(i % 3);

    size_t nDiscriminating = 0;
    for (int h = nDAG; h < nBlocks - 1; h++)
    {
        const CBlockIndex* p = &vChain[h];

        // The width the walk must produce: one gap until there is post-DAG
        // history to span, then the post-DAG depth, capped at the window.
        int nExpectWidth = h - nDAG;
        if (nExpectWidth < 1) nExpectWidth = 1;
        if (nExpectWidth > nWin) nExpectWidth = nWin;
        BOOST_REQUIRE(h - nExpectWidth >= nDAG - 1);

        int64_t nSpan = (int64_t)p->nTime - (int64_t)vChain[h - nExpectWidth].nTime;
        unsigned int nWant = ComputeRetargetedBits(nBits, nSpan, 1, nExpectWidth,
                                                   true, bnLimit);
        BOOST_CHECK_MESSAGE(GetNextTargetRequired(p, false) == nWant,
            "tip " << h << ": window walk did not produce width " << nExpectWidth
            << " over span " << nSpan);

        // Guard the guard: a neighbouring width must give a different answer,
        // otherwise the equality above does not actually pin the width.
        int nOther = (nExpectWidth < nWin) ? nExpectWidth + 1 : nExpectWidth - 1;
        if (nOther >= 1 && h - nOther >= 0)
        {
            int64_t nOtherSpan = (int64_t)p->nTime - (int64_t)vChain[h - nOther].nTime;
            if (ComputeRetargetedBits(nBits, nOtherSpan, 1, nOther, true, bnLimit) != nWant)
                nDiscriminating++;
        }
    }

    BOOST_CHECK_MESSAGE(nDiscriminating > (size_t)(nWin / 2),
        "width fixture is not sensitive to the window width -- an off-by-one in "
        "the walk would go unnoticed (got " << nDiscriminating << ")");
}

// On regtest GetNextTargetRequired must return the limit however fast blocks arrive, or
// regtest difficulty ramps under rapid generation.
BOOST_AUTO_TEST_CASE(regtest_never_retargets_off_the_limit)
{
    bool fOldRegTest = fRegTest, fOldTestNet = fTestNet;
    fRegTest = true;
    fTestNet = false;

    const unsigned int nLimitBits = bnProofOfWorkLimit.GetCompact();
    const unsigned int nBits = (bnProofOfWorkLimit / 1000).GetCompact();

    // All blocks share a timestamp: the fastest possible chain, which is what a
    // regtest generate loop actually produces.
    std::vector<CBlockIndex> vChain;
    BuildChain(vChain, 200, 0, nBits);

    for (int h = 3; h < 199; h++)
        BOOST_CHECK_EQUAL(GetNextTargetRequired(&vChain[h], false), nLimitBits);

    fRegTest = fOldRegTest;
    fTestNet = fOldTestNet;
}

// The regtest short-circuit is behaviour preserving: regtest nBits is pinned at
// the limit for every block, since the target starts there and can only rise.
BOOST_AUTO_TEST_CASE(regtest_bits_were_already_pinned_at_the_limit)
{
    const CBigNum bnLimit = CBigNum(~uint256(0) >> 1); // regtest PoW limit
    const unsigned int nPinned = bnLimit.GetCompact();

    unsigned int nBits = nPinned;
    for (int i = 0; i < 500; i++)
    {
        // Regtest spacing is 1 at every height and drift is tight from height 1.
        int64_t nGap = (int64_t)(i % 7) - 1; // includes 0 and negative gaps
        nBits = LegacyRetarget(nBits, nGap, 1, true, bnLimit);
        BOOST_CHECK_EQUAL(nBits, nPinned);
    }
}

BOOST_AUTO_TEST_SUITE_END()
