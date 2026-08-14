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

// The window must never be applied pre-DAG: a window > 1 genuinely changes the
// result, which is why the height gate is the load-bearing part of the fix.
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
