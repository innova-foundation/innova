#include "blockprofile.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <chrono>
#include <mutex>

bool fBlockProfile = false;

namespace {

struct PhaseAccum
{
    int64_t nExclusive;
    int64_t nInclusive;
    int64_t nCalls;
};

PhaseAccum g_phase[BP_PHASE_COUNT];
std::mutex g_phaseMutex;
int g_nFirstHeight = -1;
int g_nLastHeight = -1;
int64_t g_nBlocks = 0;
int64_t g_nWallStartUs = 0;

// Time already charged to nested profiled phases on this thread.
thread_local int64_t tlChildMicros = 0;

int64_t NowMicros()
{
    return (int64_t)std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

const char* kPhaseNames[BP_PHASE_COUNT] = {
    "process_block",
    "check_block",
    "pow_hash",
    "merkle_root",
    "check_tx",
    "accept_block",
    "write_disk",
    "add_block_index",
    "dag_init",
    "dag_color",
    "dag_order",
    "dag_write",
    "set_best_chain",
    "connect_block",
    "fetch_inputs",
    "connect_inputs",
    "sig_verify",
    "fcmp_verify",
    "txindex_write",
    "epoch_build",
    "epoch_write",
    "iv5_tree",
    "name_index",
    "db_commit",
    "post_effects",
    "wallet_sync",
    "shield_scan",
    "wallet_locator",
    "recovery_clear",
};

const int kMaxCounters = 24;
const char* g_counterName[kMaxCounters];
int64_t g_counterValue[kMaxCounters];
int g_nCounters = 0;

} // namespace

void BlockProfileCount(const char* szName, int64_t nAmount)
{
    if (!fBlockProfile)
        return;
    std::lock_guard<std::mutex> lock(g_phaseMutex);
    for (int i = 0; i < g_nCounters; i++)
        if (strcmp(g_counterName[i], szName) == 0)
        {
            g_counterValue[i] += nAmount;
            return;
        }
    if (g_nCounters >= kMaxCounters)
        return;
    g_counterName[g_nCounters] = szName;
    g_counterValue[g_nCounters] = nAmount;
    g_nCounters++;
}

const char* BlockPhaseName(int nPhase)
{
    if (nPhase < 0 || nPhase >= BP_PHASE_COUNT)
        return "?";
    return kPhaseNames[nPhase];
}

void BlockProfileAdd(int nPhase, int64_t nExclusiveMicros, int64_t nInclusiveMicros)
{
    if (nPhase < 0 || nPhase >= BP_PHASE_COUNT)
        return;
    std::lock_guard<std::mutex> lock(g_phaseMutex);
    g_phase[nPhase].nExclusive += nExclusiveMicros;
    g_phase[nPhase].nInclusive += nInclusiveMicros;
    g_phase[nPhase].nCalls++;
}

void BlockProfileNoteHeight(int nHeight)
{
    if (!fBlockProfile)
        return;
    std::lock_guard<std::mutex> lock(g_phaseMutex);
    if (g_nFirstHeight < 0)
    {
        g_nFirstHeight = nHeight;
        g_nWallStartUs = NowMicros();
    }
    g_nLastHeight = nHeight;
    g_nBlocks++;
}

void BlockProfileReset()
{
    std::lock_guard<std::mutex> lock(g_phaseMutex);
    memset(g_phase, 0, sizeof(g_phase));
    memset(g_counterValue, 0, sizeof(g_counterValue));
    g_nFirstHeight = -1;
    g_nLastHeight = -1;
    g_nBlocks = 0;
    g_nWallStartUs = 0;
}

std::string BlockProfileReport()
{
    std::lock_guard<std::mutex> lock(g_phaseMutex);
    const int64_t nWallUs = g_nWallStartUs ? (NowMicros() - g_nWallStartUs) : 0;
    const double dBlocks = g_nBlocks > 0 ? (double)g_nBlocks : 1.0;
    char buf[512];
    std::string s;
    snprintf(buf, sizeof(buf),
             "blockprofile blocks=%" PRId64 " heights=%d..%d wall_us=%" PRId64
             " wall_us_per_block=%.1f\n",
             g_nBlocks, g_nFirstHeight, g_nLastHeight, nWallUs,
             (double)nWallUs / dBlocks);
    s += buf;
    snprintf(buf, sizeof(buf), "%-18s %12s %12s %12s %12s\n", "phase", "calls",
             "excl_us", "incl_us", "excl_us/blk");
    s += buf;
    for (int i = 0; i < BP_PHASE_COUNT; i++)
    {
        if (g_phase[i].nCalls == 0)
            continue;
        snprintf(buf, sizeof(buf), "%-18s %12" PRId64 " %12" PRId64 " %12" PRId64 " %12.2f\n",
                 kPhaseNames[i], g_phase[i].nCalls, g_phase[i].nExclusive,
                 g_phase[i].nInclusive, (double)g_phase[i].nExclusive / dBlocks);
        s += buf;
    }
    for (int i = 0; i < g_nCounters; i++)
    {
        snprintf(buf, sizeof(buf), "%-18s %12" PRId64 " %12s %12s %12.2f\n",
                 g_counterName[i], g_counterValue[i], "-", "-",
                 (double)g_counterValue[i] / dBlocks);
        s += buf;
    }
    return s;
}

CBlockPhaseTimer::CBlockPhaseTimer(int nPhaseIn)
    : nPhase(nPhaseIn), nStart(0), nSavedChild(0), fActive(fBlockProfile)
{
    if (!fActive)
        return;
    nSavedChild = tlChildMicros;
    tlChildMicros = 0;
    nStart = NowMicros();
}

CBlockPhaseTimer::~CBlockPhaseTimer()
{
    if (!fActive)
        return;
    const int64_t nElapsed = NowMicros() - nStart;
    const int64_t nChild = tlChildMicros;
    int64_t nExclusive = nElapsed - nChild;
    if (nExclusive < 0)
        nExclusive = 0;
    BlockProfileAdd(nPhase, nExclusive, nElapsed);
    tlChildMicros = nSavedChild + nElapsed;
}
