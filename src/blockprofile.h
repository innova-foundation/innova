// Block-connect phase profiler. Measurement only: every timer is inert unless
// -blockprofile is set, and no consensus value depends on it.
#ifndef INNOVA_BLOCKPROFILE_H
#define INNOVA_BLOCKPROFILE_H

#include <stdint.h>
#include <string>

enum BlockPhase
{
    BP_PROCESSBLOCK = 0,
    BP_CHECKBLOCK,
    BP_POW,
    BP_MERKLE,
    BP_CHECKTX,
    BP_ACCEPTBLOCK,
    BP_WRITEDISK,
    BP_ADDINDEX,
    BP_DAG_INIT,
    BP_DAG_COLOR,
    BP_DAG_ORDER,
    BP_DAG_WRITE,
    BP_SETBESTCHAIN,
    BP_CONNECTBLOCK,
    BP_FETCHINPUTS,
    BP_CONNECTINPUTS,
    BP_SIGVERIFY,
    BP_FCMP_VERIFY,
    BP_TXINDEX_WRITE,
    BP_EPOCH_BUILD,
    BP_EPOCH_WRITE,
    BP_IV5_TREE,
    BP_NAME_INDEX,
    BP_DB_COMMIT,
    BP_EFFECTS,
    BP_PHASE_COUNT
};

extern bool fBlockProfile;

// Named counters for breaking a phase down below timer granularity. Inert unless
// -blockprofile is set; the name must be a string literal with static lifetime.
void BlockProfileCount(const char* szName, int64_t nAmount);

const char* BlockPhaseName(int nPhase);
// Exclusive micros: time in this phase minus time in nested profiled phases.
void BlockProfileAdd(int nPhase, int64_t nExclusiveMicros, int64_t nInclusiveMicros);
void BlockProfileReset();
std::string BlockProfileReport();
// Height range covered by the current accumulation window.
void BlockProfileNoteHeight(int nHeight);

class CBlockPhaseTimer
{
public:
    explicit CBlockPhaseTimer(int nPhaseIn);
    ~CBlockPhaseTimer();

private:
    int nPhase;
    int64_t nStart;
    int64_t nSavedChild;
    bool fActive;
};

#define BP_CAT_INNER(a, b) a##b
#define BP_CAT(a, b) BP_CAT_INNER(a, b)
#define BLOCK_PHASE(phase) CBlockPhaseTimer BP_CAT(bpTimer_, __LINE__)(phase)

#endif // INNOVA_BLOCKPROFILE_H
