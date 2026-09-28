// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_SUBSIDY_H
#define INN_SUBSIDY_H

#include <stdint.h>

#include <string>

class CBlockIndex;

// One subsidy per block, split at payment into finality reserve, collateralnode
// share and producer remainder. Nothing is minted outside it, so the supply cap
// clamps a single number.

// Share of each block's subsidy withheld for the epoch finality budget, in basis
// points. Issuance only, never fees (reserving fees would mint new supply).
// Post-DAG only; pre-DAG the reserve is zero, so historical splits are unchanged.
static const int64_t FINALITY_RESERVE_BPS = 1000;   // 10%
static const int64_t SUBSIDY_BPS_DEN = 10000;

/** The block subsidy schedule: a pure function of height, before any clamp and
 *  before fees. */
int64_t GetBlockSubsidySchedule(int nHeight);

/** Reserve withheld from the block at nHeight. Height-only, so
 *  sum(paid) + sum(reserved) == sum(schedule). */
int64_t GetFinalityReservePerBlock(int nHeight);

/** The height range [H_{E-1}, H_E) whose reserve funds epoch nSettlementEpoch's
 *  settlement, and whether that epoch has one. Bounds the epoch number before
 *  narrowing, and requires the epoch functions to agree on both boundaries. */
bool GetFinalityAccrualRange(int nSettlementEpoch, int& nBeginOut, int& nEndOut);

/** Sum of the per-block reserve over [nBegin, nEnd). Total over any range: the
 *  reserve is defined at every height and is zero below the DAG fork. */
int64_t SumFinalityReserve(int nBegin, int nEnd);

/** Budget for epoch nSettlementEpoch's settlement: the reserve accrued over the
 *  PREVIOUS epoch [H_{E-1}, H_E), which is closed and all ancestors of the
 *  settlement block. The first post-DAG settlement therefore pays nothing. */
int64_t GetFinalityEpochBudget(int nSettlementEpoch);

/** What one counted note vote may mint into its own reissue: the epoch budget
 *  divided by the note-vote slot cap. A pure function of the epoch number, and
 *  dividing by the cap (not turnout) keeps total mint within budget. */
int64_t GetFinalityNoteVoteReward(int nSettlementEpoch);

/** One block's reward at a height, for display surfaces. Derived from the
 *  consensus schedule and CBlockSubsidySplit; never restate the ladder or rates. */
struct CBlockRewardSummary
{
    int nHeight;
    int nTargetSpacing;         // seconds between blocks at nHeight
    bool fPostDag;              // nHeight is at or above this network's DAG fork
    int64_t nSubsidy;           // issuance at nHeight: clamped, fees excluded
    int64_t nProducer;          // producer's share when a collateralnode is paid
    int64_t nCollateralnode;
    int64_t nFinalityReserve;
    int64_t nPerDay;            // nSubsidy over one day at nHeight's spacing
};

/** Evaluate the schedule at nHeight. pindexPrev is the parent of the block at
 *  nHeight, as ConnectBlock would pass it, so the supply-cap clamp is the one
 *  that block would actually meet; NULL leaves the clamp unreached. */
CBlockRewardSummary GetBlockRewardSummary(int nHeight, const CBlockIndex* pindexPrev);

/** "0.01333333 INN per block (~1152 INN/day)". Both figures are shown because
 *  only the per-day one is comparable across the spacing change at the fork. */
std::string FormatBlockRewardPerBlock(const CBlockRewardSummary& summary);

/** "65% of the block reward -- 0.00866666 INN per block". The rate is divided
 *  back out of the split, never restated. */
std::string FormatCollateralnodeReward(const CBlockRewardSummary& summary);

/** Whether this block pays a collateralnode. Not a bool: a bare true/false at a
 *  call site is the shape that silently takes the wrong branch. */
enum class CollateralnodeShare
{
    None,   // no payee resolved for this block
    Paid,   // a payee is being paid out of this block
};

/** One block's subsidy, split at the point of payment.
 *  Producer() + Collateralnode() + FinalityReserve() == Total() exactly.
 *  Producer and validator must both derive shares from this class only. */
class CBlockSubsidySplit
{
public:
    /** nSubsidy is clamped issuance excluding fees; nFees is the rest of the
     *  allowance. The reserve is a share of issuance only, the CN share of both. */
    static CBlockSubsidySplit ForBlock(int nBlockHeight,
                                       int64_t nSubsidy,
                                       int64_t nFees,
                                       CollateralnodeShare cnShare);

    /** The collateralnode share of an already-reserve-netted base; the single
     *  definition of that arithmetic, for callers that observe the paid base. */
    static int64_t CollateralnodeShareOfBase(int64_t nBase);

    int64_t Total() const { return nTotal; }
    int64_t Producer() const { return nProducer; }
    int64_t Collateralnode() const { return nCollateralnode; }
    int64_t FinalityReserve() const { return nFinalityReserve; }

    /** What this block's own outputs may carry: everything except the reserve,
     *  which is not paid here and not minted here. */
    int64_t PaidToBlock() const { return nProducer + nCollateralnode; }

    CBlockSubsidySplit() = delete;

private:
    CBlockSubsidySplit(int64_t nTotalIn, int64_t nProducerIn,
                       int64_t nCollateralnodeIn, int64_t nFinalityReserveIn)
        : nTotal(nTotalIn), nProducer(nProducerIn),
          nCollateralnode(nCollateralnodeIn), nFinalityReserve(nFinalityReserveIn) {}

    int64_t nTotal;
    int64_t nProducer;
    int64_t nCollateralnode;
    int64_t nFinalityReserve;
};

#endif // INN_SUBSIDY_H
