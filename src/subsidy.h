// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_SUBSIDY_H
#define INN_SUBSIDY_H

#include <stdint.h>

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

/** Budget available to the settlement of epoch nSettlementEpoch: the reserve
 *  accrued over the epoch BEFORE it, [H_{E-1}, H_E).
 *
 *  Settlement happens at H_E + FINALITY_VOTE_INCLUSION_WINDOW, well before epoch
 *  E itself closes, so E's own accrual is not yet a fixed quantity there. The
 *  preceding epoch is closed and is entirely made of ancestors of the settlement
 *  block, so producer and validator sum the identical range. The first post-DAG
 *  settlement therefore pays nothing: its predecessor accrued at the pre-DAG
 *  rate, which is zero. */
int64_t GetFinalityEpochBudget(int nSettlementEpoch, int nHeightHint);

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
