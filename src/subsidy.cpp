// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "subsidy.h"

#include "main.h"
#include "finality.h"

// Basis-point share of nValue, taken as quotient plus scaled remainder so a
// large value cannot overflow the intermediate product. Same shape the
// collateralnode rate has always used.
static int64_t BpsShare(int64_t nValue, int64_t nBps)
{
    if (nValue <= 0 || nBps <= 0)
        return 0;
    return (nValue / SUBSIDY_BPS_DEN) * nBps + ((nValue % SUBSIDY_BPS_DEN) * nBps) / SUBSIDY_BPS_DEN;
}

int64_t GetFinalityReservePerBlock(int nHeight)
{
    // The reserve exists only where finality settlement exists. Below the DAG
    // fork this is zero at every height, which is what keeps every split on this
    // page identical to the arithmetic that has always run.
    if (nHeight < FORK_HEIGHT_DAG)
        return 0;

    const int64_t nSchedule = GetBlockSubsidySchedule(nHeight);
    if (nSchedule <= 0)
        return 0;
    return BpsShare(nSchedule, FINALITY_RESERVE_BPS);
}

int64_t GetFinalityEpochBudget(int nSettlementEpoch, int nHeightHint)
{
    if (nSettlementEpoch <= 0)
        return 0;

    const int nAccrualEnd = GetEpochBoundaryHeight(nSettlementEpoch, nHeightHint);
    const int nAccrualBegin = GetEpochBoundaryHeight(nSettlementEpoch - 1, nHeightHint);
    if (nAccrualBegin < 0 || nAccrualBegin >= nAccrualEnd)
        return 0;
    // Adjacent boundaries are one epoch apart by construction. Fail closed on
    // anything wider rather than walk a range a corrupted epoch number chose:
    // a zero budget settles nothing, which is a state the rule already handles.
    if (nAccrualEnd - nAccrualBegin > FINALITY_EPOCH_INTERVAL_POST_DAG)
        return 0;

    // A closed sum over a height range. No block bodies, no index, no disk: the
    // per-block reserve is a function of height alone, so producer and validator
    // evaluate the same arithmetic from the same two integers.
    int64_t nBudget = 0;
    for (int nHeight = nAccrualBegin; nHeight < nAccrualEnd; nHeight++)
    {
        const int64_t nReserve = GetFinalityReservePerBlock(nHeight);
        if (nReserve <= 0)
            continue;
        if (nBudget > MAX_MONEY - nReserve)
            return MAX_MONEY;
        nBudget += nReserve;
    }
    return nBudget;
}

int64_t CBlockSubsidySplit::CollateralnodeShareOfBase(int64_t nBase)
{
    if (nBase <= 0)
        return 0;
    return (nBase / 100) * 65 + ((nBase % 100) * 65) / 100;
}

CBlockSubsidySplit CBlockSubsidySplit::ForBlock(int nBlockHeight,
                                                int64_t nSubsidy,
                                                int64_t nFees,
                                                CollateralnodeShare cnShare)
{
    if (nSubsidy < 0)
        nSubsidy = 0;
    if (nFees < 0)
        nFees = 0;

    // The reserve is the height-only figure the epoch budget sums and comes off issuance
    // first, so a penalised or clamped block gives up the producer share, not the voters'.
    int64_t nReserve = GetFinalityReservePerBlock(nBlockHeight);
    if (nReserve > nSubsidy)
        nReserve = nSubsidy;

    // What the block's own outputs may carry: subsidy net of the reserve, plus fees.
    // The collateralnode share is taken from this base.
    const int64_t nPaidBase = (nSubsidy - nReserve) + nFees;
    int64_t nCollateralnode = (cnShare == CollateralnodeShare::Paid)
                                  ? CollateralnodeShareOfBase(nPaidBase) : 0;
    if (nCollateralnode > nPaidBase)
        nCollateralnode = nPaidBase;

    const int64_t nProducer = nPaidBase - nCollateralnode;
    const int64_t nTotal = nProducer + nCollateralnode + nReserve;
    return CBlockSubsidySplit(nTotal, nProducer, nCollateralnode, nReserve);
}
