// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "subsidy.h"

#include "main.h"
#include "finality.h"

#include <limits>

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

bool GetFinalityAccrualRange(int nSettlementEpoch, int& nBeginOut, int& nEndOut)
{
    nBeginOut = 0;
    nEndOut = 0;
    if (nSettlementEpoch <= 0)
        return false;

    // Compute both boundaries in 64 bits before narrowing: an out-of-range epoch number
    // would overflow the multiply.
    const int64_t nBegin64 = GetEpochBoundaryHeight64(nSettlementEpoch - 1);
    const int64_t nEnd64 = GetEpochBoundaryHeight64(nSettlementEpoch);
    if (nBegin64 < 0 || nBegin64 >= nEnd64)
        return false;
    if (nEnd64 > (int64_t)std::numeric_limits<int>::max())
        return false;

    const int nBegin = (int)nBegin64;
    const int nEnd = (int)nEnd64;

    // The range is the pair of boundaries the epoch functions themselves place for
    // E-1 and E: an identity on the range, not a bound on its width. A width
    // compared against one regime's interval constant is a zero budget for every
    // epoch under any later regime -- voter pay silently going to zero, which is
    // the direction this channel exists to defend. This holds under every regime
    // because both sides move together, and it also rejects a boundary function
    // that stopped being strictly increasing, which a width check would accept and
    // which would pay the same withheld reserve to two settlements.
    if (GetEpochForHeight(nBegin) != nSettlementEpoch - 1)
        return false;
    if (GetEpochForHeight(nEnd) != nSettlementEpoch)
        return false;

    nBeginOut = nBegin;
    nEndOut = nEnd;
    return true;
}

int64_t SumFinalityReserve(int nBegin, int nEnd)
{
    // Closed sum over heights: the reserve is a function of height alone (zero below the
    // DAG fork), so producer and validator agree and any range sums correctly.
    int64_t nSum = 0;
    for (int nHeight = nBegin; nHeight < nEnd; nHeight++)
    {
        const int64_t nReserve = GetFinalityReservePerBlock(nHeight);
        if (nReserve <= 0)
            continue;
        if (nSum > MAX_MONEY - nReserve)
            return MAX_MONEY;
        nSum += nReserve;
    }
    return nSum;
}

int64_t GetFinalityEpochBudget(int nSettlementEpoch)
{
    int nAccrualBegin = 0;
    int nAccrualEnd = 0;
    if (!GetFinalityAccrualRange(nSettlementEpoch, nAccrualBegin, nAccrualEnd))
        return 0;
    return SumFinalityReserve(nAccrualBegin, nAccrualEnd);
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
