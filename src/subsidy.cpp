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
    if (nEnd64 > (int64_t)std::numeric_limits<int>::max())
        return false;

    const int nBegin = (int)nBegin64;
    const int nEnd = (int)nEnd64;

    // The range must be exactly the boundaries of E-1 and E (an identity, not a width
    // check), which holds under every regime and rejects a non-increasing boundary function.
    // GetEpochForHeight is monotonic, so this also orders the pair.
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

static const int64_t SECONDS_PER_DAY = 24 * 60 * 60;

CBlockRewardSummary GetBlockRewardSummary(int nHeight, const CBlockIndex* pindexPrev)
{
    CBlockRewardSummary summary;
    summary.nHeight = nHeight;
    summary.fPostDag = (nHeight >= FORK_HEIGHT_DAG);

    // Same spacings as GetPostDagProofOfWorkSubsidy: the pre-DAG reference is the
    // compile-time constant, never the mutable nTargetSpacing global.
    summary.nTargetSpacing = summary.fPostDag
                                 ? (int)GetTargetSpacingForHeight(nHeight)
                                 : (int)PRE_DAG_TARGET_SPACING;

    // Zero fees and zero committed settlement: what is wanted is the schedule
    // this height pays, under the clamp a block here would meet, and nothing
    // that belongs to one particular block body.
    summary.nSubsidy = GetProofOfWorkReward(nHeight, 0, pindexPrev, 0);

    // Paid: the collateralnode figure is what a payee would receive, which is
    // the only reason to show it. The producer figure is therefore the share
    // left on a block that pays one.
    const CBlockSubsidySplit split = CBlockSubsidySplit::ForBlock(
        nHeight, summary.nSubsidy, 0, CollateralnodeShare::Paid);
    summary.nProducer = split.Producer();
    summary.nCollateralnode = split.Collateralnode();
    summary.nFinalityReserve = split.FinalityReserve();

    const int64_t nBlocksPerDay = (summary.nTargetSpacing > 0)
                                      ? SECONDS_PER_DAY / summary.nTargetSpacing : 0;
    summary.nPerDay = summary.nSubsidy * nBlocksPerDay;

    return summary;
}

std::string FormatBlockRewardPerBlock(const CBlockRewardSummary& summary)
{
    std::string str = FormatMoney(summary.nSubsidy) + " INN per block";
    if (summary.nPerDay > 0)
        str += " (~" + FormatMoney(summary.nPerDay) + " INN/day)";
    return str;
}

std::string FormatCollateralnodeReward(const CBlockRewardSummary& summary)
{
    const int64_t nPaid = summary.nProducer + summary.nCollateralnode;
    if (nPaid <= 0)
        return "0 INN per block";

    // Divide the rate back out rather than naming it: the one place 65% is
    // written is CollateralnodeShareOfBase.
    const int nPercent = (int)((summary.nCollateralnode * 100 + nPaid / 2) / nPaid);

    return strprintf("%d%% of the block reward -- %s INN per block",
                     nPercent, FormatMoney(summary.nCollateralnode).c_str());
}
