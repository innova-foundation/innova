// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Post-DAG blocks have no per-block spacing floor; only the MTP and drift legs bound
// timestamps, so at most six blocks share one second. Mines on the shared regtest
// chain, so it is linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "../bignum.h"
#include "../main.h"
#include "../miner.h"
#include "../util.h"
#include "../wallet.h"

extern CWallet* pwalletMain;
extern bool fPrintToConsole;

BOOST_AUTO_TEST_SUITE(block_spacing_floor_tests)

namespace {

struct DetachedWalletGuard
{
    DetachedWalletGuard() { UnregisterWallet(pwalletMain); }
    ~DetachedWalletGuard() { RegisterWallet(pwalletMain); }
};

struct MockClockGuard
{
    ~MockClockGuard() { SetMockTime(0); }
};

// One call's log output. AcceptBlock refuses a bad timestamp through a plain
// error(), so the printed reason is what separates "refused by the timestamp
// rule" from "refused".
class CaptureLog
{
public:
    CaptureLog() : nSavedFd(-1), fSavedPrintToConsole(fPrintToConsole), pFile(NULL) {}

    bool Begin()
    {
        pFile = tmpfile();
        if (pFile == NULL)
            return false;
        fflush(stdout);
        nSavedFd = dup(fileno(stdout));
        if (nSavedFd == -1 || dup2(fileno(pFile), fileno(stdout)) == -1)
            return false;
        fPrintToConsole = true;
        return true;
    }

    std::string End()
    {
        fPrintToConsole = fSavedPrintToConsole;
        fflush(stdout);
        if (nSavedFd != -1)
        {
            dup2(nSavedFd, fileno(stdout));
            close(nSavedFd);
            nSavedFd = -1;
        }
        std::string out;
        if (pFile != NULL)
        {
            rewind(pFile);
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), pFile)) > 0)
                out.append(buf, n);
            fclose(pFile);
            pFile = NULL;
        }
        return out;
    }

    ~CaptureLog()
    {
        if (pFile != NULL || nSavedFd != -1)
            End();
    }

private:
    int nSavedFd;
    bool fSavedPrintToConsole;
    FILE* pFile;
};

CBlockIndex* BestIndex()
{
    LOCK(cs_main);
    return pindexBest;
}

bool GrindHeader(CBlock* pblock)
{
    CBigNum target;
    target.SetCompact(pblock->nBits);
    const uint256 hashTarget = target.getuint256();
    unsigned int nHashes = 0;
    while (pblock->GetPoWHash() > hashTarget)
    {
        ++pblock->nNonce;
        if (pblock->nNonce == 0)
            ++pblock->nTime;
        if (++nHashes > 4000000U)
            return false;
    }
    return true;
}

// Mine nBlocks, advancing the mock clock nStep seconds before each, so timestamps
// strictly increase and the median leg does not decide the arms below.
bool MineSpacedBlocks(int nBlocks, int nStep)
{
    unsigned int nExtraNonce = 0;
    for (int i = 0; i < nBlocks; i++)
    {
        SetMockTime(GetTime() + nStep);
        CBlockIndex* pindexPrev = BestIndex();
        if (pindexPrev == NULL)
            return false;
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        if (pblock.get() == NULL)
            return false;
        IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
        if (!GrindHeader(pblock.get()))
            return false;
        if (!ProcessBlock(NULL, pblock.get()))
            return false;
        if (BestIndex()->nHeight != pindexPrev->nHeight + 1)
            return false;
    }
    return true;
}

struct Offer
{
    bool fBuilt;
    bool fStamped;   // the header still carries the timestamp we asked for
    bool fAccepted;
    std::string strLog;
    Offer() : fBuilt(false), fStamped(false), fAccepted(false) {}
};

// Build a child of the current tip carrying an exact timestamp and offer it.
// Only nTime (and the coinbase's copy of it) differs from a block the node
// would have produced itself.
Offer OfferBlockAt(int64_t nWhen)
{
    Offer r;
    CBlockIndex* pindexPrev = BestIndex();
    if (pindexPrev == NULL)
        return r;

    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return r;
    if (pblock->hashPrevBlock != pindexPrev->GetBlockHash())
        return r;

    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    pblock->nTime = (unsigned int)nWhen;
    pblock->vtx[0].nTime = pblock->nTime;
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    if (!GrindHeader(pblock.get()))
        return r;

    r.fBuilt = true;
    // GrindHeader advances nTime when the nonce wraps. At regtest difficulty it
    // never has to, but the timestamp is the entire subject here, so say so.
    r.fStamped = ((int64_t)pblock->nTime == nWhen);

    CaptureLog log;
    if (!log.Begin())
        return r;
    r.fAccepted = ProcessBlock(NULL, pblock.get());
    r.strLog = log.End();
    return r;
}

// The highest timestamp in the median window ending at pindex.
int64_t MaxTimeInMedianWindow(const CBlockIndex* pindex)
{
    int64_t nMax = 0;
    const CBlockIndex* p = pindex;
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan && p != NULL; i++, p = p->pprev)
        if (p->GetBlockTime() > nMax)
            nMax = p->GetBlockTime();
    return nMax;
}

} // namespace

// No monotonicity rule: a block carrying exactly its parent's timestamp is valid.
BOOST_AUTO_TEST_CASE(a_block_may_carry_its_parents_timestamp)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(BestIndex() != NULL);

    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;

    // Strictly increasing timestamps, so the parent's median-time-past is well
    // below its own time and cannot be what decides either arm.
    BOOST_REQUIRE_MESSAGE(MineSpacedBlocks(CBlockIndex::nMedianTimeSpan + 1, 10),
                          "could not build the spaced fixture");

    const CBlockIndex* pindexParent = BestIndex();
    const int64_t nParentTime = pindexParent->GetBlockTime();
    const int64_t nParentMedian = pindexParent->GetPastTimeLimit();
    BOOST_REQUIRE_MESSAGE(nParentMedian < nParentTime,
        "the fixture's median-time-past (" << nParentMedian << ") is not below the "
        "parent's own time (" << nParentTime << "), so a same-second child would "
        "be refused by the median leg and this case would prove nothing");

    const Offer same = OfferBlockAt(nParentTime);
    BOOST_REQUIRE_MESSAGE(same.fBuilt, "could not build the same-second child");
    BOOST_REQUIRE_MESSAGE(same.fStamped, "the grind moved the timestamp under test");
    BOOST_CHECK_MESSAGE(same.fAccepted,
        "a block carrying its parent's timestamp must be accepted -- there is no "
        "per-block minimum spacing; log: " << same.strLog);

    // Positive control, on the same rule and the same code path: a timestamp at
    // or below the median IS refused, and refused by the timestamp branch. If
    // this passed too, the acceptance above would not be evidence of anything.
    const Offer stale = OfferBlockAt(nParentMedian);
    BOOST_REQUIRE_MESSAGE(stale.fBuilt, "could not build the stale-timestamp child");
    BOOST_CHECK_MESSAGE(!stale.fAccepted,
        "a block at the median-time-past must be refused; log: " << stale.strLog);
    BOOST_CHECK_MESSAGE(stale.strLog.find("block's timestamp is too early") != std::string::npos,
        "the refusal did not come from the timestamp rule; log: " << stale.strLog);
}

// The ceiling. Six blocks may share one timestamp; the seventh may not, because
// by then the eleven-block median has reached that second. This is the only
// bound consensus places on how fast blocks may be stamped.
BOOST_AUTO_TEST_CASE(six_blocks_may_share_a_timestamp_and_the_seventh_may_not)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(BestIndex() != NULL);

    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;

    BOOST_REQUIRE_MESSAGE(MineSpacedBlocks(CBlockIndex::nMedianTimeSpan + 1, 10),
                          "could not build the spaced fixture");

    // One second past everything the median window can see, so the run starts
    // from a clean second.
    const int64_t nShared = MaxTimeInMedianWindow(BestIndex()) + 1;
    const int nStartHeight = BestIndex()->nHeight;

    for (int i = 1; i <= 6; i++)
    {
        const Offer o = OfferBlockAt(nShared);
        BOOST_REQUIRE_MESSAGE(o.fBuilt, "could not build shared-timestamp block " << i);
        BOOST_REQUIRE_MESSAGE(o.fStamped, "the grind moved the timestamp under test");
        BOOST_CHECK_MESSAGE(o.fAccepted,
            "block " << i << " of a shared-timestamp run must be accepted; log: "
            << o.strLog);
        BOOST_REQUIRE_MESSAGE(BestIndex()->nHeight == nStartHeight + i,
            "shared-timestamp block " << i << " did not become the tip");
    }

    // The median has now reached the shared second, so the seventh is refused.
    const Offer seventh = OfferBlockAt(nShared);
    BOOST_REQUIRE_MESSAGE(seventh.fBuilt, "could not build the seventh block");
    BOOST_CHECK_MESSAGE(BestIndex()->GetPastTimeLimit() == nShared,
        "the median should have reached the shared second by the sixth block");
    BOOST_CHECK_MESSAGE(!seventh.fAccepted,
        "a seventh block in the same second must be refused; log: " << seventh.strLog);
    BOOST_CHECK_MESSAGE(seventh.strLog.find("block's timestamp is too early") != std::string::npos,
        "the refusal did not come from the timestamp rule; log: " << seventh.strLog);

    // Positive control: the same block one second later is accepted, so what
    // refused the seventh was the shared second and not exhaustion of the
    // fixture, the wallet, or the block template.
    const Offer next = OfferBlockAt(nShared + 1);
    BOOST_REQUIRE_MESSAGE(next.fBuilt, "could not build the next-second block");
    BOOST_CHECK_MESSAGE(next.fAccepted,
        "the seventh block one second later must be accepted; log: " << next.strLog);
    BOOST_CHECK_MESSAGE(BestIndex()->nHeight == nStartHeight + 7,
        "the next-second block did not extend the chain");
}

// The same ceiling stated generally, on the production median itself rather
// than on one mined fixture: whatever the history underneath, a run of blocks
// sharing a timestamp is cut off after six.
BOOST_AUTO_TEST_CASE(the_median_rule_caps_a_shared_second_at_six_blocks)
{
    const int nSpan = CBlockIndex::nMedianTimeSpan;

    for (int nOlderSpacing = 0; nOlderSpacing <= 30; nOlderSpacing++)
    {
        std::vector<CBlockIndex> vChain;
        vChain.resize(nSpan + 12);

        // Arbitrary older history, including the degenerate case where it too
        // is entirely within one second (nOlderSpacing == 0).
        for (int i = 0; i < nSpan; i++)
        {
            vChain[i].nHeight = i;
            vChain[i].nTime = 1700000000u + (unsigned int)(i * nOlderSpacing);
            vChain[i].pprev = (i == 0) ? NULL : &vChain[i - 1];
        }

        // The shared second starts one past everything the window can see.
        int64_t nShared = 0;
        for (int i = 0; i < nSpan; i++)
            if ((int64_t)vChain[i].nTime > nShared) nShared = vChain[i].nTime;
        nShared += 1;

        int nAccepted = 0;
        for (int i = nSpan; i < nSpan + 12; i++)
        {
            // The median leg of AcceptBlock: strictly greater than the parent's
            // median-time-past.
            if (nShared <= vChain[i - 1].GetPastTimeLimit())
                break;
            vChain[i].nHeight = i;
            vChain[i].nTime = (unsigned int)nShared;
            vChain[i].pprev = &vChain[i - 1];
            nAccepted++;
        }

        BOOST_CHECK_MESSAGE(nAccepted == 6,
            "older spacing " << nOlderSpacing << ": " << nAccepted
            << " blocks could share a timestamp, expected exactly 6");
    }
}

BOOST_AUTO_TEST_SUITE_END()
