// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The collateral scan's advance must not depend on a block body reading, or one
// unreadable block file pins the walk.

#include <boost/test/unit_test.hpp>

#include "collateralnode.h"
#include "main.h"

#include <set>
#include <vector>

BOOST_AUTO_TEST_SUITE(cn_rescan_tests)

namespace {

// A tip-to-genesis index chain of nLength entries, heights nLength down to 1.
struct IndexChain
{
    std::vector<CBlockIndex> vIndex;

    explicit IndexChain(int nLength)
    {
        vIndex.resize(nLength);
        for (int i = 0; i < nLength; i++) {
            vIndex[i].nHeight = i + 1;
            vIndex[i].pprev = (i == 0) ? NULL : &vIndex[i - 1];
        }
    }

    CBlockIndex* Tip() { return vIndex.empty() ? NULL : &vIndex.back(); }
};

// Records the walk and stops it after nBudget visits, so a walk that fails to
// advance reports a failure instead of never returning.
struct WalkRecorder
{
    std::vector<const CBlockIndex*> vVisited;
    size_t nBudget;
    bool fBudgetExhausted;

    explicit WalkRecorder(size_t nBudgetIn)
        : nBudget(nBudgetIn), fBudgetExhausted(false) {}

    bool Over(const CBlockIndex* p)
    {
        vVisited.push_back(p);
        if (vVisited.size() >= nBudget) {
            fBudgetExhausted = true;
            return true;
        }
        return false;
    }

    bool Repeats() const
    {
        std::set<const CBlockIndex*> setSeen(vVisited.begin(), vVisited.end());
        return setSeen.size() != vVisited.size();
    }
};

} // namespace

// Every block skipped: the shape a chain with an unreadable block file takes.
BOOST_AUTO_TEST_CASE(walk_advances_when_every_block_is_skipped)
{
    const int nLength = 64;
    IndexChain chain(nLength);
    WalkRecorder rec(10 * (size_t)nLength);

    const size_t nWalked = CNWalkChain(chain.Tip(), 0,
        [&](const CBlockIndex* p) {
            if (rec.Over(p))
                return CNScanStep::Stop;
            return CNScanStep::Next; // stands in for a failed ReadFromDisk
        });

    BOOST_CHECK_MESSAGE(!rec.fBudgetExhausted,
        "CNWalkChain did not advance past a skipped block: the walk ran to the caller's budget");
    BOOST_CHECK_MESSAGE(!rec.Repeats(),
        "CNWalkChain visited the same index entry more than once");
    BOOST_CHECK_EQUAL(nWalked, (size_t)nLength);
    BOOST_CHECK_EQUAL(rec.vVisited.size(), (size_t)nLength);

    for (size_t i = 0; i < rec.vVisited.size(); i++)
        BOOST_CHECK_EQUAL(rec.vVisited[i]->nHeight, nLength - (int)i);
}

// The walk follows pprev, not the order the entries happen to sit in memory.
BOOST_AUTO_TEST_CASE(walk_follows_pprev_not_storage_order)
{
    const int nLength = 50;
    std::vector<CBlockIndex> vIndex(nLength);
    for (int i = 0; i < nLength; i++) {
        vIndex[i].nHeight = nLength - i; // tip first in storage
        vIndex[i].pprev = (i + 1 < nLength) ? &vIndex[i + 1] : NULL;
    }

    WalkRecorder rec(10 * (size_t)nLength);
    const size_t nWalked = CNWalkChain(&vIndex[0], 0,
        [&](const CBlockIndex* p) {
            if (rec.Over(p))
                return CNScanStep::Stop;
            return CNScanStep::Next;
        });

    BOOST_CHECK_MESSAGE(!rec.fBudgetExhausted, "CNWalkChain stalled walking a reversed layout");
    BOOST_CHECK_MESSAGE(!rec.Repeats(), "CNWalkChain revisited an entry walking a reversed layout");
    BOOST_CHECK_EQUAL(nWalked, (size_t)nLength);
    for (size_t i = 0; i < rec.vVisited.size(); i++)
        BOOST_CHECK_EQUAL(rec.vVisited[i]->nHeight, nLength - (int)i);
}

// A hit ends the walk where it was found, not one entry later.
BOOST_AUTO_TEST_CASE(walk_stops_at_the_visit_that_asks_to_stop)
{
    const int nLength = 40;
    IndexChain chain(nLength);
    WalkRecorder rec(10 * (size_t)nLength);
    const int nStopAtHeight = 33;

    const size_t nWalked = CNWalkChain(chain.Tip(), 0,
        [&](const CBlockIndex* p) {
            if (rec.Over(p))
                return CNScanStep::Stop;
            if (p->nHeight == nStopAtHeight)
                return CNScanStep::Stop;
            return CNScanStep::Next;
        });

    BOOST_CHECK_MESSAGE(!rec.fBudgetExhausted, "CNWalkChain ignored a Stop");
    BOOST_CHECK_EQUAL(nWalked, (size_t)(nLength - nStopAtHeight + 1));
    BOOST_CHECK_EQUAL(rec.vVisited.back()->nHeight, nStopAtHeight);
}

// nStopHeight is exclusive, matching the > comparison the scans used.
BOOST_AUTO_TEST_CASE(walk_honours_the_stop_height)
{
    const int nLength = 30;
    IndexChain chain(nLength);
    WalkRecorder rec(10 * (size_t)nLength);
    const int nStopHeight = 25;

    const size_t nWalked = CNWalkChain(chain.Tip(), nStopHeight,
        [&](const CBlockIndex* p) {
            if (rec.Over(p))
                return CNScanStep::Stop;
            return CNScanStep::Next;
        });

    BOOST_CHECK_MESSAGE(!rec.fBudgetExhausted, "CNWalkChain ran past its stop height");
    BOOST_CHECK_EQUAL(nWalked, (size_t)(nLength - nStopHeight));
    BOOST_CHECK_EQUAL(rec.vVisited.back()->nHeight, nStopHeight + 1);
}

// FindCNPayment walks with nStopHeight 1, so height 1 is never visited.
BOOST_AUTO_TEST_CASE(walk_leaves_the_genesis_entry_alone)
{
    IndexChain chain(4);
    WalkRecorder rec(64);

    const size_t nWalked = CNWalkChain(chain.Tip(), 1,
        [&](const CBlockIndex* p) {
            if (rec.Over(p))
                return CNScanStep::Stop;
            return CNScanStep::Next;
        });

    BOOST_CHECK_EQUAL(nWalked, (size_t)3);
    BOOST_CHECK_EQUAL(rec.vVisited.back()->nHeight, 2);
}

// A null tip and a tip already at the stop height both walk nothing.
BOOST_AUTO_TEST_CASE(walk_visits_nothing_when_there_is_nothing_to_visit)
{
    size_t nCalls = 0;
    const size_t nWalkedNull = CNWalkChain(NULL, 0,
        [&](const CBlockIndex*) { nCalls++; return CNScanStep::Next; });
    BOOST_CHECK_EQUAL(nWalkedNull, (size_t)0);
    BOOST_CHECK_EQUAL(nCalls, (size_t)0);

    IndexChain chain(5);
    const size_t nWalkedBelow = CNWalkChain(chain.Tip(), 5,
        [&](const CBlockIndex*) { nCalls++; return CNScanStep::Next; });
    BOOST_CHECK_EQUAL(nWalkedBelow, (size_t)0);
    BOOST_CHECK_EQUAL(nCalls, (size_t)0);
}

// A chain that ends before the stop height must end the walk, not dereference
// past it.
BOOST_AUTO_TEST_CASE(walk_ends_at_a_chain_shorter_than_the_stop_height)
{
    IndexChain chain(6);
    WalkRecorder rec(64);

    const size_t nWalked = CNWalkChain(chain.Tip(), 0,
        [&](const CBlockIndex* p) {
            if (rec.Over(p))
                return CNScanStep::Stop;
            return CNScanStep::Next;
        });

    BOOST_CHECK_MESSAGE(!rec.fBudgetExhausted, "CNWalkChain did not stop at the end of the chain");
    BOOST_CHECK_EQUAL(nWalked, (size_t)6);
    BOOST_CHECK_EQUAL(rec.vVisited.back()->nHeight, 1);
    BOOST_CHECK(rec.vVisited.back()->pprev == NULL);
}

BOOST_AUTO_TEST_SUITE_END()
