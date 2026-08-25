#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include "main.h"
#include "net.h"
#include "util.h"

#include <memory>

BOOST_AUTO_TEST_SUITE(block_request_order_tests)

// Builds a bare peer with a nonzero protocol version so SendMessages' getdata
// flush path is actually reached.
static CNode* MakeReadyPeer()
{
    CNode* peer = new CNode(INVALID_SOCKET, CAddress(), "b1-order", false);
    peer->nVersion = PROTOCOL_VERSION;
    return peer;
}

// Snapshots and clears global already-asked state so the suite stays isolated
// from other test suites and from cross-test leakage.
class CScopedAlreadyAsked
{
private:
    std::map<CInv, int64_t> saved;

public:
    CScopedAlreadyAsked()
    {
        LOCK(cs_mapAlreadyAskedFor);
        saved = mapAlreadyAskedFor;
        mapAlreadyAskedFor.clear();
    }
    ~CScopedAlreadyAsked()
    {
        LOCK(cs_mapAlreadyAskedFor);
        mapAlreadyAskedFor = saved;
    }
};

// Fills the per-peer inflight table up to the cap SendMessages enforces.
static void FillInFlightCap(CNode* peer)
{
    for (size_t i = 0; i < 128; ++i)
        peer->MarkBlockInFlight(uint256((uint64_t)(7000 + i)));
}

// Queues a full-block request directly into the per-peer priority queue.
static void QueueBlockRequest(CNode* peer, int64_t nRequestTime, const uint256& hash)
{
    peer->mapAskFor.insert(std::make_pair(nRequestTime, CInv(MSG_BLOCK, hash)));
}

BOOST_AUTO_TEST_CASE(inflight_cap_preserves_front_request)
{
    CScopedAlreadyAsked isIdx;
    std::unique_ptr<CNode> peer(MakeReadyPeer());
    const uint256 hashP((uint64_t)6001);
    const uint256 hashC((uint64_t)6002);
    const uint256 hashD((uint64_t)6003);
    const int64_t nBaseKey = (GetTime() - 10) * 1000000;

    QueueBlockRequest(peer.get(), nBaseKey, hashP);
    QueueBlockRequest(peer.get(), nBaseKey + 1, hashC);
    QueueBlockRequest(peer.get(), nBaseKey + 2, hashD);
    FillInFlightCap(peer.get());
    BOOST_REQUIRE_EQUAL(peer->setBlocksInFlight.size(), 128U);

    BOOST_CHECK(SendMessages(peer.get(), true));

    // Queue size, exact front request and key, and relative order must be
    // unchanged: hitting the cap must not erase/re-add the front request.
    BOOST_REQUIRE_EQUAL(peer->mapAskFor.size(), 3U);
    std::multimap<int64_t, CInv>::const_iterator it = peer->mapAskFor.begin();
    BOOST_CHECK(it->second.hash == hashP);
    BOOST_CHECK_EQUAL(it->first, nBaseKey);
    ++it;
    BOOST_CHECK(it->second.hash == hashC);
    BOOST_CHECK_EQUAL(it->first, nBaseKey + 1);
    ++it;
    BOOST_CHECK(it->second.hash == hashD);
    BOOST_CHECK_EQUAL(it->first, nBaseKey + 2);
}

BOOST_AUTO_TEST_CASE(next_request_sent_after_slot_freed)
{
    CScopedAlreadyAsked isIdx;
    std::unique_ptr<CNode> peer(MakeReadyPeer());
    const uint256 hashP((uint64_t)6011);
    const uint256 hashC((uint64_t)6012);
    const uint256 hashD((uint64_t)6013);
    const int64_t nBaseKey = (GetTime() - 10) * 1000000;

    QueueBlockRequest(peer.get(), nBaseKey, hashP);
    QueueBlockRequest(peer.get(), nBaseKey + 1, hashC);
    QueueBlockRequest(peer.get(), nBaseKey + 2, hashD);
    FillInFlightCap(peer.get());
    SendMessages(peer.get(), true); // at cap; queue must remain P,C,D

    // Free exactly one inflight slot.
    peer->ClearBlockInFlight(uint256((uint64_t)7000));
    BOOST_REQUIRE_EQUAL(peer->setBlocksInFlight.size(), 127U);

    BOOST_CHECK(SendMessages(peer.get(), true));

    // P must be the next request selected/sent: it leaves the queue and is
    // marked inflight. C,D keep their order.
    BOOST_REQUIRE_EQUAL(peer->mapAskFor.size(), 2U);
    std::multimap<int64_t, CInv>::const_iterator it = peer->mapAskFor.begin();
    BOOST_CHECK(it->second.hash == hashC);
    BOOST_CHECK_EQUAL(it->first, nBaseKey + 1);
    ++it;
    BOOST_CHECK(it->second.hash == hashD);
    BOOST_CHECK_EQUAL(it->first, nBaseKey + 2);

    BOOST_CHECK(peer->IsBlockInFlight(hashP));
}

BOOST_AUTO_TEST_CASE(repeated_cap_hits_do_not_reorder_or_duplicate)
{
    CScopedAlreadyAsked isIdx;
    std::unique_ptr<CNode> peer(MakeReadyPeer());
    const uint256 hashP((uint64_t)6021);
    const uint256 hashC((uint64_t)6022);
    const uint256 hashD((uint64_t)6023);
    const int64_t nBaseKey = (GetTime() - 10) * 1000000;

    QueueBlockRequest(peer.get(), nBaseKey, hashP);
    QueueBlockRequest(peer.get(), nBaseKey + 1, hashC);
    QueueBlockRequest(peer.get(), nBaseKey + 2, hashD);
    FillInFlightCap(peer.get());

    for (int i = 0; i < 5; ++i)
        SendMessages(peer.get(), true);

    // Hitting the cap repeatedly must keep queue size, order, and keys stable,
    // and must not duplicate any block hash.
    BOOST_REQUIRE_EQUAL(peer->mapAskFor.size(), 3U);
    std::multimap<int64_t, CInv>::const_iterator it = peer->mapAskFor.begin();
    BOOST_CHECK(it->second.hash == hashP);
    BOOST_CHECK_EQUAL(it->first, nBaseKey);
    ++it;
    BOOST_CHECK(it->second.hash == hashC);
    BOOST_CHECK_EQUAL(it->first, nBaseKey + 1);
    ++it;
    BOOST_CHECK(it->second.hash == hashD);
    BOOST_CHECK_EQUAL(it->first, nBaseKey + 2);
}

BOOST_AUTO_TEST_SUITE_END()