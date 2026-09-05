// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Collateralnode gossip edge cases: rate limiter keyed by peer id, maps pruned on
// expiry, outpoint map hard-capped, refusals do not score the peer.
// Runs against the shared regtest fixture; linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <vector>

#include "../collateralnode.h"
#include "../core.h"
#include "../main.h"
#include "../net.h"
#include "../netbase.h"
#include "../serialize.h"
#include "../util.h"

BOOST_AUTO_TEST_SUITE(collateralnode_relay_tests)

namespace {

const int kBasePort = 33400;

// Every peer here is on 127.0.0.1: one address, several peer ids, which is the
// shape the address-keyed limiter collapsed.
CAddress LoopbackAt(int nPort)
{
    return CAddress(CService("127.0.0.1", nPort));
}

// A peer the message handler will serve: versioned, not RFC1918, socketless.
void ArmPeer(CNode& node)
{
    node.nVersion = PROTOCOL_VERSION;
    node.nPingNonceSent = 1;
    node.fRelayTxes = true;
}

void JoinNodes(CNode& node)
{
    LOCK(cs_vNodes);
    vNodes.push_back(&node);
}

void LeaveNodes(CNode& node)
{
    LOCK(cs_vNodes);
    vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), &node), vNodes.end());
}

// An iseg asking for the whole list, as it arrives off the wire.
void AskForList(CNode& node)
{
    CDataStream vRecv(SER_NETWORK, PROTOCOL_VERSION);
    vRecv << CTxIn();
    std::string strCommand = "iseg";
    ProcessMessageCollateralnode(&node, strCommand, vRecv);
}

int MisbehaviourOf(CNode& node)
{
    LOCK(node.cs_nMisbehavior);
    return node.nMisbehavior;
}

COutPoint OutpointNumber(unsigned int n)
{
    uint256 hash = 0;
    hash = n + 1;
    return COutPoint(hash, 0);
}

} // namespace

// Papercut 1. Two peers, one address. The second must get its own slot.
BOOST_AUTO_TEST_CASE(iseg_slot_is_per_peer_not_per_address)
{
    CollateralnodeAskedForClear();

    CNode first(INVALID_SOCKET, LoopbackAt(kBasePort), "", true);
    CNode second(INVALID_SOCKET, LoopbackAt(kBasePort + 1), "", true);
    ArmPeer(first);
    ArmPeer(second);
    BOOST_REQUIRE(first.GetId() != second.GetId());
    BOOST_REQUIRE((CNetAddr)first.addr == (CNetAddr)second.addr);

    JoinNodes(first);
    JoinNodes(second);
    AskForList(first);
    const bool fSecondAllowed = CollateralnodeListRequestAllowed(second.GetId(), GetTime());
    AskForList(second);
    const size_t nSlots = CollateralnodeAskedListSize();
    LeaveNodes(first);
    LeaveNodes(second);

    BOOST_CHECK_MESSAGE(fSecondAllowed,
        "a second peer on 127.0.0.1 was refused the list because the first peer had "
        "just asked: the slot is keyed by address, so one peer's refresh silences "
        "every other peer behind that address");
    BOOST_CHECK_MESSAGE(nSlots == 2,
        "two peers asked and the limiter armed " << nSlots << " slot(s): a slot per "
        "peer id is what stops peers sharing an address from sharing a 60 s budget");
}

// Papercut 4. The refusal is not a protocol violation, so nobody is scored.
BOOST_AUTO_TEST_CASE(a_refused_list_request_scores_nobody)
{
    CollateralnodeAskedForClear();

    CNode node(INVALID_SOCKET, LoopbackAt(kBasePort + 2), "", true);
    ArmPeer(node);
    JoinNodes(node);

    AskForList(node);
    const bool fArmed = !CollateralnodeListRequestAllowed(node.GetId(), GetTime());
    AskForList(node);   // inside the window: refused
    const int nScore = MisbehaviourOf(node);
    const size_t nSlots = CollateralnodeAskedListSize();
    LeaveNodes(node);

    BOOST_CHECK_MESSAGE(fArmed,
        "the first list request did not arm the peer's slot, so the second was not "
        "the refused case this asserts on");
    BOOST_CHECK_MESSAGE(nScore == 0,
        "a peer that asked twice inside the window was scored " << nScore << ": "
        "asking again is what a reconnecting peer does, and scoring it bans honest "
        "peers off a loopback fleet");
    BOOST_CHECK_MESSAGE(nSlots == 1,
        "the refused request armed a second slot for the same peer");
}

// Papercut 2, peer map. A departing peer takes its slot with it, so the map is
// bounded by the live peer count.
BOOST_AUTO_TEST_CASE(a_departing_peer_takes_its_iseg_slot_with_it)
{
    CollateralnodeAskedForClear();

    const int64_t nNow = GetTime();
    size_t nWhileConnected = 0;
    {
        CNode a(INVALID_SOCKET, LoopbackAt(kBasePort + 3), "", true);
        CNode b(INVALID_SOCKET, LoopbackAt(kBasePort + 4), "", true);
        CollateralnodeListRequestRecord(a.GetId(), nNow);
        CollateralnodeListRequestRecord(b.GetId(), nNow);
        nWhileConnected = CollateralnodeAskedListSize();
    }
    const size_t nAfter = CollateralnodeAskedListSize();

    BOOST_CHECK_MESSAGE(nWhileConnected == 2,
        "two connected peers hold " << nWhileConnected << " slots, expected 2");
    BOOST_CHECK_MESSAGE(nAfter == 0,
        "both peers were destroyed and the limiter still holds " << nAfter <<
        " slot(s): nothing else retires a slot early, so the map grows with peer "
        "churn for the life of the process");
}

// Papercut 2, both maps. An expired slot is dropped when it is next read.
BOOST_AUTO_TEST_CASE(expired_slots_are_pruned_on_the_next_read)
{
    CollateralnodeAskedForClear();

    const int64_t nNow = 1600000000;
    CollateralnodeListRequestRecord(7, nNow);
    BOOST_REQUIRE(CollateralnodeEntryRequestRecord(OutpointNumber(1), nNow));
    BOOST_REQUIRE(CollateralnodeAskedListSize() == 1);
    BOOST_REQUIRE(CollateralnodeAskedEntrySize() == 1);

    const bool fListAllowed = CollateralnodeListRequestAllowed(7, nNow + COLLATERALNODE_ISEG_LIST_SECONDS);
    const bool fEntryAllowed = CollateralnodeEntryRequestAllowed(OutpointNumber(1), nNow + COLLATERALNODE_ISEG_ENTRY_SECONDS);

    BOOST_CHECK_MESSAGE(fListAllowed, "a list slot outlived its own window");
    BOOST_CHECK_MESSAGE(fEntryAllowed, "an entry slot outlived its own window");
    BOOST_CHECK_MESSAGE(CollateralnodeAskedListSize() == 0,
        "the expired list slot was still held after the read that answered on it");
    BOOST_CHECK_MESSAGE(CollateralnodeAskedEntrySize() == 0,
        "the expired entry slot was still held after the read that answered on it");
    CollateralnodeAskedForClear();
}

// Papercut 2, outpoint map. An iseep names an unknown vin and arms a slot before
// any signature is checked, so only a cap bounds it.
BOOST_AUTO_TEST_CASE(the_entry_pull_map_is_capped)
{
    CollateralnodeAskedForClear();

    const int64_t nNow = 1600000000;
    const size_t nOffered = COLLATERALNODE_ASKED_ENTRY_MAX + 500;
    size_t nAccepted = 0;
    for (size_t i = 0; i < nOffered; i++)
        if (CollateralnodeEntryRequestRecord(OutpointNumber((unsigned int)i), nNow))
            nAccepted++;
    const size_t nHeld = CollateralnodeAskedEntrySize();
    CollateralnodeAskedForClear();

    BOOST_CHECK_MESSAGE(nHeld <= COLLATERALNODE_ASKED_ENTRY_MAX,
        nOffered << " unknown outpoints left " << nHeld << " slots held, over the "
        << COLLATERALNODE_ASKED_ENTRY_MAX << " cap: an unauthenticated iseep grows "
        "the map, so it has to refuse rather than allocate");
    BOOST_CHECK_MESSAGE(nAccepted == COLLATERALNODE_ASKED_ENTRY_MAX,
        "the cap accepted " << nAccepted << " of " << nOffered << " outpoints, "
        "expected exactly " << COLLATERALNODE_ASKED_ENTRY_MAX);
}

// Papercut 3. The refresh clock is stamped by the request, not by the socket.
BOOST_AUTO_TEST_CASE(the_handshake_request_stamps_the_refresh_clock)
{
    CNode node(INVALID_SOCKET, LoopbackAt(kBasePort + 5), "", false);
    ArmPeer(node);

    // The version handshake can land long after the socket opened: a peer that is
    // still syncing answers late. The constructor stamped nLastDseg at connect.
    const int64_t nHandshakeDelay = 45;
    node.nLastDseg = GetTime() - nHandshakeDelay;

    PushCollateralnodeListRequest(&node);
    const int64_t nRequested = GetTime();

    size_t nIsegSent = 0;
    {
        LOCK(node.cs_vSend);
        for (size_t i = 0; i < node.vSendMsg.size(); i++)
        {
            const CSerializeData& data = node.vSendMsg[i];
            if (data.size() < CMessageHeader::HEADER_SIZE) continue;
            const char* pszCommand = &data[0] + offsetof(CMessageHeader, pchCommand);
            if (strncmp(pszCommand, "iseg", 4) == 0) nIsegSent++;
        }
    }

    const bool fDueEarly = CollateralnodeRefreshDue(node.nLastDseg,
                                                    nRequested + COLLATERALNODE_ISEG_REFRESH_SECONDS - 1);
    const bool fDueOnTime = CollateralnodeRefreshDue(node.nLastDseg,
                                                     nRequested + COLLATERALNODE_ISEG_REFRESH_SECONDS);

    BOOST_CHECK_MESSAGE(nIsegSent == 1,
        "the list request queued " << nIsegSent << " iseg messages, expected 1");
    BOOST_CHECK_MESSAGE(!fDueEarly,
        "the periodic refresh was due " << (COLLATERALNODE_ISEG_REFRESH_SECONDS - 1) <<
        "s after the handshake request, inside the " << COLLATERALNODE_ISEG_REFRESH_SECONDS <<
        "s interval: the clock is anchored to the CNode constructor, so a handshake "
        "that lands " << nHandshakeDelay << "s after connect duplicates its own request");
    BOOST_CHECK_MESSAGE(fDueOnTime,
        "the refresh never came due a full interval after the request");
}

// Papercut 5. The drop the log hid: the tolerance is measured against the tip
// block time, so a stalled chain refuses every registration offered to it.
BOOST_AUTO_TEST_CASE(a_future_sigtime_is_dropped_against_the_tip_time)
{
    const int64_t nTipTime = 1600000000;

    BOOST_CHECK_MESSAGE(!CollateralnodeSigTimeTooFarAhead(nTipTime, nTipTime),
        "an isee stamped at the tip time was dropped");
    BOOST_CHECK_MESSAGE(!CollateralnodeSigTimeTooFarAhead(nTipTime + COLLATERALNODE_SIGTIME_FUTURE_SECONDS, nTipTime),
        "an isee exactly at the tolerance was dropped");
    BOOST_CHECK_MESSAGE(CollateralnodeSigTimeTooFarAhead(nTipTime + COLLATERALNODE_SIGTIME_FUTURE_SECONDS + 1, nTipTime),
        "an isee past the tolerance was accepted");
    // A chain stalled for an hour: a registration signed now is refused by every
    // receiver.
    BOOST_CHECK_MESSAGE(CollateralnodeSigTimeTooFarAhead(nTipTime + 3600, nTipTime),
        "a registration signed an hour past a stalled tip was accepted");
}

// Papercut 6. Relaying an entry learned from a list reply is opt-in, and a fresh
// announcement is relayed either way.
BOOST_AUTO_TEST_CASE(relaying_a_learned_entry_is_opt_in)
{
    const int nFresh = -1;      // a "collateralnode start" broadcast
    const int nFromList = 1;    // served in reply to an iseg, count = list size

    BOOST_CHECK_MESSAGE(CollateralnodeRelayOnAccept(nFresh, false, false),
        "a fresh announcement was not relayed");
    BOOST_CHECK_MESSAGE(CollateralnodeRelayOnAccept(nFresh, false, true),
        "a fresh announcement was not relayed with -cnrelaylearned on");
    BOOST_CHECK_MESSAGE(!CollateralnodeRelayOnAccept(nFromList, false, false),
        "an entry learned from a list reply was relayed with -cnrelaylearned off: "
        "the default has to stay byte-for-byte the current relay behaviour, because "
        "a height-gated release runs beside un-upgraded nodes for weeks");
    BOOST_CHECK_MESSAGE(CollateralnodeRelayOnAccept(nFromList, false, true),
        "an entry learned from a list reply was not relayed with -cnrelaylearned on: "
        "without it every hop of a line costs a full refresh interval");
    BOOST_CHECK_MESSAGE(!CollateralnodeRelayOnAccept(nFresh, true, true),
        "an RFC1918 endpoint was gossiped");
}

BOOST_AUTO_TEST_SUITE_END()
