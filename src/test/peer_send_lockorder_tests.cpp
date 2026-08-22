// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

#include "dandelion.h"
#include "main.h"
#include "net.h"
#include "protocol.h"
#include "util.h"

#include <algorithm>

// SendMessages runs with a peer's cs_vSend held, so it must not take cs_vNodes (fan-out
// order is cs_vNodes then cs_vSend). Global relay work lives in SendMessagesGlobal.

BOOST_AUTO_TEST_SUITE(peer_send_lockorder_tests)

namespace {

volatile bool g_fNodesLockHeld = false;

void HoldVNodesLock(int nHoldMs)
{
    LOCK(cs_vNodes);
    g_fNodesLockHeld = true;
    MilliSleep(nHoldMs);
    g_fNodesLockHeld = false;
}

// A stem entry old enough to have timed out, with its inv in the relay map:
// this is what drives the send path into the fluff fan-out.
uint256 ArmTimedOutStem(int64_t nBase)
{
    SetMockTime(nBase);
    uint256 hash = GetRandHash();
    BOOST_REQUIRE(dandelionState.AddTransaction(hash, false, false));
    {
        LOCK(cs_mapRelay);
        mapRelay.insert(std::make_pair(CInv(MSG_TX, hash),
                                       CDataStream(SER_NETWORK, PROTOCOL_VERSION)));
    }
    SetMockTime(nBase + 24 * 60 * 60);
    return hash;
}

void DisarmStem(const uint256& hash)
{
    SetMockTime(0);
    {
        LOCK(cs_mapRelay);
        mapRelay.erase(CInv(MSG_TX, hash));
    }
    dandelionState.RemoveTransaction(hash);
}

} // namespace

BOOST_AUTO_TEST_CASE(send_messages_does_not_wait_on_cs_vnodes)
{
    const uint256 hash = ArmTimedOutStem(1600000000);

    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 18444)), "", false);
    node.nVersion = PROTOCOL_VERSION;
    node.nPingNonceSent = 1; // the socket is not real, so send no ping

    g_fNodesLockHeld = false;
    boost::thread holder(boost::bind(&HoldVNodesLock, 3000));
    for (int i = 0; i < 1000 && !g_fNodesLockHeld; i++)
        MilliSleep(5);
    BOOST_REQUIRE(g_fNodesLockHeld);

    const int64_t nStart = GetTimeMillis();
    {
        LOCK(node.cs_vSend);
        SendMessages(&node, false);
    }
    const int64_t nElapsed = GetTimeMillis() - nStart;

    holder.join();
    DisarmStem(hash);

    BOOST_CHECK_MESSAGE(nElapsed < 1000,
        "SendMessages took " << nElapsed << " ms with a peer's cs_vSend held while "
        "another thread held cs_vNodes: the peer send path is waiting on cs_vNodes, "
        "which deadlocks against every cs_vNodes -> cs_vSend fan-out");
}

BOOST_AUTO_TEST_CASE(send_messages_global_still_fluffs_a_timed_out_stem)
{
    const uint256 hash = ArmTimedOutStem(1600000000);
    const CInv inv(MSG_TX, hash);

    CNode node(INVALID_SOCKET, CAddress(CService("127.0.0.1", 18445)), "", false);
    node.nVersion = PROTOCOL_VERSION;
    node.nPingNonceSent = 1;
    {
        LOCK(cs_vNodes);
        vNodes.push_back(&node);
    }

    SendMessagesGlobal();

    {
        LOCK(cs_vNodes);
        vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), &node), vNodes.end());
    }

    bool fForced = false;
    {
        LOCK(node.cs_inventory);
        fForced = node.setInventoryForce.count(inv) != 0;
    }
    const EDandelionPhase phase = dandelionState.GetPhase(hash);
    DisarmStem(hash);

    BOOST_CHECK_MESSAGE(fForced,
        "the timed-out stem was not queued to the peer: hoisting the fan-out out of "
        "SendMessages must move the work, not drop it");
    BOOST_CHECK_MESSAGE(phase == DANDELION_FLUFF,
        "the timed-out stem did not transition to fluff");
}

BOOST_AUTO_TEST_SUITE_END()
