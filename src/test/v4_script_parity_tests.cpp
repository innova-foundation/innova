// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Behaviour below the v5 gates must match v4.3.9.5: SignatureHash out of range,
// FindAndDelete, GetOp push sizes, vector deserialization and the ring-signature
// height. Peer-height views take the lower median so one peer cannot move them.

#include <boost/test/unit_test.hpp>

#include "main.h"
#include "net.h"
#include "script.h"
#include "serialize.h"
#include "v5activation.h"

#include <algorithm>
#include <climits>
#include <string>
#include <vector>

extern uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);

namespace {

struct NetworkGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    NetworkGuard() : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet) {}
    ~NetworkGuard() { fRegTest = fRegTestSaved; fTestNet = fTestNetSaved; }
};

CScript RawScript(const std::vector<unsigned char>& v)
{
    return CScript(v.begin(), v.end());
}

struct PeerSet
{
    std::vector<CNode*> vPeers;

    CNode* Add(int nPort, int nHeight)
    {
        CNode* pnode = new CNode(INVALID_SOCKET, CAddress(CService("203.0.113.41", nPort)), "", false);
        pnode->nVersion = PROTOCOL_VERSION;
        pnode->nPingNonceSent = 1;
        pnode->fStartSync = false;
        pnode->nLastBlockRecv = 0;
        pnode->nChainHeight = nHeight;
        pnode->UpdateBestKnownBlock(nHeight, uint256(0));
        vPeers.push_back(pnode);
        LOCK(cs_vNodes);
        vNodes.push_back(pnode);
        return pnode;
    }

    ~PeerSet()
    {
        LOCK(cs_vNodes);
        for (size_t i = 0; i < vPeers.size(); ++i)
        {
            vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), vPeers[i]), vNodes.end());
            delete vPeers[i];
        }
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(v4_script_parity_tests)

BOOST_AUTO_TEST_CASE(signature_hash_out_of_range_is_one)
{
    CTransaction tx;
    tx.vin.resize(2);
    tx.vout.resize(1);
    CScript scriptCode;
    scriptCode << OP_1;

    // SIGHASH_SINGLE with no matching output.
    BOOST_CHECK(SignatureHash(scriptCode, tx, 1, SIGHASH_SINGLE) == uint256(1));
    BOOST_CHECK(SignatureHash(scriptCode, tx, 1, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY) == uint256(1));
    // nIn past the inputs, any hash type.
    BOOST_CHECK(SignatureHash(scriptCode, tx, 2, SIGHASH_ALL) == uint256(1));
    BOOST_CHECK(SignatureHash(scriptCode, tx, 7, SIGHASH_SINGLE) == uint256(1));
    // In range is an ordinary hash.
    BOOST_CHECK(SignatureHash(scriptCode, tx, 0, SIGHASH_SINGLE) != uint256(1));
    BOOST_CHECK(SignatureHash(scriptCode, tx, 1, SIGHASH_ALL) != uint256(1));
}

BOOST_AUTO_TEST_CASE(find_and_delete_removes_adjacent_duplicates)
{
    // v4: every match at an opcode start is erased, re-checked in place.
    CScript s = RawScript({OP_CODESEPARATOR, OP_CODESEPARATOR, OP_1, OP_CODESEPARATOR});
    CScript b = RawScript({OP_CODESEPARATOR});
    BOOST_CHECK_EQUAL(s.FindAndDelete(b), 3);
    BOOST_CHECK(s == RawScript({OP_1}));

    s = RawScript({OP_1, OP_CODESEPARATOR, OP_CODESEPARATOR, OP_CODESEPARATOR});
    BOOST_CHECK_EQUAL(s.FindAndDelete(b), 3);
    BOOST_CHECK(s == RawScript({OP_1}));

    // Pushed data that looks like the pattern is skipped.
    s = RawScript({0x01, OP_CODESEPARATOR, OP_CODESEPARATOR});
    BOOST_CHECK_EQUAL(s.FindAndDelete(b), 1);
    BOOST_CHECK(s == RawScript({0x01, OP_CODESEPARATOR}));
}

BOOST_AUTO_TEST_CASE(find_and_delete_matches_a_partial_opcode)
{
    // Pattern {push2, 0xab} ends inside the push; v4 still erases it.
    CScript s = RawScript({0x02, 0xab, 0xcd, OP_1});
    CScript b = RawScript({0x02, 0xab});
    BOOST_CHECK_EQUAL(s.FindAndDelete(b), 1);
    BOOST_CHECK(s == RawScript({0xcd, OP_1}));

    // Match at a later opcode start, leaving the tail of the push behind.
    s = RawScript({OP_1, 0x02, 0xab, 0xcd, 0x02, 0xab, 0xcd});
    BOOST_CHECK_EQUAL(s.FindAndDelete(b), 2);
    BOOST_CHECK(s == RawScript({OP_1, 0xcd, 0xcd}));
}

BOOST_AUTO_TEST_CASE(getop_accepts_pushes_over_520_bytes)
{
    std::vector<unsigned char> vData(MAX_SCRIPT_ELEMENT_SIZE + 1, 0x42);
    CScript s;
    s << vData << OP_CHECKMULTISIG << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(s.GetSigOpCount(false), 21U);

    CScript::const_iterator pc = s.begin();
    opcodetype opcode;
    std::vector<unsigned char> vRet;
    BOOST_CHECK(s.GetOp(pc, opcode, vRet));
    BOOST_CHECK_EQUAL(vRet.size(), vData.size());

    CScript push;
    push << vData;
    BOOST_CHECK(push.IsPushOnly());
}

BOOST_AUTO_TEST_CASE(vector_of_transactions_past_5mb_of_objects_deserializes)
{
    const size_t nCount = std::max<size_t>(20000, MAX_VECTOR_SIZE / sizeof(CTransaction) + 1000);
    BOOST_REQUIRE(nCount * sizeof(CTransaction) > MAX_VECTOR_SIZE);

    std::vector<CTransaction> vtx(nCount);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << vtx;
    BOOST_CHECK(ss.size() < MAX_BLOCK_SIZE);

    std::vector<CTransaction> vOut;
    BOOST_CHECK_NO_THROW(ss >> vOut);
    BOOST_CHECK_EQUAL(vOut.size(), nCount);
    BOOST_CHECK(ss.empty());
}

BOOST_AUTO_TEST_CASE(ring_signature_deprecation_is_the_first_v5_gate_on_mainnet)
{
    NetworkGuard guard;

    fRegTest = false; fTestNet = false;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_RINGSIG_DEPRECATION, ShiftMainnetV5Activation(MAINNET_V5_ACTIVATION_BASE));

    fRegTest = false; fTestNet = true;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_RINGSIG_DEPRECATION, 0);

    fRegTest = true; fTestNet = false;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_RINGSIG_DEPRECATION, 0);
}

BOOST_AUTO_TEST_CASE(one_peer_cannot_raise_the_peer_height)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(vNodes.empty());
    const int nHonest = nBestHeight + 1;

    PeerSet peers;
    peers.Add(19601, nHonest);
    peers.Add(19602, INT_MAX);
    BOOST_CHECK_EQUAL(GetNumBlocksOfPeers(), nHonest);
    peers.Add(19603, nHonest);
    BOOST_CHECK_EQUAL(GetNumBlocksOfPeers(), nHonest);
}

BOOST_AUTO_TEST_CASE(one_peer_cannot_hold_the_node_in_initial_download)
{
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_REQUIRE(vNodes.empty());
    NetworkGuard guard;
    // Testnet: no checkpoint floor and no regtest short-circuit.
    fRegTest = false; fTestNet = true;
    const int nHonest = nBestHeight + 1;

    {
        PeerSet peers;
        peers.Add(19611, nHonest);
        peers.Add(19612, nHonest);
        CNode* pAttacker = peers.Add(19613, INT_MAX);
        BOOST_CHECK(!IsInitialBlockDownload());

        // In-flight work does not let it claim catch-up either.
        pAttacker->mapAskFor.insert(std::make_pair(GetTime() * 1000000,
                                                   CInv(MSG_BLOCK, uint256((uint64_t)0x76345001ull))));
        pAttacker->nLastHeightUpdate = GetTime() - 1000;
        BOOST_CHECK(!IsInitialBlockDownload());
    }

    {
        // Control: most peers far ahead is initial download.
        PeerSet peers;
        peers.Add(19621, nBestHeight + 100000);
        peers.Add(19622, nBestHeight + 100000);
        peers.Add(19623, nHonest);
        BOOST_CHECK(IsInitialBlockDownload());
    }
}

BOOST_AUTO_TEST_SUITE_END()
