// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Behavioural cover for the owner-reclaim gates in CTransaction::ConnectInputs
// (R-RECL-001).
//
// A reclaim spends an idle M-of-N cold-stake note by owner authority instead of
// the quorum's, and it is what opens the cv_plain carve-out on the spend path.
// Everything guarding that carve-out is a fail-closed check in one block: the
// fork height, a shielded spend, a 33-byte owner key, the recomputed delegation
// hash, the spend key being the owner key, and the leaf's inactivity timelock.
// Reached only on regtest, where the legacy privacy policy is not disabled.
//
// The rejection REASON is read out of the log rather than inferred from the
// return value. Six checks in one block all return false, so "returned false"
// cannot tell one from the next, and a mutation that deletes one would leave
// every arm still passing.
//
// Only the first two of the six are reachable from a unit test, and the ladder
// is why: the reclaim fork sits above the epoch-root FCMP transition, so a
// reclaim carrying a shielded spend loads a finalized epoch state before its own
// gates are read, and no epoch has been finalized on this chain. The window
// below that transition is the one place a reclaim with a real spend reaches the
// height check; the spendless shape reaches the second check at any height
// because it skips the root load. The last case pins that arithmetic so the gap
// is reported rather than assumed, and stops being a gap the day the ladder
// moves.

#include <boost/test/unit_test.hpp>

#include "../bulletproof_ac.h"
#include "../main.h"
#include "../nullstake.h"
#include "../shielded.h"
#include "../txdb.h"
#include "../zkproof.h"

#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

namespace {

int ReclaimHeight() { return FORK_HEIGHT_NULLSTAKE_RECLAIM; }

// The highest block at which a shielded spend still binds to the live curve
// tree instead of a finalized epoch snapshot. A function, not a constant: the
// fork getters read fRegTest, which the harness sets after static init.
int SpendableReclaimWindowHeight() { return FORK_HEIGHT_EPOCH_ROOT_FCMP - 1; }

const int64_t RECLAIM_NOTE_VALUE = 1 * COIN;

// Regtest ladder plus a tip at a chosen height, restored on scope exit.
struct ReclaimTipGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    int nBestHeightSaved;
    CBlockIndex* pindexBestSaved;
    CBlockIndex tip;

    explicit ReclaimTipGuard(int nHeight)
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet),
          nBestHeightSaved(nBestHeight), pindexBestSaved(pindexBest)
    {
        fRegTest = true;
        fTestNet = false;
        tip.nHeight = nHeight;
        nBestHeight = nHeight;
        pindexBest = &tip;
    }
    ~ReclaimTipGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
        nBestHeight = nBestHeightSaved;
        pindexBest = pindexBestSaved;
    }
};

// Fails if a ladder edit moves the suite off the window the arms rely on.
void RequireReclaimWindow()
{
    BOOST_REQUIRE(!IsLegacyPrivacyPolicyDisabled());
    BOOST_REQUIRE(ReclaimHeight() >= FORK_HEIGHT_SHIELDED);
    BOOST_REQUIRE(ReclaimHeight() >= FORK_HEIGHT_FCMP_VALIDATION);
    // Boundary A quarantines every legacy shielded version, so the whole window
    // the arms use has to sit below it.
    BOOST_REQUIRE(ReclaimHeight() + 1 < FORK_HEIGHT_BOUNDARY_A);
    BOOST_REQUIRE(SpendableReclaimWindowHeight() >= FORK_HEIGHT_SHIELDED);
    BOOST_REQUIRE(IsLegacyShieldedTransactionVersion(
        SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM));
}

// Routes error()/LogPrintStr to a file for the duration of one validation call.
class CLogCapture
{
public:
    CLogCapture() : nSavedFd(-1), fSavedConsole(fPrintToConsole),
                    fSavedDebugger(fPrintToDebugger)
    {
        strPath = (GetDataDir() / "reclaim-capture.log").string();
        fPrintToConsole = true;
        fPrintToDebugger = false;
        fflush(stdout);
        nSavedFd = dup(STDOUT_FILENO);
        int fd = ::open(strPath.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0)
        {
            dup2(fd, STDOUT_FILENO);
            ::close(fd);
        }
    }

    ~CLogCapture() { Release(); }

    std::string Release()
    {
        if (nSavedFd < 0)
            return strCaptured;
        fflush(stdout);
        dup2(nSavedFd, STDOUT_FILENO);
        ::close(nSavedFd);
        nSavedFd = -1;
        fPrintToConsole = fSavedConsole;
        fPrintToDebugger = fSavedDebugger;
        std::ifstream in(strPath.c_str());
        std::ostringstream ss;
        ss << in.rdbuf();
        strCaptured = ss.str();
        return strCaptured;
    }

private:
    int nSavedFd;
    bool fSavedConsole;
    bool fSavedDebugger;
    std::string strPath;
    std::string strCaptured;
};

struct Outcome
{
    bool fAccepted;
    std::string strLog;
    Outcome() : fAccepted(false) {}
};

Outcome RunConnectInputs(CTransaction& tx, const CBlockIndex* pindex)
{
    Outcome out;
    CTxDB txdb("r+");
    MapPrevTx mapInputs;
    std::map<uint256, CTxIndex> mapTestPool;
    CLogCapture capture;
    out.fAccepted = tx.ConnectInputs(txdb, mapInputs, mapTestPool,
                                     CDiskTxPos(1, 1, 1), pindex, false, false,
                                     STANDARD_SCRIPT_VERIFY_FLAGS, true, true);
    out.strLog = capture.Release();
    return out;
}

bool LogHas(const std::string& strLog, const std::string& strNeedle)
{
    return strLog.find(strNeedle) != std::string::npos;
}

std::string Excerpt(const std::string& strLog)
{
    std::string s;
    size_t pos = 0;
    while (pos < strLog.size())
    {
        size_t nl = strLog.find('\n', pos);
        if (nl == std::string::npos)
            nl = strLog.size();
        const std::string line = strLog.substr(pos, nl - pos);
        if (line.compare(0, 7, "ERROR: ") == 0)
            s += line + " | ";
        pos = nl + 1;
    }
    return s.empty() ? std::string("<no ERROR line captured>") : s;
}

const char* RC_BEFORE_FORK = "ConnectInputs() : owner reclaim before fork height";
const char* RC_NO_SPEND    = "ConnectInputs() : owner reclaim has no shielded spend";
const char* RC_BAD_PUBKEY  = "ConnectInputs() : owner reclaim invalid owner pubkey";
const char* RC_BAD_HASH    = "ConnectInputs() : owner reclaim delegation hash mismatch";
const char* RC_NOT_OWNER   = "ConnectInputs() : owner reclaim spend key is not the owner key";
const char* RC_NO_LEAF     = "ConnectInputs() : owner reclaim leaf not found for timelock";
const char* RC_TIMELOCK    = "ConnectInputs() : owner reclaim before inactivity timelock";

// Every message the reclaim block can print, so an arm can assert that the ones
// ahead of the check under test did not fire.
const char* const RC_ALL[7] = {RC_BEFORE_FORK, RC_NO_SPEND, RC_BAD_PUBKEY,
                               RC_BAD_HASH, RC_NOT_OWNER, RC_NO_LEAF,
                               RC_TIMELOCK};

void CheckRejectedBy(CTransaction& tx, const CBlockIndex* pindex,
                     const char* pszReason, const std::string& strCase)
{
    Outcome out = RunConnectInputs(tx, pindex);
    BOOST_CHECK_MESSAGE(!out.fAccepted, strCase + ": ConnectInputs ACCEPTED it");
    BOOST_CHECK_MESSAGE(LogHas(out.strLog, pszReason),
        strCase + ": did not reject with \"" + pszReason + "\"; captured: " +
        Excerpt(out.strLog));
    for (size_t i = 0; i < 7; ++i)
        if (std::string(RC_ALL[i]) != std::string(pszReason))
            BOOST_CHECK_MESSAGE(!LogHas(out.strLog, RC_ALL[i]),
                strCase + ": a second reclaim gate also fired (" +
                std::string(RC_ALL[i]) + ")");
}

// A note whose commitment and nullifier point are genuine, so the reclaim block
// is the only thing with a reason to reject.
struct ReclaimNote
{
    int64_t nValue;
    std::vector<unsigned char> vchBlind;
    CPedersenCommitment cv;
    std::vector<unsigned char> vchNfPoint;
};

ReclaimNote MakeNote()
{
    ReclaimNote note;
    note.nValue = RECLAIM_NOTE_VALUE;
    BOOST_REQUIRE(GenerateBlindingFactor(note.vchBlind));
    BOOST_REQUIRE(CreatePedersenCommitment(note.nValue, note.vchBlind, note.cv));
    BOOST_REQUIRE(ComputeNullifierPoint(note.vchBlind, note.vchNfPoint));
    return note;
}

uint256 MakeAnchor()
{
    const uint256 anchor = GetRandHash();
    CTxDB txdb("r+");
    BOOST_REQUIRE(txdb.WriteShieldedAnchor(anchor));
    return anchor;
}

// The FCMP root load runs for every FCMP-era spend and fails on an absent or
// empty tree, so one leaf is seeded once.
void EnsureCurveTree()
{
    static bool fSeeded = false;
    if (fSeeded)
        return;
    CTxDB txdb("r+");
    CCurveTree tree;
    if (!txdb.ReadCurveTree(tree) || tree.IsEmpty())
    {
        std::vector<unsigned char> vchBlind;
        BOOST_REQUIRE(GenerateBlindingFactor(vchBlind));
        CPedersenCommitment leaf;
        BOOST_REQUIRE(CreatePedersenCommitment(RECLAIM_NOTE_VALUE, vchBlind, leaf));
        CCurveTree seeded;
        BOOST_REQUIRE(seeded.InsertLeaf(leaf));
        BOOST_REQUIRE(txdb.WriteCurveTree(seeded));
    }
    fSeeded = true;
}

// A 33-byte compressed key whose private half this process holds.
std::vector<unsigned char> OwnerKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key.GetPubKey().Raw();
}

// The delegation set an owner reveals, and the hash consensus recomputes from it.
void FillReclaimAuth(CNullStakeReclaimAuth& auth,
                     const std::vector<unsigned char>& vchOwner)
{
    auth.vStakerSet.clear();
    auth.vStakerSet.push_back(OwnerKey());
    auth.vStakerSet.push_back(OwnerKey());
    std::sort(auth.vStakerSet.begin(), auth.vStakerSet.end());
    auth.nThresholdM = 2;
    auth.vchPkOwner = vchOwner;
    BOOST_REQUIRE(ComputeNullStakeV3DelegationSetHash(
        auth.vStakerSet, auth.nThresholdM, auth.vchPkOwner, auth.delegationHash));
}

// A reclaim transaction whose every field ahead of the gate under test is
// genuine: one shielded spend of a real note, a real anchor, a delegation hash
// that recomputes, and a spend key equal to the owner key.
CTransaction BuildReclaimTx(const ReclaimNote& note, bool fWithSpend)
{
    EnsureCurveTree();

    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM;
    tx.nTime = (unsigned int)GetAdjustedTime();
    tx.nPrivacyMode = PRIVACY_HIDE_AMOUNT | PRIVACY_HIDE_RECEIVER;
    tx.nValueBalance = fWithSpend ? note.nValue : 0;

    const std::vector<unsigned char> vchOwner = OwnerKey();
    FillReclaimAuth(tx.reclaimAuth, vchOwner);

    if (!fWithSpend)
        return tx;

    tx.vShieldedSpend.resize(1);
    CShieldedSpendDescription& sp = tx.vShieldedSpend[0];
    sp.cv = note.cv;
    sp.anchor = MakeAnchor();
    BOOST_REQUIRE(CreateBulletproofRangeProof(note.nValue, note.vchBlind, note.cv,
                                              sp.rangeProof));
    sp.vchNullifierPoint = note.vchNfPoint;
    sp.nullifier = NullifierTagFromPoint(note.vchNfPoint);

    const uint256 sighash = tx.GetBindingSigHash();
    BOOST_REQUIRE(CreateNullifierBindingProof(note.nValue, note.vchBlind, note.cv,
                                              note.vchNfPoint, sighash,
                                              sp.vchNullifierBindingProof));
    // The owner authorization is the spend-auth signature itself, so rk is the
    // owner key rather than a fresh one.
    sp.vchRk = vchOwner;
    sp.vchSpendAuthSig.assign(64, 0);

    std::vector<std::vector<unsigned char> > vInBlinds(1, note.vchBlind);
    std::vector<std::vector<unsigned char> > vOutBlinds;
    BOOST_REQUIRE(CreateBindingSignature(vInBlinds, vOutBlinds, sighash,
                                         tx.bindingSig.bindingSig));
    return tx;
}

} // namespace

BOOST_AUTO_TEST_SUITE(nullstake_reclaim_gate_tests)

// Below the reclaim fork a reclaim-shaped tx is refused by the height gate. The control
// (same spend, non-reclaim version) is refused later with no reclaim message.
BOOST_AUTO_TEST_CASE(a_reclaim_below_its_fork_height_is_refused)
{
    RequireReclaimWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    ReclaimTipGuard guard(SpendableReclaimWindowHeight());
    BOOST_REQUIRE_LT(guard.tip.nHeight, ReclaimHeight());

    const ReclaimNote note = MakeNote();
    CTransaction tx = BuildReclaimTx(note, true);
    BOOST_REQUIRE(tx.IsMofNReclaim());
    BOOST_REQUIRE(tx.IsShielded());
    CheckRejectedBy(tx, &guard.tip, RC_BEFORE_FORK, "below the reclaim fork");

    // Control: ordinary FCMP-era version; no reclaim message fires.
    CTransaction txPlain = BuildReclaimTx(note, true);
    txPlain.nVersion = SHIELDED_TX_VERSION_FCMP;
    BOOST_REQUIRE(!txPlain.IsMofNReclaim());
    Outcome control = RunConnectInputs(txPlain, &guard.tip);
    BOOST_CHECK_MESSAGE(!control.fAccepted,
        "the control was accepted; it is meant to be refused further down");
    for (size_t i = 0; i < 7; ++i)
        BOOST_CHECK_MESSAGE(!LogHas(control.strLog, RC_ALL[i]),
            std::string("a non-reclaim tripped a reclaim gate: ") + RC_ALL[i] +
            "; captured: " + Excerpt(control.strLog));
}

// A reclaim must carry a shielded spend. Reachable at any height (no root load);
// asserted at the fork height and one above.
BOOST_AUTO_TEST_CASE(a_reclaim_without_a_shielded_spend_is_refused)
{
    RequireReclaimWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    const ReclaimNote note = MakeNote();
    for (int nOffset = 0; nOffset <= 1; ++nOffset)
    {
        ReclaimTipGuard guard(ReclaimHeight() + nOffset);
        CTransaction tx = BuildReclaimTx(note, false);
        BOOST_REQUIRE(tx.IsMofNReclaim());
        BOOST_REQUIRE(tx.vShieldedSpend.empty());
        CheckRejectedBy(tx, &guard.tip, RC_NO_SPEND,
                        strprintf("spendless reclaim at fork + %d", nOffset));
    }
}

// Where the other four gates went. A reclaim that carries a spend loads the
// finalized epoch curve-tree snapshot before its own block is reached, and above
// the epoch-root transition that snapshot is the chain's, not this fixture's --
// so the owner-key check, the delegation-hash recomputation, the owner-key match
// and the inactivity timelock have no unit-testable window on this ladder. The
// regtest script drives them against a chain that has finalized an epoch.
//
// Written as an arithmetic assertion rather than a comment so that moving the
// reclaim fork below the transition, or moving the transition above it, turns
// this case red instead of leaving a stale note in a header.
BOOST_AUTO_TEST_CASE(the_gates_past_the_spend_check_need_a_finalized_epoch)
{
    RequireReclaimWindow();
    BOOST_REQUIRE(fRegTest && !fTestNet);

    BOOST_CHECK_MESSAGE(
        ReclaimHeight() > FORK_HEIGHT_EPOCH_ROOT_FCMP,
        "the reclaim fork has moved below the epoch-root FCMP transition; the "
        "gates past the shielded-spend check are now reachable from a unit test "
        "and this suite should cover them");
    BOOST_CHECK_MESSAGE(
        SpendableReclaimWindowHeight() < ReclaimHeight(),
        "the window below the epoch-root transition no longer sits under the "
        "reclaim fork, so the height arm above has stopped exercising the gate");
    BOOST_CHECK_MESSAGE(
        SpendableReclaimWindowHeight() >= FORK_HEIGHT_FCMP_VALIDATION &&
            SpendableReclaimWindowHeight() >= FORK_HEIGHT_SHIELDED,
        "the window has dropped below the gates a shielded spend needs");
}

BOOST_AUTO_TEST_SUITE_END()
