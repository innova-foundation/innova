// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Owner-reclaim gates in ConnectInputs, regtest only; rejections are read
// from the log since every gate returns false.

#include <boost/test/unit_test.hpp>

#include "../bulletproof_ac.h"
#include "../curvetree.h"
#include "../dag.h"
#include "../finality.h"
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
                                     STANDARD_SCRIPT_VERIFY_FLAGS, true);
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

// --- the window above the epoch-root transition -------------------------------
//
// Chain state is staged (the records LoadFCMPValidationRoot reads) in a discarded batch.

// Comfortably above RECLAIM_TIMELOCK so a leaf can be aged on either side of it,
// and under Boundary A, which quarantines every legacy shielded version.
int StagedReclaimHeight() { return RECLAIM_TIMELOCK * 2; }

// The finalized epoch a spend above the transition validates against, plus the
// curve-tree snapshot its root must match. Returns that root.
uint256 StageFinalizedEpoch(CTxDB& txdb, int nBlockHeight)
{
    const int nAsOfEpoch = GetEpochForHeight(nBlockHeight) - 1;
    BOOST_REQUIRE_MESSAGE(nAsOfEpoch >= 0,
        "height " << nBlockHeight << " has no preceding epoch to finalize");
    // nFinalizedHeightAsOf 0 lands back in epoch 0, so one record answers both
    // the as-of lookup and the finalized-epoch read whenever nAsOfEpoch is 0.
    BOOST_REQUIRE_EQUAL(nAsOfEpoch, 0);

    std::vector<unsigned char> vchBlind;
    BOOST_REQUIRE(GenerateBlindingFactor(vchBlind));
    CPedersenCommitment leaf;
    BOOST_REQUIRE(CreatePedersenCommitment(RECLAIM_NOTE_VALUE, vchBlind, leaf));
    CCurveTree tree;
    BOOST_REQUIRE(tree.InsertLeaf(leaf));
    // Rebuilt the way the loader rebuilds it, so the root written here is the
    // root it will compute.
    BOOST_REQUIRE(tree.RebuildParentNodes());
    const uint256 hashRoot = tree.GetRoot();
    BOOST_REQUIRE(hashRoot != 0);

    CEpochState state;
    state.nEpoch = nAsOfEpoch;
    state.nFinalizedHeightAsOf = 0;
    state.hashCurveRoot = hashRoot;
    BOOST_REQUIRE(txdb.WriteEpochState(nAsOfEpoch, state));
    BOOST_REQUIRE(txdb.WriteCurveTreeAtEpoch(nAsOfEpoch, tree));
    return hashRoot;
}

// The four records the timelock reads about the note's leaf: its reverse index,
// the count that bounds it, the commitment stored under it, and the height it
// was inserted at.
void StageLeaf(CTxDB& txdb, const ReclaimNote& note, uint64_t nLeafIdx,
               int nLeafHeight)
{
    BOOST_REQUIRE(txdb.WriteShieldedCommitmentIndex(note.cv.vchCommitment,
                                                    nLeafIdx));
    BOOST_REQUIRE(txdb.WriteShieldedCommitmentCount(nLeafIdx + 1));
    BOOST_REQUIRE(txdb.WriteShieldedCommitment(nLeafIdx, note.cv));
    BOOST_REQUIRE(txdb.WriteShieldedCommitmentHeight(nLeafIdx, nLeafHeight));
}

// Validate against staged state on the same CTxDB, then discard every write.
Outcome RunConnectInputsStaged(CTransaction& tx, const CBlockIndex* pindex,
                               const ReclaimNote& note, int nLeafHeight,
                               bool fStageLeaf)
{
    Outcome out;
    CTxDB txdb("r+");
    BOOST_REQUIRE(txdb.TxnBegin());
    const uint256 hashRoot = StageFinalizedEpoch(txdb, pindex->nHeight);
    for (size_t i = 0; i < tx.vShieldedSpend.size(); ++i)
        tx.vShieldedSpend[i].curveTreeRoot = hashRoot;
    if (fStageLeaf)
        StageLeaf(txdb, note, 0, nLeafHeight);

    MapPrevTx mapInputs;
    std::map<uint256, CTxIndex> mapTestPool;
    {
        CLogCapture capture;
        out.fAccepted = tx.ConnectInputs(txdb, mapInputs, mapTestPool,
                                         CDiskTxPos(1, 1, 1), pindex, false,
                                         false, STANDARD_SCRIPT_VERIFY_FLAGS,
                                         true);
        out.strLog = capture.Release();
    }
    BOOST_REQUIRE(txdb.TxnAbort());
    return out;
}

void CheckStagedRejectedBy(CTransaction& tx, const CBlockIndex* pindex,
                           const ReclaimNote& note, int nLeafHeight,
                           bool fStageLeaf, const char* pszReason,
                           const std::string& strCase)
{
    Outcome out = RunConnectInputsStaged(tx, pindex, note, nLeafHeight, fStageLeaf);
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

// Delegation-hash gate, above the transition with staged state; nothing ahead of it
// fires. The control with a recomputing hash passes the gate.
BOOST_AUTO_TEST_CASE(a_reclaim_above_the_transition_reaches_its_own_gates)
{
    RequireReclaimWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    ReclaimTipGuard guard(StagedReclaimHeight());
    BOOST_REQUIRE_GE(guard.tip.nHeight, ReclaimHeight());
    BOOST_REQUIRE_GE(guard.tip.nHeight, FORK_HEIGHT_EPOCH_ROOT_FCMP);
    BOOST_REQUIRE_LT(guard.tip.nHeight + 1, FORK_HEIGHT_BOUNDARY_A);

    const ReclaimNote note = MakeNote();

    CTransaction tampered = BuildReclaimTx(note, true);
    tampered.reclaimAuth.delegationHash =
        tampered.reclaimAuth.delegationHash ^ uint256(1);
    CheckStagedRejectedBy(tampered, &guard.tip, note, 0, true, RC_BAD_HASH,
                          "delegation hash that does not recompute");

    CTransaction genuine = BuildReclaimTx(note, true);
    Outcome control = RunConnectInputsStaged(genuine, &guard.tip, note,
                                             guard.tip.nHeight - RECLAIM_TIMELOCK,
                                             true);
    BOOST_CHECK_MESSAGE(!control.fAccepted,
        "the control was accepted; it is meant to be refused further down");
    for (size_t i = 0; i < 7; ++i)
        BOOST_CHECK_MESSAGE(!LogHas(control.strLog, RC_ALL[i]),
            std::string("a fully formed reclaim tripped a reclaim gate: ") +
            RC_ALL[i] + "; captured: " + Excerpt(control.strLog));
}

// A reclaim naming a note absent from the commitment index is refused.
BOOST_AUTO_TEST_CASE(an_owner_reclaim_of_an_unindexed_leaf_is_refused)
{
    RequireReclaimWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    ReclaimTipGuard guard(StagedReclaimHeight());
    const ReclaimNote note = MakeNote();
    CTransaction tx = BuildReclaimTx(note, true);
    CheckStagedRejectedBy(tx, &guard.tip, note, 0, false, RC_NO_LEAF,
                          "reclaim of a leaf the index does not carry");
}

// The inactivity timelock. The two arms differ only by one block of
// leaf-insertion height; the accepted arm prints no reclaim message.
BOOST_AUTO_TEST_CASE(an_owner_reclaim_before_the_inactivity_timelock_is_refused)
{
    RequireReclaimWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    ReclaimTipGuard guard(StagedReclaimHeight());
    const int nHeight = guard.tip.nHeight;
    BOOST_REQUIRE_MESSAGE(nHeight - RECLAIM_TIMELOCK >= 0,
        "the staged height is too low for a leaf to reach the timelock");

    const ReclaimNote note = MakeNote();

    // One block short: the leaf has aged RECLAIM_TIMELOCK - 1 blocks.
    CTransaction tooYoung = BuildReclaimTx(note, true);
    CheckStagedRejectedBy(tooYoung, &guard.tip, note,
                          nHeight - RECLAIM_TIMELOCK + 1, true, RC_TIMELOCK,
                          "leaf one block short of the timelock");

    // Exactly aged: the timelock is satisfied and no reclaim gate answers.
    CTransaction aged = BuildReclaimTx(note, true);
    Outcome out = RunConnectInputsStaged(aged, &guard.tip, note,
                                         nHeight - RECLAIM_TIMELOCK, true);
    for (size_t i = 0; i < 7; ++i)
        BOOST_CHECK_MESSAGE(!LogHas(out.strLog, RC_ALL[i]),
            std::string("a leaf aged exactly RECLAIM_TIMELOCK tripped ") +
            RC_ALL[i] + "; captured: " + Excerpt(out.strLog));
}

// The ladder arithmetic the two windows rest on.
BOOST_AUTO_TEST_CASE(the_reclaim_windows_are_where_the_ladder_puts_them)
{
    RequireReclaimWindow();
    BOOST_REQUIRE(fRegTest && !fTestNet);

    BOOST_CHECK_MESSAGE(
        ReclaimHeight() > FORK_HEIGHT_EPOCH_ROOT_FCMP,
        "the reclaim fork has moved below the epoch-root FCMP transition; the "
        "staged-epoch fixture is no longer what the gates past the shielded-spend "
        "check need");
    BOOST_CHECK_MESSAGE(
        SpendableReclaimWindowHeight() < ReclaimHeight(),
        "the window below the epoch-root transition no longer sits under the "
        "reclaim fork, so the height arm above has stopped exercising the gate");
    BOOST_CHECK_MESSAGE(
        SpendableReclaimWindowHeight() >= FORK_HEIGHT_FCMP_VALIDATION &&
            SpendableReclaimWindowHeight() >= FORK_HEIGHT_SHIELDED,
        "the window has dropped below the gates a shielded spend needs");
    BOOST_CHECK_MESSAGE(
        StagedReclaimHeight() >= ReclaimHeight() &&
            StagedReclaimHeight() >= FORK_HEIGHT_EPOCH_ROOT_FCMP &&
            StagedReclaimHeight() + 1 < FORK_HEIGHT_BOUNDARY_A,
        "the staged window has left the range where a reclaim is admissible");
    BOOST_CHECK_MESSAGE(
        GetEpochForHeight(StagedReclaimHeight()) == 1,
        "the staged height no longer sits in the first post-DAG epoch, so one "
        "epoch-state record no longer answers both reads the loader makes");
}

BOOST_AUTO_TEST_SUITE_END()
