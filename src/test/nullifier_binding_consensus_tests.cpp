// R-NB-001: every shielded spend must carry a nullifier point and a nullifier
// binding proof of the exact expected sizes, enforced in CTransaction::ConnectInputs.
// The rejection REASON is captured from the log, not inferred from the return
// value: error() routes through LogPrintStr, which discards every message unless
// fPrintToConsole or fDebug is set, so a test that only checks "returned false"
// cannot tell this rule apart from any other failure.
//
// The rule's second site, CTxMemPool::accept, has no reachable height on this
// ladder. Its binding check needs nBestHeight+1 >= FORK_HEIGHT_NULLIFIER_BINDING
// while the post-FCMP version reject above it needs nBestHeight <
// FORK_HEIGHT_FCMP_VALIDATION, and regtest orders those gates 8 and 2. The last
// case pins that arithmetic so the gap is reported rather than assumed.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../txdb.h"
#include "../shielded.h"
#include "../zkproof.h"
#include "../curvetree.h"

#include <boost/filesystem.hpp>

#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

namespace {

// A function, not a constant: fork getters read fRegTest, which is set after static
// initialization.
int NfBindHeight() { return FORK_HEIGHT_NULLIFIER_BINDING; }

// FORK_HEIGHT_FCMP_VALIDATION sits below the binding gate on regtest, so the
// spend must carry an FCMP-era version to clear the post-FCMP version reject
// that guards the binding checks.
const int NFBIND_TX_VERSION = SHIELDED_TX_VERSION_FCMP;
const int64_t NFBIND_NOTE_VALUE = 1 * COIN;

// Regtest ladder + a tip at the binding gate, restored on scope exit.
struct NfBindTipGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    int nBestHeightSaved;
    CBlockIndex* pindexBestSaved;
    CBlockIndex tip;

    NfBindTipGuard()
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet),
          nBestHeightSaved(nBestHeight), pindexBestSaved(pindexBest)
    {
        fRegTest = true;
        fTestNet = false;
        tip.nHeight = NfBindHeight();
        nBestHeight = NfBindHeight();
        pindexBest = &tip;
    }
    ~NfBindTipGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
        nBestHeight = nBestHeightSaved;
        pindexBest = pindexBestSaved;
    }
};

// Fail loudly if a ladder or policy edit moves the test off the height where the
// rule is the reason a spend is rejected: the cases would otherwise keep passing
// while exercising a different check.
void RequireForkWindow()
{
    BOOST_REQUIRE(!IsLegacyPrivacyPolicyDisabled());
    BOOST_REQUIRE(NfBindHeight() >= FORK_HEIGHT_SHIELDED);
    BOOST_REQUIRE(NfBindHeight() >= FORK_HEIGHT_NULLIFIER_BINDING);
    BOOST_REQUIRE(NfBindHeight() < FORK_HEIGHT_DAG);
    BOOST_REQUIRE(NfBindHeight() < FORK_HEIGHT_BOUNDARY_A);
    BOOST_REQUIRE(NfBindHeight() < FORK_HEIGHT_EPOCH_ROOT_FCMP);
    BOOST_REQUIRE(NFBIND_TX_VERSION >= SHIELDED_TX_VERSION_FCMP);
    BOOST_REQUIRE(IsLegacyShieldedTransactionVersion(NFBIND_TX_VERSION));
}

// Routes error()/LogPrintStr to a file for the duration of one validation call.
class CLogCapture
{
public:
    CLogCapture() : nSavedFd(-1), fSavedConsole(fPrintToConsole), fSavedDebugger(fPrintToDebugger)
    {
        strPath = (GetDataDir() / "nfbind-capture.log").string();
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
        std::ifstream in(strPath.c_str(), std::ios::binary);
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
};

struct SpendNote
{
    int64_t nValue;
    std::vector<unsigned char> vchBlind;
    CPedersenCommitment cv;
    std::vector<unsigned char> vchNfPoint;
};

SpendNote MakeNote(int64_t nValue)
{
    SpendNote note;
    note.nValue = nValue;
    BOOST_REQUIRE(GenerateBlindingFactor(note.vchBlind));
    BOOST_REQUIRE(CreatePedersenCommitment(nValue, note.vchBlind, note.cv));
    BOOST_REQUIRE(ComputeNullifierPoint(note.vchBlind, note.vchNfPoint));
    BOOST_REQUIRE_EQUAL(note.vchNfPoint.size(), (size_t)NULLIFIER_POINT_SIZE);
    return note;
}

// A fresh anchor with no height record, so the non-strict reader below
// FORK_HEIGHT_EPOCH_STATE_V3 skips MIN_SHIELDED_SPEND_DEPTH.
uint256 MakeAnchor()
{
    uint256 anchor = GetRandHash();
    CTxDB txdb("r+");
    BOOST_REQUIRE(txdb.WriteShieldedAnchor(anchor));
    return anchor;
}

// The FCMP root load runs for every FCMP-era spend regardless of fSkipFCMP and
// fails on an absent or empty tree, so one leaf is seeded once.
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
        BOOST_REQUIRE(CreatePedersenCommitment(NFBIND_NOTE_VALUE, vchBlind, leaf));
        CCurveTree seeded;
        BOOST_REQUIRE(seeded.InsertLeaf(leaf));
        BOOST_REQUIRE(txdb.WriteCurveTree(seeded));
    }
    fSeeded = true;
}

// A well-formed one-note spend (hidden amount, public sender, all fee), so an injected
// defect is the only reason to reject. pNullifierOverride is applied before the sighash
// (the tag is inside GetBindingSigHash).
CTransaction BuildValidSpendTx(const SpendNote& note, const uint256* pNullifierOverride = NULL)
{
    EnsureCurveTree();

    CTransaction tx;
    tx.nVersion = NFBIND_TX_VERSION;
    tx.nTime = (unsigned int)GetAdjustedTime();
    tx.nPrivacyMode = PRIVACY_HIDE_AMOUNT | PRIVACY_HIDE_RECEIVER;
    tx.nValueBalance = note.nValue;
    tx.vShieldedSpend.resize(1);

    CShieldedSpendDescription& sp = tx.vShieldedSpend[0];
    sp.cv = note.cv;
    sp.anchor = MakeAnchor();
    BOOST_REQUIRE(CreateBulletproofRangeProof(note.nValue, note.vchBlind, note.cv, sp.rangeProof));
    sp.vchNullifierPoint = note.vchNfPoint;
    sp.nullifier = pNullifierOverride ? *pNullifierOverride : NullifierTagFromPoint(note.vchNfPoint);

    // vchRk / vchSpendAuthSig / vchNullifierPoint / vchNullifierBindingProof sit
    // outside GetBindingSigHash, so injecting a defect never invalidates the
    // range proof, the spend-auth signature or the binding signature.
    uint256 sighash = tx.GetBindingSigHash();
    BOOST_REQUIRE(CreateNullifierBindingProof(note.nValue, note.vchBlind, note.cv,
                                              note.vchNfPoint, sighash,
                                              sp.vchNullifierBindingProof));
    BOOST_REQUIRE_EQUAL(sp.vchNullifierBindingProof.size(), (size_t)NULLIFIER_BINDING_PROOF_SIZE);

    uint256 skSpend = GetRandHash();
    BOOST_REQUIRE(CreateSpendAuthSignature(skSpend, sighash, sp.vchRk, sp.vchSpendAuthSig));

    std::vector<std::vector<unsigned char> > vInBlinds(1, note.vchBlind);
    std::vector<std::vector<unsigned char> > vOutBlinds;
    BOOST_REQUIRE(CreateBindingSignature(vInBlinds, vOutBlinds, sighash, tx.bindingSig.bindingSig));
    return tx;
}

// fSkipFCMP isolates the binding checks from the membership verifier, which is
// fail-closed in this tree and would otherwise reject every spend before them.
Outcome RunConnectInputs(CTransaction& tx, const CBlockIndex* pindex)
{
    Outcome out;
    CTxDB txdb("r+");
    MapPrevTx mapInputs;
    std::map<uint256, CTxIndex> mapTestPool;
    CLogCapture capture;
    out.fAccepted = tx.ConnectInputs(txdb, mapInputs, mapTestPool, CDiskTxPos(1, 1, 1),
                                     pindex, false, false, STANDARD_SCRIPT_VERIFY_FLAGS,
                                     true, true);
    out.strLog = capture.Release();
    return out;
}

bool LogHas(const std::string& strLog, const std::string& strNeedle)
{
    return strLog.find(strNeedle) != std::string::npos;
}

// Every ERROR line the captured run produced, for the failure message.
std::string Excerpt(const std::string& strLog)
{
    std::string s;
    size_t pos = 0;
    while (pos < strLog.size())
    {
        size_t nl = strLog.find('\n', pos);
        if (nl == std::string::npos)
            nl = strLog.size();
        std::string line = strLog.substr(pos, nl - pos);
        if (line.compare(0, 7, "ERROR: ") == 0)
            s += line + " | ";
        pos = nl + 1;
    }
    return s.empty() ? std::string("<no ERROR line captured>") : s;
}

const char* CI_MISSING  = "ConnectInputs() : shielded spend 0 missing nullifier binding proof (required post-fork)";
const char* CI_MISMATCH = "ConnectInputs() : shielded spend 0 nullifier does not match bound note";
const char* CI_FAILED   = "ConnectInputs() : shielded spend 0 nullifier binding proof failed";

void CheckConnectInputsRejects(CTransaction& tx, const CBlockIndex* pindex,
                               const char* pszReason, const std::string& strCase)
{
    Outcome out = RunConnectInputs(tx, pindex);
    BOOST_CHECK_MESSAGE(!out.fAccepted,
        strCase + ": ConnectInputs ACCEPTED an unbound shielded spend");
    BOOST_CHECK_MESSAGE(LogHas(out.strLog, pszReason),
        strCase + ": ConnectInputs did not reject with \"" + pszReason +
        "\"; captured: " + Excerpt(out.strLog));
}

} // namespace

BOOST_AUTO_TEST_SUITE(nullifier_binding_consensus_tests)

// Positive control: a spend carrying a correct 33-byte point and 130-byte proof
// passes, and none of the binding rejections fire.
BOOST_AUTO_TEST_CASE(valid_bound_spend_is_accepted)
{
    NfBindTipGuard guard;
    RequireForkWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
    CTransaction tx = BuildValidSpendTx(note);

    Outcome ci = RunConnectInputs(tx, &guard.tip);
    BOOST_CHECK_MESSAGE(ci.fAccepted,
        std::string("ConnectInputs rejected a correctly bound spend; captured: ") + Excerpt(ci.strLog));
    BOOST_CHECK(!LogHas(ci.strLog, CI_MISSING));
    BOOST_CHECK(!LogHas(ci.strLog, CI_MISMATCH));
    BOOST_CHECK(!LogHas(ci.strLog, CI_FAILED));
}

// No nullifier point at all.
BOOST_AUTO_TEST_CASE(spend_without_nullifier_point_is_rejected)
{
    NfBindTipGuard guard;
    RequireForkWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
    CTransaction tx = BuildValidSpendTx(note);
    tx.vShieldedSpend[0].vchNullifierPoint.clear();

    CheckConnectInputsRejects(tx, &guard.tip, CI_MISSING, "no nullifier point");
}

// No binding proof at all -- the double-spend case: without it the nullifier is
// an attacker-chosen field and one note spends repeatedly.
BOOST_AUTO_TEST_CASE(spend_without_binding_proof_is_rejected)
{
    NfBindTipGuard guard;
    RequireForkWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
    CTransaction tx = BuildValidSpendTx(note);
    tx.vShieldedSpend[0].vchNullifierBindingProof.clear();

    CheckConnectInputsRejects(tx, &guard.tip, CI_MISSING, "no binding proof");
}

// One byte short of NULLIFIER_BINDING_PROOF_SIZE.
BOOST_AUTO_TEST_CASE(spend_with_short_binding_proof_is_rejected)
{
    NfBindTipGuard guard;
    RequireForkWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
    CTransaction tx = BuildValidSpendTx(note);
    tx.vShieldedSpend[0].vchNullifierBindingProof.resize(NULLIFIER_BINDING_PROOF_SIZE - 1);

    CheckConnectInputsRejects(tx, &guard.tip, CI_MISSING, "short binding proof");
}

// One byte over NULLIFIER_BINDING_PROOF_SIZE: the size test must be exact
// equality, not a lower bound.
BOOST_AUTO_TEST_CASE(spend_with_long_binding_proof_is_rejected)
{
    NfBindTipGuard guard;
    RequireForkWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
    CTransaction tx = BuildValidSpendTx(note);
    tx.vShieldedSpend[0].vchNullifierBindingProof.push_back(0x00);
    BOOST_REQUIRE_EQUAL(tx.vShieldedSpend[0].vchNullifierBindingProof.size(),
                        (size_t)NULLIFIER_BINDING_PROOF_SIZE + 1);

    CheckConnectInputsRejects(tx, &guard.tip, CI_MISSING, "long binding proof");
}

// Same exactness requirement on the point.
BOOST_AUTO_TEST_CASE(spend_with_wrong_sized_nullifier_point_is_rejected)
{
    NfBindTipGuard guard;
    RequireForkWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    {
        SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
        CTransaction tx = BuildValidSpendTx(note);
        tx.vShieldedSpend[0].vchNullifierPoint.resize(NULLIFIER_POINT_SIZE - 1);
        CheckConnectInputsRejects(tx, &guard.tip, CI_MISSING, "short nullifier point");
    }
    {
        SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
        CTransaction tx = BuildValidSpendTx(note);
        tx.vShieldedSpend[0].vchNullifierPoint.push_back(0x00);
        CheckConnectInputsRejects(tx, &guard.tip, CI_MISSING, "long nullifier point");
    }
}

// Correct sizes, wrong contents: the size test must not be the only gate.
BOOST_AUTO_TEST_CASE(spend_with_tampered_binding_proof_is_rejected)
{
    NfBindTipGuard guard;
    RequireForkWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
    CTransaction tx = BuildValidSpendTx(note);
    tx.vShieldedSpend[0].vchNullifierBindingProof[100] ^= 0x01;
    BOOST_REQUIRE_EQUAL(tx.vShieldedSpend[0].vchNullifierBindingProof.size(),
                        (size_t)NULLIFIER_BINDING_PROOF_SIZE);

    CheckConnectInputsRejects(tx, &guard.tip, CI_FAILED, "tampered binding proof");
}

// The spent-set key must be the tag of the bound point, not a free field.
BOOST_AUTO_TEST_CASE(spend_with_unbound_nullifier_tag_is_rejected)
{
    NfBindTipGuard guard;
    RequireForkWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
    uint256 nfForged = GetRandHash();
    BOOST_REQUIRE(nfForged != 0);
    BOOST_REQUIRE(nfForged != NullifierTagFromPoint(note.vchNfPoint));
    CTransaction tx = BuildValidSpendTx(note, &nfForged);
    BOOST_REQUIRE(tx.vShieldedSpend[0].nullifier == nfForged);

    CheckConnectInputsRejects(tx, &guard.tip, CI_MISMATCH, "unbound nullifier tag");
}

// The relay site's binding check has no reachable height while the binding gate
// sits at or above the FCMP gate: every height that runs it is already rejected
// by the post-FCMP version check above it, and an FCMP-era version is rejected
// there by the membership verifier instead. When this fails the site became
// reachable and the cases above should be extended to CTxMemPool::accept.
BOOST_AUTO_TEST_CASE(mempool_binding_site_has_no_reachable_height)
{
    NfBindTipGuard guard;
    BOOST_CHECK_MESSAGE(FORK_HEIGHT_NULLIFIER_BINDING - 1 >= FORK_HEIGHT_FCMP_VALIDATION,
        "CTxMemPool::accept nullifier binding is now reachable on regtest; extend this suite");
}

BOOST_AUTO_TEST_SUITE_END()
