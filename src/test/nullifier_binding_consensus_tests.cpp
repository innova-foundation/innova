// R-NB-001: the nullifier-binding checks are unreachable because the FCMP-era rule
// refuses first. Pins that dominance; if it fails, restore the binding cases.

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
    BOOST_REQUIRE(NfBindHeight() < FORK_HEIGHT_DAG);
    BOOST_REQUIRE(NfBindHeight() < FORK_HEIGHT_BOUNDARY_A);
    BOOST_REQUIRE(NfBindHeight() < FORK_HEIGHT_EPOCH_ROOT_FCMP);
    // The spend carries an FCMP-era version only because the FCMP gate sits at
    // or below the binding gate. If that order flips, a pre-FCMP version is what
    // reaches the rule and these cases stop exercising it.
    BOOST_REQUIRE(NfBindHeight() >= FORK_HEIGHT_FCMP_VALIDATION);
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

// The fixture note is a real leaf, so the spend it builds is well formed in
// every respect the binding checks read. Seeded once.
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

Outcome RunConnectInputs(CTransaction& tx, const CBlockIndex* pindex)
{
    Outcome out;
    CTxDB txdb("r+");
    MapPrevTx mapInputs;
    std::map<uint256, CTxIndex> mapTestPool;
    CLogCapture capture;
    out.fAccepted = tx.ConnectInputs(txdb, mapInputs, mapTestPool, CDiskTxPos(1, 1, 1),
                                     pindex, false, false, STANDARD_SCRIPT_VERIFY_FLAGS,
                                     true);
    out.strLog = capture.Release();
    return out;
}

// The relay mirror of the site above. An isolated pool so an accepted arm cannot
// leak into any other case, and fCheckInputs off so the reason under test is
// reached without this fixture's inputs having to resolve.
Outcome RunMempoolAccept(CTransaction& tx)
{
    Outcome out;
    CTxDB txdb("r");
    CTxMemPool isolatedPool;
    bool fMissingInputs = false;
    CLogCapture capture;
    out.fAccepted = isolatedPool.accept(txdb, tx, false, &fMissingInputs, true);
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

} // namespace

BOOST_AUTO_TEST_SUITE(nullifier_binding_consensus_tests)

const char* CI_FCMP_ERA =
    "FCMP-era membership is unverifiable; the encoding is permanently invalid";

// One block below FORK_HEIGHT_FCMP_VALIDATION the same spend must not hit the rule,
// so the next case's refusals are attributable to it.
BOOST_AUTO_TEST_CASE(the_fcmp_era_rule_is_bounded_by_its_own_height)
{
    NfBindTipGuard guard;
    RequireForkWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    BOOST_REQUIRE_GE(FORK_HEIGHT_FCMP_VALIDATION, 1);
    BOOST_REQUIRE_GE(FORK_HEIGHT_FCMP_VALIDATION - 1, FORK_HEIGHT_SHIELDED);

    SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
    CTransaction tx = BuildValidSpendTx(note);

    CBlockIndex below;
    below.nHeight = FORK_HEIGHT_FCMP_VALIDATION - 1;
    nBestHeight = below.nHeight;
    Outcome out = RunConnectInputs(tx, &below);
    BOOST_CHECK_MESSAGE(!LogHas(out.strLog, CI_FCMP_ERA),
        std::string("the FCMP-era rule fired below its own height, so the case "
                    "below proves nothing about it; captured: ") + Excerpt(out.strLog));
}

// Every shape the binding cases were written for -- the well-formed spend and
// each defect -- is refused by the FCMP-era rule, and no binding reason is ever
// reached. A binding reason appearing here means the site became reachable.
BOOST_AUTO_TEST_CASE(the_fcmp_era_rule_dominates_the_binding_site)
{
    NfBindTipGuard guard;
    RequireForkWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    BOOST_REQUIRE_GE(guard.tip.nHeight, FORK_HEIGHT_FCMP_VALIDATION);
    BOOST_REQUIRE_GE(guard.tip.nHeight, FORK_HEIGHT_NULLIFIER_BINDING);

    for (int nShape = 0; nShape < 8; ++nShape)
    {
        SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
        uint256 nfForged = GetRandHash();
        CTransaction tx = (nShape == 7) ? BuildValidSpendTx(note, &nfForged)
                                        : BuildValidSpendTx(note);
        CShieldedSpendDescription& sp = tx.vShieldedSpend[0];
        std::string strCase;
        switch (nShape)
        {
        case 0: strCase = "a well-formed bound spend"; break;
        case 1: sp.vchNullifierPoint.clear();
                strCase = "no nullifier point"; break;
        case 2: sp.vchNullifierBindingProof.clear();
                strCase = "no binding proof"; break;
        case 3: sp.vchNullifierBindingProof.resize(NULLIFIER_BINDING_PROOF_SIZE - 1);
                strCase = "short binding proof"; break;
        case 4: sp.vchNullifierBindingProof.push_back(0x00);
                strCase = "long binding proof"; break;
        case 5: sp.vchNullifierPoint.resize(NULLIFIER_POINT_SIZE - 1);
                strCase = "short nullifier point"; break;
        case 6: sp.vchNullifierBindingProof[100] ^= 0x01;
                strCase = "tampered binding proof"; break;
        default: strCase = "unbound nullifier tag"; break;
        }

        Outcome out = RunConnectInputs(tx, &guard.tip);
        BOOST_CHECK_MESSAGE(!out.fAccepted,
            strCase + ": ConnectInputs ACCEPTED an FCMP-era shielded spend");
        BOOST_CHECK_MESSAGE(LogHas(out.strLog, CI_FCMP_ERA),
            strCase + ": ConnectInputs did not refuse with the FCMP-era rule; "
            "captured: " + Excerpt(out.strLog));
        BOOST_CHECK_MESSAGE(!LogHas(out.strLog, CI_MISSING) &&
                            !LogHas(out.strLog, CI_MISMATCH) &&
                            !LogHas(out.strLog, CI_FAILED),
            strCase + ": a nullifier-binding reason was reached, so the site is "
            "reachable again and this suite must carry the binding cases; "
            "captured: " + Excerpt(out.strLog));
    }
}

// The relay path refuses with the same rule at or above the FCMP gate and not one block
// below.
BOOST_AUTO_TEST_CASE(the_fcmp_era_rule_is_mirrored_on_the_relay_path)
{
    NfBindTipGuard guard;
    RequireForkWindow();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    const char* kRelay =
        "CTxMemPool::accept() : shielded spend 0 FCMP-era membership is "
        "unverifiable; the encoding is permanently invalid";

    // Below the gate: the rule's height condition is false and its reason must
    // be absent.
    {
        SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
        CTransaction tx = BuildValidSpendTx(note);
        nBestHeight = FORK_HEIGHT_FCMP_VALIDATION - 1;
        Outcome out = RunMempoolAccept(tx);
        BOOST_CHECK_MESSAGE(!LogHas(out.strLog, kRelay),
            std::string("the relay rule fired below its own height, so the arm "
                        "below proves nothing about it; captured: ") + Excerpt(out.strLog));
    }

    // At the gate.
    {
        SpendNote note = MakeNote(NFBIND_NOTE_VALUE);
        CTransaction tx = BuildValidSpendTx(note);
        nBestHeight = guard.tip.nHeight;
        BOOST_REQUIRE_GE(nBestHeight, FORK_HEIGHT_FCMP_VALIDATION);
        Outcome out = RunMempoolAccept(tx);
        BOOST_CHECK_MESSAGE(!out.fAccepted,
            "the relay path ACCEPTED an FCMP-era shielded spend");
        BOOST_CHECK_MESSAGE(LogHas(out.strLog, kRelay),
            std::string("the relay path did not refuse with the FCMP-era rule; "
                        "captured: ") + Excerpt(out.strLog));
    }
}

// Ladder arithmetic: the FCMP gate is below the binding gate, and every legacy shielded
// version at the binding gate is at or above the FCMP version.
BOOST_AUTO_TEST_CASE(neither_binding_site_has_a_reachable_height)
{
    NfBindTipGuard guard;
    BOOST_CHECK_MESSAGE(FORK_HEIGHT_NULLIFIER_BINDING >= FORK_HEIGHT_FCMP_VALIDATION,
        "the binding gate moved below the FCMP gate; ConnectInputs nullifier "
        "binding is reachable again, so extend this suite");
    BOOST_CHECK_MESSAGE(FORK_HEIGHT_NULLIFIER_BINDING - 1 >= FORK_HEIGHT_FCMP_VALIDATION,
        "CTxMemPool::accept nullifier binding is now reachable on regtest; "
        "extend this suite");
    BOOST_CHECK_MESSAGE(NFBIND_TX_VERSION >= SHIELDED_TX_VERSION_FCMP,
        "a pre-FCMP shielded version can carry a spend past the FCMP-era rule; "
        "extend this suite");
}

BOOST_AUTO_TEST_SUITE_END()
