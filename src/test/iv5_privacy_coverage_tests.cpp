// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Privacy gates with no other executing check: each arm pairs an admitted control with a
// one-field negative, reason read from the log. Linked last (shared regtest chain).

#include <boost/test/unit_test.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "../base58.h"
#include "../bignum.h"
#include "../curvetree.h"
#include "../dag.h"
#include "../finality.h"
#include "../hooks.h"
#include "../init.h"
#include "../main.h"
#include "../miner.h"
#include "../nullsend.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../shielded.h"
#include "../txdb.h"
#include "../wallet.h"
#include "../zkproof.h"

extern bool fRegTest;
extern bool fTestNet;

namespace {

// ---------------------------------------------------------------------------
// Globals the gates read, restored on scope exit.
// ---------------------------------------------------------------------------

struct LadderGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    int nBoundaryBSaved;
    bool fRehearsalSaved;
    int nFeeNoteSaved;

    LadderGuard()
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet),
          nBoundaryBSaved(nRegtestBoundaryBHeight),
          fRehearsalSaved(fRegtestShieldedVNextRehearsal),
          nFeeNoteSaved(nRegtestIV5FeeNoteHeight) {}

    ~LadderGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
        nRegtestBoundaryBHeight = nBoundaryBSaved;
        fRegtestShieldedVNextRehearsal = fRehearsalSaved;
        nRegtestIV5FeeNoteHeight = nFeeNoteSaved;
    }

    void SelectMainnet() { fRegTest = false; fTestNet = false; }
    void SelectTestnet() { fRegTest = false; fTestNet = true; }
    void SelectRegtest() { fRegTest = true;  fTestNet = false; }
};

// nBestHeight is not restored: connecting blocks advances it. A case that parks
// the tip artificially must restore it and must not mine.
struct TipHeightGuard
{
    int nSaved;
    TipHeightGuard() : nSaved(nBestHeight) {}
    ~TipHeightGuard() { nBestHeight = nSaved; }
};

// ---------------------------------------------------------------------------
// Rejection reason from error(); several sites share a DoS score.
// ---------------------------------------------------------------------------

class LogCapture
{
public:
    LogCapture() : nSavedFd(-1), fSavedConsole(fPrintToConsole),
                   fSavedDebugger(fPrintToDebugger)
    {
        strPath = (GetDataDir() / "iv5-privacy-capture.log").string();
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

    ~LogCapture() { Release(); }

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

struct Outcome
{
    bool fAccepted;
    std::string strLog;
    Outcome() : fAccepted(false) {}
};

Outcome RunCheckTransaction(CTransaction& tx)
{
    Outcome out;
    tx.nDoS = 0;
    LogCapture capture;
    out.fAccepted = tx.CheckTransaction();
    out.strLog = capture.Release();
    return out;
}

Outcome RunConnectInputs(CTransaction& tx, const CBlockIndex* pindex)
{
    Outcome out;
    tx.nDoS = 0;
    CTxDB txdb("r+");
    MapPrevTx mapInputs;
    std::map<uint256, CTxIndex> mapTestPool;
    LogCapture capture;
    out.fAccepted = tx.ConnectInputs(txdb, mapInputs, mapTestPool,
                                     CDiskTxPos(1, 1, 1), pindex, true, false,
                                     STANDARD_SCRIPT_VERIFY_FLAGS, true);
    out.strLog = capture.Release();
    return out;
}

void ExpectReason(const Outcome& out, const char* pszReason,
                  const std::string& strCase)
{
    BOOST_CHECK_MESSAGE(!out.fAccepted, strCase + ": it was ACCEPTED");
    BOOST_CHECK_MESSAGE(LogHas(out.strLog, pszReason),
        strCase + ": did not reject with \"" + pszReason + "\"; captured: " +
        Excerpt(out.strLog));
}

void ExpectPastReason(const Outcome& out, const char* pszReason,
                      const std::string& strCase)
{
    BOOST_CHECK_MESSAGE(!LogHas(out.strLog, pszReason),
        strCase + ": the gate under test still fired (\"" + pszReason +
        "\"); captured: " + Excerpt(out.strLog));
}

// ---------------------------------------------------------------------------
// IV5 payloads. A shield proves no membership, so it is the cheapest valid payload.
// ---------------------------------------------------------------------------

PrivacyVNextDigest FillDigest(unsigned char c)
{
    PrivacyVNextDigest d;
    d.fill(c);
    return d;
}

PrivacyVNextDigest LocalGenesis()
{
    PrivacyVNextDigest d;
    PrivacyVNextLocalGenesis(d.data());
    return d;
}

uint8_t LocalNetwork() { return PrivacyVNextLocalNetworkId(); }

PrivacyVNextDigest BindingOf(const CTransaction& tx)
{
    PrivacyVNextDigest d;
    const uint256 h = GetPrivacyVNextTransparentBinding(tx);
    std::memcpy(d.data(), h.begin(), 32);
    return d;
}

// A shield payload moving nValueIn into the pool and charging nFee, bound to tx
// as it stands. The recipient is a key this process derives, so the payload is
// one a wallet could actually have produced.
std::vector<unsigned char> BuildShieldPayload(const CTransaction& tx,
                                              uint64_t nValueIn,
                                              uint64_t nFee,
                                              uint8_t nDisclosureMask = 7,
                                              unsigned char nSeed = 0x31)
{
    std::string error;
    const PrivacyVNextDigest genesis = LocalGenesis();
    PrivacyVNextDerivedKeys keys;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(FillDigest(nSeed), genesis, 0, LocalNetwork(), 0,
                               keys, error), error);

    // The same anchor a validator reads before any epoch has carried the pool,
    // and the parameter digest that belongs to it.
    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    BOOST_REQUIRE_EQUAL(epochSeed.vchRoot.size(), 32U);
    PrivacyVNextDigest root;
    std::memcpy(root.data(), &epochSeed.vchRoot[0], 32);
    const uint64_t nTreeSize = epochSeed.nTreeSize;

    std::vector<PrivacyVNextNewOutput> outs;
    outs.resize(1);
    outs[0].recipient.nNetwork = LocalNetwork();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = keys.spendPublic;
    outs[0].recipient.viewPublic = keys.viewPublic;
    outs[0].nAmount = nValueIn - nFee;

    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextShieldPayload(LocalNetwork(), nDisclosureMask, genesis,
                                       keys.outgoingViewSecret, root, nTreeSize,
                                       BindingOf(tx), nValueIn, nFee, outs,
                                       payload, error,
                                       &epochSeed.vchParameterDigest),
        error);
    BOOST_REQUIRE(!payload.empty());
    return payload;
}

// A canonical-envelope transaction carrying a shield payload built under the
// globals in force when it is called.
CTransaction MakeIV5EnvelopeTx(uint64_t nValueIn = 10000, uint64_t nFee = 100)
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_DSP;
    tx.nTime = (unsigned int)GetAdjustedTime();
    tx.privacyVNext.SetPresent();
    tx.privacyVNext.vchPayload = BuildShieldPayload(tx, nValueIn, nFee);
    BOOST_REQUIRE(tx.IsPrivacyVNext());
    BOOST_REQUIRE(!tx.IsShielded());
    return tx;
}

// ---------------------------------------------------------------------------
// Legacy shielded shapes, accepted by CheckTransaction on regtest, used as controls.
// ---------------------------------------------------------------------------

CTransaction MakeDSPShape(int nPrivacyMode)
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_DSP_PROTOTYPE;
    tx.nTime = (unsigned int)GetAdjustedTime();
    tx.nPrivacyMode = (uint8_t)nPrivacyMode;

    CShieldedOutputDescription out;
    if (!DSP_HideAmount((uint8_t)nPrivacyMode))
    {
        out.nPlaintextValue = 1000;
        out.vchPlaintextBlind.assign(BLINDING_FACTOR_SIZE, 0x2a);
    }
    tx.vShieldedOutput.push_back(out);
    return tx;
}


// ---------------------------------------------------------------------------
// The shared regtest chain; later cases mine on it and read per-block records back.
// ---------------------------------------------------------------------------

bool SolveBlock(CBlock* pblock)
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

CBlockIndex* BestIndex()
{
    LOCK(cs_main);
    return pindexBest;
}

void MineTo(int nTarget)
{
    unsigned int nExtraNonce = 0;
    while (BestIndex()->nHeight < nTarget)
    {
        CBlockIndex* pindexPrev = BestIndex();
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        BOOST_REQUIRE(pblock.get() != NULL);
        IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
        BOOST_REQUIRE(SolveBlock(pblock.get()));
        const uint256 hash = pblock->GetHash();
        BOOST_REQUIRE(ProcessBlock(NULL, pblock.get()));
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
    }
}

// The connected block at nHeight on this node's own chain.
CBlockIndex* AncestorAtHeight(int nHeight)
{
    LOCK(cs_main);
    CBlockIndex* p = pindexBest;
    while (p != NULL && p->nHeight > nHeight)
        p = p->pprev;
    return (p != NULL && p->nHeight == nHeight) ? p : NULL;
}

// A block template on the tip with the stack index ConnectBlock is handed. Edit
// it, then Seal: the merkle root and the work are recomputed there, so an arm's
// edit rides a block that is otherwise what the producer emitted.
struct Candidate
{
    CBlock block;
    uint256 hash;
    CBlockIndex index;
    CBlockIndex* pparent;

    Candidate() : pparent(NULL) {}
    CBlockIndex* Index() { return &index; }
    int Height() const { return pparent->nHeight + 1; }
};

CBlockIndex* ParentIndexOf(const CBlock& block)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::const_iterator mi =
        mapBlockIndex.find(block.hashPrevBlock);
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

bool BuildCandidate(Candidate& out)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexParent = ParentIndexOf(*pblock);
    if (pindexParent == NULL)
        return false;
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexParent, nExtraNonce);
    out.block = *pblock;
    out.pparent = pindexParent;
    return true;
}

bool SealCandidate(Candidate& out)
{
    out.block.hashMerkleRoot = out.block.BuildMerkleTree();
    if (!SolveBlock(&out.block))
        return false;
    out.hash = out.block.GetHash();
    out.index = CBlockIndex(0, 0, out.block);
    out.index.pprev = out.pparent;
    out.index.nHeight = out.pparent->nHeight + 1;
    out.index.phashBlock = &out.hash;
    return true;
}

struct ConnectOutcome
{
    CBlock::ConnectResult result;
    std::string strLog;
    ConnectOutcome() : result(CBlock::CONNECT_RESULT_INVALID) {}
    bool Ok() const { return result == CBlock::CONNECT_RESULT_OK; }
};

// Connect and discard every write. Without the abort an accepted arm would spend
// this chain's outputs for the rest of the binary.
ConnectOutcome ConnectAndRollBack(Candidate& cb)
{
    ConnectOutcome out;
    LOCK(cs_main);
    CTxDB txdb;
    BOOST_REQUIRE(txdb.TxnBegin());
    {
        LogCapture capture;
        cb.block.ConnectBlock(txdb, cb.Index(), false, false, &out.result);
        out.strLog = capture.Release();
    }
    BOOST_REQUIRE(txdb.TxnAbort());
    return out;
}

void ExpectBlockReason(const ConnectOutcome& out, const char* pszReason,
                       const std::string& strCase)
{
    BOOST_CHECK_MESSAGE(!out.Ok(), strCase + ": the block CONNECTED");
    BOOST_CHECK_MESSAGE(LogHas(out.strLog, pszReason),
        strCase + ": did not reject with \"" + pszReason + "\"; captured: " +
        Excerpt(out.strLog));
}

// ---------------------------------------------------------------------------
// An M-of-N mint output with a genuine value binding; only the fork height can refuse it.
// ---------------------------------------------------------------------------

// The genesis seeding derivation, restated independently: consensus keeps it
// file-static, and the case checks that the activation block ran it.
bool ExpectedGenesisCommitment(int nSeed, CPedersenCommitment& commitmentOut)
{
    CHashWriter ssBlind(SER_GETHASH, 0);
    ssBlind << std::string("Innova_Genesis_Seed_");
    ssBlind << nSeed;
    uint256 blindHash = ssBlind.GetHash();
    std::vector<unsigned char> vchBlind(blindHash.begin(),
                                        blindHash.begin() + 32);
    return CreateBlindCommitment(vchBlind, commitmentOut);
}

// ---------------------------------------------------------------------------
// Legacy private-finality objects, built up to the structural check; arms vary the network.
// ---------------------------------------------------------------------------

std::vector<unsigned char> SerializedBindingProof()
{
    CBindingSignature bindingSig;
    bindingSig.vchSignature.assign(BINDING_SIGNATURE_SIZE, 0x51);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << bindingSig;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

CPedersenCommitment SomeCommitment(int64_t nValue)
{
    std::vector<unsigned char> vchBlind;
    BOOST_REQUIRE(GenerateBlindingFactor(vchBlind));
    CPedersenCommitment commit;
    BOOST_REQUIRE(CreatePedersenCommitment(nValue, vchBlind, commit));
    return commit;
}

// A private (NullStake V2) finality vote whose structure passes CFinalityVote::IsValid,
// so the next thing with an opinion about it is the seal.
CFinalityVote MakePrivateVote(int nHeight)
{
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_NULLSTAKE_V2;
    vote.nEpoch = GetEpochForHeight(nHeight);
    vote.nHeight = GetEpochBoundaryHeight(vote.nEpoch, nHeight);
    vote.hashBlock = uint256(0x51D0F1);
    vote.nullifier = uint256(0x51D0F2);
    vote.nVoteWeight = 0;
    vote.nReward = 0;
    vote.nTime = GetAdjustedTime();

    vote.privateProof.nVersion = 1;
    vote.privateProof.nProofMode = vote.nProofMode;
    vote.privateProof.nEpoch = vote.nEpoch;
    vote.privateProof.hashEpochBlock = vote.hashBlock;
    vote.privateProof.nullifier = vote.nullifier;
    vote.privateProof.hashCurveRoot = uint256(0x51D0F3);
    vote.privateProof.hashNullifierRoot = uint256(0x51D0F4);
    vote.privateProof.stakeWeightCommitment = SomeCommitment(1000);
    vote.privateProof.rewardCommitment = SomeCommitment(7);
    vote.privateProof.fcmpProof.vchProof.assign(64, 0x11);
    vote.privateProof.vchRewardOutputCommitment.assign(33, 0x22);
    vote.privateProof.vchBindingProof = SerializedBindingProof();
    vote.privateProof.nullStakeV2Proof.acProof.vchAI.assign(33, 0x33);
    vote.privateProof.nullStakeV2Proof.acProof.ipaProof.vchAFinal.assign(32, 0x34);

    BOOST_REQUIRE(vote.IsPrivate());
    return vote;
}

// A tally share whose structure passes IsValidBasic. Every tally share is
// private, so the seal covers the whole object rather than one field of it.
CFinalityTallyShare MakeTallyShare(int nEpoch)
{
    CFinalityTallyShare share;
    share.nVersion = 2;
    share.nEpoch = nEpoch;
    share.voteNullifier = uint256(0x5A1E01);
    share.hashBlock = uint256(0x5A1E02);
    share.hashCurveRoot = uint256(0x5A1E03);
    share.hashNullifierRoot = uint256(0x5A1E04);
    share.committeeSetHash = uint256(0x5A1E05);
    share.stakeWeightCommitment = SomeCommitment(1000);
    share.rewardCommitment = SomeCommitment(7);
    share.vEncryptedRecipientShares.push_back(std::vector<unsigned char>(64, 0x44));
    share.vchShareProof = SerializedBindingProof();
    BOOST_REQUIRE(share.IsValidBasic());
    return share;
}

// A v2 certificate carrying private weight, structurally valid.
CFinalityTallyCertificate MakePrivateCertificate(int nHeight)
{
    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = GetEpochForHeight(nHeight);
    cert.nHeight = GetEpochBoundaryHeight(cert.nEpoch, nHeight);
    cert.hashBlock = uint256(0xCE1201);
    cert.nTier = FINALITY_SOFT;
    cert.nTransparentActiveWeight = 0;
    cert.nTransparentWinningWeight = 0;
    cert.nTransparentRewardBudget = 0;
    cert.vVoteNullifiers.push_back(uint256(0xCE1202));
    cert.hashCurveRoot = uint256(0xCE1203);
    cert.hashNullifierRoot = uint256(0xCE1204);
    cert.committeeSetHash = uint256(0xCE1205);
    cert.activeWeightCommitment = SomeCommitment(1000);
    cert.winningWeightCommitment = SomeCommitment(900);
    cert.rewardBudgetCommitment = SomeCommitment(7);
    cert.vTallyShareHashes.push_back(uint256(0xCE1206));
    cert.vchAggregateThresholdProof.assign(64, 0x55);
    cert.vchRewardBudgetProof.assign(64, 0x56);
    BOOST_REQUIRE(cert.HasPrivateWeight());
    std::string strBasic;
    BOOST_REQUIRE_MESSAGE(cert.IsValidBasic(&strBasic), strBasic);
    return cert;
}

// ---------------------------------------------------------------------------
// `hooks` is null in the unit binary (set only by AppInit2); supplied here for relay.
// ---------------------------------------------------------------------------

struct NameHooksGuard
{
    CHooks* pSaved;
    bool fOwned;

    NameHooksGuard() : pSaved(hooks), fOwned(false)
    {
        if (hooks == NULL)
        {
            hooks = InitHook();
            fOwned = true;
        }
    }
    ~NameHooksGuard()
    {
        if (fOwned)
        {
            CHooks* pMine = hooks;
            hooks = pSaved;
            delete pMine;
        }
    }
};

// ---------------------------------------------------------------------------
// Supplies the unlocked 32-byte IV5 seed the shield and fee-note builders need, then restores it.
// ---------------------------------------------------------------------------

struct WalletIV5SeedGuard
{
    CKeyingMaterial saved;

    WalletIV5SeedGuard() : saved(pwalletMain->vchPrivacyVNextSeed)
    {
        if (pwalletMain->vchPrivacyVNextSeed.size() != 32)
        {
            const std::vector<unsigned char> vchSeed(32, 0x5c);
            pwalletMain->vchPrivacyVNextSeed.assign(vchSeed.begin(),
                                                    vchSeed.end());
        }
    }
    ~WalletIV5SeedGuard() { pwalletMain->vchPrivacyVNextSeed = saved; }
};

// An address this wallet holds spendable value on. Every coinbase pays a fresh
// reserved key, so one address carries one output and a sweep of it is a shield
// with a known transparent side.
std::string FundedTransparentAddress(int64_t nAtLeast)
{
    std::vector<COutput> vCoins;
    pwalletMain->AvailableCoins(vCoins, true);
    for (size_t i = 0; i < vCoins.size(); ++i)
    {
        if (!vCoins[i].fSpendable)
            continue;
        const CTxOut& out = vCoins[i].tx->vout[vCoins[i].i];
        if (out.nValue < nAtLeast)
            continue;
        CTxDestination dest;
        if (!ExtractDestination(out.scriptPubKey, dest))
            continue;
        CBitcoinAddress addr(dest);
        if (!addr.IsValid())
            continue;
        return addr.ToString();
    }
    return std::string();
}

// The IV5 fee this block's transactions declare, read out of their payloads the
// way the validator sums them.
int64_t DeclaredIV5FeeSum(const CBlock& block)
{
    int64_t nSum = 0;
    for (unsigned int i = 1; i < block.vtx.size(); ++i)
    {
        if (!block.vtx[i].IsPrivacyVNext())
            continue;
        PrivacyVNextStateEffects effects;
        const PrivacyVNextPayloadValidation r =
            ExtractPrivacyVNextPayloadEffects(
                static_cast<uint32_t>(block.vtx[i].nVersion),
                block.vtx[i].privacyVNext.vchPayload, effects);
        BOOST_REQUIRE_MESSAGE(r.IsValid(), r.strError);
        nSum += effects.nFee;
    }
    return nSum;
}


CTransaction MakeMofNMintTx()
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_MOFN_MINT;
    tx.nTime = (unsigned int)GetAdjustedTime();
    tx.nPrivacyMode = PRIVACY_HIDE_AMOUNT | PRIVACY_HIDE_RECEIVER;
    tx.nValueBalance = 0;

    const int64_t nValue = 3 * COIN;
    std::vector<unsigned char> vchBlindCv3;
    std::vector<unsigned char> vchBlindVv;
    BOOST_REQUIRE(GenerateBlindingFactor(vchBlindCv3));
    BOOST_REQUIRE(GenerateBlindingFactor(vchBlindVv));

    CShieldedOutputDescription out;
    out.nMofNType = 1;
    out.nPlaintextValue = -1;
    BOOST_REQUIRE(CreatePedersenCommitment(nValue, vchBlindCv3, out.cv));
    BOOST_REQUIRE(CreatePedersenCommitment(nValue, vchBlindVv,
                                           out.valueCommitmentVv));
    BOOST_REQUIRE(CreateBulletproofRangeProof(nValue, vchBlindVv,
                                              out.valueCommitmentVv,
                                              out.rangeProof));
    BOOST_REQUIRE(CreateNullStakeMofNMintLink(out.cv, out.valueCommitmentVv,
                                              vchBlindCv3, vchBlindVv,
                                              uint256(0), out.vchMofNLink));
    tx.vShieldedOutput.push_back(out);
    return tx;
}

} // namespace

BOOST_AUTO_TEST_SUITE(iv5_privacy_coverage_tests)

// ---------------------------------------------------------------------------
// R-SEAL-002: an IV5-envelope tx is invalid unless vNext consensus is active.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(an_iv5_envelope_is_refused_until_the_vnext_implementation_is_active)
{
    LadderGuard guard;

    const char* kInactive =
        "CTransaction::CheckTransaction() : IV5 consensus implementation is inactive";

    // Each network's arm gets a payload that network otherwise accepts, so the seal
    // answers rather than the network-id check.
    guard.SelectRegtest();
    CTransaction tx = MakeIV5EnvelopeTx();

    // The control first: with the rehearsal switch on, this exact transaction is
    // accepted. Every refusal below is therefore the readiness leg.
    nRegtestBoundaryBHeight = 1;
    fRegtestShieldedVNextRehearsal = true;
    BOOST_REQUIRE(IsShieldedVNextConsensusReady());
    Outcome control = RunCheckTransaction(tx);
    BOOST_REQUIRE_MESSAGE(control.fAccepted,
        "the control payload was refused with the seal open, so every arm below "
        "would pass for the wrong reason; captured: " + Excerpt(control.strLog));

    // Regtest with the switch off -- the default, and the shipped configuration.
    fRegtestShieldedVNextRehearsal = false;
    BOOST_REQUIRE(!IsShieldedVNextConsensusReady());
    Outcome offRegtest = RunCheckTransaction(tx);
    ExpectReason(offRegtest, kInactive, "regtest with the rehearsal switch off");
    BOOST_CHECK_EQUAL(tx.nDoS, 100);

    // And on the networks that carry value, where no switch can open it. The
    // payload is rebuilt under those globals so it is that chain's own payload.
    guard.SelectMainnet();
    fRegtestShieldedVNextRehearsal = true;   // has no effect off regtest
    BOOST_REQUIRE(!IsShieldedVNextConsensusReady());
    CTransaction onMainnetTx = MakeIV5EnvelopeTx();
    Outcome onMainnet = RunCheckTransaction(onMainnetTx);
    ExpectReason(onMainnet, kInactive, "mainnet globals");
    BOOST_CHECK_EQUAL(onMainnetTx.nDoS, 100);

    guard.SelectTestnet();
    BOOST_REQUIRE(!IsShieldedVNextConsensusReady());
    CTransaction onTestnetTx = MakeIV5EnvelopeTx();
    Outcome onTestnet = RunCheckTransaction(onTestnetTx);
    ExpectReason(onTestnet, kInactive, "testnet globals");
    BOOST_CHECK_EQUAL(onTestnetTx.nDoS, 100);
}

// The same seal in ConnectInputs: boundary height and implementation switch are
// each refused with the other satisfied; the control has both.
BOOST_AUTO_TEST_CASE(the_iv5_seal_is_mirrored_on_the_block_connection_path)
{
    LadderGuard guard;
    TipHeightGuard tipGuard;
    guard.SelectRegtest();
    LOCK(cs_main);

    const char* kInactive =
        "ConnectInputs() : privacy-vNext is inactive before Boundary B";

    CBlockIndex index;
    index.nHeight = FORK_HEIGHT_SHIELDED + 4;
    nBestHeight = index.nHeight;

    CTransaction tx = MakeIV5EnvelopeTx();

    // Boundary B unset: the envelope is inactive whatever the switch says.
    nRegtestBoundaryBHeight = PRIVACY_VNEXT_HEIGHT_UNSET;
    fRegtestShieldedVNextRehearsal = true;
    BOOST_REQUIRE(!IsBoundaryBActiveAtHeight(index.nHeight));
    ExpectReason(RunConnectInputs(tx, &index), kInactive, "Boundary B unset");

    // Boundary B live but the implementation is not: the other leg, alone.
    nRegtestBoundaryBHeight = 1;
    fRegtestShieldedVNextRehearsal = false;
    BOOST_REQUIRE(IsBoundaryBActiveAtHeight(index.nHeight));
    BOOST_REQUIRE(!IsShieldedVNextConsensusReady());
    ExpectReason(RunConnectInputs(tx, &index), kInactive,
                 "the implementation switch off");

    // Both legs satisfied: the seal no longer answers. The transaction is still
    // refused further down -- it names no funded transparent input -- and that
    // is the point: the two arms above are attributable to this gate.
    fRegtestShieldedVNextRehearsal = true;
    Outcome past = RunConnectInputs(tx, &index);
    ExpectPastReason(past, kInactive, "both legs satisfied");
}

// ---------------------------------------------------------------------------
// R-SEAL-003: private votes refused everywhere; private-weight certs off regtest and above A.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(legacy_private_finality_objects_are_sealed_off_regtest)
{
    LadderGuard guard;
    TipHeightGuard tipGuard;
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    const char* kVoteSeal =
        "legacy private-finality proofs have no verifiable membership and are permanently invalid";
    const char* kShareSeal =
        "legacy private tally shares are disabled pending privacy vNext";
    const char* kCertSeal =
        "legacy private tally certificates are disabled pending privacy vNext";

    CFinalityTracker tracker;
    CTxDB txdb("r");
    std::string strWhy;

    // -- the vote --------------------------------------------------------------
    // Regtest below Boundary A: the vote rule is unconditional, so it is refused here too.
    guard.SelectRegtest();
    const int nOpenHeight = FORK_HEIGHT_DAG + 1;
    BOOST_REQUIRE(!IsLegacyPrivacyPolicyDisabled());
    BOOST_REQUIRE(!IsBoundaryAActiveAtHeight(nOpenHeight));
    {
        CFinalityVote vote = MakePrivateVote(nOpenHeight);
        BOOST_CHECK(!tracker.CheckVote(vote, txdb, &strWhy,
                                       CFinalityVoteContext::ChainHeight(nOpenHeight), NULL));
        BOOST_CHECK_EQUAL(strWhy, kVoteSeal);
    }

    // The same object with a transparent proof mode. It is refused for its own
    // reasons and never with this one, so the refusals here are the private
    // encoding and not the fixture.
    {
        CFinalityVote vote = MakePrivateVote(nOpenHeight);
        vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
        vote.privateProof.nProofMode = FINALITY_PROOF_TRANSPARENT;
        BOOST_REQUIRE(!vote.IsPrivate());
        BOOST_CHECK(!tracker.CheckVote(vote, txdb, &strWhy,
                                       CFinalityVoteContext::ChainHeight(nOpenHeight), NULL));
        BOOST_CHECK_MESSAGE(strWhy != kVoteSeal,
            "a transparent vote was refused by the private-vote rule: " + strWhy);
    }

    // Regtest above the quarantine height, and both public networks.
    {
        const int nSealed = FORK_HEIGHT_BOUNDARY_A;
        BOOST_REQUIRE(IsBoundaryAActiveAtHeight(nSealed));
        CFinalityVote vote = MakePrivateVote(nSealed);
        BOOST_CHECK(!tracker.CheckVote(vote, txdb, &strWhy,
                                       CFinalityVoteContext::ChainHeight(nSealed), NULL));
        BOOST_CHECK_EQUAL(strWhy, kVoteSeal);
    }

    for (int nPass = 0; nPass < 2; ++nPass)
    {
        if (nPass == 0)
            guard.SelectMainnet();
        else
            guard.SelectTestnet();
        BOOST_REQUIRE(IsLegacyPrivacyPolicyDisabled());
        const int nHeight = FORK_HEIGHT_DAG + 1;
        BOOST_REQUIRE(!IsBoundaryAActiveAtHeight(nHeight));
        CFinalityVote vote = MakePrivateVote(nHeight);
        BOOST_CHECK(!tracker.CheckVote(vote, txdb, &strWhy,
                                       CFinalityVoteContext::ChainHeight(nHeight), NULL));
        BOOST_CHECK_MESSAGE(strWhy == kVoteSeal,
                            (nPass == 0 ? "mainnet" : "testnet") +
                            std::string(" refused a private vote with: ") + strWhy);
    }

    // -- the tally share -------------------------------------------------------
    guard.SelectRegtest();
    {
        CFinalityTallyShare share = MakeTallyShare(GetEpochForHeight(nOpenHeight));
        BOOST_REQUIRE(!tracker.CheckTallyShare(share, &strWhy, NULL, false, nOpenHeight));
        BOOST_CHECK_MESSAGE(strWhy != kShareSeal,
            "the share seal fired on regtest below Boundary A: " + strWhy);
    }
    {
        const int nSealed = FORK_HEIGHT_BOUNDARY_A;
        CFinalityTallyShare share = MakeTallyShare(GetEpochForHeight(nSealed));
        BOOST_CHECK(!tracker.CheckTallyShare(share, &strWhy, NULL, false, nSealed));
        BOOST_CHECK_EQUAL(strWhy, kShareSeal);
    }
    for (int nPass = 0; nPass < 2; ++nPass)
    {
        if (nPass == 0)
            guard.SelectMainnet();
        else
            guard.SelectTestnet();
        const int nHeight = FORK_HEIGHT_DAG + 1;
        CFinalityTallyShare share = MakeTallyShare(GetEpochForHeight(nHeight));
        BOOST_CHECK(!tracker.CheckTallyShare(share, &strWhy, NULL, false, nHeight));
        BOOST_CHECK_MESSAGE(strWhy == kShareSeal,
                            (nPass == 0 ? "mainnet" : "testnet") +
                            std::string(" refused a tally share with: ") + strWhy);
    }

    // -- the certificate -------------------------------------------------------
    guard.SelectRegtest();
    {
        CFinalityTallyCertificate cert = MakePrivateCertificate(nOpenHeight);
        BOOST_REQUIRE(!tracker.CheckTallyCertificate(cert, txdb, &strWhy, NULL, false,
                                                     nOpenHeight, true, NULL));
        BOOST_CHECK_MESSAGE(strWhy != kCertSeal,
            "the certificate seal fired on regtest below Boundary A: " + strWhy);
    }
    {
        const int nSealed = FORK_HEIGHT_BOUNDARY_A;
        CFinalityTallyCertificate cert = MakePrivateCertificate(nSealed);
        BOOST_CHECK(!tracker.CheckTallyCertificate(cert, txdb, &strWhy, NULL, false,
                                                   nSealed, true, NULL));
        BOOST_CHECK_EQUAL(strWhy, kCertSeal);
    }
    for (int nPass = 0; nPass < 2; ++nPass)
    {
        if (nPass == 0)
            guard.SelectMainnet();
        else
            guard.SelectTestnet();
        const int nHeight = FORK_HEIGHT_DAG + 1;
        CFinalityTallyCertificate cert = MakePrivateCertificate(nHeight);
        BOOST_CHECK(!tracker.CheckTallyCertificate(cert, txdb, &strWhy, NULL, false,
                                                   nHeight, true, NULL));
        BOOST_CHECK_MESSAGE(strWhy == kCertSeal,
                            (nPass == 0 ? "mainnet" : "testnet") +
                            std::string(" refused a private certificate with: ") + strWhy);
    }
}

// ---------------------------------------------------------------------------
// R-DSP-001: DSP tx invalid before the DSP height; its privacy mode may not exceed the mask.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_dsp_transaction_is_bounded_by_its_height_and_its_mode)
{
    LadderGuard guard;
    TipHeightGuard tipGuard;
    guard.SelectRegtest();
    BOOST_REQUIRE(!IsLegacyPrivacyPolicyDisabled());
    BOOST_REQUIRE_GT(FORK_HEIGHT_DSP, 0);

    // The control: at the activation height a well-formed DSP transaction is
    // accepted, so the refusals below are the gate rather than the shape.
    CTransaction tx = MakeDSPShape(PRIVACY_MODE_MASK);
    BOOST_REQUIRE(tx.IsDSP());
    nBestHeight = FORK_HEIGHT_DSP;
    Outcome control = RunCheckTransaction(tx);
    BOOST_REQUIRE_MESSAGE(control.fAccepted,
        "the control DSP shape was refused at the activation height; captured: " +
        Excerpt(control.strLog));

    // One block below it, nothing else changed.
    nBestHeight = FORK_HEIGHT_DSP - 1;
    Outcome below = RunCheckTransaction(tx);
    ExpectReason(below, "DSP transactions not active until height",
                 "one block below the DSP fork");
    BOOST_CHECK_EQUAL(tx.nDoS, 100);

    // The mode mask, at a height that admits DSP.
    nBestHeight = FORK_HEIGHT_DSP;
    CTransaction over = MakeDSPShape(PRIVACY_MODE_MASK + 1);
    Outcome overMask = RunCheckTransaction(over);
    ExpectReason(overMask, "invalid privacy mode", "a mode above the mask");
    BOOST_CHECK_EQUAL(over.nDoS, 100);

    // Every mode the mask permits is admitted, so the refusal above is the bound
    // and not one particular bit pattern.
    for (int nMode = 0; nMode <= PRIVACY_MODE_MASK; ++nMode)
    {
        CTransaction each = MakeDSPShape(nMode);
        Outcome ok = RunCheckTransaction(each);
        BOOST_CHECK_MESSAGE(ok.fAccepted,
            "privacy mode " << nMode << " was refused: " << Excerpt(ok.strLog));
    }
}

// ---------------------------------------------------------------------------
// R-CJ-001: a NullSend session at or above the Chaumian height generates a session RSA key.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_nullsend_session_is_chaumian_from_its_fork_height)
{
    LadderGuard guard;
    TipHeightGuard tipGuard;
    guard.SelectRegtest();
    BOOST_REQUIRE_GT(FORK_HEIGHT_CHAUMIAN_CJ, 0);

    const size_t nSessionsBefore = nullSendPool.mapSessions.size();

    nBestHeight = FORK_HEIGHT_CHAUMIAN_CJ - 1;
    const int nLegacy = nullSendPool.NewSession(PRIVACY_MODE_MASK, 3);
    BOOST_REQUIRE_GT(nLegacy, 0);
    BOOST_REQUIRE(nullSendPool.mapSessions.count(nLegacy) != 0);
    BOOST_CHECK(!nullSendPool.mapSessions[nLegacy].fChaumian);
    BOOST_CHECK(nullSendPool.mapSessions[nLegacy].vchRSA_N.empty());
    BOOST_CHECK_EQUAL(nullSendPool.mapSessions[nLegacy].nState,
                      NULLSEND_STATE_ACCEPTING);

    nBestHeight = FORK_HEIGHT_CHAUMIAN_CJ;
    const int nChaumian = nullSendPool.NewSession(PRIVACY_MODE_MASK, 3);
    BOOST_REQUIRE_GT(nChaumian, 0);
    BOOST_REQUIRE(nullSendPool.mapSessions.count(nChaumian) != 0);
    BOOST_CHECK(nullSendPool.mapSessions[nChaumian].fChaumian);
    BOOST_CHECK(!nullSendPool.mapSessions[nChaumian].vchRSA_N.empty());
    BOOST_CHECK(!nullSendPool.mapSessions[nChaumian].vchRSA_E.empty());
    BOOST_CHECK_EQUAL(nullSendPool.mapSessions[nChaumian].nState,
                      NULLSEND_STATE_INPUT_REG);

    nullSendPool.mapSessions.erase(nLegacy);
    nullSendPool.mapSessions.erase(nChaumian);
    BOOST_CHECK_EQUAL(nullSendPool.mapSessions.size(), nSessionsBefore);
}


// ---------------------------------------------------------------------------
// R-DELEG-001 mint leg: an M-of-N mint output is invalid below the delegation-set height.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(an_mofn_mint_output_is_refused_below_the_delegation_set_fork)
{
    LadderGuard guard;
    TipHeightGuard tipGuard;
    guard.SelectRegtest();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    const char* kBeforeFork = "M-of-N mint output before DELEGSET fork height";

    BOOST_REQUIRE_GT(FORK_HEIGHT_NULLSTAKE_DELEGSET, 0);
    BOOST_REQUIRE_MESSAGE(
        FORK_HEIGHT_NULLSTAKE_DELEGSET + 1 < FORK_HEIGHT_BOUNDARY_A,
        "the delegation-set fork has reached Boundary A, which quarantines every "
        "legacy shielded version, so neither arm exercises this gate");

    CTransaction tx = MakeMofNMintTx();
    BOOST_REQUIRE(tx.IsShielded());
    BOOST_REQUIRE(!tx.vShieldedOutput.empty());

    CBlockIndex below;
    below.nHeight = FORK_HEIGHT_NULLSTAKE_DELEGSET - 1;
    nBestHeight = below.nHeight;
    ExpectReason(RunConnectInputs(tx, &below), kBeforeFork,
                 "one block below the delegation-set fork");
    BOOST_CHECK_EQUAL(tx.nDoS, 100);

    CBlockIndex at;
    at.nHeight = FORK_HEIGHT_NULLSTAKE_DELEGSET;
    nBestHeight = at.nHeight;
    Outcome past = RunConnectInputs(tx, &at);
    ExpectPastReason(past, kBeforeFork, "at the delegation-set fork");
    // The same transaction with its value binding broken is refused at the fork
    // height too, so admission above is the binding holding and not the gate
    // having stopped being read.
    CTransaction broken = tx;
    broken.vShieldedOutput[0].vchMofNLink.assign(NULLSTAKE_MOFN_MINTLINK_SIZE, 0);
    ExpectReason(RunConnectInputs(broken, &at),
                 "M-of-N mint (G,J) value-binding link failed",
                 "a mint output whose link does not verify");
}

// ---------------------------------------------------------------------------
// R-ANON-001: a ring-signature tx is invalid in any connected block (ConnectInputs, ConnectBlock).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_ring_signature_transaction_is_refused_at_every_height)
{
    LadderGuard guard;
    TipHeightGuard tipGuard;
    guard.SelectRegtest();
    LOCK(cs_main);

    const char* kDeprecated =
        "ConnectInputs() : ring signature transactions deprecated after height";

    BOOST_REQUIRE_EQUAL(FORK_HEIGHT_RINGSIG_DEPRECATION, 0);

    CTransaction anon;
    anon.nVersion = ANON_TXN_VERSION;
    anon.nTime = (unsigned int)GetAdjustedTime();
    anon.vout.push_back(CTxOut(1 * COIN, CScript()));

    // Genesis, the shielded fork, and the tip: the gate admits no window.
    const int nHeights[] = {0, 1, FORK_HEIGHT_SHIELDED, FORK_HEIGHT_DAG,
                            BestIndex()->nHeight};
    for (size_t i = 0; i < sizeof(nHeights) / sizeof(nHeights[0]); ++i)
    {
        CBlockIndex index;
        index.nHeight = nHeights[i];
        nBestHeight = index.nHeight;
        ExpectReason(RunConnectInputs(anon, &index), kDeprecated,
                     strprintf("ring-signature transaction at height %d",
                               nHeights[i]));
    }

    // The control: the same shape under an ordinary version walks past the gate
    // and is refused further down, so the refusals above are this branch.
    CTransaction plain = anon;
    plain.nVersion = CTransaction::CURRENT_VERSION;
    CBlockIndex index;
    index.nHeight = BestIndex()->nHeight;
    nBestHeight = index.nHeight;
    ExpectPastReason(RunConnectInputs(plain, &index), kDeprecated,
                     "an ordinary transaction");
}

// The same rule at the site ahead of it, reached with a real block. The
// transaction names an output the chain actually holds, so the block gets past
// input resolution and the ring-signature branch is what refuses it.
BOOST_AUTO_TEST_CASE(a_block_carrying_a_ring_signature_transaction_does_not_connect)
{
    LadderGuard guard;
    guard.SelectRegtest();

    const char* kDeprecated =
        "ConnectBlock() : ring signature transactions deprecated after height";

    MineTo(BestIndex()->nHeight + 2);

    // The producer's own block connects. Every arm below rides this template, so
    // without this the refusal could be anything.
    Candidate control;
    BOOST_REQUIRE(BuildCandidate(control));
    BOOST_REQUIRE(SealCandidate(control));
    ConnectOutcome ok = ConnectAndRollBack(control);
    BOOST_REQUIRE_MESSAGE(ok.Ok(),
        "the producer's own block was refused; captured: " + Excerpt(ok.strLog));

    // An output two blocks back, which this chain holds and which resolves.
    CBlockIndex* pFunding = AncestorAtHeight(BestIndex()->nHeight - 1);
    BOOST_REQUIRE(pFunding != NULL);
    CBlock funding;
    BOOST_REQUIRE(funding.ReadFromDisk(pFunding, true));
    BOOST_REQUIRE(!funding.vtx.empty());

    Candidate cb;
    BOOST_REQUIRE(BuildCandidate(cb));
    CTransaction anon;
    anon.nVersion = ANON_TXN_VERSION;
    anon.nTime = cb.block.nTime;
    anon.vin.push_back(CTxIn(funding.vtx[0].GetHash(), 0));
    anon.vout.push_back(CTxOut(1, funding.vtx[0].vout[0].scriptPubKey));
    cb.block.vtx.push_back(anon);
    BOOST_REQUIRE(SealCandidate(cb));
    ExpectBlockReason(ConnectAndRollBack(cb), kDeprecated,
                      "a block carrying a ring-signature transaction");
}

// ---------------------------------------------------------------------------
// R-SH-002: the activation block seeds the genesis commitment set exactly once.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(the_activation_block_seeds_the_genesis_commitment_set_once)
{
    LadderGuard guard;
    guard.SelectRegtest();
    MineTo(FORK_HEIGHT_SHIELDED + 1);

    CTxDB txdb("r");
    uint64_t nCount = 0;
    BOOST_REQUIRE(txdb.ReadShieldedCommitmentCount(nCount));
    BOOST_REQUIRE_MESSAGE(nCount >= (uint64_t)LELANTUS_GENESIS_SEED_COUNT,
        "the commitment set is smaller than the genesis seeding");

    for (int i = 0; i < LELANTUS_GENESIS_SEED_COUNT; ++i)
    {
        CPedersenCommitment expected;
        BOOST_REQUIRE(ExpectedGenesisCommitment(i, expected));

        CPedersenCommitment stored;
        BOOST_REQUIRE_MESSAGE(txdb.ReadShieldedCommitment((uint64_t)i, stored),
                              "genesis seed " << i << " is not in the commitment set");
        BOOST_CHECK_MESSAGE(stored.vchCommitment == expected.vchCommitment,
                            "genesis seed " << i << " is not the commitment the "
                            "activation block should have written");

        int nHeight = -1;
        BOOST_REQUIRE_MESSAGE(
            txdb.ReadShieldedCommitmentHeight((uint64_t)i, nHeight),
            "genesis seed " << i << " carries no insertion height");
        BOOST_CHECK_MESSAGE(nHeight == FORK_HEIGHT_SHIELDED,
                            "genesis seed " << i << " was inserted at height "
                            << nHeight << " rather than at the activation height "
                            << FORK_HEIGHT_SHIELDED);

        uint64_t nIndexed = 0;
        BOOST_REQUIRE_MESSAGE(
            txdb.ReadShieldedCommitmentIndex(expected.vchCommitment, nIndexed),
            "genesis seed " << i << " has no reverse index");
        BOOST_CHECK_MESSAGE(nIndexed == (uint64_t)i,
                            "genesis seed " << i << " resolves to index "
                            << nIndexed << ", so it was seeded more than once");
    }
}

// ---------------------------------------------------------------------------
// R-SH-001: every block from the shielded fork persists a tree snapshot and pool value.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_block_with_no_shielded_transaction_still_persists_the_tree)
{
    LadderGuard guard;
    guard.SelectRegtest();

    MineTo(BestIndex()->nHeight + 1);
    CBlockIndex* pTip = BestIndex();
    BOOST_REQUIRE(pTip != NULL);
    BOOST_REQUIRE_GE(pTip->nHeight, FORK_HEIGHT_SHIELDED);

    CBlock block;
    BOOST_REQUIRE(block.ReadFromDisk(pTip, true));
    for (unsigned int i = 0; i < block.vtx.size(); ++i)
        BOOST_REQUIRE_MESSAGE(!block.vtx[i].IsShielded(),
            "the block mined for this case carries a shielded transaction, so it "
            "no longer tests the branch the rule is about");

    CTxDB txdb("r");
    CIncrementalMerkleTree snapshot;
    BOOST_CHECK_MESSAGE(
        txdb.ReadShieldedTreeAtBlock(pTip->GetBlockHash(), snapshot),
        "no shielded tree snapshot is keyed by a block that carries no shielded "
        "transaction");

    int64_t nPool = 0;
    BOOST_CHECK_MESSAGE(txdb.ReadShieldedPoolValue(nPool),
                        "no shielded pool value is recorded after the block");
    BOOST_CHECK(nPool >= 0);

    // A height below the fork has no snapshot, so the presence above is the rule
    // and not a record every block index happens to carry.
    if (FORK_HEIGHT_SHIELDED > 0)
    {
        CBlockIndex* pBelow = AncestorAtHeight(FORK_HEIGHT_SHIELDED - 1);
        BOOST_REQUIRE(pBelow != NULL);
        CIncrementalMerkleTree none;
        BOOST_CHECK_MESSAGE(
            !txdb.ReadShieldedTreeAtBlock(pBelow->GetBlockHash(), none),
            "a block below the shielded fork carries a tree snapshot");
    }
}

// ---------------------------------------------------------------------------
// R-NS-004: a legacy NullStake coinstake block does not connect; reason derived from height.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_block_whose_coinstake_is_a_nullstake_encoding_does_not_connect)
{
    LadderGuard guard;
    guard.SelectRegtest();

    const char* kFCMPEra =
        "carries an FCMP-era shielded spend whose membership is unverifiable; "
        "the encoding is permanently invalid";
    const char* kPostDAG =
        "ConnectBlock() : proof-of-stake blocks are not allowed after DAG fork";
    const char* kNullStakeV1 = "NullStake stake note membership is unverifiable";
    const char* kNullStakeV2 = "NullStake V2 stake note membership is unverifiable";
    const char* kNullStakeV3 = "NullStake V3 stake note membership is unverifiable";

    MineTo(BestIndex()->nHeight + 2);
    BOOST_REQUIRE_GE(BestIndex()->nHeight + 1, FORK_HEIGHT_NULLSTAKE_V3);

    const int nStakeVersions[] = {SHIELDED_TX_VERSION_NULLSTAKE,
                                  SHIELDED_TX_VERSION_NULLSTAKE_V2,
                                  SHIELDED_TX_VERSION_NULLSTAKE_COLD};
    for (size_t i = 0; i < sizeof(nStakeVersions) / sizeof(nStakeVersions[0]); ++i)
    {
        Candidate cb;
        BOOST_REQUIRE(BuildCandidate(cb));

        // What CheckBlock requires of a proof-of-stake block: an empty coinbase
        // output and a coinstake at index 1 stamped with the block's own time.
        cb.block.vtx[0].vout.resize(1);
        cb.block.vtx[0].vout[0].SetEmpty();

        CTransaction stake;
        stake.nVersion = nStakeVersions[i];
        stake.nTime = cb.block.nTime;
        stake.vin.push_back(CTxIn(uint256(0x5104), 0));
        stake.vout.resize(2);
        stake.vout[0].SetEmpty();
        stake.vout[1].nValue = 1 * COIN;
        stake.vShieldedSpend.resize(1);
        stake.vShieldedSpend[0].nullifier = uint256(0xFC3D02);
        stake.nValueBalance = -1;
        BOOST_REQUIRE(stake.IsCoinStake() && stake.IsShielded());

        cb.block.vtx.insert(cb.block.vtx.begin() + 1, stake);
        BOOST_REQUIRE(cb.block.IsProofOfStake());
        BOOST_REQUIRE(SealCandidate(cb));

        const std::string strCase =
            strprintf("a block whose coinstake is NullStake version %d",
                      nStakeVersions[i]);
        ConnectOutcome out = ConnectAndRollBack(cb);
        ExpectBlockReason(out,
                          cb.Height() >= FORK_HEIGHT_DAG ? kPostDAG : kFCMPEra,
                          strCase);
        BOOST_CHECK_MESSAGE(!LogHas(out.strLog, kNullStakeV1) &&
                            !LogHas(out.strLog, kNullStakeV2) &&
                            !LogHas(out.strLog, kNullStakeV3),
            strCase + ": a NullStake coinstake branch was reached, so those three "
            "branches decide again and each needs its own case; captured: " +
            Excerpt(out.strLog));
    }
}

// Below the DAG gate: every NullStake version and gate is at or above the FCMP
// one, so the block-level FCMP-era rule runs first. Checked on all three networks.
BOOST_AUTO_TEST_CASE(the_nullstake_coinstake_branches_have_no_reachable_shape)
{
    LadderGuard guard;

    BOOST_CHECK_GE(SHIELDED_TX_VERSION_NULLSTAKE, SHIELDED_TX_VERSION_FCMP);
    BOOST_CHECK_GE(SHIELDED_TX_VERSION_NULLSTAKE_V2, SHIELDED_TX_VERSION_FCMP);
    BOOST_CHECK_GE(SHIELDED_TX_VERSION_NULLSTAKE_COLD, SHIELDED_TX_VERSION_FCMP);

    for (int nPass = 0; nPass < 3; ++nPass)
    {
        if (nPass == 0)
            guard.SelectRegtest();
        else if (nPass == 1)
            guard.SelectTestnet();
        else
            guard.SelectMainnet();

        const std::string strNet = nPass == 0 ? "regtest"
                                 : nPass == 1 ? "testnet" : "mainnet";
        BOOST_CHECK_MESSAGE(FORK_HEIGHT_NULLSTAKE >= FORK_HEIGHT_FCMP_VALIDATION,
            strNet + ": the NullStake gate moved below the FCMP gate, so the "
            "NullStake coinstake branch decides again and needs its own case");
        BOOST_CHECK_MESSAGE(FORK_HEIGHT_NULLSTAKE_V2 >= FORK_HEIGHT_FCMP_VALIDATION,
            strNet + ": the NullStake V2 gate moved below the FCMP gate");
        BOOST_CHECK_MESSAGE(FORK_HEIGHT_NULLSTAKE_V3 >= FORK_HEIGHT_FCMP_VALIDATION,
            strNet + ": the NullStake V3 gate moved below the FCMP gate");
    }
}

// ---------------------------------------------------------------------------
// R-B2C-001 (retired): the DAG-gate PoS refusal and CheckVote answer first at each limb.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_b2c_hidden_coinstake_is_refused_before_its_own_bound)
{
    LadderGuard guard;
    guard.SelectRegtest();

    const char* kPostDAG =
        "ConnectBlock() : proof-of-stake blocks are not allowed after DAG fork";
    const char* kB2CBound =
        "NullStake V3 B2-c hidden coinstake before B2C fork height";
    const char* kDelegSetBound =
        "NullStake V3 M-of-N coinstake before DELEGSET fork height";

    // Absolute, so the case neither depends on nor moves the shared chain height
    // beyond what it needs: the window the retired bound named is at or above the
    // DAG gate on every network.
    MineTo(FORK_HEIGHT_DAG);

    Candidate cb;
    BOOST_REQUIRE(BuildCandidate(cb));
    BOOST_REQUIRE_GE(cb.Height(), FORK_HEIGHT_DAG);

    cb.block.vtx[0].vout.resize(1);
    cb.block.vtx[0].vout[0].SetEmpty();

    // The shape the retired rule named: a V3 cold coinstake carrying an M-of-N
    // proof tagged with the hidden-signer authorization mode.
    CTransaction stake;
    stake.nVersion = SHIELDED_TX_VERSION_NULLSTAKE_COLD;
    stake.nTime = cb.block.nTime;
    stake.vin.push_back(CTxIn(uint256(0xB2C001), 0));
    stake.vout.resize(2);
    stake.vout[0].SetEmpty();
    stake.vout[1].nValue = 1 * COIN;
    stake.vShieldedSpend.resize(1);
    stake.vShieldedSpend[0].nullifier = uint256(0xB2C002);
    stake.nValueBalance = -1;
    stake.nullstakeProofV3.acProof.vchAI.assign(33, 0x33);
    stake.nullstakeProofV3.acProof.ipaProof.vchAFinal.assign(32, 0x34);
    stake.nullstakeProofV3.nThresholdM = 2;
    stake.nullstakeProofV3.nAuthMode = NULLSTAKE_AUTHMODE_B2C_HIDDEN;
    stake.nullstakeProofV3.vStakerSet.assign(3, std::vector<unsigned char>(33, 0x02));
    stake.nullstakeProofV3.hiddenAuth.vchResearchProof.assign(64, 0x35);

    BOOST_REQUIRE(stake.IsCoinStake() && stake.IsShielded());
    BOOST_REQUIRE(!stake.nullstakeProofV3.IsNull());
    BOOST_REQUIRE(stake.nullstakeProofV3.nThresholdM > 0);
    BOOST_REQUIRE_EQUAL(stake.nullstakeProofV3.nAuthMode,
                        NULLSTAKE_AUTHMODE_B2C_HIDDEN);

    cb.block.vtx.insert(cb.block.vtx.begin() + 1, stake);
    BOOST_REQUIRE(cb.block.IsProofOfStake());
    BOOST_REQUIRE(SealCandidate(cb));

    ConnectOutcome out = ConnectAndRollBack(cb);
    ExpectBlockReason(out, kPostDAG, "a B2-c hidden M-of-N coinstake");
    BOOST_CHECK_MESSAGE(!LogHas(out.strLog, kB2CBound),
        "the B2-c hidden-signer bound decided this block, so it is reachable and "
        "R-B2C-001's coinstake limb was retired wrongly; captured: " +
        Excerpt(out.strLog));
    BOOST_CHECK_MESSAGE(!LogHas(out.strLog, kDelegSetBound),
        "the DELEGSET bound decided this block, so the coinstake dispatch is "
        "reachable at this height; captured: " + Excerpt(out.strLog));
}

BOOST_AUTO_TEST_CASE(a_b2c_hidden_private_vote_is_refused_before_its_own_bound)
{
    LadderGuard guard;
    TipHeightGuard tipGuard;
    guard.SelectRegtest();
    BOOST_REQUIRE(CZKContext::Initialize());
    LOCK(cs_main);

    const char* kVoteSeal =
        "legacy private-finality proofs have no verifiable membership and are permanently invalid";

    CFinalityTracker tracker;
    CTxDB txdb("r");
    std::string strWhy;

    // The vote the deleted bound existed to refuse, at a height inside the window
    // it would have refused it in.
    CFinalityVote vote = MakePrivateVote(FORK_HEIGHT_DAG + 1);
    vote.nProofMode = FINALITY_PROOF_NULLSTAKE_V3_COLD;
    vote.privateProof.nProofMode = vote.nProofMode;
    vote.privateProof.nullStakeV3Proof.acProof.vchAI.assign(33, 0x33);
    vote.privateProof.nullStakeV3Proof.acProof.ipaProof.vchAFinal.assign(32, 0x34);
    vote.privateProof.nullStakeV3Proof.nThresholdM = 2;
    vote.privateProof.nullStakeV3Proof.nAuthMode = NULLSTAKE_AUTHMODE_B2C_HIDDEN;
    vote.privateProof.nullStakeV3Proof.vStakerSet.assign(
        3, std::vector<unsigned char>(33, 0x02));
    vote.privateProof.nullStakeV3Proof.hiddenAuth.vchResearchProof.assign(64, 0x35);

    BOOST_REQUIRE(vote.IsPrivate());
    BOOST_REQUIRE(vote.IsValid());
    BOOST_REQUIRE_MESSAGE(vote.nHeight < FORK_HEIGHT_NULLSTAKE_B2C,
        "the epoch arithmetic no longer places this vote below the B2C gate, so "
        "the case no longer probes the window the retired bound named");

    BOOST_CHECK(!tracker.CheckVote(vote, txdb, &strWhy,
                                   CFinalityVoteContext::ChainHeight(vote.nHeight),
                                   NULL));
    BOOST_CHECK_EQUAL(strWhy, kVoteSeal);

    // The auth mode plays no part in that answer: the public half-aggregated tier
    // is refused with the same reason, at the same height.
    CFinalityVote halfAgg = vote;
    halfAgg.privateProof.nullStakeV3Proof.nAuthMode = NULLSTAKE_AUTHMODE_HALFAGG;
    halfAgg.privateProof.nullStakeV3Proof.hiddenAuth =
        CNullStakeMofNHiddenAuthProof();
    halfAgg.privateProof.nullStakeV3Proof.vSignerPubKeys.assign(
        2, std::vector<unsigned char>(33, 0x02));
    halfAgg.privateProof.nullStakeV3Proof.vSignerRPoints.assign(
        2, std::vector<unsigned char>(33, 0x03));
    halfAgg.privateProof.nullStakeV3Proof.vchAggregatedSScalar.assign(32, 0x04);
    BOOST_REQUIRE(halfAgg.IsValid());
    BOOST_CHECK(!tracker.CheckVote(halfAgg, txdb, &strWhy,
                                   CFinalityVoteContext::ChainHeight(halfAgg.nHeight),
                                   NULL));
    BOOST_CHECK_EQUAL(strWhy, kVoteSeal);

    // The control the two checks above need: a transparent vote reaches the same
    // call and is never refused with this reason, so the seal is the private
    // encoding and not the fixture.
    CFinalityVote transparent = vote;
    transparent.nProofMode = FINALITY_PROOF_TRANSPARENT;
    transparent.privateProof.nProofMode = FINALITY_PROOF_TRANSPARENT;
    BOOST_REQUIRE(!transparent.IsPrivate());
    BOOST_CHECK(!tracker.CheckVote(transparent, txdb, &strWhy,
                                   CFinalityVoteContext::ChainHeight(transparent.nHeight),
                                   NULL));
    BOOST_CHECK_MESSAGE(strWhy != kVoteSeal,
        "a transparent vote was refused by the private-vote rule: " + strWhy);
}

// ---------------------------------------------------------------------------
// R-FCMP-001: curve-tree snapshots from FCMP activation until the epoch-root height only.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(the_mutable_curve_tree_window_is_where_the_ladder_puts_it)
{
    LadderGuard guard;
    guard.SelectRegtest();
    BOOST_REQUIRE_LT(FORK_HEIGHT_FCMP, FORK_HEIGHT_EPOCH_ROOT_FCMP);

    MineTo(FORK_HEIGHT_EPOCH_ROOT_FCMP + 1);
    CTxDB txdb("r");

    for (int nHeight = FORK_HEIGHT_FCMP;
         nHeight < FORK_HEIGHT_EPOCH_ROOT_FCMP; ++nHeight)
    {
        CBlockIndex* p = AncestorAtHeight(nHeight);
        BOOST_REQUIRE_MESSAGE(p != NULL, "height " << nHeight << " is not on this chain");
        CCurveTree tree;
        BOOST_CHECK_MESSAGE(txdb.ReadCurveTreeAtBlock(p->GetBlockHash(), tree),
            "no curve-tree snapshot for block " << nHeight << ", which is inside "
            "the mutable window [" << FORK_HEIGHT_FCMP << ", "
            << FORK_HEIGHT_EPOCH_ROOT_FCMP << ")");
    }

    for (int nHeight = FORK_HEIGHT_EPOCH_ROOT_FCMP;
         nHeight <= FORK_HEIGHT_EPOCH_ROOT_FCMP + 1; ++nHeight)
    {
        CBlockIndex* p = AncestorAtHeight(nHeight);
        BOOST_REQUIRE(p != NULL);
        CCurveTree tree;
        BOOST_CHECK_MESSAGE(!txdb.ReadCurveTreeAtBlock(p->GetBlockHash(), tree),
            "block " << nHeight << " carries a curve-tree snapshot at or above "
            "the epoch-root height, where the mutable tree is retired");
    }

    // And below activation, where the tree does not exist at all.
    if (FORK_HEIGHT_FCMP > 0)
    {
        CBlockIndex* p = AncestorAtHeight(FORK_HEIGHT_FCMP - 1);
        BOOST_REQUIRE(p != NULL);
        CCurveTree tree;
        BOOST_CHECK_MESSAGE(!txdb.ReadCurveTreeAtBlock(p->GetBlockHash(), tree),
            "a block below FCMP activation carries a curve-tree snapshot");
    }
}


// ---------------------------------------------------------------------------
// R-SH-004, the half of it that can execute.
//
// The rule says a shielded transaction may be the coinstake only when its
// version is the NullStake generation permitted at that height. Two clauses
// enforce that and only one of them can run.
//
//   version set   CTransaction::CheckTransaction refuses a coinstake under any
//                 shielded version outside {2003, 2004, 2005}. Covered here.
//   height window CBlock::ConnectBlock refuses a permitted version outside its
//                 own generation's height range. NOT covered, and not coverable:
//                 the only version whose branch and window disagree is 2003 at
//                 or above the V2 fork, that branch requires a shielded spend,
//                 and a spend's anchor must be MIN_SHIELDED_SPEND_DEPTH blocks
//                 deep while proof-of-stake blocks stop connecting at the DAG
//                 gate -- one block sooner than the earliest anchor can age.
//                 The arithmetic is asserted below so the day a gate moves this
//                 case says so.
//
// No covering edge rests on this case: half a rule tested is not the rule.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_shielded_coinstake_is_refused_outside_the_nullstake_versions)
{
    LadderGuard guard;
    TipHeightGuard tipGuard;
    guard.SelectRegtest();
    BOOST_REQUIRE(!IsLegacyPrivacyPolicyDisabled());
    nBestHeight = FORK_HEIGHT_NULLSTAKE_V3 + 1;

    // A coinstake-shaped shielded transaction: a spend, an empty first output,
    // and the reward paid into the pool.
    CTransaction shape;
    shape.nTime = (unsigned int)GetAdjustedTime();
    shape.vin.push_back(CTxIn(uint256(0x5104), 0));
    shape.vout.resize(2);
    shape.vout[0].SetEmpty();
    shape.vout[1].nValue = 1 * COIN;
    shape.vShieldedSpend.resize(1);
    shape.vShieldedSpend[0].nullifier = uint256(0x5105);
    shape.nValueBalance = -1;

    // The three NullStake generations are admitted by this clause.
    const int nAllowed[] = {SHIELDED_TX_VERSION_NULLSTAKE,
                            SHIELDED_TX_VERSION_NULLSTAKE_V2,
                            SHIELDED_TX_VERSION_NULLSTAKE_COLD};
    for (size_t i = 0; i < sizeof(nAllowed) / sizeof(nAllowed[0]); ++i)
    {
        CTransaction tx = shape;
        tx.nVersion = nAllowed[i];
        BOOST_REQUIRE(tx.IsCoinStake() && tx.IsShielded());
        Outcome out = RunCheckTransaction(tx);
        BOOST_CHECK_MESSAGE(out.fAccepted,
            "NullStake generation " << nAllowed[i] << " was refused as a "
            "coinstake: " << Excerpt(out.strLog));
    }

    // Every other shielded version is not.
    for (int nVersion = SHIELDED_TX_VERSION;
         nVersion <= SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM; ++nVersion)
    {
        if (nVersion == SHIELDED_TX_VERSION_NULLSTAKE ||
            nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2 ||
            nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
            continue;
        CTransaction tx = shape;
        tx.nVersion = nVersion;
        BOOST_REQUIRE(tx.IsCoinStake() && tx.IsShielded());
        ExpectReason(RunCheckTransaction(tx),
                     "shielded transaction cannot be coinstake",
                     strprintf("a coinstake under shielded version %d", nVersion));
    }

    // Why the height window below this clause cannot be reached, as arithmetic.
    BOOST_CHECK_MESSAGE(
        FORK_HEIGHT_SHIELDED + MIN_SHIELDED_SPEND_DEPTH >= FORK_HEIGHT_DAG,
        "a shielded spend's anchor can now age past MIN_SHIELDED_SPEND_DEPTH "
        "while proof-of-stake blocks still connect, so the NullStake "
        "generation-window branch in ConnectBlock has become reachable and this "
        "suite should cover it");
}

// ---------------------------------------------------------------------------
// R-SEAL-004: a block with an FCMP-era shielded spend does not connect; one field per arm.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_block_carrying_an_fcmp_era_shielded_spend_does_not_connect)
{
    LadderGuard guard;
    guard.SelectRegtest();

    const char* kFCMPEra =
        "carries an FCMP-era shielded spend whose membership is unverifiable; "
        "the encoding is permanently invalid";

    MineTo(BestIndex()->nHeight + 2);
    BOOST_REQUIRE_GE(BestIndex()->nHeight + 1, FORK_HEIGHT_FCMP_VALIDATION);

    Candidate control;
    BOOST_REQUIRE(BuildCandidate(control));
    BOOST_REQUIRE(SealCandidate(control));
    ConnectOutcome ok = ConnectAndRollBack(control);
    BOOST_REQUIRE_MESSAGE(ok.Ok(),
        "the producer's own block was refused; captured: " + Excerpt(ok.strLog));

    CBlockIndex* pFunding = AncestorAtHeight(BestIndex()->nHeight - 1);
    BOOST_REQUIRE(pFunding != NULL);
    CBlock funding;
    BOOST_REQUIRE(funding.ReadFromDisk(pFunding, true));
    BOOST_REQUIRE(!funding.vtx.empty());

    // One shielded-spend-carrying transaction, built once and re-versioned per
    // arm. Only the version and the spend vector are read by the rule.
    CTransaction spendShape;
    spendShape.vin.push_back(CTxIn(funding.vtx[0].GetHash(), 0));
    spendShape.vout.push_back(CTxOut(1, funding.vtx[0].vout[0].scriptPubKey));
    spendShape.vShieldedSpend.resize(1);
    spendShape.vShieldedSpend[0].nullifier = uint256(0xFC3D01);
    spendShape.vShieldedSpend[0].cv = SomeCommitment(1);

    // Every FCMP-era version, including the three NullStake generations and the
    // reclaim version, is refused.
    const int nEraVersions[] = {SHIELDED_TX_VERSION_FCMP,
                                SHIELDED_TX_VERSION_NULLSTAKE,
                                SHIELDED_TX_VERSION_NULLSTAKE_V2,
                                SHIELDED_TX_VERSION_NULLSTAKE_COLD,
                                SHIELDED_TX_VERSION_MOFN_MINT,
                                SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM};
    for (size_t i = 0; i < sizeof(nEraVersions) / sizeof(nEraVersions[0]); ++i)
    {
        Candidate cb;
        BOOST_REQUIRE(BuildCandidate(cb));
        CTransaction tx = spendShape;
        tx.nVersion = nEraVersions[i];
        tx.nTime = cb.block.nTime;
        cb.block.vtx.push_back(tx);
        BOOST_REQUIRE(SealCandidate(cb));
        ExpectBlockReason(ConnectAndRollBack(cb), kFCMPEra,
                          strprintf("a block carrying a version-%d shielded spend",
                                    nEraVersions[i]));
    }

    // The version leg. One version below the floor, same spend vector: refused
    // for its own reasons, never with this one.
    {
        Candidate cb;
        BOOST_REQUIRE(BuildCandidate(cb));
        CTransaction tx = spendShape;
        tx.nVersion = SHIELDED_TX_VERSION_FCMP - 1;
        tx.nTime = cb.block.nTime;
        cb.block.vtx.push_back(tx);
        BOOST_REQUIRE(SealCandidate(cb));
        ConnectOutcome out = ConnectAndRollBack(cb);
        BOOST_CHECK_MESSAGE(!LogHas(out.strLog, kFCMPEra),
            "the rule fired below the FCMP version floor, so the arms above are "
            "the fixture and not the rule; captured: " + Excerpt(out.strLog));
    }

    // The emptiness leg, at the FCMP version. This is the vNext envelope's shape
    // too: a version at or above the floor carrying no shielded spend.
    {
        Candidate cb;
        BOOST_REQUIRE(BuildCandidate(cb));
        CTransaction tx = spendShape;
        tx.nVersion = SHIELDED_TX_VERSION_FCMP;
        tx.nTime = cb.block.nTime;
        tx.vShieldedSpend.clear();
        cb.block.vtx.push_back(tx);
        BOOST_REQUIRE(SealCandidate(cb));
        ConnectOutcome out = ConnectAndRollBack(cb);
        BOOST_CHECK_MESSAGE(!LogHas(out.strLog, kFCMPEra),
            "the rule fired on a transaction carrying no shielded spend, so it "
            "covers the vNext envelope as well; captured: " + Excerpt(out.strLog));
    }

    // The same, at the vNext version itself.
    {
        Candidate cb;
        BOOST_REQUIRE(BuildCandidate(cb));
        CTransaction tx = spendShape;
        tx.nVersion = SHIELDED_TX_VERSION_DSP;
        tx.nTime = cb.block.nTime;
        tx.vShieldedSpend.clear();
        cb.block.vtx.push_back(tx);
        BOOST_REQUIRE(SealCandidate(cb));
        ConnectOutcome out = ConnectAndRollBack(cb);
        BOOST_CHECK_MESSAGE(!LogHas(out.strLog, kFCMPEra),
            "the rule fired on the vNext envelope; captured: " + Excerpt(out.strLog));
    }
}


// ---------------------------------------------------------------------------
// R-MASK-014: a coinbase IV5 payload spends nothing, charges no fee, balance = fee sum.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(a_coinbase_iv5_note_is_worth_exactly_the_block_iv5_fee_sum)
{
    LadderGuard guard;
    guard.SelectRegtest();
    WalletIV5SeedGuard seedGuard;
    NameHooksGuard hooksGuard;

    // The pool balance record is only allowed to be absent at the boundary block
    // itself, so the boundary is the block under test. The fee-note fork rides
    // the same height, which is the flag day the two share.
    const int nHeight = BestIndex()->nHeight + 1;
    nRegtestBoundaryBHeight = nHeight;
    nRegtestIV5FeeNoteHeight = nHeight;
    fRegtestShieldedVNextRehearsal = true;
    BOOST_REQUIRE(IsShieldedVNextConsensusReady());
    BOOST_REQUIRE(IsIV5FeeNoteActiveAtHeight(nHeight));

    const std::string strFrom = FundedTransparentAddress(2 * MIN_TX_FEE_SHIELDED);
    BOOST_REQUIRE_MESSAGE(!strFrom.empty(),
                          "the wallet holds no spendable transparent output");

    CWalletTx wtxShield;
    int64_t nShielded = 0;
    size_t nInputsUsed = 0;
    std::string strError;
    std::string strShieldLog;
    bool fShield = false;
    {
        LogCapture capture;
        fShield = pwalletMain->CreatePrivacyVNextShield(strFrom, 1, true, wtxShield,
                                                        nShielded, nInputsUsed,
                                                        strError);
        strShieldLog = capture.Release();
    }
    BOOST_REQUIRE_MESSAGE(fShield,
        "could not build the shield that pays this block's IV5 fee: " + strError +
        "; captured: " + Excerpt(strShieldLog));
    BOOST_REQUIRE(wtxShield.IsPrivacyVNext());

    // The producer's own block. It carries the shield and the coinbase note the
    // miner attached; without it connecting, every arm below would be refused
    // for reasons that have nothing to do with this rule.
    Candidate control;
    BOOST_REQUIRE(BuildCandidate(control));
    BOOST_REQUIRE_EQUAL(control.Height(), nHeight);
    bool fCarriesShield = false;
    for (unsigned int i = 1; i < control.block.vtx.size(); ++i)
        fCarriesShield = fCarriesShield ||
                         control.block.vtx[i].GetHash() == wtxShield.GetHash();
    BOOST_REQUIRE_MESSAGE(fCarriesShield,
                          "the producer did not include the shield, so the block "
                          "carries no IV5 fee for the note to collect");
    BOOST_REQUIRE_MESSAGE(control.block.vtx[0].IsPrivacyVNext(),
                          "the producer did not attach a coinbase IV5 note");

    const int64_t nFeeSum = DeclaredIV5FeeSum(control.block);
    BOOST_REQUIRE_GT(nFeeSum, 0);

    const CTransaction coinbaseTemplate = control.block.vtx[0];
    BOOST_REQUIRE(SealCandidate(control));
    ConnectOutcome ok = ConnectAndRollBack(control);
    BOOST_REQUIRE_MESSAGE(ok.Ok(),
        "the producer's own fee-note block was refused; captured: " +
        Excerpt(ok.strLog));

    // -- the shape half, in CheckTransaction --------------------------------
    // A coinbase payload charging a fee would take value out of the pool.
    {
        CTransaction charging = coinbaseTemplate;
        charging.privacyVNext.vchPayload =
            BuildShieldPayload(charging, (uint64_t)nFeeSum + 1000, 1000);
        ExpectReason(RunCheckTransaction(charging),
                     "coinbase IV5 payload charges a fee",
                     "a coinbase note that charges a fee");
    }

    // A coinbase payload that takes nothing into the pool is a payload with no
    // reason to be on a coinbase at all, and the equality below would hold
    // vacuously for it.
    {
        CTransaction empty = coinbaseTemplate;
        empty.privacyVNext.vchPayload = BuildShieldPayload(empty, 0, 0);
        ExpectReason(RunCheckTransaction(empty),
                     "coinbase IV5 payload takes no value into the pool",
                     "a coinbase note declaring no value");
    }

    // The control for both: the miner's own note passes the shape checks.
    {
        CTransaction good = coinbaseTemplate;
        Outcome shapeOk = RunCheckTransaction(good);
        BOOST_CHECK_MESSAGE(shapeOk.fAccepted,
            "the miner's own coinbase note failed the shape checks; captured: " +
            Excerpt(shapeOk.strLog));
    }

    // -- the equality half, in ConnectBlock ---------------------------------
    // One satoshi above the fee sum; only the equality can refuse it.
    {
        Candidate over;
        BOOST_REQUIRE(BuildCandidate(over));
        std::string strNote;
        std::vector<unsigned char> vchPayload;
        BOOST_REQUIRE_MESSAGE(
            pwalletMain->BuildPrivacyVNextFeeNote(nFeeSum + 1, over.block.vtx[0],
                                                  vchPayload, strNote),
            strNote);
        over.block.vtx[0].privacyVNext.vchPayload = vchPayload;
        BOOST_REQUIRE(SealCandidate(over));
        ExpectBlockReason(ConnectAndRollBack(over),
                          "against a block IV5 fee sum of",
                          "a coinbase note worth one satoshi more than the fees");
    }

    // And one below, so the refusal is an equality rather than a ceiling.
    {
        Candidate under;
        BOOST_REQUIRE(BuildCandidate(under));
        std::string strNote;
        std::vector<unsigned char> vchPayload;
        BOOST_REQUIRE_MESSAGE(
            pwalletMain->BuildPrivacyVNextFeeNote(nFeeSum - 1, under.block.vtx[0],
                                                  vchPayload, strNote),
            strNote);
        under.block.vtx[0].privacyVNext.vchPayload = vchPayload;
        BOOST_REQUIRE(SealCandidate(under));
        ExpectBlockReason(ConnectAndRollBack(under),
                          "against a block IV5 fee sum of",
                          "a coinbase note worth one satoshi less than the fees");
    }

    // A note in a block with no IV5 fee at all: the sum is zero and the note
    // would credit the pool with value no transaction ever paid.
    {
        Candidate lone;
        BOOST_REQUIRE(BuildCandidate(lone));
        std::vector<CTransaction> vKept;
        vKept.push_back(lone.block.vtx[0]);
        for (unsigned int i = 1; i < lone.block.vtx.size(); ++i)
            if (!lone.block.vtx[i].IsPrivacyVNext())
                vKept.push_back(lone.block.vtx[i]);
        lone.block.vtx = vKept;
        BOOST_REQUIRE_EQUAL(DeclaredIV5FeeSum(lone.block), 0);
        BOOST_REQUIRE(SealCandidate(lone));
        ExpectBlockReason(ConnectAndRollBack(lone),
                          "coinbase IV5 note in a block with no IV5 fees",
                          "a coinbase note in a block that collected no IV5 fees");
    }

    // A fee note may declare only one mask; any other is a per-producer
    // fingerprint. Each arm builds the note at another mask.
    {
        // The control for the arms below: the same helper, at the pinned mask,
        // produces a note this block connects with. Without it a refusal could be
        // anything about a rebuilt note rather than the mask it declares.
        Candidate rebuilt;
        BOOST_REQUIRE(BuildCandidate(rebuilt));
        rebuilt.block.vtx[0].privacyVNext.vchPayload =
            BuildShieldPayload(rebuilt.block.vtx[0], (uint64_t)nFeeSum, 0,
                               iv5::COINBASE_FEE_NOTE_DISCLOSURE_MASK);
        BOOST_REQUIRE(SealCandidate(rebuilt));
        ConnectOutcome rebuiltOk = ConnectAndRollBack(rebuilt);
        BOOST_CHECK_MESSAGE(rebuiltOk.Ok(),
            "a fee note rebuilt at the pinned mask was refused; captured: " +
            Excerpt(rebuiltOk.strLog));
    }

    for (unsigned nMask = 0; nMask <= iv5::DISCLOSURE_MASK; ++nMask)
    {
        if (nMask == iv5::COINBASE_FEE_NOTE_DISCLOSURE_MASK)
            continue;
        Candidate other;
        BOOST_REQUIRE(BuildCandidate(other));
        other.block.vtx[0].privacyVNext.vchPayload =
            BuildShieldPayload(other.block.vtx[0], (uint64_t)nFeeSum, 0,
                               (uint8_t)nMask);
        BOOST_REQUIRE(SealCandidate(other));
        ExpectBlockReason(ConnectAndRollBack(other),
                          "coinbase IV5 note does not declare the fee note's",
                          strprintf("a coinbase note built at mask %u", nMask));
    }

    // And below the fork the coinbase may carry no payload at all, whatever it
    // declares: the transparent allowance still carries the fees there, so a
    // note would be the second payment of the same money.
    {
        Candidate early;
        BOOST_REQUIRE(BuildCandidate(early));
        BOOST_REQUIRE(SealCandidate(early));
        nRegtestIV5FeeNoteHeight = early.Height() + 1;
        BOOST_REQUIRE(!IsIV5FeeNoteActiveAtHeight(early.Height()));
        ExpectBlockReason(ConnectAndRollBack(early),
                          "coinbase IV5 payload before height",
                          "a coinbase note below the fee-note fork");
        nRegtestIV5FeeNoteHeight = nHeight;
    }
}

BOOST_AUTO_TEST_SUITE_END()
