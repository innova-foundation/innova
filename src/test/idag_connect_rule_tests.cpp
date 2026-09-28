// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Post-DAG rules in ConnectBlock, CheckTallyCertificate and LoadDAGLinks, each arm after a
// passing control. Mines past the DAG fork, so it is linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "../bignum.h"
#include "../dag.h"
#include "../finality.h"
#include "../hooks.h"
#include "../key.h"
#include "../main.h"
#include "../miner.h"
#include "../namecoin.h"
#include "../script.h"
#include "../txdb.h"
#include "../util.h"
#include "../wallet.h"

extern CWallet* pwalletMain;
extern bool fPrintToConsole;
extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(idag_connect_rule_tests)

namespace {

// The suite mines real blocks. A registered wallet would record their coinbases,
// moving the ordering counters other suites pin.
struct DetachedWalletGuard
{
    DetachedWalletGuard() { UnregisterWallet(pwalletMain); }
    ~DetachedWalletGuard() { RegisterWallet(pwalletMain); }
};

struct MockClockGuard
{
    ~MockClockGuard() { SetMockTime(0); }
};

// One validation call's log output. The rules under test are several branches
// apart and all of them return false, so matching the rejection the site prints
// is what separates "refused for the reason claimed" from "refused".
class ConnectLog
{
public:
    ConnectLog() : nSavedFd(-1), fSavedPrintToConsole(fPrintToConsole), pFile(NULL) {}

    bool Begin()
    {
        pFile = tmpfile();
        if (pFile == NULL)
            return false;
        fflush(stdout);
        nSavedFd = dup(fileno(stdout));
        if (nSavedFd == -1 || dup2(fileno(pFile), fileno(stdout)) == -1)
            return false;
        fPrintToConsole = true;
        return true;
    }

    std::string End()
    {
        fPrintToConsole = fSavedPrintToConsole;
        fflush(stdout);
        if (nSavedFd != -1)
        {
            dup2(nSavedFd, fileno(stdout));
            close(nSavedFd);
            nSavedFd = -1;
        }
        std::string out;
        if (pFile != NULL)
        {
            rewind(pFile);
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), pFile)) > 0)
                out.append(buf, n);
            fclose(pFile);
            pFile = NULL;
        }
        return out;
    }

    ~ConnectLog()
    {
        if (pFile != NULL || nSavedFd != -1)
            End();
    }

private:
    int nSavedFd;
    bool fSavedPrintToConsole;
    FILE* pFile;
};

bool Says(const std::string& strLog, const char* pszReason)
{
    return strLog.find(pszReason) != std::string::npos;
}

CBlockIndex* BestIndex()
{
    LOCK(cs_main);
    return pindexBest;
}

CBlockIndex* IndexOf(const uint256& hash)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::const_iterator mi = mapBlockIndex.find(hash);
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

CBlockIndex* ParentOf(const CBlock& block)
{
    return IndexOf(block.hashPrevBlock);
}

bool GrindHeader(CBlock* pblock)
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

// Seal a template the caller has already filled and put it on the chain.
bool SealAndProcess(CBlock* pblock, CBlockIndex* pindexParent, std::string& strLogOut)
{
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock, pindexParent, nExtraNonce);
    if (!GrindHeader(pblock))
        return false;
    ConnectLog log;
    if (!log.Begin())
        return false;
    const bool fAccepted = ProcessBlock(NULL, pblock);
    strLogOut = log.End();
    return fAccepted;
}

// Seal a template whose coinbase the caller has finished editing, so the merkle
// tree is rebuilt here rather than by IncrementExtraNonce.
bool SealEditedAndProcess(CBlock* pblock, std::string& strLogOut)
{
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    if (!GrindHeader(pblock))
        return false;
    ConnectLog log;
    if (!log.Begin())
        return false;
    const bool fAccepted = ProcessBlock(NULL, pblock);
    strLogOut = log.End();
    return fAccepted;
}

bool MineOne(CBlock& blockOut, std::string& strLogOut)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexParent = ParentOf(*pblock);
    if (pindexParent == NULL)
        return false;
    if (!SealAndProcess(pblock.get(), pindexParent, strLogOut))
        return false;
    blockOut = *pblock;
    return true;
}

void MineTo(int nTarget)
{
    while (BestIndex()->nHeight < nTarget)
    {
        CBlock block;
        std::string strLog;
        BOOST_REQUIRE_MESSAGE(MineOne(block, strLog),
                              "could not extend the chain to " << nTarget
                              << "; log: " << strLog);
    }
}

// Past the DAG fork and off any settlement height, so a candidate's coinbase
// allowance is one quantity rather than one carrying a settlement leg too.
void MineToPlainPostDAG()
{
    MineTo(FORK_HEIGHT_DAG + 2);
    while (IsFinalitySettlementHeight(BestIndex()->nHeight + 1))
        MineTo(BestIndex()->nHeight + 1);
}

// A template on the tip together with the stack index ConnectBlock is handed.
// Edit the block, then Seal: the merkle root and the work are recomputed there.
struct Candidate
{
    CBlock block;
    uint256 hash;
    CBlockIndex index;
    CBlockIndex* pparent;

    Candidate() : pparent(NULL) {}
    CBlockIndex* Index() { return &index; }
    int Height() const { return index.nHeight; }
    CTransaction& Coinbase() { return block.vtx[0]; }
};

bool BuildCandidate(Candidate& out)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexParent = ParentOf(*pblock);
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
    if (!GrindHeader(&out.block))
        return false;
    out.hash = out.block.GetHash();
    out.index = CBlockIndex(0, 0, out.block);
    out.index.pprev = out.pparent;
    out.index.nHeight = out.pparent->nHeight + 1;
    out.index.phashBlock = &out.hash;
    return true;
}

// Connect and discard every write. Without the abort an accepted arm would spend
// this chain's outputs for the rest of the binary.
CBlock::ConnectResult ConnectAndRollBack(Candidate& cb, std::string& strLogOut)
{
    LOCK(cs_main);
    CTxDB txdb;
    CBlock::ConnectResult result = CBlock::CONNECT_RESULT_INVALID;
    BOOST_REQUIRE(txdb.TxnBegin());
    ConnectLog log;
    BOOST_REQUIRE(log.Begin());
    const bool fConnected = cb.block.ConnectBlock(txdb, cb.Index(), false, false, &result);
    strLogOut = log.End();
    BOOST_REQUIRE(txdb.TxnAbort());
    BOOST_CHECK_EQUAL(fConnected, result == CBlock::CONNECT_RESULT_OK);
    return result;
}

// The coinbase output carrying the producer's payout. Chosen by value rather than
// position: the IDAG commitment is a zero-value OP_RETURN whose index is the
// producer's to choose.
unsigned int LargestCoinbaseOutput(const CTransaction& coinbase)
{
    unsigned int nBest = 0;
    for (unsigned int i = 1; i < coinbase.vout.size(); i++)
        if (coinbase.vout[i].nValue > coinbase.vout[nBest].nValue)
            nBest = i;
    return nBest;
}

const char* DAG005_ALLOWANCE = "ConnectBlock() : coinbase reward exceeded";
const char* DAG005_CONSERVE  = "ConnectBlock() : block mints value";

} // namespace

// R-DAG-005: block-level value conservation. The allowance check refuses an
// over-paying block first, at DoS 50 rather than 100.
BOOST_AUTO_TEST_CASE(block_value_conservation_stands_behind_the_coinbase_allowance)
{
    BOOST_REQUIRE(fRegTest);
    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;
    SetMockTime(GetTime() + 10 * CollateralnodePaymentWindowSeconds());

    MineToPlainPostDAG();

    // Control: the producer's own block connects, so every arm below differs from
    // an accepted block by exactly the edit it makes.
    Candidate control;
    BOOST_REQUIRE(BuildCandidate(control));
    BOOST_REQUIRE(SealCandidate(control));
    BOOST_REQUIRE_MESSAGE(control.Height() >= FORK_HEIGHT_DAG,
                          "the conservation branch is gated on the DAG height and "
                          "this candidate is at " << control.Height());
    BOOST_REQUIRE(control.block.IsProofOfWork());
    std::string strControlLog;
    BOOST_REQUIRE_MESSAGE(ConnectAndRollBack(control, strControlLog) ==
                              CBlock::CONNECT_RESULT_OK,
                          "the producer's own block was refused, so every arm below "
                          "would pass for the wrong reason; log: " << strControlLog);
    BOOST_CHECK(!Says(strControlLog, DAG005_ALLOWANCE));
    BOOST_CHECK(!Says(strControlLog, DAG005_CONSERVE));

    // One satoshi over the allowance. Both candidate rules would refuse this
    // block; the allowance is the one that runs first, and it scores 50.
    Candidate over;
    BOOST_REQUIRE(BuildCandidate(over));
    const unsigned int nOut = LargestCoinbaseOutput(over.Coinbase());
    BOOST_REQUIRE(over.Coinbase().vout[nOut].nValue > 0);
    over.Coinbase().vout[nOut].nValue += 1;
    BOOST_REQUIRE(SealCandidate(over));
    over.block.nDoS = 0;
    std::string strOverLog;
    BOOST_CHECK_MESSAGE(ConnectAndRollBack(over, strOverLog) ==
                            CBlock::CONNECT_RESULT_INVALID,
                        "a coinbase one satoshi above the allowance was accepted; log: "
                        << strOverLog);
    BOOST_CHECK_MESSAGE(Says(strOverLog, DAG005_ALLOWANCE),
                        "the refusal did not come from the coinbase allowance; log: "
                        << strOverLog);
    BOOST_CHECK_MESSAGE(!Says(strOverLog, DAG005_CONSERVE),
                        "the block-level conservation branch refused a block the "
                        "allowance check refuses first; the two lines have swapped "
                        "order; log: " << strOverLog);
    BOOST_CHECK_MESSAGE(over.block.nDoS == 50,
                        "an over-paying coinbase scored " << over.block.nDoS
                        << " instead of the allowance check's 50");

    // A gross overpayment takes the same line. The conservation branch compares
    // nValueOut against nValueIn, so a reader could expect a large enough
    // overpayment to reach it. It does not, and that is the shadow recorded here.
    Candidate gross;
    BOOST_REQUIRE(BuildCandidate(gross));
    const unsigned int nGrossOut = LargestCoinbaseOutput(gross.Coinbase());
    gross.Coinbase().vout[nGrossOut].nValue += 1000 * COIN;
    BOOST_REQUIRE(SealCandidate(gross));
    gross.block.nDoS = 0;
    std::string strGrossLog;
    BOOST_CHECK(ConnectAndRollBack(gross, strGrossLog) == CBlock::CONNECT_RESULT_INVALID);
    BOOST_CHECK_MESSAGE(Says(strGrossLog, DAG005_ALLOWANCE), "log: " << strGrossLog);
    BOOST_CHECK_MESSAGE(!Says(strGrossLog, DAG005_CONSERVE), "log: " << strGrossLog);
    BOOST_CHECK_EQUAL(gross.block.nDoS, 50);
}

// R-DAG-009: below the DAG fork a tagged OP_RETURN is plain data; at or above it a PoW
// block validates the carrier and a PoS block is refused.

namespace {

const char* DAG009_VOTES  =
    "ConnectBlock() : finality votes are only valid in post-DAG proof-of-work blocks";
const char* DAG009_SHARES =
    "ConnectBlock() : finality tally shares are only valid in post-DAG proof-of-work blocks";
const char* DAG009_CERTS  =
    "ConnectBlock() : finality tally certificates are only valid in post-DAG proof-of-work blocks";

// The carrier's own validation, several hundred lines past the gate. Seeing one
// of these is what proves a control reached the gate and was let through.
bool SaysCarrierWasValidatedLater(const std::string& strLog)
{
    return Says(strLog, "ConnectBlock() : finality stake proof spent in including block") ||
           Says(strLog, "ConnectBlock() : finality vote commitments invalid") ||
           Says(strLog, "ConnectBlock() : finality vote invalid") ||
           Says(strLog, "ConnectBlock() : finality tally share invalid") ||
           Says(strLog, "ConnectBlock() : finality tally certificate invalid") ||
           Says(strLog, "ConnectBlock() : finality tally certificate has wrong epoch boundary");
}

CFinalityVote CarrierVote(int nEpoch, int nHeight, const uint256& hashBlock)
{
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    vote.nEpoch = nEpoch;
    vote.nHeight = nHeight;
    vote.hashBlock = hashBlock;
    vote.nTime = 1000;
    vote.nVoteWeight = 1000 * COIN;
    vote.nReward = 0;
    vote.nullifier = uint256(0x0d0a9001);
    vote.vStakeProof.push_back(COutPoint(uint256(0x0d0a9002), 0));
    vote.vchPubKey = std::vector<unsigned char>(33, 0x02);
    vote.vchSig = std::vector<unsigned char>(70, 0x30);
    return vote;
}

CFinalityTallyShare CarrierShare(int nEpoch)
{
    CFinalityTallyShare share;
    share.nVersion = 2;
    share.nEpoch = nEpoch;
    share.voteNullifier = uint256(0x0d0a9003);
    share.hashBlock = uint256(0x0d0a9004);
    return share;
}

CFinalityTallyCertificate CarrierCert(int nEpoch, int nHeight, const uint256& hashBlock)
{
    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = nEpoch;
    cert.hashBlock = hashBlock;
    cert.nHeight = nHeight;
    cert.nTier = FINALITY_HARD;
    cert.nTransparentActiveWeight = 1000 * COIN;
    cert.nTransparentWinningWeight = 1000 * COIN;
    cert.nTransparentRewardBudget = 0;
    cert.vVoteNullifiers.push_back(uint256(0x0d0a9005));
    cert.vVoteNullifiers.push_back(uint256(0x0d0a9006));
    return cert;
}

void AppendCoinbaseCarrier(Candidate& cb, const CScript& script)
{
    CTxOut out;
    out.nValue = 0;
    out.scriptPubKey = script;
    cb.Coinbase().vout.push_back(out);
}

// A proof-of-stake block on the tip, built rather than mined (its coinbase may carry
// only an empty output and zero-value OP_RETURNs). The coinstake is unsigned; checks
// up to the carrier gate read only the block's shape.
bool BuildProofOfStakeCandidate(const CScript* pCarrier, Candidate& out)
{
    CBlockIndex* pindexPrev = BestIndex();
    if (pindexPrev == NULL)
        return false;
    const unsigned int nTime = (unsigned int)(pindexPrev->GetBlockTime() + 1);
    const int nHeight = pindexPrev->nHeight + 1;

    CTransaction coinbase;
    coinbase.nTime = nTime;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << nHeight << CBigNum(1);
    coinbase.vout.resize(1);
    coinbase.vout[0].SetEmpty();
    if (pCarrier != NULL)
    {
        CTxOut carrier;
        carrier.nValue = 0;
        carrier.scriptPubKey = *pCarrier;
        coinbase.vout.push_back(carrier);
    }

    CTransaction coinstake;
    coinstake.nTime = nTime;
    coinstake.vin.push_back(CTxIn(COutPoint(uint256(0x0d0a9008), 0)));
    coinstake.vout.push_back(CTxOut());
    coinstake.vout[0].SetEmpty();
    coinstake.vout.push_back(CTxOut(1 * CENT, CScript() << OP_TRUE));

    out.block.SetNull();
    out.block.nVersion = CBlock::CURRENT_VERSION;
    out.block.hashPrevBlock = pindexPrev->GetBlockHash();
    out.block.nTime = nTime;
    out.block.nBits = GetNextTargetRequired(pindexPrev, true);
    out.block.nNonce = 0;
    out.block.vtx.push_back(coinbase);
    out.block.vtx.push_back(coinstake);
    out.block.hashMerkleRoot = out.block.BuildMerkleTree();
    if (!out.block.IsProofOfStake())
        return false;

    out.pparent = pindexPrev;
    out.hash = out.block.GetHash();
    out.index = CBlockIndex(0, 0, out.block);
    out.index.pprev = pindexPrev;
    out.index.nHeight = nHeight;
    out.index.phashBlock = &out.hash;
    return true;
}

// The ancestor at nHeight, walked back from the tip.
CBlockIndex* AncestorAt(int nHeight)
{
    LOCK(cs_main);
    CBlockIndex* p = pindexBest;
    while (p != NULL && p->nHeight > nHeight)
        p = p->pprev;
    return (p != NULL && p->nHeight == nHeight) ? p : NULL;
}

// One carrier, driven three ways. The block arms straddle the DAG fork, both below
// Boundary A, where the carrier envelope is chosen by height.
void RunCarrierArms(const char* pszCarrier, const CScript& carrierScript,
                    const char* strReason, int nPostForkHeight, int nPreForkHeight)
{
    BOOST_TEST_MESSAGE("carrier: " << pszCarrier);
    CBlockIndex* pPostParent = AncestorAt(nPostForkHeight - 1);
    CBlockIndex* pPreParent = AncestorAt(nPreForkHeight - 1);
    BOOST_REQUIRE(pPostParent != NULL && pPreParent != NULL);

    // Control: post-DAG height, proof-of-work block. The gate lets it through and the
    // carrier's own validation refuses it.
    Candidate powCarrier;
    BOOST_REQUIRE(BuildCandidate(powCarrier));
    AppendCoinbaseCarrier(powCarrier, carrierScript);
    BOOST_REQUIRE(SealCandidate(powCarrier));
    BOOST_REQUIRE(powCarrier.block.IsProofOfWork());
    powCarrier.index.pprev = pPostParent;
    powCarrier.index.nHeight = nPostForkHeight;
    BOOST_REQUIRE(powCarrier.Height() >= FORK_HEIGHT_DAG);
    std::string strPowLog;
    ConnectAndRollBack(powCarrier, strPowLog);
    BOOST_CHECK_MESSAGE(!Says(strPowLog, strReason),
                        pszCarrier << ": a post-DAG proof-of-work block was refused "
                        "by the carrier gate; log: " << strPowLog);
    BOOST_CHECK_MESSAGE(SaysCarrierWasValidatedLater(strPowLog),
                        pszCarrier << ": the block never reached the carrier's own "
                        "validation, so nothing here shows the gate was passed "
                        "rather than skipped; log: " << strPowLog);

    // Arm: the same block, one height lower, below the DAG fork. The carrier is
    // plain data there: no gate refusal, no envelope refusal, no validation.
    Candidate preDag;
    BOOST_REQUIRE(BuildCandidate(preDag));
    AppendCoinbaseCarrier(preDag, carrierScript);
    BOOST_REQUIRE(SealCandidate(preDag));
    preDag.index.pprev = pPreParent;
    preDag.index.nHeight = nPreForkHeight;
    BOOST_REQUIRE(preDag.Height() < FORK_HEIGHT_DAG);
    Candidate preDagPlain;
    BOOST_REQUIRE(BuildCandidate(preDagPlain));
    BOOST_REQUIRE(SealCandidate(preDagPlain));
    preDagPlain.index.pprev = pPreParent;
    preDagPlain.index.nHeight = nPreForkHeight;
    std::string strPlainLog;
    const CBlock::ConnectResult plainResult = ConnectAndRollBack(preDagPlain, strPlainLog);
    std::string strPreDagLog;
    BOOST_CHECK_MESSAGE(ConnectAndRollBack(preDag, strPreDagLog) == plainResult,
                        pszCarrier << ": below the DAG fork the carrier changed the "
                        "connect result; log: " << strPreDagLog);
    BOOST_CHECK_MESSAGE(!Says(strPreDagLog, strReason),
                        pszCarrier << ": a block below the DAG fork was refused by "
                        "the carrier gate; log: " << strPreDagLog);
    BOOST_CHECK_MESSAGE(!Says(strPreDagLog, "finality vote envelope") &&
                        !Says(strPreDagLog, "finality certificate envelope"),
                        pszCarrier << ": a block below the DAG fork was refused by "
                        "the envelope decoder; log: " << strPreDagLog);
    BOOST_CHECK_MESSAGE(!SaysCarrierWasValidatedLater(strPreDagLog),
                        pszCarrier << ": a carrier below the DAG fork was validated; "
                        "log: " << strPreDagLog);

    // The proof-of-stake half of the gate is shadowed on every reachable input: at or
    // above the DAG height a PoS block is refused for its type at the top of
    // ConnectBlock. This pins which line refuses it.
    Candidate posCarrier;
    BOOST_REQUIRE(BuildProofOfStakeCandidate(&carrierScript, posCarrier));
    BOOST_REQUIRE(posCarrier.block.IsProofOfStake());
    BOOST_REQUIRE(posCarrier.Height() >= FORK_HEIGHT_DAG);
    std::string strPosLog;
    BOOST_CHECK(ConnectAndRollBack(posCarrier, strPosLog) == CBlock::CONNECT_RESULT_INVALID);
    BOOST_CHECK_MESSAGE(
        Says(strPosLog, "ConnectBlock() : proof-of-stake blocks are not allowed after DAG fork"),
        pszCarrier << ": a post-DAG proof-of-stake block was not refused for its "
        "type; log: " << strPosLog);
    BOOST_CHECK_MESSAGE(!Says(strPosLog, strReason),
                        pszCarrier << ": the carrier gate refused a post-DAG "
                        "proof-of-stake block, so it is no longer shadowed by the "
                        "block-type refusal above it; log: " << strPosLog);
}

} // namespace

BOOST_AUTO_TEST_CASE(finality_carriers_are_refused_outside_a_post_dag_proof_of_work_block)
{
    BOOST_REQUIRE(fRegTest);
    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;
    SetMockTime(GetTime() + 10 * CollateralnodePaymentWindowSeconds());

    MineToPlainPostDAG();

    // The pair of heights the arms are connected at: the first block at or above
    // the DAG fork, and the last one below it. Both are below Boundary A, so one
    // envelope serves both and the arms differ only in the height.
    const int nPostForkHeight = FORK_HEIGHT_DAG;
    const int nPreForkHeight = FORK_HEIGHT_DAG - 1;
    BOOST_REQUIRE(nPreForkHeight > 0);
    BOOST_REQUIRE_MESSAGE(!IsBoundaryAActiveAtHeight(nPostForkHeight),
                          "the DAG fork and Boundary A coincide on this network, so "
                          "no height carries the pre-boundary envelope");
    BOOST_REQUIRE_MESSAGE(BestIndex()->nHeight >= nPostForkHeight,
                          "the chain has not reached the DAG fork");

    const int nEpoch = GetEpochForHeight(nPostForkHeight);
    CBlockIndex* pTarget = AncestorAt(nPostForkHeight);
    BOOST_REQUIRE(pTarget != NULL);
    const uint256 hashTarget = pTarget->GetBlockHash();

    CScript voteScript;
    BOOST_REQUIRE(BuildFinalityVoteScriptForHeight(
        CarrierVote(nEpoch, nPostForkHeight, hashTarget), nPostForkHeight, voteScript));
    RunCarrierArms("finality vote", voteScript, DAG009_VOTES,
                   nPostForkHeight, nPreForkHeight);

    const CScript shareScript = BuildFinalityTallyShareScript(CarrierShare(nEpoch));
    RunCarrierArms("tally share", shareScript, DAG009_SHARES,
                   nPostForkHeight, nPreForkHeight);

    // The certificate is given an epoch boundary that is not its own height, so
    // the control's later refusal is the certificate rule rather than an
    // envelope that happens to be well formed.
    CScript certScript;
    BOOST_REQUIRE(BuildFinalityTallyCertificateScriptForHeight(
        CarrierCert(nEpoch, nPostForkHeight + 1, hashTarget), nPostForkHeight,
        certScript));
    RunCarrierArms("tally certificate", certScript, DAG009_CERTS,
                   nPostForkHeight, nPreForkHeight);
}

// R-DAG-010: a tally certificate must target a post-DAG proof-of-work epoch block;
// each arm changes one property of the index it resolves to.

namespace {

const char* DAG010_PREDAG =
    "tally certificates require DAG epoch mode";
const char* DAG010_NOTPOW =
    "tally certificates must target proof-of-work epoch blocks";

// A block index entry standing in mapBlockIndex for one case, removed again on
// scope exit so the shared map is unchanged.
struct ScopedIndexEntry
{
    uint256 hashBlock;
    CBlockIndex index;
    CBlockIndex* pOld;
    bool fHadOld;

    ScopedIndexEntry(const uint256& hashBlockIn, int nHeight)
        : hashBlock(hashBlockIn), pOld(NULL), fHadOld(false)
    {
        LOCK(cs_main);
        std::map<uint256, CBlockIndex*>::iterator itOld = mapBlockIndex.find(hashBlock);
        if (itOld != mapBlockIndex.end())
        {
            fHadOld = true;
            pOld = itOld->second;
        }
        index.nHeight = nHeight;
        index.nFlags = 0; // proof-of-work
        mapBlockIndex[hashBlock] = &index;
        index.phashBlock = &mapBlockIndex.find(hashBlock)->first;
    }

    ~ScopedIndexEntry()
    {
        LOCK(cs_main);
        if (fHadOld)
            mapBlockIndex[hashBlock] = pOld;
        else
            mapBlockIndex.erase(hashBlock);
    }
};

CFinalityVote CertVote(const CKey& key, int nEpoch, int nHeight,
                       const uint256& hashBlock)
{
    CPubKey pubkey = key.GetPubKey();
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    vote.nEpoch = nEpoch;
    vote.nHeight = nHeight;
    vote.hashBlock = hashBlock;
    vote.nTime = 1000;
    vote.nVoteWeight = 1000 * COIN;
    vote.nReward = 0;
    vote.vchPubKey.assign(pubkey.begin(), pubkey.end());
    vote.vStakeProof.push_back(COutPoint(uint256(0x0d0a1001), 0));

    CHashWriter ss(SER_GETHASH, 0);
    ss << vote.vchPubKey;
    ss << vote.nEpoch;
    vote.nullifier = ss.GetHash();
    return vote;
}

// A certificate this node accepts, built from a freshly voted epoch on a private
// tracker so the shared tracker keeps its state.
bool BuildAcceptedCertificate(CFinalityTracker& tracker, int nTargetHeight,
                              const uint256& hashTarget,
                              CFinalityTallyCertificate& certOut,
                              std::string& strError)
{
    const int nEpoch = GetEpochForHeight(nTargetHeight);
    std::vector<CFinalityVote> votes;
    for (int i = 0; i < FINALITY_MIN_VOTERS; ++i)
    {
        CKey key;
        key.MakeNewKey(true);
        CFinalityVote vote = CertVote(key, nEpoch, nTargetHeight, hashTarget);
        vote.MarkCanonicalEnvelope();
        if (!tracker.AddVote(vote, false, true))
            return false;
        votes.push_back(vote);
    }
    return BuildCanonicalTransparentFinalityCertificate(votes, certOut, &strError);
}

} // namespace

BOOST_AUTO_TEST_CASE(a_tally_certificate_must_target_a_post_dag_proof_of_work_epoch_block)
{
    BOOST_REQUIRE(fRegTest);

    // Control: the epoch block is a post-DAG proof-of-work block and the
    // certificate validates. Every arm below is this certificate with one
    // property of the block it names changed.
    const int nTargetHeight = FORK_HEIGHT_BOUNDARY_A;
    BOOST_REQUIRE(nTargetHeight >= FORK_HEIGHT_DAG);
    const int nEpoch = GetEpochForHeight(nTargetHeight);
    BOOST_REQUIRE_EQUAL(GetEpochBoundaryHeight(nEpoch, nTargetHeight), nTargetHeight);
    const int nContextHeight = nTargetHeight + FINALITY_VOTE_INCLUSION_WINDOW;
    const uint256 hashTarget(0x0d0a1002);

    CFinalityTracker tracker;
    CFinalityTallyCertificate cert;
    std::string strBuild;
    {
        ScopedIndexEntry target(hashTarget, nTargetHeight);
        BOOST_REQUIRE_MESSAGE(
            BuildAcceptedCertificate(tracker, nTargetHeight, hashTarget, cert, strBuild),
            "could not build a certificate to test against: " << strBuild);

        CTxDB txdb("r");
        std::string strError;
        BOOST_REQUIRE_MESSAGE(tracker.CheckTallyCertificate(
                                  cert, txdb, &strError, NULL, false,
                                  nContextHeight, false),
                              "the control certificate was refused, so every arm "
                              "below would pass for the wrong reason: " << strError);

        // Arm 1: the same certificate, the same height, a proof-of-stake epoch
        // block. Nothing else about the certificate moves.
        target.index.SetProofOfStake();
        BOOST_REQUIRE(!target.index.IsProofOfWork());
        strError.clear();
        BOOST_CHECK(!tracker.CheckTallyCertificate(cert, txdb, &strError, NULL, false,
                                                   nContextHeight, false));
        BOOST_CHECK_MESSAGE(strError.find(DAG010_NOTPOW) != std::string::npos,
                            "a certificate targeting a proof-of-stake epoch block was "
                            "refused for another reason: " << strError);
    }

    // Arm 2: below the DAG fork. Height 0 is the only epoch boundary regtest has
    // there, and the certificate's own height must equal the block's, so this arm
    // is a separate certificate rather than the same one relabelled.
    const int nPreDagBoundary = GetEpochBoundaryHeight(0, 0);
    BOOST_REQUIRE_MESSAGE(nPreDagBoundary < FORK_HEIGHT_DAG,
                          "epoch 0 does not sit below the DAG fork on this network");
    const uint256 hashPreDag(0x0d0a1003);
    {
        ScopedIndexEntry preDagTarget(hashPreDag, nPreDagBoundary);
        BOOST_REQUIRE(preDagTarget.index.IsProofOfWork());

        CFinalityTracker preDagTracker;
        CFinalityTallyCertificate preDagCert;
        std::string strPreDagBuild;
        BOOST_REQUIRE_MESSAGE(
            BuildAcceptedCertificate(preDagTracker, nPreDagBoundary, hashPreDag,
                                     preDagCert, strPreDagBuild),
            "could not build the below-the-fork certificate: " << strPreDagBuild);
        BOOST_REQUIRE_EQUAL(preDagCert.nHeight, nPreDagBoundary);

        CTxDB txdb("r");
        std::string strError;
        BOOST_CHECK(!preDagTracker.CheckTallyCertificate(
            preDagCert, txdb, &strError, NULL, false,
            nPreDagBoundary + FINALITY_VOTE_INCLUSION_WINDOW, false));
        BOOST_CHECK_MESSAGE(strError.find(DAG010_PREDAG) != std::string::npos,
                            "a certificate targeting a block below the DAG fork was "
                            "refused for another reason: " << strError);
    }
}

// R-DAG-011: a name transaction the DAG ordering skips invalidates the block, since the
// name index is keyed by operation and would depend on sibling arrival order.

namespace {

const char* DAG011_REASON = "ConnectBlock() : DAG conflict in name transaction";

// Spend one output of txFrom back to its own script, less a fee.
bool BuildSpend(const CTransaction& txFrom, unsigned int nOut, int nVersion,
                unsigned int nTime, CTransaction& txOut)
{
    if (nOut >= txFrom.vout.size())
        return false;
    const int64_t nIn = txFrom.vout[nOut].nValue;
    if (nIn <= CENT)
        return false;

    CTransaction tx;
    tx.nVersion = nVersion;
    tx.nTime = nTime;
    tx.vin.push_back(CTxIn(txFrom.GetHash(), nOut));
    tx.vout.push_back(CTxOut(nIn - CENT, txFrom.vout[nOut].scriptPubKey));
    if (!SignSignature(*pwalletMain, txFrom, tx, 0, SIGHASH_ALL))
        return false;
    txOut = tx;
    return true;
}

// The coinbase output a spend can take: the largest one, since the IDAG
// commitment output carries no value.
unsigned int SpendableCoinbaseOutput(const CTransaction& coinbase)
{
    unsigned int nBest = 0;
    for (unsigned int i = 1; i < coinbase.vout.size(); i++)
        if (coinbase.vout[i].nValue > coinbase.vout[nBest].nValue)
            nBest = i;
    return nBest;
}

int FindCommitmentOutput(const CBlock& block)
{
    if (block.vtx.empty())
        return -1;
    for (unsigned int i = 0; i < block.vtx[0].vout.size(); ++i)
    {
        std::vector<uint256> vDecoded;
        std::string strError;
        if (DecodeCanonicalDAGParentScript(block.vtx[0].vout[i].scriptPubKey,
                                           vDecoded, strError) != DAG_PARENT_NOT_FOUND)
            return (int)i;
    }
    return -1;
}

// A merging candidate on the tip that commits [tip, grandparent] and carries one
// conflicting spend, stamped with the template's header time (CheckBlock refuses a
// block older than a transaction it carries).
bool BuildMergingCandidate(const CTransaction& txFrom, unsigned int nOut,
                           int nTxVersion, CBlock& blockOut,
                           CTransaction& txExtraOut)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexPrev = ParentOf(*pblock);
    if (pindexPrev == NULL || pindexPrev->pprev == NULL)
        return false;
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);

    std::vector<uint256> vParents;
    vParents.push_back(pindexPrev->GetBlockHash());
    vParents.push_back(pindexPrev->pprev->GetBlockHash());
    const CScript commitment = BuildDAGParentScript(vParents);
    if (commitment.size() == 0)
        return false;
    const int nCommitOut = FindCommitmentOutput(*pblock);
    if (nCommitOut < 0)
        return false;
    pblock->vtx[0].vout[nCommitOut].scriptPubKey = commitment;

    if (!BuildSpend(txFrom, nOut, nTxVersion, pblock->nTime, txExtraOut))
        return false;
    pblock->vtx.push_back(txExtraOut);
    blockOut = *pblock;
    return true;
}

} // namespace

BOOST_AUTO_TEST_CASE(a_dag_skipped_name_transaction_invalidates_the_block)
{
    BOOST_REQUIRE(fRegTest);
    // The rule's site dereferences the name hooks. AppInit installs them; the
    // unit-test harness does not call it, so without this the site faults rather
    // than refusing the block and the rule is untestable here.
    if (!hooks)
        hooks = InitHook();
    BOOST_REQUIRE(hooks != NULL);
    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;
    SetMockTime(GetTime() + 10 * CollateralnodePaymentWindowSeconds());

    MineToPlainPostDAG();

    // The funding block. Its coinbase is the output both siblings will spend.
    CBlock blockFunding;
    std::string strFundingLog;
    BOOST_REQUIRE_MESSAGE(MineOne(blockFunding, strFundingLog),
                          "could not mine the funding block; log: " << strFundingLog);
    const unsigned int nFundOut = SpendableCoinbaseOutput(blockFunding.vtx[0]);
    BOOST_REQUIRE(blockFunding.vtx[0].vout[nFundOut].nValue > CENT);

    // P, the shared parent. A will extend it and so will the merging block's
    // commitment, which is what makes the two siblings.
    CBlock blockP;
    std::string strPLog;
    BOOST_REQUIRE_MESSAGE(MineOne(blockP, strPLog),
                          "could not mine the shared parent; log: " << strPLog);
    CBlockIndex* pindexP = BestIndex();
    BOOST_REQUIRE(pindexP != NULL);
    BOOST_REQUIRE(pindexP->nHeight >= FORK_HEIGHT_DAG);

    // A: extends P and spends the funding output.
    std::unique_ptr<CBlock> pblockA(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblockA.get() != NULL);
    CBlockIndex* pindexAParent = ParentOf(*pblockA);
    BOOST_REQUIRE(pindexAParent == pindexP);
    CTransaction txSibling;
    BOOST_REQUIRE_MESSAGE(BuildSpend(blockFunding.vtx[0], nFundOut, 1,
                                     pblockA->nTime, txSibling),
                          "could not build the sibling's spend");
    pblockA->vtx.push_back(txSibling);
    std::string strALog;
    BOOST_REQUIRE_MESSAGE(SealAndProcess(pblockA.get(), pindexAParent, strALog),
                          "the sibling block was refused, so the conflict below "
                          "never arises; log: " << strALog);
    const uint256 hashA = pblockA->GetHash();
    BOOST_REQUIRE(BestIndex() != NULL && BestIndex()->GetBlockHash() == hashA);

    // The arm: B commits [A, P] and carries a name transaction spending the
    // output A already spent.
    CBlock blockName;
    CTransaction txName;
    BOOST_REQUIRE_MESSAGE(BuildMergingCandidate(blockFunding.vtx[0], nFundOut,
                                                NAMECOIN_TX_VERSION, blockName,
                                                txName),
                          "could not build the merging block");
    BOOST_REQUIRE(hooks->IsNameTx(txName.nVersion));
    std::string strNameLog;
    const bool fNameAccepted = SealEditedAndProcess(&blockName, strNameLog);
    BOOST_CHECK_MESSAGE(!fNameAccepted,
                        "a block carrying a DAG-skipped name transaction was "
                        "accepted; log: " << strNameLog);
    BOOST_CHECK_MESSAGE(Says(strNameLog, DAG011_REASON),
                        "the block was not refused by the DAG name-conflict rule; "
                        "log: " << strNameLog);
    BOOST_REQUIRE_MESSAGE(BestIndex()->GetBlockHash() == hashA,
                          "the refused block moved the tip");

    // Control: same geometry and spend, one field changed. It connects only because
    // the ordering skipped the transaction, so the arm above was refused for the name
    // version.
    CBlock blockPlain;
    CTransaction txPlain;
    BOOST_REQUIRE(BuildMergingCandidate(blockFunding.vtx[0], nFundOut, 1,
                                        blockPlain, txPlain));
    BOOST_REQUIRE(!hooks->IsNameTx(txPlain.nVersion));
    BOOST_REQUIRE(txPlain.GetHash() != txName.GetHash());
    std::string strPlainLog;
    const bool fPlainAccepted = SealEditedAndProcess(&blockPlain, strPlainLog);
    BOOST_CHECK_MESSAGE(fPlainAccepted,
                        "the same block carrying a plain conflicting transaction "
                        "was refused, so the arm above proves nothing about the "
                        "name rule; log: " << strPlainLog);
    BOOST_CHECK_MESSAGE(!Says(strPlainLog, DAG011_REASON),
                        "log: " << strPlainLog);

    if (fPlainAccepted)
    {
        BOOST_CHECK(BestIndex()->GetBlockHash() == blockPlain.GetHash());
        // The skipped transaction is inactive, so it is not in the transaction index.
        CTxDB txdb("r");
        CTxIndex txindex;
        BOOST_CHECK_MESSAGE(!txdb.ReadTxIndex(txPlain.GetHash(), txindex),
                            "a DAG-skipped transaction was written to the "
                            "transaction index, so it was not skipped at all");
        CTxIndex txindexSibling;
        BOOST_CHECK_MESSAGE(txdb.ReadTxIndex(txSibling.GetHash(), txindexSibling),
                            "the sibling's own spend is missing from the index, so "
                            "the conflict was never between two real spends");
    }
}

// R-BA-007: every retained schema-V3 vertex commits a non-empty bounded parent list
// headed by its own predecessor, else the load fails and asks for a reindex.

namespace {

// A V3-height index chain in mapBlockIndex, with a matching DAG vertex per block
// in LevelDB. Both are removed on scope exit.
struct V3VertexFixture
{
    std::vector<uint256>      vHashes;
    std::vector<CBlockIndex*> vIndex;

    explicit V3VertexFixture(int nCount)
    {
        LOCK(cs_main);
        CTxDB txdb("r+");
        CBlockIndex* pprev = NULL;
        for (int i = 0; i < nCount; i++)
        {
            CBlock header;
            header.nVersion = CBlock::CURRENT_VERSION;
            header.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
            header.nTime = (unsigned int)(1750000000 + i);
            header.nBits = bnProofOfWorkLimit.GetCompact();
            header.nNonce = 0x0ba0070u + i;
            header.hashMerkleRoot = uint256(0x0ba00700u + i);

            const uint256 hash = header.GetHash();
            CBlockIndex* pindex = new CBlockIndex(0, 0, header);
            pindex->nHeight = FORK_HEIGHT_EPOCH_STATE_V3 - 1 + i;
            pindex->pprev = pprev;
            std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
                mapBlockIndex.insert(std::make_pair(hash, pindex));
            BOOST_REQUIRE(ins.second);
            pindex->phashBlock = &ins.first->first;

            vHashes.push_back(hash);
            vIndex.push_back(pindex);
            pprev = pindex;

            WriteVertex(txdb, i, Parents(i));
        }
    }

    ~V3VertexFixture()
    {
        LOCK(cs_main);
        CTxDB txdb("r+");
        for (size_t i = vHashes.size(); i-- > 0; )
        {
            txdb.EraseDAGLinks(vHashes[i]);
            mapBlockIndex.erase(vHashes[i]);
            delete vIndex[i];
        }
    }

    // Entry 0 is the block's own predecessor. The fixture is rooted one block below
    // the schema-V3 height, so the rule applies from the next block.
    std::vector<uint256> Parents(int i) const
    {
        std::vector<uint256> vParents;
        if (i > 0)
            vParents.push_back(vHashes[i - 1]);
        return vParents;
    }

    void WriteVertex(CTxDB& txdb, int i, const std::vector<uint256>& vParents) const
    {
        CBlockDAGData data;
        data.vDAGParents = vParents;
        BOOST_REQUIRE(txdb.WriteDAGLinks(vHashes[i], data));
    }

    void WriteVertex(int i, const std::vector<uint256>& vParents) const
    {
        CTxDB txdb("r+");
        WriteVertex(txdb, i, vParents);
    }

    void EraseVertex(int i) const
    {
        CTxDB txdb("r+");
        BOOST_REQUIRE(txdb.EraseDAGLinks(vHashes[i]));
    }
};

bool LoadsCleanly(std::string* pstrLogOut = NULL)
{
    LOCK(cs_main);
    CTxDB txdb("r");
    CDAGManager manager;
    ConnectLog log;
    const bool fLog = log.Begin();
    const bool fLoaded = manager.LoadDAGLinks(txdb);
    const std::string strLog = fLog ? log.End() : std::string();
    if (pstrLogOut)
        *pstrLogOut = strLog;
    return fLoaded;
}

} // namespace

BOOST_AUTO_TEST_CASE(a_retained_v3_vertex_must_commit_its_own_predecessor_first)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(IsEpochStateV3Configured());

    // Four vertices: one below the schema-V3 height to root the chain, three at
    // and above it. Case arms name index 2, which is a V3 vertex with a V3
    // predecessor.
    V3VertexFixture fixture(4);
    BOOST_REQUIRE(fixture.vIndex[1]->nHeight == FORK_HEIGHT_EPOCH_STATE_V3);
    BOOST_REQUIRE(fixture.vIndex[2]->nHeight > FORK_HEIGHT_EPOCH_STATE_V3);

    // Control: with every retained vertex well formed the load succeeds. Without
    // this, an arm returning false would prove only that the store was unusable
    // for some other reason.
    std::string strLog;
    BOOST_REQUIRE_MESSAGE(LoadsCleanly(&strLog),
                          "the loader refused a well-formed store, so every arm "
                          "below would pass for the wrong reason; log: " << strLog);

    // The loader's fatals all return false, so each arm matches its own: BINDING is
    // the primary-parent rule, PARENT the per-parent resolution behind it.
    const char* BA007_BINDING = "has an invalid primary-parent binding";
    const char* BA007_PARENT  = "references invalid/missing parent";
    const char* BA007_NOVERTEX = "has no DAG vertex";

    // Arm 1: an empty parent list.
    fixture.WriteVertex(2, std::vector<uint256>());
    BOOST_CHECK_MESSAGE(!LoadsCleanly(&strLog),
                        "a retained V3 vertex committing no parent was loaded");
    BOOST_CHECK_MESSAGE(Says(strLog, BA007_BINDING),
                        "an empty parent list was not refused by the primary-parent "
                        "binding; log: " << strLog);
    fixture.WriteVertex(2, fixture.Parents(2));
    BOOST_REQUIRE(LoadsCleanly());

    // Arm 2: a first parent that is not the block's own predecessor. The hash
    // named is a block the store does know, so the per-parent resolution below
    // would accept it and the binding is the only thing that can refuse it.
    {
        std::vector<uint256> vWrong;
        vWrong.push_back(fixture.vHashes[0]);
        fixture.WriteVertex(2, vWrong);
        BOOST_CHECK_MESSAGE(!LoadsCleanly(&strLog),
                            "a retained V3 vertex whose first parent is not its "
                            "predecessor was loaded");
        BOOST_CHECK_MESSAGE(Says(strLog, BA007_BINDING),
                            "a wrong first parent was not refused by the "
                            "primary-parent binding; log: " << strLog);
        BOOST_CHECK_MESSAGE(!Says(strLog, BA007_PARENT),
                            "the parent named is a known block, so a missing-parent "
                            "refusal means the arm is not testing the binding; log: "
                            << strLog);
    }
    fixture.WriteVertex(2, fixture.Parents(2));
    BOOST_REQUIRE(LoadsCleanly());

    // Arm 3: too many parents. CTxDB::IterateDAGLinks rejects the count against
    // MAX_DAG_PARENTS while deserializing, before LoadDAGLinks; the arm asserts that
    // reason and that it is not the binding.
    {
        std::vector<uint256> vTooMany = fixture.Parents(2);
        for (int i = 0; i <= MAX_DAG_PARENTS; i++)
            vTooMany.push_back(uint256(0x0ba00800u + i));
        BOOST_REQUIRE(vTooMany.size() > (size_t)MAX_DAG_PARENTS);
        fixture.WriteVertex(2, vTooMany);
        BOOST_CHECK_MESSAGE(!LoadsCleanly(&strLog),
                            "a retained V3 vertex committing more than "
                            "MAX_DAG_PARENTS parents was loaded");
        BOOST_CHECK_MESSAGE(Says(strLog, "oversized DAG parent set"),
                            "an over-long parent list was not refused by the "
                            "deserializer's own bound; log: " << strLog);
        BOOST_CHECK_MESSAGE(!Says(strLog, BA007_BINDING),
                            "the loader's count clause refused a record the reader "
                            "refuses first, so the two have swapped order; log: "
                            << strLog);
    }
    fixture.WriteVertex(2, fixture.Parents(2));
    BOOST_REQUIRE(LoadsCleanly());

    // Arm 4: a retained V3 block index with no vertex at all. The rule is about
    // every retained vertex, so the absent one has to be fatal too -- otherwise a
    // partial store passes by holding fewer records rather than better ones.
    fixture.EraseVertex(2);
    BOOST_CHECK_MESSAGE(!LoadsCleanly(&strLog),
                        "a retained V3 block index with no DAG vertex was loaded");
    BOOST_CHECK_MESSAGE(Says(strLog, BA007_NOVERTEX),
                        "the missing vertex was not what refused the load; log: "
                        << strLog);
    fixture.WriteVertex(2, fixture.Parents(2));
    BOOST_REQUIRE_MESSAGE(LoadsCleanly(),
                          "the store did not return to a loadable state, so the "
                          "arms above may have left it broken");
}

BOOST_AUTO_TEST_SUITE_END()
