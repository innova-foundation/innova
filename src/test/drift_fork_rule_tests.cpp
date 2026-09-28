// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Rules crossing FORK_HEIGHT_TIGHTER_DRIFT (R-DRIFT-001, -003..-006). Mainnet/testnet
// values are asserted under a network guard.

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <memory>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "../bignum.h"
#include "../checkpoints.h"
#include "../finality.h"
#include "../kernel.h"
#include "../key.h"
#include "../main.h"
#include "../miner.h"
#include "../script.h"
#include "../subsidy.h"
#include "../txdb.h"
#include "../util.h"
#include "../wallet.h"

extern CWallet* pwalletMain;
extern bool fPrintToConsole;

BOOST_AUTO_TEST_SUITE(drift_fork_rule_tests)

namespace {

struct DetachedWalletGuard
{
    DetachedWalletGuard() { UnregisterWallet(pwalletMain); }
    ~DetachedWalletGuard() { RegisterWallet(pwalletMain); }
};

struct MockClockGuard
{
    ~MockClockGuard() { SetMockTime(0); }
};

struct NetworkGuard
{
    bool fRegSaved;
    bool fTestSaved;
    NetworkGuard(bool fRegTestWanted, bool fTestNetWanted)
        : fRegSaved(fRegTest), fTestSaved(fTestNet)
    {
        fRegTest = fRegTestWanted;
        fTestNet = fTestNetWanted;
    }
    ~NetworkGuard() { fRegTest = fRegSaved; fTestNet = fTestSaved; }
};

// Regtest reads the mainnet checkpoints, so ConnectBlock would skip ECDSA at fixture
// heights; -fullreplayverify turns verification back on.
struct FullReplayVerifyGuard
{
    bool fSaved;
    FullReplayVerifyGuard() : fSaved(fFullReplayVerify) { fFullReplayVerify = true; }
    ~FullReplayVerifyGuard() { fFullReplayVerify = fSaved; }
};

// One call's log output. Several of the rules below refuse through a plain
// error() rather than a distinct return code, so the printed reason is what
// separates "refused by this branch" from "refused".
class CaptureLog
{
public:
    CaptureLog() : nSavedFd(-1), fSavedPrintToConsole(fPrintToConsole), pFile(NULL) {}

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

    ~CaptureLog()
    {
        if (pFile != NULL || nSavedFd != -1)
            End();
    }

private:
    int nSavedFd;
    bool fSavedPrintToConsole;
    FILE* pFile;
};

CBlockIndex* BestIndex()
{
    LOCK(cs_main);
    return pindexBest;
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

bool MineTo(int nTarget)
{
    unsigned int nExtraNonce = 0;
    while (BestIndex() != NULL && BestIndex()->nHeight < nTarget)
    {
        CBlockIndex* pindexPrev = BestIndex();
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        if (pblock.get() == NULL)
            return false;
        IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
        if (!GrindHeader(pblock.get()))
            return false;
        if (!ProcessBlock(NULL, pblock.get()))
            return false;
        if (BestIndex()->nHeight != pindexPrev->nHeight + 1)
            return false;
    }
    return BestIndex() != NULL && BestIndex()->nHeight >= nTarget;
}

CBlockIndex* AncestorAt(int nHeight)
{
    LOCK(cs_main);
    CBlockIndex* p = pindexBest;
    while (p != NULL && p->nHeight > nHeight)
        p = p->pprev;
    return (p != NULL && p->nHeight == nHeight) ? p : NULL;
}

// An unspent, wallet-owned output in a block at or below nMaxHeight.
bool FindFundingOutput(int nMaxHeight, CTransaction& txOut, unsigned int& nOutIndex)
{
    CTxDB txdb("r");
    for (int h = nMaxHeight; h >= 1; h--)
    {
        CBlockIndex* pindex = AncestorAt(h);
        if (pindex == NULL)
            continue;
        CBlock block;
        if (!block.ReadFromDisk(pindex, true))
            continue;
        for (const CTransaction& tx : block.vtx)
        {
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(tx.GetHash(), txindex))
                continue;
            for (unsigned int n = 0; n < tx.vout.size(); n++)
            {
                if (tx.vout[n].nValue <= 0)
                    continue;
                if (n >= txindex.vSpent.size() || !txindex.vSpent[n].IsNull())
                    continue;
                if (IsMine(*pwalletMain, tx.vout[n].scriptPubKey) == MINE_NO)
                    continue;
                txOut = tx;
                nOutIndex = n;
                return true;
            }
        }
    }
    return false;
}

// Moves the node's tip height for one arm, so an arm can show a rule reads the
// evaluated block's height and not nBestHeight.
struct BestHeightGuard
{
    int nSaved;
    explicit BestHeightGuard(int nHeight)
    {
        LOCK(cs_main);
        nSaved = nBestHeight;
        nBestHeight = nHeight;
    }
    ~BestHeightGuard()
    {
        LOCK(cs_main);
        nBestHeight = nSaved;
    }
};

CBlockIndex* ParentIndexOf(const CBlock& block)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::const_iterator mi =
        mapBlockIndex.find(block.hashPrevBlock);
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

// A producer template on the tip, with the stack index ConnectBlock is handed.
// Edit the body, then Seal: the merkle root is rebuilt there, so an arm's edit
// rides a block that is otherwise exactly what the producer emitted.
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

// ConnectBlock re-runs CheckBlock, so an edited body has to be re-solved: an
// unsolved header is refused for its work and no arm below would be reached.
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

// Connect and discard every write, so an accepted arm does not spend outputs
// the next arm needs and the fixture's tip does not move.
CBlock::ConnectResult ConnectAndRollBack(Candidate& cb, std::string& strLogOut)
{
    LOCK(cs_main);
    CTxDB txdb;
    CBlock::ConnectResult result = CBlock::CONNECT_RESULT_INVALID;
    BOOST_REQUIRE(txdb.TxnBegin());
    CaptureLog log;
    BOOST_REQUIRE(log.Begin());
    const bool fConnected = cb.block.ConnectBlock(txdb, cb.Index(), false, false, &result);
    strLogOut = log.End();
    BOOST_REQUIRE(txdb.TxnAbort());
    BOOST_CHECK_EQUAL(fConnected, result == CBlock::CONNECT_RESULT_OK);
    return result;
}

// The coinbase output carrying the producer's payout, chosen by value: the
// IDAG parent commitment is a zero-value OP_RETURN and its index is the
// producer's to choose.
unsigned int LargestCoinbaseOutput(const CTransaction& coinbase)
{
    unsigned int nBest = 0;
    for (unsigned int i = 1; i < coinbase.vout.size(); i++)
        if (coinbase.vout[i].nValue > coinbase.vout[nBest].nValue)
            nBest = i;
    return nBest;
}

// The first height at or above nFrom whose subsidy differs from the height
// below it. The subsidy-height arm is vacuous anywhere else: reading the
// neighbouring height there returns the same number.
int FindSubsidyStepAtOrAbove(int nFrom, int nLimit)
{
    for (int h = (nFrom < 1 ? 1 : nFrom); h <= nLimit; h++)
        if (GetBlockSubsidySchedule(h) != GetBlockSubsidySchedule(h - 1))
            return h;
    return -1;
}

} // namespace

// R-DRIFT-003: the PoW allowance uses the block's own height. Tested at a height where
// the neighbouring height's subsidy differs.
BOOST_AUTO_TEST_CASE(the_coinbase_allowance_follows_the_block_own_height)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);

    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;

    const int nStep = FindSubsidyStepAtOrAbove(BestIndex()->nHeight + 1, 2000);
    BOOST_REQUIRE_MESSAGE(nStep > 0,
                          "no height in [" << BestIndex()->nHeight + 1
                          << ", 2000] pays a different subsidy from the height below "
                          "it, so this arm cannot separate nHeight from nHeight - 1");
    BOOST_TEST_MESSAGE("subsidy step at height " << nStep << ": "
                       << GetBlockSubsidySchedule(nStep - 1) << " -> "
                       << GetBlockSubsidySchedule(nStep));
    BOOST_REQUIRE_MESSAGE(!IsFinalitySettlementHeight(nStep),
                          "height " << nStep << " is a settlement height, so the "
                          "allowance carries a settlement leg as well and the arm no "
                          "longer names one quantity");
    BOOST_REQUIRE_MESSAGE(MineTo(nStep - 1),
                          "could not extend the fixture to height " << nStep - 1);
    SetMockTime(GetTime() + 10 * CollateralnodePaymentWindowSeconds());

    Candidate accepted;
    BOOST_REQUIRE(BuildCandidate(accepted));
    BOOST_REQUIRE_EQUAL(accepted.Height(), nStep);
    BOOST_REQUIRE(accepted.block.IsProofOfWork());
    BOOST_REQUIRE(SealCandidate(accepted));

    std::string strAcceptedLog;
    const CBlock::ConnectResult acceptedResult = ConnectAndRollBack(accepted, strAcceptedLog);
    BOOST_CHECK_MESSAGE(acceptedResult == CBlock::CONNECT_RESULT_OK,
                        "the producer's own block at height " << nStep
                        << " must connect; the allowance is computed from a height "
                        "that pays " << GetBlockSubsidySchedule(nStep)
                        << " and the neighbouring height pays "
                        << GetBlockSubsidySchedule(nStep - 1) << "; log: " << strAcceptedLog);

    Candidate overpaid;
    BOOST_REQUIRE(BuildCandidate(overpaid));
    BOOST_REQUIRE_EQUAL(overpaid.Height(), nStep);
    overpaid.block.vtx[0].vout[LargestCoinbaseOutput(overpaid.block.vtx[0])].nValue += 1;
    BOOST_REQUIRE(SealCandidate(overpaid));

    std::string strOverpaidLog;
    const CBlock::ConnectResult overpaidResult = ConnectAndRollBack(overpaid, strOverpaidLog);
    BOOST_CHECK_MESSAGE(overpaidResult == CBlock::CONNECT_RESULT_INVALID,
                        "one satoshi above this height's allowance must be refused at "
                        "height " << nStep << ", got result " << (int)overpaidResult
                        << "; log: " << strOverpaidLog);
    BOOST_CHECK_MESSAGE(strOverpaidLog.find("coinbase reward exceeded") != std::string::npos,
                        "the refusal did not come from the coinbase allowance; log: "
                        << strOverpaidLog);
}

// R-DRIFT-004: from the gate, scripts verify under mandatory flags plus STRICTENC and
// CHECKLOCKTIMEVERIFY. An undefined sighash type is refused by STRICTENC alone.
BOOST_AUTO_TEST_CASE(strict_script_flags_apply_from_the_gate)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_REQUIRE_EQUAL(FORK_HEIGHT_TIGHTER_DRIFT, 1);

    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;
    FullReplayVerifyGuard replayGuard;

    BOOST_REQUIRE_MESSAGE(MineTo(2), "could not extend the fixture to height 2");
    SetMockTime(GetTime() + 10 * CollateralnodePaymentWindowSeconds());

    CTransaction txFund;
    unsigned int nFundOut = 0;
    BOOST_REQUIRE_MESSAGE(FindFundingOutput(BestIndex()->nHeight, txFund, nFundOut),
                          "no unspent wallet output to spend");
    const int64_t nFundValue = txFund.vout[nFundOut].nValue;
    const int64_t nFee = CENT;
    BOOST_REQUIRE(nFundValue > 8 * nFee);

    // P2SH outputs differing only in the wrapped script: [0] accepted; [1] needs P2SH,
    // [2] needs CHECKLOCKTIMEVERIFY, [3] needs STRICTENC (not mandatory).
    CScript vRedeem[4];
    vRedeem[0] = CScript() << OP_1;
    vRedeem[1] = CScript() << OP_0;
    vRedeem[2] = CScript() << 500 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_1;
    vRedeem[3] = CScript() << valtype() << valtype(33, 0x00)
                           << OP_CHECKSIG << OP_DROP << OP_1;

    CTransaction txP2SH;
    txP2SH.nTime = (unsigned int)BestIndex()->GetBlockTime();
    txP2SH.vin.push_back(CTxIn(txFund.GetHash(), nFundOut));
    const int64_t nEach = (nFundValue - nFee) / 4;
    for (int i = 0; i < 4; i++)
        txP2SH.vout.push_back(
            CTxOut(nEach, GetScriptForDestination(vRedeem[i].GetID())));
    BOOST_REQUIRE(SignSignature(*pwalletMain, txFund, txP2SH, 0, SIGHASH_ALL));

    // The wrapped scripts have to be spendable from a connected block, so this
    // one is mined rather than rolled back.
    {
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        BOOST_REQUIRE(pblock.get() != NULL);
        CBlockIndex* pindexParent = ParentIndexOf(*pblock);
        BOOST_REQUIRE(pindexParent != NULL);
        unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock.get(), pindexParent, nExtraNonce);
        txP2SH.nTime = pblock->nTime;
        BOOST_REQUIRE(SignSignature(*pwalletMain, txFund, txP2SH, 0, SIGHASH_ALL));
        pblock->vtx.push_back(txP2SH);
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        BOOST_REQUIRE(GrindHeader(pblock.get()));
        std::string strMineLog;
        CaptureLog log;
        BOOST_REQUIRE(log.Begin());
        const bool fMined = ProcessBlock(NULL, pblock.get());
        strMineLog = log.End();
        BOOST_REQUIRE_MESSAGE(fMined,
                              "the chain refused the block carrying the wrapped scripts, "
                              "so the arms below are unreachable; log: " << strMineLog);
    }

    CBlock::ConnectResult vResults[4];
    std::string vLogs[4];

    for (int a = 0; a < 4; a++)
    {
        Candidate cb;
        BOOST_REQUIRE(BuildCandidate(cb));
        BOOST_REQUIRE(cb.Height() >= FORK_HEIGHT_TIGHTER_DRIFT);

        CTransaction tx;
        tx.nTime = cb.block.nTime;
        tx.nLockTime = 0;
        tx.vin.push_back(CTxIn(txP2SH.GetHash(), (unsigned int)a));
        tx.vin[0].scriptSig = CScript() << static_cast<valtype>(vRedeem[a]);
        tx.vout.push_back(CTxOut(nEach - nFee, txFund.vout[nFundOut].scriptPubKey));

        cb.block.vtx.push_back(tx);
        BOOST_REQUIRE(SealCandidate(cb));
        vResults[a] = ConnectAndRollBack(cb, vLogs[a]);
    }

    BOOST_CHECK_MESSAGE(vResults[0] == CBlock::CONNECT_RESULT_OK,
                        "the control spend, whose wrapped script leaves true, must "
                        "connect; got result " << (int)vResults[0] << "; log: " << vLogs[0]);
    BOOST_CHECK_MESSAGE(vResults[1] != CBlock::CONNECT_RESULT_OK,
                        "a spend whose wrapped script leaves false must be refused: "
                        "without SCRIPT_VERIFY_P2SH the wrapper alone satisfies the "
                        "output and the script is never run; got result "
                        << (int)vResults[1] << "; log: " << vLogs[1]);
    BOOST_CHECK_MESSAGE(vResults[2] != CBlock::CONNECT_RESULT_OK,
                        "a spend whose wrapped script demands a lock time it does not "
                        "meet must be refused: without "
                        "SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY the opcode is a no-op and the "
                        "script succeeds; got result " << (int)vResults[2]
                        << "; log: " << vLogs[2]);
    BOOST_CHECK_MESSAGE(vLogs[1].find("VerifySignature failed") != std::string::npos,
                        "the refusal did not come from script verification; log: "
                        << vLogs[1]);
    BOOST_CHECK_MESSAGE(vLogs[2].find("VerifySignature failed") != std::string::npos,
                        "the refusal did not come from script verification; log: "
                        << vLogs[2]);
    BOOST_CHECK_MESSAGE(vResults[3] != CBlock::CONNECT_RESULT_OK,
                        "a spend whose wrapped script runs OP_CHECKSIG over an "
                        "unencodable signature and public key and discards the result "
                        "must be refused: without SCRIPT_VERIFY_STRICTENC the bad "
                        "encoding only makes OP_CHECKSIG push false, which OP_DROP "
                        "removes; got result " << (int)vResults[3] << "; log: " << vLogs[3]);
    BOOST_CHECK_MESSAGE(vLogs[3].find("VerifySignature failed") != std::string::npos,
                        "the refusal did not come from script verification; log: "
                        << vLogs[3]);
}

// R-DRIFT-005. Each input's contribution to coin age is capped at one year, so
// an input older than that scores exactly one year and not its true age.
BOOST_AUTO_TEST_CASE(coin_age_is_capped_at_one_year)
{
    BOOST_REQUIRE(fRegTest);

    DetachedWalletGuard walletGuard;

    BOOST_REQUIRE_MESSAGE(MineTo(2), "could not extend the fixture to height 2");
    const int nEvalHeight = BestIndex()->nHeight + 1;
    BOOST_REQUIRE(nEvalHeight >= FORK_HEIGHT_TIGHTER_DRIFT);

    CTransaction txPrev;
    unsigned int nOut = 0;
    BOOST_REQUIRE_MESSAGE(FindFundingOutput(BestIndex()->nHeight, txPrev, nOut),
                          "no unspent wallet output to age");

    const int64_t nYear = 365 * 24 * 60 * 60;
    const int64_t nValueIn = txPrev.vout[nOut].nValue;
    BOOST_REQUIRE(nValueIn > 0);

    // Two ages either side of the cap. The capped one is the control: below the
    // cap the true age is counted, so the two must differ or the arm proves
    // nothing about the cap.
    const int64_t vAges[2] = { nYear - 24 * 60 * 60, nYear + 400 * 24 * 60 * 60 };
    uint64_t vCoinAge[2] = { 0, 0 };

    CTxDB txdb("r");
    CTransaction vTx[2];
    for (int a = 0; a < 2; a++)
    {
        CTransaction& tx = vTx[a];
        tx.nTime = (unsigned int)((int64_t)txPrev.nTime + vAges[a]);
        tx.vin.push_back(CTxIn(txPrev.GetHash(), nOut));
        tx.vout.push_back(CTxOut(nValueIn, txPrev.vout[nOut].scriptPubKey));
        BOOST_REQUIRE_MESSAGE(tx.GetCoinAge(txdb, vCoinAge[a], nEvalHeight),
                              "GetCoinAge failed for age " << vAges[a]);
    }

    auto CoinDaysFor = [&](int64_t nTimeDiff) -> uint64_t {
        CBigNum bnCentSecond = CBigNum(nValueIn) * nTimeDiff / CENT;
        CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
        return bnCoinDay.getuint64();
    };

    BOOST_CHECK_MESSAGE(vCoinAge[0] == CoinDaysFor(vAges[0]),
                        "below the cap an input must score its true age: got "
                        << vCoinAge[0] << ", expected " << CoinDaysFor(vAges[0]));
    BOOST_CHECK_MESSAGE(vCoinAge[1] == CoinDaysFor(nYear),
                        "above the cap an input must score exactly one year: got "
                        << vCoinAge[1] << ", expected " << CoinDaysFor(nYear));
    BOOST_CHECK_MESSAGE(CoinDaysFor(vAges[1]) > CoinDaysFor(nYear),
                        "the over-cap age scores the same as one year even uncapped, "
                        "so this arm cannot see the cap");
    BOOST_CHECK_MESSAGE(vCoinAge[1] < CoinDaysFor(vAges[1]),
                        "the over-cap input scored its uncapped age " << vCoinAge[1]
                        << ", so the cap did not apply");

    // Mainnet gate: the cap follows the carrying block's height, whatever the
    // node's tip is.
    {
        NetworkGuard net(false, false);
        const int nGate = FORK_HEIGHT_TIGHTER_DRIFT;
        BOOST_REQUIRE(nGate > nBestHeight + 1);
        uint64_t nBelow = 0, nAt = 0;
        {
            BestHeightGuard tip(nGate + 1000);
            BOOST_REQUIRE(vTx[1].GetCoinAge(txdb, nBelow, nGate - 1));
        }
        BOOST_REQUIRE(vTx[1].GetCoinAge(txdb, nAt, nGate));
        BOOST_CHECK_MESSAGE(nBelow == CoinDaysFor(vAges[1]),
                            "a block below the mainnet gate must score the uncapped age "
                            "with the tip above the gate: got " << nBelow);
        BOOST_CHECK_MESSAGE(nAt == CoinDaysFor(nYear),
                            "a block at the mainnet gate must score the capped age "
                            "with the tip below the gate: got " << nAt);
    }
}

// R-DRIFT-006. A stake kernel is refused when the staked output is more than
// ninety days older than the transaction time. Both arms run the same kernel
// on the same block; only nTimeTx moves, by one second across the boundary.
BOOST_AUTO_TEST_CASE(a_stake_kernel_older_than_ninety_days_is_refused)
{
    BOOST_REQUIRE(fRegTest);

    DetachedWalletGuard walletGuard;

    BOOST_REQUIRE_MESSAGE(MineTo(2), "could not extend the fixture to height 2");
    const int nEvalHeight = BestIndex()->nHeight + 1;
    BOOST_REQUIRE(nEvalHeight >= FORK_HEIGHT_TIGHTER_DRIFT);

    CBlockIndex* pindexFrom = AncestorAt(BestIndex()->nHeight - 1);
    BOOST_REQUIRE(pindexFrom != NULL);
    CBlock blockFrom;
    BOOST_REQUIRE(blockFrom.ReadFromDisk(pindexFrom, true));
    BOOST_REQUIRE(!blockFrom.vtx.empty());
    const CTransaction& txPrev = blockFrom.vtx[0];
    BOOST_REQUIRE(!txPrev.vout.empty());

    const unsigned int nBits = GetNextTargetRequired(BestIndex(), true);
    const int64_t nMaxAge = 90 * 24 * 60 * 60;
    const unsigned int nTimeBlockFrom = (unsigned int)blockFrom.GetBlockTime();
    const COutPoint prevout(txPrev.GetHash(), 0);

    // At the boundary and one second past it.
    const unsigned int vTimes[2] = {
        (unsigned int)(nTimeBlockFrom + nMaxAge),
        (unsigned int)(nTimeBlockFrom + nMaxAge + 1)
    };
    std::string vLogs[2];

    for (int a = 0; a < 2; a++)
    {
        uint256 hashProof = 0, hashTarget = 0;
        CaptureLog log;
        BOOST_REQUIRE(log.Begin());
        CheckStakeKernelHash(nBits, blockFrom, 0, txPrev, prevout, vTimes[a],
                             hashProof, hashTarget, false, nEvalHeight);
        vLogs[a] = log.End();
    }

    BOOST_CHECK_MESSAGE(vLogs[0].find("max age violation") == std::string::npos,
                        "a kernel exactly ninety days old must pass the maximum-age "
                        "branch; log: " << vLogs[0]);
    BOOST_CHECK_MESSAGE(vLogs[1].find("max age violation") != std::string::npos,
                        "a kernel one second past ninety days must be refused by the "
                        "maximum-age branch; log: " << vLogs[1]);

    // Mainnet gate: the maximum age follows the carrying block's height, not
    // the node's tip. Both arms use the over-age time.
    {
        NetworkGuard net(false, false);
        const int nGate = FORK_HEIGHT_TIGHTER_DRIFT;
        BOOST_REQUIRE(nGate > nBestHeight + 1);
        std::string strBelow, strAt;
        {
            BestHeightGuard tip(nGate + 1000);
            uint256 hashProof = 0, hashTarget = 0;
            CaptureLog log;
            BOOST_REQUIRE(log.Begin());
            CheckStakeKernelHash(nBits, blockFrom, 0, txPrev, prevout, vTimes[1],
                                 hashProof, hashTarget, false, nGate - 1);
            strBelow = log.End();
        }
        {
            uint256 hashProof = 0, hashTarget = 0;
            CaptureLog log;
            BOOST_REQUIRE(log.Begin());
            CheckStakeKernelHash(nBits, blockFrom, 0, txPrev, prevout, vTimes[1],
                                 hashProof, hashTarget, false, nGate);
            strAt = log.End();
        }
        BOOST_CHECK_MESSAGE(strBelow.find("max age violation") == std::string::npos,
                            "a block below the mainnet gate must not apply the maximum "
                            "age with the tip above the gate; log: " << strBelow);
        BOOST_CHECK_MESSAGE(strAt.find("max age violation") != std::string::npos,
                            "a block at the mainnet gate must apply the maximum age with "
                            "the tip below the gate; log: " << strAt);
    }
}

namespace {

// A transparent coinstake spending one wallet output, signed, with its time set
// by the case.
CTransaction SignedCoinstake(const CTransaction& txPrev, unsigned int nOut,
                             unsigned int nTime, int64_t nValueOut)
{
    CTransaction tx;
    tx.nTime = nTime;
    tx.vin.push_back(CTxIn(txPrev.GetHash(), nOut));
    tx.vout.resize(2);
    tx.vout[0].SetEmpty();
    tx.vout[1] = CTxOut(nValueOut, txPrev.vout[nOut].scriptPubKey);
    BOOST_REQUIRE(SignSignature(*pwalletMain, txPrev, tx, 0));
    BOOST_REQUIRE(tx.IsCoinStake());
    return tx;
}

// The block that carries txPrev, header only.
unsigned int BlockTimeOf(const CTransaction& txPrev)
{
    CTxDB txdb("r");
    CTxIndex txindex;
    BOOST_REQUIRE(txdb.ReadTxIndex(txPrev.GetHash(), txindex));
    CBlock block;
    BOOST_REQUIRE(block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false));
    return (unsigned int)block.GetBlockTime();
}

} // namespace

// R-KERN-003b. CheckProofOfStake hands the kernel the carrying block's height,
// so the ninety-day maximum is decided by that height and not by the tip. The
// arms put the two on opposite sides of the mainnet gate.
BOOST_AUTO_TEST_CASE(check_proof_of_stake_reads_the_maximum_age_at_the_block_height)
{
    BOOST_REQUIRE(fRegTest);

    DetachedWalletGuard walletGuard;

    BOOST_REQUIRE_MESSAGE(MineTo(2), "could not extend the fixture to height 2");
    CTransaction txPrev;
    unsigned int nOut = 0;
    BOOST_REQUIRE_MESSAGE(FindFundingOutput(BestIndex()->nHeight, txPrev, nOut),
                          "no unspent wallet output to stake");

    const unsigned int nTimeFrom = BlockTimeOf(txPrev);
    const unsigned int nTimeTx = nTimeFrom + 90 * 24 * 60 * 60 + 1;
    CTransaction tx = SignedCoinstake(txPrev, nOut, nTimeTx, txPrev.vout[nOut].nValue);
    const unsigned int nBits = GetNextTargetRequired(BestIndex(), true);

    NetworkGuard net(false, false);
    const int nGate = FORK_HEIGHT_TIGHTER_DRIFT;
    BOOST_REQUIRE(nGate > nBestHeight + 1);

    bool vResult[2] = { false, false };
    std::string vLogs[2];
    const int vEvalHeight[2] = { nGate - 1, nGate };
    const int vTipHeight[2] = { nGate + 1000, nGate - 1 };
    for (int a = 0; a < 2; a++)
    {
        BestHeightGuard tip(vTipHeight[a]);
        uint256 hashProof = 0, hashTarget = 0;
        CaptureLog log;
        BOOST_REQUIRE(log.Begin());
        vResult[a] = CheckProofOfStake(tx, nBits, hashProof, hashTarget, vEvalHeight[a]);
        vLogs[a] = log.End();
    }

    BOOST_CHECK_MESSAGE(vLogs[0].find("max age violation") == std::string::npos,
                        "a block below the mainnet gate must not apply the maximum age "
                        "with the tip above the gate; log: " << vLogs[0]);
    BOOST_CHECK_MESSAGE(vResult[0] || vLogs[0].find("check kernel failed") != std::string::npos,
                        "the below-gate arm did not reach the kernel; log: " << vLogs[0]);
    BOOST_CHECK(!vResult[1]);
    BOOST_CHECK_MESSAGE(vLogs[1].find("max age violation") != std::string::npos,
                        "a block at the mainnet gate must apply the maximum age with the "
                        "tip below the gate; log: " << vLogs[1]);
}

// R-KERN-004b: coin age is capped at the block's own height, not the tip's. Each arm
// overpays by one satoshi so the refusal prints the reward it was scored against.
BOOST_AUTO_TEST_CASE(connect_block_scores_coin_age_at_the_block_height)
{
    BOOST_REQUIRE(fRegTest);

    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;

    BOOST_REQUIRE_MESSAGE(MineTo(2), "could not extend the fixture to height 2");
    CTransaction txPrev;
    unsigned int nOut = 0;
    BOOST_REQUIRE_MESSAGE(FindFundingOutput(BestIndex()->nHeight, txPrev, nOut),
                          "no unspent wallet output to stake");
    CBlockIndex* pparent = BestIndex();
    const int64_t nValueIn = txPrev.vout[nOut].nValue;

    const int64_t nYear = 365 * 24 * 60 * 60;
    const int64_t nAge = nYear + 400 * 24 * 60 * 60;
    const unsigned int nTimeTx = (unsigned int)((int64_t)txPrev.nTime + nAge);
    SetMockTime((int64_t)nTimeTx + 60);

    auto CoinDaysFor = [&](int64_t nTimeDiff) -> uint64_t {
        CBigNum bnCentSecond = CBigNum(nValueIn) * nTimeDiff / CENT;
        CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
        return bnCoinDay.getuint64();
    };

    NetworkGuard net(false, false);
    const int nGate = FORK_HEIGHT_TIGHTER_DRIFT;
    BOOST_REQUIRE(nGate > nBestHeight + 1);
    BOOST_REQUIRE(nGate < FORK_HEIGHT_DAG);

    auto PaidFor = [&](int nHeight, int64_t nTimeDiff) -> int64_t {
        const int64_t nSubsidy =
            GetProofOfStakeReward((int64_t)CoinDaysFor(nTimeDiff), 0, pparent, 0);
        return CBlockSubsidySplit::ForBlock(nHeight, nSubsidy, 0,
                                            CollateralnodeShare::Paid).PaidToBlock();
    };

    const int vHeight[2] = { nGate - 1, nGate };
    const int vTipHeight[2] = { nGate + 1000, nGate - 1 };
    const int64_t vExpected[2] = { PaidFor(nGate - 1, nAge), PaidFor(nGate, nYear) };
    BOOST_REQUIRE_MESSAGE(PaidFor(nGate - 1, nYear) < vExpected[0] &&
                          vExpected[1] < PaidFor(nGate, nAge),
                          "the capped and uncapped rewards coincide, so no arm can see "
                          "which height scored the coin age");
    const int64_t nPaid = std::max(PaidFor(nGate - 1, nAge), PaidFor(nGate, nAge)) + 1;

    std::string vLogs[2];
    for (int a = 0; a < 2; a++)
    {
        CBlock block;
        block.nVersion = CBlock::CURRENT_VERSION;
        block.hashPrevBlock = pparent->GetBlockHash();
        block.nTime = nTimeTx;
        block.nBits = pparent->nBits;

        CTransaction coinbase;
        coinbase.nTime = nTimeTx;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript() << vHeight[a] << OP_0;
        coinbase.vout.resize(1);
        coinbase.vout[0].SetEmpty();

        block.vtx.push_back(coinbase);
        block.vtx.push_back(SignedCoinstake(txPrev, nOut, nTimeTx, nValueIn + nPaid));
        block.hashMerkleRoot = block.BuildMerkleTree();
        BOOST_REQUIRE(block.IsProofOfStake());

        const uint256 hash = block.GetHash();
        CBlockIndex index(0, 0, block);
        index.pprev = pparent;
        index.nHeight = vHeight[a];
        index.phashBlock = &hash;

        BestHeightGuard tip(vTipHeight[a]);
        LOCK(cs_main);
        CTxDB txdb;
        BOOST_REQUIRE(txdb.TxnBegin());
        CBlock::ConnectResult result = CBlock::CONNECT_RESULT_INVALID;
        CaptureLog log;
        BOOST_REQUIRE(log.Begin());
        const bool fConnected = block.ConnectBlock(txdb, &index, false, false, &result);
        vLogs[a] = log.End();
        BOOST_REQUIRE(txdb.TxnAbort());
        BOOST_CHECK(!fConnected);
    }

    for (int a = 0; a < 2; a++)
    {
        const std::string strWant = strprintf("coinstake pays too much(actual=%" PRId64
                                              " vs calculated=%" PRId64 ")",
                                              nPaid, vExpected[a]);
        BOOST_CHECK_MESSAGE(vLogs[a].find(strWant) != std::string::npos,
                            (a == 0 ? "a block below the mainnet gate must score the "
                                      "uncapped coin age with the tip above the gate"
                                    : "a block at the mainnet gate must score the capped "
                                      "coin age with the tip below the gate")
                            << "; want '" << strWant << "'; log: " << vLogs[a]);
    }
}

// R-DRIFT-001 on all three networks, the only place the ten-minute branch is reachable.
BOOST_AUTO_TEST_CASE(the_drift_window_is_two_minutes_from_the_gate)
{
    const int64_t nRef = 1700000000;

    struct Net { bool fRegTestWanted; bool fTestNetWanted; const char* strName; };
    const Net vNets[] = {
        { true,  false, "regtest" },
        { false, true,  "testnet" },
        { false, false, "mainnet" },
    };

    for (size_t i = 0; i < ARRAYLEN(vNets); i++)
    {
        NetworkGuard guard(vNets[i].fRegTestWanted, vNets[i].fTestNetWanted);
        const int nGate = FORK_HEIGHT_TIGHTER_DRIFT;
        BOOST_REQUIRE_MESSAGE(nGate >= 1, vNets[i].strName << " gate is " << nGate);

        BOOST_CHECK_MESSAGE(PastDrift(nRef, nGate) == nRef - 2 * 60,
                            vNets[i].strName << ": past drift at the gate is not two minutes");
        BOOST_CHECK_MESSAGE(FutureDrift(nRef, nGate) == nRef + 2 * 60,
                            vNets[i].strName << ": future drift at the gate is not two minutes");
        BOOST_CHECK_MESSAGE(PastDrift(nRef, nGate - 1) == nRef - 10 * 60,
                            vNets[i].strName << ": past drift below the gate is not ten minutes");
        BOOST_CHECK_MESSAGE(FutureDrift(nRef, nGate - 1) == nRef + 10 * 60,
                            vNets[i].strName << ": future drift below the gate is not ten minutes");
    }

    // The height-blind overloads are the pre-gate window and stay there: they
    // are read where no height is available and must not tighten silently.
    BOOST_CHECK_EQUAL(PastDrift(nRef), nRef - 10 * 60);
    BOOST_CHECK_EQUAL(FutureDrift(nRef), nRef + 10 * 60);
}

// R-DRIFT-001 on the block path: a timestamp more than two minutes before the parent's
// is refused, one inside is accepted. The clock is advanced first so median-time-past
// does not decide the arms.
BOOST_AUTO_TEST_CASE(a_block_more_than_two_minutes_before_its_parent_is_refused)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);

    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;

    BOOST_REQUIRE(MineTo(BestIndex()->nHeight + 1));
    SetMockTime(GetTime() + 10 * 60);
    BOOST_REQUIRE_MESSAGE(MineTo(BestIndex()->nHeight + 1),
                          "could not mine the parent under the advanced clock");

    CBlockIndex* pindexParent = BestIndex();
    const int64_t nParentTime = pindexParent->GetBlockTime();
    const int64_t nParentMedian = pindexParent->GetPastTimeLimit();
    BOOST_REQUIRE_MESSAGE(nParentTime - nParentMedian > 2 * 60 + 2,
                          "the parent's median time past is " << nParentMedian
                          << " against a block time of " << nParentTime
                          << ", so the drift leg is shadowed by the median leg and "
                          "neither arm below would test the drift window");

    // Only nTime differs between the arms: one second outside the window and
    // one second inside it.
    const int64_t vTimes[2] = { nParentTime - 2 * 60 - 1, nParentTime - 2 * 60 + 1 };
    bool vAccepted[2] = { false, false };
    std::string vLogs[2];

    for (int a = 0; a < 2; a++)
    {
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        BOOST_REQUIRE(pblock.get() != NULL);
        BOOST_REQUIRE(pblock->hashPrevBlock == pindexParent->GetBlockHash());
        unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock.get(), pindexParent, nExtraNonce);
        pblock->nTime = (unsigned int)vTimes[a];
        pblock->vtx[0].nTime = pblock->nTime;
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        BOOST_REQUIRE(GrindHeader(pblock.get()));

        CaptureLog log;
        BOOST_REQUIRE(log.Begin());
        vAccepted[a] = ProcessBlock(NULL, pblock.get());
        vLogs[a] = log.End();
    }

    BOOST_CHECK_MESSAGE(!vAccepted[0],
                        "a block " << (nParentTime - vTimes[0]) << " seconds before its "
                        "parent must be refused above the gate; log: " << vLogs[0]);
    BOOST_CHECK_MESSAGE(vLogs[0].find("block's timestamp is too early") != std::string::npos,
                        "the refusal did not come from the timestamp window; log: "
                        << vLogs[0]);
    BOOST_CHECK_MESSAGE(vAccepted[1],
                        "a block " << (nParentTime - vTimes[1]) << " seconds before its "
                        "parent is inside the two-minute window and must be accepted; "
                        "log: " << vLogs[1]);
}

BOOST_AUTO_TEST_SUITE_END()
