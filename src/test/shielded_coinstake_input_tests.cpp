// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// R-SH-005: a plain coinstake may not spend a shielded tx's transparent output (NullStake
// generations exempt). Two blocks differ only in that input; matched on the logged reason.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "../bignum.h"
#include "../key.h"
#include "../main.h"
#include "../miner.h"
#include "../script.h"
#include "../shielded.h"
#include "../txdb.h"
#include "../util.h"
#include "../wallet.h"
#include "../zkproof.h"

extern CWallet* pwalletMain;
extern bool fPrintToConsole;

BOOST_AUTO_TEST_SUITE(shielded_coinstake_input_tests)

namespace {

// The suite mines real blocks. A registered wallet would record their coinbases
// and the shielding transaction, moving the ordering counters other suites pin.
struct DetachedWalletGuard
{
    DetachedWalletGuard() { UnregisterWallet(pwalletMain); }
    ~DetachedWalletGuard() { RegisterWallet(pwalletMain); }
};

// Restores the mocked clock on scope exit. The collateralnode payment rule reads
// the wall clock, and it is not what this suite is about.
struct MockClockGuard
{
    ~MockClockGuard() { SetMockTime(0); }
};

// One ConnectBlock call's log output. The rules under test are several branches
// apart and all of them return false, so matching the rejection this site prints
// is what distinguishes "refused for the reason claimed" from "refused".
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

CBlockIndex* ParentOf(const CBlock& block)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::const_iterator mi =
        mapBlockIndex.find(block.hashPrevBlock);
    return mi == mapBlockIndex.end() ? NULL : mi->second;
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
        if (++nHashes > 2000000U)
            return false;
    }
    return true;
}

// Seal a template the caller has already filled and put it on the chain.
// IncrementExtraNonce rebuilds the merkle tree, so it runs after the append.
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

// One empty proof-of-work block on the tip.
bool MineBlock(CBlock& blockOut, std::string& strLogOut)
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

// A v2000 shielding transaction with a transparent change output. The change is
// what a coinstake can reach: it is an ordinary output of a transaction the
// shielded pool has already accounted for.
bool BuildShieldingTx(const CTransaction& txFunding, unsigned int nOut,
                      int64_t nShieldAmount, unsigned int nTime,
                      CTransaction& txOut)
{
    CShieldedPaymentAddress zAddr = pwalletMain->GenerateNewShieldedAddress();

    CShieldedNote note;
    note.addr = zAddr;
    note.nValue = nShieldAmount;
    for (int i = 0; i < 32; i++)
    {
        note.rho.begin()[i] = (unsigned char)(0x51 + i);
        note.rcm.begin()[i] = (unsigned char)(0x91 + i);
    }
    if (!note.GenerateBlindingFactor())
        return false;

    CPedersenCommitment cv;
    if (!note.GetPedersenCommitment(cv))
        return false;

    CShieldedOutputDescription output;
    output.cv = cv;
    output.cmu = note.GetCommitment();
    if (!CreateBulletproofRangeProof(note.nValue, note.vchBlind, cv,
                                     output.rangeProof))
        return false;
    if (!EncryptShieldedNote(note, zAddr, output.vchEphemeralKey,
                             output.vchEncCiphertext))
        return false;

    const int64_t nIn = txFunding.vout[nOut].nValue;
    const int64_t nFee = MIN_TX_FEE_SHIELDED;
    if (nIn <= nShieldAmount + nFee)
        return false;

    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION;
    tx.nTime = nTime;
    tx.nValueBalance = -nShieldAmount;
    tx.vShieldedOutput.push_back(output);
    tx.vin.push_back(CTxIn(txFunding.GetHash(), nOut));
    tx.vout.push_back(CTxOut(nIn - nShieldAmount - nFee,
                             txFunding.vout[nOut].scriptPubKey));
    if (!SignSignature(*pwalletMain, txFunding, tx, 0, SIGHASH_ALL))
        return false;

    std::vector<std::vector<unsigned char> > vInputBlinds, vOutputBlinds;
    vOutputBlinds.push_back(note.vchBlind);
    vInputBlinds.push_back(std::vector<unsigned char>(32, 0));
    CBindingSignature bindingSig;
    if (!CreateBindingSignature(vInputBlinds, vOutputBlinds,
                                tx.GetBindingSigHash(), bindingSig))
        return false;
    tx.bindingSig.bindingSig = bindingSig;

    txOut = tx;
    return true;
}

// A proof-of-stake block on the tip whose coinstake spends one output and pays
// the whole of it back. It mints nothing, so no coin age is needed and the reward
// cap holds; the only thing that varies between the arms is which output it took.
struct StakeBlock
{
    CBlock block;
    uint256 hash;
    CBlockIndex index;

    CBlockIndex* Index() { return &index; }
};

bool BuildStakeBlock(const CTransaction& txPrev, unsigned int nOut,
                     StakeBlock& out)
{
    CBlockIndex* pindexPrev = pindexBest;
    if (pindexPrev == NULL || nOut >= txPrev.vout.size())
        return false;
    const int64_t nBlockTime = pindexPrev->GetBlockTime() + 1;
    const int64_t nIn = txPrev.vout[nOut].nValue;
    if (nIn <= 0)
        return false;

    CTransaction txStake;
    txStake.nTime = (unsigned int)nBlockTime;
    txStake.vin.push_back(CTxIn(txPrev.GetHash(), nOut));
    txStake.vout.push_back(CTxOut());
    txStake.vout[0].SetEmpty();
    txStake.vout.push_back(CTxOut(nIn, txPrev.vout[nOut].scriptPubKey));
    if (!SignSignature(*pwalletMain, txPrev, txStake, 0, SIGHASH_ALL))
        return false;
    if (!txStake.IsCoinStake())
        return false;

    const int nHeight = pindexPrev->nHeight + 1;

    CTransaction txCoinBase;
    txCoinBase.nTime = (unsigned int)nBlockTime;
    txCoinBase.vin.resize(1);
    txCoinBase.vin[0].prevout.SetNull();
    txCoinBase.vin[0].scriptSig = CScript() << nHeight << CBigNum(1);
    txCoinBase.vout.resize(1);
    txCoinBase.vout[0].SetEmpty();

    out.block.SetNull();
    out.block.nVersion = CBlock::CURRENT_VERSION;
    out.block.hashPrevBlock = pindexPrev->GetBlockHash();
    out.block.nTime = (unsigned int)nBlockTime;
    out.block.nBits = GetNextTargetRequired(pindexPrev, true);
    out.block.nNonce = 0;
    out.block.vtx.push_back(txCoinBase);
    out.block.vtx.push_back(txStake);
    out.block.hashMerkleRoot = out.block.BuildMerkleTree();

    out.hash = out.block.GetHash();
    out.index = CBlockIndex(0, 0, out.block);
    out.index.pprev = pindexPrev;
    out.index.nHeight = nHeight;
    out.index.phashBlock = &out.hash;
    return out.block.IsProofOfStake();
}

// Connect and discard every write: an accepted arm would otherwise spend the
// outputs the next arm needs.
CBlock::ConnectResult ConnectAndRollBack(StakeBlock& sb, std::string& strLogOut)
{
    LOCK(cs_main);
    CTxDB txdb;
    CBlock::ConnectResult result = CBlock::CONNECT_RESULT_INVALID;
    BOOST_REQUIRE(txdb.TxnBegin());
    ConnectLog log;
    BOOST_REQUIRE(log.Begin());
    const bool fConnected = sb.block.ConnectBlock(txdb, sb.Index(), false, false, &result);
    strLogOut = log.End();
    BOOST_REQUIRE(txdb.TxnAbort());
    BOOST_CHECK_EQUAL(fConnected, result == CBlock::CONNECT_RESULT_OK);
    return result;
}

} // namespace

// The rule, both ways, on one chain. The refused block and the accepted block
// differ only in which output the coinstake spends.
BOOST_AUTO_TEST_CASE(a_plain_coinstake_may_not_spend_a_shielded_output)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_REQUIRE_MESSAGE(pindexBest->nHeight + 3 < FORK_HEIGHT_DAG,
                          "the coinstake rules sit on the proof-of-stake path, "
                          "which ends at the DAG fork " << FORK_HEIGHT_DAG
                          << "; the chain is already at " << pindexBest->nHeight);

    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;

    CBlock blockFunding;
    std::string strFundingLog;
    BOOST_REQUIRE_MESSAGE(MineBlock(blockFunding, strFundingLog),
                          "could not mine the funding block: " << strFundingLog);

    // The shielding transaction is stamped with the template's own header time.
    // A template built in the same second as its parent repeats the parent's
    // time, and CheckBlock refuses a block older than a transaction it carries.
    std::unique_ptr<CBlock> pblockShield(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblockShield.get() != NULL);
    CBlockIndex* pindexShieldParent = ParentOf(*pblockShield);
    BOOST_REQUIRE(pindexShieldParent != NULL);

    CTransaction txShield;
    BOOST_REQUIRE_MESSAGE(
        BuildShieldingTx(blockFunding.vtx[0], 0, 5 * CENT,
                         pblockShield->nTime, txShield),
        "could not build the shielding transaction");
    BOOST_REQUIRE(txShield.IsShielded());
    pblockShield->vtx.push_back(txShield);

    std::string strShieldMineLog;
    BOOST_REQUIRE_MESSAGE(SealAndProcess(pblockShield.get(), pindexShieldParent,
                                         strShieldMineLog),
                          "the chain refused a block carrying a legacy shielded "
                          "transaction, so the rule below is unreachable here: "
                          << strShieldMineLog);
    const CBlock blockShield = *pblockShield;
    BOOST_REQUIRE_EQUAL(blockShield.vtx.size(), 2u);
    BOOST_REQUIRE(blockShield.vtx[1].GetHash() == txShield.GetHash());

    // The clock is pushed past the collateralnode payment window, so the accepted
    // arm is not judged on gossiped state this suite does not set up.
    SetMockTime(GetTime() + 10 * CollateralnodePaymentWindowSeconds());

    // Accepted: the same shape, spending the shielded block's own coinbase.
    StakeBlock plain;
    BOOST_REQUIRE_MESSAGE(BuildStakeBlock(blockShield.vtx[0], 0, plain),
                          "could not build the control coinstake block");
    BOOST_REQUIRE(plain.index.nHeight < FORK_HEIGHT_DAG);
    std::string strPlainLog;
    const CBlock::ConnectResult plainResult = ConnectAndRollBack(plain, strPlainLog);
    BOOST_CHECK_MESSAGE(plainResult == CBlock::CONNECT_RESULT_OK,
                        "a coinstake spending an ordinary output must connect, got result "
                        << (int)plainResult << "; log: " << strPlainLog);
    BOOST_CHECK(strPlainLog.find("coinstake input from shielded transaction") ==
                std::string::npos);

    // Refused: the same shape, spending the shielded transaction's change output.
    StakeBlock shielded;
    BOOST_REQUIRE_MESSAGE(BuildStakeBlock(txShield, 0, shielded),
                          "could not build the shielded-input coinstake block");
    BOOST_REQUIRE_EQUAL(shielded.index.nHeight, plain.index.nHeight);
    std::string strShieldedLog;
    const CBlock::ConnectResult shieldedResult = ConnectAndRollBack(shielded, strShieldedLog);
    BOOST_CHECK_MESSAGE(shieldedResult == CBlock::CONNECT_RESULT_INVALID,
                        "a coinstake spending a shielded transaction's output must be "
                        "refused as consensus-invalid, got result " << (int)shieldedResult
                        << "; log: " << strShieldedLog);
    BOOST_CHECK_MESSAGE(
        strShieldedLog.find("coinstake input from shielded transaction") != std::string::npos,
        "the refusal did not come from the coinstake shielded-input rule; log: "
        << strShieldedLog);
}

BOOST_AUTO_TEST_SUITE_END()
