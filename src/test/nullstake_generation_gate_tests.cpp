// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NullStake generation gates in ConnectBlock (R-NS-001..003): each needs its own fork height
// and kernel proof. Arms are spend-free fork candidates connected and rolled back, with a
// plain PoS coinstake at the same height as control.

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

BOOST_AUTO_TEST_SUITE(nullstake_generation_gate_tests)

namespace {

// The suite mines when the fixture is short. A registered wallet would record
// those coinbases and move the ordering counters other suites pin.
struct DetachedWalletGuard
{
    DetachedWalletGuard() { UnregisterWallet(pwalletMain); }
    ~DetachedWalletGuard() { RegisterWallet(pwalletMain); }
};

struct MockClockGuard
{
    ~MockClockGuard() { SetMockTime(0); }
};

// One ConnectBlock call's log output. Every arm returns false; which branch
// printed the refusal is the whole assertion.
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
        if (++nHashes > 2000000U)
            return false;
    }
    return true;
}

// Extend the fixture to nTarget. A no-op when some earlier suite already got
// there, which is what keeps the arms below independent of run order.
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

// An unspent, wallet-owned output in a block at or below nMaxHeight. The
// candidate forks at nMaxHeight + 1, so anything found here is one confirmation
// deep at least, which clears the regtest coinbase maturity of one.
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

// Spend-free shielded body: one zero-value output note with range proof. The
// binding signature covers vin, so SealShieldedBody attaches it after signing.
bool AttachSpendFreeShieldedBody(CTransaction& tx, std::vector<unsigned char>& vchBlindOut)
{
    CShieldedPaymentAddress zAddr = pwalletMain->GenerateNewShieldedAddress();

    CShieldedNote note;
    note.addr = zAddr;
    note.nValue = 0;
    for (int i = 0; i < 32; i++)
    {
        note.rho.begin()[i] = (unsigned char)(0x31 + i);
        note.rcm.begin()[i] = (unsigned char)(0x71 + i);
    }
    if (!note.GenerateBlindingFactor())
        return false;

    CPedersenCommitment cv;
    if (!note.GetPedersenCommitment(cv))
        return false;

    CShieldedOutputDescription output;
    output.cv = cv;
    output.cmu = note.GetCommitment();
    if (!CreateBulletproofRangeProof(note.nValue, note.vchBlind, cv, output.rangeProof))
        return false;
    if (!EncryptShieldedNote(note, zAddr, output.vchEphemeralKey, output.vchEncCiphertext))
        return false;

    tx.nValueBalance = 0;
    tx.vShieldedOutput.push_back(output);
    vchBlindOut = note.vchBlind;
    return true;
}

// Smallest kernel proof each generation reads as non-null; placeholder bytes that
// clear the proof-missing refusal and never reach a verifier.
void AttachNonNullKernelProof(CTransaction& tx, int nTxVersion)
{
    if (nTxVersion == SHIELDED_TX_VERSION_NULLSTAKE)
    {
        tx.nullstakeProof.vchProof.assign(1, 0x01);
        return;
    }
    CBulletproofACProof* pProof = NULL;
    if (nTxVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2)
        pProof = &tx.nullstakeProofV2.acProof;
    else if (nTxVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
        pProof = &tx.nullstakeProofV3.acProof;
    if (pProof == NULL)
        return;
    pProof->vchAI.assign(SECP256K1_POINT_SIZE, 0x02);
    pProof->ipaProof.vchAFinal.assign(IPA_SCALAR_SIZE, 0x03);
}

// The binding signature over the finished transaction.
bool SealShieldedBody(CTransaction& tx, const std::vector<unsigned char>& vchBlind)
{
    std::vector<std::vector<unsigned char> > vInputBlinds, vOutputBlinds;
    vInputBlinds.push_back(std::vector<unsigned char>(32, 0));
    vOutputBlinds.push_back(vchBlind);
    CBindingSignature bindingSig;
    if (!CreateBindingSignature(vInputBlinds, vOutputBlinds, tx.GetBindingSigHash(), bindingSig))
        return false;
    tx.bindingSig.bindingSig = bindingSig;
    return true;
}

// A proof-of-stake candidate forked off pindexParent. The coinstake pays back
// exactly what it spends, so it mints nothing and no reward rule can decide the
// arm; only the transaction version varies between arms.
struct StakeCandidate
{
    CBlock block;
    uint256 hash;
    CBlockIndex index;

    CBlockIndex* Index() { return &index; }
    int Height() const { return index.nHeight; }
};

bool BuildStakeCandidate(CBlockIndex* pindexParent, const CTransaction& txPrev,
                         unsigned int nOut, int nTxVersion, StakeCandidate& out,
                         bool fB2CHiddenMofN = false,
                         bool fNonNullKernelProof = false)
{
    if (pindexParent == NULL || nOut >= txPrev.vout.size())
        return false;
    const int64_t nBlockTime = pindexParent->GetBlockTime() + 1;
    const int64_t nIn = txPrev.vout[nOut].nValue;
    if (nIn <= 0)
        return false;

    CTransaction txStake;
    txStake.nTime = (unsigned int)nBlockTime;
    txStake.vin.push_back(CTxIn(txPrev.GetHash(), nOut));
    txStake.vout.push_back(CTxOut());
    txStake.vout[0].SetEmpty();
    txStake.vout.push_back(CTxOut(nIn, txPrev.vout[nOut].scriptPubKey));
    std::vector<unsigned char> vchBlind;
    if (nTxVersion != 0)
    {
        txStake.nVersion = nTxVersion;
        if (!AttachSpendFreeShieldedBody(txStake, vchBlind))
            return false;
        // Before the seal: the binding-sig hash commits to the kernel proof.
        if (fNonNullKernelProof)
            AttachNonNullKernelProof(txStake, nTxVersion);
    }
    if (fB2CHiddenMofN)
    {
        // M-of-N cold-stake coinstake must keep all value shielded, or ConnectInputs
        // refuses the transparent pay-back before the version gate.
        txStake.vout[1].nValue = 0;

        // The shape the B2-c bound names: an M-of-N V3 kernel proof tagged with
        // the hidden-signer authorization mode. Set before the signature and the
        // binding seal so the arm is signed over the body it carries.
        txStake.nullstakeProofV3.acProof.vchAI.assign(33, 0x33);
        txStake.nullstakeProofV3.acProof.ipaProof.vchAFinal.assign(32, 0x34);
        txStake.nullstakeProofV3.nThresholdM = 2;
        txStake.nullstakeProofV3.nAuthMode = NULLSTAKE_AUTHMODE_B2C_HIDDEN;
        txStake.nullstakeProofV3.vStakerSet.assign(3, std::vector<unsigned char>(33, 0x02));
        txStake.nullstakeProofV3.hiddenAuth.vchResearchProof.assign(64, 0x35);
    }
    if (!SignSignature(*pwalletMain, txPrev, txStake, 0, SIGHASH_ALL))
        return false;
    if (nTxVersion != 0 && !SealShieldedBody(txStake, vchBlind))
        return false;
    if (!txStake.IsCoinStake())
        return false;

    const int nHeight = pindexParent->nHeight + 1;

    CTransaction txCoinBase;
    txCoinBase.nTime = (unsigned int)nBlockTime;
    txCoinBase.vin.resize(1);
    txCoinBase.vin[0].prevout.SetNull();
    txCoinBase.vin[0].scriptSig = CScript() << nHeight << CBigNum(1);
    txCoinBase.vout.resize(1);
    txCoinBase.vout[0].SetEmpty();

    out.block.SetNull();
    out.block.nVersion = CBlock::CURRENT_VERSION;
    out.block.hashPrevBlock = pindexParent->GetBlockHash();
    out.block.nTime = (unsigned int)nBlockTime;
    out.block.nBits = GetNextTargetRequired(pindexParent, true);
    out.block.nNonce = 0;
    out.block.vtx.push_back(txCoinBase);
    out.block.vtx.push_back(txStake);
    out.block.hashMerkleRoot = out.block.BuildMerkleTree();

    out.hash = out.block.GetHash();
    out.index = CBlockIndex(0, 0, out.block);
    out.index.pprev = pindexParent;
    out.index.nHeight = nHeight;
    out.index.phashBlock = &out.hash;
    return out.block.IsProofOfStake();
}

// Connect with fJustCheck and discard writes, so the tip never moves. fJustCheck
// because the commitment tree is node-global and a full connect of a low fork
// candidate would be refused on the tip's anchor height.
CBlock::ConnectResult ConnectAndRollBack(StakeCandidate& sc, std::string& strLogOut)
{
    LOCK(cs_main);
    CTxDB txdb;
    CBlock::ConnectResult result = CBlock::CONNECT_RESULT_INVALID;
    BOOST_REQUIRE(txdb.TxnBegin());
    ConnectLog log;
    BOOST_REQUIRE(log.Begin());
    const bool fConnected = sc.block.ConnectBlock(txdb, sc.Index(), true, false, &result);
    strLogOut = log.End();
    BOOST_REQUIRE(txdb.TxnAbort());
    BOOST_CHECK_EQUAL(fConnected, result == CBlock::CONNECT_RESULT_OK);
    return result;
}

// The control every arm below rests on: a plain coinstake of the same shape, at
// the same height, on the same parent, must connect. If it does not, a refusal
// of the shielded arm says nothing about the version gate.
void RequirePlainCoinstakeConnects(CBlockIndex* pindexParent,
                                   const CTransaction& txPrev, unsigned int nOut)
{
    StakeCandidate plain;
    BOOST_REQUIRE_MESSAGE(BuildStakeCandidate(pindexParent, txPrev, nOut, 0, plain),
                          "could not build the plain control coinstake at height "
                          << pindexParent->nHeight + 1);
    std::string strLog;
    const CBlock::ConnectResult result = ConnectAndRollBack(plain, strLog);
    BOOST_REQUIRE_MESSAGE(result == CBlock::CONNECT_RESULT_OK,
                          "the plain control coinstake did not connect at height "
                          << plain.Height() << ", so a refusal of the shielded arm "
                          "at this height proves nothing; log: " << strLog);
}

// One arm: a coinstake of nTxVersion at pindexParent + 1 must be refused, and
// the refusal must be the one strReason names.
void CheckGateRefusal(CBlockIndex* pindexParent, const CTransaction& txPrev,
                      unsigned int nOut, int nTxVersion, const std::string& strReason)
{
    StakeCandidate arm;
    BOOST_REQUIRE_MESSAGE(BuildStakeCandidate(pindexParent, txPrev, nOut, nTxVersion, arm),
                          "could not build the version " << nTxVersion
                          << " coinstake at height " << pindexParent->nHeight + 1);
    std::string strLog;
    const CBlock::ConnectResult result = ConnectAndRollBack(arm, strLog);
    BOOST_CHECK_MESSAGE(result == CBlock::CONNECT_RESULT_INVALID,
                        "version " << nTxVersion << " coinstake at height " << arm.Height()
                        << " must be refused as consensus-invalid, got result "
                        << (int)result << "; log: " << strLog);
    BOOST_CHECK_MESSAGE(strLog.find(strReason) != std::string::npos,
                        "version " << nTxVersion << " coinstake at height " << arm.Height()
                        << " was not refused by \"" << strReason << "\"; log: " << strLog);
}

// The same arm, carrying a kernel proof its branch reads as present, so the
// refusal comes from the check after the proof-missing one.
void CheckRefusalWithKernelProof(CBlockIndex* pindexParent, const CTransaction& txPrev,
                                 unsigned int nOut, int nTxVersion,
                                 const std::string& strReason)
{
    StakeCandidate arm;
    BOOST_REQUIRE_MESSAGE(BuildStakeCandidate(pindexParent, txPrev, nOut, nTxVersion, arm, false, true),
                          "could not build the version " << nTxVersion
                          << " coinstake at height " << pindexParent->nHeight + 1);
    std::string strLog;
    const CBlock::ConnectResult result = ConnectAndRollBack(arm, strLog);
    BOOST_CHECK_MESSAGE(result == CBlock::CONNECT_RESULT_INVALID,
                        "version " << nTxVersion << " coinstake at height " << arm.Height()
                        << " must be refused as consensus-invalid, got result "
                        << (int)result << "; log: " << strLog);
    BOOST_CHECK_MESSAGE(strLog.find(strReason) != std::string::npos,
                        "version " << nTxVersion << " coinstake at height " << arm.Height()
                        << " was not refused by \"" << strReason << "\"; log: " << strLog);
}

} // namespace

// Below its own fork height each generation is refused by its own branch, and
// the three branches answer separately: at height 2 all three are below their
// gate, and each prints the refusal that names its own generation.
BOOST_AUTO_TEST_CASE(each_generation_is_refused_below_its_own_fork_height)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_REQUIRE_MESSAGE(FORK_HEIGHT_NULLSTAKE == 3 && FORK_HEIGHT_NULLSTAKE_V2 == 5 &&
                              FORK_HEIGHT_NULLSTAKE_V3 == 7 && FORK_HEIGHT_DAG == 11,
                          "the regtest NullStake ladder moved; the heights below are "
                          "chosen against 3/5/7 under the DAG gate at 11");

    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;

    BOOST_REQUIRE_MESSAGE(MineTo(6), "could not extend the fixture to height 6");
    SetMockTime(GetTime() + 10 * CollateralnodePaymentWindowSeconds());

    // Height 2 is below all three gates. 4 and 6 are below the V2 and V3 gates
    // while the V1 gate is already open, so a refusal there cannot be the
    // shared shielded-coinstake rule further down ConnectBlock.
    struct Arm { int nParentHeight; int nTxVersion; const char* strReason; };
    const Arm vArms[] = {
        { 1, SHIELDED_TX_VERSION_NULLSTAKE,      "NullStake coinstake before fork height" },
        { 1, SHIELDED_TX_VERSION_NULLSTAKE_V2,   "NullStake V2 coinstake before fork height" },
        { 1, SHIELDED_TX_VERSION_NULLSTAKE_COLD, "NullStake V3 cold stake coinstake before fork height" },
        { 3, SHIELDED_TX_VERSION_NULLSTAKE_V2,   "NullStake V2 coinstake before fork height" },
        { 3, SHIELDED_TX_VERSION_NULLSTAKE_COLD, "NullStake V3 cold stake coinstake before fork height" },
        { 5, SHIELDED_TX_VERSION_NULLSTAKE_COLD, "NullStake V3 cold stake coinstake before fork height" },
    };

    for (size_t i = 0; i < ARRAYLEN(vArms); i++)
    {
        CBlockIndex* pindexParent = AncestorAt(vArms[i].nParentHeight);
        BOOST_REQUIRE_MESSAGE(pindexParent != NULL,
                              "no ancestor at height " << vArms[i].nParentHeight);
        CTransaction txPrev;
        unsigned int nOut = 0;
        BOOST_REQUIRE_MESSAGE(FindFundingOutput(vArms[i].nParentHeight, txPrev, nOut),
                              "no unspent wallet output at or below height "
                              << vArms[i].nParentHeight << "; the arm at height "
                              << vArms[i].nParentHeight + 1 << " has nothing to stake");

        RequirePlainCoinstakeConnects(pindexParent, txPrev, nOut);
        CheckGateRefusal(pindexParent, txPrev, nOut, vArms[i].nTxVersion, vArms[i].strReason);
    }
}

// At and above its own fork height each generation still needs its own kernel
// proof, and the proof it needs is its own: a body carrying none is refused by
// the branch that names that generation, never by a neighbour's.
BOOST_AUTO_TEST_CASE(each_generation_requires_its_own_kernel_proof)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);

    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;

    BOOST_REQUIRE_MESSAGE(MineTo(6), "could not extend the fixture to height 6");
    SetMockTime(GetTime() + 10 * CollateralnodePaymentWindowSeconds());

    const int nParentHeight = 6;    // the arms connect at 7: at or above all three gates
    BOOST_REQUIRE(nParentHeight + 1 >= FORK_HEIGHT_NULLSTAKE);
    BOOST_REQUIRE(nParentHeight + 1 >= FORK_HEIGHT_NULLSTAKE_V2);
    BOOST_REQUIRE(nParentHeight + 1 >= FORK_HEIGHT_NULLSTAKE_V3);
    BOOST_REQUIRE(nParentHeight + 1 < FORK_HEIGHT_DAG);
    BOOST_REQUIRE_MESSAGE(IsNullStakeBlockProductionReachableAtHeight(nParentHeight + 1),
                          "height " << nParentHeight + 1 << " is outside the reachable "
                          "NullStake window, so these arms would be decided by the "
                          "shared reachability rule instead of by the generation gates");

    CBlockIndex* pindexParent = AncestorAt(nParentHeight);
    BOOST_REQUIRE(pindexParent != NULL);
    CTransaction txPrev;
    unsigned int nOut = 0;
    BOOST_REQUIRE_MESSAGE(FindFundingOutput(nParentHeight, txPrev, nOut),
                          "no unspent wallet output at or below height " << nParentHeight);

    RequirePlainCoinstakeConnects(pindexParent, txPrev, nOut);

    CheckGateRefusal(pindexParent, txPrev, nOut, SHIELDED_TX_VERSION_NULLSTAKE,
                     "NullStake kernel proof missing");
    CheckGateRefusal(pindexParent, txPrev, nOut, SHIELDED_TX_VERSION_NULLSTAKE_V2,
                     "NullStake V2 kernel proof missing");
    CheckGateRefusal(pindexParent, txPrev, nOut, SHIELDED_TX_VERSION_NULLSTAKE_COLD,
                     "NullStake V3 kernel proof missing");
}

// A spend-free body is refused by the next check after proof-missing; this is the
// last reachable statement in each branch (a shielded spend is refused block-wide
// by the FCMP-era rule first).
BOOST_AUTO_TEST_CASE(each_generation_refuses_a_coinstake_with_no_shielded_spend)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);

    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;

    BOOST_REQUIRE_MESSAGE(MineTo(6), "could not extend the fixture to height 6");
    SetMockTime(GetTime() + 10 * CollateralnodePaymentWindowSeconds());

    const int nParentHeight = 6;    // the arms connect at 7: at or above all three gates
    BOOST_REQUIRE(nParentHeight + 1 >= FORK_HEIGHT_NULLSTAKE_V3);
    BOOST_REQUIRE(nParentHeight + 1 < FORK_HEIGHT_DAG);
    BOOST_REQUIRE_MESSAGE(IsNullStakeBlockProductionReachableAtHeight(nParentHeight + 1),
                          "height " << nParentHeight + 1 << " is outside the reachable "
                          "NullStake window, so these arms would be decided by the "
                          "shared reachability rule instead of by the branch");

    CBlockIndex* pindexParent = AncestorAt(nParentHeight);
    BOOST_REQUIRE(pindexParent != NULL);
    CTransaction txPrev;
    unsigned int nOut = 0;
    BOOST_REQUIRE_MESSAGE(FindFundingOutput(nParentHeight, txPrev, nOut),
                          "no unspent wallet output at or below height " << nParentHeight);

    RequirePlainCoinstakeConnects(pindexParent, txPrev, nOut);

    // The control for the arms: without the kernel proof the same body stops one
    // check earlier, so reaching the spend refusal is the proof and not the shape.
    CheckGateRefusal(pindexParent, txPrev, nOut, SHIELDED_TX_VERSION_NULLSTAKE,
                     "NullStake kernel proof missing");
    CheckGateRefusal(pindexParent, txPrev, nOut, SHIELDED_TX_VERSION_NULLSTAKE_V2,
                     "NullStake V2 kernel proof missing");
    CheckGateRefusal(pindexParent, txPrev, nOut, SHIELDED_TX_VERSION_NULLSTAKE_COLD,
                     "NullStake V3 kernel proof missing");

    CheckRefusalWithKernelProof(pindexParent, txPrev, nOut, SHIELDED_TX_VERSION_NULLSTAKE,
                                "NullStake coinstake has no shielded spends");
    CheckRefusalWithKernelProof(pindexParent, txPrev, nOut, SHIELDED_TX_VERSION_NULLSTAKE_V2,
                                "NullStake V2 coinstake has no shielded spends");
    CheckRefusalWithKernelProof(pindexParent, txPrev, nOut, SHIELDED_TX_VERSION_NULLSTAKE_COLD,
                                "NullStake V3 coinstake has no shielded spends");
}

// No fully valid NullStake block exists in [FORK_HEIGHT_NULLSTAKE, FORK_HEIGHT_DAG):
// the earliest deep-enough spend is FORK_HEIGHT_SHIELDED + MIN_SHIELDED_SPEND_DEPTH,
// which is the DAG gate. Pins that relation between the three constants.
BOOST_AUTO_TEST_CASE(the_window_admits_no_fully_valid_nullstake_block)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_CHECK(!IsNullStakeBlockProductionReachableAtHeight(FORK_HEIGHT_NULLSTAKE - 1));
    BOOST_CHECK(IsNullStakeBlockProductionReachableAtHeight(FORK_HEIGHT_NULLSTAKE));
    BOOST_CHECK(IsNullStakeBlockProductionReachableAtHeight(FORK_HEIGHT_DAG - 1));
    BOOST_CHECK(!IsNullStakeBlockProductionReachableAtHeight(FORK_HEIGHT_DAG));

    const int nEarliestDeepEnough = FORK_HEIGHT_SHIELDED + MIN_SHIELDED_SPEND_DEPTH;
    BOOST_CHECK_MESSAGE(nEarliestDeepEnough >= FORK_HEIGHT_DAG,
                        "a shielded spend can be " << MIN_SHIELDED_SPEND_DEPTH
                        << " deep by height " << nEarliestDeepEnough
                        << ", which is below the DAG gate " << FORK_HEIGHT_DAG
                        << ": the NullStake accept path is reachable again and needs "
                        "a positive control, not this measurement");
}

// R-B2C-001: the B2-c bound is only reached after the DELEGSET bound, whose window
// lies at or above the DAG gate. Below it, the DELEGSET bound must answer.
BOOST_AUTO_TEST_CASE(the_b2c_hidden_bound_never_answers_where_the_branch_is_alive)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_REQUIRE_MESSAGE(FORK_HEIGHT_NULLSTAKE_V3 == 7 && FORK_HEIGHT_DAG == 11 &&
                              FORK_HEIGHT_NULLSTAKE_DELEGSET == 12 &&
                              FORK_HEIGHT_NULLSTAKE_B2C == 14,
                          "the regtest NullStake ladder moved; the heights below are "
                          "chosen against V3 at 7 under the DAG gate at 11, with "
                          "DELEGSET 12 and B2C 14 above it");

    // What the two bounds' windows are, restated from the gates themselves: the
    // branch is alive on [V3, DAG) and the B2-c bound can only decide on
    // [DELEGSET, B2C). The two do not meet.
    BOOST_REQUIRE_GE(FORK_HEIGHT_NULLSTAKE_DELEGSET, FORK_HEIGHT_DAG);
    BOOST_REQUIRE_GT(FORK_HEIGHT_DAG, FORK_HEIGHT_NULLSTAKE_V3);

    DetachedWalletGuard walletGuard;
    MockClockGuard clockGuard;

    BOOST_REQUIRE_MESSAGE(MineTo(9), "could not extend the fixture to height 9");
    SetMockTime(GetTime() + 10 * CollateralnodePaymentWindowSeconds());

    const char* kDelegSet = "NullStake V3 M-of-N coinstake before DELEGSET fork height";
    const char* kB2C = "NullStake V3 B2-c hidden coinstake before B2C fork height";

    // Candidate heights 7 and 10: the bottom and top of the window where the V3
    // branch is alive, both below DELEGSET and below B2C.
    const int vParents[] = { 6, 9 };
    for (size_t i = 0; i < ARRAYLEN(vParents); i++)
    {
        CBlockIndex* pindexParent = AncestorAt(vParents[i]);
        BOOST_REQUIRE_MESSAGE(pindexParent != NULL,
                              "no ancestor at height " << vParents[i]);
        CTransaction txPrev;
        unsigned int nOut = 0;
        BOOST_REQUIRE_MESSAGE(FindFundingOutput(vParents[i], txPrev, nOut),
                              "no unspent wallet output at or below height "
                              << vParents[i]);

        RequirePlainCoinstakeConnects(pindexParent, txPrev, nOut);

        StakeCandidate arm;
        BOOST_REQUIRE_MESSAGE(
            BuildStakeCandidate(pindexParent, txPrev, nOut,
                                SHIELDED_TX_VERSION_NULLSTAKE_COLD, arm, true),
            "could not build the B2-c hidden M-of-N coinstake at height "
            << pindexParent->nHeight + 1);
        BOOST_REQUIRE_LT(arm.Height(), FORK_HEIGHT_NULLSTAKE_B2C);

        std::string strLog;
        const CBlock::ConnectResult result = ConnectAndRollBack(arm, strLog);
        BOOST_CHECK_MESSAGE(result == CBlock::CONNECT_RESULT_INVALID,
                            "the B2-c hidden coinstake at height " << arm.Height()
                            << " must be refused as consensus-invalid, got result "
                            << (int)result << "; log: " << strLog);
        BOOST_CHECK_MESSAGE(strLog.find(kDelegSet) != std::string::npos,
                            "at height " << arm.Height() << " the DELEGSET bound did "
                            "not answer, so the bound that starves the B2-c bound in "
                            "the reachable window is gone; log: " << strLog);
        BOOST_CHECK_MESSAGE(strLog.find(kB2C) == std::string::npos,
                            "at height " << arm.Height() << " the B2-c hidden-signer "
                            "bound decided the block, so it is reachable and "
                            "R-B2C-001 was retired wrongly; log: " << strLog);
    }
}

BOOST_AUTO_TEST_SUITE_END()
