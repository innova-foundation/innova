// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Pins proof-of-stake validity to the v4.3.9.x mainnet rules, against a detached index
// run in mapBlockIndex: truncated coin-day weight, modifier choice, empty PoS coinbase.

#include <boost/test/unit_test.hpp>

#include <stdio.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "../bignum.h"
#include "../kernel.h"
#include "../main.h"
#include "../util.h"

BOOST_AUTO_TEST_SUITE(stake_kernel_v4_tests)

namespace {

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

struct Successor
{
    unsigned int nTime;
    bool fGenerated;
    uint64_t nModifier;
};

// A kernel source block and the blocks after it, detached from the real chain.
class SyntheticRun
{
public:
    CBlock blockFrom;
    std::vector<CBlockIndex*> vIndex;

    SyntheticRun(unsigned int nTimeFrom, int nHeightFrom, const std::vector<Successor>& vNext)
    {
        static unsigned int nSalt = 0;
        blockFrom.nVersion = 7;
        blockFrom.hashPrevBlock = Hash(BEGIN(nSalt), END(nSalt));
        ++nSalt;
        blockFrom.hashMerkleRoot = 0;
        blockFrom.nTime = nTimeFrom;
        blockFrom.nBits = 0x1e0fffff;
        blockFrom.nNonce = 0;

        LOCK(cs_main);
        Add(blockFrom.GetHash(), nTimeFrom, nHeightFrom, false, 0x5eed5eed5eed5eedULL);
        for (size_t i = 0; i < vNext.size(); i++)
        {
            uint256 hash = Hash(BEGIN(nSalt), END(nSalt));
            ++nSalt;
            Add(hash, vNext[i].nTime, nHeightFrom + 1 + (int)i, vNext[i].fGenerated, vNext[i].nModifier);
        }
    }

    ~SyntheticRun()
    {
        LOCK(cs_main);
        for (size_t i = 0; i < vIndex.size(); i++)
        {
            mapBlockIndex.erase(*vIndex[i]->phashBlock);
            delete vIndex[i];
        }
    }

    uint256 HashFrom() const { return *vIndex[0]->phashBlock; }

private:
    void Add(const uint256& hash, unsigned int nTime, int nHeight, bool fGenerated, uint64_t nModifier)
    {
        BOOST_REQUIRE(mapBlockIndex.count(hash) == 0);
        CBlockIndex* pindex = new CBlockIndex();
        pindex->nTime = nTime;
        pindex->nHeight = nHeight;
        pindex->SetStakeModifier(nModifier, fGenerated);
        if (!vIndex.empty())
        {
            pindex->pprev = vIndex.back();
            vIndex.back()->pnext = pindex;
        }
        std::map<uint256, CBlockIndex*>::iterator mi =
            mapBlockIndex.insert(std::make_pair(hash, pindex)).first;
        pindex->phashBlock = &(mi->first);
        vIndex.push_back(pindex);
    }
};

// One call's log output: the coinbase rule refuses through error(), so the
// printed reason separates it from a later refusal.
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

const unsigned int TIME_FROM = 1700000000;
const unsigned int ONE_DAY = 24 * 60 * 60;
// The height of the first block of the rejected branch.
const int EVAL_HEIGHT = 7886518;

CTransaction KernelSource(int64_t nValue)
{
    CTransaction tx;
    tx.nTime = TIME_FROM;
    tx.vout.push_back(CTxOut(nValue, CScript()));
    return tx;
}

CBigNum CeilDiv(const CBigNum& a, const CBigNum& b)
{
    return (a + b - 1) / b;
}

} // namespace

// A kernel hash above floor(value * weight / COIN / 86400) * target is refused
// even when hash * COIN * 86400 <= value * weight * target.
BOOST_AUTO_TEST_CASE(the_coin_day_weight_is_truncated_before_the_target_multiply)
{
    std::vector<Successor> vNext;
    Successor next = { TIME_FROM + 7 * ONE_DAY, true, 0x0123456789abcdefULL };
    vNext.push_back(next);
    SyntheticRun run(TIME_FROM, EVAL_HEIGHT - 100000, vNext);

    const unsigned int nTimeTx = TIME_FROM + 2 * ONE_DAY;
    const int64_t nWeight = GetWeight((int64_t)TIME_FROM, (int64_t)nTimeTx);
    BOOST_REQUIRE(nWeight > 0);
    const COutPoint prevout(Hash(BEGIN(TIME_FROM), END(TIME_FROM)), 0);

    // The hash does not depend on the output value or nBits.
    uint256 hashProbe = 0, targetProbe = 0;
    CheckStakeKernelHash(0x207fffff, run.blockFrom, 0, KernelSource(COIN), prevout, nTimeTx,
                         hashProbe, targetProbe, false, EVAL_HEIGHT);
    BOOST_REQUIRE(hashProbe != 0);
    const CBigNum bnHash(hashProbe);

    CBigNum bnTarget = bnHash * 2 / 5;
    const unsigned int nBits = bnTarget.GetCompact();
    bnTarget.SetCompact(nBits);
    BOOST_REQUIRE(bnTarget > 0);
    const CBigNum bnFloor = bnHash / bnTarget;
    BOOST_REQUIRE(bnFloor >= 2);
    BOOST_REQUIRE(bnFloor * bnTarget < bnHash);

    const CBigNum bnDay = CBigNum(COIN) * (int64_t)ONE_DAY;
    const CBigNum bnValueCross = CeilDiv(bnHash * bnDay, CBigNum(nWeight) * bnTarget);
    const CBigNum bnValueControl = CeilDiv((bnFloor + 1) * bnDay, CBigNum(nWeight));
    BOOST_REQUIRE(bnValueCross < CBigNum(MAX_MONEY));
    BOOST_REQUIRE(bnValueControl < CBigNum(MAX_MONEY));
    const int64_t nValueCross = (int64_t)CBigNum(bnValueCross).getuint64();
    const int64_t nValueControl = (int64_t)CBigNum(bnValueControl).getuint64();

    // The refused case is exactly the one the cross-multiplied form accepts.
    BOOST_REQUIRE(CBigNum(nValueCross) * nWeight / COIN / (int64_t)ONE_DAY == bnFloor);
    BOOST_REQUIRE(bnHash * bnDay <= CBigNum(nValueCross) * nWeight * bnTarget);
    BOOST_REQUIRE(CBigNum(nValueControl) * nWeight / COIN / (int64_t)ONE_DAY == bnFloor + 1);

    const bool vNets[3][2] = { { false, false }, { false, true }, { true, false } };
    for (int i = 0; i < 3; i++)
    {
        NetworkGuard net(vNets[i][0], vNets[i][1]);

        uint256 hashProof = 0, hashTarget = 0;
        const bool fCross = CheckStakeKernelHash(nBits, run.blockFrom, 0, KernelSource(nValueCross),
                                                 prevout, nTimeTx, hashProof, hashTarget, false, EVAL_HEIGHT);
        BOOST_CHECK_MESSAGE(!fCross, "net " << i << ": a hash above floor(coin-day weight) * target "
                            "was accepted");
        BOOST_CHECK(hashProof == hashProbe);
        BOOST_CHECK(hashTarget == (bnFloor * bnTarget).getuint256());

        hashProof = 0; hashTarget = 0;
        const bool fControl = CheckStakeKernelHash(nBits, run.blockFrom, 0, KernelSource(nValueControl),
                                                   prevout, nTimeTx, hashProof, hashTarget, false, EVAL_HEIGHT);
        BOOST_CHECK_MESSAGE(fControl, "net " << i << ": a hash below (floor + 1) * target was refused");
    }
}

// The tip has no generated modifier past the selection interval: selection
// fails rather than taking the tip's inherited modifier.
BOOST_AUTO_TEST_CASE(the_kernel_modifier_is_never_taken_from_the_tip)
{
    NetworkGuard net(false, false);
    const uint64_t nInherited = 0xaaaaaaaaaaaaaaaaULL;
    const uint64_t nGenerated = 0xbbbbbbbbbbbbbbbbULL;

    {
        std::vector<Successor> vNext;
        Successor tip = { TIME_FROM + 7 * ONE_DAY, false, nInherited };
        vNext.push_back(tip);
        SyntheticRun run(TIME_FROM, EVAL_HEIGHT - 100000, vNext);

        uint64_t nModifier = 0;
        int nModifierHeight = 0;
        int64_t nModifierTime = 0;
        BOOST_CHECK_MESSAGE(!GetKernelStakeModifier(run.HashFrom(), nModifier, nModifierHeight,
                                                    nModifierTime, false),
                            "the tip's inherited modifier was selected: 0x" << std::hex << nModifier);

        uint256 hashProof = 0, hashTarget = 0;
        const COutPoint prevout(Hash(BEGIN(TIME_FROM), END(TIME_FROM)), 0);
        BOOST_CHECK(!CheckStakeKernelHash(0x207fffff, run.blockFrom, 0, KernelSource(1000 * COIN),
                                          prevout, TIME_FROM + 2 * ONE_DAY, hashProof, hashTarget,
                                          false, EVAL_HEIGHT));
        BOOST_CHECK(hashProof == 0);
    }

    // Control: the next generated modifier after the interval is selected.
    {
        std::vector<Successor> vNext;
        Successor inherited = { TIME_FROM + 7 * ONE_DAY, false, nInherited };
        Successor generated = { TIME_FROM + 8 * ONE_DAY, true, nGenerated };
        vNext.push_back(inherited);
        vNext.push_back(generated);
        SyntheticRun run(TIME_FROM, EVAL_HEIGHT - 100000, vNext);

        uint64_t nModifier = 0;
        int nModifierHeight = 0;
        int64_t nModifierTime = 0;
        BOOST_REQUIRE(GetKernelStakeModifier(run.HashFrom(), nModifier, nModifierHeight,
                                             nModifierTime, false));
        BOOST_CHECK(nModifier == nGenerated);
        BOOST_CHECK_EQUAL(nModifierHeight, run.vIndex[2]->nHeight);
        BOOST_CHECK_EQUAL(nModifierTime, (int64_t)(TIME_FROM + 8 * ONE_DAY));
    }
}

// Below the ms-timestamp gate a proof-of-stake coinbase with any output beyond
// the single empty one is refused, whatever the extra output carries.
BOOST_AUTO_TEST_CASE(a_proof_of_stake_coinbase_is_one_empty_output_below_the_gate)
{
    NetworkGuard net(false, false);

    CBlockIndex* pindexPrev = NULL;
    {
        LOCK(cs_main);
        pindexPrev = pindexBest;
    }
    BOOST_REQUIRE(pindexPrev != NULL);
    BOOST_REQUIRE(pindexPrev->nHeight + 1 < FORK_HEIGHT_MS_TIMESTAMP);

    std::string vLogs[2];
    bool vResults[2] = { true, true };
    for (int a = 0; a < 2; a++)
    {
        CBlock block;
        block.nVersion = CBlock::CURRENT_VERSION;
        block.hashPrevBlock = pindexPrev->GetBlockHash();
        block.nTime = pindexPrev->nTime + 15;
        block.nBits = 0;

        CTransaction coinbase;
        coinbase.nTime = block.nTime;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript() << (pindexPrev->nHeight + 1);
        coinbase.vout.resize(1);
        coinbase.vout[0].SetEmpty();
        if (a == 1)
            coinbase.vout.push_back(CTxOut(0, CScript() << OP_RETURN << std::vector<unsigned char>(4, 0x42)));

        CTransaction coinstake;
        coinstake.nTime = block.nTime;
        coinstake.vin.push_back(CTxIn(Hash(BEGIN(TIME_FROM), END(TIME_FROM)), 0));
        coinstake.vout.resize(2);
        coinstake.vout[0].SetEmpty();
        coinstake.vout[1] = CTxOut(COIN, CScript() << OP_TRUE);

        block.vtx.push_back(coinbase);
        block.vtx.push_back(coinstake);
        block.hashMerkleRoot = block.BuildMerkleTree();
        BOOST_REQUIRE(block.IsProofOfStake());

        CaptureLog log;
        BOOST_REQUIRE(log.Begin());
        {
            LOCK(cs_main);
            vResults[a] = block.AcceptBlock();
        }
        vLogs[a] = log.End();
    }

    // The control has the v4 shape and is refused later, for its nBits.
    BOOST_CHECK(!vResults[0]);
    BOOST_CHECK_MESSAGE(vLogs[0].find("proof-of-stake coinbase has") == std::string::npos,
                        "a single empty coinbase output was refused by the coinbase rule; log: "
                        << vLogs[0]);
    BOOST_CHECK_MESSAGE(vLogs[0].find("incorrect proof-of-stake") != std::string::npos,
                        "the control did not reach the nBits check; log: " << vLogs[0]);
    BOOST_CHECK(!vResults[1]);
    BOOST_CHECK_MESSAGE(vLogs[1].find("proof-of-stake coinbase has 2 outputs") != std::string::npos,
                        "a proof-of-stake coinbase with an extra OP_RETURN output was not refused "
                        "by the coinbase rule; log: " << vLogs[1]);
}

BOOST_AUTO_TEST_SUITE_END()
