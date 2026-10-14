// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Mempool fee-rate eviction and replace-by-fee. Policy only: nothing here touches
// block validity.

#include <boost/test/unit_test.hpp>

#include "../hooks.h"
#include "../key.h"
#include "../keystore.h"
#include "../main.h"
#include "../script.h"
#include "../txdb.h"
#include "../util.h"

#include <set>
#include <string>
#include <vector>

extern bool fRequestShutdown;

BOOST_AUTO_TEST_SUITE(mempool_rbf_tests)

namespace {

COutPoint FreshOutPoint()
{
    static uint64_t n = 0x5100;
    return COutPoint(uint256(++n), 0);
}

CTransaction MakeTx(const std::vector<COutPoint>& vIn, unsigned int nOut, size_t nPad = 0)
{
    static unsigned int nSalt = 0;
    CTransaction tx;
    tx.nTime = 1000 + (++nSalt);
    for (size_t i = 0; i < vIn.size(); i++)
        tx.vin.push_back(CTxIn(vIn[i]));
    for (unsigned int i = 0; i < nOut; i++)
    {
        CScript script;
        script << OP_TRUE;
        tx.vout.push_back(CTxOut(COIN, script));
    }
    if (nPad)
        tx.vout[0].scriptPubKey << std::vector<unsigned char>(nPad, 0x01);
    return tx;
}

CTransaction MakeTx(const COutPoint& in, unsigned int nOut = 1, size_t nPad = 0)
{
    return MakeTx(std::vector<COutPoint>(1, in), nOut, nPad);
}

unsigned int Size(const CTransaction& tx)
{
    return ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
}

// Smallest fee whose rate is at least nRate.
int64_t FeeAt(int64_t nRate, const CTransaction& tx)
{
    return (nRate * Size(tx) + 999) / 1000;
}

uint256 Add(CTxMemPool& pool, CTransaction tx, int64_t nFee, bool fReplaceable = true)
{
    const uint256 hash = tx.GetHash();
    LOCK(pool.cs);
    pool.addUnchecked(hash, tx, nFee, fReplaceable);
    return hash;
}

struct Plan
{
    bool fOk;
    std::set<uint256> setReplaced;
    std::set<uint256> setEvicted;
    int64_t nEvictedRate;
    std::string strReason;
};

Plan PlanFor(const CTxMemPool& pool, const CTransaction& tx, int64_t nFee,
             const std::set<uint256>& setConflicts, size_t nLimit,
             bool fMayReplace = true)
{
    Plan plan;
    plan.nEvictedRate = 0;
    plan.fOk = pool.PlanAdmission(tx, nFee, Size(tx), setConflicts, fMayReplace, nLimit,
                                  plan.setReplaced, plan.setEvicted, plan.nEvictedRate,
                                  plan.strReason);
    return plan;
}

std::set<uint256> One(const uint256& hash)
{
    return std::set<uint256>(&hash, &hash + 1);
}

const size_t kRoomy = 100000000;

} // namespace

BOOST_AUTO_TEST_CASE(fee_rate_arithmetic)
{
    BOOST_CHECK_EQUAL(MempoolFeeRate(1000, 250), 4000);
    BOOST_CHECK_EQUAL(MempoolFeeRate(1000, 0), 0);
    BOOST_CHECK_EQUAL(MempoolFeeRate(-5, 100), 0);
    BOOST_CHECK_EQUAL(MempoolFeeRate(MAX_MONEY * 4, 1), MAX_MONEY * 1000);
    BOOST_CHECK_EQUAL(MempoolIncrementalFee(250), MEMPOOL_INCREMENTAL_RELAY_FEE / 4);
    BOOST_CHECK_EQUAL(MempoolIncrementalFee(1), 1);
    BOOST_CHECK_EQUAL(MempoolIncrementalFee(0), 0);
}

BOOST_AUTO_TEST_CASE(size_is_tracked_through_add_remove_and_clear)
{
    CTxMemPool pool;
    CTransaction a = MakeTx(FreshOutPoint(), 1, 300);
    CTransaction b = MakeTx(FreshOutPoint(), 2);
    BOOST_CHECK_EQUAL(pool.GetTotalMemoryUsage(), 0U);

    Add(pool, a, 1000);
    BOOST_CHECK_EQUAL(pool.GetTotalMemoryUsage(), Size(a));
    Add(pool, a, 1000);
    BOOST_CHECK_EQUAL(pool.GetTotalMemoryUsage(), Size(a));
    Add(pool, b, -1);
    BOOST_CHECK_EQUAL(pool.GetTotalMemoryUsage(), Size(a) + Size(b));
    BOOST_CHECK(!pool.mapTxFeeInfo[b.GetHash()].fReplaceable);

    pool.remove(a);
    BOOST_CHECK_EQUAL(pool.GetTotalMemoryUsage(), Size(b));
    BOOST_CHECK_EQUAL(pool.mapTxFeeInfo.count(a.GetHash()), 0U);

    pool.clear();
    BOOST_CHECK_EQUAL(pool.GetTotalMemoryUsage(), 0U);
    BOOST_CHECK(pool.mapTxFeeInfo.empty());
}

BOOST_AUTO_TEST_CASE(descendants_follow_in_pool_spends)
{
    CTxMemPool pool;
    CTransaction a = MakeTx(FreshOutPoint(), 2);
    const uint256 ha = Add(pool, a, 1000);
    const uint256 hb = Add(pool, MakeTx(COutPoint(ha, 0)), 1000);
    const uint256 hc = Add(pool, MakeTx(COutPoint(hb, 0)), 1000);
    const uint256 hd = Add(pool, MakeTx(COutPoint(ha, 1)), 1000);
    const uint256 he = Add(pool, MakeTx(FreshOutPoint()), 1000);

    std::set<uint256> setA;
    pool.CalculateDescendants(ha, setA);
    BOOST_CHECK_EQUAL(setA.size(), 4U);
    BOOST_CHECK(setA.count(ha) && setA.count(hb) && setA.count(hc) && setA.count(hd));
    BOOST_CHECK(!setA.count(he));

    std::set<uint256> setB;
    pool.CalculateDescendants(hb, setB);
    BOOST_CHECK_EQUAL(setB.size(), 2U);
}

BOOST_AUTO_TEST_CASE(a_replacement_needs_a_higher_rate_and_a_higher_absolute_fee)
{
    CTxMemPool pool;
    const COutPoint x = FreshOutPoint();
    CTransaction a = MakeTx(x, 1, 400);
    const int64_t nOldFee = 3000;
    const uint256 ha = Add(pool, a, nOldFee);

    // Same size, same fee: the rate does not rise.
    CTransaction same = MakeTx(x, 1, 400);
    Plan plan = PlanFor(pool, same, nOldFee, One(ha), kRoomy);
    BOOST_CHECK(!plan.fOk);
    BOOST_CHECK(plan.strReason.find("fee rate") != std::string::npos);

    // A smaller tx at a far higher rate that pays less in total.
    CTransaction small = MakeTx(x, 1);
    BOOST_REQUIRE(MempoolFeeRate(nOldFee, Size(small)) > MempoolFeeRate(nOldFee, Size(a)));
    plan = PlanFor(pool, small, nOldFee, One(ha), kRoomy);
    BOOST_CHECK(!plan.fOk);
    BOOST_CHECK(plan.strReason.find("does not cover") != std::string::npos);

    // One satoshi short of the incremental fee.
    const int64_t nNeeded = nOldFee + MempoolIncrementalFee(Size(small));
    plan = PlanFor(pool, small, nNeeded - 1, One(ha), kRoomy);
    BOOST_CHECK(!plan.fOk);

    plan = PlanFor(pool, small, nNeeded, One(ha), kRoomy);
    BOOST_CHECK_MESSAGE(plan.fOk, plan.strReason);
    BOOST_CHECK(plan.setReplaced == One(ha));
    BOOST_CHECK(plan.setEvicted.empty());

    // Replacement switched off.
    plan = PlanFor(pool, small, nNeeded * 10, One(ha), kRoomy, false);
    BOOST_CHECK(!plan.fOk);
}

BOOST_AUTO_TEST_CASE(a_replacement_pays_for_the_descendants_it_removes)
{
    CTxMemPool pool;
    const COutPoint x = FreshOutPoint();
    CTransaction a = MakeTx(x, 1);
    const uint256 ha = Add(pool, a, 1000);
    const uint256 hb = Add(pool, MakeTx(COutPoint(ha, 0)), 5000);

    CTransaction n = MakeTx(x, 1, 1);
    Plan plan = PlanFor(pool, n, 3000, One(ha), kRoomy);
    BOOST_CHECK(!plan.fOk);
    BOOST_CHECK(plan.strReason.find("does not cover") != std::string::npos);

    plan = PlanFor(pool, n, 6000 + MempoolIncrementalFee(Size(n)), One(ha), kRoomy);
    BOOST_CHECK_MESSAGE(plan.fOk, plan.strReason);
    BOOST_CHECK_EQUAL(plan.setReplaced.size(), 2U);
    BOOST_CHECK(plan.setReplaced.count(ha) && plan.setReplaced.count(hb));
}

BOOST_AUTO_TEST_CASE(replacement_refuses_protected_or_oversized_sets)
{
    const int64_t nBig = 50 * COIN;

    // A conflict that was admitted as non-replaceable, or with an unknown fee.
    {
        CTxMemPool pool;
        const COutPoint x = FreshOutPoint();
        const uint256 ha = Add(pool, MakeTx(x), 1000, false);
        Plan plan = PlanFor(pool, MakeTx(x, 1, 1), nBig, One(ha), kRoomy);
        BOOST_CHECK(!plan.fOk);
        BOOST_CHECK(plan.strReason.find("not replaceable") != std::string::npos);

        const COutPoint y = FreshOutPoint();
        const uint256 hu = Add(pool, MakeTx(y), -1, true);
        BOOST_CHECK(!PlanFor(pool, MakeTx(y, 1, 1), nBig, One(hu), kRoomy).fOk);
    }

    // A protected descendant.
    {
        CTxMemPool pool;
        const COutPoint x = FreshOutPoint();
        const uint256 ha = Add(pool, MakeTx(x), 1000);
        Add(pool, MakeTx(COutPoint(ha, 0)), 1000, false);
        Plan plan = PlanFor(pool, MakeTx(x, 1, 1), nBig, One(ha), kRoomy);
        BOOST_CHECK(!plan.fOk);
        BOOST_CHECK(plan.strReason.find("descendant") != std::string::npos);
    }

    // The candidate cap counts descendants.
    {
        CTxMemPool pool;
        const COutPoint x = FreshOutPoint();
        const uint256 ha = Add(pool, MakeTx(x, MAX_REPLACEMENT_CANDIDATES + 1), 1000);
        for (unsigned int i = 0; i < MAX_REPLACEMENT_CANDIDATES - 1; i++)
            Add(pool, MakeTx(COutPoint(ha, i)), 1000);
        Plan plan = PlanFor(pool, MakeTx(x, 1, 1), nBig, One(ha), kRoomy);
        BOOST_CHECK_MESSAGE(plan.fOk, plan.strReason);
        BOOST_CHECK_EQUAL(plan.setReplaced.size(), MAX_REPLACEMENT_CANDIDATES);

        Add(pool, MakeTx(COutPoint(ha, MAX_REPLACEMENT_CANDIDATES - 1)), 1000);
        plan = PlanFor(pool, MakeTx(x, 1, 1), nBig, One(ha), kRoomy);
        BOOST_CHECK(!plan.fOk);
        BOOST_CHECK(plan.strReason.find("more than") != std::string::npos);
    }

    // Spending what it replaces, or adding an unconfirmed parent.
    {
        CTxMemPool pool;
        const COutPoint x = FreshOutPoint();
        const uint256 hp = Add(pool, MakeTx(FreshOutPoint(), 2), 1000);
        std::vector<COutPoint> vA;
        vA.push_back(x);
        vA.push_back(COutPoint(hp, 1));
        const uint256 ha = Add(pool, MakeTx(vA, 2), 1000);

        std::vector<COutPoint> vSelf;
        vSelf.push_back(x);
        vSelf.push_back(COutPoint(ha, 0));
        Plan plan = PlanFor(pool, MakeTx(vSelf, 1), nBig, One(ha), kRoomy);
        BOOST_CHECK(!plan.fOk);
        BOOST_CHECK(plan.strReason.find("spends an output") != std::string::npos);

        const uint256 hq = Add(pool, MakeTx(FreshOutPoint(), 1), 1000);
        std::vector<COutPoint> vNew;
        vNew.push_back(x);
        vNew.push_back(COutPoint(hq, 0));
        plan = PlanFor(pool, MakeTx(vNew, 1), nBig, One(ha), kRoomy);
        BOOST_CHECK(!plan.fOk);
        BOOST_CHECK(plan.strReason.find("unconfirmed input") != std::string::npos);

        // A parent the replaced tx already spent is allowed.
        std::vector<COutPoint> vKept;
        vKept.push_back(x);
        vKept.push_back(COutPoint(hp, 0));
        plan = PlanFor(pool, MakeTx(vKept, 1), nBig, One(ha), kRoomy);
        BOOST_CHECK_MESSAGE(plan.fOk, plan.strReason);
    }
}

BOOST_AUTO_TEST_CASE(a_full_pool_evicts_only_cheaper_transactions)
{
    CTxMemPool pool;
    CTransaction lo = MakeTx(FreshOutPoint(), 1, 600);
    CTransaction hi = MakeTx(FreshOutPoint(), 1, 600);
    const uint256 hlo = Add(pool, lo, FeeAt(2000, lo));
    const uint256 hhi = Add(pool, hi, FeeAt(50000, hi));
    const size_t nLimit = pool.GetTotalMemoryUsage();

    CTransaction n = MakeTx(FreshOutPoint(), 1, 100);
    BOOST_REQUIRE(Size(n) <= Size(lo));

    Plan plan = PlanFor(pool, n, FeeAt(10000, n), std::set<uint256>(), nLimit);
    BOOST_CHECK_MESSAGE(plan.fOk, plan.strReason);
    BOOST_CHECK(plan.setEvicted == One(hlo));
    BOOST_CHECK_EQUAL(plan.nEvictedRate, MempoolFeeRate(FeeAt(2000, lo), Size(lo)));

    // Never to admit a lower or equal rate.
    plan = PlanFor(pool, n, FeeAt(1000, n), std::set<uint256>(), nLimit);
    BOOST_CHECK(!plan.fOk);
    BOOST_CHECK(plan.setEvicted.empty());
    BOOST_CHECK(plan.strReason.find("mempool full") != std::string::npos);
    const int64_t nLoRate = MempoolFeeRate(FeeAt(2000, lo), Size(lo));
    plan = PlanFor(pool, n, nLoRate * Size(n) / 1000, std::set<uint256>(), nLimit);
    BOOST_CHECK(!plan.fOk);

    // A parent of the incoming tx stays.
    CTransaction child = MakeTx(COutPoint(hlo, 0), 1, 100);
    plan = PlanFor(pool, child, FeeAt(10000, child), std::set<uint256>(), nLimit);
    BOOST_CHECK(!plan.fOk);

    // Room is planned all or nothing.
    CTransaction huge = MakeTx(FreshOutPoint(), 1, 3000);
    plan = PlanFor(pool, huge, FeeAt(10000, huge), std::set<uint256>(), nLimit);
    BOOST_CHECK(!plan.fOk);
    BOOST_CHECK(plan.setEvicted.empty());

    // Under the limit nothing is evicted.
    plan = PlanFor(pool, n, FeeAt(1000, n), std::set<uint256>(), kRoomy);
    BOOST_CHECK(plan.fOk);
    BOOST_CHECK(plan.setEvicted.empty());
    BOOST_CHECK(pool.exists(hhi));
}

BOOST_AUTO_TEST_CASE(eviction_takes_descendants_and_spares_protected_entries)
{
    // A cheap parent goes with its child.
    {
        CTxMemPool pool;
        CTransaction p = MakeTx(FreshOutPoint(), 1, 600);
        const uint256 hp = Add(pool, p, FeeAt(1000, p));
        CTransaction c = MakeTx(COutPoint(hp, 0), 1);
        const uint256 hc = Add(pool, c, FeeAt(3000, c));
        const size_t nLimit = pool.GetTotalMemoryUsage();
        CTransaction n = MakeTx(FreshOutPoint(), 1, 100);
        Plan plan = PlanFor(pool, n, FeeAt(20000, n), std::set<uint256>(), nLimit);
        BOOST_CHECK_MESSAGE(plan.fOk, plan.strReason);
        BOOST_CHECK(plan.setEvicted.count(hp) && plan.setEvicted.count(hc));
    }

    // A child paying for its parent lifts the package above the incoming rate.
    {
        CTxMemPool pool;
        CTransaction p = MakeTx(FreshOutPoint(), 1, 600);
        const uint256 hp = Add(pool, p, FeeAt(1000, p));
        CTransaction c = MakeTx(COutPoint(hp, 0), 1);
        Add(pool, c, 10 * COIN);
        const size_t nLimit = pool.GetTotalMemoryUsage();
        CTransaction n = MakeTx(FreshOutPoint(), 1, 100);
        Plan plan = PlanFor(pool, n, FeeAt(20000, n), std::set<uint256>(), nLimit);
        BOOST_CHECK(!plan.fOk);
    }

    // A protected entry is never evicted, however cheap.
    {
        CTxMemPool pool;
        CTransaction v = MakeTx(FreshOutPoint(), 1, 600);
        Add(pool, v, 0, false);
        const size_t nLimit = pool.GetTotalMemoryUsage();
        CTransaction n = MakeTx(FreshOutPoint(), 1, 100);
        BOOST_CHECK(!PlanFor(pool, n, 10 * COIN, std::set<uint256>(), nLimit).fOk);
    }

    // Space freed by a replacement counts before anything is evicted.
    {
        CTxMemPool pool;
        const COutPoint x = FreshOutPoint();
        CTransaction a = MakeTx(x, 1, 600);
        const uint256 ha = Add(pool, a, FeeAt(1000, a));
        CTransaction cheap = MakeTx(FreshOutPoint(), 1, 600);
        const uint256 hcheap = Add(pool, cheap, FeeAt(1000, cheap));
        const size_t nLimit = pool.GetTotalMemoryUsage();
        CTransaction n = MakeTx(x, 1, 100);
        Plan plan = PlanFor(pool, n, FeeAt(1000, a) + FeeAt(20000, n), One(ha), nLimit);
        BOOST_CHECK_MESSAGE(plan.fOk, plan.strReason);
        BOOST_CHECK(plan.setReplaced == One(ha));
        BOOST_CHECK(plan.setEvicted.empty());
        BOOST_CHECK(pool.exists(hcheap));
    }
}

BOOST_AUTO_TEST_CASE(removal_releases_every_index_including_iv5)
{
    CTxMemPool pool;
    const COutPoint x = FreshOutPoint();
    CTransaction a = MakeTx(x, 1);
    const uint256 ha = Add(pool, a, 1000);
    const uint256 hb = Add(pool, MakeTx(COutPoint(ha, 0)), 1000);

    CTransaction iv5 = MakeTx(std::vector<COutPoint>(), 1);
    iv5.nVersion = SHIELDED_TX_VERSION_DSP;
    BOOST_REQUIRE(iv5.IsPrivacyVNext());
    const uint256 hiv5 = Add(pool, iv5, 1000);
    const uint256 keyImage(0xabcdef);
    {
        LOCK(pool.cs);
        CShieldedNullifierSpent spent;
        spent.txnHash = hiv5;
        spent.nIndex = 0;
        pool.mapPrivacyVNextNullifier[keyImage] = spent;
        pool.mapPrivacyVNextTxNullifiers[hiv5] = std::vector<uint256>(1, keyImage);
        pool.mapPrivacyVNextTxAttestations[hiv5] = std::vector<uint256>();
    }

    std::set<uint256> setConflicts;
    setConflicts.insert(ha);
    setConflicts.insert(hiv5);
    CTransaction n = MakeTx(x, 1, 1);
    Plan plan = PlanFor(pool, n, 10 * COIN, setConflicts, kRoomy);
    BOOST_REQUIRE_MESSAGE(plan.fOk, plan.strReason);
    BOOST_CHECK_EQUAL(plan.setReplaced.size(), 3U);

    const bool fShutdownBefore = fRequestShutdown;
    pool.RemoveSet(plan.setReplaced);
    BOOST_CHECK_EQUAL(fRequestShutdown, fShutdownBefore);
    BOOST_CHECK_EQUAL(pool.size(), 0U);
    BOOST_CHECK(pool.mapNextTx.empty());
    BOOST_CHECK(pool.mapTxFeeInfo.empty());
    BOOST_CHECK(pool.mapPrivacyVNextNullifier.empty());
    BOOST_CHECK(pool.mapPrivacyVNextTxNullifiers.empty());
    BOOST_CHECK(pool.mapPrivacyVNextTxAttestations.empty());
    BOOST_CHECK_EQUAL(pool.GetTotalMemoryUsage(), 0U);
    BOOST_CHECK(!pool.exists(hb));
}

BOOST_AUTO_TEST_CASE(the_rolling_minimum_rises_on_eviction_and_decays)
{
    const int64_t nStart = 1800000000;
    SetMockTime(nStart);
    CTxMemPool pool;
    pool.clear();
    const size_t nLimit = 1000000;
    BOOST_CHECK_EQUAL(pool.GetRollingMinFeeRate(nLimit), 0);

    pool.TrackEviction(7000);
    BOOST_CHECK_EQUAL(pool.GetRollingMinFeeRate(nLimit), 7000 + MEMPOOL_INCREMENTAL_RELAY_FEE);
    SetMockTime(nStart + 5);
    BOOST_CHECK_EQUAL(pool.GetRollingMinFeeRate(nLimit), 7000 + MEMPOOL_INCREMENTAL_RELAY_FEE);

    // An empty pool decays on a quarter of the half-life.
    SetMockTime(nStart + MEMPOOL_ROLLING_FEE_HALFLIFE / 4);
    BOOST_CHECK_EQUAL(pool.GetRollingMinFeeRate(nLimit), (7000 + MEMPOOL_INCREMENTAL_RELAY_FEE) / 2);

    // A lower eviction does not pull it down.
    pool.TrackEviction(100);
    BOOST_CHECK_EQUAL(pool.GetRollingMinFeeRate(nLimit), (7000 + MEMPOOL_INCREMENTAL_RELAY_FEE) / 2);

    SetMockTime(nStart + 4 * MEMPOOL_ROLLING_FEE_HALFLIFE);
    BOOST_CHECK_EQUAL(pool.GetRollingMinFeeRate(nLimit), 0);

    pool.TrackEviction(7000);
    pool.clear();
    BOOST_CHECK_EQUAL(pool.GetRollingMinFeeRate(nLimit), 0);
    SetMockTime(0);
}

namespace {

struct ArgGuard
{
    std::string strName;
    bool fHad;
    std::string strOld;
    explicit ArgGuard(const std::string& name) : strName(name)
    {
        fHad = mapArgs.count(name) != 0;
        if (fHad)
            strOld = mapArgs[name];
    }
    ~ArgGuard()
    {
        if (fHad)
            mapArgs[strName] = strOld;
        else
            mapArgs.erase(strName);
    }
};

// The unit binary leaves the name hooks null; accept() calls them.
struct NameHooksGuard
{
    NameHooksGuard()
    {
        if (!hooks)
            hooks = InitHook();
    }
};

struct Wallet
{
    CKey key;
    CBasicKeyStore keystore;
    CScript script;
    CTransaction parent;
    uint256 hashParent;

    Wallet()
    {
        key.MakeNewKey(true);
        keystore.AddKey(key);
        script.SetDestination(key.GetPubKey().GetID());
        parent.nTime = GetAdjustedTime() - 600;
        parent.vin.push_back(CTxIn(FreshOutPoint()));
        for (int i = 0; i < 4; i++)
            parent.vout.push_back(CTxOut(10 * COIN, script));
        hashParent = parent.GetHash();
        LOCK(mempool.cs);
        mempool.addUnchecked(hashParent, parent);
    }

    // Spends parent:n, paying nFee; nTag varies the txid at equal size.
    CTransaction Spend(unsigned int n, int64_t nFee, unsigned int nTag = 0)
    {
        CTransaction tx;
        tx.nTime = parent.nTime + 1 + nTag;
        tx.vin.push_back(CTxIn(COutPoint(hashParent, n)));
        tx.vout.push_back(CTxOut(10 * COIN - nFee, script));
        BOOST_REQUIRE(SignSignature(keystore, parent, tx, 0));
        return tx;
    }

    CTransaction SpendChild(const CTransaction& from, int64_t nFee)
    {
        CTransaction tx;
        tx.nTime = from.nTime + 1;
        tx.vin.push_back(CTxIn(COutPoint(from.GetHash(), 0)));
        tx.vout.push_back(CTxOut(from.vout[0].nValue - nFee, script));
        BOOST_REQUIRE(SignSignature(keystore, from, tx, 0));
        return tx;
    }
};

bool Accept(CTransaction tx)
{
    LOCK(cs_main);
    CTxDB txdb("r");
    bool fMissing = false;
    return mempool.accept(txdb, tx, true, &fMissing);
}

} // namespace

BOOST_AUTO_TEST_CASE(accept_replaces_a_transparent_spend)
{
    NameHooksGuard hooksGuard;
    ArgGuard guard("-mempoolreplacement");
    mapArgs.erase("-mempoolreplacement");
    mempool.clear();
    Wallet w;

    CTransaction a = w.Spend(0, 2000);
    BOOST_REQUIRE(Accept(a));
    BOOST_CHECK(mempool.exists(a.GetHash()));
    BOOST_CHECK_EQUAL(mempool.mapTxFeeInfo[a.GetHash()].nFee, 2000);
    BOOST_CHECK(mempool.mapTxFeeInfo[a.GetHash()].fReplaceable);

    // Equal fee at equal size is not a replacement.
    CTransaction same = w.Spend(0, 2000, 1);
    BOOST_CHECK(!Accept(same));
    BOOST_CHECK(mempool.exists(a.GetHash()));

    CTransaction b = w.Spend(0, 2000 + 1000, 2);
    BOOST_REQUIRE(Accept(b));
    BOOST_CHECK(!mempool.exists(a.GetHash()));
    BOOST_CHECK(mempool.exists(b.GetHash()));
    BOOST_CHECK_EQUAL(mempool.mapTxFeeInfo.count(a.GetHash()), 0U);
    {
        LOCK(mempool.cs);
        std::map<COutPoint, CInPoint>::const_iterator it =
            mempool.mapNextTx.find(COutPoint(w.hashParent, 0));
        BOOST_REQUIRE(it != mempool.mapNextTx.end());
        BOOST_CHECK(it->second.ptx->GetHash() == b.GetHash());
    }

    // A chain is replaced whole, and only when its fees are covered.
    CTransaction a2 = w.Spend(1, 2000);
    BOOST_REQUIRE(Accept(a2));
    CTransaction a2c = w.SpendChild(a2, 2000);
    BOOST_REQUIRE(Accept(a2c));
    BOOST_CHECK(!Accept(w.Spend(1, 3000, 1)));
    BOOST_CHECK(mempool.exists(a2.GetHash()) && mempool.exists(a2c.GetHash()));
    CTransaction r = w.Spend(1, 6000, 2);
    BOOST_REQUIRE(Accept(r));
    BOOST_CHECK(!mempool.exists(a2.GetHash()));
    BOOST_CHECK(!mempool.exists(a2c.GetHash()));
    BOOST_CHECK(mempool.exists(r.GetHash()));

    // Switched off, the first spend stays.
    mapArgs["-mempoolreplacement"] = "0";
    CTransaction x = w.Spend(2, 2000);
    BOOST_REQUIRE(Accept(x));
    BOOST_CHECK(!Accept(w.Spend(2, 9000, 1)));
    BOOST_CHECK(mempool.exists(x.GetHash()));

    size_t nExpected = 0;
    {
        LOCK(mempool.cs);
        for (std::map<uint256, CTransaction>::const_iterator it = mempool.mapTx.begin();
             it != mempool.mapTx.end(); ++it)
            nExpected += Size(it->second);
    }
    BOOST_CHECK_EQUAL(mempool.GetTotalMemoryUsage(), nExpected);
    mempool.clear();
}

BOOST_AUTO_TEST_CASE(accept_enforces_the_rolling_minimum)
{
    NameHooksGuard hooksGuard;
    const int64_t nNow = GetTime();
    SetMockTime(nNow);
    mempool.clear();
    Wallet w;

    mempool.TrackEviction(100000);
    BOOST_CHECK(!Accept(w.Spend(0, 2000)));
    CTransaction rich = w.Spend(1, 200000);
    BOOST_CHECK(Accept(rich));

    // Two days on, with the pool nearly empty, the floor is gone.
    SetMockTime(nNow + 2 * 24 * 60 * 60);
    CTransaction later = w.Spend(0, 2000, 1);
    later.nTime = GetAdjustedTime() - 1;
    BOOST_REQUIRE(SignSignature(w.keystore, w.parent, later, 0));
    BOOST_CHECK(Accept(later));

    mempool.clear();
    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()
