// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Fee-exempt migration: window, shape, decoded effects, input rule, mempool sub-cap.

#include <boost/test/unit_test.hpp>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../main.h"
#include "../privacy_vnext/iv5_protocol.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../wallet.h"
#include "../key.h"

#include <cstring>
#include <limits>
#include <vector>

extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(migration_exempt_tests)

namespace {

struct MigrationHeight
{
    int nOld;
    explicit MigrationHeight(int nHeight) : nOld(::nRegtestMigrationHeight)
    {
        ::nRegtestMigrationHeight = nHeight;
    }
    ~MigrationHeight() { ::nRegtestMigrationHeight = nOld; }
};

PrivacyVNextDigest FillDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

std::vector<unsigned char> HeaderOnly(uint8_t nOperation)
{
    std::vector<unsigned char> v(64, 0);
    v[0] = (unsigned char)(iv5::PROTOCOL_SCHEMA & 0xff);
    v[1] = (unsigned char)(iv5::PROTOCOL_SCHEMA >> 8);
    v[2] = nOperation;
    v[5] = 7;
    return v;
}

CTransaction Carrier(const std::vector<unsigned char>& payload, unsigned int nInputs)
{
    CTransaction tx;
    tx.nVersion = INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION;
    tx.nTime = 1500000000;
    tx.privacyVNext.vchPayload = payload;
    for (unsigned int i = 0; i < nInputs; ++i)
        tx.vin.push_back(CTxIn(COutPoint(uint256(i + 1), 0)));
    return tx;
}

bool BuildShield(uint64_t nIn, uint64_t nFee, unsigned int nOutputs,
                 std::vector<unsigned char>& payload, std::string& error)
{
    PrivacyVNextDigest genesis;
    PrivacyVNextLocalGenesis(genesis.data());
    const uint8_t nNetwork = PrivacyVNextLocalNetworkId();
    PrivacyVNextDerivedKeys owner;
    if (!DerivePrivacyVNextKeys(FillDigest(0x5a), genesis, 0, nNetwork, 0, owner, error))
        return false;
    PrivacyVNextEpochSeed seed;
    if (!LoadPrivacyVNextEpochSeed(seed, error))
        return false;
    std::vector<unsigned char> vchRoot;
    uint64_t nTreeSize = 0;
    if (!DecodePrivacyVNextTreeState(seed.vchTreeState, vchRoot, nTreeSize, error) ||
        vchRoot.size() < 32)
        return false;
    PrivacyVNextDigest root;
    std::memcpy(root.data(), &vchRoot[0], 32);

    std::vector<PrivacyVNextNewOutput> vOut(nOutputs);
    const uint64_t nEach = (nIn - nFee) / nOutputs;
    for (unsigned int i = 0; i < nOutputs; ++i)
    {
        vOut[i].recipient.nNetwork = nNetwork;
        vOut[i].recipient.nAddressType = 0;
        vOut[i].recipient.spendPublic = owner.spendPublic;
        vOut[i].recipient.viewPublic = owner.viewPublic;
        vOut[i].nAmount = nEach;
    }
    vOut[0].nAmount += (nIn - nFee) - nEach * nOutputs;
    return BuildPrivacyVNextShieldPayload(nNetwork, 7, genesis, owner.outgoingViewSecret,
                                          root, nTreeSize, FillDigest(0x11), nIn, nFee,
                                          vOut, payload, error);
}

} // namespace

BOOST_AUTO_TEST_CASE(window_is_one_year_from_the_fork)
{
    {
        MigrationHeight unset(PRIVACY_VNEXT_HEIGHT_UNSET);
        BOOST_CHECK(!IsMigrationConfigured());
        BOOST_CHECK(!IsMigrationActiveAtHeight(1000));
        BOOST_CHECK(!IsMigrationActiveAtHeight(std::numeric_limits<int>::max()));
    }
    MigrationHeight set(1000);
    BOOST_CHECK(IsMigrationConfigured());
    BOOST_CHECK_EQUAL(GetMigrationSnapshotHeight(), 999);
    BOOST_CHECK_EQUAL(GetMigrationEndHeight(), 1000 + 31536000);
    BOOST_CHECK(!IsMigrationActiveAtHeight(999));
    BOOST_CHECK(IsMigrationActiveAtHeight(1000));
    BOOST_CHECK(IsMigrationActiveAtHeight(1000 + 31536000 - 1));
    BOOST_CHECK(!IsMigrationActiveAtHeight(1000 + 31536000));

    MigrationHeight high(PRIVACY_VNEXT_HEIGHT_UNSET - 10);
    BOOST_CHECK_EQUAL(GetMigrationEndHeight(), PRIVACY_VNEXT_HEIGHT_UNSET);
}

BOOST_AUTO_TEST_CASE(mainnet_height_is_pinned)
{
    BOOST_CHECK_EQUAL(MAINNET_MIGRATION_HEIGHT, 8547840);
    BOOST_CHECK_EQUAL(MAINNET_MIGRATION_HEIGHT, MAINNET_MERGESET_HEIGHT);
    BOOST_CHECK_EQUAL(MIGRATION_MAX_PER_BLOCK, 4u);
    BOOST_CHECK_EQUAL(MIGRATION_MAX_INPUTS, 50u);
    BOOST_CHECK_EQUAL(MIGRATION_DURATION, 31536000);
}

BOOST_AUTO_TEST_CASE(header_shape)
{
    const std::vector<unsigned char> shield = HeaderOnly(iv5::NOTE_SHIELD);
    BOOST_CHECK(IsMigrationShape(Carrier(shield, 1)));
    BOOST_CHECK(IsMigrationShape(Carrier(shield, MIGRATION_MAX_INPUTS)));
    BOOST_CHECK(!IsMigrationShape(Carrier(shield, 0)));
    BOOST_CHECK(!IsMigrationShape(Carrier(shield, MIGRATION_MAX_INPUTS + 1)));
    BOOST_CHECK(!IsMigrationShape(Carrier(HeaderOnly(iv5::NOTE_TRANSFER), 1)));
    BOOST_CHECK(!IsMigrationShape(Carrier(HeaderOnly(iv5::NOTE_FINALITY_VOTE), 1)));

    CTransaction withOut = Carrier(shield, 1);
    withOut.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
    BOOST_CHECK(!IsMigrationShape(withOut));

    CTransaction transparent = Carrier(std::vector<unsigned char>(), 1);
    transparent.nVersion = 1;
    BOOST_CHECK(!IsMigrationShape(transparent));

    // The attestation exemption stays as it was.
    BOOST_CHECK(!IsPrivacyVNextFeeExemptShape(Carrier(shield, 1)));
}

BOOST_AUTO_TEST_CASE(decoded_effects)
{
    std::string error;
    std::vector<unsigned char> one, two, paid;
    BOOST_REQUIRE_MESSAGE(BuildShield(50000, 0, 1, one, error), error);
    BOOST_REQUIRE_MESSAGE(BuildShield(50000, 0, 2, two, error), error);
    BOOST_REQUIRE_MESSAGE(BuildShield(50000, 100, 1, paid, error), error);

    std::string reason;
    BOOST_CHECK_MESSAGE(CheckMigrationEffects(Carrier(one, 1), reason), reason);
    BOOST_CHECK(!CheckMigrationEffects(Carrier(two, 1), reason));
    BOOST_CHECK(!CheckMigrationEffects(Carrier(paid, 1), reason));
    BOOST_CHECK(!CheckMigrationEffects(Carrier(one, 0), reason));
}

BOOST_AUTO_TEST_CASE(exemption_gates)
{
    std::string error;
    std::vector<unsigned char> one;
    BOOST_REQUIRE_MESSAGE(BuildShield(50000, 0, 1, one, error), error);
    const CTransaction tx = Carrier(one, 1);

    CTransaction prev;
    prev.vout.push_back(CTxOut(50000, CScript() << OP_TRUE));
    MapPrevTx inputs;
    inputs[tx.vin[0].prevout.hash] =
        std::make_pair(CTxIndex(CDiskTxPos(1,1,1), prev.vout.size()), prev);

    MigrationHeight set(1000);
    std::string reason;
    BOOST_CHECK(!IsFeeExemptMigration(tx, 999, 0, inputs, NULL, &reason));
    BOOST_CHECK_EQUAL(reason, "migration window closed");
    BOOST_CHECK(!IsFeeExemptMigration(tx, 1000 + MIGRATION_DURATION, 0, inputs, NULL, &reason));
    BOOST_CHECK(!IsFeeExemptMigration(tx, 1000, 1, inputs, NULL, &reason));
    BOOST_CHECK_EQUAL(reason, "migration fee is not zero");
    // A mempool parent is never eligible.
    BOOST_CHECK(!IsFeeExemptMigration(tx, 1000, 0, inputs, pindexBest, &reason));
    BOOST_CHECK_EQUAL(reason, "input not confirmed at or below the snapshot height");
    MapPrevTx missing;
    BOOST_CHECK(!IsFeeExemptMigration(tx, 1000, 0, missing, pindexBest, &reason));
    BOOST_CHECK_EQUAL(reason, "missing input");
}

BOOST_AUTO_TEST_CASE(mempool_subcap_is_fifo)
{
    CTxMemPool pool;
    std::vector<uint256> vHashes;
    for (unsigned int i = 0; i < MIGRATION_MEMPOOL_MAX_TXS + 3; ++i)
    {
        CTransaction tx;
        tx.nTime = 1500000000 + i;
        tx.vin.push_back(CTxIn(COutPoint(uint256(1000 + i), 0)));
        const uint256 hash = tx.GetHash();
        {
            LOCK(pool.cs);
            pool.addUnchecked(hash, tx, 0, true);
        }
        pool.TrackMigrationExempt(hash, 100);
        vHashes.push_back(hash);
    }
    BOOST_CHECK_EQUAL(pool.MigrationExemptCount(), MIGRATION_MEMPOOL_MAX_TXS);
    for (unsigned int i = 0; i < 3; ++i)
    {
        BOOST_CHECK(!pool.IsMigrationExempt(vHashes[i]));
        BOOST_CHECK(!pool.mapTx.count(vHashes[i]));
    }
    BOOST_CHECK(pool.IsMigrationExempt(vHashes.back()));

    // Removal by any path drops the record.
    {
        LOCK(pool.cs);
        const CTransaction txLast = pool.mapTx[vHashes.back()];
        pool.remove(txLast);
    }
    BOOST_CHECK(!pool.IsMigrationExempt(vHashes.back()));
    BOOST_CHECK_EQUAL(pool.MigrationExemptCount(), MIGRATION_MEMPOOL_MAX_TXS - 1);

    // Byte cap.
    CTxMemPool small;
    for (unsigned int i = 0; i < 3; ++i)
    {
        CTransaction tx;
        tx.nTime = 1600000000 + i;
        tx.vin.push_back(CTxIn(COutPoint(uint256(5000 + i), 0)));
        {
            LOCK(small.cs);
            small.addUnchecked(tx.GetHash(), tx, 0, true);
        }
        small.TrackMigrationExempt(tx.GetHash(), MIGRATION_MEMPOOL_MAX_BYTES / 2);
    }
    BOOST_CHECK_EQUAL(small.MigrationExemptCount(), 2u);
}

BOOST_AUTO_TEST_CASE(mempool_prunes_when_window_closes)
{
    MigrationHeight set(1000);
    CTxMemPool pool;
    std::vector<uint256> vHashes;
    for (unsigned int i = 0; i < 3; ++i)
    {
        CTransaction tx;
        tx.nTime = 1700000000 + i;
        tx.vin.push_back(CTxIn(COutPoint(uint256(9000 + i), 0)));
        {
            LOCK(pool.cs);
            pool.addUnchecked(tx.GetHash(), tx, 0, true);
        }
        pool.TrackMigrationExempt(tx.GetHash(), 100);
        vHashes.push_back(tx.GetHash());
    }
    pool.PruneMigrationExempt(1000);
    BOOST_CHECK_EQUAL(pool.MigrationExemptCount(), 3u);
    pool.PruneMigrationExempt(1000 + 31536000);
    BOOST_CHECK_EQUAL(pool.MigrationExemptCount(), 0u);
    for (unsigned int i = 0; i < 3; ++i)
        BOOST_CHECK(!pool.mapTx.count(vHashes[i]));
}

BOOST_AUTO_TEST_CASE(declares_zero_fee_without_proofs)
{
    std::string error;
    std::vector<unsigned char> one, paid;
    BOOST_REQUIRE_MESSAGE(BuildShield(50000, 0, 1, one, error), error);
    BOOST_REQUIRE_MESSAGE(BuildShield(50000, 100, 1, paid, error), error);
    const size_t nCache = PrivacyVNextEffectsCacheSize();
    BOOST_CHECK(MigrationDeclaresZeroFee(Carrier(one, 1)));
    // A fee-paying shield of migration shape is not rate limited or pre-checked.
    BOOST_CHECK(IsMigrationShape(Carrier(paid, 1)));
    BOOST_CHECK(!MigrationDeclaresZeroFee(Carrier(paid, 1)));
    BOOST_CHECK(!MigrationDeclaresZeroFee(Carrier(HeaderOnly(iv5::NOTE_SHIELD), 1)));
    BOOST_CHECK(!MigrationDeclaresZeroFee(Carrier(one, MIGRATION_MAX_INPUTS + 1)));
    BOOST_CHECK_EQUAL(PrivacyVNextEffectsCacheSize(), nCache);
}

BOOST_AUTO_TEST_CASE(reorg_prunes_ineligible)
{
    MigrationHeight set(1000);
    CTransaction tx;
    tx.nTime = 1700000100;
    tx.vin.push_back(CTxIn(COutPoint(uint256(9100), 0)));
    {
        LOCK2(cs_main, mempool.cs);
        mempool.addUnchecked(tx.GetHash(), tx, 0, true);
    }
    mempool.TrackMigrationExempt(tx.GetHash(), 100);
    BOOST_CHECK(mempool.IsMigrationExempt(tx.GetHash()));
    {
        LOCK(cs_main);
        PruneIneligibleMigrationExempt();
    }
    BOOST_CHECK(!mempool.IsMigrationExempt(tx.GetHash()));
    BOOST_CHECK(!mempool.exists(tx.GetHash()));
}

BOOST_AUTO_TEST_CASE(wallet_free_coin_rule)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    CScript p2pkh;
    p2pkh.SetDestination(pub.GetID());
    CScript p2pk;
    p2pk << pub.Raw() << OP_CHECKSIG;
    CScript bare;
    bare << OP_RETURN;

    MigrationHeight set(1000);
    // Window open at the next block; snapshot is 999.
    BOOST_CHECK(PoolMigrationCoinIsFree(p2pkh, 999, 1000));
    BOOST_CHECK(PoolMigrationCoinIsFree(p2pk, 1, 1000));
    BOOST_CHECK(!PoolMigrationCoinIsFree(p2pkh, 1000, 1001));
    BOOST_CHECK(!PoolMigrationCoinIsFree(p2pkh, 0, 1000));
    BOOST_CHECK(!PoolMigrationCoinIsFree(p2pkh, 500, 999));
    BOOST_CHECK(!PoolMigrationCoinIsFree(p2pkh, 500, 1000 + MIGRATION_DURATION));
    const int nLastFree = 1000 + MIGRATION_DURATION - MIGRATION_WALLET_END_MARGIN - 1;
    BOOST_CHECK(PoolMigrationCoinIsFree(p2pkh, 500, nLastFree));
    BOOST_CHECK(!PoolMigrationCoinIsFree(p2pkh, 500, nLastFree + 1));
    BOOST_CHECK(!PoolMigrationCoinIsFree(bare, 500, 1000));

    MigrationHeight unset(PRIVACY_VNEXT_HEIGHT_UNSET);
    BOOST_CHECK(!PoolMigrationCoinIsFree(p2pkh, 500, 1000));
}

BOOST_AUTO_TEST_CASE(wallet_free_relay_budget)
{
    CMigrationRelayBudget budget;
    BOOST_CHECK_EQUAL(budget.RetryAfter(1000), 0);
    budget.Record(1000);
    BOOST_CHECK_EQUAL(budget.RetryAfter(1010), 0);
    budget.Record(1010);
    BOOST_CHECK_EQUAL(MIGRATION_RELAY_PER_MINUTE, 2u);
    BOOST_CHECK_EQUAL(budget.RetryAfter(1020), 40);
    BOOST_CHECK_EQUAL(budget.RetryAfter(1059), 1);
    BOOST_CHECK_EQUAL(budget.RetryAfter(1060), 0);
    budget.Record(1060);
    BOOST_CHECK_EQUAL(budget.RetryAfter(1065), 5);
    // A clock step back does not wedge the budget.
    BOOST_CHECK_EQUAL(budget.RetryAfter(900), 0);
}

BOOST_AUTO_TEST_SUITE_END()
