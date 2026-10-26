// Pool-migration grouping: every output an address's key owns is swept with that address.

#include <boost/test/unit_test.hpp>

#include "../key.h"
#include "../script.h"
#include "../wallet.h"

#include <map>
#include <utility>
#include <vector>

BOOST_AUTO_TEST_SUITE(pool_migration_tests)

namespace {

CPubKey NewPubKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key.GetPubKey();
}

CScript P2PKH(const CPubKey& pubkey)
{
    CScript script;
    script.SetDestination(pubkey.GetID());
    return script;
}

CScript P2PK(const CPubKey& pubkey)
{
    CScript script;
    script << pubkey << OP_CHECKSIG;
    return script;
}

} // namespace

BOOST_AUTO_TEST_CASE(owner_script_of_each_output_type)
{
    const CPubKey pubkey = NewPubKey();
    CScript owner;

    BOOST_CHECK(PoolMigrationOwnerScript(P2PKH(pubkey), owner));
    BOOST_CHECK(owner == P2PKH(pubkey));

    BOOST_CHECK(PoolMigrationOwnerScript(P2PK(pubkey), owner));
    BOOST_CHECK(owner == P2PKH(pubkey));

    const CPubKey staker = NewPubKey();
    BOOST_CHECK(PoolMigrationOwnerScript(GetScriptForColdStaking(staker.GetID(), pubkey.GetID()),
                                         owner));
    BOOST_CHECK(owner == P2PKH(pubkey));

    CScript scriptData;
    scriptData << OP_RETURN << std::vector<unsigned char>(8, 0x42);
    BOOST_CHECK(!PoolMigrationOwnerScript(scriptData, owner));
    BOOST_CHECK(owner.empty());
}

BOOST_AUTO_TEST_CASE(stake_reward_groups_with_its_address)
{
    const CPubKey a = NewPubKey();
    const CPubKey b = NewPubKey();

    std::vector<std::pair<CScript, int64_t> > vOutputs;
    vOutputs.push_back(std::make_pair(P2PKH(a), 5 * COIN));
    vOutputs.push_back(std::make_pair(P2PK(a), 3 * COIN));
    vOutputs.push_back(std::make_pair(P2PK(b), 2 * COIN));
    CScript scriptData;
    scriptData << OP_RETURN << std::vector<unsigned char>(8, 0x42);
    vOutputs.push_back(std::make_pair(scriptData, 7));

    std::map<CScript, std::vector<int64_t> > mapByOwner;
    int64_t nUnaddressedOutputs = -1, nUnaddressedValue = -1;
    GroupPoolMigrationOutputs(vOutputs, mapByOwner, nUnaddressedOutputs, nUnaddressedValue);

    // One group per key, never one spanning two keys.
    BOOST_CHECK_EQUAL(mapByOwner.size(), 2U);
    BOOST_CHECK_EQUAL(mapByOwner[P2PKH(a)].size(), 2U);
    BOOST_CHECK_EQUAL(mapByOwner[P2PKH(a)][0] + mapByOwner[P2PKH(a)][1], 8 * COIN);
    BOOST_CHECK_EQUAL(mapByOwner[P2PKH(b)].size(), 1U);
    BOOST_CHECK_EQUAL(mapByOwner[P2PKH(b)][0], 2 * COIN);
    BOOST_CHECK_EQUAL(nUnaddressedOutputs, 1);
    BOOST_CHECK_EQUAL(nUnaddressedValue, 7);
}

BOOST_AUTO_TEST_SUITE_END()
