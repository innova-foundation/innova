#include <boost/test/unit_test.hpp>

#include <cstring>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../txdb.h"

namespace
{

PrivacyVNextOutputLeaf StoreTestLeaf(uint64_t nIndex)
{
    // Leaf tuples must be canonical curve points, so take them from key derivation
    // rather than filling bytes that would fail to decompress.
    PrivacyVNextOutputLeaf leaf;
    PrivacyVNextDigest seed;
    PrivacyVNextDigest genesis;
    for (size_t i = 0; i < 32; ++i)
    {
        seed[i] = static_cast<unsigned char>((nIndex + i) & 0xff);
        genesis[i] = 0x11;
    }
    PrivacyVNextDerivedKeys keys;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(seed, genesis, 0, 2, 0, keys, strError), strError);
    leaf.owner = keys.spendPublic;
    leaf.nullifierBase = keys.viewPublic;
    leaf.commitment = keys.spendPublic;
    return leaf;
}

std::vector<unsigned char> EmptyVNextTreeState()
{
    // Take the empty frontier from the canonical seed so this test never invents
    // consensus state of its own.
    std::vector<unsigned char> root;
    uint64_t nSize = 0;
    std::string strError;
    PrivacyVNextEpochSeed seed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(seed, strError), strError);
    const std::vector<unsigned char> state = seed.vchTreeState;
    BOOST_REQUIRE_EQUAL(state.size(),
                        (size_t)INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE);
    BOOST_REQUIRE(DecodePrivacyVNextTreeState(state, root, nSize, strError));
    BOOST_REQUIRE_EQUAL(nSize, 0U);
    return state;
}

// Test cases share one database, so each starts from an empty store.
void ResetStore(CTxDB& txdb, const std::vector<unsigned char>& emptyState)
{
    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        TrimPrivacyVNextTreeStore(txdb, 0, emptyState, strError), strError);
    uint64_t nStored = 1;
    BOOST_REQUIRE(ReadPrivacyVNextTreeStoreSize(txdb, nStored));
    BOOST_REQUIRE_EQUAL(nStored, 0U);
}

} // namespace

BOOST_AUTO_TEST_SUITE(privacy_vnext_store_tests)

// A witness read out of the store must equal the one a full leaf replay produces. If the
// two ever disagreed the store would hand a spender a path opening a root nobody holds.
BOOST_AUTO_TEST_CASE(stored_paths_reproduce_the_replayed_witness)
{
    CTxDB txdb("r+");
    std::string strError;

    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    for (uint64_t i = 0; i < 120; ++i)
        vLeaves.push_back(StoreTestLeaf(i));

    std::vector<unsigned char> state = EmptyVNextTreeState();
    ResetStore(txdb, state);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vLeaves, state, strError), strError);

    uint64_t nStored = 0;
    BOOST_REQUIRE(ReadPrivacyVNextTreeStoreSize(txdb, nStored));
    BOOST_CHECK_EQUAL(nStored, vLeaves.size());

    std::vector<uint64_t> vTargets;
    vTargets.push_back(0);
    vTargets.push_back(37);
    vTargets.push_back(38);
    vTargets.push_back(119);

    std::vector<unsigned char> vchPaths;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, nStored, state, vTargets, vchPaths,
                                  strError),
        strError);

    std::vector<PrivacyVNextMembershipWitness> vFromPaths;
    PrivacyVNextDigest rootFromPaths;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnessesFromPaths(state, vTargets, vchPaths,
                                            vFromPaths, rootFromPaths,
                                            strError),
        strError);

    std::vector<PrivacyVNextMembershipWitness> vFromLeaves;
    PrivacyVNextDigest rootFromLeaves;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnesses(state, vLeaves, vTargets, vFromLeaves,
                                   rootFromLeaves, strError),
        strError);

    BOOST_REQUIRE_EQUAL(vFromPaths.size(), vFromLeaves.size());
    BOOST_CHECK(rootFromPaths == rootFromLeaves);
    for (size_t i = 0; i < vFromPaths.size(); ++i)
    {
        BOOST_CHECK_EQUAL(vFromPaths[i].nLeafIndex, vFromLeaves[i].nLeafIndex);
        BOOST_CHECK(vFromPaths[i].vchRecord == vFromLeaves[i].vchRecord);
    }
}

// Rolling the store back must leave exactly the tree the shorter leaf set builds.
BOOST_AUTO_TEST_CASE(a_trimmed_store_matches_a_freshly_grown_one)
{
    CTxDB txdb("r+");
    std::string strError;

    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    for (uint64_t i = 0; i < 90; ++i)
        vLeaves.push_back(StoreTestLeaf(1000 + i));

    // Grow to the short size first and keep both the frontier and a reference witness.
    const size_t nShort = 45;
    const std::vector<PrivacyVNextOutputLeaf> vShort(vLeaves.begin(),
                                                     vLeaves.begin() + nShort);
    std::vector<unsigned char> shortState = EmptyVNextTreeState();
    ResetStore(txdb, shortState);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vShort, shortState, strError), strError);

    std::vector<uint64_t> vTargets;
    vTargets.push_back(0);
    vTargets.push_back(44);

    std::vector<unsigned char> vchShortPaths;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, nShort, shortState, vTargets,
                                  vchShortPaths, strError),
        strError);

    // Extend past it, then roll back to exactly where it was.
    std::vector<unsigned char> longState = shortState;
    const std::vector<PrivacyVNextOutputLeaf> vRest(vLeaves.begin() + nShort,
                                                    vLeaves.end());
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vRest, longState, strError), strError);
    BOOST_REQUIRE_MESSAGE(
        TrimPrivacyVNextTreeStore(txdb, nShort, shortState, strError), strError);

    uint64_t nStored = 0;
    BOOST_REQUIRE(ReadPrivacyVNextTreeStoreSize(txdb, nStored));
    BOOST_CHECK_EQUAL(nStored, (uint64_t)nShort);

    std::vector<unsigned char> vchTrimmedPaths;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, nShort, shortState, vTargets,
                                  vchTrimmedPaths, strError),
        strError);
    BOOST_CHECK(vchTrimmedPaths == vchShortPaths);

    // The restored store must still produce the witness the shorter tree defines.
    std::vector<PrivacyVNextMembershipWitness> vFromPaths;
    PrivacyVNextDigest rootFromPaths;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnessesFromPaths(shortState, vTargets,
                                            vchTrimmedPaths, vFromPaths,
                                            rootFromPaths, strError),
        strError);

    std::vector<PrivacyVNextMembershipWitness> vFromLeaves;
    PrivacyVNextDigest rootFromLeaves;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnesses(shortState, vShort, vTargets, vFromLeaves,
                                   rootFromLeaves, strError),
        strError);
    BOOST_CHECK(rootFromPaths == rootFromLeaves);
    BOOST_REQUIRE_EQUAL(vFromPaths.size(), vFromLeaves.size());
    for (size_t i = 0; i < vFromPaths.size(); ++i)
        BOOST_CHECK(vFromPaths[i].vchRecord == vFromLeaves[i].vchRecord);
}

// A store that is behind the frontier must refuse to append rather than write leaves at
// indices consensus never assigned. Recovery is the sync path's job, not the caller's.
BOOST_AUTO_TEST_CASE(growing_a_store_that_lags_the_frontier_fails_closed)
{
    CTxDB txdb("r+");
    std::string strError;

    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    for (uint64_t i = 0; i < 40; ++i)
        vLeaves.push_back(StoreTestLeaf(2000 + i));

    std::vector<unsigned char> state = EmptyVNextTreeState();
    ResetStore(txdb, state);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vLeaves, state, strError), strError);

    // The frontier has moved on; the store has not. Appending against it would place the
    // next leaf at the wrong index.
    ResetStore(txdb, EmptyVNextTreeState());
    std::vector<PrivacyVNextOutputLeaf> vMore;
    vMore.push_back(StoreTestLeaf(3000));
    BOOST_CHECK(!GrowPrivacyVNextTreeStore(txdb, vMore, state, strError));
    BOOST_CHECK(!strError.empty());

    uint64_t nStored = 1;
    BOOST_REQUIRE(ReadPrivacyVNextTreeStoreSize(txdb, nStored));
    BOOST_CHECK_EQUAL(nStored, 0U);
}

// Trimming lowers the recorded size before erasing, so an interrupted trim can never leave
// the store claiming leaves it no longer holds.
BOOST_AUTO_TEST_CASE(a_trim_never_claims_more_than_it_holds)
{
    CTxDB txdb("r+");
    std::string strError;

    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    for (uint64_t i = 0; i < 50; ++i)
        vLeaves.push_back(StoreTestLeaf(4000 + i));

    std::vector<unsigned char> state = EmptyVNextTreeState();
    ResetStore(txdb, state);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vLeaves, state, strError), strError);

    // Recover the frontier the shorter tree has by replaying it, then trim to it. Every
    // leaf and node the trimmed store still reports must be readable, at every position.
    const std::vector<PrivacyVNextOutputLeaf> vShort(vLeaves.begin(),
                                                     vLeaves.begin() + 20);
    std::vector<unsigned char> shortState = EmptyVNextTreeState();
    {
        std::vector<unsigned char> nextRoot;
        uint64_t nNextSize = 0;
        for (size_t i = 0; i < vShort.size(); ++i)
        {
            const std::vector<PrivacyVNextOutputLeaf> vOne(vShort.begin() + i,
                                                           vShort.begin() + i + 1);
            std::vector<unsigned char> nextState;
            BOOST_REQUIRE_MESSAGE(
                ApplyPrivacyVNextOutputLeaves(shortState, vOne, nextState,
                                              nextRoot, nNextSize, strError),
                strError);
            shortState.swap(nextState);
        }
        BOOST_REQUIRE_EQUAL(nNextSize, 20U);
    }

    BOOST_REQUIRE_MESSAGE(
        TrimPrivacyVNextTreeStore(txdb, 20, shortState, strError), strError);
    uint64_t nStored = 0;
    BOOST_REQUIRE(ReadPrivacyVNextTreeStoreSize(txdb, nStored));
    BOOST_CHECK_EQUAL(nStored, 20U);

    for (uint64_t nTarget = 0; nTarget < nStored; ++nTarget)
    {
        std::vector<uint64_t> vTargets;
        vTargets.push_back(nTarget);
        std::vector<unsigned char> vchPaths;
        BOOST_REQUIRE_MESSAGE(
            ReadPrivacyVNextTreePaths(txdb, nStored, shortState, vTargets, vchPaths,
                                      strError),
            strError);
        std::vector<PrivacyVNextMembershipWitness> vWitnesses;
        PrivacyVNextDigest root;
        BOOST_REQUIRE_MESSAGE(
            BuildPrivacyVNextWitnessesFromPaths(shortState, vTargets, vchPaths,
                                                vWitnesses, root, strError),
            strError);
    }
}

// The store routinely runs ahead of a spend's finalized anchor; serving the older anchor
// must give the witness the store gave at that size.
BOOST_AUTO_TEST_CASE(paths_serve_an_anchor_older_than_the_store)
{
    CTxDB txdb("r+");
    std::string strError;

    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    for (uint64_t i = 0; i < 200; ++i)
        vLeaves.push_back(StoreTestLeaf(5000 + i));

    // Targets on both sides of a level-0 boundary, plus the last leaf of the anchor,
    // which is the one whose ancestors were still partial when the anchor was current.
    std::vector<uint64_t> vTargets;
    vTargets.push_back(0);
    vTargets.push_back(37);
    vTargets.push_back(38);
    vTargets.push_back(74);

    const size_t nAnchor = 75;
    const std::vector<PrivacyVNextOutputLeaf> vAnchorLeaves(
        vLeaves.begin(), vLeaves.begin() + nAnchor);

    std::vector<unsigned char> anchorState = EmptyVNextTreeState();
    ResetStore(txdb, anchorState);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vAnchorLeaves, anchorState, strError),
        strError);

    std::vector<unsigned char> vchAtAnchor;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, nAnchor, anchorState, vTargets,
                                  vchAtAnchor, strError),
        strError);

    // Grow past the anchor, which rewrites the trailing node of each level.
    std::vector<unsigned char> laterState = anchorState;
    const std::vector<PrivacyVNextOutputLeaf> vRest(vLeaves.begin() + nAnchor,
                                                    vLeaves.end());
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vRest, laterState, strError), strError);
    uint64_t nStored = 0;
    BOOST_REQUIRE(ReadPrivacyVNextTreeStoreSize(txdb, nStored));
    BOOST_REQUIRE_EQUAL(nStored, vLeaves.size());

    std::vector<unsigned char> vchAfterGrowth;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, nAnchor, anchorState, vTargets,
                                  vchAfterGrowth, strError),
        strError);
    BOOST_CHECK(vchAfterGrowth == vchAtAnchor);

    // The witness must still fold onto the anchor root, not the store's current one.
    std::vector<PrivacyVNextMembershipWitness> vFromPaths;
    PrivacyVNextDigest rootFromPaths;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnessesFromPaths(anchorState, vTargets,
                                            vchAfterGrowth, vFromPaths,
                                            rootFromPaths, strError),
        strError);

    std::vector<PrivacyVNextMembershipWitness> vFromLeaves;
    PrivacyVNextDigest rootFromLeaves;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnesses(anchorState, vAnchorLeaves, vTargets,
                                   vFromLeaves, rootFromLeaves, strError),
        strError);
    BOOST_CHECK(rootFromPaths == rootFromLeaves);
    BOOST_REQUIRE_EQUAL(vFromPaths.size(), vFromLeaves.size());
    for (size_t i = 0; i < vFromPaths.size(); ++i)
        BOOST_CHECK(vFromPaths[i].vchRecord == vFromLeaves[i].vchRecord);

    // An anchor the store cannot reach yet still has to fail closed.
    std::vector<unsigned char> vchTooNew;
    BOOST_CHECK(!ReadPrivacyVNextTreePaths(txdb, nStored + 1, laterState,
                                           vTargets, vchTooNew, strError));

    // So does a frontier that does not describe the requested size.
    std::vector<unsigned char> vchMismatched;
    BOOST_CHECK(!ReadPrivacyVNextTreePaths(txdb, nAnchor, laterState, vTargets,
                                           vchMismatched, strError));
}

BOOST_AUTO_TEST_SUITE_END()
