#include <boost/test/unit_test.hpp>

#include <cstring>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../dag.h"
#include "../main.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../txdb.h"

namespace
{

PrivacyVNextDigest BuilderDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

// Scalars must be canonical field elements, so build them from a small value rather than
// a repeated byte, which overflows the group order.
PrivacyVNextDigest BuilderScalar(unsigned char low)
{
    PrivacyVNextDigest d;
    d.fill(0);
    d[0] = low;
    return d;
}

} // namespace

BOOST_AUTO_TEST_SUITE(privacy_vnext_builder_tests)

// Encrypting an output must produce a leaf its own scan reopens.
BOOST_AUTO_TEST_CASE(an_encrypted_output_reopens_under_its_own_keys)
{
    const PrivacyVNextDigest seed = BuilderDigest(0x21);
    const PrivacyVNextDigest genesis = BuilderDigest(0x11);
    PrivacyVNextDerivedKeys keys;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(seed, genesis, 0, 2, 0, keys, error), error);

    const uint64_t nAmount = 123456;
    PrivacyVNextEncryptedOutput note;
    BOOST_REQUIRE_MESSAGE(
        EncryptPrivacyVNextNote(2, 0, 0, genesis, keys.spendPublic,
                                keys.viewPublic, keys.outgoingViewSecret,
                                BuilderScalar(13), nAmount,
                                BuilderScalar(17), BuilderScalar(19), note,
                                error),
        error);
    BOOST_CHECK_EQUAL(note.vchRecipientCiphertext.size(),
                      (size_t)INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE);
    BOOST_CHECK_EQUAL(note.vchOutgoingCiphertext.size(),
                      (size_t)INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE);

    // The recipient's own full scan must recover the amount and the spend authority.
    PrivacyVNextEncryptedNote onChain;
    onChain.nOutputIndex = 0;
    onChain.genesis = genesis;
    onChain.leafO = note.leaf.owner;
    onChain.leafC = note.leaf.commitment;
    onChain.ephemeral = note.ephemeral;
    onChain.vchCiphertext = note.vchRecipientCiphertext;

    PrivacyVNextScannedNote scanned;
    BOOST_REQUIRE_MESSAGE(
        ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, 2, 0, onChain,
                             keys.viewSecret, keys.spendSecret, scanned, error),
        error);
    BOOST_CHECK_EQUAL(scanned.nAmount, nAmount);

    const PrivacyVNextDigest zero = BuilderDigest(0);
    BOOST_CHECK(scanned.keyImage != zero);
    BOOST_CHECK(scanned.spendSecret != zero);
}

// The proof size the prover emits must be exactly the size the ABI fixes for that input
// count, because a payload carrying any other length is not the canonical one.
BOOST_AUTO_TEST_CASE(proof_size_is_fixed_per_input_count)
{
    std::string error;
    size_t nPrevious = 0;
    for (uint32_t nInputs = 1; nInputs <= 4; ++nInputs)
    {
        size_t nSize = 0;
        BOOST_REQUIRE_MESSAGE(
            GetPrivacyVNextProofSize(nInputs, nSize, error), error);
        BOOST_CHECK(nSize > 0);
        BOOST_CHECK(nSize > nPrevious);
        nPrevious = nSize;
    }

    size_t nSize = 0;
    BOOST_CHECK(!GetPrivacyVNextProofSize(0, nSize, error));
    BOOST_CHECK(!GetPrivacyVNextProofSize(INNOVA_PRIVACY_VNEXT_MAX_INPUTS + 1,
                                          nSize, error));
}

// The prover must refuse the inputs it cannot honour rather than emitting something a
// verifier would later reject.
BOOST_AUTO_TEST_CASE(membership_proving_fails_closed_on_bad_inputs)
{
    std::string error;
    std::vector<PrivacyVNextSpendConstruction> constructions;
    std::vector<unsigned char> proof;

    std::vector<PrivacyVNextSpendInput> none;
    BOOST_CHECK(!ProvePrivacyVNextMembership(
        BuilderDigest(1), BuilderDigest(2), BuilderScalar(3), none,
        constructions, proof, error));

    // Zero entropy would make the proof deterministic in the prover's nonces.
    std::vector<PrivacyVNextSpendInput> one;
    one.resize(1);
    one[0].vchWitnessRecord.assign(16, 0);
    BOOST_CHECK(!ProvePrivacyVNextMembership(
        BuilderDigest(1), BuilderDigest(2), BuilderScalar(0), one,
        constructions, proof, error));
    BOOST_CHECK(!error.empty());

    // A missing witness record cannot be spliced into a proving request.
    std::vector<PrivacyVNextSpendInput> empty;
    empty.resize(1);
    BOOST_CHECK(!ProvePrivacyVNextMembership(
        BuilderDigest(1), BuilderDigest(2), BuilderScalar(3), empty,
        constructions, proof, error));
    BOOST_CHECK(!error.empty());
}

// The signing hash must depend on every byte a builder commits to, and on the outer wire
// version, or a proof could be lifted onto a different payload or envelope.
BOOST_AUTO_TEST_CASE(the_signing_hash_binds_the_prefix_and_the_wire_version)
{
    std::string error;
    std::vector<unsigned char> prefix;
    for (size_t i = 0; i < 64; ++i)
        prefix.push_back(static_cast<unsigned char>(i));

    PrivacyVNextDigest base;
    BOOST_REQUIRE_MESSAGE(
        HashPrivacyVNextPayloadPrefix(2008, prefix, base, error), error);

    // A different envelope version must not reuse the same hash.
    PrivacyVNextDigest otherVersion;
    BOOST_REQUIRE_MESSAGE(
        HashPrivacyVNextPayloadPrefix(2002, prefix, otherVersion, error), error);
    BOOST_CHECK(base != otherVersion);

    // Every byte of the prefix must matter.
    for (size_t i = 0; i < prefix.size(); ++i)
    {
        std::vector<unsigned char> altered = prefix;
        altered[i] ^= 0x01;
        PrivacyVNextDigest changed;
        BOOST_REQUIRE_MESSAGE(
            HashPrivacyVNextPayloadPrefix(2008, altered, changed, error), error);
        BOOST_CHECK_MESSAGE(base != changed,
                            "flipping prefix byte " + std::to_string(i) +
                                " did not change the signing hash");
    }

    // Appending must change it too, so a truncated prefix cannot pass for a longer one.
    std::vector<unsigned char> longer = prefix;
    longer.push_back(0);
    PrivacyVNextDigest extended;
    BOOST_REQUIRE_MESSAGE(
        HashPrivacyVNextPayloadPrefix(2008, longer, extended, error), error);
    BOOST_CHECK(base != extended);

    PrivacyVNextDigest empty;
    BOOST_CHECK(!HashPrivacyVNextPayloadPrefix(
        2008, std::vector<unsigned char>(), empty, error));
}

// Full spend path: create, place, witness, scan, spend. The builder validates its output
// with the consensus decoder.
BOOST_AUTO_TEST_CASE(a_note_placed_in_the_tree_can_be_spent)
{
    CTxDB txdb("r+");
    std::string error;

    const PrivacyVNextDigest seed = BuilderDigest(0x77);
    const PrivacyVNextDigest genesis = BuilderDigest(0x11);
    PrivacyVNextDerivedKeys keys;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(seed, genesis, 0, 2, 0, keys, error), error);

    // Create the note that will be spent.
    const uint64_t nAmount = 5000;
    PrivacyVNextEncryptedOutput funding;
    BOOST_REQUIRE_MESSAGE(
        EncryptPrivacyVNextNote(2, 0, 0, genesis, keys.spendPublic,
                                keys.viewPublic, keys.outgoingViewSecret,
                                BuilderScalar(29), nAmount, BuilderScalar(31),
                                BuilderScalar(37), funding, error),
        error);

    // Place it in the tree, then reopen it by scanning as the wallet would.
    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    BOOST_REQUIRE_MESSAGE(
        TrimPrivacyVNextTreeStore(txdb, 0, treeState, error), error);

    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    vLeaves.push_back(funding.leaf);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, error), error);

    std::vector<unsigned char> vchRoot;
    uint64_t nTreeSize = 0;
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(treeState, vchRoot, nTreeSize, error), error);
    BOOST_REQUIRE_EQUAL(nTreeSize, 1U);
    BOOST_REQUIRE_EQUAL(vchRoot.size(), 32U);

    std::vector<uint64_t> vTargets;
    vTargets.push_back(0);
    std::vector<unsigned char> vchPaths;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, nTreeSize, vTargets, vchPaths, error),
        error);
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths,
                                            vWitnesses, treeRoot, error),
        error);
    BOOST_REQUIRE_EQUAL(vWitnesses.size(), 1U);

    PrivacyVNextEncryptedNote onChain;
    onChain.nOutputIndex = 0;
    onChain.genesis = genesis;
    onChain.leafO = funding.leaf.owner;
    onChain.leafC = funding.leaf.commitment;
    onChain.ephemeral = funding.ephemeral;
    onChain.vchCiphertext = funding.vchRecipientCiphertext;
    PrivacyVNextScannedNote scanned;
    BOOST_REQUIRE_MESSAGE(
        ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, 2, 0, onChain,
                             keys.viewSecret, keys.spendSecret, scanned, error),
        error);
    BOOST_REQUIRE_EQUAL(scanned.nAmount, nAmount);

    // Spend it back to ourselves, less a fee.
    std::vector<PrivacyVNextSpendNote> spends;
    spends.resize(1);
    spends[0].spendSecret = scanned.spendSecret;
    spends[0].y = scanned.y;
    spends[0].mask = scanned.mask;
    spends[0].nAmount = scanned.nAmount;
    spends[0].leaf = funding.leaf;
    spends[0].vchWitnessRecord = vWitnesses[0].vchRecord;

    const uint64_t nFee = 100;
    std::vector<PrivacyVNextNewOutput> outs;
    outs.resize(1);
    outs[0].recipient.nNetwork = 2;
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = keys.spendPublic;
    outs[0].recipient.viewPublic = keys.viewPublic;
    outs[0].nAmount = nAmount - nFee;

    PrivacyVNextDigest finalizedRoot;
    std::memcpy(finalizedRoot.data(), &vchRoot[0], 32);

    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(2, genesis, keys.outgoingViewSecret,
                                         finalizedRoot, nTreeSize, nFee, spends,
                                         outs, payload, error),
        error);
    BOOST_CHECK(!payload.empty());

    // Independently confirm what the builder already checked, and confirm the payload's
    // effects name the note it spent.
    const PrivacyVNextPayloadValidation validation =
        ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                    payload);
    BOOST_CHECK_MESSAGE(validation.IsValid(), validation.strError);

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation extracted =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects);
    BOOST_REQUIRE_MESSAGE(extracted.IsValid(), extracted.strError);
    BOOST_CHECK_EQUAL(effects.keyImages.size(), 1U);
    BOOST_CHECK_EQUAL(effects.outputLeaves.size(), 1U);
    BOOST_CHECK(effects.keyImages[0] == scanned.keyImage);
    BOOST_CHECK_EQUAL(effects.nFinalizedTreeSize, nTreeSize);
}

// Memoized effects must equal full-validation effects and must not survive a cache clear.
BOOST_AUTO_TEST_CASE(memoized_effects_match_a_full_validation)
{
    CTxDB txdb("r+");
    std::string error;

    const PrivacyVNextDigest seed = BuilderDigest(0x5b);
    const PrivacyVNextDigest genesis = BuilderDigest(0x11);
    PrivacyVNextDerivedKeys keys;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(seed, genesis, 0, 2, 0, keys, error), error);

    const uint64_t nAmount = 4000;
    PrivacyVNextEncryptedOutput funding;
    BOOST_REQUIRE_MESSAGE(
        EncryptPrivacyVNextNote(2, 0, 0, genesis, keys.spendPublic,
                                keys.viewPublic, keys.outgoingViewSecret,
                                BuilderScalar(41), nAmount, BuilderScalar(43),
                                BuilderScalar(47), funding, error),
        error);

    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    BOOST_REQUIRE_MESSAGE(
        TrimPrivacyVNextTreeStore(txdb, 0, treeState, error), error);
    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    vLeaves.push_back(funding.leaf);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, error), error);

    std::vector<unsigned char> vchRoot;
    uint64_t nTreeSize = 0;
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(treeState, vchRoot, nTreeSize, error), error);
    std::vector<uint64_t> vTargets;
    vTargets.push_back(0);
    std::vector<unsigned char> vchPaths;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, nTreeSize, vTargets, vchPaths, error),
        error);
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths,
                                            vWitnesses, treeRoot, error),
        error);

    PrivacyVNextEncryptedNote onChain;
    onChain.nOutputIndex = 0;
    onChain.genesis = genesis;
    onChain.leafO = funding.leaf.owner;
    onChain.leafC = funding.leaf.commitment;
    onChain.ephemeral = funding.ephemeral;
    onChain.vchCiphertext = funding.vchRecipientCiphertext;
    PrivacyVNextScannedNote scanned;
    BOOST_REQUIRE_MESSAGE(
        ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, 2, 0, onChain,
                             keys.viewSecret, keys.spendSecret, scanned, error),
        error);

    std::vector<PrivacyVNextSpendNote> spends;
    spends.resize(1);
    spends[0].spendSecret = scanned.spendSecret;
    spends[0].y = scanned.y;
    spends[0].mask = scanned.mask;
    spends[0].nAmount = scanned.nAmount;
    spends[0].leaf = funding.leaf;
    spends[0].vchWitnessRecord = vWitnesses[0].vchRecord;

    std::vector<PrivacyVNextNewOutput> outs;
    outs.resize(1);
    outs[0].recipient.nNetwork = 2;
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = keys.spendPublic;
    outs[0].recipient.viewPublic = keys.viewPublic;
    outs[0].nAmount = nAmount - 50;

    PrivacyVNextDigest finalizedRoot;
    std::memcpy(finalizedRoot.data(), &vchRoot[0], 32);
    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(2, genesis, keys.outgoingViewSecret,
                                         finalizedRoot, nTreeSize, 50, spends,
                                         outs, payload, error),
        error);

    // Cold, then warm, then cold again.
    ClearPrivacyVNextEffectsCache();
    PrivacyVNextStateEffects cold;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, cold).IsValid());
    PrivacyVNextStateEffects warm;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, warm).IsValid());
    ClearPrivacyVNextEffectsCache();
    PrivacyVNextStateEffects recold;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, recold).IsValid());

    BOOST_CHECK(warm.finalizedRoot == cold.finalizedRoot);
    BOOST_CHECK_EQUAL(warm.nFinalizedTreeSize, cold.nFinalizedTreeSize);
    BOOST_CHECK(warm.parameterDigest == cold.parameterDigest);
    BOOST_REQUIRE_EQUAL(warm.keyImages.size(), cold.keyImages.size());
    for (size_t i = 0; i < cold.keyImages.size(); ++i)
        BOOST_CHECK(warm.keyImages[i] == cold.keyImages[i]);
    BOOST_REQUIRE_EQUAL(warm.outputLeaves.size(), cold.outputLeaves.size());
    for (size_t i = 0; i < cold.outputLeaves.size(); ++i)
    {
        BOOST_CHECK(warm.outputLeaves[i].owner == cold.outputLeaves[i].owner);
        BOOST_CHECK(warm.outputLeaves[i].commitment ==
                    cold.outputLeaves[i].commitment);
    }
    BOOST_CHECK(recold.keyImages.size() == cold.keyImages.size());

    // A payload the cache has never seen must still be rejected on its own merits.
    std::vector<unsigned char> tampered = payload;
    tampered[tampered.size() - 1] ^= 0x01;
    PrivacyVNextStateEffects rejected;
    BOOST_CHECK(!ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, tampered,
        rejected).IsValid());
}

// A shield spends no note, so it carries no membership proof.
BOOST_AUTO_TEST_CASE(a_shield_carries_no_membership_proof_and_stays_spendable)
{
    CTxDB txdb("r+");
    std::string error;

    const PrivacyVNextDigest seed = BuilderDigest(0x6c);
    const PrivacyVNextDigest genesis = BuilderDigest(0x11);
    PrivacyVNextDerivedKeys keys;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(seed, genesis, 0, 2, 0, keys, error), error);

    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    BOOST_REQUIRE_MESSAGE(
        TrimPrivacyVNextTreeStore(txdb, 0, treeState, error), error);

    std::vector<unsigned char> vchRoot;
    uint64_t nTreeSize = 0;
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(treeState, vchRoot, nTreeSize, error), error);
    BOOST_REQUIRE_EQUAL(nTreeSize, 0U);
    PrivacyVNextDigest emptyRoot;
    std::memcpy(emptyRoot.data(), &vchRoot[0], 32);

    // Shielding into an empty pool must work.
    const uint64_t nValueIn = 10000;
    const uint64_t nFee = 100;
    std::vector<PrivacyVNextNewOutput> outs;
    outs.resize(1);
    outs[0].recipient.nNetwork = 2;
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = keys.spendPublic;
    outs[0].recipient.viewPublic = keys.viewPublic;
    outs[0].nAmount = nValueIn - nFee;

    std::vector<unsigned char> shieldPayload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextShieldPayload(2, genesis, keys.outgoingViewSecret,
                                       emptyRoot, nTreeSize, nValueIn, nFee,
                                       outs, shieldPayload, error),
        error);

    // A shield is a fraction of a transfer because it proves no membership.
    size_t nTransferProof = 0;
    BOOST_REQUIRE(GetPrivacyVNextProofSize(1, nTransferProof, error));
    BOOST_CHECK_MESSAGE(shieldPayload.size() < nTransferProof,
                        "a shield must be smaller than a single membership proof");

    PrivacyVNextStateEffects shieldEffects;
    const PrivacyVNextPayloadValidation shieldValid =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, shieldPayload,
            shieldEffects);
    BOOST_REQUIRE_MESSAGE(shieldValid.IsValid(), shieldValid.strError);
    BOOST_CHECK_EQUAL(shieldEffects.keyImages.size(), 0U);
    BOOST_REQUIRE_EQUAL(shieldEffects.outputLeaves.size(), 1U);

    // The shielded note must then be findable, placeable, and spendable.
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, shieldEffects.outputLeaves, treeState,
                                  error),
        error);
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(treeState, vchRoot, nTreeSize, error), error);
    BOOST_REQUIRE_EQUAL(nTreeSize, 1U);

    std::vector<PrivacyVNextScanMatch> matches;
    std::vector<PrivacyVNextDigest> keyImages;
    uint8_t nOutputCount = 0;
    std::vector<PrivacyVNextScanKey> vKeys(1);
    vKeys[0].scanSecret = keys.viewSecret;
    vKeys[0].spendMaterial = keys.spendSecret;
    BOOST_REQUIRE_MESSAGE(
        ScanPrivacyVNextPayload(PRIVACY_VNEXT_SCAN_FULL, 2, 0,
                                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                shieldPayload, vKeys, matches, keyImages,
                                nOutputCount, error),
        error);
    BOOST_REQUIRE_EQUAL(matches.size(), 1U);
    BOOST_CHECK_EQUAL(matches[0].nAmount, nValueIn - nFee);

    std::vector<uint64_t> vTargets;
    vTargets.push_back(0);
    std::vector<unsigned char> vchPaths;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, nTreeSize, vTargets, vchPaths, error),
        error);
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths,
                                            vWitnesses, treeRoot, error),
        error);

    std::vector<PrivacyVNextSpendNote> spends;
    spends.resize(1);
    spends[0].spendSecret = matches[0].spendSecret;
    spends[0].y = matches[0].y;
    spends[0].mask = matches[0].mask;
    spends[0].nAmount = matches[0].nAmount;
    spends[0].leaf = shieldEffects.outputLeaves[0];
    spends[0].vchWitnessRecord = vWitnesses[0].vchRecord;

    std::vector<PrivacyVNextNewOutput> onward;
    onward.resize(1);
    onward[0].recipient = outs[0].recipient;
    onward[0].nAmount = matches[0].nAmount - nFee;

    std::vector<unsigned char> transferPayload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(2, genesis, keys.outgoingViewSecret,
                                         treeRoot, nTreeSize, nFee, spends,
                                         onward, transferPayload, error),
        error);
    BOOST_CHECK(transferPayload.size() > shieldPayload.size());
}

// Concurrent cache warming must match the sequential validator exactly.
BOOST_AUTO_TEST_CASE(parallel_warming_agrees_with_sequential_validation)
{
    std::string error;
    const PrivacyVNextDigest seed = BuilderDigest(0x2e);
    const PrivacyVNextDigest genesis = BuilderDigest(0x11);
    PrivacyVNextDerivedKeys keys;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(seed, genesis, 0, 2, 0, keys, error), error);

    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    std::vector<unsigned char> vchRoot;
    uint64_t nTreeSize = 0;
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(epochSeed.vchTreeState, vchRoot, nTreeSize,
                                    error),
        error);
    PrivacyVNextDigest emptyRoot;
    std::memcpy(emptyRoot.data(), &vchRoot[0], 32);

    // Shields need no membership proof, so a batch of distinct ones is cheap to build.
    const size_t nCount = 8;
    std::vector<std::vector<unsigned char> > vPayloads;
    for (size_t i = 0; i < nCount; ++i)
    {
        std::vector<PrivacyVNextNewOutput> outs;
        outs.resize(1);
        outs[0].recipient.nNetwork = 2;
        outs[0].recipient.nAddressType = 0;
        outs[0].recipient.spendPublic = keys.spendPublic;
        outs[0].recipient.viewPublic = keys.viewPublic;
        outs[0].nAmount = 1000 + (uint64_t)i;   // distinct value, distinct payload

        std::vector<unsigned char> payload;
        BOOST_REQUIRE_MESSAGE(
            BuildPrivacyVNextShieldPayload(2, genesis, keys.outgoingViewSecret,
                                           emptyRoot, nTreeSize,
                                           outs[0].nAmount + 10, 10, outs,
                                           payload, error),
            error);
        vPayloads.push_back(payload);
    }

    // Cold sequential pass is the reference.
    ClearPrivacyVNextEffectsCache();
    std::vector<PrivacyVNextStateEffects> vSequential(nCount);
    for (size_t i = 0; i < nCount; ++i)
    {
        BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vPayloads[i],
            vSequential[i]).IsValid());
    }

    // Same batch, warmed concurrently from cold.
    ClearPrivacyVNextEffectsCache();
    std::vector<std::pair<uint32_t, const std::vector<unsigned char>*> > vWarm;
    for (size_t i = 0; i < nCount; ++i)
        vWarm.push_back(std::make_pair(
            (uint32_t)INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, &vPayloads[i]));
    WarmPrivacyVNextEffectsCache(vWarm, 4);

    for (size_t i = 0; i < nCount; ++i)
    {
        PrivacyVNextStateEffects warmed;
        BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vPayloads[i],
            warmed).IsValid());
        BOOST_CHECK(warmed.finalizedRoot == vSequential[i].finalizedRoot);
        BOOST_CHECK_EQUAL(warmed.nFinalizedTreeSize,
                          vSequential[i].nFinalizedTreeSize);
        BOOST_REQUIRE_EQUAL(warmed.outputLeaves.size(),
                            vSequential[i].outputLeaves.size());
        for (size_t j = 0; j < warmed.outputLeaves.size(); ++j)
            BOOST_CHECK(warmed.outputLeaves[j].commitment ==
                        vSequential[i].outputLeaves[j].commitment);
    }

    // An invalid payload in the batch must not be cached by the warm pass, so the
    // sequential validator still rejects it on its own terms.
    std::vector<unsigned char> tampered = vPayloads[0];
    tampered[tampered.size() - 1] ^= 0x01;
    ClearPrivacyVNextEffectsCache();
    std::vector<std::pair<uint32_t, const std::vector<unsigned char>*> > vMixed;
    vMixed.push_back(std::make_pair(
        (uint32_t)INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, &tampered));
    vMixed.push_back(std::make_pair(
        (uint32_t)INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, &vPayloads[1]));
    WarmPrivacyVNextEffectsCache(vMixed, 2);

    PrivacyVNextStateEffects rejected;
    BOOST_CHECK(!ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, tampered,
        rejected).IsValid());
    PrivacyVNextStateEffects accepted;
    BOOST_CHECK(ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vPayloads[1],
        accepted).IsValid());

    // A null entry and a single-item batch must both be no-ops rather than faults.
    std::vector<std::pair<uint32_t, const std::vector<unsigned char>*> > vOdd;
    vOdd.push_back(std::make_pair((uint32_t)0, (const std::vector<unsigned char>*)NULL));
    vOdd.push_back(std::make_pair(
        (uint32_t)INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, &vPayloads[2]));
    WarmPrivacyVNextEffectsCache(vOdd, 2);
    WarmPrivacyVNextEffectsCache(
        std::vector<std::pair<uint32_t, const std::vector<unsigned char>*> >(), 4);
}

// Standardness is only consulted on mainnet; IV5 transactions must be standard.
BOOST_AUTO_TEST_CASE(an_iv5_transaction_is_standard)
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_VNEXT;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = uint256(1);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig << OP_1;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey.SetDestination(CKeyID(uint160(7)));
    tx.privacyVNext.vchPayload.assign(64, 0x11);

    BOOST_REQUIRE(tx.IsPrivacyVNext());
    // The helper excludes payload-bearing transactions.
    BOOST_CHECK(!tx.IsShielded());

    std::string reason;
    BOOST_CHECK_MESSAGE(IsStandardTx(tx, reason),
                        "IV5 transaction judged nonstandard: " + reason);
}

// Pool balance accounting: a shield reports exactly what it moved; a transfer reports
// only the fee leaving.
BOOST_AUTO_TEST_CASE(payload_effects_report_what_the_pool_gained_or_lost)
{
    std::string error;
    const PrivacyVNextDigest seed = BuilderDigest(0x3d);
    const PrivacyVNextDigest genesis = BuilderDigest(0x11);
    PrivacyVNextDerivedKeys keys;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(seed, genesis, 0, 2, 0, keys, error), error);

    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    std::vector<unsigned char> vchRoot;
    uint64_t nTreeSize = 0;
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(epochSeed.vchTreeState, vchRoot, nTreeSize,
                                    error),
        error);
    PrivacyVNextDigest emptyRoot;
    std::memcpy(emptyRoot.data(), &vchRoot[0], 32);

    const uint64_t nValueIn = 9000;
    const uint64_t nFee = 100;
    std::vector<PrivacyVNextNewOutput> outs;
    outs.resize(1);
    outs[0].recipient.nNetwork = 2;
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = keys.spendPublic;
    outs[0].recipient.viewPublic = keys.viewPublic;
    outs[0].nAmount = nValueIn - nFee;

    std::vector<unsigned char> shieldPayload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextShieldPayload(2, genesis, keys.outgoingViewSecret,
                                       emptyRoot, nTreeSize, nValueIn, nFee,
                                       outs, shieldPayload, error),
        error);

    PrivacyVNextStateEffects shieldEffects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, shieldPayload,
        shieldEffects).IsValid());

    // A shield moves the transparent value in and pays the fee out of it, so the pool
    // gains exactly what the notes are worth.
    BOOST_CHECK_EQUAL(shieldEffects.nTransparentValueBalance, (int64_t)nValueIn);
    BOOST_CHECK_EQUAL(shieldEffects.nFee, nFee);
    BOOST_CHECK_EQUAL(shieldEffects.PoolDelta(), (int64_t)(nValueIn - nFee));
    BOOST_CHECK(shieldEffects.PoolDelta() > 0);

    // The note the shield created, spent onward, must take only the fee out of the pool.
    CTxDB txdb("r+");
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    BOOST_REQUIRE_MESSAGE(
        TrimPrivacyVNextTreeStore(txdb, 0, treeState, error), error);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, shieldEffects.outputLeaves, treeState,
                                  error),
        error);
    uint64_t nGrownSize = 0;
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(treeState, vchRoot, nGrownSize, error), error);

    std::vector<PrivacyVNextScanMatch> matches;
    std::vector<PrivacyVNextDigest> spentImages;
    uint8_t nOutputCount = 0;
    std::vector<PrivacyVNextScanKey> vKeys(1);
    vKeys[0].scanSecret = keys.viewSecret;
    vKeys[0].spendMaterial = keys.spendSecret;
    BOOST_REQUIRE_MESSAGE(
        ScanPrivacyVNextPayload(PRIVACY_VNEXT_SCAN_FULL, 2, 0,
                                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                shieldPayload, vKeys, matches, spentImages,
                                nOutputCount, error),
        error);
    BOOST_REQUIRE_EQUAL(matches.size(), 1U);

    std::vector<uint64_t> vTargets;
    vTargets.push_back(0);
    std::vector<unsigned char> vchPaths;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, nGrownSize, vTargets, vchPaths, error),
        error);
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths,
                                            vWitnesses, treeRoot, error),
        error);

    std::vector<PrivacyVNextSpendNote> spends;
    spends.resize(1);
    spends[0].spendSecret = matches[0].spendSecret;
    spends[0].y = matches[0].y;
    spends[0].mask = matches[0].mask;
    spends[0].nAmount = matches[0].nAmount;
    spends[0].leaf = shieldEffects.outputLeaves[0];
    spends[0].vchWitnessRecord = vWitnesses[0].vchRecord;

    std::vector<PrivacyVNextNewOutput> onward;
    onward.resize(1);
    onward[0].recipient = outs[0].recipient;
    onward[0].nAmount = matches[0].nAmount - nFee;

    std::vector<unsigned char> transferPayload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(2, genesis, keys.outgoingViewSecret,
                                         treeRoot, nGrownSize, nFee, spends,
                                         onward, transferPayload, error),
        error);

    PrivacyVNextStateEffects transferEffects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, transferPayload,
        transferEffects).IsValid());
    BOOST_CHECK_EQUAL(transferEffects.nTransparentValueBalance, 0);
    BOOST_CHECK_EQUAL(transferEffects.PoolDelta(), -(int64_t)nFee);

    // The pair leaves the pool holding what it received.
    const int64_t nPool = shieldEffects.PoolDelta() + transferEffects.PoolDelta();
    BOOST_CHECK_EQUAL(nPool, (int64_t)(nValueIn - nFee - nFee));
    BOOST_CHECK(nPool > 0);
}

// The pool may not go negative; driven directly since no honest tx can reach it.
BOOST_AUTO_TEST_CASE(the_pool_balance_refuses_to_go_negative)
{
    std::string error;
    int64_t nPool = 0;

    // Value entering accumulates.
    BOOST_REQUIRE(ApplyPrivacyVNextPoolDelta(nPool, 5000, error));
    BOOST_CHECK_EQUAL(nPool, 5000);
    BOOST_REQUIRE(ApplyPrivacyVNextPoolDelta(nPool, 2500, error));
    BOOST_CHECK_EQUAL(nPool, 7500);

    // Value leaving is fine while the pool covers it, including to exactly empty.
    BOOST_REQUIRE(ApplyPrivacyVNextPoolDelta(nPool, -7500, error));
    BOOST_CHECK_EQUAL(nPool, 0);

    // One satoshi more than the pool holds is refused.
    BOOST_CHECK(!ApplyPrivacyVNextPoolDelta(nPool, -1, error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK_EQUAL(nPool, 0);   // rejected leaves the balance untouched

    nPool = 1000;
    BOOST_CHECK(!ApplyPrivacyVNextPoolDelta(nPool, -1001, error));
    BOOST_CHECK_EQUAL(nPool, 1000);
    BOOST_REQUIRE(ApplyPrivacyVNextPoolDelta(nPool, -1000, error));
    BOOST_CHECK_EQUAL(nPool, 0);

    // The pool can never hold more than the money supply.
    nPool = 0;
    BOOST_CHECK(!ApplyPrivacyVNextPoolDelta(nPool, MAX_MONEY + 1, error));
    BOOST_CHECK_EQUAL(nPool, 0);
    BOOST_REQUIRE(ApplyPrivacyVNextPoolDelta(nPool, MAX_MONEY, error));
    BOOST_CHECK_EQUAL(nPool, MAX_MONEY);
    BOOST_CHECK(!ApplyPrivacyVNextPoolDelta(nPool, 1, error));
    BOOST_CHECK_EQUAL(nPool, MAX_MONEY);

    // Overflow in either direction is refused, not wrapped.
    nPool = 1;
    BOOST_CHECK(!ApplyPrivacyVNextPoolDelta(
        nPool, std::numeric_limits<int64_t>::max(), error));
    BOOST_CHECK_EQUAL(nPool, 1);
    BOOST_CHECK(!ApplyPrivacyVNextPoolDelta(
        nPool, std::numeric_limits<int64_t>::min(), error));
    BOOST_CHECK_EQUAL(nPool, 1);

    // A balance that is already out of range cannot be extended.
    int64_t nCorrupt = -1;
    BOOST_CHECK(!ApplyPrivacyVNextPoolDelta(nCorrupt, 100, error));
    nCorrupt = MAX_MONEY + 1;
    BOOST_CHECK(!ApplyPrivacyVNextPoolDelta(nCorrupt, -100, error));

    // Shield then transfer: the pool gains the shielded value, then loses only the fee.
    nPool = 0;
    BOOST_REQUIRE(ApplyPrivacyVNextPoolDelta(nPool, 9000 - 100, error));
    BOOST_REQUIRE(ApplyPrivacyVNextPoolDelta(nPool, -100, error));
    BOOST_CHECK_EQUAL(nPool, 8800);
}

// A transfer that does not balance must be refused before any proving work.
BOOST_AUTO_TEST_CASE(an_unbalanced_transfer_is_refused)
{
    std::string error;
    std::vector<PrivacyVNextSpendNote> spends;
    spends.resize(1);
    spends[0].nAmount = 1000;
    spends[0].vchWitnessRecord.assign(32, 0);

    std::vector<PrivacyVNextNewOutput> outs;
    outs.resize(1);
    outs[0].nAmount = 999;   // plus a fee of 100 is more than the input covers

    std::vector<unsigned char> payload;
    BOOST_CHECK(!BuildPrivacyVNextTransferPayload(
        2, BuilderDigest(0x11), BuilderScalar(3), BuilderDigest(0x22), 1, 100,
        spends, outs, payload, error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(payload.empty());
}

BOOST_AUTO_TEST_SUITE_END()
