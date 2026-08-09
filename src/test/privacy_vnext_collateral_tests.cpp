#include <boost/test/unit_test.hpp>

#include <cstring>
#include <set>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../main.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../txdb.h"

namespace
{

const uint64_t kTier = INNOVA_PRIVACY_VNEXT_COLLATERAL_ATTESTATION_AMOUNT;

PrivacyVNextDigest CollateralDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

PrivacyVNextDigest CollateralScalar(unsigned char low)
{
    PrivacyVNextDigest d;
    d.fill(0);
    d[0] = low;
    return d;
}

PrivacyVNextDigest LocalGenesis()
{
    PrivacyVNextDigest d;
    PrivacyVNextLocalGenesis(d.data());
    return d;
}

uint8_t LocalNetwork()
{
    return PrivacyVNextLocalNetworkId();
}

PrivacyVNextDigest NoTransparentSide()
{
    PrivacyVNextDigest d;
    const uint256 binding = GetPrivacyVNextTransparentBinding(CTransaction());
    std::memcpy(d.data(), binding.begin(), 32);
    return d;
}

uint256 AsUint256(const PrivacyVNextDigest& d)
{
    uint256 out;
    std::memcpy(out.begin(), d.data(), d.size());
    return out;
}

// One note of a chosen amount, placed in a fresh tree and reopened by its owner, with the
// membership witness a proof over it needs.
struct FundedNote
{
    PrivacyVNextDerivedKeys keys;
    PrivacyVNextEncryptedOutput encrypted;
    PrivacyVNextSpendNote spend;
    PrivacyVNextDigest finalizedRoot;
    uint64_t nTreeSize;

    FundedNote() : nTreeSize(0) { finalizedRoot.fill(0); }
};

bool FundNote(CTxDB& txdb, unsigned char nSeed, uint64_t nAmount,
              FundedNote& out, std::string& error)
{
    const PrivacyVNextDigest genesis = LocalGenesis();
    if (!DerivePrivacyVNextKeys(CollateralDigest(nSeed), genesis, 0,
                                LocalNetwork(), 0, out.keys, error))
        return false;
    if (!EncryptPrivacyVNextNote(
            LocalNetwork(), 0, 0, genesis, out.keys.spendPublic,
            out.keys.viewPublic, out.keys.outgoingViewSecret,
            CollateralScalar(nSeed + 1), CollateralScalar(nSeed + 2), nAmount,
            CollateralScalar(nSeed + 3), CollateralScalar(nSeed + 4),
            out.encrypted, error))
        return false;

    PrivacyVNextEpochSeed epochSeed;
    if (!LoadPrivacyVNextEpochSeed(epochSeed, error))
        return false;
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    if (!TrimPrivacyVNextTreeStore(txdb, 0, treeState, error))
        return false;
    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    vLeaves.push_back(out.encrypted.leaf);
    if (!GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, error))
        return false;

    std::vector<unsigned char> vchRoot;
    if (!DecodePrivacyVNextTreeState(treeState, vchRoot, out.nTreeSize, error))
        return false;
    std::memcpy(out.finalizedRoot.data(), &vchRoot[0], 32);

    std::vector<uint64_t> vTargets;
    vTargets.push_back(0);
    std::vector<unsigned char> vchPaths;
    if (!ReadPrivacyVNextTreePaths(txdb, out.nTreeSize, treeState, vTargets,
                                   vchPaths, error))
        return false;
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    if (!BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths,
                                             vWitnesses, treeRoot, error))
        return false;

    PrivacyVNextEncryptedNote onChain;
    onChain.nOutputIndex = 0;
    onChain.genesis = genesis;
    onChain.leafO = out.encrypted.leaf.owner;
    onChain.leafC = out.encrypted.leaf.commitment;
    onChain.noteEphemeral = out.encrypted.noteEphemeral;
    onChain.tweakEphemeral = out.encrypted.tweakEphemeral;
    onChain.vchCiphertext = out.encrypted.vchRecipientCiphertext;
    PrivacyVNextScannedNote scanned;
    if (!ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, LocalNetwork(), 0,
                              onChain, out.keys.viewSecret,
                              out.keys.spendSecret, scanned, error))
        return false;

    out.spend.spendSecret = scanned.spendSecret;
    out.spend.y = scanned.y;
    out.spend.mask = scanned.mask;
    out.spend.nAmount = scanned.nAmount;
    out.spend.leaf = out.encrypted.leaf;
    out.spend.vchWitnessRecord = vWitnesses[0].vchRecord;
    return true;
}

// A transaction that carries a payload, which is all the consensus transitions read.
CTransaction CarryingTx(const std::vector<unsigned char>& payload, uint32_t nTime)
{
    CTransaction tx;
    tx.nVersion = INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION;
    tx.nTime = nTime;
    tx.privacyVNext.vchPayload = payload;
    return tx;
}

} // namespace

BOOST_AUTO_TEST_SUITE(privacy_vnext_collateral_tests)

// An attestation names a note without spending it: its key image goes to the watch set,
// never the spent-key index, or the collateral becomes unspendable.
BOOST_AUTO_TEST_CASE(an_attestation_is_watched_and_never_spent)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0x41, kTier, note, error), error);

    const PrivacyVNextDigest context = CollateralDigest(0xa7);
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), context, note.spend, payload, keyImage, error),
        error);

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation extracted =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects);
    BOOST_REQUIRE_MESSAGE(extracted.IsValid(), extracted.strError);

    // The routing itself: reported as an attestation, absent from the spends.
    BOOST_CHECK_EQUAL(effects.attestationKeyImages.size(), 1U);
    BOOST_CHECK_EQUAL(effects.keyImages.size(), 0U);
    BOOST_CHECK(effects.attestationKeyImages[0] == keyImage);
    BOOST_CHECK(effects.registrationContext == context);
    // Nothing is created and nothing crosses the boundary.
    BOOST_CHECK_EQUAL(effects.outputLeaves.size(), 0U);
    BOOST_CHECK_EQUAL(effects.nTransparentValueBalance, 0);
    BOOST_CHECK_EQUAL(effects.nFee, 0U);
    BOOST_CHECK_EQUAL(effects.PoolDelta(), 0);

    const uint256 watched = AsUint256(keyImage);
    const CTransaction tx = CarryingTx(payload, 1500000001);
    std::set<uint256> setBlockAttestations;
    bool fLocalFailure = false;
    BOOST_REQUIRE_MESSAGE(
        ConnectPrivacyVNextAttestations(txdb, tx, effects, 900, false,
                                        setBlockAttestations, fLocalFailure,
                                        error),
        error);

    // Both halves of the rule, asserted against the persisted indexes.
    CPrivacyVNextCollateralAttestation attested;
    BOOST_CHECK_EQUAL(txdb.ReadPrivacyVNextCollateralStatus(watched, attested),
                      TXDB_READ_FOUND);
    BOOST_CHECK(attested.txnHash == tx.GetHash());
    BOOST_CHECK(attested.contextDigest == AsUint256(context));
    CShieldedNullifierSpent spent;
    BOOST_CHECK_EQUAL(txdb.ReadPrivacyVNextNullifierStatus(watched, spent),
                      TXDB_READ_NOT_FOUND);

    CPrivacyVNextCollateralAttestation live;
    BOOST_CHECK(IsPrivacyVNextCollateralRegistered(txdb, watched, live,
                                                   fLocalFailure));
    BOOST_CHECK(!fLocalFailure);

    // Disconnecting the attestation leaves neither index holding anything.
    BOOST_REQUIRE_MESSAGE(
        DisconnectPrivacyVNextAttestations(txdb, tx, effects, error), error);
    BOOST_CHECK_EQUAL(txdb.ReadPrivacyVNextCollateralStatus(watched, attested),
                      TXDB_READ_NOT_FOUND);
    BOOST_CHECK(!IsPrivacyVNextCollateralRegistered(txdb, watched, live,
                                                    fLocalFailure));
}

// The tier is proved, never published. Nothing but the proof separates a note holding
// exactly 25,000 INN from one holding a coin less or a coin more.
BOOST_AUTO_TEST_CASE(only_the_collateral_tier_can_be_attested)
{
    CTxDB txdb("r+");
    std::string error;
    const PrivacyVNextDigest context = CollateralDigest(0xb3);

    // A note of the tier attests; the same construction one atom either side does not.
    // The declared amount is forced to the tier in every case, so what fails is the
    // proof over the commitment and not a bookkeeping check on the caller's own number.
    const uint64_t vOffTier[] = { kTier - 1, kTier + 1 };
    for (size_t i = 0; i < 2; ++i)
    {
        FundedNote note;
        BOOST_REQUIRE_MESSAGE(
            FundNote(txdb, (unsigned char)(0x51 + i), vOffTier[i], note, error),
            error);
        BOOST_CHECK_EQUAL(note.spend.nAmount, vOffTier[i]);
        note.spend.nAmount = kTier;

        std::vector<unsigned char> payload;
        PrivacyVNextDigest keyImage;
        BOOST_CHECK_MESSAGE(
            !BuildPrivacyVNextCollateralAttestationPayload(
                LocalNetwork(), LocalGenesis(), note.finalizedRoot,
                note.nTreeSize, NoTransparentSide(), context, note.spend,
                payload, keyImage, error),
            "a note off the tier must not produce an attestation");
        BOOST_CHECK(payload.empty());
    }

    FundedNote tier;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0x53, kTier, tier, error), error);
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), tier.finalizedRoot, tier.nTreeSize,
            NoTransparentSide(), context, tier.spend, payload, keyImage, error),
        error);
    BOOST_CHECK(ValidatePrivacyVNextPayload(
                    INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload)
                    .IsValid());

    // The tier proof is the last but one length-prefixed section: the payload ends with
    // the 64-byte operation proof and an empty disclosure section.
    BOOST_REQUIRE(payload.size() > 66);
    BOOST_REQUIRE_EQUAL(payload[payload.size() - 1], 0);
    const size_t nProofAt = payload.size() - 65;
    BOOST_REQUIRE_EQUAL(payload[nProofAt - 1],
                        (unsigned char)INNOVA_PRIVACY_VNEXT_AMOUNT_EQUALITY_PROOF_SIZE);

    // A proof that is not the one this payload's commitment admits is refused, whichever
    // byte of it is wrong.
    for (size_t i = 0; i < 64; i += 21)
    {
        std::vector<unsigned char> tampered = payload;
        tampered[nProofAt + i] ^= 1;
        BOOST_CHECK_MESSAGE(
            !ValidatePrivacyVNextPayload(
                 INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, tampered)
                 .IsValid(),
            "an altered tier proof must not be accepted");
    }

    // Mix and match: a real proof made over a second tier note's own commitment, spliced
    // into this payload. Both notes hold exactly 25,000, so only the binding to this
    // instance separates them.
    FundedNote other;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0x59, kTier, other, error), error);
    std::vector<unsigned char> otherPayload;
    PrivacyVNextDigest otherKeyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), other.finalizedRoot,
            other.nTreeSize, NoTransparentSide(), context, other.spend,
            otherPayload, otherKeyImage, error),
        error);
    BOOST_REQUIRE(otherPayload.size() > 66);
    std::vector<unsigned char> foreign = payload;
    std::copy(otherPayload.end() - 65, otherPayload.end() - 1,
              foreign.begin() + nProofAt);
    BOOST_CHECK_MESSAGE(
        !ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                     foreign)
             .IsValid(),
        "a tier proof made against a foreign commitment must not be accepted");
}

// The opening is the secret, not the amount: with the opening published anyone tests the
// commitment against every leaf in the tree and the note is identified. An attestation
// carries no disclosure section at all, and nothing in it opens the commitment.
BOOST_AUTO_TEST_CASE(an_attestation_publishes_no_opening)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0x61, kTier, note, error), error);
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), CollateralDigest(0xc1), note.spend, payload,
            keyImage, error),
        error);

    // The mask this payload could have leaked is the note's own and the re-randomized one
    // the tier proof knows; neither appears anywhere in the serialized bytes, and neither
    // does the leaf the attestation names.
    const PrivacyVNextDigest& mask = note.spend.mask;
    BOOST_CHECK(std::search(payload.begin(), payload.end(), mask.begin(),
                            mask.end()) == payload.end());
    BOOST_CHECK(std::search(payload.begin(), payload.end(),
                            note.encrypted.leaf.commitment.begin(),
                            note.encrypted.leaf.commitment.end()) ==
                payload.end());
    BOOST_CHECK(std::search(payload.begin(), payload.end(),
                            note.encrypted.leaf.owner.begin(),
                            note.encrypted.leaf.owner.end()) == payload.end());
    // Nor is the amount itself on the wire.
    std::vector<unsigned char> tierBytes(8, 0);
    for (size_t i = 0; i < 8; ++i)
        tierBytes[i] = (unsigned char)(kTier >> (8 * i));
    BOOST_CHECK(std::search(payload.begin(), payload.end(), tierBytes.begin(),
                            tierBytes.end()) == payload.end());
}

// One node per note, and never a node whose collateral is already gone.
BOOST_AUTO_TEST_CASE(a_note_is_attested_once_and_only_while_unspent)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0x71, kTier, note, error), error);
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), CollateralDigest(0xd1), note.spend, payload,
            keyImage, error),
        error);
    PrivacyVNextStateEffects effects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload,
                      effects)
                      .IsValid());

    const uint256 watched = AsUint256(keyImage);
    const CTransaction first = CarryingTx(payload, 1500000002);
    bool fLocalFailure = false;

    // Twice in one block, caught before anything is written.
    {
        std::set<uint256> setBlock;
        BOOST_CHECK(ConnectPrivacyVNextAttestations(txdb, first, effects, 901,
                                                    true, setBlock,
                                                    fLocalFailure, error));
        BOOST_CHECK(!ConnectPrivacyVNextAttestations(txdb, first, effects, 901,
                                                     true, setBlock,
                                                     fLocalFailure, error));
        BOOST_CHECK(!fLocalFailure);
    }

    // Twice across blocks, caught against the persisted watch set.
    {
        std::set<uint256> setBlock;
        BOOST_REQUIRE(ConnectPrivacyVNextAttestations(txdb, first, effects, 901,
                                                      false, setBlock,
                                                      fLocalFailure, error));
    }
    {
        std::set<uint256> setBlock;
        const CTransaction second = CarryingTx(payload, 1500000003);
        BOOST_CHECK(!ConnectPrivacyVNextAttestations(txdb, second, effects, 902,
                                                     false, setBlock,
                                                     fLocalFailure, error));
        BOOST_CHECK(!fLocalFailure);
    }
    BOOST_REQUIRE(DisconnectPrivacyVNextAttestations(txdb, first, effects,
                                                     error));

    // An attestation over a note the chain has already seen spent proves nothing about
    // live collateral.
    CShieldedNullifierSpent spent;
    spent.txnHash = uint256(1);
    spent.nIndex = 0;
    BOOST_REQUIRE(txdb.WritePrivacyVNextNullifier(watched, spent));
    {
        std::set<uint256> setBlock;
        BOOST_CHECK(!ConnectPrivacyVNextAttestations(txdb, first, effects, 903,
                                                     false, setBlock,
                                                     fLocalFailure, error));
        BOOST_CHECK(!fLocalFailure);
    }
    BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(watched));
}

// Registration is derived from the two indexes rather than stored, so a spend deregisters
// on its own, is never refused, and a reorg that reorders the attestation and the spend
// lands the same way whichever order a node replays them in.
BOOST_AUTO_TEST_CASE(a_spend_deregisters_and_a_reorg_restores)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0x81, kTier, note, error), error);
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), CollateralDigest(0xe1), note.spend, payload,
            keyImage, error),
        error);
    PrivacyVNextStateEffects effects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload,
                      effects)
                      .IsValid());

    const uint256 watched = AsUint256(keyImage);
    const CTransaction attestation = CarryingTx(payload, 1500000004);
    CPrivacyVNextCollateralAttestation live;
    bool fLocalFailure = false;

    std::set<uint256> setBlock;
    BOOST_REQUIRE(ConnectPrivacyVNextAttestations(txdb, attestation, effects,
                                                  910, false, setBlock,
                                                  fLocalFailure, error));
    BOOST_CHECK(IsPrivacyVNextCollateralRegistered(txdb, watched, live,
                                                   fLocalFailure));

    // The spend is an ordinary one: it writes the spent-key index and consults nothing
    // about registration, so there is no path by which it could be blocked.
    CShieldedNullifierSpent spent;
    spent.txnHash = uint256(7);
    spent.nIndex = 0;
    BOOST_REQUIRE(txdb.WritePrivacyVNextNullifier(watched, spent));
    BOOST_CHECK(!IsPrivacyVNextCollateralRegistered(txdb, watched, live,
                                                    fLocalFailure));
    BOOST_CHECK(!fLocalFailure);
    // Deregistration removed nothing: the attestation is still on record.
    CPrivacyVNextCollateralAttestation attested;
    BOOST_CHECK_EQUAL(txdb.ReadPrivacyVNextCollateralStatus(watched, attested),
                      TXDB_READ_FOUND);

    // Disconnect the spend, as a reorg dropping the spending block does.
    BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(watched));
    BOOST_CHECK(IsPrivacyVNextCollateralRegistered(txdb, watched, live,
                                                   fLocalFailure));

    // Replayed the other way round, the spend lands first and the attestation is then
    // simply invalid, so both orders end with the node not registered.
    BOOST_REQUIRE(DisconnectPrivacyVNextAttestations(txdb, attestation, effects,
                                                     error));
    BOOST_REQUIRE(txdb.WritePrivacyVNextNullifier(watched, spent));
    {
        std::set<uint256> setReplay;
        BOOST_CHECK(!ConnectPrivacyVNextAttestations(txdb, attestation, effects,
                                                     911, false, setReplay,
                                                     fLocalFailure, error));
    }
    BOOST_CHECK(!IsPrivacyVNextCollateralRegistered(txdb, watched, live,
                                                    fLocalFailure));
    BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(watched));
}

// A transfer's authorization proof must not be repackaged as an attestation, and one
// node's attestation must not be replayed under another node's identity. Both are the same
// binding: the registration context sits inside the prefix the signing hash covers.
BOOST_AUTO_TEST_CASE(an_attestation_is_bound_to_one_registration_context)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0x91, kTier, note, error), error);
    const PrivacyVNextDigest context = CollateralDigest(0xf1);
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), context, note.spend, payload, keyImage, error),
        error);
    BOOST_REQUIRE(ValidatePrivacyVNextPayload(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload)
                      .IsValid());

    // Restating the context in place leaves every proof made over the old one.
    std::vector<unsigned char>::iterator at =
        std::search(payload.begin(), payload.end(), context.begin(),
                    context.end());
    BOOST_REQUIRE(at != payload.end());
    std::vector<unsigned char> replayed = payload;
    replayed[at - payload.begin()] ^= 0xff;
    BOOST_CHECK_MESSAGE(
        !ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                     replayed)
             .IsValid(),
        "an attestation must not be replayed under another node's context");

    // An attestation with no context at all is not a well-formed one.
    std::vector<unsigned char> blank = payload;
    for (size_t i = 0; i < context.size(); ++i)
        blank[(at - payload.begin()) + i] = 0;
    BOOST_CHECK(!ValidatePrivacyVNextPayload(
                     INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, blank)
                     .IsValid());

    // A transfer over the same note carries the same kind of proof and never becomes an
    // attestation: the operation byte is inside the signing hash too.
    std::vector<PrivacyVNextSpendNote> spends;
    spends.resize(1);
    spends[0].spendSecret = note.spend.spendSecret;
    spends[0].y = note.spend.y;
    spends[0].mask = note.spend.mask;
    spends[0].nAmount = note.spend.nAmount;
    spends[0].leaf = note.spend.leaf;
    spends[0].vchWitnessRecord = note.spend.vchWitnessRecord;
    std::vector<PrivacyVNextNewOutput> outs;
    outs.resize(1);
    outs[0].recipient.nNetwork = LocalNetwork();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = note.keys.spendPublic;
    outs[0].recipient.viewPublic = note.keys.viewPublic;
    outs[0].nAmount = kTier - 100;
    std::vector<unsigned char> transfer;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(
            LocalNetwork(), 7, LocalGenesis(), note.keys.outgoingViewSecret,
            note.finalizedRoot, note.nTreeSize, NoTransparentSide(), 100,
            spends, outs, transfer, error),
        error);

    // A transfer's key image is a spend and is reported as one, never as an attestation.
    PrivacyVNextStateEffects spendEffects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, transfer,
                      spendEffects)
                      .IsValid());
    BOOST_CHECK_EQUAL(spendEffects.keyImages.size(), 1U);
    BOOST_CHECK_EQUAL(spendEffects.attestationKeyImages.size(), 0U);
    BOOST_CHECK(spendEffects.keyImages[0] == keyImage);

    // Relabelling that transfer as an attestation invalidates it: the operation byte is
    // the third byte of the payload and every proof binds the prefix that carries it.
    std::vector<unsigned char> relabelled = transfer;
    relabelled[2] = 8;
    BOOST_CHECK_MESSAGE(
        !ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                     relabelled)
             .IsValid(),
        "a transfer must not become an attestation by relabelling");
}

namespace
{

// What CTxMemPool::accept writes once a transaction is admitted, so the policy helpers
// below are exercised against the same bookkeeping the real path keeps.
void ReserveInMempool(CTransaction& tx, const PrivacyVNextStateEffects& effects)
{
    const uint256 hash = tx.GetHash();
    LOCK(mempool.cs);
    mempool.addUnchecked(hash, tx);

    std::vector<uint256> vKeyImages;
    for (size_t i = 0; i < effects.keyImages.size(); ++i)
    {
        CShieldedNullifierSpent spent;
        spent.txnHash = hash;
        spent.nIndex = i;
        vKeyImages.push_back(AsUint256(effects.keyImages[i]));
        mempool.mapPrivacyVNextNullifier[vKeyImages.back()] = spent;
    }
    mempool.mapPrivacyVNextTxNullifiers[hash] = vKeyImages;

    std::vector<uint256> vBases;
    for (size_t i = 0; i < effects.outputLeaves.size(); ++i)
    {
        CShieldedNullifierSpent created;
        created.txnHash = hash;
        created.nIndex = i;
        vBases.push_back(AsUint256(effects.outputLeaves[i].nullifierBase));
        mempool.mapPrivacyVNextOutputBase[vBases.back()] = created;
    }
    mempool.mapPrivacyVNextTxOutputBases[hash] = vBases;

    std::vector<uint256> vAttestations;
    for (size_t i = 0; i < effects.attestationKeyImages.size(); ++i)
    {
        CShieldedNullifierSpent attested;
        attested.txnHash = hash;
        attested.nIndex = i;
        vAttestations.push_back(AsUint256(effects.attestationKeyImages[i]));
        mempool.mapPrivacyVNextAttestation[vAttestations.back()] = attested;
    }
    mempool.mapPrivacyVNextTxAttestations[hash] = vAttestations;
}

} // namespace

// A spend and an attestation of one key image must never share the mempool; the
// attestation always gives way.
BOOST_AUTO_TEST_CASE(a_spend_and_an_attestation_of_one_note_never_wait_together)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xb1, kTier, note, error), error);

    std::vector<unsigned char> attestationPayload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), CollateralDigest(0xb2), note.spend,
            attestationPayload, keyImage, error),
        error);

    std::vector<PrivacyVNextSpendNote> spends;
    spends.push_back(note.spend);
    std::vector<PrivacyVNextNewOutput> outs(1);
    outs[0].recipient.nNetwork = LocalNetwork();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = note.keys.spendPublic;
    outs[0].recipient.viewPublic = note.keys.viewPublic;
    outs[0].nAmount = kTier - 100;
    std::vector<unsigned char> spendPayload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(
            LocalNetwork(), 7, LocalGenesis(), note.keys.outgoingViewSecret,
            note.finalizedRoot, note.nTreeSize, NoTransparentSide(), 100,
            spends, outs, spendPayload, error),
        error);

    PrivacyVNextStateEffects attestationEffects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                      attestationPayload, attestationEffects)
                      .IsValid());
    PrivacyVNextStateEffects spendEffects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, spendPayload,
                      spendEffects)
                      .IsValid());
    BOOST_REQUIRE_EQUAL(attestationEffects.attestationKeyImages.size(), 1U);
    BOOST_REQUIRE_EQUAL(spendEffects.keyImages.size(), 1U);
    // The same note, so the same key image on both sides.
    BOOST_REQUIRE(spendEffects.keyImages[0] ==
                  attestationEffects.attestationKeyImages[0]);
    const uint256 watched = AsUint256(keyImage);

    CTransaction attestation = CarryingTx(attestationPayload, 1500000020);
    CTransaction spend = CarryingTx(spendPayload, 1500000021);

    mempool.clear();
    ReserveInMempool(attestation, attestationEffects);
    BOOST_REQUIRE_EQUAL(mempool.size(), 1U);
    // Nothing spends it yet, so an arriving attestation would be admitted.
    BOOST_CHECK(!mempool.HasPendingPrivacyVNextSpend(watched));

    // The spend arrives: the attestation can no longer connect and is dropped, with its
    // reservation released.
    BOOST_CHECK_EQUAL(mempool.EvictPrivacyVNextAttestationsSpentBy(
                          std::vector<uint256>(1, watched), spend.GetHash()),
                      1U);
    BOOST_CHECK_EQUAL(mempool.size(), 0U);
    BOOST_CHECK_EQUAL(mempool.mapPrivacyVNextAttestation.count(watched), 0U);
    BOOST_CHECK_EQUAL(mempool.mapPrivacyVNextTxAttestations.count(
                          attestation.GetHash()), 0U);
    // The reverse bookkeeping stayed consistent; remove() halts the node if it does not.
    BOOST_CHECK(!fRequestShutdown);

    // With the spend reserved, an attestation of the same note is the one refused.
    ReserveInMempool(spend, spendEffects);
    BOOST_CHECK(mempool.HasPendingPrivacyVNextSpend(watched));
    BOOST_CHECK_EQUAL(mempool.EvictPrivacyVNextAttestationsSpentBy(
                          std::vector<uint256>(1, watched), spend.GetHash()),
                      0U);
    BOOST_CHECK_EQUAL(mempool.size(), 1U);

    mempool.clear();
}

BOOST_AUTO_TEST_SUITE_END()
