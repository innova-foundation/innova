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

#include <algorithm>

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

// A canonical compressed secp256k1 key whose private half this process holds, so the
// registration a test builds is one a real member could decrypt shares for.
std::vector<unsigned char> MemberKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key.GetPubKey().Raw();
}

// Regtest fork height for note-weighted finality, restored on scope exit.
struct ScopedNoteVoteHeight
{
    int nSaved;
    explicit ScopedNoteVoteHeight(int nHeight)
        : nSaved(nRegtestIV5NoteVoteHeight)
    {
        nRegtestIV5NoteVoteHeight = nHeight;
    }
    ~ScopedNoteVoteHeight() { nRegtestIV5NoteVoteHeight = nSaved; }
};

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

// The registry's whole point: the key other voters seal their tally shares to has to
// survive the payload, the decoder and the index byte for byte. Nothing can be encrypted
// to a digest, so a member registration that arrived as a hash would be a committee seat
// nobody could reach.
//
// Mutation proving this: drop `member_key` from PayloadEffects::encode in payload.rs, or
// stop copying it in ExtractPrivacyVNextPayloadEffectsUncached, or drop vchMemberKey from
// the row the connect path writes -- each fails a different assertion below.
BOOST_AUTO_TEST_CASE(a_member_key_survives_the_payload_and_the_index)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xc5, kTier, note, error), error);

    const std::vector<unsigned char> vchMember = MemberKey();
    BOOST_REQUIRE_EQUAL(vchMember.size(), (size_t)iv5::FINALITY_MEMBER_KEY_BYTES);
    BOOST_REQUIRE(IsPrivacyVNextMemberKeyOnCurve(&vchMember[0], vchMember.size()));

    const PrivacyVNextDigest context = CollateralDigest(0xc6);
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextFinalityMemberRegistrationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), context, vchMember, note.spend, payload,
            keyImage, error),
        error);

    // The registration declares operation 9, which is what carries the extra field.
    uint8_t nOperation = 0;
    uint8_t nMask = 0;
    BOOST_REQUIRE(iv5::ReadDeclaredEnvelope(&payload[0], payload.size(), nOperation,
                                            nMask));
    BOOST_CHECK_EQUAL((int)nOperation, (int)iv5::NOTE_FINALITY_MEMBER_REGISTER);
    BOOST_CHECK_EQUAL((int)nMask, (int)iv5::DISCLOSURE_MASK);

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation extracted =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects);
    BOOST_REQUIRE_MESSAGE(extracted.IsValid(), extracted.strError);

    // Same routing as a collateralnode attestation: watched, never spent.
    BOOST_CHECK_EQUAL(effects.attestationKeyImages.size(), 1U);
    BOOST_CHECK_EQUAL(effects.keyImages.size(), 0U);
    BOOST_CHECK_EQUAL(effects.outputLeaves.size(), 0U);
    BOOST_CHECK_EQUAL(effects.PoolDelta(), 0);
    BOOST_CHECK(effects.registrationContext == context);
    // The key, unchanged, through the decoder.
    BOOST_CHECK(effects.HasMemberKey());
    BOOST_CHECK(std::equal(effects.memberKey.begin(), effects.memberKey.end(),
                           vchMember.begin()));

    const uint256 watched = AsUint256(keyImage);
    const CTransaction tx = CarryingTx(payload, 1500000030);
    std::set<uint256> setBlock;
    bool fLocalFailure = false;
    BOOST_REQUIRE_MESSAGE(
        ConnectPrivacyVNextAttestations(txdb, tx, effects, 950, false, setBlock,
                                        fLocalFailure, error),
        error);

    // And unchanged again through the index.
    CPrivacyVNextCollateralAttestation attested;
    BOOST_REQUIRE_EQUAL(txdb.ReadPrivacyVNextCollateralStatus(watched, attested),
                        TXDB_READ_FOUND);
    BOOST_CHECK(attested.IsFinalityMember());
    BOOST_CHECK(attested.vchMemberKey == vchMember);
    BOOST_CHECK(attested.contextDigest == AsUint256(context));
    BOOST_CHECK_EQUAL(attested.nHeight, 950);
    CShieldedNullifierSpent spent;
    BOOST_CHECK_EQUAL(txdb.ReadPrivacyVNextNullifierStatus(watched, spent),
                      TXDB_READ_NOT_FOUND);

    // Exact inverse: the row and the key go together, and nothing is left behind.
    BOOST_REQUIRE_MESSAGE(
        DisconnectPrivacyVNextAttestations(txdb, tx, effects, error), error);
    BOOST_CHECK_EQUAL(txdb.ReadPrivacyVNextCollateralStatus(watched, attested),
                      TXDB_READ_NOT_FOUND);

    // The key is bound inside the signing hash, so it cannot be swapped after the
    // collateral was proved.
    std::vector<unsigned char>::iterator at =
        std::search(payload.begin(), payload.end(), vchMember.begin(),
                    vchMember.end());
    BOOST_REQUIRE(at != payload.end());
    std::vector<unsigned char> swapped = payload;
    swapped[(at - payload.begin()) + 1] ^= 0x01;
    BOOST_CHECK_MESSAGE(
        !ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                     swapped)
             .IsValid(),
        "a member key must not be replaceable after the proof is made");
}

// One quantum of collateral buys one service slot. A note registered either way can never
// be registered again, in either direction, because a second registration would let one
// 25000 INN note hold two seats.
//
// Mutation proving this: drop the prior-row check in ConnectPrivacyVNextAttestations, or
// key the row on anything but the key image -- either lets the second registration land.
BOOST_AUTO_TEST_CASE(a_note_holds_one_registration_across_both_operations)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xd5, kTier, note, error), error);
    const std::vector<unsigned char> vchMember = MemberKey();

    std::vector<unsigned char> collateralPayload;
    PrivacyVNextDigest collateralKeyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), CollateralDigest(0xd6), note.spend,
            collateralPayload, collateralKeyImage, error),
        error);
    std::vector<unsigned char> memberPayload;
    PrivacyVNextDigest memberKeyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextFinalityMemberRegistrationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), CollateralDigest(0xd7), vchMember, note.spend,
            memberPayload, memberKeyImage, error),
        error);
    // One note, so one key image whichever way it registers: that is what makes the
    // two operations compete for the same slot.
    BOOST_REQUIRE(collateralKeyImage == memberKeyImage);

    PrivacyVNextStateEffects collateralEffects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                      collateralPayload, collateralEffects)
                      .IsValid());
    PrivacyVNextStateEffects memberEffects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, memberPayload,
                      memberEffects)
                      .IsValid());
    BOOST_CHECK(!collateralEffects.HasMemberKey());
    BOOST_CHECK(memberEffects.HasMemberKey());

    const uint256 watched = AsUint256(memberKeyImage);
    const CTransaction collateralTx = CarryingTx(collateralPayload, 1500000040);
    const CTransaction memberTx = CarryingTx(memberPayload, 1500000041);
    bool fLocalFailure = false;

    // Member first, then the collateralnode attestation is refused.
    {
        std::set<uint256> setBlock;
        BOOST_REQUIRE(ConnectPrivacyVNextAttestations(
            txdb, memberTx, memberEffects, 960, false, setBlock, fLocalFailure,
            error));
    }
    {
        std::set<uint256> setBlock;
        BOOST_CHECK(!ConnectPrivacyVNextAttestations(
            txdb, collateralTx, collateralEffects, 961, false, setBlock,
            fLocalFailure, error));
        BOOST_CHECK(!fLocalFailure);
    }
    // The refusal changed nothing: the member row is still the one on record.
    CPrivacyVNextCollateralAttestation attested;
    BOOST_REQUIRE_EQUAL(txdb.ReadPrivacyVNextCollateralStatus(watched, attested),
                        TXDB_READ_FOUND);
    BOOST_CHECK(attested.vchMemberKey == vchMember);
    BOOST_REQUIRE(DisconnectPrivacyVNextAttestations(txdb, memberTx,
                                                     memberEffects, error));

    // And the other way round.
    {
        std::set<uint256> setBlock;
        BOOST_REQUIRE(ConnectPrivacyVNextAttestations(
            txdb, collateralTx, collateralEffects, 962, false, setBlock,
            fLocalFailure, error));
    }
    {
        std::set<uint256> setBlock;
        BOOST_CHECK(!ConnectPrivacyVNextAttestations(
            txdb, memberTx, memberEffects, 963, false, setBlock, fLocalFailure,
            error));
    }
    BOOST_REQUIRE_EQUAL(txdb.ReadPrivacyVNextCollateralStatus(watched, attested),
                        TXDB_READ_FOUND);
    BOOST_CHECK(!attested.IsFinalityMember());
    BOOST_REQUIRE(DisconnectPrivacyVNextAttestations(txdb, collateralTx,
                                                     collateralEffects, error));
    BOOST_CHECK_EQUAL(txdb.ReadPrivacyVNextCollateralStatus(watched, attested),
                      TXDB_READ_NOT_FOUND);
}

// The registry rides note-weighted finality and nothing reaches chain state below it. A
// collateralnode attestation is untouched by that height, because it is not what the
// committee draws from.
//
// Mutation proving this: delete the IsIV5NoteVoteActiveAtHeight guard in
// ConnectPrivacyVNextAttestations and the below-fork registrations start connecting.
BOOST_AUTO_TEST_CASE(a_member_registration_is_unreachable_below_its_fork)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xe5, kTier, note, error), error);
    const std::vector<unsigned char> vchMember = MemberKey();

    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    {
        ScopedNoteVoteHeight fork(0);
        BOOST_REQUIRE_MESSAGE(
            BuildPrivacyVNextFinalityMemberRegistrationPayload(
                LocalNetwork(), LocalGenesis(), note.finalizedRoot,
                note.nTreeSize, NoTransparentSide(), CollateralDigest(0xe6),
                vchMember, note.spend, payload, keyImage, error),
            error);
    }
    PrivacyVNextStateEffects effects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects)
                      .IsValid());
    const uint256 watched = AsUint256(keyImage);
    const CTransaction tx = CarryingTx(payload, 1500000050);
    bool fLocalFailure = false;

    // Unset on every public network, which is where this build stands today.
    {
        ScopedNoteVoteHeight fork(PRIVACY_VNEXT_HEIGHT_UNSET);
        BOOST_REQUIRE(!IsIV5NoteVoteConfigured());
        std::set<uint256> setBlock;
        BOOST_CHECK_MESSAGE(
            !ConnectPrivacyVNextAttestations(txdb, tx, effects, 970, false,
                                             setBlock, fLocalFailure, error),
            "a member registration must be unreachable where the fork is unset");
        BOOST_CHECK(!fLocalFailure);
        CPrivacyVNextCollateralAttestation unwritten;
        BOOST_CHECK_EQUAL(
            txdb.ReadPrivacyVNextCollateralStatus(watched, unwritten),
            TXDB_READ_NOT_FOUND);
    }

    // Configured, but one block short of it.
    {
        ScopedNoteVoteHeight fork(971);
        std::set<uint256> setBlock;
        BOOST_CHECK(!ConnectPrivacyVNextAttestations(txdb, tx, effects, 970,
                                                     false, setBlock,
                                                     fLocalFailure, error));
        CPrivacyVNextCollateralAttestation attested;
        BOOST_CHECK_EQUAL(
            txdb.ReadPrivacyVNextCollateralStatus(watched, attested),
            TXDB_READ_NOT_FOUND);
    }

    // At the fork height itself it connects.
    {
        ScopedNoteVoteHeight fork(971);
        std::set<uint256> setBlock;
        BOOST_REQUIRE_MESSAGE(
            ConnectPrivacyVNextAttestations(txdb, tx, effects, 971, false,
                                            setBlock, fLocalFailure, error),
            error);
        BOOST_REQUIRE(DisconnectPrivacyVNextAttestations(txdb, tx, effects,
                                                         error));
    }

    // A collateralnode attestation of the same note is not gated by that height: it
    // backs a service the committee draw does not read.
    std::vector<unsigned char> collateralPayload;
    PrivacyVNextDigest collateralKeyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), CollateralDigest(0xe7), note.spend,
            collateralPayload, collateralKeyImage, error),
        error);
    PrivacyVNextStateEffects collateralEffects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                      collateralPayload, collateralEffects)
                      .IsValid());
    {
        ScopedNoteVoteHeight fork(PRIVACY_VNEXT_HEIGHT_UNSET);
        std::set<uint256> setBlock;
        BOOST_REQUIRE(ConnectPrivacyVNextAttestations(
            txdb, CarryingTx(collateralPayload, 1500000051), collateralEffects,
            970, false, setBlock, fLocalFailure, error));
        BOOST_REQUIRE(DisconnectPrivacyVNextAttestations(
            txdb, CarryingTx(collateralPayload, 1500000051), collateralEffects,
            error));
    }
}

// The snapshot the committee draw will consume. It answers from the two indexes and the
// height it is handed, and from nothing the node happens to have seen: an anchor taken
// from live node state is what splits a chain.
//
// Mutation proving this: drop the `nHeight > nAnchorHeight` filter and a registration
// made after the anchor appears in it; drop the spent-index consultation and a spent
// collateral keeps its seat; drop the sort and the sequence follows leveldb.
BOOST_AUTO_TEST_CASE(a_registry_snapshot_is_anchored_and_ordered)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    std::string error;
    bool fLocalFailure = false;

    // Anything an earlier case left behind is not this case's to reason about.
    std::vector<CPrivacyVNextRegistryEntry> vPrior;
    BOOST_REQUIRE(GetPrivacyVNextCollateralSnapshot(
        txdb, std::numeric_limits<int>::max(), false, vPrior, fLocalFailure,
        error));
    const size_t nPriorAll = vPrior.size();
    BOOST_REQUIRE(GetPrivacyVNextCollateralSnapshot(
        txdb, std::numeric_limits<int>::max(), true, vPrior, fLocalFailure,
        error));
    const size_t nPriorMembers = vPrior.size();

    // Two members and one collateralnode, at three separate heights.
    struct Registered
    {
        uint256 watched;
        CTransaction tx;
        PrivacyVNextStateEffects effects;
    };
    std::vector<Registered> vMade;
    std::vector<unsigned char> vchFirstMember;
    for (int i = 0; i < 3; ++i)
    {
        FundedNote note;
        BOOST_REQUIRE_MESSAGE(
            FundNote(txdb, (unsigned char)(0xf0 + i), kTier, note, error),
            error);
        const bool fMember = i < 2;
        const std::vector<unsigned char> vchMember =
            fMember ? MemberKey()
                    : std::vector<unsigned char>();
        if (i == 0)
            vchFirstMember = vchMember;
        std::vector<unsigned char> payload;
        PrivacyVNextDigest keyImage;
        const bool fBuilt =
            fMember
                ? BuildPrivacyVNextFinalityMemberRegistrationPayload(
                      LocalNetwork(), LocalGenesis(), note.finalizedRoot,
                      note.nTreeSize, NoTransparentSide(),
                      CollateralDigest((unsigned char)(0x20 + i)), vchMember,
                      note.spend, payload, keyImage, error)
                : BuildPrivacyVNextCollateralAttestationPayload(
                      LocalNetwork(), LocalGenesis(), note.finalizedRoot,
                      note.nTreeSize, NoTransparentSide(),
                      CollateralDigest((unsigned char)(0x20 + i)), note.spend,
                      payload, keyImage, error);
        BOOST_REQUIRE_MESSAGE(fBuilt, error);

        Registered made;
        BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                          INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload,
                          made.effects)
                          .IsValid());
        made.watched = AsUint256(keyImage);
        made.tx = CarryingTx(payload, 1500000060 + i);
        std::set<uint256> setBlock;
        BOOST_REQUIRE_MESSAGE(
            ConnectPrivacyVNextAttestations(txdb, made.tx, made.effects,
                                            1000 + i, false, setBlock,
                                            fLocalFailure, error),
            error);
        vMade.push_back(made);
    }

    std::vector<CPrivacyVNextRegistryEntry> vEntries;
    // The anchor bounds by the height a registration was recorded at, not by the tip.
    BOOST_REQUIRE(GetPrivacyVNextCollateralSnapshot(txdb, 999, true, vEntries,
                                                    fLocalFailure, error));
    BOOST_CHECK_EQUAL(vEntries.size(), nPriorMembers);
    BOOST_REQUIRE(GetPrivacyVNextCollateralSnapshot(txdb, 1000, true, vEntries,
                                                    fLocalFailure, error));
    BOOST_CHECK_EQUAL(vEntries.size(), nPriorMembers + 1);
    BOOST_REQUIRE(GetPrivacyVNextCollateralSnapshot(txdb, 1001, true, vEntries,
                                                    fLocalFailure, error));
    BOOST_CHECK_EQUAL(vEntries.size(), nPriorMembers + 2);

    // The collateralnode is a registration but not a committee member.
    BOOST_REQUIRE(GetPrivacyVNextCollateralSnapshot(txdb, 1002, true, vEntries,
                                                    fLocalFailure, error));
    BOOST_CHECK_EQUAL(vEntries.size(), nPriorMembers + 2);
    std::vector<CPrivacyVNextRegistryEntry> vAll;
    BOOST_REQUIRE(GetPrivacyVNextCollateralSnapshot(txdb, 1002, false, vAll,
                                                    fLocalFailure, error));
    BOOST_CHECK_EQUAL(vAll.size(), nPriorAll + 3);

    // Every member row carries a usable key and the height it was recorded at.
    for (size_t i = 0; i < vEntries.size(); ++i)
    {
        BOOST_CHECK(vEntries[i].IsFinalityMember());
        BOOST_CHECK(IsPrivacyVNextMemberKeyOnCurve(&vEntries[i].vchMemberKey[0],
                                                   vEntries[i].vchMemberKey.size()));
        BOOST_CHECK(vEntries[i].nHeight <= 1002);
    }
    // Key-image order, so the draw that consumes this reads one sequence everywhere.
    for (size_t i = 1; i < vEntries.size(); ++i)
        BOOST_CHECK(vEntries[i - 1].keyImage < vEntries[i].keyImage);

    // A member whose collateral is spent loses the seat, with nothing erased for it.
    CShieldedNullifierSpent spent;
    spent.txnHash = uint256(31);
    spent.nIndex = 0;
    BOOST_REQUIRE(txdb.WritePrivacyVNextNullifier(vMade[0].watched, spent));
    BOOST_REQUIRE(GetPrivacyVNextCollateralSnapshot(txdb, 1002, true, vEntries,
                                                    fLocalFailure, error));
    BOOST_CHECK_EQUAL(vEntries.size(), nPriorMembers + 1);
    for (size_t i = 0; i < vEntries.size(); ++i)
        BOOST_CHECK(vEntries[i].keyImage != vMade[0].watched);
    // Disconnecting the spend restores it: nothing about the registration changed.
    BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(vMade[0].watched));
    BOOST_REQUIRE(GetPrivacyVNextCollateralSnapshot(txdb, 1002, true, vEntries,
                                                    fLocalFailure, error));
    BOOST_CHECK_EQUAL(vEntries.size(), nPriorMembers + 2);
    bool fFoundFirst = false;
    for (size_t i = 0; i < vEntries.size(); ++i)
        if (vEntries[i].keyImage == vMade[0].watched)
        {
            fFoundFirst = true;
            BOOST_CHECK(vEntries[i].vchMemberKey == vchFirstMember);
        }
    BOOST_CHECK(fFoundFirst);

    for (size_t i = vMade.size(); i > 0; --i)
        BOOST_REQUIRE(DisconnectPrivacyVNextAttestations(
            txdb, vMade[i - 1].tx, vMade[i - 1].effects, error));
    BOOST_REQUIRE(GetPrivacyVNextCollateralSnapshot(txdb, 1002, false, vAll,
                                                    fLocalFailure, error));
    BOOST_CHECK_EQUAL(vAll.size(), nPriorAll);
}

// A key that names no point on secp256k1 cannot be encrypted to, so a registration
// carrying one is a committee seat its holder could never serve. The Rust decoder proves
// the encoding is canonical and stops there; the on-curve test is the caller's.
//
// Mutation proving this: delete the IsPrivacyVNextMemberKeyOnCurve call in
// ConnectPrivacyVNextAttestations and the off-curve registration connects.
BOOST_AUTO_TEST_CASE(a_member_key_off_the_curve_is_refused)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    std::string error;

    const std::vector<unsigned char> vchMember = MemberKey();
    BOOST_REQUIRE(IsPrivacyVNextMemberKeyOnCurve(&vchMember[0], vchMember.size()));

    // Canonical encoding, x below the field prime, and no y: exactly what Rust admits
    // and the caller must not.
    std::vector<unsigned char> vchOffCurve = vchMember;
    size_t nTries = 0;
    while (IsPrivacyVNextMemberKeyOnCurve(&vchOffCurve[0], vchOffCurve.size()) &&
           nTries < 64)
    {
        vchOffCurve[1 + (nTries % 31)] ^= 0x01;
        ++nTries;
    }
    BOOST_REQUIRE(!IsPrivacyVNextMemberKeyOnCurve(&vchOffCurve[0],
                                                  vchOffCurve.size()));
    BOOST_CHECK_EQUAL(vchOffCurve.size(), (size_t)iv5::FINALITY_MEMBER_KEY_BYTES);

    // The builder refuses it, so a wallet never spends a proof on it.
    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xa5, kTier, note, error), error);
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_CHECK(!BuildPrivacyVNextFinalityMemberRegistrationPayload(
        LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
        NoTransparentSide(), CollateralDigest(0xa6), vchOffCurve, note.spend,
        payload, keyImage, error));
    BOOST_CHECK(payload.empty());

    // And so does consensus, given effects that name it anyway.
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextFinalityMemberRegistrationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), CollateralDigest(0xa6), vchMember, note.spend,
            payload, keyImage, error),
        error);
    PrivacyVNextStateEffects effects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects)
                      .IsValid());
    std::copy(vchOffCurve.begin(), vchOffCurve.end(), effects.memberKey.begin());
    const CTransaction tx = CarryingTx(payload, 1500000070);
    std::set<uint256> setBlock;
    bool fLocalFailure = false;
    BOOST_CHECK(!ConnectPrivacyVNextAttestations(txdb, tx, effects, 980, false,
                                                 setBlock, fLocalFailure,
                                                 error));
    BOOST_CHECK(!fLocalFailure);

    // A payload carrying a non-canonical encoding never gets that far: the decoder
    // refuses it outright, whichever byte is wrong.
    std::vector<unsigned char>::iterator at =
        std::search(payload.begin(), payload.end(), vchMember.begin(),
                    vchMember.end());
    BOOST_REQUIRE(at != payload.end());
    const size_t nKeyAt = at - payload.begin();
    for (int nPrefix = 0; nPrefix < 8; ++nPrefix)
    {
        if (nPrefix == 2 || nPrefix == 3)
            continue;
        std::vector<unsigned char> tampered = payload;
        tampered[nKeyAt] = (unsigned char)nPrefix;
        BOOST_CHECK_MESSAGE(
            !ValidatePrivacyVNextPayload(
                 INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, tampered)
                 .IsValid(),
            "only the two parity tags encode a compressed key");
    }
    std::vector<unsigned char> zeroed = payload;
    for (size_t i = 1; i < iv5::FINALITY_MEMBER_KEY_BYTES; ++i)
        zeroed[nKeyAt + i] = 0;
    BOOST_CHECK(!ValidatePrivacyVNextPayload(
                     INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, zeroed)
                     .IsValid());
}


BOOST_AUTO_TEST_SUITE_END()
