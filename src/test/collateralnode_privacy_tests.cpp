#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../collateralnode.h"
#include "../key.h"
#include "../main.h"
#include "../net.h"
#include "../netbase.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../serialize.h"
#include "../txdb.h"

// Private collateralnode registration publishes a key-image pseudonym (mask 7) and,
// on chain, only a digest of (identity, endpoint, payout); which pool note is the
// collateral stays private. Assertions are on the wire.
BOOST_AUTO_TEST_SUITE(collateralnode_privacy_tests)

namespace
{

const uint64_t kTier = INNOVA_PRIVACY_VNEXT_COLLATERAL_ATTESTATION_AMOUNT;

PrivacyVNextDigest FillDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

PrivacyVNextDigest LowScalar(unsigned char low)
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

PrivacyVNextDigest AsDigest(const uint256& value)
{
    PrivacyVNextDigest d;
    std::memcpy(d.data(), value.begin(), 32);
    return d;
}

std::vector<unsigned char> Bytes(const PrivacyVNextDigest& d)
{
    return std::vector<unsigned char>(d.begin(), d.end());
}

std::vector<unsigned char> Bytes(const std::string& str)
{
    return std::vector<unsigned char>(str.begin(), str.end());
}

std::vector<unsigned char> LE64(uint64_t v)
{
    std::vector<unsigned char> out;
    for (size_t i = 0; i < 8; ++i)
        out.push_back((unsigned char)(v >> (8 * i)));
    return out;
}

bool Contains(const std::vector<unsigned char>& haystack,
              const std::vector<unsigned char>& needle)
{
    if (needle.empty())
        return true;
    return std::search(haystack.begin(), haystack.end(), needle.begin(),
                       needle.end()) != haystack.end();
}

// One note of a chosen amount, placed in a fresh tree and reopened by its owner,
// with the membership witness a proof over it needs.
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
    if (!DerivePrivacyVNextKeys(FillDigest(nSeed), genesis, 0, LocalNetwork(), 0,
                                out.keys, error))
        return false;
    if (!EncryptPrivacyVNextNote(
            LocalNetwork(), 0, 0, genesis, out.keys.spendPublic,
            out.keys.viewPublic, out.keys.outgoingViewSecret,
            LowScalar(nSeed + 1), LowScalar(nSeed + 2), nAmount,
            LowScalar(nSeed + 3), LowScalar(nSeed + 4), out.encrypted, error))
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
    if (!ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, LocalNetwork(), 0, onChain,
                              out.keys.viewSecret, out.keys.spendSecret, scanned,
                              error))
        return false;

    out.spend.spendSecret = scanned.spendSecret;
    out.spend.y = scanned.y;
    out.spend.mask = scanned.mask;
    out.spend.nAmount = scanned.nAmount;
    out.spend.leaf = out.encrypted.leaf;
    out.spend.vchWitnessRecord = vWitnesses[0].vchRecord;
    return true;
}

int32_t ValidationResult(const std::vector<unsigned char>& payload)
{
    return ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                       payload)
        .nResult;
}

const int32_t kValid = 0;

// The node identity, endpoint and payout an operator has to publish somewhere.
struct NodeContext
{
    CKey keyCollateralnode;
    CPubKey pubkey2;
    CService addr;
    std::string strPoolPayout;
    uint256 digest;

    NodeContext()
        : addr(CService("203.0.113.7", 15539)),
          strPoolPayout("iRPrivacyPayoutTargetAddressProbe11")
    {
        keyCollateralnode.MakeNewKey(true);
        pubkey2 = keyCollateralnode.GetPubKey();
        digest = GetCollateralnodeRegistrationContext(pubkey2, addr,
                                                      strPoolPayout);
    }
};

// The "isee" announcement exactly as SendCollaTeralElectionEntry pushes it: the
// one message a peer actually receives when a private registration is announced.
std::vector<unsigned char> AnnouncementBytes(const NodeContext& node,
                                             const uint256& keyImage,
                                             const CPubKey& pubkeyAnnounce,
                                             const std::vector<unsigned char>& vchSig,
                                             int64_t nNow)
{
    const CTxIn vin(COutPoint(keyImage, 0));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << vin << node.addr << vchSig << nNow << pubkeyAnnounce << node.pubkey2
       << (int)-1 << (int)-1 << nNow << (int)PROTOCOL_VERSION << keyImage
       << node.strPoolPayout;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

// Where the parameter digest a payload declares sits: schema, six envelope
// bytes, the reserved byte, then the genesis hash.
const size_t kParameterDigestOffset = 2 + 7 + 32;

} // namespace

// The chain carries only the digest of identity, endpoint and payout; the gossip
// announcement carries them in the clear so peers can dial the endpoint.
BOOST_AUTO_TEST_CASE(the_chain_carries_only_the_registration_digest)
{
    CTxDB txdb("r+");
    std::string error;
    const NodeContext node;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xc4, kTier, note, error), error);

    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), AsDigest(node.digest), note.spend, payload,
            keyImage, error),
        error);

    // Positive control: the preimages are all recoverable from the announcement
    // a peer receives, so searching a byte string for them is a search that can
    // succeed.
    CKey keyAnnounce;
    keyAnnounce.MakeNewKey(true);
    const std::vector<unsigned char> vchSig(72, 0x5a);
    uint256 keyImage256;
    std::memcpy(keyImage256.begin(), keyImage.data(), 32);
    const std::vector<unsigned char> announcement = AnnouncementBytes(
        node, keyImage256, keyAnnounce.GetPubKey(), vchSig, 1750000000);

    CDataStream ssAddr(SER_NETWORK, PROTOCOL_VERSION);
    ssAddr << node.addr;
    const std::vector<unsigned char> vchAddr(ssAddr.begin(), ssAddr.end());
    BOOST_CHECK(Contains(announcement, vchAddr));
    BOOST_CHECK(Contains(announcement, Bytes(node.strPoolPayout)));
    BOOST_CHECK(Contains(announcement, node.pubkey2.Raw()));

    // The chain carries the digest of those three and none of the three.
    BOOST_CHECK(Contains(payload, Bytes(AsDigest(node.digest))));
    BOOST_CHECK(!Contains(payload, vchAddr));
    BOOST_CHECK(!Contains(payload, Bytes(node.addr.ToString())));
    BOOST_CHECK(!Contains(payload, Bytes(node.strPoolPayout)));
    BOOST_CHECK(!Contains(payload, node.pubkey2.Raw()));

    // And the digest is what a validator reads back out of the payload, so the
    // absences above are not a search of some other object.
    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation extracted =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects);
    BOOST_REQUIRE_MESSAGE(extracted.IsValid(), extracted.strError);
    BOOST_CHECK(effects.registrationContext == AsDigest(node.digest));
    BOOST_REQUIRE_EQUAL(effects.attestationKeyImages.size(), 1U);
    BOOST_CHECK(effects.attestationKeyImages[0] == keyImage);

    // The digest binds each field on its own: moving only the endpoint, or only
    // the payout, moves it, so neither can be substituted in an announcement and
    // still match the registration.
    BOOST_CHECK(GetCollateralnodeRegistrationContext(
                    node.pubkey2, CService("198.51.100.9", 15539),
                    node.strPoolPayout) != node.digest);
    BOOST_CHECK(GetCollateralnodeRegistrationContext(
                    node.pubkey2, node.addr, node.strPoolPayout + "x") !=
                node.digest);
}

// The announcement publishes the key image and nothing that identifies the pool note.
BOOST_AUTO_TEST_CASE(an_announcement_carries_no_note_material)
{
    CTxDB txdb("r+");
    std::string error;
    const NodeContext node;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xc5, kTier, note, error), error);

    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), AsDigest(node.digest), note.spend, payload,
            keyImage, error),
        error);

    CKey keyAnnounce;
    keyAnnounce.MakeNewKey(true);
    uint256 keyImage256;
    std::memcpy(keyImage256.begin(), keyImage.data(), 32);
    const std::vector<unsigned char> announcement =
        AnnouncementBytes(node, keyImage256, keyAnnounce.GetPubKey(),
                          std::vector<unsigned char>(72, 0x5a), 1750000001);

    // Positive control: the pseudonym is there, twice over -- as the outpoint a
    // peer keys the node by and as the attested key image itself.
    BOOST_CHECK(Contains(announcement, Bytes(keyImage)));

    // Nothing that opens the note is.
    BOOST_CHECK(!Contains(announcement, Bytes(note.spend.mask)));
    BOOST_CHECK(!Contains(announcement, Bytes(note.spend.spendSecret)));
    BOOST_CHECK(!Contains(announcement, Bytes(note.spend.y)));
    BOOST_CHECK(!Contains(announcement, Bytes(note.encrypted.leaf.commitment)));
    BOOST_CHECK(!Contains(announcement, Bytes(note.encrypted.leaf.owner)));
    BOOST_CHECK(!Contains(announcement, note.spend.vchWitnessRecord));
    BOOST_CHECK(!Contains(announcement, note.encrypted.vchRecipientCiphertext));

    // Nor is the tier amount, which is the one number an amount-matching observer
    // would want on the wire.
    BOOST_CHECK(!Contains(announcement, LE64(kTier)));
}

// A shield states its transparent value in the clear, so a fresh shield of exactly the
// tier links to the registration; carving the collateral from an existing pool balance
// avoids that. The registration itself names no amount.
BOOST_AUTO_TEST_CASE(the_funding_shield_is_public_and_the_registration_is_not)
{
    CTxDB txdb("r+");
    std::string error;
    const NodeContext node;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xc6, kTier, note, error), error);

    // Positive control: a shield sized to the tier publishes that number.
    const uint64_t nFee = MIN_TX_FEE;
    const uint64_t nShieldIn = kTier + nFee;
    std::vector<PrivacyVNextNewOutput> outs;
    outs.resize(1);
    outs[0].recipient.nNetwork = LocalNetwork();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = note.keys.spendPublic;
    outs[0].recipient.viewPublic = note.keys.viewPublic;
    outs[0].nAmount = kTier;

    std::vector<unsigned char> shield;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextShieldPayload(
            LocalNetwork(), 7, LocalGenesis(), note.keys.outgoingViewSecret,
            note.finalizedRoot, note.nTreeSize, NoTransparentSide(), nShieldIn,
            nFee, outs, shield, error),
        error);

    PrivacyVNextStateEffects shieldEffects;
    const PrivacyVNextPayloadValidation shieldExtract =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, shield, shieldEffects);
    BOOST_REQUIRE_MESSAGE(shieldExtract.IsValid(), shieldExtract.strError);
    BOOST_CHECK_EQUAL(shieldEffects.nTransparentValueBalance,
                      (int64_t)nShieldIn);
    BOOST_CHECK(Contains(shield, LE64(nShieldIn)));

    // The registration of a note of exactly that amount states no amount.
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), AsDigest(node.digest), note.spend, payload,
            keyImage, error),
        error);
    BOOST_CHECK(!Contains(payload, LE64(kTier)));
    BOOST_CHECK(!Contains(payload, LE64(nShieldIn)));

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation extracted =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects);
    BOOST_REQUIRE_MESSAGE(extracted.IsValid(), extracted.strError);
    BOOST_CHECK_EQUAL(effects.nTransparentValueBalance, 0);
    BOOST_CHECK_EQUAL(effects.nFee, 0U);
}

// The deregistering spend republishes the key image and keeps the note closed.
BOOST_AUTO_TEST_CASE(the_deregistering_spend_republishes_only_the_pseudonym)
{
    CTxDB txdb("r+");
    std::string error;
    const NodeContext node;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xc7, kTier, note, error), error);

    std::vector<unsigned char> attestation;
    PrivacyVNextDigest attestedKeyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), AsDigest(node.digest), note.spend, attestation,
            attestedKeyImage, error),
        error);

    const uint64_t nFee = MIN_TX_FEE;
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
    outs[0].nAmount = kTier - nFee;

    std::vector<unsigned char> spend;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(
            LocalNetwork(), 7, LocalGenesis(), note.keys.outgoingViewSecret,
            note.finalizedRoot, note.nTreeSize, NoTransparentSide(), nFee, spends,
            outs, spend, error),
        error);

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation extracted =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, spend, effects);
    BOOST_REQUIRE_MESSAGE(extracted.IsValid(), extracted.strError);

    // Positive control, and the mechanism itself: the spend names the same key
    // image the registration published, which is exactly how the watcher learns
    // the collateral is gone.
    BOOST_REQUIRE_EQUAL(effects.keyImages.size(), 1U);
    BOOST_CHECK(effects.keyImages[0] == attestedKeyImage);
    BOOST_CHECK(Contains(spend, Bytes(attestedKeyImage)));

    // A deregistration is a spend, not an attestation, so it must not land in the
    // collateral watch set.
    BOOST_CHECK(effects.attestationKeyImages.empty());
    BOOST_CHECK(effects.registrationContext == FillDigest(0));

    // What it does not say: the amount, the note it consumed, or the context the
    // registration was bound to.
    BOOST_CHECK(!Contains(spend, LE64(kTier)));
    BOOST_CHECK(!Contains(spend, LE64(kTier - nFee)));
    BOOST_CHECK(!Contains(spend, Bytes(note.spend.mask)));
    BOOST_CHECK(!Contains(spend, Bytes(note.spend.spendSecret)));
    BOOST_CHECK(!Contains(spend, Bytes(note.encrypted.leaf.commitment)));
    BOOST_CHECK(!Contains(spend, Bytes(note.encrypted.leaf.owner)));
    BOOST_CHECK(!Contains(spend, Bytes(AsDigest(node.digest))));
}

// Mask 7 is pinned only for the two registration operations; other v2008 pool
// traffic may use any disclosure mask.
BOOST_AUTO_TEST_CASE(only_the_registration_operations_are_pinned_to_mask_seven)
{
    // Positive control: a transfer on the same version is admitted at every mask,
    // so the refusals below are the attestation clause and not a blanket rule.
    for (uint8_t nMask = 0; nMask <= iv5::DISCLOSURE_MASK; ++nMask)
        BOOST_CHECK_MESSAGE(
            iv5::EnvelopeAllows(2008, iv5::NOTE_TRANSFER, iv5::FINALITY_NONE,
                                iv5::AUTH_OWNER, iv5::FINALITY_OBJECT_NONE,
                                nMask),
            strprintf("a transfer was refused at mask %u", (unsigned)nMask));

    for (uint8_t nMask = 0; nMask < iv5::DISCLOSURE_MASK; ++nMask)
    {
        BOOST_CHECK_MESSAGE(
            !iv5::EnvelopeAllows(2008, iv5::NOTE_COLLATERAL_REGISTER,
                                 iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                                 iv5::FINALITY_OBJECT_NONE, nMask),
            strprintf("a collateral registration was admitted at mask %u",
                      (unsigned)nMask));
        BOOST_CHECK_MESSAGE(
            !iv5::EnvelopeAllows(2008, iv5::NOTE_FINALITY_MEMBER_REGISTER,
                                 iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                                 iv5::FINALITY_OBJECT_NONE, nMask),
            strprintf("a member registration was admitted at mask %u",
                      (unsigned)nMask));
    }
    BOOST_CHECK(iv5::EnvelopeAllows(2008, iv5::NOTE_COLLATERAL_REGISTER,
                                    iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                                    iv5::FINALITY_OBJECT_NONE,
                                    iv5::DISCLOSURE_MASK));
    BOOST_CHECK(iv5::EnvelopeAllows(2008, iv5::NOTE_FINALITY_MEMBER_REGISTER,
                                    iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                                    iv5::FINALITY_OBJECT_NONE,
                                    iv5::DISCLOSURE_MASK));

    // The builder takes no mask argument at all -- unlike every other payload
    // builder -- so a wallet cannot ask for a disclosed registration in the first
    // place. What it stamps is read back off the wire below.
    CTxDB txdb("r+");
    std::string error;
    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xc8, kTier, note, error), error);

    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), FillDigest(0xd7), note.spend, payload, keyImage,
            error),
        error);

    // The mask the builder stamped is the pinned one, read back off the wire.
    BOOST_REQUIRE_GT(payload.size(), kParameterDigestOffset);
    BOOST_CHECK_EQUAL((unsigned)payload[5], (unsigned)iv5::DISCLOSURE_MASK);
    BOOST_CHECK_EQUAL((unsigned)payload[2],
                      (unsigned)iv5::NOTE_COLLATERAL_REGISTER);
    BOOST_CHECK_EQUAL(ValidationResult(payload), kValid);

    // An in-place mask flip is not asserted: it breaks the membership proof, not the shape
    // rule. privacy_vnext_collateral_tests re-proves at masks {0, 6, 7} instead.
}

BOOST_AUTO_TEST_SUITE_END()
