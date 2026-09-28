#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cctype>
#include <limits>
#include <cstring>
#include <set>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../main.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../privacy_vnext_wallet.h"
#include "../shielded.h"
#include "../txdb.h"
#include "../wallet.h"

namespace
{

PrivacyVNextDigest RotationDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

// Scalars must be canonical field elements, so build them from a small value rather
// than a repeated byte, which overflows the group order.
PrivacyVNextDigest RotationScalar(unsigned char low)
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

// What a transfer commits to: no transparent input, no transparent output, no lock
// time. The value CreatePrivacyVNextTransfer computes for every transfer it builds.
PrivacyVNextDigest NoTransparentSide()
{
    PrivacyVNextDigest d;
    const uint256 binding = GetPrivacyVNextTransparentBinding(CTransaction());
    std::memcpy(d.data(), binding.begin(), 32);
    return d;
}

// The input context of a shield with no transparent side. The notes funded by hand below
// are grown straight into the tree, never carried by a payload, so encrypt and scan only
// have to agree on it.
PrivacyVNextDigest FundingContext()
{
    PrivacyVNextDigest context;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextInputContext(iv5::NOTE_SHIELD, NoTransparentSide(),
                                       std::vector<PrivacyVNextDigest>(), context,
                                       error),
        error);
    return context;
}

// The 64 bytes a receiver disclosure publishes for one output: the recipient's spend
// key then its view key, in the order the payload carries them.
std::vector<unsigned char> AddressBytes(const PrivacyVNextDerivedKeys& keys)
{
    std::vector<unsigned char> v;
    v.insert(v.end(), keys.spendPublic.begin(), keys.spendPublic.end());
    v.insert(v.end(), keys.viewPublic.begin(), keys.viewPublic.end());
    return v;
}

bool PayloadContains(const std::vector<unsigned char>& payload,
                     const std::vector<unsigned char>& needle)
{
    if (needle.empty() || payload.size() < needle.size())
        return false;
    for (size_t i = 0; i + needle.size() <= payload.size(); ++i)
        if (std::memcmp(&payload[i], &needle[0], needle.size()) == 0)
            return true;
    return false;
}

// Several independent notes of `nAmount`, each placed in one tree and each ready to be
// spent on its own. Two spends need two notes: a spend's key images are what its
// self-pay index is drawn from, and one note can only be spent once.
struct FundedNotes
{
    PrivacyVNextDigest genesis;
    PrivacyVNextDerivedKeys keys;
    std::vector<PrivacyVNextSpendNote> vNotes;
    // What the wallet stores as CPrivacyVNextWalletNote::vchKeyImage, and what the
    // spend path draws its self-pay index from before any payload exists.
    std::vector<PrivacyVNextDigest> vKeyImages;
    PrivacyVNextDigest finalizedRoot;
    uint64_t nTreeSize;
    uint64_t nAmount;

    FundedNotes() : nTreeSize(0), nAmount(0) {}
};

void FundNotes(CTxDB& txdb, size_t nCount, FundedNotes& funded,
               unsigned char seedFill, uint64_t nAmount = 8000)
{
    std::string error;
    funded.genesis = LocalGenesis();
    funded.nAmount = nAmount;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(RotationDigest(seedFill), funded.genesis, 0,
                               LocalNetwork(), 0, funded.keys, error),
        error);

    std::vector<PrivacyVNextEncryptedOutput> vFunding(nCount);
    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    for (size_t i = 0; i < nCount; ++i)
    {
        // Distinct openings, so the notes are distinct leaves with distinct key
        // images rather than one note repeated.
        BOOST_REQUIRE_MESSAGE(
            EncryptPrivacyVNextNote(
                LocalNetwork(), 0, (uint32_t)i, funded.genesis,
                funded.keys.spendPublic, funded.keys.viewPublic,
                funded.keys.outgoingViewSecret,
                RotationScalar((unsigned char)(29 + i)),
                RotationScalar((unsigned char)(59 + i)), funded.nAmount,
                RotationScalar((unsigned char)(89 + i)),
                RotationScalar((unsigned char)(113 + i)), FundingContext(),
                vFunding[i], error),
            error);
        vLeaves.push_back(vFunding[i].leaf);
    }

    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    BOOST_REQUIRE_MESSAGE(TrimPrivacyVNextTreeStore(txdb, 0, treeState, error),
                          error);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, error), error);

    std::vector<unsigned char> vchRoot;
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(treeState, vchRoot, funded.nTreeSize, error),
        error);
    BOOST_REQUIRE_EQUAL(funded.nTreeSize, (uint64_t)nCount);
    std::memcpy(funded.finalizedRoot.data(), &vchRoot[0], 32);

    std::vector<uint64_t> vTargets(nCount);
    for (size_t i = 0; i < nCount; ++i)
        vTargets[i] = (uint64_t)i;
    std::vector<unsigned char> vchPaths;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, funded.nTreeSize, treeState, vTargets,
                                  vchPaths, error),
        error);
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths,
                                            vWitnesses, treeRoot, error),
        error);

    funded.vNotes.resize(nCount);
    funded.vKeyImages.resize(nCount);
    for (size_t i = 0; i < nCount; ++i)
    {
        PrivacyVNextEncryptedNote onChain;
        onChain.nOutputIndex = (uint32_t)i;
        onChain.genesis = funded.genesis;
        onChain.leafO = vFunding[i].leaf.owner;
        onChain.leafC = vFunding[i].leaf.commitment;
        onChain.noteEphemeral = vFunding[i].noteEphemeral;
        onChain.tweakEphemeral = vFunding[i].tweakEphemeral;
        onChain.vchCiphertext = vFunding[i].vchRecipientCiphertext;
        onChain.inputContext = FundingContext();
        PrivacyVNextScannedNote scanned;
        BOOST_REQUIRE_MESSAGE(
            ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, LocalNetwork(), 0, onChain,
                                 funded.keys.viewSecret, funded.keys.spendSecret,
                                 scanned, error),
            error);
        funded.vNotes[i].spendSecret = scanned.spendSecret;
        funded.vNotes[i].y = scanned.y;
        funded.vNotes[i].mask = scanned.mask;
        funded.vNotes[i].nAmount = scanned.nAmount;
        funded.vNotes[i].leaf = vFunding[i].leaf;
        funded.vNotes[i].vchWitnessRecord = vWitnesses[i].vchRecord;
        funded.vKeyImages[i] = scanned.keyImage;
    }
}

// A transfer of one funded note to `payee`, with the sender's change paid to
// `nChangeIndex`. Everything from the index to the payload bytes runs through the
// functions the wallet's own spend path calls.
bool BuildTransferWithChangeAt(const FundedNotes& funded, size_t nNote,
                               const PrivacyVNextDigest& senderSeed,
                               uint32_t nChangeIndex, uint8_t nMask,
                               const PrivacyVNextDerivedKeys& payee,
                               uint64_t nPaid, uint64_t nFee,
                               PrivacyVNextDerivedKeys& changeOut,
                               std::vector<unsigned char>& payloadOut,
                               std::string& error)
{
    if (!DerivePrivacyVNextChangeKeys(senderSeed, funded.genesis, LocalNetwork(),
                                      nChangeIndex, changeOut, error))
        return false;

    std::vector<PrivacyVNextNewOutput> outs(2);
    outs[0].recipient.nNetwork = LocalNetwork();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = payee.spendPublic;
    outs[0].recipient.viewPublic = payee.viewPublic;
    outs[0].nAmount = nPaid;
    outs[1].recipient.nNetwork = LocalNetwork();
    outs[1].recipient.nAddressType = 0;
    outs[1].recipient.spendPublic = changeOut.spendPublic;
    outs[1].recipient.viewPublic = changeOut.viewPublic;
    outs[1].nAmount = funded.nAmount - nPaid - nFee;

    const std::vector<PrivacyVNextSpendNote> vSpends(1, funded.vNotes[nNote]);
    return BuildPrivacyVNextTransferPayload(
        LocalNetwork(), nMask, funded.genesis, changeOut.outgoingViewSecret,
        funded.finalizedRoot, funded.nTreeSize, NoTransparentSide(), nFee,
        vSpends, outs, payloadOut, error);
}

// The transaction the wallet builds around a transfer payload: no transparent input,
// no transparent output. What a scan is handed once the block lands.
CTransaction CarrierOf(const std::vector<unsigned char>& payload)
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_DSP;
    tx.privacyVNext.vchPayload = payload;
    return tx;
}

// The self-pay index the wallet's spend path would draw for a payload spending these
// key images out of a transaction with no transparent side.
uint32_t ChangeIndexForSpendOf(const PrivacyVNextDigest& genesis,
                               const std::vector<PrivacyVNextDigest>& vKeyImages)
{
    return PrivacyVNextChangeIndexFor(genesis, LocalNetwork(), NoTransparentSide(),
                                      vKeyImages);
}

// Whether any key in the list opens an output of this payload, and with what.
bool ScanFinds(const std::vector<unsigned char>& payload,
               const std::vector<PrivacyVNextScanKey>& vKeys,
               std::vector<PrivacyVNextScanMatch>& vMatchesOut,
               std::string& error)
{
    std::vector<PrivacyVNextDigest> vKeyImages;
    uint8_t nOutputCount = 0;
    vMatchesOut.clear();
    return ScanPrivacyVNextPayload(PRIVACY_VNEXT_SCAN_FULL, LocalNetwork(), 0,
                                   INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                   payload, vKeys, vMatchesOut, vKeyImages,
                                   nOutputCount, error);
}

} // namespace

BOOST_AUTO_TEST_SUITE(privacy_vnext_change_rotation_tests)

// The index has to move with the payload and stay inside the self-pay range. Moving is
// what stops a disclosing wallet from publishing one address forever; staying inside
// the range is what stops a disclosure from publishing an address the user handed out.
BOOST_AUTO_TEST_CASE(the_self_pay_index_moves_with_the_payload_and_stays_internal)
{
    const PrivacyVNextDigest genesis = LocalGenesis();
    const PrivacyVNextDigest binding = NoTransparentSide();

    std::vector<PrivacyVNextDigest> vNoImages;
    std::set<uint32_t> setSeen;

    // Output-only operations -- a shield, the coinbase fee note -- spend nothing, so
    // the binding is the whole nonce and has to be enough on its own.
    for (unsigned char i = 1; i <= 32; ++i)
    {
        const uint32_t nIndex =
            PrivacyVNextChangeIndexFor(genesis, LocalNetwork(),
                                       RotationDigest(i), vNoImages);
        BOOST_CHECK_MESSAGE(nIndex >= PRIVACY_VNEXT_INTERNAL_CHANGE_BASE,
                            strprintf("binding %u drew index %u, below the self-pay "
                                      "range", (unsigned)i, nIndex));
        BOOST_CHECK_MESSAGE(nIndex >= PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES,
                            strprintf("binding %u drew issuable index %u",
                                      (unsigned)i, nIndex));
        setSeen.insert(nIndex);
    }
    BOOST_CHECK_MESSAGE(setSeen.size() == 32,
                        strprintf("32 distinct bindings drew only %u distinct "
                                  "self-pay indices", (unsigned)setSeen.size()));

    // Spends: the key images carry the nonce. Consensus retires each key image once,
    // so no two spends of one wallet present the same set.
    setSeen.clear();
    for (unsigned char i = 1; i <= 32; ++i)
    {
        const std::vector<PrivacyVNextDigest> vOne(1, RotationDigest(i));
        const uint32_t nIndex =
            PrivacyVNextChangeIndexFor(genesis, LocalNetwork(), binding, vOne);
        BOOST_CHECK_MESSAGE(nIndex >= PRIVACY_VNEXT_INTERNAL_CHANGE_BASE,
                            strprintf("key image %u drew index %u, below the "
                                      "self-pay range", (unsigned)i, nIndex));
        setSeen.insert(nIndex);
    }
    BOOST_CHECK_MESSAGE(setSeen.size() == 32,
                        strprintf("32 distinct key images drew only %u distinct "
                                  "self-pay indices", (unsigned)setSeen.size()));

    // A rescan has to reach the same index the builder did, so the draw is a pure
    // function of the payload's own bytes and of nothing else.
    const std::vector<PrivacyVNextDigest> vOne(1, RotationDigest(7));
    BOOST_CHECK_EQUAL(
        PrivacyVNextChangeIndexFor(genesis, LocalNetwork(), binding, vOne),
        PrivacyVNextChangeIndexFor(genesis, LocalNetwork(), binding, vOne));

    // And it must not depend on the order the payload serializes its key images in,
    // which is the builder's choice and not something a scan can rely on.
    std::vector<PrivacyVNextDigest> vAscending;
    for (unsigned char i = 1; i <= 4; ++i)
        vAscending.push_back(RotationDigest(i));
    std::vector<PrivacyVNextDigest> vReversed(vAscending.rbegin(),
                                              vAscending.rend());
    BOOST_CHECK_EQUAL(
        PrivacyVNextChangeIndexFor(genesis, LocalNetwork(), binding, vAscending),
        PrivacyVNextChangeIndexFor(genesis, LocalNetwork(), binding, vReversed));

    // Separate nonce components, so one cannot be swapped for the other.
    BOOST_CHECK(PrivacyVNextChangeIndexFor(genesis, LocalNetwork(), binding,
                                           vAscending) !=
                PrivacyVNextChangeIndexFor(genesis, LocalNetwork(),
                                           RotationDigest(0x5a), vAscending));
}

// Every mask that leaves the receiver bit clear publishes the outputs, so the pseudonym
// spanned all four of them and so must its removal. Covering one mask would leave a
// wallet that alternates masks linkable across the ones nothing checked.
BOOST_AUTO_TEST_CASE(every_receiver_disclosing_mask_publishes_a_fresh_change_address)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNotes funded;
    FundNotes(txdb, 4, funded, 0x55);

    const PrivacyVNextDigest senderSeed = RotationDigest(0x55);
    PrivacyVNextDerivedKeys payee;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(RotationDigest(0x56), funded.genesis, 0,
                               LocalNetwork(), 0, payee, error),
        error);

    // Masks 0, 1, 4 and 5: every value with iv5::DISCLOSURE_HIDE_RECEIVER clear.
    const uint8_t vMasks[4] = { 0, 1, 4, 5 };
    const uint64_t nPaid = 1500;
    const uint64_t nFee = 100;

    // The control: at the pre-rotation index all four masks publish one set of 64
    // bytes. It is what the absence checks below are absence *of*, and it is what says
    // the needle is findable in a payload of each mask at all.
    std::vector<unsigned char> vFixedBytes;
    for (size_t m = 0; m < 4; ++m)
    {
        PrivacyVNextDerivedKeys fixedChange;
        std::vector<unsigned char> fixedPayload;
        BOOST_REQUIRE_MESSAGE(
            BuildTransferWithChangeAt(funded, m, senderSeed,
                                      PRIVACY_VNEXT_INTERNAL_CHANGE_INDEX,
                                      vMasks[m], payee, nPaid, nFee, fixedChange,
                                      fixedPayload, error),
            error);
        if (vFixedBytes.empty())
            vFixedBytes = AddressBytes(fixedChange);
        BOOST_REQUIRE(AddressBytes(fixedChange) == vFixedBytes);
        BOOST_CHECK_MESSAGE(
            PayloadContains(fixedPayload, vFixedBytes),
            strprintf("mask %u published no change address at the fixed index, so "
                      "its absence below would prove nothing", (unsigned)vMasks[m]));
    }

    // The same four masks with the index drawn per payload, each spending its own note.
    std::vector<std::vector<unsigned char> > vPayloads;
    std::vector<std::vector<unsigned char> > vAddresses;
    for (size_t i = 0; i < 4; ++i)
    {
        const uint8_t nMask = vMasks[i];
        const std::vector<PrivacyVNextDigest> vSpent(1, funded.vKeyImages[i]);
        PrivacyVNextDerivedKeys change;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE_MESSAGE(
            BuildTransferWithChangeAt(funded, i, senderSeed,
                                      ChangeIndexForSpendOf(funded.genesis, vSpent),
                                      nMask, payee, nPaid, nFee, change, payload,
                                      error),
            error);
        vPayloads.push_back(payload);
        vAddresses.push_back(AddressBytes(change));
    }

    for (size_t i = 0; i < 4; ++i)
    {
        BOOST_CHECK_MESSAGE(
            PayloadContains(vPayloads[i], vAddresses[i]),
            strprintf("the mask-%u transfer published no change address at all",
                      (unsigned)vMasks[i]));
        BOOST_CHECK_MESSAGE(
            !PayloadContains(vPayloads[i], vFixedBytes),
            strprintf("the mask-%u transfer still carried the fixed change address",
                      (unsigned)vMasks[i]));
        // Across masks, not only within one: a wallet that alternates masks must not
        // become linkable at the seam between them.
        for (size_t j = 0; j < 4; ++j)
        {
            if (i == j)
                continue;
            BOOST_CHECK_MESSAGE(
                vAddresses[i] != vAddresses[j],
                strprintf("the mask-%u and mask-%u transfers drew the same change "
                          "address", (unsigned)vMasks[i], (unsigned)vMasks[j]));
            BOOST_CHECK_MESSAGE(
                !PayloadContains(vPayloads[i], vAddresses[j]),
                strprintf("the mask-%u transfer republished the mask-%u transfer's "
                          "change address", (unsigned)vMasks[i], (unsigned)vMasks[j]));
        }
    }
}

// A multi-note spend draws from every key image it publishes, and a scan recovers the
// same index from the payload alone (one note cannot tell these apart).
BOOST_AUTO_TEST_CASE(a_multi_note_spend_draws_from_every_key_image_it_publishes)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNotes funded;
    FundNotes(txdb, 2, funded, 0x39);

    const PrivacyVNextDigest senderSeed = RotationDigest(0x39);
    PrivacyVNextDerivedKeys payee;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(RotationDigest(0x3a), funded.genesis, 0,
                               LocalNetwork(), 0, payee, error),
        error);

    // Key images of the selected notes, in reverse of the builder order: selection order is not
    // payload order, and the scan sees only the latter.
    std::vector<PrivacyVNextDigest> vSelected;
    vSelected.push_back(funded.vKeyImages[0]);
    vSelected.push_back(funded.vKeyImages[1]);
    const uint32_t nIndex = ChangeIndexForSpendOf(funded.genesis, vSelected);

    PrivacyVNextDerivedKeys change;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextChangeKeys(senderSeed, funded.genesis, LocalNetwork(),
                                     nIndex, change, error),
        error);

    const uint64_t nPaid = 1500;
    const uint64_t nFee = 100;
    const uint64_t nChange = funded.nAmount * 2 - nPaid - nFee;
    std::vector<PrivacyVNextNewOutput> outs(2);
    outs[0].recipient.nNetwork = LocalNetwork();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = payee.spendPublic;
    outs[0].recipient.viewPublic = payee.viewPublic;
    outs[0].nAmount = nPaid;
    outs[1].recipient.nNetwork = LocalNetwork();
    outs[1].recipient.nAddressType = 0;
    outs[1].recipient.spendPublic = change.spendPublic;
    outs[1].recipient.viewPublic = change.viewPublic;
    outs[1].nAmount = nChange;

    std::vector<PrivacyVNextSpendNote> vSpends;
    vSpends.push_back(funded.vNotes[1]);
    vSpends.push_back(funded.vNotes[0]);
    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(
            LocalNetwork(), 5, funded.genesis, change.outgoingViewSecret,
            funded.finalizedRoot, funded.nTreeSize, NoTransparentSide(), nFee,
            vSpends, outs, payload, error),
        error);

    PrivacyVNextStateEffects effects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects)
                      .IsValid());
    BOOST_REQUIRE_EQUAL(effects.keyImages.size(), 2U);
    // The two orders have to differ, or the equality below would hold whether or not
    // the draw sorts and the check would be worth nothing.
    BOOST_REQUIRE_MESSAGE(effects.keyImages != vSelected,
                          "the payload published the key images in the order the "
                          "index was drawn from, so this case no longer separates a "
                          "sorted draw from an unsorted one");
    std::vector<PrivacyVNextDigest> vPublished(effects.keyImages.begin(),
                                               effects.keyImages.end());
    std::vector<PrivacyVNextDigest> vExpected(vSelected);
    std::sort(vPublished.begin(), vPublished.end());
    std::sort(vExpected.begin(), vExpected.end());
    BOOST_CHECK_MESSAGE(vPublished == vExpected,
                        "the payload does not publish the key images the self-pay "
                        "index was drawn from");
    BOOST_CHECK_MESSAGE(
        ChangeIndexForSpendOf(funded.genesis, effects.keyImages) == nIndex,
        "the index a scan draws from the published order is not the one the builder "
        "drew from its selection order");

    // Dropping one image draws a different index, which is what says both were load
    // bearing rather than the first one alone.
    BOOST_CHECK(ChangeIndexForSpendOf(
                    funded.genesis,
                    std::vector<PrivacyVNextDigest>(1, vSelected[0])) != nIndex);

    // And the scan reaches it from the carrying transaction with nothing else.
    CWallet localWallet;
    std::vector<PrivacyVNextScanKey> vKeys;
    BOOST_REQUIRE_MESSAGE(
        localWallet.BuildPrivacyVNextScanKeys(senderSeed, funded.genesis,
                                              LocalNetwork(), vKeys, error),
        error);
    const size_t nBaseKeys = vKeys.size();
    const CTransaction txCarrier = CarrierOf(payload);
    BOOST_REQUIRE_MESSAGE(
        localWallet.ExtendPrivacyVNextScanKeysForPayload(
            senderSeed, funded.genesis, LocalNetwork(), txCarrier, nBaseKeys, vKeys,
            error),
        error);
    std::vector<PrivacyVNextScanMatch> vMatches;
    BOOST_REQUIRE_MESSAGE(ScanFinds(payload, vKeys, vMatches, error), error);
    BOOST_REQUIRE_EQUAL(vMatches.size(), 1U);
    BOOST_CHECK_EQUAL(vMatches[0].nAmount, nChange);
    BOOST_CHECK_EQUAL((size_t)vMatches[0].nKeyIndex, nBaseKeys);
}

// Two disclosing transfers from one wallet must publish different change-address
// bytes, or they are linkable to each other.
BOOST_AUTO_TEST_CASE(two_disclosing_transfers_publish_different_change_addresses)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNotes funded;
    FundNotes(txdb, 2, funded, 0x63);

    const PrivacyVNextDigest senderSeed = RotationDigest(0x63);
    PrivacyVNextDerivedKeys payee;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(RotationDigest(0x64), funded.genesis, 0,
                               LocalNetwork(), 0, payee, error),
        error);

    // Mask 5 hides the sender and the amounts and publishes the recipients: the mode a
    // payee is given to prove a payment without learning who paid, and the one that
    // published the pseudonym.
    const uint8_t nMask = iv5::DISCLOSURE_HIDE_SENDER | iv5::DISCLOSURE_HIDE_AMOUNT;
    const uint64_t nPaid = 1500;
    const uint64_t nFee = 100;

    // The control, and the defect itself: at one fixed index both payloads carry the
    // same 64 bytes. Without this the absence checks below would pass against a needle
    // that never appears in any payload.
    std::vector<unsigned char> vFixed[2];
    PrivacyVNextDerivedKeys fixedChange[2];
    for (size_t i = 0; i < 2; ++i)
        BOOST_REQUIRE_MESSAGE(
            BuildTransferWithChangeAt(funded, i, senderSeed,
                                      PRIVACY_VNEXT_INTERNAL_CHANGE_INDEX, nMask,
                                      payee, nPaid, nFee, fixedChange[i], vFixed[i],
                                      error),
            error);
    const std::vector<unsigned char> vFixedBytes = AddressBytes(fixedChange[0]);
    BOOST_REQUIRE(AddressBytes(fixedChange[1]) == vFixedBytes);
    BOOST_CHECK_MESSAGE(PayloadContains(vFixed[0], vFixedBytes),
                        "a receiver-disclosing transfer did not publish its change "
                        "address at all");
    BOOST_CHECK_MESSAGE(PayloadContains(vFixed[1], vFixedBytes),
                        "the fixed change address is the pseudonym this test exists "
                        "to remove, and it did not appear in the second payload");

    // Rotated: each transfer draws its index from the key image of the note it spends,
    // through the same call the spend path makes before the payload exists.
    std::vector<unsigned char> vRotated[2];
    PrivacyVNextDerivedKeys rotatedChange[2];
    for (size_t i = 0; i < 2; ++i)
    {
        const std::vector<PrivacyVNextDigest> vSpent(1, funded.vKeyImages[i]);
        const uint32_t nIndex = ChangeIndexForSpendOf(funded.genesis, vSpent);
        BOOST_REQUIRE_MESSAGE(
            BuildTransferWithChangeAt(funded, i, senderSeed, nIndex, nMask, payee,
                                      nPaid, nFee, rotatedChange[i], vRotated[i],
                                      error),
            error);

        // The whole scheme rests on the builder's nonce being the one a later scan
        // reads off the wire, so the payload has to publish exactly the key image the
        // index was drawn from.
        PrivacyVNextStateEffects effects;
        BOOST_REQUIRE_MESSAGE(
            ExtractPrivacyVNextPayloadEffects(
                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vRotated[i], effects)
                .IsValid(),
            "a rotated transfer did not validate");
        BOOST_REQUIRE_EQUAL(effects.keyImages.size(), 1U);
        BOOST_CHECK(effects.keyImages[0] == funded.vKeyImages[i]);
        BOOST_CHECK_EQUAL(ChangeIndexForSpendOf(funded.genesis, effects.keyImages),
                          nIndex);
    }

    // Each still publishes its own change address, so the disclosure still does what
    // the payee needs. What it no longer does is publish the same one twice.
    const std::vector<unsigned char> vFirst = AddressBytes(rotatedChange[0]);
    const std::vector<unsigned char> vSecond = AddressBytes(rotatedChange[1]);
    BOOST_CHECK(vFirst != vSecond);
    BOOST_CHECK_MESSAGE(PayloadContains(vRotated[0], vFirst),
                        "the first rotated transfer published no change address");
    BOOST_CHECK_MESSAGE(PayloadContains(vRotated[1], vSecond),
                        "the second rotated transfer published no change address");
    BOOST_CHECK_MESSAGE(
        !PayloadContains(vRotated[1], vFirst),
        "the second transfer republished the first transfer's change address");
    BOOST_CHECK_MESSAGE(
        !PayloadContains(vRotated[0], vSecond),
        "the first transfer carried the second transfer's change address");

    // Neither half on its own, either: half an address still names the wallet.
    const std::vector<unsigned char> vFirstSpend(
        rotatedChange[0].spendPublic.begin(), rotatedChange[0].spendPublic.end());
    const std::vector<unsigned char> vFirstView(
        rotatedChange[0].viewPublic.begin(), rotatedChange[0].viewPublic.end());
    BOOST_CHECK(!PayloadContains(vRotated[1], vFirstSpend));
    BOOST_CHECK(!PayloadContains(vRotated[1], vFirstView));

    // And the rotated address is still one the sender could never have handed out.
    for (uint32_t nIndex = 0; nIndex < 32; ++nIndex)
    {
        PrivacyVNextDerivedKeys issued;
        BOOST_REQUIRE_MESSAGE(
            DerivePrivacyVNextKeys(senderSeed, funded.genesis, nIndex,
                                   LocalNetwork(), 0, issued, error),
            error);
        for (size_t i = 0; i < 2; ++i)
            BOOST_CHECK_MESSAGE(
                !PayloadContains(vRotated[i], AddressBytes(issued)),
                strprintf("a rotated transfer published the sender's issued "
                          "address %u", nIndex));
    }
}

// Rotation is only safe if a scan reaches it. A change note nothing opens is
// unspendable value, and unshield is retired, so there is no recovery path but a
// rescan that does reach it.
BOOST_AUTO_TEST_CASE(a_rotated_change_note_reopens_under_the_payload_scan_list)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNotes funded;
    FundNotes(txdb, 2, funded, 0x71);

    const PrivacyVNextDigest senderSeed = RotationDigest(0x71);
    PrivacyVNextDerivedKeys payee;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(RotationDigest(0x72), funded.genesis, 0,
                               LocalNetwork(), 0, payee, error),
        error);

    CWallet localWallet;
    std::vector<PrivacyVNextScanKey> vBase;
    BOOST_REQUIRE_MESSAGE(
        localWallet.BuildPrivacyVNextScanKeys(senderSeed, funded.genesis,
                                              LocalNetwork(), vBase, error),
        error);
    const uint32_t nIssued = localWallet.GetPrivacyVNextScanIndexCount();
    const size_t nBaseKeys = vBase.size();
    BOOST_REQUIRE_EQUAL(nBaseKeys,
                        (size_t)nIssued + (size_t)PRIVACY_VNEXT_SCAN_LOOKAHEAD + 1);

    const uint64_t nPaid = 1500;
    const uint64_t nFee = 100;
    const uint64_t nChange = funded.nAmount - nPaid - nFee;

    // The positive control first, and the backward-compatibility case in one: change
    // paid at the pre-rotation index must still open under the base list, or every
    // wallet holding change from before this change loses it.
    PrivacyVNextDerivedKeys legacyChange;
    std::vector<unsigned char> legacyPayload;
    BOOST_REQUIRE_MESSAGE(
        BuildTransferWithChangeAt(funded, 0, senderSeed,
                                  PRIVACY_VNEXT_INTERNAL_CHANGE_INDEX, 7, payee,
                                  nPaid, nFee, legacyChange, legacyPayload, error),
        error);
    std::vector<PrivacyVNextScanMatch> vMatches;
    BOOST_REQUIRE_MESSAGE(ScanFinds(legacyPayload, vBase, vMatches, error), error);
    BOOST_REQUIRE_EQUAL(vMatches.size(), 1U);
    BOOST_CHECK_EQUAL(vMatches[0].nAmount, nChange);
    // The pre-rotation self-pay key is the last of the built list, above every address
    // index and the lookahead window; it is not an index anyone was paid at.
    BOOST_CHECK_EQUAL((size_t)vMatches[0].nKeyIndex, vBase.size() - 1);

    // Now a rotated one, spending the other note, at the index that note's key image
    // names.
    const std::vector<PrivacyVNextDigest> vSpent(1, funded.vKeyImages[1]);
    const uint32_t nRotated = ChangeIndexForSpendOf(funded.genesis, vSpent);
    BOOST_REQUIRE(nRotated != PRIVACY_VNEXT_INTERNAL_CHANGE_INDEX);

    PrivacyVNextDerivedKeys rotatedChange;
    std::vector<unsigned char> rotatedPayload;
    BOOST_REQUIRE_MESSAGE(
        BuildTransferWithChangeAt(funded, 1, senderSeed, nRotated, 7, payee, nPaid,
                                  nFee, rotatedChange, rotatedPayload, error),
        error);

    // The negative control: the base list alone cannot open rotated change. This is
    // what makes the pass below evidence that the appended key did the work, rather
    // than the legacy key happening to match.
    BOOST_REQUIRE_MESSAGE(ScanFinds(rotatedPayload, vBase, vMatches, error), error);
    BOOST_CHECK_MESSAGE(vMatches.empty(),
                        "the base scan list opened rotated change without the "
                        "payload's own key");

    // And the list the wallet actually scans with, built by the production call from
    // the carrying transaction alone -- no stored index, no counter.
    std::vector<PrivacyVNextScanKey> vKeys(vBase);
    const CTransaction txCarrier = CarrierOf(rotatedPayload);
    BOOST_REQUIRE_MESSAGE(
        localWallet.ExtendPrivacyVNextScanKeysForPayload(
            senderSeed, funded.genesis, LocalNetwork(), txCarrier, nBaseKeys, vKeys,
            error),
        error);
    BOOST_REQUIRE_EQUAL(vKeys.size(), nBaseKeys + 1);
    BOOST_CHECK(vKeys[nBaseKeys].scanSecret == rotatedChange.viewSecret);
    BOOST_CHECK(vKeys[nBaseKeys].spendMaterial == rotatedChange.spendSecret);

    BOOST_REQUIRE_MESSAGE(ScanFinds(rotatedPayload, vKeys, vMatches, error), error);
    BOOST_REQUIRE_EQUAL(vMatches.size(), 1U);
    BOOST_CHECK_EQUAL(vMatches[0].nAmount, nChange);
    BOOST_CHECK_EQUAL((size_t)vMatches[0].nKeyIndex, nBaseKeys);
    // Spend material, not merely a view of it: change that opens but cannot be spent
    // is the same loss one step later.
    const PrivacyVNextDigest zero = RotationDigest(0);
    BOOST_CHECK(vMatches[0].spendSecret != zero);
    BOOST_CHECK(vMatches[0].keyImage != zero);

    // Extending reuses the list per payload: the previous payload's key must not stay behind,
    // or the list grows without bound across a block.
    const CTransaction txLegacy = CarrierOf(legacyPayload);
    BOOST_REQUIRE_MESSAGE(
        localWallet.ExtendPrivacyVNextScanKeysForPayload(
            senderSeed, funded.genesis, LocalNetwork(), txLegacy, nBaseKeys, vKeys,
            error),
        error);
    BOOST_CHECK_EQUAL(vKeys.size(), nBaseKeys + 1);
    BOOST_CHECK(vKeys[nBaseKeys].scanSecret != rotatedChange.viewSecret);
    // The legacy payload still opens, now through the base list's own legacy key.
    BOOST_REQUIRE_MESSAGE(ScanFinds(legacyPayload, vKeys, vMatches, error), error);
    BOOST_REQUIRE_EQUAL(vMatches.size(), 1U);
    BOOST_CHECK_EQUAL((size_t)vMatches[0].nKeyIndex, nBaseKeys - 1);
}

// A wallet issued to the bound must still be able to build a scan list, or it scans
// nothing at all and every note it receives goes undetected.
BOOST_AUTO_TEST_CASE(the_scan_budget_carries_every_issued_index_and_both_self_pay_keys)
{
    BOOST_CHECK_EQUAL((size_t)PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES + 2,
                      (size_t)PRIVACY_VNEXT_MAX_SCAN_KEYS);
    BOOST_CHECK(PRIVACY_VNEXT_MAX_SCAN_KEYS <= PRIVACY_VNEXT_INTERNAL_CHANGE_BASE);

    const PrivacyVNextDigest genesis = LocalGenesis();
    const PrivacyVNextDigest seed = RotationDigest(0x4b);
    std::string error;

    CWallet localWallet;
    std::vector<PrivacyVNextScanKey> vKeys;
    BOOST_REQUIRE_MESSAGE(
        localWallet.BuildPrivacyVNextScanKeys(seed, genesis, LocalNetwork(), vKeys,
                                              error),
        error);
    // Issued indices, the lookahead window above them, and the pre-rotation self-pay key.
    const size_t nBaseKeys = vKeys.size();
    BOOST_REQUIRE_EQUAL(nBaseKeys,
                        (size_t)localWallet.GetPrivacyVNextScanIndexCount() +
                            (size_t)PRIVACY_VNEXT_SCAN_LOOKAHEAD + 1);

    // The ABI refuses a longer list than this, so the worst case a wallet at the
    // issuance bound reaches has to still fit.
    BOOST_CHECK_LE((size_t)PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES + 2,
                   (size_t)PRIVACY_VNEXT_MAX_SCAN_KEYS);

    // A list already at the ABI bound cannot take the payload key, and the refusal has
    // to be loud: dropping the key quietly would hide the wallet's own change.
    std::vector<PrivacyVNextScanKey> vFull(PRIVACY_VNEXT_MAX_SCAN_KEYS);
    const CTransaction txEmpty = CarrierOf(std::vector<unsigned char>());
    error.clear();
    BOOST_CHECK(!localWallet.ExtendPrivacyVNextScanKeysForPayload(
        seed, genesis, LocalNetwork(), txEmpty, vFull.size(), vFull, error));
    BOOST_CHECK(!error.empty());
}

// A block with pre-rotation and rotated self-pay outputs, scanned through the wallet
// entry point used by connect and rescan: both must open.
BOOST_AUTO_TEST_CASE(the_wallet_block_scan_recovers_pre_rotation_and_rotated_change)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNotes funded;
    FundNotes(txdb, 2, funded, 0x63);

    const PrivacyVNextDigest senderSeed = RotationDigest(0x63);
    PrivacyVNextDerivedKeys payee;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(RotationDigest(0x64), funded.genesis, 0,
                               LocalNetwork(), 0, payee, error),
        error);

    const uint64_t nPaid = 1500;
    const uint64_t nFee = 100;
    const uint64_t nChange = funded.nAmount - nPaid - nFee;

    // Note 0 pays change at the index every wallet used before rotation.
    PrivacyVNextDerivedKeys legacyChange;
    std::vector<unsigned char> legacyPayload;
    BOOST_REQUIRE_MESSAGE(
        BuildTransferWithChangeAt(funded, 0, senderSeed,
                                  PRIVACY_VNEXT_INTERNAL_CHANGE_INDEX, 7, payee,
                                  nPaid, nFee, legacyChange, legacyPayload, error),
        error);

    // Note 1 pays change at the index its own key image names.
    const std::vector<PrivacyVNextDigest> vSpent(1, funded.vKeyImages[1]);
    const uint32_t nRotated = ChangeIndexForSpendOf(funded.genesis, vSpent);
    BOOST_REQUIRE(nRotated != PRIVACY_VNEXT_INTERNAL_CHANGE_INDEX);
    PrivacyVNextDerivedKeys rotatedChange;
    std::vector<unsigned char> rotatedPayload;
    BOOST_REQUIRE_MESSAGE(
        BuildTransferWithChangeAt(funded, 1, senderSeed, nRotated, 7, payee, nPaid,
                                  nFee, rotatedChange, rotatedPayload, error),
        error);

    CBlock block;
    block.vtx.push_back(CarrierOf(legacyPayload));
    block.vtx.push_back(CarrierOf(rotatedPayload));
    const uint256 hashLegacy = block.vtx[0].GetHash();
    const uint256 hashRotated = block.vtx[1].GetHash();
    BOOST_REQUIRE(hashLegacy != hashRotated);

    CBlockIndex index;
    index.nHeight = 100;
    const std::set<uint256> setNoneSkipped;

    // The negative control runs first: a wallet holding a different seed scans the same
    // block through the same call and must open nothing. Without it, a scan that
    // credited every output it saw would read as a pass below.
    CWallet stranger;
    const PrivacyVNextDigest strangerSeed = RotationDigest(0x2d);
    stranger.vchPrivacyVNextSeed.assign(strangerSeed.begin(), strangerSeed.end());
    BOOST_REQUIRE_MESSAGE(
        stranger.ApplyPrivacyVNextBlock(block, setNoneSkipped, &index, error),
        error);
    BOOST_CHECK_MESSAGE(stranger.vPrivacyVNextNotes.empty(),
                        "a wallet that owns none of these outputs opened one anyway");

    CWallet sender;
    sender.vchPrivacyVNextSeed.assign(senderSeed.begin(), senderSeed.end());
    BOOST_REQUIRE_MESSAGE(
        sender.ApplyPrivacyVNextBlock(block, setNoneSkipped, &index, error), error);
    BOOST_REQUIRE_EQUAL(sender.vPrivacyVNextNotes.size(), 2U);

    const CPrivacyVNextWalletNote* pLegacy = 0;
    const CPrivacyVNextWalletNote* pRotated = 0;
    for (size_t i = 0; i < sender.vPrivacyVNextNotes.size(); ++i)
    {
        if (sender.vPrivacyVNextNotes[i].txhash == hashLegacy)
            pLegacy = &sender.vPrivacyVNextNotes[i];
        if (sender.vPrivacyVNextNotes[i].txhash == hashRotated)
            pRotated = &sender.vPrivacyVNextNotes[i];
    }
    BOOST_REQUIRE_MESSAGE(pLegacy != 0,
                          "the wallet scan lost change built at the pre-rotation "
                          "index; a wallet holding older change would strand it");
    BOOST_REQUIRE_MESSAGE(pRotated != 0,
                          "the wallet scan did not reach the rotated self-pay index");
    BOOST_CHECK_EQUAL(pLegacy->nAmount, nChange);
    BOOST_CHECK_EQUAL(pRotated->nAmount, nChange);
    BOOST_CHECK(pLegacy->IsComplete());
    BOOST_CHECK(pRotated->IsComplete());
    BOOST_CHECK_EQUAL(pLegacy->nHeight, index.nHeight);

    // Found is not spendable. The recovered pre-rotation note is placed in a tree and
    // spent through the builder the wallet's own spend path calls, so what passes here
    // is live authority rather than a scan echoing an amount back.
    const CPrivacyVNextWalletNote legacyNote = *pLegacy;
    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    BOOST_REQUIRE_MESSAGE(TrimPrivacyVNextTreeStore(txdb, 0, treeState, error),
                          error);

    PrivacyVNextOutputLeaf leaf;
    std::memcpy(leaf.owner.data(), &legacyNote.vchOwner[0], 32);
    std::memcpy(leaf.nullifierBase.data(), &legacyNote.vchNullifierBase[0], 32);
    std::memcpy(leaf.commitment.data(), &legacyNote.vchCommitment[0], 32);
    std::vector<PrivacyVNextOutputLeaf> vLeaves(1, leaf);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, error), error);

    std::vector<unsigned char> vchRoot;
    uint64_t nTreeSize = 0;
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(treeState, vchRoot, nTreeSize, error), error);
    const std::vector<uint64_t> vTargets(1, (uint64_t)0);
    std::vector<unsigned char> vchPaths;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, nTreeSize, treeState, vTargets, vchPaths,
                                  error),
        error);
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths,
                                            vWitnesses, treeRoot, error),
        error);

    PrivacyVNextSpendNote spend;
    std::memcpy(spend.spendSecret.data(), &legacyNote.vchSpendSecret[0], 32);
    std::memcpy(spend.y.data(), &legacyNote.vchY[0], 32);
    std::memcpy(spend.mask.data(), &legacyNote.vchMask[0], 32);
    spend.nAmount = legacyNote.nAmount;
    spend.leaf = leaf;
    spend.vchWitnessRecord = vWitnesses[0].vchRecord;

    const uint64_t nOnward = 400;
    const uint64_t nOnwardFee = 100;
    std::vector<PrivacyVNextNewOutput> outs(2);
    outs[0].recipient.nNetwork = LocalNetwork();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = payee.spendPublic;
    outs[0].recipient.viewPublic = payee.viewPublic;
    outs[0].nAmount = nOnward;
    outs[1].recipient.nNetwork = LocalNetwork();
    outs[1].recipient.nAddressType = 0;
    outs[1].recipient.spendPublic = legacyChange.spendPublic;
    outs[1].recipient.viewPublic = legacyChange.viewPublic;
    outs[1].nAmount = legacyNote.nAmount - nOnward - nOnwardFee;

    PrivacyVNextDigest finalizedRoot;
    std::memcpy(finalizedRoot.data(), &vchRoot[0], 32);
    std::vector<unsigned char> onwardPayload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(
            LocalNetwork(), 7, funded.genesis, legacyChange.outgoingViewSecret,
            finalizedRoot, nTreeSize, NoTransparentSide(), nOnwardFee,
            std::vector<PrivacyVNextSpendNote>(1, spend), outs, onwardPayload,
            error),
        "recovered pre-rotation change could not be spent: " + error);

    // The spend retires the key image the recovered note carries, which is what makes
    // it that note rather than a second one that happens to hold the same value.
    PrivacyVNextStateEffects effects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, onwardPayload,
                      effects)
                      .IsValid());
    BOOST_REQUIRE_EQUAL(effects.keyImages.size(), 1U);
    BOOST_CHECK(std::memcmp(effects.keyImages[0].data(),
                            &legacyNote.vchKeyImage[0], 32) == 0);
}

// A restored wallet must scan a lookahead window above its issued indices; a note at a
// higher index would otherwise match no key and owe no scan gap.
BOOST_AUTO_TEST_CASE(a_restored_wallet_scans_a_lookahead_window_above_its_issued_indices)
{
    const PrivacyVNextDigest genesis = LocalGenesis();
    const PrivacyVNextDigest seed = RotationDigest(0x6d);
    std::string error;

    CWallet restored;
    std::vector<PrivacyVNextScanKey> vKeys;
    BOOST_REQUIRE_MESSAGE(
        restored.BuildPrivacyVNextScanKeys(seed, genesis, LocalNetwork(), vKeys, error),
        error);

    const uint32_t nIssued = restored.GetPrivacyVNextScanIndexCount();
    BOOST_REQUIRE_EQUAL(vKeys.size(),
                        (size_t)nIssued + (size_t)PRIVACY_VNEXT_SCAN_LOOKAHEAD + 1);
    BOOST_REQUIRE(PRIVACY_VNEXT_SCAN_LOOKAHEAD > 0);

    // Every key in the window is the address key for its own index, so a note paid to any
    // of them opens. Checking the derivation rather than the count is the point: a window
    // of the right SIZE holding the wrong keys would still lose the value.
    for (uint32_t i = 0; i < nIssued + PRIVACY_VNEXT_SCAN_LOOKAHEAD; ++i)
    {
        PrivacyVNextDerivedKeys keys;
        std::string strKeyError;
        BOOST_REQUIRE_MESSAGE(
            DerivePrivacyVNextKeys(seed, genesis, i, LocalNetwork(), 0, keys,
                                   strKeyError),
            strKeyError);
        BOOST_CHECK_MESSAGE(vKeys[i].scanSecret == keys.viewSecret,
                            "index " << i << " is not scanned by its own view key");
        BOOST_CHECK(vKeys[i].spendMaterial == keys.spendSecret);
    }

    // The self-pay key stays last, above the whole window: it is not an index anyone was
    // paid at, which is why a hit on it must never raise the issued count.
    PrivacyVNextDerivedKeys changeKeys;
    BOOST_REQUIRE(DerivePrivacyVNextChangeKeys(seed, genesis, LocalNetwork(),
                                               PRIVACY_VNEXT_INTERNAL_CHANGE_INDEX,
                                               changeKeys, error));
    BOOST_CHECK(vKeys.back().scanSecret == changeKeys.viewSecret);
}

// The budget claim is about a wallet at the issuance bound, so it has to be made at the
// bound. A fresh wallet carries one issued index and clears every check by 1021.

BOOST_AUTO_TEST_CASE(the_scan_budget_holds_at_the_issuance_bound)
{
    const PrivacyVNextDigest genesis = LocalGenesis();
    const PrivacyVNextDigest seed = RotationDigest(0x4b);
    std::string error;

    CWallet atBound;
    atBound.privacyVNextSeedRecord.nNextAddressIndex =
        PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES;
    BOOST_REQUIRE_EQUAL(atBound.GetPrivacyVNextScanIndexCount(),
                        PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES);

    std::vector<PrivacyVNextScanKey> vKeys;
    BOOST_REQUIRE_MESSAGE(
        atBound.BuildPrivacyVNextScanKeys(seed, genesis, LocalNetwork(), vKeys,
                                          error),
        "a wallet issued to the bound cannot build a scan list at all: " + error);
    const size_t nBaseKeys = vKeys.size();
    BOOST_CHECK_EQUAL(nBaseKeys, (size_t)PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES + 1);

    // The worst case the ABI has to hold: every issued index, the legacy self-pay key,
    // and the rotated key one payload names.
    CTxDB txdb("r+");
    FundedNotes funded;
    FundNotes(txdb, 1, funded, 0x4c);
    PrivacyVNextDerivedKeys payee;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(RotationDigest(0x4d), funded.genesis, 0,
                               LocalNetwork(), 0, payee, error),
        error);
    const std::vector<PrivacyVNextDigest> vSpent(1, funded.vKeyImages[0]);
    PrivacyVNextDerivedKeys change;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildTransferWithChangeAt(funded, 0, seed,
                                  ChangeIndexForSpendOf(funded.genesis, vSpent), 7,
                                  payee, 1500, 100, change, payload, error),
        error);
    const CTransaction txCarrier = CarrierOf(payload);

    BOOST_REQUIRE_MESSAGE(
        atBound.ExtendPrivacyVNextScanKeysForPayload(
            seed, genesis, LocalNetwork(), txCarrier, nBaseKeys, vKeys, error),
        "a wallet at the bound cannot carry the rotated self-pay key: " + error);
    BOOST_CHECK_EQUAL(vKeys.size(), (size_t)PRIVACY_VNEXT_MAX_SCAN_KEYS);

    // The same payload one slot past the bound. Refusing here and accepting above is
    // what says the refusal is the list length rather than anything about the payload.
    std::vector<PrivacyVNextScanKey> vOver(PRIVACY_VNEXT_MAX_SCAN_KEYS);
    error.clear();
    BOOST_CHECK(!atBound.ExtendPrivacyVNextScanKeysForPayload(
        seed, genesis, LocalNetwork(), txCarrier, vOver.size(), vOver, error));
    BOOST_CHECK(!error.empty());

    // A wallet issued one index past the current bound -- reachable only for one issued
    // under the older, larger bound -- must refuse loudly rather than scan a short list
    // and report the blocks as covered.
    CWallet overBound;
    overBound.privacyVNextSeedRecord.nNextAddressIndex =
        PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES + 1;
    std::vector<PrivacyVNextScanKey> vRefused;
    error.clear();
    BOOST_CHECK(!overBound.BuildPrivacyVNextScanKeys(seed, genesis, LocalNetwork(),
                                                     vRefused, error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(vRefused.empty());
}

BOOST_AUTO_TEST_SUITE_END()

namespace
{

uint256 LocalGenesisHash()
{
    const PrivacyVNextDigest d = LocalGenesis();
    uint256 h;
    std::memcpy(h.begin(), d.data(), 32);
    return h;
}

CPrivacyVNextViewKeyEntry ViewEntryFor(unsigned char seedFill, uint32_t nIndex)
{
    PrivacyVNextDerivedKeys keys;
    std::string error;
    BOOST_REQUIRE_MESSAGE(DerivePrivacyVNextKeys(RotationDigest(seedFill), LocalGenesis(),
                                                 nIndex, LocalNetwork(), 0, keys, error),
                          error);
    CPrivacyVNextViewKeyEntry entry;
    entry.nIndex = nIndex;
    entry.vchViewSecret.assign(keys.viewSecret.begin(), keys.viewSecret.end());
    entry.vchSpendPublic.assign(keys.spendPublic.begin(), keys.spendPublic.end());
    entry.vchViewPublic.assign(keys.viewPublic.begin(), keys.viewPublic.end());
    return entry;
}

CPrivacyVNextViewKeyRecord ViewKeyFor(unsigned char seedFill,
                                      const std::vector<uint32_t>& vIndices)
{
    CPrivacyVNextViewKeyRecord record;
    record.nNetwork = LocalNetwork();
    record.hashGenesis = LocalGenesisHash();
    for (size_t i = 0; i < vIndices.size(); ++i)
        record.vEntries.push_back(ViewEntryFor(seedFill, vIndices[i]));
    return record;
}

bool SameEntries(const CPrivacyVNextViewKeyRecord& a, const CPrivacyVNextViewKeyRecord& b)
{
    if (a.vEntries.size() != b.vEntries.size() || a.nNetwork != b.nNetwork ||
        a.hashGenesis != b.hashGenesis || a.nVersion != b.nVersion)
        return false;
    for (size_t i = 0; i < a.vEntries.size(); ++i)
        if (a.vEntries[i].nIndex != b.vEntries[i].nIndex ||
            a.vEntries[i].vchViewSecret != b.vEntries[i].vchViewSecret ||
            a.vEntries[i].vchSpendPublic != b.vEntries[i].vchSpendPublic ||
            a.vEntries[i].vchViewPublic != b.vEntries[i].vchViewPublic)
            return false;
    return true;
}

} // namespace

BOOST_AUTO_TEST_SUITE(privacy_vnext_viewkey_tests)

BOOST_AUTO_TEST_CASE(a_viewing_key_round_trips_and_refuses_corruption)
{
    std::vector<uint32_t> vIndices;
    vIndices.push_back(0);
    vIndices.push_back(1);
    vIndices.push_back(4);
    const CPrivacyVNextViewKeyRecord record = ViewKeyFor(0x81, vIndices);
    const std::string strKey = EncodePrivacyVNextViewKey(record);
    const std::string strHrp = PrivacyVNextViewKeyHrp(LocalNetwork());
    BOOST_REQUIRE_EQUAL(strKey.substr(0, strHrp.size() + 1), strHrp + "1");

    CPrivacyVNextViewKeyRecord decoded;
    std::string error;
    BOOST_REQUIRE_MESSAGE(DecodePrivacyVNextViewKey(strKey, LocalNetwork(), LocalGenesisHash(),
                                                    decoded, error),
                          error);
    BOOST_CHECK(SameEntries(record, decoded));
    BOOST_CHECK(PrivacyVNextViewKeyId(record) == PrivacyVNextViewKeyId(decoded));
    BOOST_CHECK(EncodePrivacyVNextViewKey(decoded) == strKey);

    // Case and whitespace are transport noise, not a different key.
    std::string strUpper;
    for (size_t i = 0; i < strKey.size(); ++i)
        strUpper += (char)toupper(strKey[i]);
    BOOST_CHECK(DecodePrivacyVNextViewKey(" " + strUpper + "\n", LocalNetwork(),
                                          LocalGenesisHash(), decoded, error));

    // Checksum: every single-character change in the data part is refused.
    const char* pszAlphabet = "abcdefghijklmnopqrstuvwxyz234567";
    size_t nTried = 0;
    for (size_t pos = strHrp.size() + 1; pos < strKey.size(); pos += 3)
    {
        std::string strBad = strKey;
        const char* p = strchr(pszAlphabet, strBad[pos]);
        BOOST_REQUIRE(p != NULL);
        strBad[pos] = pszAlphabet[((p - pszAlphabet) + 1) % 32];
        CPrivacyVNextViewKeyRecord refused;
        BOOST_CHECK_MESSAGE(!DecodePrivacyVNextViewKey(strBad, LocalNetwork(),
                                                       LocalGenesisHash(), refused, error),
                            strprintf("a key with character %u changed decoded", (unsigned)pos));
        BOOST_CHECK(refused.vEntries.empty());
        ++nTried;
    }
    BOOST_CHECK(nTried > 100);
    {
        // A changed view-secret byte, as a checksum-only difference would carry it.
        std::string strBad = strKey;
        const size_t pos = strHrp.size() + 1 + 80;
        strBad[pos] = strBad[pos] == 'a' ? 'b' : 'a';
        BOOST_CHECK(!DecodePrivacyVNextViewKey(strBad, LocalNetwork(), LocalGenesisHash(),
                                               decoded, error));
        BOOST_CHECK_MESSAGE(error.find("checksum") != std::string::npos, error);
    }

    // Network tag: the same key on another network, and a prefix swapped onto it.
    for (uint8_t nOther = 0; nOther <= 2; ++nOther)
    {
        if (nOther == LocalNetwork())
            continue;
        CPrivacyVNextViewKeyRecord refused;
        BOOST_CHECK(!DecodePrivacyVNextViewKey(strKey, nOther, LocalGenesisHash(), refused,
                                               error));
        BOOST_CHECK_MESSAGE(error.find("network") != std::string::npos, error);

        const std::string strSwapped =
            PrivacyVNextViewKeyHrp(nOther) + strKey.substr(strHrp.size());
        BOOST_CHECK(!DecodePrivacyVNextViewKey(strSwapped, LocalNetwork(), LocalGenesisHash(),
                                               refused, error));
        BOOST_CHECK(!DecodePrivacyVNextViewKey(strSwapped, nOther, LocalGenesisHash(),
                                               refused, error));
    }

    // Another chain's genesis.
    uint256 otherGenesis = LocalGenesisHash();
    otherGenesis.begin()[0] ^= 1;
    BOOST_CHECK(!DecodePrivacyVNextViewKey(strKey, LocalNetwork(), otherGenesis, decoded,
                                           error));

    // A well-formed key of a version this build does not know.
    CPrivacyVNextViewKeyRecord future = record;
    future.nVersion = PRIVACY_VNEXT_VIEWKEY_VERSION + 1;
    BOOST_CHECK(!DecodePrivacyVNextViewKey(EncodePrivacyVNextViewKey(future), LocalNetwork(),
                                           LocalGenesisHash(), decoded, error));
    BOOST_CHECK_MESSAGE(error.find("version") != std::string::npos, error);

    // Self-pay indices and non-canonical order are never in a viewing key.
    CPrivacyVNextViewKeyRecord selfPay = record;
    selfPay.vEntries[2].nIndex = PRIVACY_VNEXT_INTERNAL_CHANGE_INDEX;
    BOOST_CHECK(!DecodePrivacyVNextViewKey(EncodePrivacyVNextViewKey(selfPay), LocalNetwork(),
                                           LocalGenesisHash(), decoded, error));
    CPrivacyVNextViewKeyRecord reversed = record;
    std::swap(reversed.vEntries[0], reversed.vEntries[1]);
    BOOST_CHECK(!DecodePrivacyVNextViewKey(EncodePrivacyVNextViewKey(reversed), LocalNetwork(),
                                           LocalGenesisHash(), decoded, error));

    // Truncation and trailing garbage.
    BOOST_CHECK(!DecodePrivacyVNextViewKey(strKey.substr(0, strKey.size() - 8), LocalNetwork(),
                                           LocalGenesisHash(), decoded, error));
    BOOST_CHECK(!DecodePrivacyVNextViewKey(strKey + "q", LocalNetwork(), LocalGenesisHash(),
                                           decoded, error));
}

BOOST_AUTO_TEST_CASE(an_import_proves_each_view_secret_opens_its_address)
{
    std::string error;
    BOOST_CHECK_MESSAGE(VerifyPrivacyVNextViewKeyEntry(LocalNetwork(), LocalGenesisHash(),
                                                       ViewEntryFor(0x82, 3), error),
                        error);

    // Index 1's view secret against index 0's address: well-formed, and wrong.
    CPrivacyVNextViewKeyEntry mixed = ViewEntryFor(0x82, 0);
    mixed.vchViewSecret = ViewEntryFor(0x82, 1).vchViewSecret;
    BOOST_CHECK(!VerifyPrivacyVNextViewKeyEntry(LocalNetwork(), LocalGenesisHash(), mixed,
                                                error));

    std::vector<uint32_t> vIndices(1, 0);
    CPrivacyVNextViewKeyRecord record = ViewKeyFor(0x82, vIndices);
    record.vEntries[0] = mixed;
    CWallet wallet;
    uint256 id;
    bool fNew = false;
    BOOST_CHECK(!wallet.ImportPrivacyVNextViewKey(record, id, fNew, error));
    BOOST_CHECK(wallet.mapPrivacyVNextViewKeys.empty());
}

BOOST_AUTO_TEST_CASE(an_export_covers_exactly_the_issued_addresses)
{
    CWallet wallet;
    const PrivacyVNextDigest seed = RotationDigest(0x83);
    wallet.vchPrivacyVNextSeed.assign(seed.begin(), seed.end());
    wallet.privacyVNextSeedRecord.nGeneration = PRIVACY_VNEXT_WALLET_SEED_GENERATION;
    wallet.privacyVNextSeedRecord.nNextAddressIndex = 3;

    CPrivacyVNextViewKeyRecord exported;
    std::vector<std::string> vAddresses;
    std::string error;
    BOOST_REQUIRE_MESSAGE(wallet.ExportPrivacyVNextViewKey("", exported, vAddresses, error),
                          error);
    std::vector<uint32_t> vIssued;
    vIssued.push_back(0);
    vIssued.push_back(1);
    vIssued.push_back(2);
    BOOST_CHECK(SameEntries(exported, ViewKeyFor(0x83, vIssued)));
    BOOST_CHECK_EQUAL(vAddresses.size(), 3U);

    // One address: exactly its index, nothing else.
    std::string strSingle;
    PrivacyVNextAddressComponents components;
    components.nNetwork = LocalNetwork();
    const CPrivacyVNextViewKeyEntry second = ViewEntryFor(0x83, 1);
    std::memcpy(components.spendPublic.data(), &second.vchSpendPublic[0], 32);
    std::memcpy(components.viewPublic.data(), &second.vchViewPublic[0], 32);
    BOOST_REQUIRE_MESSAGE(EncodePrivacyVNextAddress(components, strSingle, error), error);
    BOOST_REQUIRE_MESSAGE(wallet.ExportPrivacyVNextViewKey(strSingle, exported, vAddresses,
                                                           error),
                          error);
    BOOST_REQUIRE_EQUAL(exported.vEntries.size(), 1U);
    BOOST_CHECK_EQUAL(exported.vEntries[0].nIndex, 1U);
    BOOST_REQUIRE_EQUAL(vAddresses.size(), 1U);
    BOOST_CHECK_EQUAL(vAddresses[0], strSingle);

    // An address above the issued range is not exported.
    const CPrivacyVNextViewKeyEntry unissued = ViewEntryFor(0x83, 3);
    std::memcpy(components.spendPublic.data(), &unissued.vchSpendPublic[0], 32);
    std::memcpy(components.viewPublic.data(), &unissued.vchViewPublic[0], 32);
    BOOST_REQUIRE_MESSAGE(EncodePrivacyVNextAddress(components, strSingle, error), error);
    BOOST_CHECK(!wallet.ExportPrivacyVNextViewKey(strSingle, exported, vAddresses, error));

    // No seed, no export.
    CWallet seedless;
    BOOST_CHECK(!seedless.ExportPrivacyVNextViewKey("", exported, vAddresses, error));
}

BOOST_AUTO_TEST_CASE(a_watch_only_wallet_sees_incoming_notes_and_cannot_spend_them)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNotes funded;
    FundNotes(txdb, 1, funded, 0x84);

    const PrivacyVNextDigest senderSeed = RotationDigest(0x84);
    const unsigned char payeeFill = 0x85;
    PrivacyVNextDerivedKeys payee;
    BOOST_REQUIRE_MESSAGE(DerivePrivacyVNextKeys(RotationDigest(payeeFill), funded.genesis, 2,
                                                 LocalNetwork(), 0, payee, error),
                          error);

    const uint64_t nPaid = 1500;
    const uint64_t nFee = 100;
    const uint64_t nChange = funded.nAmount - nPaid - nFee;
    const std::vector<PrivacyVNextDigest> vSpent(1, funded.vKeyImages[0]);
    PrivacyVNextDerivedKeys change;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildTransferWithChangeAt(funded, 0, senderSeed,
                                  ChangeIndexForSpendOf(funded.genesis, vSpent), 7, payee,
                                  nPaid, nFee, change, payload, error),
        error);

    CBlock block;
    block.vtx.push_back(CarrierOf(payload));
    const uint256 hashTx = block.vtx[0].GetHash();
    CBlockIndex index;
    index.nHeight = 120;
    const std::set<uint256> setNoneSkipped;

    // Control: the payee's own wallet opens the payment as an owned note.
    CWallet owner;
    const PrivacyVNextDigest payeeSeed = RotationDigest(payeeFill);
    owner.vchPrivacyVNextSeed.assign(payeeSeed.begin(), payeeSeed.end());
    owner.privacyVNextSeedRecord.nNextAddressIndex = 3;
    BOOST_REQUIRE_MESSAGE(owner.ApplyPrivacyVNextBlock(block, setNoneSkipped, &index, error),
                          error);
    BOOST_REQUIRE_EQUAL(owner.vPrivacyVNextNotes.size(), 1U);
    BOOST_CHECK_EQUAL(owner.vPrivacyVNextNotes[0].nAmount, nPaid);

    // A seedless wallet holding the payee's viewing key and the sender's issued-address
    // key. The sender's key must not open the rotated change: it derives from the seed.
    CWallet watcher;
    std::vector<uint32_t> vPayee;
    vPayee.push_back(0);
    vPayee.push_back(1);
    vPayee.push_back(2);
    std::vector<uint32_t> vSender(1, 0);
    uint256 idPayee, idSender;
    bool fNew = false;
    BOOST_REQUIRE_MESSAGE(watcher.ImportPrivacyVNextViewKey(ViewKeyFor(payeeFill, vPayee),
                                                            idPayee, fNew, error),
                          error);
    BOOST_CHECK(fNew);
    BOOST_REQUIRE_MESSAGE(watcher.ImportPrivacyVNextViewKey(ViewKeyFor(0x84, vSender),
                                                            idSender, fNew, error),
                          error);
    BOOST_CHECK(watcher.ImportPrivacyVNextViewKey(ViewKeyFor(payeeFill, vPayee), idPayee, fNew,
                                                  error));
    BOOST_CHECK(!fNew);
    BOOST_CHECK_EQUAL(watcher.mapPrivacyVNextViewKeys.size(), 2U);

    BOOST_REQUIRE_MESSAGE(watcher.ApplyPrivacyVNextBlock(block, setNoneSkipped, &index, error),
                          error);
    // Re-applying the same block credits nothing twice.
    BOOST_REQUIRE_MESSAGE(watcher.ApplyPrivacyVNextBlock(block, setNoneSkipped, &index, error),
                          error);
    BOOST_REQUIRE_EQUAL(watcher.vPrivacyVNextWatchNotes.size(), 1U);
    const CPrivacyVNextWatchNote& watch = watcher.vPrivacyVNextWatchNotes[0];
    BOOST_CHECK(watch.txhash == hashTx);
    BOOST_CHECK_EQUAL(watch.nAmount, nPaid);
    BOOST_CHECK_EQUAL(watch.nKeyIndex, 2U);
    BOOST_CHECK(watch.viewKeyId == idPayee);
    BOOST_CHECK(watch.nHeight == index.nHeight);
    BOOST_CHECK(std::memcmp(&watch.vchOwner[0], &owner.vPrivacyVNextNotes[0].vchOwner[0],
                            32) == 0);
    BOOST_CHECK_EQUAL(watcher.GetPrivacyVNextWatchOnlyBalance(), (int64_t)nPaid);
    BOOST_CHECK_MESSAGE(watcher.GetPrivacyVNextWatchOnlyBalance() != (int64_t)(nPaid + nChange),
                        "a viewing key over issued addresses opened rotated change");

    // Nothing reaches the owned side: no note, no owned balance, nothing to select.
    BOOST_CHECK_MESSAGE(watcher.vPrivacyVNextNotes.empty(),
                        "a watch-only note entered the spendable note set");
    BOOST_CHECK_EQUAL(watcher.GetPrivacyVNextUnconfirmedBalance(
                          std::numeric_limits<uint64_t>::max()), 0);
    BOOST_CHECK_EQUAL(watcher.GetPrivacyVNextBalance(std::numeric_limits<uint64_t>::max()), 0);
    BOOST_CHECK_EQUAL(watcher.GetPrivacyVNextUnplacedBalance(), 0);
    BOOST_CHECK_EQUAL(watcher.GetPrivacyVNextHeldBalance(), 0);
    std::vector<CPrivacyVNextWalletNote> vSelected;
    int64_t nSelected = 0;
    BOOST_CHECK(!watcher.SelectPrivacyVNextNotes((int64_t)nPaid, 1000000, vSelected, nSelected));
    BOOST_CHECK(vSelected.empty());

    // The payee's key held by the owner itself is not counted twice.
    BOOST_REQUIRE(owner.ImportPrivacyVNextViewKey(ViewKeyFor(payeeFill, vPayee), idPayee, fNew,
                                                  error));
    BOOST_REQUIRE(owner.ApplyPrivacyVNextBlock(block, setNoneSkipped, &index, error));
    BOOST_CHECK_EQUAL(owner.vPrivacyVNextWatchNotes.size(), 1U);
    BOOST_CHECK_EQUAL(owner.GetPrivacyVNextWatchOnlyBalance(), 0);

    // A disconnect takes the watch note back out.
    BOOST_REQUIRE_MESSAGE(watcher.DisconnectPrivacyVNextBlock(block, setNoneSkipped, &index,
                                                              error),
                          error);
    BOOST_CHECK(watcher.vPrivacyVNextWatchNotes.empty());
    BOOST_CHECK_EQUAL(watcher.GetPrivacyVNextWatchOnlyBalance(), 0);

    // A skipped transaction created nothing, for a viewing key as for the owner.
    std::set<uint256> setSkipped;
    setSkipped.insert(hashTx);
    BOOST_REQUIRE(watcher.ApplyPrivacyVNextBlock(block, setSkipped, &index, error));
    BOOST_CHECK(watcher.vPrivacyVNextWatchNotes.empty());
}

// A block carrying one skipped and one active payload: the watch scan runs, and
// records the active payment only.
BOOST_AUTO_TEST_CASE(a_watch_scan_skips_a_skipped_payload_beside_an_active_one)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNotes funded;
    FundNotes(txdb, 2, funded, 0x86);

    const PrivacyVNextDigest senderSeed = RotationDigest(0x86);
    const unsigned char payeeFill = 0x87;
    PrivacyVNextDerivedKeys vPayee[2];
    for (int i = 0; i < 2; ++i)
        BOOST_REQUIRE_MESSAGE(DerivePrivacyVNextKeys(RotationDigest(payeeFill), funded.genesis,
                                                     (uint32_t)(1 + i), LocalNetwork(), 0,
                                                     vPayee[i], error),
                              error);

    const uint64_t vPaid[2] = { 1500, 2500 };
    const uint64_t nFee = 100;
    CBlock block;
    for (size_t n = 0; n < 2; ++n)
    {
        const std::vector<PrivacyVNextDigest> vSpent(1, funded.vKeyImages[n]);
        PrivacyVNextDerivedKeys change;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE_MESSAGE(
            BuildTransferWithChangeAt(funded, n, senderSeed,
                                      ChangeIndexForSpendOf(funded.genesis, vSpent), 7,
                                      vPayee[n], vPaid[n], nFee, change, payload, error),
            error);
        block.vtx.push_back(CarrierOf(payload));
    }
    const uint256 hashSkipped = block.vtx[0].GetHash();
    const uint256 hashActive = block.vtx[1].GetHash();
    BOOST_REQUIRE(hashSkipped != hashActive);
    CBlockIndex index;
    index.nHeight = 121;

    std::vector<uint32_t> vIndices;
    vIndices.push_back(0);
    vIndices.push_back(1);
    vIndices.push_back(2);
    CWallet watcher;
    uint256 id;
    bool fNew = false;
    BOOST_REQUIRE_MESSAGE(watcher.ImportPrivacyVNextViewKey(ViewKeyFor(payeeFill, vIndices),
                                                            id, fNew, error),
                          error);

    // Control: with nothing skipped the key opens both payments.
    {
        CWallet control;
        BOOST_REQUIRE(control.ImportPrivacyVNextViewKey(ViewKeyFor(payeeFill, vIndices), id,
                                                        fNew, error));
        const std::set<uint256> setNoneSkipped;
        BOOST_REQUIRE_MESSAGE(control.ApplyPrivacyVNextBlock(block, setNoneSkipped, &index,
                                                             error),
                              error);
        BOOST_CHECK_EQUAL(control.vPrivacyVNextWatchNotes.size(), 2U);
    }

    std::set<uint256> setSkipped;
    setSkipped.insert(hashSkipped);
    BOOST_REQUIRE_MESSAGE(watcher.ApplyPrivacyVNextBlock(block, setSkipped, &index, error),
                          error);
    BOOST_REQUIRE_EQUAL(watcher.vPrivacyVNextWatchNotes.size(), 1U);
    BOOST_CHECK(watcher.vPrivacyVNextWatchNotes[0].txhash == hashActive);
    BOOST_CHECK_EQUAL(watcher.vPrivacyVNextWatchNotes[0].nAmount, vPaid[1]);
    BOOST_CHECK_EQUAL(watcher.GetPrivacyVNextWatchOnlyBalance(), (int64_t)vPaid[1]);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(privacy_vnext_held_balance_tests)

BOOST_AUTO_TEST_CASE(holding_a_note_moves_value_from_owned_figures_to_held)
{
    CWallet wallet;
    CPrivacyVNextWalletNote note;
    note.txhash = uint256(7);
    note.nOutputIndex = 1;
    note.nHeight = 50;
    note.nAmount = 4200;
    note.vchOwner.assign(32, 1);
    note.vchNullifierBase.assign(32, 2);
    note.vchCommitment.assign(32, 3);
    note.vchSpendSecret.assign(32, 4);
    note.vchY.assign(32, 5);
    note.vchMask.assign(32, 6);
    note.vchKeyImage.assign(32, 7);
    CPrivacyVNextWalletNote other = note;
    other.txhash = uint256(8);
    other.nAmount = 800;
    other.vchKeyImage.assign(32, 9);
    wallet.vPrivacyVNextNotes.push_back(note);
    wallet.vPrivacyVNextNotes.push_back(other);

    const uint64_t nAll = std::numeric_limits<uint64_t>::max();
    const int64_t nOwnedBefore = wallet.GetPrivacyVNextBalance(nAll) +
                                 wallet.GetPrivacyVNextUnconfirmedBalance(nAll) +
                                 wallet.GetPrivacyVNextCollateralBalance() +
                                 wallet.GetPrivacyVNextHeldBalance();
    BOOST_CHECK_EQUAL(nOwnedBefore, 5000);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextHeldBalance(), 0);

    std::string error;
    BOOST_REQUIRE_MESSAGE(wallet.SetPrivacyVNextHold(note.txhash, note.nOutputIndex, true,
                                                     error),
                          error);
    const int64_t nFree = wallet.GetPrivacyVNextBalance(nAll) +
                          wallet.GetPrivacyVNextUnconfirmedBalance(nAll);
    BOOST_CHECK_EQUAL(nFree, 800);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextHeldBalance(), 4200);
    BOOST_CHECK_EQUAL(nFree + wallet.GetPrivacyVNextCollateralBalance() +
                          wallet.GetPrivacyVNextHeldBalance(),
                      nOwnedBefore);

    BOOST_REQUIRE(wallet.SetPrivacyVNextHold(note.txhash, note.nOutputIndex, false, error));
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextHeldBalance(), 0);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextBalance(nAll) +
                          wallet.GetPrivacyVNextUnconfirmedBalance(nAll),
                      5000);
}

BOOST_AUTO_TEST_SUITE_END()
