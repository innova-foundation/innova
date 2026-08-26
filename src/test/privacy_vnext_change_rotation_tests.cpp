#include <boost/test/unit_test.hpp>

#include <algorithm>
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
                RotationScalar((unsigned char)(113 + i)), vFunding[i], error),
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
    BOOST_REQUIRE_EQUAL(nBaseKeys, (size_t)nIssued + 1);

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
    BOOST_CHECK_EQUAL((size_t)vMatches[0].nKeyIndex, (size_t)nIssued);

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
    BOOST_CHECK_EQUAL((size_t)vMatches[0].nKeyIndex, (size_t)nIssued);
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
    const size_t nBaseKeys = vKeys.size();
    BOOST_REQUIRE_EQUAL(nBaseKeys,
                        (size_t)localWallet.GetPrivacyVNextScanIndexCount() + 1);

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

BOOST_AUTO_TEST_SUITE_END()
