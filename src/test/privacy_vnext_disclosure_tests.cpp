#include <boost/test/unit_test.hpp>

#include <cstring>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../main.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../privacy_vnext_wallet.h"
#include "../txdb.h"
#include "../wallet.h"

namespace
{

PrivacyVNextDigest DisclosureDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

PrivacyVNextDigest DisclosureScalar(unsigned char low)
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

// One note of `nAmount`, placed in the tree and ready to be spent.
struct FundedNote
{
    PrivacyVNextDigest genesis;
    PrivacyVNextDerivedKeys keys;
    std::vector<PrivacyVNextSpendNote> spends;
    PrivacyVNextDigest finalizedRoot;
    uint64_t nTreeSize;
    uint64_t nAmount;
};

void FundOneNote(CTxDB& txdb, FundedNote& funded, unsigned char seedFill)
{
    std::string error;
    funded.genesis = LocalGenesis();
    funded.nAmount = 5000;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(DisclosureDigest(seedFill), funded.genesis, 0,
                               LocalNetwork(), 0, funded.keys, error),
        error);

    PrivacyVNextEncryptedOutput funding;
    BOOST_REQUIRE_MESSAGE(
        EncryptPrivacyVNextNote(LocalNetwork(), 0, 0, funded.genesis,
                                funded.keys.spendPublic, funded.keys.viewPublic,
                                funded.keys.outgoingViewSecret,
                                DisclosureScalar(29), DisclosureScalar(30),
                                funded.nAmount, DisclosureScalar(31),
                                DisclosureScalar(37), funding, error),
        error);

    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    BOOST_REQUIRE_MESSAGE(TrimPrivacyVNextTreeStore(txdb, 0, treeState, error),
                          error);
    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    vLeaves.push_back(funding.leaf);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, error), error);

    std::vector<unsigned char> vchRoot;
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(treeState, vchRoot, funded.nTreeSize, error),
        error);
    std::vector<uint64_t> vTargets;
    vTargets.push_back(0);
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

    PrivacyVNextEncryptedNote onChain;
    onChain.nOutputIndex = 0;
    onChain.genesis = funded.genesis;
    onChain.leafO = funding.leaf.owner;
    onChain.leafC = funding.leaf.commitment;
    onChain.noteEphemeral = funding.noteEphemeral;
    onChain.tweakEphemeral = funding.tweakEphemeral;
    onChain.vchCiphertext = funding.vchRecipientCiphertext;
    PrivacyVNextScannedNote scanned;
    BOOST_REQUIRE_MESSAGE(
        ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, LocalNetwork(), 0, onChain,
                             funded.keys.viewSecret, funded.keys.spendSecret,
                             scanned, error),
        error);

    funded.spends.resize(1);
    funded.spends[0].spendSecret = scanned.spendSecret;
    funded.spends[0].y = scanned.y;
    funded.spends[0].mask = scanned.mask;
    funded.spends[0].nAmount = scanned.nAmount;
    funded.spends[0].leaf = funding.leaf;
    funded.spends[0].vchWitnessRecord = vWitnesses[0].vchRecord;
    std::memcpy(funded.finalizedRoot.data(), &vchRoot[0], 32);
}

} // namespace

BOOST_AUTO_TEST_SUITE(privacy_vnext_disclosure_tests)

// A receiver disclosure publishes the change recipient's address keys, so change from a
// user-facing index would name the sender.
BOOST_AUTO_TEST_CASE(change_keys_are_never_an_issued_address)
{
    const PrivacyVNextDigest seed = DisclosureDigest(0x4d);
    const PrivacyVNextDigest genesis = LocalGenesis();
    std::string error;

    PrivacyVNextDerivedKeys change;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextChangeKeys(seed, genesis, LocalNetwork(), change, error),
        error);

    // Issuance refuses at PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES, so the issuable range is
    // [0, PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES). Both ends are covered plus a run at the
    // start, where every wallet issues before it issues anywhere else.
    std::vector<uint32_t> vIssuable;
    for (uint32_t i = 0; i < 64; ++i)
        vIssuable.push_back(i);
    vIssuable.push_back(PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES - 1);

    for (size_t i = 0; i < vIssuable.size(); ++i)
    {
        PrivacyVNextDerivedKeys issued;
        BOOST_REQUIRE_MESSAGE(
            DerivePrivacyVNextKeys(seed, genesis, vIssuable[i], LocalNetwork(), 0,
                                   issued, error),
            error);
        BOOST_CHECK_MESSAGE(
            change.spendPublic != issued.spendPublic,
            strprintf("change shares its spend key with issuable index %u",
                      vIssuable[i]));
        BOOST_CHECK_MESSAGE(
            change.viewPublic != issued.viewPublic,
            strprintf("change shares its view key with issuable index %u",
                      vIssuable[i]));
    }

    // The separation only holds while the change index sits outside everything the
    // allocator can reach.
    BOOST_CHECK(PRIVACY_VNEXT_INTERNAL_CHANGE_INDEX >= PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES);
    // And the change key has to fit the scan alongside every issuable one, or a full
    // wallet would build a key list the scan ABI refuses and would scan nothing.
    BOOST_CHECK_LE((size_t)PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES + 1,
                   (size_t)PRIVACY_VNEXT_MAX_SCAN_KEYS);
}

// The property at the level it is actually observed: the bytes on the wire. Mask 5
// hides the sender and the amounts and publishes the recipients, which is the mode a
// payee is given to prove a payment without learning who paid.
BOOST_AUTO_TEST_CASE(a_disclosing_transfer_publishes_no_issued_address)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNote funded;
    FundOneNote(txdb, funded, 0x63);

    // The payee: a different wallet's address, and the one party the disclosure exists
    // for.
    PrivacyVNextDerivedKeys payee;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(DisclosureDigest(0x64), funded.genesis, 0,
                               LocalNetwork(), 0, payee, error),
        error);

    // The sender's change, through the one function every self-pay site uses.
    PrivacyVNextDerivedKeys change;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextChangeKeys(DisclosureDigest(0x63), funded.genesis,
                                     LocalNetwork(), change, error),
        error);

    const uint64_t nFee = 100;
    const uint64_t nPaid = 1500;
    std::vector<PrivacyVNextNewOutput> outs;
    outs.resize(2);
    outs[0].recipient.nNetwork = LocalNetwork();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = payee.spendPublic;
    outs[0].recipient.viewPublic = payee.viewPublic;
    outs[0].nAmount = nPaid;
    outs[1].recipient.nNetwork = LocalNetwork();
    outs[1].recipient.nAddressType = 0;
    outs[1].recipient.spendPublic = change.spendPublic;
    outs[1].recipient.viewPublic = change.viewPublic;
    outs[1].nAmount = funded.nAmount - nPaid - nFee;

    const uint8_t nMask = iv5::DISCLOSURE_HIDE_SENDER | iv5::DISCLOSURE_HIDE_AMOUNT;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(
            LocalNetwork(), nMask, funded.genesis, funded.keys.outgoingViewSecret,
            funded.finalizedRoot, funded.nTreeSize, NoTransparentSide(), nFee,
            funded.spends, outs, payload, error),
        error);
    BOOST_REQUIRE_MESSAGE(
        ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                    payload).IsValid(),
        "the disclosing transfer did not validate");

    // The disclosure really does publish both recipients. Without this the absence
    // checks below would pass against a payload that discloses nothing at all.
    BOOST_CHECK(PayloadContains(payload, AddressBytes(payee)));
    BOOST_CHECK(PayloadContains(payload, AddressBytes(change)));

    // And the address published for the change output is one the sender could never
    // have given anybody: no index the allocator can issue derives it.
    for (uint32_t nIndex = 0; nIndex < 64; ++nIndex)
    {
        PrivacyVNextDerivedKeys issued;
        BOOST_REQUIRE_MESSAGE(
            DerivePrivacyVNextKeys(DisclosureDigest(0x63), funded.genesis, nIndex,
                                   LocalNetwork(), 0, issued, error),
            error);
        BOOST_CHECK_MESSAGE(
            !PayloadContains(payload, AddressBytes(issued)),
            strprintf("the disclosure publishes the sender's issued address %u",
                      nIndex));
        // Neither half on its own, either: half an address still names the wallet.
        const std::vector<unsigned char> vSpend(issued.spendPublic.begin(),
                                                issued.spendPublic.end());
        const std::vector<unsigned char> vView(issued.viewPublic.begin(),
                                               issued.viewPublic.end());
        BOOST_CHECK_MESSAGE(
            !PayloadContains(payload, vSpend),
            strprintf("the disclosure publishes issued index %u's spend key", nIndex));
        BOOST_CHECK_MESSAGE(
            !PayloadContains(payload, vView),
            strprintf("the disclosure publishes issued index %u's view key", nIndex));
    }
}

// Change that a scan cannot reach is change that cannot be spent, and unshield is
// retired, so it would be value with no recovery path. Moving change off the issued
// range put it outside the bound a scan derives from issuance, so the key list has to
// carry it explicitly.
BOOST_AUTO_TEST_CASE(a_change_note_stays_findable_and_spendable)
{
    const PrivacyVNextDigest seed = DisclosureDigest(0x71);
    const PrivacyVNextDigest genesis = LocalGenesis();
    std::string error;

    CWallet localWallet;
    std::vector<PrivacyVNextScanKey> vKeys;
    BOOST_REQUIRE_MESSAGE(
        localWallet.BuildPrivacyVNextScanKeys(seed, genesis, LocalNetwork(), vKeys,
                                              error),
        error);
    const uint32_t nIssued = localWallet.GetPrivacyVNextScanIndexCount();
    BOOST_REQUIRE_EQUAL(vKeys.size(), (size_t)nIssued + 1);

    PrivacyVNextDerivedKeys change;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextChangeKeys(seed, genesis, LocalNetwork(), change, error),
        error);
    BOOST_CHECK(vKeys[nIssued].scanSecret == change.viewSecret);
    BOOST_CHECK(vKeys[nIssued].spendMaterial == change.spendSecret);

    // A note actually paid to change must reopen under that list, with the material a
    // spend needs and not merely the view of it.
    PrivacyVNextEncryptedOutput note;
    BOOST_REQUIRE_MESSAGE(
        EncryptPrivacyVNextNote(LocalNetwork(), 0, 0, genesis, change.spendPublic,
                                change.viewPublic, change.outgoingViewSecret,
                                DisclosureScalar(41), DisclosureScalar(43), 777,
                                DisclosureScalar(47), DisclosureScalar(53), note,
                                error),
        error);

    PrivacyVNextEncryptedNote onChain;
    onChain.nOutputIndex = 0;
    onChain.genesis = genesis;
    onChain.leafO = note.leaf.owner;
    onChain.leafC = note.leaf.commitment;
    onChain.noteEphemeral = note.noteEphemeral;
    onChain.tweakEphemeral = note.tweakEphemeral;
    onChain.vchCiphertext = note.vchRecipientCiphertext;

    bool fFound = false;
    PrivacyVNextDigest zero;
    zero.fill(0);
    for (size_t i = 0; i < vKeys.size(); ++i)
    {
        PrivacyVNextScannedNote scanned;
        std::string strScanError;
        if (!ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, LocalNetwork(), 0, onChain,
                                  vKeys[i].scanSecret, vKeys[i].spendMaterial,
                                  scanned, strScanError))
            continue;
        fFound = true;
        BOOST_CHECK_EQUAL(i, (size_t)nIssued);
        BOOST_CHECK_EQUAL(scanned.nAmount, 777U);
        BOOST_CHECK(scanned.spendSecret != zero);
        BOOST_CHECK(scanned.keyImage != zero);
    }
    BOOST_CHECK_MESSAGE(fFound, "a change note did not reopen under the scan key list");
}

BOOST_AUTO_TEST_SUITE_END()
