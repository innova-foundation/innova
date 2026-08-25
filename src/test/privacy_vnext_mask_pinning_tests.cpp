// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Disclosure-mask pinning on serialized bytes: only the builder sets a legal mask, and
// paths taking no caller mask emit their pinned one.

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../main.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../txdb.h"

namespace
{

PrivacyVNextDigest MaskDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

// Canonical field elements: a repeated byte overflows the group order.
PrivacyVNextDigest MaskScalar(unsigned char low)
{
    PrivacyVNextDigest d;
    d.fill(0);
    d[0] = low;
    return d;
}

PrivacyVNextDigest NoTransparentSide()
{
    PrivacyVNextDigest d;
    const uint256 binding = GetPrivacyVNextTransparentBinding(CTransaction());
    std::memcpy(d.data(), binding.begin(), 32);
    return d;
}

PrivacyVNextDigest LocalGenesis()
{
    PrivacyVNextDigest d;
    PrivacyVNextLocalGenesis(d.data());
    return d;
}

// Read at use: the fixture sets fRegTest after this unit's globals are constructed.
uint8_t LocalNetwork()
{
    return PrivacyVNextLocalNetworkId();
}

// Fixed-header offsets the decoder reads from, so a case can assert on the field
// rather than on a scan of the whole payload.
const size_t kMaskAt = 5;
const size_t kHeaderBytes = 9 + 32 + 32 + 32 + 8 + 8 + 8 + 32;
const size_t kBalanceAt = 9 + 32 + 32 + 32 + 8;
const size_t kFeeAt = kBalanceAt + 8;

size_t DisclosureRecordsAt(size_t nInputs, size_t nOutputs)
{
    const size_t nOutputRecord =
        128 + 1 + INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE + 1 +
        INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE;
    return kHeaderBytes + 1 + (nInputs * 64) + 1 + (nOutputs * nOutputRecord);
}

uint64_t ReadLE64At(const std::vector<unsigned char>& v, size_t at)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i)
        value |= (uint64_t)v[at + i] << (8 * i);
    return value;
}

std::vector<unsigned char> LE64(uint64_t value)
{
    std::vector<unsigned char> v(8);
    for (size_t i = 0; i < 8; ++i)
        v[i] = (unsigned char)((value >> (8 * i)) & 0xff);
    return v;
}

bool Contains(const std::vector<unsigned char>& haystack,
              const std::vector<unsigned char>& needle)
{
    return std::search(haystack.begin(), haystack.end(), needle.begin(),
                       needle.end()) != haystack.end();
}

bool ConsensusRefuses(const std::vector<unsigned char>& payload)
{
    const PrivacyVNextPayloadValidation validation =
        ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                    payload);
    // A node-local failure is not a verdict, so a case that only saw "not valid"
    // would pass on a build that could not run the verifier at all.
    BOOST_CHECK(!validation.fLocalFailure);
    return !validation.IsValid() && !validation.fLocalFailure;
}

bool ConsensusAccepts(const std::vector<unsigned char>& payload)
{
    const PrivacyVNextPayloadValidation validation =
        ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                    payload);
    BOOST_CHECK_MESSAGE(validation.IsValid(), validation.strError);
    return validation.IsValid();
}

// Amounts carrying six distinct nonzero bytes each, so "this amount is nowhere in the
// payload" is a claim about the amount rather than about a run of zeros.
const uint64_t kFunded = 1234567890123457ULL;
const uint64_t kFee = 999999937ULL;
const uint64_t kFirstOut = 314159265358979ULL;

struct FundedNote
{
    PrivacyVNextDigest genesis;
    PrivacyVNextDerivedKeys keys;
    std::vector<PrivacyVNextSpendNote> spends;
    PrivacyVNextDigest finalizedRoot;
    uint64_t nTreeSize;
    uint64_t nAmount;
};

// One funded note and its witness against a tree holding just it.
void FundOneNote(CTxDB& txdb, FundedNote& funded, unsigned char seedFill)
{
    std::string error;
    funded.genesis = LocalGenesis();
    funded.nAmount = kFunded;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(MaskDigest(seedFill), funded.genesis, 0,
                               LocalNetwork(), 0, funded.keys, error),
        error);

    PrivacyVNextEncryptedOutput funding;
    BOOST_REQUIRE_MESSAGE(
        EncryptPrivacyVNextNote(LocalNetwork(), 0, 0, funded.genesis,
                                funded.keys.spendPublic, funded.keys.viewPublic,
                                funded.keys.outgoingViewSecret, MaskScalar(29),
                                MaskScalar(30), funded.nAmount, MaskScalar(31),
                                MaskScalar(37), funding, error),
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

// Outputs paying the funded note's owner, split as the caller asks.
std::vector<PrivacyVNextNewOutput> TwoOutputs(const FundedNote& funded,
                                              uint64_t nFirst, uint64_t nSecond)
{
    std::vector<PrivacyVNextNewOutput> outs(2);
    for (size_t i = 0; i < outs.size(); ++i)
    {
        outs[i].recipient.nNetwork = LocalNetwork();
        outs[i].recipient.nAddressType = 0;
        outs[i].recipient.spendPublic = funded.keys.spendPublic;
        outs[i].recipient.viewPublic = funded.keys.viewPublic;
    }
    outs[0].nAmount = nFirst;
    outs[1].nAmount = nSecond;
    return outs;
}

std::vector<PrivacyVNextNewOutput> OneOutput(const FundedNote& funded,
                                             uint64_t nAmount)
{
    std::vector<PrivacyVNextNewOutput> outs(1);
    outs[0].recipient.nNetwork = LocalNetwork();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = funded.keys.spendPublic;
    outs[0].recipient.viewPublic = funded.keys.viewPublic;
    outs[0].nAmount = nAmount;
    return outs;
}

std::vector<unsigned char> BuildTransfer(
    const FundedNote& funded, uint8_t nMask,
    const std::vector<PrivacyVNextNewOutput>& outs, uint64_t nFee)
{
    std::string error;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(
            2, nMask, funded.genesis, funded.keys.outgoingViewSecret,
            funded.finalizedRoot, funded.nTreeSize, NoTransparentSide(), nFee,
            funded.spends, outs, payload, error),
        strprintf("mask %d: %s", (int)nMask, error.c_str()));
    BOOST_REQUIRE(payload.size() > kHeaderBytes);
    BOOST_REQUIRE_EQUAL((int)payload[kMaskAt], (int)nMask);
    return payload;
}

// A shield spends no note, so it is the shape where the sender bit governs no record
// at all and only the signing hash separates the two masks that differ in it.
std::vector<unsigned char> BuildShield(const FundedNote& funded, uint8_t nMask,
                                       uint64_t nAmount)
{
    std::string error;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextShieldPayload(
            2, nMask, funded.genesis, funded.keys.outgoingViewSecret,
            funded.finalizedRoot, funded.nTreeSize, NoTransparentSide(), nAmount,
            0, OneOutput(funded, nAmount), payload, error),
        strprintf("mask %d: %s", (int)nMask, error.c_str()));
    BOOST_REQUIRE(payload.size() > kHeaderBytes);
    BOOST_REQUIRE_EQUAL((int)payload[kMaskAt], (int)nMask);
    return payload;
}

} // namespace

BOOST_AUTO_TEST_SUITE(privacy_vnext_mask_pinning_tests)

// Restating the mask byte to another in-range value is the downgrade that matters
// (out-of-range values are refused by the header reader). Every ordered pair is tried,
// each derived from a validated payload.
BOOST_AUTO_TEST_CASE(no_in_range_mask_restatement_survives)
{
    CTxDB txdb("r+");
    FundedNote funded;
    FundOneNote(txdb, funded, 0x71);

    const uint64_t nSecondOut = kFunded - kFee - kFirstOut;
    std::vector<unsigned char> vPayloads[8];
    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
    {
        vPayloads[nMask] = BuildTransfer(
            funded, nMask, TwoOutputs(funded, kFirstOut, nSecondOut), kFee);
        // The control: as built, each mask is a payload consensus accepts.
        BOOST_REQUIRE_MESSAGE(ConsensusAccepts(vPayloads[nMask]),
                              strprintf("mask %d did not validate as built",
                                        (int)nMask));
    }

    for (uint8_t nFrom = 0; nFrom <= 7; ++nFrom)
    {
        for (uint8_t nTo = 0; nTo <= 7; ++nTo)
        {
            if (nFrom == nTo)
                continue;
            std::vector<unsigned char> restated = vPayloads[nFrom];
            restated[kMaskAt] = nTo;
            // The header reader still names it, so nothing upstream filters it out
            // before the verifier decides.
            uint8_t nOperation = 0;
            uint8_t nDeclared = 0;
            BOOST_CHECK(iv5::ReadDeclaredEnvelope(&restated[0], restated.size(),
                                                  nOperation, nDeclared));
            BOOST_CHECK_EQUAL((int)nDeclared, (int)nTo);
            BOOST_CHECK_MESSAGE(ConsensusRefuses(restated),
                                strprintf("mask %d restated as %d was accepted",
                                          (int)nFrom, (int)nTo));
        }
    }
}

// With no inputs the sender bit governs no record, so two masks differing only in it
// have identical layouts and only the mask byte in the signing hash separates them.
BOOST_AUTO_TEST_CASE(a_mask_bit_governing_no_record_is_still_pinned)
{
    CTxDB txdb("r+");
    FundedNote funded;
    FundOneNote(txdb, funded, 0x72);

    for (uint8_t nBase = 0; nBase <= 6; nBase = (uint8_t)(nBase + 2))
    {
        const uint8_t nDisclosing = nBase;
        const uint8_t nHiding = (uint8_t)(nBase | iv5::DISCLOSURE_HIDE_SENDER);

        const std::vector<unsigned char> disclosing =
            BuildShield(funded, nDisclosing, kFirstOut);
        const std::vector<unsigned char> hiding =
            BuildShield(funded, nHiding, kFirstOut);
        BOOST_REQUIRE(ConsensusAccepts(disclosing));
        BOOST_REQUIRE(ConsensusAccepts(hiding));
        // The control for the claim being made: with no input to name, the bit costs
        // no bytes, so the two payloads are the same length and differ in the header.
        BOOST_CHECK_MESSAGE(disclosing.size() == hiding.size(),
                            strprintf("masks %d and %d differ in length by %d",
                                      (int)nDisclosing, (int)nHiding,
                                      (int)((ptrdiff_t)disclosing.size() -
                                            (ptrdiff_t)hiding.size())));

        std::vector<unsigned char> raised = disclosing;
        raised[kMaskAt] = nHiding;
        BOOST_CHECK_MESSAGE(ConsensusRefuses(raised),
                            strprintf("mask %d restated as %d was accepted",
                                      (int)nDisclosing, (int)nHiding));

        std::vector<unsigned char> lowered = hiding;
        lowered[kMaskAt] = nDisclosing;
        BOOST_CHECK_MESSAGE(ConsensusRefuses(lowered),
                            strprintf("mask %d restated as %d was accepted",
                                      (int)nHiding, (int)nDisclosing));
    }
}

// Restating the byte alone leaves the layout mismatched. Deleting the records the raised
// mask no longer describes, or splicing in records from a payload that does, is refused
// as well.
BOOST_AUTO_TEST_CASE(neither_stripping_nor_splicing_repairs_a_restated_mask)
{
    CTxDB txdb("r+");
    FundedNote funded;
    FundOneNote(txdb, funded, 0x73);

    const uint64_t nSecondOut = kFunded - kFee - kFirstOut;
    const std::vector<PrivacyVNextNewOutput> outs =
        TwoOutputs(funded, kFirstOut, nSecondOut);
    // Mask 3 publishes the amounts and carries no range proof; mask 7 publishes
    // nothing and carries one.
    const std::vector<unsigned char> amountDisclosed =
        BuildTransfer(funded, 3, outs, kFee);
    const std::vector<unsigned char> fullyPrivate =
        BuildTransfer(funded, 7, outs, kFee);
    BOOST_REQUIRE(ConsensusAccepts(amountDisclosed));
    BOOST_REQUIRE(ConsensusAccepts(fullyPrivate));

    const size_t nRecordsAt = DisclosureRecordsAt(1, 2);
    const size_t nAmountRecords = 2 * (8 + 32);
    BOOST_REQUIRE(amountDisclosed.size() > nRecordsAt + nAmountRecords);
    // The records really are where the layout says: the first is the amount paid.
    BOOST_CHECK_EQUAL(ReadLE64At(amountDisclosed, nRecordsAt), kFirstOut);

    // Raise the mask and delete the records it no longer describes.
    std::vector<unsigned char> stripped = amountDisclosed;
    stripped[kMaskAt] = 7;
    stripped.erase(stripped.begin() + nRecordsAt,
                   stripped.begin() + nRecordsAt + nAmountRecords);
    BOOST_CHECK(ConsensusRefuses(stripped));

    // Lower the mask and splice in the records a payload that declares it carries.
    std::vector<unsigned char> spliced = fullyPrivate;
    spliced[kMaskAt] = 3;
    spliced.insert(spliced.begin() + nRecordsAt,
                   amountDisclosed.begin() + nRecordsAt,
                   amountDisclosed.begin() + nRecordsAt + nAmountRecords);
    BOOST_CHECK(ConsensusRefuses(spliced));
}

// A coinbase fee note carries the block's declared IV5 fee sum. The payload layer
// accepts any of the eight masks for that shape, so the block rule pins it; its
// predicate is checked here.
BOOST_AUTO_TEST_CASE(the_coinbase_fee_note_envelope_admits_one_mask)
{
    CTxDB txdb("r+");
    FundedNote funded;
    FundOneNote(txdb, funded, 0x74);

    BOOST_CHECK_EQUAL((int)iv5::COINBASE_FEE_NOTE_DISCLOSURE_MASK,
                      (int)(iv5::DISCLOSURE_HIDE_SENDER |
                            iv5::DISCLOSURE_HIDE_RECEIVER));

    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
    {
        const std::vector<unsigned char> feeNote =
            BuildShield(funded, nMask, kFirstOut);
        // The control: every mask is a payload consensus accepts on its own, which
        // is why the envelope has to be pinned at the block instead.
        BOOST_REQUIRE_MESSAGE(ConsensusAccepts(feeNote),
                              strprintf("fee-note shape at mask %d did not validate",
                                        (int)nMask));

        uint8_t nDeclared = 0;
        const bool fAllowed = iv5::CoinbaseFeeNoteEnvelopeAllows(
            &feeNote[0], feeNote.size(), nDeclared);
        BOOST_CHECK_EQUAL((int)nDeclared, (int)nMask);
        BOOST_CHECK_MESSAGE(
            fAllowed == (nMask == iv5::COINBASE_FEE_NOTE_DISCLOSURE_MASK),
            strprintf("fee-note envelope verdict %d at mask %d", (int)fAllowed,
                      (int)nMask));
    }

    // The mask the wallet's fee-note builder is pinned to publishes the amount, so
    // the sum a validator holds against the block is on the wire with its opening.
    const std::vector<unsigned char> pinned =
        BuildShield(funded, iv5::COINBASE_FEE_NOTE_DISCLOSURE_MASK, kFirstOut);
    BOOST_CHECK(Contains(pinned, LE64(kFirstOut)));
    // And the same value is what the cleartext balance field declares.
    BOOST_CHECK_EQUAL(ReadLE64At(pinned, kBalanceAt), kFirstOut);
}

// With the amount bit set the value must be absent from the payload, not merely
// absent from the record it would have occupied. The complementary mask is read first
// so the search is known to be able to find the value it then reports missing.
BOOST_AUTO_TEST_CASE(an_amount_hiding_mask_leaves_no_amount_on_the_wire)
{
    CTxDB txdb("r+");
    FundedNote funded;
    FundOneNote(txdb, funded, 0x75);

    const uint64_t nSecondOut = kFunded - kFee - kFirstOut;
    const std::vector<PrivacyVNextNewOutput> outs =
        TwoOutputs(funded, kFirstOut, nSecondOut);

    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
    {
        const std::vector<unsigned char> payload =
            BuildTransfer(funded, nMask, outs, kFee);
        BOOST_REQUIRE(ConsensusAccepts(payload));
        const bool fHidden = (nMask & iv5::DISCLOSURE_HIDE_AMOUNT) != 0;
        BOOST_CHECK_MESSAGE(Contains(payload, LE64(kFirstOut)) != fHidden,
                            strprintf("mask %d: first amount on wire %d", (int)nMask,
                                      (int)Contains(payload, LE64(kFirstOut))));
        BOOST_CHECK_MESSAGE(Contains(payload, LE64(nSecondOut)) != fHidden,
                            strprintf("mask %d: second amount on wire %d", (int)nMask,
                                      (int)Contains(payload, LE64(nSecondOut))));
        // The fee is a cleartext field under every mask, and it is the flat charge
        // the spend path applies rather than anything derived from the amounts.
        BOOST_CHECK_EQUAL(ReadLE64At(payload, kFeeAt), kFee);
        // A transfer moves nothing across the boundary, so the balance field says so
        // under every mask and never stands in for the amounts.
        BOOST_CHECK_EQUAL(ReadLE64At(payload, kBalanceAt), 0U);
    }
}

// Size is a channel the mask cannot close: it tracks only the spent and created note
// counts, which the prefix declares in the clear, so it does not leak hidden amounts.
BOOST_AUTO_TEST_CASE(payload_size_follows_the_declared_shape_and_not_the_amounts)
{
    CTxDB txdb("r+");
    FundedNote funded;
    FundOneNote(txdb, funded, 0x76);

    const uint64_t nSpendable = kFunded - kFee;
    size_t nDefaultTwoOut = 0;
    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
    {
        // The same shape and total, split two very different ways.
        const std::vector<unsigned char> even = BuildTransfer(
            funded, nMask,
            TwoOutputs(funded, nSpendable / 2, nSpendable - nSpendable / 2), kFee);
        const std::vector<unsigned char> lopsided =
            BuildTransfer(funded, nMask, TwoOutputs(funded, 1, nSpendable - 1),
                          kFee);
        BOOST_REQUIRE(ConsensusAccepts(even));
        BOOST_REQUIRE(ConsensusAccepts(lopsided));
        BOOST_CHECK_MESSAGE(even.size() == lopsided.size(),
                            strprintf("mask %d: %d bytes of split", (int)nMask,
                                      (int)((ptrdiff_t)even.size() -
                                            (ptrdiff_t)lopsided.size())));
        if (nMask == iv5::WALLET_DEFAULT_DISCLOSURE_MASK)
            nDefaultTwoOut = even.size();
    }

    // The control for those comparisons being able to move at all: the output count
    // does move the size, and the output count is declared in the clear.
    const std::vector<unsigned char> single = BuildTransfer(
        funded, iv5::WALLET_DEFAULT_DISCLOSURE_MASK,
        OneOutput(funded, nSpendable), kFee);
    BOOST_REQUIRE(ConsensusAccepts(single));
    BOOST_CHECK(single.size() < nDefaultTwoOut);

    // What size tracks is what the prefix already states: the counts sit in the clear
    // at the offsets the decoder reads them from, ahead of any disclosure record.
    const std::vector<unsigned char> payload = BuildTransfer(
        funded, iv5::WALLET_DEFAULT_DISCLOSURE_MASK,
        TwoOutputs(funded, kFirstOut, kFunded - kFee - kFirstOut), kFee);
    BOOST_REQUIRE(payload.size() > kHeaderBytes + 1 + 64);
    BOOST_CHECK_EQUAL((int)payload[kHeaderBytes], 1);
    BOOST_CHECK_EQUAL((int)payload[kHeaderBytes + 1 + 64], 2);
}

BOOST_AUTO_TEST_SUITE_END()
