#include <boost/test/unit_test.hpp>

#include <cstring>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../finality_note.h"
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

void FundOneNote(CTxDB& txdb, FundedNote& funded, unsigned char seedFill,
                 uint64_t nAmount = 5000)
{
    std::string error;
    funded.genesis = LocalGenesis();
    funded.nAmount = nAmount;
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

// Mask rules are enforced in the Rust decoder reached through ValidatePrivacyVNextPayload,
// independent of Boundary B. Every case validates a builder payload first, then tampers.

void PutTestCompactSize(std::vector<unsigned char>& out, uint64_t nSize)
{
    if (nSize < 253)
        out.push_back((unsigned char)nSize);
    else if (nSize <= 0xffff)
    {
        out.push_back(253);
        out.push_back((unsigned char)(nSize & 0xff));
        out.push_back((unsigned char)((nSize >> 8) & 0xff));
    }
    else
    {
        out.push_back(254);
        for (int i = 0; i < 4; ++i)
            out.push_back((unsigned char)((nSize >> (8 * i)) & 0xff));
    }
}

void PutTestVector(std::vector<unsigned char>& out,
                   const std::vector<unsigned char>& v)
{
    PutTestCompactSize(out, v.size());
    out.insert(out.end(), v.begin(), v.end());
}

// What a length-prefixed section costs on the wire, framing included.
size_t FramedSize(size_t nBytes)
{
    std::vector<unsigned char> v;
    PutTestCompactSize(v, nBytes);
    return v.size() + nBytes;
}

uint64_t ReadU64(const std::vector<unsigned char>& v, size_t nOffset)
{
    uint64_t n = 0;
    for (size_t i = 0; i < 8; ++i)
        n |= (uint64_t)v[nOffset + i] << (8 * i);
    return n;
}

std::vector<size_t> FindAll(const std::vector<unsigned char>& haystack,
                            const std::vector<unsigned char>& needle)
{
    std::vector<size_t> v;
    if (needle.empty() || haystack.size() < needle.size())
        return v;
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i)
        if (std::memcmp(&haystack[i], &needle[0], needle.size()) == 0)
            v.push_back(i);
    return v;
}

std::vector<unsigned char> DigestBytes(const PrivacyVNextDigest& d)
{
    return std::vector<unsigned char>(d.begin(), d.end());
}

bool Validates(const std::vector<unsigned char>& payload)
{
    return ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                       payload).IsValid();
}

int32_t ValidationResult(const std::vector<unsigned char>& payload)
{
    return ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                       payload).nResult;
}

// The one anchor a shield needs: the bootstrap epoch seed's empty tree. A shield spends
// no note, so nothing has to be in that tree for the payload to be complete.
struct ShieldAnchor
{
    PrivacyVNextDigest genesis;
    PrivacyVNextDigest root;
    uint64_t nTreeSize;

    ShieldAnchor() : nTreeSize(0)
    {
        genesis.fill(0);
        root.fill(0);
    }
};

bool LoadShieldAnchor(ShieldAnchor& anchor, std::string& error)
{
    anchor.genesis = LocalGenesis();
    PrivacyVNextEpochSeed seed;
    if (!LoadPrivacyVNextEpochSeed(seed, error))
        return false;
    if (seed.vchRoot.size() != 32)
    {
        error = "the epoch seed root is not 32 bytes";
        return false;
    }
    std::memcpy(anchor.root.data(), &seed.vchRoot[0], 32);
    anchor.nTreeSize = seed.nTreeSize;
    return true;
}

bool BuildShield(uint8_t nMask, const ShieldAnchor& anchor,
                 const std::vector<uint64_t>& vAmounts, uint64_t nFee,
                 unsigned char seedFill,
                 std::vector<unsigned char>& payloadOut, std::string& error)
{
    std::vector<PrivacyVNextNewOutput> outs(vAmounts.size());
    PrivacyVNextDigest outgoingViewSecret;
    outgoingViewSecret.fill(0);
    uint64_t nIn = nFee;
    for (size_t i = 0; i < vAmounts.size(); ++i)
    {
        PrivacyVNextDerivedKeys keys;
        if (!DerivePrivacyVNextKeys(DisclosureDigest(seedFill), anchor.genesis,
                                    (uint32_t)i, LocalNetwork(), 0, keys, error))
            return false;
        if (i == 0)
            outgoingViewSecret = keys.outgoingViewSecret;
        outs[i].recipient.nNetwork = LocalNetwork();
        outs[i].recipient.nAddressType = 0;
        outs[i].recipient.spendPublic = keys.spendPublic;
        outs[i].recipient.viewPublic = keys.viewPublic;
        outs[i].nAmount = vAmounts[i];
        nIn += vAmounts[i];
    }
    return BuildPrivacyVNextShieldPayload(
        LocalNetwork(), nMask, anchor.genesis, outgoingViewSecret, anchor.root,
        anchor.nTreeSize, NoTransparentSide(), nIn, nFee, outs, payloadOut, error);
}

// Proof sections after a disclosed-amount shield's prefix: no membership, no range,
// the 64-byte balance proof, no operation proof, no disclosure proof.
const size_t SHIELD_OPEN_TAIL_BYTES = 1 + 1 + (1 + 64) + 1 + 1;

// Split such a payload at the boundary the signing hash stops at. The section shape is
// asserted rather than assumed: a layout change has to fail here loudly instead of moving
// the split silently and leaving every case below tampering with the wrong bytes.
void SplitDisclosedShield(const std::vector<unsigned char>& payload,
                          std::vector<unsigned char>& prefixOut,
                          std::vector<unsigned char>& tailOut)
{
    BOOST_REQUIRE_GT(payload.size(), SHIELD_OPEN_TAIL_BYTES);
    const size_t nPrefix = payload.size() - SHIELD_OPEN_TAIL_BYTES;
    BOOST_REQUIRE_EQUAL((int)payload[nPrefix - 1], 0);
    BOOST_REQUIRE_EQUAL((int)payload[nPrefix + 0], 0);
    BOOST_REQUIRE_EQUAL((int)payload[nPrefix + 1], 0);
    BOOST_REQUIRE_EQUAL((int)payload[nPrefix + 2], 64);
    BOOST_REQUIRE_EQUAL((int)payload[payload.size() - 2], 0);
    BOOST_REQUIRE_EQUAL((int)payload[payload.size() - 1], 0);
    prefixOut.assign(payload.begin(), payload.begin() + nPrefix);
    tailOut.assign(payload.begin() + nPrefix, payload.end());
}

// Re-prove the value side over a prefix the caller has edited, so a case can change one
// declared field and leave every other proof honest. Without it a prefix edit is refused
// by the balance proof and the check under test never runs.
bool ReproveDisclosedShield(const std::vector<unsigned char>& prefix,
                            const std::vector<PrivacyVNextValueOutput>& vOutputs,
                            int64_t nTransparentValueBalance, uint64_t nFee,
                            std::vector<unsigned char>& payloadOut,
                            std::string& error)
{
    PrivacyVNextDigest signingHash;
    if (!HashPrivacyVNextPayloadPrefix(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                       prefix, signingHash, error))
        return false;
    uint256 excess = 0;
    for (size_t i = 0; i < vOutputs.size(); ++i)
        excess = Ed25519ScalarSub(excess,
                                  Ed25519ScalarFromDigest(vOutputs[i].mask));
    PrivacyVNextValueProof proof;
    if (!ProvePrivacyVNextValue(std::vector<PrivacyVNextDigest>(), vOutputs,
                                nTransparentValueBalance, nFee, signingHash,
                                DisclosureScalar(0x17),
                                Ed25519ScalarToDigest(excess), proof, error))
        return false;
    payloadOut = prefix;
    PutTestVector(payloadOut, std::vector<unsigned char>());
    PutTestVector(payloadOut, std::vector<unsigned char>());
    PutTestVector(payloadOut, std::vector<unsigned char>(
                                  proof.balanceProof.begin(),
                                  proof.balanceProof.end()));
    PutTestVector(payloadOut, std::vector<unsigned char>());
    PutTestVector(payloadOut, std::vector<unsigned char>());
    return true;
}

// A transfer of one funded note to a payee and back to change, at one mask.
bool BuildMaskedTransfer(const FundedNote& funded, uint8_t nMask,
                         uint64_t nPaid, uint64_t nFee,
                         PrivacyVNextDerivedKeys& payeeOut,
                         std::vector<unsigned char>& payloadOut,
                         std::string& error)
{
    if (!DerivePrivacyVNextKeys(DisclosureDigest(0x64), funded.genesis, 0,
                                LocalNetwork(), 0, payeeOut, error))
        return false;
    PrivacyVNextDerivedKeys change;
    if (!DerivePrivacyVNextChangeKeys(DisclosureDigest(0x63), funded.genesis,
                                      LocalNetwork(), change, error))
        return false;
    std::vector<PrivacyVNextNewOutput> outs(2);
    outs[0].recipient.nNetwork = LocalNetwork();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = payeeOut.spendPublic;
    outs[0].recipient.viewPublic = payeeOut.viewPublic;
    outs[0].nAmount = nPaid;
    outs[1].recipient.nNetwork = LocalNetwork();
    outs[1].recipient.nAddressType = 0;
    outs[1].recipient.spendPublic = change.spendPublic;
    outs[1].recipient.viewPublic = change.viewPublic;
    outs[1].nAmount = funded.nAmount - nPaid - nFee;
    return BuildPrivacyVNextTransferPayload(
        LocalNetwork(), nMask, funded.genesis, funded.keys.outgoingViewSecret,
        funded.finalizedRoot, funded.nTreeSize, NoTransparentSide(), nFee,
        funded.spends, outs, payloadOut, error);
}

// Every byte of what a payload settles, laid end to end so a disclosed field can be
// searched for in it.
std::vector<unsigned char> SettledBytes(const PrivacyVNextStateEffects& e)
{
    std::vector<unsigned char> v;
    v.insert(v.end(), e.finalizedRoot.begin(), e.finalizedRoot.end());
    for (size_t i = 0; i < 8; ++i)
        v.push_back((unsigned char)((e.nFinalizedTreeSize >> (8 * i)) & 0xff));
    v.insert(v.end(), e.parameterDigest.begin(), e.parameterDigest.end());
    const uint64_t nBalance = (uint64_t)e.nTransparentValueBalance;
    for (size_t i = 0; i < 8; ++i)
        v.push_back((unsigned char)((nBalance >> (8 * i)) & 0xff));
    for (size_t i = 0; i < 8; ++i)
        v.push_back((unsigned char)((e.nFee >> (8 * i)) & 0xff));
    v.insert(v.end(), e.transparentBinding.begin(), e.transparentBinding.end());
    for (size_t i = 0; i < e.keyImages.size(); ++i)
        v.insert(v.end(), e.keyImages[i].begin(), e.keyImages[i].end());
    for (size_t i = 0; i < e.outputLeaves.size(); ++i)
    {
        v.insert(v.end(), e.outputLeaves[i].owner.begin(),
                 e.outputLeaves[i].owner.end());
        v.insert(v.end(), e.outputLeaves[i].nullifierBase.begin(),
                 e.outputLeaves[i].nullifierBase.end());
        v.insert(v.end(), e.outputLeaves[i].commitment.begin(),
                 e.outputLeaves[i].commitment.end());
    }
    for (size_t i = 0; i < e.attestationKeyImages.size(); ++i)
        v.insert(v.end(), e.attestationKeyImages[i].begin(),
                 e.attestationKeyImages[i].end());
    v.insert(v.end(), e.registrationContext.begin(), e.registrationContext.end());
    v.insert(v.end(), e.memberKey.begin(), e.memberKey.end());
    return v;
}

// The authority a spend publishes when bit 1 is clear, taken from the prover rather than
// assumed. It is a property of the note: proving the same note twice under different
// entropy yields the same 32 bytes, which is what makes publishing it name one leaf.
bool SenderAuthorityOf(const FundedNote& funded, unsigned char entropyFill,
                       PrivacyVNextDigest& authorityOut, std::string& error)
{
    std::vector<PrivacyVNextSpendInput> vInputs(funded.spends.size());
    for (size_t i = 0; i < funded.spends.size(); ++i)
    {
        vInputs[i].spendScalar = funded.spends[i].spendSecret;
        vInputs[i].commitmentScalar = funded.spends[i].y;
        vInputs[i].leaf = funded.spends[i].leaf;
        vInputs[i].vchWitnessRecord = funded.spends[i].vchWitnessRecord;
    }
    std::vector<PrivacyVNextSpendConstruction> vConstructions;
    std::vector<unsigned char> vchProof;
    if (!ProvePrivacyVNextMembership(funded.finalizedRoot, DisclosureScalar(0x21),
                                     DisclosureScalar(entropyFill), vInputs,
                                     vConstructions, vchProof, error))
        return false;
    if (vConstructions.empty())
    {
        error = "the prover reported no input";
        return false;
    }
    authorityOut = vConstructions[0].senderAuthority;
    return true;
}

// Where the disclosure proof section starts, for a payload carrying `nBytes` of it. The
// section is the payload's last, so its own length prefix locates it from the end.
size_t DisclosureSectionStart(const std::vector<unsigned char>& payload,
                              size_t nBytes)
{
    std::vector<unsigned char> header;
    PutTestCompactSize(header, nBytes);
    BOOST_REQUIRE_GT(payload.size(), nBytes + header.size());
    const size_t nStart = payload.size() - nBytes - header.size();
    BOOST_REQUIRE(std::memcmp(&payload[nStart], &header[0], header.size()) == 0);
    return nStart + header.size();
}

// The eight-byte little-endian encoding a disclosed amount is published in.
std::vector<unsigned char> AmountBytes(uint64_t nAmount)
{
    std::vector<unsigned char> v(8, 0);
    for (size_t i = 0; i < 8; ++i)
        v[i] = (unsigned char)((nAmount >> (8 * i)) & 0xff);
    return v;
}

std::vector<unsigned char> Slice(const std::vector<unsigned char>& v, size_t nAt,
                                 size_t nBytes)
{
    BOOST_REQUIRE_GE(v.size(), nAt + nBytes);
    return std::vector<unsigned char>(v.begin() + nAt, v.begin() + nAt + nBytes);
}

PrivacyVNextDigest DigestAt(const std::vector<unsigned char>& v, size_t nAt)
{
    BOOST_REQUIRE_GE(v.size(), nAt + 32);
    PrivacyVNextDigest d;
    std::memcpy(d.data(), &v[nAt], 32);
    return d;
}

// Where each field of a canonical payload prefix sits, for `nIn` inputs and `nOut` outputs
// at one mask. Everything ahead of the proofs has a pinned width, so the counts (< 253, one
// byte each) fix every offset; nothing is read from the payload's own framing.
struct PrefixLayout
{
    size_t nIn;
    size_t nOut;
    uint8_t nMask;
    size_t nFeeAt;
    size_t nInputCountAt;
    size_t nInputsAt;
    size_t nOutputCountAt;
    size_t nOutputsAt;
    size_t nOutputStride;
    size_t nDisclosedAt;

    PrefixLayout(size_t nInputs, size_t nOutputs, uint8_t nDisclosureMask)
        : nIn(nInputs), nOut(nOutputs), nMask(nDisclosureMask)
    {
        // header 9, genesis 32, parameter digest 32, finalized root 32, tree size 8,
        // transparent value balance 8, then the fee.
        nFeeAt = 9 + 32 + 32 + 32 + 8 + 8;
        nInputCountAt = nFeeAt + 8 + 32;
        nInputsAt = nInputCountAt + 1;
        nOutputCountAt = nInputsAt + nIn * 64;
        nOutputsAt = nOutputCountAt + 1;
        nOutputStride =
            4 * 32 + FramedSize(INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE) +
            FramedSize(INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE);
        nDisclosedAt = nOutputsAt + nOut * nOutputStride;
    }

    bool DisclosesSender() const
    {
        return (nMask & iv5::DISCLOSURE_HIDE_SENDER) == 0;
    }
    bool DisclosesReceiver() const
    {
        return (nMask & iv5::DISCLOSURE_HIDE_RECEIVER) == 0;
    }
    bool DisclosesAmount() const
    {
        return (nMask & iv5::DISCLOSURE_HIDE_AMOUNT) == 0;
    }

    size_t KeyImageAt(size_t i) const { return nInputsAt + i * 64 + 32; }
    size_t OwnerAt(size_t i) const { return nOutputsAt + i * nOutputStride; }
    size_t NoteEphemeralAt(size_t i) const { return OwnerAt(i) + 64; }
    size_t TweakEphemeralAt(size_t i) const { return OwnerAt(i) + 96; }

    size_t SenderRecordBytes() const { return DisclosesSender() ? nIn * 32 : 0; }
    size_t ReceiverRecordBytes() const { return DisclosesReceiver() ? nOut * 64 : 0; }

    size_t SenderRecordAt(size_t i) const { return nDisclosedAt + i * 32; }
    size_t ReceiverRecordAt(size_t i) const
    {
        return nDisclosedAt + SenderRecordBytes() + i * 64;
    }
    size_t AmountRecordAt(size_t i) const
    {
        return nDisclosedAt + SenderRecordBytes() + ReceiverRecordBytes() + i * 40;
    }

    // The disclosure proof section carries the same records in the same order.
    size_t SenderProofBytes() const
    {
        return DisclosesSender()
                   ? nIn * INNOVA_PRIVACY_VNEXT_SENDER_DISCLOSURE_PROOF_SIZE
                   : 0;
    }
    size_t ReceiverProofBytes() const
    {
        return DisclosesReceiver()
                   ? nOut * INNOVA_PRIVACY_VNEXT_RECEIVER_DISCLOSURE_PROOF_SIZE
                   : 0;
    }
    size_t DisclosureProofBytes() const
    {
        return SenderProofBytes() + ReceiverProofBytes();
    }
};

// The receiver disclosure's DH point for one output, recomputed from the recipient's view
// secret and the cleartext tweak ephemeral, independent of the payload's own framing.
bool SharedPointOf(const PrivacyVNextDigest& viewSecret,
                   const PrivacyVNextDigest& tweakEphemeral,
                   PrivacyVNextDigest& pointOut, std::string& error)
{
    std::vector<PrivacyVNextCombineTerm> vTerms(1);
    vTerms[0].nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    vTerms[0].scalar = viewSecret;
    vTerms[0].point = tweakEphemeral;
    return CombinePrivacyVNextPoints(vTerms, pointOut, error);
}

// One needle and where it is expected to be. `strName` names it in the failure message,
// `vchNeedle` is the byte string, and `nAt` is the offset the publishing mask puts it at.
struct DisclosedField
{
    std::string strName;
    std::vector<unsigned char> vchNeedle;
    size_t nAt;

    DisclosedField(const std::string& name,
                   const std::vector<unsigned char>& needle, size_t at)
        : strName(name), vchNeedle(needle), nAt(at)
    {
    }
};

// `fDisclosed` selects the half: required at its record's offset, or absent from the whole
// payload. Both halves run over one needle so absence is a result, not an unsearchable needle.
void CheckDisclosedField(const std::vector<unsigned char>& payload, uint8_t nMask,
                         bool fDisclosed, const DisclosedField& field)
{
    if (fDisclosed)
    {
        BOOST_CHECK_MESSAGE(
            Slice(payload, field.nAt, field.vchNeedle.size()) == field.vchNeedle,
            strprintf("mask %u does not publish %s where its record sits",
                      (unsigned)nMask, field.strName.c_str()));
        return;
    }
    const std::vector<size_t> vAt = FindAll(payload, field.vchNeedle);
    BOOST_CHECK_MESSAGE(
        vAt.empty(),
        strprintf("mask %u hides %s and the payload carries it at offset %u",
                  (unsigned)nMask, field.strName.c_str(),
                  (unsigned)(vAt.empty() ? 0 : vAt[0])));
}

// Length is separable when the bytes one mask bit moves do not depend on the other bits;
// then length is a function of the mask and the cleartext counts.
void CheckMaskSizeIsSeparable(const size_t* pSize, size_t nIn, size_t nOut)
{
    static const uint8_t vBits[3] = {iv5::DISCLOSURE_HIDE_SENDER,
                                     iv5::DISCLOSURE_HIDE_RECEIVER,
                                     iv5::DISCLOSURE_HIDE_AMOUNT};
    for (size_t b = 0; b < 3; ++b)
    {
        const uint8_t nBit = vBits[b];
        // Clearing bit 4 also drops the aggregate range proof, whose length this test
        // does not model, so only bits 1 and 2 are held to a closed form. Bit 4 is held
        // to agreeing with itself across its four pairs, which is the separability claim.
        const bool fClosedForm = nBit != iv5::DISCLOSURE_HIDE_AMOUNT;
        const int64_t nRecords = (nBit == iv5::DISCLOSURE_HIDE_SENDER)
                                     ? (int64_t)(nIn * 32)
                                     : (int64_t)(nOut * 64);
        bool fHave = false;
        int64_t nDelta = 0;
        for (uint8_t nMask = 0; nMask <= 7; ++nMask)
        {
            if ((nMask & nBit) != 0)
                continue;
            const uint8_t nHidden = (uint8_t)(nMask | nBit);
            const int64_t nThis = (int64_t)pSize[nMask] - (int64_t)pSize[nHidden];
            if (fClosedForm)
            {
                const int64_t nFraming =
                    (int64_t)FramedSize(
                        PrefixLayout(nIn, nOut, nMask).DisclosureProofBytes()) -
                    (int64_t)FramedSize(
                        PrefixLayout(nIn, nOut, nHidden).DisclosureProofBytes());
                BOOST_CHECK_MESSAGE(
                    nThis == nRecords + nFraming,
                    strprintf("mask %u to %u moved %ld bytes, not the %ld its records "
                              "and framing account for",
                              (unsigned)nMask, (unsigned)nHidden, (long)nThis,
                              (long)(nRecords + nFraming)));
            }
            if (!fHave)
            {
                nDelta = nThis;
                fHave = true;
                continue;
            }
            BOOST_CHECK_MESSAGE(
                nThis == nDelta,
                strprintf("bit %u moves %ld bytes at mask %u and %ld bytes elsewhere",
                          (unsigned)nBit, (long)nThis, (unsigned)nMask, (long)nDelta));
        }
        BOOST_REQUIRE(fHave);
    }
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

// A disclosed amount replaces the range proof, so it must open its own commitment. The
// value side is re-proved over the edited prefix to reach this rule past the balance proof.
BOOST_AUTO_TEST_CASE(a_disclosed_amount_must_open_its_own_commitment)
{
    std::string error;
    ShieldAnchor anchor;
    BOOST_REQUIRE_MESSAGE(LoadShieldAnchor(anchor, error), error);

    const uint64_t nAmount = 4200;
    const uint64_t nFee = 55;
    const std::vector<uint64_t> vAmounts(1, nAmount);
    std::vector<unsigned char> payload;
    // Mask 3 hides the sender and the recipient and publishes the amount, so the payload
    // carries no disclosure proof at all and no membership proof: the declared amount is
    // held to its commitment by this rule alone.
    BOOST_REQUIRE_MESSAGE(
        BuildShield(3, anchor, vAmounts, nFee, 0x91, payload, error), error);
    BOOST_REQUIRE_MESSAGE(Validates(payload), "the disclosing shield did not validate");

    std::vector<unsigned char> prefix;
    std::vector<unsigned char> tail;
    SplitDisclosedShield(payload, prefix, tail);

    // The prefix ends with one (amount, opening) pair per output and then the empty
    // finality body. Reading the amount back out of that offset is what says the bytes
    // edited below are the fields this rule names.
    const size_t nAmountAt = prefix.size() - 1 - 40;
    const size_t nOpeningAt = nAmountAt + 8;
    BOOST_REQUIRE_EQUAL(ReadU64(prefix, nAmountAt), nAmount);

    PrivacyVNextValueOutput out;
    out.nAmount = nAmount;
    std::memcpy(out.mask.data(), &prefix[nOpeningAt], 32);
    const std::vector<PrivacyVNextValueOutput> vOutputs(1, out);
    const int64_t nBalance = (int64_t)(nAmount + nFee);

    // The harness first: re-proving an unedited prefix has to validate, or every rejection
    // below would be about the reassembly rather than about the rule.
    std::vector<unsigned char> rebuilt;
    BOOST_REQUIRE_MESSAGE(
        ReproveDisclosedShield(prefix, vOutputs, nBalance, nFee, rebuilt, error), error);
    BOOST_REQUIRE_MESSAGE(Validates(rebuilt),
                          "a re-proved but unedited shield did not validate");

    // A declared amount one greater than the one its commitment was made over.
    {
        std::vector<unsigned char> edited = prefix;
        const uint64_t nLie = nAmount + 1;
        for (size_t i = 0; i < 8; ++i)
            edited[nAmountAt + i] = (unsigned char)((nLie >> (8 * i)) & 0xff);
        std::vector<unsigned char> crafted;
        BOOST_REQUIRE_MESSAGE(
            ReproveDisclosedShield(edited, vOutputs, nBalance, nFee, crafted, error),
            error);
        BOOST_CHECK_MESSAGE(!Validates(crafted),
                            "a declared amount that does not open its commitment validated");
        BOOST_CHECK_EQUAL(ValidationResult(crafted), 1);
    }

    // An opening that is still a canonical scalar but not this commitment's.
    {
        std::vector<unsigned char> edited = prefix;
        edited[nOpeningAt] ^= 0x01;
        std::vector<unsigned char> crafted;
        BOOST_REQUIRE_MESSAGE(
            ReproveDisclosedShield(edited, vOutputs, nBalance, nFee, crafted, error),
            error);
        BOOST_CHECK_MESSAGE(!Validates(crafted),
                            "an opening that does not open its commitment validated");
        BOOST_CHECK_EQUAL(ValidationResult(crafted), 1);
    }

    // An opening no reduced scalar can encode.
    {
        std::vector<unsigned char> edited = prefix;
        for (size_t i = 0; i < 32; ++i)
            edited[nOpeningAt + i] = 0xff;
        std::vector<unsigned char> crafted;
        BOOST_REQUIRE_MESSAGE(
            ReproveDisclosedShield(edited, vOutputs, nBalance, nFee, crafted, error),
            error);
        BOOST_CHECK_MESSAGE(!Validates(crafted), "a non-canonical opening validated");
        BOOST_CHECK_EQUAL(ValidationResult(crafted), 1);
    }

    // One pair per commitment, not one pair: a two-output payload missing its second pair
    // is short by the whole record, not by a field.
    {
        std::vector<uint64_t> vTwo;
        vTwo.push_back(1200);
        vTwo.push_back(3000);
        std::vector<unsigned char> two;
        BOOST_REQUIRE_MESSAGE(
            BuildShield(3, anchor, vTwo, nFee, 0x93, two, error), error);
        BOOST_REQUIRE(Validates(two));
        std::vector<unsigned char> twoPrefix;
        std::vector<unsigned char> twoTail;
        SplitDisclosedShield(two, twoPrefix, twoTail);
        BOOST_REQUIRE_EQUAL(ReadU64(twoPrefix, twoPrefix.size() - 1 - 80), vTwo[0]);
        BOOST_REQUIRE_EQUAL(ReadU64(twoPrefix, twoPrefix.size() - 1 - 40), vTwo[1]);

        std::vector<PrivacyVNextValueOutput> vTwoOutputs(2);
        for (size_t i = 0; i < 2; ++i)
        {
            vTwoOutputs[i].nAmount = vTwo[i];
            std::memcpy(vTwoOutputs[i].mask.data(),
                        &twoPrefix[twoPrefix.size() - 1 - 40 * (2 - i) + 8], 32);
        }
        std::vector<unsigned char> control;
        BOOST_REQUIRE_MESSAGE(
            ReproveDisclosedShield(twoPrefix, vTwoOutputs,
                                   (int64_t)(vTwo[0] + vTwo[1] + nFee), nFee,
                                   control, error),
            error);
        BOOST_REQUIRE_MESSAGE(Validates(control),
                              "the two-output harness control did not validate");

        std::vector<unsigned char> dropped(twoPrefix.begin(),
                                           twoPrefix.end() - 41);
        dropped.push_back(0);   // the finality body the dropped pair displaced
        std::vector<unsigned char> crafted;
        BOOST_REQUIRE_MESSAGE(
            ReproveDisclosedShield(dropped, vTwoOutputs,
                                   (int64_t)(vTwo[0] + vTwo[1] + nFee), nFee,
                                   crafted, error),
            error);
        BOOST_CHECK_MESSAGE(!Validates(crafted),
                            "a payload declaring fewer amounts than commitments validated");
    }
}

// A range proof is present exactly when an amount is hidden. Tested on shields: with no
// input, membership is skipped and the range section is outside the signing hash.
BOOST_AUTO_TEST_CASE(a_range_proof_is_present_exactly_when_an_amount_is_hidden)
{
    std::string error;
    ShieldAnchor anchor;
    BOOST_REQUIRE_MESSAGE(LoadShieldAnchor(anchor, error), error);

    const uint64_t nAmount = 4200;
    const uint64_t nFee = 55;
    const std::vector<uint64_t> vAmounts(1, nAmount);
    std::vector<unsigned char> open3;
    std::vector<unsigned char> hidden7;
    BOOST_REQUIRE_MESSAGE(
        BuildShield(3, anchor, vAmounts, nFee, 0x92, open3, error), error);
    BOOST_REQUIRE_MESSAGE(
        BuildShield(7, anchor, vAmounts, nFee, 0x92, hidden7, error), error);
    BOOST_REQUIRE(Validates(open3));
    BOOST_REQUIRE(Validates(hidden7));

    std::vector<unsigned char> prefix3;
    std::vector<unsigned char> tail3;
    SplitDisclosedShield(open3, prefix3, tail3);

    // The payloads differ only in what bit 4 selects, which puts the mask-7 prefix at a
    // derivable offset; the two zero bytes below confirm it.
    const size_t nPrefix7 = prefix3.size() - 40 * vAmounts.size();
    BOOST_REQUIRE_GT(hidden7.size(), nPrefix7 + 68);
    BOOST_REQUIRE_EQUAL((int)hidden7[nPrefix7 - 1], 0);
    BOOST_REQUIRE_EQUAL((int)hidden7[nPrefix7], 0);
    const std::vector<unsigned char> prefix7(hidden7.begin(),
                                             hidden7.begin() + nPrefix7);
    // 67 bytes close every one of these payloads: the framed 64-byte balance proof, then
    // the empty operation and disclosure sections.
    const std::vector<unsigned char> range7(hidden7.begin() + nPrefix7 + 1,
                                            hidden7.end() - 67);
    const std::vector<unsigned char> value7(hidden7.end() - 67, hidden7.end());
    const std::vector<unsigned char> value3(tail3.begin() + 2, tail3.end());
    BOOST_REQUIRE_GT(range7.size(), 1U);
    BOOST_REQUIRE_EQUAL((int)value7[0], 64);
    BOOST_REQUIRE_EQUAL((int)value3[0], 64);
    BOOST_REQUIRE_EQUAL(value3.size(), 67U);

    // The reassembly, before either half: rebuilding mask 7 from its own parts validates.
    {
        std::vector<unsigned char> rebuilt = prefix7;
        rebuilt.push_back(0);
        rebuilt.insert(rebuilt.end(), range7.begin(), range7.end());
        rebuilt.insert(rebuilt.end(), value7.begin(), value7.end());
        BOOST_REQUIRE_MESSAGE(Validates(rebuilt),
                              "the reassembled mask-7 shield did not validate");
    }

    // Absent when required.
    {
        std::vector<unsigned char> stripped = prefix7;
        stripped.push_back(0);
        stripped.push_back(0);
        stripped.insert(stripped.end(), value7.begin(), value7.end());
        BOOST_CHECK_MESSAGE(!Validates(stripped),
                            "a hidden amount validated with no range proof");
        BOOST_CHECK_EQUAL(ValidationResult(stripped), 1);
    }

    // Present when not required. Nothing downstream looks at this section once the
    // amounts are disclosed, so the biconditional is the only thing that refuses it.
    {
        std::vector<unsigned char> injected = prefix3;
        injected.push_back(0);
        injected.insert(injected.end(), range7.begin(), range7.end());
        injected.insert(injected.end(), value3.begin(), value3.end());
        BOOST_CHECK_MESSAGE(!Validates(injected),
                            "a disclosed amount validated alongside a range proof");
        BOOST_CHECK_EQUAL(ValidationResult(injected), 1);
    }
}

// All or none: one record per declared input and output. Counts are read off the wire by
// differencing payloads built at every mask.
BOOST_AUTO_TEST_CASE(a_mask_publishes_one_record_per_input_and_per_output)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNote funded;
    FundOneNote(txdb, funded, 0x66);

    const uint64_t nPaid = 1500;
    const uint64_t nFee = 100;
    std::vector<unsigned char> vPayload[8];
    PrivacyVNextDerivedKeys payee;
    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
    {
        BOOST_REQUIRE_MESSAGE(
            BuildMaskedTransfer(funded, nMask, nPaid, nFee, payee,
                                vPayload[nMask], error),
            strprintf("mask %u: %s", (unsigned)nMask, error.c_str()));
        BOOST_REQUIRE_MESSAGE(
            Validates(vPayload[nMask]),
            strprintf("mask %u did not validate", (unsigned)nMask));
        BOOST_CHECK_EQUAL((int)vPayload[nMask][5], (int)nMask);
    }

    const size_t nInputs = funded.spends.size();
    const size_t nOutputs = 2;
    const size_t nSenderProofs =
        nInputs * INNOVA_PRIVACY_VNEXT_SENDER_DISCLOSURE_PROOF_SIZE;
    const size_t nReceiverProofs =
        nOutputs * INNOVA_PRIVACY_VNEXT_RECEIVER_DISCLOSURE_PROOF_SIZE;
    // Publishing the sender adds one 32-byte authority and one sender proof per input and
    // nothing else; the framing of the proof section moves with it.
    BOOST_CHECK_EQUAL(vPayload[6].size() - vPayload[7].size(),
                      nInputs * 32 + FramedSize(nSenderProofs) - FramedSize(0));
    // Publishing the recipients adds one spend key, one view key and one receiver proof
    // per output, the sender's own change included.
    BOOST_CHECK_EQUAL(vPayload[5].size() - vPayload[7].size(),
                      nOutputs * 64 + FramedSize(nReceiverProofs) - FramedSize(0));
    // And the two bits are independent: publishing both adds exactly the sum.
    BOOST_CHECK_EQUAL(
        vPayload[4].size() - vPayload[7].size(),
        nInputs * 32 + nOutputs * 64 +
            FramedSize(nSenderProofs + nReceiverProofs) - FramedSize(0));

    // The published authority is fixed by the note rather than drawn per proof, which is
    // what makes clearing bit 1 name one leaf instead of describing it.
    PrivacyVNextDigest authority;
    PrivacyVNextDigest again;
    BOOST_REQUIRE_MESSAGE(SenderAuthorityOf(funded, 0x31, authority, error), error);
    BOOST_REQUIRE_MESSAGE(SenderAuthorityOf(funded, 0x32, again, error), error);
    BOOST_CHECK(authority == again);
    BOOST_CHECK(PayloadContains(vPayload[6], DigestBytes(authority)));
    BOOST_CHECK(!PayloadContains(vPayload[7], DigestBytes(authority)));
    BOOST_CHECK(PayloadContains(vPayload[5], AddressBytes(payee)));
    BOOST_CHECK(!PayloadContains(vPayload[7], AddressBytes(payee)));

    // A fourth bit selects nothing, and no payload may carry one.
    std::vector<unsigned char> refused;
    BOOST_CHECK(!BuildMaskedTransfer(funded, 8, nPaid, nFee, payee, refused, error));
}

// The disclosed authority is not asserted, it is proved: knowledge of its discrete log
// over G, and of the re-randomization the membership proof applied, over T.
BOOST_AUTO_TEST_CASE(a_published_authority_is_proved_to_be_the_output_key_spent)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNote funded;
    FundOneNote(txdb, funded, 0x67);

    PrivacyVNextDerivedKeys payee;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildMaskedTransfer(funded, 6, 1500, 100, payee, payload, error), error);
    BOOST_REQUIRE(Validates(payload));
    PrivacyVNextDigest authority;
    BOOST_REQUIRE_MESSAGE(SenderAuthorityOf(funded, 0x33, authority, error), error);
    BOOST_REQUIRE(PayloadContains(payload, DigestBytes(authority)));

    const size_t nProofs =
        funded.spends.size() * INNOVA_PRIVACY_VNEXT_SENDER_DISCLOSURE_PROOF_SIZE;
    const size_t nStart = DisclosureSectionStart(payload, nProofs);
    BOOST_REQUIRE_EQUAL(nStart + nProofs, payload.size());

    // The proof sits past the region the signing hash covers, so a byte changed here is
    // refused by this check and by nothing ahead of it.
    for (size_t i = 0; i < nProofs; i += 16)
    {
        std::vector<unsigned char> tampered = payload;
        tampered[nStart + i] ^= 0x01;
        BOOST_CHECK_MESSAGE(
            !Validates(tampered),
            strprintf("a sender disclosure validated with proof byte %u flipped",
                      (unsigned)i));
    }
    std::vector<unsigned char> zeroed = payload;
    for (size_t i = 0; i < nProofs; ++i)
        zeroed[nStart + i] = 0;
    BOOST_CHECK_MESSAGE(!Validates(zeroed), "a zeroed sender disclosure validated");
}

// The disclosed pair has to reconstruct the tweak and land on the output key the payload
// creates at that index, or a payer could publish any address beside a payment.
BOOST_AUTO_TEST_CASE(a_published_address_is_proved_to_own_the_output_it_names)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNote funded;
    FundOneNote(txdb, funded, 0x68);

    PrivacyVNextDerivedKeys payee;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildMaskedTransfer(funded, 5, 1500, 100, payee, payload, error), error);
    BOOST_REQUIRE(Validates(payload));
    BOOST_REQUIRE(PayloadContains(payload, AddressBytes(payee)));

    const size_t nEach = INNOVA_PRIVACY_VNEXT_RECEIVER_DISCLOSURE_PROOF_SIZE;
    const size_t nProofs = 2 * nEach;
    const size_t nStart = DisclosureSectionStart(payload, nProofs);
    BOOST_REQUIRE_EQUAL(nStart + nProofs, payload.size());

    for (size_t i = 0; i < nProofs; i += 16)
    {
        std::vector<unsigned char> tampered = payload;
        tampered[nStart + i] ^= 0x01;
        BOOST_CHECK_MESSAGE(
            !Validates(tampered),
            strprintf("a receiver disclosure validated with proof byte %u flipped",
                      (unsigned)i));
    }

    // The two proofs are not interchangeable: each binds its own output index and the
    // address published at that index.
    std::vector<unsigned char> swapped = payload;
    for (size_t i = 0; i < nEach; ++i)
        std::swap(swapped[nStart + i], swapped[nStart + nEach + i]);
    BOOST_CHECK_MESSAGE(!Validates(swapped),
                        "two receiver disclosures validated in each other's place");
}

// With the mask bounded and every section length pinned, one transaction has one
// encoding: no slack byte a relay or a builder could vary, and no trailing byte at all.
BOOST_AUTO_TEST_CASE(the_disclosure_proof_section_has_no_slack)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNote funded;
    FundOneNote(txdb, funded, 0x69);

    PrivacyVNextDerivedKeys payee;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildMaskedTransfer(funded, 0, 1500, 100, payee, payload, error), error);
    BOOST_REQUIRE(Validates(payload));

    const size_t nProofs =
        funded.spends.size() * INNOVA_PRIVACY_VNEXT_SENDER_DISCLOSURE_PROOF_SIZE +
        2 * INNOVA_PRIVACY_VNEXT_RECEIVER_DISCLOSURE_PROOF_SIZE;
    const size_t nStart = DisclosureSectionStart(payload, nProofs);
    BOOST_REQUIRE_EQUAL(nStart + nProofs, payload.size());
    std::vector<unsigned char> header;
    PutTestCompactSize(header, nProofs);
    const size_t nHeaderAt = nStart - header.size();
    const std::vector<unsigned char> section(payload.begin() + nStart, payload.end());
    const std::vector<unsigned char> head(payload.begin(),
                                          payload.begin() + nHeaderAt);

    // One byte past the end of a complete payload.
    {
        std::vector<unsigned char> trailing = payload;
        trailing.push_back(0);
        BOOST_CHECK_MESSAGE(!Validates(trailing),
                            "a payload validated with a trailing byte");
        BOOST_CHECK_EQUAL(ValidationResult(trailing), 1);
    }
    // A correctly framed section one byte longer than the records call for.
    {
        std::vector<unsigned char> longer = head;
        std::vector<unsigned char> s = section;
        s.push_back(0);
        PutTestVector(longer, s);
        BOOST_CHECK_MESSAGE(!Validates(longer),
                            "a disclosure section validated one byte too long");
        BOOST_CHECK_EQUAL(ValidationResult(longer), 1);
    }
    // And one byte shorter.
    {
        std::vector<unsigned char> shorter = head;
        PutTestVector(shorter,
                      std::vector<unsigned char>(section.begin(), section.end() - 1));
        BOOST_CHECK_MESSAGE(!Validates(shorter),
                            "a disclosure section validated one byte too short");
    }
    // An absent section, which is what a payload publishing nothing would carry.
    {
        std::vector<unsigned char> empty = head;
        PutTestVector(empty, std::vector<unsigned char>());
        BOOST_CHECK_MESSAGE(!Validates(empty),
                            "a payload that published records validated with no proofs");
    }
    // The reassembly control: the same section put back unchanged still validates.
    {
        std::vector<unsigned char> same = head;
        PutTestVector(same, section);
        BOOST_REQUIRE(same == payload);
    }
}

// This is what makes the mask non-malleable by a third party: editing it, or any record
// it selects, changes the signing hash, which invalidates the balance and membership
// proofs, and neither can be remade without the spend keys.
BOOST_AUTO_TEST_CASE(the_signing_hash_covers_the_mask_and_every_disclosed_record)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNote funded;
    FundOneNote(txdb, funded, 0x6a);

    const uint64_t nPaid = 1500;
    PrivacyVNextDerivedKeys payee;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildMaskedTransfer(funded, 0, nPaid, 100, payee, payload, error), error);
    BOOST_REQUIRE(Validates(payload));
    BOOST_REQUIRE_EQUAL((int)payload[5], 0);

    for (int nBit = 0; nBit < 8; ++nBit)
    {
        std::vector<unsigned char> tampered = payload;
        tampered[5] ^= (unsigned char)(1 << nBit);
        BOOST_CHECK_MESSAGE(
            !Validates(tampered),
            strprintf("the mask took bit %d and the payload still validated", nBit));
    }

    // Each disclosed record, located where it is actually published rather than where the
    // layout is assumed to put it.
    PrivacyVNextDigest authority;
    BOOST_REQUIRE_MESSAGE(SenderAuthorityOf(funded, 0x34, authority, error), error);
    std::vector<std::pair<size_t, size_t> > vRecords;
    std::vector<size_t> vAt = FindAll(payload, DigestBytes(authority));
    BOOST_REQUIRE_EQUAL(vAt.size(), 1U);
    vRecords.push_back(std::make_pair(vAt[0], (size_t)32));
    vAt = FindAll(payload, AddressBytes(payee));
    BOOST_REQUIRE_EQUAL(vAt.size(), 1U);
    vRecords.push_back(std::make_pair(vAt[0], (size_t)64));
    vAt = FindAll(payload, AmountBytes(nPaid));
    BOOST_REQUIRE_EQUAL(vAt.size(), 1U);
    vRecords.push_back(std::make_pair(vAt[0], (size_t)8));

    for (size_t r = 0; r < vRecords.size(); ++r)
        for (size_t i = 0; i < vRecords[r].second; ++i)
        {
            std::vector<unsigned char> tampered = payload;
            tampered[vRecords[r].first + i] ^= 0x01;
            BOOST_CHECK_MESSAGE(
                !Validates(tampered),
                strprintf("record %u validated with byte %u flipped", (unsigned)r,
                          (unsigned)i));
        }
}

// The pool credit, key images, leaves, fee and transparent binding are the same objects at
// every mask; no consensus site may branch on the mask.
BOOST_AUTO_TEST_CASE(what_a_payload_settles_carries_no_disclosed_field)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNote funded;
    FundOneNote(txdb, funded, 0x6b);

    const uint64_t nPaid = 1500;
    const uint64_t nFee = 100;
    PrivacyVNextDerivedKeys payee;
    std::vector<unsigned char> vPayload[8];
    PrivacyVNextStateEffects vEffects[8];
    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
    {
        BOOST_REQUIRE_MESSAGE(
            BuildMaskedTransfer(funded, nMask, nPaid, nFee, payee, vPayload[nMask],
                                error),
            strprintf("mask %u: %s", (unsigned)nMask, error.c_str()));
        BOOST_REQUIRE_MESSAGE(
            ExtractPrivacyVNextPayloadEffects(
                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vPayload[nMask],
                vEffects[nMask]).IsValid(),
            strprintf("mask %u produced no effects", (unsigned)nMask));
    }

    // The effects have to describe a transaction that actually moves, or the comparison
    // below would hold across eight empty structures.
    BOOST_REQUIRE_EQUAL(vEffects[7].keyImages.size(), funded.spends.size());
    BOOST_REQUIRE_EQUAL(vEffects[7].outputLeaves.size(), 2U);
    BOOST_REQUIRE_EQUAL(vEffects[7].nFee, nFee);

    PrivacyVNextDigest zero;
    zero.fill(0);
    for (int m = 0; m < 8; ++m)
    {
        const PrivacyVNextStateEffects& e = vEffects[m];
        BOOST_CHECK_MESSAGE(e.finalizedRoot == vEffects[7].finalizedRoot,
                            strprintf("mask %d settles a different anchor", m));
        BOOST_CHECK_EQUAL(e.nFinalizedTreeSize, vEffects[7].nFinalizedTreeSize);
        BOOST_CHECK(e.parameterDigest == vEffects[7].parameterDigest);
        BOOST_CHECK_EQUAL(e.nTransparentValueBalance,
                          vEffects[7].nTransparentValueBalance);
        BOOST_CHECK_EQUAL(e.nFee, vEffects[7].nFee);
        BOOST_CHECK(e.transparentBinding == vEffects[7].transparentBinding);
        // Deterministic per note, so this one is an equality and not merely a shape.
        BOOST_CHECK_MESSAGE(e.keyImages == vEffects[7].keyImages,
                            strprintf("mask %d spends a different key image", m));
        BOOST_CHECK_EQUAL(e.outputLeaves.size(), vEffects[7].outputLeaves.size());
        BOOST_CHECK(e.attestationKeyImages.empty());
        BOOST_CHECK(e.registrationContext == zero);
        BOOST_CHECK(!e.HasMemberKey());
    }

    // And nothing the fully disclosing payload publishes reaches the effects at all.
    const std::vector<unsigned char> settled = SettledBytes(vEffects[0]);
    std::vector<std::pair<std::string, std::vector<unsigned char> > > vSecrets;
    vSecrets.push_back(std::make_pair(std::string("the payee address"),
                                      AddressBytes(payee)));
    vSecrets.push_back(std::make_pair(
        std::string("the payee spend key"),
        std::vector<unsigned char>(payee.spendPublic.begin(),
                                   payee.spendPublic.end())));
    vSecrets.push_back(std::make_pair(
        std::string("the payee view key"),
        std::vector<unsigned char>(payee.viewPublic.begin(),
                                   payee.viewPublic.end())));
    PrivacyVNextDigest authority;
    BOOST_REQUIRE_MESSAGE(SenderAuthorityOf(funded, 0x35, authority, error), error);
    vSecrets.push_back(std::make_pair(std::string("the spending authority"),
                                      DigestBytes(authority)));
    vSecrets.push_back(std::make_pair(std::string("the paid amount"),
                                      AmountBytes(nPaid)));

    for (size_t i = 0; i < vSecrets.size(); ++i)
    {
        // The control: the payload really does publish it, so the absence below is about
        // the effects and not about a needle that is nowhere.
        BOOST_CHECK_MESSAGE(PayloadContains(vPayload[0], vSecrets[i].second),
                            "mask 0 does not publish " + vSecrets[i].first);
        BOOST_CHECK_MESSAGE(!PayloadContains(settled, vSecrets[i].second),
                            "what the payload settles carries " + vSecrets[i].first);
    }
}

// For each mask, every field a clear bit publishes is required at its record offset, byte
// for byte against wallet-derived material, and every hidden field is required absent.
// A needle is shown findable where published before it is required missing elsewhere.
BOOST_AUTO_TEST_CASE(each_mask_publishes_exactly_the_fields_its_clear_bits_name)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNote funded;
    // Amounts with four nonzero bytes each. An eight-byte needle that is mostly zero
    // would match the zero runs the fixed-width header already contains, and the absence
    // half is only as good as its needle.
    FundOneNote(txdb, funded, 0x6c, 0xA3B5C7D9ULL);

    const uint64_t nPaid = 0x51C3E7A9ULL;
    const uint64_t nFee = 100;
    const uint64_t nChange = funded.nAmount - nPaid - nFee;
    const size_t nIn = funded.spends.size();
    const size_t nOut = 2;
    BOOST_REQUIRE_EQUAL(nIn, 1U);

    // Derived exactly as BuildMaskedTransfer derives them, so every needle below is the
    // wallet's own material rather than something read back out of a payload.
    PrivacyVNextDerivedKeys change;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextChangeKeys(DisclosureDigest(0x63), funded.genesis,
                                     LocalNetwork(), change, error),
        error);
    PrivacyVNextDigest authority;
    BOOST_REQUIRE_MESSAGE(SenderAuthorityOf(funded, 0x36, authority, error), error);

    PrivacyVNextDerivedKeys payee;
    std::vector<unsigned char> vPayload[8];
    PrivacyVNextDigest vKeyImage[8];
    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
    {
        std::vector<unsigned char>& payload = vPayload[nMask];
        BOOST_REQUIRE_MESSAGE(
            BuildMaskedTransfer(funded, nMask, nPaid, nFee, payee, payload, error),
            strprintf("mask %u: %s", (unsigned)nMask, error.c_str()));

        // Validation and the decoder's own view of the payload in one call: what the
        // offsets below are checked against comes from the decoder, not from this test's
        // arithmetic agreeing with itself.
        PrivacyVNextStateEffects effects;
        BOOST_REQUIRE_MESSAGE(
            ExtractPrivacyVNextPayloadEffects(
                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects).IsValid(),
            strprintf("mask %u did not validate", (unsigned)nMask));

        const PrefixLayout layout(nIn, nOut, nMask);

        // The mask off the wire, never off the request that asked for it.
        BOOST_CHECK_EQUAL((int)payload[5], (int)nMask);

        // The offsets, before anything is asserted at them. A layout change has to fail
        // here rather than move every needle below onto the wrong bytes.
        BOOST_REQUIRE_EQUAL(ReadU64(payload, layout.nFeeAt), nFee);
        BOOST_REQUIRE_EQUAL((size_t)payload[layout.nInputCountAt], nIn);
        BOOST_REQUIRE_EQUAL((size_t)payload[layout.nOutputCountAt], nOut);
        BOOST_REQUIRE_EQUAL(effects.keyImages.size(), nIn);
        BOOST_REQUIRE_EQUAL(effects.outputLeaves.size(), nOut);
        for (size_t i = 0; i < nIn; ++i)
            BOOST_REQUIRE(DigestAt(payload, layout.KeyImageAt(i)) ==
                          effects.keyImages[i]);
        for (size_t i = 0; i < nOut; ++i)
        {
            BOOST_REQUIRE(DigestAt(payload, layout.OwnerAt(i)) ==
                          effects.outputLeaves[i].owner);
            BOOST_REQUIRE(DigestAt(payload, layout.OwnerAt(i) + 32) ==
                          effects.outputLeaves[i].commitment);
        }
        vKeyImage[nMask] = effects.keyImages[0];

        // Bit 1: one authority per input, and the authority is a property of the note, so
        // publishing it names one leaf to anyone who knows that leaf.
        for (size_t i = 0; i < nIn; ++i)
            CheckDisclosedField(payload, nMask, layout.DisclosesSender(),
                                DisclosedField("the spending authority",
                                               DigestBytes(authority),
                                               layout.SenderRecordAt(i)));

        // Bit 2: the address of every output, the sender's own change included.
        CheckDisclosedField(payload, nMask, layout.DisclosesReceiver(),
                            DisclosedField("the payee address", AddressBytes(payee),
                                           layout.ReceiverRecordAt(0)));
        CheckDisclosedField(payload, nMask, layout.DisclosesReceiver(),
                            DisclosedField("the change address", AddressBytes(change),
                                           layout.ReceiverRecordAt(1)));
        // Half an address still names a wallet, so each key is a needle of its own.
        CheckDisclosedField(payload, nMask, layout.DisclosesReceiver(),
                            DisclosedField("the payee spend key",
                                           DigestBytes(payee.spendPublic),
                                           layout.ReceiverRecordAt(0)));
        CheckDisclosedField(payload, nMask, layout.DisclosesReceiver(),
                            DisclosedField("the payee view key",
                                           DigestBytes(payee.viewPublic),
                                           layout.ReceiverRecordAt(0) + 32));
        CheckDisclosedField(payload, nMask, layout.DisclosesReceiver(),
                            DisclosedField("the change spend key",
                                           DigestBytes(change.spendPublic),
                                           layout.ReceiverRecordAt(1)));
        CheckDisclosedField(payload, nMask, layout.DisclosesReceiver(),
                            DisclosedField("the change view key",
                                           DigestBytes(change.viewPublic),
                                           layout.ReceiverRecordAt(1) + 32));

        // Bit 2 at the DH layer: the shared point, recomputed from the recipient's view secret
        // and this payload's cleartext ephemeral, must appear only when disclosed.
        const size_t nProofsAt =
            DisclosureSectionStart(payload, layout.DisclosureProofBytes());
        const PrivacyVNextDigest* vViewSecret[2] = {&payee.viewSecret,
                                                    &change.viewSecret};
        static const char* vWhose[2] = {"the payee", "the change"};
        for (size_t i = 0; i < nOut; ++i)
        {
            PrivacyVNextDigest shared;
            BOOST_REQUIRE_MESSAGE(
                SharedPointOf(*vViewSecret[i],
                              DigestAt(payload, layout.TweakEphemeralAt(i)), shared,
                              error),
                error);
            CheckDisclosedField(
                payload, nMask, layout.DisclosesReceiver(),
                DisclosedField(std::string(vWhose[i]) + " shared point",
                               DigestBytes(shared),
                               nProofsAt + layout.SenderProofBytes() +
                                   i * INNOVA_PRIVACY_VNEXT_RECEIVER_DISCLOSURE_PROOF_SIZE));
        }

        // Bit 4: one amount per output.
        if (layout.DisclosesAmount())
        {
            BOOST_CHECK_EQUAL(ReadU64(payload, layout.AmountRecordAt(0)), nPaid);
            BOOST_CHECK_EQUAL(ReadU64(payload, layout.AmountRecordAt(1)), nChange);
        }
        CheckDisclosedField(payload, nMask, layout.DisclosesAmount(),
                            DisclosedField("the paid amount", AmountBytes(nPaid),
                                           layout.AmountRecordAt(0)));
        CheckDisclosedField(payload, nMask, layout.DisclosesAmount(),
                            DisclosedField("the change amount", AmountBytes(nChange),
                                           layout.AmountRecordAt(1)));

        // The spent leaf is on the wire nowhere, at any mask; the created leaves are the controls.
        // The sender disclosure names the spent note by one-time key, never by leaf.
        BOOST_CHECK_MESSAGE(
            FindAll(payload, DigestBytes(funded.spends[0].leaf.owner)).empty(),
            strprintf("mask %u carries the owner key of the leaf it spends",
                      (unsigned)nMask));
        BOOST_CHECK_MESSAGE(
            FindAll(payload, DigestBytes(funded.spends[0].leaf.commitment)).empty(),
            strprintf("mask %u carries the commitment of the leaf it spends",
                      (unsigned)nMask));
        // The spend secret and the view secrets are the material the published authority
        // and the published shared point are computed from. Those two are on the wire at
        // the masks that publish them; the secrets behind them are on the wire at none.
        BOOST_CHECK_MESSAGE(
            FindAll(payload, DigestBytes(funded.spends[0].spendSecret)).empty(),
            strprintf("mask %u carries the spend secret of the note it spends",
                      (unsigned)nMask));
        BOOST_CHECK_MESSAGE(
            FindAll(payload, DigestBytes(payee.viewSecret)).empty(),
            strprintf("mask %u carries the payee's view secret", (unsigned)nMask));
        BOOST_CHECK_MESSAGE(
            FindAll(payload, DigestBytes(change.viewSecret)).empty(),
            strprintf("mask %u carries the change view secret", (unsigned)nMask));

        // Both ephemerals in every output at every mask, and never equal. Their presence
        // is uniform, so carrying a second ephemeral is not itself a mark of a payload
        // that discloses its receiver.
        for (size_t i = 0; i < nOut; ++i)
        {
            const std::vector<unsigned char> note =
                Slice(payload, layout.NoteEphemeralAt(i), 32);
            const std::vector<unsigned char> tweak =
                Slice(payload, layout.TweakEphemeralAt(i), 32);
            BOOST_CHECK(note != tweak);
            BOOST_CHECK(note != std::vector<unsigned char>(32, 0));
            BOOST_CHECK(tweak != std::vector<unsigned char>(32, 0));
        }
    }

    // The identifier that does recur across transactions, stated rather than left
    // implied: the key image is the same 32 bytes at every mask, mask 7 included. Hiding
    // the sender hides which note was spent, not that this note was spent.
    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
        BOOST_CHECK_MESSAGE(vKeyImage[nMask] == vKeyImage[7],
                            strprintf("mask %u spends a different key image",
                                      (unsigned)nMask));

    // Rewriting the mask byte to any other value is refused from every mask, in both directions.
    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
        for (uint8_t nOther = 0; nOther <= 7; ++nOther)
        {
            if (nOther == nMask)
                continue;
            std::vector<unsigned char> relabelled = vPayload[nMask];
            relabelled[5] = nOther;
            BOOST_CHECK_MESSAGE(
                !Validates(relabelled),
                strprintf("a mask-%u payload validated relabelled as mask %u",
                          (unsigned)nMask, (unsigned)nOther));
        }
}

// Payload length reveals nothing beyond the cleartext mask and counts: each mask bit moves
// a fixed number of bytes, and at a fixed mask and shape amount, recipient and fee do not.
BOOST_AUTO_TEST_CASE(payload_size_follows_the_mask_and_never_the_secret_it_hides)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNote funded;
    FundOneNote(txdb, funded, 0x6d, 0xA3B5C7D9ULL);
    const size_t nIn = funded.spends.size();
    BOOST_REQUIRE_EQUAL(nIn, 1U);

    PrivacyVNextDerivedKeys payee;
    size_t vTransfer[8];
    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
    {
        std::vector<unsigned char> payload;
        BOOST_REQUIRE_MESSAGE(
            BuildMaskedTransfer(funded, nMask, 0x51C3E7A9ULL, 100, payee, payload,
                                error),
            strprintf("mask %u: %s", (unsigned)nMask, error.c_str()));
        BOOST_REQUIRE_MESSAGE(Validates(payload),
                              strprintf("mask %u did not validate", (unsigned)nMask));
        vTransfer[nMask] = payload.size();
    }
    CheckMaskSizeIsSeparable(vTransfer, nIn, 2);

    // The same algebra where there is nothing to disclose a sender about. A shield
    // declares no input, so bit 1 has no record to add and has to move no bytes at all --
    // which is what says the sender term is one record per input and not a constant.
    ShieldAnchor anchor;
    BOOST_REQUIRE_MESSAGE(LoadShieldAnchor(anchor, error), error);
    const std::vector<uint64_t> vOne(1, 4200);
    size_t vShield[8];
    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
    {
        std::vector<unsigned char> payload;
        BOOST_REQUIRE_MESSAGE(
            BuildShield(nMask, anchor, vOne, 55, 0x94, payload, error),
            strprintf("shield mask %u: %s", (unsigned)nMask, error.c_str()));
        BOOST_REQUIRE_MESSAGE(
            Validates(payload),
            strprintf("shield mask %u did not validate", (unsigned)nMask));
        vShield[nMask] = payload.size();
    }
    CheckMaskSizeIsSeparable(vShield, 0, 1);
    for (uint8_t nMask = 0; nMask <= 7; ++nMask)
    {
        if ((nMask & iv5::DISCLOSURE_HIDE_SENDER) != 0)
            continue;
        BOOST_CHECK_EQUAL(vShield[nMask],
                          vShield[nMask | iv5::DISCLOSURE_HIDE_SENDER]);
    }

    // Same declared shape, different secrets. One unit and a payment nine decimal digits
    // larger, to different addresses, under different fees, come out the same length --
    // at the mask that publishes all three and at the mask that publishes none.
    std::vector<uint64_t> vSmall;
    vSmall.push_back(1);
    vSmall.push_back(2);
    std::vector<uint64_t> vLarge;
    vLarge.push_back(0xA3B5C7D9ULL);
    vLarge.push_back(0x51C3E7A9ULL);
    static const uint8_t vShapeMasks[2] = {0, 7};
    for (size_t i = 0; i < 2; ++i)
    {
        std::vector<unsigned char> small;
        std::vector<unsigned char> large;
        BOOST_REQUIRE_MESSAGE(
            BuildShield(vShapeMasks[i], anchor, vSmall, 7, 0xA1, small, error), error);
        BOOST_REQUIRE_MESSAGE(
            BuildShield(vShapeMasks[i], anchor, vLarge, 0x1D4C, 0xA2, large, error),
            error);
        BOOST_REQUIRE(Validates(small));
        BOOST_REQUIRE(Validates(large));
        BOOST_CHECK_MESSAGE(
            small.size() == large.size(),
            strprintf("mask %u: %u bytes for one payment and %u for another",
                      (unsigned)vShapeMasks[i], (unsigned)small.size(),
                      (unsigned)large.size()));
    }
}
BOOST_AUTO_TEST_SUITE_END()
