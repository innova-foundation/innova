#include <boost/test/unit_test.hpp>

#include <cstring>
#include <set>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../main.h"
#include "../ed25519_zk.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../txdb.h"

#include <algorithm>

namespace
{

const uint64_t kTier = INNOVA_PRIVACY_VNEXT_COLLATERAL_ATTESTATION_AMOUNT;
// A note at the finality stake floor (100 INN), the note a vote spends.
const uint64_t kVoteNote = 500ULL * 100000000ULL;   // the stake floor a vote proves

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
            FundingContext(),
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
    onChain.inputContext = FundingContext();
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

// Compact size the way the payload decoder reads it: the short form below 253, the
// two-byte form above it. A membership proof is well past 253 bytes.
void PutCompact(std::vector<unsigned char>& out, uint64_t nSize)
{
    if (nSize < 253)
    {
        out.push_back((unsigned char)nSize);
        return;
    }
    if (nSize <= 0xffff)
    {
        out.push_back(253);
        out.push_back((unsigned char)nSize);
        out.push_back((unsigned char)(nSize >> 8));
        return;
    }
    out.push_back(254);
    for (size_t i = 0; i < 4; ++i)
        out.push_back((unsigned char)(nSize >> (8 * i)));
}

void PutDigest(std::vector<unsigned char>& out, const PrivacyVNextDigest& d)
{
    out.insert(out.end(), d.begin(), d.end());
}

void PutLE64(std::vector<unsigned char>& out, uint64_t v)
{
    for (size_t i = 0; i < 8; ++i)
        out.push_back((unsigned char)(v >> (8 * i)));
}

void PutSection(std::vector<unsigned char>& out, const std::vector<unsigned char>& v)
{
    PutCompact(out, v.size());
    out.insert(out.end(), v.begin(), v.end());
}

std::vector<unsigned char> DigestBytes(const PrivacyVNextDigest& d)
{
    return std::vector<unsigned char>(d.begin(), d.end());
}

// Where the parameter digest a payload declares sits: schema, six envelope bytes, the
// reserved byte, then the genesis hash.
const size_t kParameterDigestOffset = 2 + 7 + 32;

// The attestation builder's assembly with the shape-pinned fields left to the caller; every
// proof verifies, so only the shape check can refuse it.
bool BuildShapedAttestation(const FundedNote& note,
                            const PrivacyVNextDigest& parameterDigest,
                            uint8_t nDisclosureMask,
                            int64_t nTransparentValueBalance,
                            uint64_t nFee,
                            std::vector<unsigned char>& vchPayloadOut,
                            std::string& error)
{
    vchPayloadOut.clear();
    const PrivacyVNextDigest entropy = CollateralScalar(0x27);

    std::vector<PrivacyVNextSpendInput> vInputs(1);
    vInputs[0].spendScalar = note.spend.spendSecret;
    vInputs[0].commitmentScalar = note.spend.y;
    vInputs[0].leaf = note.spend.leaf;
    vInputs[0].vchWitnessRecord = note.spend.vchWitnessRecord;

    // Two passes: the prefix names the pseudo-output, and the hash over that prefix is
    // what the proof binds to.
    PrivacyVNextDigest provisional;
    provisional.fill(0);
    provisional[0] = 1;
    std::vector<PrivacyVNextSpendConstruction> vDraft;
    std::vector<unsigned char> vchDraft;
    if (!ProvePrivacyVNextMembership(note.finalizedRoot, provisional, entropy,
                                     vInputs, vDraft, vchDraft, error))
        return false;
    if (vDraft.size() != 1)
    {
        error = "shaped attestation proving returned the wrong input count";
        return false;
    }

    std::vector<unsigned char> prefix;
    prefix.push_back((unsigned char)iv5::PROTOCOL_SCHEMA);
    prefix.push_back(0);
    prefix.push_back(iv5::NOTE_COLLATERAL_REGISTER);
    prefix.push_back(0);                         // finality profile: none
    prefix.push_back(iv5::AUTH_OWNER);
    prefix.push_back(nDisclosureMask);
    prefix.push_back(0);                         // finality object: none
    prefix.push_back(LocalNetwork());
    prefix.push_back(0);                         // reserved
    PutDigest(prefix, LocalGenesis());
    PutDigest(prefix, parameterDigest);
    PutDigest(prefix, note.finalizedRoot);
    PutLE64(prefix, note.nTreeSize);
    PutLE64(prefix, (uint64_t)nTransparentValueBalance);
    PutLE64(prefix, nFee);
    PutDigest(prefix, NoTransparentSide());
    PutCompact(prefix, 1);
    PutDigest(prefix, vDraft[0].pseudoOut);
    PutDigest(prefix, vDraft[0].keyImage);
    PutCompact(prefix, 0);
    PutDigest(prefix, CollateralDigest(0xe1));    // registration context
    PutSection(prefix, std::vector<unsigned char>());

    PrivacyVNextDigest signingHash;
    if (!HashPrivacyVNextPayloadPrefix(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                       prefix, signingHash, error))
        return false;

    std::vector<PrivacyVNextSpendConstruction> vFinal;
    std::vector<unsigned char> vchMembership;
    if (!ProvePrivacyVNextMembership(note.finalizedRoot, signingHash, entropy,
                                     vInputs, vFinal, vchMembership, error))
        return false;
    if (vFinal.size() != 1 || vFinal[0].pseudoOut != vDraft[0].pseudoOut ||
        vFinal[0].keyImage != vDraft[0].keyImage)
    {
        error = "shaped attestation proving is not deterministic in its entropy";
        return false;
    }

    std::vector<unsigned char> vchMask;
    if (!Ed25519ScalarAdd(DigestBytes(note.spend.mask),
                          DigestBytes(vFinal[0].pseudoOutMaskDelta), vchMask) ||
        vchMask.size() != 32)
    {
        error = "shaped attestation mask accumulation failed";
        return false;
    }
    PrivacyVNextDigest amountMask;
    std::memcpy(amountMask.data(), &vchMask[0], 32);

    std::vector<unsigned char> vchAmountProof;
    if (!ProvePrivacyVNextAmountEquality(vFinal[0].pseudoOut, kTier, amountMask,
                                         signingHash, CollateralScalar(0x33),
                                         vchAmountProof, error))
        return false;

    std::vector<unsigned char> payload = prefix;
    PutSection(payload, vchMembership);
    PutSection(payload, std::vector<unsigned char>());   // no range proof
    PutSection(payload, std::vector<unsigned char>());   // no balance proof
    PutSection(payload, vchAmountProof);                 // the tier proof
    PutSection(payload, std::vector<unsigned char>());   // no disclosures
    vchPayloadOut.swap(payload);
    return true;
}

// The contract digest this build was compiled against; the decoder carries it and never
// judges it, so any nonzero value serves a payload that is only ever validated.
PrivacyVNextDigest ContractDigest()
{
    PrivacyVNextDigest d;
    BOOST_REQUIRE(iv5::DecodeDigestHex(iv5::PROTOCOL_CONTRACT_SHA256, d.data()));
    return d;
}

// A note vote built from the wallet builder's primitives with the shape-pinned fields
// left to the caller, so an off-shape payload is refused only by the shape rule.
bool BuildShapedNoteVote(const FundedNote& note,
                         const PrivacyVNextDigest& parameterDigest,
                         uint64_t nReissueAmount,
                         int64_t nTransparentValueBalance,
                         uint64_t nFee,
                         const PrivacyVNextDigest& boundaryHash,
                         uint32_t nBoundaryHeight,
                         std::vector<unsigned char>& vchPayloadOut,
                         PrivacyVNextDigest& keyImageOut,
                         PrivacyVNextOutputLeaf& reissueOut,
                         std::string& error)
{
    vchPayloadOut.clear();
    const PrivacyVNextDigest entropy = CollateralScalar(0x5c);

    std::vector<PrivacyVNextSpendInput> vInputs(1);
    vInputs[0].spendScalar = note.spend.spendSecret;
    vInputs[0].commitmentScalar = note.spend.y;
    vInputs[0].leaf = note.spend.leaf;
    vInputs[0].vchWitnessRecord = note.spend.vchWitnessRecord;

    // Pass one fixes the pseudo-output and key image the entropy determines.
    PrivacyVNextDigest provisional;
    provisional.fill(0);
    provisional[0] = 1;
    std::vector<PrivacyVNextSpendConstruction> vDraft;
    std::vector<unsigned char> vchDraft;
    if (!ProvePrivacyVNextMembership(note.finalizedRoot, provisional, entropy,
                                     vInputs, vDraft, vchDraft, error))
        return false;
    if (vDraft.size() != 1)
    {
        error = "shaped vote proving returned the wrong input count";
        return false;
    }

    // The reissue derives under the vote's context: operation 10, the binding, the key
    // image. Unique per note, so the reissue's one-time key cannot recur.
    std::vector<PrivacyVNextDigest> vKeyImages(1, vDraft[0].keyImage);
    PrivacyVNextDigest context;
    if (!DerivePrivacyVNextInputContext(iv5::NOTE_FINALITY_VOTE, NoTransparentSide(),
                                        vKeyImages, context, error))
        return false;
    const PrivacyVNextDigest outputMask = CollateralScalar(0x61);
    PrivacyVNextEncryptedOutput reissue;
    if (!EncryptPrivacyVNextNote(LocalNetwork(), 0, 0, LocalGenesis(),
                                 note.keys.spendPublic, note.keys.viewPublic,
                                 note.keys.outgoingViewSecret, CollateralScalar(0x62),
                                 CollateralScalar(0x63), nReissueAmount,
                                 CollateralScalar(0x64), outputMask, context, reissue,
                                 error))
        return false;

    std::vector<unsigned char> prefix;
    prefix.push_back((unsigned char)iv5::PROTOCOL_SCHEMA);
    prefix.push_back(0);
    prefix.push_back(iv5::NOTE_FINALITY_VOTE);
    prefix.push_back(0);                         // finality profile: none
    prefix.push_back(iv5::AUTH_OWNER);
    prefix.push_back(iv5::DISCLOSURE_MASK);
    prefix.push_back(0);                         // finality object: none
    prefix.push_back(LocalNetwork());
    prefix.push_back(0);                         // reserved
    PutDigest(prefix, LocalGenesis());
    PutDigest(prefix, parameterDigest);
    PutDigest(prefix, note.finalizedRoot);
    PutLE64(prefix, note.nTreeSize);
    PutLE64(prefix, (uint64_t)nTransparentValueBalance);
    PutLE64(prefix, nFee);
    PutDigest(prefix, NoTransparentSide());
    PutCompact(prefix, 1);
    PutDigest(prefix, vDraft[0].pseudoOut);
    PutDigest(prefix, vDraft[0].keyImage);
    PutCompact(prefix, 1);
    PutDigest(prefix, reissue.leaf.owner);
    PutDigest(prefix, reissue.leaf.commitment);
    PutDigest(prefix, reissue.noteEphemeral);
    PutDigest(prefix, reissue.tweakEphemeral);
    PutSection(prefix, reissue.vchRecipientCiphertext);
    PutSection(prefix, reissue.vchOutgoingCiphertext);
    PutDigest(prefix, boundaryHash);             // the vote names its boundary
    for (size_t i = 0; i < 4; ++i)
        prefix.push_back((unsigned char)(nBoundaryHeight >> (8 * i)));
    PutSection(prefix, std::vector<unsigned char>());   // finality body

    PrivacyVNextDigest signingHash;
    if (!HashPrivacyVNextPayloadPrefix(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                       prefix, signingHash, error))
        return false;

    std::vector<PrivacyVNextSpendConstruction> vFinal;
    std::vector<unsigned char> vchMembership;
    if (!ProvePrivacyVNextMembership(note.finalizedRoot, signingHash, entropy,
                                     vInputs, vFinal, vchMembership, error))
        return false;
    if (vFinal.size() != 1 || vFinal[0].pseudoOut != vDraft[0].pseudoOut ||
        vFinal[0].keyImage != vDraft[0].keyImage)
    {
        error = "shaped vote proving is not deterministic in its entropy";
        return false;
    }

    // excess = (note mask + rerandomization delta) - reissue mask
    std::vector<unsigned char> vchInputMask;
    std::vector<unsigned char> vchNegatedOutput;
    std::vector<unsigned char> vchExcess;
    if (!Ed25519ScalarAdd(DigestBytes(note.spend.mask),
                          DigestBytes(vFinal[0].pseudoOutMaskDelta), vchInputMask) ||
        !Ed25519ScalarNeg(DigestBytes(outputMask), vchNegatedOutput) ||
        !Ed25519ScalarAdd(vchInputMask, vchNegatedOutput, vchExcess) ||
        vchExcess.size() != 32)
    {
        error = "shaped vote excess mask accumulation failed";
        return false;
    }
    PrivacyVNextDigest excessMask;
    std::memcpy(excessMask.data(), &vchExcess[0], 32);

    std::vector<PrivacyVNextDigest> vPseudoOuts(1, vFinal[0].pseudoOut);
    std::vector<PrivacyVNextValueOutput> vOutputs(1);
    vOutputs[0].nAmount = nReissueAmount;
    vOutputs[0].mask = outputMask;
    PrivacyVNextValueProof valueProof;
    if (!ProvePrivacyVNextValue(vPseudoOuts, vOutputs, nTransparentValueBalance, nFee,
                                signingHash, CollateralScalar(0x65), excessMask,
                                valueProof, error))
        return false;
    if (valueProof.vOutputCommitments.size() != 1 ||
        valueProof.vOutputCommitments[0] != reissue.leaf.commitment)
    {
        error = "shaped vote value proof does not open the reissue commitment";
        return false;
    }

    // The stake-floor proof a vote carries, shaped as the builder makes it: over the
    // output commitment moved down by the floor and by the value entering. A case asking
    // for a reissue below the shift leaves it empty so it sees the decoder's refusal.
    std::vector<unsigned char> vchFloorProof;
    if (nTransparentValueBalance >= 0)
    {
        const uint64_t nShift = (uint64_t)iv5::NOTE_VOTE_MIN_WEIGHT +
                                (uint64_t)nTransparentValueBalance;
        if (nReissueAmount >= nShift)
        {
            PrivacyVNextDigest floorCommitment;
            floorCommitment.fill(0);
            if (!ProvePrivacyVNextRange(nReissueAmount - nShift, outputMask,
                                        CollateralScalar(0x66), floorCommitment,
                                        vchFloorProof, error))
                return false;
        }
    }

    std::vector<unsigned char> payload = prefix;
    PutSection(payload, vchMembership);
    PutSection(payload, valueProof.vchRangeProof);
    PutSection(payload, std::vector<unsigned char>(valueProof.balanceProof.begin(),
                                                   valueProof.balanceProof.end()));
    PutSection(payload, vchFloorProof);
    PutSection(payload, std::vector<unsigned char>());   // no disclosures
    vchPayloadOut.swap(payload);
    keyImageOut = vFinal[0].keyImage;
    reissueOut = reissue.leaf;
    return true;
}

// Offset of the boundary hash inside a shaped vote: the one 32-byte run of its fill byte.
size_t BoundaryOffset(const std::vector<unsigned char>& payload,
                      const PrivacyVNextDigest& boundaryHash)
{
    std::vector<unsigned char>::const_iterator it =
        std::search(payload.begin(), payload.end(), boundaryHash.begin(),
                    boundaryHash.end());
    BOOST_REQUIRE(it != payload.end());
    return (size_t)(it - payload.begin());
}

// A nine-byte v2008 envelope and nothing after it. Enough to reach every refusal the
// parser makes before it reads a field, and short enough that anything past them ends
// the payload instead.
std::vector<unsigned char> EnvelopeOnly(uint8_t nOperation, uint8_t nProfile,
                                        uint8_t nAuthorization, uint8_t nFinalityObject,
                                        uint8_t nDisclosureMask)
{
    std::vector<unsigned char> out;
    out.push_back((unsigned char)iv5::PROTOCOL_SCHEMA);
    out.push_back(0);
    out.push_back(nOperation);
    out.push_back(nProfile);
    out.push_back(nAuthorization);
    out.push_back(nDisclosureMask);
    out.push_back(nFinalityObject);
    out.push_back(LocalNetwork());
    out.push_back(0);
    return out;
}

int32_t ValidationResult(const std::vector<unsigned char>& payload)
{
    return ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                       payload).nResult;
}

// The result codes the ABI contract names, used here because two refusals a case apart
// are the difference between a rule holding and a later check standing in for it.
const int32_t kValid            = 0;
const int32_t kConsensusInvalid = 1;
const int32_t kUnsupported      = 3;

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
    CPrivacyVNextNullifierSpent spent;
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
    CPrivacyVNextNullifierSpent spent;
    spent.txnHash = uint256(1);
    spent.nIndex = 0;
    spent.nHeight = 900;
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
    CPrivacyVNextNullifierSpent spent;
    spent.txnHash = uint256(7);
    spent.nIndex = 0;
    spent.nHeight = 900;
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
    // Same note, same key image. Deregistration depends on this (the attestation row
    // is read from the spent-key index); it also links the closing spend to the
    // collateralnode. Neither side of this equality may change alone.
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
    CPrivacyVNextNullifierSpent spent;
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

    // The unset case, which regtest still reaches and which the public
    // networks saw before the note fork was scheduled.
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
    CPrivacyVNextNullifierSpent spent;
    spent.txnHash = uint256(31);
    spent.nIndex = 0;
    spent.nHeight = 900;
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


// An attestation moves no value: no leaf, no transparent side, no fee, pinned by the
// shape check before proofs run. Proofs are honest, so refusals are the shape check.
BOOST_AUTO_TEST_CASE(an_attestation_moves_no_value_and_takes_no_fee)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xb1, kTier, note, error), error);

    // The digest the chain answers with, taken from a payload the shipping builder made.
    std::vector<unsigned char> reference;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), CollateralDigest(0xe1), note.spend, reference,
            keyImage, error),
        error);
    BOOST_REQUIRE_GT(reference.size(), kParameterDigestOffset + 32);
    PrivacyVNextDigest parameterDigest;
    std::memcpy(parameterDigest.data(), &reference[kParameterDigestOffset], 32);

    // Positive control: the same assembly at the shape the rule requires validates. A
    // refusal below is therefore about the field that changed and nothing else.
    std::vector<unsigned char> conforming;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedAttestation(note, parameterDigest, iv5::DISCLOSURE_MASK, 0, 0,
                               conforming, error),
        error);
    BOOST_REQUIRE_EQUAL(ValidationResult(conforming), kValid);
    PrivacyVNextStateEffects effects;
    BOOST_REQUIRE(ExtractPrivacyVNextPayloadEffects(
                      INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, conforming, effects)
                      .IsValid());
    BOOST_CHECK_EQUAL(effects.attestationKeyImages.size(), 1U);
    BOOST_CHECK_EQUAL(effects.nTransparentValueBalance, 0);
    BOOST_CHECK_EQUAL(effects.nFee, 0U);

    // Value out of the pool, proved as carefully as the conforming payload was.
    std::vector<unsigned char> spending;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedAttestation(note, parameterDigest, iv5::DISCLOSURE_MASK, -1, 0,
                               spending, error),
        error);
    BOOST_CHECK_EQUAL(ValidationResult(spending), kConsensusInvalid);

    // And value into it, which would credit the pool against no note at all.
    std::vector<unsigned char> crediting;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedAttestation(note, parameterDigest, iv5::DISCLOSURE_MASK, 1, 0,
                               crediting, error),
        error);
    BOOST_CHECK_EQUAL(ValidationResult(crediting), kConsensusInvalid);

    // A fee is value the block producer collects, and the attestation spends nothing to
    // cover it.
    std::vector<unsigned char> charging;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedAttestation(note, parameterDigest, iv5::DISCLOSURE_MASK, 0, 1,
                               charging, error),
        error);
    BOOST_CHECK_EQUAL(ValidationResult(charging), kConsensusInvalid);

    // The three refused payloads differ from the accepted one in one field each: same
    // length, same proofs, one number apart.
    BOOST_CHECK_EQUAL(spending.size(), conforming.size());
    BOOST_CHECK_EQUAL(crediting.size(), conforming.size());
    BOOST_CHECK_EQUAL(charging.size(), conforming.size());
}

// Mask 7 (fully private) is the only mask a registration operation may carry;
// disclosing the sender would link the pseudonym to its collateral note. Enforced by
// the 2008 envelope table (proved here) and the attestation shape check.
BOOST_AUTO_TEST_CASE(an_attestation_carries_only_the_private_mask)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xb2, kTier, note, error), error);
    std::vector<unsigned char> reference;
    PrivacyVNextDigest keyImage;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextCollateralAttestationPayload(
            LocalNetwork(), LocalGenesis(), note.finalizedRoot, note.nTreeSize,
            NoTransparentSide(), CollateralDigest(0xe1), note.spend, reference,
            keyImage, error),
        error);
    PrivacyVNextDigest parameterDigest;
    std::memcpy(parameterDigest.data(), &reference[kParameterDigestOffset], 32);

    // Masks 0 (all disclosed), 6 (sender disclosed) and 7 (control); the full sweep is
    // in privacy_vnext_abi_tests.
    const uint8_t vMasks[3] = {0, 6, iv5::DISCLOSURE_MASK};
    for (size_t i = 0; i < 3; ++i)
    {
        std::vector<unsigned char> payload;
        BOOST_REQUIRE_MESSAGE(
            BuildShapedAttestation(note, parameterDigest, vMasks[i], 0, 0, payload, error),
            error);
        BOOST_CHECK_MESSAGE(
            ValidationResult(payload) ==
                (vMasks[i] == iv5::DISCLOSURE_MASK ? kValid : kConsensusInvalid),
            strprintf("attestation at mask %u answered %d", (unsigned)vMasks[i],
                      (int)ValidationResult(payload)));
    }

    // Both registration operations are bound by it, on the table both decoders share.
    for (uint8_t nMask = 0; nMask < iv5::DISCLOSURE_MASK; ++nMask)
    {
        BOOST_CHECK(!iv5::EnvelopeAllows(2008, iv5::NOTE_COLLATERAL_REGISTER, 0,
                                         iv5::AUTH_OWNER, iv5::FINALITY_OBJECT_NONE,
                                         nMask));
        BOOST_CHECK(!iv5::EnvelopeAllows(2008, iv5::NOTE_FINALITY_MEMBER_REGISTER, 0,
                                         iv5::AUTH_OWNER, iv5::FINALITY_OBJECT_NONE,
                                         nMask));
    }
}

// A v2008 payload declaring a finality object or an unbuilt operation is refused
// "unsupported format" before any field is read. Matched on the code, since each
// nine-byte payload would also fail parsing.
BOOST_AUTO_TEST_CASE(a_v2008_payload_acts_on_no_finality_object_and_no_unbuilt_operation)
{
    // The envelope table admits these tuples, so the fail-closed branch is the only thing
    // standing between them and a parser that would read their fields.
    BOOST_REQUIRE(iv5::EnvelopeAllows(2008, iv5::NOTE_OPERATION_NONE,
                                      iv5::FINALITY_NULLSTAKE_V1, iv5::AUTH_OWNER,
                                      iv5::FINALITY_OBJECT_VOTE, iv5::DISCLOSURE_MASK));
    BOOST_REQUIRE(iv5::EnvelopeAllows(2008, iv5::NOTE_DELEGATION_CREATE,
                                      iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                                      iv5::FINALITY_OBJECT_NONE, iv5::DISCLOSURE_MASK));

    // A finality object, at every profile and object the table admits with it.
    for (uint8_t nProfile = iv5::FINALITY_NULLSTAKE_V1;
         nProfile <= iv5::FINALITY_NULLSTAKE_V3; ++nProfile)
    for (uint8_t nObject = iv5::FINALITY_OBJECT_VOTE;
         nObject <= iv5::FINALITY_OBJECT_COMMITTEE_ROTATION; ++nObject)
    {
        const std::vector<unsigned char> payload =
            EnvelopeOnly(iv5::NOTE_OPERATION_NONE, nProfile, iv5::AUTH_OWNER, nObject,
                         iv5::DISCLOSURE_MASK);
        BOOST_CHECK_MESSAGE(
            ValidationResult(payload) == kUnsupported,
            strprintf("finality profile %u object %u answered %d", (unsigned)nProfile,
                      (unsigned)nObject, (int)ValidationResult(payload)));
    }

    // And the operations the envelope admits that no v2008 verifier was written for.
    const uint8_t vUnbuilt[4] = {iv5::NOTE_NULLSEND, iv5::NOTE_DELEGATION_CREATE,
                                 iv5::NOTE_M_OF_N_MINT, iv5::NOTE_RECLAIM};
    for (size_t i = 0; i < 4; ++i)
    {
        const std::vector<unsigned char> payload =
            EnvelopeOnly(vUnbuilt[i], iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                         iv5::FINALITY_OBJECT_NONE, iv5::DISCLOSURE_MASK);
        BOOST_CHECK_MESSAGE(
            ValidationResult(payload) == kUnsupported,
            strprintf("operation %u answered %d", (unsigned)vUnbuilt[i],
                      (int)ValidationResult(payload)));
    }

    // The control. The five operations a v2008 payload may act on get past the branch and
    // are refused for running out of bytes, which is the ordinary refusal.
    const uint8_t vBuilt[5] = {iv5::NOTE_SHIELD, iv5::NOTE_UNSHIELD, iv5::NOTE_TRANSFER,
                               iv5::NOTE_COLLATERAL_REGISTER,
                               iv5::NOTE_FINALITY_MEMBER_REGISTER};
    for (size_t i = 0; i < 5; ++i)
    {
        const std::vector<unsigned char> payload =
            EnvelopeOnly(vBuilt[i], iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                         iv5::FINALITY_OBJECT_NONE, iv5::DISCLOSURE_MASK);
        BOOST_CHECK_MESSAGE(
            ValidationResult(payload) == kConsensusInvalid,
            strprintf("operation %u answered %d", (unsigned)vBuilt[i],
                      (int)ValidationResult(payload)));
    }

    // Owner is the only authorization mode a v2008 payload may declare, and the envelope
    // refuses the rest with the consensus code rather than the fail-closed one.
    const uint8_t vModes[3] = {iv5::AUTH_COLD_STAKER, iv5::AUTH_M_OF_N_PUBLIC_SIGNERS,
                               iv5::AUTH_M_OF_N_HIDDEN_SIGNERS};
    for (size_t i = 0; i < 3; ++i)
    {
        const std::vector<unsigned char> payload =
            EnvelopeOnly(iv5::NOTE_TRANSFER, iv5::FINALITY_NONE, vModes[i],
                         iv5::FINALITY_OBJECT_NONE, iv5::DISCLOSURE_MASK);
        BOOST_CHECK_MESSAGE(
            ValidationResult(payload) == kConsensusInvalid,
            strprintf("authorization %u answered %d", (unsigned)vModes[i],
                      (int)ValidationResult(payload)));
    }
}


// ---- The note finality vote (operation 10) ----

// A vote spends its note and reissues the value: transfer effects, with the spent-key index
// making the vote unrepeatable. Nothing crosses the boundary or is registered.
BOOST_AUTO_TEST_CASE(a_note_vote_spends_its_note_and_reissues_it_whole)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xc1, kVoteNote, note, error), error);

    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    PrivacyVNextOutputLeaf reissue;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedNoteVote(note, ContractDigest(), kVoteNote, 0, 0,
                            CollateralDigest(0x7e), 1200, payload, keyImage, reissue,
                            error),
        error);

    uint8_t nOperation = 0;
    uint8_t nMask = 0;
    BOOST_REQUIRE(iv5::ReadDeclaredEnvelope(&payload[0], payload.size(), nOperation,
                                            nMask));
    BOOST_CHECK_EQUAL((int)nOperation, (int)iv5::NOTE_FINALITY_VOTE);
    BOOST_CHECK_EQUAL((int)nMask, (int)iv5::DISCLOSURE_MASK);

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation extracted =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects);
    BOOST_REQUIRE_MESSAGE(extracted.IsValid(), extracted.strError);

    // Routed as a spend, never as an attestation.
    BOOST_REQUIRE_EQUAL(effects.keyImages.size(), 1U);
    BOOST_CHECK(effects.keyImages[0] == keyImage);
    BOOST_CHECK_EQUAL(effects.attestationKeyImages.size(), 0U);
    // The reissue is the one leaf, exactly as encrypted.
    BOOST_REQUIRE_EQUAL(effects.outputLeaves.size(), 1U);
    BOOST_CHECK(effects.outputLeaves[0].owner == reissue.owner);
    BOOST_CHECK(effects.outputLeaves[0].nullifierBase == reissue.nullifierBase);
    BOOST_CHECK(effects.outputLeaves[0].commitment == reissue.commitment);
    // Nothing crosses the boundary and nothing is registered.
    BOOST_CHECK_EQUAL(effects.nTransparentValueBalance, 0);
    BOOST_CHECK_EQUAL(effects.nFee, 0U);
    BOOST_CHECK_EQUAL(effects.PoolDelta(), 0);
    PrivacyVNextDigest zero;
    zero.fill(0);
    BOOST_CHECK(effects.registrationContext == zero);
    BOOST_CHECK(!effects.HasMemberKey());
}

// The decoder pins a vote's fee to zero, so IsPrivacyVNextFeeExemptShape must exempt
// the vote shape like an attestation.
BOOST_AUTO_TEST_CASE(a_note_vote_is_fee_exempt_like_an_attestation)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xc2, kVoteNote, note, error), error);

    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    PrivacyVNextOutputLeaf reissue;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedNoteVote(note, ContractDigest(), kVoteNote, 0, 0,
                            CollateralDigest(0x7e), 1200, payload, keyImage, reissue,
                            error),
        error);
    BOOST_REQUIRE_EQUAL(ValidationResult(payload), kValid);

    const CTransaction tx = CarryingTx(payload, 1500000002);
    BOOST_CHECK(IsPrivacyVNextFeeExemptShape(tx));
    // Still not an attestation: the key image is a spend, never a watch-set entry.
    BOOST_CHECK(!iv5::IsAttestationOperation(iv5::NOTE_FINALITY_VOTE));
    // The exemption is for the bare carrier only; a transparent side prices as usual.
    CTransaction withInput = tx;
    withInput.vin.push_back(CTxIn(COutPoint(uint256(1), 0)));
    BOOST_CHECK(!IsPrivacyVNextFeeExemptShape(withInput));
}

// Refusals are the vote shape rule. The reward amount is chain-dependent and pinned in
// note_vote_reward_tests; here only its direction: a vote never drains the pool.
BOOST_AUTO_TEST_CASE(a_note_vote_takes_no_fee_and_never_drains_the_pool)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xc3, kVoteNote, note, error), error);
    const PrivacyVNextDigest digest = ContractDigest();
    const PrivacyVNextDigest boundary = CollateralDigest(0x7e);
    PrivacyVNextDigest keyImage;
    PrivacyVNextOutputLeaf reissue;

    // Positive control: the shape the rule requires validates.
    std::vector<unsigned char> conforming;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedNoteVote(note, digest, kVoteNote, 0, 0, boundary, 1200, conforming,
                            keyImage, reissue, error),
        error);
    BOOST_CHECK_EQUAL(ValidationResult(conforming), kValid);

    // A fee: the reissue is one atom short and the difference is declared as fee.
    std::vector<unsigned char> paying;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedNoteVote(note, digest, kVoteNote - 1, 0, 1, boundary, 1200, paying,
                            keyImage, reissue, error),
        error);
    BOOST_CHECK_EQUAL(ValidationResult(paying), kConsensusInvalid);

    // The reward: one atom enters through the reissue. Well-formed here by construction;
    // whether the epoch owes that atom is the caller's equality, not this decoder's.
    std::vector<unsigned char> rewarded;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedNoteVote(note, digest, kVoteNote + 1, 1, 0, boundary, 1200, rewarded,
                            keyImage, reissue, error),
        error);
    BOOST_CHECK_EQUAL(ValidationResult(rewarded), kValid);
    // And the caller sees the declared figure, which is what it holds against the epoch.
    PrivacyVNextStateEffects rewardedEffects;
    const PrivacyVNextPayloadValidation rewardedRead =
        ExtractPrivacyVNextPayloadEffects(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                          rewarded, rewardedEffects);
    BOOST_REQUIRE_MESSAGE(rewardedRead.IsValid(), rewardedRead.strError);
    BOOST_CHECK_EQUAL(rewardedEffects.nTransparentValueBalance, 1);

    // A leak: one atom leaves.
    std::vector<unsigned char> leaking;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedNoteVote(note, digest, kVoteNote - 1, -1, 0, boundary, 1200, leaking,
                            keyImage, reissue, error),
        error);
    BOOST_CHECK_EQUAL(ValidationResult(leaking), kConsensusInvalid);
}

// The boundary a vote names and the operation byte it carries are both inside the signing
// hash, so neither can be changed after proving: a vote cannot be moved to another epoch
// and a transfer's proofs cannot be repackaged as a vote.
BOOST_AUTO_TEST_CASE(a_note_vote_binds_its_boundary_and_its_operation)
{
    CTxDB txdb("r+");
    std::string error;

    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xc4, kVoteNote, note, error), error);
    const PrivacyVNextDigest boundary = CollateralDigest(0x7e);

    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    PrivacyVNextOutputLeaf reissue;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedNoteVote(note, ContractDigest(), kVoteNote, 0, 0, boundary, 1200,
                            payload, keyImage, reissue, error),
        error);
    BOOST_REQUIRE_EQUAL(ValidationResult(payload), kValid);

    const size_t nBoundaryAt = BoundaryOffset(payload, boundary);
    std::vector<unsigned char> otherBlock = payload;
    otherBlock[nBoundaryAt] ^= 0x01;
    BOOST_CHECK_EQUAL(ValidationResult(otherBlock), kConsensusInvalid);

    std::vector<unsigned char> otherHeight = payload;
    otherHeight[nBoundaryAt + 32] ^= 0x01;
    BOOST_CHECK_EQUAL(ValidationResult(otherHeight), kConsensusInvalid);

    std::vector<unsigned char> relabeled = payload;
    relabeled[2] = iv5::NOTE_TRANSFER;
    BOOST_CHECK_NE(ValidationResult(relabeled), kValid);
}

BOOST_AUTO_TEST_SUITE_END()
