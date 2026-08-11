// Copyright (c) 2026 The Innova developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "privacy_vnext_builder.h"

#include <cstring>
#include <limits>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "ed25519_zk.h"
#include "privacy_vnext/iv5_protocol.h"
#include "privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "util.h"

namespace
{

// Aliases of the protocol enum, never independent numbers: a builder that names its own
// operation codes is a second decoder table nothing cross-checks.
const uint8_t VNEXT_OPERATION_SHIELD = iv5::NOTE_SHIELD;
const uint8_t VNEXT_OPERATION_UNSHIELD = iv5::NOTE_UNSHIELD;
const uint8_t VNEXT_OPERATION_TRANSFER = iv5::NOTE_TRANSFER;

void PutCompactSize(std::vector<unsigned char>& out, uint64_t nSize)
{
    if (nSize < 253)
    {
        out.push_back(static_cast<unsigned char>(nSize));
    }
    else if (nSize <= 0xffff)
    {
        out.push_back(253);
        out.push_back(static_cast<unsigned char>(nSize));
        out.push_back(static_cast<unsigned char>(nSize >> 8));
    }
    else
    {
        out.push_back(254);
        for (size_t i = 0; i < 4; ++i)
            out.push_back(static_cast<unsigned char>(nSize >> (8 * i)));
    }
}

void PutBytes(std::vector<unsigned char>& out, const PrivacyVNextDigest& d)
{
    out.insert(out.end(), d.begin(), d.end());
}

void PutU64(std::vector<unsigned char>& out, uint64_t v)
{
    for (size_t i = 0; i < 8; ++i)
        out.push_back(static_cast<unsigned char>(v >> (8 * i)));
}

void PutI64(std::vector<unsigned char>& out, int64_t v)
{
    PutU64(out, static_cast<uint64_t>(v));
}

void PutVector(std::vector<unsigned char>& out,
               const std::vector<unsigned char>& v)
{
    PutCompactSize(out, v.size());
    out.insert(out.end(), v.begin(), v.end());
}

// A uniformly random canonical scalar.
bool RandomScalar(PrivacyVNextDigest& out, std::string& strErrorOut)
{
    std::vector<unsigned char> wide(64, 0);
    // Every IV5 secret is drawn here -- prover entropy, ephemerals, output y and
    // the output masks. A failed draw leaves the buffer zeroed, and a zero mask is
    // not rejected anywhere downstream, so it has to fail here.
    if (RAND_bytes(&wide[0], 64) != 1)
    {
        OPENSSL_cleanse(&wide[0], wide.size());
        strErrorOut = "the system random source failed while drawing an IV5 scalar";
        return false;
    }
    std::vector<unsigned char> reduced;
    if (!Ed25519ScalarReduce(wide, reduced) || reduced.size() != 32)
    {
        OPENSSL_cleanse(&wide[0], wide.size());
        strErrorOut = "could not draw a canonical IV5 scalar";
        return false;
    }
    std::memcpy(out.data(), &reduced[0], 32);
    OPENSSL_cleanse(&wide[0], wide.size());
    OPENSSL_cleanse(&reduced[0], reduced.size());
    return true;
}

std::vector<unsigned char> AsVector(const PrivacyVNextDigest& d)
{
    return std::vector<unsigned char>(d.begin(), d.end());
}

// Openings a receiver disclosure needs after encryption, wiped on every exit path.
struct RetainedScalars
{
    std::vector<PrivacyVNextDigest> v;

    ~RetainedScalars()
    {
        for (size_t i = 0; i < v.size(); ++i)
            OPENSSL_cleanse(v[i].data(), v[i].size());
    }
};

// The draft pass's proof is never serialized, so nothing else wipes it.
struct RetainedBytes
{
    std::vector<unsigned char> v;

    ~RetainedBytes()
    {
        if (!v.empty())
            OPENSSL_cleanse(&v[0], v.size());
    }
};

} // namespace

void PrivacyVNextSpendNote::Clear()
{
    OPENSSL_cleanse(spendSecret.data(), spendSecret.size());
    OPENSSL_cleanse(y.data(), y.size());
    OPENSSL_cleanse(mask.data(), mask.size());
    if (!vchWitnessRecord.empty())
        OPENSSL_cleanse(&vchWitnessRecord[0], vchWitnessRecord.size());
    vchWitnessRecord.clear();
    nAmount = 0;
}

// One path for every payload shape.
//
// A shield is simply the case with no notes spent: it takes its value from the transparent
// side instead, so it names no pseudo-outputs and needs no membership proof. Keeping both in
// one function is what stops the two drifting apart in how they serialize or balance.
static bool BuildPrivacyVNextPayload(
    uint8_t nNetwork,
    uint8_t nOperation,
    uint8_t nDisclosureMask,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    int64_t nTransparentValueBalance,
    uint64_t nFee,
    const std::vector<PrivacyVNextSpendNote>& spends,
    const std::vector<PrivacyVNextNewOutput>& outputs,
    std::vector<unsigned char>& vchPayloadOut,
    std::string& strErrorOut)
{
    vchPayloadOut.clear();
    strErrorOut.clear();

    if (nDisclosureMask > iv5::DISCLOSURE_MASK)
    {
        strErrorOut = "an IV5 disclosure mask is three bits";
        return false;
    }
    // A clear bit puts the field on the wire; a set bit keeps it hidden.
    const bool fDiscloseSender =
        (nDisclosureMask & iv5::DISCLOSURE_HIDE_SENDER) == 0;
    const bool fDiscloseReceiver =
        (nDisclosureMask & iv5::DISCLOSURE_HIDE_RECEIVER) == 0;
    const bool fDiscloseAmount =
        (nDisclosureMask & iv5::DISCLOSURE_HIDE_AMOUNT) == 0;

    if (spends.size() > INNOVA_PRIVACY_VNEXT_MAX_INPUTS)
    {
        strErrorOut = "an IV5 payload takes at most sixteen inputs";
        return false;
    }
    if (outputs.empty() || outputs.size() > INNOVA_PRIVACY_VNEXT_MAX_OUTPUTS)
    {
        strErrorOut = "an IV5 transfer needs between one and sixteen outputs";
        return false;
    }

    // Inputs plus any transparent value entering the pool must cover the outputs and the
    // fee exactly, or the value proof cannot balance.
    uint64_t nIn = nTransparentValueBalance > 0
                       ? (uint64_t)nTransparentValueBalance : 0;
    for (size_t i = 0; i < spends.size(); ++i)
    {
        if (spends[i].nAmount > std::numeric_limits<uint64_t>::max() - nIn)
        {
            strErrorOut = "IV5 input amounts overflow";
            return false;
        }
        nIn += spends[i].nAmount;
        if (spends[i].vchWitnessRecord.empty())
        {
            strErrorOut = "an IV5 input is missing its membership witness";
            return false;
        }
    }
    uint64_t nOut = nFee;
    for (size_t i = 0; i < outputs.size(); ++i)
    {
        if (outputs[i].nAmount > std::numeric_limits<uint64_t>::max() - nOut)
        {
            strErrorOut = "IV5 output amounts overflow";
            return false;
        }
        nOut += outputs[i].nAmount;
    }
    // Value leaving the pool is spent by the payload just as a new note is: it is
    // covered by the inputs and settled on the transparent side.
    if (nTransparentValueBalance < 0)
    {
        const uint64_t nLeaving = (uint64_t)(-(nTransparentValueBalance + 1)) + 1;
        if (nLeaving > std::numeric_limits<uint64_t>::max() - nOut)
        {
            strErrorOut = "IV5 unshield amount overflows";
            return false;
        }
        nOut += nLeaving;
    }
    if (nIn != nOut)
    {
        strErrorOut = strprintf(
            "IV5 payload does not balance: %" PRIu64 " in against %" PRIu64 " out",
            nIn, nOut);
        return false;
    }

    PrivacyVNextEpochSeed seed;
    if (!LoadPrivacyVNextEpochSeed(seed, strErrorOut))
        return false;
    if (seed.vchParameterDigest.size() != 32)
    {
        strErrorOut = "IV5 parameter digest is unavailable";
        return false;
    }
    PrivacyVNextDigest parameterDigest;
    std::memcpy(parameterDigest.data(), &seed.vchParameterDigest[0], 32);

    PrivacyVNextDigest entropy;
    if (!RandomScalar(entropy, strErrorOut))
        return false;

    // Encrypt every output. Openings survive the loop for the receiver disclosure and
    // are wiped when the builder returns.
    std::vector<PrivacyVNextEncryptedOutput> vEncrypted(outputs.size());
    std::vector<PrivacyVNextDigest> vOutputMasks(outputs.size());
    RetainedScalars tweakEphemeralSecrets;
    RetainedScalars outputYs;
    if (fDiscloseReceiver)
    {
        tweakEphemeralSecrets.v.resize(outputs.size());
        outputYs.v.resize(outputs.size());
    }
    for (size_t i = 0; i < outputs.size(); ++i)
    {
        // Two independent ephemerals per output. A receiver disclosure opens the tweak
        // one's shared point on chain, so the note is keyed under the other.
        PrivacyVNextDigest noteEphemeralSecret;
        PrivacyVNextDigest tweakEphemeralSecret;
        PrivacyVNextDigest outY;
        if (!RandomScalar(noteEphemeralSecret, strErrorOut) ||
            !RandomScalar(tweakEphemeralSecret, strErrorOut) ||
            !RandomScalar(outY, strErrorOut) ||
            !RandomScalar(vOutputMasks[i], strErrorOut))
            return false;
        const bool fEncrypted = EncryptPrivacyVNextNote(
            nNetwork, outputs[i].recipient.nAddressType,
            static_cast<uint32_t>(i), genesis,
            outputs[i].recipient.spendPublic, outputs[i].recipient.viewPublic,
            outgoingViewSecret, noteEphemeralSecret, tweakEphemeralSecret,
            outputs[i].nAmount, outY, vOutputMasks[i], vEncrypted[i],
            strErrorOut);
        if (fEncrypted && fDiscloseReceiver)
        {
            tweakEphemeralSecrets.v[i] = tweakEphemeralSecret;
            outputYs.v[i] = outY;
        }
        OPENSSL_cleanse(noteEphemeralSecret.data(), noteEphemeralSecret.size());
        OPENSSL_cleanse(tweakEphemeralSecret.data(), tweakEphemeralSecret.size());
        OPENSSL_cleanse(outY.data(), outY.size());
        if (!fEncrypted)
            return false;
    }

    std::vector<PrivacyVNextSpendInput> vProveInputs(spends.size());
    for (size_t i = 0; i < spends.size(); ++i)
    {
        vProveInputs[i].spendScalar = spends[i].spendSecret;
        vProveInputs[i].commitmentScalar = spends[i].y;
        vProveInputs[i].leaf = spends[i].leaf;
        vProveInputs[i].vchWitnessRecord = spends[i].vchWitnessRecord;
    }

    // The prefix the proofs bind to already names each input's pseudo-output, but those
    // only exist once the prover has run. Rerandomization is deterministic in the caller's
    // entropy and independent of the signing hash, so the prover is run twice with the same
    // entropy: once to learn the pseudo-outputs and key images, and again to prove against
    // the hash they produce. Proof nonces are drawn from a hash-dependent stream, so the
    // two passes share none of them.
    PrivacyVNextDigest provisional;
    provisional.fill(0);
    provisional[0] = 1;
    std::vector<PrivacyVNextSpendConstruction> vDraft;
    RetainedBytes draftProof;
    if (!vProveInputs.empty() &&
        !ProvePrivacyVNextMembership(finalizedRoot, provisional, entropy,
                                     vProveInputs, vDraft, draftProof.v,
                                     strErrorOut))
        return false;

    std::vector<unsigned char> prefix;
    prefix.push_back(static_cast<unsigned char>(iv5::PROTOCOL_SCHEMA));
    prefix.push_back(0);
    prefix.push_back(nOperation);
    prefix.push_back(0);                         // finality profile: none
    prefix.push_back(0);                         // authorization: owner
    prefix.push_back(nDisclosureMask);
    prefix.push_back(0);                         // finality object: none
    prefix.push_back(nNetwork);
    prefix.push_back(0);                         // reserved
    PutBytes(prefix, genesis);
    PutBytes(prefix, parameterDigest);
    PutBytes(prefix, finalizedRoot);
    PutU64(prefix, nFinalizedTreeSize);
    PutI64(prefix, nTransparentValueBalance);
    PutU64(prefix, nFee);
    // Before the proofs, so the signing hash covers it and no assembler can restate the
    // transparent side of a payload that already verified.
    PutBytes(prefix, transparentBinding);

    PutCompactSize(prefix, vDraft.size());
    for (size_t i = 0; i < vDraft.size(); ++i)
    {
        PutBytes(prefix, vDraft[i].pseudoOut);
        PutBytes(prefix, vDraft[i].keyImage);
    }
    PutCompactSize(prefix, vEncrypted.size());
    for (size_t i = 0; i < vEncrypted.size(); ++i)
    {
        // I is absent by design: validators derive it from this output's own owner key.
        PutBytes(prefix, vEncrypted[i].leaf.owner);
        PutBytes(prefix, vEncrypted[i].leaf.commitment);
        PutBytes(prefix, vEncrypted[i].noteEphemeral);
        PutBytes(prefix, vEncrypted[i].tweakEphemeral);
        PutVector(prefix, vEncrypted[i].vchRecipientCiphertext);
        PutVector(prefix, vEncrypted[i].vchOutgoingCiphertext);
    }
    // Disclosed records, in the order the decoder reads them: senders per input, then
    // receivers per output, then amounts per output. They sit inside the signing hash, so
    // a payload cannot be re-disclosed after its proofs are made.
    if (fDiscloseSender)
    {
        for (size_t i = 0; i < vDraft.size(); ++i)
            PutBytes(prefix, vDraft[i].senderAuthority);
    }
    if (fDiscloseReceiver)
    {
        for (size_t i = 0; i < outputs.size(); ++i)
        {
            PutBytes(prefix, outputs[i].recipient.spendPublic);
            PutBytes(prefix, outputs[i].recipient.viewPublic);
        }
    }
    if (fDiscloseAmount)
    {
        // The disclosed amount is the same value the commitment was made over, so the
        // builder has no way to publish one figure and commit to another.
        for (size_t i = 0; i < outputs.size(); ++i)
        {
            PutU64(prefix, outputs[i].nAmount);
            PutBytes(prefix, vOutputMasks[i]);
        }
    }
    PutVector(prefix, std::vector<unsigned char>());   // empty finality body

    PrivacyVNextDigest signingHash;
    if (!HashPrivacyVNextPayloadPrefix(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                       prefix, signingHash, strErrorOut))
        return false;

    std::vector<PrivacyVNextSpendConstruction> vFinal;
    std::vector<unsigned char> vchMembership;
    if (!vProveInputs.empty() &&
        !ProvePrivacyVNextMembership(finalizedRoot, signingHash, entropy,
                                     vProveInputs, vFinal, vchMembership,
                                     strErrorOut))
        return false;
    // Determinism in the entropy is what makes the two passes agree. If it ever failed to
    // hold, the prefix would name pseudo-outputs the proof does not open.
    if (vFinal.size() != vDraft.size())
    {
        strErrorOut = "IV5 proving passes disagree on input count";
        return false;
    }
    for (size_t i = 0; i < vFinal.size(); ++i)
    {
        // The authority is named in the prefix from the draft pass but proved in the
        // final one, so the two passes must agree on it as well.
        if (vFinal[i].pseudoOut != vDraft[i].pseudoOut ||
            vFinal[i].keyImage != vDraft[i].keyImage ||
            vFinal[i].senderAuthority != vDraft[i].senderAuthority)
        {
            strErrorOut = "IV5 proving is not deterministic in its entropy";
            return false;
        }
    }

    // The value proof balances the rerandomized inputs against the outputs, so the excess
    // is the input masks plus their rerandomization deltas, less the output masks.
    std::vector<unsigned char> excess(32, 0);
    for (size_t i = 0; i < spends.size(); ++i)
    {
        std::vector<unsigned char> sum;
        if (!Ed25519ScalarAdd(excess, AsVector(spends[i].mask), sum) ||
            !Ed25519ScalarAdd(sum, AsVector(vFinal[i].pseudoOutMaskDelta), excess))
        {
            strErrorOut = "IV5 excess mask accumulation failed";
            return false;
        }
    }
    for (size_t i = 0; i < vOutputMasks.size(); ++i)
    {
        std::vector<unsigned char> negated;
        std::vector<unsigned char> sum;
        if (!Ed25519ScalarNeg(AsVector(vOutputMasks[i]), negated) ||
            !Ed25519ScalarAdd(excess, negated, sum))
        {
            strErrorOut = "IV5 excess mask accumulation failed";
            return false;
        }
        excess = sum;
    }
    PrivacyVNextDigest excessMask;
    if (excess.size() != 32)
    {
        strErrorOut = "IV5 excess mask is not a canonical scalar";
        return false;
    }
    std::memcpy(excessMask.data(), &excess[0], 32);

    std::vector<PrivacyVNextDigest> vPseudoOuts(vFinal.size());
    for (size_t i = 0; i < vFinal.size(); ++i)
        vPseudoOuts[i] = vFinal[i].pseudoOut;
    std::vector<PrivacyVNextValueOutput> vValueOutputs(outputs.size());
    for (size_t i = 0; i < outputs.size(); ++i)
    {
        vValueOutputs[i].nAmount = outputs[i].nAmount;
        vValueOutputs[i].mask = vOutputMasks[i];
    }

    PrivacyVNextDigest valueEntropy;
    if (!RandomScalar(valueEntropy, strErrorOut))
        return false;
    PrivacyVNextValueProof valueProof;
    // The balance the proof signs must be the one the prefix declares, or the payload names
    // a transparent movement its own proof does not cover.
    if (!ProvePrivacyVNextValue(vPseudoOuts, vValueOutputs,
                                nTransparentValueBalance, nFee, signingHash,
                                valueEntropy, excessMask, valueProof,
                                strErrorOut))
        return false;

    // The commitments the value proof produced must be the ones the outputs already
    // carry, or the payload would name two different sets.
    if (valueProof.vOutputCommitments.size() != vEncrypted.size())
    {
        strErrorOut = "IV5 value proof returned the wrong commitment count";
        return false;
    }
    for (size_t i = 0; i < vEncrypted.size(); ++i)
    {
        if (valueProof.vOutputCommitments[i] != vEncrypted[i].leaf.commitment)
        {
            strErrorOut = "IV5 value proof commitments do not match the encrypted outputs";
            return false;
        }
    }

    // Sender proofs in input order, then receiver proofs in output order.
    std::vector<unsigned char> vchDisclosureProofs;
    if (fDiscloseSender)
    {
        for (size_t i = 0; i < vFinal.size(); ++i)
        {
            if (vFinal[i].vchSenderDisclosureProof.size() !=
                INNOVA_PRIVACY_VNEXT_SENDER_DISCLOSURE_PROOF_SIZE)
            {
                strErrorOut = "IV5 sender disclosure proof has the wrong size";
                return false;
            }
            vchDisclosureProofs.insert(
                vchDisclosureProofs.end(),
                vFinal[i].vchSenderDisclosureProof.begin(),
                vFinal[i].vchSenderDisclosureProof.end());
        }
    }
    if (fDiscloseReceiver)
    {
        for (size_t i = 0; i < outputs.size(); ++i)
        {
            PrivacyVNextDigest receiverEntropy;
            if (!RandomScalar(receiverEntropy, strErrorOut))
                return false;
            std::vector<unsigned char> vchReceiverProof;
            const bool fProved = ProvePrivacyVNextReceiverDisclosure(
                static_cast<uint32_t>(i), outputs[i].recipient.spendPublic,
                outputs[i].recipient.viewPublic, vEncrypted[i].leaf.owner,
                vEncrypted[i].tweakEphemeral, tweakEphemeralSecrets.v[i],
                outputYs.v[i], signingHash, receiverEntropy, vchReceiverProof,
                strErrorOut);
            OPENSSL_cleanse(receiverEntropy.data(), receiverEntropy.size());
            if (!fProved)
                return false;
            vchDisclosureProofs.insert(vchDisclosureProofs.end(),
                                       vchReceiverProof.begin(),
                                       vchReceiverProof.end());
        }
    }

    std::vector<unsigned char> payload = prefix;
    PutVector(payload, vchMembership);
    // A disclosed amount is checked against its own commitment instead, so the range proof
    // is left out. It is still constructed above, because the value proof produces the
    // output commitments alongside it.
    PutVector(payload, fDiscloseAmount ? std::vector<unsigned char>()
                                       : valueProof.vchRangeProof);
    PutVector(payload, std::vector<unsigned char>(
                           valueProof.balanceProof.begin(),
                           valueProof.balanceProof.end()));
    PutVector(payload, std::vector<unsigned char>());   // operation proof: none
    PutVector(payload, vchDisclosureProofs);

    // Run the decoder consensus uses before handing the payload back, so a payload that
    // would be rejected never leaves the builder.
    const PrivacyVNextPayloadValidation validation =
        ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                    payload);
    if (!validation.IsValid())
    {
        strErrorOut = "the built IV5 payload does not validate: " +
                      validation.strError;
        return false;
    }

    vchPayloadOut.swap(payload);
    return true;
}

bool BuildPrivacyVNextTransferPayload(
    uint8_t nNetwork,
    uint8_t nDisclosureMask,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    uint64_t nFee,
    const std::vector<PrivacyVNextSpendNote>& spends,
    const std::vector<PrivacyVNextNewOutput>& outputs,
    std::vector<unsigned char>& vchPayloadOut,
    std::string& strErrorOut)
{
    if (spends.empty())
    {
        vchPayloadOut.clear();
        strErrorOut = "an IV5 transfer needs at least one input";
        return false;
    }
    // A transfer moves nothing across the transparent boundary.
    return BuildPrivacyVNextPayload(nNetwork, VNEXT_OPERATION_TRANSFER,
                                    nDisclosureMask, genesis,
                                    outgoingViewSecret, finalizedRoot,
                                    nFinalizedTreeSize, transparentBinding, 0,
                                    nFee, spends, outputs, vchPayloadOut,
                                    strErrorOut);
}

bool BuildPrivacyVNextUnshieldPayload(
    uint8_t nNetwork,
    uint8_t nDisclosureMask,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    uint64_t nTransparentValueOut,
    uint64_t nFee,
    const std::vector<PrivacyVNextSpendNote>& spends,
    const std::vector<PrivacyVNextNewOutput>& outputs,
    std::vector<unsigned char>& vchPayloadOut,
    std::string& strErrorOut)
{
    vchPayloadOut.clear();
    strErrorOut.clear();
    if (spends.empty())
    {
        strErrorOut = "an IV5 unshield needs at least one input";
        return false;
    }
    if (nTransparentValueOut == 0)
    {
        strErrorOut = "an IV5 unshield must release a non-zero amount";
        return false;
    }
    if (nTransparentValueOut > (uint64_t)std::numeric_limits<int64_t>::max())
    {
        strErrorOut = "IV5 unshield value is out of range";
        return false;
    }
    // Negative balance is value the pool releases to the transparent side.
    return BuildPrivacyVNextPayload(
        nNetwork, VNEXT_OPERATION_UNSHIELD, nDisclosureMask, genesis,
        outgoingViewSecret, finalizedRoot, nFinalizedTreeSize,
        transparentBinding, -(int64_t)nTransparentValueOut, nFee, spends,
        outputs, vchPayloadOut, strErrorOut);
}

bool BuildPrivacyVNextShieldPayload(
    uint8_t nNetwork,
    uint8_t nDisclosureMask,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    uint64_t nTransparentValueIn,
    uint64_t nFee,
    const std::vector<PrivacyVNextNewOutput>& outputs,
    std::vector<unsigned char>& vchPayloadOut,
    std::string& strErrorOut)
{
    vchPayloadOut.clear();
    strErrorOut.clear();
    if (nTransparentValueIn > (uint64_t)std::numeric_limits<int64_t>::max())
    {
        strErrorOut = "IV5 shield value is out of range";
        return false;
    }
    // Positive balance is value entering the pool; no note is spent, so there is no
    // membership proof and the payload is a fraction of a transfer's size.
    return BuildPrivacyVNextPayload(
        nNetwork, VNEXT_OPERATION_SHIELD, nDisclosureMask, genesis,
        outgoingViewSecret, finalizedRoot, nFinalizedTreeSize,
        transparentBinding, (int64_t)nTransparentValueIn, nFee,
        std::vector<PrivacyVNextSpendNote>(), outputs, vchPayloadOut,
        strErrorOut);
}

// Attestation payload (no note, no value, no balance proof): proves the named commitment
// opens to the collateral tier. Shared by both attestation operations.
static bool BuildPrivacyVNextAttestationPayload(
    uint8_t nOperation,
    uint8_t nNetwork,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    const PrivacyVNextDigest& registrationContext,
    const std::vector<unsigned char>& vchMemberKey,
    const PrivacyVNextSpendNote& collateral,
    std::vector<unsigned char>& vchPayloadOut,
    PrivacyVNextDigest& keyImageOut,
    std::string& strErrorOut)
{
    vchPayloadOut.clear();
    keyImageOut.fill(0);
    strErrorOut.clear();

    if (!iv5::IsAttestationOperation(nOperation))
    {
        strErrorOut = "IV5 attestation building was asked for an operation that "
                      "is not one";
        return false;
    }
    const bool fMember = nOperation == iv5::NOTE_FINALITY_MEMBER_REGISTER;
    if (fMember != (vchMemberKey.size() == iv5::FINALITY_MEMBER_KEY_BYTES))
    {
        strErrorOut = fMember
            ? "an IV5 finality member registration needs a 33-byte "
              "compressed tally-encryption key"
            : "a collateralnode attestation carries no tally-encryption key";
        return false;
    }
    // Refused here as well as by consensus, so a wallet cannot spend a proof on a
    // registration the chain will reject.
    if (fMember && !IsPrivacyVNextMemberKeyOnCurve(&vchMemberKey[0],
                                                   vchMemberKey.size()))
    {
        strErrorOut = "the IV5 tally-encryption key is not a point on secp256k1";
        return false;
    }

    if (collateral.nAmount != INNOVA_PRIVACY_VNEXT_COLLATERAL_ATTESTATION_AMOUNT)
    {
        strErrorOut = "an IV5 collateral attestation names a note of exactly "
                      "25000 INN";
        return false;
    }
    if (collateral.vchWitnessRecord.empty())
    {
        strErrorOut = "an IV5 collateral attestation is missing its membership witness";
        return false;
    }
    bool fContext = false;
    for (size_t i = 0; i < registrationContext.size(); ++i)
        fContext = fContext || registrationContext[i] != 0;
    if (!fContext)
    {
        strErrorOut = "an IV5 collateral attestation needs a registration context";
        return false;
    }

    PrivacyVNextEpochSeed seed;
    if (!LoadPrivacyVNextEpochSeed(seed, strErrorOut))
        return false;
    if (seed.vchParameterDigest.size() != 32)
    {
        strErrorOut = "IV5 parameter digest is unavailable";
        return false;
    }
    PrivacyVNextDigest parameterDigest;
    std::memcpy(parameterDigest.data(), &seed.vchParameterDigest[0], 32);

    PrivacyVNextDigest entropy;
    if (!RandomScalar(entropy, strErrorOut))
        return false;

    std::vector<PrivacyVNextSpendInput> vProveInputs(1);
    vProveInputs[0].spendScalar = collateral.spendSecret;
    vProveInputs[0].commitmentScalar = collateral.y;
    vProveInputs[0].leaf = collateral.leaf;
    vProveInputs[0].vchWitnessRecord = collateral.vchWitnessRecord;

    // Two passes for the same reason a spend needs them: the prefix names the
    // pseudo-output, and the hash over that prefix is what the proof binds to.
    PrivacyVNextDigest provisional;
    provisional.fill(0);
    provisional[0] = 1;
    std::vector<PrivacyVNextSpendConstruction> vDraft;
    RetainedBytes draftProof;
    if (!ProvePrivacyVNextMembership(finalizedRoot, provisional, entropy,
                                     vProveInputs, vDraft, draftProof.v,
                                     strErrorOut))
        return false;
    if (vDraft.size() != 1)
    {
        strErrorOut = "IV5 attestation proving returned the wrong input count";
        return false;
    }

    std::vector<unsigned char> prefix;
    prefix.push_back(static_cast<unsigned char>(iv5::PROTOCOL_SCHEMA));
    prefix.push_back(0);
    prefix.push_back(nOperation);
    prefix.push_back(0);                         // finality profile: none
    prefix.push_back(0);                         // authorization: owner
    prefix.push_back(iv5::DISCLOSURE_MASK);      // fully private: the only mask allowed
    prefix.push_back(0);                         // finality object: none
    prefix.push_back(nNetwork);
    prefix.push_back(0);                         // reserved
    PutBytes(prefix, genesis);
    PutBytes(prefix, parameterDigest);
    PutBytes(prefix, finalizedRoot);
    PutU64(prefix, nFinalizedTreeSize);
    PutI64(prefix, 0);                           // nothing crosses the boundary
    PutU64(prefix, 0);                           // and no fee is taken
    PutBytes(prefix, transparentBinding);

    PutCompactSize(prefix, 1);
    PutBytes(prefix, vDraft[0].pseudoOut);
    PutBytes(prefix, vDraft[0].keyImage);
    PutCompactSize(prefix, 0);                   // no note is created
    // Inside the prefix the signing hash covers, so the proof below is bound to this
    // node's identity, endpoint and payout address and to no other.
    PutBytes(prefix, registrationContext);
    if (fMember)
        prefix.insert(prefix.end(), vchMemberKey.begin(), vchMemberKey.end());
    PutVector(prefix, std::vector<unsigned char>());   // empty finality body

    PrivacyVNextDigest signingHash;
    if (!HashPrivacyVNextPayloadPrefix(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                       prefix, signingHash, strErrorOut))
        return false;

    std::vector<PrivacyVNextSpendConstruction> vFinal;
    std::vector<unsigned char> vchMembership;
    if (!ProvePrivacyVNextMembership(finalizedRoot, signingHash, entropy,
                                     vProveInputs, vFinal, vchMembership,
                                     strErrorOut))
        return false;
    if (vFinal.size() != 1 || vFinal[0].pseudoOut != vDraft[0].pseudoOut ||
        vFinal[0].keyImage != vDraft[0].keyImage)
    {
        strErrorOut = "IV5 attestation proving is not deterministic in its entropy";
        return false;
    }

    // The mask behind the re-randomized commitment is the note's own plus what the
    // re-randomization added; that is the secret the tier proof knows.
    std::vector<unsigned char> rerandomizedMask;
    if (!Ed25519ScalarAdd(AsVector(collateral.mask),
                          AsVector(vFinal[0].pseudoOutMaskDelta),
                          rerandomizedMask) ||
        rerandomizedMask.size() != 32)
    {
        strErrorOut = "IV5 attestation mask accumulation failed";
        return false;
    }
    PrivacyVNextDigest amountMask;
    std::memcpy(amountMask.data(), &rerandomizedMask[0], 32);
    OPENSSL_cleanse(&rerandomizedMask[0], rerandomizedMask.size());

    PrivacyVNextDigest amountEntropy;
    std::vector<unsigned char> vchAmountProof;
    bool fProved = RandomScalar(amountEntropy, strErrorOut);
    if (fProved)
        fProved = ProvePrivacyVNextAmountEquality(
            vFinal[0].pseudoOut,
            INNOVA_PRIVACY_VNEXT_COLLATERAL_ATTESTATION_AMOUNT, amountMask,
            signingHash, amountEntropy, vchAmountProof, strErrorOut);
    OPENSSL_cleanse(amountMask.data(), amountMask.size());
    OPENSSL_cleanse(amountEntropy.data(), amountEntropy.size());
    if (!fProved)
        return false;

    std::vector<unsigned char> payload = prefix;
    PutVector(payload, vchMembership);
    PutVector(payload, std::vector<unsigned char>());   // no range proof
    PutVector(payload, std::vector<unsigned char>());   // no balance proof
    PutVector(payload, vchAmountProof);                 // the tier proof
    PutVector(payload, std::vector<unsigned char>());   // no disclosures

    const PrivacyVNextPayloadValidation validation =
        ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                    payload);
    if (!validation.IsValid())
    {
        strErrorOut = "the built IV5 attestation does not validate: " +
                      validation.strError;
        return false;
    }

    keyImageOut = vFinal[0].keyImage;
    vchPayloadOut.swap(payload);
    return true;
}

bool BuildPrivacyVNextCollateralAttestationPayload(
    uint8_t nNetwork,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    const PrivacyVNextDigest& registrationContext,
    const PrivacyVNextSpendNote& collateral,
    std::vector<unsigned char>& vchPayloadOut,
    PrivacyVNextDigest& keyImageOut,
    std::string& strErrorOut)
{
    return BuildPrivacyVNextAttestationPayload(
        iv5::NOTE_COLLATERAL_REGISTER, nNetwork, genesis, finalizedRoot,
        nFinalizedTreeSize, transparentBinding, registrationContext,
        std::vector<unsigned char>(), collateral, vchPayloadOut, keyImageOut,
        strErrorOut);
}

bool BuildPrivacyVNextFinalityMemberRegistrationPayload(
    uint8_t nNetwork,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    const PrivacyVNextDigest& registrationContext,
    const std::vector<unsigned char>& vchMemberKey,
    const PrivacyVNextSpendNote& collateral,
    std::vector<unsigned char>& vchPayloadOut,
    PrivacyVNextDigest& keyImageOut,
    std::string& strErrorOut)
{
    return BuildPrivacyVNextAttestationPayload(
        iv5::NOTE_FINALITY_MEMBER_REGISTER, nNetwork, genesis, finalizedRoot,
        nFinalizedTreeSize, transparentBinding, registrationContext,
        vchMemberKey, collateral, vchPayloadOut, keyImageOut, strErrorOut);
}
