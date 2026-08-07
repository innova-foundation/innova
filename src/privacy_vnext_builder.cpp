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

// Every disclosure bit set: nothing is revealed, and the outputs need a range proof.
const uint8_t VNEXT_DISCLOSURE_PRIVATE = 7;
const uint8_t VNEXT_OPERATION_SHIELD = 0;
const uint8_t VNEXT_OPERATION_UNSHIELD = 1;
const uint8_t VNEXT_OPERATION_TRANSFER = 2;

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
    RAND_bytes(&wide[0], 64);
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
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    int64_t nTransparentValueBalance,
    uint64_t nFee,
    const std::vector<PrivacyVNextSpendNote>& spends,
    const std::vector<PrivacyVNextNewOutput>& outputs,
    std::vector<unsigned char>& vchPayloadOut,
    std::string& strErrorOut)
{
    vchPayloadOut.clear();
    strErrorOut.clear();

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

    // Encrypt every output, keeping the openings the value proof needs.
    std::vector<PrivacyVNextEncryptedOutput> vEncrypted(outputs.size());
    std::vector<PrivacyVNextDigest> vOutputMasks(outputs.size());
    for (size_t i = 0; i < outputs.size(); ++i)
    {
        PrivacyVNextDigest ephemeralSecret;
        PrivacyVNextDigest outY;
        if (!RandomScalar(ephemeralSecret, strErrorOut) ||
            !RandomScalar(outY, strErrorOut) ||
            !RandomScalar(vOutputMasks[i], strErrorOut))
            return false;
        if (!EncryptPrivacyVNextNote(
                nNetwork, outputs[i].recipient.nAddressType,
                static_cast<uint32_t>(i), genesis,
                outputs[i].recipient.spendPublic, outputs[i].recipient.viewPublic,
                outgoingViewSecret, ephemeralSecret, outputs[i].nAmount, outY,
                vOutputMasks[i], vEncrypted[i], strErrorOut))
        {
            OPENSSL_cleanse(ephemeralSecret.data(), ephemeralSecret.size());
            OPENSSL_cleanse(outY.data(), outY.size());
            return false;
        }
        OPENSSL_cleanse(ephemeralSecret.data(), ephemeralSecret.size());
        OPENSSL_cleanse(outY.data(), outY.size());
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
    // only exist once the prover has run. The prover is deterministic in the caller's
    // entropy, so it is run twice with the same entropy: once to learn the pseudo-outputs
    // and key images, and again to prove against the hash they produce.
    PrivacyVNextDigest provisional;
    provisional.fill(0);
    provisional[0] = 1;
    std::vector<PrivacyVNextSpendConstruction> vDraft;
    std::vector<unsigned char> vchDraftProof;
    if (!vProveInputs.empty() &&
        !ProvePrivacyVNextMembership(finalizedRoot, provisional, entropy,
                                     vProveInputs, vDraft, vchDraftProof,
                                     strErrorOut))
        return false;

    std::vector<unsigned char> prefix;
    prefix.push_back(static_cast<unsigned char>(iv5::PROTOCOL_SCHEMA));
    prefix.push_back(0);
    prefix.push_back(nOperation);
    prefix.push_back(0);                         // finality profile: none
    prefix.push_back(0);                         // authorization: owner
    prefix.push_back(VNEXT_DISCLOSURE_PRIVATE);
    prefix.push_back(0);                         // finality object: none
    prefix.push_back(nNetwork);
    prefix.push_back(0);                         // reserved
    PutBytes(prefix, genesis);
    PutBytes(prefix, parameterDigest);
    PutBytes(prefix, finalizedRoot);
    PutU64(prefix, nFinalizedTreeSize);
    PutI64(prefix, nTransparentValueBalance);
    PutU64(prefix, nFee);

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
        PutBytes(prefix, vEncrypted[i].ephemeral);
        PutVector(prefix, vEncrypted[i].vchRecipientCiphertext);
        PutVector(prefix, vEncrypted[i].vchOutgoingCiphertext);
    }
    // Every disclosure bit is set, so no sender, receiver or amount records follow.
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
        if (vFinal[i].pseudoOut != vDraft[i].pseudoOut ||
            vFinal[i].keyImage != vDraft[i].keyImage)
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

    std::vector<unsigned char> payload = prefix;
    PutVector(payload, vchMembership);
    PutVector(payload, valueProof.vchRangeProof);
    PutVector(payload, std::vector<unsigned char>(
                           valueProof.balanceProof.begin(),
                           valueProof.balanceProof.end()));
    PutVector(payload, std::vector<unsigned char>());   // operation proof: none
    PutVector(payload, std::vector<unsigned char>());   // disclosure proofs: none
    PutVector(payload, std::vector<unsigned char>(
                           valueProof.bindingSignature.begin(),
                           valueProof.bindingSignature.end()));

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
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
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
    return BuildPrivacyVNextPayload(nNetwork, VNEXT_OPERATION_TRANSFER, genesis,
                                    outgoingViewSecret, finalizedRoot,
                                    nFinalizedTreeSize, 0, nFee, spends, outputs,
                                    vchPayloadOut, strErrorOut);
}

bool BuildPrivacyVNextUnshieldPayload(
    uint8_t nNetwork,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
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
        nNetwork, VNEXT_OPERATION_UNSHIELD, genesis, outgoingViewSecret,
        finalizedRoot, nFinalizedTreeSize, -(int64_t)nTransparentValueOut, nFee,
        spends, outputs, vchPayloadOut, strErrorOut);
}

bool BuildPrivacyVNextShieldPayload(
    uint8_t nNetwork,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
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
        nNetwork, VNEXT_OPERATION_SHIELD, genesis, outgoingViewSecret,
        finalizedRoot, nFinalizedTreeSize, (int64_t)nTransparentValueIn, nFee,
        std::vector<PrivacyVNextSpendNote>(), outputs, vchPayloadOut,
        strErrorOut);
}
