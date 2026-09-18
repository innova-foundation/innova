#include "nullsend_v2008.h"

#include <algorithm>
#include <limits>

#include "ed25519_zk.h"
#include "netbase.h"
#include "nullsend.h"
#include "shielded.h"
#include "privacy_vnext/iv5_protocol.h"

uint256 MixRoundKeyCommitment(const std::vector<unsigned char>& vchRSA_N,
                              const std::vector<unsigned char>& vchRSA_E)
{
    // Both halves are length-prefixed, so no pair of keys can be re-cut into the
    // same byte string and open one commitment as two.
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/round-key/v1");
    ss << vchRSA_N;
    ss << vchRSA_E;
    return ss.GetHash();
}

bool IsMixOnionEndpoint(const std::string& strEndpoint)
{
    static const std::string strSuffix = ".onion";
    if (strEndpoint.size() != 56 + strSuffix.size())
        return false;
    if (strEndpoint.compare(56, strSuffix.size(), strSuffix) != 0)
        return false;
    for (size_t i = 0; i < 56; i++)
    {
        const char ch = strEndpoint[i];
        const bool fBase32 = (ch >= 'a' && ch <= 'z') || (ch >= '2' && ch <= '7');
        if (!fBase32)
            return false;
    }
    return true;
}

uint256 CMixRoundAnnouncement::GetSignatureHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/announce/v2");
    ss << nVersion;
    ss << hashRound;
    ss << hashRoundKey;
    ss << strEndpoint;
    ss << nPort;
    ss << nParticipants;
    ss << nTime;
    ss << pubkeyCoordinator;
    ss.write((const char*)&nNetwork, 1);
    ss.write((const char*)genesis.data(), genesis.size());
    ss.write((const char*)parameterDigest.data(), parameterDigest.size());
    ss.write((const char*)finalizedRoot.data(), finalizedRoot.size());
    ss << nFinalizedTreeSize;
    ss << nDenomination;
    ss << nFee;
    ss << nJoinSecs;
    ss << nViewSecs;
    ss << nTokenSecs;
    ss << nOutputSecs;
    ss << nApproveSecs;
    ss << nNonceSecs;
    ss << nResponseSecs;
    ss << nTerminalSecs;
    return ss.GetHash();
}

uint256 CMixRoundAnnouncement::DerivedRoundId() const
{
    // Every field but hashRound and the signature. Including hashRound would be
    // circular; including the signature would make the identifier depend on the nonce.
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/round-id/v2");
    ss << nVersion;
    ss << hashRoundKey;
    ss << strEndpoint;
    ss << nPort;
    ss << nParticipants;
    ss << nTime;
    ss << pubkeyCoordinator;
    ss.write((const char*)&nNetwork, 1);
    ss.write((const char*)genesis.data(), genesis.size());
    ss.write((const char*)parameterDigest.data(), parameterDigest.size());
    ss.write((const char*)finalizedRoot.data(), finalizedRoot.size());
    ss << nFinalizedTreeSize;
    ss << nDenomination;
    ss << nFee;
    ss << nJoinSecs;
    ss << nViewSecs;
    ss << nTokenSecs;
    ss << nOutputSecs;
    ss << nApproveSecs;
    ss << nNonceSecs;
    ss << nResponseSecs;
    ss << nTerminalSecs;
    return ss.GetHash();
}

bool CMixRoundAnnouncement::Sign(const CKey& key)
{
    vchSig.clear();
    if (!key.IsValid())
        return false;
    pubkeyCoordinator = key.GetPubKey();
    if (!pubkeyCoordinator.IsValid())
        return false;
    hashRound = DerivedRoundId();
    return key.Sign(GetSignatureHash(), vchSig);
}

bool CMixRoundAnnouncement::CheckSignature() const
{
    if (vchSig.empty() || !pubkeyCoordinator.IsValid())
        return false;
    return pubkeyCoordinator.Verify(GetSignatureHash(), vchSig);
}

bool CMixRoundAnnouncement::IsValidBasic(std::string* pstrError) const
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (nVersion != CURRENT_VERSION)
        FAIL("unsupported announcement version");
    if (hashRound == 0)
        FAIL("round identifier is zero");
    // A zero commitment is what an announcement built without one carries, and it
    // opens to no key, so accepting it would mean accepting any key at all.
    if (hashRoundKey == 0)
        FAIL("round key commitment is zero");
    // Derived, not declared: this is what makes two announcements naming one round with
    // two different key commitments impossible to build rather than merely detectable.
    if (hashRound != DerivedRoundId())
        FAIL("round identifier is not the one this announcement's contents derive");
    if (strEndpoint.empty() || strEndpoint.size() > MIX_ROUND_ENDPOINT_MAX)
        FAIL("endpoint is empty or too long");
    if (!IsMixOnionEndpoint(strEndpoint))
        FAIL("endpoint is not a v3 onion, so the stream has nothing protecting it");
    if (nPort < 1 || nPort > 65535)
        FAIL("port is out of range");
    if (nParticipants < NULLSEND_MIN_PARTICIPANTS || nParticipants > (int)iv5::MAX_NULLSEND_INPUTS)
        FAIL("participant count is outside the range a v2008 mix can carry");
    if (nDenomination == 0)
        FAIL("the round announces no denomination");
    // Equal shares, exactly: a seat paying a remainder pays a different amount from every
    // other seat, and an amount is a tag.
    if (nFee % (uint64_t)nParticipants != 0)
        FAIL("the fee does not divide evenly into one share per seat");
    PrivacyVNextDigest zero;
    zero.fill(0);
    if (genesis == zero || parameterDigest == zero || finalizedRoot == zero)
        FAIL("the round announces no chain to anchor to");
    if (nFinalizedTreeSize == 0)
        FAIL("the round announces an empty anchor tree");
    const uint16_t vWindows[8] = { nJoinSecs, nViewSecs, nTokenSecs, nOutputSecs,
                                   nApproveSecs, nNonceSecs, nResponseSecs, nTerminalSecs };
    int64_t nTotal = 0;
    for (size_t i = 0; i < 8; i++)
    {
        if (vWindows[i] < MIX_WINDOW_MIN_SECS || vWindows[i] > MIX_WINDOW_MAX_SECS)
            FAIL("a scheduled window is outside the range a round may use");
        nTotal += (int64_t)vWindows[i];
    }
    // Two windows carry a one-input prove, not one: the pseudo-output a seat submits in
    // the view window comes out of the same proving pass its membership proof does.
    if (nApproveSecs < MIX_PROOF_WINDOW_MIN_SECS || nViewSecs < MIX_PROOF_WINDOW_MIN_SECS)
        FAIL("a window that carries a membership proof is shorter than the proof takes");
    // The anonymous window is the one a seat cannot be asked to hurry: it has to build a
    // bundle, then pick an instant inside the window to submit at.
    if (nOutputSecs < MIX_OUTPUT_WINDOW)
        FAIL("the output window is shorter than a registration is given");
    if (nTotal > MIX_SCHEDULE_MAX_TOTAL_SECS)
        FAIL("the schedule holds the round's anchor open for too long");
    if (nTime <= 0)
        FAIL("announcement carries no time");
    if (!pubkeyCoordinator.IsValid())
        FAIL("coordinator public key is not valid");
    if (!CheckSignature())
        FAIL("coordinator signature does not verify");
    return true;
    #undef FAIL
}

bool CMixRoundAnnouncement::KeyOpensCommitment(const std::vector<unsigned char>& vchRSA_N,
                                               const std::vector<unsigned char>& vchRSA_E) const
{
    if (hashRoundKey == 0 || vchRSA_N.empty() || vchRSA_E.empty())
        return false;
    return MixRoundKeyCommitment(vchRSA_N, vchRSA_E) == hashRoundKey;
}

bool BuildMixFrame(MixFrameType nType, const std::vector<unsigned char>& vchPayload,
                   std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (nType == MIX_FRAME_NONE || (int)nType > MIX_FRAME_TYPE_MAX)
        return false;
    if (vchPayload.size() > MIX_FRAME_MAX_PAYLOAD)
        return false;
    const uint32_t nLength = (uint32_t)vchPayload.size();
    vchOut.insert(vchOut.end(), MIX_FRAME_MAGIC, MIX_FRAME_MAGIC + sizeof(MIX_FRAME_MAGIC));
    vchOut.push_back((unsigned char)nType);
    vchOut.push_back((unsigned char)(nLength & 0xFF));
    vchOut.push_back((unsigned char)((nLength >> 8) & 0xFF));
    vchOut.push_back((unsigned char)((nLength >> 16) & 0xFF));
    vchOut.push_back((unsigned char)((nLength >> 24) & 0xFF));
    vchOut.insert(vchOut.end(), vchPayload.begin(), vchPayload.end());
    return true;
}

MixFrameDecode ReadMixFrame(const std::vector<unsigned char>& vchBuffer,
                            MixFrameType& nTypeOut,
                            std::vector<unsigned char>& vchPayloadOut,
                            size_t& nConsumedOut)
{
    nTypeOut = MIX_FRAME_NONE;
    vchPayloadOut.clear();
    nConsumedOut = 0;
    if (vchBuffer.size() < MIX_FRAME_HEADER_BYTES)
        return MIX_DECODE_INCOMPLETE;
    if (memcmp(&vchBuffer[0], MIX_FRAME_MAGIC, sizeof(MIX_FRAME_MAGIC)) != 0)
        return MIX_DECODE_INVALID;
    const unsigned char chType = vchBuffer[4];
    if (chType == MIX_FRAME_NONE || (int)chType > MIX_FRAME_TYPE_MAX)
        return MIX_DECODE_INVALID;
    const uint32_t nLength = (uint32_t)vchBuffer[5]
                           | ((uint32_t)vchBuffer[6] << 8)
                           | ((uint32_t)vchBuffer[7] << 16)
                           | ((uint32_t)vchBuffer[8] << 24);
    // Judged before the buffer is: a length past the bound is refused outright, so a
    // peer cannot hold a reader waiting on bytes it will never send.
    if (nLength > MIX_FRAME_MAX_PAYLOAD)
        return MIX_DECODE_INVALID;
    if (vchBuffer.size() < MIX_FRAME_HEADER_BYTES + nLength)
        return MIX_DECODE_INCOMPLETE;
    nTypeOut = (MixFrameType)chType;
    vchPayloadOut.assign(vchBuffer.begin() + MIX_FRAME_HEADER_BYTES,
                         vchBuffer.begin() + MIX_FRAME_HEADER_BYTES + nLength);
    nConsumedOut = MIX_FRAME_HEADER_BYTES + nLength;
    return MIX_DECODE_OK;
}

uint256 MixSessionSigHash(const uint256& hashRound, MixFrameType nType,
                          const std::vector<unsigned char>& vchPayload)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/session/v1");
    ss << hashRound;
    ss << (unsigned char)nType;
    ss << vchPayload;
    return ss.GetHash();
}

bool BuildMixRoster(const std::vector<CMixRosterEntry>& vIn,
                    std::vector<CMixRosterEntry>& vOut)
{
    vOut = vIn;
    std::sort(vOut.begin(), vOut.end(),
              [](const CMixRosterEntry& a, const CMixRosterEntry& b) {
                  return std::lexicographical_compare(a.keyImage.begin(), a.keyImage.end(),
                                                      b.keyImage.begin(), b.keyImage.end());
              });
    for (size_t i = 0; i < vOut.size(); i++)
    {
        if (!vOut[i].pubkeySession.IsValid() || vOut[i].keyImage == 0)
        {
            vOut.clear();
            return false;
        }
        for (size_t j = i + 1; j < vOut.size(); j++)
        {
            // One seat holds one of each. A roster that repeats either is not a roster of
            // n seats, and the count is what a seat checks against the announcement.
            if (vOut[i].keyImage == vOut[j].keyImage ||
                vOut[i].pubkeySession == vOut[j].pubkeySession)
            {
                vOut.clear();
                return false;
            }
        }
    }
    return true;
}

uint256 MixViewDigest(const uint256& hashAnnouncement,
                      const std::vector<CMixRosterEntry>& vRoster)
{
    std::vector<CMixRosterEntry> vSorted;
    if (!BuildMixRoster(vRoster, vSorted))
        return 0;
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/view/v1");
    ss << hashAnnouncement;
    ss << (unsigned int)vSorted.size();
    for (size_t i = 0; i < vSorted.size(); i++)
    {
        ss << vSorted[i].keyImage;
        ss << vSorted[i].pubkeySession;
    }
    return ss.GetHash();
}

static void PutMixCompactSize(std::vector<unsigned char>& vch, uint64_t nSize)
{
    if (nSize < 253)
    {
        vch.push_back((unsigned char)nSize);
    }
    else if (nSize <= 0xffff)
    {
        vch.push_back(253);
        vch.push_back((unsigned char)nSize);
        vch.push_back((unsigned char)(nSize >> 8));
    }
    else
    {
        vch.push_back(254);
        for (size_t i = 0; i < 4; i++)
            vch.push_back((unsigned char)(nSize >> (8 * i)));
    }
}

// amount*H + mask*G == commitment. False for a mask that is not a usable scalar.
static bool MixOpeningOpens(uint64_t nAmount, const PrivacyVNextDigest& mask,
                            const PrivacyVNextDigest& commitment)
{
    std::vector<PrivacyVNextCombineTerm> vTerms(2);
    PrivacyVNextDigest amountScalar;
    amountScalar.fill(0);
    uint64_t nLeft = nAmount;
    for (size_t i = 0; i < 8; i++)
    {
        amountScalar[i] = (uint8_t)(nLeft & 0xff);
        nLeft >>= 8;
    }
    vTerms[0].nSource = PRIVACY_VNEXT_TERM_MONERO_H;
    vTerms[0].scalar = amountScalar;
    vTerms[1].nSource = PRIVACY_VNEXT_TERM_ED25519_G;
    vTerms[1].scalar = mask;
    PrivacyVNextDigest derived;
    std::string strCombine;
    if (!CombinePrivacyVNextPoints(vTerms, derived, strCombine))
        return false;
    return derived == commitment;
}

namespace
{
struct PrefixReader
{
    const std::vector<unsigned char>& vch;
    size_t nAt;
    explicit PrefixReader(const std::vector<unsigned char>& vchIn) : vch(vchIn), nAt(0) {}
    bool U8(uint8_t& out)
    {
        if (nAt + 1 > vch.size())
            return false;
        out = vch[nAt++];
        return true;
    }
    bool U64(uint64_t& out)
    {
        if (nAt + 8 > vch.size())
            return false;
        out = 0;
        for (size_t i = 0; i < 8; i++)
            out |= (uint64_t)vch[nAt + i] << (8 * i);
        nAt += 8;
        return true;
    }
    bool Digest(PrivacyVNextDigest& out)
    {
        if (nAt + 32 > vch.size())
            return false;
        memcpy(out.data(), &vch[nAt], 32);
        nAt += 32;
        return true;
    }
    // The canonical compact size the builder writes, and nothing longer than needed.
    bool CompactSize(uint64_t& out)
    {
        uint8_t nFirst = 0;
        if (!U8(nFirst))
            return false;
        if (nFirst < 253)
        {
            out = nFirst;
            return true;
        }
        if (nFirst == 253)
        {
            if (nAt + 2 > vch.size())
                return false;
            out = (uint64_t)vch[nAt] | ((uint64_t)vch[nAt + 1] << 8);
            nAt += 2;
            return out >= 253;
        }
        if (nFirst == 254)
        {
            if (nAt + 4 > vch.size())
                return false;
            out = 0;
            for (size_t i = 0; i < 4; i++)
                out |= (uint64_t)vch[nAt + i] << (8 * i);
            nAt += 4;
            return out > 0xffff;
        }
        return false;
    }
    bool Bytes(size_t nLen, std::vector<unsigned char>& out)
    {
        if (nAt + nLen > vch.size())
            return false;
        out.assign(vch.begin() + nAt, vch.begin() + nAt + nLen);
        nAt += nLen;
        return true;
    }
};
} // namespace

bool ParseMixPrefix(const std::vector<unsigned char>& vchPrefix, CMixPrefixView& view,
                    std::string& strError)
{
    view = CMixPrefixView();
    strError.clear();
    #define BAD(msg) do { strError = (msg); return false; } while (0)
    PrefixReader r(vchPrefix);
    uint8_t nSchema = 0, nZero = 0, nProfile = 0, nAuth = 0, nFinalityObject = 0, nReserved = 0;
    if (!r.U8(nSchema) || !r.U8(nZero) || !r.U8(view.nOperation) || !r.U8(nProfile) ||
        !r.U8(nAuth) || !r.U8(view.nDisclosureMask) || !r.U8(nFinalityObject) ||
        !r.U8(view.nNetwork) || !r.U8(nReserved))
        BAD("prefix header is truncated");
    if (nSchema != (uint8_t)iv5::PROTOCOL_SCHEMA || nZero != 0 || nProfile != 0 || nAuth != 0 ||
        nFinalityObject != 0 || nReserved != 0)
        BAD("prefix header is not the mix layout");
    if (!iv5::IsNullSendOperation(view.nOperation))
        BAD("prefix does not name the NullSend operation");
    if (view.nDisclosureMask != iv5::NULLSEND_DISCLOSURE_MASK)
        BAD("prefix is not at the NullSend disclosure mask");
    uint64_t nBalance = 0;
    if (!r.Digest(view.genesis) || !r.Digest(view.parameterDigest) ||
        !r.Digest(view.finalizedRoot) || !r.U64(view.nFinalizedTreeSize) || !r.U64(nBalance) ||
        !r.U64(view.nFee) || !r.Digest(view.transparentBinding))
        BAD("prefix fixed fields are truncated");
    view.nTransparentValueBalance = (int64_t)nBalance;

    uint64_t nInputs = 0;
    if (!r.CompactSize(nInputs) || nInputs == 0 || nInputs > iv5::MAX_NULLSEND_INPUTS)
        BAD("prefix input count is out of range");
    for (uint64_t i = 0; i < nInputs; i++)
    {
        PrivacyVNextDigest pseudoOut, keyImage;
        if (!r.Digest(pseudoOut) || !r.Digest(keyImage))
            BAD("prefix inputs are truncated");
        uint256 key;
        memcpy(key.begin(), keyImage.data(), 32);
        view.vPseudoOuts.push_back(pseudoOut);
        view.vKeyImages.push_back(key);
    }
    uint64_t nOutputs = 0;
    if (!r.CompactSize(nOutputs) || nOutputs == 0 || nOutputs > iv5::MAX_NULLSEND_INPUTS)
        BAD("prefix output count is out of range");
    for (uint64_t i = 0; i < nOutputs; i++)
    {
        CMixOutputRecord record;
        uint64_t nLen = 0;
        if (!r.Digest(record.owner) || !r.Digest(record.commitment) ||
            !r.Digest(record.noteEphemeral) || !r.Digest(record.tweakEphemeral))
            BAD("prefix outputs are truncated");
        if (!r.CompactSize(nLen) || nLen != INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE ||
            !r.Bytes(nLen, record.vchRecipientCiphertext))
            BAD("prefix recipient ciphertext is not the payload size");
        if (!r.CompactSize(nLen) || nLen != INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE ||
            !r.Bytes(nLen, record.vchOutgoingCiphertext))
            BAD("prefix outgoing ciphertext is not the payload size");
        view.vOutputs.push_back(record);
    }
    // Mask 3 hides senders and receivers and discloses amounts: one amount and mask per
    // output, then the empty finality body, then nothing.
    for (uint64_t i = 0; i < nOutputs; i++)
    {
        uint64_t nAmount = 0;
        if (!r.U64(nAmount) || !r.Digest(view.vOutputs[i].mask))
            BAD("prefix disclosed amounts are truncated");
        view.vAmounts.push_back(nAmount);
    }
    uint64_t nFinalityBody = 0;
    if (!r.CompactSize(nFinalityBody) || nFinalityBody != 0)
        BAD("prefix carries a finality body");
    if (r.nAt != vchPrefix.size())
        BAD("prefix has trailing bytes");
    return true;
    #undef BAD
}

bool BuildMixTransaction(const std::vector<unsigned char>& vchPayload, uint32_t nTime,
                         CTransaction& txOut, std::string& strError)
{
    txOut = CTransaction();
    strError.clear();
    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation validation = ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vchPayload, effects);
    if (validation.nResult != INNOVA_PRIVACY_VNEXT_VALID)
    {
        strError = "the payload does not validate: " + validation.strError;
        return false;
    }
    // Byte 2 of the canonical header, which validation has just accepted.
    if (vchPayload.size() < 9 || !iv5::IsNullSendOperation(vchPayload[2]))
    {
        strError = "the payload is not a mix";
        return false;
    }
    CTransaction tx;
    tx.nVersion = INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION;
    tx.nTime = nTime;
    tx.nLockTime = 0;
    tx.privacyVNext.vchPayload = vchPayload;
    const uint256 binding = GetPrivacyVNextTransparentBinding(tx);
    if (memcmp(binding.begin(), effects.transparentBinding.data(), 32) != 0)
    {
        strError = "the payload's transparent binding is not a mix transaction's";
        return false;
    }
    txOut = tx;
    return true;
}

PrivacyVNextDigest MixTransparentBinding()
{
    CTransaction tx;
    tx.vin.clear();
    tx.vout.clear();
    tx.nLockTime = 0;
    const uint256 binding = GetPrivacyVNextTransparentBinding(tx);
    PrivacyVNextDigest out;
    memcpy(out.data(), binding.begin(), 32);
    return out;
}

uint256 MixPrefixDigest(const uint256& hashView, const PrivacyVNextDigest& signingHash)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/prefix/v1");
    ss << hashView;
    ss.write((const char*)signingHash.data(), signingHash.size());
    return ss.GetHash();
}

bool CheckMixPrefixForSeat(const std::vector<unsigned char>& vchPrefix,
                           const CMixSeatExpectation& expect, std::string& strError)
{
    #define BAD(msg) do { strError = (msg); return false; } while (0)
    CMixPrefixView view;
    if (!ParseMixPrefix(vchPrefix, view, strError))
        return false;
    if (view.nNetwork != expect.nNetwork || !(view.genesis == expect.genesis))
        BAD("prefix names another network");
    if (!(view.parameterDigest == expect.parameterDigest))
        BAD("prefix names another parameter digest");
    if (!(view.finalizedRoot == expect.finalizedRoot) ||
        view.nFinalizedTreeSize != expect.nFinalizedTreeSize)
        BAD("prefix anchors to a tree this seat did not expect");
    if (view.nTransparentValueBalance != 0)
        BAD("prefix moves value across the transparent boundary");
    if (view.nFee != expect.nFee)
        BAD("prefix fee is not the agreed fee");
    if (!(view.transparentBinding == expect.transparentBinding))
        BAD("prefix transparent binding is not a mix's");

    // Inputs: exactly the agreed roster, in the byte order the round sorts it, with this
    // seat's own construction at its own key image.
    std::vector<uint256> vRoster = expect.vRosterKeyImages;
    std::sort(vRoster.begin(), vRoster.end(), [](const uint256& a, const uint256& b) {
        return memcmp(a.begin(), b.begin(), 32) < 0;
    });
    if (view.vKeyImages != vRoster)
        BAD("prefix inputs are not the agreed roster in its order");
    bool fFoundInput = false;
    for (size_t i = 0; i < view.vKeyImages.size(); i++)
    {
        for (size_t j = 0; j < i; j++)
            if (view.vPseudoOuts[j] == view.vPseudoOuts[i])
                BAD("prefix repeats a pseudo-output");
        if (view.vKeyImages[i] != expect.myKeyImage)
            continue;
        if (!(view.vPseudoOuts[i] == expect.myPseudoOut))
            BAD("prefix carries another pseudo-output for this seat's input");
        fFoundInput = true;
    }
    if (!fFoundInput)
        BAD("prefix does not carry this seat's input");

    // Outputs: one per seat, every one at the denomination with an opening that opens.
    if (view.vOutputs.size() != view.vKeyImages.size())
        BAD("prefix output count is not the seat count");
    std::vector<unsigned char> vchMine, vchTheirs;
    size_t nMine = 0;
    for (size_t i = 0; i < view.vOutputs.size(); i++)
    {
        const CMixOutputRecord& output = view.vOutputs[i];
        if (view.vAmounts[i] != expect.nDenomination)
            BAD("prefix discloses an amount other than the denomination");
        if (!MixOpeningOpens(view.vAmounts[i], output.mask, output.commitment))
            BAD("prefix discloses an opening that does not open its commitment");
        for (size_t j = 0; j < i; j++)
        {
            if (view.vOutputs[j].owner == output.owner)
                BAD("prefix repeats an output owner");
            if (view.vOutputs[j].commitment == output.commitment)
                BAD("prefix repeats an output commitment");
        }
        if (!EncodeMixOutputRecord(output, vchTheirs))
            BAD("prefix output is malformed");
        for (size_t k = 0; k < expect.vMyOutputs.size(); k++)
        {
            if (!EncodeMixOutputRecord(expect.vMyOutputs[k].second, vchMine) || vchMine != vchTheirs)
                continue;
            if (expect.vMyOutputs[k].first >= 0 && (size_t)expect.vMyOutputs[k].first != i)
                BAD("prefix places this seat's output at a position it is not valid at");
            nMine++;
        }
    }
    if (nMine != 1)
        BAD(nMine == 0 ? "prefix does not carry this seat's output"
                       : "prefix carries this seat's output more than once");
    return true;
    #undef BAD
}

uint256 CMixOutputRecord::OwnerKey() const
{
    uint256 key;
    memcpy(key.begin(), owner.data(), 32);
    return key;
}

bool EncodeMixOutputRecord(const CMixOutputRecord& record, std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (record.vchRecipientCiphertext.size() != INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE ||
        record.vchOutgoingCiphertext.size() != INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE)
        return false;
    vchOut.reserve(MIX_OUTPUT_RECORD_BYTES);
    vchOut.insert(vchOut.end(), record.owner.begin(), record.owner.end());
    vchOut.insert(vchOut.end(), record.commitment.begin(), record.commitment.end());
    vchOut.insert(vchOut.end(), record.noteEphemeral.begin(), record.noteEphemeral.end());
    vchOut.insert(vchOut.end(), record.tweakEphemeral.begin(), record.tweakEphemeral.end());
    vchOut.insert(vchOut.end(), record.vchRecipientCiphertext.begin(),
                  record.vchRecipientCiphertext.end());
    vchOut.insert(vchOut.end(), record.vchOutgoingCiphertext.begin(),
                  record.vchOutgoingCiphertext.end());
    vchOut.insert(vchOut.end(), record.mask.begin(), record.mask.end());
    return vchOut.size() == MIX_OUTPUT_RECORD_BYTES;
}

bool DecodeMixOutputRecord(const std::vector<unsigned char>& vchIn, CMixOutputRecord& recordOut)
{
    recordOut = CMixOutputRecord();
    if (vchIn.size() != MIX_OUTPUT_RECORD_BYTES)
        return false;
    size_t nAt = 0;
    const auto take32 = [&](PrivacyVNextDigest& out) {
        memcpy(out.data(), &vchIn[nAt], 32);
        nAt += 32;
    };
    take32(recordOut.owner);
    take32(recordOut.commitment);
    take32(recordOut.noteEphemeral);
    take32(recordOut.tweakEphemeral);
    recordOut.vchRecipientCiphertext.assign(
        vchIn.begin() + nAt, vchIn.begin() + nAt + INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE);
    nAt += INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE;
    recordOut.vchOutgoingCiphertext.assign(
        vchIn.begin() + nAt, vchIn.begin() + nAt + INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE);
    nAt += INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE;
    take32(recordOut.mask);
    return nAt == vchIn.size();
}

bool EncodeMixOutputBundle(const std::vector<CMixOutputRecord>& vBundle,
                           std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (vBundle.empty() || vBundle.size() > iv5::MAX_NULLSEND_INPUTS)
        return false;
    vchOut.push_back((unsigned char)vBundle.size());
    for (size_t i = 0; i < vBundle.size(); i++)
    {
        std::vector<unsigned char> vchRecord;
        if (!EncodeMixOutputRecord(vBundle[i], vchRecord))
        {
            vchOut.clear();
            return false;
        }
        vchOut.insert(vchOut.end(), vchRecord.begin(), vchRecord.end());
    }
    return true;
}

bool DecodeMixOutputBundle(const std::vector<unsigned char>& vchIn,
                           std::vector<CMixOutputRecord>& vBundleOut)
{
    vBundleOut.clear();
    if (vchIn.empty())
        return false;
    const size_t nCount = vchIn[0];
    if (nCount == 0 || nCount > iv5::MAX_NULLSEND_INPUTS ||
        vchIn.size() != 1 + nCount * MIX_OUTPUT_RECORD_BYTES)
        return false;
    for (size_t i = 0; i < nCount; i++)
    {
        const std::vector<unsigned char> vchRecord(
            vchIn.begin() + 1 + i * MIX_OUTPUT_RECORD_BYTES,
            vchIn.begin() + 1 + (i + 1) * MIX_OUTPUT_RECORD_BYTES);
        CMixOutputRecord record;
        if (!DecodeMixOutputRecord(vchRecord, record))
        {
            vBundleOut.clear();
            return false;
        }
        vBundleOut.push_back(record);
    }
    return true;
}

uint256 MixOutputBundleCredentialHash(const std::vector<CMixOutputRecord>& vBundle)
{
    std::vector<unsigned char> vchBundle;
    if (!EncodeMixOutputBundle(vBundle, vchBundle))
        return 0;
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/token/v4");
    ss << vchBundle;
    return ss.GetHash();
}

bool BuildMixOutputBundle(uint8_t nNetwork, const PrivacyVNextDigest& genesis,
                          const PrivacyVNextDigest& recipientSpend,
                          const PrivacyVNextDigest& recipientView,
                          const PrivacyVNextDigest& outgoingSecret,
                          const PrivacyVNextDigest& inputContext, uint64_t nAmount,
                          const PrivacyVNextDigest& y, const PrivacyVNextDigest& mask,
                          const std::vector<std::pair<PrivacyVNextDigest, PrivacyVNextDigest> >& vEphemerals,
                          std::vector<CMixOutputRecord>& vBundleOut, std::string& strError)
{
    vBundleOut.clear();
    strError.clear();
    if (vEphemerals.empty() || vEphemerals.size() > iv5::MAX_NULLSEND_INPUTS)
    {
        strError = "a bundle carries one variant per seat";
        return false;
    }
    for (size_t i = 0; i < vEphemerals.size(); i++)
    {
        // Same amount, opening and commitment at every position; everything the position
        // enters is generated for that position, with its own ephemeral secrets.
        PrivacyVNextEncryptedOutput out;
        if (!EncryptPrivacyVNextNote(nNetwork, 0, (uint32_t)i, genesis, recipientSpend,
                                     recipientView, outgoingSecret, vEphemerals[i].first,
                                     vEphemerals[i].second, nAmount, y, mask, inputContext,
                                     out, strError))
        {
            vBundleOut.clear();
            return false;
        }
        CMixOutputRecord record;
        record.owner = out.leaf.owner;
        record.commitment = out.leaf.commitment;
        record.noteEphemeral = out.noteEphemeral;
        record.tweakEphemeral = out.tweakEphemeral;
        record.vchRecipientCiphertext = out.vchRecipientCiphertext;
        record.vchOutgoingCiphertext = out.vchOutgoingCiphertext;
        record.mask = mask;
        vBundleOut.push_back(record);
    }
    return true;
}

bool SignMixSessionFrame(const CKey& key, const uint256& hashRound, MixFrameType nType,
                         const std::vector<unsigned char>& vchPayload,
                         std::vector<unsigned char>& vchSigOut)
{
    vchSigOut.clear();
    if (!key.IsValid())
        return false;
    if (nType == MIX_FRAME_NONE || (int)nType > MIX_FRAME_TYPE_MAX)
        return false;
    return key.Sign(MixSessionSigHash(hashRound, nType, vchPayload), vchSigOut);
}

bool CheckMixSessionFrame(const CPubKey& pubkey, const uint256& hashRound, MixFrameType nType,
                          const std::vector<unsigned char>& vchPayload,
                          const std::vector<unsigned char>& vchSig)
{
    if (vchSig.empty() || !pubkey.IsValid())
        return false;
    if (nType == MIX_FRAME_NONE || (int)nType > MIX_FRAME_TYPE_MAX)
        return false;
    return pubkey.Verify(MixSessionSigHash(hashRound, nType, vchPayload), vchSig);
}

// ---------------------------------------------------------------------------
// The round
// ---------------------------------------------------------------------------

CMixRound::CMixRound()
    : nPhase(MIX_PHASE_ABORTED), hashRound(0), nTargetParticipants(0),
      fStreamIsolated(false), fNoncesFrozen(false), fHasSigned(false),
      nOpened(0), nWindowCloses(0), hashPrefixAnnouncement(0), nDenomination(0)
{
    strAbortReason = "not opened";
    prefixSigningHash.fill(0);
    prefixFinalizedRoot.fill(0);
}

int CMixRound::SeatFor(const CPubKey& pubkeySession) const
{
    for (size_t i = 0; i < vParticipants.size(); i++)
        if (vParticipants[i].pubkeySession == pubkeySession)
            return (int)i;
    return -1;
}

bool CMixRound::Require(MixRoundPhase nExpected, std::string* pstrError)
{
    if (nPhase != nExpected)
    {
        if (pstrError)
            *pstrError = strprintf("round is in phase %d, not %d", (int)nPhase, (int)nExpected);
        return false;
    }
    return true;
}

bool CMixRound::Open(const uint256& hashRoundIn, int nTargetParticipantsIn,
                     const std::vector<unsigned char>& vchRSA_N_In,
                     const std::vector<unsigned char>& vchRSA_E_In,
                     bool fStreamIsolatedIn, bool fAllowUnisolatedIn,
                     uint64_t nDenominationIn,
                     int64_t nNow, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    // Only a finished round is reusable: reopening a live one keeps its id and blind-signing
    // key, so old tokens and frames would still open.
    if (nPhase != MIX_PHASE_ABORTED && nPhase != MIX_PHASE_COMPLETE)
        FAIL("the round is still live; abort it before opening another");
    if (hashRoundIn == 0)
        FAIL("round identifier is zero");
    if (nTargetParticipantsIn < NULLSEND_MIN_PARTICIPANTS ||
        nTargetParticipantsIn > (int)iv5::MAX_NULLSEND_INPUTS)
        FAIL("participant count is outside the range a v2008 mix can carry");
    if (vchRSA_N_In.empty() || vchRSA_E_In.empty())
        FAIL("round has no blind-signature key");
    // Without stream isolation the coordinator sees the participant's real address at
    // every phase, so refuse rather than degrade silently.
    if (!fStreamIsolatedIn && !fAllowUnisolatedIn)
        FAIL("no stream isolation; a mix without it links every phase to one address");
    hashRound = hashRoundIn;
    nTargetParticipants = nTargetParticipantsIn;
    vchRSA_N = vchRSA_N_In;
    vchRSA_E = vchRSA_E_In;
    fStreamIsolated = fStreamIsolatedIn;
    fNoncesFrozen = false;
    fHasSigned = false;
    nOpened = nNow;
    nWindowCloses = 0;
    strAbortReason.clear();
    vParticipants.clear();
    vFinalKeyImages.clear();
    vOutputs.clear();
    vOutputCommitments.clear();
    vOutputMasks.clear();
    vOutputRecords.clear();
    vRoster.clear();
    vSpentCredentials.clear();
    vchFrozenPrefix.clear();
    prefixSigningHash.fill(0);
    prefixFinalizedRoot.fill(0);
    hashPrefixAnnouncement = 0;
    nDenomination = nDenominationIn;
    nPhase = MIX_PHASE_JOIN;
    return true;
    #undef FAIL
}

bool CMixRound::Join(const CPubKey& pubkeySession, const uint256& keyImage,
                     std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_JOIN, pstrError))
        return false;
    if (!pubkeySession.IsValid())
        FAIL("session key is not valid");
    if (keyImage == 0)
        FAIL("input has no key image");
    if ((int)vParticipants.size() >= nTargetParticipants)
        FAIL("round is full");
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
    // One seat per session key and one per note (key image).
        if (vParticipants[i].pubkeySession == pubkeySession)
            FAIL("session key already holds a seat");
        if (vParticipants[i].keyImage == keyImage)
            FAIL("key image already holds a seat");
    }
    CMixParticipant p;
    p.pubkeySession = pubkeySession;
    p.keyImage = keyImage;
    vParticipants.push_back(p);
    return true;
    #undef FAIL
}

bool CMixRound::CloseJoin(int64_t nNow, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_JOIN, pstrError))
        return false;
    if ((int)vParticipants.size() != nTargetParticipants)
        FAIL("round did not fill; the index binds the seats it announced");
    vFinalKeyImages.clear();
    for (size_t i = 0; i < vParticipants.size(); i++)
        vFinalKeyImages.push_back(vParticipants[i].keyImage);
    // Sorted in BYTE order, not uint256::operator<, to match PrivacyVNextChangeIndexFor;
    // otherwise the participant cannot see its own output.
    std::sort(vFinalKeyImages.begin(), vFinalKeyImages.end(),
              [](const uint256& a, const uint256& b) {
                  return std::lexicographical_compare(a.begin(), a.end(),
                                                      b.begin(), b.end());
              });
    // The roster is the same freeze seen as (key image, session key) pairs. It is built
    // here so nothing can present a different set of signers for the same input set.
    {
        std::vector<CMixRosterEntry> vRaw;
        for (size_t i = 0; i < vParticipants.size(); i++)
        {
            CMixRosterEntry e;
            e.keyImage = vParticipants[i].keyImage;
            e.pubkeySession = vParticipants[i].pubkeySession;
            vRaw.push_back(e);
        }
        if (!BuildMixRoster(vRaw, vRoster))
            FAIL("the seats do not form a roster of distinct key images and session keys");
    }

    // Each seat learns its position in that set now, before any nonce exists. The
    // joint signature reads the nonce points in this order, so it cannot be settled
    // later by whoever happens to submit first.
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        vParticipants[i].nInputIndex = -1;
        for (size_t j = 0; j < vFinalKeyImages.size(); j++)
            if (vFinalKeyImages[j] == vParticipants[i].keyImage)
                vParticipants[i].nInputIndex = (int)j;
    }
    nPhase = MIX_PHASE_KEYED;
    (void)nNow;
    return true;
    #undef FAIL
}

bool CMixRound::IssueToken(const CPubKey& pubkeySession, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_KEYED, pstrError))
        return false;
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        if (!(vParticipants[i].pubkeySession == pubkeySession))
            continue;
        if (vParticipants[i].fTokenIssued)
            FAIL("participant already holds a token");
        vParticipants[i].fTokenIssued = true;
        return true;
    }
    FAIL("no seat under that session key");
    #undef FAIL
}

uint256 CMixRound::ViewDigest(const uint256& hashAnnouncement) const
{
    if (vRoster.empty() || vRoster.size() != vParticipants.size())
        return 0;
    return MixViewDigest(hashAnnouncement, vRoster);
}

bool CMixRound::SubmitViewSignature(const CPubKey& pubkeySession,
                                    const uint256& hashAnnouncement,
                                    const std::vector<unsigned char>& vchSig,
                                    std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (nPhase == MIX_PHASE_JOIN)
        FAIL("the roster is not frozen yet");
    if (nPhase == MIX_PHASE_ABORTED || nPhase == MIX_PHASE_COMPLETE)
        FAIL("the round is over");
    const uint256 hashView = ViewDigest(hashAnnouncement);
    if (hashView == 0)
        FAIL("the round has no view to sign");
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        if (!(vParticipants[i].pubkeySession == pubkeySession))
            continue;
        // One view per seat per attempt. Accepting a second, over any view, would let a
        // coordinator that showed two seats two views still collect a full certificate.
        if (!vParticipants[i].vchViewSig.empty())
            FAIL("that seat has already signed a view");
        if (!pubkeySession.Verify(hashView, vchSig))
            FAIL("the signature does not verify over this round's view");
        vParticipants[i].vchViewSig = vchSig;
        return true;
    }
    FAIL("that key holds no seat");
    #undef FAIL
}

bool CMixRound::SubmitInputConstruction(const CPubKey& pubkeySession,
                                        const uint256& hashAnnouncement,
                                        const uint256& keyImage,
                                        const PrivacyVNextDigest& pseudoOut,
                                        std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_KEYED, pstrError))
        return false;
    if (!ViewAgreed(hashAnnouncement))
        FAIL("the seats have not all signed this view");
    PrivacyVNextDigest zero;
    zero.fill(0);
    if (pseudoOut == zero)
        FAIL("the construction carries no pseudo-output");
    for (size_t i = 0; i < vParticipants.size(); i++)
        if (vParticipants[i].fHavePseudoOut && vParticipants[i].pseudoOut == pseudoOut)
            FAIL("that pseudo-output is already submitted");
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        if (!(vParticipants[i].pubkeySession == pubkeySession))
            continue;
        if (vParticipants[i].keyImage != keyImage)
            FAIL("the construction names a key image this seat did not join with");
        if (vParticipants[i].fHavePseudoOut)
            FAIL("that seat has already submitted its construction");
        vParticipants[i].pseudoOut = pseudoOut;
        vParticipants[i].fHavePseudoOut = true;
        return true;
    }
    FAIL("that key holds no seat");
    #undef FAIL
}

bool CMixRound::AssemblePrefix(const PrivacyVNextPrefixHeader& header,
                               std::vector<unsigned char>& vchPrefixOut,
                               std::string* pstrError) const
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vchPrefixOut.clear();
    if (nPhase != MIX_PHASE_OUTPUT && nPhase != MIX_PHASE_SIGN)
        FAIL("the round has not reached its outputs");
    if (!iv5::IsNullSendOperation(header.nOperation))
        FAIL("a mix prefix names the NullSend operation");
    if (header.nDisclosureMask != iv5::NULLSEND_DISCLOSURE_MASK)
        FAIL("a mix prefix discloses amounts and nothing else");
    if (header.nTransparentValueBalance != 0)
        FAIL("nothing crosses the transparent boundary in a mix");
    if (header.pVoteBoundaryHash != NULL)
        FAIL("a mix names no vote boundary");
    const std::vector<PrivacyVNextDigest> vPseudoOuts = PseudoOutsInInputOrder();
    if (vPseudoOuts.empty() || vPseudoOuts.size() != vFinalKeyImages.size())
        FAIL("not every input construction is in");
    if (vOutputRecords.size() != vParticipants.size())
        FAIL("not every output is registered");

    std::vector<PrivacyVNextPrefixInput> vInputs(vPseudoOuts.size());
    for (size_t i = 0; i < vInputs.size(); i++)
    {
        vInputs[i].pseudoOut = vPseudoOuts[i];
        memcpy(vInputs[i].keyImage.data(), vFinalKeyImages[i].begin(), 32);
        vInputs[i].senderAuthority.fill(0);
    }
    std::vector<PrivacyVNextPrefixOutput> vOutputs(vOutputRecords.size());
    for (size_t i = 0; i < vOutputs.size(); i++)
    {
        const CMixOutputRecord& record = vOutputRecords[i];
        vOutputs[i].owner = record.owner;
        vOutputs[i].commitment = record.commitment;
        vOutputs[i].noteEphemeral = record.noteEphemeral;
        vOutputs[i].tweakEphemeral = record.tweakEphemeral;
        vOutputs[i].vchRecipientCiphertext = record.vchRecipientCiphertext;
        vOutputs[i].vchOutgoingCiphertext = record.vchOutgoingCiphertext;
        vOutputs[i].recipientSpend.fill(0);
        vOutputs[i].recipientView.fill(0);
        vOutputs[i].nAmount = nDenomination;
        vOutputs[i].mask = record.mask;
    }
    std::string strAssemble;
    if (!AssemblePrivacyVNextPayloadPrefix(header, vInputs, vOutputs, vchPrefixOut, strAssemble))
        FAIL(strAssemble);
    return true;
    #undef FAIL
}

bool CMixRound::FreezePrefix(const PrivacyVNextPrefixHeader& header,
                             const uint256& hashAnnouncement, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_SIGN, pstrError))
        return false;
    if (!vchFrozenPrefix.empty())
        FAIL("the prefix is already frozen");
    for (size_t i = 0; i < vParticipants.size(); i++)
        if (!vParticipants[i].vchNonce.empty())
            FAIL("a nonce is already in; the prefix must be agreed before any nonce");
    if (!ViewAgreed(hashAnnouncement))
        FAIL("the seats have not all signed this view");
    if (!(header.transparentBinding == MixTransparentBinding()))
        FAIL("a mix prefix carries the binding of a transaction with no transparent side");
    std::vector<unsigned char> vchPrefix;
    if (!AssemblePrefix(header, vchPrefix, pstrError))
        return false;
    PrivacyVNextDigest signingHash;
    std::string strHash;
    if (!HashPrivacyVNextPayloadPrefix(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vchPrefix,
                                       signingHash, strHash))
        FAIL(strHash);
    vchFrozenPrefix = vchPrefix;
    prefixSigningHash = signingHash;
    prefixFinalizedRoot = header.finalizedRoot;
    hashPrefixAnnouncement = hashAnnouncement;
    return true;
    #undef FAIL
}

uint256 CMixRound::PrefixDigest() const
{
    if (vchFrozenPrefix.empty())
        return 0;
    const uint256 hashView = ViewDigest(hashPrefixAnnouncement);
    if (hashView == 0)
        return 0;
    return MixPrefixDigest(hashView, prefixSigningHash);
}

bool CMixRound::SubmitPrefixSignature(const CPubKey& pubkeySession,
                                      const std::vector<unsigned char>& vchSig,
                                      std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_SIGN, pstrError))
        return false;
    const uint256 hashPrefix = PrefixDigest();
    if (hashPrefix == 0)
        FAIL("no prefix is frozen");
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        if (!(vParticipants[i].pubkeySession == pubkeySession))
            continue;
        if (!vParticipants[i].vchPrefixSig.empty())
            FAIL("that seat has already approved the prefix");
        if (!pubkeySession.Verify(hashPrefix, vchSig))
            FAIL("the signature does not verify over the frozen prefix");
        vParticipants[i].vchPrefixSig = vchSig;
        return true;
    }
    FAIL("that key holds no seat");
    #undef FAIL
}

bool CMixRound::PrefixAgreed() const
{
    const uint256 hashPrefix = PrefixDigest();
    if (hashPrefix == 0 || vParticipants.empty())
        return false;
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        if (vParticipants[i].vchPrefixSig.empty())
            return false;
        if (!vParticipants[i].pubkeySession.Verify(hashPrefix, vParticipants[i].vchPrefixSig))
            return false;
    }
    return true;
}

bool CMixRound::SubmitMembershipProof(const CPubKey& pubkeySession,
                                      const std::vector<unsigned char>& vchProof,
                                      std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_SIGN, pstrError))
        return false;
    if (!PrefixAgreed())
        FAIL("the seats have not all approved the prefix");
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        if (!(vParticipants[i].pubkeySession == pubkeySession))
            continue;
        if (!vParticipants[i].vchMembershipProof.empty())
            FAIL("that seat has already proved its input");
        if (!vParticipants[i].fHavePseudoOut)
            FAIL("that seat has no construction to prove");
        PrivacyVNextDigest keyImage;
        memcpy(keyImage.data(), vParticipants[i].keyImage.begin(), 32);
        std::string strVerify;
        if (!VerifyPrivacyVNextInputMembership(prefixFinalizedRoot, prefixSigningHash,
                                               vParticipants[i].pseudoOut, keyImage, vchProof,
                                               strVerify))
            FAIL("the membership proof does not verify for this seat's input under the approved prefix");
        vParticipants[i].vchMembershipProof = vchProof;
        return true;
    }
    FAIL("that key holds no seat");
    #undef FAIL
}

bool CMixRound::MembershipProofsComplete() const
{
    if (vParticipants.empty())
        return false;
    for (size_t i = 0; i < vParticipants.size(); i++)
        if (vParticipants[i].vchMembershipProof.empty())
            return false;
    return true;
}

std::vector<unsigned char> CMixRound::MembershipSection() const
{
    std::vector<unsigned char> vchOut;
    if (!MembershipProofsComplete())
        return vchOut;
    for (size_t k = 0; k < vFinalKeyImages.size(); k++)
    {
        size_t nFound = 0;
        for (size_t i = 0; i < vParticipants.size(); i++)
        {
            if (vParticipants[i].keyImage != vFinalKeyImages[k])
                continue;
            vchOut.insert(vchOut.end(), vParticipants[i].vchMembershipProof.begin(),
                          vParticipants[i].vchMembershipProof.end());
            nFound++;
        }
        if (nFound != 1)
            return std::vector<unsigned char>();
    }
    return vchOut;
}

bool CMixRound::AssemblePayload(std::vector<unsigned char>& vchPayloadOut,
                                std::string* pstrError) const
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vchPayloadOut.clear();
    if (!SigningComplete())
        FAIL("not every seat has responded under the fixed aggregate");
    if (!PrefixAgreed())
        FAIL("the seats have not all approved the prefix");
    const std::vector<unsigned char> vchMembership = MembershipSection();
    if (vchMembership.empty())
        FAIL("not every seat has proved its input");
    CMixPrefixView view;
    std::string strParse;
    if (!ParseMixPrefix(vchFrozenPrefix, view, strParse))
        FAIL(strParse);

    PrivacyVNextMixBalanceFacts facts;
    facts.nInputCount = (uint8_t)view.vPseudoOuts.size();
    facts.nOutputCount = (uint8_t)view.vOutputs.size();
    facts.nTransparentValueBalance = view.nTransparentValueBalance;
    facts.nFee = view.nFee;
    facts.signableHash = prefixSigningHash;
    facts.vPseudoOuts = view.vPseudoOuts;
    std::vector<PrivacyVNextDigest> vOutputMasks;
    for (size_t i = 0; i < view.vOutputs.size(); i++)
    {
        facts.vOutputs.push_back(view.vOutputs[i].commitment);
        vOutputMasks.push_back(view.vOutputs[i].mask);
    }
    const std::vector<std::vector<unsigned char> > vNonceBytes = NoncesInInputOrder();
    const std::vector<std::vector<unsigned char> > vResponseBytes = ResponsesInInputOrder();
    if (vNonceBytes.size() != view.vPseudoOuts.size() ||
        vResponseBytes.size() != view.vPseudoOuts.size())
        FAIL("the shares do not cover every input");
    std::vector<PrivacyVNextDigest> vNonces(vNonceBytes.size()), vResponses(vResponseBytes.size());
    for (size_t i = 0; i < vNonceBytes.size(); i++)
    {
        if (vNonceBytes[i].size() != 32 || vResponseBytes[i].size() != 32)
            FAIL("a share is not 32 bytes");
        memcpy(vNonces[i].data(), &vNonceBytes[i][0], 32);
        memcpy(vResponses[i].data(), &vResponseBytes[i][0], 32);
    }
    std::vector<unsigned char> vchBalance;
    std::string strCombine;
    if (!PrivacyVNextMixBalanceCombine(facts, vNonces, vResponses, vOutputMasks, vchBalance,
                                       strCombine))
        FAIL("the joint balance proof does not verify: " + strCombine);

    std::vector<unsigned char> vchPayload = vchFrozenPrefix;
    PutMixCompactSize(vchPayload, vchMembership.size());
    vchPayload.insert(vchPayload.end(), vchMembership.begin(), vchMembership.end());
    PutMixCompactSize(vchPayload, 0);   // range: amounts are disclosed
    PutMixCompactSize(vchPayload, vchBalance.size());
    vchPayload.insert(vchPayload.end(), vchBalance.begin(), vchBalance.end());
    PutMixCompactSize(vchPayload, 0);   // operation proof
    PutMixCompactSize(vchPayload, 0);   // disclosure proofs: senders and receivers hidden

    const PrivacyVNextPayloadValidation validation =
        ValidatePrivacyVNextPayload(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vchPayload);
    if (validation.nResult != INNOVA_PRIVACY_VNEXT_VALID)
        FAIL("the assembled payload does not validate: " + validation.strError);
    vchPayloadOut.swap(vchPayload);
    return true;
    #undef FAIL
}

std::vector<std::vector<unsigned char> > CMixRound::ViewCertificate(
    const uint256& hashAnnouncement) const
{
    std::vector<std::vector<unsigned char> > vOut;
    if (!ViewAgreed(hashAnnouncement))
        return vOut;
    vOut.resize(vParticipants.size());
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        const CMixParticipant& p = vParticipants[i];
        if (p.nInputIndex < 0 || p.nInputIndex >= (int)vOut.size())
            return std::vector<std::vector<unsigned char> >();
        vOut[p.nInputIndex] = p.vchViewSig;
    }
    return vOut;
}

std::vector<std::vector<unsigned char> > CMixRound::PrefixCertificate() const
{
    std::vector<std::vector<unsigned char> > vOut;
    if (!PrefixAgreed())
        return vOut;
    vOut.resize(vParticipants.size());
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        const CMixParticipant& p = vParticipants[i];
        if (p.nInputIndex < 0 || p.nInputIndex >= (int)vOut.size())
            return std::vector<std::vector<unsigned char> >();
        vOut[p.nInputIndex] = p.vchPrefixSig;
    }
    return vOut;
}

bool CMixRound::MarkComplete(std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (nPhase == MIX_PHASE_COMPLETE)
        return true;
    if (!Require(MIX_PHASE_SIGN, pstrError))
        return false;
    if (vchFrozenPrefix.empty() || !SigningComplete())
        FAIL("the round has no finished signature to complete over");
    nPhase = MIX_PHASE_COMPLETE;
    return true;
    #undef FAIL
}

bool CMixRound::InputConstructionsComplete() const
{
    if (vParticipants.empty())
        return false;
    for (size_t i = 0; i < vParticipants.size(); i++)
        if (!vParticipants[i].fHavePseudoOut)
            return false;
    return true;
}

std::vector<PrivacyVNextDigest> CMixRound::PseudoOutsInInputOrder() const
{
    std::vector<PrivacyVNextDigest> vOut;
    if (!InputConstructionsComplete())
        return vOut;
    vOut.resize(vParticipants.size());
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        const int nIndex = vParticipants[i].nInputIndex;
        if (nIndex < 0 || (size_t)nIndex >= vOut.size())
            return std::vector<PrivacyVNextDigest>();
        vOut[nIndex] = vParticipants[i].pseudoOut;
    }
    return vOut;
}

bool CMixRound::ViewAgreed(const uint256& hashAnnouncement) const
{
    const uint256 hashView = ViewDigest(hashAnnouncement);
    if (hashView == 0)
        return false;
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        if (vParticipants[i].vchViewSig.empty())
            return false;
        if (!vParticipants[i].pubkeySession.Verify(hashView,
                                                   vParticipants[i].vchViewSig))
            return false;
    }
    return !vParticipants.empty();
}

bool CMixRound::OpenOutputWindow(int64_t nNow, int64_t nClosesAt, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_KEYED, pstrError))
        return false;
    for (size_t i = 0; i < vParticipants.size(); i++)
        if (!vParticipants[i].fTokenIssued)
            FAIL("a seat holds no token; it could not register an output");
    if (nClosesAt < nNow + MIX_OUTPUT_WINDOW)
        FAIL("the output window is shorter than a registration is given");
    nWindowCloses = nClosesAt;
    nPhase = MIX_PHASE_OUTPUT;
    return true;
    #undef FAIL
}

bool CMixRound::RegisterOutput(const std::vector<unsigned char>& vchCredential,
                               const std::vector<unsigned char>& vchBlindSignature,
                               const std::vector<CMixOutputRecord>& vBundle,
                               int64_t nNow,
                               std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_OUTPUT, pstrError))
        return false;
    // One variant per position. The registrant cannot choose which one is kept: a caller
    // that could would be choosing which seat's slot it takes, and every other variant is
    // useless to it anyway, because the encryption binds the position.
    if (vBundle.size() != vParticipants.size())
        FAIL("a bundle carries one variant per seat");
    if (vchCredential.empty() || vchBlindSignature.empty())
        FAIL("output carries no token");
    // The token names the whole bundle, so any in-flight rewrite fails to open. Tokens from
    // another round fail the signature check (per-round modulus), so the round is not in
    // the message. Checked first: arithmetic-free.
    const uint256 hashExpected = MixOutputBundleCredentialHash(vBundle);
    if (hashExpected == 0)
        FAIL("output bundle is not the shape a payload carries");
    if (vchCredential.size() != 32 ||
        !std::equal(hashExpected.begin(), hashExpected.end(), vchCredential.begin()))
        FAIL("token does not authorise this output bundle in this round");
    if (!VerifyMixCredential(vchRSA_N, vchRSA_E, vchCredential, vchBlindSignature))
        FAIL("token does not verify under the round key");

    // A repeat of the SAME token is a retransmission, answered as such (the credential is
    // the bundle hash). Checked after the signature and before round progress, since the
    // next position may be taken by the time a retry lands.
    CHashWriter ss(SER_GETHASH, 0);
    ss << vchCredential;
    const uint256 hashCredential = ss.GetHash();
    for (size_t i = 0; i < vSpentCredentials.size(); i++)
        if (vSpentCredentials[i] == hashCredential)
            return true;

    if (nNow > nWindowCloses)
        FAIL("the output window has closed");
    if (vOutputs.size() >= vParticipants.size())
        FAIL("every seat already has an output");
    const size_t nPosition = vOutputRecords.size();
    const CMixOutputRecord& record = vBundle[nPosition];
    const uint256 outputKey = record.OwnerKey();
    const PrivacyVNextDigest& commitment = record.commitment;
    const PrivacyVNextDigest& mask = record.mask;
    if (outputKey == 0)
        FAIL("output has no key");
    // Check the kept variant's opening BEFORE spending the token: blind signing cannot see
    // it, and the combiner sees only the sum. A round with no denomination registers nothing.
    if (nDenomination == 0)
        FAIL("the round carries no denomination, so an opening cannot be checked");
    if (!MixOpeningOpens(nDenomination, mask, commitment))
        FAIL("output opening does not open the commitment it is registered with");
    for (size_t i = 0; i < vOutputCommitments.size(); i++)
        if (vOutputCommitments[i] == commitment)
            FAIL("that output commitment is already registered");
    for (size_t i = 0; i < vOutputs.size(); i++)
        if (vOutputs[i] == outputKey)
            FAIL("output key is already registered");
    vSpentCredentials.push_back(hashCredential);
    vOutputs.push_back(outputKey);
    vOutputCommitments.push_back(commitment);
    vOutputMasks.push_back(mask);
    vOutputRecords.push_back(record);

    return true;
    #undef FAIL
}

bool CMixRound::CanPublish(int64_t nNow) const
{
    if (nPhase != MIX_PHASE_OUTPUT)
        return false;
    if (vOutputs.size() != vParticipants.size())
        return false;
    // The window decorrelates arrival from publication order for outside observers only;
    // the coordinator sees every arrival.
    return nNow > nWindowCloses;
}

void CMixRound::Drop(const CPubKey& pubkeySession)
{
    if (nPhase == MIX_PHASE_COMPLETE || nPhase == MIX_PHASE_ABORTED)
        return;
    // Membership before phase. Past JOIN a drop ends the round, so a key that holds no
    // seat could otherwise abort a round it never joined -- a one-frame denial of
    // service against every other participant.
    size_t nSeat = vParticipants.size();
    for (size_t i = 0; i < vParticipants.size(); i++)
        if (vParticipants[i].pubkeySession == pubkeySession)
        {
            nSeat = i;
            break;
        }
    if (nSeat == vParticipants.size())
        return;
    if (nPhase != MIX_PHASE_JOIN)
    {
        // The self-pay index binds the key image set, so losing a seat re-points
        // every participant's output. Carrying on would build a payload whose
        // outputs sit at an index nobody derived.
        Abort("a seat was lost after the input set was frozen");
        return;
    }
    vParticipants.erase(vParticipants.begin() + nSeat);
}

void CMixRound::Abort(const std::string& strReason)
{
    nPhase = MIX_PHASE_ABORTED;
    strAbortReason = strReason;
}

bool CMixRound::OpenSigning(int64_t nNow, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    // A round signs once: a second signing with different nonce points lets the coordinator
    // recover a mask. No retry path by design.
    if (fHasSigned)
    {
        Abort("signing was opened twice; a second aggregate would solve for a share");
        FAIL("signing was opened twice");
    }
    if (!Require(MIX_PHASE_OUTPUT, pstrError))
        return false;
    if (!CanPublish(nNow))
        FAIL("the output set is not final; the signable hash covers it");
    fHasSigned = true;
    nPhase = MIX_PHASE_SIGN;
    return true;
    #undef FAIL
}

bool CMixRound::SubmitNonce(const CPubKey& pubkeySession,
                            const std::vector<unsigned char>& vchNonce,
                            std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_SIGN, pstrError))
        return false;
    if (fNoncesFrozen)
        FAIL("the aggregate is fixed; a nonce cannot move under it");
    if (vchNonce.size() != 32)
        FAIL("a nonce point is 32 bytes");
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        if (!(vParticipants[i].pubkeySession == pubkeySession))
            continue;
        if (!vParticipants[i].vchNonce.empty())
            FAIL("seat already published a nonce");
        vParticipants[i].vchNonce = vchNonce;
        return true;
    }
    FAIL("no seat under that session key");
    #undef FAIL
}

bool CMixRound::FreezeNonces(std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_SIGN, pstrError))
        return false;
    if (fNoncesFrozen)
        FAIL("the aggregate is already fixed");
    for (size_t i = 0; i < vParticipants.size(); i++)
        if (vParticipants[i].vchNonce.empty())
            FAIL("a seat has not published a nonce; the aggregate is incomplete");
    fNoncesFrozen = true;
    return true;
    #undef FAIL
}

bool CMixRound::SubmitResponse(const CPubKey& pubkeySession,
                               const std::vector<unsigned char>& vchResponse,
                               std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_SIGN, pstrError))
        return false;
    // A response under an aggregate that is not yet fixed is a response under a
    // challenge that can still move, which is the second signature the guard exists
    // to refuse.
    if (!fNoncesFrozen)
        FAIL("the aggregate is not fixed; there is no challenge to respond under");
    if (vchResponse.size() != 32)
        FAIL("a response is 32 bytes");
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        if (!(vParticipants[i].pubkeySession == pubkeySession))
            continue;
        if (!vParticipants[i].vchResponse.empty())
            FAIL("seat already responded");
        vParticipants[i].vchResponse = vchResponse;
        return true;
    }
    FAIL("no seat under that session key");
    #undef FAIL
}

bool CMixRound::SigningComplete() const
{
    if (nPhase != MIX_PHASE_SIGN || !fNoncesFrozen)
        return false;
    for (size_t i = 0; i < vParticipants.size(); i++)
        if (vParticipants[i].vchResponse.empty())
            return false;
    return true;
}

std::vector<std::vector<unsigned char> > CMixRound::NoncesInInputOrder() const
{
    std::vector<std::vector<unsigned char> > vOut(vParticipants.size());
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        const CMixParticipant& p = vParticipants[i];
        if (p.nInputIndex < 0 || p.nInputIndex >= (int)vOut.size() || p.vchNonce.empty())
            return std::vector<std::vector<unsigned char> >();
        vOut[p.nInputIndex] = p.vchNonce;
    }
    return vOut;
}

std::vector<std::vector<unsigned char> > CMixRound::ResponsesInInputOrder() const
{
    std::vector<std::vector<unsigned char> > vOut(vParticipants.size());
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        const CMixParticipant& p = vParticipants[i];
        if (p.nInputIndex < 0 || p.nInputIndex >= (int)vOut.size() || p.vchResponse.empty())
            return std::vector<std::vector<unsigned char> >();
        vOut[p.nInputIndex] = p.vchResponse;
    }
    return vOut;
}

bool CMixRound::IsExpired(int64_t nNow, int64_t nEnds) const
{
    if (nPhase == MIX_PHASE_COMPLETE || nPhase == MIX_PHASE_ABORTED)
        return false;
    return nNow > nEnds;
}

// ---------------------------------------------------------------------------
// Framed connections
// ---------------------------------------------------------------------------

CMixStream::CMixStream() : hSocket(INVALID_SOCKET) {}

CMixStream::~CMixStream()
{
    Close();
}

void CMixStream::Adopt(SOCKET hSocketIn)
{
    Close();
    hSocket = hSocketIn;
    vchBuffer.clear();
}

void CMixStream::Close()
{
    if (hSocket != INVALID_SOCKET)
        CloseSocket(hSocket);
    hSocket = INVALID_SOCKET;
    vchBuffer.clear();
}

bool CMixStream::Send(MixFrameType nType, const std::vector<unsigned char>& vchPayload,
                      std::string* pstrError, int nTimeoutMs)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (hSocket == INVALID_SOCKET)
        FAIL("stream is not open");
    std::vector<unsigned char> vchFrame;
    if (!BuildMixFrame(nType, vchPayload, vchFrame))
        FAIL("frame has no encoding");
    // The deadline bounds the FRAME, as the reader's does. A peer that stops reading
    // otherwise holds this thread in send() for as long as it likes.
    const int64_t nNow = GetTimeMillis();
    const int64_t nBudget = nTimeoutMs > 0 ? (int64_t)nTimeoutMs : 0;
    const int64_t nDeadline =
        (nNow > std::numeric_limits<int64_t>::max() - nBudget)
            ? std::numeric_limits<int64_t>::max()
            : nNow + nBudget;
    size_t nSent = 0;
    while (nSent < vchFrame.size())
    {
        const int nSlice = MixReceiveSliceMs(nDeadline, GetTimeMillis());
        if (nSlice <= 0)
            FAIL("the peer did not take the frame before the deadline");
        SetSocketSendTimeout(hSocket, nSlice);
        const ssize_t nWrote = send(hSocket, (const char*)&vchFrame[nSent],
                                    vchFrame.size() - nSent, MSG_NOSIGNAL);
        if (nWrote > 0)
        {
            nSent += (size_t)nWrote;
            continue;
        }
        if (nWrote == 0)
            FAIL("the peer went away mid-frame");
#ifndef WIN32
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            FAIL("the peer did not take the frame before the deadline");
#endif
        FAIL("the peer went away mid-frame");
    }
    return true;
    #undef FAIL
}

int MixReceiveSliceMs(int64_t nDeadlineMs, int64_t nNowMs);

int MixReceiveSliceMs(int64_t nDeadlineMs, int64_t nNowMs)
{
    if (nNowMs >= nDeadlineMs)
        return 0;
    // Unsigned: the signed difference can overflow; the order above guarantees it is positive.
    const uint64_t nLeft = (uint64_t)nDeadlineMs - (uint64_t)nNowMs;
    return nLeft > 0x7fffffffULL ? 0x7fffffff : (int)nLeft;
}

bool CMixStream::Receive(MixFrameType& nTypeOut, std::vector<unsigned char>& vchPayloadOut,
                         int nTimeoutMs, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    nTypeOut = MIX_FRAME_NONE;
    vchPayloadOut.clear();
    if (hSocket == INVALID_SOCKET)
        FAIL("stream is not open");

    // The deadline bounds the whole FRAME, not each recv; saturating.
    const int64_t nNow = GetTimeMillis();
    const int64_t nBudget = nTimeoutMs > 0 ? (int64_t)nTimeoutMs : 0;
    const int64_t nDeadline =
        (nNow > std::numeric_limits<int64_t>::max() - nBudget)
            ? std::numeric_limits<int64_t>::max()
            : nNow + nBudget;

    const size_t nCeiling = MIX_FRAME_HEADER_BYTES + MIX_FRAME_MAX_PAYLOAD;
    while (true)
    {
        size_t nConsumed = 0;
        const MixFrameDecode nDecode =
            ReadMixFrame(vchBuffer, nTypeOut, vchPayloadOut, nConsumed);
        if (nDecode == MIX_DECODE_OK)
        {
            vchBuffer.erase(vchBuffer.begin(), vchBuffer.begin() + nConsumed);
            return true;
        }
        if (nDecode == MIX_DECODE_INVALID)
            FAIL("the peer sent something that is not a frame");
        // Incomplete. A buffer already holding a whole maximum frame's worth without
        // decoding one cannot be waiting on a legal frame.
        if (vchBuffer.size() >= nCeiling)
            FAIL("the peer sent more than one frame's worth without a frame in it");
        const int nSlice = MixReceiveSliceMs(nDeadline, GetTimeMillis());
        if (nSlice <= 0)
            FAIL("the peer did not finish a frame before the deadline");
        // Portably: Winsock reads a DWORD of milliseconds here, so a timeval would set
        // the timeout to tv_sec and a sub-second slice would arm a non-blocking socket.
        SetSocketReceiveTimeout(hSocket, nSlice);
        unsigned char pchRead[4096];
        const ssize_t nRead = recv(hSocket, (char*)pchRead, sizeof(pchRead), 0);
        if (nRead == 0)
            FAIL("the peer closed the connection");
        if (nRead < 0)
        {
#ifndef WIN32
            // A signal is not the deadline. The deadline above still bounds the loop.
            if (errno == EINTR)
                continue;
#endif
            FAIL("the peer sent nothing before the deadline");
        }
        vchBuffer.insert(vchBuffer.end(), pchRead, pchRead + nRead);
    }
    #undef FAIL
}

CMixListener::CMixListener() : hListen(INVALID_SOCKET), nBoundPort(0) {}

CMixListener::~CMixListener()
{
    Close();
}

void CMixListener::Close()
{
    if (hListen != INVALID_SOCKET)
        CloseSocket(hListen);
    hListen = INVALID_SOCKET;
    nBoundPort = 0;
}

bool CMixListener::Listen(int nPort, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); Close(); return false; } while (0)
    Close();
    if (nPort < 0 || nPort > 0xFFFF)
        FAIL("listen port is out of range");
    hListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hListen == INVALID_SOCKET)
        FAIL("could not create a listening socket");
#ifndef WIN32
    int nOne = 1;
    setsockopt(hListen, SOL_SOCKET, SO_REUSEADDR, (void*)&nOne, sizeof(int));
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)nPort);
    if (::bind(hListen, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
        FAIL("could not bind the mix listener");
    if (::listen(hListen, 32) == SOCKET_ERROR)
        FAIL("could not listen on the mix port");
    socklen_t nLen = sizeof(addr);
    if (getsockname(hListen, (struct sockaddr*)&addr, &nLen) == SOCKET_ERROR)
        FAIL("could not read back the bound port");
    nBoundPort = ntohs(addr.sin_port);
    return true;
    #undef FAIL
}

bool CMixListener::Accept(CMixStream& streamOut, int nTimeoutMs, std::string* pstrError)
{
    streamOut.Close();
    if (pstrError)
        pstrError->clear();
    if (hListen == INVALID_SOCKET)
    {
        if (pstrError)
            *pstrError = "the listener is not open";
        return false;
    }
    // One wait, one connection. A service loop calls this on its tick, so an expiry is
    // the ordinary case and carries no error: only a broken listener does.
    struct timeval tv;
    tv.tv_sec = nTimeoutMs / 1000;
    tv.tv_usec = (nTimeoutMs % 1000) * 1000;
    fd_set setRead;
    FD_ZERO(&setRead);
    FD_SET(hListen, &setRead);
    const int nReady = select(hListen + 1, &setRead, NULL, NULL, &tv);
    if (nReady == 0)
        return false;
    if (nReady < 0)
    {
#ifndef WIN32
        if (errno == EINTR)
            return false;
#endif
        if (pstrError)
            *pstrError = "the mix listener failed while waiting";
        return false;
    }
    const SOCKET hAccepted = accept(hListen, NULL, NULL);
    if (hAccepted == INVALID_SOCKET)
    {
        if (pstrError)
            *pstrError = "the mix listener could not accept a connection";
        return false;
    }
    streamOut.Adopt(hAccepted);
    return true;
}

bool DialMixPhase(const CService& addrProxy, const std::string& strEndpoint, int nPort,
                  bool fIsolate, int nTimeoutMs, CMixStream& streamOut,
                  std::string* pstrError)
{
    streamOut.Close();
    SOCKET hSocket = INVALID_SOCKET;
    bool fDialed = false;
    if (fIsolate)
    {
        // A fresh pair per phase. Reusing one would put every phase on one circuit,
        // which is the same exit address, which is the mapping this is here to deny.
        const ProxyCredentials auth = RandomProxyCredentials();
        fDialed = ConnectSocks5ByName(addrProxy, strEndpoint, nPort, hSocket, nTimeoutMs, &auth);
    }
    else
    {
        fDialed = ConnectSocks5ByName(addrProxy, strEndpoint, nPort, hSocket, nTimeoutMs);
    }
    if (!fDialed)
    {
        if (pstrError)
            *pstrError = "could not reach the coordinator";
        return false;
    }
    streamOut.Adopt(hSocket);
    return true;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

namespace {

void PutU16(std::vector<unsigned char>& vch, size_t n)
{
    vch.push_back((unsigned char)(n & 0xFF));
    vch.push_back((unsigned char)((n >> 8) & 0xFF));
}

bool TakeU16(const std::vector<unsigned char>& vch, size_t& nAt, size_t& nOut)
{
    if (nAt + 2 > vch.size())
        return false;
    nOut = (size_t)vch[nAt] | ((size_t)vch[nAt + 1] << 8);
    nAt += 2;
    return true;
}

bool TakeBytes(const std::vector<unsigned char>& vch, size_t& nAt, size_t nLen,
               std::vector<unsigned char>& vchOut)
{
    if (nAt + nLen > vch.size())
        return false;
    vchOut.assign(vch.begin() + nAt, vch.begin() + nAt + nLen);
    nAt += nLen;
    return true;
}

const size_t MIX_SESSION_PUBKEY_BYTES = 33;

bool TakeSessionKey(const std::vector<unsigned char>& vchBody, size_t& nAt, CPubKey& pubkeyOut)
{
    std::vector<unsigned char> vchKey;
    if (!TakeBytes(vchBody, nAt, MIX_SESSION_PUBKEY_BYTES, vchKey))
        return false;
    pubkeyOut = CPubKey(vchKey);
    return pubkeyOut.IsValid();
}

} // namespace

bool SplitAuthedMixFrame(const std::vector<unsigned char>& vchPayload,
                         std::vector<unsigned char>& vchBodyOut,
                         std::vector<unsigned char>& vchSigOut)
{
    vchBodyOut.clear();
    vchSigOut.clear();
    if (vchPayload.empty())
        return false;
    const size_t nSigLen = vchPayload.back();
    if (nSigLen == 0 || nSigLen + 1 > vchPayload.size())
        return false;
    const size_t nBody = vchPayload.size() - 1 - nSigLen;
    vchBodyOut.assign(vchPayload.begin(), vchPayload.begin() + nBody);
    vchSigOut.assign(vchPayload.begin() + nBody, vchPayload.end() - 1);
    return true;
}

bool BuildAuthedMixFrame(const CKey& key, const uint256& hashRound, MixFrameType nType,
                         const std::vector<unsigned char>& vchBody,
                         std::vector<unsigned char>& vchPayloadOut)
{
    vchPayloadOut.clear();
    std::vector<unsigned char> vchSig;
    // The signature is over the body under this round and this frame type, so a
    // message cannot be lifted into another round or presented as another phase.
    if (!SignMixSessionFrame(key, hashRound, nType, vchBody, vchSig))
        return false;
    if (vchSig.empty() || vchSig.size() > 255)
        return false;
    vchPayloadOut = vchBody;
    vchPayloadOut.insert(vchPayloadOut.end(), vchSig.begin(), vchSig.end());
    vchPayloadOut.push_back((unsigned char)vchSig.size());
    return true;
}

bool BuildMixJoinBody(const CPubKey& pubkeySession, const uint256& keyImage,
                      std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (!pubkeySession.IsValid())
        return false;
    const std::vector<unsigned char> vchKey = pubkeySession.Raw();
    if (vchKey.size() != MIX_SESSION_PUBKEY_BYTES)
        return false;
    vchOut.insert(vchOut.end(), vchKey.begin(), vchKey.end());
    vchOut.insert(vchOut.end(), keyImage.begin(), keyImage.end());
    return true;
}

bool BuildMixScalarBody(const CPubKey& pubkeySession, const std::vector<unsigned char>& vch32,
                        std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (!pubkeySession.IsValid() || vch32.size() != 32)
        return false;
    const std::vector<unsigned char> vchKey = pubkeySession.Raw();
    if (vchKey.size() != MIX_SESSION_PUBKEY_BYTES)
        return false;
    vchOut.insert(vchOut.end(), vchKey.begin(), vchKey.end());
    vchOut.insert(vchOut.end(), vch32.begin(), vch32.end());
    return true;
}

static bool BuildMixAnnouncedBody(const CPubKey& pubkeySession,
                                  const uint256& hashAnnouncement,
                                  const std::vector<unsigned char>& vchTail,
                                  std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (!pubkeySession.IsValid() || vchTail.empty() || vchTail.size() > 0xffff)
        return false;
    // Fixed-width key first, the shape TakeSessionKey reads; the tail is length-prefixed
    // because a signature and a blinded message are both variable.
    const std::vector<unsigned char> vchKey = pubkeySession.Raw();
    if (vchKey.size() != MIX_SESSION_PUBKEY_BYTES)
        return false;
    vchOut.insert(vchOut.end(), vchKey.begin(), vchKey.end());
    vchOut.insert(vchOut.end(), hashAnnouncement.begin(), hashAnnouncement.end());
    PutU16(vchOut, vchTail.size());
    vchOut.insert(vchOut.end(), vchTail.begin(), vchTail.end());
    return true;
}

bool BuildMixViewSigBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                         const std::vector<unsigned char>& vchViewSig,
                         std::vector<unsigned char>& vchOut)
{
    return BuildMixAnnouncedBody(pubkeySession, hashAnnouncement, vchViewSig, vchOut);
}

bool BuildMixInputConstructionBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                                   const uint256& keyImage, const PrivacyVNextDigest& pseudoOut,
                                   std::vector<unsigned char>& vchOut)
{
    std::vector<unsigned char> vchTail(keyImage.begin(), keyImage.end());
    vchTail.insert(vchTail.end(), pseudoOut.begin(), pseudoOut.end());
    return BuildMixAnnouncedBody(pubkeySession, hashAnnouncement, vchTail, vchOut);
}

bool BuildMixPrefixBody(const std::vector<unsigned char>& vchPrefix, std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (vchPrefix.empty() || vchPrefix.size() > 0xffff)
        return false;
    PutU16(vchOut, vchPrefix.size());
    vchOut.insert(vchOut.end(), vchPrefix.begin(), vchPrefix.end());
    return true;
}

bool ReadMixPrefixBody(const std::vector<unsigned char>& vchIn, std::vector<unsigned char>& vchPrefixOut)
{
    vchPrefixOut.clear();
    size_t nAt = 0, nLen = 0;
    if (!TakeU16(vchIn, nAt, nLen) || nLen == 0 || !TakeBytes(vchIn, nAt, nLen, vchPrefixOut) ||
        nAt != vchIn.size())
    {
        vchPrefixOut.clear();
        return false;
    }
    return true;
}

bool BuildMixPrefixSigBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                           const std::vector<unsigned char>& vchSig, std::vector<unsigned char>& vchOut)
{
    return BuildMixAnnouncedBody(pubkeySession, hashAnnouncement, vchSig, vchOut);
}

bool BuildMixMembershipProofBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                                 const std::vector<unsigned char>& vchProof,
                                 std::vector<unsigned char>& vchOut)
{
    return BuildMixAnnouncedBody(pubkeySession, hashAnnouncement, vchProof, vchOut);
}

bool BuildMixBlindRequestBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                              const std::vector<unsigned char>& vchBlinded,
                              std::vector<unsigned char>& vchOut)
{
    return BuildMixAnnouncedBody(pubkeySession, hashAnnouncement, vchBlinded, vchOut);
}

bool BuildMixSnapshot(const CMixRound& round, MixSnapshotAudience nAudience,
                      CMixSnapshot& snapshotOut)
{
    snapshotOut = CMixSnapshot();
    snapshotOut.nAudience = (uint8_t)nAudience;
    snapshotOut.nPhase = (uint8_t)round.Phase();
    if (round.Seats() > 0xff)
        return false;
    snapshotOut.nSeats = (uint8_t)round.Seats();
    snapshotOut.hashRound = round.RoundId();
    if (nAudience != MIX_SNAPSHOT_SEAT)
        return true;
    // All of this exists only once the round froze it, and a seat needs all of it.
    snapshotOut.vRoster = round.Roster();
    snapshotOut.vchRsaN = round.RsaModulus();
    snapshotOut.vchRsaE = round.RsaExponent();
    snapshotOut.vchPrefix = round.FrozenPrefix();
    snapshotOut.vViewSigs = round.ViewCertificate(round.PrefixAnnouncement());
    snapshotOut.vPrefixSigs = round.PrefixCertificate();
    const std::vector<std::vector<unsigned char> > vNonces = round.NoncesInInputOrder();
    for (size_t i = 0; i < vNonces.size(); i++)
    {
        if (vNonces[i].size() != 32)
        {
            snapshotOut.vNonces.clear();
            break;
        }
        PrivacyVNextDigest nonce;
        memcpy(nonce.data(), &vNonces[i][0], 32);
        snapshotOut.vNonces.push_back(nonce);
    }
    return true;
}

bool BuildMixSnapshotBody(const CMixSnapshot& snapshot, std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (snapshot.nVersion != 1)
        return false;
    if (snapshot.nAudience != MIX_SNAPSHOT_PUBLIC && snapshot.nAudience != MIX_SNAPSHOT_SEAT)
        return false;
    if (snapshot.nAudience == MIX_SNAPSHOT_PUBLIC &&
        (!snapshot.vRoster.empty() || !snapshot.vchRsaN.empty() || !snapshot.vchRsaE.empty() ||
         !snapshot.vchPrefix.empty() || !snapshot.vNonces.empty() ||
         !snapshot.vViewSigs.empty() || !snapshot.vPrefixSigs.empty()))
        return false;   // the public form carries none of it, by construction
    vchOut.push_back(snapshot.nVersion);
    vchOut.push_back(snapshot.nAudience);
    vchOut.push_back(snapshot.nPhase);
    vchOut.push_back(snapshot.nSeats);
    vchOut.insert(vchOut.end(), snapshot.hashRound.begin(), snapshot.hashRound.end());
    if (snapshot.nAudience == MIX_SNAPSHOT_PUBLIC)
        return true;

    std::vector<unsigned char> vchRoster;
    if (!snapshot.vRoster.empty() && !BuildMixRosterBody(snapshot.vRoster, vchRoster))
        return false;
    if (vchRoster.size() > 0xffff || snapshot.vchRsaN.size() > 0xffff ||
        snapshot.vchRsaE.size() > 0xffff || snapshot.vchPrefix.size() > 0xffff ||
        snapshot.vNonces.size() > iv5::MAX_NULLSEND_INPUTS)
        return false;
    PutU16(vchOut, vchRoster.size());
    vchOut.insert(vchOut.end(), vchRoster.begin(), vchRoster.end());
    PutU16(vchOut, snapshot.vchRsaN.size());
    vchOut.insert(vchOut.end(), snapshot.vchRsaN.begin(), snapshot.vchRsaN.end());
    PutU16(vchOut, snapshot.vchRsaE.size());
    vchOut.insert(vchOut.end(), snapshot.vchRsaE.begin(), snapshot.vchRsaE.end());
    PutU16(vchOut, snapshot.vchPrefix.size());
    vchOut.insert(vchOut.end(), snapshot.vchPrefix.begin(), snapshot.vchPrefix.end());
    vchOut.push_back((unsigned char)snapshot.vNonces.size());
    for (size_t i = 0; i < snapshot.vNonces.size(); i++)
        vchOut.insert(vchOut.end(), snapshot.vNonces[i].begin(), snapshot.vNonces[i].end());
    for (size_t nWhich = 0; nWhich < 2; nWhich++)
    {
        const std::vector<std::vector<unsigned char> >& vSigs =
            nWhich == 0 ? snapshot.vViewSigs : snapshot.vPrefixSigs;
        if (vSigs.size() > iv5::MAX_NULLSEND_INPUTS)
            return false;
        vchOut.push_back((unsigned char)vSigs.size());
        for (size_t i = 0; i < vSigs.size(); i++)
        {
            if (vSigs[i].empty() || vSigs[i].size() > 0xffff)
                return false;   // a certificate is complete or it is not published at all
            PutU16(vchOut, vSigs[i].size());
            vchOut.insert(vchOut.end(), vSigs[i].begin(), vSigs[i].end());
        }
    }
    return true;
}

bool ReadMixSnapshotBody(const std::vector<unsigned char>& vchIn, CMixSnapshot& snapshotOut)
{
    snapshotOut = CMixSnapshot();
    size_t nAt = 0;
    std::vector<unsigned char> vch;
    if (!TakeBytes(vchIn, nAt, 4, vch))
        return false;
    snapshotOut.nVersion = vch[0];
    snapshotOut.nAudience = vch[1];
    snapshotOut.nPhase = vch[2];
    snapshotOut.nSeats = vch[3];
    if (snapshotOut.nVersion != 1)
        return false;
    if (!TakeBytes(vchIn, nAt, 32, vch))
        return false;
    memcpy(snapshotOut.hashRound.begin(), &vch[0], 32);
    if (snapshotOut.nAudience == MIX_SNAPSHOT_PUBLIC)
        return nAt == vchIn.size();
    if (snapshotOut.nAudience != MIX_SNAPSHOT_SEAT)
        return false;

    size_t nLen = 0;
    if (!TakeU16(vchIn, nAt, nLen) || !TakeBytes(vchIn, nAt, nLen, vch))
        return false;
    if (nLen > 0 && !ReadMixRosterBody(vch, snapshotOut.vRoster))
        return false;
    if (!TakeU16(vchIn, nAt, nLen) || !TakeBytes(vchIn, nAt, nLen, snapshotOut.vchRsaN))
        return false;
    if (!TakeU16(vchIn, nAt, nLen) || !TakeBytes(vchIn, nAt, nLen, snapshotOut.vchRsaE))
        return false;
    if (!TakeU16(vchIn, nAt, nLen) || !TakeBytes(vchIn, nAt, nLen, snapshotOut.vchPrefix))
        return false;
    if (!TakeBytes(vchIn, nAt, 1, vch))
        return false;
    const size_t nNonces = vch[0];
    if (nNonces > iv5::MAX_NULLSEND_INPUTS)
        return false;
    for (size_t i = 0; i < nNonces; i++)
    {
        if (!TakeBytes(vchIn, nAt, 32, vch))
            return false;
        PrivacyVNextDigest nonce;
        memcpy(nonce.data(), &vch[0], 32);
        snapshotOut.vNonces.push_back(nonce);
    }
    for (size_t nWhich = 0; nWhich < 2; nWhich++)
    {
        std::vector<std::vector<unsigned char> >& vSigs =
            nWhich == 0 ? snapshotOut.vViewSigs : snapshotOut.vPrefixSigs;
        if (!TakeBytes(vchIn, nAt, 1, vch))
            return false;
        const size_t nSigs = vch[0];
        if (nSigs > iv5::MAX_NULLSEND_INPUTS)
            return false;
        for (size_t i = 0; i < nSigs; i++)
        {
            std::vector<unsigned char> vchSig;
            if (!TakeU16(vchIn, nAt, nLen) || nLen == 0 ||
                !TakeBytes(vchIn, nAt, nLen, vchSig))
                return false;
            vSigs.push_back(vchSig);
        }
    }
    return nAt == vchIn.size();
}

bool BuildMixAckBody(bool fAccepted, std::vector<unsigned char>& vchOut)
{
    vchOut.assign(1, fAccepted ? 1 : 0);
    return true;
}

bool ReadMixAckBody(const std::vector<unsigned char>& vchIn, bool& fAcceptedOut)
{
    fAcceptedOut = false;
    if (vchIn.size() != 1 || vchIn[0] > 1)
        return false;
    fAcceptedOut = vchIn[0] == 1;
    return true;
}

bool BuildMixStateAuthBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                           std::vector<unsigned char>& vchOut)
{
    // One byte of tail, because an announced body carries a length-prefixed tail and an
    // empty one would not round-trip. It names nothing: the read carries no argument.
    return BuildMixAnnouncedBody(pubkeySession, hashAnnouncement,
                                 std::vector<unsigned char>(1, 0), vchOut);
}

bool BuildMixRosterBody(const std::vector<CMixRosterEntry>& vRoster,
                        std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (vRoster.empty() || vRoster.size() > iv5::MAX_NULLSEND_INPUTS)
        return false;
    for (size_t i = 0; i < vRoster.size(); i++)
    {
        if (!vRoster[i].pubkeySession.IsValid() ||
            vRoster[i].pubkeySession.Raw().size() != MIX_SESSION_PUBKEY_BYTES)
            return false;
        if (i > 0 && !std::lexicographical_compare(vRoster[i - 1].keyImage.begin(),
                                                   vRoster[i - 1].keyImage.end(),
                                                   vRoster[i].keyImage.begin(),
                                                   vRoster[i].keyImage.end()))
            return false;   // unsorted, or a repeat
    }
    PutU16(vchOut, vRoster.size());
    for (size_t i = 0; i < vRoster.size(); i++)
    {
        vchOut.insert(vchOut.end(), vRoster[i].keyImage.begin(), vRoster[i].keyImage.end());
        const std::vector<unsigned char> vchKey = vRoster[i].pubkeySession.Raw();
        vchOut.insert(vchOut.end(), vchKey.begin(), vchKey.end());
    }
    return true;
}

bool ReadMixRosterBody(const std::vector<unsigned char>& vchIn,
                       std::vector<CMixRosterEntry>& vOut)
{
    vOut.clear();
    size_t nAt = 0, nCount = 0;
    if (!TakeU16(vchIn, nAt, nCount))
        return false;
    if (nCount == 0 || nCount > iv5::MAX_NULLSEND_INPUTS)
        return false;
    for (size_t i = 0; i < nCount; i++)
    {
        std::vector<unsigned char> vchImage, vchKey;
        if (!TakeBytes(vchIn, nAt, 32, vchImage) ||
            !TakeBytes(vchIn, nAt, MIX_SESSION_PUBKEY_BYTES, vchKey))
        {
            vOut.clear();
            return false;
        }
        CMixRosterEntry entry;
        memcpy(entry.keyImage.begin(), &vchImage[0], 32);
        entry.pubkeySession = CPubKey(vchKey);
        if (!entry.pubkeySession.IsValid())
        {
            vOut.clear();
            return false;
        }
        // The reader refuses an order it would have to fix: a seat that reconstructed the
        // roster in another order derives another input_context and never sees its output.
        if (i > 0 && !std::lexicographical_compare(vOut[i - 1].keyImage.begin(),
                                                   vOut[i - 1].keyImage.end(),
                                                   entry.keyImage.begin(),
                                                   entry.keyImage.end()))
        {
            vOut.clear();
            return false;
        }
        vOut.push_back(entry);
    }
    if (nAt != vchIn.size())
    {
        vOut.clear();
        return false;
    }
    return true;
}

bool BuildMixKeySetBody(const std::vector<uint256>& vKeyImages,
                        std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (vKeyImages.empty() || vKeyImages.size() > iv5::MAX_NULLSEND_INPUTS)
        return false;
    for (size_t i = 1; i < vKeyImages.size(); i++)
        if (!std::lexicographical_compare(vKeyImages[i - 1].begin(), vKeyImages[i - 1].end(),
                                          vKeyImages[i].begin(), vKeyImages[i].end()))
            return false;   // unsorted, or a repeat
    PutU16(vchOut, vKeyImages.size());
    for (size_t i = 0; i < vKeyImages.size(); i++)
        vchOut.insert(vchOut.end(), vKeyImages[i].begin(), vKeyImages[i].end());
    return true;
}

bool ReadMixKeySetBody(const std::vector<unsigned char>& vchIn,
                       std::vector<uint256>& vOut)
{
    vOut.clear();
    size_t nAt = 0, nCount = 0;
    if (!TakeU16(vchIn, nAt, nCount))
        return false;
    if (nCount == 0 || nCount > iv5::MAX_NULLSEND_INPUTS)
        return false;
    for (size_t i = 0; i < nCount; i++)
    {
        std::vector<unsigned char> vch;
        if (!TakeBytes(vchIn, nAt, 32, vch))
            return false;
        uint256 image;
        memcpy(image.begin(), &vch[0], 32);
        vOut.push_back(image);
    }
    if (nAt != vchIn.size())
    {
        vOut.clear();
        return false;
    }
    // Byte order, strictly increasing. Not sorted here: a misordered set is refused, since
    // reordering would desync input_context from the scanner.
    for (size_t i = 1; i < vOut.size(); i++)
    {
        if (!std::lexicographical_compare(vOut[i - 1].begin(), vOut[i - 1].end(),
                                          vOut[i].begin(), vOut[i].end()))
        {
            vOut.clear();
            return false;
        }
    }
    return true;
}

bool BuildMixOutputBundleBody(const std::vector<unsigned char>& vchCredential,
                              const std::vector<unsigned char>& vchBlindSignature,
                              const std::vector<CMixOutputRecord>& vBundle,
                              std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (vchCredential.empty() || vchCredential.size() > 0xFFFF)
        return false;
    if (vchBlindSignature.empty() || vchBlindSignature.size() > 0xFFFF)
        return false;
    std::vector<unsigned char> vchBundle;
    if (!EncodeMixOutputBundle(vBundle, vchBundle))
        return false;
    PutU16(vchOut, vchCredential.size());
    vchOut.insert(vchOut.end(), vchCredential.begin(), vchCredential.end());
    PutU16(vchOut, vchBlindSignature.size());
    vchOut.insert(vchOut.end(), vchBlindSignature.begin(), vchBlindSignature.end());
    vchOut.insert(vchOut.end(), vchBundle.begin(), vchBundle.end());
    return true;
}

MixDispatch DispatchMixFrame(CMixRound& round,
                             MixFrameType nType,
                             const std::vector<unsigned char>& vchPayload,
                             int64_t nNow, std::string& strError,
                             CMixDispatchEffect* pEffect)
{
    if (pEffect)
        pEffect->Clear();
    // The round's own id, never one the caller names: the two disagreeing is what would
    // let a coordinator run one round while telling each seat it is in a different one.
    const uint256& hashRound = round.RoundId();
    strError.clear();
    #define REFUSE(msg) do { strError = (msg); return MIX_DISPATCH_REFUSED; } while (0)

    // An output registration carries only a token: no session key, so it cannot name the
    // seat it came from.
    if (nType == MIX_FRAME_OUTPUT)
    {
        size_t nAt = 0, nLen = 0;
        std::vector<unsigned char> vchCredential, vchBlindSignature;
        if (!TakeU16(vchPayload, nAt, nLen) || !TakeBytes(vchPayload, nAt, nLen, vchCredential))
            REFUSE("output frame is malformed");
        if (!TakeU16(vchPayload, nAt, nLen) || !TakeBytes(vchPayload, nAt, nLen, vchBlindSignature))
            REFUSE("output frame is malformed");
        std::vector<unsigned char> vchBundle(vchPayload.begin() + nAt, vchPayload.end());
        std::vector<CMixOutputRecord> vRecords;
        if (vchBundle.empty() || !DecodeMixOutputBundle(vchBundle, vRecords))
            REFUSE("output frame is malformed");
        if (!round.RegisterOutput(vchCredential, vchBlindSignature, vRecords, nNow, &strError))
            return MIX_DISPATCH_REFUSED;
        return MIX_DISPATCH_OK;
    }

    if (nType != MIX_FRAME_JOIN && nType != MIX_FRAME_NONCE && nType != MIX_FRAME_RESPONSE &&
        nType != MIX_FRAME_VIEW_SIG && nType != MIX_FRAME_BLIND_REQUEST &&
        nType != MIX_FRAME_INPUT_CONSTRUCTION && nType != MIX_FRAME_PREFIX_SIG &&
        nType != MIX_FRAME_MEMBERSHIP_PROOF)
        REFUSE("a participant does not send that frame");

    std::vector<unsigned char> vchBody, vchSig;
    if (!SplitAuthedMixFrame(vchPayload, vchBody, vchSig))
        REFUSE("frame carries no session signature");
    size_t nAt = 0;
    CPubKey pubkeySession;
    if (!TakeSessionKey(vchBody, nAt, pubkeySession))
        REFUSE("frame carries no session key");
    if (!CheckMixSessionFrame(pubkeySession, hashRound, nType, vchBody, vchSig))
        REFUSE("session signature does not verify");

    // These frames carry a variable tail rather than one 32-byte field, so they are taken
    // before the fixed-shape parse below.
    if (nType == MIX_FRAME_VIEW_SIG)
    {
        std::vector<unsigned char> vchAnnounce, vchViewSig;
        size_t nLen = 0;
        if (!TakeBytes(vchBody, nAt, 32, vchAnnounce))
            REFUSE("view frame is malformed");
        if (!TakeU16(vchBody, nAt, nLen) || !TakeBytes(vchBody, nAt, nLen, vchViewSig) ||
            nAt != vchBody.size())
            REFUSE("view frame is malformed");
        uint256 hashAnnouncement;
        memcpy(hashAnnouncement.begin(), &vchAnnounce[0], 32);
        if (!round.SubmitViewSignature(pubkeySession, hashAnnouncement, vchViewSig,
                                       &strError))
            return MIX_DISPATCH_REFUSED;
        return MIX_DISPATCH_OK;
    }
    if (nType == MIX_FRAME_PREFIX_SIG)
    {
        std::vector<unsigned char> vchAnnounce, vchPrefixSig;
        size_t nLen = 0;
        if (!TakeBytes(vchBody, nAt, 32, vchAnnounce))
            REFUSE("prefix approval is malformed");
        if (!TakeU16(vchBody, nAt, nLen) || !TakeBytes(vchBody, nAt, nLen, vchPrefixSig) ||
            nAt != vchBody.size())
            REFUSE("prefix approval is malformed");
        uint256 hashAnnouncement;
        memcpy(hashAnnouncement.begin(), &vchAnnounce[0], 32);
        if (!round.ViewAgreed(hashAnnouncement))
            REFUSE("the seats have not all signed this view");
        if (!round.SubmitPrefixSignature(pubkeySession, vchPrefixSig, &strError))
            return MIX_DISPATCH_REFUSED;
        return MIX_DISPATCH_OK;
    }
    if (nType == MIX_FRAME_MEMBERSHIP_PROOF)
    {
        std::vector<unsigned char> vchAnnounce, vchProof;
        size_t nLen = 0;
        if (!TakeBytes(vchBody, nAt, 32, vchAnnounce))
            REFUSE("membership proof is malformed");
        if (!TakeU16(vchBody, nAt, nLen) || !TakeBytes(vchBody, nAt, nLen, vchProof) ||
            nAt != vchBody.size())
            REFUSE("membership proof is malformed");
        uint256 hashAnnouncement;
        memcpy(hashAnnouncement.begin(), &vchAnnounce[0], 32);
        if (!round.ViewAgreed(hashAnnouncement))
            REFUSE("the seats have not all signed this view");
        if (!round.SubmitMembershipProof(pubkeySession, vchProof, &strError))
            return MIX_DISPATCH_REFUSED;
        return MIX_DISPATCH_OK;
    }
    if (nType == MIX_FRAME_INPUT_CONSTRUCTION)
    {
        std::vector<unsigned char> vchAnnounce, vchTail;
        size_t nLen = 0;
        if (!TakeBytes(vchBody, nAt, 32, vchAnnounce))
            REFUSE("input construction is malformed");
        if (!TakeU16(vchBody, nAt, nLen) || nLen != 64 ||
            !TakeBytes(vchBody, nAt, nLen, vchTail) || nAt != vchBody.size())
            REFUSE("input construction is malformed");
        uint256 hashAnnouncement, keyImage;
        memcpy(hashAnnouncement.begin(), &vchAnnounce[0], 32);
        memcpy(keyImage.begin(), &vchTail[0], 32);
        PrivacyVNextDigest pseudoOut;
        memcpy(pseudoOut.data(), &vchTail[32], 32);
        if (!round.SubmitInputConstruction(pubkeySession, hashAnnouncement, keyImage,
                                           pseudoOut, &strError))
            return MIX_DISPATCH_REFUSED;
        return MIX_DISPATCH_OK;
    }
    if (nType == MIX_FRAME_BLIND_REQUEST)
    {
        // A token is the authority to register an output, so issuance waits until every
        // seat has signed the same view. Without that gate a coordinator can hand out
        // tokens under per-seat announcements and the certificate buys nothing.
        std::vector<unsigned char> vchAnnounce, vchBlinded;
        size_t nLen = 0;
        if (!TakeBytes(vchBody, nAt, 32, vchAnnounce))
            REFUSE("blind request is malformed");
        if (!TakeU16(vchBody, nAt, nLen) || !TakeBytes(vchBody, nAt, nLen, vchBlinded) ||
            nAt != vchBody.size())
            REFUSE("blind request is malformed");
        if (vchBlinded.empty())
            REFUSE("blind request carries no blinded message");
        uint256 hashAnnouncement;
        memcpy(hashAnnouncement.begin(), &vchAnnounce[0], 32);
        if (!round.ViewAgreed(hashAnnouncement))
            REFUSE("the seats have not all signed this view");
        // And until every seat has submitted its input construction: the prefix needs one
        // per input, and a token issued before them lets outputs register for a round
        // that can never be assembled.
        if (!round.InputConstructionsComplete())
            REFUSE("the seats have not all submitted their input constructions");
        if (!round.IssueToken(pubkeySession, &strError))
            return MIX_DISPATCH_REFUSED;
        if (pEffect)
        {
            pEffect->nFrame = MIX_FRAME_BLIND_REQUEST;
            pEffect->pubkeySession = pubkeySession;
            pEffect->vchBlinded = vchBlinded;
        }
        return MIX_DISPATCH_OK;
    }

    std::vector<unsigned char> vchTail;
    if (!TakeBytes(vchBody, nAt, 32, vchTail) || nAt != vchBody.size())
        REFUSE("frame body is malformed");

    if (nType == MIX_FRAME_JOIN)
    {
        uint256 keyImage;
        memcpy(keyImage.begin(), &vchTail[0], 32);
        if (!round.Join(pubkeySession, keyImage, &strError))
            return MIX_DISPATCH_REFUSED;
        return MIX_DISPATCH_OK;
    }
    if (nType == MIX_FRAME_NONCE)
    {
        // A nonce fixes this seat's share of the challenge. Before every seat has approved
        // one prefix, the statement under that challenge can still change; before every
        // proof is in, a round that can never assemble would still collect shares.
        if (!round.PrefixAgreed())
            REFUSE("the seats have not all approved the prefix");
        if (!round.MembershipProofsComplete())
            REFUSE("the seats have not all proved their inputs");
        if (!round.SubmitNonce(pubkeySession, vchTail, &strError))
            return MIX_DISPATCH_REFUSED;
        return MIX_DISPATCH_OK;
    }
    if (!round.SubmitResponse(pubkeySession, vchTail, &strError))
        return round.Phase() == MIX_PHASE_ABORTED ? MIX_DISPATCH_ABORTED : MIX_DISPATCH_REFUSED;
    return MIX_DISPATCH_OK;
    #undef REFUSE
}

// ---------------------------------------------------------------------------
// The coordinator service
// ---------------------------------------------------------------------------

namespace {

boost::filesystem::path MixRoundKeyLedgerPath()
{
    return GetDataDir() / "mixroundkeys.log";
}

uint256 MixRoundKeyFingerprint(const std::vector<unsigned char>& vchRSA_N)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/roundkey/used/v1");
    ss << vchRSA_N;
    return ss.GetHash();
}

} // namespace

bool MixRoundKeyWasUsed(const std::vector<unsigned char>& vchRSA_N)
{
    if (vchRSA_N.empty())
        return true;
    const std::string strWanted = MixRoundKeyFingerprint(vchRSA_N).ToString();
    FILE* file = fopen(MixRoundKeyLedgerPath().string().c_str(), "r");
    if (file == NULL)
        return false;
    char pszLine[256];
    bool fFound = false;
    while (!fFound && fgets(pszLine, sizeof(pszLine), file) != NULL)
    {
        std::string strLine(pszLine);
        if (strLine.find(strWanted) != std::string::npos)
            fFound = true;
    }
    fclose(file);
    return fFound;
}

bool RecordMixRoundKeyUse(const std::vector<unsigned char>& vchRSA_N, const uint256& hashRound)
{
    if (vchRSA_N.empty())
        return false;
    FILE* file = fopen(MixRoundKeyLedgerPath().string().c_str(), "a");
    if (file == NULL)
        return false;
    // Appended and flushed before the round runs: a crash that loses the record would let
    // the key be offered again, which is the one thing the ledger exists to stop.
    fprintf(file, "%s %s\n", MixRoundKeyFingerprint(vchRSA_N).ToString().c_str(),
            hashRound.ToString().c_str());
    fflush(file);
    fclose(file);
    return true;
}

CMixCoordinator::CMixCoordinator()
    : fOpen(false), fPublished(false), nLastStage(MIX_STAGE_JOIN), nPublicSecond(0),
      nPublicReads(0)
{
}

bool IsAuthenticatedMixFrame(MixFrameType nType)
{
    switch (nType)
    {
    case MIX_FRAME_JOIN:
    case MIX_FRAME_VIEW_SIG:
    case MIX_FRAME_INPUT_CONSTRUCTION:
    case MIX_FRAME_BLIND_REQUEST:
    case MIX_FRAME_PREFIX_SIG:
    case MIX_FRAME_MEMBERSHIP_PROOF:
    case MIX_FRAME_NONCE:
    case MIX_FRAME_RESPONSE:
    case MIX_FRAME_STATE_AUTH:
        return true;
    default:
        // OUTPUT is deliberately not here: it names no seat, and it is bounded by the
        // token it carries rather than by any budget.
        return false;
    }
}

bool CMixCoordinator::SpendSeatBudget(const CPubKey& pubkeySession, MixFrameType nType)
{
    if (!pubkeySession.IsValid())
        return false;
    const std::vector<unsigned char> vchKey = pubkeySession.Raw();
    CHashWriter ss(SER_GETHASH, 0);
    ss << vchKey;
    const std::pair<uint256, int> key(ss.GetHash(), (int)nType);
    std::map<std::pair<uint256, int>, int>::iterator it = mapSeatRequests.find(key);
    if (it == mapSeatRequests.end())
    {
        mapSeatRequests[key] = 1;
        return true;
    }
    if (it->second >= MIX_SEAT_REQUEST_BUDGET)
        return false;
    it->second++;
    return true;
}

bool CMixCoordinator::SpendPublicBudget(int64_t nNow)
{
    if (nNow != nPublicSecond)
    {
        nPublicSecond = nNow;
        nPublicReads = 0;
    }
    if (nPublicReads >= MIX_PUBLIC_READS_PER_SECOND)
        return false;
    nPublicReads++;
    return true;
}

bool CMixCoordinator::Open(const CMixRoundAnnouncement& announce,
                           const CNullSendSession& roundKey, int64_t nNow,
                           std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (fOpen)
        FAIL("this coordinator is already running a round");
    if (!announce.IsValidBasic(pstrError))
        return false;
    if (!announce.CheckSignature())
        FAIL("the announcement is not signed by the key it names");
    if (!announce.KeyOpensCommitment(roundKey.vchRSA_N, roundKey.vchRSA_E))
        FAIL("the round key is not the one the announcement commits to");
    if (roundKey.vchRSA_D.empty())
        FAIL("the round key cannot sign");
    if (MixRoundKeyWasUsed(roundKey.vchRSA_N))
        FAIL("that round key has already run a round; a token from it would open in this one");
    if (nNow >= announce.JoinCloses())
        FAIL("the announced join window has already closed");
    if (!round.Open(announce.hashRound, announce.nParticipants, roundKey.vchRSA_N,
                    roundKey.vchRSA_E, true, false, announce.nDenomination, nNow, pstrError))
        return false;
    if (!RecordMixRoundKeyUse(roundKey.vchRSA_N, announce.hashRound))
        FAIL("the round key could not be recorded as used");
    announcement = announce;
    key = roundKey;
    vBlinded.assign(announce.nParticipants, std::vector<unsigned char>());
    vBlindSignatures.assign(announce.nParticipants, std::vector<unsigned char>());
    fOpen = true;
    fPublished = false;
    nLastStage = MIX_STAGE_JOIN;
    return true;
    #undef FAIL
}

MixServiceStage CMixCoordinator::Stage(int64_t nNow) const
{
    if (!fOpen)
        return MIX_STAGE_TERMINAL;
    if (nNow < announcement.JoinCloses())     return MIX_STAGE_JOIN;
    if (nNow < announcement.ViewCloses())     return MIX_STAGE_VIEW;
    if (nNow < announcement.TokenCloses())    return MIX_STAGE_TOKEN;
    // Strictly past the close, matching the round's own comparison, so stage and round agree.
    if (nNow <= announcement.OutputCloses())  return MIX_STAGE_OUTPUT;
    if (nNow < announcement.ApproveCloses())  return MIX_STAGE_APPROVE;
    if (nNow < announcement.NonceCloses())    return MIX_STAGE_NONCE;
    if (nNow < announcement.ResponseCloses()) return MIX_STAGE_RESPONSE;
    return MIX_STAGE_TERMINAL;
}

void CMixCoordinator::Tick(int64_t nNow)
{
    if (!fOpen || round.Phase() == MIX_PHASE_ABORTED || round.Phase() == MIX_PHASE_COMPLETE)
        return;
    const MixServiceStage nStage = Stage(nNow);
    std::string strError;
    // One transition per boundary crossed, in order, so a service that missed a tick
    // still runs every step rather than skipping to the stage the clock is in.
    while (nLastStage < nStage)
    {
        const MixServiceStage nCrossed = nLastStage;
        nLastStage = (MixServiceStage)(nLastStage + 1);
        switch (nCrossed)
        {
        case MIX_STAGE_JOIN:
            if ((int)round.Seats() != announcement.nParticipants)
            {
                round.Abort("the round did not fill before its join window closed");
                return;
            }
            if (!round.CloseJoin(nNow, &strError))
            {
                round.Abort("the join set could not be frozen: " + strError);
                return;
            }
            break;
        case MIX_STAGE_VIEW:
            if (!round.ViewAgreed(announcement.hashRound) || !round.InputConstructionsComplete())
            {
                round.Abort("the seats did not all agree the view and construct their inputs");
                return;
            }
            break;
        case MIX_STAGE_TOKEN:
            // Every seat must hold a token, or the round cannot fill its outputs; opening
            // the window with the close the announcement scheduled, not one of its own.
            if (!round.OpenOutputWindow(nNow, announcement.OutputCloses(), &strError))
            {
                round.Abort("the output window could not open: " + strError);
                return;
            }
            break;
        case MIX_STAGE_OUTPUT:
            if (round.Outputs() != round.Seats())
            {
                round.Abort("the round is short of outputs");
                return;
            }
            if (!round.OpenSigning(nNow, &strError))
            {
                round.Abort("signing could not open: " + strError);
                return;
            }
            else
            {
                PrivacyVNextPrefixHeader header;
                header.nOperation = iv5::NOTE_NULLSEND;
                header.nDisclosureMask = iv5::NULLSEND_DISCLOSURE_MASK;
                header.nNetwork = announcement.nNetwork;
                header.genesis = announcement.genesis;
                header.parameterDigest = announcement.parameterDigest;
                header.finalizedRoot = announcement.finalizedRoot;
                header.nFinalizedTreeSize = announcement.nFinalizedTreeSize;
                header.nTransparentValueBalance = 0;
                header.nFee = announcement.nFee;
                header.transparentBinding = MixTransparentBinding();
                if (!round.FreezePrefix(header, announcement.hashRound, &strError))
                {
                    round.Abort("the prefix could not be frozen: " + strError);
                    return;
                }
            }
            break;
        case MIX_STAGE_APPROVE:
            if (!round.PrefixAgreed() || !round.MembershipProofsComplete())
            {
                round.Abort("the seats did not all approve the prefix and prove their inputs");
                return;
            }
            break;
        case MIX_STAGE_NONCE:
            if (!round.FreezeNonces(&strError))
            {
                round.Abort("the aggregate could not be fixed: " + strError);
                return;
            }
            break;
        case MIX_STAGE_RESPONSE:
            Assemble(nNow);
            return;
        case MIX_STAGE_TERMINAL:
            return;
        }
    }
}

void CMixCoordinator::Assemble(int64_t nNow)
{
    std::string strError;
    std::vector<unsigned char> vchPayload;
    if (!round.AssemblePayload(vchPayload, &strError))
    {
        round.Abort("the payload could not be assembled: " + strError);
        return;
    }
    // Stamped now, once the proving and signing are done: a time taken earlier would
    // publish how long the round's slowest seat took.
    if (!BuildMixTransaction(vchPayload, (uint32_t)nNow, txPublished, strError))
    {
        round.Abort("the transaction could not be built: " + strError);
        return;
    }
    if (!round.MarkComplete(&strError))
    {
        round.Abort("the round could not be completed: " + strError);
        return;
    }
    fPublished = true;
}

bool CMixCoordinator::StageAccepts(MixServiceStage nStage, MixFrameType nType) const
{
    switch (nType)
    {
    case MIX_FRAME_JOIN:                return nStage == MIX_STAGE_JOIN;
    case MIX_FRAME_VIEW_SIG:            return nStage == MIX_STAGE_VIEW;
    case MIX_FRAME_INPUT_CONSTRUCTION:  return nStage == MIX_STAGE_VIEW;
    case MIX_FRAME_BLIND_REQUEST:       return nStage == MIX_STAGE_TOKEN;
    case MIX_FRAME_OUTPUT:              return nStage == MIX_STAGE_OUTPUT;
    case MIX_FRAME_PREFIX_SIG:          return nStage == MIX_STAGE_APPROVE;
    case MIX_FRAME_MEMBERSHIP_PROOF:    return nStage == MIX_STAGE_APPROVE;
    case MIX_FRAME_NONCE:               return nStage == MIX_STAGE_NONCE;
    case MIX_FRAME_RESPONSE:            return nStage == MIX_STAGE_RESPONSE;
    default:                            return false;
    }
}

bool CMixCoordinator::ServeSeatRead(const std::vector<unsigned char>& vchPayload,
                                    MixFrameType& nReplyTypeOut,
                                    std::vector<unsigned char>& vchReplyOut)
{
    // A seat read is authenticated, because the seat snapshot carries the frozen prefix
    // and with it every output's disclosed opening. Anyone may have the public form.
    std::vector<unsigned char> vchBody, vchSig;
    if (!SplitAuthedMixFrame(vchPayload, vchBody, vchSig))
        return false;
    size_t nAt = 0;
    CPubKey pubkeySession;
    if (!TakeSessionKey(vchBody, nAt, pubkeySession))
        return false;
    if (!CheckMixSessionFrame(pubkeySession, round.RoundId(), MIX_FRAME_STATE_AUTH, vchBody,
                              vchSig))
        return false;
    if (round.SeatFor(pubkeySession) < 0)
        return false;
    CMixSnapshot snapshot;
    if (!BuildMixSnapshot(round, MIX_SNAPSHOT_SEAT, snapshot) ||
        !BuildMixSnapshotBody(snapshot, vchReplyOut))
        return false;
    nReplyTypeOut = MIX_FRAME_SNAPSHOT;
    return true;
}

bool CMixCoordinator::ServeTokenRequest(const std::vector<unsigned char>& vchPayload,
                                        int64_t nNow, MixFrameType& nReplyTypeOut,
                                        std::vector<unsigned char>& vchReplyOut)
{
    // The seat is named on this frame, so a lost reply can be re-served: the same blinded
    // message gets the same signature back, and a different one under the same seat is not
    // a retry and gets nothing.
    std::vector<unsigned char> vchBody, vchSig;
    size_t nAt = 0;
    CPubKey pubkeySession;
    if (SplitAuthedMixFrame(vchPayload, vchBody, vchSig) &&
        TakeSessionKey(vchBody, nAt, pubkeySession) &&
        CheckMixSessionFrame(pubkeySession, round.RoundId(), MIX_FRAME_BLIND_REQUEST, vchBody,
                             vchSig))
    {
        const int nSeat = round.SeatFor(pubkeySession);
        if (nSeat >= 0 && (size_t)nSeat < vBlinded.size() && !vBlinded[nSeat].empty())
        {
            std::vector<unsigned char> vchAnnounce, vchBlinded;
            size_t nLen = 0;
            if (TakeBytes(vchBody, nAt, 32, vchAnnounce) && TakeU16(vchBody, nAt, nLen) &&
                TakeBytes(vchBody, nAt, nLen, vchBlinded) && vchBlinded == vBlinded[nSeat])
            {
                nReplyTypeOut = MIX_FRAME_BLIND_SIGNATURE;
                vchReplyOut = vBlindSignatures[nSeat];
                return true;
            }
            return false;
        }
    }

    std::string strError;
    CMixDispatchEffect effect;
    if (DispatchMixFrame(round, MIX_FRAME_BLIND_REQUEST, vchPayload, nNow, strError, &effect)
            != MIX_DISPATCH_OK)
        return false;
    const int nSeat = round.SeatFor(effect.pubkeySession);
    std::vector<unsigned char> vchSignature;
    if (nSeat < 0 || (size_t)nSeat >= vBlinded.size() ||
        !key.BlindSign(effect.vchBlinded, vchSignature))
        return false;
    vBlinded[nSeat] = effect.vchBlinded;
    vBlindSignatures[nSeat] = vchSignature;
    nReplyTypeOut = MIX_FRAME_BLIND_SIGNATURE;
    vchReplyOut = vchSignature;
    return true;
}

bool CMixCoordinator::Serve(MixFrameType nType, const std::vector<unsigned char>& vchPayload,
                            int64_t nNow, MixFrameType& nReplyTypeOut,
                            std::vector<unsigned char>& vchReplyOut)
{
    nReplyTypeOut = MIX_FRAME_NONE;
    vchReplyOut.clear();
    if (!fOpen)
        return false;
    Tick(nNow);

    if (nType == MIX_FRAME_STATE)
    {
        if (!vchPayload.empty())
            return false;
        // Nothing identifies an unauthenticated caller, and every read costs a snapshot
        // build, so the ceiling is the round's rather than any one caller's.
        if (!SpendPublicBudget(nNow))
            return false;
        CMixSnapshot snapshot;
        if (!BuildMixSnapshot(round, MIX_SNAPSHOT_PUBLIC, snapshot) ||
            !BuildMixSnapshotBody(snapshot, vchReplyOut))
            return false;
        nReplyTypeOut = MIX_FRAME_SNAPSHOT;
        return true;
    }
    // Authenticated frames charge the seat's budget BEFORE the work (proof verification is
    // tens of ms). The cheap signature check comes first so forged frames cost nothing.
    if (IsAuthenticatedMixFrame(nType))
    {
        std::vector<unsigned char> vchBody, vchSig;
        size_t nAt = 0;
        CPubKey pubkeySession;
        if (!SplitAuthedMixFrame(vchPayload, vchBody, vchSig) ||
            !TakeSessionKey(vchBody, nAt, pubkeySession) ||
            !CheckMixSessionFrame(pubkeySession, round.RoundId(), nType, vchBody, vchSig))
            return false;
        if (nType != MIX_FRAME_JOIN && round.SeatFor(pubkeySession) < 0)
            return false;
        if (!SpendSeatBudget(pubkeySession, nType))
        {
            nReplyTypeOut = MIX_FRAME_ACK;
            return BuildMixAckBody(false, vchReplyOut);
        }
    }
    if (nType == MIX_FRAME_STATE_AUTH)
        return ServeSeatRead(vchPayload, nReplyTypeOut, vchReplyOut);
    if (nType == MIX_FRAME_RESULT)
    {
        if (!vchPayload.empty())
            return false;
        if (!SpendPublicBudget(nNow))
            return false;
        if (fPublished)
        {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << txPublished;
            vchReplyOut.assign(ss.begin(), ss.end());
            nReplyTypeOut = MIX_FRAME_TRANSACTION;
            return true;
        }
        if (round.Phase() == MIX_PHASE_ABORTED)
        {
            // No reason and no list of who was missing: either would publish which roster
            // position owns the output that did not arrive.
            nReplyTypeOut = MIX_FRAME_ABORT;
            vchReplyOut.clear();
            return true;
        }
        return BuildMixAckBody(false, vchReplyOut) && (nReplyTypeOut = MIX_FRAME_ACK, true);
    }

    const MixServiceStage nStage = Stage(nNow);
    if (!StageAccepts(nStage, nType))
    {
        nReplyTypeOut = MIX_FRAME_ACK;
        return BuildMixAckBody(false, vchReplyOut);
    }
    if (nType == MIX_FRAME_BLIND_REQUEST)
    {
        if (ServeTokenRequest(vchPayload, nNow, nReplyTypeOut, vchReplyOut))
            return true;
        nReplyTypeOut = MIX_FRAME_ACK;
        return BuildMixAckBody(false, vchReplyOut);
    }

    std::string strError;
    const MixDispatch nVerdict = DispatchMixFrame(round, nType, vchPayload, nNow, strError);
    nReplyTypeOut = MIX_FRAME_ACK;
    return BuildMixAckBody(nVerdict == MIX_DISPATCH_OK, vchReplyOut);
}

// ---------------------------------------------------------------------------
// The seat
// ---------------------------------------------------------------------------

int64_t MixRendezvousSlot(int64_t nTime)
{
    if (nTime < 0)
        return 0;
    return nTime / MIX_RENDEZVOUS_SLOT_SECONDS;
}

uint256 MixRendezvousCommitment(const CPubKey& pubkeyCoordinator, int64_t nSlot,
                                const uint256& hashRound)
{
    if (!pubkeyCoordinator.IsValid() || hashRound == 0 || nSlot < 0)
        return 0;
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/rendezvous/v1");
    ss << pubkeyCoordinator;
    ss << nSlot;
    ss << hashRound;
    return ss.GetHash();
}

uint256 MixRendezvousIdentitySlot(const CPubKey& pubkeyCoordinator, int64_t nSlot)
{
    if (!pubkeyCoordinator.IsValid() || nSlot < 0)
        return 0;
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/rendezvous/slot/v1");
    ss << pubkeyCoordinator;
    ss << nSlot;
    return ss.GetHash();
}

CScript BuildMixRendezvousScript(const uint256& idSlot, const uint256& hashCommitment)
{
    std::vector<unsigned char> vchData(MIX_RENDEZVOUS_TAG, MIX_RENDEZVOUS_TAG + 4);
    vchData.insert(vchData.end(), idSlot.begin(), idSlot.end());
    vchData.insert(vchData.end(), hashCommitment.begin(), hashCommitment.end());
    CScript script;
    script << OP_RETURN << vchData;
    return script;
}

bool DecodeMixRendezvousScript(const CScript& script, uint256& idSlotOut,
                               uint256& hashCommitmentOut)
{
    idSlotOut = 0;
    hashCommitmentOut = 0;
    if (script.size() < 2 || script[0] != OP_RETURN)
        return false;
    // Read the one push directly rather than through CScript::GetOp, so a non-minimal
    // encoding of a tagged payload is refused instead of reading as an unrelated OP_RETURN.
    size_t nOffset = 1;
    const unsigned char opcode = script[nOffset++];
    size_t nDataSize = 0;
    if (opcode <= 75)
        nDataSize = opcode;
    else if (opcode == OP_PUSHDATA1)
    {
        if (nOffset + 1 > script.size())
            return false;
        nDataSize = script[nOffset++];
    }
    else
        return false;
    if (nDataSize != MIX_RENDEZVOUS_PAYLOAD_SIZE || nOffset + nDataSize != script.size())
        return false;
    if (std::memcmp(&script[nOffset], MIX_RENDEZVOUS_TAG, 4) != 0)
        return false;
    std::memcpy(idSlotOut.begin(), &script[nOffset + 4], 32);
    std::memcpy(hashCommitmentOut.begin(), &script[nOffset + 36], 32);
    // The canonical form is the only one that counts: two encodings of one record would let a
    // coordinator publish a second that a stricter reader sees and a looser one does not.
    return BuildMixRendezvousScript(idSlotOut, hashCommitmentOut) == script;
}

bool SelectMixRendezvous(const std::vector<std::pair<uint256, uint256> >& vRecords,
                         const CPubKey& pubkeyCoordinator, int64_t nSlot,
                         CMixRendezvous& rendezvousOut)
{
    rendezvousOut = CMixRendezvous();
    const uint256 idSlot = MixRendezvousIdentitySlot(pubkeyCoordinator, nSlot);
    if (idSlot == 0)
        return false;
    for (size_t i = 0; i < vRecords.size(); ++i)
    {
        if (vRecords[i].first != idSlot || vRecords[i].second == 0)
            continue;
        rendezvousOut.pubkeyCoordinator = pubkeyCoordinator;
        rendezvousOut.nSlot = nSlot;
        rendezvousOut.hashCommitment = vRecords[i].second;
        return true;
    }
    return false;
}

void CollectMixRendezvousRecords(const CBlock& block,
                                 std::vector<std::pair<uint256, uint256> >& vRecordsOut)
{
    for (size_t i = 0; i < block.vtx.size(); ++i)
        for (size_t j = 0; j < block.vtx[i].vout.size(); ++j)
        {
            uint256 idSlot, hashCommitment;
            if (DecodeMixRendezvousScript(block.vtx[i].vout[j].scriptPubKey, idSlot,
                                          hashCommitment))
                vRecordsOut.push_back(std::make_pair(idSlot, hashCommitment));
        }
}

bool ReadMixRendezvousRecords(const CBlockIndex* pindexTip, int64_t nSlot,
                              std::vector<std::pair<uint256, uint256> >& vRecordsOut,
                              std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vRecordsOut.clear();
    if (!pindexTip || nSlot <= 0)
        FAIL("a rendezvous read needs a chain and a slot");
    const int64_t nSlotOpens = nSlot * MIX_RENDEZVOUS_SLOT_SECONDS;
    const int64_t nEarliest = nSlotOpens -
        (int64_t)MIX_RENDEZVOUS_PUBLISH_SLOTS * MIX_RENDEZVOUS_SLOT_SECONDS;

    // A settled view, not the tip: two seats reading at the tip can select different records
    // across a reorg, which is the disagreement the commitment exists to remove.
    const CBlockIndex* pindex = pindexTip->GetAncestor(pindexTip->nHeight -
                                                       MIX_RENDEZVOUS_MIN_DEPTH);
    if (!pindex)
        FAIL("the chain is not deep enough to select a rendezvous from a settled view");

    std::vector<const CBlockIndex*> vScan;
    for (int nScanned = 0; pindex && nScanned < MIX_RENDEZVOUS_MAX_BLOCKS;
         pindex = pindex->pprev, ++nScanned)
    {
        const int64_t nBlockTime = pindex->GetBlockTime();
        if (nBlockTime < nEarliest)
            break;
        if (MixRendezvousPublishedInTime(nBlockTime, nSlot))
            vScan.push_back(pindex);
    }
    // Chain order, which is what first-wins is defined over.
    for (size_t i = vScan.size(); i-- > 0; )
    {
        CBlock block;
        if (!block.ReadFromDisk(vScan[i], true))
            FAIL("a block this rendezvous window covers could not be read");
        CollectMixRendezvousRecords(block, vRecordsOut);
        if (vRecordsOut.size() > MIX_RENDEZVOUS_MAX_RECORDS)
            FAIL("this rendezvous window carries more records than a seat will read");
    }
    return true;
    #undef FAIL
}

bool LookupMixRendezvous(const CBlockIndex* pindexTip, const CPubKey& pubkeyCoordinator,
                         int64_t nSlot, CMixRendezvous& rendezvousOut,
                         std::string* pstrError)
{
    rendezvousOut = CMixRendezvous();
    std::vector<std::pair<uint256, uint256> > vRecords;
    if (!ReadMixRendezvousRecords(pindexTip, nSlot, vRecords, pstrError))
        return false;
    if (!SelectMixRendezvous(vRecords, pubkeyCoordinator, nSlot, rendezvousOut))
    {
        if (pstrError)
            *pstrError = "this slot published no round for that coordinator";
        return false;
    }
    return true;
}

bool MixAnnouncementMatchesRendezvous(const CMixRoundAnnouncement& announce,
                                      const CMixRendezvous& rendezvous,
                                      std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (rendezvous.IsNull())
        FAIL("this slot has no published round; skip it rather than take an unpublished one");
    if (!(announce.pubkeyCoordinator == rendezvous.pubkeyCoordinator))
        FAIL("the announcement is not from the coordinator this slot authorises");
    // The slot the announcement belongs to is its own start time's, so a coordinator cannot
    // publish once and then run the round at a time of its choosing.
    if (MixRendezvousSlot(announce.nTime) != rendezvous.nSlot)
        FAIL("the announcement does not start in the slot it was published for");
    if (MixRendezvousCommitment(announce.pubkeyCoordinator, rendezvous.nSlot,
                                announce.hashRound) != rendezvous.hashCommitment)
        FAIL("the announcement is not the one this slot authorises");
    return true;
    #undef FAIL
}

CMixPolicy CMixPolicy::Standard()
{
    CMixPolicy out;
    out.vDenominations.push_back(100000000ULL);        // 1 INN
    out.vDenominations.push_back(1000000000ULL);       // 10 INN
    out.nFeeSharePerSeat = MIN_TX_FEE_SHIELDED;        // 0.001 INN, one shielded fee per seat
    return out;
}

bool CMixPolicy::Allows(uint64_t nDenomination) const
{
    for (size_t i = 0; i < vDenominations.size(); i++)
        if (vDenominations[i] == nDenomination)
            return true;
    return false;
}

bool CMixPolicy::AllowsRound(uint64_t nDenomination, uint64_t nFee, int nSeats,
                             std::string* pstrError) const
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (nSeats < NULLSEND_MIN_PARTICIPANTS || nSeats > (int)iv5::MAX_NULLSEND_INPUTS)
        FAIL("that seat count is outside the range a round can carry");
    if (!Allows(nDenomination))
        FAIL("that denomination is not one this wallet mixes at");
    if (nFeeSharePerSeat == 0 || nFee / (uint64_t)nSeats != nFeeSharePerSeat ||
        nFee % (uint64_t)nSeats != 0)
        FAIL("that round's fee is not the share per seat this wallet pays");
    return true;
    #undef FAIL
}

CMixSeat::CMixSeat() : fBegun(false), keyImage(0), hashViewSigned(0), nMyPosition(-1)
{
    pseudoOut.fill(0);
    pseudoOutMaskDelta.fill(0);
    approvedSigningHash.fill(0);
}

bool CMixSeat::Begin(const CMixRoundAnnouncement& announce, const CKey& keySessionIn,
                     const CMixSeatMaterial& materialIn, const CMixPolicy& policyIn,
                     const CMixRendezvous& rendezvousIn, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (fBegun)
        FAIL("this seat is already in an attempt; a new one needs fresh entropy");
    if (!announce.IsValidBasic(pstrError))
        return false;
    if (!announce.CheckSignature())
        FAIL("the announcement is not signed by the key it names");
    if (!keySessionIn.IsValid())
        FAIL("the session key is not usable");
    if ((int)materialIn.vEphemerals.size() != announce.nParticipants)
        FAIL("a bundle needs one variant per announced seat");
    // The denomination and the share are this wallet's choice, not the coordinator's: a
    // round at an amount nobody else mixes at has no anonymity to offer, and a share the
    // coordinator picked could make one seat pay a distinctive amount.
    if (!policyIn.AllowsRound(announce.nDenomination, announce.nFee, announce.nParticipants,
                              pstrError))
        return false;
    // Before anything is revealed: an announcement that is not the one its slot authorises
    // is one a coordinator could have minted per seat, and this seat would be alone in it.
    if (!MixAnnouncementMatchesRendezvous(announce, rendezvousIn, pstrError))
        return false;
    PrivacyVNextDigest zero;
    zero.fill(0);
    // Fresh per attempt, and the caller has to have drawn them: reusing either is how a
    // repeated proof or a repeated nonce gives up what it was hiding.
    if (materialIn.membershipEntropy == zero || materialIn.balanceEntropy == zero)
        FAIL("this attempt has no entropy of its own");

    announcement = announce;
    keySession = keySessionIn;
    pubkeySession = keySessionIn.GetPubKey();
    material = materialIn;
    policy = policyIn;

    // The proving pass that fixes what this seat will publish about its input. The
    // signable hash does not enter it, which is why the pseudo-output and key image can be
    // committed to before the prefix that names them exists.
    PrivacyVNextDigest provisional;
    provisional.fill(0);
    provisional[0] = 1;
    std::vector<PrivacyVNextSpendInput> vInputs(1, material.input);
    std::vector<PrivacyVNextSpendConstruction> vDraft;
    std::vector<unsigned char> vchDraft;
    std::string strProve;
    if (!ProvePrivacyVNextMembership(announce.finalizedRoot, provisional,
                                     material.membershipEntropy, vInputs, vDraft, vchDraft,
                                     strProve))
        FAIL("this seat could not prove its own input: " + strProve);
    if (vDraft.size() != 1)
        FAIL("proving returned the wrong input count");
    pseudoOut = vDraft[0].pseudoOut;
    pseudoOutMaskDelta = vDraft[0].pseudoOutMaskDelta;
    memcpy(keyImage.begin(), vDraft[0].keyImage.data(), 32);
    fBegun = true;
    return true;
    #undef FAIL
}

bool CMixSeat::BuildJoin(std::vector<unsigned char>& vchFrameOut, std::string* pstrError) const
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vchFrameOut.clear();
    if (!fBegun)
        FAIL("this seat has not started an attempt");
    std::vector<unsigned char> vchBody;
    if (!BuildMixJoinBody(pubkeySession, keyImage, vchBody) ||
        !BuildAuthedMixFrame(keySession, announcement.hashRound, MIX_FRAME_JOIN, vchBody,
                             vchFrameOut))
        FAIL("the join frame could not be built");
    return true;
    #undef FAIL
}

bool CMixSeat::AcceptRoster(const CMixSnapshot& snapshot, std::vector<unsigned char>& vchFrameOut,
                            std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vchFrameOut.clear();
    if (!fBegun)
        FAIL("this seat has not started an attempt");
    // One view per attempt. A seat that signs a second has signed two rosters, and a
    // coordinator holding both can run two rounds against one input.
    if (hashViewSigned != 0)
        FAIL("this attempt has already signed a view");
    if ((int)snapshot.vRoster.size() != announcement.nParticipants)
        FAIL("the roster is not the size the announcement published");
    bool fFound = false;
    for (size_t i = 0; i < snapshot.vRoster.size(); i++)
    {
        if (snapshot.vRoster[i].keyImage != keyImage)
            continue;
        if (!(snapshot.vRoster[i].pubkeySession == pubkeySession))
            FAIL("the roster pairs this seat's input with another session key");
        fFound = true;
    }
    if (!fFound)
        FAIL("the roster does not carry this seat");

    const uint256 hashView = MixViewDigest(announcement.hashRound, snapshot.vRoster);
    if (hashView == 0)
        FAIL("that roster has no view digest");
    std::vector<unsigned char> vchSig, vchBody;
    if (!keySession.Sign(hashView, vchSig) ||
        !BuildMixViewSigBody(pubkeySession, announcement.hashRound, vchSig, vchBody) ||
        !BuildAuthedMixFrame(keySession, announcement.hashRound, MIX_FRAME_VIEW_SIG, vchBody,
                             vchFrameOut))
        FAIL("the view signature could not be built");
    vRoster = snapshot.vRoster;
    hashViewSigned = hashView;
    return true;
    #undef FAIL
}

bool CMixSeat::BuildConstruction(std::vector<unsigned char>& vchFrameOut,
                                 std::string* pstrError) const
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vchFrameOut.clear();
    if (hashViewSigned == 0)
        FAIL("this seat has not agreed a view to construct under");
    std::vector<unsigned char> vchBody;
    if (!BuildMixInputConstructionBody(pubkeySession, announcement.hashRound, keyImage,
                                       pseudoOut, vchBody) ||
        !BuildAuthedMixFrame(keySession, announcement.hashRound, MIX_FRAME_INPUT_CONSTRUCTION,
                             vchBody, vchFrameOut))
        FAIL("the construction frame could not be built");
    return true;
    #undef FAIL
}

bool CMixSeat::BuildTokenRequest(const CMixSnapshot& snapshot,
                                 std::vector<unsigned char>& vchFrameOut, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vchFrameOut.clear();
    if (hashViewSigned == 0)
        FAIL("this seat has not agreed a view");
    // Checked BEFORE anything is blinded to it: a key the announcement did not commit to
    // is a per-seat key, and a token under one is a tag the coordinator reads off the
    // anonymous connection.
    if (!announcement.KeyOpensCommitment(snapshot.vchRsaN, snapshot.vchRsaE))
        FAIL("the round key is not the one the announcement commits to");
    if (vBundle.empty())
    {
        // The input context of the round this seat is in, which is what its own output
        // derives under -- and the roster it signed is where the key images come from.
        std::vector<PrivacyVNextDigest> vImages;
        for (size_t i = 0; i < vRoster.size(); i++)
        {
            PrivacyVNextDigest image;
            memcpy(image.data(), vRoster[i].keyImage.begin(), 32);
            vImages.push_back(image);
        }
        PrivacyVNextDigest context;
        std::string strContext;
        if (!DerivePrivacyVNextInputContext(iv5::NOTE_NULLSEND, MixTransparentBinding(), vImages,
                                            context, strContext))
            FAIL("this seat could not derive the round's input context: " + strContext);
        std::string strBundle;
        if (!BuildMixOutputBundle(announcement.nNetwork, announcement.genesis,
                                  material.recipientSpend, material.recipientView,
                                  material.outgoingSecret, context, announcement.nDenomination,
                                  material.outputY, material.outputMask, material.vEphemerals,
                                  vBundle, strBundle))
            FAIL("this seat could not build its output bundle: " + strBundle);
    }
    vchRsaN = snapshot.vchRsaN;
    vchRsaE = snapshot.vchRsaE;
    if (!blinder.BlindCredentialMessage(snapshot.vchRsaN, snapshot.vchRsaE,
                                        MixOutputBundleCredentialHash(vBundle)))
        FAIL("the bundle credential could not be blinded");
    vchBlinded = blinder.vchBlindedCredential;
    std::vector<unsigned char> vchBody;
    if (!BuildMixBlindRequestBody(pubkeySession, announcement.hashRound, vchBlinded, vchBody) ||
        !BuildAuthedMixFrame(keySession, announcement.hashRound, MIX_FRAME_BLIND_REQUEST, vchBody,
                             vchFrameOut))
        FAIL("the token request could not be built");
    return true;
    #undef FAIL
}

bool CMixSeat::AcceptToken(const std::vector<unsigned char>& vchBlindSignature,
                           std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (vchBlinded.empty())
        FAIL("this seat has not asked for a token");
    // UnblindSignature verifies the credential against the round key, keeping this on the
    // authenticated connection; a failed token must not surface on the anonymous one.
    if (!blinder.UnblindSignature(vchBlindSignature))
        FAIL("the token does not verify under the round key this seat blinded to");
    vchToken = blinder.vchCredentialHash;
    vchTokenSig = blinder.vchUnblindedSig;
    if (vchToken.size() != 32 || vchTokenSig.empty())
        FAIL("the token is not the shape a registration carries");
    return true;
    #undef FAIL
}

bool CMixSeat::BuildRegistration(std::vector<unsigned char>& vchBodyOut,
                                 std::string* pstrError) const
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vchBodyOut.clear();
    if (vchToken.empty() || vBundle.empty())
        FAIL("this seat has no token to register with");
    if (!BuildMixOutputBundleBody(vchToken, vchTokenSig, vBundle, vchBodyOut))
        FAIL("the registration could not be built");
    return true;
    #undef FAIL
}

bool CMixSeat::AcceptPrefix(const CMixSnapshot& snapshot, std::vector<unsigned char>& vchFrameOut,
                            std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vchFrameOut.clear();
    if (hashViewSigned == 0 || vBundle.empty())
        FAIL("this seat has nothing to check a prefix against");
    // One prefix per attempt. Approving a second is how one input ends up proved under two
    // statements, and the coordinator refusing to offer one is not this seat's guarantee.
    if (!vchApprovedPrefix.empty())
        FAIL("this attempt has already approved a prefix");
    if (snapshot.vchPrefix.empty())
        FAIL("the round has not frozen a prefix");

    CMixSeatExpectation expect;
    expect.nNetwork = announcement.nNetwork;
    expect.genesis = announcement.genesis;
    expect.parameterDigest = announcement.parameterDigest;
    expect.finalizedRoot = announcement.finalizedRoot;
    expect.nFinalizedTreeSize = announcement.nFinalizedTreeSize;
    expect.nFee = announcement.nFee;
    expect.nDenomination = announcement.nDenomination;
    expect.transparentBinding = MixTransparentBinding();
    for (size_t i = 0; i < vRoster.size(); i++)
        expect.vRosterKeyImages.push_back(vRoster[i].keyImage);
    expect.myKeyImage = keyImage;
    expect.myPseudoOut = pseudoOut;
    // Every variant, each valid only at its own position: the encryption binds the slot,
    // so a record kept anywhere else is a note this seat could not see.
    for (size_t i = 0; i < vBundle.size(); i++)
        expect.vMyOutputs.push_back(std::make_pair((int)i, vBundle[i]));
    std::string strCheck;
    if (!CheckMixPrefixForSeat(snapshot.vchPrefix, expect, strCheck))
        FAIL("this seat refuses the prefix: " + strCheck);

    // Which slot it was given, which is what its response has to answer for.
    CMixPrefixView view;
    if (!ParseMixPrefix(snapshot.vchPrefix, view, strCheck))
        FAIL(strCheck);
    nMyPosition = -1;
    std::vector<unsigned char> vchMine, vchTheirs;
    for (size_t i = 0; i < view.vOutputs.size(); i++)
    {
        if (!EncodeMixOutputRecord(view.vOutputs[i], vchTheirs) ||
            !EncodeMixOutputRecord(vBundle[i], vchMine))
            continue;
        if (vchMine == vchTheirs)
            nMyPosition = (int)i;
    }
    if (nMyPosition < 0)
        FAIL("this seat cannot find its own output in a prefix it just accepted");

    std::string strHash;
    if (!HashPrivacyVNextPayloadPrefix(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                       snapshot.vchPrefix, approvedSigningHash, strHash))
        FAIL(strHash);
    const uint256 hashPrefix = MixPrefixDigest(hashViewSigned, approvedSigningHash);
    std::vector<unsigned char> vchSig, vchBody;
    if (!keySession.Sign(hashPrefix, vchSig) ||
        !BuildMixPrefixSigBody(pubkeySession, announcement.hashRound, vchSig, vchBody) ||
        !BuildAuthedMixFrame(keySession, announcement.hashRound, MIX_FRAME_PREFIX_SIG, vchBody,
                             vchFrameOut))
        FAIL("the approval could not be built");
    vchApprovedPrefix = snapshot.vchPrefix;
    return true;
    #undef FAIL
}

bool CMixSeat::BuildMembershipProof(std::vector<unsigned char>& vchFrameOut,
                                    std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vchFrameOut.clear();
    if (vchApprovedPrefix.empty())
        FAIL("this seat has approved no prefix to prove under");
    std::vector<PrivacyVNextSpendInput> vInputs(1, material.input);
    std::vector<PrivacyVNextSpendConstruction> vFinal;
    std::vector<unsigned char> vchProof;
    std::string strProve;
    // The same entropy as the draft pass, which is what makes the pseudo-output it
    // published the one this proof opens; the signable hash is the approved prefix's, and
    // the prover's two streams keep the nonces apart.
    if (!ProvePrivacyVNextMembership(announcement.finalizedRoot, approvedSigningHash,
                                     material.membershipEntropy, vInputs, vFinal, vchProof,
                                     strProve))
        FAIL("this seat could not prove its input: " + strProve);
    if (vFinal.size() != 1 || !(vFinal[0].pseudoOut == pseudoOut))
        FAIL("proving did not reproduce the pseudo-output this seat published");
    std::vector<unsigned char> vchBody;
    if (!BuildMixMembershipProofBody(pubkeySession, announcement.hashRound, vchProof, vchBody) ||
        !BuildAuthedMixFrame(keySession, announcement.hashRound, MIX_FRAME_MEMBERSHIP_PROOF,
                             vchBody, vchFrameOut))
        FAIL("the proof frame could not be built");
    return true;
    #undef FAIL
}

bool CMixSeat::BalanceFacts(PrivacyVNextMixBalanceFacts& factsOut,
                            PrivacyVNextMixBalanceShare& shareOut, std::string* pstrError) const
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (vchApprovedPrefix.empty() || nMyPosition < 0)
        FAIL("this seat has approved no prefix to sign under");
    CMixPrefixView view;
    std::string strParse;
    if (!ParseMixPrefix(vchApprovedPrefix, view, strParse))
        FAIL(strParse);
    factsOut = PrivacyVNextMixBalanceFacts();
    factsOut.nInputCount = (uint8_t)view.vPseudoOuts.size();
    factsOut.nOutputCount = (uint8_t)view.vOutputs.size();
    factsOut.nTransparentValueBalance = view.nTransparentValueBalance;
    factsOut.nFee = view.nFee;
    factsOut.signableHash = approvedSigningHash;
    factsOut.vPseudoOuts = view.vPseudoOuts;
    for (size_t i = 0; i < view.vOutputs.size(); i++)
        factsOut.vOutputs.push_back(view.vOutputs[i].commitment);

    shareOut = PrivacyVNextMixBalanceShare();
    shareOut.nInputIndex = 0xff;
    for (size_t i = 0; i < view.vKeyImages.size(); i++)
        if (view.vKeyImages[i] == keyImage)
            shareOut.nInputIndex = (uint8_t)i;
    if (shareOut.nInputIndex == 0xff)
        FAIL("the approved prefix does not carry this seat's input");
    shareOut.nOutputIndex = (uint8_t)nMyPosition;
    if (announcement.nParticipants <= 0)
        FAIL("the announcement carries no seat count");
    shareOut.nFeeShare = announcement.nFee / (uint64_t)announcement.nParticipants;
    // What this seat signs with is its pseudo-output's mask: the note's own mask plus the
    // rerandomisation the proving pass drew. It never signs the difference against its
    // output, which would name that output as its own.
    std::vector<unsigned char> vchSum;
    if (!Ed25519ScalarAdd(std::vector<unsigned char>(material.noteMask.begin(),
                                                     material.noteMask.end()),
                          std::vector<unsigned char>(pseudoOutMaskDelta.begin(),
                                                     pseudoOutMaskDelta.end()),
                          vchSum) ||
        vchSum.size() != 32)
        FAIL("this seat could not form the mask it signs with");
    memcpy(shareOut.mask.data(), &vchSum[0], 32);
    shareOut.outputMask = material.outputMask;
    shareOut.entropy = material.balanceEntropy;
    return true;
    #undef FAIL
}

bool CMixSeat::BuildNonce(std::vector<unsigned char>& vchFrameOut, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vchFrameOut.clear();
    PrivacyVNextMixBalanceFacts facts;
    PrivacyVNextMixBalanceShare share;
    if (!BalanceFacts(facts, share, pstrError))
        return false;
    PrivacyVNextDigest nonce;
    std::string strNonce;
    if (!PrivacyVNextMixBalanceNonce(facts, share, nonce, strNonce))
        FAIL("this seat could not draw its nonce: " + strNonce);
    std::vector<unsigned char> vchBody;
    if (!BuildMixScalarBody(pubkeySession, std::vector<unsigned char>(nonce.begin(), nonce.end()),
                            vchBody) ||
        !BuildAuthedMixFrame(keySession, announcement.hashRound, MIX_FRAME_NONCE, vchBody,
                             vchFrameOut))
        FAIL("the nonce frame could not be built");
    return true;
    #undef FAIL
}

bool CMixSeat::BuildResponse(const CMixSnapshot& snapshot, std::vector<unsigned char>& vchFrameOut,
                             std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    vchFrameOut.clear();
    PrivacyVNextMixBalanceFacts facts;
    PrivacyVNextMixBalanceShare share;
    if (!BalanceFacts(facts, share, pstrError))
        return false;
    if (snapshot.vNonces.size() != facts.nInputCount)
        FAIL("the aggregate this seat was shown does not cover every input");
    // The challenge is rebuilt from the prefix this seat approved and the aggregate it read
    // back, never from anything the coordinator states about either.
    PrivacyVNextDigest response;
    std::string strSign;
    if (!PrivacyVNextMixBalanceSign(facts, share, snapshot.vNonces, response, strSign))
        FAIL("this seat could not answer the challenge: " + strSign);
    std::vector<unsigned char> vchBody;
    if (!BuildMixScalarBody(pubkeySession,
                            std::vector<unsigned char>(response.begin(), response.end()),
                            vchBody) ||
        !BuildAuthedMixFrame(keySession, announcement.hashRound, MIX_FRAME_RESPONSE, vchBody,
                             vchFrameOut))
        FAIL("the response frame could not be built");
    return true;
    #undef FAIL
}
