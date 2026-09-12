#include "nullsend_v2008.h"

#include <algorithm>

#include "nullsend.h"
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

uint256 CMixRoundAnnouncement::GetSignatureHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/announce/v1");
    ss << nVersion;
    ss << hashRound;
    ss << hashRoundKey;
    ss << strEndpoint;
    ss << nPort;
    ss << nParticipants;
    ss << nTime;
    ss << pubkeyCoordinator;
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
    if (strEndpoint.empty() || strEndpoint.size() > MIX_ROUND_ENDPOINT_MAX)
        FAIL("endpoint is empty or too long");
    if (nPort < 1 || nPort > 65535)
        FAIL("port is out of range");
    if (nParticipants < NULLSEND_MIN_PARTICIPANTS || nParticipants > (int)iv5::MAX_NULLSEND_INPUTS)
        FAIL("participant count is outside the range a v2008 mix can carry");
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
      fStreamIsolated(false), nOpened(0), nWindowCloses(0)
{
    strAbortReason = "not opened";
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
                     int64_t nNow, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
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
    nOpened = nNow;
    nWindowCloses = 0;
    strAbortReason.clear();
    vParticipants.clear();
    vFinalKeyImages.clear();
    vOutputs.clear();
    vSpentCredentials.clear();
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
    // Sorted, because the index is derived from the set and not from arrival order:
    // two coordinators reading the same seats must reach the same index.
    std::sort(vFinalKeyImages.begin(), vFinalKeyImages.end());
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

bool CMixRound::OpenOutputWindow(int64_t nNow, std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_KEYED, pstrError))
        return false;
    for (size_t i = 0; i < vParticipants.size(); i++)
        if (!vParticipants[i].fTokenIssued)
            FAIL("a seat holds no token; it could not register an output");
    nWindowCloses = nNow + MIX_OUTPUT_WINDOW;
    nPhase = MIX_PHASE_OUTPUT;
    return true;
    #undef FAIL
}

bool CMixRound::RegisterOutput(const std::vector<unsigned char>& vchCredential,
                               const std::vector<unsigned char>& vchBlindSignature,
                               const uint256& outputKey, int64_t nNow,
                               std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (!Require(MIX_PHASE_OUTPUT, pstrError))
        return false;
    if (nNow > nWindowCloses)
        FAIL("the output window has closed");
    if (outputKey == 0)
        FAIL("output has no key");
    if (vchCredential.empty() || vchBlindSignature.empty())
        FAIL("output carries no token");
    if (!VerifyMixCredential(vchRSA_N, vchRSA_E, vchCredential, vchBlindSignature))
        FAIL("token does not verify under the round key");
    // One token, once. Nothing else limits how many outputs an unlinkable caller may
    // present, and the token is deliberately not tied to a seat.
    CHashWriter ss(SER_GETHASH, 0);
    ss << vchCredential;
    const uint256 hashCredential = ss.GetHash();
    for (size_t i = 0; i < vSpentCredentials.size(); i++)
        if (vSpentCredentials[i] == hashCredential)
            FAIL("token has already registered an output");
    if (vOutputs.size() >= vParticipants.size())
        FAIL("every seat already has an output");
    for (size_t i = 0; i < vOutputs.size(); i++)
        if (vOutputs[i] == outputKey)
            FAIL("output key is already registered");
    vSpentCredentials.push_back(hashCredential);
    vOutputs.push_back(outputKey);
    return true;
    #undef FAIL
}

bool CMixRound::CanPublish(int64_t nNow) const
{
    if (nPhase != MIX_PHASE_OUTPUT)
        return false;
    if (vOutputs.size() != vParticipants.size())
        return false;
    // Not when the last output arrives: the window is what decorrelates arrival order
    // from registration order, and publishing early throws that away.
    return nNow > nWindowCloses;
}

void CMixRound::Drop(const CPubKey& pubkeySession)
{
    if (nPhase == MIX_PHASE_COMPLETE || nPhase == MIX_PHASE_ABORTED)
        return;
    if (nPhase != MIX_PHASE_JOIN)
    {
        // The self-pay index binds the key image set, so losing a seat re-points
        // every participant's output. Carrying on would build a payload whose
        // outputs sit at an index nobody derived.
        Abort("a seat was lost after the input set was frozen");
        return;
    }
    for (size_t i = 0; i < vParticipants.size(); i++)
    {
        if (vParticipants[i].pubkeySession == pubkeySession)
        {
            vParticipants.erase(vParticipants.begin() + i);
            return;
        }
    }
}

void CMixRound::Abort(const std::string& strReason)
{
    nPhase = MIX_PHASE_ABORTED;
    strAbortReason = strReason;
}

bool CMixRound::IsExpired(int64_t nNow) const
{
    if (nPhase == MIX_PHASE_COMPLETE || nPhase == MIX_PHASE_ABORTED)
        return false;
    return (nNow - nOpened) > NULLSEND_QUEUE_TIMEOUT;
}
