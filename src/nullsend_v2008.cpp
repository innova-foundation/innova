#include "nullsend_v2008.h"

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
