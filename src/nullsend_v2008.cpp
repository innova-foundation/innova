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
