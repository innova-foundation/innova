// The v2008 mix round announcement. Kept apart from the legacy structures in nullsend.h,
// which serialize on a live wire until Boundary A.

#ifndef INNOVA_NULLSEND_V2008_H
#define INNOVA_NULLSEND_V2008_H

#include <string>
#include <vector>

#include "key.h"
#include "serialize.h"
#include "uint256.h"
#include "util.h"

/** How long an announcement stays joinable. */
static const int64_t MIX_ROUND_ANNOUNCE_TIMEOUT = 300;
/** Bound on the endpoint string, so a decoder cannot be made to hold an
 *  unbounded name. A v3 onion address is 62 characters. */
static const size_t MIX_ROUND_ENDPOINT_MAX = 255;

/** The commitment a round announcement carries to the coordinator's blind-signature key.
 *  Blind signatures do not bind the key to the round, so a participant refuses any key
 *  that does not open this commitment (prevents per-participant keys). */
uint256 MixRoundKeyCommitment(const std::vector<unsigned char>& vchRSA_N,
                              const std::vector<unsigned char>& vchRSA_E);

class CMixRoundAnnouncement
{
public:
    static const int CURRENT_VERSION = 1;

    int nVersion;
    uint256 hashRound;
    uint256 hashRoundKey;
    std::string strEndpoint;
    int nPort;
    int nParticipants;
    int64_t nTime;
    CPubKey pubkeyCoordinator;
    std::vector<unsigned char> vchSig;

    CMixRoundAnnouncement()
    {
        SetNull();
    }

    void SetNull()
    {
        nVersion = CURRENT_VERSION;
        hashRound = 0;
        hashRoundKey = 0;
        strEndpoint.clear();
        nPort = 0;
        nParticipants = 0;
        nTime = 0;
        pubkeyCoordinator = CPubKey();
        vchSig.clear();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nVersion);
        READWRITE(hashRound);
        READWRITE(hashRoundKey);
        READWRITE(strEndpoint);
        READWRITE(nPort);
        READWRITE(nParticipants);
        READWRITE(nTime);
        READWRITE(pubkeyCoordinator);
        READWRITE(vchSig);
    )

    /** Everything the coordinator commits to, which is every field but the
     *  signature. The key commitment is inside it: an announcement whose
     *  commitment could be edited in flight would commit to nothing. */
    uint256 GetSignatureHash() const;

    bool Sign(const CKey& key);
    bool CheckSignature() const;

    bool IsExpired(int64_t nNow) const { return (nNow - nTime) > MIX_ROUND_ANNOUNCE_TIMEOUT; }

    /** Shape only: nothing here reads the chain. */
    bool IsValidBasic(std::string* pstrError = NULL) const;

    /** Whether a key handed out later is the one this announcement named. The
     *  participant calls it before blinding anything. */
    bool KeyOpensCommitment(const std::vector<unsigned char>& vchRSA_N,
                            const std::vector<unsigned char>& vchRSA_E) const;
};

#endif // INNOVA_NULLSEND_V2008_H
