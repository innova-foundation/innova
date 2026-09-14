#include "nullsend_v2008.h"

#include <algorithm>
#include <limits>

#include "netbase.h"
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

uint256 CMixRoundAnnouncement::DerivedRoundId() const
{
    // Every field but hashRound and the signature. Including hashRound would be
    // circular; including the signature would make the identifier depend on the nonce.
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/round-id/v1");
    ss << nVersion;
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

uint256 MixOutputCredentialHash(const uint256& outputKey)
{
    // The round is deliberately absent: see the header. Including it turned the credential
    // into a per-seat tag under a coordinator that gives each seat its own round id.
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/token/v2");
    ss << outputKey;
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
      fStreamIsolated(false), fNoncesFrozen(false), fHasSigned(false),
      nOpened(0), nWindowCloses(0)
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
    fNoncesFrozen = false;
    fHasSigned = false;
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
    // The token names the key it authorises, so rewriting the key in flight makes the
    // token stop opening. A token from another round is refused by the signature check
    // below instead, because it was signed under that round's modulus -- which is why the
    // round must not appear in the message. Checked first: this is arithmetic-free.
    const uint256 hashExpected = MixOutputCredentialHash(outputKey);
    if (vchCredential.size() != 32 ||
        !std::equal(hashExpected.begin(), hashExpected.end(), vchCredential.begin()))
        FAIL("token does not authorise this output key in this round");
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
    // A round signs once. Signing again over one payload with a different set of
    // nonce points is how a coordinator recovers a participant's mask from two
    // responses under two challenges, so the second attempt ends the round instead
    // of producing the pair that leaks.
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

bool CMixRound::IsExpired(int64_t nNow) const
{
    if (nPhase == MIX_PHASE_COMPLETE || nPhase == MIX_PHASE_ABORTED)
        return false;
    return (nNow - nOpened) > NULLSEND_QUEUE_TIMEOUT;
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
                      std::string* pstrError)
{
    #define FAIL(msg) do { if (pstrError) *pstrError = (msg); return false; } while (0)
    if (hSocket == INVALID_SOCKET)
        FAIL("stream is not open");
    std::vector<unsigned char> vchFrame;
    if (!BuildMixFrame(nType, vchPayload, vchFrame))
        FAIL("frame has no encoding");
    size_t nSent = 0;
    while (nSent < vchFrame.size())
    {
        const ssize_t nWrote = send(hSocket, (const char*)&vchFrame[nSent],
                                    vchFrame.size() - nSent, MSG_NOSIGNAL);
        if (nWrote <= 0)
            FAIL("the peer went away mid-frame");
        nSent += (size_t)nWrote;
    }
    return true;
    #undef FAIL
}

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

bool BuildMixOutputBody(const std::vector<unsigned char>& vchCredential,
                        const std::vector<unsigned char>& vchBlindSignature,
                        const uint256& outputKey,
                        std::vector<unsigned char>& vchOut)
{
    vchOut.clear();
    if (vchCredential.empty() || vchCredential.size() > 0xFFFF)
        return false;
    if (vchBlindSignature.empty() || vchBlindSignature.size() > 0xFFFF)
        return false;
    PutU16(vchOut, vchCredential.size());
    vchOut.insert(vchOut.end(), vchCredential.begin(), vchCredential.end());
    PutU16(vchOut, vchBlindSignature.size());
    vchOut.insert(vchOut.end(), vchBlindSignature.begin(), vchBlindSignature.end());
    vchOut.insert(vchOut.end(), outputKey.begin(), outputKey.end());
    return true;
}

MixDispatch DispatchMixFrame(CMixRound& round,
                             MixFrameType nType,
                             const std::vector<unsigned char>& vchPayload,
                             int64_t nNow, std::string& strError)
{
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
        std::vector<unsigned char> vchCredential, vchBlindSignature, vchKey;
        if (!TakeU16(vchPayload, nAt, nLen) || !TakeBytes(vchPayload, nAt, nLen, vchCredential))
            REFUSE("output frame is malformed");
        if (!TakeU16(vchPayload, nAt, nLen) || !TakeBytes(vchPayload, nAt, nLen, vchBlindSignature))
            REFUSE("output frame is malformed");
        if (!TakeBytes(vchPayload, nAt, 32, vchKey) || nAt != vchPayload.size())
            REFUSE("output frame is malformed");
        uint256 outputKey;
        memcpy(outputKey.begin(), &vchKey[0], 32);
        if (!round.RegisterOutput(vchCredential, vchBlindSignature, outputKey, nNow, &strError))
            return MIX_DISPATCH_REFUSED;
        return MIX_DISPATCH_OK;
    }

    if (nType != MIX_FRAME_JOIN && nType != MIX_FRAME_NONCE && nType != MIX_FRAME_RESPONSE)
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
        if (!round.SubmitNonce(pubkeySession, vchTail, &strError))
            return MIX_DISPATCH_REFUSED;
        return MIX_DISPATCH_OK;
    }
    if (!round.SubmitResponse(pubkeySession, vchTail, &strError))
        return round.Phase() == MIX_PHASE_ABORTED ? MIX_DISPATCH_ABORTED : MIX_DISPATCH_REFUSED;
    return MIX_DISPATCH_OK;
    #undef REFUSE
}
