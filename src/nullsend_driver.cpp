// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nullsend_driver.h"

#include <algorithm>
#include <limits>

// ---------------------------------------------------------------------------
// Coordinator
// ---------------------------------------------------------------------------

CMixCoordinatorJob::CMixCoordinatorJob(const CMixCoordinatorConfig& configIn,
                                       CMixCoordinatorEnv& envIn, CMixDialer& dialerIn)
    : config(configIn), env(envIn), dialer(dialerIn), nState(MIX_COORD_WAITING),
      strStatus("waiting for the publishing window"), txidRecord(0), nNextUpload(0),
      fRecordMined(false), fBroadcast(false), nNextBroadcast(0)
{
}

void CMixCoordinatorJob::Fail(const std::string& strWhy)
{
    nState = MIX_COORD_FAILED;
    strStatus = strWhy;
}

bool CMixCoordinatorJob::OpenIfUploaded(int64_t nNow)
{
    if (nState != MIX_COORD_PUBLISHED ||
        std::find(vUploaded.begin(), vUploaded.end(), true) == vUploaded.end())
        return false;
    std::string strError;
    if (!coordinator.Open(announce, roundKey, nNow, &strError))
    {
        Fail("the round could not be opened: " + strError);
        return false;
    }
    nState = MIX_COORD_UPLOADED;
    strStatus = "round open";
    return true;
}

void CMixCoordinatorJob::Step(int64_t nNow)
{
    // Uploads dial directories and each can take an exchange's whole deadline, so they run
    // outside the lock every request for the round needs.
    std::vector<size_t> vDue;
    CMixRoundAnnouncement announceSent;
    {
        LOCK(cs);
        StepLocked(nNow);
        const bool fWanted =
            (nState == MIX_COORD_PUBLISHED && fRecordMined) ||
            (nState == MIX_COORD_UPLOADED &&
             nNow + MIX_EXCHANGE_TIMEOUT_MS / 1000 < announce.nTime);
        if (fWanted && nNow >= nNextUpload)
        {
            for (size_t i = 0; i < vUploaded.size(); i++)
                if (!vUploaded[i])
                    vDue.push_back(i);
            announceSent = announce;
            nNextUpload = nNow + UPLOAD_RETRY_SECS;
        }
    }
    if (vDue.empty())
        return;
    std::vector<size_t> vTaken;
    for (size_t k = 0; k < vDue.size(); k++)
    {
        std::vector<CMixDirectoryEndpoint> vOne(1, config.vDirectories[vDue[k]]);
        int nAccepted = 0;
        std::string strError;
        if (UploadMixAnnouncement(dialer, vOne, announceSent, nAccepted, &strError) &&
            nAccepted > 0)
            vTaken.push_back(vDue[k]);
    }
    LOCK(cs);
    for (size_t k = 0; k < vTaken.size(); k++)
        vUploaded[vTaken[k]] = true;
    OpenIfUploaded(nNow);
}

void CMixCoordinatorJob::StepLocked(int64_t nNow)
{
    std::string strError;
    if (nState == MIX_COORD_WAITING)
    {
        CMixRoundPlan planNew;
        if (!env.PlanRound(nNow, planNew, strError))
        {
            strStatus = "waiting: " + strError;
            return;
        }
        plan = planNew;
        roundKey = CNullSendSession();
        roundKey.nSessionID = GetRandInt(std::numeric_limits<int>::max());
        if (!roundKey.GenerateSessionRSAKey())
            return Fail("the round key could not be generated");

        announce.SetNull();
        announce.hashRoundKey = MixRoundKeyCommitment(roundKey.vchRSA_N, roundKey.vchRSA_E);
        announce.strEndpoint = config.strEndpoint;
        announce.nPort = config.nPort;
        announce.nParticipants = config.nParticipants;
        env.ChainIdentity(announce.nNetwork, announce.genesis);
        plan.ApplyTo(announce);
        announce.nDenomination = config.nDenomination;
        announce.nFee = (uint64_t)config.nParticipants * config.nFeeSharePerSeat;
        if (!announce.Sign(config.keyCoordinator))
            return Fail("the announcement could not be signed");
        if (!announce.IsValidBasic(&strError))
            return Fail("the planned round is not valid: " + strError);

        CMixRendezvousRecord record;
        if (!SignMixRendezvous(config.keyCoordinator, plan.nSlot, announce.hashRound, record,
                               &strError))
            return Fail("the rendezvous record could not be signed: " + strError);
        if (!env.PublishRecord(BuildMixRendezvousScript(record), txidRecord, strError))
            return Fail("the rendezvous record could not be published: " + strError);
        vUploaded.assign(config.vDirectories.size(), false);
        nNextUpload = nNow;
        fRecordMined = false;
        nState = MIX_COORD_PUBLISHED;
        strStatus = "record published, waiting for it to be mined";
        return;
    }
    if (nState == MIX_COORD_PUBLISHED)
    {
        if (!fRecordMined)
        {
            if (!env.RecordConfirmed(txidRecord))
            {
                // Mined after the opening, it is outside the only window a seat reads.
                if (nNow >= plan.nSlot * MIX_RENDEZVOUS_SLOT_SECONDS)
                    Fail("the record was not mined before its slot opened");
                return;
            }
            fRecordMined = true;
            strStatus = "record mined, no directory has taken the announcement yet";
        }
        if (OpenIfUploaded(nNow))
            return;
        if (nNow >= announce.nTime)
            Fail("no directory took the announcement before the round started");
        return;
    }
    if (nState == MIX_COORD_UPLOADED)
    {
        coordinator.Tick(nNow);
        if (coordinator.HasTransaction() && !fBroadcast && nNow >= nNextBroadcast)
        {
            // A refused broadcast is tried again on an interval: each attempt verifies the
            // payload under cs_main.
            nNextBroadcast = nNow + UPLOAD_RETRY_SECS;
            if (env.Broadcast(coordinator.Transaction(), strError))
            {
                fBroadcast = true;
                strStatus = "transaction broadcast";
            }
            else
                strStatus = "transaction assembled, broadcast refused: " + strError;
        }
        if (nNow > announce.Ends())
        {
            nState = MIX_COORD_DONE;
            if (!fBroadcast)
                strStatus = coordinator.HasTransaction() ? "round ended; broadcast never accepted"
                                                         : "round ended without a transaction";
        }
    }
}

bool CMixCoordinatorJob::Serve(MixFrameType nType, const std::vector<unsigned char>& vchPayload,
                               int64_t nNow, MixFrameType& nReplyTypeOut,
                               std::vector<unsigned char>& vchReplyOut)
{
    LOCK(cs);
    nReplyTypeOut = MIX_FRAME_NONE;
    vchReplyOut.clear();
    if (nState != MIX_COORD_UPLOADED)
        return false;
    return coordinator.Serve(nType, vchPayload, nNow, nReplyTypeOut, vchReplyOut);
}

MixCoordinatorJobState CMixCoordinatorJob::State() const
{
    LOCK(cs);
    return nState;
}

std::string CMixCoordinatorJob::Status() const
{
    LOCK(cs);
    return strStatus;
}

CMixRoundAnnouncement CMixCoordinatorJob::Announcement() const
{
    LOCK(cs);
    return announce;
}

bool CMixCoordinatorJob::Broadcasted() const
{
    LOCK(cs);
    return fBroadcast;
}

// ---------------------------------------------------------------------------
// Seat
// ---------------------------------------------------------------------------

CMixSeatJob::CMixSeatJob(const CMixSeatConfig& configIn, CMixSeatEnv& envIn,
                         CMixDialer& dialerIn)
    : config(configIn), env(envIn), dialer(dialerIn), nState(MIX_SEAT_FINDING),
      strStatus("waiting for the record slot to settle"), nNextAction(0),
      nExchangeTimeoutMs(MIX_EXCHANGE_TIMEOUT_MS), nWindowCloses(0), fKeyImageRevealed(false),
      fFinalShareSent(false), fCancelled(false)
{
    NewCircuit();
}

void CMixSeatJob::NewCircuit()
{
    unsigned char vch[16];
    GetRandBytes(vch, sizeof(vch));
    strCircuit = HexStr(vch, vch + sizeof(vch));
}

MixSeatJobState CMixSeatJob::State() const { return nState; }
std::string CMixSeatJob::Status() const { return strStatus; }
bool CMixSeatJob::KeyImageRevealed() const { return fKeyImageRevealed; }
bool CMixSeatJob::FinalShareSent() const { return fFinalShareSent; }

bool CMixSeatJob::Cancel(bool fForce, std::string& strWhyNot)
{
    if (nState == MIX_SEAT_DONE || nState == MIX_SEAT_FAILED)
    {
        strWhyNot = "the attempt has already ended";
        return false;
    }
    if (fFinalShareSent)
    {
        strWhyNot = "the final share has left: the note is committed to this round and a "
                    "transaction spending it may still be published, so the attempt runs to "
                    "the round's end";
        return false;
    }
    if (fKeyImageRevealed && !fForce)
    {
        strWhyNot = "the key image has gone to the coordinator: cancelling now ends the round "
                    "for every seat and does not take the key image back; pass force to "
                    "cancel anyway";
        return false;
    }
    Fail(fKeyImageRevealed ? "cancelled by the user after the key image was sent"
                           : "cancelled by the user");
    fCancelled = true;
    return true;
}

void CMixSeatJob::Fail(const std::string& strWhy)
{
    // Before the last share has left, the note is only disclosed, not committed; after, the
    // coordinator may hold a transaction that spends it, so it stays held.
    if (nState >= MIX_SEAT_BEGUN && !fFinalShareSent)
        env.ReleaseNote();
    nState = MIX_SEAT_FAILED;
    strStatus = strWhy;
    if (fFinalShareSent)
        strStatus += "; the note stays held and out of other rounds until a transaction "
                     "spending it is mined, or until z_holdiv5note releases it by hand";
}

void CMixSeatJob::Window(int64_t nNow, int64_t nCloses)
{
    nWindowCloses = nCloses;
    const int64_t nLeftMs = (nCloses - nNow) * 1000;
    nExchangeTimeoutMs = (int)std::max<int64_t>(
        3000, std::min<int64_t>(nLeftMs, MIX_EXCHANGE_TIMEOUT_MS));
}

const int64_t CMixSeatJob::RETRY_SECS;

int64_t MixSeatRetryDelay(int64_t nNow, int64_t nWindowCloses)
{
    if (nWindowCloses <= 0)
        return CMixSeatJob::RETRY_SECS;
    const int64_t nLeft = nWindowCloses - nNow;
    return std::min<int64_t>(CMixSeatJob::RETRY_SECS, std::max<int64_t>(1, nLeft / 3));
}

int64_t MixSeatRetryWait(int64_t nNow, int64_t nWindowCloses)
{
    // Drawn from the upper half of the bound, so a seat's retries keep no fixed cadence.
    const int64_t nMax = MixSeatRetryDelay(nNow, nWindowCloses);
    const int64_t nMin = std::max<int64_t>(1, (nMax + 1) / 2);
    return nMin + GetRandInt((int)(nMax - nMin + 1));
}

void CMixSeatJob::Retry(int64_t nNow)
{
    nNextAction = nNow + MixSeatRetryWait(nNow, nWindowCloses);
}

void CMixSeatJob::Schedule(int64_t nFrom, int64_t nUntil)
{
    if (nUntil <= nFrom)
    {
        nNextAction = nFrom;
        return;
    }
    const int64_t nSpan = std::min<int64_t>(nUntil - nFrom, std::numeric_limits<int>::max());
    nNextAction = nFrom + GetRandInt((int)nSpan);
}

bool CMixSeatJob::Ask(MixFrameType nType, const std::vector<unsigned char>& vchPayload,
                      MixFrameType& nReplyOut, std::vector<unsigned char>& vchReplyOut)
{
    // An authenticated frame already names its seat, so sharing the seat's circuit tells the
    // coordinator nothing new. The output registration and the public result read go on
    // circuits of their own: one must never name the seat, the other need not.
    const std::string strOn = IsAuthenticatedMixFrame(nType) ? strCircuit : std::string();
    std::string strError;
    if (!dialer.Exchange(announce.strEndpoint, announce.nPort, nType, vchPayload, nReplyOut,
                         vchReplyOut, &strError, nExchangeTimeoutMs, strOn))
    {
        // Tor keeps sending the seat's streams down a circuit that has died, each until its
        // deadline, so the next attempt goes on a new one.
        if (!strOn.empty())
            NewCircuit();
        strStatus = "exchange failed: " + strError;
        return false;
    }
    return true;
}

bool CMixSeatJob::AskAccepted(MixFrameType nType, const std::vector<unsigned char>& vchPayload)
{
    MixFrameType nReply = MIX_FRAME_NONE;
    std::vector<unsigned char> vchReply;
    bool fAccepted = false;
    return Ask(nType, vchPayload, nReply, vchReply) && nReply == MIX_FRAME_ACK &&
           ReadMixAckBody(vchReply, fAccepted) && fAccepted;
}

bool CMixSeatJob::ReadSnapshot(CMixSnapshot& snapshotOut)
{
    std::vector<unsigned char> vchRequest, vchReply;
    MixFrameType nReply = MIX_FRAME_NONE;
    return seat.BuildStateRequest(vchRequest) &&
           Ask(MIX_FRAME_STATE_AUTH, vchRequest, nReply, vchReply) &&
           nReply == MIX_FRAME_SNAPSHOT && ReadMixSnapshotBody(vchReply, snapshotOut);
}

bool CMixSeatJob::FreshAnchor(int64_t nNow, CMixAnchorView& viewOut)
{
    std::string strError;
    if (!env.ReadAnchor(announce, nNow, viewOut, strError))
    {
        strStatus = "the anchor cannot be read: " + strError;
        return false;
    }
    return true;
}

void CMixSeatJob::Step(int64_t nNow)
{
    if (nState == MIX_SEAT_DONE || nState == MIX_SEAT_FAILED || !Due(nNow))
        return;
    std::string strError;
    const int64_t nConnectBy = announce.ResponseCloses() + MIX_INCLUSION_ALLOWANCE_SECS;

    switch (nState)
    {
    case MIX_SEAT_FINDING:
    {
        if (rendezvous.IsNull())
        {
            bool fPending = false;
            if (!env.ReadRendezvous(config.pubkeyCoordinator, config.nRecordSlot, rendezvous,
                                    fPending, strError))
            {
                if (fPending)
                {
                    strStatus = "waiting for the record slot to settle";
                    Retry(nNow);
                    return;
                }
                return Fail("the record slot cannot be read: " + strError);
            }
            if (rendezvous.IsNull())
                return Fail("the slot published no round for this coordinator");
        }
        // A round runs in the slot after its record's and starts inside it.
        if (nNow >= (config.nRecordSlot + 2) * MIX_RENDEZVOUS_SLOT_SECONDS)
            return Fail("the round's slot has passed");
        CMixRoundAnnouncement fetched;
        if (!FetchMixAnnouncement(dialer, config.vDirectories, rendezvous, fetched, &strError))
        {
            strStatus = "fetching the announcement: " + strError;
            Retry(nNow);
            return;
        }
        announce = fetched;
        if (nNow >= announce.JoinCloses())
            return Fail("the announcement arrived after its join window closed");
        nState = MIX_SEAT_READY;
        strStatus = "announcement verified against the chain";
        nNextAction = nNow;
        return;
    }
    case MIX_SEAT_READY:
    {
        CMixSeatMaterial material;
        if (!env.BuildMaterial(announce, material, strError))
            return Fail("no note for this round: " + strError);
        nState = MIX_SEAT_BEGUN;   // the note is held from here
        CMixAnchorView view;
        if (!FreshAnchor(nNow, view))
            return Fail(strStatus);
        CKey keySession;
        keySession.MakeNewKey(true);
        if (!seat.Begin(announce, keySession, material, config.policy, rendezvous, view,
                        &strError))
            return Fail("refused the round: " + strError);
        strStatus = "proved, waiting to join";
        Schedule(std::max(nNow, announce.nTime), announce.nTime + announce.nJoinSecs / 2);
        return;
    }
    case MIX_SEAT_BEGUN:
    {
        if (nNow >= announce.JoinCloses())
        {
            // A JOIN the round took whose reply never arrived: the seat is in the roster, and
            // an authenticated read is the one request that says so.
            CMixSnapshot snapshot;
            if (fKeyImageRevealed && ReadSnapshot(snapshot))
            {
                nState = MIX_SEAT_JOINED;
                strStatus = "joined";
                nNextAction = nNow;
                return;
            }
            return Fail("the join window closed before the key image went out");
        }
        Window(nNow, announce.JoinCloses());
        CMixAnchorView view;
        if (!FreshAnchor(nNow, view))
            return Fail(strStatus);
        if (vchJoin.empty())
        {
            if (!seat.BuildJoin(view, vchJoin, &strError))
                return Fail("refused to join: " + strError);
        }
        else if (!CheckMixAnchorBudget(announce, view, nConnectBy, &strError))
            return Fail("refused to join: " + strError);
        fKeyImageRevealed = true;
        if (!AskAccepted(MIX_FRAME_JOIN, vchJoin))
        {
            Retry(nNow);
            return;
        }
        nState = MIX_SEAT_JOINED;
        strStatus = "joined";
        Schedule(announce.JoinCloses(), announce.JoinCloses() + announce.nViewSecs / 3);
        return;
    }
    case MIX_SEAT_JOINED:
    {
        if (nNow >= announce.ViewCloses())
            return Fail("the view window closed before this seat signed a view");
        Window(nNow, announce.ViewCloses());
        if (vchViewSig.empty())
        {
            CMixSnapshot snapshot;
            if (!ReadSnapshot(snapshot) || (int)snapshot.vRoster.size() != announce.nParticipants)
            {
                Retry(nNow);
                return;
            }
            CMixAnchorView view;
            if (!FreshAnchor(nNow, view))
                return Fail(strStatus);
            if (!seat.AcceptRoster(snapshot, view, vchViewSig, &strError))
                return Fail("refused the view: " + strError);
            std::vector<uint256> vImages;
            for (size_t i = 0; i < seat.Roster().size(); i++)
                vImages.push_back(seat.Roster()[i].keyImage);
            PrivacyVNextDigest spend, viewKey, outgoing;
            if (!env.DeriveRecipient(vImages, spend, viewKey, outgoing, strError) ||
                !seat.SetRecipient(spend, viewKey, outgoing, &strError))
                return Fail("no recipient for this round: " + strError);
        }
        if (!AskAccepted(MIX_FRAME_VIEW_SIG, vchViewSig))
        {
            Retry(nNow);
            return;
        }
        nState = MIX_SEAT_VIEWED;
        strStatus = "view signed";
        nNextAction = nNow;
        return;
    }
    case MIX_SEAT_VIEWED:
    {
        // Taken only once every seat has signed the same view, so a refusal is a wait.
        if (nNow >= announce.ViewCloses())
            return Fail("the view window closed before this seat's construction was taken");
        Window(nNow, announce.ViewCloses());
        if (vchConstruction.empty() && !seat.BuildConstruction(vchConstruction, &strError))
            return Fail(strError);
        if (!AskAccepted(MIX_FRAME_INPUT_CONSTRUCTION, vchConstruction))
        {
            Retry(nNow);
            return;
        }
        nState = MIX_SEAT_CONSTRUCTED;
        strStatus = "construction taken";
        Schedule(announce.ViewCloses(), announce.ViewCloses() + announce.nTokenSecs / 2);
        return;
    }
    case MIX_SEAT_CONSTRUCTED:
    {
        if (nNow >= announce.TokenCloses())
            return Fail("the token window closed before this seat held a token");
        Window(nNow, announce.TokenCloses());
        if (vchTokenRequest.empty())
        {
            CMixSnapshot snapshot;
            if (!ReadSnapshot(snapshot) || snapshot.vchRsaN.empty())
            {
                Retry(nNow);
                return;
            }
            if (!seat.BuildTokenRequest(snapshot, vchTokenRequest, &strError))
                return Fail("refused the round key: " + strError);
        }
        MixFrameType nReply = MIX_FRAME_NONE;
        std::vector<unsigned char> vchReply;
        if (!Ask(MIX_FRAME_BLIND_REQUEST, vchTokenRequest, nReply, vchReply) ||
            nReply != MIX_FRAME_BLIND_SIGNATURE)
        {
            Retry(nNow);
            return;
        }
        if (!seat.AcceptToken(vchReply, &strError))
            return Fail("the token does not verify: " + strError);
        nState = MIX_SEAT_TOKENED;
        strStatus = "token held";
        Schedule(announce.TokenCloses(),
                 announce.TokenCloses() + (2 * (int64_t)announce.nOutputSecs) / 3);
        return;
    }
    case MIX_SEAT_TOKENED:
    {
        if (nNow > announce.OutputCloses())
            return Fail("the output window closed before this seat registered");
        Window(nNow, announce.OutputCloses());
        if (vchRegistration.empty() && !seat.BuildRegistration(vchRegistration, &strError))
            return Fail(strError);
        if (!AskAccepted(MIX_FRAME_OUTPUT, vchRegistration))
        {
            Retry(nNow);
            return;
        }
        nState = MIX_SEAT_REGISTERED;
        strStatus = "output registered";
        Schedule(announce.OutputCloses() + 1,
                 announce.OutputCloses() + 1 + announce.nApproveSecs / 3);
        return;
    }
    case MIX_SEAT_REGISTERED:
    {
        if (nNow >= announce.ApproveCloses())
            return Fail("the approval window closed before this seat approved a prefix");
        Window(nNow, announce.ApproveCloses());
        if (vchPrefixSig.empty())
        {
            CMixSnapshot snapshot;
            if (!ReadSnapshot(snapshot) || snapshot.vchPrefix.empty())
            {
                Retry(nNow);
                return;
            }
            CMixAnchorView view;
            if (!FreshAnchor(nNow, view))
                return Fail(strStatus);
            if (!seat.AcceptPrefix(snapshot, view, vchPrefixSig, &strError))
                return Fail("refused the prefix: " + strError);
        }
        if (!AskAccepted(MIX_FRAME_PREFIX_SIG, vchPrefixSig))
        {
            Retry(nNow);
            return;
        }
        nState = MIX_SEAT_APPROVED;
        strStatus = "prefix approved";
        nNextAction = nNow;
        return;
    }
    case MIX_SEAT_APPROVED:
    {
        // Taken only once every seat has approved, so a refusal is a wait.
        if (nNow >= announce.ApproveCloses())
            return Fail("the approval window closed before this seat's proof was taken");
        Window(nNow, announce.ApproveCloses());
        if (vchProof.empty() && !seat.BuildMembershipProof(vchProof, &strError))
            return Fail(strError);
        if (!AskAccepted(MIX_FRAME_MEMBERSHIP_PROOF, vchProof))
        {
            Retry(nNow);
            return;
        }
        nState = MIX_SEAT_PROVED;
        strStatus = "proof taken";
        Schedule(announce.ApproveCloses(), announce.ApproveCloses() + announce.nNonceSecs / 2);
        return;
    }
    case MIX_SEAT_PROVED:
    {
        if (nNow >= announce.NonceCloses())
            return Fail("the nonce window closed before this seat's nonce was taken");
        Window(nNow, announce.NonceCloses());
        if (vchNonce.empty() && !seat.BuildNonce(vchNonce, &strError))
            return Fail(strError);
        if (!AskAccepted(MIX_FRAME_NONCE, vchNonce))
        {
            Retry(nNow);
            return;
        }
        nState = MIX_SEAT_NONCED;
        strStatus = "nonce taken";
        Schedule(announce.NonceCloses(), announce.NonceCloses() + announce.nResponseSecs / 2);
        return;
    }
    case MIX_SEAT_NONCED:
    {
        if (nNow >= announce.ResponseCloses())
            return Fail("the response window closed before this seat answered");
        Window(nNow, announce.ResponseCloses());
        if (vchResponse.empty())
        {
            CMixSnapshot snapshot;
            if (!ReadSnapshot(snapshot) ||
                (int)snapshot.vNonces.size() != announce.nParticipants)
            {
                Retry(nNow);
                return;
            }
            CMixAnchorView view;
            if (!FreshAnchor(nNow, view))
                return Fail(strStatus);
            if (!seat.BuildResponse(snapshot, view, vchResponse, &strError))
                return Fail("refused to answer: " + strError);
        }
        if (!fFinalShareSent && !env.NoteFinalShare(announce.Ends()))
            return Fail("the note could not be recorded as committed, so the final share "
                        "was not sent");
        fFinalShareSent = true;
        if (!AskAccepted(MIX_FRAME_RESPONSE, vchResponse))
        {
            Retry(nNow);
            return;
        }
        nState = MIX_SEAT_RESPONDED;
        strStatus = "final share sent";
        nNextAction = announce.ResponseCloses();
        return;
    }
    case MIX_SEAT_RESPONDED:
    {
        if (nNow > announce.Ends())
            return Fail("the round ended without publishing a transaction");
        Window(nNow, announce.Ends());
        MixFrameType nReply = MIX_FRAME_NONE;
        std::vector<unsigned char> vchReply;
        if (!Ask(MIX_FRAME_RESULT, std::vector<unsigned char>(), nReply, vchReply))
        {
            Retry(nNow);
            return;
        }
        if (nReply == MIX_FRAME_ABORT)
            return Fail("the round aborted");
        if (nReply != MIX_FRAME_TRANSACTION)
        {
            Retry(nNow);
            return;
        }
        CTransaction tx;
        try
        {
            CDataStream ss(vchReply, SER_NETWORK, PROTOCOL_VERSION);
            ss >> tx;
        }
        catch (const std::exception&)
        {
            Retry(nNow);
            return;
        }
        // Not taken on the coordinator's word: the transaction has to be built on the prefix
        // this seat approved, and its payload has to validate, before the attempt counts.
        if (!seat.CarriesApprovedPrefix(tx))
            return Fail("the published transaction is not built on the prefix this seat "
                        "approved");
        if (!env.VerifyResult(tx, strError))
            return Fail("the published transaction is not the one this seat approved: " +
                        strError);
        txResult = tx;
        nState = MIX_SEAT_DONE;
        strStatus = "round complete";
        return;
    }
    default:
        return;
    }
}

// ---------------------------------------------------------------------------
// The node's mix service
// ---------------------------------------------------------------------------

#include "dag.h"
#include "finality.h"
#include "idnsdescriptor.h"
#include "main.h"
#include "net.h"
#include "txdb.h"
#include "util.h"
#include "wallet.h"

#include <cstring>
#include <memory>

extern uint8_t PrivacyVNextNetworkIdForWallet();

boost::filesystem::path GetMixOnionServiceDir(const std::string& strRole)
{
    return GetDataDir(false) / ("onion-mix-" + strRole);
}

bool ReadSettledMixRendezvous(const CPubKey& pubkeyCoordinator, int64_t nSlot,
                              CMixRendezvous& rendezvousOut, bool& fPendingOut,
                              std::string& strError)
{
    fPendingOut = false;
    rendezvousOut = CMixRendezvous();
    LOCK(cs_main);
    if (!pindexBest)
    {
        fPendingOut = true;
        strError = "no chain yet";
        return false;
    }
    // The deterministic latch of the last epoch complete at the tip, which every node
    // computes alike; the live finalized height differs between nodes.
    const int nUpToEpoch = GetEpochForHeight(pindexBest->nHeight + 1) - 1;
    int nHeight = 0;
    uint256 hashBlock = 0;
    if (!g_dagManager.TryGetDeterministicFinalizedAnchor(nUpToEpoch, nHeight, hashBlock) ||
        nHeight <= 0)
    {
        fPendingOut = true;
        strError = "nothing is finalized yet";
        return false;
    }
    const CBlockIndex* pindexFinal = pindexBest->GetAncestor(nHeight);
    if (!pindexFinal ||
        pindexFinal->GetMedianTimePast() < nSlot * MIX_RENDEZVOUS_SLOT_SECONDS)
    {
        fPendingOut = true;
        strError = "the record slot is not settled yet";
        return false;
    }
    return LookupMixRendezvous(pindexBest, CMixSettledPoint(nHeight, hashBlock),
                               pubkeyCoordinator, nSlot, rendezvousOut, &strError);
}

namespace {

class CNodeMixCoordinatorEnv : public CMixCoordinatorEnv
{
public:
    explicit CNodeMixCoordinatorEnv(CWallet* pwalletIn) : pwallet(pwalletIn) {}

    bool PlanRound(int64_t nNow, CMixRoundPlan& planOut, std::string& strError)
    {
        LOCK(cs_main);
        CTxDB txdb("r");
        return PlanMixRound(txdb, nBestHeight, nNow, planOut, &strError);
    }
    void ChainIdentity(uint8_t& nNetworkOut, PrivacyVNextDigest& genesisOut)
    {
        nNetworkOut = PrivacyVNextNetworkIdForWallet();
        const uint256 hashGenesis = GetGenesisBlockHash();
        std::memcpy(genesisOut.data(), hashGenesis.begin(), 32);
    }
    bool PublishRecord(const CScript& scriptRecord, uint256& txidOut, std::string& strError)
    {
        LOCK2(cs_main, pwallet->cs_wallet);
        CWalletTx wtx;
        int64_t nFee = 0;
        size_t nNotes = 0;
        if (!pwallet->CreatePrivacyVNextStamp(scriptRecord, iv5::WALLET_DEFAULT_DISCLOSURE_MASK,
                                              true, wtx, nFee, nNotes, strError))
            return false;
        txidOut = wtx.GetHash();
        return true;
    }
    bool RecordConfirmed(const uint256& txid)
    {
        LOCK2(cs_main, pwallet->cs_wallet);
        std::map<uint256, CWalletTx>::const_iterator it = pwallet->mapWallet.find(txid);
        return it != pwallet->mapWallet.end() && it->second.GetDepthInMainChain() >= 1;
    }
    bool Broadcast(const CTransaction& tx, std::string& strError)
    {
        LOCK(cs_main);
        CTxDB txdb("r");
        CTransaction txCopy = tx;
        if (!txCopy.AcceptToMemoryPool(txdb))
        {
            strError = "the mempool refused the transaction";
            return false;
        }
        SyncWithWallets(txCopy, NULL, true);
        RelayTransaction(txCopy, txCopy.GetHash());
        return true;
    }

private:
    CWallet* pwallet;
};

class CNodeMixSeatEnv : public CMixSeatEnv
{
public:
    explicit CNodeMixSeatEnv(CWallet* pwalletIn)
        : pwallet(pwalletIn), fHeld(false), txhashHeld(0), nHeldIndex(0) {}

    bool ReadRendezvous(const CPubKey& pubkeyCoordinator, int64_t nSlot,
                        CMixRendezvous& rendezvousOut, bool& fPendingOut, std::string& strError)
    {
        return ReadSettledMixRendezvous(pubkeyCoordinator, nSlot, rendezvousOut, fPendingOut,
                                        strError);
    }
    bool ReadAnchor(const CMixRoundAnnouncement& announce, int64_t nNow,
                    CMixAnchorView& viewOut, std::string& strError)
    {
        LOCK(cs_main);
        CTxDB txdb("r");
        return ReadMixAnchorView(txdb, nBestHeight, nNow, announce, viewOut, &strError);
    }
    bool BuildMaterial(const CMixRoundAnnouncement& announce, CMixSeatMaterial& materialOut,
                       std::string& strError)
    {
        if (announce.nParticipants <= 0)
        {
            strError = "the round names no seats";
            return false;
        }
        const uint64_t nRequired =
            announce.nDenomination + announce.nFee / (uint64_t)announce.nParticipants;
        LOCK2(cs_main, pwallet->cs_wallet);
        CTxDB txdb("r");
        if (!pwallet->BuildPrivacyVNextMixMaterial(txdb, announce, nRequired, materialOut,
                                                   txhashHeld, nHeldIndex, strError))
            return false;
        fHeld = true;
        return true;
    }
    bool DeriveRecipient(const std::vector<uint256>& vRosterKeyImages,
                         PrivacyVNextDigest& spendOut, PrivacyVNextDigest& viewOut,
                         PrivacyVNextDigest& outgoingOut, std::string& strError)
    {
        LOCK(pwallet->cs_wallet);
        PrivacyVNextDerivedKeys keys;
        if (!pwallet->DerivePrivacyVNextMixRecipient(vRosterKeyImages, keys, strError))
            return false;
        spendOut = keys.spendPublic;
        viewOut = keys.viewPublic;
        outgoingOut = keys.outgoingViewSecret;
        return true;
    }
    void ReleaseNote()
    {
        if (!fHeld)
            return;
        LOCK(pwallet->cs_wallet);
        pwallet->EndPrivacyVNextMixAttempt(txhashHeld, nHeldIndex);
        fHeld = false;
    }
    bool NoteFinalShare(int64_t nRoundEnds)
    {
        if (!fHeld)
            return false;
        LOCK(pwallet->cs_wallet);
        std::string strError;
        if (!pwallet->MarkPrivacyVNextMixCommitted(txhashHeld, nHeldIndex, nRoundEnds, strError))
        {
            printf("NullSend seat: %s\n", strError.c_str());
            return false;
        }
        return true;
    }
    bool VerifyResult(const CTransaction& tx, std::string& strError)
    {
        const PrivacyVNextPayloadValidation validation = ValidatePrivacyVNextPayload(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, tx.privacyVNext.vchPayload);
        if (validation.nResult != INNOVA_PRIVACY_VNEXT_VALID)
        {
            strError = validation.strError;
            return false;
        }
        return true;
    }

private:
    CWallet* pwallet;
    bool fHeld;
    uint256 txhashHeld;
    uint32_t nHeldIndex;
};

// The job holds references to the env and the dialer, so it is declared last and freed first.
struct CMixSeatSlot
{
    std::shared_ptr<CMixDialer> dialer;
    std::unique_ptr<CNodeMixSeatEnv> env;
    std::unique_ptr<CMixSeatJob> job;
    CMixJobStatus status;
    // 0 none, 1 cancel, 2 cancel after the key image has gone out. Taken by the seats thread.
    int nCancelRequest;
    bool fCancelAnswered;
    bool fCancelDone;
    std::string strCancelAnswer;
    CMixSeatSlot() : nCancelRequest(0), fCancelAnswered(false), fCancelDone(false) {}
};

// A coordinator job and the environment it holds a reference to, kept alive together by
// whoever is stepping or serving it: a round replaced while a connection thread still has a
// request for it in hand must not be freed under that thread.
struct CMixCoordinatorRun
{
    std::shared_ptr<CMixDialer> dialer;
    std::unique_ptr<CNodeMixCoordinatorEnv> env;
    std::unique_ptr<CMixCoordinatorJob> job;
};

struct CMixServiceState
{
    CCriticalSection cs;
    bool fRunning;
    volatile bool fStop;
    CWallet* pwallet;
    // Replaced when the proxy changes; every job keeps the one it started with alive.
    std::shared_ptr<CMixDialer> dialer;
    CService addrProxy;
    std::string strProxy;
    std::string strProxySource;
    std::vector<CMixDirectoryEndpoint> vDirectories;
    std::string strCoordinatorOnion;
    int nCoordinatorPort;
    int nDirectoryPort;
    std::unique_ptr<CMixRendezvousIndex> index;
    std::unique_ptr<CMixDirectory> directory;
    std::shared_ptr<CMixCoordinatorRun> coordinator;
    std::vector<std::shared_ptr<CMixSeatSlot> > vSeats;
    CMixListener listenCoordinator;
    CMixListener listenDirectory;
    int nConnections;
    int64_t nNextJobId;
    // The rounds the last listing returned, by round id, for eligibility queries.
    std::map<uint256, CMixRoundAnnouncement> mapListed;

    CMixServiceState()
        : fRunning(false), fStop(false), pwallet(NULL), nCoordinatorPort(0), nDirectoryPort(0),
          nConnections(0), nNextJobId(1) {}
};

CMixServiceState g_mix;

struct CMixConnectionJob
{
    CMixStream stream;
    bool fDirectory;
    std::shared_ptr<CMixCoordinatorRun> coordinator;
};

bool ServeCoordinatorRunFrame(void* pRun, MixFrameType nType,
                              const std::vector<unsigned char>& vchPayload, int64_t nNow,
                              MixFrameType& nReplyTypeOut, std::vector<unsigned char>& vchReplyOut)
{
    return static_cast<CMixCoordinatorRun*>(pRun)->job->Serve(nType, vchPayload, nNow,
                                                              nReplyTypeOut, vchReplyOut);
}

void ThreadMixConnection(void* parg)
{
    std::unique_ptr<CMixConnectionJob> conn(static_cast<CMixConnectionJob*>(parg));
    try
    {
        if (conn->fDirectory)
            ServeMixConnection(conn->stream, ServeMixDirectoryFrame, g_mix.directory.get(), 0,
                               MIX_CONNECTION_TIMEOUT_MS);
        else if (conn->coordinator)
            ServeMixConnection(conn->stream, ServeCoordinatorRunFrame, conn->coordinator.get(), 0,
                               MIX_CONNECTION_TIMEOUT_MS);
    }
    catch (std::exception& e)
    {
        PrintException(&e, "ThreadMixConnection()");
    }
    catch (...)
    {
        PrintException(NULL, "ThreadMixConnection()");
    }
    conn->stream.Close();
    conn.reset();
    {
        LOCK(g_mix.cs);
        g_mix.nConnections--;
    }
    vnThreadsRunning[THREAD_MIX]--;
}

void AcceptMixConnections(CMixListener& listener, bool fDirectory, int nTimeoutMs)
{
    if (!listener.IsOpen())
        return;
    CMixStream stream;
    if (!listener.Accept(stream, nTimeoutMs))
        return;
    CMixConnectionJob* pConn = new CMixConnectionJob();
    pConn->fDirectory = fDirectory;
    {
        LOCK(g_mix.cs);
        // A connection past the cap is dropped rather than queued: over Tor nothing tells two
        // callers apart, so a queue would be one caller's to fill.
        if (g_mix.nConnections >= MIX_MAX_CONNECTIONS ||
            (fDirectory ? !g_mix.directory : !g_mix.coordinator))
        {
            delete pConn;
            return;
        }
        pConn->coordinator = g_mix.coordinator;
        g_mix.nConnections++;
    }
    pConn->stream.Adopt(stream.Release());
    // Counted before the thread exists, so a stop cannot see zero while one is starting.
    vnThreadsRunning[THREAD_MIX]++;
    if (!NewThread(ThreadMixConnection, pConn))
    {
        vnThreadsRunning[THREAD_MIX]--;
        delete pConn;
        LOCK(g_mix.cs);
        g_mix.nConnections--;
    }
}

// Accepting is its own thread, so a seat job waiting on a slow exchange of its own cannot
// hold up the round or directory this node serves.
void ThreadMixListen(void*)
{
    try
    {
        while (!g_mix.fStop && !fShutdown)
        {
            if (!g_mix.listenDirectory.IsOpen() && !g_mix.listenCoordinator.IsOpen())
            {
                MilliSleep(250);
                continue;
            }
            AcceptMixConnections(g_mix.listenDirectory, true, 50);
            AcceptMixConnections(g_mix.listenCoordinator, false, 50);
        }
    }
    catch (std::exception& e)
    {
        PrintException(&e, "ThreadMixListen()");
    }
    catch (...)
    {
        PrintException(NULL, "ThreadMixListen()");
    }
    vnThreadsRunning[THREAD_MIX]--;
}

// The coordinator and the stores: nothing here waits on the network for long.
void ThreadMixService(void*)
{
    printf("ThreadMixService started\n");
    try
    {
        while (!g_mix.fStop && !fShutdown)
        {
            const int64_t nNow = GetTime();
            if (g_mix.directory)
                g_mix.directory->Expire(nNow);
            if (g_mix.index)
                g_mix.index->Expire(nNow);
            std::shared_ptr<CMixCoordinatorRun> coordinator;
            {
                LOCK(g_mix.cs);
                coordinator = g_mix.coordinator;
            }
            if (coordinator)
                coordinator->job->Step(nNow);
            MilliSleep(250);
        }
    }
    catch (std::exception& e)
    {
        PrintException(&e, "ThreadMixService()");
    }
    catch (...)
    {
        PrintException(NULL, "ThreadMixService()");
    }
    printf("ThreadMixService stopped\n");
    vnThreadsRunning[THREAD_MIX]--;
}

// Seats, on a thread of their own: each step may wait on an exchange for as long as its
// window allows, and that must not stall the round this node serves.
void ThreadMixSeats(void*)
{
    try
    {
        while (!g_mix.fStop && !fShutdown)
        {
            std::vector<std::shared_ptr<CMixSeatSlot> > vSeats;
            {
                LOCK(g_mix.cs);
                vSeats = g_mix.vSeats;
            }
            for (size_t i = 0; i < vSeats.size() && !g_mix.fStop; i++)
            {
                CMixSeatSlot& slot = *vSeats[i];
                int nCancel = 0;
                {
                    LOCK(g_mix.cs);
                    nCancel = slot.nCancelRequest;
                    slot.nCancelRequest = 0;
                }
                // Applied here, between steps, because nothing else touches the job.
                std::string strWhyNot;
                const bool fCancelled = nCancel != 0 && slot.job->Cancel(nCancel == 2, strWhyNot);
                if (nCancel == 0)
                    slot.job->Step(GetTime());
                LOCK(g_mix.cs);
                if (nCancel != 0)
                {
                    slot.fCancelAnswered = true;
                    slot.fCancelDone = fCancelled;
                    slot.strCancelAnswer = fCancelled ? slot.job->Status() : strWhyNot;
                    slot.status.fCancelPending = false;
                }
                const std::string strState = strprintf("%d", (int)slot.job->State());
                const std::string strStatus = slot.job->Status();
                if (strState != slot.status.strState || strStatus != slot.status.strStatus)
                    slot.status.nUpdated = GetTime();
                slot.status.strState = strState;
                slot.status.strStatus = strStatus;
                slot.status.fFinished = slot.job->State() == MIX_SEAT_DONE ||
                                        slot.job->State() == MIX_SEAT_FAILED;
                slot.status.fCancelled = slot.job->Cancelled();
            }
            MilliSleep(250);
        }
    }
    catch (std::exception& e)
    {
        PrintException(&e, "ThreadMixSeats()");
    }
    catch (...)
    {
        PrintException(NULL, "ThreadMixSeats()");
    }
    vnThreadsRunning[THREAD_MIX]--;
}

bool ReadMixOnionHostname(const std::string& strRole, std::string& strOut)
{
    const boost::filesystem::path path = GetMixOnionServiceDir(strRole) / "hostname";
    FILE* file = fopen(path.string().c_str(), "r");
    if (!file)
        return false;
    char buf[128] = {0};
    const bool fRead = fgets(buf, sizeof(buf), file) != NULL;
    fclose(file);
    if (!fRead)
        return false;
    std::string str(buf);
    while (!str.empty() && (str[str.size() - 1] == '\n' || str[str.size() - 1] == '\r'))
        str.erase(str.size() - 1);
    if (!IsMixOnionEndpoint(str))
        return false;
    strOut = str;
    return true;
}

// Reads recent chain records once at start so a late-started directory still accepts
// their uploads. Seats read records through LookupMixRendezvous.
void BackfillMixRendezvousIndex()
{
    LOCK(cs_main);
    const int64_t nOldest = GetTime() - CMixRendezvousIndex::KEEP_SECS;
    const std::set<uint256> setNone;
    int nRead = 0;
    for (const CBlockIndex* pindex = pindexBest; pindex && nRead < 8192;
         pindex = pindex->pprev, ++nRead)
    {
        if (pindex->GetBlockTime() < nOldest)
            break;
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            break;
        NoteMixRendezvousBlock(block, setNone, true);
    }
}

bool StartThread(void (*pfn)(void*))
{
    vnThreadsRunning[THREAD_MIX]++;
    if (NewThread(pfn, NULL))
        return true;
    vnThreadsRunning[THREAD_MIX]--;
    return false;
}

} // namespace

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

const std::vector<std::string>& MixSettingNames()
{
    static std::vector<std::string> vNames;
    if (vNames.empty())
    {
        vNames.push_back("mixdir");
        vNames.push_back("mixproxy");
        vNames.push_back("mixonion");
        vNames.push_back("mixcoordinatorport");
        vNames.push_back("mixdirectoryport");
    }
    return vNames;
}

bool MixSettingIsLive(const std::string& strName)
{
    return strName == "mixdir" || strName == "mixproxy";
}

static bool IsMixSettingName(const std::string& strName)
{
    const std::vector<std::string>& v = MixSettingNames();
    return std::find(v.begin(), v.end(), strName) != v.end();
}

bool ParseMixDirectories(const std::vector<std::string>& vIn,
                         std::vector<CMixDirectoryEndpoint>& vOut, std::string& strError)
{
    vOut.clear();
    for (size_t i = 0; i < vIn.size(); i++)
    {
        const std::string& str = vIn[i];
        const size_t nColon = str.rfind(':');
        const std::string strHost = nColon == std::string::npos ? str : str.substr(0, nColon);
        const std::string strPort = nColon == std::string::npos ? "" : str.substr(nColon + 1);
        int nPort = 0;
        if (!strPort.empty() && strPort.size() <= 5 &&
            strPort.find_first_not_of("0123456789") == std::string::npos)
            nPort = atoi(strPort.c_str());
        if (!IsMixOnionEndpoint(strHost) || nPort < 1 || nPort > 65535)
        {
            strError = "-mixdir must be an onion name and a port: " + str;
            return false;
        }
        for (size_t k = 0; k < vOut.size(); k++)
            if (vOut[k].strHost == strHost && vOut[k].nPort == nPort)
            {
                strError = "-mixdir names one directory twice: " + str;
                return false;
            }
        vOut.push_back(CMixDirectoryEndpoint(strHost, nPort));
    }
    return true;
}

bool ParseMixProxy(const std::string& str, CService& addrOut, std::string& strError)
{
    if (str.empty() || !LookupNumeric(str.c_str(), addrOut, 9050) || !addrOut.IsValid() ||
        addrOut.GetPort() == 0)
    {
        strError = "invalid -mixproxy: " + str + " (a numeric address and port)";
        return false;
    }
    return true;
}

static std::vector<std::string> SplitMixList(const std::string& str)
{
    std::vector<std::string> vOut;
    std::string strCur;
    for (size_t i = 0; i <= str.size(); i++)
    {
        const char c = i < str.size() ? str[i] : ',';
        if (c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r')
        {
            if (!strCur.empty())
                vOut.push_back(strCur);
            strCur.clear();
        }
        else
            strCur += c;
    }
    return vOut;
}

static std::string TrimMix(const std::string& str)
{
    const size_t nBegin = str.find_first_not_of(" \t\r\n");
    if (nBegin == std::string::npos)
        return std::string();
    const size_t nEnd = str.find_last_not_of(" \t\r\n");
    return str.substr(nBegin, nEnd - nBegin + 1);
}

bool CheckMixSettingValue(const std::string& strName, const std::string& strValue,
                          std::string& strError)
{
    if (!IsMixSettingName(strName))
    {
        strError = "unknown mix setting: " + strName;
        return false;
    }
    if (strValue.empty())
        return true;
    if (strName == "mixdir")
    {
        std::vector<CMixDirectoryEndpoint> vDirs;
        return ParseMixDirectories(SplitMixList(strValue), vDirs, strError);
    }
    if (strName == "mixproxy")
    {
        CService addr;
        return ParseMixProxy(strValue, addr, strError);
    }
    if (strName == "mixonion")
    {
        if (!IsMixOnionEndpoint(strValue))
        {
            strError = "-mixonion must be a v3 onion name";
            return false;
        }
        return true;
    }
    if (strValue.size() > 5 || strValue.find_first_not_of("0123456789") != std::string::npos ||
        atoi(strValue.c_str()) > 65535)
    {
        strError = "-" + strName + " must be a port from 0 (off) to 65535";
        return false;
    }
    return true;
}

bool ParseMixSettingsText(const std::string& strText,
                          std::map<std::string, std::vector<std::string> >& mapOut,
                          std::string& strError)
{
    mapOut.clear();
    std::map<std::string, std::vector<std::string> > mapRead;
    size_t nAt = 0;
    int nLine = 0;
    while (nAt <= strText.size())
    {
        size_t nEnd = strText.find('\n', nAt);
        if (nEnd == std::string::npos)
            nEnd = strText.size();
        const std::string strLine = TrimMix(strText.substr(nAt, nEnd - nAt));
        nAt = nEnd + 1;
        nLine++;
        if (strLine.empty() || strLine[0] == '#')
            continue;
        const size_t nEq = strLine.find('=');
        const std::string strKey = TrimMix(strLine.substr(0, nEq));
        const std::string strValue =
            nEq == std::string::npos ? std::string() : TrimMix(strLine.substr(nEq + 1));
        if (nEq == std::string::npos || strValue.empty() || !IsMixSettingName(strKey))
        {
            strError = strprintf("mix settings line %d is not a mix setting: %s", nLine,
                                 strLine.c_str());
            return false;
        }
        if (strKey != "mixdir" && mapRead.count(strKey))
        {
            strError = strprintf("mix settings line %d sets %s a second time", nLine,
                                 strKey.c_str());
            return false;
        }
        if (!CheckMixSettingValue(strKey, strValue, strError))
            return false;
        mapRead[strKey].push_back(strValue);
    }
    if (mapRead.count("mixdir"))
    {
        std::vector<CMixDirectoryEndpoint> vDirs;
        if (!ParseMixDirectories(mapRead["mixdir"], vDirs, strError))
            return false;
    }
    mapOut.swap(mapRead);
    return true;
}

std::string FormatMixSettingsText(const std::map<std::string, std::vector<std::string> >& mapIn)
{
    std::string str = "# NullSend settings written by mixsetsetting. A key here takes precedence "
                      "over innova.conf.\n";
    const std::vector<std::string>& vNames = MixSettingNames();
    for (size_t i = 0; i < vNames.size(); i++)
    {
        std::map<std::string, std::vector<std::string> >::const_iterator it = mapIn.find(vNames[i]);
        if (it == mapIn.end())
            continue;
        for (size_t k = 0; k < it->second.size(); k++)
            str += vNames[i] + "=" + it->second[k] + "\n";
    }
    return str;
}

boost::filesystem::path GetMixSettingsPath()
{
    return GetDataDir(true) / "mixsettings.conf";
}

namespace {

// Bounded: a settings file is a few lines.
static const size_t MIX_SETTINGS_MAX_BYTES = 65536;

bool ReadMixSettingsFile(std::map<std::string, std::vector<std::string> >& mapOut,
                         std::string& strError)
{
    mapOut.clear();
    const boost::filesystem::path path = GetMixSettingsPath();
    FILE* file = fopen(path.string().c_str(), "rb");
    if (!file)
        return true;
    std::string strText;
    char buf[4096];
    size_t nRead = 0;
    while ((nRead = fread(buf, 1, sizeof(buf), file)) > 0)
    {
        strText.append(buf, nRead);
        if (strText.size() > MIX_SETTINGS_MAX_BYTES)
        {
            fclose(file);
            strError = path.string() + " is too large to be mix settings";
            return false;
        }
    }
    fclose(file);
    if (!ParseMixSettingsText(strText, mapOut, strError))
    {
        strError = path.string() + ": " + strError;
        return false;
    }
    return true;
}

bool WriteMixSettingsFile(const std::map<std::string, std::vector<std::string> >& mapIn,
                          std::string& strError)
{
    const boost::filesystem::path path = GetMixSettingsPath();
    const boost::filesystem::path pathTmp = path.string() + ".new";
    const std::string strText = FormatMixSettingsText(mapIn);
    FILE* file = fopen(pathTmp.string().c_str(), "wb");
    if (!file)
    {
        strError = "cannot write " + pathTmp.string();
        return false;
    }
    const bool fWritten = fwrite(strText.data(), 1, strText.size(), file) == strText.size();
    const bool fClosed = fclose(file) == 0;
    if (!fWritten || !fClosed)
    {
        strError = "cannot write " + pathTmp.string();
        return false;
    }
    try
    {
        boost::filesystem::rename(pathTmp, path);
    }
    catch (const boost::filesystem::filesystem_error& e)
    {
        strError = std::string("cannot replace the mix settings file: ") + e.what();
        return false;
    }
    return true;
}

// Settings the RPC changes are read and written under this, apart from the service's lock.
CCriticalSection cs_mixSettings;

} // namespace

bool ResolveMixSettings(CMixSettings& out, std::string& strError)
{
    out = CMixSettings();
    std::map<std::string, std::vector<std::string> > mapFile;
    {
        LOCK(cs_mixSettings);
        if (!ReadMixSettingsFile(mapFile, strError))
            return false;
    }
    for (std::map<std::string, std::vector<std::string> >::const_iterator it = mapFile.begin();
         it != mapFile.end(); ++it)
        out.vOverridden.push_back(it->first);

    std::vector<std::string> vDirs;
    if (mapFile.count("mixdir"))
        vDirs = mapFile["mixdir"];
    else
    {
        std::map<std::string, std::vector<std::string> >::const_iterator it =
            mapMultiArgs.find("-mixdir");
        if (it != mapMultiArgs.end())
            vDirs = it->second;
    }
    if (!ParseMixDirectories(vDirs, out.vDirectories, strError))
        return false;

    // The SOCKS proxy mix exchanges go through: the bundled tor's when it runs. There is no
    // direct fallback -- an exchange that cannot go through the proxy does not happen.
    if (mapFile.count("mixproxy"))
    {
        out.strProxy = mapFile["mixproxy"].back();
        out.strProxySource = "settings file";
    }
    else if (mapArgs.count("-mixproxy"))
    {
        out.strProxy = mapArgs["-mixproxy"];
        out.strProxySource = "config";
    }
    else if (fNativeTor)
    {
        out.strProxy = strprintf("127.0.0.1:%u", NATIVETOR_SOCKS_PORT);
        out.strProxySource = "nativetor";
    }
    else
    {
        out.strProxy = "127.0.0.1:9050";
        out.strProxySource = "default";
    }
    CService addrProxy;
    if (!ParseMixProxy(out.strProxy, addrProxy, strError))
        return false;

    out.strOnion = mapFile.count("mixonion") ? mapFile["mixonion"].back()
                                             : GetArg("-mixonion", "");
    out.nCoordinatorPort = mapFile.count("mixcoordinatorport")
                               ? atoi(mapFile["mixcoordinatorport"].back().c_str())
                               : (int)GetArg("-mixcoordinatorport", 0);
    out.nDirectoryPort = mapFile.count("mixdirectoryport")
                             ? atoi(mapFile["mixdirectoryport"].back().c_str())
                             : (int)GetArg("-mixdirectoryport", 0);
    if (out.nCoordinatorPort < 0 || out.nCoordinatorPort > 65535 || out.nDirectoryPort < 0 ||
        out.nDirectoryPort > 65535)
    {
        strError = "a mix port must be from 0 (off) to 65535";
        return false;
    }
    if (out.nCoordinatorPort > 0 && !out.strOnion.empty() && !IsMixOnionEndpoint(out.strOnion))
    {
        strError = "-mixonion must be a v3 onion name";
        return false;
    }
    return true;
}

void GetRunningMixSettings(CMixSettings& out, bool& fRunningOut)
{
    out = CMixSettings();
    LOCK(g_mix.cs);
    fRunningOut = g_mix.fRunning;
    out.vDirectories = g_mix.vDirectories;
    out.strProxy = g_mix.strProxy;
    out.strProxySource = g_mix.strProxySource;
    out.strOnion = g_mix.strCoordinatorOnion;
    out.nCoordinatorPort = g_mix.nCoordinatorPort;
    out.nDirectoryPort = g_mix.nDirectoryPort;
}

bool MixSetSetting(const std::string& strName, const std::string& strValue, bool& fRestartOut,
                   std::string& strError)
{
    fRestartOut = false;
    const std::string strTrimmed = TrimMix(strValue);
    if (!CheckMixSettingValue(strName, strTrimmed, strError))
        return false;
    {
        LOCK(cs_mixSettings);
        std::map<std::string, std::vector<std::string> > mapFile;
        if (!ReadMixSettingsFile(mapFile, strError))
            return false;
        if (strTrimmed.empty())
            mapFile.erase(strName);
        else if (strName == "mixdir")
            mapFile[strName] = SplitMixList(strTrimmed);
        else
            mapFile[strName] = std::vector<std::string>(1, strTrimmed);
        if (!WriteMixSettingsFile(mapFile, strError))
            return false;
    }
    CMixSettings resolved;
    if (!ResolveMixSettings(resolved, strError))
        return false;
    if (!MixSettingIsLive(strName))
    {
        bool fRunning = false;
        CMixSettings running;
        GetRunningMixSettings(running, fRunning);
        fRestartOut = running.strOnion != resolved.strOnion ||
                      running.nCoordinatorPort != resolved.nCoordinatorPort ||
                      running.nDirectoryPort != resolved.nDirectoryPort;
        return true;
    }
    CService addrProxy;
    if (!ParseMixProxy(resolved.strProxy, addrProxy, strError))
        return false;
    LOCK(g_mix.cs);
    if (!g_mix.fRunning)
    {
        fRestartOut = true;
        return true;
    }
    g_mix.vDirectories = resolved.vDirectories;
    if (!(addrProxy == g_mix.addrProxy))
        g_mix.dialer.reset(new CMixTorDialer(addrProxy));
    g_mix.addrProxy = addrProxy;
    g_mix.strProxy = resolved.strProxy;
    g_mix.strProxySource = resolved.strProxySource;
    return true;
}

bool StartMixService(CWallet* pwallet, std::string& strError)
{
    CMixSettings settings;
    if (!ResolveMixSettings(settings, strError))
        return false;
    CService addrProxy;
    if (!ParseMixProxy(settings.strProxy, addrProxy, strError))
        return false;

    LOCK(g_mix.cs);
    if (g_mix.fRunning)
        return true;
    g_mix.pwallet = pwallet;
    g_mix.fStop = false;
    g_fMixExchangesStopped = false;
    g_mix.nCoordinatorPort = settings.nCoordinatorPort;
    g_mix.nDirectoryPort = settings.nDirectoryPort;
    g_mix.addrProxy = addrProxy;
    g_mix.strProxy = settings.strProxy;
    g_mix.strProxySource = settings.strProxySource;
    g_mix.dialer.reset(new CMixTorDialer(addrProxy));
    g_mix.vDirectories = settings.vDirectories;

    if (g_mix.nDirectoryPort > 0)
    {
        g_mix.index.reset(new CMixRendezvousIndex());
        g_mix.directory.reset(new CMixDirectory(g_mix.index.get()));
        if (!g_mix.listenDirectory.Listen(g_mix.nDirectoryPort, &strError))
            return false;
        g_pmixRendezvousIndex = g_mix.index.get();
        BackfillMixRendezvousIndex();
    }
    if (g_mix.nCoordinatorPort > 0)
    {
        if (!g_mix.listenCoordinator.Listen(g_mix.nCoordinatorPort, &strError))
            return false;
        g_mix.strCoordinatorOnion = settings.strOnion;
    }
    g_mix.fRunning = true;
    if (!StartThread(ThreadMixService) || !StartThread(ThreadMixListen) ||
        !StartThread(ThreadMixSeats))
    {
        g_mix.fStop = true;
        strError = "the mix service threads could not start";
        return false;
    }
    return true;
}

void StopMixService()
{
    {
        LOCK(g_mix.cs);
        if (!g_mix.fRunning)
            return;
        g_mix.fStop = true;
    }
    // An exchange not yet dialed returns at once; one in flight ends within its deadline.
    g_fMixExchangesStopped = true;
    const int64_t nStart = GetTimeMillis();
    while (vnThreadsRunning[THREAD_MIX] > 0 &&
           GetTimeMillis() - nStart < 3 * MIX_EXCHANGE_TIMEOUT_MS)
        MilliSleep(20);
    LOCK(g_mix.cs);
    if (vnThreadsRunning[THREAD_MIX] > 0)
    {
        // Something is still inside a step. Leave everything it could touch alive: the
        // process is exiting, and freeing it under that thread is worse than not freeing it.
        printf("StopMixService : %d mix thread(s) still running\n",
               (int)vnThreadsRunning[THREAD_MIX]);
        return;
    }
    g_pmixRendezvousIndex = NULL;
    g_mix.listenDirectory.Close();
    g_mix.listenCoordinator.Close();
    g_mix.vSeats.clear();
    g_mix.coordinator.reset();
    g_mix.fRunning = false;
}

bool MixStartCoordinator(const CKey& keyCoordinator, uint64_t nDenomination, int nSeats,
                         std::string& strError)
{
    LOCK(g_mix.cs);
    if (!g_mix.fRunning || g_mix.nCoordinatorPort <= 0)
    {
        strError = "this node runs no coordinator: set -mixcoordinatorport";
        return false;
    }
    if (g_mix.coordinator && g_mix.coordinator->job->State() < MIX_COORD_DONE)
    {
        strError = "a round is already running";
        return false;
    }
    if (g_mix.vDirectories.empty())
    {
        strError = "no directory to publish to: set -mixdir";
        return false;
    }
    std::string strOnion = g_mix.strCoordinatorOnion;
    if (strOnion.empty() && !ReadMixOnionHostname("coordinator", strOnion))
    {
        strError = "the coordinator's onion name is not available yet";
        return false;
    }
    const CMixPolicy policy = CMixPolicy::Standard();
    if (!policy.AllowsRound(nDenomination, (uint64_t)nSeats * policy.nFeeSharePerSeat, nSeats,
                            &strError))
        return false;
    CMixCoordinatorConfig config;
    config.keyCoordinator = keyCoordinator;
    config.strEndpoint = strOnion;
    config.nPort = g_mix.nCoordinatorPort;
    config.nParticipants = nSeats;
    config.nDenomination = nDenomination;
    config.nFeeSharePerSeat = policy.nFeeSharePerSeat;
    config.vDirectories = g_mix.vDirectories;
    std::shared_ptr<CMixCoordinatorRun> run(new CMixCoordinatorRun());
    run->dialer = g_mix.dialer;
    run->env.reset(new CNodeMixCoordinatorEnv(g_mix.pwallet));
    run->job.reset(new CMixCoordinatorJob(config, *run->env, *run->dialer));
    // The previous round, if any, lives on in whatever connection still holds it.
    g_mix.coordinator = run;
    return true;
}

bool MixStartSeat(const CPubKey& pubkeyCoordinator, int64_t nRecordSlot, std::string& strError,
                  int64_t* pnIdOut)
{
    LOCK(g_mix.cs);
    if (!g_mix.fRunning || !g_mix.pwallet)
    {
        strError = "the mix service is not running";
        return false;
    }
    if (g_mix.vDirectories.empty())
    {
        strError = "no directory to fetch from: set -mixdir, or add one with mixsetsetting";
        return false;
    }
    if (!pubkeyCoordinator.IsValid() || !pubkeyCoordinator.IsCompressed())
    {
        strError = "the coordinator key must be a compressed public key";
        return false;
    }
    if (nRecordSlot <= 0)
    {
        strError = "a record slot is required";
        return false;
    }
    CMixSeatConfig config;
    config.pubkeyCoordinator = pubkeyCoordinator;
    config.nRecordSlot = nRecordSlot;
    config.policy = CMixPolicy::Standard();
    config.vDirectories = g_mix.vDirectories;
    std::shared_ptr<CMixSeatSlot> slot(new CMixSeatSlot());
    slot->dialer = g_mix.dialer;
    slot->env.reset(new CNodeMixSeatEnv(g_mix.pwallet));
    slot->job.reset(new CMixSeatJob(config, *slot->env, *slot->dialer));
    slot->status.nId = g_mix.nNextJobId++;
    slot->status.strRole = "seat";
    slot->status.nRecordSlot = nRecordSlot;
    slot->status.nStarted = GetTime();
    slot->status.nUpdated = slot->status.nStarted;
    slot->status.strState = strprintf("%d", (int)MIX_SEAT_FINDING);
    slot->status.strStatus = slot->job->Status();
    g_mix.vSeats.push_back(slot);
    if (pnIdOut)
        *pnIdOut = slot->status.nId;
    return true;
}

void GetMixServiceStatus(std::vector<CMixJobStatus>& vJobsOut, size_t& nDirectoryEntriesOut,
                         size_t& nRecordsOut)
{
    vJobsOut.clear();
    LOCK(g_mix.cs);
    nDirectoryEntriesOut = g_mix.directory ? g_mix.directory->Size() : 0;
    nRecordsOut = g_mix.index ? g_mix.index->Size() : 0;
    if (g_mix.coordinator)
    {
        CMixJobStatus status;
        status.nId = 0;
        status.strRole = "coordinator";
        const MixCoordinatorJobState nState = g_mix.coordinator->job->State();
        status.strState = strprintf("%d", (int)nState);
        status.strStatus = g_mix.coordinator->job->Status();
        status.fFinished = nState == MIX_COORD_DONE || nState == MIX_COORD_FAILED;
        const CMixRoundAnnouncement announce = g_mix.coordinator->job->Announcement();
        status.strRound = announce.hashRound.ToString();
        status.nRecordSlot = announce.nTime > 0 ? MixRendezvousRecordSlot(announce.nTime) : 0;
        vJobsOut.push_back(status);
    }
    for (size_t i = 0; i < g_mix.vSeats.size(); i++)
        vJobsOut.push_back(g_mix.vSeats[i]->status);
}

bool MixCancelSeat(int64_t nId, bool fForce, int nWaitMs, bool& fAppliedOut,
                   std::string& strResult, std::string& strError)
{
    fAppliedOut = false;
    std::shared_ptr<CMixSeatSlot> slot;
    {
        LOCK(g_mix.cs);
        for (size_t i = 0; i < g_mix.vSeats.size(); i++)
            if (g_mix.vSeats[i]->status.nId == nId)
                slot = g_mix.vSeats[i];
        if (!slot)
        {
            strError = "no seat has that id";
            return false;
        }
        if (slot->status.fFinished)
        {
            strError = "that seat's attempt has already ended";
            return false;
        }
        slot->nCancelRequest = fForce ? 2 : 1;
        slot->fCancelAnswered = false;
        slot->status.fCancelPending = true;
    }
    const int64_t nUntil = GetTimeMillis() + std::max(0, nWaitMs);
    while (true)
    {
        {
            LOCK(g_mix.cs);
            if (slot->fCancelAnswered)
            {
                fAppliedOut = true;
                if (!slot->fCancelDone)
                {
                    strError = slot->strCancelAnswer;
                    return false;
                }
                strResult = slot->strCancelAnswer;
                return true;
            }
        }
        if (GetTimeMillis() >= nUntil || fShutdown)
            break;
        MilliSleep(50);
    }
    strResult = "queued: it is applied when the seat's current exchange ends";
    return true;
}

size_t MixClearFinishedSeats()
{
    LOCK(g_mix.cs);
    size_t nCleared = 0;
    for (size_t i = 0; i < g_mix.vSeats.size();)
    {
        if (g_mix.vSeats[i]->status.fFinished && g_mix.vSeats[i]->nCancelRequest == 0)
        {
            g_mix.vSeats.erase(g_mix.vSeats.begin() + i);
            nCleared++;
        }
        else
            i++;
    }
    return nCleared;
}

// ---------------------------------------------------------------------------
// Proxy readiness
// ---------------------------------------------------------------------------

bool ProbeMixProxy(const CService& addrProxy, int nTimeoutMs, CMixProxyStatus& statusOut)
{
    statusOut.fReachable = false;
    statusOut.fSocks5 = false;
    statusOut.fIsolation = false;
    statusOut.nLatencyMs = -1;
    statusOut.strError.clear();
    const int64_t nStart = GetTimeMillis();
    statusOut.fReachable = ProbeSocks5Proxy(addrProxy, nTimeoutMs, statusOut.fSocks5,
                                            statusOut.fIsolation, statusOut.strError);
    if (statusOut.fReachable)
        statusOut.nLatencyMs = GetTimeMillis() - nStart;
    return statusOut.Ready();
}

void GetMixProxyStatus(int nTimeoutMs, CMixProxyStatus& statusOut)
{
    statusOut = CMixProxyStatus();
    CService addrProxy;
    bool fRunning = false;
    {
        LOCK(g_mix.cs);
        fRunning = g_mix.fRunning;
        addrProxy = g_mix.addrProxy;
        statusOut.strProxy = g_mix.strProxy;
        statusOut.strSource = g_mix.strProxySource;
    }
    if (!fRunning)
    {
        statusOut.strError = "the mix service is not running";
        return;
    }
    ProbeMixProxy(addrProxy, nTimeoutMs, statusOut);
}

// ---------------------------------------------------------------------------
// Round discovery
// ---------------------------------------------------------------------------

bool MixListRounds(const std::string& strOnly, std::vector<CMixListedRound>& vOut,
                   std::vector<std::pair<std::string, std::string> >& vFailuresOut,
                   std::string& strError)
{
    vOut.clear();
    vFailuresOut.clear();
    std::shared_ptr<CMixDialer> dialer;
    std::vector<CMixDirectoryEndpoint> vDirs;
    {
        LOCK(g_mix.cs);
        if (!g_mix.fRunning)
        {
            strError = "the mix service is not running";
            return false;
        }
        dialer = g_mix.dialer;
        vDirs = g_mix.vDirectories;
    }
    if (!strOnly.empty())
    {
        std::vector<CMixDirectoryEndpoint> vOnly;
        if (!ParseMixDirectories(std::vector<std::string>(1, strOnly), vOnly, strError))
            return false;
        vDirs = vOnly;
    }
    if (vDirs.empty())
    {
        strError = "no directory to ask: set -mixdir, or add one with mixsetsetting";
        return false;
    }
    uint8_t nNetwork = PrivacyVNextNetworkIdForWallet();
    PrivacyVNextDigest genesis;
    const uint256 hashGenesis = GetGenesisBlockHash();
    std::memcpy(genesis.data(), hashGenesis.begin(), 32);

    // Each directory on a fresh circuit, in a random order.
    for (size_t i = vDirs.size(); i > 1; i--)
        std::swap(vDirs[i - 1], vDirs[GetRandInt((int)i)]);
    std::map<uint256, size_t> mapAt;
    size_t nAsked = 0;
    for (size_t d = 0; d < vDirs.size(); d++)
    {
        const std::string strDir = strprintf("%s:%d", vDirs[d].strHost.c_str(), vDirs[d].nPort);
        std::vector<CMixRoundAnnouncement> vListed;
        std::string strFetch;
        if (!FetchMixRoundIndex(*dialer, vDirs[d], vListed, &strFetch))
        {
            vFailuresOut.push_back(std::make_pair(strDir, strFetch));
            continue;
        }
        nAsked++;
        for (size_t k = 0; k < vListed.size(); k++)
        {
            const CMixRoundAnnouncement& announce = vListed[k];
            if (announce.nNetwork != nNetwork || !(announce.genesis == genesis))
                continue;
            std::map<uint256, size_t>::const_iterator it = mapAt.find(announce.hashRound);
            if (it != mapAt.end())
            {
                vOut[it->second].vDirectories.push_back(strDir);
                continue;
            }
            mapAt[announce.hashRound] = vOut.size();
            CMixListedRound row;
            row.announce = announce;
            row.vDirectories.push_back(strDir);
            vOut.push_back(row);
        }
    }
    std::sort(vOut.begin(), vOut.end(),
              [](const CMixListedRound& a, const CMixListedRound& b) {
                  return a.announce.nTime < b.announce.nTime ||
                         (a.announce.nTime == b.announce.nTime &&
                          a.announce.hashRound < b.announce.hashRound);
              });
    {
        LOCK(g_mix.cs);
        g_mix.mapListed.clear();
        for (size_t i = 0; i < vOut.size(); i++)
            g_mix.mapListed[vOut[i].announce.hashRound] = vOut[i].announce;
    }
    if (nAsked == 0)
    {
        strError = "no directory answered";
        return false;
    }
    return true;
}

bool MixCachedRound(const uint256& hashRound, CMixRoundAnnouncement& announceOut)
{
    LOCK(g_mix.cs);
    std::map<uint256, CMixRoundAnnouncement>::const_iterator it = g_mix.mapListed.find(hashRound);
    if (it == g_mix.mapListed.end())
        return false;
    announceOut = it->second;
    return true;
}

// ---------------------------------------------------------------------------
// Note eligibility
// ---------------------------------------------------------------------------

int MixNoteEligibleHeight(int nNoteHeight)
{
    if (nNoteHeight <= 0)
        return -1;
    // An epoch's anchor covers the notes of blocks up to its last height, and a round takes
    // an anchor only once it is this deep at JOIN.
    const int64_t nEnd = GetEpochBoundaryHeight64(GetEpochForHeight(nNoteHeight) + 1) - 1;
    const int64_t nHeight = std::max<int64_t>(
        nEnd + EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH,
        (int64_t)nNoteHeight + MIN_SHIELDED_SPEND_DEPTH);
    return nHeight > std::numeric_limits<int>::max() ? std::numeric_limits<int>::max()
                                                     : (int)nHeight;
}

std::string MixNoteIneligibility(const CMixNoteFacts& note, const CMixRoundAnnouncement& announce)
{
    if (announce.nParticipants <= 0)
        return "the round names no seats";
    const uint64_t nRequired =
        announce.nDenomination + announce.nFee / (uint64_t)announce.nParticipants;
    if (note.nAmount != nRequired)
        return strprintf("the round takes a note of exactly %s INN", FormatMoney(nRequired).c_str());
    if (!note.strUnusable.empty())
        return note.strUnusable;
    if (!note.fLeafIndexKnown)
        return "the note is not in the tree yet: its epoch has not been built";
    if (note.nLeafIndex >= announce.nFinalizedTreeSize)
        return "the note is newer than this round's anchor; it can join a round planned later";
    return std::string();
}
