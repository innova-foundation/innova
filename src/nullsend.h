// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_NULLSEND_H
#define INN_NULLSEND_H

#include "main.h"
#include "shielded.h"
#include "zkproof.h"

#include <vector>
#include <map>
#include <set>
#include <string>

#include <openssl/crypto.h>
#include <openssl/bn.h>

class CNode;
class CDataStream;

#define NULLSEND_STATE_IDLE              0
#define NULLSEND_STATE_ACCEPTING         1
#define NULLSEND_STATE_NONCE_COMMIT      2
#define NULLSEND_STATE_PARTIAL_SIG       3
#define NULLSEND_STATE_SUCCESS           5
#define NULLSEND_STATE_ERROR             6

#define NULLSEND_STATE_INPUT_REG         10
#define NULLSEND_STATE_OUTPUT_REG        11

#define NULLSEND_ACCEPTED                1
#define NULLSEND_REJECTED                0
#define NULLSEND_RESET                  -1

static const int NULLSEND_MIN_PARTICIPANTS = 2;
static const int NULLSEND_MAX_PARTICIPANTS = 16;
static const int NULLSEND_DEFAULT_PARTICIPANTS = 5;
static const int NULLSEND_QUEUE_TIMEOUT = 300;
static const int NULLSEND_ROUND_TIMEOUT = 60;
static const int NULLSEND_OUTPUT_REG_TIMEOUT = 120;
static const int64_t NULLSEND_FEE = 100000;
static const int NULLSEND_RSA_BITS = 2048;


class CNullSendQueue
{
public:
    CTxIn vin;
    int64_t nTime;
    uint8_t nPrivacyMode;
    int nPoolSize;
    int nSessionID;
    uint256 sessionNonce;
    std::vector<unsigned char> vchSig;

    CNullSendQueue()
    {
        nTime = 0;
        nPrivacyMode = PRIVACY_MODE_FULL;
        nPoolSize = NULLSEND_DEFAULT_PARTICIPANTS;
        nSessionID = 0;
        sessionNonce = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vin);
        READWRITE(nTime);
        READWRITE(nPrivacyMode);
        READWRITE(nPoolSize);
        READWRITE(nSessionID);
        READWRITE(sessionNonce);
        READWRITE(vchSig);
    )

    bool IsExpired() const { return (GetTime() - nTime) > NULLSEND_QUEUE_TIMEOUT; }
};

class CNullSendEntry
{
public:
    int nSessionID;
    std::vector<CShieldedSpendDescription> vMySpends;
    std::vector<CShieldedOutputDescription> vMyOutputs;
    int64_t nMyValueBalance;
    uint8_t nPrivacyMode;
    int64_t nAddedTime;

    CNullSendEntry()
    {
        nSessionID = 0;
        nMyValueBalance = 0;
        nPrivacyMode = PRIVACY_MODE_FULL;
        nAddedTime = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSessionID);
        READWRITE(vMySpends);
        READWRITE(vMyOutputs);
        READWRITE(nMyValueBalance);
        READWRITE(nPrivacyMode);
    )

    bool IsExpired() const { return (GetTime() - nAddedTime) > NULLSEND_QUEUE_TIMEOUT; }
};

class CNullSendAccept
{
public:
    int nSessionID;
    int nStatusCode;
    int nParticipantID;
    std::string strMessage;

    CNullSendAccept()
    {
        nSessionID = 0;
        nStatusCode = 0;
        nParticipantID = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSessionID);
        READWRITE(nStatusCode);
        READWRITE(nParticipantID);
        READWRITE(strMessage);
    )
};

class CNullSendInputReg
{
public:
    int nSessionID;
    std::vector<CShieldedSpendDescription> vMySpends;
    int64_t nMyInputValue;
    uint8_t nPrivacyMode;
    std::vector<uint256> vBlindedNullifiers;
    std::vector<unsigned char> vchBlindedCredential;

    CNullSendInputReg()
    {
        nSessionID = 0;
        nMyInputValue = 0;
        nPrivacyMode = PRIVACY_MODE_FULL;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSessionID);
        READWRITE(vMySpends);
        READWRITE(nMyInputValue);
        READWRITE(nPrivacyMode);
        READWRITE(vBlindedNullifiers);
        READWRITE(vchBlindedCredential);
    )
};

class CNullSendInputAccept
{
public:
    int nSessionID;
    int nStatusCode;
    int nParticipantID;
    std::vector<unsigned char> vchBlindSignature;
    std::vector<unsigned char> vchRSA_N;
    std::vector<unsigned char> vchRSA_E;
    std::string strMessage;

    CNullSendInputAccept()
    {
        nSessionID = 0;
        nStatusCode = 0;
        nParticipantID = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSessionID);
        READWRITE(nStatusCode);
        READWRITE(nParticipantID);
        READWRITE(vchBlindSignature);
        READWRITE(vchRSA_N);
        READWRITE(vchRSA_E);
        READWRITE(strMessage);
    )
};

class CNullSendOutputReg
{
public:
    int nSessionID;
    std::vector<CShieldedOutputDescription> vMyOutputs;
    int64_t nMyOutputValue;
    std::vector<unsigned char> vchCredentialHash;
    std::vector<unsigned char> vchCredentialSig;

    CNullSendOutputReg()
    {
        nSessionID = 0;
        nMyOutputValue = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSessionID);
        READWRITE(vMyOutputs);
        READWRITE(nMyOutputValue);
        READWRITE(vchCredentialHash);
        READWRITE(vchCredentialSig);
    )
};


class CNullSendNonceCommit
{
public:
    int nSessionID;
    int nParticipantID;
    uint256 nonceCommitment;       // SHA256("Innova_NullSendNonce" || R_i)

    CNullSendNonceCommit()
    {
        nSessionID = 0;
        nParticipantID = -1;
        nonceCommitment = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSessionID);
        READWRITE(nParticipantID);
        READWRITE(nonceCommitment);
    )
};

class CNullSendChallenge
{
public:
    int nSessionID;
    std::vector<unsigned char> vchAggregateNonce;     // R = sum(R_i) (33 bytes)
    std::vector<unsigned char> vchChallenge;           // e (32 bytes)
    std::vector<std::vector<unsigned char>> vNoncePoints; // All R_i for verification
    CTransaction unsignedTx;                           // Complete unsigned transaction
    uint256 sighash;                                   // Hash to sign

    CNullSendChallenge()
    {
        nSessionID = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSessionID);
        READWRITE(vchAggregateNonce);
        READWRITE(vchChallenge);
        READWRITE(vNoncePoints);
        READWRITE(unsignedTx);
        READWRITE(sighash);
    )
};

class CNullSendPartialSig
{
public:
    int nSessionID;
    int nParticipantID;
    std::vector<unsigned char> vchPartialSig;          // s_i (32 bytes)
    std::vector<std::vector<unsigned char>> vSpendAuthSigs;
    std::vector<std::vector<unsigned char>> vSpendRks;

    CNullSendPartialSig()
    {
        nSessionID = 0;
        nParticipantID = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSessionID);
        READWRITE(nParticipantID);
        READWRITE(vchPartialSig);
        READWRITE(vSpendAuthSigs);
        READWRITE(vSpendRks);
    )
};

class CNullSendBroadcastTx
{
public:
    int nSessionID;
    CTransaction tx;
    CTxIn vin;
    std::vector<unsigned char> vchSig;

    CNullSendBroadcastTx()
    {
        nSessionID = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSessionID);
        READWRITE(tx);
        READWRITE(vin);
        READWRITE(vchSig);
    )
};


class CNullSendParticipant
{
public:
    int nID;
    CNode* pnode;
    CNullSendEntry entry;
    CNullSendInputReg inputReg;
    uint256 nonceCommitment;
    std::vector<unsigned char> vchNoncePoint;
    std::vector<unsigned char> vchPartialSig;
    std::vector<std::vector<unsigned char>> vSpendAuthSigs;
    std::vector<std::vector<unsigned char>> vSpendRks;
    bool fNonceCommitted;
    bool fPartialSigReceived;
    int nSpendOffset;
    int nOutputOffset;
    int64_t nLastActivity;

    CNullSendParticipant()
    {
        nID = -1;
        pnode = NULL;
        nonceCommitment = 0;
        fNonceCommitted = false;
        fPartialSigReceived = false;
        nSpendOffset = -1;
        nOutputOffset = -1;
        nLastActivity = 0;
    }
};

struct CNullSendAnonymousOutput
{
    std::vector<CShieldedOutputDescription> vOutputs;
    int64_t nOutputValue;

    CNullSendAnonymousOutput() : nOutputValue(0) {}
};

class CNullSendSession
{
public:
    int nSessionID;
    int nState;
    int64_t nStartTime;
    int64_t nStateChangeTime;
    int nTargetParticipants;
    uint8_t nPrivacyMode;
    uint256 sessionNonce;
    bool fChaumian;

    std::vector<CNullSendParticipant> vParticipants;
    CTransaction unsignedTx;
    uint256 sighash;
    std::vector<unsigned char> vchAggregateNonce;
    std::vector<unsigned char> vchChallenge;
    CTransaction finalTx;

    std::vector<unsigned char> vchRSA_N;
    std::vector<unsigned char> vchRSA_E;
    std::vector<unsigned char> vchRSA_D;
    std::vector<CNullSendAnonymousOutput> vAnonymousOutputs;
    std::set<uint256> setUsedCredentials;

    CNullSendSession()
    {
        nSessionID = 0;
        nState = NULLSEND_STATE_IDLE;
        nStartTime = 0;
        nStateChangeTime = 0;
        nTargetParticipants = NULLSEND_DEFAULT_PARTICIPANTS;
        nPrivacyMode = PRIVACY_MODE_FULL;
        fChaumian = false;
    }

    ~CNullSendSession()
    {
        if (!vchRSA_D.empty())
            OPENSSL_cleanse(vchRSA_D.data(), vchRSA_D.size());
    }

    void SetState(int newState);

    bool AcceptEntry(const CNullSendEntry& entry, CNode* pfrom);
    bool GenerateSessionRSAKey();
    bool BlindSign(const std::vector<unsigned char>& vchBlinded,
                   std::vector<unsigned char>& vchSignatureOut);
    bool VerifyCredential(const std::vector<unsigned char>& vchCredential,
                          const std::vector<unsigned char>& vchSignature);
    bool AcceptInputReg(const CNullSendInputReg& reg, CNode* pfrom);
    bool AcceptOutputReg(const CNullSendOutputReg& reg);
    bool ProcessNonceCommit(int nParticipantID, const uint256& commitment);
    bool AssembleTransaction();
    bool AssembleTransactionChaumian();
    bool ProcessPartialSig(int nParticipantID, const CNullSendPartialSig& msg);
    bool FinalizeTransaction();
    void BroadcastChallenge();
    void BroadcastFinalTx();
    void Reset(const std::string& strReason);
    bool CheckTimeout();
    bool AllNoncesCommitted() const;
    bool AllPartialSigsReceived() const;
};

class CNullSendPool
{
public:
    std::map<int, CNullSendSession> mapSessions;
    int nNextSessionID;

    CNullSendPool()
    {
        nNextSessionID = 1;
    }

    int NewSession(uint8_t nPrivacyMode, int nPoolSize);
    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    void CheckTimeouts();
};

class CNullSendClient
{
public:
    int nCurrentSession;
    int nParticipantID;
    int nState;
    std::vector<unsigned char> vchMyNonce;
    std::vector<unsigned char> vchMyNoncePoint;
    std::vector<std::vector<unsigned char>> vMyInputBlinds;
    std::vector<std::vector<unsigned char>> vMyOutputBlinds;
    CNullSendEntry myEntry;
    CNode* pCoordinator;
    int64_t nTimeout;
    int64_t nStartTime;

    std::vector<unsigned char> vchBlindingFactor;
    std::vector<unsigned char> vchCredentialHash;
    std::vector<unsigned char> vchBlindedCredential;
    std::vector<unsigned char> vchBlindSigFromCoord;
    std::vector<unsigned char> vchUnblindedSig;
    std::vector<unsigned char> vchSessionRSA_N;
    std::vector<unsigned char> vchSessionRSA_E;
    std::vector<CShieldedOutputDescription> vMyOutputsDeferred;
    int64_t nMyOutputValue;

    CNullSendClient()
    {
        nMyOutputValue = 0;
        Reset();
    }

    ~CNullSendClient()
    {
        if (!vchMyNonce.empty())
            OPENSSL_cleanse(vchMyNonce.data(), vchMyNonce.size());
        if (!vchBlindingFactor.empty())
            OPENSSL_cleanse(vchBlindingFactor.data(), vchBlindingFactor.size());
    }

    bool JoinSession(const std::string& fromAddr,
                     uint8_t nPrivacyMode, int nPoolSize, int nTimeout);
    void ProcessAccept(const CNullSendAccept& msg, CNode* pfrom);
    void ProcessInputAccept(const CNullSendInputAccept& msg, CNode* pfrom);
    void ProcessChallenge(const CNullSendChallenge& msg);
    void ProcessFinalTx(const CNullSendBroadcastTx& msg);

    bool BlindOutputCredential(const std::vector<unsigned char>& vchRSA_N,
                               const std::vector<unsigned char>& vchRSA_E);
    bool UnblindSignature(const std::vector<unsigned char>& vchBlindSig);
    bool SubmitOutputsAnonymously();

    void Reset();
    bool IsActive() const { return nState != NULLSEND_STATE_IDLE; }
};

extern CNullSendPool nullSendPool;
extern CNullSendClient nullSendClient;
extern CCriticalSection cs_nullsend;
extern std::vector<CNullSendQueue> vecNullSendQueue;

void ProcessMessageNullSend(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

void ThreadNullSend(void* parg);

#endif // INN_NULLSEND_H
