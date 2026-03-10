// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_SHIELDED_COINJOIN_H
#define INN_SHIELDED_COINJOIN_H

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


#define CJOIN_STATE_IDLE              0
#define CJOIN_STATE_ACCEPTING         1
#define CJOIN_STATE_NONCE_COMMIT      2
#define CJOIN_STATE_PARTIAL_SIG       3
#define CJOIN_STATE_TRANSMISSION      4
#define CJOIN_STATE_SUCCESS           5
#define CJOIN_STATE_ERROR             6

#define CJOIN_STATE_INPUT_REG         10
#define CJOIN_STATE_OUTPUT_REG        11

#define CJOIN_ACCEPTED                1
#define CJOIN_REJECTED                0
#define CJOIN_RESET                  -1

static const int CJOIN_MIN_PARTICIPANTS = 3;
static const int CJOIN_MAX_PARTICIPANTS = 8;
static const int CJOIN_DEFAULT_PARTICIPANTS = 5;
static const int CJOIN_QUEUE_TIMEOUT = 300;
static const int CJOIN_ROUND_TIMEOUT = 60;
static const int CJOIN_OUTPUT_REG_TIMEOUT = 120;
static const int64_t CJOIN_FEE = 100000;
static const int CJOIN_RSA_BITS = 2048;


class CShieldedCJQueue
{
public:
    CTxIn vin;
    int64_t nTime;
    int64_t nMinAmount;
    int64_t nMaxAmount;
    uint8_t nPrivacyMode;
    int nPoolSize;
    int nSessionID;
    uint256 sessionNonce;
    std::vector<unsigned char> vchSig;

    CShieldedCJQueue()
    {
        nTime = 0;
        nMinAmount = 0;
        nMaxAmount = 0;
        nPrivacyMode = PRIVACY_MODE_FULL;
        nPoolSize = CJOIN_DEFAULT_PARTICIPANTS;
        nSessionID = 0;
        sessionNonce = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vin);
        READWRITE(nTime);
        READWRITE(nMinAmount);
        READWRITE(nMaxAmount);
        READWRITE(nPrivacyMode);
        READWRITE(nPoolSize);
        READWRITE(nSessionID);
        READWRITE(sessionNonce);
        READWRITE(vchSig);
    )

    bool IsExpired() const { return (GetTime() - nTime) > CJOIN_QUEUE_TIMEOUT; }
};

class CShieldedCJEntry
{
public:
    int nSessionID;
    std::vector<CShieldedSpendDescription> vMySpends;
    std::vector<CShieldedOutputDescription> vMyOutputs;
    int64_t nMyValueBalance;
    uint8_t nPrivacyMode;
    int64_t nAddedTime;
    std::vector<uint256> vBlindedNullifiers;

    CShieldedCJEntry()
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
        READWRITE(vBlindedNullifiers);
    )

    bool IsExpired() const { return (GetTime() - nAddedTime) > CJOIN_QUEUE_TIMEOUT; }
};

class CShieldedCJAccept
{
public:
    int nSessionID;
    int nStatusCode;
    int nParticipantID;
    std::string strMessage;

    CShieldedCJAccept()
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


class CShieldedCJInputReg
{
public:
    int nSessionID;
    std::vector<CShieldedSpendDescription> vMySpends;
    int64_t nMyInputValue;
    uint8_t nPrivacyMode;
    std::vector<uint256> vBlindedNullifiers;
    std::vector<unsigned char> vchBlindedCredential;

    CShieldedCJInputReg()
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

class CShieldedCJInputAccept
{
public:
    int nSessionID;
    int nStatusCode;
    int nParticipantID;
    std::vector<unsigned char> vchBlindSignature;
    std::vector<unsigned char> vchRSA_N;
    std::vector<unsigned char> vchRSA_E;
    std::string strMessage;

    CShieldedCJInputAccept()
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

class CShieldedCJOutputReg
{
public:
    int nSessionID;
    std::vector<CShieldedOutputDescription> vMyOutputs;
    int64_t nMyOutputValue;
    std::vector<unsigned char> vchCredentialHash;
    std::vector<unsigned char> vchCredentialSig;

    CShieldedCJOutputReg()
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


class CShieldedCJNonceCommit
{
public:
    int nSessionID;
    int nParticipantID;
    uint256 nonceCommitment;       // SHA256("Innova_CJNonce" || R_i)

    CShieldedCJNonceCommit()
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

class CShieldedCJChallenge
{
public:
    int nSessionID;
    std::vector<unsigned char> vchAggregateNonce;     // R = sum(R_i) (33 bytes)
    std::vector<unsigned char> vchChallenge;           // e (32 bytes)
    std::vector<std::vector<unsigned char>> vNoncePoints; // All R_i for verification
    CTransaction unsignedTx;                           // Complete unsigned transaction
    uint256 sighash;                                   // Hash to sign

    CShieldedCJChallenge()
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

class CShieldedCJPartialSig
{
public:
    int nSessionID;
    int nParticipantID;
    std::vector<unsigned char> vchPartialSig;          // s_i (32 bytes)
    std::vector<std::vector<unsigned char>> vSpendAuthSigs;
    std::vector<std::vector<unsigned char>> vSpendRks;

    CShieldedCJPartialSig()
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

class CShieldedCJBroadcastTx
{
public:
    int nSessionID;
    CTransaction tx;
    CTxIn vin;
    std::vector<unsigned char> vchSig;

    CShieldedCJBroadcastTx()
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


class CShieldedCJParticipant
{
public:
    int nID;
    CNode* pnode;
    CShieldedCJEntry entry;
    CShieldedCJInputReg inputReg;
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

    CShieldedCJParticipant()
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

struct CAnonymousOutput
{
    std::vector<CShieldedOutputDescription> vOutputs;
    int64_t nOutputValue;

    CAnonymousOutput() : nOutputValue(0) {}
};

class CShieldedCoinJoinSession
{
public:
    int nSessionID;
    int nState;
    int64_t nStartTime;
    int64_t nStateChangeTime;
    int nTargetParticipants;
    int64_t nMinAmount;
    int64_t nMaxAmount;
    uint8_t nPrivacyMode;
    uint256 sessionNonce;
    bool fChaumian;

    std::vector<CShieldedCJParticipant> vParticipants;
    CTransaction unsignedTx;
    uint256 sighash;
    std::vector<unsigned char> vchAggregateNonce;
    std::vector<unsigned char> vchChallenge;
    CTransaction finalTx;

    std::vector<unsigned char> vchRSA_N;
    std::vector<unsigned char> vchRSA_E;
    std::vector<unsigned char> vchRSA_D;
    std::vector<CAnonymousOutput> vAnonymousOutputs;
    std::set<uint256> setUsedCredentials;

    CShieldedCoinJoinSession()
    {
        nSessionID = 0;
        nState = CJOIN_STATE_IDLE;
        nStartTime = 0;
        nStateChangeTime = 0;
        nTargetParticipants = CJOIN_DEFAULT_PARTICIPANTS;
        nMinAmount = 0;
        nMaxAmount = 0;
        nPrivacyMode = PRIVACY_MODE_FULL;
        fChaumian = false;
    }

    ~CShieldedCoinJoinSession()
    {
        if (!vchRSA_D.empty())
            OPENSSL_cleanse(vchRSA_D.data(), vchRSA_D.size());
    }

    void SetState(int newState);

    bool AcceptEntry(const CShieldedCJEntry& entry, CNode* pfrom);
    bool GenerateSessionRSAKey();
    bool BlindSign(const std::vector<unsigned char>& vchBlinded,
                   std::vector<unsigned char>& vchSignatureOut);
    bool VerifyCredential(const std::vector<unsigned char>& vchCredential,
                          const std::vector<unsigned char>& vchSignature);
    bool AcceptInputReg(const CShieldedCJInputReg& reg, CNode* pfrom);
    bool AcceptOutputReg(const CShieldedCJOutputReg& reg);
    bool ProcessNonceCommit(int nParticipantID, const uint256& commitment);
    bool AssembleTransaction();
    bool AssembleTransactionChaumian();
    bool ProcessPartialSig(int nParticipantID, const CShieldedCJPartialSig& msg);
    bool FinalizeTransaction();
    void BroadcastChallenge();
    void BroadcastFinalTx();
    void Reset(const std::string& strReason);
    bool CheckTimeout();
    bool AllNoncesCommitted() const;
    bool AllPartialSigsReceived() const;
};

class CShieldedCoinJoinPool
{
public:
    std::map<int, CShieldedCoinJoinSession> mapSessions;
    int nNextSessionID;

    CShieldedCoinJoinPool()
    {
        nNextSessionID = 1;
    }

    int NewSession(int64_t nMinAmount, int64_t nMaxAmount, uint8_t nPrivacyMode, int nPoolSize);
    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    void CheckTimeouts();
};

class CShieldedCoinJoinClient
{
public:
    int nCurrentSession;
    int nParticipantID;
    int nState;
    std::vector<unsigned char> vchMyNonce;
    std::vector<unsigned char> vchMyNoncePoint;
    std::vector<std::vector<unsigned char>> vMyInputBlinds;
    std::vector<std::vector<unsigned char>> vMyOutputBlinds;
    CShieldedCJEntry myEntry;
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

    CShieldedCoinJoinClient()
    {
        nMyOutputValue = 0;
        Reset();
    }

    ~CShieldedCoinJoinClient()
    {
        if (!vchMyNonce.empty())
            OPENSSL_cleanse(vchMyNonce.data(), vchMyNonce.size());
        if (!vchBlindingFactor.empty())
            OPENSSL_cleanse(vchBlindingFactor.data(), vchBlindingFactor.size());
    }

    bool JoinSession(const std::string& fromAddr, int64_t nAmount,
                     uint8_t nPrivacyMode, int nPoolSize, int nTimeout);
    void ProcessAccept(const CShieldedCJAccept& msg, CNode* pfrom);
    void ProcessInputAccept(const CShieldedCJInputAccept& msg, CNode* pfrom);
    void ProcessChallenge(const CShieldedCJChallenge& msg);
    void ProcessFinalTx(const CShieldedCJBroadcastTx& msg);

    bool BlindOutputCredential(const std::vector<unsigned char>& vchRSA_N,
                               const std::vector<unsigned char>& vchRSA_E);
    bool UnblindSignature(const std::vector<unsigned char>& vchBlindSig);
    bool SubmitOutputsAnonymously();

    void Reset();
    bool IsActive() const { return nState != CJOIN_STATE_IDLE; }
};

extern CShieldedCoinJoinPool shieldedCoinJoinPool;
extern CShieldedCoinJoinClient shieldedCoinJoinClient;
extern CCriticalSection cs_shieldedcoinjoin;
extern std::vector<CShieldedCJQueue> vecShieldedCJQueue;

void ProcessMessageShieldedCoinJoin(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

void ThreadShieldedCoinJoin(void* parg);

#endif // INN_SHIELDED_COINJOIN_H
