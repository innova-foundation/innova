// Copyright (c) 2017-2021 The Denarius developers
// Copyright (c) 2019-2021 The Innova developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef COLLATERALNODE_H
#define COLLATERALNODE_H

#include "uint256.h"
#include "uint256.h"
#include "sync.h"
#include "net.h"
#include "key.h"
#include "util.h"
#include "base58.h"
#include "hashblock.h"
#include "main.h"
#include "script.h"

class CCollateralNode;
class CCollateralnodePayments;
class uint256;

#define COLLATERALNODE_NOT_PROCESSED               0 // initial state
#define COLLATERALNODE_IS_CAPABLE                  1
#define COLLATERALNODE_NOT_CAPABLE                 2
#define COLLATERALNODE_STOPPED                     3
#define COLLATERALNODE_INPUT_TOO_NEW               4
#define COLLATERALNODE_PORT_NOT_OPEN               6
#define COLLATERALNODE_PORT_OPEN                   7
#define COLLATERALNODE_SYNC_IN_PROCESS             8
#define COLLATERALNODE_REMOTELY_ENABLED            9

#define COLLATERALNODE_MIN_CONFIRMATIONS           15
#define COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY     500
#define COLLATERALNODE_MIN_DSEEP_SECONDS           (10*60)
#define COLLATERALNODE_MIN_DSEE_SECONDS            (5*60)
#define COLLATERALNODE_PING_SECONDS                (1*60)
#define COLLATERALNODE_EXPIRATION_SECONDS          (120*60)
#define COLLATERALNODE_REMOVAL_SECONDS             (130*60)
#define COLLATERALNODE_CHECK_SECONDS               10

#define COLLATERALNODE_FAIR_PAYMENT_MINIMUM         200
#define COLLATERALNODE_FAIR_PAYMENT_ROUNDS          3

using namespace std;

class CCollateralnodePaymentWinner;

extern CCriticalSection cs_collateralnodes;
extern std::vector<CCollateralNode> vecCollateralnodes;
extern std::vector<pair<int, CCollateralNode*> > vecCollateralnodeScores;
extern std::vector<pair<int, CCollateralNode> > vecCollateralnodeRanks;
extern CCollateralnodePayments collateralnodePayments;
extern std::vector<CTxIn> vecCollateralnodeAskedFor;
extern map<uint256, CCollateralnodePaymentWinner> mapSeenCollateralnodeVotes;
extern map<int64_t, uint256> mapCacheBlockHashes;
extern unsigned int mnCount;


// manage the collateralnode connections
void ProcessCollateralnodeConnections();
int CountCollateralnodesAboveProtocol(int protocolVersion);


void ProcessMessageCollateralnode(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
bool CheckCollateralnodeVin(CTxIn& vin, std::string& errorMessage, CBlockIndex *pindex);

// For storing payData
class CCollateralNPayData
{
public:
    int height;
    uint256 hash;
    int64_t amount;

    CCollateralNPayData() {
        height = 0;
        hash = 0;
        amount = 0;
    }

};

class CCollateralNCollateral
{
public:
    CTxIn vin;
    CScript scriptPubKey;
    int height;
    uint256 blockHash;

    CCollateralNCollateral() {
        height = 0;
        blockHash = 0;
    }
};

// For storing payData
class CCollateralNPayments
{
public:
    std::vector<CCollateralNode> vStakes; // this array should be sorted
    std::vector<CCollateralNPayData> vPayments; // this array just contains our scanned data
    //std::vector<CTxIn> vCollaterals;
    std::vector<CCollateralNCollateral> vCollaterals;
    std::vector<CScript> vScripts;

    CCollateralNPayments() {
        // fill vStakes array with pointers to MN's from vecCollateralnodes
    }

    bool add(CCollateralNode* mn)
    {
        // add address of pointer into the payments array
        return true;
    }

    bool remove(CCollateralNode* mn)
    {
        // remove address of pointer from the payments array
        return true;
    }

    void update(const CBlockIndex *pindex, bool force = false);

    bool initialize(const CBlockIndex* pindex);
};

//
// The Collateralnode Class. For managing the collateral process. It contains the input of the 25000 INN, signature to prove
// it's the one who own that ip address and code for calculating the payment election.
//
class CCollateralNode
{
public:
	static int minProtoVersion;
    CService addr;
    CTxIn vin;
    int64_t lastTimeSeen;
    CPubKey pubkey;
    CPubKey pubkey2;
    std::vector<unsigned char> sig;
    std::vector<CCollateralNPayData> payData;
    pair<int, int64_t> payInfo;
    int64_t payRate;
    int payCount;
    int64_t payValue;
    int64_t now; //isee message times
    int64_t lastDseep;
    int cacheInputAge;
    int cacheInputAgeBlock;
    int enabled;
    string status;
    bool unitTest;
    bool allowFreeTx;
    int protocolVersion;
    int64_t lastTimeChecked;
    int nBlockLastPaid;
    int64_t nTimeLastChecked;
    int64_t nTimeRegistered;
    int nRank;


    //the dsq count from the last dsq broadcast of this node
    int64_t nLastDsq;
    CCollateralNode(CService newAddr, CTxIn newVin, CPubKey newPubkey, std::vector<unsigned char> newSig, int64_t newNow, CPubKey newPubkey2, int protocolVersionIn)
    {
        addr = newAddr;
        vin = newVin;
        pubkey = newPubkey;
        pubkey2 = newPubkey2;
        sig = newSig;
        now = newNow;
        enabled = 1;
        lastTimeSeen = 0;
        unitTest = false;
        cacheInputAge = 0;
        cacheInputAgeBlock = 0;
        nLastDsq = 0;
        lastDseep = 0;
        allowFreeTx = true;
        protocolVersion = protocolVersionIn;
        lastTimeChecked = 0;
        nBlockLastPaid = 0;
        nTimeLastChecked = 0;
        nTimeRegistered = newNow;
        nRank = 0;
        payValue = 0;
        payRate = 0;
        payCount = 0;
    }

    uint256 CalculateScore(int mod=1, int64_t nBlockHeight=0);

    int SetPayRate(int nHeight);
    bool GetPaymentInfo(const CBlockIndex *pindex, int64_t &totalValue, double &actualRate);
    float GetPaymentRate(const CBlockIndex *pindex);
    int GetPaymentAmount(const CBlockIndex *pindex, int nMaxBlocksToScanBack, int64_t &totalValue);
    int UpdateLastPaidAmounts(const CBlockIndex *pindex, int nMaxBlocksToScanBack, int &value);
    void UpdateLastPaidBlock(const CBlockIndex *pindex, int nMaxBlocksToScanBack);

    void UpdateLastSeen(int64_t override=0)
    {
        if(override == 0 || override > GetAdjustedTime()){
            lastTimeSeen = GetAdjustedTime();
        } else {
            lastTimeSeen = override;
        }
    }

    bool IsActive() {
        if (lastTimeSeen - now > (max(COLLATERALNODE_FAIR_PAYMENT_MINIMUM, (int)mnCount) * 30))
        { // isee broadcast is more than a round old, let's consider it active
                return true;
        }
        return false;
    }

    inline uint64_t SliceHash(uint256& hash, int slice)
    {
        uint64_t n = 0;
        memcpy(&n, &hash+slice*64, 64);
        return n;
    }

    void Check(bool forceCheck=false);

    bool UpdatedWithin(int seconds)
    {
        // printf("UpdatedWithin %d, %d --  %d \n", GetAdjustedTime() , lastTimeSeen, (GetAdjustedTime() - lastTimeSeen) < seconds);

        return (GetAdjustedTime() - lastTimeSeen) < seconds;
    }

    void Disable()
    {
        lastTimeSeen = 0;
    }

    bool IsEnabled()
    {
        return enabled == 1;
    }

    int GetCollateralnodeInputAge(CBlockIndex* pindex=pindexBest)
    {
        if(pindex == NULL) return 0;

        if(cacheInputAge == 0){
            cacheInputAge = GetInputAge(vin, pindex);
            cacheInputAgeBlock = pindex->nHeight;
        }

        return cacheInputAge+(pindex->nHeight-cacheInputAgeBlock);
    }
};



// Get the current winner for this block
int GetCurrentCollateralNode(int mod=1, int64_t nBlockHeight=0, int minProtocol=CCollateralNode::minProtoVersion);
bool CheckCNPayment(CBlockIndex* pindex, int64_t value, CCollateralNode &mn);
bool CheckPoSCNPayment(CBlockIndex* pindex, int64_t value, CCollateralNode &mn);
int64_t avg2(std::vector<CCollateralNode> const& v);
int64_t avgCount(std::vector<CCollateralNode> const& v);
int GetCollateralnodeByVin(CTxIn& vin);
int GetCollateralnodeRank(CCollateralNode& tmn, CBlockIndex* pindex, int minProtocol=CCollateralNode::minProtoVersion);
int GetCollateralnodeByRank(int findRank, int64_t nBlockHeight=0, int minProtocol=CCollateralNode::minProtoVersion);
bool GetCollateralnodeRanks(CBlockIndex* pindex=pindexBest);
extern int64_t nAverageCNIncome;
bool FindCNPayment(CScript& payee, CBlockIndex* pindex=pindexBest);

// for storing the winning payments
class CCollateralnodePaymentWinner
{
public:
    int nBlockHeight;
    CTxIn vin;
    CScript payee;
    std::vector<unsigned char> vchSig;
    uint64_t score;

    CCollateralnodePaymentWinner() {
        nBlockHeight = 0;
        score = 0;
        vin = CTxIn();
        payee = CScript();
    }

    uint256 GetHash(){
        uint256 n2 = Tribus(BEGIN(nBlockHeight), END(nBlockHeight));
        uint256 n3 = vin.prevout.hash > n2 ? (vin.prevout.hash - n2) : (n2 - vin.prevout.hash);

        return n3;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion){
	unsigned int nSerSize = 0;
        READWRITE(nBlockHeight);
        READWRITE(payee);
        READWRITE(vin);
        READWRITE(score);
        READWRITE(vchSig);
     }
};

inline bool operator==(const CCollateralNode& a, const CCollateralNode& b)
{
    return a.vin == b.vin;
}
inline bool operator!=(const CCollateralNode& a, const CCollateralNode& b)
{
    return !(a.vin == b.vin);
}
inline bool operator<(const CCollateralNode& a, const CCollateralNode& b)
{
    return (a.nBlockLastPaid < b.nBlockLastPaid);
}
inline bool operator>(const CCollateralNode& a, const CCollateralNode& b)
{
    return (a.nBlockLastPaid > b.nBlockLastPaid);
}

//
// Collateralnode Payments Class
// Keeps track of who should get paid for which blocks
//

class CCollateralnodePayments
{
private:
    std::vector<CCollateralnodePaymentWinner> vWinning;
    int nSyncedFromPeer;
    std::string strMasterPrivKey;
    std::string strTestPubKey;
    std::string strMainPubKey;
    bool enabled;

public:

    CCollateralnodePayments() {
        strMainPubKey = "";
        strTestPubKey = "";
        enabled = false;
    }

    bool SetPrivKey(std::string strPrivKey);
    bool CheckSignature(CCollateralnodePaymentWinner& winner);
    bool Sign(CCollateralnodePaymentWinner& winner);

    // Deterministically calculate a given "score" for a collateralnode depending on how close it's hash is
    // to the blockHeight. The further away they are the better, the furthest will win the election
    // and get paid this block
    //

    uint256 vecCollateralnodeRanksLastUpdated;
    uint64_t CalculateScore(uint256 blockHash, CTxIn& vin);
    bool GetWinningCollateralnode(int nBlockHeight, CTxIn& vinOut);
    bool AddWinningCollateralnode(CCollateralnodePaymentWinner& winner);
    bool ProcessBlock(int nBlockHeight);
    void Relay(CCollateralnodePaymentWinner& winner);
    void Sync(CNode* node);
    void CleanPaymentList();
    int LastPayment(CCollateralNode& mn);

    //slow
    bool GetBlockPayee(int nBlockHeight, CScript& payee);
};



#endif
