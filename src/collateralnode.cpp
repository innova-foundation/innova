// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The DarkCoin developers
// Copyright (c) 2017-2021 The Denarius developers
// Copyright (c) 2019-2022 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "collateralnode.h"
#include "activecollateralnode.h"
#include "collateral.h"
#include "txdb.h"
#include "main.h"
#include "util.h"
#include "addrman.h"
#include "sync.h"
#include "core.h"
#include <boost/lexical_cast.hpp>

int CCollateralNode::minProtoVersion = MIN_MN_PROTO_VERSION;

CCriticalSection cs_collateralnodes;

/** The list of active collateralnodes */
std::vector<CCollateralNode> vecCollateralnodes;
std::vector<pair<int, CCollateralNode*> > vecCollateralnodeScores;
std::vector<CCollateralNode> vecCollateralnodeScoresList;
CCollateralNPayments ranks;
uint256 vecCollateralnodeScoresListHash;
std::vector<pair<int, CCollateralNode> > vecCollateralnodeRanks;
/** Object for who's going to get paid on which blocks */
CCollateralnodePayments collateralnodePayments;
// keep track of collateralnode votes I've seen
map<uint256, CCollateralnodePaymentWinner> mapSeenCollateralnodeVotes;
// keep track of the scanning errors I've seen
map<uint256, int> mapSeenCollateralnodeScanningErrors;
// who's asked for the collateralnode list and the last time
std::map<CNetAddr, int64_t> askedForCollateralnodeList;
// which collateralnodes we've asked for
std::map<COutPoint, int64_t> askedForCollateralnodeListEntry;
// cache block hashes as we calculate them
std::map<int64_t, uint256> mapCacheBlockHashes;
CMedianFilter<unsigned int> mnMedianCount(10, 0);
unsigned int mnCount = 0;
int64_t nAverageCNIncome;
int64_t nAveragePayCount;

// manage the collateralnode connections
void ProcessCollateralnodeConnections(){
    LOCK(cs_vNodes);

    for (CNode* pnode : vNodes)
    {
        //if it's our collateralnode, let it be
        if(colLateralPool.submittedToCollateralnode == pnode->addr) continue;

        if( pnode->fColLateralMaster ||
            (pnode->addr.GetPort() == 14539 && pnode->nChainHeight > (nBestHeight - 120)) // disconnect collateralnodes that were in sync when they connected recently
                )
        {
            printf("Closing collateralnode connection %s \n", pnode->addr.ToString().c_str());
            pnode->CloseSocketDisconnect();
        }
    }
}

void ProcessMessageCollateralnode(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{

    if (strCommand == "isee") { // CollaTeral Election Entry
        // if (nBestHeight < (GetNumBlocksOfPeers() - 300)) return; // don't process these until near completion
        bool fIsInitialDownload = IsInitialBlockDownload();
        if(fIsInitialDownload) return;

        CTxIn vin;
        CService addr;
        CPubKey pubkey;
        CPubKey pubkey2;
        vector<unsigned char> vchSig;
        int64_t sigTime;
        int count;
        int current;
        int64_t lastUpdated;
        int protocolVersion;
        bool isLocal;
        std::string strMessage;

        // 70047 and greater
        vRecv >> vin >> addr >> vchSig >> sigTime >> pubkey >> pubkey2 >> count >> current >> lastUpdated >> protocolVersion;

        // make sure signature isn't in the future (past is OK)
        if (sigTime > pindexBest->GetBlockTime() + 30 * 30) {
            if (fDebugCN) printf("isee - Signature rejected, too far into the future %s\n", vin.ToString().c_str());
            return;
        }

        isLocal = addr.IsRFC1918() || addr.IsLocal();
        //if(Params().MineBlocksOnDemand()) isLocal = false;

        std::string vchPubKey(pubkey.begin(), pubkey.end());
        std::string vchPubKey2(pubkey2.begin(), pubkey2.end());

        strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion);

        if(protocolVersion < MIN_MN_PROTO_VERSION) {
            if (fDebugCN) printf("isee - ignoring outdated collateralnode %s protocol version %d\n", vin.ToString().c_str(), protocolVersion);
            return;
        }

        CScript pubkeyScript;
        pubkeyScript = GetScriptForDestination(pubkey.GetID());

        if(pubkeyScript.size() != 25) {
            if (fDebugCN) printf("isee - pubkey the wrong size\n");
            Misbehaving(pfrom->GetId(), 100);
            return;
        }

        CScript pubkeyScript2;
        pubkeyScript2 =GetScriptForDestination(pubkey2.GetID());

        if(pubkeyScript2.size() != 25) {
            if (fDebugCN) printf("isee - pubkey2 the wrong size\n");
            Misbehaving(pfrom->GetId(), 100);
            return;
        }

        std::string errorMessage = "";
        if(!colLateralSigner.VerifyMessage(pubkey, vchSig, strMessage, errorMessage)){
            if (fDebugCN) printf("isee - Got bad collateralnode address signature\n");
            Misbehaving(pfrom->GetId(), 100);
            return;
        }

        if((fTestNet && addr.GetPort() != 15539) || (!fTestNet && addr.GetPort() != 14539)) return;

        //search existing collateralnode list, this is where we update existing collateralnodes with new isee broadcasts
        LOCK(cs_collateralnodes);
        for (CCollateralNode& mn : vecCollateralnodes) {
            if(mn.vin.prevout == vin.prevout) {
                // count == -1 when it's a new entry
                //   e.g. We don't want the entry relayed/time updated when we're syncing the list
                // mn.pubkey = pubkey, IsVinAssociatedWithPubkey is validated once below,
                //   after that they just need to match
                if(count == -1 && mn.pubkey == pubkey && !mn.UpdatedWithin(COLLATERALNODE_MIN_DSEE_SECONDS)){
					mn.UpdateLastSeen(sigTime); // Updated UpdateLastSeen with sigTime
                    //mn.UpdateLastSeen(); // update last seen without the sigTime since it's a new entry

                    if(mn.now < sigTime){ //take the newest entry
                        if (fDebugCN & fDebugNet) printf("isee - Got updated entry for %s\n", addr.ToString().c_str());
                        mn.UpdateLastSeen(); // update with current time (i.e. the time we received this 'new' isee
                        mn.pubkey2 = pubkey2;
                        mn.now = sigTime;
                        mn.sig = vchSig;
                        mn.protocolVersion = protocolVersion;
                        mn.addr = addr;

                        RelayCollaTeralElectionEntry(vin, addr, vchSig, sigTime, pubkey, pubkey2, count, current, lastUpdated, protocolVersion);
                    }
                }

                return;
            }
        }

        sort(vecCollateralnodes.begin(), vecCollateralnodes.end());
        vecCollateralnodes.erase(unique(vecCollateralnodes.begin(), vecCollateralnodes.end() ), vecCollateralnodes.end());
        // printf("Sorted and removed duplicate CN out of the vector!!\n");

        if (count > 0) {
            mnMedianCount.input(count);
            mnCount = mnMedianCount.median();
        }

        // make sure the vout that was signed is related to the transaction that spawned the collateralnode
        //  - this is expensive, so it's only done once per collateralnode
        //  - if sigTime is newer than our chain, this will probably never work, so don't bother.
        if(sigTime < pindexBest->GetBlockTime() && !colLateralSigner.IsVinAssociatedWithPubkey(vin, pubkey)) {
            if (fDebugCN) printf("isee - Got mismatched pubkey and vin\n");
            return;
        }

        if(fDebugCN) printf("isee - Got NEW collateralnode entry %s\n", addr.ToString().c_str());

        // make sure it's still unspent
        //  - this is checked later by .check() in many places and by ThreadCheckCollaTeralPool()
        std::string vinError;
        if(CheckCollateralnodeVin(vin,vinError,pindexBest)){
            if (fDebugCN && fDebugNet) printf("isee - Accepted input for collateralnode entry %i %i\n", count, current);

            //if(GetInputAge(vin, pindexBest) < (nBestHeight > BLOCK_START_COLLATERALNODE_DELAYPAY ? COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY : COLLATERALNODE_MIN_CONFIRMATIONS)){
            //    if (fDebugCN && fDebugNet) printf("isee - Input must have least %d confirmations\n", (nBestHeight > BLOCK_START_COLLATERALNODE_DELAYPAY ? COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY : COLLATERALNODE_MIN_CONFIRMATIONS));
            //    Misbehaving(pfrom->GetId(), 20);
            //    return;
            //}

            // use this as a peer
            addrman.Add(CAddress(addr), pfrom->addr, 2*60*60);

            // add our collateralnode
            CCollateralNode mn(addr, vin, pubkey, vchSig, sigTime, pubkey2, protocolVersion);
            mn.UpdateLastSeen(lastUpdated);
            CBlockIndex* pindex = pindexBest;

            // if it matches our collateralnodeprivkey, then we've been remotely activated
            if(pubkey2 == activeCollateralnode.pubKeyCollateralnode && protocolVersion == PROTOCOL_VERSION){
                activeCollateralnode.EnableHotColdCollateralNode(vin, addr);
            }

            if(count == -1 && !isLocal)
                RelayCollaTeralElectionEntry(vin, addr, vchSig, sigTime, pubkey, pubkey2, count, current, lastUpdated, protocolVersion);

            // no need to look up the payment amounts right now, they aren't eligible for payment now anyway
            //int payments = mn.UpdateLastPaidAmounts(pindex, 1000, value); // do a search back 1000 blocks when receiving a new collateralnode to find their last payment, payments = number of payments received, value = amount


            //TODO: Set a timer to update ranks after a second

            if (fDebugCN) printf("Registered new collateralnode %s (%i/%i)\n", addr.ToString().c_str(), count, current);

            vecCollateralnodes.push_back(mn);

        } else {
            if (fDebugCN) printf("isee - Rejected collateralnode entry %s: %s\n", addr.ToString().c_str(),vinError.c_str());
        }
    }

    else if (strCommand == "iseep") { //CollaTeral Election Entry Ping
        //if (nBestHeight < (GetNumBlocksOfPeers() - 300)) return; // don't process these until near completion
        bool fIsInitialDownload = IsInitialBlockDownload();
        if(fIsInitialDownload) return;

        CTxIn vin;
        vector<unsigned char> vchSig;
        int64_t sigTime;
        bool stop;
        vRecv >> vin >> vchSig >> sigTime >> stop;

        if (fDebugCN & fDebugSmsg) printf("iseep - Received: vin: %s sigTime: %lld stop: %s\n", vin.ToString().c_str(), sigTime, stop ? "true" : "false");
        if (sigTime > pindexBest->GetBlockTime() + (60 * 60)*2) {
            if (fDebugCN) printf("iseep - Signature rejected, too far into the future %s, sig %d local %d \n", vin.ToString().c_str(), sigTime, GetAdjustedTime());
            return;
        }

        if (sigTime <= pindexBest->GetBlockTime() - (60 * 60)*2) {
            if (fDebugCN) printf("iseep - Signature rejected, too far into the past %s - sig %d local %d \n", vin.ToString().c_str(), sigTime, GetAdjustedTime());
            return;
        }

        // see if we have this collateralnode
	      LOCK(cs_collateralnodes);
        for (CCollateralNode& mn : vecCollateralnodes) {
            if(mn.vin.prevout == vin.prevout) {
            	// printf("iseep - Found corresponding mn for vin: %s\n", vin.ToString().c_str());
            	// take this only if it's newer
                if(mn.lastDseep < sigTime){
                    std::string strMessage = mn.addr.ToString() + boost::lexical_cast<std::string>(sigTime) + boost::lexical_cast<std::string>(stop);

                    std::string errorMessage = "";
                    if(!colLateralSigner.VerifyMessage(mn.pubkey2, vchSig, strMessage, errorMessage)){
                        if (fDebugCN) printf("iseep - Got bad collateralnode address signature %s \n", vin.ToString().c_str());
                        //Misbehaving(pfrom->GetId(), 100);
                        return;
                    }

                    mn.lastDseep = sigTime;

                    if(!mn.UpdatedWithin(COLLATERALNODE_MIN_DSEEP_SECONDS)){
                        mn.UpdateLastSeen();
                        if(stop) {
                            mn.Disable();
                            mn.Check(true);
                        }
                        RelayCollaTeralElectionEntryPing(vin, vchSig, sigTime, stop);
                    }
                }
                return;
            }
        }

        if (fDebugCN) printf("iseep - Couldn't find collateralnode entry %s\n", vin.ToString().c_str());

        std::map<COutPoint, int64_t>::iterator i = askedForCollateralnodeListEntry.find(vin.prevout);
        if (i != askedForCollateralnodeListEntry.end()){
            int64_t t = (*i).second;
            if (GetTime() < t) {
                // we've asked recently
                return;
            }
        }

        // ask for the isee info once from the node that sent iseep

        if (fDebugCN && fDebugNet) printf("iseep - Asking source node for missing entry %s\n", vin.ToString().c_str());
        pfrom->PushMessage("iseg", vin);
        int64_t askAgain = GetTime()+(60*1); // only ask for each isee once per minute
        askedForCollateralnodeListEntry[vin.prevout] = askAgain;

    } else if (strCommand == "iseg") { //Get collateralnode list or specific entry
        bool fIsInitialDownload = IsInitialBlockDownload();
        if(fIsInitialDownload) return;

        CTxIn vin;
        vRecv >> vin;

        if(vin == CTxIn()) { //only should ask for this once
            //local network
            //Note tor peers show up as local proxied addrs
            //if(!pfrom->addr.IsRFC1918())//&& !Params().MineBlocksOnDemand())
            //{
              if(!pfrom->addr.IsRFC1918())
              {
                std::map<CNetAddr, int64_t>::iterator i = askedForCollateralnodeList.find(pfrom->addr);
                if (i != askedForCollateralnodeList.end())
                {
                    int64_t t = (*i).second;
                    if (GetTime() < t) {
                        //Misbehaving(pfrom->GetId(), 34);
                        //printf("iseg - peer already asked me for the list\n");
                        //return;
                        //Misbehaving(pfrom->GetId(), 34);
                        printf("iseg - peer already asked me for the list\n");
                        return;
                    }
                }

                int64_t askAgain = GetTime()+(60*1); // only allow nodes to do a iseg all once per minute
                askedForCollateralnodeList[pfrom->addr] = askAgain;
            //}
              }
        } //else, asking for a specific node which is ok

	      LOCK(cs_collateralnodes);
        int count = vecCollateralnodes.size();
        int i = 0;

        for (CCollateralNode mn : vecCollateralnodes) {

            if(mn.addr.IsRFC1918()) continue; //local network

            if(vin == CTxIn()){
                mn.Check(true);
                if(mn.IsEnabled()) {
                    if(fDebugCN && fDebugNet) printf("iseg - Sending collateralnode entry - %s \n", mn.addr.ToString().c_str());
                    pfrom->PushMessage("isee", mn.vin, mn.addr, mn.sig, mn.now, mn.pubkey, mn.pubkey2, count, i, mn.lastTimeSeen, mn.protocolVersion);
                }
            } else if (vin == mn.vin) {
                if(fDebugCN && fDebugNet) printf("iseg - Sending collateralnode entry - %s \n", mn.addr.ToString().c_str());
                pfrom->PushMessage("isee", mn.vin, mn.addr, mn.sig, mn.now, mn.pubkey, mn.pubkey2, count, i, mn.lastTimeSeen, mn.protocolVersion);
                printf("iseg - Sent 1 collateralnode entries to %s\n", pfrom->addr.ToString().c_str());
                return;
            }
            i++;
        }

        printf("iseg - Sent %d collateralnode entries to %s\n", count, pfrom->addr.ToString().c_str());
    }

    else if (strCommand == "mnget") { //Collateralnode Payments Request Sync
        bool fIsInitialDownload = IsInitialBlockDownload();
        if(fIsInitialDownload) return;

        if(pfrom->HasFulfilledRequest("mnget")) {
            printf("mnget - peer already asked me for the list\n");
            Misbehaving(pfrom->GetId(), 20);
            return;
        }

        pfrom->FulfilledRequest("mnget");
        collateralnodePayments.Sync(pfrom);
        printf("mnget - Sent collateralnode winners to %s\n", pfrom->addr.ToString().c_str());
    }
    else if (strCommand == "mnw") { //Collateralnode Payments Declare Winner
        bool fIsInitialDownload = IsInitialBlockDownload();
        if(fIsInitialDownload) return;

        CCollateralnodePaymentWinner winner;
        int a = 0;
        vRecv >> winner >> a;

        if(pindexBest == NULL) return;

        uint256 hash = winner.GetHash();
        if(mapSeenCollateralnodeVotes.count(hash)) {
            if(fDebug) printf("mnw - seen vote %s Height %d bestHeight %d\n", hash.ToString().c_str(), winner.nBlockHeight, pindexBest->nHeight);
            return;
        }

        if(winner.nBlockHeight < pindexBest->nHeight - 10 || winner.nBlockHeight > pindexBest->nHeight+20){
            printf("mnw - winner out of range %s Height %d bestHeight %d\n", winner.vin.ToString().c_str(), winner.nBlockHeight, pindexBest->nHeight);
            return;
        }

        if(winner.vin.nSequence != std::numeric_limits<unsigned int>::max()){
            printf("mnw - invalid nSequence\n");
            Misbehaving(pfrom->GetId(), 100);
            return;
        }

        printf("mnw - winning vote  %s Height %d bestHeight %d\n", winner.vin.ToString().c_str(), winner.nBlockHeight, pindexBest->nHeight);

        if(!collateralnodePayments.CheckSignature(winner)){
            printf("mnw - invalid signature\n");
            Misbehaving(pfrom->GetId(), 100);
            return;
        }

        mapSeenCollateralnodeVotes.insert(make_pair(hash, winner));

        if(collateralnodePayments.AddWinningCollateralnode(winner)){
            collateralnodePayments.Relay(winner);
        }
    }
}

struct CompareValueOnly
{
    bool operator()(const pair<int64_t, CTxIn>& t1,
                    const pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};

struct CompareLastPaidBlock
{
    bool operator()(const pair<int, CCollateralNode*>& t1,
                    const pair<int, CCollateralNode*>& t2) const
    {
        return (t1.first != t2.first ? t1.first > t2.first : t1.second->CalculateScore(1, pindexBest->nHeight) > t1.second->CalculateScore(1, pindexBest->nHeight));
    }
};

struct CompareLastPayRate
{
    bool operator()(const pair<int, CCollateralNode*>& t1,
                    const pair<int, CCollateralNode*>& t2) const
    {
        return (t1.second->payRate == t2.second->payRate ? t1.first > t2.first : t1.second->payRate > t2.second->payRate);
    }
};

struct CompareLastPay
{
    CompareLastPay(CBlockIndex* pindex) { this->pindex = pindex; }
    bool operator()(const pair<int, CCollateralNode*>& t1,
                    const pair<int, CCollateralNode*>& t2) const
    {
        if (t1.second->IsActive() == t2.second->IsActive()) {
            return (t1.second->payValue == t2.second->payValue ? t1.second->pubkey.GetHash() > t2.second->pubkey.GetHash() : t1.second->payValue > t2.second->payValue);
        } else {
            return (t1.second->IsActive() < t2.second->IsActive()); //always put actives before non-actives
        }
        return false;
    }
    CBlockIndex* pindex;
};

struct CompareSigTimeTo
{
    CompareSigTimeTo(CBlockIndex* pindex) { this->pindex = pindex; }
    bool operator()(const pair<int, CCollateralNode*>& t1,
                    const pair<int, CCollateralNode*>& t2) const
    {
        return (t2.second->nTimeRegistered > pindex->GetBlockTime() && t1.second->nTimeRegistered == t2.second->nTimeRegistered ? t1.second->CalculateScore(1, pindex->nHeight) > t2.second->CalculateScore(1, pindex->nHeight) : t2.second->nTimeRegistered > pindex->GetBlockTime());
    }
    CBlockIndex* pindex;
};

struct CompareLastPayValue
{
    bool operator()(const pair<int, CCollateralNode*>& t1,
                    const pair<int, CCollateralNode*>& t2) const
    {
        return (t1.second->payValue == t2.second->payValue ? t1.first > t2.first : t1.second->payValue > t2.second->payValue);
    }
};

struct CompareValueOnly2
{
    bool operator()(const pair<int64_t, int>& t1,
                    const pair<int64_t, int>& t2) const
    {
        return t1.first < t2.first;
    }
};

int CountCollateralnodesAboveProtocol(int protocolVersion)
{
    int i = 0;
    LOCK(cs_collateralnodes);
    for (CCollateralNode& mn : vecCollateralnodes) {
        if(mn.protocolVersion < protocolVersion) continue;
        i++;
    }

    return i;
}


int GetCollateralnodeByVin(CTxIn& vin)
{
    int i = 0;
    LOCK(cs_collateralnodes);
    for (CCollateralNode& mn : vecCollateralnodes) {
        if (mn.vin == vin) return i;
        i++;
    }

    return -1;
}

int GetCurrentCollateralNode(int mod, int64_t nBlockHeight, int minProtocol)
{
    if (IsInitialBlockDownload()) return 0;
    int i = 0;
    unsigned int score = 0;
    int winner = -1;
    LOCK(cs_collateralnodes);
    // scan for winner
    for (CCollateralNode mn : vecCollateralnodes) {
        mn.Check();
        if(mn.protocolVersion < minProtocol) continue;
        if(!mn.IsEnabled()) {
            i++;
            continue;
        }

        // calculate the score for each collateralnode
        uint256 n = mn.CalculateScore(mod, nBlockHeight);
        unsigned int n2 = 0;
        memcpy(&n2, &n, sizeof(n2));

        // determine the winner
        if(n2 > score){
            score = n2;
            winner = i;
        }
        i++;
    }

    return winner;
}

bool GetCollateralnodeRanks(CBlockIndex* pindex)
{
    LOCK(cs_collateralnodes);
    int64_t nStartTime = GetTimeMillis();
    if (fDebug) printf("GetCollateralnodeRanks: ");
    if (!pindex || pindex == NULL || pindex->pprev == NULL || IsInitialBlockDownload() || vecCollateralnodes.size() == 0) return true;

    int i = 0;
    vecCollateralnodeScores.clear();
    if (vecCollateralnodeScoresListHash.size() > 0 && vecCollateralnodeScoresListHash == pindex->GetBlockHash()) {
        // if ScoresList was calculated for the current pindex hash, then just use that list
        // TODO: make a vector of these somehow
        if (fDebug) printf(" STARTCOPY (%" PRId64"ms)", GetTimeMillis() - nStartTime);
        for (CCollateralNode& mn : vecCollateralnodeScoresList)
        {
            i++;
            vecCollateralnodeScores.push_back(make_pair(i, &mn));
        }
    } else {
        vecCollateralnodeScoresList.clear();
        // now we've put the data in, let's recalculate the ranks.
        if (GetBoolArg("-newranksystem",false)) ranks.initialize(pindex);
        ranks.update(pindex,CollateralNReorgBlock); // this should be set true the first time this is run
        CollateralNReorgBlock = false; // reset reorg flag, we can check now it's updated

        // now we build the list for sorting
        if (fDebug) printf(" STARTLOOP (%" PRId64"ms)", GetTimeMillis() - nStartTime);
        for (CCollateralNode& mn : vecCollateralnodes) {

            mn.Check();
            if(mn.protocolVersion < MIN_MN_PROTO_VERSION) continue;

            // check the block time against the entry and don't use it if it's newer than the current block time + 600 secs
            // stops new stakes from being calculated in rank lists until the time of their first seen broadcast
            // if (mn.now > pindex->GetBlockTime()) continue;

            int value = -1;
            // CBlockIndex* pindex = pindexBest; // don't use the best chain, use the chain we're asking about!
            // int payments = mn.UpdateLastPaidAmounts(pindex, max(COLLATERALNODE_FAIR_PAYMENT_MINIMUM, (int)mnCount) * COLLATERALNODE_FAIR_PAYMENT_ROUNDS, value); // do a search back 1000 blocks when receiving a new collateralnode to find their last payment, payments = number of payments received, value = amount


            vecCollateralnodeScores.push_back(make_pair(value, &mn));
            vecCollateralnodeScoresList.push_back(mn);

        }

        vecCollateralnodeScoresListHash = pindex->GetBlockHash();
    }

    // TODO: Store the whole Scores vector in a caching hash map, maybe need hashPrev as well to make sure it re calculates any different chains with the same end block?
    //vecCollateralnodeScoresCache.insert(make_pair(pindex->GetBlockHash(), vecCollateralnodeScoresList));

    if (fDebug) printf(" SORT (%" PRId64"ms)", GetTimeMillis() - nStartTime);
    sort(vecCollateralnodeScores.rbegin(), vecCollateralnodeScores.rend(), CompareLastPay(pindex)); // sort requires current pindex for modulus as pindexBest is different between clients

    i = 0;
    // set ranks
    BOOST_FOREACH(PAIRTYPE(int, CCollateralNode*)& s, vecCollateralnodeScores)
    {
        i++;
        s.first = i;
        s.second->nRank = i;
    }
    if (fDebug) printf(" DONE (%" PRId64"ms)\n", GetTimeMillis() - nStartTime);
    return true;
}

int GetCollateralnodeRank(CCollateralNode &tmn, CBlockIndex* pindex, int minProtocol)
{
    if (IsInitialBlockDownload()) return 0;
    LOCK(cs_collateralnodes);
    GetCollateralnodeRanks(pindex);
    unsigned int i = 0;

    BOOST_FOREACH(PAIRTYPE(int, CCollateralNode*)& s, vecCollateralnodeScores)
    {
        i++;
        if (s.second->vin == tmn.vin)
            return i;
    }
    return 0;
}

bool CheckCNPayment(CBlockIndex* pindex, int64_t value, CCollateralNode &mn) {
    if (mn.nBlockLastPaid == 0) return true; // if we didn't find a payment for this MN, let it through regardless of rate

    //if (mn.nBlockLastPaid - vCollateralnodes.count()) return false;

    // find height
    // calculate average payment across all CN
    // check if value is > 25% higher
    nAverageCNIncome = avg2(vecCollateralnodeScoresList);
    if (nAverageCNIncome < 1 * COIN) return true; // if we can't calculate a decent average, then let the payment through
    int64_t max = nAverageCNIncome * 10 / 8;
    if (value > max) {
        return false;
    }

    CScript pubScript;
    pubScript = GetScriptForDestination(mn.pubkey.GetID());
    CTxDestination address1;
    ExtractDestination(pubScript, address1);
    CBitcoinAddress address2(address1);

    // calculate pay count average across CN
    // check if pay count is > 50% higher than the avg
    nAveragePayCount = avgCount(vecCollateralnodeScoresList);
    if (nAveragePayCount < 1) return true; // if the pay count is less than 1 just let it through
    int64_t maxed = nAveragePayCount * 12 / 8;
    if (mn.payCount > maxed) {
        printf("CheckCNPayment() Current payCount of %s CN is %d - payCount Overall Average %d\n", address2.ToString().c_str(), mn.payCount, nAveragePayCount);
        return false;
    }

    return true;
}

bool CheckPoSCNPayment(CBlockIndex* pindex, int64_t value, CCollateralNode &mn) {
    if (mn.nBlockLastPaid == 0) return true; // if we didn't find a payment for this MN, let it through regardless of rate

    // find height
    // calculate average payment across all CN
    // check if value is > 25% higher
    nAverageCNIncome = avg2(vecCollateralnodeScoresList);
    if (nAverageCNIncome < 1 * COIN) return true; // if we can't calculate a decent average, then let the payment through
    //int64_t max = nAverageCNIncome * 10 / 8;
    /* // Dont check if value is > 25% higher since PoS
    if (value > max) {
        return false;
    }
    */
    CScript pubScript;
    pubScript = GetScriptForDestination(mn.pubkey.GetID());
    CTxDestination address1;
    ExtractDestination(pubScript, address1);
    CBitcoinAddress address2(address1);

    // calculate pay count average across CN
    // check if pay count is > 50% higher than the avg
    nAveragePayCount = avgCount(vecCollateralnodeScoresList);
    if (nAveragePayCount < 1) return true; // if the pay count is less than 1 just let it through
    int64_t maxed = nAveragePayCount * 12 / 8;
    if (mn.payCount > maxed) {
        printf("CheckPoSCNPayment() Current payCount of %s is %d - payCount Overall Average %d\n", address2.ToString().c_str(), mn.payCount, nAveragePayCount);
        return false;
    }

    return true;
}

int64_t avg2(std::vector<CCollateralNode> const& v) {
    int n = 0;
    int64_t mean = 0;
    for (int i = 0; i < v.size(); i++) {
        int64_t x = v[i].payValue;
        int64_t delta = x - mean;
        //TODO: implement in mandatory update, will reduce average & lead to rejections
        //if (v[i].payValue > 2*COIN) { continue; } // don't consider payees above 2.00000000D (pos only / lucky payees)
        if (v[i].payValue < 1*COIN) { continue; } // don't consider payees below 1.00000000D (pos only / new payees)
        mean += delta/++n;
    }
    return mean;
}

int64_t avgCount(std::vector<CCollateralNode> const& v) {
    int n = 0;
    int64_t mean = 0;
    for (int i = 0; i < v.size(); i++) {
        int64_t x = v[i].payCount;
        int64_t delta = x - mean;
        //TODO: implement in mandatory update, will reduce average & lead to rejections
        if (v[i].payCount < 1) { continue; } // don't consider payees below 1 payment (pos only / new payees)
        mean += delta/++n;
    }
    return mean;
}

int GetCollateralnodeByRank(int findRank, int64_t nBlockHeight, int minProtocol)
{
    if (IsInitialBlockDownload()) return 0;
    LOCK(cs_collateralnodes);
    GetCollateralnodeRanks(pindexBest);
    unsigned int i = 0;

    BOOST_FOREACH(PAIRTYPE(int, CCollateralNode*)& s, vecCollateralnodeScores)
    {
        i++;
        if (i == findRank)
            return s.first;
    }
    return 0;
}

//Get the last hash that matches the modulus given. Processed in reverse order
bool GetBlockHash(uint256& hash, int nBlockHeight)
{
    if (pindexBest == NULL) return false;

    if(nBlockHeight == 0)
        nBlockHeight = pindexBest->nHeight;

    if(mapCacheBlockHashes.count(nBlockHeight)){
        hash = mapCacheBlockHashes[nBlockHeight];
        return true;
    }

    const CBlockIndex *BlockLastSolved = pindexBest;
    const CBlockIndex *BlockReading = pindexBest;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || pindexBest->nHeight+1 < nBlockHeight) return false;

    int nBlocksAgo = 0;
    if(nBlockHeight > 0) nBlocksAgo = (pindexBest->nHeight+1)-nBlockHeight;
    assert(nBlocksAgo >= 0);

    int n = 0;
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if(n >= nBlocksAgo){
            hash = BlockReading->GetBlockHash();
            mapCacheBlockHashes[nBlockHeight] = hash;
            return true;
        }
        n++;

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    return false;
}

bool CCollateralNode::GetPaymentInfo(const CBlockIndex *pindex, int64_t &totalValue, double &actualRate)
{
    int scanBack = max(COLLATERALNODE_FAIR_PAYMENT_MINIMUM, (int)mnCount) * COLLATERALNODE_FAIR_PAYMENT_ROUNDS;
    double requiredRate = scanBack / (int)mnCount;
    int actualPayments = GetPaymentAmount(pindex, scanBack, totalValue);
    actualRate = actualPayments / requiredRate;
    // TODO: stop payment if collateralnode vin age is under mnCount*30 old
    if (actualRate > 0) return true;
    return false;
}

float CCollateralNode::GetPaymentRate(const CBlockIndex *pindex)
{
    int scanBack = max(COLLATERALNODE_FAIR_PAYMENT_MINIMUM, (int)mnCount) * COLLATERALNODE_FAIR_PAYMENT_ROUNDS;
    double requiredRate = scanBack / (int)mnCount;
    int64_t totalValue;
    int actualPayments = GetPaymentAmount(pindex, scanBack, totalValue);
    float actualRate = actualPayments/requiredRate;
    return actualRate;
}

int CCollateralNode::SetPayRate(int nHeight)
{
     int scanBack = max(COLLATERALNODE_FAIR_PAYMENT_MINIMUM, (int)mnCount) * COLLATERALNODE_FAIR_PAYMENT_ROUNDS;
     if (nHeight > pindexBest->nHeight) {
         scanBack += nHeight - pindexBest->nHeight;
     } // if going past current height, add to scan back height to account for how far it is - e.g. 200 in front will get 200 more blocks to smooth it out

     // reset to default
     payCount = 0;
     payValue = 0;
     payRate = 0;

     if (payData.size()>0) {
         // printf("Using collateralnode cached payments data for pay rate");
         // printf(" (payInfo:%d@%f)...", payCount, payRate);
         int64_t amount = 0;
         int matches = 0;
         for (CCollateralNPayData &item : payData)
         {
             if (item.height > nHeight - scanBack && mapBlockIndex.count(item.hash)) { // find payments in last scanrange
                amount += item.amount;
                matches++;
             }
         }
         if (matches > 0) {
             payCount = matches;
             payValue = amount;
             // set the node's current 'reward rate' - pay value divided by rounds (3)
             // this rate is representative of "INN per day"
             payRate = ((payValue / scanBack) / 30) * 86400;
             // printf("%d found with %s value %.2f rate\n", matches, FormatMoney(amount).c_str(), payRate);
             return matches;
         }
     }
}

int CCollateralNode::GetPaymentAmount(const CBlockIndex *pindex, int nMaxBlocksToScanBack, int64_t &totalValue)
{
    if(!pindex) return 0;
    CScript mnpayee = GetScriptForDestination(pubkey.GetID());
    CTxDestination address1;
    ExtractDestination(mnpayee, address1);
    CBitcoinAddress address2(address1);
    totalValue = 0;
    if (payData.size()>0) {
        //printf("Using collateralnode cached payments data");
        //printf("(payInfo:%d@%f)...", payCount, payRate);
        int64_t amount = 0;
        int matches = 0;
        for (CCollateralNPayData &item : payData)
        {
            if (item.height > pindex->nHeight - nMaxBlocksToScanBack && mapBlockIndex.count(item.hash)) { // find payments in last scanrange
               amount += item.amount;
               matches++;
            }
        }
        //printf("done checking for matches: %d found with %s value\n", matches, FormatMoney(amount).c_str());
        if (matches > 0) {
            totalValue = amount;
            return totalValue / COIN;
        }
    }
    const CBlockIndex *BlockReading = pindex;

    int blocksFound = 0;
    totalValue = 0;
    for (int i = 0; BlockReading && BlockReading->nHeight > nBlockLastPaid && i < nMaxBlocksToScanBack; i++) {
            CBlock block;
            if(!block.ReadFromDisk(BlockReading, true)) // shouldn't really happen
                continue;

            if (block.IsProofOfWork())
            {
                for (CTxOut txout : block.vtx[0].vout)
                    if(mnpayee == txout.scriptPubKey) {
                        blocksFound++;
                        totalValue += txout.nValue / COIN;
                    }
            } else if (block.IsProofOfStake())
            {
                for (CTxOut txout : block.vtx[1].vout)
                    if(mnpayee == txout.scriptPubKey) {
                        blocksFound++;
                        totalValue += txout.nValue / COIN;
                    }
            }

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }

        BlockReading = BlockReading->pprev;
    }
    return totalValue;

}

int CCollateralNode::UpdateLastPaidAmounts(const CBlockIndex *pindex, int nMaxBlocksToScanBack, int &value)
{
    if (!pindex || IsInitialBlockDownload()) return 0;
    const CBlockIndex *BlockReading = pindex;
    int rewardCount = 0;
    int64_t rewardValue = 0;
    int64_t val = 0;
    value = 0;
    int scanBack = max(COLLATERALNODE_FAIR_PAYMENT_MINIMUM, (int)mnCount) * COLLATERALNODE_FAIR_PAYMENT_ROUNDS;

    //if (now > pindex->GetBlockTime()) return 0; // don't update paid amounts for nodes before the block they broadcasted on
    if (payData.size()) {
        // when operating on cache, prune old entries to keep this at exactly the last 600 blocks. (note: don't do this)
        // if a node doesn't get any reorgs, it won't clear old payments here and the average amount will increase
        // then they will approve high rates, leading to other nodes who DID reorg seeing the average lower and rejecting it.
        /*
                std::vector<pair<int, int64_t> >::iterator it = payData.begin();
                while(it != payData.end()){
                    if ((*it).first > pindex->nHeight - scanBack) { // find payments in last scanrange
                       rewardValue += (*it).second;
                       rewardCount++;
                       ++it;
                    } else {
                        // remove it from payData
                        if (fDebug) { printf("Removing old payData for CN %s at height %d\n",addr.ToString().c_str(),(*it).first); }
                        it = payData.erase(it);
                    }
                }
        */
        // all of that doesn't matter if we pay attention to the hash of the payment!
        for (CCollateralNPayData &item : payData)
        {
            if (mapBlockIndex.count(item.hash)) {
                if (item.height > pindex->nHeight - nMaxBlocksToScanBack) { // find payments in last scanrange
                rewardValue += item.amount;
                rewardCount++;
                }
            }
        }

        // return the count and value
        value = rewardValue / COIN;
        payCount = rewardCount;
        payValue = rewardValue;

        // set the node's current 'reward rate' - pay per day
        payRate = ((payValue / scanBack) / 30) * 86400;
        return payValue;
    }

    CScript mnpayee = GetScriptForDestination(pubkey.GetID());
    CTxDestination address1;
    ExtractDestination(mnpayee, address1);
    CBitcoinAddress address2(address1);


    // reset counts
    payCount = 0;
    payValue = 0;

    LOCK(cs_collateralnodes);
    for (int i = 0; i < scanBack; i++) {
            val = 0;
            CBlock block;
            if(!block.ReadFromDisk(BlockReading, true)) // shouldn't really happen
                continue;

            // if it's a legit block, then count it against this node and record it in a vector
            if (block.IsProofOfWork() || block.IsProofOfStake())
            {
                for (CTxOut txout : block.vtx[block.IsProofOfWork() ? 0 : 1].vout)
                {

                    if(mnpayee == txout.scriptPubKey) {
                        int height = BlockReading->nHeight;
                        int64_t amount = txout.nValue;
                        uint256 hash = BlockReading->GetBlockHash();
                        CCollateralNPayData data;

                        data.height = height;
                        data.amount = amount;
                        data.hash = hash;

                        // first match is the last! ;)
                        if (nBlockLastPaid == 0) {
                            nBlockLastPaid = height;
                        }

                        // add this profit & the reward itself so we can update the node
                        rewardValue += amount;
                        rewardCount++;

                        // make a note in the node for later lookup
                        payData.push_back(data);
                    }
                }
            }

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }

        BlockReading = BlockReading->pprev;
    }

    if (rewardCount > 0)
    {
        // return the count and value
        value = rewardValue / COIN;
        payCount = rewardCount;
        payValue = rewardValue;

        // set the node's current 'reward rate' - pay per day
        payRate = ((payValue / scanBack) / 30) * 86400;

        if (fDebugCN) printf("CCollateralNode::UpdateLastPaidAmounts -- MN %s in last %d blocks was paid %d times for %s D, rateperday:%s count:%d val:%s\n", address2.ToString().c_str(), scanBack, rewardCount, FormatMoney(rewardValue).c_str(), FormatMoney(payRate).c_str(), payCount, FormatMoney(payValue).c_str());

        return rewardCount;
    } else {
        payCount = rewardCount;
        payValue = rewardValue;
        payRate = 0;
        value = 0;
        return 0;
    }

}

void CCollateralNode::UpdateLastPaidBlock(const CBlockIndex *pindex, int nMaxBlocksToScanBack)
{
    if(!pindex) return;

    const CBlockIndex *BlockReading = pindex;

    CScript mnpayee = GetScriptForDestination(pubkey.GetID());
    CTxDestination address1;
    ExtractDestination(mnpayee, address1);
    CBitcoinAddress address2(address1);
    uint64_t nCoinAge;

    for (int i = 0; BlockReading && BlockReading->nHeight > nBlockLastPaid && i < nMaxBlocksToScanBack; i++) {
            CBlock block;
            if(!block.ReadFromDisk(BlockReading, true)) // shouldn't really happen
                continue;

    /*  no amount checking for now
     * TODO: Scan block for payments to calculate reward
            // Calculate Coin Age for Collateralnode Reward Calculation
            if (!block.vtx[1].GetCoinAge(txdb, nCoinAge))
                return error("CheckBlock-POS : %s unable to get coin age for coinstake, Can't Calculate Collateralnode Reward\n", block.vtx[1].GetHash().ToString().substr(0,10).c_str());
            int64_t nCalculatedStakeReward = GetProofOfStakeReward(nCoinAge, nFees);
            int64_t nCollateralnodePayment = GetCollateralnodePayment(BlockReading->nHeight, block.IsProofOfStake() ? nCalculatedStakeReward : block.vtx[0].GetValueOut());
    */
            if (block.IsProofOfWork())
            {
                // TODO HERE: Scan the block for collateralnode payment amount
                for (CTxOut txout : block.vtx[0].vout)
                    if(mnpayee == txout.scriptPubKey) {
                        nBlockLastPaid = BlockReading->nHeight;
                        int lastPay = pindexBest->nHeight - nBlockLastPaid;
                        int value = txout.nValue;
                        // TODO HERE: Check the nValue for the collateralnode payment amount
                        if (fDebug) printf("CCollateralNode::UpdateLastPaidBlock -- searching for block with payment to %s -- found pow %d (%d blocks ago)\n", address2.ToString().c_str(), nBlockLastPaid, lastPay);
                        return;
                    }
            } else if (block.IsProofOfStake())
            {
                // TODO HERE: Scan the block for collateralnode payment amount
                for (CTxOut txout : block.vtx[1].vout)
                    if(mnpayee == txout.scriptPubKey) {
                        nBlockLastPaid = BlockReading->nHeight;
                        int lastPay = pindexBest->nHeight - nBlockLastPaid;
                        int value = txout.nValue;
                        // TODO HERE: Check the nValue for the collateralnode payment amount
                        if (fDebug) printf("CCollateralNode::UpdateLastPaidBlock -- searching for block with payment to %s -- found pos %d (%d blocks ago)\n", address2.ToString().c_str(), nBlockLastPaid, lastPay);
                        return;
                    }
            }

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }

        BlockReading = BlockReading->pprev;
    }
    if (!nBlockLastPaid)
    {
        if (fDebug) printf("CCollateralnode::UpdateLastPaidBlock -- searching for block with payment to %s e.g. %s -- NOT FOUND\n", vin.prevout.ToString().c_str(),address2.ToString().c_str());
        nBlockLastPaid = 1;
    }
}

//
// Deterministically calculate a given "score" for a collateralnode with tribus depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
uint256 CCollateralNode::CalculateScore(int mod, int64_t nBlockHeight)
{
    if(pindexBest == NULL) return 0;

    uint256 hash = 0;
    uint256 aux = vin.prevout.hash + vin.prevout.n;

    if(!GetBlockHash(hash, nBlockHeight)) return 0;

    uint256 hash2 = Tribus(BEGIN(hash), END(hash)); //Tribus Algo Integrated, WIP
    uint256 hash3 = Tribus(BEGIN(hash), END(aux));

    uint256 r = (hash3 > hash2 ? hash3 - hash2 : hash2 - hash3);

    return r;
}

void CCollateralNode::Check(bool forceCheck)
{
    if(!forceCheck && (GetTime() - lastTimeChecked < COLLATERALNODE_CHECK_SECONDS)) return;
    lastTimeChecked = GetTime();


    //once spent, stop doing the checks
    if(enabled==3) return;


    if(!UpdatedWithin(COLLATERALNODE_REMOVAL_SECONDS)){
        status = "Expired";
        enabled = 4;
        return;
    }

    if(!UpdatedWithin(COLLATERALNODE_EXPIRATION_SECONDS)){
        status = "Inactive, expiring soon";
        enabled = 2;
        return;
    }

    if(!unitTest){
        std::string vinError;
        if(!CheckCollateralnodeVin(vin,vinError,pindexBest)) {
                enabled = 3; //MN input was spent, disable checks for this MN
                if (fDebug) printf("error checking collateralnode %s: %s\n", vin.prevout.ToString().c_str(), vinError.c_str());
                status = "vin was spent";
                return;
            }
        }
    status = "OK";
    enabled = 1; // OK
}

bool CheckCollateralnodeVin(CTxIn& vin, std::string& errorMessage, CBlockIndex* pindex) {
    CTxDB txdb("r");
    CTxIndex txindex;
    CTransaction ctx;
    uint256 hashBlock;

    if (!GetTransaction(vin.prevout.hash,ctx,hashBlock))
    {
        errorMessage = "could not find transaction";
        return false;
    } else {
        if(mapBlockIndex.find(hashBlock) != mapBlockIndex.end())
        {
            int confirms = pindex->nHeight - mapBlockIndex[hashBlock]->nHeight;
            if (confirms < COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY) {
                errorMessage = strprintf("specified vin has only %d/%d more confirms",confirms,COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY);
                return false;
            }
        }
    }

    CTxOut vout = ctx.vout[vin.prevout.n];
    if (vout.nValue != GetMNCollateral()*COIN)
    {
        errorMessage = "specified vin was not a collateralnode capable transaction";
        return false;
    }

    if (txdb.ReadTxIndex(vin.prevout.hash, txindex))
    {
        if (txindex.vSpent[vin.prevout.n].nTxPos != 0) {
            errorMessage = "vin was spent";
            return false;
        }
        return true;
    } else {
        errorMessage = "specified vin transaction was not found in the txindex\n";
    }
    return false;
}

bool CCollateralnodePayments::CheckSignature(CCollateralnodePaymentWinner& winner)
{
    //note: need to investigate why this is failing
    std::string strMessage = winner.vin.ToString().c_str() + boost::lexical_cast<std::string>(winner.nBlockHeight) + winner.payee.ToString();
    std::string strPubKey = fTestNet? strTestPubKey : strMainPubKey;
    CPubKey pubkey(ParseHex(strPubKey));

    std::string errorMessage = "";
    if(!colLateralSigner.VerifyMessage(pubkey, winner.vchSig, strMessage, errorMessage)){
        return false;
    }

    return true;
}

bool CCollateralnodePayments::Sign(CCollateralnodePaymentWinner& winner)
{
    std::string strMessage = winner.vin.ToString().c_str() + boost::lexical_cast<std::string>(winner.nBlockHeight) + winner.payee.ToString();

    CKey key2;
    CPubKey pubkey2;
    std::string errorMessage = "";

    if(!colLateralSigner.SetKey(strMasterPrivKey, errorMessage, key2, pubkey2))
    {
        printf("CCollateralnodePayments::Sign - ERROR: Invalid collateralnodeprivkey: '%s'\n", errorMessage.c_str());
        return false;
    }

    if(!colLateralSigner.SignMessage(strMessage, errorMessage, winner.vchSig, key2)) {
        printf("CCollateralnodePayments::Sign - Sign message failed");
        return false;
    }

    if(!colLateralSigner.VerifyMessage(pubkey2, winner.vchSig, strMessage, errorMessage)) {
        printf("CCollateralnodePayments::Sign - Verify message failed");
        return false;
    }

    return true;
}

uint64_t CCollateralnodePayments::CalculateScore(uint256 blockHash, CTxIn& vin)
{
    uint256 n1 = blockHash;
    uint256 n2 = Tribus(BEGIN(n1), END(n1));
    uint256 n3 = Tribus(BEGIN(vin.prevout.hash), END(vin.prevout.hash));
    uint256 n4 = n3 > n2 ? (n3 - n2) : (n2 - n3);

    //printf(" -- CCollateralnodePayments CalculateScore() n2 = %d \n", n2.Get64());
    //printf(" -- CCollateralnodePayments CalculateScore() n3 = %d \n", n3.Get64());
    //printf(" -- CCollateralnodePayments CalculateScore() n4 = %d \n", n4.Get64());

    return n4.Get64();
}

bool CCollateralnodePayments::GetBlockPayee(int nBlockHeight, CScript& payee)
{
    for (CCollateralnodePaymentWinner& winner : vWinning){
        if(winner.nBlockHeight == nBlockHeight) {
            CTransaction tx;
            uint256 hash;
            if(GetTransaction(winner.vin.prevout.hash, tx, hash)){
                for (CTxOut out : tx.vout){
                    if(out.nValue == GetMNCollateral()*COIN){
                        payee = out.scriptPubKey;
                        return true;
                    }
                }
            }
            return false;
        }
    }
    return false;
}

bool CCollateralnodePayments::GetWinningCollateralnode(int nBlockHeight, CTxIn& vinOut)
{
    for (CCollateralnodePaymentWinner& winner : vWinning){
        if(winner.nBlockHeight == nBlockHeight) {
            vinOut = winner.vin;
            return true;
        }
    }

    return false;
}

bool CCollateralnodePayments::AddWinningCollateralnode(CCollateralnodePaymentWinner& winnerIn)
{
    uint256 blockHash = 0;
    if(!GetBlockHash(blockHash, winnerIn.nBlockHeight-576)) {
        return false;
    }

    winnerIn.score = CalculateScore(blockHash, winnerIn.vin);

    bool foundBlock = false;
    for (CCollateralnodePaymentWinner& winner : vWinning){
        if(winner.nBlockHeight == winnerIn.nBlockHeight) {
            foundBlock = true;
            if(winner.score < winnerIn.score){
                winner.score = winnerIn.score;
                winner.vin = winnerIn.vin;
                winner.payee = winnerIn.payee;
                winner.vchSig = winnerIn.vchSig;

                return true;
            }
        }
    }

    // if it's not in the vector
    if(!foundBlock){
        vWinning.push_back(winnerIn);
        mapSeenCollateralnodeVotes.insert(make_pair(winnerIn.GetHash(), winnerIn));

        return true;
    }

    return false;
}

void CCollateralnodePayments::CleanPaymentList()
{
    LOCK(cs_collateralnodes);
    if(pindexBest == NULL) return;

    int nLimit = std::max(((int)vecCollateralnodes.size())*2, 5000);

    vector<CCollateralnodePaymentWinner>::iterator it;
    for(it=vWinning.begin();it<vWinning.end();it++){
        if(pindexBest->nHeight - (*it).nBlockHeight > nLimit){
            if(fDebug) printf("CCollateralnodePayments::CleanPaymentList - Removing old collateralnode payment - block %d\n", (*it).nBlockHeight);
            vWinning.erase(it);
            break;
        }
    }
}

int CCollateralnodePayments::LastPayment(CCollateralNode& mn)
{
    if(pindexBest == NULL) return 0;

    int ret = mn.GetCollateralnodeInputAge();

    for (CCollateralnodePaymentWinner& winner : vWinning){
        if(winner.vin == mn.vin && pindexBest->nHeight - winner.nBlockHeight < ret)
            ret = pindexBest->nHeight - winner.nBlockHeight;
    }

    return ret;
}

bool CCollateralnodePayments::ProcessBlock(int nBlockHeight)
{
    LOCK(cs_collateralnodes);
    if(!enabled) return false; // don't process blocks for collateralnode winners if we aren't signing a winner list
    CCollateralnodePaymentWinner winner;

    std::vector<CTxIn> vecLastPayments;
    int c = 0;
    BOOST_REVERSE_FOREACH(CCollateralnodePaymentWinner& winner, vWinning){
        vecLastPayments.push_back(winner.vin);
        //if we have one full payment cycle, break
        if(++c > (int)vecCollateralnodes.size()) break;
    }

    std::random_shuffle ( vecCollateralnodes.begin(), vecCollateralnodes.end() );
    for (CCollateralNode& mn : vecCollateralnodes) {
        bool found = false;
        for (CTxIn& vin : vecLastPayments)
            if(mn.vin == vin) found = true;

        if(found) continue;

        mn.Check();
        if(!mn.IsEnabled()) {
            continue;
        }

        winner.score = 0;
        winner.nBlockHeight = nBlockHeight;
        winner.vin = mn.vin;
        winner.payee =GetScriptForDestination(mn.pubkey.GetID());

        break;
    }

    //if we can't find someone to get paid, pick randomly
    if(winner.nBlockHeight == 0 && vecCollateralnodes.size() > 0) {
        winner.score = 0;
        winner.nBlockHeight = nBlockHeight;
        winner.vin = vecCollateralnodes[0].vin;
        winner.payee =GetScriptForDestination(vecCollateralnodes[0].pubkey.GetID());
    }


    if(CCollateralnodePayments::enabled && Sign(winner)){
        if(AddWinningCollateralnode(winner)){
            Relay(winner);
            return true;
        }
    }

    return false;
}

void CCollateralnodePayments::Relay(CCollateralnodePaymentWinner& winner)
{
    CInv inv(MSG_COLLATERALNODE_WINNER, winner.GetHash());

    vector<CInv> vInv;
    vInv.push_back(inv);
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes){
        pnode->PushMessage("inv", vInv);
    }
}

void CCollateralnodePayments::Sync(CNode* node)
{
    int a = 0;
    for (CCollateralnodePaymentWinner& winner : vWinning)
        if(winner.nBlockHeight >= pindexBest->nHeight-10 && winner.nBlockHeight <= pindexBest->nHeight + 20)
            node->PushMessage("mnw", winner, a);
}


bool CCollateralnodePayments::SetPrivKey(std::string strPrivKey)
{
    CCollateralnodePaymentWinner winner;

    // Test signing successful, proceed
    strMasterPrivKey = strPrivKey;

    Sign(winner);

    if(CheckSignature(winner)){
        printf("CCollateralnodePayments::SetPrivKey - Successfully initialized as collateralnode payments master\n");
        enabled = true;
        return true;
    } else {
        return false;
    }
}

struct MatchPubkey
{
 MatchPubkey(const CScript& s) : s_(s) {}
 bool operator()(const CCollateralNode& mn) const
 {
   return GetScriptForDestination(mn.pubkey.GetID()) == s_;
 }
 private:
   const CScript& s_;
};

void CCollateralNPayments::update(const CBlockIndex *pindex, bool force)
{
    if (!pindex || IsInitialBlockDownload()) return; //return 0 should not return value
    const CBlockIndex *BlockReading = pindex;
    int rewardCount = 0;
    int64_t rewardValue = 0;
    int64_t val = 0;
    int scanBack = max(COLLATERALNODE_FAIR_PAYMENT_MINIMUM, (int)mnCount) * COLLATERALNODE_FAIR_PAYMENT_ROUNDS;

    int64_t nStart = GetTimeMillis();

    // situations we want to force update:
    // - update is called from GetForunstakeRanks which is called with new pindex, or pindexBest
    // we only want to update this on a reorg
    if (force) {
    LOCK(cs_collateralnodes);

        // clear existing pay data
        for (CCollateralNode& mn : vecCollateralnodes)
        {
            mn.payData.clear();
        }

        // do the loop and fill all the payments in
        for (int i = 0; i < scanBack; i++) {
                val = 0;
                CBlock block;
                if(!block.ReadFromDisk(BlockReading, true)) // shouldn't really happen
                    continue;

                bool found = false;
                // if it's a legit block, then count it against this node and record it in a vector
                if (block.IsProofOfWork() || block.IsProofOfStake())
                {
                    for (CTxOut txout : block.vtx[block.IsProofOfWork() ? 0 : 1].vout)
                    {
                        for (CCollateralNode& mn : vecCollateralnodes)
                        {
                            if (GetScriptForDestination(mn.pubkey.GetID()) == txout.scriptPubKey)
                            {
                                  int height = BlockReading->nHeight;
                                  int64_t amount = txout.nValue;
                                  uint256 hash = BlockReading->GetBlockHash();
                                  CCollateralNPayData data;

                                  data.height = height;
                                  data.amount = amount;
                                  data.hash = hash;
                                  mn.payData.push_back(data);

                                  // first match is the last! ;)
                                  if (mn.nBlockLastPaid == 0) {
                                      mn.nBlockLastPaid = height;
                                  }
                                  found = true;
                                  break;
                            }
                        }
                        if (found) break;
                    }
                }
            if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
            BlockReading = BlockReading->pprev;
        }

    }
    if (fDebug) printf("Calculating payrates (%d ms)\n",GetTimeMillis() - nStart);

    // do pay rate loops, already do this in connectblock()
    for (CCollateralNode& mn : vecCollateralnodes)
    {
        CCollateralNPayData data;
        data.height = pindex->nHeight;
        data.hash = pindex->GetBlockHash();
        mn.payData.push_back(data);
        mn.SetPayRate(pindex->nHeight);
    }

    if (fDebug) printf("Finished CN payments. (%d ms)\n",GetTimeMillis() - nStart);

}

bool CCollateralNPayments::initialize(const CBlockIndex *pindex)
{
    if (vCollaterals.size() > 0) return 0; //return should return value here
    printf("Setting up CN payment validation...\n");
    CTxDB txdb("r");
    const CBlockIndex *BlockReading = pindex;
    int blocksFound = 0;
    int nHeight = 0;
    if (fTestNet) {
        for (int i = 0; BlockReading && BlockReading->nHeight > BLOCK_START_COLLATERALNODE_PAYMENTS_TESTNET; i++) {
            CBlock block;
            if(!block.ReadFromDisk(BlockReading, true)) // shouldn't really happen
                continue;

            nHeight = BlockReading->nHeight;

            if (block.IsProofOfWork() || block.IsProofOfStake())
            {
                for (const CTransaction& tx : block.vtx) {
                    int n = 0;
                    for (const CTxOut& txout : tx.vout)
                    {
                        if(txout.nValue == GetMNCollateral() * COIN) {
                            COutPoint cout = COutPoint(tx.GetHash(),n);
                            CTxIn vin = CTxIn(cout, txout.scriptPubKey);
                            CTxOut vout = CTxOut(1 * COIN, txout.scriptPubKey);
                            CScript mnpayee = GetScriptForDestination(txout.scriptPubKey.GetID());
                            CTransaction txCollateral;
                            txCollateral.vin.push_back(vin);
                            txCollateral.vout.push_back(vout);

                            CCollateralNCollateral data;
                            data.vin = vin;
                            data.blockHash = block.GetHash();
                            data.height = nHeight;
                            data.scriptPubKey = txout.scriptPubKey;

                            // if data is already in the vector for this script, let's just skip
                            if (std::find(vScripts.begin(), vScripts.end(), mnpayee) != vScripts.end()) { continue; }

                            //if (fDebug) printf("Found CN payment at height %d - TX %s\n TXOut %s\n",nHeight,tx.ToString().c_str(),txout.ToString().c_str());
                            // TODO: check spent with fetch inputs?
                            bool* pfMissingInputs;
                            //if(fDebug) printf("CCollaTeralPool::IsCollateralValid - Testing TX %s\n",txCollateral.ToString().c_str());
                            if(!AcceptableInputs(mempool, txCollateral, false, pfMissingInputs)){
                                //if(fDebug) printf("CCollaTeralPool::IsCollateralValid - didn't pass IsAcceptable\n");
                                continue;
                            } else {
                                // show addy?
                                if(fDebug) printf("CCollaTeralPool::IsCollateralValid - Valid CN Collateral found for outpoint %s\n",vin.ToString().c_str());

                                vCollaterals.push_back(data);
                                vScripts.push_back(mnpayee);

                            }
                        }
                        n++;
                    }
                }
            }

            if (BlockReading->pprev == NULL) { assert(BlockReading); break; }

            BlockReading = BlockReading->pprev;
        }
    } else { //For mainnet CN checking
        for (int i = 0; BlockReading && BlockReading->nHeight > BLOCK_START_COLLATERALNODE_PAYMENTS && BlockReading->nHeight > 2085000; i++) {
                CBlock block;
                if(!block.ReadFromDisk(BlockReading, true)) // shouldn't really happen
                    continue;

                nHeight = BlockReading->nHeight;

                if (block.IsProofOfWork() || block.IsProofOfStake())
                {
                    for (const CTransaction& tx : block.vtx) {
                        int n = 0;
                        for (const CTxOut& txout : tx.vout)
                        {
                            if(txout.nValue == GetMNCollateral() * COIN) {
                                COutPoint cout = COutPoint(tx.GetHash(),n);
                                CTxIn vin = CTxIn(cout, txout.scriptPubKey);
                                CTxOut vout = CTxOut(1 * COIN, txout.scriptPubKey);
                                CScript mnpayee = GetScriptForDestination(txout.scriptPubKey.GetID());
                                CTransaction txCollateral;
                                txCollateral.vin.push_back(vin);
                                txCollateral.vout.push_back(vout);

                                CCollateralNCollateral data;
                                data.vin = vin;
                                data.blockHash = block.GetHash();
                                data.height = nHeight;
                                data.scriptPubKey = txout.scriptPubKey;

                                // if data is already in the vector for this script, let's just skip
                                if (std::find(vScripts.begin(), vScripts.end(), mnpayee) != vScripts.end()) { continue; }

                                //if (fDebug) printf("Found CN payment at height %d - TX %s\n TXOut %s\n",nHeight,tx.ToString().c_str(),txout.ToString().c_str());
                                // TODO: check spent with fetch inputs?
                                bool* pfMissingInputs;
                                //if(fDebug) printf("CCollaTeralPool::IsCollateralValid - Testing TX %s\n",txCollateral.ToString().c_str());
                                if(!AcceptableInputs(mempool, txCollateral, false, pfMissingInputs)){
                                    //if(fDebug) printf("CCollaTeralPool::IsCollateralValid - didn't pass IsAcceptable\n");
                                    continue;
                                } else {
                                    // show addy?
                                    if(fDebug) printf("CCollaTeralPool::IsCollateralValid - Valid CN Collateral found for outpoint %s\n",vin.ToString().c_str());

                                    vCollaterals.push_back(data);
                                    vScripts.push_back(mnpayee);

                                }
                            }
                            n++;
                        }
                    }
                }

            if (BlockReading->pprev == NULL) { assert(BlockReading); break; }

            BlockReading = BlockReading->pprev;
        }
    }
    if (fDebug){
        printf("finished at height %d\n-----------%d collaterals------------",nHeight,vCollaterals.size());
        for (CCollateralNCollateral& rec : vCollaterals)
        {
            CTxDestination address1;
            ExtractDestination(rec.scriptPubKey, address1);
            CBitcoinAddress address2(address1);
            printf("Height %d: MN Address %s secured by collateral %s\n",rec.height,address2.ToString().c_str(),rec.vin.ToString().c_str());
        }
    }

    return (blocksFound > 0);

}

bool FindCNPayment(CScript& payee, CBlockIndex* pindex)
{
    if (fDebug) printf("Searching for CN collateral...\n");
    CTxDB txdb("r");
    const CBlockIndex *BlockReading = pindex;
    int blocksFound = 0;
    int nHeight = 0;
    for (int i = 0; BlockReading && BlockReading->nHeight > 1; i++) {
            CBlock block;
            if(!block.ReadFromDisk(BlockReading, true)) // shouldn't really happen
                continue;

            nHeight = BlockReading->nHeight;

            if (block.IsProofOfWork() || block.IsProofOfStake())
            {
                bool found = false;
                for (const CTransaction& tx : block.vtx) {
                    if (tx.IsCoinBase()) continue;
                    int n = 0;
                    for (const CTxOut& txout : tx.vout)
                    {
                        if(payee == txout.scriptPubKey && txout.nValue == GetMNCollateral() * COIN) {
                            if (fDebug) printf("Found CN payment at height %d - to %s\n",nHeight,txout.ToString().c_str());
                            // TODO: check spent with fetch inputs?
                            CTransaction txCollateral;
                            COutPoint cout = COutPoint(tx.GetHash(),n);
                            CTxOut vout = CTxOut(1 * COIN, txout.scriptPubKey);
                            CTxIn vin = CTxIn(cout, txout.scriptPubKey);
                            txCollateral.vin.push_back(vin);
                            txCollateral.vout.push_back(vout);
                            //if(fDebug) printf("CCollaTeralPool::IsCollateralValid - Testing TX %s\n",txCollateral.ToString().c_str());
                            bool* pfMissingInputs;
                            if(!AcceptableInputs(mempool, txCollateral, false, pfMissingInputs)){
                                if(fDebug) printf("CCollaTeralPool::IsCollateralValid - didn't pass IsAcceptable\n");
                                continue;
                            } else {
                                found = true;
                                return true;
                            }

                        }
                        n++;
                    }
                    if (found) return true;
                }
            }

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }

        BlockReading = BlockReading->pprev;
    }
    printf("finished at height %d\n",nHeight);
    return (blocksFound > 0);

}

bool FindCNPayments(CScript& payee, CBlockIndex* pindex)
{
    printf("CNPayment:");
    CTxDB txdb("r");
    const CBlockIndex *BlockReading = pindex;
    int blocksFound = 0;
    int nHeight = 0;
    if (fTestNet) {
        for (int i = 0; BlockReading && BlockReading->nHeight > MN_ENFORCEMENT_ACTIVE_HEIGHT_TESTNET; i++) {
                CBlock block;
                if(!block.ReadFromDisk(BlockReading, true)) // shouldn't really happen
                    continue;

                nHeight = BlockReading->nHeight;

                if (block.IsProofOfWork() || block.IsProofOfStake())
                {
                    for (const CTransaction& tx : block.vtx) {
                        int n = 0;
                        for (const CTxOut& txout : tx.vout)
                        {
                            if(payee == txout.scriptPubKey && txout.nValue == GetMNCollateral() * COIN) {
                                if (fDebug) printf("Found CN payment at height %d - to %s\n",nHeight,txout.ToString().c_str());
                                // TODO: check spent with fetch inputs?
                                CTransaction txCollateral;
                                CTxOut vout = CTxOut((GetMNCollateral() - 1)* COIN, colLateralPool.collateralPubKey);
                                CTxIn vin = CTxIn(txout.GetHash(),n);
                                txCollateral.vin.push_back(vin);
                                txCollateral.vout.push_back(vout);
                                bool* pfMissingInputs;
                                if(!AcceptableInputs(mempool, txCollateral, false, pfMissingInputs)){
                                    if(fDebug) printf("CCollaTeralPool::IsCollateralValid - didn't pass IsAcceptable\n");
                                    continue;
                                }
                                return true;

                            }
                            n++;
                        }
                    }
                }

            if (BlockReading->pprev == NULL) { assert(BlockReading); break; }

            BlockReading = BlockReading->pprev;
        }
    } else {
        for (int i = 0; BlockReading && BlockReading->nHeight > MN_ENFORCEMENT_ACTIVE_HEIGHT; i++) {
                CBlock block;
                if(!block.ReadFromDisk(BlockReading, true)) // shouldn't really happen
                    continue;

                nHeight = BlockReading->nHeight;

                if (block.IsProofOfWork() || block.IsProofOfStake())
                {
                    for (const CTransaction& tx : block.vtx) {
                        int n = 0;
                        for (const CTxOut& txout : tx.vout)
                        {
                            if(payee == txout.scriptPubKey && txout.nValue == GetMNCollateral() * COIN) {
                                if (fDebug) printf("Found CN payment at height %d - to %s\n",nHeight,txout.ToString().c_str());
                                // TODO: check spent with fetch inputs?
                                CTransaction txCollateral;
                                CTxOut vout = CTxOut((GetMNCollateral() - 1)* COIN, colLateralPool.collateralPubKey);
                                CTxIn vin = CTxIn(txout.GetHash(),n);
                                txCollateral.vin.push_back(vin);
                                txCollateral.vout.push_back(vout);
                                bool* pfMissingInputs;
                                if(!AcceptableInputs(mempool, txCollateral, false, pfMissingInputs)){
                                    if(fDebug) printf("CCollaTeralPool::IsCollateralValid - didn't pass IsAcceptable\n");
                                    continue;
                                }
                                return true;

                            }
                            n++;
                        }
                    }
                }

            if (BlockReading->pprev == NULL) { assert(BlockReading); break; }

            BlockReading = BlockReading->pprev;
        }
    }
    printf("finished at height %d\n",nHeight);
    return (blocksFound > 0);

}
