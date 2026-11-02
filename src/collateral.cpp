// Copyright (c) 2019-2026 The Innova developers
// Copyright (c) 2017-2021 The Denarius developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "collateral.h"
#include "main.h"
#include "init.h"
#include "util.h"
#include "collateralnode.h"
#include "ui_interface.h"
#include "txdb.h"

#include <openssl/rand.h>

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/lexical_cast.hpp>

#include <algorithm>
#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost;

static uint32_t SecureRand(uint32_t max) {
    if (max <= 1) return 0;

    uint32_t rand_val;
    uint32_t limit = UINT32_MAX - (UINT32_MAX % max);

    static int nRandFailures = 0;
    do {
        if (RAND_bytes((unsigned char*)&rand_val, sizeof(rand_val)) != 1) {
            nRandFailures++;
            if (nRandFailures >= 10)
                printf("SecureRand: WARNING: %d RAND_bytes failures, falling back to GetRandBytes\n", nRandFailures);
            GetRandBytes((unsigned char*)&rand_val, sizeof(rand_val));
        }
    } while (rand_val >= limit);

    return rand_val % max;
}

/** A helper object for signing messages from collateralnodes */
CCollaTeralSigner colLateralSigner;
/** Keep track of the used collateralnodes */
std::vector<CTxIn> vecCollateralnodesUsed;
//
CActiveCollateralnode activeCollateralnode;
// count peers we've requested the list from
int RequestedCollateralNodeList = 0;

//MIN_MN_PROTO_VERSION
int MIN_MN_PROTO_VERSION = 31000;

bool CCollaTeralSigner::IsVinAssociatedWithPubkey(CTxIn& vin, CPubKey& pubkey){
    bool fIsInitialDownload = IsInitialBlockDownload();
    if(fIsInitialDownload) return false;

    CScript payee2;
    payee2= GetScriptForDestination(pubkey.GetID());

    CTransaction txVin;
    uint256 hash;

    if(GetTransaction(vin.prevout.hash, txVin, hash)){
        // Bounds check on prevout index
        if (vin.prevout.n >= txVin.vout.size())
        {
            if (fDebug)
                printf("IsVinAssociatedWithPubKey:: prevout.n %u out of range (vout size %u) for %s\n",
                       vin.prevout.n, (unsigned int)txVin.vout.size(), vin.prevout.hash.ToString().c_str());
            return false;
        }

        CTxOut out = txVin.vout[vin.prevout.n];
        if ((out.nValue == GetMNCollateral()*COIN) && (out.scriptPubKey == payee2))
        {
            // Verify the UTXO is actually unspent via the tx index
            CTxDB txdb("r");
            CTxIndex txindex;
            if (txdb.ReadTxIndex(vin.prevout.hash, txindex))
            {
                if (vin.prevout.n < txindex.vSpent.size() && !txindex.vSpent[vin.prevout.n].IsNull())
                {
                    if (fDebug)
                        printf("IsVinAssociatedWithPubKey:: collateral UTXO %s:%u is already spent\n",
                               vin.prevout.hash.ToString().c_str(), vin.prevout.n);
                    return false;
                }
            }
            return true;
        }
    } else {
        if (fDebug) {
            printf("IsVinAssociatedWithPubKey:: GetTransaction failed for %s\n",vin.prevout.hash.ToString().c_str());
        }
    }

    CTxDestination address1;
    ExtractDestination(payee2, address1);
    CBitcoinAddress address2(address1);
    if (fDebug) {
        printf("IsVinAssociatedWithPubKey:: vin %s is not associated with pubkey %s for address %s\n",
               vin.ToString().c_str(), pubkey.GetHash().ToString().c_str(), address2.ToString().c_str());
    }
    return false;
}

bool CCollaTeralSigner::SetKey(std::string strSecret, std::string& errorMessage, CKey& key, CPubKey& pubkey){
    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) {
        errorMessage = _("Invalid private key.");
        return false;
    }

    key = vchSecret.GetKey();
    pubkey = key.GetPubKey();

    return true;
}

bool CCollaTeralSigner::SignMessage(std::string strMessage, std::string& errorMessage, vector<unsigned char>& vchSig, CKey key)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    if (!key.SignCompact(ss.GetHash(), vchSig)) {
        errorMessage = _("Signing failed.");
        return false;
    }

    return true;
}

bool CCollaTeralSigner::VerifyMessage(CPubKey pubkey, vector<unsigned char>& vchSig, std::string strMessage, std::string& errorMessage)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey2;
    if (!pubkey2.RecoverCompact(ss.GetHash(), vchSig)) {
        errorMessage = _("Error recovering public key.");
        return false;
    }

    if (fDebug && pubkey2.GetID() != pubkey.GetID())
        printf("CCollaTeralSigner::VerifyMessage -- keys don't match: %s %s", pubkey2.GetID().ToString().c_str(), pubkey.GetID().ToString().c_str());

    return (pubkey2.GetID() == pubkey.GetID());
}

void ThreadCheckCollaTeralPool(void* parg)
{
    // Make this thread recognisable as the wallet flushing thread
    RenameThread("innova-mn");

    unsigned int c = 0;
    std::string errorMessage;

    while (true && !fShutdown)
    {
        c++;

        MilliSleep(1000);
        ReplayCollateralnodeAnnouncements();
        if (CollateralnodeAnnouncementsDirty())
            DumpCollateralnodeAnnouncements();

        int mnTimeout = 150; //2.5 minutes

        if(c % mnTimeout == 0){
            LOCK(cs_main);
            /*
                cs_main is required for doing collateralnode.Check because something
                is modifying the coins view without a mempool lock. It causes
                segfaults from this code without the cs_main lock.
            */
        {

        LOCK(cs_collateralnodes);
            vector<CCollateralNode>::iterator it = vecCollateralnodes.begin();
            //check them separately
            while(it != vecCollateralnodes.end()){
                (*it).Check();
                ++it;
            }

            //remove inactive
            it = vecCollateralnodes.begin();
            while(it != vecCollateralnodes.end()){
                if((*it).enabled == 4 || (*it).enabled == 3){
                    printf("Removing inactive collateralnode %s\n", (*it).addr.ToString().c_str());
                    it = vecCollateralnodes.erase(it);
                    mnCount = mnCount-1;
                } else {
                    ++it;
                }
            }

        }
            collateralnodePayments.CleanPaymentList();
        }

        int mnRefresh = 30;

        // Refresh the collateralnode list from every peer, each at most once per 120 s,
        // regardless of peer count or whether the local count matches the announced one.
        if(!vNodes.empty() && c % mnRefresh == 0) {
            bool fIsInitialDownload = IsInitialBlockDownload();
            if(!fIsInitialDownload) {
                LOCK(cs_vNodes);
                for (CNode* pnode : vNodes)
                {
                    if (pnode->nVersion >= COLLATERALN_LIST_MIN_PEER_VERSION) {

                        // re-request from each node every 120 seconds
                        if(!CollateralnodeRefreshDue(pnode->nLastDseg, GetTime()))
                        {
                            continue;
                        } else {
                            printf("Asking for Collateralnode list from %s\n",pnode->addr.ToStringIPPort().c_str());
                            PushCollateralnodeListRequest(pnode); //request full mn list
                            RequestedCollateralNodeList++;
                        }
                    }
                }
            }
        }

        if(c % COLLATERALNODE_PING_SECONDS == 0){
            activeCollateralnode.ManageStatus();
        }

        //if(c % (60*5) == 0){
        if(c % 60 == 0) {
            LOCK(cs_collateralnodes);
            if (vecCollateralnodes.size()) {
            //let's connect to a random collateralnode every minute!
            int cn = (int)SecureRand((uint32_t)vecCollateralnodes.size());
            CService addr = vecCollateralnodes[cn].addr;
            OpenNetworkConnectionSimple((CAddress)addr, NULL);
            if (fDebug) printf("connected to collateralnode at %s\n",addr.ToStringIPPort().c_str());


            //if we're low on peers, let's connect to some random ipv4 collateralnodes. ipv6 probably won't route anyway
            if (GetArg("-maxconnections", 125) > 16 && vNodes.size() < min(25, (int)GetArg("-maxconnections", 125)) && vecCollateralnodes.size() > 25) {
                int x = 25 - vNodes.size();
                for (int i = x; i-- > 0; ) {
                    int cn = (int)SecureRand((uint32_t)vecCollateralnodes.size());
                    CService addr = vecCollateralnodes[cn].addr;
                    if (addr.IsIPv4() && !addr.IsLocal()) {
                        OpenNetworkConnectionSimple((CAddress)addr, NULL);
                    }
                }

            }
            //if we've used 1/5 of the collateralnode list, then clear the list.
            if((int)vecCollateralnodesUsed.size() > (int)vecCollateralnodes.size() / 5)
                vecCollateralnodesUsed.clear();
            } // if (vecCollateralnodes.size())
        }
    }
}
