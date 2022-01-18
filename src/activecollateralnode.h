// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The DarkCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ACTIVECOLLATERALNODE_H
#define ACTIVECOLLATERALNODE_H

#include "uint256.h"
#include "sync.h"
#include "net.h"
#include "key.h"
#include "main.h"
#include "init.h"
#include "wallet.h"
#include "collateral.h"

// Responsible for activating the collateralnode and pinging the network
class CActiveCollateralnode
{
public:
	// Initialized by init.cpp
	// Keys for the main collateralnode
	CPubKey pubKeyCollateralnode;

	// Initialized while registering collateralnode
	CTxIn vin;
    CService service;

    int status;
    std::string notCapableReason;

    CActiveCollateralnode()
    {
        status = COLLATERALNODE_NOT_PROCESSED;
    }

    void ManageStatus(); // manage status of main collateralnode

    bool Dseep(std::string& errorMessage); // ping for main collateralnode
    bool Dseep(CTxIn vin, CService service, CKey key, CPubKey pubKey, std::string &retErrorMessage, bool stop); // ping for any collateralnode

    bool StopCollateralNode(std::string& errorMessage); // stop main collateralnode
    bool StopCollateralNode(std::string strService, std::string strKeyCollateralnode, std::string& errorMessage); // stop remote collateralnode
    bool StopCollateralNode(CTxIn vin, CService service, CKey key, CPubKey pubKey, std::string& errorMessage); // stop any collateralnode

    bool Register(std::string strService, std::string strKey, std::string txHash, std::string strOutputIndex, std::string& errorMessage); // register remote collateralnode
    bool Register(CTxIn vin, CService service, CKey key, CPubKey pubKey, CKey keyCollateralnode, CPubKey pubKeyCollateralnode, std::string &retErrorMessage); // register any collateralnode
    bool RegisterByPubKey(std::string strService, std::string strKeyCollateralnode, std::string collateralAddress, std::string& errorMessage); // register for a specific collateral address

    // get 25000INN input that can be used for the collateralnode
    bool GetCollateralNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey);
    bool GetCollateralNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex);
    bool GetCollateralNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage);

    bool GetCollateralNodeVinForPubKey(std::string collateralAddress, CTxIn& vin, CPubKey& pubkey, CKey& secretKey);
    bool GetCollateralNodeVinForPubKey(std::string collateralAddress, CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex);
    vector<COutput> SelectCoinsCollateralnode(bool fSelectUnlocked=true);
    vector<COutput> SelectCoinsCollateralnodeForPubKey(std::string collateralAddress);
    bool GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey);
    //bool SelectCoinsCollateralnode(CTxIn& vin, int64& nValueIn, CScript& pubScript, std::string strTxHash, std::string strOutputIndex);

    // enable hot wallet mode (run a collateralnode with no funds)
    bool EnableHotColdCollateralNode(CTxIn& vin, CService& addr);
};

#endif
