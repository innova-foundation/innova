// Copyright (c) 2017-2019 The Denarius developers
// Copyright (c) 2017-2019 The Innova developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef COLLATERALN_H
#define COLLATERALN_H

#include "main.h"
#include "collateralnode.h"
#include "activecollateralnode.h"

class CCollaTeralSigner;
class CActiveCollateralnode;

// Lowest peer version asked for the collateralnode list.
static const int COLLATERALN_LIST_MIN_PEER_VERSION = 41015;

extern CCollaTeralSigner colLateralSigner;
extern std::string strCollateralNodePrivKey;
extern CActiveCollateralnode activeCollateralnode;

//
// Helper object for signing and checking signatures
//
class CCollaTeralSigner
{
public:
    bool IsVinAssociatedWithPubkey(CTxIn& vin, CPubKey& pubkey);
    bool SetKey(std::string strSecret, std::string& errorMessage, CKey& key, CPubKey& pubkey);
    bool SignMessage(std::string strMessage, std::string& errorMessage, std::vector<unsigned char>& vchSig, CKey key);
    bool VerifyMessage(CPubKey pubkey, std::vector<unsigned char>& vchSig, std::string strMessage, std::string& errorMessage);
};

void ThreadCheckCollaTeralPool(void* parg);

#endif
