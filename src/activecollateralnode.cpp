// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The DarkCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "protocol.h"
#include "activecollateralnode.h"
#include "collateralnodeconfig.h"
#include <boost/lexical_cast.hpp>
#include "clientversion.h"

//
// Bootup the collateralnode, look for a 25000 INN input and register on the network
//
void CActiveCollateralnode::ManageStatus()
{
    std::string errorMessage;

    if(!fCollateralNode) return;

    if (fDebug) printf("CActiveCollateralnode::ManageStatus() - Begin\n");

    //need correct adjusted time to send ping
    bool fIsInitialDownload = IsInitialBlockDownload();
    if(fIsInitialDownload) {
        status = COLLATERALNODE_SYNC_IN_PROCESS;
        printf("CActiveCollateralnode::ManageStatus() - Sync in progress. Must wait until sync is complete to start collateralnode.\n");
        return;
    }

    if(status == COLLATERALNODE_INPUT_TOO_NEW || status == COLLATERALNODE_NOT_CAPABLE || status == COLLATERALNODE_SYNC_IN_PROCESS){
        status = COLLATERALNODE_NOT_PROCESSED;
    }

    if(status == COLLATERALNODE_NOT_PROCESSED) {
        if(strCollateralNodeAddr.empty()) {
            if(!GetLocal(service)) {
                notCapableReason = "Can't detect external address. Please use the collateralnodeaddr configuration option.";
                status = COLLATERALNODE_NOT_CAPABLE;
                printf("CActiveCollateralnode::ManageStatus() - not capable: %s\n", notCapableReason.c_str());
                return;
            }
        } else {
            service = CService(strCollateralNodeAddr);
        }

        printf("CActiveCollateralnode::ManageStatus() - Checking inbound connection to '%s'\n", service.ToString().c_str());

            if(!ConnectNode((CAddress)service, service.ToString().c_str())){
                notCapableReason = "Could not connect to " + service.ToString();
                status = COLLATERALNODE_NOT_CAPABLE;
                printf("CActiveCollateralnode::ManageStatus() - not capable: %s\n", notCapableReason.c_str());
                return;
            }

        if(pwalletMain->IsLocked()){
            notCapableReason = "Wallet is locked.";
            status = COLLATERALNODE_NOT_CAPABLE;
            printf("CActiveCollateralnode::ManageStatus() - not capable: %s\n", notCapableReason.c_str());
            return;
        }

        // Set defaults
        status = COLLATERALNODE_NOT_CAPABLE;
        notCapableReason = "Unknown. Check debug.log for more information.\n";

        // Choose coins to use
        CPubKey pubKeyCollateralAddress;
        CKey keyCollateralAddress;

        if(GetCollateralNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress)) {

            //if(GetInputAge(vin, pindexBest) < (nBestHeight > BLOCK_START_COLLATERALNODE_DELAYPAY ? COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY : COLLATERALNODE_MIN_CONFIRMATIONS)){
            //    printf("CActiveCollateralnode::ManageStatus() - Input must have least %d confirmations - %d confirmations\n", (nBestHeight > BLOCK_START_COLLATERALNODE_DELAYPAY ? COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY : COLLATERALNODE_MIN_CONFIRMATIONS), GetInputAge(vin, pindexBest));
            //    status = COLLATERALNODE_INPUT_TOO_NEW;
            //    return;
            //}

            printf("CActiveCollateralnode::ManageStatus() - Is a capable CollateralNode.\n");

            status = COLLATERALNODE_IS_CAPABLE;
            notCapableReason = "";

            pwalletMain->LockCoin(vin.prevout);

            // send to all nodes
            CPubKey pubKeyCollateralnode;
            CKey keyCollateralnode;

            if(!forTunaSigner.SetKey(strCollateralNodePrivKey, errorMessage, keyCollateralnode, pubKeyCollateralnode))
            {
                printf("Register::ManageStatus() - Error upon calling SetKey: %s\n", errorMessage.c_str());
                return;
            }

            if(!Register(vin, service, keyCollateralAddress, pubKeyCollateralAddress, keyCollateralnode, pubKeyCollateralnode, errorMessage)) {
                printf("CActiveCollateralnode::ManageStatus() - Error on Register: %s\n", errorMessage.c_str());
            }

            return;
        } else {
            printf("CActiveCollateralnode::ManageStatus() - Could not find suitable coins!\n");
        }
    }

    //send to all peers
    if(!Dseep(errorMessage)) {
        printf("CActiveCollateralnode::ManageStatus() - Error on Ping: %s", errorMessage.c_str());
    }
}

// Send stop dseep to network for remote collateralnode
bool CActiveCollateralnode::StopCollateralNode(std::string strService, std::string strKeyCollateralnode, std::string& errorMessage) {
    CTxIn vin;
    CKey keyCollateralnode;
    CPubKey pubKeyCollateralnode;

    if(!forTunaSigner.SetKey(strKeyCollateralnode, errorMessage, keyCollateralnode, pubKeyCollateralnode)) {
        printf("CActiveCollateralnode::StopCollateralNode() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    return StopCollateralNode(vin, CService(strService), keyCollateralnode, pubKeyCollateralnode, errorMessage);
}

// Send stop dseep to network for main collateralnode
bool CActiveCollateralnode::StopCollateralNode(std::string& errorMessage) {
    if(status != COLLATERALNODE_IS_CAPABLE && status != COLLATERALNODE_REMOTELY_ENABLED) {
        errorMessage = "collateralnode is not in a running status";
        printf("CActiveCollateralnode::StopCollateralNode() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    status = COLLATERALNODE_STOPPED;

    CPubKey pubKeyCollateralnode;
    CKey keyCollateralnode;

    if(!forTunaSigner.SetKey(strCollateralNodePrivKey, errorMessage, keyCollateralnode, pubKeyCollateralnode))
    {
        printf("Register::ManageStatus() - Error upon calling SetKey: %s\n", errorMessage.c_str());
        return false;
    }

    return StopCollateralNode(vin, service, keyCollateralnode, pubKeyCollateralnode, errorMessage);
}

// Send stop dseep to network for any collateralnode
bool CActiveCollateralnode::StopCollateralNode(CTxIn vin, CService service, CKey keyCollateralnode, CPubKey pubKeyCollateralnode, std::string& errorMessage) {
       pwalletMain->UnlockCoin(vin.prevout);
    return Dseep(vin, service, keyCollateralnode, pubKeyCollateralnode, errorMessage, true);
}

bool CActiveCollateralnode::Dseep(std::string& errorMessage) {
    if(status != COLLATERALNODE_IS_CAPABLE && status != COLLATERALNODE_REMOTELY_ENABLED) {
        errorMessage = "collateralnode is not in a running status";
        printf("CActiveCollateralnode::Dseep() - Error: %s\n", errorMessage.c_str());
        return false;
    }

    CPubKey pubKeyCollateralnode;
    CKey keyCollateralnode;

    if(!forTunaSigner.SetKey(strCollateralNodePrivKey, errorMessage, keyCollateralnode, pubKeyCollateralnode))
    {
        printf("Register::ManageStatus() - Error upon calling SetKey: %s\n", errorMessage.c_str());
        return false;
    }

    return Dseep(vin, service, keyCollateralnode, pubKeyCollateralnode, errorMessage, false);
}

bool CActiveCollateralnode::Dseep(CTxIn vin, CService service, CKey keyCollateralnode, CPubKey pubKeyCollateralnode, std::string &retErrorMessage, bool stop) {
    std::string errorMessage;
    std::vector<unsigned char> vchCollateralNodeSignature;
    std::string strCollateralNodeSignMessage;
    int64_t masterNodeSignatureTime = GetAdjustedTime();

    std::string strMessage = service.ToString() + boost::lexical_cast<std::string>(masterNodeSignatureTime) + boost::lexical_cast<std::string>(stop);

    if(!forTunaSigner.SignMessage(strMessage, errorMessage, vchCollateralNodeSignature, keyCollateralnode)) {
        retErrorMessage = "sign message failed: " + errorMessage;
        printf("CActiveCollateralnode::Dseep() - Error: %s\n", retErrorMessage.c_str());
        return false;
    }

    if(!forTunaSigner.VerifyMessage(pubKeyCollateralnode, vchCollateralNodeSignature, strMessage, errorMessage)) {
        retErrorMessage = "Verify message failed: " + errorMessage;
        printf("CActiveCollateralnode::Dseep() - Error: %s\n", retErrorMessage.c_str());
        return false;
    }

    // Update Last Seen timestamp in collateralnode list
    bool found = false;
    for (CCollateralNode& mn : vecCollateralnodes) {
        //printf(" -- %s\n", mn.vin.ToString().c_str());
        if(mn.vin == vin) {
            found = true;
            mn.UpdateLastSeen();
        }
    }

    if(!found){
        // Seems like we are trying to send a ping while the collateralnode is not registered in the network
        retErrorMessage = "CollateralN Collateralnode List doesn't include our collateralnode, Shutting down collateralnode pinging service! " + vin.ToString();
        printf("CActiveCollateralnode::Dseep() - Error: %s\n", retErrorMessage.c_str());
        status = COLLATERALNODE_NOT_CAPABLE;
        notCapableReason = retErrorMessage;
        return false;
    }

    //send to all peers
    printf("CActiveCollateralnode::Dseep() - SendCollaTeralElectionEntryPing vin = %s\n", vin.ToString().c_str());
    SendCollaTeralElectionEntryPing(vin, vchCollateralNodeSignature, masterNodeSignatureTime, stop);

    return true;
}

bool CActiveCollateralnode::RegisterByPubKey(std::string strService, std::string strKeyCollateralnode, std::string collateralAddress, std::string& errorMessage) {
    CTxIn vin;
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;
    CPubKey pubKeyCollateralnode;
    CKey keyCollateralnode;

    if(!forTunaSigner.SetKey(strKeyCollateralnode, errorMessage, keyCollateralnode, pubKeyCollateralnode))
    {
        printf("CActiveCollateralnode::RegisterByPubKey() - Error upon calling SetKey: %s\n", errorMessage.c_str());
        return false;
    }

    if(!GetCollateralNodeVinForPubKey(collateralAddress, vin, pubKeyCollateralAddress, keyCollateralAddress)) {
        errorMessage = "could not allocate vin for collateralAddress";
        printf("Register::Register() - Error: %s\n", errorMessage.c_str());
        return false;
    }
    return Register(vin, CService(strService), keyCollateralAddress, pubKeyCollateralAddress, keyCollateralnode, pubKeyCollateralnode, errorMessage);
}

bool CActiveCollateralnode::Register(std::string strService, std::string strKeyCollateralnode, std::string txHash, std::string strOutputIndex, std::string& errorMessage) {
    CTxIn vin;
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;
    CPubKey pubKeyCollateralnode;
    CKey keyCollateralnode;

    if(!forTunaSigner.SetKey(strKeyCollateralnode, errorMessage, keyCollateralnode, pubKeyCollateralnode))
    {
        printf("CActiveCollateralnode::Register() - Error upon calling SetKey: %s\n", errorMessage.c_str());
        return false;
    }

    if(!GetCollateralNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress, txHash, strOutputIndex, errorMessage)) {
        //errorMessage = "could not allocate vin";
        printf("Register::Register() - Error: %s\n", errorMessage.c_str());
        return false;
    }
    return Register(vin, CService(strService), keyCollateralAddress, pubKeyCollateralAddress, keyCollateralnode, pubKeyCollateralnode, errorMessage);
}

bool CActiveCollateralnode::Register(CTxIn vin, CService service, CKey keyCollateralAddress, CPubKey pubKeyCollateralAddress, CKey keyCollateralnode, CPubKey pubKeyCollateralnode, std::string &retErrorMessage) {
    std::string errorMessage;
    std::vector<unsigned char> vchCollateralNodeSignature;
    std::string strCollateralNodeSignMessage;
    int64_t masterNodeSignatureTime = GetAdjustedTime();

    std::string vchPubKey(pubKeyCollateralAddress.begin(), pubKeyCollateralAddress.end());
    std::string vchPubKey2(pubKeyCollateralnode.begin(), pubKeyCollateralnode.end());

    std::string strMessage = service.ToString() + boost::lexical_cast<std::string>(masterNodeSignatureTime) + vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(PROTOCOL_VERSION);
    if(!forTunaSigner.SignMessage(strMessage, errorMessage, vchCollateralNodeSignature, keyCollateralAddress)) {
        retErrorMessage = "sign message failed: " + errorMessage;
        printf("CActiveCollateralnode::Register() - Error: %s\n", retErrorMessage.c_str());
        return false;
    }
    if(!forTunaSigner.VerifyMessage(pubKeyCollateralAddress, vchCollateralNodeSignature, strMessage, errorMessage)) {
        retErrorMessage = "Verify message failed: " + errorMessage;
        printf("CActiveCollateralnode::Register() - Error: %s\n", retErrorMessage.c_str());
        return false;
    }

    bool found = false;
    bool dup = false;
    LOCK(cs_collateralnodes);
    for (CCollateralNode& mn : vecCollateralnodes)
    {
      if(mn.pubkey == pubKeyCollateralAddress) {
              dup = true;
          }
      }
      if (dup) {
        retErrorMessage = "Failed, CN already in list, use a different pubkey";
      printf("CActiveCollateralnode::Register() FAILED! CN Already in List. Change your collateral address to a different address for this CN.\n", retErrorMessage.c_str());
          return false;
      }
      for (CCollateralNode& mn : vecCollateralnodes)
      {
          if(mn.vin == vin) {
              printf("Found CN VIN in CollateralNodes List\n");
              found = true;
      }
    }

    if(!found) {
        printf("CActiveCollateralnode::Register() - Adding to collateralnode list service: %s - vin: %s\n", service.ToString().c_str(), vin.ToString().c_str());
        CCollateralNode mn(service, vin, pubKeyCollateralAddress, vchCollateralNodeSignature, masterNodeSignatureTime, pubKeyCollateralnode, PROTOCOL_VERSION);
        mn.UpdateLastSeen(masterNodeSignatureTime);
        vecCollateralnodes.push_back(mn);
    }

    //send to all peers
    printf("CActiveCollateralnode::Register() - SendCollaTeralElectionEntry vin = %s\n", vin.ToString().c_str());
    SendCollaTeralElectionEntry(vin, service, vchCollateralNodeSignature, masterNodeSignatureTime, pubKeyCollateralAddress, pubKeyCollateralnode, -1, -1, masterNodeSignatureTime, PROTOCOL_VERSION);

    return true;
}

bool CActiveCollateralnode::GetCollateralNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey) {
    return GetCollateralNodeVin(vin, pubkey, secretKey, "", "");
}

bool CActiveCollateralnode::GetCollateralNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex) {
    CScript pubScript;
    // Find possible candidates
    vector<COutput> possibleCoins = SelectCoinsCollateralnode();
    COutput *selectedOutput;

    // Find the vin
    if(!strTxHash.empty()) {
        // Let's find it
        uint256 txHash(strTxHash);
        int outputIndex = boost::lexical_cast<int>(strOutputIndex);
        bool found = false;
        BOOST_FOREACH(COutput& out, possibleCoins) {
            if(out.tx->GetHash() == txHash && out.i == outputIndex)
            {
                selectedOutput = &out;
                found = true;
                break;
            }
        }
        if(!found) {
            printf("CActiveCollateralnode::GetCollateralNodeVin - Could not locate valid vin\n");
            return false;
        }
        if (selectedOutput->nDepth < COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY) {
            CScript mn;
            mn = GetScriptForDestination(pubkey.GetID());
            CTxDestination address1;
            ExtractDestination(mn, address1);
            CBitcoinAddress address2(address1);
            int remain = COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY - selectedOutput->nDepth;
            printf("CActiveCollateralnode::GetCollateralNodeVin - Transaction for MN %s is too young (%d more confirms required)", address2.ToString().c_str(), remain);
            return false;
        }
        //Check the list
        bool dup = false;
        LOCK(cs_collateralnodes);
        BOOST_FOREACH(CCollateralNode& mn, vecCollateralnodes)
        {
            if(mn.pubkey == pubkey) {
                dup = true;
            }
        }
        if (dup) {
            printf("CActiveCollateralnode::Register() FAILED! CN ALREADY IN LIST.\n");
            return false;
        }
    } else {
        // No output specified,  Select the first one
        if(possibleCoins.size() > 0) {
            // May cause problems with multiple transactions.
            selectedOutput = &possibleCoins[0];
        } else {
            printf("CActiveCollateralnode::GetCollateralNodeVin - Could not locate specified vin from possible list\n");
            return false;
        }
    }

    // At this point we have a selected output, retrieve the associated info
    return GetVinFromOutput(*selectedOutput, vin, pubkey, secretKey);
}

bool CActiveCollateralnode::GetCollateralNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage) {

  if (pwalletMain->IsLocked())
  {
      errorMessage = "Error: Your wallet is locked! Please unlock your wallet!";
      return false;
  }

    // Find possible candidates
    vector<COutput> possibleCoins = SelectCoinsCollateralnode(false);
    COutput *selectedOutput;

    // Find the vin
    if(!strTxHash.empty()) {
        // Let's find it
        uint256 txHash(strTxHash);
        int outputIndex = boost::lexical_cast<int>(strOutputIndex);
        bool found = false;
        BOOST_FOREACH(COutput& out, possibleCoins) {
            if(out.tx->GetHash() == txHash && out.i == outputIndex)
            {
                if (out.tx->IsSpent(outputIndex))
                {
                        errorMessage = "vin was spent";
                        return false;
                }
                selectedOutput = &out;
                found = true;
                break;
            }
        }
        if(!found) {
            errorMessage = "Could not locate valid vin";
            return false;
        }
        if (selectedOutput->nDepth < COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY) {
            int remain = COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY - selectedOutput->nDepth;
            errorMessage = strprintf("%d more confirms required", remain);
            return false;
        }
    } else {
        // No output specified,  Select the first one
        if(possibleCoins.size() > 0) {
            // May cause problems with multiple transactions.
            selectedOutput = &possibleCoins[0];
        } else {
            errorMessage = "Could not locate specified vin from coins in wallet";
            return false;
        }
    }

    // At this point we have a selected output, retrieve the associated info
    if (!GetVinFromOutput(*selectedOutput, vin, pubkey, secretKey))
    {
        errorMessage = "could not allocate vin";
        return false;
    }
    return true;
}

bool CActiveCollateralnode::GetCollateralNodeVinForPubKey(std::string collateralAddress, CTxIn& vin, CPubKey& pubkey, CKey& secretKey) {
    return GetCollateralNodeVinForPubKey(collateralAddress, vin, pubkey, secretKey, "", "");
}

bool CActiveCollateralnode::GetCollateralNodeVinForPubKey(std::string collateralAddress, CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex) {
    CScript pubScript;

    // Find possible candidates
    vector<COutput> possibleCoins = SelectCoinsCollateralnodeForPubKey(collateralAddress);
    COutput *selectedOutput;

    // Find the vin
    if(!strTxHash.empty()) {
        // Let's find it
        uint256 txHash(strTxHash);
        int outputIndex = boost::lexical_cast<int>(strOutputIndex);
        bool found = false;
        BOOST_FOREACH(COutput& out, possibleCoins) {
            if(out.tx->GetHash() == txHash && out.i == outputIndex)
            {
                selectedOutput = &out;
                found = true;
                break;
            }
        }
        if(!found) {
            printf("CActiveCollateralnode::GetCollateralNodeVinForPubKey - Could not locate valid vin\n");
            return false;
        }
    } else {
        // No output specified,  Select the first one
        if(possibleCoins.size() > 0) {
            selectedOutput = &possibleCoins[0];
        } else {
            printf("CActiveCollateralnode::GetCollateralNodeVinForPubKey - Could not locate specified vin from possible list\n");
            return false;
        }
    }

    // At this point we have a selected output, retrieve the associated info
    return GetVinFromOutput(*selectedOutput, vin, pubkey, secretKey);
}


// Extract collateralnode vin information from output
bool CActiveCollateralnode::GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey) {

    CScript pubScript;

    vin = CTxIn(out.tx->GetHash(),out.i);
    pubScript = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);
    CBitcoinAddress address2(address1);

    CKeyID keyID;
    if (!address2.GetKeyID(keyID)) {
        printf("CActiveCollateralnode::GetCollateralNodeVin - Address does not refer to a key\n");
        return false;
    }

    if (!pwalletMain->GetKey(keyID, secretKey)) {
        printf("CActiveCollateralnode::GetCollateralNodeVin - Private key for address is not known\n");
        return false;
    }

    pubkey = secretKey.GetPubKey();
    return true;
}

// get all possible outputs for running collateralnode
vector<COutput> CActiveCollateralnode::SelectCoinsCollateralnode(bool fSelectUnlocked)
{
    vector<COutput> vCoins;
    vector<COutput> filteredCoins;
    vector<COutPoint> confLockedCoins;

    // Temporary unlock MN coins from collateralnode.conf
    if(fSelectUnlocked && GetBoolArg("-cnconflock", true)) {
        uint256 mnTxHash;
        BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry mne, collateralnodeConfig.getEntries()) {
            mnTxHash.SetHex(mne.getTxHash());
            COutPoint outpoint = COutPoint(mnTxHash, boost::lexical_cast<unsigned int>(mne.getOutputIndex()));
            confLockedCoins.push_back(outpoint);
            pwalletMain->UnlockCoin(outpoint);
        }
    }

    // Retrieve all possible outputs
    pwalletMain->AvailableCoinsMN(vCoins, true, fSelectUnlocked);

    // Lock MN coins from collateralnode.conf back if they where temporary unlocked
    if(!confLockedCoins.empty()) {
        BOOST_FOREACH(COutPoint outpoint, confLockedCoins)
            pwalletMain->LockCoin(outpoint);
    }

    // Filter
    BOOST_FOREACH(const COutput& out, vCoins)
    {
        if(out.tx->vout[out.i].nValue == GetMNCollateral()*COIN) { //exactly 25,000 INN
            filteredCoins.push_back(out);
        }
    }
    return filteredCoins;
}

// get all possible outputs for running collateralnode for a specific pubkey
vector<COutput> CActiveCollateralnode::SelectCoinsCollateralnodeForPubKey(std::string collateralAddress)
{
    CBitcoinAddress address(collateralAddress);
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address.Get());
    vector<COutput> vCoins;
    vector<COutput> filteredCoins;

    // Retrieve all possible outputs
    pwalletMain->AvailableCoins(vCoins);

    // Filter
    BOOST_FOREACH(const COutput& out, vCoins)
    {
        if(out.tx->vout[out.i].scriptPubKey == scriptPubKey && out.tx->vout[out.i].nValue == GetMNCollateral()*COIN) { //exactly 25,000 INN
            filteredCoins.push_back(out);
        }
    }
    return filteredCoins;
}

// when starting a collateralnode, this can enable to run as a hot wallet with no funds
bool CActiveCollateralnode::EnableHotColdCollateralNode(CTxIn& newVin, CService& newService)
{
    if(!fCollateralNode) fCollateralNode = true;

    status = COLLATERALNODE_REMOTELY_ENABLED;

    //The values below are needed for signing dseep messages going forward
    this->vin = newVin;
    this->service = newService;

    printf("CActiveCollateralnode::EnableHotColdCollateralNode() - Enabled! You may shut down the cold daemon.\n");

    return true;
}
