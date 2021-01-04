// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2017 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "db.h"
#include "init.h"
#include "collateralnode.h"
#include "activecollateralnode.h"
#include "collateralnodeconfig.h"
#include "innovarpc.h"
#include <boost/lexical_cast.hpp>
#include "util.h"
#include "base58.h"

#include <fstream>
using namespace json_spirit;
using namespace std;




Value getpoolinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getpoolinfo\n"
            "Returns an object containing anonymous pool-related information.");

    Object obj;
    obj.push_back(Pair("current_collateralnode",        GetCurrentCollateralNode()));
    obj.push_back(Pair("state",        forTunaPool.GetState()));
    obj.push_back(Pair("entries",      forTunaPool.GetEntriesCount()));
    obj.push_back(Pair("entries_accepted",      forTunaPool.GetCountEntriesAccepted()));
    return obj;
}

Value collateralnode(const Array& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp  ||
        (strCommand != "start" && strCommand != "start-alias" && strCommand != "start-many" && strCommand != "stop" && strCommand != "stop-alias" && strCommand != "stop-many" && strCommand != "list" && strCommand != "list-conf" && strCommand != "count"  && strCommand != "enforce"
            && strCommand != "debug" && strCommand != "current" && strCommand != "winners" && strCommand != "genkey" && strCommand != "connect" && strCommand != "outputs" && strCommand != "status"))
		throw runtime_error(
			"collateralnode \"command\"... ( \"passphrase\" )\n"
			"Set of commands to execute collateralnode related actions\n"
			"\nArguments:\n"
			"1. \"command\"        (string or set of strings, required) The command to execute\n"
			"2. \"passphrase\"     (string, optional) The wallet passphrase\n"
			"\nAvailable commands:\n"
			"  count        - Print number of all known collateralnodes (optional: 'enabled', 'both')\n"
			"  current      - Print info on current collateralnode winner\n"
			"  debug        - Print collateralnode status\n"
			"  genkey       - Generate new collateralnodeprivkey\n"
			"  enforce      - Enforce collateralnode payments\n"
			"  outputs      - Print collateralnode compatible outputs\n"
            "  status       - Current collateralnode status\n"
			"  start        - Start collateralnode configured in innova.conf\n"
			"  start-alias  - Start single collateralnode by assigned alias configured in collateralnode.conf\n"
			"  start-many   - Start all collateralnodes configured in collateralnode.conf\n"
			"  stop         - Stop collateralnode configured in innova.conf\n"
			"  stop-alias   - Stop single collateralnode by assigned alias configured in collateralnode.conf\n"
			"  stop-many    - Stop all collateralnodes configured in collateralnode.conf\n"
			"  list         - Print list of all known collateralnodes (see collateralnodelist for more info)\n"
			"  list-conf    - Print collateralnode.conf in JSON format\n"
			"  winners      - Print list of collateralnode winners\n"
			//"  vote-many    - Vote on a Innova initiative\n"
			//"  vote         - Vote on a Innova initiative\n"
            );
    if (strCommand == "stop")
    {
        if(!fCollateralNode) return "You must set collateralnode=1 in the configuration";

        if(pwalletMain->IsLocked()) {
            SecureString strWalletPass;
            strWalletPass.reserve(100);

            if (params.size() == 2){
                strWalletPass = params[1].get_str().c_str();
            } else {
                throw runtime_error(
                    "Your wallet is locked, passphrase is required\n");
            }

            if(!pwalletMain->Unlock(strWalletPass)){
                return "Incorrect passphrase";
            }
        }

        std::string errorMessage;
        if(!activeCollateralnode.StopCollateralNode(errorMessage)) {
        	return "Stop Failed: " + errorMessage;
        }
        pwalletMain->Lock();

        if(activeCollateralnode.status == COLLATERALSTAKE_STOPPED) return "Successfully Stopped Collateralnode";
        if(activeCollateralnode.status == COLLATERALSTAKE_NOT_CAPABLE) return "Not a capable Collateralnode";

        return "unknown";
    }

    if (strCommand == "stop-alias")
    {
	    if (params.size() < 2){
			throw runtime_error(
			"command needs at least 2 parameters\n");
	    }

	    std::string alias = params[1].get_str().c_str();

    	if(pwalletMain->IsLocked()) {
    		SecureString strWalletPass;
    	    strWalletPass.reserve(100);

			if (params.size() == 3){
				strWalletPass = params[2].get_str().c_str();
			} else {
				throw runtime_error(
				"Your wallet is locked, passphrase is required\n");
			}

			if(!pwalletMain->Unlock(strWalletPass)){
				return "Incorrect passphrase";
			}
        }

    	bool found = false;

		Object statusObj;
		statusObj.push_back(Pair("alias", alias));

    	BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry mne, collateralnodeConfig.getEntries()) {
    		if(mne.getAlias() == alias) {
    			found = true;
    			std::string errorMessage;
    			bool result = activeCollateralnode.StopCollateralNode(mne.getIp(), mne.getPrivKey(), errorMessage);

				statusObj.push_back(Pair("result", result ? "successful" : "failed"));
    			if(!result) {
   					statusObj.push_back(Pair("errorMessage", errorMessage));
   				}
    			break;
    		}
    	}

    	if(!found) {
    		statusObj.push_back(Pair("result", "failed"));
    		statusObj.push_back(Pair("errorMessage", "could not find alias in config. Verify with list-conf."));
    	}

    	pwalletMain->Lock();
    	return statusObj;
    }

    if (strCommand == "stop-many")
    {
    	if(pwalletMain->IsLocked()) {
			SecureString strWalletPass;
			strWalletPass.reserve(100);

			if (params.size() == 2){
				strWalletPass = params[1].get_str().c_str();
			} else {
				throw runtime_error(
				"Your wallet is locked, passphrase is required\n");
			}

			if(!pwalletMain->Unlock(strWalletPass)){
				return "incorrect passphrase";
			}
		}

		int total = 0;
		int successful = 0;
		int fail = 0;


		Object resultsObj;

		BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry mne, collateralnodeConfig.getEntries()) {
			total++;

			std::string errorMessage;
			bool result = activeCollateralnode.StopCollateralNode(mne.getIp(), mne.getPrivKey(), errorMessage);

			Object statusObj;
			statusObj.push_back(Pair("alias", mne.getAlias()));
			statusObj.push_back(Pair("result", result ? "successful" : "failed"));

			if(result) {
				successful++;
			} else {
				fail++;
				statusObj.push_back(Pair("errorMessage", errorMessage));
			}

			resultsObj.push_back(Pair("status", statusObj));
		}
		pwalletMain->Lock();

		Object returnObj;
		returnObj.push_back(Pair("overall", "Successfully stopped " + boost::lexical_cast<std::string>(successful) + " collateralnodes, failed to stop " +
				boost::lexical_cast<std::string>(fail) + ", total " + boost::lexical_cast<std::string>(total)));
		returnObj.push_back(Pair("detail", resultsObj));

		return returnObj;

    }

    if (strCommand == "list")
    {
        std::string strCommand = "active";

        if (params.size() == 2){
            strCommand = params[1].get_str().c_str();
        }

        if (strCommand != "active" && strCommand != "txid" && strCommand != "pubkey" && strCommand != "lastseen" && strCommand != "lastpaid" && strCommand != "activeseconds" && strCommand != "rank" && strCommand != "n" && strCommand != "full" && strCommand != "protocol" && strCommand != "roundpayments" && strCommand != "roundearnings" && strCommand != "dailyrate"){
            throw runtime_error(
                "list supports 'active', 'txid', 'pubkey', 'lastseen', 'lastpaid', 'activeseconds', 'rank', 'n', 'protocol', 'roundpayments', 'roundearnings', 'dailyrate', full'\n");
        }

        Object obj;
        BOOST_FOREACH(CCollateralNode mn, vecCollateralnodes) {
            mn.Check();

            if(strCommand == "active"){
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int)mn.IsActive()));
            } else if (strCommand == "txid") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       mn.vin.prevout.hash.ToString().c_str()));
            } else if (strCommand == "pubkey") {
                CScript pubkey;
                pubkey =GetScriptForDestination(mn.pubkey.GetID());
                CTxDestination address1;
                ExtractDestination(pubkey, address1);
                CBitcoinAddress address2(address1);

                obj.push_back(Pair(mn.addr.ToString().c_str(),       address2.ToString().c_str()));
            } else if (strCommand == "protocol") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int64_t)mn.protocolVersion));
            } else if (strCommand == "n") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int64_t)mn.vin.prevout.n));
            } else if (strCommand == "lastpaid") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       mn.nBlockLastPaid));
            } else if (strCommand == "lastseen") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int64_t)mn.lastTimeSeen));
            } else if (strCommand == "activeseconds") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int64_t)(mn.lastTimeSeen - mn.now)));
            } else if (strCommand == "rank") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int)(GetCollateralnodeRank(mn, pindexBest))));
            } else if (strCommand == "roundpayments") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       mn.payCount));
            } else if (strCommand == "roundearnings") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       mn.payRate));
            } else if (strCommand == "dailyrate") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       mn.payValue));
            }
			else if (strCommand == "full") {
                Object list;
                list.push_back(Pair("active",          (int)mn.IsActive()));
                list.push_back(Pair("txid",            mn.vin.prevout.hash.ToString().c_str()));
                list.push_back(Pair("n",               (int64_t)mn.vin.prevout.n));
                list.push_back(Pair("ip",              mn.addr.ToString().c_str()));

                CScript pubkey;
                pubkey =GetScriptForDestination(mn.pubkey.GetID());
                CTxDestination address1;
                ExtractDestination(pubkey, address1);
                CBitcoinAddress address2(address1);

                list.push_back(Pair("pubkey",         address2.ToString().c_str()));
                list.push_back(Pair("protocolversion",       (int64_t)mn.protocolVersion));
                list.push_back(Pair("lastseen",       (int64_t)mn.lastTimeSeen));
                list.push_back(Pair("activeseconds",  (int64_t)(mn.lastTimeSeen - mn.now)));
                list.push_back(Pair("rank",           (int)(GetCollateralnodeRank(mn, pindexBest))));
                list.push_back(Pair("lastpaid",       mn.nBlockLastPaid));
                list.push_back(Pair("roundpayments",       mn.payCount));
                list.push_back(Pair("roundearnings",       mn.payValue));
                list.push_back(Pair("dailyrate",       mn.payRate));
                obj.push_back(Pair(mn.addr.ToString().c_str(), list));
            }
        }
        return obj;
    }
    if (strCommand == "count") return (int)vecCollateralnodes.size();

    if (strCommand == "start")
    {
        if(!fCollateralNode) return "you must set collateralnode=1 in the configuration";

        if(pwalletMain->IsLocked()) {
            SecureString strWalletPass;
            strWalletPass.reserve(100);

            if (params.size() == 2){
                strWalletPass = params[1].get_str().c_str();
            } else {
                throw runtime_error(
                    "Your wallet is locked, passphrase is required\n");
            }

            if(!pwalletMain->Unlock(strWalletPass)){
                return "incorrect passphrase";
            }
        }

        if(activeCollateralnode.status != COLLATERALSTAKE_REMOTELY_ENABLED && activeCollateralnode.status != COLLATERALSTAKE_IS_CAPABLE){
            activeCollateralnode.status = COLLATERALSTAKE_NOT_PROCESSED; // TODO: consider better way
            std::string errorMessage;
            activeCollateralnode.ManageStatus();
            pwalletMain->Lock();
        }

        if(activeCollateralnode.status == COLLATERALSTAKE_REMOTELY_ENABLED) return "collateralnode started remotely";
        if(activeCollateralnode.status == COLLATERALSTAKE_INPUT_TOO_NEW) return "collateralnode input must have at least 15 confirmations";
        if(activeCollateralnode.status == COLLATERALSTAKE_STOPPED) return "collateralnode is stopped";
        if(activeCollateralnode.status == COLLATERALSTAKE_IS_CAPABLE) return "successfully started collateralnode";
        if(activeCollateralnode.status == COLLATERALSTAKE_NOT_CAPABLE) return "not capable collateralnode: " + activeCollateralnode.notCapableReason;
        if(activeCollateralnode.status == COLLATERALSTAKE_SYNC_IN_PROCESS) return "sync in process. Must wait until client is synced to start.";

        return "unknown";
    }

    if (strCommand == "start-alias")
    {
	    if (params.size() < 2){
			throw runtime_error(
			"command needs at least 2 parameters\n");
	    }

	    std::string alias = params[1].get_str().c_str();

    	if(pwalletMain->IsLocked()) {
    		SecureString strWalletPass;
    	    strWalletPass.reserve(100);

			if (params.size() == 3){
				strWalletPass = params[2].get_str().c_str();
			} else {
				throw runtime_error(
				"Your wallet is locked, passphrase is required\n");
			}

			if(!pwalletMain->Unlock(strWalletPass)){
				return "incorrect passphrase";
			}
        }

    	bool found = false;

		Object statusObj;
		statusObj.push_back(Pair("alias", alias));

    	BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry mne, collateralnodeConfig.getEntries()) {
    		if(mne.getAlias() == alias) {
    			found = true;
    			std::string errorMessage;
    			bool result = activeCollateralnode.Register(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage);

    			statusObj.push_back(Pair("result", result ? "successful" : "failed"));
    			if(!result) {
					statusObj.push_back(Pair("errorMessage", errorMessage));
				}
    			break;
    		}
    	}

    	if(!found) {
    		statusObj.push_back(Pair("result", "failed"));
    		statusObj.push_back(Pair("errorMessage", "could not find alias in config. Verify with list-conf."));
    	}

    	pwalletMain->Lock();
    	return statusObj;

    }

    if (strCommand == "start-many")
    {
    	if(pwalletMain->IsLocked()) {
			SecureString strWalletPass;
			strWalletPass.reserve(100);

			if (params.size() == 2){
				strWalletPass = params[1].get_str().c_str();
			} else {
				throw runtime_error(
				"Your wallet is locked, passphrase is required\n");
			}

			if(!pwalletMain->Unlock(strWalletPass)){
				return "incorrect passphrase";
			}
		}

		std::vector<CCollateralnodeConfig::CCollateralnodeEntry> mnEntries;
		mnEntries = collateralnodeConfig.getEntries();

		int total = 0;
		int successful = 0;
		int fail = 0;

		Object resultsObj;

		BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry mne, collateralnodeConfig.getEntries()) {
			total++;

			std::string errorMessage;
			bool result = activeCollateralnode.Register(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage);

			Object statusObj;
			statusObj.push_back(Pair("alias", mne.getAlias()));
			statusObj.push_back(Pair("result", result ? "succesful" : "failed"));

			if(result) {
				successful++;
			} else {
				fail++;
				statusObj.push_back(Pair("errorMessage", errorMessage));
			}

			resultsObj.push_back(Pair("status", statusObj));
		}
		pwalletMain->Lock();

		Object returnObj;
		returnObj.push_back(Pair("overall", "Successfully started " + boost::lexical_cast<std::string>(successful) + " collateralnodes, failed to start " +
				boost::lexical_cast<std::string>(fail) + ", total " + boost::lexical_cast<std::string>(total)));
		returnObj.push_back(Pair("detail", resultsObj));

		return returnObj;
    }

    if (strCommand == "debug")
    {
        if(activeCollateralnode.status == COLLATERALSTAKE_REMOTELY_ENABLED) return "collateralnode started remotely";
        if(activeCollateralnode.status == COLLATERALSTAKE_INPUT_TOO_NEW) return "collateralnode input must have at least 15 confirmations";
        if(activeCollateralnode.status == COLLATERALSTAKE_IS_CAPABLE) return "successfully started collateralnode";
        if(activeCollateralnode.status == COLLATERALSTAKE_STOPPED) return "collateralnode is stopped";
        if(activeCollateralnode.status == COLLATERALSTAKE_NOT_CAPABLE) return "not capable collateralnode: " + activeCollateralnode.notCapableReason;
        if(activeCollateralnode.status == COLLATERALSTAKE_SYNC_IN_PROCESS) return "sync in process. Must wait until client is synced to start.";

        CTxIn vin = CTxIn();
        CPubKey pubkey = CScript();
        CKey key;
        bool found = activeCollateralnode.GetCollateralNodeVin(vin, pubkey, key);
        if(!found){
            return "Missing collateralnode input, please look at the documentation for instructions on collateralnode creation";
        } else {
            return "No problems were found";
        }
    }

    if (strCommand == "create")
    {

        return "Not implemented yet, please look at the documentation for instructions on collateralnode creation";
    }

    if (strCommand == "current")
    {
        int winner = GetCurrentCollateralNode(1);
        if(winner >= 0) {
            return vecCollateralnodes[winner].addr.ToString().c_str();
        }

        return "unknown";
    }

    if (strCommand == "genkey")
    {
		CKey secret;
		secret.MakeNewKey(false);
		return CBitcoinSecret(secret).ToString();
    }

    if (strCommand == "winners")
    {
        Object obj;

        for(int nHeight = pindexBest->nHeight-10; nHeight < pindexBest->nHeight+20; nHeight++)
        {
            CScript payee;
            if(collateralnodePayments.GetBlockPayee(nHeight, payee)){
                CTxDestination address1;
                ExtractDestination(payee, address1);
                CBitcoinAddress address2(address1);
                obj.push_back(Pair(boost::lexical_cast<std::string>(nHeight),       address2.ToString().c_str()));
            } else {
                obj.push_back(Pair(boost::lexical_cast<std::string>(nHeight),       ""));
            }
        }

        return obj;
    }

    if(strCommand == "enforce")
    {
        return (uint64_t)enforceCollateralnodePaymentsTime;
    }

    if(strCommand == "connect")
    {
        std::string strAddress = "";
        if (params.size() == 2){
            strAddress = params[1].get_str().c_str();
        } else {
            throw runtime_error(
                "Collateralnode address required\n");
        }

        CService addr = CService(strAddress);

        if(ConnectNode((CAddress)addr, NULL, true)){
            return "successfully connected";
        } else {
            return "error connecting";
        }
    }

    if(strCommand == "list-conf")
    {
    	std::vector<CCollateralnodeConfig::CCollateralnodeEntry> mnEntries;
    	mnEntries = collateralnodeConfig.getEntries();

        Object resultObj;

        BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry mne, collateralnodeConfig.getEntries()) {
    		Object mnObj;
    		mnObj.push_back(Pair("alias", mne.getAlias()));
    		mnObj.push_back(Pair("address", mne.getIp()));
    		mnObj.push_back(Pair("privateKey", mne.getPrivKey()));
    		mnObj.push_back(Pair("txHash", mne.getTxHash()));
    		mnObj.push_back(Pair("outputIndex", mne.getOutputIndex()));
    		resultObj.push_back(Pair("collateralnode", mnObj));
    	}

    	return resultObj;
    }

    if (strCommand == "outputs"){
        // Find possible candidates
        vector<COutput> possibleCoins = activeCollateralnode.SelectCoinsCollateralnode();

        Object obj;
        BOOST_FOREACH(COutput& out, possibleCoins) {
            obj.push_back(Pair(out.tx->GetHash().ToString().c_str(), boost::lexical_cast<std::string>(out.i)));
        }

        return obj;

    }

    if(strCommand == "status")
    {
        std::vector<CCollateralnodeConfig::CCollateralnodeEntry> mnEntries;
        mnEntries = collateralnodeConfig.getEntries();
        Object mnObj;

            CScript pubkey;
            pubkey = GetScriptForDestination(activeCollateralnode.pubKeyCollateralnode.GetID());
            CTxDestination address1;
            ExtractDestination(pubkey, address1);
            CBitcoinAddress address2(address1);

            uint256 mnTxHash;
            int outputIndex;


            if (activeCollateralnode.pubKeyCollateralnode.IsFullyValid()) {
                CScript pubkey;
                CTxDestination address1;
                std::string address = "";
                bool found = false;
                Object localObj;
                localObj.push_back(Pair("vin", activeCollateralnode.vin.ToString().c_str()));
                localObj.push_back(Pair("service", activeCollateralnode.service.ToString().c_str()));
                LOCK(cs_collateralnodes);
                BOOST_FOREACH(CCollateralNode& mn, vecCollateralnodes) {
                    if (mn.vin == activeCollateralnode.vin) {
                        //int mnRank = GetCollateralnodeRank(mn, pindexBest);
                        pubkey = GetScriptForDestination(mn.pubkey.GetID());
                        ExtractDestination(pubkey, address1);
                        CBitcoinAddress address2(address1);
                        address = address2.ToString();
                        localObj.push_back(Pair("payment_address", address));
                        //localObj.push_back(Pair("rank", GetCollateralnodeRank(mn, pindexBest)));
                        localObj.push_back(Pair("network_status", mn.IsActive() ? "active" : "registered"));
                        if (mn.IsActive()) {
                          localObj.push_back(Pair("activetime",(mn.lastTimeSeen - mn.now)));

                        }
                        localObj.push_back(Pair("earnings", mn.payValue));
                        found = true;
                        break;
                    }
                }
                string reason;
                if(activeCollateralnode.status == COLLATERALSTAKE_REMOTELY_ENABLED) reason = "collateralnode started remotely";
                if(activeCollateralnode.status == COLLATERALSTAKE_INPUT_TOO_NEW) reason = "collateralnode input must have at least 15 confirmations";
                if(activeCollateralnode.status == COLLATERALSTAKE_IS_CAPABLE) reason = "successfully started collateralnode";
                if(activeCollateralnode.status == COLLATERALSTAKE_STOPPED) reason = "collateralnode is stopped";
                if(activeCollateralnode.status == COLLATERALSTAKE_NOT_CAPABLE) reason = "not capable collateralnode: " + activeCollateralnode.notCapableReason;
                if(activeCollateralnode.status == COLLATERALSTAKE_SYNC_IN_PROCESS) reason = "sync in process. Must wait until client is synced to start.";

                if (!found) {
                    localObj.push_back(Pair("network_status", "unregistered"));
                    if (activeCollateralnode.status != 9 && activeCollateralnode.status != 7)
                    {
                        localObj.push_back(Pair("notCapableReason", reason));
                    }
                } else {
                    localObj.push_back(Pair("local_status", reason));
                }


                //localObj.push_back(Pair("address", address2.ToString().c_str()));

                mnObj.push_back(Pair("local",localObj));
            } else {
                Object localObj;
                localObj.push_back(Pair("status", "unconfigured"));
                mnObj.push_back(Pair("local",localObj));
            }

            BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry& mne, collateralnodeConfig.getEntries()) {
                Object remoteObj;
                std::string address = mne.getIp();

                CTxIn vin;
                CTxDestination address1;
                CActiveCollateralnode amn;
                CPubKey pubKeyCollateralAddress;
                CKey keyCollateralAddress;
                CPubKey pubKeyCollateralnode;
                CKey keyCollateralnode;
                std::string errorMessage;
                std::string forTunaError;
                std::string vinError;

                mnTxHash.SetHex(mne.getTxHash());
                outputIndex = boost::lexical_cast<unsigned int>(mne.getOutputIndex());
                COutPoint outpoint = COutPoint(mnTxHash, outputIndex);

                if(!forTunaSigner.SetKey(mne.getPrivKey(), forTunaError, keyCollateralnode, pubKeyCollateralnode))
                {
                    errorMessage = forTunaError;
                }

                if (!amn.GetCollateralNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress, mne.getTxHash(), mne.getOutputIndex(), vinError))
                {
                    errorMessage = vinError;
                }

                CScript pubkey = GetScriptForDestination(pubKeyCollateralAddress.GetID());
                ExtractDestination(pubkey, address1);
                CBitcoinAddress address2(address1);

                remoteObj.push_back(Pair("alias", mne.getAlias()));
                remoteObj.push_back(Pair("ipaddr", address));

                // if(pwalletMain->IsLocked() || fWalletUnlockStakingOnly) {
                // remoteObj.push_back(Pair("collateral1", "Wallet is Locked"));
                // } else {
                // remoteObj.push_back(Pair("collateral1", address2.ToString())); //Incorrect address?
                // }

                // CWalletTx tx;
                // if (pwalletMain->GetTransaction(mnTxHash, tx))
                // {
                // CTxOut vout = tx.vout[outputIndex];
                // }

                //remoteObj.push_back(Pair("collateral", address2.ToString()));
				        //remoteObj.push_back(Pair("collateral", CBitcoinAddress(mn->pubKeyCollateralAddress.GetID()).ToString()));

                //INNOVA - Q0lSQ1VJVEJSRUFLRVI=

                bool mnfound = false;
                BOOST_FOREACH(CCollateralNode& mn, vecCollateralnodes)
                {
                    if (mn.addr.ToString() == mne.getIp()) {
                      //remoteObj.push_back(Pair("status", "online"));
                      if (mn.IsActive()) {
                          //nstatus = QString::fromStdString("Active for payment");
                          remoteObj.push_back(Pair("status", "online"));
                      } else if (mn.status == "OK") {
                          if (mn.lastDseep > 0) {
                              //nstatus = QString::fromStdString("Verified");
                              remoteObj.push_back(Pair("status", "verified"));
                          } else {
                              //nstatus = QString::fromStdString("Registered");
                              remoteObj.push_back(Pair("status", "registered"));
                          }
                      } else if (mn.status == "Expired") {
                          //nstatus = QString::fromStdString("Expired");
                          remoteObj.push_back(Pair("status", "expired"));
                      } else if (mn.status == "Inactive, expiring soon") {
                          //nstatus = QString::fromStdString("Inactive, expiring soon");
                          remoteObj.push_back(Pair("status", "inactive"));
                      } else {
                          //nstatus = QString::fromStdString(mn.status);
                          remoteObj.push_back(Pair("status", mn.status));
                      }
                        remoteObj.push_back(Pair("lastpaidblock",mn.nBlockLastPaid));
						            CScript pubkey;
						            pubkey =GetScriptForDestination(mn.pubkey.GetID());
						            CTxDestination address3;
						            ExtractDestination(pubkey, address3);
						            CBitcoinAddress address4(address3);
						            if(pwalletMain->IsLocked() || fWalletUnlockStakingOnly) {
							                   remoteObj.push_back(Pair("collateral", "Wallet is Locked"));
							                   remoteObj.push_back(Pair("txid", "Wallet is Locked"));
						            } else {
							                   remoteObj.push_back(Pair("collateral", address4.ToString().c_str()));
							                   remoteObj.push_back(Pair("txid",mn.vin.prevout.hash.ToString().c_str()));
						            }
						         //remoteObj.push_back(Pair("txid",mn.vin.prevout.hash.ToString().c_str()));
						          remoteObj.push_back(Pair("outputindex", (int64_t)mn.vin.prevout.n));
						          remoteObj.push_back(Pair("rank", GetCollateralnodeRank(mn, pindexBest)));
						          remoteObj.push_back(Pair("roundpayments", mn.payCount));
						          remoteObj.push_back(Pair("earnings", mn.payValue));
						          remoteObj.push_back(Pair("daily", mn.payRate));
                      remoteObj.push_back(Pair("version",mn.protocolVersion));

						//printf("CollateralnodeSTATUS:: %s %s - found %s - %s for alias %s\n", mne.getTxHash().c_str(), mne.getOutputIndex().c_str(), address4.ToString().c_str(), address2.ToString().c_str(), mne.getAlias().c_str());
                        mnfound = true;
                        break;
                    }
                }
                if (!mnfound)
                {
                    if (!errorMessage.empty()) {
                        remoteObj.push_back(Pair("status", "error"));
                        remoteObj.push_back(Pair("error", errorMessage));
                    } else {
                        remoteObj.push_back(Pair("status", "notfound"));
                    }
                }
                mnObj.push_back(Pair(mne.getAlias(),remoteObj));
            }

            return mnObj;
    }


    return Value::null;
}

Value masternode(const Array& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp  ||
        (strCommand != "start" && strCommand != "start-alias" && strCommand != "start-many" && strCommand != "stop" && strCommand != "stop-alias" && strCommand != "stop-many" && strCommand != "list" && strCommand != "list-conf" && strCommand != "count"  && strCommand != "enforce"
            && strCommand != "debug" && strCommand != "current" && strCommand != "winners" && strCommand != "genkey" && strCommand != "connect" && strCommand != "outputs" && strCommand != "status"))
		throw runtime_error(
			"collateralnode \"command\"... ( \"passphrase\" )\n"
			"Set of commands to execute collateralnode related actions\n"
			"\nArguments:\n"
			"1. \"command\"        (string or set of strings, required) The command to execute\n"
			"2. \"passphrase\"     (string, optional) The wallet passphrase\n"
			"\nAvailable commands:\n"
			"  count        - Print number of all known collateralnodes (optional: 'enabled', 'both')\n"
			"  current      - Print info on current collateralnode winner\n"
			"  debug        - Print collateralnode status\n"
			"  genkey       - Generate new collateralnodeprivkey\n"
			"  enforce      - Enforce collateralnode payments\n"
			"  outputs      - Print collateralnode compatible outputs\n"
            "  status       - Current collateralnode status\n"
			"  start        - Start collateralnode configured in innova.conf\n"
			"  start-alias  - Start single collateralnode by assigned alias configured in collateralnode.conf\n"
			"  start-many   - Start all collateralnodes configured in collateralnode.conf\n"
			"  stop         - Stop collateralnode configured in innova.conf\n"
			"  stop-alias   - Stop single collateralnode by assigned alias configured in collateralnode.conf\n"
			"  stop-many    - Stop all collateralnodes configured in collateralnode.conf\n"
			"  list         - Print list of all known collateralnodes (see collateralnodelist for more info)\n"
			"  list-conf    - Print collateralnode.conf in JSON format\n"
			"  winners      - Print list of collateralnode winners\n"
			//"  vote-many    - Vote on a Innova initiative\n"
			//"  vote         - Vote on a Innova initiative\n"
            );
    if (strCommand == "stop")
    {
        if(!fCollateralNode) return "You must set collateralnode=1 in the configuration";

        if(pwalletMain->IsLocked()) {
            SecureString strWalletPass;
            strWalletPass.reserve(100);

            if (params.size() == 2){
                strWalletPass = params[1].get_str().c_str();
            } else {
                throw runtime_error(
                    "Your wallet is locked, passphrase is required\n");
            }

            if(!pwalletMain->Unlock(strWalletPass)){
                return "Incorrect passphrase";
            }
        }

        std::string errorMessage;
        if(!activeCollateralnode.StopCollateralNode(errorMessage)) {
        	return "Stop Failed: " + errorMessage;
        }
        pwalletMain->Lock();

        if(activeCollateralnode.status == COLLATERALSTAKE_STOPPED) return "Successfully Stopped Collateralnode";
        if(activeCollateralnode.status == COLLATERALSTAKE_NOT_CAPABLE) return "Not a capable Collateralnode";

        return "unknown";
    }

    if (strCommand == "stop-alias")
    {
	    if (params.size() < 2){
			throw runtime_error(
			"command needs at least 2 parameters\n");
	    }

	    std::string alias = params[1].get_str().c_str();

    	if(pwalletMain->IsLocked()) {
    		SecureString strWalletPass;
    	    strWalletPass.reserve(100);

			if (params.size() == 3){
				strWalletPass = params[2].get_str().c_str();
			} else {
				throw runtime_error(
				"Your wallet is locked, passphrase is required\n");
			}

			if(!pwalletMain->Unlock(strWalletPass)){
				return "Incorrect passphrase";
			}
        }

    	bool found = false;

		Object statusObj;
		statusObj.push_back(Pair("alias", alias));

    	BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry mne, collateralnodeConfig.getEntries()) {
    		if(mne.getAlias() == alias) {
    			found = true;
    			std::string errorMessage;
    			bool result = activeCollateralnode.StopCollateralNode(mne.getIp(), mne.getPrivKey(), errorMessage);

				statusObj.push_back(Pair("result", result ? "successful" : "failed"));
    			if(!result) {
   					statusObj.push_back(Pair("errorMessage", errorMessage));
   				}
    			break;
    		}
    	}

    	if(!found) {
    		statusObj.push_back(Pair("result", "failed"));
    		statusObj.push_back(Pair("errorMessage", "could not find alias in config. Verify with list-conf."));
    	}

    	pwalletMain->Lock();
    	return statusObj;
    }

    if (strCommand == "stop-many")
    {
    	if(pwalletMain->IsLocked()) {
			SecureString strWalletPass;
			strWalletPass.reserve(100);

			if (params.size() == 2){
				strWalletPass = params[1].get_str().c_str();
			} else {
				throw runtime_error(
				"Your wallet is locked, passphrase is required\n");
			}

			if(!pwalletMain->Unlock(strWalletPass)){
				return "incorrect passphrase";
			}
		}

		int total = 0;
		int successful = 0;
		int fail = 0;


		Object resultsObj;

		BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry mne, collateralnodeConfig.getEntries()) {
			total++;

			std::string errorMessage;
			bool result = activeCollateralnode.StopCollateralNode(mne.getIp(), mne.getPrivKey(), errorMessage);

			Object statusObj;
			statusObj.push_back(Pair("alias", mne.getAlias()));
			statusObj.push_back(Pair("result", result ? "successful" : "failed"));

			if(result) {
				successful++;
			} else {
				fail++;
				statusObj.push_back(Pair("errorMessage", errorMessage));
			}

			resultsObj.push_back(Pair("status", statusObj));
		}
		pwalletMain->Lock();

		Object returnObj;
		returnObj.push_back(Pair("overall", "Successfully stopped " + boost::lexical_cast<std::string>(successful) + " collateralnodes, failed to stop " +
				boost::lexical_cast<std::string>(fail) + ", total " + boost::lexical_cast<std::string>(total)));
		returnObj.push_back(Pair("detail", resultsObj));

		return returnObj;

    }

    if (strCommand == "list")
    {
        std::string strCommand = "active";

        if (params.size() == 2){
            strCommand = params[1].get_str().c_str();
        }

        if (strCommand != "active" && strCommand != "txid" && strCommand != "pubkey" && strCommand != "lastseen" && strCommand != "lastpaid" && strCommand != "activeseconds" && strCommand != "rank" && strCommand != "n" && strCommand != "full" && strCommand != "protocol"){
            throw runtime_error(
                "list supports 'active', 'txid', 'pubkey', 'lastseen', 'lastpaid', 'activeseconds', 'rank', 'n', 'protocol', 'full'\n");
        }

        Object obj;
        BOOST_FOREACH(CCollateralNode mn, vecCollateralnodes) {
            mn.Check();

            if(strCommand == "active"){
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int)mn.IsEnabled()));
            } else if (strCommand == "txid") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       mn.vin.prevout.hash.ToString().c_str()));
            } else if (strCommand == "pubkey") {
                CScript pubkey;
                pubkey =GetScriptForDestination(mn.pubkey.GetID());
                CTxDestination address1;
                ExtractDestination(pubkey, address1);
                CBitcoinAddress address2(address1);

                obj.push_back(Pair(mn.addr.ToString().c_str(),       address2.ToString().c_str()));
            } else if (strCommand == "protocol") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int64_t)mn.protocolVersion));
            } else if (strCommand == "n") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int64_t)mn.vin.prevout.n));
            } else if (strCommand == "lastpaid") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       mn.nBlockLastPaid));
            } else if (strCommand == "lastseen") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int64_t)mn.lastTimeSeen));
            } else if (strCommand == "activeseconds") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int64_t)(mn.lastTimeSeen - mn.now)));
            } else if (strCommand == "rank") {
                obj.push_back(Pair(mn.addr.ToString().c_str(),       (int)(GetCollateralnodeRank(mn, pindexBest))));
            }
			else if (strCommand == "full") {
                Object list;
                list.push_back(Pair("active",        (int)mn.IsEnabled()));
                list.push_back(Pair("txid",           mn.vin.prevout.hash.ToString().c_str()));
                list.push_back(Pair("n",       (int64_t)mn.vin.prevout.n));

                CScript pubkey;
                pubkey =GetScriptForDestination(mn.pubkey.GetID());
                CTxDestination address1;
                ExtractDestination(pubkey, address1);
                CBitcoinAddress address2(address1);

                list.push_back(Pair("pubkey",         address2.ToString().c_str()));
                list.push_back(Pair("protocolversion",       (int64_t)mn.protocolVersion));
                list.push_back(Pair("lastseen",       (int64_t)mn.lastTimeSeen));
                list.push_back(Pair("activeseconds",  (int64_t)(mn.lastTimeSeen - mn.now)));
                list.push_back(Pair("rank",           (int)(GetCollateralnodeRank(mn, pindexBest))));
                list.push_back(Pair("lastpaid",       mn.nBlockLastPaid));
                obj.push_back(Pair(mn.addr.ToString().c_str(), list));
            }
        }
        return obj;
    }
    if (strCommand == "count") return (int)vecCollateralnodes.size();

    if (strCommand == "start")
    {
        if(!fCollateralNode) return "you must set collateralnode=1 in the configuration";

        if(pwalletMain->IsLocked()) {
            SecureString strWalletPass;
            strWalletPass.reserve(100);

            if (params.size() == 2){
                strWalletPass = params[1].get_str().c_str();
            } else {
                throw runtime_error(
                    "Your wallet is locked, passphrase is required\n");
            }

            if(!pwalletMain->Unlock(strWalletPass)){
                return "incorrect passphrase";
            }
        }

        if(activeCollateralnode.status != COLLATERALSTAKE_REMOTELY_ENABLED && activeCollateralnode.status != COLLATERALSTAKE_IS_CAPABLE){
            activeCollateralnode.status = COLLATERALSTAKE_NOT_PROCESSED; // TODO: consider better way
            std::string errorMessage;
            activeCollateralnode.ManageStatus();
            pwalletMain->Lock();
        }

        if(activeCollateralnode.status == COLLATERALSTAKE_REMOTELY_ENABLED) return "collateralnode started remotely";
        if(activeCollateralnode.status == COLLATERALSTAKE_INPUT_TOO_NEW) return "collateralnode input must have at least 15 confirmations";
        if(activeCollateralnode.status == COLLATERALSTAKE_STOPPED) return "collateralnode is stopped";
        if(activeCollateralnode.status == COLLATERALSTAKE_IS_CAPABLE) return "successfully started collateralnode";
        if(activeCollateralnode.status == COLLATERALSTAKE_NOT_CAPABLE) return "not capable collateralnode: " + activeCollateralnode.notCapableReason;
        if(activeCollateralnode.status == COLLATERALSTAKE_SYNC_IN_PROCESS) return "sync in process. Must wait until client is synced to start.";

        return "unknown";
    }

    if (strCommand == "start-alias")
    {
	    if (params.size() < 2){
			throw runtime_error(
			"command needs at least 2 parameters\n");
	    }

	    std::string alias = params[1].get_str().c_str();

    	if(pwalletMain->IsLocked()) {
    		SecureString strWalletPass;
    	    strWalletPass.reserve(100);

			if (params.size() == 3){
				strWalletPass = params[2].get_str().c_str();
			} else {
				throw runtime_error(
				"Your wallet is locked, passphrase is required\n");
			}

			if(!pwalletMain->Unlock(strWalletPass)){
				return "incorrect passphrase";
			}
        }

    	bool found = false;

		Object statusObj;
		statusObj.push_back(Pair("alias", alias));

    	BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry mne, collateralnodeConfig.getEntries()) {
    		if(mne.getAlias() == alias) {
    			found = true;
    			std::string errorMessage;
    			bool result = activeCollateralnode.Register(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage);

    			statusObj.push_back(Pair("result", result ? "successful" : "failed"));
    			if(!result) {
					statusObj.push_back(Pair("errorMessage", errorMessage));
				}
    			break;
    		}
    	}

    	if(!found) {
    		statusObj.push_back(Pair("result", "failed"));
    		statusObj.push_back(Pair("errorMessage", "could not find alias in config. Verify with list-conf."));
    	}

    	pwalletMain->Lock();
    	return statusObj;

    }

    if (strCommand == "start-many")
    {
    	if(pwalletMain->IsLocked()) {
			SecureString strWalletPass;
			strWalletPass.reserve(100);

			if (params.size() == 2){
				strWalletPass = params[1].get_str().c_str();
			} else {
				throw runtime_error(
				"Your wallet is locked, passphrase is required\n");
			}

			if(!pwalletMain->Unlock(strWalletPass)){
				return "incorrect passphrase";
			}
		}

		std::vector<CCollateralnodeConfig::CCollateralnodeEntry> mnEntries;
		mnEntries = collateralnodeConfig.getEntries();

		int total = 0;
		int successful = 0;
		int fail = 0;

		Object resultsObj;

		BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry mne, collateralnodeConfig.getEntries()) {
			total++;

			std::string errorMessage;
			bool result = activeCollateralnode.Register(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage);

			Object statusObj;
			statusObj.push_back(Pair("alias", mne.getAlias()));
			statusObj.push_back(Pair("result", result ? "succesful" : "failed"));

			if(result) {
				successful++;
			} else {
				fail++;
				statusObj.push_back(Pair("errorMessage", errorMessage));
			}

			resultsObj.push_back(Pair("status", statusObj));
		}
		pwalletMain->Lock();

		Object returnObj;
		returnObj.push_back(Pair("overall", "Successfully started " + boost::lexical_cast<std::string>(successful) + " collateralnodes, failed to start " +
				boost::lexical_cast<std::string>(fail) + ", total " + boost::lexical_cast<std::string>(total)));
		returnObj.push_back(Pair("detail", resultsObj));

		return returnObj;
    }

    if (strCommand == "debug")
    {
        if(activeCollateralnode.status == COLLATERALSTAKE_REMOTELY_ENABLED) return "collateralnode started remotely";
        if(activeCollateralnode.status == COLLATERALSTAKE_INPUT_TOO_NEW) return "collateralnode input must have at least 15 confirmations";
        if(activeCollateralnode.status == COLLATERALSTAKE_IS_CAPABLE) return "successfully started collateralnode";
        if(activeCollateralnode.status == COLLATERALSTAKE_STOPPED) return "collateralnode is stopped";
        if(activeCollateralnode.status == COLLATERALSTAKE_NOT_CAPABLE) return "not capable collateralnode: " + activeCollateralnode.notCapableReason;
        if(activeCollateralnode.status == COLLATERALSTAKE_SYNC_IN_PROCESS) return "sync in process. Must wait until client is synced to start.";

        CTxIn vin = CTxIn();
        CPubKey pubkey = CScript();
        CKey key;
        bool found = activeCollateralnode.GetCollateralNodeVin(vin, pubkey, key);
        if(!found){
            return "Missing collateralnode input, please look at the documentation for instructions on collateralnode creation";
        } else {
            return "No problems were found";
        }
    }

    if (strCommand == "create")
    {

        return "Not implemented yet, please look at the documentation for instructions on collateralnode creation";
    }

    if (strCommand == "current")
    {
        int winner = GetCurrentCollateralNode(1);
        if(winner >= 0) {
            return vecCollateralnodes[winner].addr.ToString().c_str();
        }

        return "unknown";
    }

    if (strCommand == "genkey")
    {
		CKey secret;
		secret.MakeNewKey(false);
		return CBitcoinSecret(secret).ToString();
    }

    if (strCommand == "winners")
    {
        Object obj;

        for(int nHeight = pindexBest->nHeight-10; nHeight < pindexBest->nHeight+20; nHeight++)
        {
            CScript payee;
            if(collateralnodePayments.GetBlockPayee(nHeight, payee)){
                CTxDestination address1;
                ExtractDestination(payee, address1);
                CBitcoinAddress address2(address1);
                obj.push_back(Pair(boost::lexical_cast<std::string>(nHeight),       address2.ToString().c_str()));
            } else {
                obj.push_back(Pair(boost::lexical_cast<std::string>(nHeight),       ""));
            }
        }

        return obj;
    }

    if(strCommand == "enforce")
    {
        return (uint64_t)enforceCollateralnodePaymentsTime;
    }

    if(strCommand == "connect")
    {
        std::string strAddress = "";
        if (params.size() == 2){
            strAddress = params[1].get_str().c_str();
        } else {
            throw runtime_error(
                "Collateralnode address required\n");
        }

        CService addr = CService(strAddress);

        if(ConnectNode((CAddress)addr, NULL, true)){
            return "successfully connected";
        } else {
            return "error connecting";
        }
    }

    if(strCommand == "list-conf")
    {
    	std::vector<CCollateralnodeConfig::CCollateralnodeEntry> mnEntries;
    	mnEntries = collateralnodeConfig.getEntries();

        Object resultObj;

        BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry mne, collateralnodeConfig.getEntries()) {
    		Object mnObj;
    		mnObj.push_back(Pair("alias", mne.getAlias()));
    		mnObj.push_back(Pair("address", mne.getIp()));
    		mnObj.push_back(Pair("privateKey", mne.getPrivKey()));
    		mnObj.push_back(Pair("txHash", mne.getTxHash()));
    		mnObj.push_back(Pair("outputIndex", mne.getOutputIndex()));
    		resultObj.push_back(Pair("collateralnode", mnObj));
    	}

    	return resultObj;
    }

    if (strCommand == "outputs"){
        // Find possible candidates
        vector<COutput> possibleCoins = activeCollateralnode.SelectCoinsCollateralnode();

        Object obj;
        BOOST_FOREACH(COutput& out, possibleCoins) {
            obj.push_back(Pair(out.tx->GetHash().ToString().c_str(), boost::lexical_cast<std::string>(out.i)));
        }

        return obj;

    }

    if(strCommand == "status")
    {
        std::vector<CCollateralnodeConfig::CCollateralnodeEntry> mnEntries;
        mnEntries = collateralnodeConfig.getEntries();
        Object mnObj;

        CScript pubkey;
      pubkey = GetScriptForDestination(activeCollateralnode.pubKeyCollateralnode.GetID());
      CTxDestination address1;
      ExtractDestination(pubkey, address1);
      CBitcoinAddress address2(address1);
      if (activeCollateralnode.pubKeyCollateralnode.IsFullyValid()) {
            CScript pubkey;
            CTxDestination address1;
            std::string address = "";
            bool found = false;
            Object localObj;
            localObj.push_back(Pair("vin", activeCollateralnode.vin.ToString().c_str()));
            localObj.push_back(Pair("service", activeCollateralnode.service.ToString().c_str()));
            LOCK(cs_collateralnodes);
            BOOST_FOREACH(CCollateralNode& mn, vecCollateralnodes) {
                if (mn.vin == activeCollateralnode.vin) {
                    //int mnRank = GetCollateralnodeRank(mn, pindexBest);
                    pubkey = GetScriptForDestination(mn.pubkey.GetID());
                    ExtractDestination(pubkey, address1);
                    CBitcoinAddress address2(address1);
                    address = address2.ToString();
                    localObj.push_back(Pair("payment_address", address));
                    //localObj.push_back(Pair("rank", GetCollateralnodeRank(mn, pindexBest)));
                    localObj.push_back(Pair("network_status", mn.IsActive() ? "active" : "registered"));
                    if (mn.IsActive()) {
                        localObj.push_back(Pair("activetime",(mn.lastTimeSeen - mn.now)));

                      }
                          localObj.push_back(Pair("earnings", mn.payValue));
                          found = true;
                          break;
                      }
                  }
                  string reason;
                  if(activeCollateralnode.status == COLLATERALSTAKE_REMOTELY_ENABLED) reason = "collateralnode started remotely";
                  if(activeCollateralnode.status == COLLATERALSTAKE_INPUT_TOO_NEW) reason = "collateralnode input must have at least 15 confirmations";
                  if(activeCollateralnode.status == COLLATERALSTAKE_IS_CAPABLE) reason = "successfully started collateralnode";
                  if(activeCollateralnode.status == COLLATERALSTAKE_STOPPED) reason = "collateralnode is stopped";
                  if(activeCollateralnode.status == COLLATERALSTAKE_NOT_CAPABLE) reason = "not capable collateralnode: " + activeCollateralnode.notCapableReason;
                  if(activeCollateralnode.status == COLLATERALSTAKE_SYNC_IN_PROCESS) reason = "sync in process. Must wait until client is synced to start.";

                  if (!found) {
                      localObj.push_back(Pair("network_status", "unregistered"));
                      if (activeCollateralnode.status != 9 && activeCollateralnode.status != 7)
                      {
                          localObj.push_back(Pair("notCapableReason", reason));
                      }
            } else {
                localObj.push_back(Pair("local_status", reason));
            }

              //localObj.push_back(Pair("address", address2.ToString().c_str()));

              mnObj.push_back(Pair("local",localObj));
                } else {
                  Object localObj;
                  localObj.push_back(Pair("status", "unconfigured"));
                  mnObj.push_back(Pair("local",localObj));
                }

                BOOST_FOREACH(CCollateralnodeConfig::CCollateralnodeEntry& mne, collateralnodeConfig.getEntries()) {
                  Object remoteObj;
                  std::string address = mne.getIp();

                CTxIn vin;
                CTxDestination address1;
                CActiveCollateralnode amn;
                CPubKey pubKeyCollateralAddress;
                CKey keyCollateralAddress;
                CPubKey pubKeyCollateralnode;
                CKey keyCollateralnode;
                std::string errorMessage;
                std::string forTunaError;
                std::string vinError;

                if(!forTunaSigner.SetKey(mne.getPrivKey(), forTunaError, keyCollateralnode, pubKeyCollateralnode))
              {
                  errorMessage = forTunaError;
              }

              if (!amn.GetCollateralNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress, mne.getTxHash(), mne.getOutputIndex(), vinError))
          {
              errorMessage = vinError;
          }

          CScript pubkey = GetScriptForDestination(pubKeyCollateralAddress.GetID());
          ExtractDestination(pubkey, address1);
          CBitcoinAddress address2(address1);

          remoteObj.push_back(Pair("alias", mne.getAlias()));
          remoteObj.push_back(Pair("ipaddr", address));

          if(pwalletMain->IsLocked() || fWalletUnlockStakingOnly) {
              remoteObj.push_back(Pair("collateral", "Wallet is Locked"));
          } else {
              remoteObj.push_back(Pair("collateral", address2.ToString()));
          }
          //remoteObj.push_back(Pair("collateral", address2.ToString()));
          //remoteObj.push_back(Pair("collateral", CBitcoinAddress(mn->pubKeyCollateralAddress.GetID()).ToString()));

          bool mnfound = false;
          BOOST_FOREACH(CCollateralNode& mn, vecCollateralnodes)
          {
              if (mn.addr.ToString() == mne.getIp()) {
                  remoteObj.push_back(Pair("status", "online"));
                  remoteObj.push_back(Pair("lastpaidblock",mn.nBlockLastPaid));
                  remoteObj.push_back(Pair("version",mn.protocolVersion));
                  mnfound = true;
                  break;
                }
              }
          if (!mnfound)
          {
              if (!errorMessage.empty()) {
                  remoteObj.push_back(Pair("status", "error"));
                  remoteObj.push_back(Pair("error", errorMessage));
              } else {
                  remoteObj.push_back(Pair("status", "notfound"));
                }
            }
            mnObj.push_back(Pair(mne.getAlias(),remoteObj));
       }
            return mnObj;
    }


    return Value::null;
}
