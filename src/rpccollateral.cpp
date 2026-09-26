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
#include "txdb.h"
#include "wallet.h"

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
    obj.push_back(Pair("state",        colLateralPool.GetState()));
    obj.push_back(Pair("entries",      colLateralPool.GetEntriesCount()));
    obj.push_back(Pair("entries_accepted",      colLateralPool.GetCountEntriesAccepted()));
    return obj;
}

extern uint8_t PrivacyVNextNetworkIdForWallet();

namespace
{

const char* PrivacyVNextProvenanceName(int nProvenance)
{
    switch (nProvenance)
    {
    case IV5_NOTE_SELF_TRANSFER:     return "A: own mask-7 transfer";
    case IV5_NOTE_RECEIVED_TRANSFER: return "B: received mask-7 transfer";
    case IV5_NOTE_DISCLOSED_TRANSFER:return "C: transfer with a disclosure";
    case IV5_NOTE_SHIELD_FUNDED:     return "D: shield-funded";
    default:                         return "unknown funding transaction";
    }
}

// What an observer actually learns, not how private it "feels".
const char* PrivacyVNextProvenanceCaveat(int nProvenance)
{
    switch (nProvenance)
    {
    case IV5_NOTE_SELF_TRANSFER:
        return "the transaction that created this note discloses nothing; only the gap "
               "between it and this registration is visible";
    case IV5_NOTE_RECEIVED_TRANSFER:
        return "the chain shows nothing, but whoever sent this note knows its amount and "
               "timing and can link this collateralnode to it";
    case IV5_NOTE_DISCLOSED_TRANSFER:
        return "the transaction that created this note disclosed its amount or receiver; "
               "anyone reading it can link this collateralnode to that transaction";
    case IV5_NOTE_SHIELD_FUNDED:
        return "a shield declares its transparent inputs and a public +25000 balance, so "
               "this collateralnode is linked to the coins that funded it, permanently "
               "and for anyone";
    default:
        return "the funding transaction could not be read here, so what it disclosed is "
               "unknown";
    }
}

Object PrivacyVNextCandidateObject(const CPrivacyVNextCollateralCandidate& c)
{
    Object obj;
    obj.push_back(Pair("note", c.note.txhash.ToString() + ":" +
                                   boost::lexical_cast<std::string>(
                                       (int)c.note.nOutputIndex)));
    obj.push_back(Pair("funding_txid", c.note.txhash.ToString()));
    obj.push_back(Pair("class", PrivacyVNextProvenanceName(c.nProvenance)));
    obj.push_back(Pair("caveat", PrivacyVNextProvenanceCaveat(c.nProvenance)));
    obj.push_back(Pair("funded_at_height", c.note.nHeight));
    obj.push_back(Pair("age_blocks", c.nAgeBlocks));
    obj.push_back(Pair("key_image", c.keyImage.ToString()));
    obj.push_back(Pair("default_choice",
                       c.nProvenance != IV5_NOTE_SHIELD_FUNDED));
    return obj;
}

// The remedy the operator must be handed, because refusing without naming the safe path
// pushes them into `z_shield 25000`, which is the worst flow available.
const char* kNoCandidateRemedy =
    "No IV5 note of exactly 25000 INN can be attested right now.\n"
    "Carve one with a self-transfer from notes you already hold:\n"
    "    z_iv5transfer <one of your own IV5 addresses> 25000\n"
    "The wallet's default disclosure mask is 7, which discloses nothing, and the "
    "transfer costs MIN_TX_FEE_SHIELDED on top. Wait for the epoch holding the new note "
    "to finalize, then run this command again.\n"
    "Do NOT shield exactly 25000 in one step: a shield's transparent inputs and its "
    "+25000 balance are both public, so that flow links this collateralnode to your "
    "identified coins permanently. Fund the pool with amounts other than 25000, let them "
    "settle, then carve the collateral note.";

// strAddr of a held record written by the retired finality-member verb. Such a
// record has no endpoint, so the collateralnode verbs skip it.
const char* kFinalityMemberMarker = "iv5-finality-member";

void RequirePrivacyVNextReady()
{
    if (pwalletMain == NULL)
        throw runtime_error("no wallet is loaded");
    const int nCandidateHeight =
        nBestHeight == std::numeric_limits<int>::max() ? nBestHeight
                                                       : nBestHeight + 1;
    if (!IsBoundaryBActiveAtHeight(nCandidateHeight) ||
        !IsShieldedVNextConsensusReady())
        throw runtime_error("privacy vNext is not active on this network yet");
}

// pubkey2: the identity the registration context binds, and the only thing a peer can
// check an announcement against.
CPubKey RequireCollateralnodeKey(CKey& keyOut)
{
    if (strCollateralNodePrivKey.empty())
        throw runtime_error(
            "collateralnodeprivkey is not set; generate one with "
            "'collateralnode genkey' and put it in innova.conf");
    std::string strError;
    CPubKey pubkey;
    if (!colLateralSigner.SetKey(strCollateralNodePrivKey, strError, keyOut,
                                 pubkey))
        throw runtime_error("collateralnodeprivkey is unusable: " + strError);
    return pubkey;
}

CService RequireCollateralnodeEndpoint(const std::string& strEndpoint)
{
    const CService service(strEndpoint, GetDefaultPort());
    if (!service.IsValid())
        throw runtime_error("endpoint is not a usable address: " + strEndpoint);
    const unsigned short nPinned = fTestNet ? 15539 : 14539;
    if (service.GetPort() != nPinned)
        throw runtime_error(strprintf(
            "announcements are pinned to port %d; peers drop any other port",
            (int)nPinned));
    return service;
}

void RequirePoolPayout(const std::string& strPoolPayout)
{
    if (strPoolPayout.size() > MAX_POOL_PAYOUT_CHARS)
        throw runtime_error("pool payout address is too long");
    PrivacyVNextAddressComponents components;
    std::string strError;
    if (!DecodePrivacyVNextAddress(strPoolPayout, PrivacyVNextNetworkIdForWallet(),
                                   components, strError))
        throw runtime_error("pool payout is not an IV5 address for this network: " +
                            strError);
}

// Chain state for one key image, read live. Registration is derived, never cached: a
// reorg that disconnects the attestation must flip the answer with it.
Object PrivacyVNextChainLayer(const uint256& keyImage)
{
    Object obj;
    CTxDB txdb("r");
    CPrivacyVNextCollateralAttestation attested;
    const TxDBReadStatus watchStatus =
        txdb.ReadPrivacyVNextCollateralStatus(keyImage, attested);
    CPrivacyVNextNullifierSpent spent;
    const TxDBReadStatus spentStatus =
        txdb.ReadPrivacyVNextNullifierStatus(keyImage, spent);

    obj.push_back(Pair("attested", watchStatus == TXDB_READ_FOUND));
    if (watchStatus == TXDB_READ_FOUND)
    {
        obj.push_back(Pair("attestation_txid", attested.txnHash.ToString()));
        obj.push_back(Pair("attestation_height", (int)attested.nHeight));
        const int nConfirms = nBestHeight - attested.nHeight + 1;
        obj.push_back(Pair("confirmations", nConfirms));
        obj.push_back(Pair("confirmations_required",
                           COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY));
        obj.push_back(Pair("context_digest", attested.contextDigest.ToString()));
    }
    obj.push_back(Pair("spent", spentStatus == TXDB_READ_FOUND));
    obj.push_back(Pair("registered", watchStatus == TXDB_READ_FOUND &&
                                         spentStatus != TXDB_READ_FOUND));
    if (watchStatus == TXDB_READ_FOUND && spentStatus == TXDB_READ_FOUND)
        obj.push_back(Pair("note",
                           "this key image is retired: the watch record survives the "
                           "spend, so it can never be registered again"));
    {
        LOCK(mempool.cs);
        obj.push_back(Pair("attestation_pending",
                           mempool.mapPrivacyVNextAttestation.count(keyImage) != 0));
        obj.push_back(Pair("spend_pending",
                           mempool.mapPrivacyVNextNullifier.count(keyImage) != 0));
    }
    return obj;
}

} // namespace

Value collateralnode(const Array& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp  ||
        (strCommand != "start" && strCommand != "start-alias" && strCommand != "start-many" && strCommand != "stop" && strCommand != "stop-alias" && strCommand != "stop-many" && strCommand != "list" && strCommand != "list-conf" && strCommand != "count"  && strCommand != "enforce"
            && strCommand != "debug" && strCommand != "current" && strCommand != "winners" && strCommand != "genkey" && strCommand != "connect" && strCommand != "outputs" && strCommand != "status"
            && strCommand != "collateral-notes" && strCommand != "registerprivate" && strCommand != "announceprivate" && strCommand != "releaseprivate" && strCommand != "statusprivate"))
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
			"  collateral-notes  - List IV5 notes that could back a private registration\n"
			"  registerprivate   - Attest a 25000 INN IV5 note as collateral (dry run unless confirmed)\n"
			"  announceprivate   - Announce a confirmed private registration to peers\n"
			"  releaseprivate    - Release a held collateral note back to ordinary spending\n"
			"  statusprivate     - Chain, local-list and payment view of a private registration\n"
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

        if(activeCollateralnode.status == COLLATERALNODE_STOPPED) return "Successfully Stopped Collateralnode";
        if(activeCollateralnode.status == COLLATERALNODE_NOT_CAPABLE) return "Not a capable Collateralnode";

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

    	for (CCollateralnodeConfig::CCollateralnodeEntry mne : collateralnodeConfig.getEntries()) {
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
        for (CCollateralNode mn : vecCollateralnodes) {
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
                list.push_back(Pair("active",        (int)mn.IsActive()));
                list.push_back(Pair("txid",           mn.vin.prevout.hash.ToString().c_str()));
                list.push_back(Pair("n",       (int64_t)mn.vin.prevout.n));
				list.push_back(Pair("ip",       		mn.addr.ToString().c_str()));

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
        if(!fCollateralNode) return "You must set collateralnode=1 in your innova.conf";

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

        if(activeCollateralnode.status != COLLATERALNODE_REMOTELY_ENABLED && activeCollateralnode.status != COLLATERALNODE_IS_CAPABLE){
            activeCollateralnode.ResetStatus();
            std::string errorMessage;
            activeCollateralnode.ManageStatus();
            pwalletMain->Lock();
        }

        if(activeCollateralnode.status == COLLATERALNODE_REMOTELY_ENABLED) return "collateralnode started remotely";
        if(activeCollateralnode.status == COLLATERALNODE_INPUT_TOO_NEW) return "collateralnode input must have at least 15 confirmations";
        if(activeCollateralnode.status == COLLATERALNODE_STOPPED) return "collateralnode is stopped";
        if(activeCollateralnode.status == COLLATERALNODE_IS_CAPABLE) return "successfully started collateralnode";
        if(activeCollateralnode.status == COLLATERALNODE_NOT_CAPABLE) return "not capable collateralnode: " + activeCollateralnode.notCapableReason;
        if(activeCollateralnode.status == COLLATERALNODE_SYNC_IN_PROCESS) return "sync in process. Must wait until client is synced to start.";

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
        if(activeCollateralnode.status == COLLATERALNODE_REMOTELY_ENABLED) return "collateralnode started remotely";
        if(activeCollateralnode.status == COLLATERALNODE_INPUT_TOO_NEW) return "collateralnode input must have at least 15 confirmations";
        if(activeCollateralnode.status == COLLATERALNODE_IS_CAPABLE) return "successfully started collateralnode";
        if(activeCollateralnode.status == COLLATERALNODE_STOPPED) return "collateralnode is stopped";
        if(activeCollateralnode.status == COLLATERALNODE_NOT_CAPABLE) return "not capable collateralnode: " + activeCollateralnode.notCapableReason;
        if(activeCollateralnode.status == COLLATERALNODE_SYNC_IN_PROCESS) return "sync in process. Must wait until client is synced to start.";

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

    if (strCommand == "collateral-notes")
    {
        RequirePrivacyVNextReady();
        std::vector<CPrivacyVNextCollateralCandidate> vCandidates;
        std::string strError;
        // No usable anchor is one more way to have no candidate, and the operator needs
        // the same remedy either way rather than a bare anchor message.
        if (!pwalletMain->ListPrivacyVNextCollateralCandidates(vCandidates,
                                                               strError))
            throw runtime_error(strError + "\n" + kNoCandidateRemedy);

        Object obj;
        Array arr;
        for (size_t i = 0; i < vCandidates.size(); ++i)
            arr.push_back(PrivacyVNextCandidateObject(vCandidates[i]));
        obj.push_back(Pair("candidates", arr));
        if (vCandidates.empty())
            obj.push_back(Pair("remedy", std::string(kNoCandidateRemedy)));
        obj.push_back(Pair("note",
                           "the wallet cannot see who else knows a note; if one came "
                           "from an exchange or a payer, name a different one "
                           "explicitly"));
        return obj;
    }

    if (strCommand == "registerprivate")
    {
        if (params.size() < 3 || params.size() > 5)
            throw runtime_error(
                "collateralnode registerprivate <endpoint> <iv5payout> "
                "[txhash:index] [confirm]\n"
                "Attests one 25000 INN IV5 note as this node's collateral.\n"
                "Prints a preview and changes nothing unless the last argument is "
                "the literal word 'confirm'.");

        RequirePrivacyVNextReady();
        if (pwalletMain->IsLocked())
            throw runtime_error("the wallet is locked; run walletpassphrase first");
        if (!pwalletMain->HasPrivacyVNextSeed())
            throw runtime_error("this wallet has no IV5 seed; run z_createiv5seed");
        if (!pwalletMain->IsPrivacyVNextSeedUnlocked())
            throw runtime_error("the IV5 seed is locked; run walletpassphrase first");

        CKey keyCollateralnode;
        const CPubKey pubkey2 = RequireCollateralnodeKey(keyCollateralnode);
        const CService service = RequireCollateralnodeEndpoint(params[1].get_str());
        const std::string strPoolPayout = params[2].get_str();
        RequirePoolPayout(strPoolPayout);

        std::string strChosen;
        bool fConfirm = false;
        for (size_t i = 3; i < params.size(); ++i)
        {
            const std::string strArg = params[i].get_str();
            if (strArg == "confirm")
                fConfirm = true;
            else
                strChosen = strArg;
        }

        std::vector<CPrivacyVNextCollateralCandidate> vCandidates;
        std::string strError;
        if (!pwalletMain->ListPrivacyVNextCollateralCandidates(vCandidates,
                                                               strError))
            throw runtime_error(strError + "\n" + kNoCandidateRemedy);
        if (vCandidates.empty())
            throw runtime_error(kNoCandidateRemedy);

        const CPrivacyVNextCollateralCandidate* pChosen = NULL;
        if (!strChosen.empty())
        {
            for (size_t i = 0; i < vCandidates.size(); ++i)
            {
                const std::string strName =
                    vCandidates[i].note.txhash.ToString() + ":" +
                    boost::lexical_cast<std::string>(
                        (int)vCandidates[i].note.nOutputIndex);
                if (strName == strChosen)
                    pChosen = &vCandidates[i];
            }
            if (pChosen == NULL)
                throw runtime_error(
                    "no attestable 25000 INN note matches " + strChosen +
                    "; 'collateralnode collateral-notes' lists the candidates");
        }
        else
        {
            // Shield-funded is never the default: its linkage is certain rather than
            // probabilistic, and the key image it publishes is permanent.
            if (vCandidates[0].nProvenance == IV5_NOTE_SHIELD_FUNDED)
                throw runtime_error(
                    std::string("Every attestable note here is shield-funded. ") +
                    PrivacyVNextProvenanceCaveat(IV5_NOTE_SHIELD_FUNDED) + ".\n" +
                    kNoCandidateRemedy +
                    "\nTo use a shield-funded note anyway, name it explicitly as "
                    "<txhash>:<index>.");
            pChosen = &vCandidates[0];
        }

        // The context digest binds the announce key, so it cannot be computed until
        // that key exists -- which is on the confirm path below. A dry run therefore
        // reports the inputs rather than a digest it could not reproduce.
        Object obj;
        obj.push_back(Pair("endpoint", service.ToString()));
        obj.push_back(Pair("collateralnode_pubkey", HexStr(pubkey2.Raw())));
        obj.push_back(Pair("pool_payout", strPoolPayout));
        obj.push_back(Pair("chosen_note", PrivacyVNextCandidateObject(*pChosen)));
        obj.push_back(Pair("override_syntax",
                           "pass <txhash>:<index> to name a different note"));
        Array warnings;
        warnings.push_back(std::string(
            "the key image this publishes is public forever, and the chain keeps its "
            "watch record even after the note is spent: this note can be registered "
            "exactly once, ever"));
        warnings.push_back(std::string(
            "the endpoint, collateralnodeprivkey and pool payout above are bound into "
            "the attestation and can never change for this note; changing any of them "
            "later makes every announcement fail on peers"));
        warnings.push_back(std::string(
            "rotating any of them means spending this note, carving a fresh one, "
            "attesting again and waiting out finality plus 15 confirmations"));
        warnings.push_back(std::string(
            "until rewards are paid as notes, a winning collateralnode is paid "
            "transparently to the announce address, not to the pool payout address"));
        warnings.push_back(std::string(
            PrivacyVNextProvenanceCaveat(pChosen->nProvenance)));
        warnings.push_back(std::string(
            "binding an onion endpoint does not anonymize this node's peer-to-peer "
            "traffic; only running the daemon behind Tor does"));
        obj.push_back(Pair("warnings", warnings));

        if (!fConfirm)
        {
            obj.push_back(Pair("dry_run", true));
            obj.push_back(Pair("to_proceed",
                               "re-run with 'confirm' as the last argument"));
            return obj;
        }

        // The announce key signs the isee and is where a winning node is paid today.
        CPubKey pubkeyAnnounce;
        if (!pwalletMain->GetKeyFromPool(pubkeyAnnounce, false))
            throw runtime_error("the key pool is empty; run keypoolrefill");
        CKey keyAnnounce;
        if (!pwalletMain->GetKey(pubkeyAnnounce.GetID(), keyAnnounce))
            throw runtime_error("could not read the announce key back from the wallet");

        // Bind the key a winner is paid at, so this attestation cannot be re-announced
        // with someone else's payee.
        const uint256 hashContext = GetCollateralnodeRegistrationContext(
            pubkey2, service, strPoolPayout, pubkeyAnnounce);
        obj.push_back(Pair("context_digest", hashContext.ToString()));
        obj.push_back(Pair("announce_pubkey", HexStr(pubkeyAnnounce.Raw())));

        CWalletTx wtx;
        uint256 keyImage = 0;
        if (!pwalletMain->CreatePrivacyVNextCollateralAttestation(
                pChosen->note, hashContext, false, wtx, keyImage, strError))
            throw runtime_error(strError);

        // Proving took seconds. Anything that retired the note in the meantime makes
        // this transaction unconnectable, so re-read all four sources before broadcast.
        {
            CTxDB txdb("r");
            CPrivacyVNextNullifierSpent spent;
            if (txdb.ReadPrivacyVNextNullifierStatus(keyImage, spent) !=
                TXDB_READ_NOT_FOUND)
                throw runtime_error("the note was spent while the proof was being "
                                    "built; nothing was broadcast");
            CPrivacyVNextCollateralAttestation attested;
            if (txdb.ReadPrivacyVNextCollateralStatus(keyImage, attested) !=
                TXDB_READ_NOT_FOUND)
                throw runtime_error("this note was attested while the proof was being "
                                    "built; nothing was broadcast");
            LOCK(mempool.cs);
            if (mempool.mapPrivacyVNextNullifier.count(keyImage) ||
                mempool.mapPrivacyVNextAttestation.count(keyImage))
                throw runtime_error("a transaction naming this note is already in the "
                                    "mempool; nothing was broadcast");
        }

        CPrivacyVNextCollateralRegistration record;
        record.keyImage = keyImage;
        record.fundingTxHash = pChosen->note.txhash;
        record.nFundingOutputIndex = pChosen->note.nOutputIndex;
        record.hashContext = hashContext;
        record.vchCollateralPubKey = pubkey2.Raw();
        record.announceKeyId = pubkeyAnnounce.GetID();
        record.strAddr = service.ToString();
        record.strPoolPayout = strPoolPayout;
        record.nTimeCreated = GetAdjustedTime();
        // Persisted before the broadcast: a wallet that dies between the two must come
        // back holding the note, not offering it to the next transfer.
        if (!pwalletMain->AddPrivacyVNextCollateralRegistration(record, strError))
            throw runtime_error(strError);

        CReserveKey reservekey(pwalletMain);
        if (!pwalletMain->CommitTransaction(wtx, reservekey))
        {
            std::string strReleaseError;
            pwalletMain->ReleasePrivacyVNextCollateralRegistration(keyImage,
                                                                   strReleaseError);
            throw runtime_error("the attestation was built but could not be committed");
        }
        if (!pwalletMain->SetPrivacyVNextCollateralAttestationTx(
                keyImage, wtx.GetHash(), strError))
            throw runtime_error(strError);

        obj.push_back(Pair("dry_run", false));
        obj.push_back(Pair("key_image", keyImage.ToString()));
        obj.push_back(Pair("attestation_txid", wtx.GetHash().ToString()));
        obj.push_back(Pair("next",
                           strprintf("wait for %d confirmations, then run "
                                     "'collateralnode announceprivate'",
                                     COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY)));
        return obj;
    }

    if (strCommand == "announceprivate")
    {
        RequirePrivacyVNextReady();
        if (pwalletMain->IsLocked())
            throw runtime_error("the wallet is locked; run walletpassphrase first");

        std::vector<CPrivacyVNextCollateralRegistration> vRecords;
        pwalletMain->ListPrivacyVNextCollateralRegistrations(vRecords);
        if (vRecords.empty())
            throw runtime_error("this wallet holds no private collateral registration");

        Array arr;
        for (size_t i = 0; i < vRecords.size(); ++i)
        {
            const CPrivacyVNextCollateralRegistration& record = vRecords[i];
            if (record.strAddr == kFinalityMemberMarker)
                continue;
            Object one;
            one.push_back(Pair("key_image", record.keyImage.ToString()));

            CTxDB txdb("r");
            CPrivacyVNextCollateralAttestation attested;
            bool fLocalFailure = false;
            if (!IsPrivacyVNextCollateralRegistered(txdb, record.keyImage, attested,
                                                    fLocalFailure))
            {
                one.push_back(Pair("status",
                                   "not registered on chain yet, or already spent"));
                arr.push_back(one);
                continue;
            }
            // Peers refuse an attested announcement until the attestation is this deep,
            // and the announcement is one-shot: too early means nobody carries it.
            const int nConfirms = nBestHeight - attested.nHeight + 1;
            if (nConfirms < COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY)
            {
                one.push_back(Pair("status",
                                   strprintf("waiting: %d of %d confirmations",
                                             nConfirms,
                                             COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY)));
                arr.push_back(one);
                continue;
            }

            CKey keyCollateralnode;
            const CPubKey pubkey2 = RequireCollateralnodeKey(keyCollateralnode);
            CPubKey pubkeyBoundPayee;
            pwalletMain->GetPubKey(record.announceKeyId, pubkeyBoundPayee);
            if (attested.contextDigest !=
                GetCollateralnodeRegistrationContext(pubkey2,
                                                     CService(record.strAddr),
                                                     record.strPoolPayout,
                                                     pubkeyBoundPayee))
            {
                one.push_back(Pair("status",
                                   "the current configuration no longer hashes to the "
                                   "attested context; peers would reject every "
                                   "announcement"));
                arr.push_back(one);
                continue;
            }

            CKey keyAnnounce;
            if (!pwalletMain->GetKey(CKeyID(record.announceKeyId), keyAnnounce))
            {
                one.push_back(Pair("status",
                                   "the announce key is missing from this wallet"));
                arr.push_back(one);
                continue;
            }
            const CPubKey pubkeyAnnounce = keyAnnounce.GetPubKey();

            std::string strError;
            const CTxIn vin(COutPoint(record.keyImage, 0));
            if (!activeCollateralnode.Register(vin, CService(record.strAddr),
                                               keyAnnounce, pubkeyAnnounce,
                                               keyCollateralnode, pubkey2, strError,
                                               record.keyImage,
                                               record.strPoolPayout))
            {
                one.push_back(Pair("status", "announce failed: " + strError));
            }
            else
            {
                // Adopt the entry as this node's active registration, or the ping loop
                // never claims it and peers drop the node when it expires.
                activeCollateralnode.vin = vin;
                activeCollateralnode.service = CService(record.strAddr);
                activeCollateralnode.status = COLLATERALNODE_IS_CAPABLE;
                activeCollateralnode.notCapableReason.clear();
                one.push_back(Pair("status", "announced and relayed"));
            }
            arr.push_back(one);
        }
        Object obj;
        obj.push_back(Pair("registrations", arr));
        obj.push_back(Pair("note",
                           "relaying an announcement is the only measurable fact here; "
                           "no node can observe another node's list"));
        return obj;
    }

    if (strCommand == "releaseprivate")
    {
        if (params.size() != 2)
            throw runtime_error(
                "collateralnode releaseprivate <keyimage>\n"
                "Releases a held collateral note back to ordinary spending.\n"
                "This is the deliberate deregistration path: the next spend that takes "
                "the note deregisters this collateralnode, and because the chain keeps "
                "the watch record forever, that key image can never be registered "
                "again.");
        if (pwalletMain == NULL)
            throw runtime_error("no wallet is loaded");

        const uint256 keyImage(params[1].get_str());
        std::string strError;
        if (!pwalletMain->ReleasePrivacyVNextCollateralRegistration(keyImage,
                                                                    strError))
            throw runtime_error(strError);

        Object obj;
        obj.push_back(Pair("released", keyImage.ToString()));
        obj.push_back(Pair("warning",
                           "the note is now an ordinary spendable note; spending it "
                           "deregisters this collateralnode and retires this key image "
                           "for registration permanently"));
        return obj;
    }

    if (strCommand == "statusprivate")
    {
        if (pwalletMain == NULL)
            throw runtime_error("no wallet is loaded");

        std::vector<CPrivacyVNextCollateralRegistration> vRecords;
        pwalletMain->ListPrivacyVNextCollateralRegistrations(vRecords);

        Array arr;
        for (size_t i = 0; i < vRecords.size(); ++i)
        {
            const CPrivacyVNextCollateralRegistration& record = vRecords[i];
            Object one;
            one.push_back(Pair("key_image", record.keyImage.ToString()));
            one.push_back(Pair("funding_txid", record.fundingTxHash.ToString()));
            const Object chain = PrivacyVNextChainLayer(record.keyImage);
            one.push_back(Pair("chain", chain));
            // An attestation whose anchor aged out of the finalized window is evicted
            // and can never connect again, so rebroadcasting it loops forever: the way
            // back is a fresh proof at a fresh anchor.
            if (record.attestationTxHash != 0)
            {
                CTxDB txdb("r");
                CPrivacyVNextCollateralAttestation attested;
                const bool fOnChain =
                    txdb.ReadPrivacyVNextCollateralStatus(record.keyImage,
                                                          attested) ==
                    TXDB_READ_FOUND;
                bool fPending = false;
                {
                    LOCK(mempool.cs);
                    fPending =
                        mempool.mapPrivacyVNextAttestation.count(record.keyImage) != 0;
                }
                if (!fOnChain && !fPending)
                    one.push_back(Pair(
                        "next",
                        "the attestation is neither confirmed nor pending; its anchor "
                        "has most likely aged out. Rebroadcasting it can never connect: "
                        "run 'collateralnode releaseprivate' for this key image and "
                        "register again, which builds a fresh proof at a fresh anchor"));
            }

            Object bound;
            bound.push_back(Pair("endpoint", record.strAddr));
            bound.push_back(Pair("pool_payout", record.strPoolPayout));
            bound.push_back(Pair("context_digest", record.hashContext.ToString()));
            // A confirmed wrong context is the only irreversible mistake here, so the
            // current configuration is re-hashed and compared every time.
            if (!strCollateralNodePrivKey.empty())
            {
                std::string strKeyError;
                CKey keyCollateralnode;
                CPubKey pubkey2;
                if (colLateralSigner.SetKey(strCollateralNodePrivKey, strKeyError,
                                            keyCollateralnode, pubkey2))
                {
                    CPubKey pubkeyAnnounce;
                    pwalletMain->GetPubKey(record.announceKeyId, pubkeyAnnounce);
                    const uint256 hashNow = GetCollateralnodeRegistrationContext(
                        pubkey2, CService(record.strAddr), record.strPoolPayout,
                        pubkeyAnnounce);
                    bound.push_back(Pair("current_config_digest",
                                         hashNow.ToString()));
                    bound.push_back(Pair("config_matches",
                                         hashNow == record.hashContext));
                    if (hashNow != record.hashContext)
                        bound.push_back(Pair(
                            "drift",
                            "the collateralnodeprivkey, endpoint or payout has changed "
                            "since this attestation; peers will reject every "
                            "announcement and the only fix is a fresh note"));
                }
            }
            one.push_back(Pair("bound", bound));

            Object local;
            const CTxIn vin(COutPoint(record.keyImage, 0));
            bool fFound = false;
            {
                LOCK(cs_collateralnodes);
                for (size_t n = 0; n < vecCollateralnodes.size(); ++n)
                {
                    if (!(vecCollateralnodes[n].vin == vin))
                        continue;
                    fFound = true;
                    local.push_back(Pair("last_seen",
                                         (int64_t)vecCollateralnodes[n].lastTimeSeen));
                    local.push_back(Pair("status", vecCollateralnodes[n].status));
                    local.push_back(Pair("enabled",
                                         (int)vecCollateralnodes[n].enabled));
                    break;
                }
            }
            local.push_back(Pair("present", fFound));
            local.push_back(Pair("scope",
                                 "this node's own list; it says nothing about what any "
                                 "peer holds"));
            one.push_back(Pair("local_list", local));

            Object payments;
            CKey keyAnnounce;
            if (pwalletMain->GetKey(CKeyID(record.announceKeyId), keyAnnounce))
            {
                const CBitcoinAddress address(CKeyID(record.announceKeyId));
                payments.push_back(Pair("announce_address", address.ToString()));
            }
            payments.push_back(Pair("paid_to",
                                    "the announce address, transparently"));
            payments.push_back(Pair("pool_payout_status",
                                    "bound and gossiped, but nothing is paid to it "
                                    "until rewards are paid as notes"));
            payments.push_back(Pair("note",
                                    "payment requires winning the ranking, so long gaps "
                                    "with no payment are expected and are not a health "
                                    "signal"));
            one.push_back(Pair("payments", payments));
            arr.push_back(one);
        }

        Object obj;
        obj.push_back(Pair("registrations", arr));
        obj.push_back(Pair("held_balance",
                           ValueFromAmount(
                               pwalletMain->GetPrivacyVNextCollateralBalance())));
        return obj;
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
                if(activeCollateralnode.status == COLLATERALNODE_REMOTELY_ENABLED) reason = "collateralnode started remotely";
                if(activeCollateralnode.status == COLLATERALNODE_INPUT_TOO_NEW) reason = "collateralnode input must have at least 15 confirmations";
                if(activeCollateralnode.status == COLLATERALNODE_IS_CAPABLE) reason = "successfully started collateralnode";
                if(activeCollateralnode.status == COLLATERALNODE_STOPPED) reason = "collateralnode is stopped";
                if(activeCollateralnode.status == COLLATERALNODE_NOT_CAPABLE) reason = "not capable collateralnode: " + activeCollateralnode.notCapableReason;
                if(activeCollateralnode.status == COLLATERALNODE_SYNC_IN_PROCESS) reason = "sync in process. Must wait until client is synced to start.";

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

            for (CCollateralnodeConfig::CCollateralnodeEntry& mne : collateralnodeConfig.getEntries()) {
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
                std::string colLateralError;
                std::string vinError;

				mnTxHash.SetHex(mne.getTxHash());
				outputIndex = boost::lexical_cast<unsigned int>(mne.getOutputIndex());
				COutPoint outpoint = COutPoint(mnTxHash, outputIndex);

                if(!colLateralSigner.SetKey(mne.getPrivKey(), colLateralError, keyCollateralnode, pubKeyCollateralnode))
                {
                    errorMessage = colLateralError;
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
				//remoteObj.push_back(Pair("collateral", CBitcoinAddress(mne->pubKeyCollateralAddress.GetID()).ToString()));

                // INNOVA - Q0lSQ1VJVEJSRUFLRVI=

                bool mnfound = false;
                for (CCollateralNode& mn : vecCollateralnodes)
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

        if(activeCollateralnode.status == COLLATERALNODE_STOPPED) return "Successfully Stopped Collateralnode";
        if(activeCollateralnode.status == COLLATERALNODE_NOT_CAPABLE) return "Not a capable Collateralnode";

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
                list.push_back(Pair("active",             (int)mn.IsEnabled()));
                list.push_back(Pair("txid",               mn.vin.prevout.hash.ToString().c_str()));
                list.push_back(Pair("n",                  (int64_t)mn.vin.prevout.n));
                //list.push_back(Pair("ip",               mn.addr.ToString().c_str()));

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

        if(activeCollateralnode.status != COLLATERALNODE_REMOTELY_ENABLED && activeCollateralnode.status != COLLATERALNODE_IS_CAPABLE){
            activeCollateralnode.ResetStatus();
            std::string errorMessage;
            activeCollateralnode.ManageStatus();
            pwalletMain->Lock();
        }

        if(activeCollateralnode.status == COLLATERALNODE_REMOTELY_ENABLED) return "collateralnode started remotely";
        if(activeCollateralnode.status == COLLATERALNODE_INPUT_TOO_NEW) return "collateralnode input must have at least 15 confirmations";
        if(activeCollateralnode.status == COLLATERALNODE_STOPPED) return "collateralnode is stopped";
        if(activeCollateralnode.status == COLLATERALNODE_IS_CAPABLE) return "successfully started collateralnode";
        if(activeCollateralnode.status == COLLATERALNODE_NOT_CAPABLE) return "not capable collateralnode: " + activeCollateralnode.notCapableReason;
        if(activeCollateralnode.status == COLLATERALNODE_SYNC_IN_PROCESS) return "sync in process. Must wait until client is synced to start.";

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
        if(activeCollateralnode.status == COLLATERALNODE_REMOTELY_ENABLED) return "collateralnode started remotely";
        if(activeCollateralnode.status == COLLATERALNODE_INPUT_TOO_NEW) return "collateralnode input must have at least 15 confirmations";
        if(activeCollateralnode.status == COLLATERALNODE_IS_CAPABLE) return "successfully started collateralnode";
        if(activeCollateralnode.status == COLLATERALNODE_STOPPED) return "collateralnode is stopped";
        if(activeCollateralnode.status == COLLATERALNODE_NOT_CAPABLE) return "not capable collateralnode: " + activeCollateralnode.notCapableReason;
        if(activeCollateralnode.status == COLLATERALNODE_SYNC_IN_PROCESS) return "sync in process. Must wait until client is synced to start.";

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
            if(activeCollateralnode.status == COLLATERALNODE_REMOTELY_ENABLED) reason = "collateralnode started remotely";
            if(activeCollateralnode.status == COLLATERALNODE_INPUT_TOO_NEW) reason = "collateralnode input must have at least 15 confirmations";
            if(activeCollateralnode.status == COLLATERALNODE_IS_CAPABLE) reason = "successfully started collateralnode";
            if(activeCollateralnode.status == COLLATERALNODE_STOPPED) reason = "collateralnode is stopped";
            if(activeCollateralnode.status == COLLATERALNODE_NOT_CAPABLE) reason = "not capable collateralnode: " + activeCollateralnode.notCapableReason;
            if(activeCollateralnode.status == COLLATERALNODE_SYNC_IN_PROCESS) reason = "sync in process. Must wait until client is synced to start.";

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
            std::string colLateralError;
            std::string vinError;

            if(!colLateralSigner.SetKey(mne.getPrivKey(), colLateralError, keyCollateralnode, pubKeyCollateralnode))
            {
                errorMessage = colLateralError;
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
