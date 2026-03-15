// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "util.h"
#include "sync.h"
#include "ui_interface.h"
#include "base58.h"
#include "innovarpc.h"
#include "db.h"

#undef printf
#include <boost/asio.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/version.hpp>
#include <list>
#include <deque>
#include <limits>

#if BOOST_VERSION >= 107300
#include <boost/bind/bind.hpp>
using boost::placeholders::_1;
using boost::placeholders::_2;
#else
#include <boost/bind.hpp>
#endif

#define printf OutputDebugStringF

using namespace std;
using namespace boost;
using namespace boost::asio;
namespace bfs = boost::filesystem;
using namespace json_spirit;

void ThreadRPCServer2(void* parg);

static std::string strRPCUserColonPass;

const Object emptyobj;

void ThreadRPCServer3(void* parg);

static inline unsigned short GetDefaultRPCPort()
{
    return GetBoolArg("-testnet", false) ? 15531 : 14531;
}

Object JSONRPCError(int code, const string& message)
{
    Object error;
    error.push_back(Pair("code", code));
    error.push_back(Pair("message", message));
    return error;
}

void RPCTypeCheck(const Array& params,
                  const list<Value_type>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    for (Value_type t : typesExpected)
    {
        if (params.size() <= i)
            break;

        const Value& v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.type() == null_type))))
        {
            string err = strprintf("Expected type %s, got %s",
                                   Value_type_name[t], Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}

void RPCTypeCheck(const Object& o,
                  const map<string, Value_type>& typesExpected,
                  bool fAllowNull)
{
    for (const PAIRTYPE(string, Value_type)& t : typesExpected)
    {
        const Value& v = find_value(o, t.first);
        if (!fAllowNull && v.type() == null_type)
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first.c_str()));

        if (!((v.type() == t.second) || (fAllowNull && (v.type() == null_type))))
        {
            string err = strprintf("Expected type %s for %s, got %s",
                                   Value_type_name[t.second], t.first.c_str(), Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

int64_t AmountFromValue(const Value& value)
{
    double dAmount = value.get_real();
    static const double dMaxCoins = (double)MAX_MONEY / (double)COIN;

    if (dAmount <= 0.0 || dAmount > dMaxCoins)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");

    static const double dSafeMax = (double)std::numeric_limits<int64_t>::max() / (double)COIN;
    if (dAmount > dSafeMax)
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount too large");

    int64_t nAmount = roundint64(dAmount * COIN);
    if (!MoneyRange(nAmount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    return nAmount;
}

Value ValueFromAmount(int64_t amount)
{
    return (double)amount / (double)COIN;
}

std::string HexBits(unsigned int nBits)
{
    union {
        int32_t nBits;
        char cBits[4];
    } uBits;
    uBits.nBits = htonl((int32_t)nBits);
    return HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}

bool IsStringBoolPositive(std::string& value)
{
    return (value == "+" || value == "on"  || value == "true"  || value == "1" || value == "yes");
};

bool IsStringBoolNegative(std::string& value)
{
    return (value == "-" || value == "off" || value == "false" || value == "0" || value == "no");
};

//
// Utilities: convert hex-encoded Values
// (throws error if not hex).
//
uint256 ParseHashV(const Value& v, string strName)
{
    string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    uint256 result;
    result.SetHex(strHex);
    return result;
}

uint256 ParseHashO(const Object& o, string strKey)
{
    return ParseHashV(find_value(o, strKey), strKey);
}

vector<unsigned char> ParseHexV(const Value& v, string strName)
{
    string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    return ParseHex(strHex);
}

vector<unsigned char> ParseHexO(const Object& o, string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}


///
/// Note: This interface may still be subject to change.
///

string CRPCTable::help(string strCommand) const
{
    //Ring Sigs - I n n o v a - Q0lSQ1VJVEJSRUFLRVI=
    bool fAllAnon = strCommand == "anon" ? true : false;
    printf("fAllAnon %d %s\n", fAllAnon, strCommand.c_str());

    string strRet;
    set<rpcfn_type> setDone;
    for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
    {
        const CRPCCommand *pcmd = mi->second;
        string strMethod = mi->first;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos)
            continue;

        if (fAllAnon)
        {
                if(strMethod != "anonoutputs"
                && strMethod != "anoninfo"
                && strMethod != "reloadanondata")
            continue;
        } else
        if (strCommand != "" && strMethod != strCommand)
            continue;

        try
        {
            Array params;
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(params, true);
        } catch (std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (fAllAnon || strCommand == "")
                if (strHelp.find('\n') != string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));
            strRet += strHelp + "\n";
        };
    };
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand.c_str());
    strRet = strRet.substr(0,strRet.size()-1);
    return strRet;
}

Value help(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "help [command]\n"
            "List commands, or get help for a command.");

    string strCommand;
    if (params.size() > 0)
        strCommand = params[0].get_str();

    if (strCommand.empty() && GetBoolArg("-disablerpchelp", false))
    {
        return "Full command listing disabled for security.\n"
               "Use 'help <command>' for specific command help.\n"
               "Contact your administrator for available commands.";
    }

    return tableRPC.help(strCommand);
}


Value stop(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "stop <detach>\n"
            "<detach> is true or false to detach the database or not for this stop only\n"
            "Stop Innova server (and possibly override the detachdb config value).");
    // Shutdown will take long enough that the response should get back
    if (params.size() > 0)
        bitdb.SetDetach(params[0].get_bool());
    StartShutdown();
    return "Innova server stopping, please wait a few minutes for full shutdown...";
}



//
// Call Table
//


static const CRPCCommand vRPCCommands[] =
{ //  name                      function                 safemd  unlocked
  //  ------------------------  -----------------------  ------  --------
    { "help",                   &help,                   true,   true },
    { "stop",                   &stop,                   true,   true },
    { "getbestblockhash",       &getbestblockhash,       true,   false },
    { "getblockchaininfo",      &getblockchaininfo,      true,   false },
    { "getblockcount",          &getblockcount,          true,   false },
    { "getconnectioncount",     &getconnectioncount,     true,   false },
    { "getpeerinfo",            &getpeerinfo,            true,   false },
    { "getaddednodeinfo",       &getaddednodeinfo,       true,   true },
    { "ping",                   &ping,                   true,   true },
    { "getnettotals",           &getnettotals,           true,   false },
    { "disconnectnode",         &disconnectnode,         true,   false },
    { "getnetworkinfo",         &getnetworkinfo,         true,   false },
    { "gethashespersec",        &gethashespersec,        true,   false },
    { "addnode",                &addnode,                true,   true },
    { "setban",                 &setban,                 true,   true },
    { "listbanned",             &listbanned,             true,   true },
    { "clearbanned",            &clearbanned,            true,   true },
    { "dumpbootstrap",          &dumpbootstrap,          false,  false },
    { "getdifficulty",          &getdifficulty,          true,   false },
    { "getinfo",                &getinfo,                true,   false },
	{ "walletstatus",           &walletstatus,           true,   false },
    { "getsubsidy",             &getsubsidy,             true,   false },
    { "getmininginfo",          &getmininginfo,          true,   false },
    { "getstakinginfo",         &getstakinginfo,         true,   false },
    { "getnewaddress",          &getnewaddress,          true,   false },
    { "getnewpubkey",           &getnewpubkey,           true,   false },
    { "getaccountaddress",      &getaccountaddress,      true,   false },
    { "setaccount",             &setaccount,             true,   false },
    { "getaccount",             &getaccount,             false,  false },
    { "getaddressesbyaccount",  &getaddressesbyaccount,  true,   false },
    { "sendtoaddress",          &sendtoaddress,          false,  false },
    { "getreceivedbyaddress",   &getreceivedbyaddress,   false,  false },
    { "getreceivedbyaccount",   &getreceivedbyaccount,   false,  false },
    { "listreceivedbyaddress",  &listreceivedbyaddress,  false,  false },
    { "listreceivedbyaccount",  &listreceivedbyaccount,  false,  false },
    { "deletetransaction",      &deletetransaction,      false,  false },
    { "backupwallet",           &backupwallet,           true,   false },
    { "keypoolrefill",          &keypoolrefill,          true,   false },
    { "walletpassphrase",       &walletpassphrase,       true,   false },
    { "walletpassphrasechange", &walletpassphrasechange, false,  false },
    { "walletlock",             &walletlock,             true,   false },
    { "encryptwallet",          &encryptwallet,          false,  false },
    { "validateaddress",        &validateaddress,        true,   false },
    { "validatepubkey",         &validatepubkey,         true,   false },
    { "fetchbalance",           &fetchbalance,           true,   false },
    { "getbalance",             &getbalance,             false,  false },
    { "move",                   &movecmd,                false,  false },
    { "sendfrom",               &sendfrom,               false,  false },
    { "sendmany",               &sendmany,               false,  false },
    { "addmultisigaddress",     &addmultisigaddress,     false,  false },
    { "addredeemscript",        &addredeemscript,        false,  false },
    { "getrawmempool",          &getrawmempool,          true,   false },
    { "getblock",               &getblock,               false,  false },
	{ "getblockheader",         &getblockheader,         false,  false },
    { "setbestblockbyheight",   &setbestblockbyheight,   false,  false },
    { "getblock_old",           &getblock_old,           false,  false },
    { "getblockbynumber",       &getblockbynumber,       false,  false },
    { "getblockhash",           &getblockhash,           false,  false },
    { "gettransaction",         &gettransaction,         false,  false },
    { "listtransactions",       &listtransactions,       false,  false },
    { "listaddressgroupings",   &listaddressgroupings,   false,  false },
	{ "listaddressgroups",      &listaddressgroups,      false,  false },
    { "signmessage",            &signmessage,            false,  false },
    { "verifymessage",          &verifymessage,          false,  false },
    { "getwork",                &getwork,                true,   false },
    { "getworkex",              &getworkex,              true,   false },
    { "listaccounts",           &listaccounts,           false,  false },
    { "settxfee",               &settxfee,               false,  false },
    { "setgenerate",            &setgenerate,            true,   false },
    { "startmining",            &startmining,            true,   false },
    { "stopmining",             &stopmining,             true,   false },
    { "getblocktemplate",       &getblocktemplate,       true,   false },
    { "submitblock",            &submitblock,            false,  false },
    { "listsinceblock",         &listsinceblock,         false,  false },
    { "dumpprivkey",            &dumpprivkey,            false,  false },
    { "dumpwallet",             &dumpwallet,             true,   false },
    { "importwallet",           &importwallet,           false,  false },
    { "importprivkey",          &importprivkey,          false,  false },
    { "listunspent",            &listunspent,            false,  false },
    { "getrawtransaction",      &getrawtransaction,      false,  false },
    { "createrawtransaction",   &createrawtransaction,   false,  false },
    { "decoderawtransaction",   &decoderawtransaction,   false,  false },
    { "createmultisig",         &createmultisig,         false,  false },
    { "decodescript",           &decodescript,           false,  false },
    { "signrawtransaction",     &signrawtransaction,     false,  false },
    { "sendrawtransaction",     &sendrawtransaction,     false,  false },
    { "searchrawtransactions",  &searchrawtransactions,  false,  false },
    { "getcheckpoint",          &getcheckpoint,          true,   false },
    { "reservebalance",         &reservebalance,         false,  true},
    { "checkwallet",            &checkwallet,            false,  true},
    { "repairwallet",           &repairwallet,           false,  true},
    { "resendtx",               &resendtx,               false,  true},
    { "makekeypair",            &makekeypair,            false,  true},
    { "setdebug",               &setdebug,               true,   false },
    { "sendalert",              &sendalert,              false,  false},
    { "gettxout",               &gettxout,               true,   false },
    { "importaddress",          &importaddress,          false,  false },
    { "burn",                   &burn,                   false,  false },

    { "getnewstealthaddress",   &getnewstealthaddress,   false,  false},
    { "liststealthaddresses",   &liststealthaddresses,   false,  false},
    { "importstealthaddress",   &importstealthaddress,   false,  false},
    { "sendtostealthaddress",   &sendtostealthaddress,   false,  true},
    { "clearwallettransactions",&clearwallettransactions,false,  false},
    { "scanforalltxns",         &scanforalltxns,         false,  false},

    // Ring Signatures - I n n o v a - v3.1.0
    { "sendinntoanon",          	&sendinntoanon,          	 false,  false},
    { "sendanontoanon",         &sendanontoanon,         false,  false},
    { "sendanontoinn",          	&sendanontoinn,         	 false,  false},
    { "estimateanonfee",        &estimateanonfee,        false,  false},
    { "checkanonbalance",       &checkanonbalance,       true,   false},
    { "txnreport",              &txnreport,              false,  false},
    { "anonoutputs",            &anonoutputs,            false,  false},
    { "anoninfo",               &anoninfo,               false,  false},
    { "reloadanondata",         &reloadanondata,         false,  false},
    { "getanonoutputinfo",      &getanonoutputinfo,      false,  false},
    { "listcompromisedoutputs", &listcompromisedoutputs, false,  false},

    /* Cold Staking */
    { "getnewstakingaddress",   &getnewstakingaddress,   false,  false},
    { "delegatestake",          &delegatestake,          false,  true},
    { "listcoldutxos",          &listcoldutxos,          false,  false},
    { "getcoldstakinginfo",     &getcoldstakinginfo,     true,   false},
    { "revokecoldstaking",      &revokecoldstaking,      false,  true},

    /* SPV (Light Client) mode */
    { "getspvinfo",             &getspvinfo,             true,   false},
    { "spvrescan",              &spvrescan,              false,  false},
    { "getstakemodifiercheckpoints", &getstakemodifiercheckpoints, true, false},
    { "downloadbootstrap",      &downloadbootstrap,      false,  false},

    /* Collateralnode features */
    { "getpoolinfo",            &getpoolinfo,            true,   false},
    { "masternode",           	&masternode,             true,   false},
    { "collateralnode",           &collateralnode,           true,   false},

    /* NullSend Mixing */
    { "startmixing",            &startmixing,            false,  true},
    { "stopmixing",             &stopmixing,             false,  false},
    { "getmixingstatus",        &getmixingstatus,        true,   false},

    { "smsgenable",             &smsgenable,             false,  false},
    { "smsgdisable",            &smsgdisable,            false,  false},
    { "smsglocalkeys",          &smsglocalkeys,          false,  false},
    { "smsgoptions",            &smsgoptions,            false,  false},
    { "smsgscanchain",          &smsgscanchain,          false,  false},
    { "smsgscanbuckets",        &smsgscanbuckets,        false,  false},
    { "smsgaddkey",             &smsgaddkey,             false,  false},
    { "smsggetpubkey",          &smsggetpubkey,          false,  false},
    { "smsgsend",               &smsgsend,               false,  false},
    { "smsgsendanon",           &smsgsendanon,           false,  false},
    { "smsginbox",              &smsginbox,              false,  false},
    { "smsgoutbox",             &smsgoutbox,             false,  false},
    { "smsgbuckets",            &smsgbuckets,            false,  false},

    { "proofofdata",          &proofofdata,              false,  true  },

    // Innova Name Commands
    { "name_new",               &name_new,               false,  true },
    { "name_update",            &name_update,            false,  true },
    { "name_delete",            &name_delete,            false,  true },
    { "sendtoname",             &sendtoname,             false,  true },
    { "name_list",              &name_list,              false,  false },
    { "name_scan",              &name_scan,              false,  false },
    { "name_mempool",           &name_mempool,           false,  false },
    { "name_history",           &name_history,           false,  false },
    { "name_filter",            &name_filter,            false,  false },
    { "name_show",              &name_show,              false,  false },
    { "name_debug",             &name_debug,             false,  false },
    { "name_count",             &name_count,             false,  false },

    /* Shielded Transaction Commands */
    { "z_getnewaddress",        &z_getnewaddress,        false,  true },
    { "z_listaddresses",        &z_listaddresses,        true,   false },
    { "z_getbalance",           &z_getbalance,           true,   false },
    { "z_gettotalbalance",      &z_gettotalbalance,      true,   false },
    { "z_shield",               &z_shield,               false,  true },
    { "z_unshield",             &z_unshield,             false,  true },
    { "z_listunspent",          &z_listunspent,          true,   false },
    { "z_validateaddress",      &z_validateaddress,      true,   false },
    { "z_exportkey",            &z_exportkey,            false,  true },
    { "z_importkey",            &z_importkey,            false,  true },
    { "z_exportviewingkey",     &z_exportviewingkey,     false,  true },
    { "z_importviewingkey",     &z_importviewingkey,     false,  true },
    { "z_getshieldedinfo",      &z_getshieldedinfo,      true,   false },
    { "z_migrateanon",          &z_migrateanon,          false,  true },
    { "z_send",                 &z_send,                 false,  true },
    { "z_nullsend",             &z_nullsend,             false,  true },
    { "z_nullsendinfo",         &z_nullsendinfo,         true,   false },

    /* Cold Staking Delegation Commands (NullStake V3) */
    { "n_delegatestake",        &n_delegatestake,        false,  true },
    { "n_importdelegation",     &n_importdelegation,     false,  true },
    { "n_revokecoldstake",      &n_revokecoldstake,      false,  true },
    { "n_coldstakeinfo",        &n_coldstakeinfo,        true,   false },

    /* Silent Payment Commands */
    { "sp_getnewaddress",       &sp_getnewaddress,       false,  true },
    { "sp_listaddresses",       &sp_listaddresses,       true,   false },
    { "sp_send",                &sp_send,                false,  true },

    /* IDAG Phase 1: Finality commands */
    { "getfinalityinfo",        &getfinalityinfo,        true,   false },
    { "isblockfinalized",       &isblockfinalized,       true,   false },

    /* IDAG: DAG consensus commands (Phase 2-4) */
    { "getdaginfo",             &getdaginfo,             true,   false },
    { "getdagtips",             &getdagtips,             true,   false },
    { "getdagorder",            &getdagorder,            true,   false },
    { "getepochinfo",           &getepochinfo,           true,   false },
    { "getdagconfidence",       &getdagconfidence,       true,   false },

#ifdef USE_IPFS
    /* Hyperfile / IPFS commands */
    { "hyperfileversion",       &hyperfileversion,       true,   false },
    { "hyperfileupload",        &hyperfileupload,        false,  false },
    { "hyperfilepod",           &hyperfilepod,           false,  false },
    { "hyperfileduo",           &hyperfileduo,           false,  false },
    { "hyperfileduopod",        &hyperfileduopod,        false,  false },
    { "hyperfilegetblock",      &hyperfilegetblock,      true,   false },
    { "hyperfilegetstat",       &hyperfilegetstat,       true,   false },
#endif

};

CRPCTable::CRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand *CRPCTable::operator[](string name) const
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

//
// HTTP protocol
//
// This ain't Apache.  We're just using HTTP header for the length field
// and to be compatible with other JSON-RPC implementations.
//

string HTTPPost(const string& strMsg, const map<string,string>& mapRequestHeaders)
{
    ostringstream s;
    s << "POST / HTTP/1.1\r\n"
      << "User-Agent: innova-json-rpc/" << FormatFullVersion() << "\r\n"
      << "Host: 127.0.0.1\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << strMsg.size() << "\r\n"
      << "Connection: close\r\n"
      << "Accept: application/json\r\n";
    for (const PAIRTYPE(string, string)& item : mapRequestHeaders)
        s << item.first << ": " << item.second << "\r\n";
    s << "\r\n" << strMsg;

    return s.str();
}

string rfc1123Time()
{
    char buffer[64];
    time_t now;
    time(&now);
    struct tm* now_gmt = gmtime(&now);
    string locale(setlocale(LC_TIME, NULL));
    setlocale(LC_TIME, "C"); // we want POSIX (aka "C") weekday/month strings
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S +0000", now_gmt);
    setlocale(LC_TIME, locale.c_str());
    return string(buffer);
}

static string HTTPReply(int nStatus, const string& strMsg, bool keepalive)
{
    if (nStatus == HTTP_UNAUTHORIZED)
        return strprintf("HTTP/1.0 401 Authorization Required\r\n"
            "Date: %s\r\n"
            "Server: innova-json-rpc\r\n"
            "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 296\r\n"
            "\r\n"
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
            "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
            "<HTML>\r\n"
            "<HEAD>\r\n"
            "<TITLE>Error</TITLE>\r\n"
            "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
            "</HEAD>\r\n"
            "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
            "</HTML>\r\n", rfc1123Time().c_str());
    const char *cStatus;
         if (nStatus == HTTP_OK) cStatus = "OK";
    else if (nStatus == HTTP_BAD_REQUEST) cStatus = "Bad Request";
    else if (nStatus == HTTP_FORBIDDEN) cStatus = "Forbidden";
    else if (nStatus == HTTP_NOT_FOUND) cStatus = "Not Found";
    else if (nStatus == HTTP_INTERNAL_SERVER_ERROR) cStatus = "Internal Server Error";
    else cStatus = "";
    return strprintf(
            "HTTP/1.1 %d %s\r\n"
            "Date: %s\r\n"
            "Connection: %s\r\n"
            "Content-Length: %" PRIszu"\r\n"
            "Content-Type: application/json\r\n"
            "Server: innova-json-rpc\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "X-Frame-Options: DENY\r\n"
            "Content-Security-Policy: default-src 'none'\r\n"
            "\r\n"
            "%s",
        nStatus,
        cStatus,
        rfc1123Time().c_str(),
        keepalive ? "keep-alive" : "close",
        strMsg.size(),
        strMsg.c_str());
}

int ReadHTTPStatus(std::basic_istream<char>& stream, int &proto)
{
    string str;
    getline(stream, str);
    vector<string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return HTTP_INTERNAL_SERVER_ERROR;
    proto = 0;
    const char *ver = strstr(str.c_str(), "HTTP/1.");
    if (ver != NULL)
        proto = atoi(ver+7);
    return atoi(vWords[1].c_str());
}

int ReadHTTPHeader(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet)
{
    int nLen = 0;
    while (true)
    {
        string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;
        string::size_type nColon = str.find(":");
        if (nColon != string::npos)
        {
            string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            string strValue = str.substr(nColon+1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length")
            {
                char* endptr = NULL;
                errno = 0;
                long nParsed = strtol(strValue.c_str(), &endptr, 10);
                if (errno == ERANGE || nParsed < 0 || nParsed > INT_MAX || endptr == strValue.c_str())
                    nLen = -1;
                else
                    nLen = static_cast<int>(nParsed);
            }
        }
    }
    return nLen;
}

int ReadHTTP(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet, string& strMessageRet)
{
    mapHeadersRet.clear();
    strMessageRet = "";

    // Read status
    int nProto = 0;
    int nStatus = ReadHTTPStatus(stream, nProto);

    // Read header
    int nLen = ReadHTTPHeader(stream, mapHeadersRet);
    if (nLen < 0 || nLen > (int)MAX_SIZE)
        return HTTP_INTERNAL_SERVER_ERROR;

    // Read message
    if (nLen > 0)
    {
        vector<char> vch(nLen);
        stream.read(&vch[0], nLen);
        strMessageRet = string(vch.begin(), vch.end());
    }

    string sConHdr = mapHeadersRet["connection"];

    if ((sConHdr != "close") && (sConHdr != "keep-alive"))
    {
        if (nProto >= 1)
            mapHeadersRet["connection"] = "keep-alive";
        else
            mapHeadersRet["connection"] = "close";
    }

    return nStatus;
}

bool HTTPAuthorized(map<string, string>& mapHeaders)
{
    string strAuth = mapHeaders["authorization"];

    bool fValidFormat = true;
    string strUserPass64;

    if (strAuth.size() < 6)
    {
        fValidFormat = false;
        strUserPass64 = "ZHVtbXk6ZHVtbXk=";  // base64("dummy:dummy")
    }
    else if (strAuth.substr(0, 6) != "Basic ")
    {
        fValidFormat = false;
        strUserPass64 = "ZHVtbXk6ZHVtbXk=";
    }
    else
    {
        strUserPass64 = strAuth.substr(6);
    }

    boost::trim(strUserPass64);
    string strUserPass = DecodeBase64(strUserPass64);

    bool fCredentialsMatch = TimingResistantEqual(strUserPass, strRPCUserColonPass);

    return fValidFormat && fCredentialsMatch;
}

//
// JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
// but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
// unspecified (HTTP errors and contents of 'error').
//
// 1.0 spec: http://json-rpc.org/wiki/specification
// 1.2 spec: http://groups.google.com/group/json-rpc/web/json-rpc-over-http
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
//

string JSONRPCRequest(const string& strMethod, const Array& params, const Value& id)
{
    Object request;
    request.push_back(Pair("method", strMethod));
    request.push_back(Pair("params", params));
    request.push_back(Pair("id", id));
    return write_string(Value(request), false) + "\n";
}

Object JSONRPCReplyObj(const Value& result, const Value& error, const Value& id)
{
    Object reply;
    if (error.type() != null_type)
        reply.push_back(Pair("result", Value::null));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return reply;
}

string JSONRPCReply(const Value& result, const Value& error, const Value& id)
{
    Object reply = JSONRPCReplyObj(result, error, id);
    return write_string(Value(reply), false) + "\n";
}

void ErrorReply(std::ostream& stream, const Object& objError, const Value& id)
{
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = find_value(objError, "code").get_int();
    if (code == RPC_INVALID_REQUEST) nStatus = HTTP_BAD_REQUEST;
    else if (code == RPC_METHOD_NOT_FOUND) nStatus = HTTP_NOT_FOUND;
    string strReply = JSONRPCReply(Value::null, objError, id);
    stream << HTTPReply(nStatus, strReply, false) << std::flush;
}

bool ClientAllowed(const boost::asio::ip::address& address)
{
    // Make sure that IPv4-compatible and IPv4-mapped IPv6 addresses are treated as IPv4 addresses
#if BOOST_VERSION >= 107300
    if (address.is_v6() && address.to_v6().is_v4_mapped()) {
        return ClientAllowed(boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, address.to_v6()));
    }
#else
    if (address.is_v6()
     && (address.to_v6().is_v4_compatible()
      || address.to_v6().is_v4_mapped()))
        return ClientAllowed(address.to_v6().to_v4());
#endif

    if (address == asio::ip::address_v4::loopback()
     || address == asio::ip::address_v6::loopback()
     || (address.is_v4()
         // Check whether IPv4 addresses match 127.0.0.0/8 (loopback subnet)
#if BOOST_VERSION >= 106600
      && (address.to_v4().to_uint() & 0xff000000) == 0x7f000000))
#else
      && (address.to_v4().to_ulong() & 0xff000000) == 0x7f000000))
#endif
        return true;

    const string strAddress = address.to_string();
    const vector<string>& vAllow = mapMultiArgs["-rpcallowip"];
    for (string strAllow : vAllow)
        if (WildcardMatch(strAddress, strAllow))
            return true;
    return false;
}

//
// IOStream device that speaks SSL but can also speak non-SSL
//
template <typename Protocol>
class SSLIOStreamDevice : public iostreams::device<iostreams::bidirectional> {
public:
    SSLIOStreamDevice(asio::ssl::stream<typename Protocol::socket> &streamIn, bool fUseSSLIn) : stream(streamIn)
    {
        fUseSSL = fUseSSLIn;
        fNeedHandshake = fUseSSLIn;
    }

    void handshake(ssl::stream_base::handshake_type role)
    {
        if (!fNeedHandshake) return;
        fNeedHandshake = false;
        stream.handshake(role);
    }
    std::streamsize read(char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::server); // HTTPS servers read first
        if (fUseSSL) return stream.read_some(asio::buffer(s, n));
        return stream.next_layer().read_some(asio::buffer(s, n));
    }
    std::streamsize write(const char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::client); // HTTPS clients write first
        if (fUseSSL) return asio::write(stream, asio::buffer(s, n));
        return asio::write(stream.next_layer(), asio::buffer(s, n));
    }
    bool connect(const std::string& server, const std::string& port)
    {
        ip::tcp::resolver resolver(GetIOService(stream));
#if BOOST_VERSION >= 106600
        boost::system::error_code error = asio::error::host_not_found;
        auto results = resolver.resolve(server, port, error);
        if (error)
            return false;
        for (const auto& endpoint : results)
        {
            stream.lowest_layer().close();
            stream.lowest_layer().connect(endpoint, error);
            if (!error)
                return true;
        }
        return false;
#else
        ip::tcp::resolver::query query(server.c_str(), port.c_str());
        ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        ip::tcp::resolver::iterator end;
        boost::system::error_code error = asio::error::host_not_found;
        while (error && endpoint_iterator != end)
        {
            stream.lowest_layer().close();
            stream.lowest_layer().connect(*endpoint_iterator++, error);
        }
        if (error)
            return false;
        return true;
#endif
    }

private:
    bool fNeedHandshake;
    bool fUseSSL;
    asio::ssl::stream<typename Protocol::socket>& stream;
};

class AcceptedConnection
{
public:
    virtual ~AcceptedConnection() {}

    virtual std::iostream& stream() = 0;
    virtual std::string peer_address_to_string() const = 0;
    virtual void close() = 0;
};

template <typename Protocol>
class AcceptedConnectionImpl : public AcceptedConnection
{
public:
    AcceptedConnectionImpl(
            ioContext& io_service,
            ssl::context &context,
            bool fUseSSL) :
        sslStream(io_service, context),
        _d(sslStream, fUseSSL),
        _stream(_d)
    {
    }

    virtual std::iostream& stream()
    {
        return _stream;
    }

    virtual std::string peer_address_to_string() const
    {
        return peer.address().to_string();
    }

    virtual void close()
    {
        _stream.close();
    }

    typename Protocol::endpoint peer;
    asio::ssl::stream<typename Protocol::socket> sslStream;

private:
    SSLIOStreamDevice<Protocol> _d;
    iostreams::stream< SSLIOStreamDevice<Protocol> > _stream;
};

void ThreadRPCServer(void* parg)
{
    // Make this thread recognisable as the RPC listener
    RenameThread("innova-rpclist");

    try
    {
        vnThreadsRunning[THREAD_RPCLISTENER]++;
        ThreadRPCServer2(parg);
        vnThreadsRunning[THREAD_RPCLISTENER]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_RPCLISTENER]--;
        PrintException(&e, "ThreadRPCServer()");
    } catch (...) {
        vnThreadsRunning[THREAD_RPCLISTENER]--;
        PrintException(NULL, "ThreadRPCServer()");
    }
    printf("ThreadRPCServer exited\n");
}

// Forward declaration required for RPCListen
#if defined BOOST_VERSION && BOOST_VERSION >= 106600
template <typename Protocol>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol> > acceptor,
                             ssl::context& context,
                             bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& error);
#else
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             ssl::context& context,
                             bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& error);
#endif

/**
 * Sets up I/O resources to accept and handle a new connection.
 */
#if defined BOOST_VERSION && BOOST_VERSION >= 106600
template <typename Protocol>
static void RPCListen(boost::shared_ptr< basic_socket_acceptor<Protocol> > acceptor,
                   ssl::context& context,
                   const bool fUseSSL)
#else
template <typename Protocol, typename SocketAcceptorService>
static void RPCListen(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                   ssl::context& context,
                   const bool fUseSSL)
#endif
{
    // Accept connection
    AcceptedConnectionImpl<Protocol>* conn = new AcceptedConnectionImpl<Protocol>(GetIOServiceFromPtr(acceptor), context, fUseSSL);

    acceptor->async_accept(
            conn->sslStream.lowest_layer(),
            conn->peer,
#if defined BOOST_VERSION && BOOST_VERSION >= 106600
            boost::bind(&RPCAcceptHandler<Protocol>,
#else
            boost::bind(&RPCAcceptHandler<Protocol, SocketAcceptorService>,
#endif
                acceptor,
                boost::ref(context),
                fUseSSL,
                conn,
                boost::asio::placeholders::error));
}

/**
 * Accept and handle incoming connection.
 */
#if defined BOOST_VERSION && BOOST_VERSION >= 106600
template <typename Protocol>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol> > acceptor,
                             ssl::context& context,
                             const bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& error)
#else
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             ssl::context& context,
                             const bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& error)
#endif
{
    vnThreadsRunning[THREAD_RPCLISTENER]++;

    // Immediately start accepting new connections, except when we're cancelled or our socket is closed.
    if (error != asio::error::operation_aborted
     && acceptor->is_open())
        RPCListen(acceptor, context, fUseSSL);

    AcceptedConnectionImpl<ip::tcp>* tcp_conn = dynamic_cast< AcceptedConnectionImpl<ip::tcp>* >(conn);

    if (error)
    {
        if (fDebug)
            printf("RPC accept error: %s\n", error.message().c_str());
        delete conn;
    }

    // Restrict callers by IP.  It is important to
    // do this before starting client thread, to filter out
    // certain DoS and misbehaving clients.
    else if (tcp_conn
          && !ClientAllowed(tcp_conn->peer.address()))
    {
        // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
        if (!fUseSSL)
            conn->stream() << HTTPReply(HTTP_FORBIDDEN, "", false) << std::flush;
        delete conn;
    }

    // start HTTP client thread
    else if (!NewThread(ThreadRPCServer3, conn)) {
        printf("Failed to create RPC server client thread\n");
        delete conn;
    }

    vnThreadsRunning[THREAD_RPCLISTENER]--;
}

void ThreadRPCServer2(void* parg)
{
    printf("ThreadRPCServer started\n");

    strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"];
    if ((mapArgs["-rpcpassword"] == "") ||
        (mapArgs["-rpcuser"] == mapArgs["-rpcpassword"]))
    {
        unsigned char rand_pwd[32];
        RAND_bytes(rand_pwd, 32);
        string strWhatAmI = "To use innovad";
        if (mapArgs.count("-server"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-server\"");
        else if (mapArgs.count("-daemon"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-daemon\"");
        uiInterface.ThreadSafeMessageBox(strprintf(
            _("%s, you must set a rpcpassword in the configuration file:\n %s\n"
              "It is recommended you use the following random password:\n"
              "rpcuser=innovarpc\n"
              "rpcpassword=%s\n"
              "(you do not need to remember this password)\n"
              "The username and password MUST NOT be the same.\n"
              "If the file does not exist, create it with owner-readable-only file permissions.\n"
              "It is also recommended to set alertnotify so you are notified of problems;\n"
              "for example: alertnotify=echo %%s | mail -s \"Innova Alert\" admin@foo.com\n"),
                strWhatAmI.c_str(),
                GetConfigFile().string().c_str(),
                EncodeBase58(&rand_pwd[0],&rand_pwd[0]+32).c_str()),
            _("Error"), CClientUIInterface::OK | CClientUIInterface::MODAL);
        StartShutdown();
        return;
    }

    const bool fUseSSL = GetBoolArg("-rpcssl");

    ioContext io_service;
#if defined BOOST_VERSION && BOOST_VERSION >= 106600
    ssl::context context(ssl::context::sslv23);
#else
    ssl::context context(io_service, ssl::context::sslv23);
#endif

    if (fUseSSL)
    {
        context.set_options(ssl::context::no_sslv2);

        bfs::path pathCertFile(GetArg("-rpcsslcertificatechainfile", "server.cert"));
        if (!pathCertFile.is_absolute()) pathCertFile = bfs::path(GetDataDir()) / pathCertFile;
        if (bfs::exists(pathCertFile)) context.use_certificate_chain_file(pathCertFile.string());
        else printf("ThreadRPCServer ERROR: missing server certificate file %s\n", pathCertFile.string().c_str());

        bfs::path pathPKFile(GetArg("-rpcsslprivatekeyfile", "server.pem"));
        if (!pathPKFile.is_absolute()) pathPKFile = bfs::path(GetDataDir()) / pathPKFile;
        if (bfs::exists(pathPKFile)) context.use_private_key_file(pathPKFile.string(), ssl::context::pem);
        else printf("ThreadRPCServer ERROR: missing server private key file %s\n", pathPKFile.string().c_str());

        string strCiphers = GetArg("-rpcsslciphers", "TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH");
#if defined BOOST_VERSION && BOOST_VERSION >= 106600
        SSL_CTX_set_cipher_list(context.native_handle(), strCiphers.c_str());
#else
        SSL_CTX_set_cipher_list(context.impl(), strCiphers.c_str());
#endif
    }

    // Try a dual IPv6/IPv4 socket, falling back to separate IPv4 and IPv6 sockets
    const bool loopback = !mapArgs.count("-rpcallowip");
    asio::ip::address bindAddress = loopback ? asio::ip::address_v6::loopback() : asio::ip::address_v6::any();
    ip::tcp::endpoint endpoint(bindAddress, GetArg("-rpcport", GetDefaultRPCPort()));
    boost::system::error_code v6_only_error;
    boost::shared_ptr<ip::tcp::acceptor> acceptor(new ip::tcp::acceptor(io_service));

    boost::signals2::signal<void ()> StopRequests;

    bool fListening = false;
    std::string strerr;
    try
    {
        acceptor->open(endpoint.protocol());
        acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

        // Try making the socket dual IPv6/IPv4 (if listening on the "any" address)
        acceptor->set_option(boost::asio::ip::v6_only(loopback), v6_only_error);

        acceptor->bind(endpoint);
        acceptor->listen(asio::socket_base::max_listen_connections);

        RPCListen(acceptor, context, fUseSSL);
        // Cancel outstanding listen-requests for this acceptor when shutting down
        StopRequests.connect(signals2::slot<void ()>(
                    static_cast<void (ip::tcp::acceptor::*)()>(&ip::tcp::acceptor::close), acceptor.get())
                .track(acceptor));

        fListening = true;
    }
    catch(boost::system::system_error &e)
    {
        strerr = strprintf(_("An error occurred while setting up the RPC port %u for listening on IPv6, falling back to IPv4: %s"), endpoint.port(), e.what());
    }

    try {
        // If dual IPv6/IPv4 failed (or we're opening loopback interfaces only), open IPv4 separately
        if (!fListening || loopback || v6_only_error)
        {
            bindAddress = loopback ? asio::ip::address_v4::loopback() : asio::ip::address_v4::any();
            endpoint.address(bindAddress);

            acceptor.reset(new ip::tcp::acceptor(io_service));
            acceptor->open(endpoint.protocol());
            acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
            acceptor->bind(endpoint);
            acceptor->listen(asio::socket_base::max_listen_connections);

            RPCListen(acceptor, context, fUseSSL);
            // Cancel outstanding listen-requests for this acceptor when shutting down
            StopRequests.connect(signals2::slot<void ()>(
                        static_cast<void (ip::tcp::acceptor::*)()>(&ip::tcp::acceptor::close), acceptor.get())
                    .track(acceptor));

            fListening = true;
        }
    }
    catch(boost::system::system_error &e)
    {
        strerr = strprintf(_("An error occurred while setting up the RPC port %u for listening on IPv4: %s"), endpoint.port(), e.what());
    }

    if (!fListening) {
        uiInterface.ThreadSafeMessageBox(strerr, _("Error"), CClientUIInterface::OK | CClientUIInterface::MODAL);
        StartShutdown();
        return;
    }

    vnThreadsRunning[THREAD_RPCLISTENER]--;
    while (!fShutdown)
        io_service.run_one();
    vnThreadsRunning[THREAD_RPCLISTENER]++;
    StopRequests();
}

class JSONRequest
{
public:
    Value id;
    string strMethod;
    Array params;

    JSONRequest() { id = Value::null; }
    void parse(const Value& valRequest);
};

void JSONRequest::parse(const Value& valRequest)
{
    // Parse request
    if (valRequest.type() != obj_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const Object& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    Value valMethod = find_value(request, "method");
    if (valMethod.type() == null_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (valMethod.type() != str_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (strMethod != "getwork" && strMethod != "getblocktemplate")
        printf("ThreadRPCServer method=%s\n", strMethod.c_str());

    // Parse params
    Value valParams = find_value(request, "params");
    if (valParams.type() == array_type)
        params = valParams.get_array();
    else if (valParams.type() == null_type)
        params = Array();
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
}

static Object JSONRPCExecOne(const Value& req)
{
    Object rpc_result;

    JSONRequest jreq;
    try {
        jreq.parse(req);

        Value result = tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result = JSONRPCReplyObj(result, Value::null, jreq.id);
    }
    catch (Object& objError)
    {
        rpc_result = JSONRPCReplyObj(Value::null, objError, jreq.id);
    }
    catch (std::exception& e)
    {
        rpc_result = JSONRPCReplyObj(Value::null,
                                     JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}

static string JSONRPCExecBatch(const Array& vReq)
{
    Array ret;
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return write_string(Value(ret), false) + "\n";
}

static CCriticalSection cs_THREAD_RPCHANDLER;

void ThreadRPCServer3(void* parg)
{
    // Make this thread recognisable as the RPC handler
    RenameThread("innova-rpchand");

    {
        LOCK(cs_THREAD_RPCHANDLER);
        vnThreadsRunning[THREAD_RPCHANDLER]++;
    }
    AcceptedConnection *conn = (AcceptedConnection *) parg;

    bool fRun = true;
    while (true)
    {
        if (fShutdown || !fRun)
        {
            conn->close();
            delete conn;
            {
                LOCK(cs_THREAD_RPCHANDLER);
                --vnThreadsRunning[THREAD_RPCHANDLER];
            }
            return;
        }
        map<string, string> mapHeaders;
        string strRequest;

        ReadHTTP(conn->stream(), mapHeaders, strRequest);

        // Check authorization
        if (mapHeaders.count("authorization") == 0)
        {
            conn->stream() << HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        if (!HTTPAuthorized(mapHeaders))
        {
            static CCriticalSection cs_authAttempts;
            static std::map<std::string, std::pair<int, int64_t>> mapFailedAttempts;
            LOCK(cs_authAttempts);
            std::string strPeer = conn->peer_address_to_string();
            int64_t nNow = GetTime();
            auto& attemptInfo = mapFailedAttempts[strPeer];
            if (nNow - attemptInfo.second > 600)
                attemptInfo.first = 0;
            attemptInfo.first++;
            attemptInfo.second = nNow;
            printf("ThreadRPCServer incorrect password attempt %d from %s\n", attemptInfo.first, strPeer.c_str());
            static const int CONSTANT_AUTH_DELAY_MS = 2000;
            int nDelay = CONSTANT_AUTH_DELAY_MS;
            if (attemptInfo.first > 3)
                nDelay = std::min(CONSTANT_AUTH_DELAY_MS * (1 << std::min(attemptInfo.first - 3, 5)), 60000);
            MilliSleep(nDelay);
            conn->stream() << HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        {
            static CCriticalSection cs_rpcRateLimit;
            static std::map<std::string, std::deque<int64_t>> mapRPCRequestTimes;
            LOCK(cs_rpcRateLimit);

            std::string strPeer = conn->peer_address_to_string();
            int64_t nNow = GetTime();
            int nMaxPerWindow = GetArg("-rpcratelimit", 100);  // Max requests per window
            static const int64_t RATE_LIMIT_WINDOW = 10;  // 10-second sliding window

            auto& requestTimes = mapRPCRequestTimes[strPeer];

            while (!requestTimes.empty() && requestTimes.front() < nNow - RATE_LIMIT_WINDOW)
            {
                requestTimes.pop_front();
            }

            int nMaxInWindow = nMaxPerWindow * RATE_LIMIT_WINDOW;  // e.g., 100/sec * 10sec = 1000 max
            if (nMaxPerWindow > 0 && (int)requestTimes.size() >= nMaxInWindow)
            {
                printf("RPC rate limit exceeded for %s (%d requests in %d seconds, limit %d)\n",
                       strPeer.c_str(), (int)requestTimes.size(), (int)RATE_LIMIT_WINDOW, nMaxInWindow);
                conn->stream() << HTTPReply(HTTP_INTERNAL_SERVER_ERROR,
                    "{\"result\":null,\"error\":{\"code\":-32600,\"message\":\"Rate limit exceeded\"},\"id\":null}\n",
                    fRun) << std::flush;
                break;
            }

            requestTimes.push_back(nNow);

            static int nCleanupCounter = 0;
            if (++nCleanupCounter >= 100)
            {
                nCleanupCounter = 0;
                for (auto it = mapRPCRequestTimes.begin(); it != mapRPCRequestTimes.end(); )
                {
                    while (!it->second.empty() && it->second.front() < nNow - RATE_LIMIT_WINDOW * 2)
                        it->second.pop_front();
                    if (it->second.empty())
                        it = mapRPCRequestTimes.erase(it);
                    else
                        ++it;
                }
            }
        }

        if (mapHeaders.count("origin") > 0)
        {
            std::string strOrigin = mapHeaders["origin"];
            std::string strOriginLower = strOrigin;
            std::transform(strOriginLower.begin(), strOriginLower.end(), strOriginLower.begin(), ::tolower);
            bool fAllowedOrigin = false;
            if (strOriginLower.find("http://127.0.0.1") == 0 ||
                strOriginLower.find("https://127.0.0.1") == 0 ||
                strOriginLower.find("http://localhost") == 0 ||
                strOriginLower.find("https://localhost") == 0 ||
                strOriginLower.find("http://[::1]") == 0 ||
                strOriginLower.find("https://[::1]") == 0)
            {
                fAllowedOrigin = true;
            }
            if (!fAllowedOrigin)
            {
                printf("RPC CSRF protection: rejected request with Origin: %s\n", strOrigin.c_str());
                conn->stream() << HTTPReply(HTTP_FORBIDDEN,
                    "{\"result\":null,\"error\":{\"code\":-32600,\"message\":\"CSRF protection: invalid origin\"},\"id\":null}\n",
                    false) << std::flush;
                break;
            }
        }

        if (mapHeaders["connection"] == "close")
            fRun = false;

        JSONRequest jreq;
        try
        {
            // Parse request
            Value valRequest;
            if (!read_string(strRequest, valRequest))
                throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");

            string strReply;

            // singleton request
            if (valRequest.type() == obj_type) {
                jreq.parse(valRequest);

                Value result = tableRPC.execute(jreq.strMethod, jreq.params);

                // Send reply
                strReply = JSONRPCReply(result, Value::null, jreq.id);

            // array of requests
            } else if (valRequest.type() == array_type)
                strReply = JSONRPCExecBatch(valRequest.get_array());
            else
                throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");

            conn->stream() << HTTPReply(HTTP_OK, strReply, fRun) << std::flush;
        }
        catch (Object& objError)
        {
            ErrorReply(conn->stream(), objError, jreq.id);
            break;
        }
        catch (std::exception& e)
        {
            ErrorReply(conn->stream(), JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
            break;
        }
    }

    delete conn;
    {
        LOCK(cs_THREAD_RPCHANDLER);
        vnThreadsRunning[THREAD_RPCHANDLER]--;
    }
}

json_spirit::Value CRPCTable::execute(const std::string &strMethod, const json_spirit::Array &params) const
{
    // Find method
    const CRPCCommand *pcmd = tableRPC[strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    // Observe safe mode
    string strWarning = GetWarnings("rpc");
    if (strWarning != "" && !GetBoolArg("-disablesafemode") &&
        !pcmd->okSafeMode)
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning);

    try
    {
        // Execute
        Value result;
        {
            if (pcmd->unlocked)
                result = pcmd->actor(params, false);
            else {
                LOCK2(cs_main, pwalletMain->cs_wallet);
                result = pcmd->actor(params, false);
            }
        }
        return result;
    }
    catch (std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }
}

//I n n o v a - Autocomplete in Debug Window

std::vector<std::string> CRPCTable::listCommands() const
{
    std::vector<std::string> commandList;
    typedef std::map<std::string, const CRPCCommand*> commandMap;

    std::transform( mapCommands.begin(), mapCommands.end(),
                   std::back_inserter(commandList),
                   boost::bind(&commandMap::value_type::first,_1) );
    return commandList;
}

Object CallRPC(const string& strMethod, const Array& params)
{
    if (mapArgs["-rpcuser"] == "" && mapArgs["-rpcpassword"] == "")
        throw runtime_error(strprintf(
            _("You must set rpcpassword=<password> in the configuration file:\n%s\n"
              "If the file does not exist, create it with owner-readable-only file permissions."),
                GetConfigFile().string().c_str()));

    // Connect to localhost
    bool fUseSSL = GetBoolArg("-rpcssl");
    ioContext io_service;
#if defined BOOST_VERSION && BOOST_VERSION >= 106600
    ssl::context context(ssl::context::sslv23);
#else
    ssl::context context(io_service, ssl::context::sslv23);
#endif
    context.set_options(ssl::context::no_sslv2);
    asio::ssl::stream<asio::ip::tcp::socket> sslStream(io_service, context);
    SSLIOStreamDevice<asio::ip::tcp> d(sslStream, fUseSSL);
    iostreams::stream< SSLIOStreamDevice<asio::ip::tcp> > stream(d);
    if (!d.connect(GetArg("-rpcconnect", "127.0.0.1"), GetArg("-rpcport", itostr(GetDefaultRPCPort()))))
        throw runtime_error("couldn't connect to server");

    // HTTP basic authentication
    string strUserPass64 = EncodeBase64(mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"]);
    map<string, string> mapRequestHeaders;
    mapRequestHeaders["Authorization"] = string("Basic ") + strUserPass64;

    // Send request
    string strRequest = JSONRPCRequest(strMethod, params, 1);
    string strPost = HTTPPost(strRequest, mapRequestHeaders);
    stream << strPost << std::flush;

    // Receive reply
    map<string, string> mapHeaders;
    string strReply;
    int nStatus = ReadHTTP(stream, mapHeaders, strReply);
    if (nStatus == HTTP_UNAUTHORIZED)
        throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (nStatus >= 400 && nStatus != HTTP_BAD_REQUEST && nStatus != HTTP_NOT_FOUND && nStatus != HTTP_INTERNAL_SERVER_ERROR)
        throw runtime_error(strprintf("server returned HTTP error %d", nStatus));
    else if (strReply.empty())
        throw runtime_error("no response from server");

    // Parse reply
    Value valReply;
    if (!read_string(strReply, valReply))
        throw runtime_error("couldn't parse reply from server");
    const Object& reply = valReply.get_obj();
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    return reply;
}




template<typename T>
void ConvertTo(Value& value, bool fAllowNull=false, int nDepth=0)
{
    if (nDepth > 3)
        throw runtime_error("ConvertTo: maximum JSON nesting depth exceeded");
    if (fAllowNull && value.type() == null_type)
        return;
    if (value.type() == str_type)
    {
        // reinterpret string as unquoted json value
        Value value2;
        string strJSON = value.get_str();
        if (!read_string(strJSON, value2))
            throw runtime_error(string("Error parsing JSON:")+strJSON);
        ConvertTo<T>(value2, fAllowNull, nDepth + 1);
        value = value2;
    }
    else
    {
        value = value.get_value<T>();
    }
}

// Convert strings to command-specific RPC representation
Array RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    Array params;
    for (const std::string &param : strParams)
        params.push_back(param);

    int n = params.size();

    //
    // Special case non-string parameter types
    //
    if (strMethod == "stop"                   && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "setgenerate"            && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "setgenerate"            && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "startmining"           && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "delegatestake"          && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "listcoldutxos"          && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "sendtoaddress"          && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "sendtoname"             && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "burn"                   && n > 0) ConvertTo<double>(params[0]);
    if (strMethod == "settxfee"               && n > 0) ConvertTo<double>(params[0]);
    if (strMethod == "getreceivedbyaddress"   && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "getreceivedbyaccount"   && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "listreceivedbyaddress"  && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "listreceivedbyaddress"  && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "listreceivedbyaddress"  && n > 2) ConvertTo<bool>(params[2]);
    if (strMethod == "listreceivedbyaddress"  && n > 3) ConvertTo<bool>(params[3]);
    if (strMethod == "listreceivedbyaccount"  && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "listreceivedbyaccount"  && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getbalance"             && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "getbalance"             && n > 2) ConvertTo<bool>(params[2]);
    if (strMethod == "getblock"               && n > 1) ConvertTo<bool>(params[1]);
	if (strMethod == "getblockheader"         && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getblock_old"           && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getblockbynumber"       && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "getblockbynumber"       && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getblockhash"           && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "getstakemodifiercheckpoints" && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "getstakemodifiercheckpoints" && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "downloadbootstrap"      && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "dumpbootstrap"          && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "move"                   && n > 2) ConvertTo<double>(params[2]);
    if (strMethod == "move"                   && n > 3) ConvertTo<int64_t>(params[3]);
    if (strMethod == "sendfrom"               && n > 2) ConvertTo<double>(params[2]);
    if (strMethod == "sendfrom"               && n > 3) ConvertTo<int64_t>(params[3]);
    if (strMethod == "listtransactions"       && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "listtransactions"       && n > 2) ConvertTo<int64_t>(params[2]);
    if (strMethod == "listtransactions"       && n > 3) ConvertTo<bool>(params[3]);
    if (strMethod == "listaccounts"           && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "walletpassphrase"       && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "walletpassphrase"       && n > 2) ConvertTo<bool>(params[2]);
    if (strMethod == "getblocktemplate"       && n > 0) ConvertTo<Object>(params[0]);
    if (strMethod == "listsinceblock"         && n > 1) ConvertTo<int64_t>(params[1]);

    if (strMethod == "z_shield"              && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "z_unshield"            && n > 2) ConvertTo<double>(params[2]);
    if (strMethod == "z_send"                && n > 2) ConvertTo<double>(params[2]);
    if (strMethod == "z_send"                && n > 3) ConvertTo<int64_t>(params[3]);
    if (strMethod == "n_delegatestake"       && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "z_nullsend"            && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "z_nullsend"            && n > 2) ConvertTo<int64_t>(params[2]);
    if (strMethod == "z_nullsend"            && n > 3) ConvertTo<int64_t>(params[3]);
    if (strMethod == "z_nullsend"            && n > 4) ConvertTo<int64_t>(params[4]);

    if (strMethod == "sp_send"                && n > 1) ConvertTo<double>(params[1]);

    if (strMethod == "sendalert"              && n > 2) ConvertTo<int64_t>(params[2]);
    if (strMethod == "sendalert"              && n > 3) ConvertTo<int64_t>(params[3]);
    if (strMethod == "sendalert"              && n > 4) ConvertTo<int64_t>(params[4]);
    if (strMethod == "sendalert"              && n > 5) ConvertTo<int64_t>(params[5]);
    if (strMethod == "sendalert"              && n > 6) ConvertTo<int64_t>(params[6]);

    if (strMethod == "sendmany"               && n > 1) ConvertTo<Object>(params[1]);
    if (strMethod == "sendmany"               && n > 2) ConvertTo<int64_t>(params[2]);
    if (strMethod == "reservebalance"         && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "reservebalance"         && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "addmultisigaddress"     && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "addmultisigaddress"     && n > 1) ConvertTo<Array>(params[1]);
    if (strMethod == "listunspent"            && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "listunspent"            && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "listunspent"            && n > 2) ConvertTo<Array>(params[2]);
    if (strMethod == "getrawtransaction"      && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "createmultisig"         && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "createmultisig"         && n > 1) ConvertTo<Array>(params[1]);
    if (strMethod == "createrawtransaction"   && n > 0) ConvertTo<Array>(params[0]);
    if (strMethod == "createrawtransaction"   && n > 1) ConvertTo<Object>(params[1]);
    if (strMethod == "signrawtransaction"     && n > 1) ConvertTo<Array>(params[1], true);
    if (strMethod == "signrawtransaction"     && n > 2) ConvertTo<Array>(params[2], true);
    if (strMethod == "keypoolrefill"          && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "gettxout"               && n == 2) ConvertTo<int64_t>(params[1]);
    if (strMethod == "gettxout"               && n == 3) { ConvertTo<int64_t>(params[1]); ConvertTo<bool>(params[2]); }
    if (strMethod == "importaddress"          && n > 2) ConvertTo<bool>(params[2]);
	if (strMethod == "importprivkey"          && n > 2) ConvertTo<bool>(params[2]);

    if (strMethod == "setban"                 && n > 2) ConvertTo<int64_t>(params[2]);
    if (strMethod == "setban"                 && n == 4) ConvertTo<bool>(params[3]);

    if (strMethod == "sendinntoanon"         	  && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "sendanontoanon"         && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "sendanontoanon"         && n > 2) ConvertTo<int64_t>(params[2]);
    if (strMethod == "sendanontoinn"        	  && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "sendanontoinn"        	  && n > 2) ConvertTo<int64_t>(params[2]);
	if (strMethod == "estimateanonfee"        && n > 0) ConvertTo<double>(params[0]);
	if (strMethod == "estimateanonfee"        && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "checkanonbalance"       && n > 0) ConvertTo<double>(params[0]);
    if (strMethod == "checkanonbalance"       && n > 1) ConvertTo<int64_t>(params[1]);

    if (strMethod == "getpoolinfo"            && n > 0) ConvertTo<int64_t>(params[0]);

    if (strMethod == "addmultisigaddress"     && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "addmultisigaddress"     && n > 1) ConvertTo<Array>(params[1]);
    if (strMethod == "createmultisig"         && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "createmultisig"         && n > 1) ConvertTo<Array>(params[1]);

    if (strMethod == "sendtostealthaddress"   && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "scanforalltxns"         && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "scanforstealthtxns"     && n > 0) ConvertTo<int64_t>(params[0]);

    if (strMethod == "setbestblockbyheight"   && n > 0) ConvertTo<int64_t>(params[0]);

    // IDAG DAG Commands
    if (strMethod == "getdagorder"            && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "getepochinfo"           && n > 0) ConvertTo<int64_t>(params[0]);

    //Innova Name Commands
    if (strMethod == "name_new"               && n > 2) ConvertTo<boost::int64_t>(params[2]);
    if (strMethod == "name_new"               && n > 4) ConvertTo<boost::int64_t>(params[4]);
    if (strMethod == "name_update"            && n > 2) ConvertTo<boost::int64_t>(params[2]);
    if (strMethod == "name_update"            && n > 4) ConvertTo<boost::int64_t>(params[4]);
    if (strMethod == "name_filter"            && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "name_filter"            && n > 2) ConvertTo<boost::int64_t>(params[2]);
    if (strMethod == "name_filter"            && n > 3) ConvertTo<boost::int64_t>(params[3]);
    if (strMethod == "sendtoname"             && n > 1) ConvertTo<double>(params[1]);

    return params;
}

int CommandLineRPC(int argc, char *argv[])
{
    string strPrint;
    int nRet = 0;
    try
    {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0]))
        {
            argc--;
            argv++;
        }

        // Method
        if (argc < 2)
            throw runtime_error("too few parameters");
        string strMethod = argv[1];

        // Parameters default to strings
        std::vector<std::string> strParams(&argv[2], &argv[argc]);
        Array params = RPCConvertValues(strMethod, strParams);

        // Execute
        Object reply = CallRPC(strMethod, params);

        // Parse reply
        const Value& result = find_value(reply, "result");
        const Value& error  = find_value(reply, "error");

        if (error.type() != null_type)
        {
            // Error
            strPrint = "error: " + write_string(error, false);
            int code = find_value(error.get_obj(), "code").get_int();
            nRet = abs(code);
        }
        else
        {
            // Result
            if (result.type() == null_type)
                strPrint = "";
            else if (result.type() == str_type)
                strPrint = result.get_str();
            else
                strPrint = write_string(result, true);
        }
    }
    catch (std::exception& e)
    {
        strPrint = string("error: ") + e.what();
        nRet = 87;
    }
    catch (...)
    {
        PrintException(NULL, "CommandLineRPC()");
    }

    if (strPrint != "")
    {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
    return nRet;
}




#ifdef TEST
int main(int argc, char *argv[])
{
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFile("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    try
    {
        if (argc >= 2 && string(argv[1]) == "-server")
        {
            printf("server ready\n");
            ThreadRPCServer(NULL);
        }
        else
        {
            return CommandLineRPC(argc, argv);
        }
    }
    catch (std::exception& e) {
        PrintException(&e, "main()");
    } catch (...) {
        PrintException(NULL, "main()");
    }
    return 0;
}
#endif

const CRPCTable tableRPC;
