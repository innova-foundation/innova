// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "innovarpc.h"
#include "smessage.h"
#include "init.h"
#include "util.h"
#include "net.h"
#include "dandelion.h"

#include <boost/lexical_cast.hpp>

using namespace json_spirit;
using namespace std;

extern CDandelionState dandelionState;
extern CDandelionRouter dandelionRouter;

static void EnsureNyxEnabled()
{
    if (!GetBoolArg("-nyx", true))
        throw runtime_error("Nyx messaging is disabled. Set nyx=1 in innova.conf.");
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled. Run smsgenable or set smsg=1.");
}

static void EnsureWalletUnlocked()
{
    if (pwalletMain->IsLocked())
        throw runtime_error("Wallet is locked. Unlock with walletpassphrase first.");
}

static std::string KeyToHex(const unsigned char* chKey)
{
    std::string hex;
    hex.reserve(36);
    for (int i = 0; i < 18; i++)
    {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", chKey[i]);
        hex += buf;
    }
    return hex;
}

static bool HexToKey(const std::string& hex, unsigned char* chKey)
{
    if (hex.size() != 36)
        return false;
    for (int i = 0; i < 18; i++)
    {
        unsigned int byte;
        if (sscanf(hex.c_str() + i * 2, "%02x", &byte) != 1)
            return false;
        chKey[i] = (unsigned char)byte;
    }
    return true;
}

static Value nyx_send(const Array& params)
{
    if (params.size() != 4)
        throw runtime_error(
            "nyx send <addrFrom> <addrTo> <message>\n"
            "Send an encrypted message.");

    EnsureNyxEnabled();

    std::string addrFrom = params[1].get_str();
    std::string addrTo   = params[2].get_str();
    std::string msg      = params[3].get_str();

    Object result;
    std::string sError;
    if (SecureMsgSend(addrFrom, addrTo, msg, sError) != 0)
    {
        result.push_back(Pair("result", "Send failed."));
        result.push_back(Pair("error", sError));
    }
    else
    {
        result.push_back(Pair("result", "Sent."));
        result.push_back(Pair("protocol", "nyx"));
    }
    return result;
}

static Value nyx_sendanon(const Array& params)
{
    if (params.size() != 3)
        throw runtime_error(
            "nyx sendanon <addrTo> <message>\n"
            "Send an anonymous encrypted message.");

    EnsureNyxEnabled();

    std::string addrFrom = "anon";
    std::string addrTo   = params[1].get_str();
    std::string msg      = params[2].get_str();

    Object result;
    std::string sError;
    if (SecureMsgSend(addrFrom, addrTo, msg, sError) != 0)
    {
        result.push_back(Pair("result", "Send failed."));
        result.push_back(Pair("error", sError));
    }
    else
    {
        result.push_back(Pair("result", "Sent anonymously."));
        result.push_back(Pair("protocol", "nyx"));
    }
    return result;
}

static Value nyx_inbox(const Array& params)
{
    EnsureNyxEnabled();
    EnsureWalletUnlocked();

    std::string mode = "unread";
    if (params.size() > 1)
        mode = params[1].get_str();

    int nOffset = 0;
    int nCount  = 50;
    if (params.size() > 2)
        nOffset = params[2].get_int();
    if (params.size() > 3)
        nCount = params[3].get_int();

    Object result;
    Array messages;

    {
        LOCK(cs_smsgDB);
        SecMsgDB dbInbox;
        if (!dbInbox.Open("cr+"))
            throw runtime_error("Could not open DB.");

        std::string sPrefix("im");
        unsigned char chKey[18];
        uint32_t nMessages = 0;
        uint32_t nShown = 0;
        char cbuf[256];

        if (mode == "clear")
        {
            dbInbox.TxnBegin();
            leveldb::Iterator* it = dbInbox.pdb->NewIterator(leveldb::ReadOptions());
            while (dbInbox.NextSmesgKey(it, sPrefix, chKey))
            {
                dbInbox.EraseSmesg(chKey);
                nMessages++;
            }
            delete it;
            dbInbox.TxnCommit();

            result.push_back(Pair("result", "Cleared."));
            result.push_back(Pair("deleted", (int)nMessages));
            return result;
        }

        bool fUnreadOnly = (mode == "unread");

        SecMsgStored smsgStored;
        MessageData msg;

        dbInbox.TxnBegin();
        leveldb::Iterator* it = dbInbox.pdb->NewIterator(leveldb::ReadOptions());
        while (dbInbox.NextSmesg(it, sPrefix, chKey, smsgStored))
        {
            if (fUnreadOnly && !(smsgStored.status & SMSG_MASK_UNREAD))
                continue;

            nMessages++;
            if ((int)nMessages <= nOffset)
                continue;
            if ((int)nShown >= nCount)
                continue;

            uint32_t nPayload = smsgStored.vchMessage.size() - SMSG_HDR_LEN;
            if (SecureMsgDecrypt(false, smsgStored.sAddrTo,
                    &smsgStored.vchMessage[0],
                    &smsgStored.vchMessage[SMSG_HDR_LEN],
                    nPayload, msg) == 0)
            {
                Object objM;
                objM.push_back(Pair("msgid", KeyToHex(chKey)));
                objM.push_back(Pair("received", getTimeString(smsgStored.timeReceived, cbuf, sizeof(cbuf))));
                objM.push_back(Pair("sent", getTimeString(msg.timestamp, cbuf, sizeof(cbuf))));
                objM.push_back(Pair("from", msg.sFromAddress));
                objM.push_back(Pair("to", smsgStored.sAddrTo));
                objM.push_back(Pair("text", std::string((char*)&msg.vchMessage[0])));
                objM.push_back(Pair("unread", (smsgStored.status & SMSG_MASK_UNREAD) ? true : false));
                messages.push_back(objM);
                nShown++;
            }
        }
        delete it;
        dbInbox.TxnCommit();

        result.push_back(Pair("messages", messages));
        result.push_back(Pair("total", (int)nMessages));
        result.push_back(Pair("shown", (int)nShown));
    }

    return result;
}

static Value nyx_outbox(const Array& params)
{
    EnsureNyxEnabled();
    EnsureWalletUnlocked();

    std::string mode = "all";
    if (params.size() > 1)
        mode = params[1].get_str();

    Object result;
    Array messages;

    {
        LOCK(cs_smsgDB);
        SecMsgDB dbOutbox;
        if (!dbOutbox.Open("cr+"))
            throw runtime_error("Could not open DB.");

        std::string sPrefix("nm");
        unsigned char chKey[18];
        uint32_t nMessages = 0;
        char cbuf[256];

        if (mode == "clear")
        {
            dbOutbox.TxnBegin();
            leveldb::Iterator* it = dbOutbox.pdb->NewIterator(leveldb::ReadOptions());
            while (dbOutbox.NextSmesgKey(it, sPrefix, chKey))
            {
                dbOutbox.EraseSmesg(chKey);
                nMessages++;
            }
            delete it;
            dbOutbox.TxnCommit();

            result.push_back(Pair("result", "Cleared."));
            result.push_back(Pair("deleted", (int)nMessages));
            return result;
        }

        SecMsgStored smsgStored;
        MessageData msg;

        leveldb::Iterator* it = dbOutbox.pdb->NewIterator(leveldb::ReadOptions());
        while (dbOutbox.NextSmesg(it, sPrefix, chKey, smsgStored))
        {
            uint32_t nPayload = smsgStored.vchMessage.size() - SMSG_HDR_LEN;
            if (SecureMsgDecrypt(false, smsgStored.sAddrOutbox,
                    &smsgStored.vchMessage[0],
                    &smsgStored.vchMessage[SMSG_HDR_LEN],
                    nPayload, msg) == 0)
            {
                Object objM;
                objM.push_back(Pair("msgid", KeyToHex(chKey)));
                objM.push_back(Pair("sent", getTimeString(msg.timestamp, cbuf, sizeof(cbuf))));
                objM.push_back(Pair("from", msg.sFromAddress));
                objM.push_back(Pair("to", smsgStored.sAddrTo));
                objM.push_back(Pair("text", std::string((char*)&msg.vchMessage[0])));
                messages.push_back(objM);
            }
            nMessages++;
        }
        delete it;

        result.push_back(Pair("messages", messages));
        result.push_back(Pair("total", (int)nMessages));
    }

    return result;
}

static Value nyx_read(const Array& params)
{
    if (params.size() != 2)
        throw runtime_error("nyx read <msgid>\nRead a specific message by ID.");

    EnsureNyxEnabled();
    EnsureWalletUnlocked();

    unsigned char chKey[18];
    if (!HexToKey(params[1].get_str(), chKey))
        throw runtime_error("Invalid message ID (expected 36 hex chars).");

    LOCK(cs_smsgDB);
    SecMsgDB db;
    if (!db.Open("cr+"))
        throw runtime_error("Could not open DB.");

    SecMsgStored smsgStored;
    if (!db.ReadSmesg(chKey, smsgStored))
        throw runtime_error("Message not found.");

    MessageData msg;
    uint32_t nPayload = smsgStored.vchMessage.size() - SMSG_HDR_LEN;
    std::string decryptAddr = smsgStored.sAddrTo.empty() ? smsgStored.sAddrOutbox : smsgStored.sAddrTo;

    if (SecureMsgDecrypt(false, decryptAddr,
            &smsgStored.vchMessage[0],
            &smsgStored.vchMessage[SMSG_HDR_LEN],
            nPayload, msg) != 0)
        throw runtime_error("Failed to decrypt message.");

    if (smsgStored.status & SMSG_MASK_UNREAD)
    {
        smsgStored.status &= ~SMSG_MASK_UNREAD;
        db.WriteSmesg(chKey, smsgStored);
    }

    char cbuf[256];
    Object result;
    result.push_back(Pair("msgid", params[1].get_str()));
    result.push_back(Pair("received", getTimeString(smsgStored.timeReceived, cbuf, sizeof(cbuf))));
    result.push_back(Pair("sent", getTimeString(msg.timestamp, cbuf, sizeof(cbuf))));
    result.push_back(Pair("from", msg.sFromAddress));
    result.push_back(Pair("to", smsgStored.sAddrTo));
    result.push_back(Pair("text", std::string((char*)&msg.vchMessage[0])));
    return result;
}

static Value nyx_delete(const Array& params)
{
    if (params.size() != 2)
        throw runtime_error("nyx delete <msgid>\nDelete a message by ID.");

    EnsureNyxEnabled();

    unsigned char chKey[18];
    if (!HexToKey(params[1].get_str(), chKey))
        throw runtime_error("Invalid message ID.");

    LOCK(cs_smsgDB);
    SecMsgDB db;
    if (!db.Open("cr+"))
        throw runtime_error("Could not open DB.");

    if (!db.ExistsSmesg(chKey))
        throw runtime_error("Message not found.");

    db.EraseSmesg(chKey);

    Object result;
    result.push_back(Pair("result", "Deleted."));
    result.push_back(Pair("msgid", params[1].get_str()));
    return result;
}

static Value nyx_markread(const Array& params)
{
    if (params.size() != 2)
        throw runtime_error("nyx markread <msgid>\nMark a message as read.");

    EnsureNyxEnabled();

    unsigned char chKey[18];
    if (!HexToKey(params[1].get_str(), chKey))
        throw runtime_error("Invalid message ID.");

    LOCK(cs_smsgDB);
    SecMsgDB db;
    if (!db.Open("cr+"))
        throw runtime_error("Could not open DB.");

    SecMsgStored smsgStored;
    if (!db.ReadSmesg(chKey, smsgStored))
        throw runtime_error("Message not found.");

    smsgStored.status &= ~SMSG_MASK_UNREAD;
    db.WriteSmesg(chKey, smsgStored);

    Object result;
    result.push_back(Pair("result", "Marked as read."));
    result.push_back(Pair("msgid", params[1].get_str()));
    return result;
}

static Value nyx_enable(const Array& params)
{
    if (fSecMsgEnabled)
    {
        Object result;
        result.push_back(Pair("result", "Nyx messaging already enabled."));
        return result;
    }

    Object result;
    if (!SecureMsgEnable())
        result.push_back(Pair("result", "Failed to enable Nyx messaging."));
    else
        result.push_back(Pair("result", "Nyx messaging enabled."));
    return result;
}

static Value nyx_disable(const Array& params)
{
    if (!fSecMsgEnabled)
    {
        Object result;
        result.push_back(Pair("result", "Nyx messaging already disabled."));
        return result;
    }

    Object result;
    if (!SecureMsgDisable())
        result.push_back(Pair("result", "Failed to disable Nyx messaging."));
    else
        result.push_back(Pair("result", "Nyx messaging disabled."));
    return result;
}

static Value nyx_status(const Array& params)
{
    Object result;

    result.push_back(Pair("nyx_enabled", GetBoolArg("-nyx", true)));
    result.push_back(Pair("smsg_enabled", fSecMsgEnabled));
    result.push_back(Pair("nyx_version", 1));
    result.push_back(Pair("encryption", "AES-256-CBC"));

    Object config;
    config.push_back(Pair("nyx", GetBoolArg("-nyx", true)));
    config.push_back(Pair("nyxanon", GetBoolArg("-nyxanon", true)));
    config.push_back(Pair("nyxgroups", GetBoolArg("-nyxgroups", true)));
    config.push_back(Pair("nyxfiles", GetBoolArg("-nyxfiles", true)));
    config.push_back(Pair("nyxchunksize", GetArg("-nyxchunksize", 1048576)));
    config.push_back(Pair("nyxconcurrency", GetArg("-nyxconcurrency", 8)));
    result.push_back(Pair("config", config));

    if (fSecMsgEnabled)
    {
        uint32_t nBuckets = 0;
        uint32_t nBucketMessages = 0;
        uint64_t nBytes = 0;

        {
            LOCK(cs_smsg);
            std::map<int64_t, SecMsgBucket>::iterator it;
            for (it = smsgBuckets.begin(); it != smsgBuckets.end(); ++it)
            {
                nBuckets++;
                nBucketMessages += it->second.getTokenCount();
            }
        }

        uint32_t nInbox = 0;
        uint32_t nOutbox = 0;
        uint32_t nUnread = 0;
        {
            LOCK(cs_smsgDB);
            SecMsgDB db;
            if (db.Open("r"))
            {
                std::string sPrefix("im");
                unsigned char chKey[18];
                SecMsgStored smsgStored;

                leveldb::Iterator* it = db.pdb->NewIterator(leveldb::ReadOptions());
                while (db.NextSmesg(it, sPrefix, chKey, smsgStored))
                {
                    nInbox++;
                    if (smsgStored.status & SMSG_MASK_UNREAD)
                        nUnread++;
                }
                delete it;

                sPrefix = "nm";
                it = db.pdb->NewIterator(leveldb::ReadOptions());
                while (db.NextSmesgKey(it, sPrefix, chKey))
                    nOutbox++;
                delete it;
            }
        }

        Object messaging;
        messaging.push_back(Pair("inbox_count", (int)nInbox));
        messaging.push_back(Pair("outbox_count", (int)nOutbox));
        messaging.push_back(Pair("unread_count", (int)nUnread));
        messaging.push_back(Pair("buckets", (int)nBuckets));
        messaging.push_back(Pair("network_messages", (int)nBucketMessages));
        result.push_back(Pair("messaging", messaging));

        Object dandel;
        dandel.push_back(Pair("enabled", dandelionState.IsEnabled()));
        {
            LOCK(cs_smsgStem);
            dandel.push_back(Pair("stem_messages", (int)mapSmsgStemState.size()));
        }
        result.push_back(Pair("dandelion", dandel));
    }

    return result;
}

static Value nyx_peers(const Array& params)
{
    EnsureNyxEnabled();

    Array peers;
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
            Object objP;
            objP.push_back(Pair("addr", pnode->addrName));
            objP.push_back(Pair("id", pnode->id));
            objP.push_back(Pair("smsg_enabled", pnode->smsgData.fEnabled));
            objP.push_back(Pair("version", pnode->nVersion));
            objP.push_back(Pair("inbound", pnode->fInbound));
            peers.push_back(objP);
        }
    }

    Object result;
    result.push_back(Pair("peers", peers));
    result.push_back(Pair("total", (int)peers.size()));
    return result;
}

Value nyx(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "nyx <subcommand> [params...]\n"
            "\nNyx Messaging Protocol — encrypted decentralized messaging.\n"
            "\nSubcommands:\n"
            "  send <from> <to> <message>  Send an encrypted message\n"
            "  sendanon <to> <message>     Send an anonymous encrypted message\n"
            "  inbox [all|unread|clear] [offset] [count]\n"
            "                              View received messages (default: unread)\n"
            "  outbox [all|clear]          View sent messages\n"
            "  read <msgid>                Read a specific message\n"
            "  delete <msgid>              Delete a message\n"
            "  markread <msgid>            Mark a message as read\n"
            "  enable                      Enable Nyx messaging\n"
            "  disable                     Disable Nyx messaging\n"
            "  status                      Show Nyx subsystem status\n"
            "  peers                       List peers with messaging support\n"
        );

    std::string subcmd = params[0].get_str();

    if (subcmd == "send")        return nyx_send(params);
    if (subcmd == "sendanon")    return nyx_sendanon(params);
    if (subcmd == "inbox")       return nyx_inbox(params);
    if (subcmd == "outbox")      return nyx_outbox(params);
    if (subcmd == "read")        return nyx_read(params);
    if (subcmd == "delete")      return nyx_delete(params);
    if (subcmd == "markread")    return nyx_markread(params);
    if (subcmd == "enable")      return nyx_enable(params);
    if (subcmd == "disable")     return nyx_disable(params);
    if (subcmd == "status")      return nyx_status(params);
    if (subcmd == "peers")       return nyx_peers(params);

    throw runtime_error("Unknown nyx subcommand: " + subcmd + ". Run 'nyx help' for usage.");
}
