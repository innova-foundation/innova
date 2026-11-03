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
#include "nyxembed.h"
#include "nyxsafety.h"
#include "nyxext.h"
#include "nyxgroup.h"
#include "nyxidentity.h"

#include <boost/lexical_cast.hpp>

using namespace json_spirit;
using namespace std;

extern CDandelionState dandelionState;
extern CDandelionRouter dandelionRouter;

struct NyxRemovalCache
{
    bool fLoaded;
    std::vector<std::pair<std::string, std::string> > v;
    bool fSentLoaded;
    std::set<std::string> sentTo, book;
    NyxRemovalCache() : fLoaded(false), fSentLoaded(false) {}
};

// Visible text plus any embed or control record carried after the NUL.
void NyxPushMessageText(json_spirit::Object& o, const MessageData& msg, NyxRemovalCache& cache)
{
    std::string text, ext, id;
    const std::string full = SecureMsgPlaintext(msg);
    NyxSplitPlain(full, text, ext);
    o.push_back(json_spirit::Pair("mid", NyxMessageId(msg.sFromAddress, msg.timestamp, full)));
    o.push_back(json_spirit::Pair("text", text));
    if (ext.empty() || msg.sFromAddress == "anon")
        return;
    NyxRecords recs = NyxParseRecords(ext);
    if (recs.fReply)
    {
        json_spirit::Object r;
        r.push_back(json_spirit::Pair("mid", recs.reply.mid));
        r.push_back(json_spirit::Pair("quoted_by_sender", recs.reply.quote));
        o.push_back(json_spirit::Pair("reply_to", r));
    }
    if (recs.IsControl())
    {
        json_spirit::Object c;
        c.push_back(json_spirit::Pair("op", recs.fReact ? (recs.react.fAdd ? "react" : "unreact")
                                            : recs.fEdit ? "edit" : "delete"));
        c.push_back(json_spirit::Pair("mid", recs.fReact ? recs.react.mid : recs.fEdit ? recs.edit.mid : recs.delMid));
        if (recs.fReact)
            c.push_back(json_spirit::Pair("emoji", recs.react.emoji));
        if (recs.fEdit)
            c.push_back(json_spirit::Pair("seq", recs.edit.seq));
        o.push_back(json_spirit::Pair("control", c));
        return;
    }
    ext = recs.embedRec;
    NyxEmbed e;
    if (NyxDecodeEmbed(ext, e))
    {
        if (!cache.fLoaded)
        {
            SecureMsgCollectEmbedRemovals(cache.v);
            cache.fLoaded = true;
        }
        json_spirit::Object em;
        em.push_back(json_spirit::Pair("id", e.id));
        em.push_back(json_spirit::Pair("url", e.url));
        em.push_back(json_spirit::Pair("title", e.title));
        em.push_back(json_spirit::Pair("description", e.desc));
        em.push_back(json_spirit::Pair("site", e.site));
        em.push_back(json_spirit::Pair("thumbnail_bytes", (int)e.thumb.size()));
        em.push_back(json_spirit::Pair("removed", NyxEmbedHidden(msg.sFromAddress, e.id, cache.v)));
        o.push_back(json_spirit::Pair("embed", em));
    }
    else if (NyxDecodeRemoval(ext, id))
    {
        json_spirit::Object c;
        c.push_back(json_spirit::Pair("op", "rmembed"));
        c.push_back(json_spirit::Pair("id", id));
        o.push_back(json_spirit::Pair("control", c));
    }
}

// Call before taking cs_smsgDB: the address book needs cs_wallet.
void NyxPrepareInboxSafety(NyxRemovalCache& cache)
{
    SecureMsgCollectSentTo(cache.sentTo);
    SecureMsgCollectAddressBook(cache.book);
    cache.fSentLoaded = true;
}

// Request gating and scam flag for a received message.
void NyxPushInboxSafety(json_spirit::Object& o, const MessageData& msg, NyxRemovalCache& cache)
{
    if (!cache.fSentLoaded)
        return;
    std::string text, ext;
    NyxSplitPlain(SecureMsgPlaintext(msg), text, ext);
    o.push_back(json_spirit::Pair("request", SecureMsgSenderState(msg.sFromAddress, cache.sentTo, cache.book) != NYX_SENDER_KNOWN));
    o.push_back(json_spirit::Pair("scam_warning", NyxLooksLikeScam(text)));
}

bool NyxParseForce(const json_spirit::Value& v)
{
    if (v.type() == json_spirit::bool_type)
        return v.get_bool();
    if (v.type() == json_spirit::int_type)
        return v.get_int() != 0;
    if (v.type() == json_spirit::str_type)
    {
        const std::string s = v.get_str();
        return s == "true" || s == "1" || s == "force";
    }
    return false;
}

// Refuses text that looks like a recovery phrase or key unless fForce.
json_spirit::Object NyxGuardedSend(std::string from, std::string to, std::string msg, bool fForce)
{
    json_spirit::Object result;
    NyxSecretKind k = NyxDetectSecret(msg);
    if (k != NYX_SECRET_NONE && !fForce)
    {
        result.push_back(json_spirit::Pair("result", "Send refused."));
        result.push_back(json_spirit::Pair("error", std::string("Message looks like a ") + NyxSecretKindName(k)
                                           + ". Pass force=true to send anyway."));
        result.push_back(json_spirit::Pair("warning", NYX_SECRET_WARNING));
        return result;
    }
    std::string sError;
    if (SecureMsgSend(from, to, msg, sError) != 0)
    {
        result.push_back(json_spirit::Pair("result", "Send failed."));
        result.push_back(json_spirit::Pair("error", sError));
    }
    else
        result.push_back(json_spirit::Pair("result", from == "anon" ? "Sent anonymously." : "Sent."));
    if (k != NYX_SECRET_NONE)
        result.push_back(json_spirit::Pair("warning", NYX_SECRET_WARNING));
    return result;
}

static void EnsureNyxEnabled()
{
    if (!GetBoolArg("-nyx", true))
        throw runtime_error("Nyx messaging is disabled. Set nyx=1 in innova.conf.");
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled. "
                            "Set smsg=1 in innova.conf (or run smsgenable) to turn it on.");
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
    if (params.size() < 4 || params.size() > 5)
        throw runtime_error(
            "nyx send <addrFrom> <addrTo> <message> [force]\n"
            "Send an encrypted message. Text that looks like a recovery phrase or private key\n"
            "is refused unless force is true.");

    EnsureNyxEnabled();

    Object result = NyxGuardedSend(params[1].get_str(), params[2].get_str(), params[3].get_str(),
                                   params.size() > 4 && NyxParseForce(params[4]));
    if (find_value(result, "result").get_str() == "Sent.")
        result.push_back(Pair("protocol", "nyx"));
    return result;
}

// Caller supplies the card fields; the node never fetches the URL.
static Value nyx_sendembed(const Array& params)
{
    if (params.size() < 5 || params.size() > 7)
        throw runtime_error(
            "nyx sendembed <from> <to> <message> <title> [description] [site]\n"
            "Send a message with a link preview card for the first https URL in <message>.");

    EnsureNyxEnabled();

    std::string addrFrom = params[1].get_str();
    std::string addrTo   = params[2].get_str();
    std::string msg      = params[3].get_str();

    NyxEmbed e;
    if (NyxDetectSecret(msg) != NYX_SECRET_NONE)
        throw runtime_error(std::string("Send refused. ") + NYX_SECRET_WARNING);
    e.url = NyxFirstHttpsUrl(msg);
    if (e.url.empty())
        throw runtime_error("Message has no https URL.");
    e.title = params[4].get_str();
    if (params.size() > 5) e.desc = params[5].get_str();
    e.site = params.size() > 6 ? params[6].get_str() : NyxUrlHost(e.url);
    e.id = GetRandHash().GetHex().substr(0, 16);

    std::string ext = NyxFitEmbed(msg, e, SMSG_MAX_MSG_BYTES);
    if (ext.empty())
        throw runtime_error("Message too long to carry a preview card.");
    std::string full = NyxComposePlain(msg, ext);

    Object result;
    std::string sError;
    if (SecureMsgSend(addrFrom, addrTo, full, sError) != 0)
    {
        result.push_back(Pair("result", "Send failed."));
        result.push_back(Pair("error", sError));
    }
    else
    {
        result.push_back(Pair("result", "Sent."));
        result.push_back(Pair("embed_id", e.id));
    }
    return result;
}

static Value nyx_removeembed(const Array& params)
{
    if (params.size() != 2)
        throw runtime_error(
            "nyx removeembed <embedid>\n"
            "Remove a link preview card you sent, for every recipient that receives the removal.");

    EnsureNyxEnabled();
    EnsureWalletUnlocked();

    Object result;
    std::string sError;
    if (SecureMsgRemoveEmbed(params[1].get_str(), sError) != 0)
    {
        result.push_back(Pair("result", "Remove failed."));
        result.push_back(Pair("error", sError));
    }
    else
        result.push_back(Pair("result", "Removal sent."));
    return result;
}

static Object NyxControlResult(int rv, const std::string& sError, const char* ok)
{
    Object result;
    if (rv != 0)
    {
        result.push_back(Pair("result", "Send failed."));
        result.push_back(Pair("error", sError));
    }
    else
        result.push_back(Pair("result", ok));
    return result;
}

static Value nyx_reply(const Array& params)
{
    if (params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "nyx reply <mid> <message> [force]\n"
            "Reply to a stored message by its mid. Old clients see only <message>.");
    EnsureNyxEnabled();
    EnsureWalletUnlocked();
    const std::string body = params[2].get_str();
    if (NyxDetectSecret(body) != NYX_SECRET_NONE && !(params.size() > 3 && NyxParseForce(params[3])))
        throw runtime_error(std::string("Send refused. ") + NYX_SECRET_WARNING);
    std::string sError;
    return NyxControlResult(SecureMsgSendReply(params[1].get_str(), body, sError), sError, "Sent.");
}

static Value nyx_react(const Array& params)
{
    if (params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "nyx react <mid> <emoji> [remove]\n"
            "Add (or with remove=true, take back) a reaction. Never sent anonymously.");
    EnsureNyxEnabled();
    EnsureWalletUnlocked();
    bool fRemove = params.size() > 3 && NyxParseForce(params[3]);
    std::string sError;
    return NyxControlResult(SecureMsgSendReact(params[1].get_str(), params[2].get_str(), !fRemove, sError),
                            sError, fRemove ? "Reaction removed." : "Reacted.");
}

static Value nyx_edit(const Array& params)
{
    if (params.size() != 3)
        throw runtime_error(
            "nyx edit <mid> <newtext>\n"
            "Edit a message you sent, within 48 hours. Recipients honour it only when signed by you.");
    EnsureNyxEnabled();
    EnsureWalletUnlocked();
    if (NyxDetectSecret(params[2].get_str()) != NYX_SECRET_NONE)
        throw runtime_error(std::string("Send refused. ") + NYX_SECRET_WARNING);
    std::string sError;
    return NyxControlResult(SecureMsgSendEdit(params[1].get_str(), params[2].get_str(), sError), sError, "Edit sent.");
}

static Value nyx_unsend(const Array& params)
{
    if (params.size() != 2)
        throw runtime_error(
            "nyx unsend <mid>\n"
            "Delete a message you sent for everyone: recipients that receive the delete replace it\n"
            "with a tombstone and erase it. Copies already read or saved elsewhere cannot be recalled.");
    EnsureNyxEnabled();
    EnsureWalletUnlocked();
    std::string sError;
    return NyxControlResult(SecureMsgSendDelete(params[1].get_str(), sError), sError, "Deleted for everyone.");
}

static Value nyx_thread(const Array& params)
{
    if (params.size() != 2)
        throw runtime_error(
            "nyx thread <address>\n"
            "Conversation with <address> after applying replies, reactions, edits and deletes.");
    EnsureNyxEnabled();
    EnsureWalletUnlocked();
    const std::string peer = params[1].get_str();
    std::set<std::string> sentTo, book;
    SecureMsgCollectSentTo(sentTo);
    SecureMsgCollectAddressBook(book);
    std::vector<NyxThreadMsg> rows;
    std::vector<bool> mine;
    SecureMsgCollectConversation(peer, rows, mine);
    std::set<std::string> self;
    for (size_t i = 0; i < rows.size(); i++)
        if (mine[i])
            self.insert(rows[i].sender);
    std::vector<NyxMsgView> v = NyxBuildThread(rows, [&](const std::string& s) {
        return self.count(s) || SecureMsgSenderState(s, sentTo, book) == NYX_SENDER_KNOWN;
    });
    Array out;
    char cbuf[256];
    for (size_t i = 0; i < rows.size(); i++)
    {
        if (v[i].fControl)
            continue;
        Object m;
        m.push_back(Pair("mid", rows[i].mid));
        m.push_back(Pair("from", rows[i].sender));
        m.push_back(Pair("mine", (bool)mine[i]));
        m.push_back(Pair("sent", getTimeString(rows[i].ts, cbuf, sizeof(cbuf))));
        m.push_back(Pair("text", v[i].text));
        if (v[i].fTombstone)
            m.push_back(Pair("deleted", true));
        if (v[i].fEdited)
            m.push_back(Pair("edited", v[i].seq));
        if (v[i].fReply)
        {
            Object r;
            r.push_back(Pair("mid", v[i].reply.mid));
            if (v[i].replyIndex >= 0)
                r.push_back(Pair("original", v[v[i].replyIndex].text));
            else
                r.push_back(Pair("quoted_by_sender", v[i].reply.quote));
            m.push_back(Pair("reply_to", r));
        }
        if (!v[i].reactions.empty())
        {
            Object rx;
            for (const auto& e : v[i].reactions)
            {
                Array who;
                for (const std::string& s : e.second)
                    who.push_back(s);
                rx.push_back(Pair(e.first, who));
            }
            m.push_back(Pair("reactions", rx));
        }
        out.push_back(m);
    }
    Object result;
    result.push_back(Pair("messages", out));
    return result;
}

static Object GroupToJson(const NyxGroupView& g)
{
    Object o;
    o.push_back(Pair("gid", g.gid));
    o.push_back(Pair("name", g.name));
    o.push_back(Pair("owner", g.owner));
    Array m;
    for (const std::string& a : g.members)
        m.push_back(a);
    o.push_back(Pair("members", m));
    o.push_back(Pair("epoch", g.epoch));
    o.push_back(Pair("my_address", g.myAddr));
    o.push_back(Pair("member", g.fMember));
    o.push_back(Pair("request", g.fRequest));
    o.push_back(Pair("hidden", g.fHidden));
    return o;
}

static Value nyx_group(const Array& params, const std::string& sub)
{
    EnsureNyxEnabled();
    EnsureWalletUnlocked();
    std::string sError, gid;
    if (sub == "groupcreate")
    {
        if (params.size() < 4)
            throw runtime_error("nyx groupcreate <from> <name> <member> [member...]\n"
                                "Create a group of up to 10 members including you. Each message is sent as one\n"
                                "encrypted copy per member.");
        std::vector<std::string> members;
        for (size_t i = 3; i < params.size(); i++)
            members.push_back(params[i].get_str());
        int rv = SecureMsgGroupCreate(params[1].get_str(), params[2].get_str(), members, gid, sError);
        Object r = NyxControlResult(rv, sError, "Group created.");
        if (rv == 0)
            r.push_back(Pair("gid", gid));
        return r;
    }
    if (sub == "grouplist")
    {
        std::vector<NyxGroupView> v;
        SecureMsgCollectGroups(v);
        Array out;
        for (const NyxGroupView& g : v)
            out.push_back(GroupToJson(g));
        return out;
    }
    if (params.size() < 2)
        throw runtime_error("nyx " + sub + " <gid> ...");
    gid = params[1].get_str();
    if (sub == "groupinfo")
    {
        NyxGroupView g;
        if (!SecureMsgGetGroup(gid, g))
            throw runtime_error("Unknown group.");
        return GroupToJson(g);
    }
    if (sub == "groupsend")
    {
        if (params.size() < 3 || params.size() > 4)
            throw runtime_error("nyx groupsend <gid> <message> [force]");
        const std::string body = params[2].get_str();
        if (NyxDetectSecret(body) != NYX_SECRET_NONE && !(params.size() > 3 && NyxParseForce(params[3])))
            throw runtime_error(std::string("Send refused. ") + NYX_SECRET_WARNING);
        return NyxControlResult(SecureMsgGroupSend(gid, body, std::vector<std::string>(), sError), sError, "Sent.");
    }
    if (sub == "groupadd" || sub == "groupremove" || sub == "groupowner" || sub == "grouprename")
    {
        if (params.size() != 3)
            throw runtime_error("nyx " + sub + " <gid> <" + (sub == "grouprename" ? "name" : "address") + ">");
        const std::string a = params[2].get_str();
        int rv = sub == "groupadd" ? SecureMsgGroupAdd(gid, a, sError)
               : sub == "groupremove" ? SecureMsgGroupRemove(gid, a, sError)
               : sub == "groupowner" ? SecureMsgGroupSetOwner(gid, a, sError)
               : SecureMsgGroupRename(gid, a, sError);
        return NyxControlResult(rv, sError, "Done.");
    }
    if (sub == "groupleave")
        return NyxControlResult(SecureMsgGroupLeave(gid, sError), sError, "Left the group.");
    if (sub == "groupaccept" || sub == "grouphide")
    {
        Object r;
        bool ok = sub == "groupaccept" ? SecureMsgGroupAccept(gid) : SecureMsgGroupHide(gid);
        r.push_back(Pair("result", ok ? "OK." : "Could not save nyxcontacts.dat."));
        return r;
    }
    if (sub == "groupthread")
    {
        std::vector<NyxThreadMsg> rows;
        std::vector<bool> mine;
        SecureMsgCollectGroupThread(gid, rows, mine);
        NyxGroupView g;
        bool fHave = SecureMsgGetGroup(gid, g);
        std::vector<NyxMsgView> v = NyxBuildThread(rows, [&](const std::string& s) {
            return fHave && std::find(g.members.begin(), g.members.end(), s) != g.members.end();
        });
        Array out;
        char cbuf[256];
        for (size_t i = 0; i < rows.size(); i++)
        {
            if (v[i].fControl)
                continue;
            Object m;
            m.push_back(Pair("mid", rows[i].mid));
            m.push_back(Pair("from", rows[i].sender));
            m.push_back(Pair("mine", (bool)mine[i]));
            m.push_back(Pair("sent", getTimeString(rows[i].ts, cbuf, sizeof(cbuf))));
            m.push_back(Pair("text", v[i].text));
            if (v[i].fTombstone)
                m.push_back(Pair("deleted", true));
            if (v[i].fEdited)
                m.push_back(Pair("edited", v[i].seq));
            if (v[i].fReply)
                m.push_back(Pair("reply_to", v[i].reply.mid));
            if (!v[i].reactions.empty())
            {
                Object rx;
                for (const auto& e : v[i].reactions)
                    rx.push_back(Pair(e.first, (int)e.second.size()));
                m.push_back(Pair("reactions", rx));
            }
            out.push_back(m);
        }
        Object result;
        result.push_back(Pair("messages", out));
        return result;
    }
    throw runtime_error("Unknown nyx subcommand: " + sub);
}

static Value nyx_sendanon(const Array& params)
{
    if (params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "nyx sendanon <addrTo> <message> [force]\n"
            "Send an anonymous encrypted message. Secret-looking text needs force.");

    EnsureNyxEnabled();

    Object result = NyxGuardedSend("anon", params[1].get_str(), params[2].get_str(),
                                   params.size() > 3 && NyxParseForce(params[3]));
    if (find_value(result, "result").get_str() == "Sent anonymously.")
        result.push_back(Pair("protocol", "nyx"));
    return result;
}

static Value nyx_contact(const Array& params, const std::string& op)
{
    if (params.size() != 2)
        throw runtime_error("nyx " + op + " <address>\n"
            "accept: show this sender's links and previews. block: discard its messages now and later.\n"
            "unblock: stop discarding.");
    std::string addr = params[1].get_str();
    if (!NyxIsValidContactAddress(addr) || addr == "anon")
        throw runtime_error("Invalid address.");
    Object result;
    bool ok = op == "accept" ? NyxAccept(addr) : op == "block" ? NyxBlock(addr) : NyxUnblock(addr);
    result.push_back(Pair("result", ok ? "OK." : "Could not save nyxcontacts.dat."));
    if (op == "block")
        result.push_back(Pair("discarded", fSecMsgEnabled ? SecureMsgDiscardFrom(addr) : 0));
    return result;
}

static Value nyx_inbox(const Array& params)
{
    NyxRemovalCache nyxRemovals;
    EnsureNyxEnabled();
    EnsureWalletUnlocked();
    NyxPrepareInboxSafety(nyxRemovals);

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

            unsigned char* pHeader = NULL;
            unsigned char* pPayload = NULL;
            uint32_t nPayload = 0;
            if (!SecureMsgSplitStored(smsgStored.vchMessage, pHeader, pPayload, nPayload))
                continue;

            if (SecureMsgDecrypt(false, smsgStored.sAddrTo,
                    pHeader, pPayload, nPayload, msg) == 0)
            {
                Object objM;
                objM.push_back(Pair("msgid", KeyToHex(chKey)));
                objM.push_back(Pair("received", getTimeString(smsgStored.timeReceived, cbuf, sizeof(cbuf))));
                objM.push_back(Pair("sent", getTimeString(msg.timestamp, cbuf, sizeof(cbuf))));
                objM.push_back(Pair("from", msg.sFromAddress));
                objM.push_back(Pair("to", smsgStored.sAddrTo));
                NyxPushMessageText(objM, msg, nyxRemovals);
                NyxPushInboxSafety(objM, msg, nyxRemovals);
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
    NyxRemovalCache nyxRemovals;
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
            unsigned char* pHeader = NULL;
            unsigned char* pPayload = NULL;
            uint32_t nPayload = 0;
            if (SecureMsgSplitStored(smsgStored.vchMessage, pHeader, pPayload, nPayload)
                && SecureMsgDecrypt(false, smsgStored.sAddrOutbox,
                    pHeader, pPayload, nPayload, msg) == 0)
            {
                Object objM;
                objM.push_back(Pair("msgid", KeyToHex(chKey)));
                objM.push_back(Pair("sent", getTimeString(msg.timestamp, cbuf, sizeof(cbuf))));
                objM.push_back(Pair("from", msg.sFromAddress));
                objM.push_back(Pair("to", smsgStored.sAddrTo));
                NyxPushMessageText(objM, msg, nyxRemovals);
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
    NyxRemovalCache nyxRemovals;
    if (params.size() != 2)
        throw runtime_error("nyx read <msgid>\nRead a specific message by ID.");

    EnsureNyxEnabled();
    EnsureWalletUnlocked();

    unsigned char chKey[18];
    if (!HexToKey(params[1].get_str(), chKey))
        throw runtime_error("Invalid message ID (expected 36 hex chars).");

    NyxPrepareInboxSafety(nyxRemovals);
    LOCK(cs_smsgDB);
    SecMsgDB db;
    if (!db.Open("cr+"))
        throw runtime_error("Could not open DB.");

    SecMsgStored smsgStored;
    if (!db.ReadSmesg(chKey, smsgStored))
        throw runtime_error("Message not found.");

    MessageData msg;
    unsigned char* pHeader = NULL;
    unsigned char* pPayload = NULL;
    uint32_t nPayload = 0;
    if (!SecureMsgSplitStored(smsgStored.vchMessage, pHeader, pPayload, nPayload))
        throw runtime_error("Stored message is truncated.");

    std::string decryptAddr = smsgStored.sAddrTo.empty() ? smsgStored.sAddrOutbox : smsgStored.sAddrTo;

    if (SecureMsgDecrypt(false, decryptAddr,
            pHeader, pPayload, nPayload, msg) != 0)
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
    NyxPushMessageText(result, msg, nyxRemovals);
    if (!smsgStored.sAddrTo.empty() && smsgStored.sAddrOutbox.empty())
        NyxPushInboxSafety(result, msg, nyxRemovals);
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

    // An explicit -nosmsg is an operator decision; a runtime RPC must not undo it.
    if (GetBoolArg("-nosmsg", false))
        throw runtime_error("Secure messaging was force-disabled with -nosmsg. "
                            "Remove it and set smsg=1 to enable messaging.");

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
    result.push_back(Pair("nyx_version", fNyxV2 ? 2 : 1));
    result.push_back(Pair("encryption", "AES-256-CBC"));
    if (fNyxV2)
    {
        std::vector<NyxSetProgress> vPriv, vPub;
        uint64_t nPriv = 0, nPub = 0;
        SecureMsgV2Progress(vPriv, vPub, nPriv, nPub);
        Object v2;
        v2.push_back(Pair("maxparts", (int)nNyxMaxParts));
        v2.push_back(Pair("private_sets", (int)vPriv.size()));
        v2.push_back(Pair("private_bytes", (int64_t)nPriv));
        v2.push_back(Pair("public_sets", (int)vPub.size()));
        v2.push_back(Pair("public_bytes", (int64_t)nPub));
        Array incomplete;
        for (size_t i = 0; i < vPriv.size(); ++i)
            incomplete.push_back(vPriv[i].owner + " " + HexStr(vPriv[i].msgid.begin(), vPriv[i].msgid.end()) + " "
                                 + boost::lexical_cast<std::string>(vPriv[i].nHave) + "/"
                                 + boost::lexical_cast<std::string>(vPriv[i].nCount));
        v2.push_back(Pair("incomplete", incomplete));
        result.push_back(Pair("v2", v2));
    }

    // Only report settings this build actually reads.
    Object config;
    config.push_back(Pair("nyx", GetBoolArg("-nyx", true)));
    // The startup setting. smsg_enabled above is the live state, which
    // smsgenable/smsgdisable can move away from this.
    config.push_back(Pair("smsg_at_startup", !fNoSmsg));
    config.push_back(Pair("nyxmaxfilesize", GetArg("-nyxmaxfilesize", "10995116277760")));
    result.push_back(Pair("config", config));

    // State what the subsystem does not implement, so a caller cannot infer it
    // from the absence of a setting.
    Array unimplemented;
    unimplemented.push_back("forward secrecy");
    unimplemented.push_back("separate messaging identity");
    unimplemented.push_back("delivery acknowledgement");
    result.push_back(Pair("unimplemented", unimplemented));

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

static Value nyx_v2(const Array& params, const std::string& sub)
{
    if (!fNyxV2)
        throw runtime_error("Nyx v2 is not enabled (-nyxv2=1).");
    std::string sError;
    if (sub == "v2sendraw" || sub == "v2sendfill")
    {
        if (params.size() != 3)
            throw runtime_error(sub == "v2sendraw" ? "nyx v2sendraw <address> <hex>" : "nyx v2sendfill <address> <bytes>");
        std::vector<unsigned char> body;
        if (sub == "v2sendraw")
            body = ParseHex(params[2].get_str());
        else
        {
            const int64_t n = boost::lexical_cast<int64_t>(params[2].get_str());
            if (n < 1 || n > (int64_t)NYX_MAX_BODY)
                throw runtime_error("bytes must be 1.." + boost::lexical_cast<std::string>(NYX_MAX_BODY));
            body.resize(n);
            body[0] = 0x01;
            for (int64_t i = 1; i < n; ++i)
                body[i] = (unsigned char)('a' + i % 26);
        }
        std::string msgid;
        if (SecureMsgV2SendPrivate(params[1].get_str(), body, msgid, sError) != 0)
            throw runtime_error(sError);
        uint8_t h[32];
        NyxSha256(&body[0], body.size(), h);
        Object o;
        o.push_back(Pair("msgid", msgid));
        o.push_back(Pair("bytes", (int)body.size()));
        o.push_back(Pair("parts", (int)((body.size() + NYX_PART_BODY_MAX - 1) / NYX_PART_BODY_MAX)));
        o.push_back(Pair("sha256", HexStr(h, h + 32)));
        return o;
    }
    if (sub == "v2recv")
    {
        std::vector<NyxV2Delivered> v;
        SecureMsgV2Delivered(v);
        Array a;
        for (size_t i = 0; i < v.size(); ++i)
        {
            Object o;
            o.push_back(Pair("to", v[i].sAddrTo));
            o.push_back(Pair("msgid", v[i].msgid));
            o.push_back(Pair("type", (int)v[i].type));
            o.push_back(Pair("bytes", (int)v[i].nLen));
            o.push_back(Pair("sha256", HexStr(v[i].hash, v[i].hash + 32)));
            o.push_back(Pair("received", v[i].timeReceived));
            a.push_back(o);
        }
        return a;
    }
    if (sub == "v2publish")
    {
        if (params.size() != 2)
            throw runtime_error("nyx v2publish <hex>");
        if (SecureMsgV2PublishPublic(ParseHex(params[1].get_str()), sError) != 0)
            throw runtime_error(sError);
        return "published";
    }
    if (sub == "poget")
    {
        if (params.size() != 2)
            throw runtime_error("nyx poget <address|addrhash160 hex>");
        std::vector<unsigned char> h;
        CBitcoinAddress addr(params[1].get_str());
        CKeyID id;
        if (addr.IsValid() && addr.GetKeyID(id))
            h.assign(id.begin(), id.end());
        else
            h = ParseHex(params[1].get_str());
        if (h.size() != 20)
            throw runtime_error("Expected an address or 20-byte hash.");
        Object o;
        o.push_back(Pair("asked", SecureMsgPoGet(h)));
        return o;
    }
    if (sub == "polist")
    {
        std::vector<NyxPoListEntry> v;
        SecureMsgPoList(v);
        Array a;
        for (size_t i = 0; i < v.size(); ++i)
        {
            Object o;
            o.push_back(Pair("addrhash", v[i].addrHash));
            o.push_back(Pair("type", (int)v[i].type));
            o.push_back(Pair("epoch", (int64_t)v[i].epoch));
            o.push_back(Pair("seq", (int64_t)v[i].seq));
            o.push_back(Pair("parts", (int)v[i].nParts));
            o.push_back(Pair("lastseen", v[i].lastSeen));
            o.push_back(Pair("relayed", v[i].fRelayed));
            a.push_back(o);
        }
        return a;
    }
    throw runtime_error("Unknown nyx subcommand: " + sub);
}

static uint8_t NyxModeArg(const Array& params, size_t i)
{
    if (params.size() <= i || params[i].get_str() == "pq")
        return NYX_MODE_PQ;
    if (params[i].get_str() == "classical")
        return NYX_MODE_CLASSICAL;
    throw runtime_error("mode must be pq or classical");
}

static Value nyx_identity(const Array& params, const std::string& sub)
{
    std::string sError;
    bool fOk = false;
    Object o;
    const std::string op = params.size() > 1 ? params[1].get_str() : "";
    if (sub == "keyring")
    {
        static const char* usage =
            "nyx keyring init <address> [pq|classical]   First device for the address (default pq)\n"
            "nyx keyring show <address>                   This node's device and keyring\n"
            "nyx keyring contact <address>                Fetch, verify and pin a contact's keyring\n"
            "nyx keyring accept <address> [downgrade]     Accept a contact's identity reset\n"
            "nyx keyring reset <address> [pq|classical]   Replace every device (epoch + 1)\n"
            "nyx keyring confirm <address>                Resolve a keyring conflict or clone alarm on this device";
        if (params.size() < 3)
            throw runtime_error(usage);
        const std::string addr = params[2].get_str();
        if (op == "init")
            fOk = NyxIdKeyringInit(addr, NyxModeArg(params, 3), o, sError);
        else if (op == "show")
            fOk = NyxIdKeyringShow(addr, o, sError);
        else if (op == "contact")
            fOk = NyxIdContact(addr, o, sError);
        else if (op == "accept")
            fOk = NyxIdAcceptReset(addr, params.size() > 3 && params[3].get_str() == "downgrade", o, sError);
        else if (op == "reset")
            fOk = NyxIdKeyringReset(addr, NyxModeArg(params, 3), o, sError);
        else if (op == "confirm")
            fOk = NyxIdKeyringConfirm(addr, o, sError);
        else
            throw runtime_error(usage);
    }
    else if (sub == "devices")
    {
        if (params.size() != 2)
            throw runtime_error("nyx devices <address>");
        Array a;
        if (!NyxIdDevices(params[1].get_str(), a, sError))
            throw JSONRPCError(-13, sError);
        return a;
    }
    else
    {
        static const char* usage =
            "nyx device pair <address> [pq|classical]     New node: create keys and print a pairing request\n"
            "nyx device approve <address> <request>       Existing device: sign the new device in (keyring seq + 1)\n"
            "nyx device install <address> <cert>          New node: install the approved cert and publish its bundle\n"
            "nyx device revoke <address> <deviceid>       Remove a device (keyring seq + 1)";
        if (params.size() < 3)
            throw runtime_error(usage);
        const std::string addr = params[2].get_str();
        if (op == "pair")
            fOk = NyxIdPairRequest(addr, NyxModeArg(params, 3), o, sError);
        else if (op == "approve" && params.size() == 4)
            fOk = NyxIdApprove(addr, params[3].get_str(), o, sError);
        else if (op == "install" && params.size() == 4)
            fOk = NyxIdInstall(addr, params[3].get_str(), o, sError);
        else if (op == "revoke" && params.size() == 4)
            fOk = NyxIdRevoke(addr, params[3].get_str(), o, sError);
        else
            throw runtime_error(usage);
    }
    if (!fOk)
        throw JSONRPCError(-13, sError);
    return o;
}

static Value nyx_session(const Array& params)
{
    static const char* usage =
        "nyx session send <from> <to> <message>     PQXDH/X3DH session message to every live device of <to>\n"
        "nyx session list <address>                 Sessions of this node's device for <address>\n"
        "nyx session messages <address> [peer]      Session inbox and sent messages (decrypted once, stored sealed)\n"
        "nyx session delete <address> <peer>        Erase the session state with <peer>\n"
        "nyx session groupcreate <address> <name> <member>...  Group over sessions (max 10 members incl. you)\n"
        "nyx session groupsend <address> <gid> <message>\n"
        "nyx session groupadd|groupremove <address> <gid> <member>   Owner only; a removed member gets no later message\n"
        "nyx session groupleave <address> <gid>\n"
        "nyx session grouplist <address>\n"
        "nyx session groupmessages <address> <gid>";
    const std::string op = params.size() > 1 ? params[1].get_str() : "";
    std::string sError;
    bool fOk = false;
    if (op == "send" && params.size() == 5)
    {
        Object o;
        if (!NyxSessSend(params[2].get_str(), params[3].get_str(), params[4].get_str(), o, sError))
            throw JSONRPCError(-13, sError);
        return o;
    }
    if ((op == "list" && params.size() == 3) || (op == "messages" && (params.size() == 3 || params.size() == 4)))
    {
        Array a;
        fOk = op == "list" ? NyxSessList(params[2].get_str(), a, sError)
                           : NyxSessMessages(params[2].get_str(), params.size() == 4 ? params[3].get_str() : "", a, sError);
        if (!fOk)
            throw JSONRPCError(-13, sError);
        return a;
    }
    if (op == "groupcreate" && params.size() >= 5)
    {
        Object o;
        std::vector<std::string> m;
        for (size_t i = 4; i < params.size(); ++i)
            m.push_back(params[i].get_str());
        if (!NyxGroupCreate2(params[2].get_str(), params[3].get_str(), m, o, sError))
            throw JSONRPCError(-13, sError);
        return o;
    }
    if (op == "groupsend" && params.size() == 5)
    {
        Object o;
        if (!NyxGroupSend2(params[2].get_str(), params[3].get_str(), params[4].get_str(), o, sError))
            throw JSONRPCError(-13, sError);
        return o;
    }
    if (((op == "groupadd" || op == "groupremove") && params.size() == 5) || (op == "groupleave" && params.size() == 4))
    {
        Object o;
        if (!NyxGroupChange2(op.substr(5), params[2].get_str(), params[3].get_str(),
                             params.size() == 5 ? params[4].get_str() : "", o, sError))
            throw JSONRPCError(-13, sError);
        return o;
    }
    if ((op == "grouplist" && params.size() == 3) || (op == "groupmessages" && params.size() == 4))
    {
        Array a;
        fOk = op == "grouplist" ? NyxGroupList2(params[2].get_str(), a, sError)
                                : NyxGroupMessages2(params[2].get_str(), params[3].get_str(), a, sError);
        if (!fOk)
            throw JSONRPCError(-13, sError);
        return a;
    }
    if (op == "delete" && params.size() == 4)
    {
        Object o;
        if (!NyxSessDelete(params[2].get_str(), params[3].get_str(), o, sError))
            throw JSONRPCError(-13, sError);
        return o;
    }
    throw runtime_error(usage);
}

Value nyx(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "nyx <subcommand> [params...]\n"
            "\nNyx Messaging Protocol — encrypted decentralized messaging.\n"
            "\nSubcommands:\n"
            "  send <from> <to> <message> [force]\n"
            "                              Send an encrypted message (secret-looking text needs force)\n"
            "  sendanon <to> <message> [force]\n"
            "                              Send an anonymous encrypted message\n"
            "  sendembed <from> <to> <message> <title> [description] [site]\n"
            "                              Send with a link preview card (fields supplied by the caller)\n"
            "  removeembed <embedid>       Remove a preview card you sent, for everyone\n"
            "  reply <mid> <message> [force] Reply to a message (mid from inbox/outbox/thread)\n"
            "  react <mid> <emoji> [remove] Add or remove a reaction\n"
            "  edit <mid> <newtext>        Edit a message you sent (48 h)\n"
            "  unsend <mid>                Delete a message you sent, for everyone\n"
            "  thread <address>            Conversation view with replies, reactions and edits applied\n"
            "  groupcreate <from> <name> <member>...  Create a group (max 10 members incl. you)\n"
            "  grouplist                   Groups, including invites (request=true)\n"
            "  groupinfo|groupthread|groupleave|groupaccept|grouphide <gid>\n"
            "  groupsend <gid> <message> [force]\n"
            "  groupadd|groupremove|groupowner <gid> <address>   Owner only\n"
            "  grouprename <gid> <name>    Owner only\n"
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
            "  accept|block|unblock <address>\n"
            "                              Accept a message request, or block/unblock a sender\n"
            "\nv2 wire (-nyxv2=1, test surface):\n"
            "  v2sendraw <address> <hex>   Send a body as {2,0} parts\n"
            "  v2sendfill <address> <bytes> Send a generated 0x01 body of that size\n"
            "  v2recv                      Bodies completed by the reassembler\n"
            "  v2publish <hex>             Publish a public object body\n"
            "  poget <address|hash160>     Ask v2 peers for an address's public objects\n"
            "  polist                      Stored public objects\n"
            "\nv2 identity (-nyxv2=1):\n"
            "  keyring init|show|contact|accept|reset|confirm <address> ...\n"
            "  devices <address>           Live devices of an address\n"
            "  device pair|approve|install|revoke <address> ...\n"
            "  session send|list|messages|delete ...  1:1 post-quantum sessions\n"
            "  session group* ...          Groups over sessions (nyx session for usage)\n"
        );

    std::string subcmd = params[0].get_str();

    if (subcmd == "send")        return nyx_send(params);
    if (subcmd == "sendanon")    return nyx_sendanon(params);
    if (subcmd == "sendembed")   return nyx_sendembed(params);
    if (subcmd == "removeembed") return nyx_removeembed(params);
    if (subcmd == "reply")       return nyx_reply(params);
    if (subcmd == "react")       return nyx_react(params);
    if (subcmd == "edit")        return nyx_edit(params);
    if (subcmd == "unsend")      return nyx_unsend(params);
    if (subcmd == "thread")      return nyx_thread(params);
    if (subcmd.compare(0, 5, "group") == 0) return nyx_group(params, subcmd);
    if (subcmd == "inbox")       return nyx_inbox(params);
    if (subcmd == "accept" || subcmd == "block" || subcmd == "unblock")
        return nyx_contact(params, subcmd);
    if (subcmd == "outbox")      return nyx_outbox(params);
    if (subcmd == "read")        return nyx_read(params);
    if (subcmd == "delete")      return nyx_delete(params);
    if (subcmd == "markread")    return nyx_markread(params);
    if (subcmd == "enable")      return nyx_enable(params);
    if (subcmd == "disable")     return nyx_disable(params);
    if (subcmd == "status")      return nyx_status(params);
    if (subcmd == "peers")       return nyx_peers(params);
    if (subcmd == "session")     return nyx_session(params);
    if (subcmd == "keyring" || subcmd == "devices" || subcmd == "device")
        return nyx_identity(params, subcmd);
    if (subcmd.compare(0, 2, "v2") == 0 || subcmd == "poget" || subcmd == "polist")
        return nyx_v2(params, subcmd);

    throw runtime_error("Unknown nyx subcommand: " + subcmd + ". Run 'nyx help' for usage.");
}
