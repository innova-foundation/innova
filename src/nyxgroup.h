// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INNOVA_NYXGROUP_H
#define INNOVA_NYXGROUP_H

#include <map>
#include <set>
#include <stdint.h>
#include <string>
#include <vector>

// Group chats by pairwise fan-out: one SMSG per member, each carrying a 'G' record.
// Layout: 'G' 0x01 gid[16 hex] epoch[4 hex] op[2 hex] payload; strings are 2-hex length + bytes.

static const size_t NYX_GROUP_MAX = 10;        // members including the owner
static const size_t NYX_GROUP_NAME_MAX = 48;
static const size_t NYX_GROUP_ADDR_MAX = 64;
static const size_t NYX_TYPING_GROUP_MAX = 3;

enum NyxGroupOp
{
    NYX_GOP_MSG = 0,
    NYX_GOP_ROSTER = 1,
    NYX_GOP_ADD = 2,
    NYX_GOP_REMOVE = 3,
    NYX_GOP_LEAVE = 4,
    NYX_GOP_RENAME = 5,
    NYX_GOP_OWNER = 6,
};

struct NyxGroupRec
{
    std::string gid;
    int epoch;
    int op;
    std::string name;                   // roster, rename
    std::vector<std::string> members;   // roster
    std::string addr;                   // add, remove, owner
    NyxGroupRec() : epoch(0), op(NYX_GOP_MSG) {}
};

/** 16 hex: first 8 bytes of SHA256(creator || createTime LE64 || 16 random bytes). */
std::string NyxNewGroupId(const std::string& creator, int64_t createTime, const unsigned char rnd[16]);

std::string NyxEncodeGroup(const NyxGroupRec& g);
/** Strict: unknown op, bad length, bad hex, over-cap roster or duplicate members fail. */
bool NyxDecodeGroup(const std::string& rec, NyxGroupRec& g);

/** "[group: name] " shown by clients that do not read the record. */
std::string NyxGroupFallback(const std::string& name);
/** Drops a leading fallback prefix. */
std::string NyxStripGroupFallback(const std::string& text);

/** Full plaintext: fallback + body, then the G record and any extra records. Empty if over maxBytes. */
std::string NyxGroupPlain(const std::string& name, const std::string& body, const NyxGroupRec& g,
                          const std::vector<std::string>& extraRecs, size_t maxBytes);

struct NyxGroupState
{
    bool fValid;
    std::string gid, owner, name;
    int epoch;
    std::vector<std::string> members;               // owner first
    std::map<int, std::set<std::string> > history;  // epoch -> roster
    std::map<std::string, int64_t> removedAt;       // member -> ts of its removal or leave
    int64_t lastTs;
    NyxGroupState() : fValid(false), epoch(0), lastTs(0) {}
    bool IsMember(const std::string& a) const;
};

/** Apply one roster op signed by signer. False (state unchanged) when the op is not honoured. */
bool NyxGroupApply(NyxGroupState& s, const std::string& signer, int64_t ts, const NyxGroupRec& r);

/** Whether a group message from signer is shown under the state. */
bool NyxGroupMsgAllowed(const NyxGroupState& s, const std::string& signer, int64_t ts, int epoch);

struct NyxGroupEvent
{
    std::string sender, mid;
    int64_t ts;
    NyxGroupRec rec;
    NyxGroupEvent() : ts(0) {}
};

/** Replay roster ops by (epoch, ts, mid); duplicate mids count once. Anonymous senders are ignored. */
std::map<std::string, NyxGroupState> NyxBuildGroups(const std::vector<NyxGroupEvent>& events);

/** Typing record 'T' 0x01 state. */
std::string NyxEncodeTyping(bool fTyping);
bool NyxDecodeTyping(const std::string& rec, bool& fTyping);
static const int64_t NYX_TYPING_SEND_INTERVAL = 60;
static const int64_t NYX_TYPING_MAX_AGE = 90;

#endif // INNOVA_NYXGROUP_H
