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
// Layout: 'G' 0x01 gid[16 hex] epoch[4 hex] op[2 hex] [prev[32 hex]] payload [sig[130 hex]]; strings are 2-hex length + bytes.
// The roster is an op log: genesis (ROSTER, epoch 0) whose content the gid binds, then ADD/REMOVE/RENAME/OWNER
// ops chained by prev and compact-signed by the owner as of the previous op. MSG/LEAVE are unchained.

static const size_t NYX_GROUP_MAX = 10;        // members including the owner
static const size_t NYX_GROUP_NAME_MAX = 48;
static const size_t NYX_GROUP_ADDR_MAX = 64;
static const size_t NYX_TYPING_GROUP_MAX = 3;
static const int NYX_GROUP_OPS_MAX = 64;       // chained ops after genesis

enum NyxGroupOp
{
    NYX_GOP_MSG = 0,
    NYX_GOP_ROSTER = 1,
    NYX_GOP_ADD = 2,
    NYX_GOP_REMOVE = 3,
    NYX_GOP_LEAVE = 4,
    NYX_GOP_RENAME = 5,
    NYX_GOP_OWNER = 6,
    NYX_GOP_CHAIN = 7,                  // bundle of encoded chain records for a new member
};

/** Chained ops: carry prev and an owner signature. */
bool NyxGroupOpChained(int op);

struct NyxGroupRec
{
    std::string gid;
    int epoch;
    int op;
    std::string name;                   // roster, rename
    std::vector<std::string> members;   // roster
    std::string addr;                   // add, remove, owner
    std::string creator;                // roster: gid binding
    int64_t createTime;
    std::string rnd;                    // roster: 32 hex
    std::string prev;                   // chained: 32 hex, hash of the previous op
    std::string sig;                    // chained: 130 hex compact signature
    std::vector<std::string> chain;     // chain bundle
    NyxGroupRec() : epoch(0), op(NYX_GOP_MSG), createTime(0) {}
};

/** gid of a genesis record equals NyxNewGroupId over its content. */
bool NyxGroupIdBinds(const NyxGroupRec& genesis);

/** 16 hex: first 8 bytes of SHA256(creator || createTime LE64 || rnd || SHA256(name, members)). */
std::string NyxNewGroupId(const std::string& creator, int64_t createTime, const unsigned char rnd[16],
                          const std::string& name, const std::vector<std::string>& members);

/** Bytes a chained op's signature covers (the encoding without sig). */
std::string NyxGroupSigningBytes(const NyxGroupRec& g);
/** 32 hex: first 16 bytes of SHA256(signing bytes); the next op's prev. */
std::string NyxGroupOpHash(const NyxGroupRec& g);
void NyxGroupDigest(const NyxGroupRec& g, unsigned char out[32]);

/** Recovers the signer address of a compact signature; empty on failure. Replaceable for tests. */
typedef std::string (*NyxGroupRecoverFn)(const unsigned char digest[32], const std::string& sigHex);
void NyxGroupSetRecover(NyxGroupRecoverFn fn);
std::string NyxGroupRecover(const NyxGroupRec& g);

/** Chain bundles each within maxBytes of encoded records. */
std::vector<NyxGroupRec> NyxGroupChainBundles(const std::string& gid, const std::vector<std::string>& chain, size_t maxBytes);

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
    bool fValid, fFrozen;               // fFrozen: owner signed two ops at one position
    std::string gid, owner, name, creator, rnd, head;
    std::vector<std::string> chain;     // encoded genesis + ops
    int64_t createTime;
    int epoch;
    std::vector<std::string> members;               // owner first
    std::map<int, std::set<std::string> > history;  // epoch -> roster
    std::map<std::string, int> removedAt;           // member -> epoch of its removal or leave
    int64_t lastTs;
    NyxGroupState() : fValid(false), fFrozen(false), createTime(0), epoch(0), lastTs(0) {}
    bool IsMember(const std::string& a) const;
};

/** Apply one record. First sight takes only a genesis that binds the gid. Chained ops must extend the head
    and be signed by the current owner; LEAVE is taken from signer. False (state unchanged) when not honoured. */
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

/** Build each group from the set of records, independent of delivery order: walk the chain from genesis;
    two distinct owner-signed ops at one position freeze the group. Leaves apply unless a later add. */
std::map<std::string, NyxGroupState> NyxBuildGroups(const std::vector<NyxGroupEvent>& events);

/** Typing record 'T' 0x01 state. */
std::string NyxEncodeTyping(bool fTyping);
bool NyxDecodeTyping(const std::string& rec, bool& fTyping);
static const int64_t NYX_TYPING_SEND_INTERVAL = 60;
static const int64_t NYX_TYPING_MAX_AGE = 90;

#endif // INNOVA_NYXGROUP_H
