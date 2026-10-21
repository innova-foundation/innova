// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INNOVA_NYXEXT_H
#define INNOVA_NYXEXT_H

#include <functional>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include "nyxgroup.h"

// Reply, reaction, edit and delete records ride after the NUL like embeds.
// Layout: tag, version 0x01, fields. Lengths are ASCII hex so the record never holds a NUL
// (v5.0 and NyxSplitPlain stop at the second NUL).

static const size_t NYX_QUOTE_MAX = 120;
static const size_t NYX_EMOJI_MAX = 16;
static const int64_t NYX_EDIT_WINDOW = 48 * 3600;
static const size_t NYX_REACT_MAX_EMOJI = 8;       // distinct emoji per reactor per message
static const size_t NYX_REACT_MAX_OPS = 20;        // per reactor per window
static const int64_t NYX_REACT_WINDOW = 600;
static const char* const NYX_DELETED_TEXT = "[message deleted]";
static const char* const NYX_EDITED_PREFIX = "[edited] ";

struct NyxReply { std::string mid, quote; };
struct NyxReact { std::string mid; bool fAdd; std::string emoji; NyxReact() : fAdd(true) {} };
struct NyxEdit { std::string mid; int seq; NyxEdit() : seq(0) {} };

/** 16 hex chars: first 8 bytes of SHA256(sender || timestamp LE64 || full plaintext). */
std::string NyxMessageId(const std::string& sender, int64_t timestamp, const std::string& fullPlain);

std::string NyxEncodeReply(const NyxReply& r);
bool NyxDecodeReply(const std::string& rec, NyxReply& r);
std::string NyxEncodeReact(const NyxReact& k);
bool NyxDecodeReact(const std::string& rec, NyxReact& k);
std::string NyxEncodeEdit(const NyxEdit& e);
bool NyxDecodeEdit(const std::string& rec, NyxEdit& e);
std::string NyxEncodeDelete(const std::string& mid);
bool NyxDecodeDelete(const std::string& rec, std::string& mid);

/** One record passes through; several are wrapped as 'M' 0x01 (len4hex record)*. */
std::string NyxJoinRecords(const std::vector<std::string>& recs);
/** Strict split; a single non-'M' ext yields itself. False on malformed framing. */
bool NyxSplitRecords(const std::string& ext, std::vector<std::string>& out);

/** Short UTF-8 emoji: no controls, spaces or plain letters. */
bool NyxIsReactionEmoji(const std::string& e);

/** Full plaintexts; empty when the result would exceed maxBytes or a field is invalid. */
std::string NyxReplyPlain(const std::string& body, const NyxReply& r, const std::string& extraRec, size_t maxBytes);
std::string NyxReactPlain(const NyxReact& k);
std::string NyxEditPlain(const std::string& body, const NyxEdit& e, size_t maxBytes);
std::string NyxDeletePlain(const std::string& mid);

/** Records of a message by kind; anything unknown is ignored. */
struct NyxRecords
{
    bool fReply, fReact, fEdit, fDelete, fGroup, fTyping;
    bool typingOn;
    NyxGroupRec group;
    NyxReply reply;
    NyxReact react;
    NyxEdit edit;
    std::string delMid;
    std::string embedRec;   // raw embed/removal record, if any
    NyxRecords() : fReply(false), fReact(false), fEdit(false), fDelete(false), fGroup(false), fTyping(false), typingOn(false) {}
    bool IsControl() const { return fReact || fEdit || fDelete; }
};
NyxRecords NyxParseRecords(const std::string& ext);

struct NyxThreadMsg
{
    std::string mid, sender;  // sender "anon" carries no authority
    int64_t ts;
    std::string text, ext;
    NyxThreadMsg() : ts(0) {}
};

struct NyxMsgView
{
    bool fControl;      // applied, not rendered as its own row
    bool fTombstone;    // render as deleted
    bool fEdited;
    int seq;
    std::string text;   // visible text after edits
    bool fReply;
    NyxReply reply;
    int replyIndex;     // row index of the original, -1 if not present
    std::vector<std::pair<std::string, std::vector<std::string> > > reactions; // emoji -> reactors
    NyxMsgView() : fControl(false), fTombstone(false), fEdited(false), seq(0), fReply(false), replyIndex(-1) {}
};

/** Apply controls over rows (any order). fReactAllowed gates which senders' reactions count. */
std::vector<NyxMsgView> NyxBuildThread(const std::vector<NyxThreadMsg>& rows,
                                       const std::function<bool(const std::string&)>& fReactAllowed);

#endif // INNOVA_NYXEXT_H
