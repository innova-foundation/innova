// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INNOVA_NYXSAFETY_H
#define INNOVA_NYXSAFETY_H

#include <set>
#include <string>

// Local, heuristic message safety checks. Nothing here leaves the machine.

static const char* const NYX_SECRET_WARNING =
    "Never share your recovery phrase or private keys. Innova staff will never ask for them.";

enum NyxSecretKind
{
    NYX_SECRET_NONE = 0,
    NYX_SECRET_PHRASE,    // BIP39-looking word run
    NYX_SECRET_PRIVKEY,   // WIF or other base58check key material
    NYX_SECRET_XPRV,      // extended private key
    NYX_SECRET_HEXSEED,   // 64+ hex chars next to seed/key wording
};

NyxSecretKind NyxDetectSecret(const std::string& text);
std::string NyxSecretKindName(NyxSecretKind k);

/** Incoming text that asks for a recovery phrase, key or a wallet "verification". */
bool NyxLooksLikeScam(const std::string& text);

enum NyxSenderState
{
    NYX_SENDER_KNOWN = 0,
    NYX_SENDER_REQUEST,   // links inert, no card, until accepted
    NYX_SENDER_BLOCKED,   // discarded
};

NyxSenderState NyxClassifySender(const std::string& from, bool fSentTo, bool fInAddressBook,
                                 bool fAccepted, bool fBlocked);

/** Accepted and blocked senders; one "accept <addr>" or "block <addr>" per line. */
class NyxContactLists
{
public:
    std::set<std::string> setAccepted;
    std::set<std::string> setBlocked;

    void Parse(const std::string& data);
    std::string Serialize() const;
    bool Load(const std::string& path);
    bool Save(const std::string& path) const;
};

bool NyxIsValidContactAddress(const std::string& addr);

/** Process-wide lists persisted as nyxcontacts.dat in the data dir. */
bool NyxIsAccepted(const std::string& addr);
bool NyxIsBlocked(const std::string& addr);
bool NyxHasBlocked();
bool NyxAccept(const std::string& addr);
bool NyxBlock(const std::string& addr);
bool NyxUnblock(const std::string& addr);

/** Drop utm_*, fbclid, gclid, mc_eid, igshid and similar query parameters. */
std::string NyxStripTracking(const std::string& url);
/** NyxStripTracking applied to every linkable URL in text. */
std::string NyxStripTrackingInText(const std::string& text);

/** Approximate registrable domain (eTLD+1) of a lowercase ASCII host. */
std::string NyxRegistrableDomain(const std::string& host);

enum
{
    NYX_URL_IDN          = 1,  // a punycode label
    NYX_URL_LOOKALIKE    = 2,  // mixed-script or all-confusable label, or bad punycode
    NYX_URL_HIDDEN_CHARS = 4,  // bidi or zero-width characters, raw or percent-encoded
};
int NyxUrlRiskFlags(const std::string& url);

/** RFC 3492 decode of one label without the xn-- prefix. */
bool NyxPunycodeDecode(const std::string& in, std::u32string& out);

#endif // INNOVA_NYXSAFETY_H
