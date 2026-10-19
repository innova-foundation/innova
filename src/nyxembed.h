// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INNOVA_NYXEMBED_H
#define INNOVA_NYXEMBED_H

#include <string>
#include <utility>
#include <vector>

// Nyx message extensions ride after a NUL in the signed SMSG plaintext.
// v5.0 clients read the plaintext as a C string, so they show only the text before it.

static const size_t NYX_EMBED_MAX_URL   = 512;
static const size_t NYX_EMBED_MAX_TITLE = 120;
static const size_t NYX_EMBED_MAX_DESC  = 200;
static const size_t NYX_EMBED_MAX_SITE  = 40;
static const size_t NYX_EMBED_MAX_THUMB = 2600;   // raw JPEG bytes
static const char* const NYX_CTL_VISIBLE = "[link preview removed]";

struct NyxEmbed
{
    std::string id;     // 16 lowercase hex chars
    std::string url;    // https only
    std::string title;
    std::string desc;
    std::string site;
    std::string thumb;  // raw JPEG, may be empty
};

/** Split a full plaintext at the first NUL. */
void NyxSplitPlain(const std::string& full, std::string& text, std::string& ext);
std::string NyxComposePlain(const std::string& text, const std::string& ext);

std::string NyxEncodeEmbed(const NyxEmbed& e);
/** Strict decode; sanitises and caps every field. */
bool NyxDecodeEmbed(const std::string& ext, NyxEmbed& e);

/** Ext record asking recipients to hide embed id. */
std::string NyxEncodeRemoval(const std::string& id);
bool NyxDecodeRemoval(const std::string& ext, std::string& id);

/** Full plaintext of a removal control message. */
std::string NyxRemovalPlain(const std::string& id);

/** An embed is hidden only by a removal whose authenticated sender owns it. Anonymous never matches. */
bool NyxEmbedHidden(const std::string& owner, const std::string& id,
                    const std::vector<std::pair<std::string, std::string> >& removals);

bool NyxIsHexId(const std::string& id);

/** Build the ext for text + embed within maxBytes, truncating text fields then dropping the
 *  thumbnail. Returns empty when no card fits. */
std::string NyxFitEmbed(const std::string& text, NyxEmbed e, size_t maxBytes);

/** http/https URL with an ASCII host, no userinfo; true when safe to render as a link. */
bool NyxIsLinkableUrl(const std::string& url);
/** Host from an http(s) URL, lowercased; empty on failure. */
std::string NyxUrlHost(const std::string& url);
/** First https URL in text, empty if none. */
std::string NyxFirstHttpsUrl(const std::string& text);

/** HTML-escape everything and wrap http/https URLs in anchors; newlines become <br>. */
std::string NyxLinkify(const std::string& text);
std::string NyxHtmlEscape(const std::string& s);
/** HTML-escape with newlines as <br>, no anchors. */
std::string NyxEscapeText(const std::string& text);
/** Next linkable http(s) URL at or after pos; returns its start or npos and sets len. */
size_t NyxNextUrl(const std::string& text, size_t pos, size_t& len);

/** Host name a preview may be fetched from: no IP literals, local or onion names, or ports. */
bool NyxIsFetchableHost(const std::string& host, bool fAllowOnion);
/** Address bytes (4 or 16) are globally routable. */
bool NyxIsPublicAddress(const unsigned char* addr, size_t len);

struct NyxPageMeta
{
    std::string title;
    std::string desc;
    std::string site;
    std::string image;  // absolute https URL or empty
};

/** Tokenise only the document head and read OpenGraph, <title> and meta description. */
NyxPageMeta NyxParseHead(const std::string& html, const std::string& pageUrl);

#endif // INNOVA_NYXEMBED_H
