// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_IDNSDESCRIPTOR_H
#define INN_IDNSDESCRIPTOR_H

#include <string>
#include <vector>

#ifndef WIN32
#include <unistd.h>  // compat.h calls close() without declaring it
#endif

#include "compat.h"
#include "json/json_spirit_value.h"

class CService;

// IDNS rendezvous descriptor: a convention over name-value bytes (consensus only
// bounds length). Names a Tor onion service; resolution goes through SOCKS5, so no
// IP is held here.

// v1 grammar, whole-value:
//
//   value    = "idnsrv" version ":" host ":" port
//   version  = 1*3DIGIT              ; no leading zero
//   host     = 56(LOWERBASE32) ".onion"
//   port     = 1*5DIGIT              ; 1..65535, no leading zero
//
// Every byte is printable ASCII. The value transits std::string, c_str() and
// snprintf on the resolver path, so an embedded NUL would truncate it.
extern const char* IDNS_RENDEZVOUS_FAMILY;      // "idnsrv"
static const int IDNS_RENDEZVOUS_VERSION = 1;   // the only version this build resolves
static const size_t IDNS_RENDEZVOUS_MAX_VALUE = 96;
static const size_t IDNS_ONION_V3_BASE32_LEN = 56;
static const unsigned char IDNS_ONION_V3_VERSION_BYTE = 0x03;

// Default SOCKS5 endpoint for the rendezvous dial (external tor). -nativetor=1 prefers
// NATIVETOR_SOCKS_PORT; -idnssocks overrides both.
extern const char* IDNS_DEFAULT_SOCKS_ENDPOINT; // "127.0.0.1:9050"
static const unsigned short IDNS_DEFAULT_SOCKS_PORT = 9050;

// SocksPort the bundled tor is started on; see run_tor() in net.cpp. The IDNS
// resolver and the tor daemon must agree on this, so it is defined once.
static const unsigned short NATIVETOR_SOCKS_PORT = 9089;

// How long init waits for tor to publish the onion descriptor and write the
// hostname file. Bootstrap plus descriptor upload is a few seconds on a warm
// network and slower on a cold one; failing to get one is not fatal.
static const int NATIVETOR_HOSTNAME_TIMEOUT_SECS = 120;

enum IDnsValueKind
{
    // Not in the descriptor family: a conventional A=/NS=/TXT= record. The
    // legacy resolver path is unchanged for these.
    IDNS_VALUE_RECORD = 0,
    // A descriptor this build understands.
    IDNS_VALUE_RENDEZVOUS = 1,
    // The descriptor family, but a version this build does not know or a body it
    // refuses. Resolution fails closed: it is not retried as a plain record.
    IDNS_VALUE_UNSUPPORTED = 2,
};

class CIDnsRendezvous
{
public:
    int nVersion;
    std::string strHost;   // lowercase, with the ".onion" suffix
    int nPort;

    CIDnsRendezvous() : nVersion(0), nPort(0) {}
    bool IsNull() const { return strHost.empty(); }
    // The canonical value bytes for this descriptor. Empty if it is not valid.
    std::string ToValue() const;
};

// True for any value in the descriptor family, valid or not. This is the
// predicate a resolver uses to decide "not a plain record", so an unknown
// version and a malformed body both stop here rather than falling through.
bool IsIDnsRendezvousFamily(const std::string& strValue);

// Full classification. strErr is set only for IDNS_VALUE_UNSUPPORTED.
IDnsValueKind ClassifyIDnsValue(const std::string& strValue,
                                CIDnsRendezvous& rendezvousOut,
                                std::string& strErr);

// Parse a v1 descriptor. False for anything else, including a well-formed
// descriptor of another version.
bool ParseIDnsRendezvous(const std::string& strValue, CIDnsRendezvous& out,
                         std::string& strErr);

// Build the canonical v1 value for a v3 onion host and port.
bool BuildIDnsRendezvous(const std::string& strHost, int nPort,
                         std::string& strValueOut, std::string& strErr);

// Shape check for a v3 onion hostname: 56 lowercase base32 chars, ".onion", version byte
// 0x03. The checksum is NOT verified (no SHA3-256 in the tree).
bool IsIDnsOnionV3Host(const std::string& strHost, std::string& strErr);

// The value the built-in DNS server may answer with for a "dns:<name>" key. False
// when unresolved or when the value is a rendezvous descriptor.
bool GetIDnsRecordValue(const std::string& strDnsName, std::string& strValueOut);

// The configured SOCKS5 endpoint, from -idnssocks. False when rendezvous dialing
// is disabled (-idnssocks=0) or the argument does not parse.
bool GetIDnsSocksEndpoint(CService& addrOut, std::string& strErr);

// Dial a descriptor's service through the SOCKS5 endpoint, by hostname. There is
// no direct-connection fallback: if the proxy is unusable the dial fails.
bool ConnectIDnsRendezvous(const CIDnsRendezvous& rendezvous, SOCKET& hSocketRet,
                           std::string& strErr);

// RPC view of a name value: stored value, classification and descriptor fields. Never a
// resolved address or proxy endpoint; this node holds none.
json_spirit::Object IDnsValueInfo(const std::string& strName,
                                  const std::string& strValue);

#endif // INN_IDNSDESCRIPTOR_H
