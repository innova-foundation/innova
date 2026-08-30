// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "idnsdescriptor.h"

#include <cstring>

#include "hooks.h"
#include "netbase.h"
#include "util.h"

using namespace json_spirit;

const char* IDNS_RENDEZVOUS_FAMILY = "idnsrv";
const char* IDNS_DEFAULT_SOCKS_ENDPOINT = "127.0.0.1:9050";

static const char* IDNS_ONION_SUFFIX = ".onion";
static const size_t IDNS_ONION_V3_DECODED_LEN = 35; // 32 pubkey + 2 checksum + 1 version

namespace
{

// The descriptor travels through std::string, c_str() and snprintf on the
// resolver path, so a byte below 0x21 would truncate or reshape it. Space is
// excluded with the control characters: the grammar has no use for it.
bool IsPrintableAscii(const std::string& str)
{
    for (size_t i = 0; i < str.size(); ++i)
    {
        const unsigned char c = (unsigned char)str[i];
        if (c < 0x21 || c > 0x7e)
            return false;
    }
    return true;
}

// Decimal, no leading zero, in range. Refusing a leading zero keeps one port to
// one byte string, so a descriptor has a single canonical encoding.
bool ParseDecimalStrict(const std::string& str, size_t nMaxDigits, int nMin,
                        int nMax, int& nOut)
{
    if (str.empty() || str.size() > nMaxDigits)
        return false;
    if (str[0] == '0')
        return false;
    int nValue = 0;
    for (size_t i = 0; i < str.size(); ++i)
    {
        if (str[i] < '0' || str[i] > '9')
            return false;
        nValue = nValue * 10 + (str[i] - '0');
    }
    if (nValue < nMin || nValue > nMax)
        return false;
    nOut = nValue;
    return true;
}

// Split "idnsrv<version>:" off the front. False when the tag is malformed, which
// the caller reports as unsupported rather than passing to the record path.
bool SplitRendezvousTag(const std::string& strValue, int& nVersionOut,
                        size_t& nBodyPosOut)
{
    const size_t nFamily = strlen(IDNS_RENDEZVOUS_FAMILY);
    const size_t nSep = strValue.find(':', nFamily);
    if (nSep == std::string::npos)
        return false;
    if (!ParseDecimalStrict(strValue.substr(nFamily, nSep - nFamily), 3, 1, 999,
                            nVersionOut))
        return false;
    nBodyPosOut = nSep + 1;
    return true;
}

std::string ToLower(const std::string& str)
{
    std::string strOut = str;
    for (size_t i = 0; i < strOut.size(); ++i)
        if (strOut[i] >= 'A' && strOut[i] <= 'Z')
            strOut[i] = (char)(strOut[i] - 'A' + 'a');
    return strOut;
}

} // namespace

bool IsIDnsOnionV3Host(const std::string& strHost, std::string& strErr)
{
    strErr.clear();
    const size_t nSuffix = strlen(IDNS_ONION_SUFFIX);
    if (strHost.size() != IDNS_ONION_V3_BASE32_LEN + nSuffix)
    {
        strErr = "onion hostname is not a 56-character v3 address";
        return false;
    }
    if (strHost.compare(IDNS_ONION_V3_BASE32_LEN, nSuffix, IDNS_ONION_SUFFIX) != 0)
    {
        strErr = "onion hostname does not end in .onion";
        return false;
    }
    for (size_t i = 0; i < IDNS_ONION_V3_BASE32_LEN; ++i)
    {
        const char c = strHost[i];
        const bool fLetter = (c >= 'a' && c <= 'z');
        const bool fDigit = (c >= '2' && c <= '7');
        if (!fLetter && !fDigit)
        {
            strErr = "onion hostname is not lowercase base32";
            return false;
        }
    }
    bool fInvalid = false;
    const std::vector<unsigned char> vchAddr = DecodeBase32(
        strHost.substr(0, IDNS_ONION_V3_BASE32_LEN).c_str(), &fInvalid);
    if (fInvalid || vchAddr.size() != IDNS_ONION_V3_DECODED_LEN)
    {
        strErr = "onion hostname does not decode to a v3 address";
        return false;
    }
    // The trailing byte is the address version. The v3 checksum is not verified:
    // it is SHA3-256 based and this tree has no SHA3, so a hostname that passes
    // here can still be one no service answers on.
    if (vchAddr[IDNS_ONION_V3_DECODED_LEN - 1] != IDNS_ONION_V3_VERSION_BYTE)
    {
        strErr = "onion address version byte is not 3";
        return false;
    }
    return true;
}

bool IsIDnsRendezvousFamily(const std::string& strValue)
{
    const size_t nFamily = strlen(IDNS_RENDEZVOUS_FAMILY);
    return strValue.compare(0, nFamily, IDNS_RENDEZVOUS_FAMILY) == 0;
}

bool ParseIDnsRendezvous(const std::string& strValue, CIDnsRendezvous& out,
                         std::string& strErr)
{
    out = CIDnsRendezvous();
    strErr.clear();

    if (!IsIDnsRendezvousFamily(strValue))
    {
        strErr = "value is not a rendezvous descriptor";
        return false;
    }
    if (strValue.size() > IDNS_RENDEZVOUS_MAX_VALUE)
    {
        strErr = "rendezvous descriptor is too long";
        return false;
    }
    if (!IsPrintableAscii(strValue))
    {
        strErr = "rendezvous descriptor has a non-printable byte";
        return false;
    }

    int nVersion = 0;
    size_t nBodyPos = 0;
    if (!SplitRendezvousTag(strValue, nVersion, nBodyPos))
    {
        strErr = "malformed rendezvous descriptor tag";
        return false;
    }
    if (nVersion != IDNS_RENDEZVOUS_VERSION)
    {
        strErr = strprintf("unsupported rendezvous descriptor version %d",
                           nVersion);
        return false;
    }

    const std::string strBody = strValue.substr(nBodyPos);
    const size_t nSep = strBody.find(':');
    if (nSep == std::string::npos)
    {
        strErr = "rendezvous descriptor has no port";
        return false;
    }
    const std::string strHost = strBody.substr(0, nSep);
    if (!IsIDnsOnionV3Host(strHost, strErr))
        return false;

    int nPort = 0;
    if (!ParseDecimalStrict(strBody.substr(nSep + 1), 5, 1, 65535, nPort))
    {
        strErr = "rendezvous descriptor has an invalid port";
        return false;
    }

    out.nVersion = nVersion;
    out.strHost = strHost;
    out.nPort = nPort;
    return true;
}

IDnsValueKind ClassifyIDnsValue(const std::string& strValue,
                                CIDnsRendezvous& rendezvousOut,
                                std::string& strErr)
{
    rendezvousOut = CIDnsRendezvous();
    strErr.clear();
    if (!IsIDnsRendezvousFamily(strValue))
        return IDNS_VALUE_RECORD;
    if (ParseIDnsRendezvous(strValue, rendezvousOut, strErr))
        return IDNS_VALUE_RENDEZVOUS;
    return IDNS_VALUE_UNSUPPORTED;
}

std::string CIDnsRendezvous::ToValue() const
{
    std::string strErr;
    if (nVersion != IDNS_RENDEZVOUS_VERSION || nPort < 1 || nPort > 65535)
        return std::string();
    if (!IsIDnsOnionV3Host(strHost, strErr))
        return std::string();
    return strprintf("%s%d:%s:%d", IDNS_RENDEZVOUS_FAMILY,
                     IDNS_RENDEZVOUS_VERSION, strHost.c_str(), nPort);
}

bool BuildIDnsRendezvous(const std::string& strHost, int nPort,
                         std::string& strValueOut, std::string& strErr)
{
    strValueOut.clear();
    strErr.clear();

    // Bound the input before copying it: this is reachable from an RPC argument.
    if (strHost.size() > IDNS_RENDEZVOUS_MAX_VALUE)
    {
        strErr = "onion hostname is not a 56-character v3 address";
        return false;
    }

    // Creation canonicalises case; parsing does not. One service therefore has
    // exactly one on-chain byte string.
    CIDnsRendezvous rendezvous;
    rendezvous.nVersion = IDNS_RENDEZVOUS_VERSION;
    rendezvous.strHost = ToLower(strHost);
    rendezvous.nPort = nPort;

    if (!IsIDnsOnionV3Host(rendezvous.strHost, strErr))
        return false;
    if (nPort < 1 || nPort > 65535)
    {
        strErr = "port is out of range";
        return false;
    }

    const std::string strValue = rendezvous.ToValue();
    if (strValue.empty() || strValue.size() > IDNS_RENDEZVOUS_MAX_VALUE ||
        !IsPrintableAscii(strValue))
    {
        strErr = "failed to encode rendezvous descriptor";
        return false;
    }
    strValueOut = strValue;
    return true;
}

bool GetIDnsRecordValue(const std::string& strDnsName, std::string& strValueOut)
{
    strValueOut.clear();
    std::string strValue;
    if (hooks == NULL)
        return false;
    if (!hooks->getNameValue(strDnsName, strValue))
        return false;
    // Fail closed on the whole descriptor family, valid or not: an unknown
    // version must not be answered as if it were an address record.
    if (IsIDnsRendezvousFamily(strValue))
        return false;
    strValueOut = strValue;
    return true;
}

bool GetIDnsSocksEndpoint(CService& addrOut, std::string& strErr)
{
    strErr.clear();
    const std::string strArg = GetArg("-idnssocks", IDNS_DEFAULT_SOCKS_ENDPOINT);
    if (strArg.empty() || strArg == "0")
    {
        strErr = "rendezvous dialing is disabled (-idnssocks=0)";
        return false;
    }
    CService addr;
    if (!LookupNumeric(strArg.c_str(), addr, IDNS_DEFAULT_SOCKS_PORT) ||
        !addr.IsValid())
    {
        strErr = "invalid -idnssocks endpoint: " + strArg;
        return false;
    }
    addrOut = addr;
    return true;
}

bool ConnectIDnsRendezvous(const CIDnsRendezvous& rendezvous, SOCKET& hSocketRet,
                           std::string& strErr)
{
    hSocketRet = INVALID_SOCKET;
    strErr.clear();

    if (rendezvous.nVersion != IDNS_RENDEZVOUS_VERSION)
    {
        strErr = "unsupported rendezvous descriptor version";
        return false;
    }
    if (!IsIDnsOnionV3Host(rendezvous.strHost, strErr))
        return false;
    if (rendezvous.nPort < 1 || rendezvous.nPort > 65535)
    {
        strErr = "rendezvous port is out of range";
        return false;
    }

    CService addrProxy;
    if (!GetIDnsSocksEndpoint(addrProxy, strErr))
        return false;

    // Hostname CONNECT only. The host is not resolved here and there is no
    // direct-connection fallback, so a proxy that is down is a failed dial and
    // never a clear-net connection.
    if (!ConnectSocks5ByName(addrProxy, rendezvous.strHost, rendezvous.nPort,
                             hSocketRet, nConnectTimeout))
    {
        strErr = "rendezvous dial failed";
        return false;
    }
    return true;
}

Object IDnsValueInfo(const std::string& strName, const std::string& strValue)
{
    Object oInfo;
    CIDnsRendezvous rendezvous;
    std::string strErr;
    const IDnsValueKind kind = ClassifyIDnsValue(strValue, rendezvous, strErr);

    // The value is echoed as stored. A conventional record therefore prints
    // whatever address its operator put in it; a descriptor prints an onion
    // hostname, because that is all a descriptor contains.
    oInfo.push_back(Pair("name", strName));
    oInfo.push_back(Pair("value", strValue));
    switch (kind)
    {
    case IDNS_VALUE_RENDEZVOUS:
        oInfo.push_back(Pair("kind", "rendezvous"));
        oInfo.push_back(Pair("resolvable", true));
        oInfo.push_back(Pair("descriptor_version", rendezvous.nVersion));
        oInfo.push_back(Pair("host", rendezvous.strHost));
        oInfo.push_back(Pair("port", rendezvous.nPort));
        break;
    case IDNS_VALUE_UNSUPPORTED:
        oInfo.push_back(Pair("kind", "unsupported"));
        oInfo.push_back(Pair("resolvable", false));
        oInfo.push_back(Pair("error", strErr));
        break;
    case IDNS_VALUE_RECORD:
    default:
        oInfo.push_back(Pair("kind", "record"));
        oInfo.push_back(Pair("resolvable", true));
        break;
    }
    return oInfo;
}
