// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_NETBASE_H
#define BITCOIN_NETBASE_H

#include <string>
#include <vector>

#include "serialize.h"
#include "compat.h"

extern int nConnectTimeout;
extern bool fNameLookup;

#ifdef WIN32
// In MSVC, this is defined as a macro, undefine it to prevent a compile and link error
#undef SetPort
#endif

/** Stream version flag selecting BIP155 (addrv2) address encoding. */
static const int ADDRV2_FORMAT = 0x20000000;

/** BIP155 network ids. */
enum BIP155Network : unsigned char
{
    BIP155_IPV4 = 1,
    BIP155_IPV6 = 2,
    BIP155_TORV2 = 3,
    BIP155_TORV3 = 4,
    BIP155_I2P = 5,
    BIP155_CJDNS = 6,
};
static const size_t MAX_ADDRV2_SIZE = 512;
static const size_t TORV3_PUBKEY_SIZE = 32;

enum Network
{
    NET_UNROUTABLE,
    NET_IPV4,
    NET_IPV6,
    NET_TOR,
    NET_I2P,

    NET_MAX,
};

/** IP address (IPv6, or IPv4 using mapped IPv6 range (::FFFF:0:0/96)) */
class CNetAddr
{
    protected:
        unsigned char ip[16]; // in network byte order
        // Tor v3: ip holds the OnionCat prefix + first 10 pubkey bytes (for grouping)
        bool fTorV3;
        unsigned char torv3[32];

    public:
        CNetAddr();
        CNetAddr(const struct in_addr& ipv4Addr);
        explicit CNetAddr(const char *pszIp, bool fAllowLookup = false);
        explicit CNetAddr(const std::string &strIp, bool fAllowLookup = false);
        void Init();
        void SetIP(const CNetAddr& ip);
        bool SetSpecial(const std::string &strName); // for Tor (v2, v3) and I2P addresses
        bool IsIPv4() const;    // IPv4 mapped address (::FFFF:0:0/96, 0.0.0.0/0)
        bool IsIPv6() const;    // IPv6 address (not mapped IPv4, not Tor/I2P)
        bool IsRFC1918() const; // IPv4 private networks (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
        bool IsRFC3849() const; // IPv6 documentation address (2001:0DB8::/32)
        bool IsRFC3927() const; // IPv4 autoconfig (169.254.0.0/16)
        bool IsRFC3964() const; // IPv6 6to4 tunnelling (2002::/16)
        bool IsRFC4193() const; // IPv6 unique local (FC00::/15)
        bool IsRFC4380() const; // IPv6 Teredo tunnelling (2001::/32)
        bool IsRFC4843() const; // IPv6 ORCHID (2001:10::/28)
        bool IsRFC4862() const; // IPv6 autoconfig (FE80::/64)
        bool IsRFC6052() const; // IPv6 well-known prefix (64:FF9B::/96)
        bool IsRFC6145() const; // IPv6 IPv4-translated address (::FFFF:0:0:0/96)
        bool IsTor() const;
        bool IsTorV3() const { return fTorV3; }
        bool IsAddrV1Compatible() const { return !fTorV3; }
        bool IsI2P() const;
        bool IsLocal() const;
        bool IsRoutable() const;
        bool IsValid() const;
        bool IsMulticast() const;
        enum Network GetNetwork() const;
        std::string ToString() const;
        std::string ToStringIP() const;
        unsigned int GetByte(int n) const;
        uint64_t GetHash() const;
        bool GetInAddr(struct in_addr* pipv4Addr) const;
        std::vector<unsigned char> GetGroup() const;
        int GetReachabilityFrom(const CNetAddr *paddrPartner = NULL) const;
        void print() const;

        CNetAddr(const struct in6_addr& pipv6Addr);
        bool GetIn6Addr(struct in6_addr* pipv6Addr) const;

        friend bool operator==(const CNetAddr& a, const CNetAddr& b);
        friend bool operator!=(const CNetAddr& a, const CNetAddr& b);
        friend bool operator<(const CNetAddr& a, const CNetAddr& b);

        void GetBIP155(unsigned char& netId, std::vector<unsigned char>& vch) const;
        bool SetBIP155(unsigned char netId, const std::vector<unsigned char>& vch);

        unsigned int GetSerializeSize(int nType, int nVersion) const
        {
            if (!(nVersion & ADDRV2_FORMAT))
                return 16;
            unsigned char id; std::vector<unsigned char> v;
            GetBIP155(id, v);
            return 1 + GetSizeOfCompactSize(v.size()) + v.size();
        }
        template<typename Stream>
        void Serialize(Stream& s, int nType, int nVersion) const
        {
            if (!(nVersion & ADDRV2_FORMAT)) {
                s.write((const char*)ip, 16);
                return;
            }
            unsigned char id; std::vector<unsigned char> v;
            GetBIP155(id, v);
            s.write((const char*)&id, 1);
            WriteCompactSize(s, v.size());
            if (!v.empty())
                s.write((const char*)&v[0], v.size());
        }
        template<typename Stream>
        void Unserialize(Stream& s, int nType, int nVersion)
        {
            Init();
            if (!(nVersion & ADDRV2_FORMAT)) {
                s.read((char*)ip, 16);
                return;
            }
            unsigned char id = 0;
            s.read((char*)&id, 1);
            uint64_t n = ReadCompactSize(s);
            if (n > MAX_ADDRV2_SIZE)
                throw std::ios_base::failure("addrv2 address too long");
            std::vector<unsigned char> v(n);
            if (n)
                s.read((char*)&v[0], n);
            if (!SetBIP155(id, v))
                throw std::ios_base::failure("addrv2 address size mismatch");
        }
        friend class CSubNet;
};

class CSubNet
{
protected:
    /// Network (base) address
    CNetAddr network;
    /// Netmask, in network byte order
    uint8_t netmask[16];
    /// Is this value valid? (only used to signal parse errors)
    bool valid;

public:
    CSubNet();
    explicit CSubNet(const std::string& strSubnet, bool fAllowLookup = false);

    //constructor for single ip subnet (<ipv4>/32 or <ipv6>/128)
    explicit CSubNet(const CNetAddr &addr);

    bool Match(const CNetAddr& addr) const;

    std::string ToString() const;
    bool IsValid() const;

    friend bool operator==(const CSubNet& a, const CSubNet& b);
    friend bool operator!=(const CSubNet& a, const CSubNet& b);
    friend bool operator<(const CSubNet& a, const CSubNet& b);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        unsigned int nSerSize = 0;
        READWRITE(network);
        READWRITE(FLATDATA(netmask));
        READWRITE(FLATDATA(valid));
    }
};

/** A combination of a network address (CNetAddr) and a (TCP) port */
class CService : public CNetAddr
{
    protected:
        unsigned short port; // host order

    public:
        CService();
        CService(const CNetAddr& ip, unsigned short port);
        CService(const struct in_addr& ipv4Addr, unsigned short port);
        CService(const struct sockaddr_in& addr);
        explicit CService(const char *pszIpPort, int portDefault, bool fAllowLookup = false);
        explicit CService(const char *pszIpPort, bool fAllowLookup = false);
        explicit CService(const std::string& strIpPort, int portDefault, bool fAllowLookup = false);
        explicit CService(const std::string& strIpPort, bool fAllowLookup = false);
        void Init();
        void SetPort(unsigned short portIn);
        unsigned short GetPort() const;
        bool GetSockAddr(struct sockaddr* paddr, socklen_t *addrlen) const;
        bool SetSockAddr(const struct sockaddr* paddr);
        friend bool operator==(const CService& a, const CService& b);
        friend bool operator!=(const CService& a, const CService& b);
        friend bool operator<(const CService& a, const CService& b);
        std::vector<unsigned char> GetKey() const;
        std::string ToString() const;
        std::string ToStringPort() const;
        std::string ToStringIPPort() const;
        void print() const;

        CService(const struct in6_addr& ipv6Addr, unsigned short port);
        CService(const struct sockaddr_in6& addr);

        IMPLEMENT_SERIALIZE
            (
             CService* pthis = const_cast<CService*>(this);
             READWRITE(*(CNetAddr*)pthis);
             unsigned short portN = htons(port);
             READWRITE(portN);
             if (fRead)
                 pthis->port = ntohs(portN);
            )
};

void SHA3_256(const unsigned char* data, size_t len, unsigned char out[32]);

typedef std::pair<CService, int> proxyType;

enum Network ParseNetwork(std::string net);
std::string GetNetworkName(enum Network net);
void SplitHostPort(std::string in, int &portOut, std::string &hostOut);
bool SetProxy(enum Network net, CService addrProxy, int nSocksVersion = 5);
bool GetProxy(enum Network net, proxyType &proxyInfoOut);
bool IsProxy(const CNetAddr &addr);
bool SetNameProxy(CService addrProxy, int nSocksVersion = 5);
bool HaveNameProxy();
bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions = 0, bool fAllowLookup = true);
bool Lookup(const char *pszName, CService& addr, int portDefault = 0, bool fAllowLookup = true);
bool Lookup(const char *pszName, std::vector<CService>& vAddr, int portDefault = 0, bool fAllowLookup = true, unsigned int nMaxSolutions = 0);
bool LookupNumeric(const char *pszName, CService& addr, int portDefault = 0);
//bool ConnectSocket(const CService &addr, SOCKET& hSocketRet, int nTimeout = nConnectTimeout);
//bool ConnectSocketByName(CService &addr, SOCKET& hSocketRet, const char *pszDest, int portDefault = 0, int nTimeout = nConnectTimeout);
bool ConnectSocket(const CService &addr, SOCKET& hSocketRet, int nTimeout, bool *outProxyConnectionFailed = 0);
bool ConnectSocketByName(CService &addr, SOCKET& hSocketRet, const char *pszDest, int portDefault, int nTimeout, bool *outProxyConnectionFailed = 0);
/** SOCKS5 CONNECT request for a hostname destination (ATYP 0x03).
 *  Exposed so a caller can assert on the bytes: a hostname CONNECT carries the
 *  name and no address, so the client neither learns nor sends the peer's IP. */
bool BuildSocks5ConnectRequest(const std::string& strDest, int port, std::vector<unsigned char>& vchOut);
/** SOCKS5 username/password credentials (RFC 1929). Tor keys stream isolation on
 *  the pair, so a distinct pair is a distinct circuit. A mix phase that dials with
 *  its own pair cannot be correlated with another phase by exit path. */
struct ProxyCredentials
{
    std::string strUser;
    std::string strPassword;
};
/** A fresh pair, so the caller lands on its own circuit. */
ProxyCredentials RandomProxyCredentials();
/** SOCKS5 username/password sub-negotiation request (RFC 1929).
 *  Exposed so a caller can assert on the bytes. */
bool BuildSocks5AuthRequest(const ProxyCredentials& auth, std::vector<unsigned char>& vchOut);
/** Dial strDest:port through SOCKS5 by hostname: never resolved locally, no direct fallback.
 *  With credentials only username/password is offered, so a non-isolating proxy fails. */
bool ConnectSocks5ByName(const CService &addrProxy, const std::string& strDest, int port, SOCKET& hSocketRet, int nTimeout, const ProxyCredentials* pAuth = NULL);
/** Connect to a SOCKS5 proxy, offer only the username/password method and read the choice,
 *  then close. No destination is named. False when the TCP connect fails; fSocks5Out and
 *  fAuthOut say what the proxy answered. */
bool ProbeSocks5Proxy(const CService& addrProxy, int nTimeout, bool& fSocks5Out, bool& fAuthOut,
                      std::string& strError);
/** Return readable error string for a network error code */
std::string NetworkErrorString(int err);
/** Close socket and set hSocket to INVALID_SOCKET */
bool CloseSocket(SOCKET& hSocket);
/** Disable or enable blocking-mode for a socket */
bool SetSocketNonBlocking(SOCKET& hSocket, bool fNonBlocking);
/** Arm a socket's receive timeout, portably (Winsock takes DWORD ms, POSIX a timeval;
 *  a timeval passed to Winsock would truncate to tv_sec). Milliseconds <= 0 = do not block. */
void SetSocketReceiveTimeout(SOCKET hSocket, int64_t nMilliseconds);
void SetSocketSendTimeout(SOCKET hSocket, int64_t nMilliseconds);

/**
 * Convert milliseconds to a struct timeval for e.g. select.
 */
struct timeval MillisToTimeval(int64_t nTimeout);

#endif
