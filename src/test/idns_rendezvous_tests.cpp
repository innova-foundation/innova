#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "base58.h"
#include "hooks.h"
#include "idnsdescriptor.h"
#include "json/json_spirit_writer_template.h"
#include "key.h"
#include "main.h"
#include "namecoin.h"
#include "netbase.h"
#include "script.h"
#include "serialize.h"
#include "util.h"
#include "wallet.h"

extern CWallet* pwalletMain;

// Defined in namecoin.cpp without a header declaration.
bool createNameScript(CScript& nameScript,
                      const std::vector<unsigned char>& vchName,
                      const std::vector<unsigned char>& vchValue,
                      int nRentalDays, int op, std::string& err_msg);
bool checkNameValues(NameTxInfo& ret);

// IDNS rendezvous: the service's IP must appear in no value, script, tx, index record,
// RPC view or proxy request; each absence check has a positive control.
BOOST_AUTO_TEST_SUITE(idns_rendezvous_tests)

namespace
{

// A documentation-range address (RFC 5737).
const char* SERVICE_IP_TEXT = "203.0.113.7";
const unsigned char SERVICE_IP_BYTES[4] = { 203, 0, 113, 7 };

std::vector<unsigned char> Bytes(const std::string& str)
{
    return std::vector<unsigned char>(str.begin(), str.end());
}

std::vector<unsigned char> RawIp()
{
    return std::vector<unsigned char>(SERVICE_IP_BYTES, SERVICE_IP_BYTES + 4);
}

std::vector<unsigned char> ScriptBytes(const CScript& script)
{
    return std::vector<unsigned char>(script.begin(), script.end());
}

template <typename T>
std::vector<unsigned char> Serialized(const T& obj)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << obj;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

bool Contains(const std::vector<unsigned char>& haystack,
              const std::vector<unsigned char>& needle)
{
    if (needle.empty())
        return true;
    return std::search(haystack.begin(), haystack.end(), needle.begin(),
                       needle.end()) != haystack.end();
}

// A syntactically valid v3 onion hostname (35 bytes base32, trailing version byte).
// The checksum bytes are arbitrary; IsIDnsOnionV3Host does not verify them.
std::string OnionV3Host(unsigned char nSeed)
{
    std::vector<unsigned char> vchAddr(35, 0);
    for (size_t i = 0; i < 32; ++i)
        vchAddr[i] = (unsigned char)(nSeed + i);
    vchAddr[32] = 0x11;
    vchAddr[33] = 0x22;
    vchAddr[34] = 0x03;
    return EncodeBase32(&vchAddr[0], vchAddr.size()) + ".onion";
}

std::string RpcBytes(const json_spirit::Object& obj)
{
    return json_spirit::write_string(json_spirit::Value(obj), false);
}

CScript NameOpScript(const std::string& strName, const std::string& strValue,
                     int nRentalDays, int op)
{
    CScript script;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        createNameScript(script, Bytes(strName), Bytes(strValue), nRentalDays,
                         op, strError),
        strError);
    return script;
}

CTransaction NameTx(const CScript& script, uint32_t nTime, unsigned int nPrev)
{
    CTransaction tx;
    tx.nVersion = NAMECOIN_TX_VERSION;
    tx.nTime = nTime;
    tx.vin.push_back(CTxIn(COutPoint(uint256(nPrev), 0)));
    tx.vout.push_back(CTxOut(MIN_TXOUT_AMOUNT, script));
    return tx;
}

// The index record connect writes for a name operation, built the way
// ConnectInputsHook builds it.
CNameRecord IndexRecord(const CScript& fullScript)
{
    NameTxInfo nti;
    BOOST_REQUIRE(DecodeNameScript(fullScript, nti));
    CNameIndex indexed;
    indexed.nHeight = 4242;
    indexed.op = nti.op;
    indexed.vchValue = nti.vchValue;
    indexed.txPos = CDiskTxPos(1, 2, 3);

    CNameRecord record;
    record.vtxPos.push_back(indexed);
    record.nExpiresAt = 4242 + (int)NameRentalBlocks(4242, nti.nRentalDays);
    record.nLastActiveChainIndex = 0;
    return record;
}

class CArgOverride
{
public:
    CArgOverride(const std::string& strKeyIn, const std::string& strValue)
        : strKey(strKeyIn), fHadValue(mapArgs.count(strKeyIn) != 0)
    {
        if (fHadValue)
            strSaved = mapArgs[strKey];
        mapArgs[strKey] = strValue;
    }
    ~CArgOverride()
    {
        if (fHadValue)
            mapArgs[strKey] = strSaved;
        else
            mapArgs.erase(strKey);
    }
private:
    std::string strKey;
    std::string strSaved;
    bool fHadValue;
};

// Hooks that answer one canned name value, to drive the DNS server fetch without a name DB.
class CCannedHooks : public CHooks
{
public:
    std::string strValue;
    bool fFound;

    CCannedHooks() : fFound(false) {}

    bool getNameValue(const std::string& name, std::string& value)
    {
        (void)name;
        if (!fFound)
            return false;
        value = strValue;
        return true;
    }

    bool CheckNameTxShape(const CTransaction&, int, std::string&) { return false; }
    bool CheckNameTxFee(const CTransaction&, int64_t, bool&, std::string&) { return true; }
    bool DisconnectInputs(const CTransaction&) { return true; }
    bool ConnectBlock(CTxDB&, CBlockIndex*) { return true; }
    bool ExtractAddress(const CScript&, std::string&) { return false; }
    void AddToPendingNames(const CTransaction&) {}
    bool IsMine(const CTxOut&) { return false; }
    bool IsNameTx(int) { return false; }
    bool IsNameScript(CScript) { return false; }
    bool deletePendingName(const CTransaction&) { return false; }
    bool DumpToTextFile() { return false; }
};

class CHooksOverride
{
public:
    explicit CHooksOverride(CHooks* pReplacement) : pSaved(hooks)
    {
        hooks = pReplacement;
    }
    ~CHooksOverride() { hooks = pSaved; }
private:
    CHooks* pSaved;
};

} // namespace

// Registering a rendezvous name publishes no address for the service.
BOOST_AUTO_TEST_CASE(a_rendezvous_registration_publishes_no_service_address)
{
    const std::string strHost = OnionV3Host(0x40);
    std::string strDescriptor, strErr;
    BOOST_REQUIRE_MESSAGE(BuildIDnsRendezvous(strHost, 8443, strDescriptor, strErr),
                          strErr);

    // Positive control: an A record puts the address in every artifact searched below.
    {
        const std::string strRecord = std::string("A=") + SERVICE_IP_TEXT;
        const CScript opScript = NameOpScript("clear.inn", strRecord, 30, OP_NAME_NEW);
        const CScript fullScript = opScript + GetScriptForDestination(CKeyID(uint160(7)));
        const CTransaction tx = NameTx(fullScript, 0x1d0f0001, 0x1d0f0101);

        BOOST_CHECK(Contains(Bytes(strRecord), Bytes(SERVICE_IP_TEXT)));
        BOOST_CHECK(Contains(ScriptBytes(fullScript), Bytes(SERVICE_IP_TEXT)));
        BOOST_CHECK(Contains(Serialized(tx), Bytes(SERVICE_IP_TEXT)));
        BOOST_CHECK(Contains(Serialized(IndexRecord(fullScript)),
                             Bytes(SERVICE_IP_TEXT)));
        BOOST_CHECK(Contains(Bytes(RpcBytes(IDnsValueInfo("clear.inn", strRecord))),
                             Bytes(SERVICE_IP_TEXT)));
    }

    // As a descriptor, the address (text or 4-byte form) is in none of them.
    const CScript opScript =
        NameOpScript("private.inn", strDescriptor, 30, OP_NAME_NEW);
    const CScript fullScript =
        opScript + GetScriptForDestination(CKeyID(uint160(9)));
    const CTransaction tx = NameTx(fullScript, 0x1d0f0002, 0x1d0f0102);
    const std::vector<unsigned char> vchRecord = Serialized(IndexRecord(fullScript));
    const std::vector<unsigned char> vchRpc =
        Bytes(RpcBytes(IDnsValueInfo("private.inn", strDescriptor)));

    BOOST_CHECK(!Contains(Bytes(strDescriptor), Bytes(SERVICE_IP_TEXT)));
    BOOST_CHECK(!Contains(Bytes(strDescriptor), RawIp()));
    BOOST_CHECK(!Contains(ScriptBytes(fullScript), Bytes(SERVICE_IP_TEXT)));
    BOOST_CHECK(!Contains(ScriptBytes(fullScript), RawIp()));
    BOOST_CHECK(!Contains(Serialized(tx), Bytes(SERVICE_IP_TEXT)));
    BOOST_CHECK(!Contains(Serialized(tx), RawIp()));
    BOOST_CHECK(!Contains(vchRecord, Bytes(SERVICE_IP_TEXT)));
    BOOST_CHECK(!Contains(vchRecord, RawIp()));
    BOOST_CHECK(!Contains(vchRpc, Bytes(SERVICE_IP_TEXT)));
    BOOST_CHECK(!Contains(vchRpc, RawIp()));

    // The descriptor itself is in all of them.
    BOOST_CHECK(Contains(ScriptBytes(fullScript), Bytes(strDescriptor)));
    BOOST_CHECK(Contains(Serialized(tx), Bytes(strDescriptor)));
    BOOST_CHECK(Contains(vchRecord, Bytes(strDescriptor)));
    BOOST_CHECK(Contains(vchRpc, Bytes(strHost)));

    // The value survives the script round trip byte for byte.
    NameTxInfo nti;
    BOOST_REQUIRE(DecodeNameScript(fullScript, nti));
    BOOST_CHECK(nti.vchValue == Bytes(strDescriptor));

    // The name, term, registration height and expiry stay public by design.
    BOOST_CHECK(nti.vchName == Bytes("private.inn"));
    BOOST_CHECK_EQUAL(nti.nRentalDays, 30);
    BOOST_CHECK(Contains(ScriptBytes(fullScript), Bytes("private.inn")));
    const CNameRecord record = IndexRecord(fullScript);
    BOOST_CHECK_EQUAL(record.vtxPos.back().nHeight, 4242);
    BOOST_CHECK_GT(record.nExpiresAt, 4242);

    // No legacy tokenizer separators, so older builds answer nothing for it.
    BOOST_CHECK(strDescriptor.find('=') == std::string::npos);
    BOOST_CHECK(strDescriptor.find('|') == std::string::npos);
    BOOST_CHECK(strDescriptor.find(',') == std::string::npos);
    BOOST_CHECK(strDescriptor.find('~') == std::string::npos);
}

// Consensus only bounds the value length.
BOOST_AUTO_TEST_CASE(a_descriptor_needs_no_consensus_change)
{
    std::string strDescriptor, strErr;
    BOOST_REQUIRE(BuildIDnsRendezvous(OnionV3Host(0x11), 65535, strDescriptor,
                                      strErr));

    // Within the value bound and the first fee bucket.
    BOOST_CHECK_LT(strDescriptor.size(), IDNS_RENDEZVOUS_MAX_VALUE);
    BOOST_CHECK_LT(strDescriptor.size(), (size_t)128);
    BOOST_CHECK_LT(strDescriptor.size(), (size_t)MAX_VALUE_LENGTH);

    // The value-level consensus check accepts it.
    NameTxInfo nti(Bytes("fits.inn"), Bytes(strDescriptor), 30, OP_NAME_NEW, 0, "");
    BOOST_CHECK_MESSAGE(checkNameValues(nti), nti.err_msg);

    // Positive control: one byte over the bound is refused.
    NameTxInfo ntiOver(Bytes("fits.inn"),
                       std::vector<unsigned char>(MAX_VALUE_LENGTH + 1, 'x'), 30,
                       OP_NAME_NEW, 0, "");
    BOOST_CHECK(!checkNameValues(ntiOver));
}

// The grammar admits exactly one encoding per service.
BOOST_AUTO_TEST_CASE(the_descriptor_grammar_admits_one_canonical_encoding)
{
    const std::string strHost = OnionV3Host(0x20);
    std::string strErr;

    // Positive control: a well-formed descriptor parses and round trips.
    std::string strValue;
    BOOST_REQUIRE_MESSAGE(BuildIDnsRendezvous(strHost, 9089, strValue, strErr),
                          strErr);
    CIDnsRendezvous parsed;
    BOOST_REQUIRE_MESSAGE(ParseIDnsRendezvous(strValue, parsed, strErr), strErr);
    BOOST_CHECK_EQUAL(parsed.nVersion, IDNS_RENDEZVOUS_VERSION);
    BOOST_CHECK_EQUAL(parsed.strHost, strHost);
    BOOST_CHECK_EQUAL(parsed.nPort, 9089);
    BOOST_CHECK_EQUAL(parsed.ToValue(), strValue);

    // Creation lowercases the hostname.
    std::string strUpperHost = strHost;
    for (size_t i = 0; i < strUpperHost.size(); ++i)
        if (strUpperHost[i] >= 'a' && strUpperHost[i] <= 'z')
            strUpperHost[i] = (char)(strUpperHost[i] - 'a' + 'A');
    std::string strFromUpper;
    BOOST_REQUIRE(BuildIDnsRendezvous(strUpperHost, 9089, strFromUpper, strErr));
    BOOST_CHECK_EQUAL(strFromUpper, strValue);

    // Parsing is strict: uppercase is refused.
    CIDnsRendezvous ignored;
    const std::string strUpperValue =
        std::string(IDNS_RENDEZVOUS_FAMILY) + "1:" + strUpperHost + ":9089";
    BOOST_CHECK(!ParseIDnsRendezvous(strUpperValue, ignored, strErr));

    // Hostname shape.
    BOOST_CHECK(!IsIDnsOnionV3Host(strHost.substr(1), strErr));            // short
    BOOST_CHECK(!IsIDnsOnionV3Host(strHost + "x", strErr));                // long
    BOOST_CHECK(!IsIDnsOnionV3Host(strHost.substr(0, 56) + ".ONION", strErr));
    BOOST_CHECK(!IsIDnsOnionV3Host(std::string(56, '1') + ".onion", strErr));
    {
        // v2 onion addresses (right alphabet, wrong length) are refused.
        std::vector<unsigned char> vchV2(10, 0x5a);
        BOOST_CHECK(!IsIDnsOnionV3Host(EncodeBase32(&vchV2[0], vchV2.size()) +
                                           ".onion",
                                       strErr));
    }
    {
        // Right length and alphabet, wrong address version byte.
        std::vector<unsigned char> vchAddr(35, 0x00);
        vchAddr[34] = 0x02;
        BOOST_CHECK(!IsIDnsOnionV3Host(EncodeBase32(&vchAddr[0], vchAddr.size()) +
                                           ".onion",
                                       strErr));
        BOOST_CHECK(strErr.find("version byte") != std::string::npos);
    }

    // Port.
    const std::string strTag = std::string(IDNS_RENDEZVOUS_FAMILY) + "1:" + strHost;
    BOOST_CHECK(!ParseIDnsRendezvous(strTag, ignored, strErr));            // absent
    BOOST_CHECK(!ParseIDnsRendezvous(strTag + ":0", ignored, strErr));
    BOOST_CHECK(!ParseIDnsRendezvous(strTag + ":09089", ignored, strErr)); // leading zero
    BOOST_CHECK(!ParseIDnsRendezvous(strTag + ":65536", ignored, strErr));
    BOOST_CHECK(!ParseIDnsRendezvous(strTag + ":80a", ignored, strErr));
    BOOST_CHECK(ParseIDnsRendezvous(strTag + ":1", ignored, strErr));
    BOOST_CHECK(ParseIDnsRendezvous(strTag + ":65535", ignored, strErr));

    // Non-printable bytes are refused (the resolver path uses c_str()/snprintf).
    std::string strWithNul = strValue;
    strWithNul.push_back('\0');
    BOOST_CHECK(!ParseIDnsRendezvous(strWithNul, ignored, strErr));
    BOOST_CHECK(!ParseIDnsRendezvous(strValue + " ", ignored, strErr));

    // Length bound, applied before the body is parsed.
    BOOST_CHECK(!ParseIDnsRendezvous(
        strValue + std::string(IDNS_RENDEZVOUS_MAX_VALUE, 'a'), ignored, strErr));
}

// An unknown tag fails closed. It is not resolved as a plain record.
BOOST_AUTO_TEST_CASE(an_unknown_descriptor_version_is_refused_not_answered)
{
    const std::string strHost = OnionV3Host(0x30);
    std::string strValue, strErr;
    BOOST_REQUIRE(BuildIDnsRendezvous(strHost, 8080, strValue, strErr));

    CIDnsRendezvous rendezvous;

    // Positive control: a conventional record classifies as a record, and the
    // descriptor this build knows classifies as a rendezvous.
    BOOST_CHECK_EQUAL((int)ClassifyIDnsValue("A=198.51.100.9|TTL=300",
                                             rendezvous, strErr),
                      (int)IDNS_VALUE_RECORD);
    BOOST_CHECK_EQUAL((int)ClassifyIDnsValue(strValue, rendezvous, strErr),
                      (int)IDNS_VALUE_RENDEZVOUS);
    BOOST_CHECK_EQUAL(rendezvous.strHost, strHost);

    // Future version, malformed tag and bare family prefix are unsupported, not records.
    const std::string strFuture =
        std::string(IDNS_RENDEZVOUS_FAMILY) + "2:" + strHost + ":8080";
    BOOST_CHECK_EQUAL((int)ClassifyIDnsValue(strFuture, rendezvous, strErr),
                      (int)IDNS_VALUE_UNSUPPORTED);
    BOOST_CHECK(strErr.find("version 2") != std::string::npos);
    BOOST_CHECK_EQUAL((int)ClassifyIDnsValue(
                          std::string(IDNS_RENDEZVOUS_FAMILY) + "1:not-an-onion:80",
                          rendezvous, strErr),
                      (int)IDNS_VALUE_UNSUPPORTED);
    BOOST_CHECK_EQUAL((int)ClassifyIDnsValue(IDNS_RENDEZVOUS_FAMILY, rendezvous,
                                             strErr),
                      (int)IDNS_VALUE_UNSUPPORTED);

    // Drive the DNS server fetch (as IDns::Search calls it) with canned values.
    CCannedHooks canned;
    CHooksOverride override(&canned);
    std::string strAnswer;

    // Positive control: a record is fetched and answered.
    canned.fFound = true;
    canned.strValue = "A=198.51.100.9";
    BOOST_CHECK(GetIDnsRecordValue("dns:clear.inn", strAnswer));
    BOOST_CHECK_EQUAL(strAnswer, canned.strValue);

    // A descriptor is not answered, and the onion is not put in the answer buffer.
    canned.strValue = strValue;
    BOOST_CHECK(!GetIDnsRecordValue("dns:private.inn", strAnswer));
    BOOST_CHECK(strAnswer.empty());

    // Nor an unsupported one.
    canned.strValue = strFuture;
    BOOST_CHECK(!GetIDnsRecordValue("dns:future.inn", strAnswer));
    BOOST_CHECK(strAnswer.empty());

    // And a name that does not resolve still does not resolve.
    canned.fFound = false;
    BOOST_CHECK(!GetIDnsRecordValue("dns:missing.inn", strAnswer));

    // The RPC view reports the refusal for every member of the family.
    const std::string strRpc = RpcBytes(IDnsValueInfo("future.inn", strFuture));
    BOOST_CHECK(strRpc.find("\"kind\":\"unsupported\"") != std::string::npos);
    BOOST_CHECK(strRpc.find("\"resolvable\":false") != std::string::npos);
    BOOST_CHECK(strRpc.find("\"host\"") == std::string::npos);
    BOOST_CHECK(strRpc.find("\"port\"") == std::string::npos);
}

// The dial hands the proxy a hostname, never the service's address.
BOOST_AUTO_TEST_CASE(a_rendezvous_dial_sends_a_hostname_and_no_address)
{
    const std::string strHost = OnionV3Host(0x50);
    std::string strValue, strErr;
    BOOST_REQUIRE(BuildIDnsRendezvous(strHost, 8443, strValue, strErr));
    CIDnsRendezvous rendezvous;
    BOOST_REQUIRE(ParseIDnsRendezvous(strValue, rendezvous, strErr));

    // Positive control: the ordinary proxy path puts the address in the request bytes.
    std::vector<unsigned char> vchClear;
    BOOST_REQUIRE(BuildSocks5ConnectRequest(SERVICE_IP_TEXT, 8443, vchClear));
    BOOST_CHECK(Contains(vchClear, Bytes(SERVICE_IP_TEXT)));

    // The rendezvous request carries the hostname and neither spelling of the
    // address.
    std::vector<unsigned char> vchOnion;
    BOOST_REQUIRE(BuildSocks5ConnectRequest(rendezvous.strHost, rendezvous.nPort,
                                            vchOnion));
    BOOST_CHECK(Contains(vchOnion, Bytes(strHost)));
    BOOST_CHECK(!Contains(vchOnion, Bytes(SERVICE_IP_TEXT)));
    BOOST_CHECK(!Contains(vchOnion, RawIp()));

    // SOCKS5 CONNECT, ATYP 3 (domain name), length byte, name, port.
    BOOST_REQUIRE_EQUAL(vchOnion.size(), 4 + 1 + strHost.size() + 2);
    BOOST_CHECK_EQUAL((int)vchOnion[0], 5);
    BOOST_CHECK_EQUAL((int)vchOnion[1], 1);
    BOOST_CHECK_EQUAL((int)vchOnion[2], 0);
    BOOST_CHECK_EQUAL((int)vchOnion[3], 3);
    BOOST_CHECK_EQUAL((size_t)vchOnion[4], strHost.size());
    BOOST_CHECK_EQUAL((int)vchOnion[vchOnion.size() - 2], (8443 >> 8) & 0xff);
    BOOST_CHECK_EQUAL((int)vchOnion[vchOnion.size() - 1], 8443 & 0xff);

    // The builder refuses what it cannot encode, before any socket exists.
    std::vector<unsigned char> vchRefused;
    BOOST_CHECK(!BuildSocks5ConnectRequest("", 8443, vchRefused));
    BOOST_CHECK(!BuildSocks5ConnectRequest(std::string(256, 'a'), 8443, vchRefused));
    BOOST_CHECK(!BuildSocks5ConnectRequest(strHost, 0, vchRefused));
    BOOST_CHECK(!BuildSocks5ConnectRequest(strHost, 65536, vchRefused));

    // Endpoint selection: defaults to an external tor SOCKS port; can be disabled.
    {
        CArgOverride socks("-idnssocks", IDNS_DEFAULT_SOCKS_ENDPOINT);
        CService addrProxy;
        BOOST_CHECK_MESSAGE(GetIDnsSocksEndpoint(addrProxy, strErr), strErr);
        BOOST_CHECK_EQUAL(addrProxy.ToStringPort(), "9050");
    }
    {
        CArgOverride socks("-idnssocks", "0");
        CService addrProxy;
        BOOST_CHECK(!GetIDnsSocksEndpoint(addrProxy, strErr));

        // Disabled: fails closed, no direct-connection fallback.
        SOCKET hSocket = (SOCKET)0;
        BOOST_CHECK(!ConnectIDnsRendezvous(rendezvous, hSocket, strErr));
        BOOST_CHECK(hSocket == INVALID_SOCKET);
        BOOST_CHECK(strErr.find("disabled") != std::string::npos);
    }
    {
        CArgOverride socks("-idnssocks", "not-an-endpoint");
        CService addrProxy;
        BOOST_CHECK(!GetIDnsSocksEndpoint(addrProxy, strErr));
    }

    // A descriptor the codec refuses is refused before any endpoint is consulted.
    {
        CArgOverride socks("-idnssocks", IDNS_DEFAULT_SOCKS_ENDPOINT);
        CIDnsRendezvous broken = rendezvous;
        broken.strHost = "example.com";
        SOCKET hSocket = (SOCKET)0;
        BOOST_CHECK(!ConnectIDnsRendezvous(broken, hSocket, strErr));
        BOOST_CHECK(hSocket == INVALID_SOCKET);

        CIDnsRendezvous future = rendezvous;
        future.nVersion = IDNS_RENDEZVOUS_VERSION + 1;
        BOOST_CHECK(!ConnectIDnsRendezvous(future, hSocket, strErr));
        BOOST_CHECK(hSocket == INVALID_SOCKET);
    }
}

// Registrations link only through a reused destination, and name paths do not reuse one.
BOOST_AUTO_TEST_CASE(name_destinations_rotate_and_never_fall_back_to_one_key)
{
    // Positive control: a reused destination links two names.
    CPubKey shared;
    BOOST_REQUIRE(GetNameDestinationKey(shared));
    const uint160 hashShared = shared.GetID();
    const std::vector<unsigned char> vchShared(hashShared.begin(),
                                               hashShared.end());
    const CScript destShared = GetScriptForDestination(shared.GetID());
    const CScript opOne = NameOpScript("rv-one.inn", "a", 30, OP_NAME_NEW);
    const CScript opTwo = NameOpScript("rv-two.inn", "b", 30, OP_NAME_NEW);
    BOOST_CHECK(Contains(Serialized(NameTx(opOne + destShared, 0x1d0f0003,
                                           0x1d0f0103)),
                         vchShared));
    BOOST_CHECK(Contains(Serialized(NameTx(opTwo + destShared, 0x1d0f0004,
                                           0x1d0f0104)),
                         vchShared));

    // Name ops without an explicit destination use GetNameDestinationKey, which refuses reuse.
    std::set<std::vector<unsigned char> > setSeen;
    std::vector<CPubKey> vAllocated;
    for (int i = 0; i < 8; ++i)
    {
        CPubKey pubkey;
        BOOST_REQUIRE(GetNameDestinationKey(pubkey));
        const uint160 hash = pubkey.GetID();
        const std::vector<unsigned char> vchHash(hash.begin(), hash.end());
        BOOST_CHECK(setSeen.insert(vchHash).second);
        vAllocated.push_back(pubkey);
    }

    // None is the wallet's default key (the reuse-allowed fallback on an exhausted pool).
    const CPubKey saved = pwalletMain->vchDefaultKey;
    pwalletMain->vchDefaultKey = vAllocated[0];
    for (size_t i = 1; i < vAllocated.size(); ++i)
        BOOST_CHECK(vAllocated[i].Raw() != pwalletMain->vchDefaultKey.Raw());
    CPubKey fresh;
    BOOST_REQUIRE(GetNameDestinationKey(fresh));
    BOOST_CHECK(fresh.Raw() != pwalletMain->vchDefaultKey.Raw());
    BOOST_CHECK(fresh.Raw() != vAllocated[0].Raw());
    pwalletMain->vchDefaultKey = saved;

    // The two registrations built on rotated destinations link through nothing.
    const std::vector<unsigned char> vchFreshOne = Serialized(
        NameTx(opOne + GetScriptForDestination(vAllocated[0].GetID()), 0x1d0f0005,
               0x1d0f0105));
    const uint160 hashTwo = vAllocated[1].GetID();
    BOOST_CHECK(!Contains(vchFreshOne, std::vector<unsigned char>(
                                           hashTwo.begin(), hashTwo.end())));
}

BOOST_AUTO_TEST_SUITE_END()
