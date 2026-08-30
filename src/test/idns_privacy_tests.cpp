#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <vector>

#include "base58.h"
#include "bignum.h"
#include "hooks.h"
#include "key.h"
#include "main.h"
#include "namecoin.h"
#include "script.h"
#include "serialize.h"
#include "shielded.h"
#include "wallet.h"

extern bool fRegTest;
extern bool fTestNet;
extern CWallet* pwalletMain;

// Defined in namecoin.cpp without a header declaration. It is the only place a
// name operation's bytes are assembled, so a case that wants the operation half
// of a script without the destination has to call it.
bool createNameScript(CScript& nameScript,
                      const std::vector<unsigned char>& vchName,
                      const std::vector<unsigned char>& vchValue,
                      int nRentalDays, int op, std::string& err_msg);

// IDNS privacy integrity. Names are transparent by design; pinned here: a name op and an
// IV5 payload never share a transaction, the op carries no key material, the index
// records no ownership beyond the chain, and reset refuses a doomed term up front.
BOOST_AUTO_TEST_SUITE(idns_privacy_tests)

namespace
{

// The fork-height accessors read fRegTest/fTestNet, and the regtest reset height
// is a knob, so a case that needs either states it and puts it back.
class CNetworkOverride
{
public:
    CNetworkOverride(bool fRegTestIn, bool fTestNetIn)
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet)
    {
        fRegTest = fRegTestIn;
        fTestNet = fTestNetIn;
    }
    ~CNetworkOverride()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
    }
private:
    bool fRegTestSaved;
    bool fTestNetSaved;
};

class CResetHeightOverride
{
public:
    explicit CResetHeightOverride(int nHeight)
        : nSaved(nRegtestIDNSResetHeight)
    {
        nRegtestIDNSResetHeight = nHeight;
    }
    ~CResetHeightOverride() { nRegtestIDNSResetHeight = nSaved; }
private:
    int nSaved;
};

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

std::vector<unsigned char> Bytes(const std::string& str)
{
    return std::vector<unsigned char>(str.begin(), str.end());
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

// The name-operation half of a name script: everything createNameScript emits,
// before any destination is appended.
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

// A key this process holds, so the destination bytes a case searches for are the
// bytes a real owner's script would carry.
CPubKey FreshKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key.GetPubKey();
}

} // namespace

// A name transaction has no IV5 envelope: the payload serializes only for
// SHIELDED_TX_VERSION_DSP.
BOOST_AUTO_TEST_CASE(a_name_transaction_carries_no_iv5_payload)
{
    std::vector<unsigned char> vchPayload;
    for (size_t i = 0; i < 64; ++i)
        vchPayload.push_back((unsigned char)(0xa0 + (i % 16)));

    // Positive control: on the version the envelope belongs to, the bytes are on
    // the wire and survive a round trip.
    CTransaction carrier;
    carrier.nVersion = SHIELDED_TX_VERSION_DSP;
    carrier.nTime = 0x1d005001;
    carrier.vin.push_back(CTxIn(COutPoint(uint256(0x1d005101), 0)));
    carrier.vout.push_back(CTxOut(MIN_TXOUT_AMOUNT, CScript() << OP_TRUE));
    carrier.privacyVNext.vchPayload = vchPayload;
    carrier.privacyVNext.SetPresent();

    const std::vector<unsigned char> vchCarrier = Serialized(carrier);
    BOOST_CHECK(Contains(vchCarrier, vchPayload));

    CDataStream ssCarrier(vchCarrier, SER_DISK, CLIENT_VERSION);
    CTransaction carrierBack;
    ssCarrier >> carrierBack;
    BOOST_CHECK(carrierBack.privacyVNext.IsPresent());
    BOOST_CHECK(carrierBack.privacyVNext.vchPayload == vchPayload);

    // The same envelope on a name transaction: not on the wire, and not there
    // after a round trip either.
    CTransaction nameTx = carrier;
    nameTx.nVersion = NAMECOIN_TX_VERSION;
    nameTx.vout[0].scriptPubKey =
        NameOpScript("payload-probe.inn", "v", 7, OP_NAME_NEW);

    const std::vector<unsigned char> vchName = Serialized(nameTx);
    BOOST_CHECK(!Contains(vchName, vchPayload));

    CDataStream ssName(vchName, SER_DISK, CLIENT_VERSION);
    CTransaction nameBack;
    ssName >> nameBack;
    BOOST_CHECK(!nameBack.privacyVNext.IsPresent());
    BOOST_CHECK(nameBack.privacyVNext.vchPayload.empty());
    BOOST_CHECK_EQUAL(nameBack.nVersion, NAMECOIN_TX_VERSION);
}

// Direction two: a payload-carrying transaction with a well-formed name script indexes
// nothing, since version admits a name operation.
BOOST_AUTO_TEST_CASE(an_iv5_payload_transaction_gets_no_name_effect)
{
    if (!hooks)
        hooks = InitHook();

    const CScript nameScript =
        NameOpScript("dual-use.inn", "value", 30, OP_NAME_NEW) +
        GetScriptForDestination(FreshKey().GetID());

    // Positive control: at the name version the very same script is an operation
    // connect would index.
    const CTransaction asName = NameTx(nameScript, 0x1d005002, 0x1d005102);
    std::string strReason;
    BOOST_CHECK_MESSAGE(hooks->CheckNameTxShape(asName, 1, strReason), strReason);
    BOOST_CHECK(hooks->IsNameTx(NAMECOIN_TX_VERSION));

    // The same script on the payload version is refused on version alone, before
    // the script is decoded.
    CTransaction asPayload = asName;
    asPayload.nVersion = SHIELDED_TX_VERSION_DSP;
    BOOST_CHECK(!hooks->IsNameTx(SHIELDED_TX_VERSION_DSP));
    BOOST_CHECK(!hooks->CheckNameTxShape(asPayload, 1, strReason));
    BOOST_CHECK(strReason.find("not a name transaction") != std::string::npos);

    // The script still decodes, so the refusal is the version rule and not a
    // malformed script standing in for it.
    NameTxInfo nti;
    BOOST_CHECK(DecodeNameScript(asPayload.vout[0].scriptPubKey, nti));
    BOOST_CHECK(nti.vchName == Bytes("dual-use.inn"));
}

// The operation carries no key material; only the destination appended after it
// does. Two owners produce byte-identical operation prefixes.
BOOST_AUTO_TEST_CASE(a_name_operation_carries_no_owner_key_material)
{
    const CPubKey pubkeyA = FreshKey();
    const CPubKey pubkeyB = FreshKey();
    BOOST_REQUIRE(pubkeyA.Raw() != pubkeyB.Raw());

    const CScript opScript =
        NameOpScript("owner-free.inn", "some-value", 30, OP_NAME_NEW);
    const std::vector<unsigned char> vchOp = ScriptBytes(opScript);

    const CScript fullA = opScript + GetScriptForDestination(pubkeyA.GetID());
    const CScript fullB = opScript + GetScriptForDestination(pubkeyB.GetID());

    // Positive control: the owner's key hash is in the full script and in the
    // serialized transaction, so a search for it is a search that can succeed.
    const uint160 hashA = pubkeyA.GetID();
    const uint160 hashB = pubkeyB.GetID();
    const std::vector<unsigned char> vchHashA(hashA.begin(), hashA.end());
    const std::vector<unsigned char> vchHashB(hashB.begin(), hashB.end());
    BOOST_CHECK(Contains(ScriptBytes(fullA), vchHashA));
    BOOST_CHECK(Contains(Serialized(NameTx(fullA, 0x1d005003, 0x1d005103)),
                         vchHashA));

    // The operation half carries neither owner's key hash, the only thing a name output
    // publishes.
    BOOST_CHECK(!Contains(vchOp, vchHashA));
    BOOST_CHECK(!Contains(vchOp, vchHashB));

    // The two owners' scripts agree byte for byte over the operation, so the
    // prefix identifies nothing about who holds the name.
    BOOST_REQUIRE(fullA.size() > vchOp.size());
    BOOST_REQUIRE(fullB.size() > vchOp.size());
    BOOST_CHECK(std::equal(vchOp.begin(), vchOp.end(), fullA.begin()));
    BOOST_CHECK(std::equal(vchOp.begin(), vchOp.end(), fullB.begin()));

    // The decoded operation is identical too: same name, value and term.
    NameTxInfo ntiA, ntiB;
    BOOST_REQUIRE(DecodeNameScript(fullA, ntiA));
    BOOST_REQUIRE(DecodeNameScript(fullB, ntiB));
    BOOST_CHECK(ntiA.vchName == ntiB.vchName);
    BOOST_CHECK(ntiA.vchValue == ntiB.vchValue);
    BOOST_CHECK_EQUAL(ntiA.nRentalDays, ntiB.nRentalDays);
}

// Address reuse is the whole linkage mechanism, and the registration path does
// not reuse. The update and delete paths can, which is pinned here as the
// behaviour it is rather than asserted away.
BOOST_AUTO_TEST_CASE(two_registrations_link_only_through_a_reused_destination)
{
    const CScript opOne = NameOpScript("link-one.inn", "a", 30, OP_NAME_NEW);
    const CScript opTwo = NameOpScript("link-two.inn", "b", 30, OP_NAME_NEW);

    // Positive control: naming the same address twice publishes the same 20
    // bytes in both transactions, which is exactly what links the two names.
    const CPubKey shared = FreshKey();
    const uint160 hashShared = shared.GetID();
    const std::vector<unsigned char> vchShared(hashShared.begin(),
                                               hashShared.end());
    const CScript destShared = GetScriptForDestination(shared.GetID());
    BOOST_CHECK(Contains(Serialized(NameTx(opOne + destShared, 0x1d005004,
                                           0x1d005104)),
                         vchShared));
    BOOST_CHECK(Contains(Serialized(NameTx(opTwo + destShared, 0x1d005005,
                                           0x1d005105)),
                         vchShared));

    // Registration takes its destination from GetNameDestinationKey (key pool, reuse refused),
    // so two default registrations share nothing. This calls name_new's own allocator.
    CPubKey pubkeyOne, pubkeyTwo;
    BOOST_REQUIRE(GetNameDestinationKey(pubkeyOne));
    BOOST_REQUIRE(GetNameDestinationKey(pubkeyTwo));
    BOOST_REQUIRE(pubkeyOne.Raw() != pubkeyTwo.Raw());

    const uint160 hashOne = pubkeyOne.GetID();
    const uint160 hashTwo = pubkeyTwo.GetID();
    const std::vector<unsigned char> vchOne(hashOne.begin(), hashOne.end());
    const std::vector<unsigned char> vchTwo(hashTwo.begin(), hashTwo.end());

    const std::vector<unsigned char> vchFreshOne = Serialized(
        NameTx(opOne + GetScriptForDestination(pubkeyOne.GetID()), 0x1d005006,
               0x1d005106));
    const std::vector<unsigned char> vchFreshTwo = Serialized(
        NameTx(opTwo + GetScriptForDestination(pubkeyTwo.GetID()), 0x1d005007,
               0x1d005107));
    BOOST_CHECK(Contains(vchFreshOne, vchOne));
    BOOST_CHECK(Contains(vchFreshTwo, vchTwo));
    BOOST_CHECK(!Contains(vchFreshOne, vchTwo));
    BOOST_CHECK(!Contains(vchFreshTwo, vchOne));

    // name_update and name_delete use the same helper, so they rotate the key too; the wallet
    // default key is unreachable from any name path.
    CPubKey rotateOne, rotateTwo;
    BOOST_REQUIRE(GetNameDestinationKey(rotateOne));
    BOOST_REQUIRE(GetNameDestinationKey(rotateTwo));
    BOOST_CHECK(rotateOne.Raw() != rotateTwo.Raw());
    BOOST_CHECK(rotateOne.Raw() != pubkeyOne.Raw());
    BOOST_CHECK(rotateTwo.Raw() != pubkeyTwo.Raw());
    BOOST_CHECK_GT(pwalletMain->GetKeyPoolSize(), 0U);

    // So the only thing that links two names is a destination the operator chose
    // to reuse, as in the control above.
    const std::vector<unsigned char> vchRotateOne = Serialized(
        NameTx(opOne + GetScriptForDestination(rotateOne.GetID()), 0x1d005009,
               0x1d005109));
    const uint160 hashRotateTwo = rotateTwo.GetID();
    BOOST_CHECK(!Contains(vchRotateOne, std::vector<unsigned char>(
                                            hashRotateTwo.begin(),
                                            hashRotateTwo.end())));
    BOOST_CHECK(!Contains(vchRotateOne, vchShared));
}

// The name index stores only {disk position, height, op, value}; no ownership record.
BOOST_AUTO_TEST_CASE(the_name_index_records_no_ownership)
{
    const CPubKey owner = FreshKey();
    const uint160 hashOwner = owner.GetID();
    const std::vector<unsigned char> vchOwner(hashOwner.begin(),
                                              hashOwner.end());
    const std::string strValue = "indexed-value";

    const CScript full = NameOpScript("indexed.inn", strValue, 30, OP_NAME_NEW) +
                         GetScriptForDestination(owner.GetID());
    const CTransaction tx = NameTx(full, 0x1d005008, 0x1d005108);

    // Positive control: the owner is public in the transaction the index points
    // at.
    const std::vector<unsigned char> vchTx = Serialized(tx);
    BOOST_CHECK(Contains(vchTx, vchOwner));

    // The record connect writes, built the way ConnectInputsHook builds it.
    NameTxInfo nti;
    BOOST_REQUIRE(DecodeNameScript(full, nti));
    CNameIndex indexed;
    indexed.nHeight = 42;
    indexed.op = nti.op;
    indexed.vchValue = nti.vchValue;
    indexed.txPos = CDiskTxPos(1, 2, 3);

    CNameRecord record;
    record.vtxPos.push_back(indexed);
    record.nExpiresAt = 42 + (int)NameRentalBlocks(42, nti.nRentalDays);
    record.nLastActiveChainIndex = 0;

    const std::vector<unsigned char> vchRecord = Serialized(record);
    BOOST_CHECK(!Contains(vchRecord, vchOwner));
    BOOST_CHECK(!Contains(vchRecord, ScriptBytes(full)));
    BOOST_CHECK(!Contains(vchRecord, ScriptBytes(GetScriptForDestination(
                                         owner.GetID()))));

    // The value is there, so the absences above are absences and not a search of
    // the wrong bytes.
    BOOST_CHECK(Contains(vchRecord, Bytes(strValue)));

    // Schema pin: the record is exactly its four declared fields. An ownership
    // field added later would make this size disagree.
    const unsigned int nDeclared =
        ::GetSerializeSize(indexed.txPos, SER_DISK, CLIENT_VERSION) +
        ::GetSerializeSize(indexed.nHeight, SER_DISK, CLIENT_VERSION) +
        ::GetSerializeSize(indexed.op, SER_DISK, CLIENT_VERSION) +
        ::GetSerializeSize(indexed.vchValue, SER_DISK, CLIENT_VERSION);
    BOOST_CHECK_EQUAL(::GetSerializeSize(indexed, SER_DISK, CLIENT_VERSION),
                      nDeclared);
}

// A registration whose term the reset would wipe is refused before any script is built
// or broadcast.
BOOST_AUTO_TEST_CASE(a_term_the_reset_wipes_is_refused_before_a_transaction_exists)
{
    // The predicate the wallet refuses on, at its boundaries.
    {
        CNetworkOverride regtest(true, false);
        CResetHeightOverride reset(500);
        int nReset = 0;
        int64_t nLost = 0;
        BOOST_CHECK(NameTermWipedByIDNSReset(100, 600, nReset, nLost));
        BOOST_CHECK_EQUAL(nReset, 500);
        BOOST_CHECK_EQUAL(nLost, 100);
        // A term ending at the reset loses nothing.
        BOOST_CHECK(!NameTermWipedByIDNSReset(100, 500, nReset, nLost));
        // A registration at or after the reset is never wiped.
        BOOST_CHECK(!NameTermWipedByIDNSReset(500, 900, nReset, nLost));
        BOOST_CHECK(!NameTermWipedByIDNSReset(501, 900, nReset, nLost));
    }
    {
        // With no reset configured the guard is inert.
        CNetworkOverride regtest(true, false);
        CResetHeightOverride reset(0);
        int nReset = 0;
        int64_t nLost = 0;
        BOOST_CHECK(!NameTermWipedByIDNSReset(100, 1000000, nReset, nLost));
    }

    // Drive the wallet path. The reset sits just above the tip, so any term at
    // all runs past it.
    const int nTip = pindexBest ? pindexBest->nHeight : 0;
    CNetworkOverride regtest(true, false);
    CResetHeightOverride reset(nTip + 2);

    const size_t nWalletBefore = pwalletMain->mapWallet.size();
    const unsigned long nPoolBefore = mempool.size();

    const NameTxReturn refused =
        name_new(Bytes("wiped-term.inn"), Bytes("value"), 30, "");
    BOOST_CHECK(!refused.ok);
    BOOST_CHECK_EQUAL((int)refused.err_code, (int)RPC_INVALID_PARAMETER);
    BOOST_CHECK(refused.err_msg.find("IDNS reset") != std::string::npos);
    BOOST_CHECK(refused.hex == uint256(0));

    // Nothing was built, signed or broadcast.
    BOOST_CHECK_EQUAL(pwalletMain->mapWallet.size(), nWalletBefore);
    BOOST_CHECK_EQUAL(mempool.size(), nPoolBefore);

    // Positive control: the same call with the loss accepted passes the guard and fails later
    // on the unfunded wallet, so the guard refused above.
    bool fPastTheGuard = false;
    try
    {
        CArgOverride allow("-allowwipednames", "1");
        const NameTxReturn attempted =
            name_new(Bytes("wiped-term-allowed.inn"), Bytes("value"), 30, "");
        // Returning at all means the guard did not fire; whatever refused it, it
        // was not the reset.
        BOOST_CHECK(attempted.err_msg.find("IDNS reset") == std::string::npos);
        fPastTheGuard = true;
    }
    catch (...)
    {
        // SendName throws once transaction construction fails, which is past the
        // guard by definition.
        fPastTheGuard = true;
    }
    BOOST_CHECK(fPastTheGuard);
    BOOST_CHECK_EQUAL(pwalletMain->mapWallet.size(), nWalletBefore);
    BOOST_CHECK_EQUAL(mempool.size(), nPoolBefore);
}

BOOST_AUTO_TEST_SUITE_END()
