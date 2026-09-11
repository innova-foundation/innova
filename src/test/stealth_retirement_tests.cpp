// Retired stealth addresses: issuance and payment are refused; listing, importing,
// scanning and spending still work, so received value is not stranded.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../stealth.h"
#include "../wallet.h"

#include <string>

BOOST_AUTO_TEST_SUITE(stealth_retirement_tests)

// The gate itself. Regtest keeps the legacy paths so replay and rejection tests can still
// drive them; every public network refuses.
BOOST_AUTO_TEST_CASE(the_retirement_gate_spares_regtest_only)
{
    extern bool fRegTest;
    const bool fSaved = fRegTest;

    fRegTest = true;
    BOOST_CHECK_MESSAGE(!IsLegacyPrivacyPolicyDisabled(),
                        "regtest must keep the legacy paths for replay tests");
    fRegTest = false;
    BOOST_CHECK_MESSAGE(IsLegacyPrivacyPolicyDisabled(),
                        "every public network retires the legacy privacy paths");

    fRegTest = fSaved;
}

// The primitive that recovers a stealth address from its encoded form. A wallet restoring
// from a backup, or importing an address it was given, runs through here -- so it must
// keep working whatever issuance does, or the retirement takes the funds with it.
BOOST_AUTO_TEST_CASE(an_existing_stealth_address_still_decodes_after_retirement)
{
    extern bool fRegTest;
    const bool fSaved = fRegTest;
    fRegTest = false;   // the retired condition
    BOOST_REQUIRE(IsLegacyPrivacyPolicyDisabled());

    // An address issued before the retirement, as a user would have kept it.
    CStealthAddress issued;
    issued.scan_secret.assign(32, 0x11);
    issued.spend_secret.assign(32, 0x22);
    issued.scan_pubkey.assign(33, 0x02);
    issued.spend_pubkey.assign(33, 0x03);
    issued.options = 0;
    issued.number_signatures = 0;

    const std::string strEncoded = issued.Encoded();
    BOOST_REQUIRE_MESSAGE(!strEncoded.empty(),
                          "a stealth address this wallet holds must still encode");

    // And back: this is the path an import takes, and it is untouched by the retirement.
    CStealthAddress recovered;
    BOOST_CHECK_MESSAGE(recovered.SetEncoded(strEncoded),
                        "a stealth address must still decode after issuance is retired");
    BOOST_CHECK(recovered.scan_pubkey == issued.scan_pubkey);
    BOOST_CHECK(recovered.spend_pubkey == issued.spend_pubkey);

    // The string is still recognised as a stealth address, which is what the send path
    // and the address book test before doing anything else.
    BOOST_CHECK(IsStealthAddress(strEncoded));

    fRegTest = fSaved;
}

// The wallet primitive is deliberately NOT gated. Only the RPC and the GUI refuse, so a
// wallet can still hold, load and reason about the addresses it already has. If someone
// later gates this too, the refusal reaches existing funds and this goes red.
BOOST_AUTO_TEST_CASE(the_wallet_primitive_is_not_gated)
{
    extern bool fRegTest;
    const bool fSaved = fRegTest;
    fRegTest = false;
    BOOST_REQUIRE(IsLegacyPrivacyPolicyDisabled());

    CWallet wallet;
    CStealthAddress sxAddr;
    std::string sError;
    std::string sLabel = "pre-retirement";

    // NewStealthAddress is the primitive the RPC calls after its own refusal. It is not
    // itself gated: the retirement is a policy at the boundary, not a change to what a
    // wallet can represent.
    const bool fMade = wallet.NewStealthAddress(sError, sLabel, sxAddr);
    BOOST_CHECK_MESSAGE(fMade,
                        "the wallet primitive must stay usable so existing addresses "
                        "keep loading: " << sError);
    if (fMade)
    {
        BOOST_CHECK(!sxAddr.scan_secret.empty());
        BOOST_CHECK(!sxAddr.Encoded().empty());
    }

    fRegTest = fSaved;
}

BOOST_AUTO_TEST_SUITE_END()
