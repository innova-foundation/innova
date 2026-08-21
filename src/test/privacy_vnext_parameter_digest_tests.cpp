// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <string>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../main.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"

// The contract digest a payload must name is the chain's, never the local build's
// compile-time list; otherwise builds with different lists would split.

namespace
{

PrivacyVNextDigest DigestOf(const std::vector<unsigned char>& vch)
{
    PrivacyVNextDigest d;
    d.fill(0);
    if (vch.size() == 32)
        std::memcpy(d.data(), &vch[0], 32);
    return d;
}

std::vector<unsigned char> BytesOf(const PrivacyVNextDigest& d)
{
    return std::vector<unsigned char>(d.begin(), d.end());
}

PrivacyVNextDigest LocalGenesis()
{
    PrivacyVNextDigest d;
    PrivacyVNextLocalGenesis(d.data());
    return d;
}

// A shield stamped with whatever digest the caller names. It proves no membership, so it
// needs no tree and no note: the smallest payload that still carries a real prefix, real
// proofs and a real signing hash over the digest under test.
bool BuildShieldUnderDigest(const std::vector<unsigned char>& vchDigest,
                            std::vector<unsigned char>& vchPayloadOut,
                            std::string& strErrorOut)
{
    const PrivacyVNextDigest genesis = LocalGenesis();
    PrivacyVNextDigest seed;
    seed.fill(0x31);

    PrivacyVNextDerivedKeys keys;
    if (!DerivePrivacyVNextKeys(seed, genesis, 0, PrivacyVNextLocalNetworkId(),
                                0, keys, strErrorOut))
        return false;

    PrivacyVNextEpochSeed epochSeed;
    if (!LoadPrivacyVNextEpochSeed(epochSeed, strErrorOut))
        return false;
    const PrivacyVNextDigest emptyRoot = DigestOf(epochSeed.vchRoot);

    PrivacyVNextDigest binding;
    const uint256 hashBinding =
        GetPrivacyVNextTransparentBinding(CTransaction());
    std::memcpy(binding.data(), hashBinding.begin(), 32);

    const uint64_t nValueIn = 10000;
    const uint64_t nFee = 100;
    std::vector<PrivacyVNextNewOutput> outs(1);
    outs[0].recipient.nNetwork = PrivacyVNextLocalNetworkId();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = keys.spendPublic;
    outs[0].recipient.viewPublic = keys.viewPublic;
    outs[0].nAmount = nValueIn - nFee;

    return BuildPrivacyVNextShieldPayload(
        PrivacyVNextLocalNetworkId(), 7, genesis, keys.outgoingViewSecret,
        emptyRoot, epochSeed.nTreeSize, binding, nValueIn, nFee, outs,
        vchPayloadOut, strErrorOut, &vchDigest);
}

// Every contract digest this build has compiled into it, current first.
std::vector<std::vector<unsigned char> > LocalDigestList()
{
    std::vector<std::vector<unsigned char> > vOut;
    size_t nRequired = 0;
    if (innova_privacy_vnext_accepted_parameter_digests(NULL, 0, &nRequired) !=
            INNOVA_PRIVACY_VNEXT_VALID ||
        nRequired < 1 + INNOVA_PRIVACY_VNEXT_DIGEST_SIZE)
        return vOut;
    std::vector<uint8_t> encoded(nRequired);
    size_t nWritten = 0;
    if (innova_privacy_vnext_accepted_parameter_digests(
            &encoded[0], encoded.size(), &nWritten) !=
            INNOVA_PRIVACY_VNEXT_VALID ||
        nWritten != nRequired)
        return vOut;
    for (size_t i = 0; i < (size_t)encoded[0]; ++i)
        vOut.push_back(std::vector<unsigned char>(
            encoded.begin() + 1 + i * INNOVA_PRIVACY_VNEXT_DIGEST_SIZE,
            encoded.begin() + 1 + (i + 1) * INNOVA_PRIVACY_VNEXT_DIGEST_SIZE));
    return vOut;
}

} // namespace

BOOST_AUTO_TEST_SUITE(privacy_vnext_parameter_digest_tests)

// Builds with different compile-time digest lists reach the same verdict: the rule's
// only input is the chain's digest. The peer is simulated by entries the chain lacks.
BOOST_AUTO_TEST_CASE(a_digest_this_build_lists_is_not_a_digest_this_chain_carries)
{
    const std::vector<std::vector<unsigned char> > vLocal = LocalDigestList();
    BOOST_REQUIRE_MESSAGE(vLocal.size() >= 2,
                          "this build must carry at least one superseded contract "
                          "digest for the divergence to be constructible");

    // Take the current digest as the one the chain carries.
    const std::vector<unsigned char> vchChain = vLocal[0];

    for (size_t i = 1; i < vLocal.size(); ++i)
    {
        const std::vector<unsigned char>& vchOther = vLocal[i];
        BOOST_REQUIRE(vchOther != vchChain);

        // This build lists it, so a rule reading the list would admit it.
        BOOST_CHECK_MESSAGE(
            IsAcceptedPrivacyVNextParameterDigest(&vchOther[0], vchOther.size()),
            "the divergence is only constructible from a digest this build lists");

        std::vector<unsigned char> vchPayload;
        std::string error;
        BOOST_REQUIRE_MESSAGE(
            BuildShieldUnderDigest(vchOther, vchPayload, error), error);

        // The decoder must not judge the field: it sees the payload and nothing else,
        // so any verdict it reached here would be the local build's, not the chain's.
        PrivacyVNextStateEffects effects;
        const PrivacyVNextPayloadValidation validation =
            ExtractPrivacyVNextPayloadEffects(
                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vchPayload, effects);
        BOOST_REQUIRE_MESSAGE(
            validation.IsValid(),
            "the decoder must not refuse a payload on its parameter digest: " +
                validation.strError);
        BOOST_CHECK(BytesOf(effects.parameterDigest) == vchOther);

        // And the consensus rule must refuse it, because it is not the chain's.
        std::string strRuleError;
        BOOST_CHECK_MESSAGE(
            !CheckPrivacyVNextParameterDigest(effects, vchChain, strRuleError),
            "a payload naming a digest this build lists but this chain does not "
            "carry must be refused, or block validity depends on which build is "
            "asking");
        BOOST_CHECK(!strRuleError.empty());

        // The same payload is valid on a chain that does carry that digest. The rule
        // reads the chain, so the chain is the only thing that moved.
        BOOST_CHECK(CheckPrivacyVNextParameterDigest(effects, vchOther,
                                                     strRuleError));
    }
}

// A digest no build lists is treated exactly like one every build lists. If the two
// classes were separated anywhere, the separator would be the compile-time list.
BOOST_AUTO_TEST_CASE(an_unlisted_digest_is_judged_no_differently)
{
    const std::vector<std::vector<unsigned char> > vLocal = LocalDigestList();
    BOOST_REQUIRE(!vLocal.empty());
    const std::vector<unsigned char> vchChain = vLocal[0];

    std::vector<unsigned char> vchStray = vchChain;
    vchStray[0] ^= 0x01;
    BOOST_REQUIRE(
        !IsAcceptedPrivacyVNextParameterDigest(&vchStray[0], vchStray.size()));

    std::vector<unsigned char> vchPayload;
    std::string error;
    BOOST_REQUIRE_MESSAGE(BuildShieldUnderDigest(vchStray, vchPayload, error),
                          error);

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation validation =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vchPayload, effects);
    BOOST_REQUIRE_MESSAGE(
        validation.IsValid(),
        "an unlisted digest must decode: refusing it here makes block validity a "
        "property of this binary's list: " + validation.strError);

    std::string strRuleError;
    BOOST_CHECK(!CheckPrivacyVNextParameterDigest(effects, vchChain,
                                                  strRuleError));
    // Carried by a chain, the very same bytes are the correct ones.
    BOOST_CHECK(CheckPrivacyVNextParameterDigest(effects, vchStray,
                                                 strRuleError));
}

// The rule's whole input is the payload and the chain's digest, and it accepts exactly on
// equality. A malformed chain digest is refused rather than compared short.
BOOST_AUTO_TEST_CASE(the_rule_accepts_exactly_the_chains_digest)
{
    const std::vector<std::vector<unsigned char> > vLocal = LocalDigestList();
    BOOST_REQUIRE(!vLocal.empty());

    std::vector<unsigned char> vchPayload;
    std::string error;
    BOOST_REQUIRE_MESSAGE(BuildShieldUnderDigest(vLocal[0], vchPayload, error),
                          error);

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation validation =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vchPayload, effects);
    BOOST_REQUIRE_MESSAGE(validation.IsValid(), validation.strError);

    std::string strRuleError;
    BOOST_CHECK(CheckPrivacyVNextParameterDigest(effects, vLocal[0],
                                                 strRuleError));

    // Every single-bit neighbour of the chain's digest is a different chain.
    for (size_t nByte = 0; nByte < 32; ++nByte)
    {
        std::vector<unsigned char> vchNear = vLocal[0];
        vchNear[nByte] ^= 0x01;
        BOOST_CHECK(!CheckPrivacyVNextParameterDigest(effects, vchNear,
                                                      strRuleError));
    }

    // A chain digest of the wrong width is not a digest.
    std::vector<unsigned char> vchShort(vLocal[0].begin(), vLocal[0].end() - 1);
    BOOST_CHECK(!CheckPrivacyVNextParameterDigest(effects, vchShort,
                                                  strRuleError));
    BOOST_CHECK(!CheckPrivacyVNextParameterDigest(
        effects, std::vector<unsigned char>(), strRuleError));
}

// The builder stamps the digest it is given; with none it uses the bootstrap seed, which
// validators read below the first IV5 epoch.
BOOST_AUTO_TEST_CASE(the_builder_stamps_the_digest_it_is_given)
{
    PrivacyVNextEpochSeed epochSeed;
    std::string error;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    BOOST_REQUIRE_EQUAL(epochSeed.vchParameterDigest.size(), (size_t)32);

    const std::vector<std::vector<unsigned char> > vLocal = LocalDigestList();
    BOOST_REQUIRE(vLocal.size() >= 2);

    for (size_t i = 0; i < vLocal.size(); ++i)
    {
        std::vector<unsigned char> vchPayload;
        BOOST_REQUIRE_MESSAGE(
            BuildShieldUnderDigest(vLocal[i], vchPayload, error), error);
        PrivacyVNextStateEffects effects;
        const PrivacyVNextPayloadValidation validation =
            ExtractPrivacyVNextPayloadEffects(
                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vchPayload, effects);
        BOOST_REQUIRE_MESSAGE(validation.IsValid(), validation.strError);
        BOOST_CHECK(BytesOf(effects.parameterDigest) == vLocal[i]);
    }
}

// Below the first IV5 epoch the pinned bootstrap seed is used for stamping and judging,
// never the linked contract text's hash, so a contract edit is not a flag day.
BOOST_AUTO_TEST_CASE(the_bootstrap_digest_is_pinned_not_the_local_builds_contract)
{
    std::vector<unsigned char> vchPinned(32, 0);
    BOOST_REQUIRE(iv5::DecodeDigestHex(iv5::GENESIS_PARAMETER_DIGEST_SHA256,
                                       &vchPinned[0]));

    PrivacyVNextEpochSeed epochSeed;
    std::string error;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    BOOST_CHECK_MESSAGE(epochSeed.vchParameterDigest == vchPinned,
                        "the bootstrap seed must carry the pinned genesis digest, or "
                        "what a chain stamps its first IV5 epoch with is decided by "
                        "the binary that happened to build it");

    // The linked library's own contract digest is a different value, and stays one.
    std::vector<unsigned char> vchLibrary(INNOVA_PRIVACY_VNEXT_DIGEST_SIZE, 0);
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_parameter_digest(&vchLibrary[0], vchLibrary.size()),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_CHECK_MESSAGE(vchLibrary != vchPinned,
                        "the genesis digest must not be a contract text's hash");
    BOOST_CHECK_MESSAGE(
        !IsAcceptedPrivacyVNextParameterDigest(&vchPinned[0], vchPinned.size()),
        "the genesis digest must not appear on the build's contract-digest list, or "
        "the chain's value and a build's own are the same namespace again");

    // A payload built the way a wallet builds one below the first IV5 epoch: no chain
    // digest to pass, so the builder falls back to the same seed the validator reads.
    std::vector<unsigned char> vchPayload;
    BOOST_REQUIRE_MESSAGE(
        BuildShieldUnderDigest(epochSeed.vchParameterDigest, vchPayload, error),
        error);
    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation validation =
        ExtractPrivacyVNextPayloadEffects(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vchPayload, effects);
    BOOST_REQUIRE_MESSAGE(validation.IsValid(), validation.strError);
    BOOST_CHECK(BytesOf(effects.parameterDigest) == vchPinned);

    std::string strRuleError;
    BOOST_CHECK(CheckPrivacyVNextParameterDigest(
        effects, epochSeed.vchParameterDigest, strRuleError));
    // ...and the same payload is refused against the library's contract digest, which
    // is what a validator would be comparing to if the seed tracked the local build.
    BOOST_CHECK_MESSAGE(
        !CheckPrivacyVNextParameterDigest(effects, vchLibrary, strRuleError),
        "a bootstrap payload must not be judged against this build's contract hash");
}

// Writes the frozen genesis digest out literally, so an edit to the header constant
// fails here.
BOOST_AUTO_TEST_CASE(genesis_parameter_digest_is_frozen)
{
    static const char FROZEN[] =
        "e34a1abae989c66e6d06906a83e419adac4ba04dc0a5dd7804a52fdad9df0387";
    BOOST_CHECK_MESSAGE(
        std::string(iv5::GENESIS_PARAMETER_DIGEST_SHA256) == std::string(FROZEN),
        "GENESIS_PARAMETER_DIGEST_SHA256 was edited; it is consensus for every chain "
        "that has stamped a first IV5 epoch, and re-deriving it from a new contract "
        "text forks them");

    // The property the derivation existed to produce, restated against the literal so it
    // holds even if the constant is what moved.
    std::vector<unsigned char> vchFrozen(32, 0);
    BOOST_REQUIRE(iv5::DecodeDigestHex(FROZEN, &vchFrozen[0]));

    std::vector<unsigned char> vchLibrary(INNOVA_PRIVACY_VNEXT_DIGEST_SIZE, 0);
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_parameter_digest(&vchLibrary[0], vchLibrary.size()),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_CHECK_MESSAGE(vchLibrary != vchFrozen,
                        "the frozen genesis digest collided with this build's contract "
                        "digest, so a chain value and a build value are confusable");
    BOOST_CHECK_MESSAGE(
        !IsAcceptedPrivacyVNextParameterDigest(&vchFrozen[0], vchFrozen.size()),
        "the frozen genesis digest appeared on the build's contract-digest list");
}

BOOST_AUTO_TEST_SUITE_END()
