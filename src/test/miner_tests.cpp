#include <boost/test/unit_test.hpp>

#include <memory>

#include "dag.h"
#include "init.h"
#include "main.h"
#include "miner.h"
#include "uint256.h"
#include "util.h"
#include "wallet.h"

extern void SHA256Transform(void* pstate, void* pinput, const void* pinit);

BOOST_AUTO_TEST_SUITE(miner_tests)

BOOST_AUTO_TEST_CASE(dag_parent_boundary_a_canonical_matrix)
{
    std::string error;
    std::vector<uint256> decoded;

    std::vector<uint256> one(1, uint256(1));
    const CScript oneScript = BuildDAGParentScript(one);
    BOOST_CHECK_EQUAL(DecodeCanonicalDAGParentScript(
                          oneScript, decoded, error), DAG_PARENT_VALID);
    BOOST_CHECK(decoded == one);

    std::vector<uint256> thirtyTwo;
    for (unsigned int i = 1; i <= 32; ++i)
        thirtyTwo.push_back(uint256(i));
    const CScript thirtyTwoScript = BuildDAGParentScript(thirtyTwo);
    BOOST_CHECK_EQUAL(DecodeCanonicalDAGParentScript(
                          thirtyTwoScript, decoded, error), DAG_PARENT_VALID);
    BOOST_CHECK(decoded == thirtyTwo);

    std::vector<unsigned char> zeroData(DAG_PARENT_TAG,
                                        DAG_PARENT_TAG + 4);
    zeroData.push_back(0);
    CScript zeroScript;
    zeroScript << OP_RETURN << zeroData;
    BOOST_CHECK_EQUAL(DecodeCanonicalDAGParentScript(
                          zeroScript, decoded, error), DAG_PARENT_MALFORMED);

    std::vector<unsigned char> thirtyThreeData(DAG_PARENT_TAG,
                                               DAG_PARENT_TAG + 4);
    thirtyThreeData.push_back(33);
    for (unsigned int i = 1; i <= 33; ++i)
    {
        uint256 hash(i);
        thirtyThreeData.insert(thirtyThreeData.end(), hash.begin(), hash.end());
    }
    CScript thirtyThreeScript;
    thirtyThreeScript << OP_RETURN << thirtyThreeData;
    BOOST_CHECK_EQUAL(DecodeCanonicalDAGParentScript(
                          thirtyThreeScript, decoded, error), DAG_PARENT_MALFORMED);

    CScript trailingPayload = oneScript;
    trailingPayload << OP_TRUE;
    BOOST_CHECK_EQUAL(DecodeCanonicalDAGParentScript(
                          trailingPayload, decoded, error), DAG_PARENT_MALFORMED);

    std::vector<unsigned char> oneData(DAG_PARENT_TAG, DAG_PARENT_TAG + 4);
    oneData.push_back(1);
    oneData.insert(oneData.end(), one[0].begin(), one[0].end());
    CScript nonMinimal;
    nonMinimal.push_back(OP_RETURN);
    nonMinimal.push_back(OP_PUSHDATA1);
    nonMinimal.push_back((unsigned char)oneData.size());
    nonMinimal.insert(nonMinimal.end(), oneData.begin(), oneData.end());
    BOOST_CHECK_EQUAL(DecodeCanonicalDAGParentScript(
                          nonMinimal, decoded, error), DAG_PARENT_MALFORMED);

    std::vector<uint256> duplicate;
    duplicate.push_back(uint256(9));
    duplicate.push_back(uint256(9));
    std::vector<unsigned char> duplicateData(DAG_PARENT_TAG,
                                             DAG_PARENT_TAG + 4);
    duplicateData.push_back(2);
    duplicateData.insert(duplicateData.end(), duplicate[0].begin(),
                         duplicate[0].end());
    duplicateData.insert(duplicateData.end(), duplicate[1].begin(),
                         duplicate[1].end());
    CScript duplicateScript;
    duplicateScript << OP_RETURN << duplicateData;
    BOOST_CHECK_EQUAL(DecodeCanonicalDAGParentScript(
                          duplicateScript, decoded, error), DAG_PARENT_MALFORMED);

    std::vector<CScript> exactlyOne;
    exactlyOne.push_back(CScript() << OP_RETURN <<
                         std::vector<unsigned char>(1, 0x42));
    exactlyOne.push_back(oneScript);
    BOOST_CHECK(ExtractCanonicalDAGParentCommitment(
        exactlyOne, decoded, error));
    exactlyOne.push_back(thirtyTwoScript);
    BOOST_CHECK(!ExtractCanonicalDAGParentCommitment(
        exactlyOne, decoded, error));
}

// Below Boundary A a payload wide enough to carry 33 parents is refused by CScript::GetOp
// before the count is read, so the count bound is reachable only by a payload claiming
// more parents than it carries.
BOOST_AUTO_TEST_CASE(dag_parent_pre_boundary_a_count_bound_is_reachable)
{
    struct Local
    {
        // Claims nClaimed parents while carrying only nCarried, so the payload
        // stays inside the push limit and the count guard is what answers.
        static CScript Claim(unsigned int nClaimed, unsigned int nCarried)
        {
            std::vector<unsigned char> vch(DAG_PARENT_TAG, DAG_PARENT_TAG + 4);
            vch.push_back((unsigned char)nClaimed);
            for (unsigned int i = 1; i <= nCarried; ++i)
            {
                uint256 hash(i);
                vch.insert(vch.end(), hash.begin(), hash.end());
            }
            CScript script;
            script << OP_RETURN << vch;
            return script;
        }
    };

    // Every count above the bound that the one-octet field can express, in a
    // payload small enough to reach the guard.
    for (unsigned int nClaimed = MAX_DAG_PARENTS + 1; nClaimed <= 255; ++nClaimed)
    {
        const CScript script = Local::Claim(nClaimed, 1);
        BOOST_REQUIRE(script.size() <= MAX_SCRIPT_ELEMENT_SIZE + 4);
        BOOST_CHECK_MESSAGE(
            ExtractDAGParents(script).empty(),
            "pre-Boundary-A decoder admitted a commitment claiming " +
                std::to_string(nClaimed) + " parents");
    }

    // Zero is outside the same range.
    BOOST_CHECK(ExtractDAGParents(Local::Claim(0, 0)).empty());

    // A count inside the bound but not carried is refused for length, so the
    // check above is the count rule and not the length rule wearing its name.
    BOOST_CHECK(ExtractDAGParents(Local::Claim(MAX_DAG_PARENTS, 1)).empty());
}

BOOST_AUTO_TEST_CASE(dag_parent_commitment_decodes_at_the_height_that_built_it)
{
    struct Local
    {
        static std::vector<uint256> Parents(unsigned int nCount)
        {
            std::vector<uint256> v;
            for (unsigned int i = 1; i <= nCount; ++i)
                v.push_back(uint256(i));
            return v;
        }

        // What AcceptBlock will do with this script at this height.
        static bool DecodesAtHeight(int nHeight, const CScript& script,
                                    std::vector<uint256>& vOut)
        {
            if (IsBoundaryAActiveAtHeight(nHeight))
            {
                std::string strError;
                std::vector<CScript> vScripts(1, script);
                return ExtractCanonicalDAGParentCommitment(vScripts, vOut,
                                                           strError);
            }
            vOut = ExtractDAGParents(script);
            return !vOut.empty();
        }
    };

    const int nHeights[] = { GetForkHeightDAG(),
                             GetForkHeightDAG() + 1,
                             GetForkHeightBoundaryA() - 1,
                             GetForkHeightBoundaryA(),
                             GetForkHeightBoundaryA() + 1 };

    for (int nHeight : nHeights)
    {
        const unsigned int nCap = MaxDAGParentsAtHeight(nHeight);
        BOOST_REQUIRE_MESSAGE(nCap >= 1 && nCap <= (unsigned int)MAX_DAG_PARENTS,
                              "cap at height " + std::to_string(nHeight) +
                                  " is outside 1..MAX_DAG_PARENTS");

        // Everything the producer may build at this height is readable by the
        // decoder that will validate it, and reads back as exactly what was
        // committed. This is the property the producer cap exists to hold.
        for (unsigned int nCount = 1; nCount <= nCap; ++nCount)
        {
            const std::vector<uint256> vParents = Local::Parents(nCount);
            const CScript script = BuildDAGParentScript(vParents);
            BOOST_REQUIRE_MESSAGE(script.size() > 0,
                                  "builder refused " + std::to_string(nCount) +
                                      " parents");
            std::vector<uint256> vDecoded;
            BOOST_CHECK_MESSAGE(
                Local::DecodesAtHeight(nHeight, script, vDecoded),
                "height " + std::to_string(nHeight) + ": commitment naming " +
                    std::to_string(nCount) +
                    " parents does not decode at the height that built it");
            BOOST_CHECK_MESSAGE(
                vDecoded == vParents,
                "height " + std::to_string(nHeight) + ": commitment naming " +
                    std::to_string(nCount) + " parents did not round-trip");
        }

        // The cap is the decoder's own limit and not an arbitrary smaller
        // number: one more parent stops decoding at this height. Without this
        // the cap could be lowered to 1 and the loop above would still pass.
        if (nCap < (unsigned int)MAX_DAG_PARENTS)
        {
            const CScript wide = BuildDAGParentScript(Local::Parents(nCap + 1));
            BOOST_REQUIRE(wide.size() > 0);
            std::vector<uint256> vDecoded;
            BOOST_CHECK_MESSAGE(
                !Local::DecodesAtHeight(nHeight, wide, vDecoded),
                "height " + std::to_string(nHeight) + ": cap of " +
                    std::to_string(nCap) + " is below what the decoder accepts");
        }
    }

    // Below Boundary A the ceiling is the script push limit, so it must move
    // with that limit rather than be restated beside it.
    BOOST_CHECK_EQUAL(MaxDAGParentsAtHeight(GetForkHeightDAG()),
                      (MAX_SCRIPT_ELEMENT_SIZE - DAG_PARENT_PAYLOAD_HEADER) / 32);

    // At and above Boundary A the strict decoder parses the payload directly and
    // the full range is available.
    BOOST_CHECK_EQUAL(MaxDAGParentsAtHeight(GetForkHeightBoundaryA()),
                      (unsigned int)MAX_DAG_PARENTS);
}

BOOST_AUTO_TEST_CASE(CreateNewBlock_validity)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_CHECK_EQUAL(mempool.size(), 0U);

    const int nInitialHeight = pindexBest->nHeight;
    const int nTerminalHeight = std::max(nInitialHeight + 2,
                                         FORK_HEIGHT_DAG + 1);
    unsigned int nExtraNonce = 0;
    bool fObservedDAGCommitment = false;

    while (pindexBest->nHeight < nTerminalHeight)
    {
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        BOOST_REQUIRE(pblock.get() != NULL);
        BOOST_REQUIRE(pblock->nVersion == CBlock::CURRENT_VERSION);
        BOOST_REQUIRE_EQUAL(pblock->vtx.size(), 1U);
        BOOST_REQUIRE(pblock->vtx[0].IsCoinBase());

        CBlockIndex* pindexParent = NULL;
        {
            LOCK(cs_main);
            std::map<uint256, CBlockIndex*>::const_iterator mi =
                mapBlockIndex.find(pblock->hashPrevBlock);
            BOOST_REQUIRE(mi != mapBlockIndex.end());
            pindexParent = mi->second;
        }
        BOOST_REQUIRE(pindexParent != NULL);
        const int nHeight = pindexParent->nHeight + 1;

        const CScript expectedHeight = CScript() << nHeight;
        BOOST_REQUIRE(pblock->vtx[0].vin[0].scriptSig.size() >=
                      expectedHeight.size());
        BOOST_CHECK(std::equal(expectedHeight.begin(), expectedHeight.end(),
                               pblock->vtx[0].vin[0].scriptSig.begin()));

        IncrementExtraNonce(pblock.get(), pindexParent, nExtraNonce);
        BOOST_CHECK(pblock->hashMerkleRoot == pblock->BuildMerkleTree());

        if (nHeight >= FORK_HEIGHT_DAG)
        {
            std::vector<uint256> parents;
            for (std::vector<CTxOut>::const_iterator out =
                     pblock->vtx[0].vout.begin();
                 out != pblock->vtx[0].vout.end() && parents.empty(); ++out)
                parents = ExtractDAGParents(out->scriptPubKey);
            BOOST_REQUIRE(!parents.empty());
            BOOST_CHECK(parents.front() == pblock->hashPrevBlock);
            fObservedDAGCommitment = true;
        }

        CBigNum target;
        target.SetCompact(pblock->nBits);
        const uint256 hashTarget = target.getuint256();
        unsigned int nHashes = 0;
        while (pblock->GetPoWHash() > hashTarget)
        {
            ++pblock->nNonce;
            if (pblock->nNonce == 0)
                ++pblock->nTime;
            ++nHashes;
            BOOST_REQUIRE_LT(nHashes, 1000000U);
        }

        BOOST_REQUIRE(pblock->CheckBlock(true, true, true));
        const uint256 blockHash = pblock->GetHash();
        BOOST_REQUIRE(ProcessBlock(NULL, pblock.get()));
        BOOST_REQUIRE(mapBlockIndex.count(blockHash) != 0);
        BOOST_CHECK_EQUAL(mapBlockIndex[blockHash]->nHeight, nHeight);
    }

    BOOST_CHECK(fObservedDAGCommitment);
    BOOST_CHECK_GE(pindexBest->nHeight, FORK_HEIGHT_DAG + 1);
    BOOST_CHECK_EQUAL(mempool.size(), 0U);
}

BOOST_AUTO_TEST_CASE(sha256transform_equality)
{
    unsigned int pSHA256InitState[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};


    // unsigned char pstate[32];
    unsigned char pinput[64];

    int i;

    for (i = 0; i < 32; i++) {
        pinput[i] = i;
        pinput[i+32] = 0;
    }

    uint256 hash;

    SHA256Transform(&hash, pinput, pSHA256InitState);

    BOOST_TEST_MESSAGE(hash.GetHex());

    uint256 hash_reference("0x2df5e1c65ef9f8cde240d23cae2ec036d31a15ec64bc68f64be242b1da6631f3");

    BOOST_CHECK(hash == hash_reference);
}

BOOST_AUTO_TEST_SUITE_END()
