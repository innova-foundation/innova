#include <boost/test/unit_test.hpp>

#include "../bulletproof_ac.h"
#include "../bignum.h"
#include "../key.h"
#include "../nullstake.h"
#include "../poseidon2.h"
#include "../shielded.h"
#include "../zkproof.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <algorithm>
#include <openssl/obj_mac.h>
#include <string.h>
#include <vector>

extern unsigned int nStakeMinAge;

// Pippenger multiexp under test (defined in bulletproof_ac.cpp, external linkage).
extern bool BPACMultiScalarMul(const EC_GROUP* group, BN_CTX* ctx,
                               const std::vector<EC_POINT*>& points,
                               const std::vector<BIGNUM*>& scalars,
                               EC_POINT* result);

namespace
{

struct CBPACTestCase
{
    CR1CSCircuit circuit;
    CR1CSWitness witness;
    std::vector<std::vector<unsigned char> > commitments;
    CBulletproofACProof proof;
};

uint256 TestScalar(uint64_t n)
{
    return FieldFromUint64(n);
}

uint256 TestZero()
{
    return FieldFromUint64(0);
}

uint256 TestNegOne()
{
    return FieldSub(TestZero(), FieldFromUint64(1));
}

static const int TEST_BPAC_KERNEL_COINDAY_BITS = 64;
static const int TEST_BPAC_KERNEL_REMAINDER_BITS = 43;
static const int TEST_BPAC_KERNEL_PRODUCT_BITS = 96;
static const int TEST_BPAC_KERNEL_COMPARE_BITS = 352;
static const uint64_t TEST_BPAC_KERNEL_DENOMINATOR = (uint64_t)100000000ULL * 86400ULL;

const BIGNUM* TestBigNumConst(const CBigNum& bn)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return bn.pbn;
#else
    return bn.getc();
#endif
}

bool TestCompactTargetMantissaAndShift(unsigned int nBits,
                                       uint64_t& nMantissaOut,
                                       int& nShiftBitsOut)
{
    if (nBits & 0x00800000)
        return false;

    unsigned int nSize = nBits >> 24;
    uint64_t nWord = nBits & 0x007fffff;
    if (nWord == 0)
        return false;

    if (nSize <= 3)
    {
        nMantissaOut = nWord >> (8 * (3 - nSize));
        nShiftBitsOut = 0;
    }
    else
    {
        nMantissaOut = nWord;
        nShiftBitsOut = 8 * (nSize - 3);
    }

    return nMantissaOut != 0 &&
           nShiftBitsOut >= 0 &&
           nShiftBitsOut + TEST_BPAC_KERNEL_PRODUCT_BITS <= TEST_BPAC_KERNEL_COMPARE_BITS;
}

void TestSetBitVectorBigNum(const CBigNum& value,
                            int nBits,
                            CR1CSWitness& witness,
                            int nStart)
{
    const BIGNUM* bn = TestBigNumConst(value);
    for (int i = 0; i < nBits; i++)
    {
        uint256 bit = FieldFromUint64(BN_is_bit_set(bn, i) ? 1 : 0);
        witness.aL[nStart + i] = bit;
        witness.aR[nStart + i] = bit;
        witness.aO[nStart + i] = bit;
    }
}

void TestSetKernelCompareBorrowBits(const CBigNum& threshold,
                                    const uint256& hashKernel,
                                    CR1CSWitness& witness,
                                    int nStart)
{
    const BIGNUM* bnThreshold = TestBigNumConst(threshold);
    const unsigned char* hashLE = hashKernel.begin();
    int nBorrow = 0;
    for (int i = 0; i < TEST_BPAC_KERNEL_COMPARE_BITS; i++)
    {
        int nThresholdBit = BN_is_bit_set(bnThreshold, i) ? 1 : 0;
        int nHashBit = 0;
        if (i < 256)
            nHashBit = (hashLE[i / 8] >> (i % 8)) & 1;
        int nBorrowOut = (nThresholdBit - nBorrow < nHashBit) ? 1 : 0;
        uint256 bit = FieldFromUint64((uint64_t)nBorrowOut);
        witness.aL[nStart + i] = bit;
        witness.aR[nStart + i] = bit;
        witness.aO[nStart + i] = bit;
        nBorrow = nBorrowOut;
    }
}

bool RewriteNullStakeKernelWitness(CR1CSWitness& witness,
                                   uint64_t nStakeModifier,
                                   unsigned int nBlockTimeFrom,
                                   unsigned int nTxPrevOffset,
                                   unsigned int nTxTimePrev,
                                   unsigned int nVoutN,
                                   unsigned int nTimeTx,
                                   unsigned int nBits,
                                   uint64_t nWeightInput,
                                   uint64_t nValueInput)
{
    const int nWeightValueGate = 339;
    const int nCoinDayBitStart = nWeightValueGate + 1;
    const int nRemainderBitStart = nCoinDayBitStart + TEST_BPAC_KERNEL_COINDAY_BITS;
    const int nProductBitStart = nRemainderBitStart + TEST_BPAC_KERNEL_REMAINDER_BITS;
    const int nDifferenceBitStart = nProductBitStart + TEST_BPAC_KERNEL_PRODUCT_BITS;
    const int nBorrowBitStart = nDifferenceBitStart + TEST_BPAC_KERNEL_COMPARE_BITS;
    const int nWeightBitStart = nBorrowBitStart + TEST_BPAC_KERNEL_COMPARE_BITS;

    uint64_t nTargetMantissa = 0;
    int nTargetShiftBits = 0;
    if (!TestCompactTargetMantissaAndShift(nBits, nTargetMantissa, nTargetShiftBits))
        return false;

    uint256 weightScalar = FieldFromUint64(nWeightInput);
    uint256 valueScalar = FieldFromUint64(nValueInput);
    witness.aL[nWeightValueGate] = weightScalar;
    witness.aR[nWeightValueGate] = valueScalar;
    witness.aO[nWeightValueGate] = FieldMul(weightScalar, valueScalar);

    uint256 kernelHash = Poseidon2KernelHash(nStakeModifier, nBlockTimeFrom,
                                             nTxPrevOffset, nTxTimePrev,
                                             nVoutN, nTimeTx);

    CBigNum bnWeightedValue = CBigNum(nValueInput) * CBigNum(nWeightInput);
    CBigNum bnDenominator(TEST_BPAC_KERNEL_DENOMINATOR);
    CBigNum bnCoinDayWeight = bnWeightedValue / bnDenominator;
    CBigNum bnRemainder = bnWeightedValue % bnDenominator;
    CBigNum bnTargetProduct = bnCoinDayWeight * CBigNum(nTargetMantissa);
    CBigNum bnThreshold = bnTargetProduct << nTargetShiftBits;
    CBigNum bnHash(kernelHash);
    if (bnHash > bnThreshold)
        return false;
    CBigNum bnDifference = bnThreshold - bnHash;

    TestSetBitVectorBigNum(bnCoinDayWeight, TEST_BPAC_KERNEL_COINDAY_BITS,
                           witness, nCoinDayBitStart);
    TestSetBitVectorBigNum(bnRemainder, TEST_BPAC_KERNEL_REMAINDER_BITS,
                           witness, nRemainderBitStart);
    TestSetBitVectorBigNum(bnTargetProduct, TEST_BPAC_KERNEL_PRODUCT_BITS,
                           witness, nProductBitStart);
    TestSetBitVectorBigNum(bnDifference, TEST_BPAC_KERNEL_COMPARE_BITS,
                           witness, nDifferenceBitStart);
    TestSetKernelCompareBorrowBits(bnThreshold, kernelHash, witness,
                                   nBorrowBitStart);

    for (int i = 0; i < 32; i++)
    {
        uint256 bit = FieldFromUint64((nWeightInput >> i) & 1);
        witness.aL[nWeightBitStart + i] = bit;
        witness.aR[nWeightBitStart + i] = bit;
        witness.aO[nWeightBitStart + i] = bit;
    }

    return true;
}

void MutateScalar(uint256& scalar)
{
    scalar = FieldAdd(scalar, FieldFromUint64(1));
}

void MutateBytes(std::vector<unsigned char>& bytes)
{
    BOOST_REQUIRE(!bytes.empty());
    bytes[bytes.size() - 1] ^= 0x01;
}

CBPACTestCase BuildValidBPACTestCase()
{
    BOOST_REQUIRE(CZKContext::Initialize());

    CBPACTestCase test;
    test.circuit.nHighLevelVars = 1;
    int nGate = test.circuit.AddMultGate();
    test.circuit.AddMultGate();
    test.circuit.PadToNextPow2();

    std::vector<CSparseEntry> wl, wr, wo, wv;
    wo.push_back(CSparseEntry(nGate, FieldFromUint64(1)));
    wv.push_back(CSparseEntry(0, TestNegOne()));
    test.circuit.AddLinearConstraint(wl, wr, wo, wv, TestZero());

    std::vector<unsigned char> blind;
    BOOST_REQUIRE(GenerateBlindingFactor(blind));

    CPedersenCommitment commit;
    BOOST_REQUIRE(CreatePedersenCommitment(12, blind, commit));
    test.commitments.push_back(commit.vchCommitment);

    test.witness.aL.resize(2);
    test.witness.aR.resize(2);
    test.witness.aO.resize(2);
    test.witness.aL[0] = TestScalar(3);
    test.witness.aR[0] = TestScalar(4);
    test.witness.aO[0] = TestScalar(12);
    test.witness.aL[1] = TestScalar(5);
    test.witness.aR[1] = TestScalar(6);
    test.witness.aO[1] = TestScalar(30);
    test.witness.v.push_back(TestScalar(12));

    uint256 blindScalar;
    for (int i = 0; i < 32; i++)
        blindScalar.begin()[i] = blind[31 - i];
    test.witness.vBlinds.push_back(blindScalar);

    BOOST_REQUIRE(CreateBulletproofACProof(test.circuit, test.witness,
                                           test.commitments, test.proof));
    return test;
}

std::vector<unsigned char> DifferentCommitmentForSameValue()
{
    std::vector<unsigned char> blind;
    BOOST_REQUIRE(GenerateBlindingFactor(blind));

    CPedersenCommitment commit;
    BOOST_REQUIRE(CreatePedersenCommitment(12, blind, commit));
    return commit.vchCommitment;
}

void ExpectMutatedProofRejected(CBulletproofACProof proof,
                                const CR1CSCircuit& circuit,
                                const std::vector<std::vector<unsigned char> >& commitments)
{
    BOOST_CHECK(!VerifyBulletproofACProof(circuit, commitments, proof));
}

} // namespace

BOOST_AUTO_TEST_SUITE(bulletproof_ac_tests)

BOOST_AUTO_TEST_CASE(valid_simple_bpac_proof_verifies)
{
    CBPACTestCase test = BuildValidBPACTestCase();
    BOOST_CHECK(VerifyBulletproofACProof(test.circuit, test.commitments, test.proof));
}

BOOST_AUTO_TEST_CASE(simple_bpac_bad_witness_and_commitment_rejected)
{
    CBPACTestCase test = BuildValidBPACTestCase();

    CR1CSWitness badWitness = test.witness;
    badWitness.aO[0] = TestScalar(13);
    CBulletproofACProof badProof;
    BOOST_CHECK(!CreateBulletproofACProof(test.circuit, badWitness,
                                          test.commitments, badProof));

    BOOST_REQUIRE(CreateBulletproofACProofUncheckedForTests(test.circuit, badWitness,
                                                            test.commitments, badProof));
    BOOST_CHECK(!VerifyBulletproofACProof(test.circuit, test.commitments, badProof));

    std::vector<std::vector<unsigned char> > wrongCommitments = test.commitments;
    wrongCommitments[0] = DifferentCommitmentForSameValue();
    BOOST_CHECK(!CreateBulletproofACProof(test.circuit, test.witness,
                                          wrongCommitments, badProof));
    BOOST_CHECK(!VerifyBulletproofACProof(test.circuit, wrongCommitments,
                                          test.proof));
}

BOOST_AUTO_TEST_CASE(simple_bpac_bad_circuit_and_transcript_rejected)
{
    CBPACTestCase test = BuildValidBPACTestCase();

    CR1CSCircuit badCircuit = test.circuit;
    badCircuit.c[0] = FieldFromUint64(1);
    BOOST_CHECK(!VerifyBulletproofACProof(badCircuit, test.commitments,
                                          test.proof));

    CBulletproofACProof transcriptProof = test.proof;
    MutateBytes(transcriptProof.vchAI);
    ExpectMutatedProofRejected(transcriptProof, test.circuit, test.commitments);

    CBulletproofACProof legacyProof = test.proof;
    legacyProof.nVersion = 1;
    ExpectMutatedProofRejected(legacyProof, test.circuit, test.commitments);
}

BOOST_AUTO_TEST_CASE(simple_bpac_tau_t_and_ipa_mutations_rejected)
{
    CBPACTestCase test = BuildValidBPACTestCase();

    CBulletproofACProof mutated = test.proof;
    MutateScalar(mutated.tauX);
    ExpectMutatedProofRejected(mutated, test.circuit, test.commitments);

    mutated = test.proof;
    MutateScalar(mutated.tHat);
    ExpectMutatedProofRejected(mutated, test.circuit, test.commitments);

    mutated = test.proof;
    MutateScalar(mutated.mu);
    ExpectMutatedProofRejected(mutated, test.circuit, test.commitments);

    mutated = test.proof;
    MutateBytes(mutated.ipaProof.vchAFinal);
    ExpectMutatedProofRejected(mutated, test.circuit, test.commitments);

    BOOST_REQUIRE(!test.proof.ipaProof.vL.empty());

    mutated = test.proof;
    MutateBytes(mutated.ipaProof.vL[0]);
    ExpectMutatedProofRejected(mutated, test.circuit, test.commitments);

    mutated = test.proof;
    MutateBytes(mutated.ipaProof.vR[0]);
    ExpectMutatedProofRejected(mutated, test.circuit, test.commitments);
}

BOOST_AUTO_TEST_CASE(simple_bpac_t_commitment_mutations_rejected)
{
    CBPACTestCase test = BuildValidBPACTestCase();

    CBulletproofACProof mutated = test.proof;
    MutateBytes(mutated.vchT1);
    ExpectMutatedProofRejected(mutated, test.circuit, test.commitments);

    mutated = test.proof;
    MutateBytes(mutated.vchT3);
    ExpectMutatedProofRejected(mutated, test.circuit, test.commitments);

    mutated = test.proof;
    MutateBytes(mutated.vchT4);
    ExpectMutatedProofRejected(mutated, test.circuit, test.commitments);

    mutated = test.proof;
    MutateBytes(mutated.vchT5);
    ExpectMutatedProofRejected(mutated, test.circuit, test.commitments);

    mutated = test.proof;
    MutateBytes(mutated.vchT6);
    ExpectMutatedProofRejected(mutated, test.circuit, test.commitments);
}

BOOST_AUTO_TEST_CASE(nullstake_v2_v3_bpac_paths_create_and_verify)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    std::vector<unsigned char> blind;
    BOOST_REQUIRE(GenerateBlindingFactor(blind));

    CPedersenCommitment commit;
    BOOST_REQUIRE(CreatePedersenCommitment(5000000000LL, blind, commit));

    const unsigned int nBits = 0x207fffff;
    const uint64_t nStakeModifier = 0x1122334455667788ULL;
    const unsigned int nBlockTimeFrom = 100000;
    const unsigned int nTxPrevOffset = 7;
    const unsigned int nTxTimePrev = 100010;
    const unsigned int nVoutN = 3;
    const unsigned int nTimeTx = nBlockTimeFrom + nStakeMinAge + 7200;
    const uint64_t nWeight = nTimeTx - nBlockTimeFrom - nStakeMinAge;

    CNullStakeKernelProofV2 proofV2;
    BOOST_REQUIRE(CreateNullStakeKernelProofV2(5000000000LL, blind, commit,
                                               nBits, nStakeModifier,
                                               nBlockTimeFrom, nTxPrevOffset,
                                               nTxTimePrev, nVoutN, nTimeTx,
                                               proofV2));
    BOOST_CHECK(VerifyNullStakeKernelProofV2(proofV2, commit, nBits));

    CNullStakeKernelProofV2 badProofV2 = proofV2;
    MutateScalar(badProofV2.acProof.tHat);
    BOOST_CHECK(!VerifyNullStakeKernelProofV2(badProofV2, commit, nBits));

    badProofV2 = proofV2;
    MutateBytes(badProofV2.vchLinkProof);
    BOOST_CHECK(!VerifyNullStakeKernelProofV2(badProofV2, commit, nBits));

    badProofV2 = proofV2;
    badProofV2.nTimeTx++;
    BOOST_CHECK(!VerifyNullStakeKernelProofV2(badProofV2, commit, nBits));

    CNullStakeKernelProofV2 losingProofV2;
    BOOST_CHECK(!CreateNullStakeKernelProofV2(5000000000LL, blind, commit,
                                              1, nStakeModifier,
                                              nBlockTimeFrom, nTxPrevOffset,
                                              nTxTimePrev, nVoutN, nTimeTx,
                                              losingProofV2));

    std::vector<std::vector<unsigned char> > maliciousCommitments;
    maliciousCommitments.push_back(commit.vchCommitment);

    {
        CR1CSCircuit maliciousV2Circuit = BuildNullStakeV2Circuit(nStakeModifier,
                                                                  nBlockTimeFrom,
                                                                  nTxPrevOffset,
                                                                  nTxTimePrev,
                                                                  nVoutN,
                                                                  nTimeTx,
                                                                  nBits);
        CR1CSWitness maliciousV2Witness;
        BOOST_REQUIRE(AssignNullStakeV2Witness(maliciousV2Circuit,
                                               nStakeModifier,
                                               nBlockTimeFrom,
                                               nTxPrevOffset,
                                               nTxTimePrev,
                                               nVoutN,
                                               nTimeTx,
                                               5000000000LL,
                                               blind,
                                               nBits,
                                               maliciousV2Witness));
        BOOST_REQUIRE(RewriteNullStakeKernelWitness(maliciousV2Witness,
                                                    nStakeModifier,
                                                    nBlockTimeFrom,
                                                    nTxPrevOffset,
                                                    nTxTimePrev,
                                                    nVoutN,
                                                    nTimeTx,
                                                    nBits,
                                                    nWeight,
                                                    10000000000ULL));
        CBulletproofACProof maliciousV2ACProof;
        BOOST_CHECK(!CreateBulletproofACProof(maliciousV2Circuit,
                                              maliciousV2Witness,
                                              maliciousCommitments,
                                              maliciousV2ACProof));
        BOOST_REQUIRE(CreateBulletproofACProofUncheckedForTests(maliciousV2Circuit,
                                                                maliciousV2Witness,
                                                                maliciousCommitments,
                                                                maliciousV2ACProof));
        BOOST_CHECK(!VerifyBulletproofACProof(maliciousV2Circuit,
                                              maliciousCommitments,
                                              maliciousV2ACProof));
    }

    {
        CR1CSCircuit maliciousV2Circuit = BuildNullStakeV2Circuit(nStakeModifier,
                                                                  nBlockTimeFrom,
                                                                  nTxPrevOffset,
                                                                  nTxTimePrev,
                                                                  nVoutN,
                                                                  nTimeTx,
                                                                  nBits);
        CR1CSWitness maliciousV2Witness;
        BOOST_REQUIRE(AssignNullStakeV2Witness(maliciousV2Circuit,
                                               nStakeModifier,
                                               nBlockTimeFrom,
                                               nTxPrevOffset,
                                               nTxTimePrev,
                                               nVoutN,
                                               nTimeTx,
                                               5000000000LL,
                                               blind,
                                               nBits,
                                               maliciousV2Witness));
        BOOST_REQUIRE(RewriteNullStakeKernelWitness(maliciousV2Witness,
                                                    nStakeModifier,
                                                    nBlockTimeFrom,
                                                    nTxPrevOffset,
                                                    nTxTimePrev,
                                                    nVoutN,
                                                    nTimeTx,
                                                    nBits,
                                                    nWeight + 86400,
                                                    5000000000ULL));
        CBulletproofACProof maliciousV2ACProof;
        BOOST_CHECK(!CreateBulletproofACProof(maliciousV2Circuit,
                                              maliciousV2Witness,
                                              maliciousCommitments,
                                              maliciousV2ACProof));
        BOOST_REQUIRE(CreateBulletproofACProofUncheckedForTests(maliciousV2Circuit,
                                                                maliciousV2Witness,
                                                                maliciousCommitments,
                                                                maliciousV2ACProof));
        BOOST_CHECK(!VerifyBulletproofACProof(maliciousV2Circuit,
                                              maliciousCommitments,
                                              maliciousV2ACProof));
    }

    uint256 skStake = FieldFromUint64(42);
    std::vector<unsigned char> pkStake;
    BOOST_REQUIRE(DeriveStakingPubKey(skStake, pkStake));
    CKey ownerKey;
    ownerKey.MakeNewKey(true);
    CPubKey ownerPubKey = ownerKey.GetPubKey();
    std::vector<unsigned char> pkOwner(ownerPubKey.begin(), ownerPubKey.end());
    uint256 delegationHash;
    BOOST_REQUIRE(ComputeNullStakeV3DelegationHash(5000000000LL,
                                                   pkStake,
                                                   pkOwner,
                                                   delegationHash));

    CNullStakeKernelProofV3 proofV3;
    BOOST_REQUIRE(CreateNullStakeKernelProofV3(5000000000LL, blind, commit,
                                               nBits, nStakeModifier,
                                               nBlockTimeFrom, nTxPrevOffset,
                                               nTxTimePrev, nVoutN, nTimeTx,
                                               skStake, pkOwner,
                                               delegationHash, proofV3));
    BOOST_CHECK(VerifyNullStakeKernelProofV3(proofV3, commit, nBits));

    uint256 wrongDelegationHash = FieldAdd(delegationHash, FieldFromUint64(1));
    CNullStakeKernelProofV3 mismatchedDelegationProofV3;
    BOOST_CHECK(!CreateNullStakeKernelProofV3(5000000000LL, blind, commit,
                                              nBits, nStakeModifier,
                                              nBlockTimeFrom, nTxPrevOffset,
                                              nTxTimePrev, nVoutN, nTimeTx,
                                              skStake, pkOwner,
                                              wrongDelegationHash,
                                              mismatchedDelegationProofV3));

    CKey otherOwnerKey;
    otherOwnerKey.MakeNewKey(true);
    CPubKey otherOwnerPubKey = otherOwnerKey.GetPubKey();
    std::vector<unsigned char> otherPkOwner(otherOwnerPubKey.begin(),
                                            otherOwnerPubKey.end());
    BOOST_CHECK(!CreateNullStakeKernelProofV3(5000000000LL, blind, commit,
                                              nBits, nStakeModifier,
                                              nBlockTimeFrom, nTxPrevOffset,
                                              nTxTimePrev, nVoutN, nTimeTx,
                                              skStake, otherPkOwner,
                                              delegationHash,
                                              mismatchedDelegationProofV3));

    CR1CSCircuit maliciousV3Circuit = BuildNullStakeV3Circuit(nStakeModifier,
                                                              nBlockTimeFrom,
                                                              nTxPrevOffset,
                                                              nTxTimePrev,
                                                              nVoutN,
	                                                              nTimeTx,
	                                                              nBits,
	                                                              wrongDelegationHash,
	                                                              pkStake,
	                                                              pkOwner);
    CR1CSWitness maliciousV3Witness;
    BOOST_REQUIRE(AssignNullStakeV3Witness(maliciousV3Circuit,
                                           nStakeModifier,
                                           nBlockTimeFrom,
                                           nTxPrevOffset,
                                           nTxTimePrev,
                                           nVoutN,
                                           nTimeTx,
                                           5000000000LL,
                                           blind,
                                           nBits,
                                           skStake,
                                           pkStake,
                                           pkOwner,
                                           delegationHash,
                                           maliciousV3Witness));
    std::vector<std::vector<unsigned char> > maliciousV3Commitments;
    maliciousV3Commitments.push_back(commit.vchCommitment);
    CBulletproofACProof maliciousV3ACProof;
    BOOST_REQUIRE(CreateBulletproofACProofUncheckedForTests(maliciousV3Circuit,
                                                            maliciousV3Witness,
                                                            maliciousV3Commitments,
                                                            maliciousV3ACProof));
	    BOOST_CHECK(!VerifyBulletproofACProof(maliciousV3Circuit,
	                                          maliciousV3Commitments,
	                                          maliciousV3ACProof));

	    {
	        CR1CSCircuit maliciousV3ValueCircuit = BuildNullStakeV3Circuit(nStakeModifier,
	                                                                       nBlockTimeFrom,
	                                                                       nTxPrevOffset,
	                                                                       nTxTimePrev,
	                                                                       nVoutN,
	                                                                       nTimeTx,
	                                                                       nBits,
	                                                                       delegationHash,
	                                                                       pkStake,
	                                                                       pkOwner);
	        CR1CSWitness maliciousV3ValueWitness;
	        BOOST_REQUIRE(AssignNullStakeV3Witness(maliciousV3ValueCircuit,
	                                               nStakeModifier,
	                                               nBlockTimeFrom,
	                                               nTxPrevOffset,
	                                               nTxTimePrev,
	                                               nVoutN,
	                                               nTimeTx,
	                                               5000000000LL,
	                                               blind,
	                                               nBits,
	                                               skStake,
	                                               pkStake,
	                                               pkOwner,
	                                               delegationHash,
	                                               maliciousV3ValueWitness));
	        BOOST_REQUIRE(RewriteNullStakeKernelWitness(maliciousV3ValueWitness,
	                                                    nStakeModifier,
	                                                    nBlockTimeFrom,
	                                                    nTxPrevOffset,
	                                                    nTxTimePrev,
	                                                    nVoutN,
	                                                    nTimeTx,
	                                                    nBits,
	                                                    nWeight,
	                                                    10000000000ULL));
	        BOOST_CHECK(!CreateBulletproofACProof(maliciousV3ValueCircuit,
	                                              maliciousV3ValueWitness,
	                                              maliciousV3Commitments,
	                                              maliciousV3ACProof));
	        BOOST_REQUIRE(CreateBulletproofACProofUncheckedForTests(maliciousV3ValueCircuit,
	                                                                maliciousV3ValueWitness,
	                                                                maliciousV3Commitments,
	                                                                maliciousV3ACProof));
	        BOOST_CHECK(!VerifyBulletproofACProof(maliciousV3ValueCircuit,
	                                              maliciousV3Commitments,
	                                              maliciousV3ACProof));
	    }

	    uint256 otherDelegationHash;
	    BOOST_REQUIRE(ComputeNullStakeV3DelegationHash(5000000000LL,
	                                                   pkStake,
	                                                   otherPkOwner,
	                                                   otherDelegationHash));
	    {
	        CR1CSCircuit ownerMismatchCircuit = BuildNullStakeV3Circuit(nStakeModifier,
	                                                                    nBlockTimeFrom,
	                                                                    nTxPrevOffset,
	                                                                    nTxTimePrev,
	                                                                    nVoutN,
	                                                                    nTimeTx,
	                                                                    nBits,
	                                                                    otherDelegationHash,
	                                                                    pkStake,
	                                                                    pkOwner);
	        CR1CSWitness ownerMismatchWitness;
	        BOOST_REQUIRE(AssignNullStakeV3Witness(ownerMismatchCircuit,
	                                               nStakeModifier,
	                                               nBlockTimeFrom,
	                                               nTxPrevOffset,
	                                               nTxTimePrev,
	                                               nVoutN,
	                                               nTimeTx,
	                                               5000000000LL,
	                                               blind,
	                                               nBits,
	                                               skStake,
	                                               pkStake,
	                                               otherPkOwner,
	                                               otherDelegationHash,
	                                               ownerMismatchWitness));
	        BOOST_CHECK(!CreateBulletproofACProof(ownerMismatchCircuit,
	                                              ownerMismatchWitness,
	                                              maliciousV3Commitments,
	                                              maliciousV3ACProof));
	        BOOST_REQUIRE(CreateBulletproofACProofUncheckedForTests(ownerMismatchCircuit,
	                                                                ownerMismatchWitness,
	                                                                maliciousV3Commitments,
	                                                                maliciousV3ACProof));
	        BOOST_CHECK(!VerifyBulletproofACProof(ownerMismatchCircuit,
	                                              maliciousV3Commitments,
	                                              maliciousV3ACProof));
	    }

	    CNullStakeKernelProofV3 badProofV3 = proofV3;
    MutateScalar(badProofV3.acProof.tHat);
    BOOST_CHECK(!VerifyNullStakeKernelProofV3(badProofV3, commit, nBits));

    badProofV3 = proofV3;
    MutateBytes(badProofV3.vchLinkProof);
    BOOST_CHECK(!VerifyNullStakeKernelProofV3(badProofV3, commit, nBits));

    badProofV3 = proofV3;
    MutateScalar(badProofV3.delegationHash);
    BOOST_CHECK(!VerifyNullStakeKernelProofV3(badProofV3, commit, nBits));

    badProofV3 = proofV3;
    badProofV3.vchPkStake.clear();
    BOOST_CHECK(!VerifyNullStakeKernelProofV3(badProofV3, commit, nBits));

	    badProofV3 = proofV3;
	    MutateBytes(badProofV3.vchPkStake);
	    BOOST_CHECK(!VerifyNullStakeKernelProofV3(badProofV3, commit, nBits));

	    badProofV3 = proofV3;
	    badProofV3.vchPkOwner = otherPkOwner;
	    BOOST_CHECK(!VerifyNullStakeKernelProofV3(badProofV3, commit, nBits));

	    badProofV3 = proofV3;
	    badProofV3.nTimeTx++;
    BOOST_CHECK(!VerifyNullStakeKernelProofV3(badProofV3, commit, nBits));

    CNullStakeKernelProofV3 losingProofV3;
    BOOST_CHECK(!CreateNullStakeKernelProofV3(5000000000LL, blind, commit,
                                              1, nStakeModifier,
                                              nBlockTimeFrom, nTxPrevOffset,
                                              nTxTimePrev, nVoutN, nTimeTx,
                                              skStake, pkOwner,
                                              delegationHash, losingProofV3));
}

// B2-e: M-of-N (half-aggregated Schnorr) cold-stake kernel proof, end-to-end create->verify
// plus adversarial cases (the consensus crypto wiring; FCMP membership is enforced separately
// in ConnectBlock and binds the 3-generator leaf cv3 to the tree).
BOOST_AUTO_TEST_CASE(nullstake_mofn_kernel_proof_create_verify)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    if (!CPoseidon2Params::IsInitialized())
        CPoseidon2Params::Initialize();

    typedef std::vector<unsigned char> valtype;
    const int64_t nValue = 5000000000LL;
    valtype blind(32, 0);
    blind[0] = 0x11; blind[31] = 0x07;   // nonzero blinding factor
    const unsigned int nBits = 0x207fffff;
    const uint64_t nStakeModifier = 0x1122334455667788ULL;
    const unsigned int nBlockTimeFrom = 100000;
    const unsigned int nTxPrevOffset = 7;
    const unsigned int nTxTimePrev = 100010;
    const unsigned int nVoutN = 3;
    const unsigned int nTimeTx = nBlockTimeFrom + nStakeMinAge + 7200;

    // 2-of-3 staker set (canonical) + an owner key.
    std::vector<uint256> setSk;
    setSk.push_back(uint256(70001ULL)); setSk.push_back(uint256(70002ULL)); setSk.push_back(uint256(70003ULL));
    std::vector<valtype> set;
    for (size_t i = 0; i < setSk.size(); i++)
    {
        valtype pk; BOOST_REQUIRE(HalfAggStakeDerivePubKey(setSk[i], pk)); set.push_back(pk);
    }
    std::sort(set.begin(), set.end());
    valtype owner; BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256(79999ULL), owner));

    uint256 delegationHash;
    BOOST_REQUIRE(ComputeNullStakeV3DelegationSetHash(set, 2, owner, delegationHash));

    // The cold-stake note leaf is the 3-generator commitment.
    CPedersenCommitment cv3;
    BOOST_REQUIRE(CreateNullStakeMofNCommitment(nValue, blind, delegationHash, cv3));

    std::vector<uint256> signers;
    signers.push_back(uint256(70001ULL)); signers.push_back(uint256(70002ULL));   // 2 of 3

    CNullStakeKernelProofV3 proof;
    BOOST_REQUIRE(CreateNullStakeMofNKernelProofV3(nValue, blind, cv3, nBits, nStakeModifier,
        nBlockTimeFrom, nTxPrevOffset, nTxTimePrev, nVoutN, nTimeTx, set, 2, owner,
        delegationHash, signers, proof));
    BOOST_CHECK_MESSAGE(VerifyNullStakeKernelProofV3(proof, cv3, nBits),
                        "a valid 2-of-3 M-of-N kernel proof should verify");
    BOOST_CHECK_EQUAL(proof.nThresholdM, 2u);
    BOOST_CHECK_MESSAGE(proof.vchPkStake.empty(), "M-of-N proof must not carry a single pkStake");
    BOOST_CHECK_EQUAL(proof.vStakerSet.size(), 3u);

    // (a) tampered aggregated s-scalar -> reject.
    {
        CNullStakeKernelProofV3 bad = proof;
        bad.vchAggregatedSScalar[0] ^= 0x01;
        BOOST_CHECK_MESSAGE(!VerifyNullStakeKernelProofV3(bad, cv3, nBits),
                            "a tampered aggregated s-scalar must be rejected");
    }
    // (b) substituted staker set (attacker keys) against the committed delegationHash -> reject.
    {
        CNullStakeKernelProofV3 bad = proof;
        std::vector<uint256> aSk;
        aSk.push_back(uint256(80001ULL)); aSk.push_back(uint256(80002ULL)); aSk.push_back(uint256(80003ULL));
        bad.vStakerSet.clear();
        for (size_t i = 0; i < aSk.size(); i++)
        {
            valtype pk; BOOST_REQUIRE(HalfAggStakeDerivePubKey(aSk[i], pk)); bad.vStakerSet.push_back(pk);
        }
        std::sort(bad.vStakerSet.begin(), bad.vStakerSet.end());
        BOOST_CHECK_MESSAGE(!VerifyNullStakeKernelProofV3(bad, cv3, nBits),
                            "a substituted staker set must not match the committed delegation hash");
    }
    // (c) downgrade: submit the M-of-N leaf/proof as nThresholdM == 0 -> 1-of-1 path rejects it.
    {
        CNullStakeKernelProofV3 bad = proof;
        bad.nThresholdM = 0;
        BOOST_CHECK_MESSAGE(!VerifyNullStakeKernelProofV3(bad, cv3, nBits),
                            "an M-of-N leaf submitted as 1-of-1 must be rejected");
    }
    // (d) verify against a DIFFERENT leaf (different delegationHash) -> cv_plain/link/digest reject.
    {
        uint256 dh2;
        BOOST_REQUIRE(ComputeNullStakeV3DelegationSetHash(set, 3, owner, dh2));   // M=3 -> different hash
        CPedersenCommitment cv3b;
        BOOST_REQUIRE(CreateNullStakeMofNCommitment(nValue, blind, dh2, cv3b));
        BOOST_CHECK_MESSAGE(!VerifyNullStakeKernelProofV3(proof, cv3b, nBits),
                            "the proof must not verify against a different note leaf");
    }
    // (e) creating a proof with fewer than M signer secrets must fail.
    {
        std::vector<uint256> one; one.push_back(uint256(70001ULL));
        CNullStakeKernelProofV3 p2;
        BOOST_CHECK_MESSAGE(!CreateNullStakeMofNKernelProofV3(nValue, blind, cv3, nBits, nStakeModifier,
            nBlockTimeFrom, nTxPrevOffset, nTxTimePrev, nVoutN, nTimeTx, set, 2, owner,
            delegationHash, one, p2),
            "creating an M-of-N proof with fewer than M signers must fail");
    }
    // (f) a leaf with the wrong value cannot be built into a proof (commitment mismatch).
    {
        CPedersenCommitment cvWrongValue;
        BOOST_REQUIRE(CreateNullStakeMofNCommitment(nValue + 1, blind, delegationHash, cvWrongValue));
        CNullStakeKernelProofV3 p3;
        BOOST_CHECK_MESSAGE(!CreateNullStakeMofNKernelProofV3(nValue, blind, cvWrongValue, nBits, nStakeModifier,
            nBlockTimeFrom, nTxPrevOffset, nTxTimePrev, nVoutN, nTimeTx, set, 2, owner,
            delegationHash, signers, p3),
            "a leaf that does not commit to (value,blind,delegationHash) must fail to build");
    }
}

// B2-e MINT LINK: the 2-generator Okamoto (G,J) representation proof binding the 3-generator leaf
// cv3 to a fresh 2-generator value commitment Vv. This is the load-bearing mint value-binding (it
// FAILS OPEN if omitted), so the adversarial cases are the inflation/forgery guards.
BOOST_AUTO_TEST_CASE(nullstake_mofn_mint_link_create_verify)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    typedef std::vector<unsigned char> valtype;
    const int64_t nValue = 5000000000LL;

    valtype blindCv3, blindVv;
    BOOST_REQUIRE(GenerateBlindingFactor(blindCv3));
    BOOST_REQUIRE(GenerateBlindingFactor(blindVv));

    std::vector<uint256> setSk;
    setSk.push_back(uint256(70001ULL)); setSk.push_back(uint256(70002ULL)); setSk.push_back(uint256(70003ULL));
    std::vector<valtype> set;
    for (size_t i = 0; i < setSk.size(); i++) { valtype pk; BOOST_REQUIRE(HalfAggStakeDerivePubKey(setSk[i], pk)); set.push_back(pk); }
    std::sort(set.begin(), set.end());
    valtype owner; BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256(79999ULL), owner));
    uint256 D; BOOST_REQUIRE(ComputeNullStakeV3DelegationSetHash(set, 2, owner, D));

    // cv3 = value*H + blindCv3*G + D*J ; Vv = value*H + blindVv*G  (same value, fresh blind).
    CPedersenCommitment cv3, Vv;
    BOOST_REQUIRE(CreateNullStakeMofNCommitment(nValue, blindCv3, D, cv3));
    BOOST_REQUIRE(CreatePedersenCommitment(nValue, blindVv, Vv));

    valtype link;
    BOOST_REQUIRE(CreateNullStakeMofNMintLink(cv3, Vv, blindCv3, blindVv, D, link));
    BOOST_CHECK_EQUAL(link.size(), (size_t)97);
    BOOST_CHECK_MESSAGE(VerifyNullStakeMofNMintLink(cv3, Vv, link),
                        "an honest mint link (cv3 and Vv share the value) must verify");

    // (a) INFLATION GUARD: Vv commits to a DIFFERENT value than cv3 -> the difference has an
    // H-component, so no (G,J) representation exists -> verify must reject.
    {
        CPedersenCommitment VvWrong;
        BOOST_REQUIRE(CreatePedersenCommitment(nValue + 1, blindVv, VvWrong));
        valtype linkW;
        BOOST_REQUIRE(CreateNullStakeMofNMintLink(cv3, VvWrong, blindCv3, blindVv, D, linkW));
        BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNMintLink(cv3, VvWrong, linkW),
                            "a Vv that commits to a different value than cv3 must be rejected (inflation guard)");
    }
    // (b) tampered s_a -> reject.
    { valtype bad = link; bad[33] ^= 0x01; BOOST_CHECK(!VerifyNullStakeMofNMintLink(cv3, Vv, bad)); }
    // (c) tampered s_b -> reject.
    { valtype bad = link; bad[65] ^= 0x01; BOOST_CHECK(!VerifyNullStakeMofNMintLink(cv3, Vv, bad)); }
    // (d) tampered R -> reject.
    { valtype bad = link; bad[1] ^= 0x01; BOOST_CHECK(!VerifyNullStakeMofNMintLink(cv3, Vv, bad)); }
    // (e) the link proves a DIFFERENT delegationHash than the leaf's J term -> reject.
    {
        uint256 D2; BOOST_REQUIRE(ComputeNullStakeV3DelegationSetHash(set, 3, owner, D2));   // M=3 -> different hash
        valtype linkW;
        BOOST_REQUIRE(CreateNullStakeMofNMintLink(cv3, Vv, blindCv3, blindVv, D2, linkW));
        BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNMintLink(cv3, Vv, linkW),
                            "a link proving a different delegationHash than the leaf's J term must be rejected");
    }
    // (f) non-canonical s_a (>= n) -> reject.
    { valtype bad = link; for (int i = 33; i < 65; i++) bad[i] = 0xFF; BOOST_CHECK(!VerifyNullStakeMofNMintLink(cv3, Vv, bad)); }
    // (g) wrong size -> reject.
    { valtype bad = link; bad.push_back(0x00); BOOST_CHECK(!VerifyNullStakeMofNMintLink(cv3, Vv, bad)); }
    // (h) swapped cv3/Vv (the link is bound to the ordered pair) -> reject.
    { BOOST_CHECK(!VerifyNullStakeMofNMintLink(Vv, cv3, link)); }
}

// The Pippenger multiexp must equal the naive sum bit-for-bit, including edge
// cases (zero scalar, identity point), across sizes up to the AC verifier's.
BOOST_AUTO_TEST_CASE(multiscalarmul_matches_naive)
{
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* order = BN_new();
    BOOST_REQUIRE(group && ctx && order);
    BOOST_REQUIRE(EC_GROUP_get_order(group, order, ctx) == 1);

    const size_t sizes[] = {1, 2, 5, 33, 100, 257, 1000, 2053};
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++)
    {
        size_t n = sizes[si];
        std::vector<EC_POINT*> pts;
        std::vector<BIGNUM*> scs;
        for (size_t i = 0; i < n; i++)
        {
            BIGNUM* k = BN_new(); BN_rand_range(k, order);
            EC_POINT* P = EC_POINT_new(group);
            BOOST_REQUIRE(EC_POINT_mul(group, P, k, NULL, NULL, ctx) == 1);
            BN_free(k);
            BIGNUM* s = BN_new(); BN_rand_range(s, order);
            pts.push_back(P);
            scs.push_back(s);
        }
        if (n >= 2)
        {
            BN_zero(scs[0]);                                        // zero-scalar skip
            BOOST_REQUIRE(EC_POINT_set_to_infinity(group, pts[1]) == 1); // identity point
        }

        EC_POINT* naive = EC_POINT_new(group);
        EC_POINT* term = EC_POINT_new(group);
        BOOST_REQUIRE(EC_POINT_set_to_infinity(group, naive) == 1);
        for (size_t i = 0; i < n; i++)
        {
            BOOST_REQUIRE(EC_POINT_mul(group, term, NULL, pts[i], scs[i], ctx) == 1);
            BOOST_REQUIRE(EC_POINT_add(group, naive, naive, term, ctx) == 1);
        }

        EC_POINT* pip = EC_POINT_new(group);
        BOOST_REQUIRE(BPACMultiScalarMul(group, ctx, pts, scs, pip));
        BOOST_CHECK_MESSAGE(EC_POINT_cmp(group, naive, pip, ctx) == 0,
                            "multiexp mismatch at n=" << n);

        for (size_t i = 0; i < n; i++) { EC_POINT_free(pts[i]); BN_free(scs[i]); }
        EC_POINT_free(naive); EC_POINT_free(term); EC_POINT_free(pip);
    }
    BN_free(order); BN_CTX_free(ctx); EC_GROUP_free(group);
}

BOOST_AUTO_TEST_SUITE_END()
