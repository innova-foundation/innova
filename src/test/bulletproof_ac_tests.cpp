#include <boost/test/unit_test.hpp>

#include "../bulletproof_ac.h"
#include "../bignum.h"
#include "../key.h"
#include "../nullstake.h"
#include "../poseidon2.h"
#include "../shielded.h"
#include "../zkproof.h"

#include <openssl/bn.h>
#include <string.h>

extern unsigned int nStakeMinAge;

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

BOOST_AUTO_TEST_SUITE_END()
