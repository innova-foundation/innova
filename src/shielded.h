// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_SHIELDED_H
#define INN_SHIELDED_H

#include "uint256.h"
#include "serialize.h"
#include "hash.h"
#include "zkproof.h"
#include "curvetree.h"

#include <vector>
#include <string>
#include <stdint.h>
#include <openssl/crypto.h>
#include <boost/thread/once.hpp>

static const int SHIELDED_TX_VERSION = 2000;

static const int SHIELDED_TX_VERSION_DSP = 2001;

static const int SHIELDED_TX_VERSION_FCMP = 2002;

static const int SHIELDED_TX_VERSION_NULLSTAKE = 2003;

static const int SHIELDED_TX_VERSION_NULLSTAKE_V2 = 2004;

static const int SHIELDED_TX_VERSION_NULLSTAKE_COLD = 2005;

static const int SHIELDED_MERKLE_DEPTH = 32;

static const int MIN_SHIELDED_SPEND_DEPTH = 10;

static const int64_t MIN_TX_FEE_SHIELDED = 100000;

static const int MAX_SHIELDED_INPUTS = 16;
static const int MAX_SHIELDED_OUTPUTS = 16;

static const uint8_t PRIVACY_HIDE_SENDER    = 0x01;
static const uint8_t PRIVACY_HIDE_RECEIVER   = 0x02;
static const uint8_t PRIVACY_HIDE_AMOUNT     = 0x04;
static const uint8_t PRIVACY_MODE_MASK       = 0x07;
static const uint8_t PRIVACY_MODE_TRANSPARENT = 0x00;
static const uint8_t PRIVACY_MODE_FULL       = 0x07;

inline bool DSP_HideSender(uint8_t mode)   { return (mode & PRIVACY_HIDE_SENDER) != 0; }
inline bool DSP_HideReceiver(uint8_t mode) { return (mode & PRIVACY_HIDE_RECEIVER) != 0; }
inline bool DSP_HideAmount(uint8_t mode)   { return (mode & PRIVACY_HIDE_AMOUNT) != 0; }

static const size_t SHIELDED_DIVERSIFIER_SIZE = 11;
static const size_t SHIELDED_PKD_SIZE = 33;
static const size_t SHIELDED_PROOF_SIZE = 672;
static const size_t SHIELDED_EPHEMERAL_KEY_SIZE = 33;
static const size_t SHIELDED_ENC_CIPHERTEXT_SIZE = 580;
static const size_t SHIELDED_OUT_CIPHERTEXT_SIZE = 80;
static const size_t SHIELDED_BINDING_SIG_SIZE = 65;


class CShieldedSpendingKey
{
public:
    uint256 skSpend;
    uint256 skPrf;
    uint256 ovk;

    CShieldedSpendingKey()
    {
        skSpend = 0;
        skPrf = 0;
        ovk = 0;
    }

    ~CShieldedSpendingKey()
    {
        OPENSSL_cleanse(skSpend.begin(), 32);
        OPENSSL_cleanse(skPrf.begin(), 32);
        OPENSSL_cleanse(ovk.begin(), 32);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(skSpend);
        READWRITE(skPrf);
        READWRITE(ovk);
    )

    bool IsNull() const { return skSpend == 0; }
};

class CShieldedFullViewingKey
{
public:
    std::vector<unsigned char> vchAk;
    uint256 nk;
    uint256 ovk;

    CShieldedFullViewingKey()
    {
        nk = 0;
        ovk = 0;
    }

    ~CShieldedFullViewingKey()
    {
        if (!vchAk.empty())
            OPENSSL_cleanse(vchAk.data(), vchAk.size());
        OPENSSL_cleanse(nk.begin(), 32);
        OPENSSL_cleanse(ovk.begin(), 32);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchAk);
        READWRITE(nk);
        READWRITE(ovk);
    )
};

class CShieldedIncomingViewingKey
{
public:
    uint256 ivk;

    CShieldedIncomingViewingKey()
    {
        ivk = 0;
    }

    ~CShieldedIncomingViewingKey()
    {
        OPENSSL_cleanse(ivk.begin(), 32);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(ivk);
    )

    bool IsNull() const { return ivk == 0; }
};

class CShieldedPaymentAddress
{
public:
    std::vector<unsigned char> vchDiversifier;
    std::vector<unsigned char> vchPkD;

    CShieldedPaymentAddress()
    {
        vchDiversifier.resize(SHIELDED_DIVERSIFIER_SIZE, 0);
        vchPkD.resize(SHIELDED_PKD_SIZE, 0);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchDiversifier);
        READWRITE(vchPkD);
    )

    bool IsNull() const
    {
        for (size_t i = 0; i < vchPkD.size(); i++)
            if (vchPkD[i] != 0) return false;
        return true;
    }

    bool operator==(const CShieldedPaymentAddress& other) const
    {
        return vchDiversifier == other.vchDiversifier && vchPkD == other.vchPkD;
    }

    bool operator<(const CShieldedPaymentAddress& other) const
    {
        if (vchDiversifier != other.vchDiversifier)
            return vchDiversifier < other.vchDiversifier;
        return vchPkD < other.vchPkD;
    }
};


class CShieldedNote
{
public:
    CShieldedPaymentAddress addr;
    int64_t nValue;
    uint256 rho;
    uint256 rcm;
    std::vector<unsigned char> vchBlind;

    CShieldedNote()
    {
        nValue = 0;
        rho = 0;
        rcm = 0;
    }

    ~CShieldedNote()
    {
        OPENSSL_cleanse(rho.begin(), 32);
        OPENSSL_cleanse(rcm.begin(), 32);
        if (!vchBlind.empty())
            OPENSSL_cleanse(vchBlind.data(), vchBlind.size());
        nValue = 0;
    }

    uint256 GetCommitment() const;

    bool GetPedersenCommitment(CPedersenCommitment& commitOut) const;

    uint256 GetNullifier(const uint256& nk) const;

    bool GenerateBlindingFactor();

    IMPLEMENT_SERIALIZE
    (
        READWRITE(addr);
        READWRITE(nValue);
        READWRITE(rho);
        READWRITE(rcm);
        READWRITE(vchBlind);
    )
};


class CShieldedSpendDescription
{
public:
    CPedersenCommitment cv;
    uint256 anchor;
    uint256 nullifier;
    std::vector<unsigned char> vchRk;
    CBulletproofRangeProof rangeProof;
    std::vector<unsigned char> vchSpendAuthSig;
    std::vector<unsigned char> vchLelantusProof;
    std::vector<CPedersenCommitment> vAnonSet;
    uint256 lelantusSerial;

    int64_t nPlaintextValue;
    std::vector<unsigned char> vchPlaintextBlind;

    CFCMPProof fcmpProof;
    uint256 curveTreeRoot;

    CShieldedSpendDescription()
    {
        anchor = 0;
        nullifier = 0;
        lelantusSerial = 0;
        nPlaintextValue = -1;
        curveTreeRoot = 0;
    }

    bool HasFCMPProof() const { return !fcmpProof.IsNull(); }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(cv);
        READWRITE(anchor);
        READWRITE(nullifier);
        READWRITE(vchRk);
        READWRITE(rangeProof);
        READWRITE(vchSpendAuthSig);
        READWRITE(vchLelantusProof);
        READWRITE(vAnonSet);
        READWRITE(lelantusSerial);

        unsigned char fHasFCMP = fcmpProof.IsNull() ? 0 : 1;
        READWRITE(fHasFCMP);
        if (fHasFCMP)
        {
            READWRITE(fcmpProof);
            READWRITE(curveTreeRoot);
        }
    )
};

class CShieldedOutputDescription
{
public:
    CPedersenCommitment cv;
    uint256 cmu;
    std::vector<unsigned char> vchEphemeralKey;
    std::vector<unsigned char> vchEncCiphertext;
    std::vector<unsigned char> vchOutCiphertext;
    CBulletproofRangeProof rangeProof;

    int64_t nPlaintextValue;
    std::vector<unsigned char> vchPlaintextBlind;
    std::vector<unsigned char> vchRecipientScript;

    CShieldedOutputDescription()
    {
        cmu = 0;
        nPlaintextValue = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(cv);
        READWRITE(cmu);
        READWRITE(vchEphemeralKey);
        READWRITE(vchEncCiphertext);
        READWRITE(vchOutCiphertext);
        READWRITE(rangeProof);
    )
};

class CShieldedBindingSig
{
public:
    CBindingSignature bindingSig;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(bindingSig);
    )

    bool IsNull() const { return bindingSig.IsNull(); }
};


class CShieldedNullifierSpent
{
public:
    uint256 txnHash;
    uint32_t nIndex;

    CShieldedNullifierSpent()
    {
        txnHash = 0;
        nIndex = 0;
    }

    CShieldedNullifierSpent(const uint256& txnHashIn, uint32_t nIndexIn)
    {
        txnHash = txnHashIn;
        nIndex = nIndexIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(txnHash);
        READWRITE(nIndex);
    )
};


class CIncrementalMerkleTree
{
public:
    std::vector<uint256> vLeft;
    std::vector<uint256> vRight;
    uint64_t nSize;

    CIncrementalMerkleTree()
    {
        nSize = 0;
        vLeft.resize(SHIELDED_MERKLE_DEPTH);
        vRight.resize(SHIELDED_MERKLE_DEPTH);
    }

    bool Append(const uint256& leaf);

    uint256 Root() const;

    bool GetWitness(uint64_t nPosition, std::vector<uint256>& vPathOut) const;

    uint64_t Size() const { return nSize; }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vLeft);
        READWRITE(vRight);
        READWRITE(nSize);
    )

    static uint256 HashCombine(int nDepth, const uint256& left, const uint256& right);

    static const uint256& EmptyRoot(int nDepth);

private:
    static std::vector<uint256> vEmptyRoots;
    static bool fEmptyRootsInitialized;
    static boost::once_flag emptyRootsOnceFlag;
    static void InitEmptyRoots();
};


class CShieldedMerkleWitness
{
public:
    uint64_t nPosition;
    std::vector<uint256> vPath;
    uint256 root;

    CShieldedMerkleWitness()
    {
        nPosition = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nPosition);
        READWRITE(vPath);
        READWRITE(root);
    )
};


bool GenerateShieldedSpendingKey(CShieldedSpendingKey& skOut);

bool DeriveShieldedFullViewingKey(const CShieldedSpendingKey& sk, CShieldedFullViewingKey& fvkOut);

bool DeriveShieldedIncomingViewingKey(const CShieldedFullViewingKey& fvk, CShieldedIncomingViewingKey& ivkOut);

bool DeriveShieldedPaymentAddress(const CShieldedIncomingViewingKey& ivk,
                                   const std::vector<unsigned char>& vchDiversifier,
                                   CShieldedPaymentAddress& addrOut);

bool GenerateShieldedDiversifier(std::vector<unsigned char>& vchDiversifierOut);

bool EncryptShieldedNote(const CShieldedNote& note,
                         const CShieldedPaymentAddress& addr,
                         std::vector<unsigned char>& vchEphemeralKeyOut,
                         std::vector<unsigned char>& vchEncCiphertextOut);

bool DecryptShieldedNote(const std::vector<unsigned char>& vchEncCiphertext,
                         const std::vector<unsigned char>& vchEphemeralKey,
                         const CShieldedIncomingViewingKey& ivk,
                         CShieldedNote& noteOut);

bool DecryptShieldedNote(const std::vector<unsigned char>& vchEncCiphertext,
                         const std::vector<unsigned char>& vchEphemeralKey,
                         const std::vector<unsigned char>& vchPkD,
                         const CShieldedIncomingViewingKey& ivk,
                         CShieldedNote& noteOut);

bool DecryptShieldedNote(const std::vector<unsigned char>& vchEncCiphertext,
                         const std::vector<unsigned char>& vchEphemeralKey,
                         const std::vector<unsigned char>& vchPkD,
                         const std::vector<unsigned char>& vchDiversifier,
                         const CShieldedIncomingViewingKey& ivk,
                         CShieldedNote& noteOut);

bool EncryptShieldedNoteForSender(const CShieldedNote& note,
                                   const uint256& ovk,
                                   const uint256& cv,
                                   const uint256& cmu,
                                   const std::vector<unsigned char>& vchEphemeralKey,
                                   std::vector<unsigned char>& vchOutCiphertextOut);

extern int64_t nShieldedPoolValue;


class CColdStakeDelegation
{
public:
    std::vector<unsigned char> vchPkStake;
    std::vector<unsigned char> vchPkOwner;
    std::vector<unsigned char> vchSkStakeEnc;
    int64_t nDelegateAmount;
    uint256 hashOwner;
    CShieldedPaymentAddress ownerAddr;
    uint256 ownerOvk;
    std::vector<unsigned char> vchOwnerSig;

    CColdStakeDelegation()
    {
        nDelegateAmount = 0;
    }

    ~CColdStakeDelegation()
    {
        if (!vchSkStakeEnc.empty())
            OPENSSL_cleanse(vchSkStakeEnc.data(), vchSkStakeEnc.size());
        if (!vchOwnerSig.empty())
            OPENSSL_cleanse(vchOwnerSig.data(), vchOwnerSig.size());
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchPkStake);
        READWRITE(vchPkOwner);
        READWRITE(vchSkStakeEnc);
        READWRITE(nDelegateAmount);
        READWRITE(hashOwner);
        READWRITE(ownerAddr);
        READWRITE(ownerOvk);
        READWRITE(vchOwnerSig);
    )

    bool IsNull() const { return vchPkStake.empty(); }

    uint256 GetDelegationHash() const;

    bool VerifyOwnerSignature(const std::vector<unsigned char>& vchOwnerPubKey) const;
};

bool DeriveStakingKey(const uint256& skSpend, uint256& skStakeOut);

bool DeriveStakingPubKey(const uint256& skStake, std::vector<unsigned char>& vchPkStakeOut);


#endif // INN_SHIELDED_H
