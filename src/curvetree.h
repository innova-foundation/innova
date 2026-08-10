// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_CURVETREE_H
#define INN_CURVETREE_H

#include "uint256.h"
#include "serialize.h"
#include "zkproof.h"
#include "v5activation.h"

#include <vector>
#include <stdint.h>

static const int CURVE_TREE_ARITY = 256;
static const int CURVE_TREE_MAX_DEPTH = 8;
static const size_t FCMP_PROOF_MAX_SIZE = 4096;
inline int GetForkHeightFCMP() {
    extern bool fRegTest;
    extern bool fTestNet;
    return (fRegTest || fTestNet) ? 2 : ShiftMainnetV5Activation(7820000);
}
#define FORK_HEIGHT_FCMP (GetForkHeightFCMP())

// The in-tree path proof establishes knowledge of an opening of a point the
// prover supplies, which any invented pair of vectors satisfies. No value is
// ever recomputed from leaf through siblings to the claimed root, so it proves
// no membership in anything and cannot be repaired where it stands: the
// statement carries no witness about a tree. CROSSCURVE is no better -- it
// chains layers by assigning the prover's own commitments, so its root
// comparison compares a value to itself.
//
// Regtest accepted it until now, which made every membership test there
// vacuous. No network accepts it at any height. Membership comes from the
// vNext verifier, over the tree it actually proves against.
inline bool IsLegacyFCMPProofAccepted() {
    return false;
}

static const size_t SECP256K1_POINT_SIZE = 33;
static const size_t ED25519_POINT_SIZE = 32;
static const size_t ED25519_SCALAR_SIZE = 32;


enum ECurveType
{
    CURVE_SECP256K1 = 0,
    CURVE_ED25519   = 1
};


class CCurveTreeNode
{
public:
    ECurveType curveType;
    std::vector<unsigned char> vchPoint;
    int nDepth;
    uint64_t nIndex;

    CCurveTreeNode()
    {
        curveType = CURVE_SECP256K1;
        nDepth = 0;
        nIndex = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchPoint);
        READWRITE(nDepth);
        READWRITE(nIndex);
    )

    void UpdateCurveType()
    {
        curveType = GetCurveAtDepth(nDepth);
    }

    bool IsNull() const
    {
        return vchPoint.empty();
    }

    uint256 GetHash() const;

    static ECurveType GetCurveAtDepth(int nDepth)
    {
        return (nDepth % 2 == 0) ? CURVE_SECP256K1 : CURVE_ED25519;
    }

    static size_t GetPointSizeAtDepth(int nDepth)
    {
        return (GetCurveAtDepth(nDepth) == CURVE_SECP256K1)
            ? SECP256K1_POINT_SIZE
            : ED25519_POINT_SIZE;
    }

    bool operator==(const CCurveTreeNode& other) const
    {
        return curveType == other.curveType &&
               vchPoint == other.vchPoint &&
               nDepth == other.nDepth &&
               nIndex == other.nIndex;
    }
};


static const uint32_t FCMP_PROOF_VERSION_LEGACY = 2;
static const uint32_t FCMP_PROOF_VERSION_BLINDED = 3;
static const uint32_t FCMP_PROOF_VERSION_ENCRYPTED = 4;
static const uint32_t FCMP_PROOF_VERSION_IPA = 5;
static const uint32_t FCMP_PROOF_VERSION_CROSSCURVE = 6;

// CURRENT is the creation default, not a recommendation: IPA binds neither the
// claimed root nor the leaf commitment, which is why the verifier confines it to
// regtest. CROSSCURVE does bind both, but VerifyFCMPProofUncached rejects any
// version above IPA and its serialized entry points have no callers, so moving
// CURRENT there would make creation produce proofs consensus rejects. Both are
// the 2002 prototype, superseded by vendored FCMP++ under 2008; the fix is
// retiring that envelope, not renumbering this.
static const uint32_t FCMP_PROOF_VERSION_CURRENT = FCMP_PROOF_VERSION_IPA;


class CFCMPProof
{
public:
    std::vector<unsigned char> vchProof;
    uint64_t nLeafIndex;                          // prover-side only
    CPedersenCommitment leafCommitment;            // prover-side only

    CFCMPProof()
    {
        nLeafIndex = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        CFCMPProof* pthis = const_cast<CFCMPProof*>(this);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchProof,
                                                 FCMP_PROOF_MAX_SIZE,
                                                 nType, nVersion, ser_action);
    )

    bool IsNull() const
    {
        return vchProof.empty();
    }

    size_t GetSize() const
    {
        return vchProof.size();
    }

    uint32_t GetVersion() const
    {
        if (vchProof.size() < 4)
            return 0;
        uint32_t nVersion;
        memcpy(&nVersion, vchProof.data(), 4);
        return nVersion;
    }

    bool IsEncrypted() const
    {
        return GetVersion() >= FCMP_PROOF_VERSION_ENCRYPTED;
    }

    bool IsIPABased() const
    {
        return GetVersion() >= FCMP_PROOF_VERSION_IPA;
    }

    bool IsCrossCurve() const
    {
        return GetVersion() >= FCMP_PROOF_VERSION_CROSSCURVE;
    }
};


class CCurveTree
{
public:
    uint64_t nLeafCount;
    std::vector<std::vector<CCurveTreeNode>> vLevels;

    CCurveTree()
    {
        nLeafCount = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nLeafCount);
        READWRITE(vLevels);
    )

    uint256 GetRoot() const;

    CCurveTreeNode GetRootNode() const;

    bool InsertLeaf(const CPedersenCommitment& commitment);

    bool GetMembershipProof(uint64_t nLeafIndex, CFCMPProof& proofOut) const;

    static int GetTreeDepth(uint64_t nLeaves);

    static ECurveType GetCurveAtDepth(int nDepth)
    {
        return CCurveTreeNode::GetCurveAtDepth(nDepth);
    }

    bool IsEmpty() const
    {
        return nLeafCount == 0;
    }

    bool RebuildParentNodes();

    int64_t FindLeafIndex(const CPedersenCommitment& cv) const;
};


bool CreateFCMPProof(const CCurveTree& tree,
                      uint64_t nLeafIndex,
                      const std::vector<unsigned char>& vchBlind,
                      const int64_t nValue,
                      const CPedersenCommitment& cv,
                      CFCMPProof& proofOut,
                      uint32_t nVersion = FCMP_PROOF_VERSION_CURRENT);

// nEvalHeight is the height whose rules this proof is judged under: the
// containing block's height, or tip+1 for a mempool check. Not defaulted, so a
// missing height is a compile error rather than an unbound cache key.
bool VerifyFCMPProof(const CCurveTreeNode& root,
                      const CFCMPProof& proof,
                      const CPedersenCommitment& cv,
                      int nEvalHeight);

bool BatchVerifyFCMPProofs(const CCurveTreeNode& root,
                            const std::vector<CFCMPProof>& vProofs,
                            const std::vector<CPedersenCommitment>& vCommitments,
                            int nEvalHeight);


CCurveTreeNode HashCurveTreeChildren(int nDepth,
                                      const std::vector<CCurveTreeNode>& vChildren);


bool Ed25519PointFromBytes(const std::vector<unsigned char>& vch,
                            std::vector<unsigned char>& pointOut,
                            bool fRejectTorsion = true);

bool Ed25519PointToBytes(const std::vector<unsigned char>& point,
                          std::vector<unsigned char>& vchOut);

bool Ed25519PointAdd(const std::vector<unsigned char>& vchA,
                      const std::vector<unsigned char>& vchB,
                      std::vector<unsigned char>& vchResultOut);

bool Ed25519ScalarMult(const std::vector<unsigned char>& vchScalar,
                        const std::vector<unsigned char>& vchPoint,
                        std::vector<unsigned char>& vchResultOut);


#endif // INN_CURVETREE_H
