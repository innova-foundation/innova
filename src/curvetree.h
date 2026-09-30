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
    return (fRegTest || fTestNet) ? 2 : ShiftMainnetV5Activation(7800120);
}
#define FORK_HEIGHT_FCMP (GetForkHeightFCMP())

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
