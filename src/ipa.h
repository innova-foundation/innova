// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_IPA_H
#define INN_IPA_H

#include "uint256.h"
#include "serialize.h"

#include <vector>
#include <stdint.h>


static const size_t IPA_SCALAR_SIZE = 32;
static const size_t IPA_SECP256K1_POINT = 33;
static const size_t IPA_SECP256K1_POINT_UNCOMPRESSED = 65;
static const size_t IPA_ED25519_POINT = 32;
static const size_t IPA_MAX_VECTOR_LEN = 2048;
static const uint32_t IPA_MAX_ROUNDS = 11; // log2(IPA_MAX_VECTOR_LEN)

static const uint32_t PATH_IPA_VERSION = 1;
static const int PATH_IPA_MAX_DEPTH = 64;
// Active FCMP v5 already caps the complete envelope at 4 KiB.  Use the same
// bound for its historically opaque/ignored inner blobs so a bogus CompactSize
// cannot allocate the generic 5 MiB limit without narrowing accepted v5 bytes.
static const size_t PATH_IPA_LEGACY_BLOB_MAX_SIZE = 4096;
static const uint32_t CROSSCURVE_MAX_DEPTH = 8;


enum EIPACurveType
{
    IPA_CURVE_SECP256K1 = 0,
    IPA_CURVE_ED25519 = 1
};



class CIPAProof
{
public:
    std::vector<std::vector<unsigned char>> vL;
    std::vector<std::vector<unsigned char>> vR;
    std::vector<unsigned char> vchAFinal;
    std::vector<unsigned char> vchBFinal;

    EIPACurveType curveType;

    CIPAProof()
    {
        curveType = IPA_CURVE_SECP256K1;
    }

    IMPLEMENT_SERIALIZE
    (
        CIPAProof* pthis = const_cast<CIPAProof*>(this);
        uint32_t nRounds = vL.size();
        if (!fRead && (vL.size() != vR.size() || vL.size() > IPA_MAX_ROUNDS))
            throw std::ios_base::failure("invalid IPA proof round vectors");
        READWRITE(nRounds);
        if (fRead)
        {
            if (nRounds > IPA_MAX_ROUNDS)
                throw std::ios_base::failure("IPA proof round count too large");
            pthis->vL.resize(nRounds);
            pthis->vR.resize(nRounds);
        }
        for (uint32_t i = 0; i < nRounds; i++)
        {
            nSerSize += ::SerReadWriteLimitedVector(s, pthis->vL[i],
                                                     IPA_SECP256K1_POINT,
                                                     nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(s, pthis->vR[i],
                                                     IPA_SECP256K1_POINT,
                                                     nType, nVersion, ser_action);
        }
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchAFinal,
                                                 IPA_SCALAR_SIZE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchBFinal,
                                                 IPA_SCALAR_SIZE,
                                                 nType, nVersion, ser_action);
        int nCurve = (int)curveType;
        READWRITE(nCurve);
        if (fRead)
        {
            if (nCurve != (int)IPA_CURVE_SECP256K1 &&
                nCurve != (int)IPA_CURVE_ED25519)
                throw std::ios_base::failure("invalid IPA proof curve type");
            pthis->curveType = (EIPACurveType)nCurve;
        }
    )

    bool IsNull() const
    {
        return vchAFinal.empty();
    }

    int GetNumRounds() const
    {
        return (int)vL.size();
    }

    int GetVectorLength() const
    {
        const int nRounds = GetNumRounds();
        if (nRounds < 0 || nRounds > (int)IPA_MAX_ROUNDS)
            return 0;
        return 1 << nRounds;
    }

    size_t GetProofSize() const
    {
        size_t nSize = vchAFinal.size() + vchBFinal.size();
        for (size_t i = 0; i < vL.size(); ++i)
            nSize += vL[i].size();
        for (size_t i = 0; i < vR.size(); ++i)
            nSize += vR[i].size();
        return nSize;
    }
};



class CIPAGenerators
{
public:
    std::vector<std::vector<unsigned char>> vG;
    std::vector<std::vector<unsigned char>> vH;
    std::vector<unsigned char> vchU;
    EIPACurveType curveType;
    int nLength;

    CIPAGenerators()
    {
        curveType = IPA_CURVE_SECP256K1;
        nLength = 0;
    }

    bool IsNull() const
    {
        return vG.empty() || vchU.empty();
    }
};



class CIPATranscript
{
public:
    std::vector<unsigned char> vchData;
    std::string strDomain;

    CIPATranscript(const std::string& domain = "Innova_IPA_v1")
    {
        strDomain = domain;
        vchData.insert(vchData.end(), domain.begin(), domain.end());
    }

    void AppendScalar(const std::vector<unsigned char>& scalar);

    void AppendPoint(const std::vector<unsigned char>& point);

    void AppendBytes(const unsigned char* data, size_t len);

    bool GetChallenge(std::vector<unsigned char>& challengeOut,
                      EIPACurveType curveType) const;

    bool GetChallengeAndUpdate(std::vector<unsigned char>& challengeOut,
                               EIPACurveType curveType);
};



bool GenerateIPAGenerators(const std::string& domain,
                           int n,
                           EIPACurveType curveType,
                           CIPAGenerators& gensOut);

bool CreateIPAProof(const std::vector<std::vector<unsigned char>>& a,
                    const std::vector<std::vector<unsigned char>>& b,
                    const std::vector<unsigned char>& z,
                    const CIPAGenerators& gens,
                    CIPATranscript& transcript,
                    CIPAProof& proofOut);

bool VerifyIPAProof(const std::vector<unsigned char>& P,
                    const std::vector<unsigned char>& z,
                    const CIPAGenerators& gens,
                    CIPATranscript& transcript,
                    const CIPAProof& proof);

bool IsCanonicalIPAScalar(const std::vector<unsigned char>& scalar,
                          EIPACurveType curveType);



bool IPAInnerProduct(const std::vector<std::vector<unsigned char>>& a,
                     const std::vector<std::vector<unsigned char>>& b,
                     std::vector<unsigned char>& resultOut,
                     EIPACurveType curveType);

bool IPAScalarMul(const std::vector<unsigned char>& scalar,
                  const std::vector<unsigned char>& point,
                  std::vector<unsigned char>& resultOut,
                  EIPACurveType curveType);

bool IPAPointAdd(const std::vector<unsigned char>& a,
                 const std::vector<unsigned char>& b,
                 std::vector<unsigned char>& resultOut,
                 EIPACurveType curveType);

bool IPAScalarAdd(const std::vector<unsigned char>& a,
                  const std::vector<unsigned char>& b,
                  std::vector<unsigned char>& resultOut,
                  EIPACurveType curveType);

bool IPAScalarMulScalar(const std::vector<unsigned char>& a,
                        const std::vector<unsigned char>& b,
                        std::vector<unsigned char>& resultOut,
                        EIPACurveType curveType);

bool IPAScalarInv(const std::vector<unsigned char>& a,
                  std::vector<unsigned char>& resultOut,
                  EIPACurveType curveType);



class CPathIPAProof
{
public:
    uint32_t nVersion;
    int nDepth;
    std::vector<unsigned char> vchPositionCommit;
    std::vector<unsigned char> vchPathCommit;
    std::vector<unsigned char> vchInnerProduct;
    std::vector<unsigned char> vchSiblingCommit;
    CIPAProof ipaProof;

    CPathIPAProof()
    {
        nVersion = PATH_IPA_VERSION;
        nDepth = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        CPathIPAProof* pthis = const_cast<CPathIPAProof*>(this);
        READWRITE(pthis->nVersion);
        READWRITE(pthis->nDepth);
        if (fRead && (pthis->nDepth <= 0 || pthis->nDepth > PATH_IPA_MAX_DEPTH))
            throw std::ios_base::failure("Path IPA depth out of range");
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchPositionCommit,
                                                 PATH_IPA_LEGACY_BLOB_MAX_SIZE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchPathCommit,
                                                 IPA_SECP256K1_POINT_UNCOMPRESSED,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchInnerProduct,
                                                 PATH_IPA_LEGACY_BLOB_MAX_SIZE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchSiblingCommit,
                                                 PATH_IPA_LEGACY_BLOB_MAX_SIZE,
                                                 nType, nVersion, ser_action);
        READWRITE(pthis->ipaProof);
    )

    bool IsNull() const
    {
        return ipaProof.IsNull() || vchPositionCommit.empty();
    }

    bool IsV5() const
    {
        return nVersion == PATH_IPA_VERSION;
    }
};

bool CreatePathIPAProof(const std::vector<std::vector<unsigned char>>& vSiblings,
                        uint64_t nPosition,
                        int nDepth,
                        const std::vector<unsigned char>& vchBlind,
                        CPathIPAProof& proofOut);

bool VerifyPathIPAProof(const std::vector<unsigned char>& vchRoot,
                        const std::vector<unsigned char>& vchLeafCommit,
                        const CPathIPAProof& proof);



bool CreateFCMPProofV5(const std::vector<std::vector<unsigned char>>& vSiblings,
                        uint64_t nLeafIndex,
                        int nDepth,
                        const std::vector<unsigned char>& vchBlind,
                        const std::vector<unsigned char>& vchLeafCommit,
                        std::vector<unsigned char>& proofOut);

bool VerifyFCMPProofV5(const std::vector<unsigned char>& vchRoot,
                        const std::vector<unsigned char>& vchLeafCommit,
                        const std::vector<unsigned char>& proof);




static const uint32_t CROSSCURVE_PROOF_VERSION = 1;

class CCrossCurveLayerProof
{
public:
    EIPACurveType curveType;
    std::vector<unsigned char> vchCommitment;
    std::vector<unsigned char> vchReRandomizer;
    CIPAProof ipaProof;

    CCrossCurveLayerProof()
    {
        curveType = IPA_CURVE_SECP256K1;
    }

    IMPLEMENT_SERIALIZE
    (
        CCrossCurveLayerProof* pthis = const_cast<CCrossCurveLayerProof*>(this);
        int nCurve = (int)curveType;
        READWRITE(nCurve);
        if (fRead)
        {
            if (nCurve != (int)IPA_CURVE_SECP256K1 &&
                nCurve != (int)IPA_CURVE_ED25519)
                throw std::ios_base::failure("invalid cross-curve layer type");
            pthis->curveType = (EIPACurveType)nCurve;
        }
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchCommitment,
                                                 IPA_SECP256K1_POINT,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchReRandomizer,
                                                 IPA_SCALAR_SIZE,
                                                 nType, nVersion, ser_action);
        READWRITE(pthis->ipaProof);
    )

    bool IsNull() const
    {
        return vchCommitment.empty();
    }
};

class CCrossCurveFCMPProof
{
public:
    uint32_t nVersion;
    uint32_t nTreeDepth;
    std::vector<unsigned char> vchLeafCommit;
    std::vector<unsigned char> vchRootCommit;
    std::vector<CCrossCurveLayerProof> vLayerProofs;
    std::vector<unsigned char> vchBindingProof;

    CCrossCurveFCMPProof()
    {
        nVersion = CROSSCURVE_PROOF_VERSION;
        nTreeDepth = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        CCrossCurveFCMPProof* pthis = const_cast<CCrossCurveFCMPProof*>(this);
        READWRITE(pthis->nVersion);
        READWRITE(pthis->nTreeDepth);
        if (fRead && (pthis->nTreeDepth == 0 ||
                      pthis->nTreeDepth > CROSSCURVE_MAX_DEPTH))
            throw std::ios_base::failure("cross-curve tree depth out of range");
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchLeafCommit, 32,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchRootCommit,
                                                 IPA_SECP256K1_POINT,
                                                 nType, nVersion, ser_action);

        uint32_t nLayers = pthis->vLayerProofs.size();
        if (!fRead && nLayers > CROSSCURVE_MAX_DEPTH)
            throw std::ios_base::failure("too many cross-curve proof layers");
        READWRITE(nLayers);
        if (fRead)
        {
            if (nLayers > CROSSCURVE_MAX_DEPTH || nLayers != pthis->nTreeDepth)
                throw std::ios_base::failure("cross-curve proof layer count mismatch");
            pthis->vLayerProofs.resize(nLayers);
        }
        for (uint32_t i = 0; i < nLayers; i++)
            READWRITE(pthis->vLayerProofs[i]);

        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchBindingProof, 32,
                                                 nType, nVersion, ser_action);
    )

    bool IsNull() const
    {
        return vLayerProofs.empty() || vchLeafCommit.empty();
    }

    size_t GetProofSize() const;

    EIPACurveType GetLayerCurve(int nLayer) const
    {
        return (nLayer % 2 == 0) ? IPA_CURVE_SECP256K1 : IPA_CURVE_ED25519;
    }
};



bool CreateFCMPProofV6(const std::vector<std::vector<unsigned char>>& vSiblings,
                        uint64_t nLeafIndex,
                        int nDepth,
                        const std::vector<unsigned char>& vchBlind,
                        const std::vector<unsigned char>& vchLeafData,
                        CCrossCurveFCMPProof& proofOut);

bool VerifyFCMPProofV6(const std::vector<unsigned char>& vchExpectedRoot,
                        const CCrossCurveFCMPProof& proof);

bool CreateFCMPProofV6Serialized(const std::vector<std::vector<unsigned char>>& vSiblings,
                                  uint64_t nLeafIndex,
                                  int nDepth,
                                  const std::vector<unsigned char>& vchBlind,
                                  const std::vector<unsigned char>& vchLeafData,
                                  std::vector<unsigned char>& proofOut);

bool VerifyFCMPProofV6Serialized(const std::vector<unsigned char>& vchExpectedRoot,
                                  const std::vector<unsigned char>& proof);


#endif // INN_IPA_H
