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
static const size_t IPA_ED25519_POINT = 32;
static const size_t IPA_MAX_VECTOR_LEN = 256;

static const uint32_t PATH_IPA_VERSION = 1;


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
        READWRITE(nRounds);
        if (fRead)
        {
            pthis->vL.resize(nRounds);
            pthis->vR.resize(nRounds);
        }
        for (uint32_t i = 0; i < nRounds; i++)
        {
            READWRITE(pthis->vL[i]);
            READWRITE(pthis->vR[i]);
        }
        READWRITE(pthis->vchAFinal);
        READWRITE(pthis->vchBFinal);
        int nCurve = (int)curveType;
        READWRITE(nCurve);
        if (fRead)
            pthis->curveType = (EIPACurveType)nCurve;
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
        return 1 << GetNumRounds();
    }

    size_t GetProofSize() const
    {
        size_t ptSize = (curveType == IPA_CURVE_SECP256K1)
            ? IPA_SECP256K1_POINT : IPA_ED25519_POINT;
        return vL.size() * ptSize * 2  // L and R points
             + IPA_SCALAR_SIZE * 2;     // a_final and b_final
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
        READWRITE(pthis->vchPositionCommit);
        READWRITE(pthis->vchPathCommit);
        READWRITE(pthis->vchInnerProduct);
        READWRITE(pthis->vchSiblingCommit);
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
            pthis->curveType = (EIPACurveType)nCurve;
        READWRITE(pthis->vchCommitment);
        READWRITE(pthis->vchReRandomizer);
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
        READWRITE(pthis->vchLeafCommit);
        READWRITE(pthis->vchRootCommit);

        uint32_t nLayers = pthis->vLayerProofs.size();
        READWRITE(nLayers);
        if (fRead)
            pthis->vLayerProofs.resize(nLayers);
        for (uint32_t i = 0; i < nLayers; i++)
            READWRITE(pthis->vLayerProofs[i]);

        READWRITE(pthis->vchBindingProof);
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
