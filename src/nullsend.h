// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_NULLSEND_H
#define INN_NULLSEND_H

#include "main.h"
#include "shielded.h"
#include "zkproof.h"

#include <vector>
#include <map>
#include <set>
#include <string>

#include <openssl/crypto.h>
#include <openssl/bn.h>

static const int NULLSEND_MIN_PARTICIPANTS = 2;
static const int NULLSEND_MAX_PARTICIPANTS = 16;
static const int NULLSEND_RSA_BITS = 2048;


/** Whether a round key has a shape honest key generation could have produced.
 *  A participant cannot prove N is a two-prime product without factoring it; this
 *  refuses the shapes that stop the blind signature being a permutation of Z_N*. */
bool IsMixRoundKeyWellFormed(const std::vector<unsigned char>& vchRSA_N,
                             const std::vector<unsigned char>& vchRSA_E);

/** Whether an RSA full-domain-hash blind signature over vchCredential verifies
 *  under the key (N, E). Shared by the legacy session and the v2008 round. */
bool VerifyMixCredential(const std::vector<unsigned char>& vchRSA_N,
                         const std::vector<unsigned char>& vchRSA_E,
                         const std::vector<unsigned char>& vchCredential,
                         const std::vector<unsigned char>& vchSignature);

/** A round's blind-signing RSA key. */
class CNullSendSession
{
public:
    int nSessionID;
    std::vector<unsigned char> vchRSA_N;
    std::vector<unsigned char> vchRSA_E;
    std::vector<unsigned char> vchRSA_D;

    CNullSendSession() : nSessionID(0) {}

    ~CNullSendSession()
    {
        if (!vchRSA_D.empty())
            OPENSSL_cleanse(vchRSA_D.data(), vchRSA_D.size());
    }

    bool GenerateSessionRSAKey();
    bool BlindSign(const std::vector<unsigned char>& vchBlinded,
                   std::vector<unsigned char>& vchSignatureOut);
    bool VerifyCredential(const std::vector<unsigned char>& vchCredential,
                          const std::vector<unsigned char>& vchSignature);
};

/** The participant side of the blind credential. */
class CNullSendClient
{
public:
    std::vector<unsigned char> vchBlindingFactor;
    std::vector<unsigned char> vchCredentialHash;
    std::vector<unsigned char> vchBlindedCredential;
    std::vector<unsigned char> vchUnblindedSig;
    std::vector<unsigned char> vchSessionRSA_N;
    std::vector<unsigned char> vchSessionRSA_E;
    std::vector<CShieldedOutputDescription> vMyOutputsDeferred;
    int64_t nMyOutputValue;

    CNullSendClient()
    {
        nMyOutputValue = 0;
        Reset();
    }

    ~CNullSendClient()
    {
        if (!vchBlindingFactor.empty())
            OPENSSL_cleanse(vchBlindingFactor.data(), vchBlindingFactor.size());
    }

    bool BlindOutputCredential(const std::vector<unsigned char>& vchRSA_N,
                               const std::vector<unsigned char>& vchRSA_E);
    bool BlindCredentialMessage(const std::vector<unsigned char>& vchRSA_N,
                                const std::vector<unsigned char>& vchRSA_E,
                                const uint256& hashMessage);
    bool UnblindSignature(const std::vector<unsigned char>& vchBlindSig);

    void Reset();
};

#endif // INN_NULLSEND_H
