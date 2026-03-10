// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_SILENTPAYMENTS_H
#define INN_SILENTPAYMENTS_H

#include "uint256.h"
#include "serialize.h"
#include "key.h"

#include <vector>
#include <stdint.h>
#include <openssl/crypto.h>

static const int SILENT_PAYMENT_VERSION = 1;
static const size_t SILENT_PAYMENT_ADDRESS_SIZE = 66;


class CSilentPaymentAddress
{
public:
    std::vector<unsigned char> vchScanPubKey;
    std::vector<unsigned char> vchSpendPubKey;

    CSilentPaymentAddress()
    {
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchScanPubKey);
        READWRITE(vchSpendPubKey);
    )

    bool IsNull() const
    {
        return vchScanPubKey.empty() || vchSpendPubKey.empty();
    }

    bool operator==(const CSilentPaymentAddress& other) const
    {
        return vchScanPubKey == other.vchScanPubKey &&
               vchSpendPubKey == other.vchSpendPubKey;
    }

    bool operator<(const CSilentPaymentAddress& other) const
    {
        if (vchScanPubKey != other.vchScanPubKey)
            return vchScanPubKey < other.vchScanPubKey;
        return vchSpendPubKey < other.vchSpendPubKey;
    }

    std::string ToString() const;

    bool FromString(const std::string& str);
};


class CSilentPaymentKey
{
public:
    CSecret skScan;
    CSecret skSpend;

    CSilentPaymentKey()
    {
    }

    ~CSilentPaymentKey()
    {
        if (!skScan.empty())
            OPENSSL_cleanse(&skScan[0], skScan.size());
        if (!skSpend.empty())
            OPENSSL_cleanse(&skSpend[0], skSpend.size());
    }

    CSilentPaymentKey(const CSilentPaymentKey&) = delete;
    CSilentPaymentKey& operator=(const CSilentPaymentKey&) = delete;

    CSilentPaymentKey(CSilentPaymentKey&& other) noexcept
        : skScan(std::move(other.skScan)), skSpend(std::move(other.skSpend))
    {
    }

    CSilentPaymentKey& operator=(CSilentPaymentKey&& other) noexcept
    {
        if (this != &other)
        {
            if (!skScan.empty()) OPENSSL_cleanse(&skScan[0], skScan.size());
            if (!skSpend.empty()) OPENSSL_cleanse(&skSpend[0], skSpend.size());
            skScan = std::move(other.skScan);
            skSpend = std::move(other.skSpend);
        }
        return *this;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(skScan);
        READWRITE(skSpend);
    )

    bool IsNull() const
    {
        return skScan.empty() || skSpend.empty();
    }

    bool GetAddress(CSilentPaymentAddress& addrOut) const;

    static bool Generate(CSilentPaymentKey& keyOut);
};


class CSilentPaymentOutput
{
public:
    std::vector<unsigned char> vchOutputPubKey;
    uint32_t nOutputIndex;

    CSilentPaymentOutput()
    {
        nOutputIndex = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchOutputPubKey);
        READWRITE(nOutputIndex);
    )
};


bool DeriveSilentPaymentOutput(const std::vector<unsigned char>& vchSenderSecretSum,
                                const CSilentPaymentAddress& addr,
                                uint32_t nOutputIndex,
                                std::vector<unsigned char>& vchOutputPubKeyOut);

bool DeriveSilentPaymentSpendKey(const CSilentPaymentKey& key,
                                  const std::vector<unsigned char>& vchSenderPubKeySum,
                                  uint32_t nOutputIndex,
                                  std::vector<unsigned char>& vchPrivKeyOut);

bool ScanForSilentPayments(const CSilentPaymentKey& key,
                            const std::vector<unsigned char>& vchSenderPubKeySum,
                            const std::vector<std::vector<unsigned char>>& vTxOutputPubKeys,
                            std::vector<uint32_t>& vMatchedOut);

bool ComputeInputPubKeySum(const std::vector<std::vector<unsigned char>>& vInputPubKeys,
                            std::vector<unsigned char>& vchSumOut);

bool ComputeInputPrivKeySum(const std::vector<std::vector<unsigned char>>& vInputPrivKeys,
                             std::vector<unsigned char>& vchSumOut);


bool DeriveSilentShieldedAddress(const std::vector<unsigned char>& vchOutputPubKey,
                                  std::vector<unsigned char>& vchDiversifierOut,
                                  std::vector<unsigned char>& vchPkDOut);


#endif // INN_SILENTPAYMENTS_H
