// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_NYXPO_H
#define INNOVA_NYXPO_H

#include <stddef.h>
#include <stdint.h>

#include <list>
#include <map>
#include <string>
#include <vector>

static const uint8_t  NYX_PO_BUNDLE  = 0x02;
static const uint8_t  NYX_PO_CERT    = 0x03;
static const uint8_t  NYX_PO_KEYRING = 0x04;

static const uint64_t NYX_PO_NODE_CAP     = 64ULL << 20;
static const int64_t  NYX_PO_KEEP         = 60 * 60 * 24 * 30;
static const size_t   NYX_PO_CACHE_SIZE   = 4096;
static const uint32_t NYX_PO_MAX_OBJECTS  = 64;
static const uint32_t NYX_PO_MAX_MSG      = 1 << 20;
static const uint32_t NYX_PO_GETS_PER_MIN = 20;

static const unsigned int NYX_MLDSA_PK  = 1952;
static const unsigned int NYX_MLDSA_SIG = 3309;
static const unsigned int NYX_MLKEM_EK  = 1184;
static const unsigned int NYX_ECDSA_SIG = 65;
static const int64_t NYX_CERT_MAX_LIFE  = 60 * 60 * 24 * 90;

bool NyxPoIsPublicType(uint8_t t);

struct NyxPoInfo
{
    uint8_t type;
    uint8_t addrHash[20];
    uint8_t deviceId[16];   // zero for a keyring
    uint32_t epoch;
    uint32_t seq;
    uint64_t ts;
};

/** Field and length checks for a reassembled public body; 0 ok, >0 reason. */
int NyxPoParse(const uint8_t* p, size_t n, NyxPoInfo& out);

enum NyxPoVerifyResult
{
    NYX_PO_UNVERIFIED = 0,
    NYX_PO_OK = 1,
    NYX_PO_BAD = 2,
};

typedef int (*NyxPoVerifyFn)(const std::vector<uint8_t>& body);

/** Signature check; stubbed to UNVERIFIED until the identity increment. Results are cached by SHA256(body). */
int NyxPoVerify(const std::vector<uint8_t>& body);
void NyxPoSetVerifyHook(NyxPoVerifyFn fn);
void NyxPoClearCache();
size_t NyxPoCacheSize();

/** Latest public objects per (addrHash, kind, deviceId), as the raw SMSG parts that carried them. */
class NyxPoStore
{
public:
    explicit NyxPoStore(uint64_t nCap = NYX_PO_NODE_CAP, int64_t nKeep = NYX_PO_KEEP) : nCap(nCap), nKeep(nKeep), nBytes(0) {}

    static std::string Key(const NyxPoInfo& info);

    struct Record
    {
        NyxPoInfo info;
        int64_t nLastSeen;
        std::vector<std::vector<uint8_t> > vParts;
        uint64_t Bytes() const;
    };

    /** Returns false when an equal or newer record is already held. */
    bool Put(const NyxPoInfo& info, const std::vector<std::vector<uint8_t> >& vParts, int64_t nNow);
    void Get(const uint8_t addrHash[20], std::vector<const Record*>& out) const;
    void Expire(int64_t nNow);
    void Load(const std::string& key, const Record& rec);
    void All(std::vector<std::pair<std::string, const Record*> >& out) const;

    size_t Count() const { return records.size(); }
    uint64_t Bytes() const { return nBytes; }

    /** Keys removed since the last call, for the caller's persistent copy. */
    std::vector<std::string> TakeErased();

private:
    void Erase(std::map<std::string, Record>::iterator it);
    void Enforce();

    uint64_t nCap;
    int64_t nKeep;
    uint64_t nBytes;
    std::map<std::string, Record> records;
    std::vector<std::string> vErased;
};

#endif // INNOVA_NYXPO_H
