// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_NYXPARTS_H
#define INNOVA_NYXPARTS_H

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

static const unsigned int NYX_FRAME_PREFIX  = 55;
static const unsigned int NYX_PART_BODY_MAX = 4224;
static const unsigned int NYX_MAX_PARTS     = 64;
static const unsigned int NYX_MAX_BODY      = 270336;
static const uint8_t      NYX_V2TYPE_PART   = 1;

static const uint64_t NYX_PRIV_BUF_ADDR    = 4ULL << 20;
static const uint64_t NYX_PRIV_BUF_NODE    = 32ULL << 20;
static const uint32_t NYX_PRIV_SETS_ADDR   = 64;
static const int64_t  NYX_PRIV_SET_TIMEOUT = 60 * 60 * 48;
static const uint64_t NYX_PUB_BUF_PEER     = 1ULL << 20;
static const uint64_t NYX_PUB_BUF_NODE     = 16ULL << 20;
static const uint32_t NYX_PUB_SETS_PEER    = 32;
static const int64_t  NYX_PUB_SET_TIMEOUT  = 600;

struct NyxFrame
{
    uint8_t msgid[16];
    uint8_t partIdx;
    uint8_t partCount;
    uint32_t totalLen;
    uint8_t totalHash[32];
    const uint8_t* pBody;
    uint32_t nBody;
};

enum NyxFrameError
{
    NYX_FRAME_OK = 0,
    NYX_FRAME_SHORT,
    NYX_FRAME_TYPE,
    NYX_FRAME_COUNT,
    NYX_FRAME_INDEX,
    NYX_FRAME_TOTAL,
    NYX_FRAME_LENGTH,
};

void NyxSha256(const uint8_t* p, size_t n, uint8_t out[32]);

/** Length of part idx of a body of totalLen bytes split into count parts. */
uint32_t NyxPartLen(uint32_t totalLen, uint8_t count, uint8_t idx);

bool NyxSplit(const std::vector<uint8_t>& body, std::vector<std::vector<uint8_t> >& frames, const uint8_t msgid[16],
              unsigned int nMaxParts = NYX_MAX_PARTS);
int NyxParseFrame(const uint8_t* p, size_t n, NyxFrame& out);

enum NyxPoolKind
{
    NYX_POOL_PRIVATE,
    NYX_POOL_PUBLIC,
};

struct NyxReassemblyLimits
{
    uint64_t nOwnerBytes;
    uint64_t nNodeBytes;
    uint32_t nOwnerSets;
    int64_t nTimeout;
    static NyxReassemblyLimits For(NyxPoolKind kind);
};

enum NyxAddResult
{
    NYX_RA_STORED,
    NYX_RA_DUPLICATE,
    NYX_RA_COMPLETE,
    NYX_RA_MISMATCH,    // part disagrees with its set; set dropped
    NYX_RA_BADHASH,     // reassembled body does not match totalHash; set dropped
    NYX_RA_REFUSED,     // could not be held within the caps
};

struct NyxSetProgress
{
    std::string owner;
    std::string msgid;
    unsigned int nHave;
    unsigned int nCount;
    int64_t nFirstSeen;
};

/** Multipart buffer charged per owner (local address or delivering peer). Deterministic: time is passed in. */
class NyxReassembler
{
public:
    explicit NyxReassembler(NyxPoolKind kind) : limits(NyxReassemblyLimits::For(kind)), nNodeBytes(0), nSeq(0) {}
    explicit NyxReassembler(const NyxReassemblyLimits& l) : limits(l), nNodeBytes(0), nSeq(0) {}

    /** pRaw, when given, is kept with the part and returned in vRawOut on completion. */
    NyxAddResult Add(const std::string& owner, const NyxFrame& f, int64_t nNow, std::vector<uint8_t>& bodyOut,
                     const std::vector<uint8_t>* pRaw = NULL, std::vector<std::vector<uint8_t> >* vRawOut = NULL);
    void Expire(int64_t nNow);
    void FreeOwner(const std::string& owner);
    void Clear();

    uint64_t NodeBytes() const { return nNodeBytes; }
    uint64_t OwnerBytes(const std::string& owner) const;
    size_t SetCount() const { return sets.size(); }
    size_t OwnerSetCount(const std::string& owner) const;
    void List(std::vector<NyxSetProgress>& out) const;
    const NyxReassemblyLimits& Limits() const { return limits; }

private:
    typedef std::pair<std::string, std::string> Key;
    struct Set
    {
        uint8_t nCount;
        uint32_t totalLen;
        uint8_t totalHash[32];
        int64_t nFirstSeen;
        uint64_t nSeq;
        uint64_t nBytes;
        std::map<uint8_t, std::vector<uint8_t> > parts;
        std::map<uint8_t, std::vector<uint8_t> > raws;
    };

    void Drop(std::map<Key, Set>::iterator it);
    bool EvictOldest(const std::string* pOwner, const Key& keep);

    NyxReassemblyLimits limits;
    std::map<Key, Set> sets;
    std::map<std::string, uint64_t> ownerBytes;
    std::map<std::string, uint32_t> ownerSets;
    uint64_t nNodeBytes;
    uint64_t nSeq;
};

#endif // INNOVA_NYXPARTS_H
