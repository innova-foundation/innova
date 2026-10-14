// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_DAGHEADERS_H
#define INNOVA_DAGHEADERS_H

#include "main.h"
#include "uint256.h"

#include <map>
#include <string>
#include <vector>

class CNode;

// Header + coinbase + coinbase merkle branch, so a peer can read DAG parents ahead of the body.

static const char DAGHEADERS_GETCMD[] = "getdaghdrs";
static const char DAGHEADERS_CMD[] = "daghdrs";

static const unsigned int MAX_DAGHEADERS_PER_MSG = 1000;
static const unsigned int MAX_DAGHEADERS_REPLY_BYTES = 2 * 1024 * 1024;
static const unsigned int MAX_DAGHEADERS_BRANCH = 32;
static const unsigned int DEFAULT_DAGHEADERS_WINDOW = 100000;
static const unsigned int MAX_DAGHEADERS_WINDOW = 2000000;
static const int DAGHEADERS_MIN_GAP = 1000;
static const int64_t DAGHEADERS_REQUEST_TIMEOUT = 60;
static const int64_t DAGHEADERS_REQUEST_INTERVAL_MS = 1100;
static const int64_t DAGHEADERS_SERVE_BURST = 3;
static const int64_t DAGHEADERS_SERVE_PER_SEC = 1;

extern bool fDAGHeadersSync;
extern bool fDAGHeadersServe;

class CDAGHeaderEntry
{
public:
    CBlock header;  // header fields only; vtx stays empty
    CTransaction txCoinbase;
    std::vector<uint256> vMerkleBranch;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(header.nVersion);
        READWRITE(header.hashPrevBlock);
        READWRITE(header.hashMerkleRoot);
        READWRITE(header.nTime);
        READWRITE(header.nBits);
        READWRITE(header.nNonce);
        READWRITE(txCoinbase);
        READWRITE(vMerkleBranch);
    )
};

/** Context-free entry check: coinbase, merkle branch and, from the DAG fork, its parents. */
bool CheckDAGHeaderEntry(const CDAGHeaderEntry& entry, int nHeight,
                         std::vector<uint256>& vParentsOut, std::string& strError);

struct CDAGSkeletonNode
{
    uint256 hashPrev;
    int nHeight;
    unsigned int nTime;
    unsigned int nBits;
    std::vector<uint256> vParents;

    CDAGSkeletonNode() : nHeight(-1), nTime(0), nBits(0) {}
};

/** Verified headers awaiting bodies, kept out of mapBlockIndex. */
class CDAGHeaderSkeleton
{
public:
    explicit CDAGHeaderSkeleton(size_t nMaxEntriesIn) : nMaxEntries(nMaxEntriesIn) {}

    void SetMaxEntries(size_t n) { nMaxEntries = n; }
    size_t MaxEntries() const { return nMaxEntries; }
    size_t Size() const { return mapNodes.size(); }
    size_t Room() const { return mapNodes.size() >= nMaxEntries ? 0 : nMaxEntries - mapNodes.size(); }
    bool Have(const uint256& hash) const { return mapNodes.count(hash) != 0; }
    const CDAGSkeletonNode* Find(const uint256& hash) const;
    int TopHeight() const { return mapByHeight.empty() ? -1 : mapByHeight.rbegin()->first; }

    bool Add(const uint256& hash, const CDAGSkeletonNode& node);
    void PruneAtOrBelow(int nHeight);
    void Clear();

    /** Held chain ending at hashTip, oldest first; hashRootOut is the first hash not held. */
    bool CollectChain(const uint256& hashTip, uint256& hashRootOut, int& nRootHeightOut,
                      std::vector<uint256>& vChainOut) const;

private:
    size_t nMaxEntries;
    std::map<uint256, CDAGSkeletonNode> mapNodes;
    std::multimap<int, uint256> mapByHeight;
};

/** Assume-valid ancestry learned from headers. Caller holds cs_main. */
void DAGHeadersSetAssumeValidAnchor(const uint256& hashAssumeValid, const uint256& hashRoot,
                                    int nRootHeight, const std::vector<uint256>& vChain);
void DAGHeadersClearAssumeValidAnchor();
bool DAGHeadersHaveAssumeValidAnchor(const uint256& hashAssumeValid);
bool DAGHeadersIsAssumeValidAncestor(const uint256& hashAssumeValid, const CBlockIndex* pindex);

CDAGHeaderSkeleton& DAGHeaderSkeleton();

void InitDAGHeaders(size_t nWindow);
/** Handles getdaghdrs/daghdrs; false when strCommand is neither. */
bool ProcessDAGHeadersMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv);
void SendDAGHeadersRequest(CNode* pto);

#endif // INNOVA_DAGHEADERS_H
