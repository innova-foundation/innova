// Synthetic block indices for guard tests: pprev-linked CBlockIndex objects registered
// in mapBlockIndex under fabricated hashes, with no block data on disk. Torn down on exit.
#ifndef INNOVA_TEST_SYNTHETIC_CHAIN_H
#define INNOVA_TEST_SYNTHETIC_CHAIN_H

#include "../hash.h"
#include "../main.h"
#include "../uint256.h"

#include <map>
#include <string>
#include <vector>

class CSyntheticChain
{
public:
    explicit CSyntheticChain(unsigned int nTagIn) : nTag(nTagIn), nNext(0) {}
    ~CSyntheticChain() { Clear(); }

    // A block at nHeight whose selected parent is pprev (NULL for a root). NULL when the
    // fabricated hash is already indexed.
    CBlockIndex* Add(CBlockIndex* pprev, int nHeight)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("Innova/test/SyntheticChain") << nTag << nNext;
        nNext++;
        const uint256 hash = ss.GetHash();
        CBlockIndex* pindex = new CBlockIndex();
        pindex->nHeight = nHeight;
        pindex->pprev = pprev;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(hash, pindex));
        if (!ins.second)
        {
            delete pindex;
            return NULL;
        }
        pindex->phashBlock = &ins.first->first;
        pindex->BuildSkip();
        vHashes.push_back(hash);
        vBlocks.push_back(pindex);
        return pindex;
    }

    // pprev extended by nCount blocks, one height per step; the new tip.
    CBlockIndex* Extend(CBlockIndex* pprev, int nCount)
    {
        CBlockIndex* p = pprev;
        for (int i = 0; i < nCount; i++)
        {
            CBlockIndex* pNext = Add(p, p ? p->nHeight + 1 : 0);
            if (!pNext)
                return NULL;
            p = pNext;
        }
        return p;
    }

    // A root at height 0 extended to height nTip; the tip.
    CBlockIndex* Linear(int nTip)
    {
        CBlockIndex* pRoot = Add(NULL, 0);
        return pRoot ? Extend(pRoot, nTip) : NULL;
    }

    void Clear()
    {
        for (size_t i = 0; i < vHashes.size(); i++)
        {
            mapBlockIndex.erase(vHashes[i]);
            delete vBlocks[i];
        }
        vHashes.clear();
        vBlocks.clear();
    }

private:
    unsigned int nTag;
    unsigned int nNext;
    std::vector<uint256> vHashes;
    std::vector<CBlockIndex*> vBlocks;
};

#endif
