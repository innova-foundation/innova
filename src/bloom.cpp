// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <math.h>
#include <stdlib.h>

#include "bloom.h"
#include "main.h"
#include "script.h"
#include "hash.h"
#define LN2SQUARED 0.4804530139182014246671025263266649717305529515945455
#define LN2 0.6931471805599453094172321214581765680755001343602552

using namespace std;

static const unsigned char bit_mask[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

CBloomFilter::CBloomFilter(unsigned int nElements, double nFPRate, unsigned int nTweakIn, unsigned char nFlagsIn) :
// The ideal size for a bloom filter with a given number of elements and false positive rate is:
// - nElements * log(fp rate) / ln(2)^2
// We ignore filter parameters which will create a bloom filter larger than the protocol limits
vData(min((unsigned int)(-1  / LN2SQUARED * nElements * log(nFPRate)), MAX_BLOOM_FILTER_SIZE * 8) / 8),
// The ideal number of hash functions is filter size * ln(2) / number of elements
// Again, we ignore filter parameters which will create a bloom filter with more hash functions than the protocol limits
// See http://en.wikipedia.org/wiki/Bloom_filter for an explanation of these formulas
isFull(false),
isEmpty(false),
nHashFuncs(min((unsigned int)(vData.size() * 8 / nElements * LN2), MAX_HASH_FUNCS)),
nTweak(nTweakIn),
nFlags(nFlagsIn)
{
}

inline unsigned int CBloomFilter::Hash(unsigned int nHashNum, const std::vector<unsigned char>& vDataToHash) const
{
    // 0xFBA4C795 chosen as it guarantees a reasonable bit difference between nHashNum values.
    return MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash) % (vData.size() * 8);
}

void CBloomFilter::insert(const vector<unsigned char>& vKey)
{
    if (isFull)
        return;
    for (unsigned int i = 0; i < nHashFuncs; i++)
    {
        unsigned int nIndex = Hash(i, vKey);
        // Sets bit nIndex of vData
        vData[nIndex >> 3] |= bit_mask[7 & nIndex];
    }
    isEmpty = false;
}

void CBloomFilter::insert(const COutPoint& outpoint)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << outpoint;
    vector<unsigned char> data(stream.begin(), stream.end());
    insert(data);
}

void CBloomFilter::insert(const uint256& hash)
{
    vector<unsigned char> data(hash.begin(), hash.end());
    insert(data);
}

bool CBloomFilter::contains(const vector<unsigned char>& vKey) const
{
    if (isFull)
        return true;
    if (isEmpty)
        return false;
    for (unsigned int i = 0; i < nHashFuncs; i++)
    {
        unsigned int nIndex = Hash(i, vKey);
        // Checks bit nIndex of vData
        if (!(vData[nIndex >> 3] & bit_mask[7 & nIndex]))
            return false;
    }
    return true;
}

bool CBloomFilter::contains(const COutPoint& outpoint) const
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << outpoint;
    vector<unsigned char> data(stream.begin(), stream.end());
    return contains(data);
}

bool CBloomFilter::contains(const uint256& hash) const
{
    vector<unsigned char> data(hash.begin(), hash.end());
    return contains(data);
}

bool CBloomFilter::IsWithinSizeConstraints() const
{
    return vData.size() <= MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS;
}

bool CBloomFilter::IsRelevantAndUpdate(const CTransaction& tx)
{
    bool fFound = false;
    // Match if the filter contains the hash of tx
    //  for finding tx when they appear in a block
    if (isFull)
        return true;
    if (isEmpty)
        return false;

    const uint256& hash = tx.GetHash();


    if (((nFlags & BLOOM_ACCEPT_STEALTH) && tx.HasStealthOutput())
        || contains(hash))
    {
        fFound = true;
        // -- don't return here!
    };


    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
        // Match if the filter contains any arbitrary script data element in any scriptPubKey in tx
        // If this matches, also add the specific output that was matched.
        // This means clients don't have to update the filter themselves when a new relevant tx
        // is discovered in order to find spending transactions, which avoids round-tripping and race conditions.
        CScript::const_iterator pc = txout.scriptPubKey.begin();
        vector<unsigned char> data;
        while (pc < txout.scriptPubKey.end())
        {
            opcodetype opcode;
            if (!txout.scriptPubKey.GetOp(pc, opcode, data))
                break;

            if (data.size() == 33) // coinstake
            {
                uint160 pkHash = Hash160(data);
                vector<unsigned char> dataHash160(pkHash.begin(), pkHash.end());

                if (dataHash160.size() != 0 && contains(dataHash160))
                    fFound = true;
            };

            if (!fFound
                && data.size() != 0 && contains(data))
                fFound = true;

            if (fFound)
            {
                if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)
                {
                    insert(COutPoint(hash, i));
                } else
                if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_P2PUBKEY_ONLY)
                {
                    txnouttype type;
                    vector<vector<unsigned char> > vSolutions;
                    if (Solver(txout.scriptPubKey, type, vSolutions) &&
                            (type == TX_PUBKEY || type == TX_MULTISIG))
                        insert(COutPoint(hash, i));
                };
                break;
            };
        };
    };

    if (fFound)
        return true;

    for (const CTxIn& txin : tx.vin)
    {
        // Match if the filter contains an outpoint tx spends
        if (contains(txin.prevout))
            return true;

        // Match if the filter contains any arbitrary script data element in any scriptSig in tx
        CScript::const_iterator pc = txin.scriptSig.begin();
        vector<unsigned char> data;
        while (pc < txin.scriptSig.end())
        {
            opcodetype opcode;
            if (!txin.scriptSig.GetOp(pc, opcode, data))
                break;
            if (data.size() != 0 && contains(data))
                return true;
        };
    };

    return false;
}

void CBloomFilter::UpdateEmptyFull()
{
    bool full = true;
    bool empty = true;
    for (unsigned int i = 0; i < vData.size(); i++)
    {
        full &= vData[i] == 0xff;
        empty &= vData[i] == 0;
    }
    isFull = full;
    isEmpty = empty;
}

uint256 CPartialMerkleTree::CalcHash(int height, unsigned int pos, const std::vector<uint256> &vTxid)
{
    if (height == 0) {
        return vTxid[pos];
    } else {
        uint256 left = CalcHash(height-1, pos*2, vTxid), right;
        if (pos*2+1 < CalcTreeWidth(height-1))
            right = CalcHash(height-1, pos*2+1, vTxid);
        else
            right = left;
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}

void CPartialMerkleTree::TraverseAndBuild(int height, unsigned int pos, const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch)
{
    bool fParentOfMatch = false;
    for (unsigned int p = pos << height; p < (pos+1) << height && p < nTransactions; p++)
        fParentOfMatch |= vMatch[p];
    vBits.push_back(fParentOfMatch);
    if (height==0 || !fParentOfMatch) {
        vHash.push_back(CalcHash(height, pos, vTxid));
    } else {
        TraverseAndBuild(height-1, pos*2, vTxid, vMatch);
        if (pos*2+1 < CalcTreeWidth(height-1))
            TraverseAndBuild(height-1, pos*2+1, vTxid, vMatch);
    }
}

uint256 CPartialMerkleTree::TraverseAndExtract(int height, unsigned int pos, unsigned int &nBitsUsed, unsigned int &nHashUsed, std::vector<uint256> &vMatch)
{
    if (nBitsUsed >= vBits.size()) {
        fBad = true;
        return 0;
    }
    bool fParentOfMatch = vBits[nBitsUsed++];
    if (height==0 || !fParentOfMatch) {
        if (nHashUsed >= vHash.size()) {
            fBad = true;
            return 0;
        }
        const uint256 &hash = vHash[nHashUsed++];
        if (height==0 && fParentOfMatch)
            vMatch.push_back(hash);
        return hash;
    } else {
        uint256 left = TraverseAndExtract(height-1, pos*2, nBitsUsed, nHashUsed, vMatch), right;
        if (pos*2+1 < CalcTreeWidth(height-1)) {
            right = TraverseAndExtract(height-1, pos*2+1, nBitsUsed, nHashUsed, vMatch);
            if (right == left) {
                fBad = true;
            }
        } else {
            right = left;
        }
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}

CPartialMerkleTree::CPartialMerkleTree(const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) : nTransactions(vTxid.size()), fBad(false)
{
    vBits.clear();
    vHash.clear();

    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1)
        nHeight++;

    TraverseAndBuild(nHeight, 0, vTxid, vMatch);
}

CPartialMerkleTree::CPartialMerkleTree() : nTransactions(0), fBad(true) {}

uint256 CPartialMerkleTree::ExtractMatches(std::vector<uint256> &vMatch)
{
    vMatch.clear();
    if (nTransactions == 0)
        return 0;
    if (nTransactions > MAX_BLOCK_SIZE / 60)
        return 0;
    if (vHash.size() > nTransactions)
        return 0;
    if (vBits.size() < vHash.size())
        return 0;
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1)
        nHeight++;
    unsigned int nBitsUsed = 0, nHashUsed = 0;
    uint256 hashMerkleRoot = TraverseAndExtract(nHeight, 0, nBitsUsed, nHashUsed, vMatch);
    if (fBad)
        return 0;
    if ((nBitsUsed+7)/8 != (vBits.size()+7)/8)
        return 0;
    if (nHashUsed != vHash.size())
        return 0;
    return hashMerkleRoot;
}

CMerkleBlock::CMerkleBlock(const CBlock& block, CBloomFilter& filter)
{
    header.nVersion = block.nVersion;
    header.hashPrevBlock = block.hashPrevBlock;
    header.hashMerkleRoot = block.hashMerkleRoot;
    header.nTime = block.nTime;
    header.nBits = block.nBits;
    header.nNonce = block.nNonce;

    vector<bool> vMatch;
    vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size());
    vHashes.reserve(block.vtx.size());

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const uint256& hash = block.vtx[i].GetHash();
        if (filter.IsRelevantAndUpdate(block.vtx[i]))
        {
            vMatch.push_back(true);
            vMatchedTxn.push_back(make_pair(i, hash));
        }
        else
            vMatch.push_back(false);
        vHashes.push_back(hash);
    }

    txn = CPartialMerkleTree(vHashes, vMatch);
}
