// Copyright (c) 2019-2026 The Innova developers
// Fuzz target: block header parsing and hash computation.
//
// This lineage has no separate CBlockHeader type: CBlock carries the header
// fields directly and serializes them ahead of its transactions, so a header is
// exercised by deserializing a CBlock with transactions switched off.

#include "main.h"
#include "serialize.h"
#include "uint256.h"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // The header is fixed-size (~80 bytes); allow slack for trailing input.
    if (size > 1000)
        return 0;

    std::vector<unsigned char> vch(data, data + size);

    try
    {
        // SER_BLOCKHEADERONLY stops the read at the header fields.
        CDataStream ss(vch, SER_NETWORK | SER_BLOCKHEADERONLY, PROTOCOL_VERSION);
        CBlock header;
        ss >> header;

        // Tribus proof-of-work hash over the header range.
        header.GetHash();
        header.GetPoWHash();

        (void)header.nVersion;
        (void)header.hashPrevBlock;
        (void)header.hashMerkleRoot;
        (void)header.nTime;
        (void)header.nBits;
        (void)header.nNonce;
    }
    catch (const std::exception&)
    {
        // Expected for malformed input.
    }

    if (size >= 32)
    {
        uint256 hash;
        memcpy(&hash, data, 32);
        hash.GetHex();
        hash.ToString();
    }

    return 0;
}
