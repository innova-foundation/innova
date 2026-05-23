// Copyright (c) 2019-2026 The Innova developers
// Fuzz target: Block header parsing and validation
// Exercises CBlockHeader deserialization and hash computation

#include "main.h"
#include "serialize.h"
#include "uint256.h"

#include <cstdint>
#include <cstddef>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // CBlockHeader is fixed-size (~80 bytes), but allow some extra
    if (size > 1000)
        return 0;

    std::vector<unsigned char> vch(data, data + size);

    // Try deserializing as CBlockHeader
    try
    {
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        CBlockHeader header;
        ss >> header;

        // Exercise header hash computation (Tribus)
        header.GetHash();
        header.GetPoWHash();

        // Exercise field access
        (void)header.nVersion;
        (void)header.hashPrevBlock;
        (void)header.hashMerkleRoot;
        (void)header.nTime;
        (void)header.nBits;
        (void)header.nNonce;
    }
    catch (const std::exception&)
    {
        // Expected for malformed data
    }

    // Try constructing uint256 from fuzz data
    if (size >= 32)
    {
        uint256 hash;
        memcpy(&hash, data, 32);
        hash.GetHex();
        hash.ToString();
    }

    return 0;
}
