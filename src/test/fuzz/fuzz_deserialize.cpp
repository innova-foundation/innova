// Copyright (c) 2019-2026 The Innova developers
// Fuzz target: Transaction deserialization
// Exercises CTransaction and CBlock deserialization from arbitrary bytes

#include "main.h"
#include "serialize.h"

#include <cstdint>
#include <cstddef>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Cap input size
    if (size > 100000)
        return 0;

    std::vector<unsigned char> vch(data, data + size);

    // Try deserializing as CTransaction
    try
    {
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        CTransaction tx;
        ss >> tx;

        // Exercise tx methods
        tx.GetHash();
        tx.GetValueOut();
        tx.IsCoinBase();
        tx.IsCoinStake();
    }
    catch (const std::exception&)
    {
        // Expected for malformed data
    }

    // Try deserializing as CBlock
    try
    {
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        CBlock block;
        ss >> block;

        // Exercise block methods
        block.GetHash();
        block.GetPoWHash();
    }
    catch (const std::exception&)
    {
        // Expected for malformed data
    }

    return 0;
}
