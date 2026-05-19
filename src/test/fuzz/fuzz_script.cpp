// Copyright (c) 2019-2026 The Innova developers
// Fuzz target: CScript parsing and evaluation
// Build: clang++ -fsanitize=fuzzer,address -std=c++11 -I../../ -I../../json
//        -I../../leveldb/include fuzz_script.cpp ../../obj/*.o [libs]

#include "script.h"
#include "base58.h"

#include <cstdint>
#include <cstddef>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Cap input size to avoid excessive processing
    if (size > 10000)
        return 0;

    // Parse as CScript
    CScript script(data, data + size);

    // Exercise classification functions
    script.IsPayToScriptHash();
    script.IsPushOnly();
    script.HasCanonicalPushes();
    script.GetSigOpCount(false);
    script.GetSigOpCount(true);

    // Exercise solver
    txnouttype typeRet;
    std::vector<std::vector<unsigned char>> vSolutions;
    Solver(script, typeRet, vSolutions);

    // Exercise GetOp iteration
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> vchData;
    while (pc < script.end())
    {
        if (!script.GetOp(pc, opcode, vchData))
            break;
    }

    return 0;
}
