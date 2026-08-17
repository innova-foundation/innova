// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Fuzz target: the IV5 privacy ABI boundary. The first byte selects the entry point.
// Every entry point must be total; CONTAINED_PANIC counts as a failure, and guard
// bytes around output buffers catch overruns.

#include "privacy_vnext/rust/include/innova_privacy_vnext.h"

#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace
{

// Bounds the fuzzer's own appetite. The ABI declares a 256 KiB payload ceiling, so a
// larger input only measures the length check.
const size_t FUZZ_PRIVACY_MAX_INPUT_SIZE = 512 * 1024;
const size_t FUZZ_PRIVACY_OUT_CAPACITY = 320 * 1024;
const size_t FUZZ_PRIVACY_GUARD_BYTES = 64;
const uint8_t FUZZ_PRIVACY_GUARD_VALUE = 0xa5;

const int32_t RESULT_VALID = 0;
const int32_t RESULT_CONSENSUS_INVALID = 1;
const int32_t RESULT_BAD_LENGTH = 2;
const int32_t RESULT_UNSUPPORTED_FORMAT = 3;
const int32_t RESULT_RESOURCE_LIMIT = 4;
const int32_t RESULT_CONTAINED_PANIC = 5;
const int32_t RESULT_INTERNAL_LOCAL_STATE_FAILURE = 6;

void CheckResultCode(int32_t nResult, const char* pszWhich)
{
    if (nResult == RESULT_CONTAINED_PANIC)
    {
        fprintf(stderr, "%s returned CONTAINED_PANIC\n", pszWhich);
        abort();
    }
    if (nResult < RESULT_VALID || nResult > RESULT_INTERNAL_LOCAL_STATE_FAILURE)
    {
        fprintf(stderr, "%s returned undeclared code %d\n", pszWhich, (int)nResult);
        abort();
    }
    // Only a locally broken build reports local state failure for peer bytes. Left
    // observable rather than fatal: the crate uses it for self-verification paths a
    // fuzzer can legitimately reach with nonsense input.
    (void)RESULT_CONSENSUS_INVALID;
    (void)RESULT_BAD_LENGTH;
    (void)RESULT_UNSUPPORTED_FORMAT;
    (void)RESULT_RESOURCE_LIMIT;
}

// A caller-owned output buffer with guard bytes on both sides.
class GuardedBuffer
{
public:
    GuardedBuffer(size_t nCapacity)
        : capacity(nCapacity),
          storage(nCapacity + (2 * FUZZ_PRIVACY_GUARD_BYTES), FUZZ_PRIVACY_GUARD_VALUE)
    {
    }

    uint8_t* Data() { return &storage[FUZZ_PRIVACY_GUARD_BYTES]; }
    size_t Capacity() const { return capacity; }

    void CheckGuards(const char* pszWhich) const
    {
        for (size_t i = 0; i < FUZZ_PRIVACY_GUARD_BYTES; ++i)
        {
            if (storage[i] != FUZZ_PRIVACY_GUARD_VALUE ||
                storage[storage.size() - 1 - i] != FUZZ_PRIVACY_GUARD_VALUE)
            {
                fprintf(stderr, "%s wrote outside its caller-owned buffer\n", pszWhich);
                abort();
            }
        }
    }

private:
    size_t capacity;
    std::vector<uint8_t> storage;
};

// Run one variable-output entry point and check the whole contract: declared code,
// buffer bounds, and a written length that never exceeds the capacity it was given.
typedef int32_t (*VariableOutputFn)(const uint8_t*, size_t, uint8_t*, size_t, size_t*);

void RunVariableOutput(VariableOutputFn fn, const uint8_t* pRequest, size_t nRequest,
                       const char* pszWhich)
{
    GuardedBuffer out(FUZZ_PRIVACY_OUT_CAPACITY);
    size_t nWritten = ~(size_t)0;
    const int32_t nResult = fn(pRequest, nRequest, out.Data(), out.Capacity(), &nWritten);
    CheckResultCode(nResult, pszWhich);
    out.CheckGuards(pszWhich);
    if (nResult == RESULT_VALID && nWritten > out.Capacity())
    {
        fprintf(stderr, "%s reported %zu bytes written into %zu of capacity\n", pszWhich,
                nWritten, out.Capacity());
        abort();
    }

    // A zero-capacity call must report the requirement rather than write anything.
    size_t nProbe = ~(size_t)0;
    const int32_t nProbeResult = fn(pRequest, nRequest, NULL, 0, &nProbe);
    CheckResultCode(nProbeResult, pszWhich);
}

typedef int32_t (*FixedOutputFn)(const uint8_t*, size_t, uint8_t*, size_t);

void RunFixedOutput(FixedOutputFn fn, const uint8_t* pRequest, size_t nRequest,
                    size_t nOutLen, const char* pszWhich)
{
    GuardedBuffer out(nOutLen);
    const int32_t nResult = fn(pRequest, nRequest, out.Data(), out.Capacity());
    CheckResultCode(nResult, pszWhich);
    out.CheckGuards(pszWhich);
}

typedef int32_t (*ValidateFn)(const uint8_t*, size_t);

void RunValidate(ValidateFn fn, const uint8_t* pRequest, size_t nRequest,
                 const char* pszWhich)
{
    CheckResultCode(fn(pRequest, nRequest), pszWhich);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0 || size > FUZZ_PRIVACY_MAX_INPUT_SIZE)
        return 0;

    const uint8_t nSelector = data[0];
    const uint8_t* pRequest = data + 1;
    const size_t nRequest = size - 1;

    switch (nSelector % 12)
    {
    case 0:
        // The consensus entry point: a peer's payload, judged.
        RunValidate(innova_privacy_vnext_payload_validate, pRequest, nRequest,
                    "payload_validate");
        break;
    case 1:
        // The same payload, decoded into the state effects a block applies. It must
        // agree with validate: effects may only succeed where validation does.
        {
            const int32_t nValidated =
                innova_privacy_vnext_payload_validate(pRequest, nRequest);
            CheckResultCode(nValidated, "payload_validate");
            GuardedBuffer out(FUZZ_PRIVACY_OUT_CAPACITY);
            size_t nWritten = 0;
            const int32_t nEffects = innova_privacy_vnext_payload_effects(
                pRequest, nRequest, out.Data(), out.Capacity(), &nWritten);
            CheckResultCode(nEffects, "payload_effects");
            out.CheckGuards("payload_effects");
            if (nEffects == RESULT_VALID && nValidated != RESULT_VALID)
            {
                fprintf(stderr,
                        "payload_effects accepted a payload payload_validate rejected\n");
                abort();
            }
        }
        break;
    case 2:
        RunFixedOutput(innova_privacy_vnext_payload_signing_hash, pRequest, nRequest,
                       INNOVA_PRIVACY_VNEXT_DIGEST_SIZE, "payload_signing_hash");
        break;
    case 3:
        RunVariableOutput(innova_privacy_vnext_payload_scan, pRequest, nRequest,
                          "payload_scan");
        break;
    case 4:
        RunVariableOutput(innova_privacy_vnext_note_scan, pRequest, nRequest, "note_scan");
        break;
    case 5:
        RunValidate(innova_privacy_vnext_fcmp_verify, pRequest, nRequest, "fcmp_verify");
        break;
    case 6:
        RunVariableOutput(innova_privacy_vnext_tree_update, pRequest, nRequest,
                          "tree_update");
        break;
    case 7:
        RunVariableOutput(innova_privacy_vnext_tree_extend, pRequest, nRequest,
                          "tree_extend");
        break;
    case 8:
        RunVariableOutput(innova_privacy_vnext_nullifier_update, pRequest, nRequest,
                          "nullifier_update");
        break;
    case 9:
        RunVariableOutput(innova_privacy_vnext_tree_witness, pRequest, nRequest,
                          "tree_witness");
        break;
    case 10:
        RunVariableOutput(innova_privacy_vnext_address_decode, pRequest, nRequest,
                          "address_decode");
        break;
    default:
        RunValidate(innova_privacy_vnext_vote_sigma_verify, pRequest, nRequest,
                    "vote_sigma_verify");
        break;
    }
    return 0;
}

#ifdef INNOVA_FUZZ_STANDALONE_MAIN
// Replay a saved artifact without libFuzzer, so a reproducer can be checked by hand.
int main(int argc, char** argv)
{
    for (int i = 1; i < argc; ++i)
    {
        FILE* pFile = fopen(argv[i], "rb");
        if (pFile == NULL)
            continue;
        std::vector<uint8_t> bytes;
        uint8_t chunk[4096];
        size_t nRead = 0;
        while ((nRead = fread(chunk, 1, sizeof(chunk), pFile)) > 0)
            bytes.insert(bytes.end(), chunk, chunk + nRead);
        fclose(pFile);
        LLVMFuzzerTestOneInput(bytes.empty() ? NULL : &bytes[0], bytes.size());
        fprintf(stderr, "replayed %s (%zu bytes)\n", argv[i], bytes.size());
    }
    return 0;
}
#endif
