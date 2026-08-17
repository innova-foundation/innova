// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Replays fuzz_privacy_payload artifacts against the release archive and reports wall time.
//   fuzz_privacy_replay <artifact> [artifact...]

#include "privacy_vnext/rust/include/innova_privacy_vnext.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <vector>

namespace
{

double MonotonicSeconds()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ((double)ts.tv_nsec / 1e9);
}

bool ReadFile(const char* pszPath, std::vector<uint8_t>& bytesOut)
{
    FILE* pFile = fopen(pszPath, "rb");
    if (pFile == NULL)
        return false;
    uint8_t chunk[4096];
    size_t nRead = 0;
    while ((nRead = fread(chunk, 1, sizeof(chunk), pFile)) > 0)
        bytesOut.insert(bytesOut.end(), chunk, chunk + nRead);
    fclose(pFile);
    return true;
}

} // namespace

int main(int argc, char** argv)
{
    for (int i = 1; i < argc; ++i)
    {
        std::vector<uint8_t> bytes;
        if (!ReadFile(argv[i], bytes) || bytes.empty())
        {
            fprintf(stderr, "%s: unreadable\n", argv[i]);
            continue;
        }
        const uint8_t nSelector = bytes[0] % 12;
        const uint8_t* pRequest = &bytes[1];
        const size_t nRequest = bytes.size() - 1;

        const double dStart = MonotonicSeconds();
        int32_t nResult = 0;
        switch (nSelector)
        {
        case 0:
            nResult = innova_privacy_vnext_payload_validate(pRequest, nRequest);
            break;
        case 5:
            nResult = innova_privacy_vnext_fcmp_verify(pRequest, nRequest);
            break;
        default:
        {
            std::vector<uint8_t> out(320 * 1024, 0);
            size_t nWritten = 0;
            nResult = innova_privacy_vnext_payload_effects(pRequest, nRequest, &out[0],
                                                           out.size(), &nWritten);
            break;
        }
        }
        const double dElapsed = MonotonicSeconds() - dStart;
        printf("%s: selector=%u bytes=%zu result=%d elapsed=%.3fs\n", argv[i],
               (unsigned)nSelector, nRequest, (int)nResult, dElapsed);
    }
    return 0;
}
