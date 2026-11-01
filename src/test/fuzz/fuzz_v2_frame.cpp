// Copyright (c) 2026 The Innova developers
// Fuzz target: Nyx v2 frame parse, and the split/parse round trip.

#include "../../nyxparts.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    NyxFrame f;
    if (NyxParseFrame(data, size, f) == NYX_FRAME_OK)
    {
        if (f.nBody != size - NYX_FRAME_PREFIX || f.partIdx >= f.partCount || f.totalLen > NYX_MAX_BODY
            || f.nBody != NyxPartLen(f.totalLen, f.partCount, f.partIdx))
            abort();
    }

    if (size == 0 || size > NYX_MAX_BODY)
        return 0;
    std::vector<uint8_t> body(data, data + size);
    uint8_t id[16] = {0};
    memcpy(id, data, size < 16 ? size : 16);
    std::vector<std::vector<uint8_t> > frames;
    if (!NyxSplit(body, frames, id))
        abort();
    std::vector<uint8_t> joined;
    for (size_t i = 0; i < frames.size(); ++i)
    {
        NyxFrame g;
        if (NyxParseFrame(&frames[i][0], frames[i].size(), g) != NYX_FRAME_OK || g.partIdx != i
            || g.partCount != frames.size() || g.totalLen != size)
            abort();
        joined.insert(joined.end(), g.pBody, g.pBody + g.nBody);
    }
    if (joined != body)
        abort();
    return 0;
}
