// Copyright (c) 2026 The Innova developers
// Fuzz target: Nyx v2 reassembler driven by a sequence of (owner, frame, clock step, disconnect) records.

#include "../../nyxparts.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    NyxReassemblyLimits l;
    l.nOwnerBytes = 3 * NYX_PART_BODY_MAX;
    l.nNodeBytes = 7 * NYX_PART_BODY_MAX;
    l.nOwnerSets = 3;
    l.nTimeout = 600;
    NyxReassembler ra(l);
    int64_t now = 1000;

    size_t off = 0;
    while (size - off >= 4)
    {
        const uint8_t owner = data[off] & 3;
        const uint8_t op = data[off + 1];
        const uint16_t n = (uint16_t)(data[off + 2] | (data[off + 3] << 8)) % (NYX_FRAME_PREFIX + NYX_PART_BODY_MAX + 1);
        off += 4;
        const std::string sOwner(1, (char)('a' + owner));

        if (op & 0x80)
            ra.FreeOwner(sOwner);
        now += op & 0x3f;
        ra.Expire(now);

        if (n > size - off)
            break;
        NyxFrame f;
        if (NyxParseFrame(data + off, n, f) == NYX_FRAME_OK)
        {
            std::vector<uint8_t> body;
            const NyxAddResult r = ra.Add(sOwner, f, now, body);
            if (r == NYX_RA_COMPLETE)
            {
                uint8_t h[32];
                NyxSha256(body.empty() ? NULL : &body[0], body.size(), h);
                if (body.size() != f.totalLen || memcmp(h, f.totalHash, 32) != 0)
                    abort();
            } else if (!body.empty())
                abort();
        }
        off += n;

        if (ra.NodeBytes() > l.nNodeBytes || ra.OwnerBytes(sOwner) > l.nOwnerBytes
            || ra.OwnerSetCount(sOwner) > l.nOwnerSets)
            abort();
    }

    for (int i = 0; i < 4; ++i)
        ra.FreeOwner(std::string(1, (char)('a' + i)));
    if (ra.NodeBytes() != 0 || ra.SetCount() != 0)
        abort();
    return 0;
}
