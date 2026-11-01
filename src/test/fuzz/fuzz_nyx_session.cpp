// Copyright (c) 2026 The Innova developers
// Fuzz target: Nyx v2 handshake (0x10), ratchet message (0x11) and envelope parsers;
// a handshake that parses must rebuild to the same bytes.

#include "../../nyxsession.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0 || size > 300000)
        return 0;
    std::vector<uint8_t> body(data, data + size);
    body[0] = NYX_BODY_HANDSHAKE;
    NyxHandshake hs;
    if (NyxParseHandshake(&body[0], body.size(), hs) == 0)
    {
        std::vector<uint8_t> v = hs.Fixed();
        v.insert(v.end(), hs.tail.begin(), hs.tail.end());
        if (v != body || hs.tail.size() < NYX_TAIL_MIN)
            abort();
    }
    body[0] = NYX_BODY_RATCHET;
    NyxRatchetMsg m;
    if (NyxParseRatchetMsg(&body[0], body.size(), m) == 0 && m.tail.size() + 33 != body.size())
        abort();
    NyxEnvelope env;
    if (env.Parse(body) && env.Serialize() != body)
        abort();
    NyxParseHandshake(data, size, hs);
    NyxParseRatchetMsg(data, size, m);
    return 0;
}
