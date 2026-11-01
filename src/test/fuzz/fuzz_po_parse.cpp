// Copyright (c) 2026 The Innova developers
// Fuzz target: Nyx public object body parse for each body type.

#include "../../nyxpo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0 || size > 300000)
        return 0;
    static const uint8_t types[3] = {NYX_PO_BUNDLE, NYX_PO_CERT, NYX_PO_KEYRING};
    std::vector<uint8_t> body(data, data + size);
    for (int i = 0; i < 3; ++i)
    {
        body[0] = types[i];
        NyxPoInfo info;
        if (NyxPoParse(&body[0], body.size(), info) == 0 && info.type != types[i])
            abort();
    }
    NyxPoInfo info;
    if (NyxPoParse(data, size, info) == 0 && !NyxPoIsPublicType(data[0]))
        abort();
    return 0;
}
