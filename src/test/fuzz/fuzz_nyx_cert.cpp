// Copyright (c) 2026 The Innova developers
// Fuzz target: Nyx v2 cert parser; a body that parses must serialize back to the same bytes.

#include "../../nyxcert.h"
#include "../../nyxpo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0 || size > 300000)
        return 0;
    std::vector<uint8_t> body(data, data + size);
    body[0] = NYX_PO_CERT;
    NyxCert obj;
    if (NyxParseCert(&body[0], body.size(), obj) == 0 && obj.Serialize() != body)
        abort();
    NyxParseCert(data, size, obj);
    return 0;
}
