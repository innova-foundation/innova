// Copyright (c) 2026 The Innova developers
// Fuzz target: SMSG header/payload validation under both -nyxv2 values, and the public object record loader.

#include "../../smessage.h"
#include "../../checkpoints.h"
#include "../../ui_interface.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifdef INNOVA_FUZZ_STANDALONE
CWallet* pwalletMain;
CClientUIInterface uiInterface;
bool fConfChange = false;
bool fEnforceCanonical = true;
bool fUseFastIndex = true;
unsigned int nDerivationMethodIndex = 0;
unsigned int nMinerSleep = 5000;
unsigned int nNodeLifespan = 7;
enum Checkpoints::CPMode CheckpointsMode = Checkpoints::STRICT;
void Shutdown(void*) { exit(0); }
void StartShutdown() { exit(0); }
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > 600000)
        return 0;
    const uint8_t sel = data[0];
    ++data;
    --size;

    if (sel & 2)
    {
        NyxPoStore::Record rec;
        if (SecureMsgPoDecodeRecord(std::string((const char*)data, size), rec)
            && (rec.vParts.empty() || rec.vParts.size() > NYX_MAX_PARTS || !NyxPoIsPublicType(rec.info.type)))
            abort();
        return 0;
    }

    if (size < SMSG_HDR_LEN)
        return 0;
    fNyxV2 = sel & 1;
    std::vector<unsigned char> buf(data, data + size);
    SecureMessage* psmsg = (SecureMessage*)&buf[0];
    // nPayload is authoritative from the wire; keep it within the bytes provided.
    const uint32_t nPayload = (uint32_t)(size - SMSG_HDR_LEN);
    psmsg->nPayload = nPayload;
    const int rv = SecureMsgValidate(&buf[0], nPayload ? &buf[SMSG_HDR_LEN] : &buf[0], nPayload);
    if (rv < 0 || rv > 5)
        abort();
    if (rv == 0 && psmsg->version[0] == 2 && !fNyxV2)
        abort();
    if (rv == 0 && nPayload > SecureMsgPayloadCap(&buf[0]))
        abort();
    return 0;
}
