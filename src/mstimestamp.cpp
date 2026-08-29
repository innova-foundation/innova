// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mstimestamp.h"

#include "util.h"

#include <string.h>

CScript BuildMsTimestampScript(uint16_t nTimeMs)
{
    if ((unsigned int)nTimeMs > MS_TIMESTAMP_MAX)
        return CScript();

    std::vector<unsigned char> vchData(MS_TIMESTAMP_TAG, MS_TIMESTAMP_TAG + 4);
    vchData.push_back((unsigned char)(nTimeMs & 0xff));
    vchData.push_back((unsigned char)((nTimeMs >> 8) & 0xff));

    CScript script;
    script << OP_RETURN << vchData;
    return script;
}

MsTimestampDecodeStatus DecodeCanonicalMsTimestampScript(
    const CScript& script, uint16_t& nTimeMs, std::string& strError)
{
    nTimeMs = 0;
    strError.clear();

    if (script.size() < 2 || script[0] != OP_RETURN)
        return MS_TIMESTAMP_NOT_FOUND;

    // Read the one bounded push directly rather than through CScript::GetOp,
    // so a non-minimal encoding of a tagged payload is classified malformed
    // instead of reading as an unrelated OP_RETURN.
    size_t nOffset = 1;
    const unsigned char opcode = script[nOffset++];
    uint64_t nDataSize = 0;
    if (opcode <= 75)
        nDataSize = opcode;
    else if (opcode == OP_PUSHDATA1)
    {
        if (nOffset + 1 > script.size())
            return MS_TIMESTAMP_NOT_FOUND;
        nDataSize = script[nOffset++];
    }
    else if (opcode == OP_PUSHDATA2)
    {
        if (nOffset + 2 > script.size())
            return MS_TIMESTAMP_NOT_FOUND;
        nDataSize = (uint64_t)script[nOffset] |
                    ((uint64_t)script[nOffset + 1] << 8);
        nOffset += 2;
    }
    else
        return MS_TIMESTAMP_NOT_FOUND;

    if (nDataSize > MS_TIMESTAMP_PAYLOAD_SIZE + 64 ||
        nOffset + nDataSize > script.size())
        return MS_TIMESTAMP_NOT_FOUND;

    std::vector<unsigned char> vchData(
        script.begin() + nOffset,
        script.begin() + nOffset + (size_t)nDataSize);
    nOffset += (size_t)nDataSize;
    if (vchData.size() < 4 ||
        memcmp(vchData.data(), MS_TIMESTAMP_TAG, 4) != 0)
        return MS_TIMESTAMP_NOT_FOUND;

    if (nOffset != script.size())
    {
        strError = "IMTS commitment has trailing script operations";
        return MS_TIMESTAMP_MALFORMED;
    }
    if (vchData.size() != MS_TIMESTAMP_PAYLOAD_SIZE)
    {
        strError = strprintf("IMTS payload length %u is not %u",
                             (unsigned int)vchData.size(),
                             (unsigned int)MS_TIMESTAMP_PAYLOAD_SIZE);
        return MS_TIMESTAMP_MALFORMED;
    }

    const unsigned int nDecoded =
        (unsigned int)vchData[4] | ((unsigned int)vchData[5] << 8);
    if (nDecoded > MS_TIMESTAMP_MAX)
    {
        strError = strprintf("IMTS offset %u is outside 0..%u",
                             nDecoded, MS_TIMESTAMP_MAX);
        return MS_TIMESTAMP_MALFORMED;
    }

    const CScript scriptCanonical = BuildMsTimestampScript((uint16_t)nDecoded);
    if (scriptCanonical != script)
    {
        strError = "IMTS commitment uses a non-canonical push encoding";
        return MS_TIMESTAMP_MALFORMED;
    }

    nTimeMs = (uint16_t)nDecoded;
    return MS_TIMESTAMP_VALID;
}

bool ExtractCanonicalMsTimestampCommitment(
    const std::vector<CScript>& vScripts,
    uint16_t& nTimeMs,
    std::string& strError)
{
    nTimeMs = 0;
    strError.clear();
    bool fFound = false;
    for (std::vector<CScript>::const_iterator it = vScripts.begin();
         it != vScripts.end(); ++it)
    {
        uint16_t nDecoded = 0;
        std::string strDecodeError;
        const MsTimestampDecodeStatus status =
            DecodeCanonicalMsTimestampScript(*it, nDecoded, strDecodeError);
        if (status == MS_TIMESTAMP_MALFORMED)
        {
            strError = strDecodeError;
            return false;
        }
        if (status != MS_TIMESTAMP_VALID)
            continue;
        if (fFound)
        {
            strError = "multiple canonical IMTS commitments";
            nTimeMs = 0;
            return false;
        }
        fFound = true;
        nTimeMs = nDecoded;
    }
    if (!fFound)
    {
        strError = "missing canonical IMTS commitment";
        return false;
    }
    return true;
}

bool MsTimestampCommitmentPresent(const std::vector<CScript>& vScripts)
{
    for (std::vector<CScript>::const_iterator it = vScripts.begin();
         it != vScripts.end(); ++it)
    {
        uint16_t nDecoded = 0;
        std::string strDecodeError;
        if (DecodeCanonicalMsTimestampScript(*it, nDecoded, strDecodeError) !=
            MS_TIMESTAMP_NOT_FOUND)
            return true;
    }
    return false;
}
