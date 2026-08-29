// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_MSTIMESTAMP_H
#define INN_MSTIMESTAMP_H

#include "script.h"

#include <stdint.h>
#include <string>
#include <vector>

// Millisecond offset past the header's nTime, committed in a coinbase OP_RETURN
// so the header and block hash are unchanged. Every time rule (drift, MTP, stake
// age, retarget) still uses nTime; validators check only presence and range.

static const unsigned char MS_TIMESTAMP_TAG[4] = { 0x49, 0x4D, 0x54, 0x53 }; // "IMTS"

/** Largest legal offset. One less than a whole second. */
static const unsigned int MS_TIMESTAMP_MAX = 999;

/** Payload is tag(4) || offset(2, little-endian). */
static const size_t MS_TIMESTAMP_PAYLOAD_SIZE = 6;

/** Full-precision block time from the two fields. */
inline int64_t MsTimestampCombine(unsigned int nTime, uint16_t nTimeMs)
{
    return (int64_t)nTime * 1000 + (int64_t)nTimeMs;
}

enum MsTimestampDecodeStatus
{
    MS_TIMESTAMP_NOT_FOUND = 0,
    MS_TIMESTAMP_VALID = 1,
    MS_TIMESTAMP_MALFORMED = 2
};

/** Build a coinbase OP_RETURN script committing to a millisecond offset.
 *  Returns an empty script for an offset outside 0..MS_TIMESTAMP_MAX. */
CScript BuildMsTimestampScript(uint16_t nTimeMs);

/** Strict decoder: minimal push, whole script, exact payload size, offset in
 *  range. Outputs without the IMTS tag are NOT_FOUND. */
MsTimestampDecodeStatus DecodeCanonicalMsTimestampScript(
    const CScript& script, uint16_t& nTimeMs, std::string& strError);

/** Require exactly one strict IMTS commitment across the supplied scripts. */
bool ExtractCanonicalMsTimestampCommitment(
    const std::vector<CScript>& vScripts,
    uint16_t& nTimeMs,
    std::string& strError);

/** True when any supplied script carries the IMTS tag, well formed or not.
 *  The below-gate absence rule keys on this. */
bool MsTimestampCommitmentPresent(const std::vector<CScript>& vScripts);

#endif // INN_MSTIMESTAMP_H
