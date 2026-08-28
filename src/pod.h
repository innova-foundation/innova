// Copyright (c) 2019-2026 The Innova Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_POD_H
#define INNOVA_POD_H

#include <string>
#include <vector>

#include "script.h"
#include "uint256.h"

class CTransaction;
class CWallet;
class CWalletTx;

// Proof-of-Data stamp, carried in an OP_RETURN so the digest itself is on chain:
//
//   OP_RETURN <"IPOD" ‖ version ‖ type ‖ digest32>              (38 bytes)
//   OP_RETURN <"IPOD" ‖ version ‖ type ‖ digest32> OP_RETURN <locator34>
//
// The second form is the only standard two-push shape (TX_NULL_DATA template in
// script.cpp), and carries a CIDv0 multihash as a retrieval locator. The digest
// push is authoritative; the locator is a hint.

static const unsigned char POD_STAMP_MAGIC[4] = { 'I', 'P', 'O', 'D' };
static const unsigned int POD_STAMP_VERSION = 0x01;
static const unsigned int POD_DIGEST_SIZE   = 32;
static const unsigned int POD_PAYLOAD_SIZE  = 38; // 4 magic + 1 version + 1 type + 32 digest
static const unsigned int POD_LOCATOR_SIZE  = 34; // 0x12 0x20 + 32 (CIDv0 multihash)
static const unsigned int POD_SALT_SIZE     = 32;

enum PodStampType
{
    POD_TYPE_PLAIN     = 0x01, // digest = SHA-256(file), equal to sha256sum
    POD_TYPE_BLINDED   = 0x02, // digest = SHA-256(SHA-256(file) ‖ salt32)
    POD_TYPE_HYPERFILE = 0x03, // digest = SHA-256(file), plus a CID locator push
};

// Paid back to the sender so the stamp tx always carries a non-data output:
// IsStandardTx rejects nDataOut > nTxnOut, and CreateTransaction can fold
// sub-cent change into the fee, which would otherwise leave none. 0.01 INN.
static const int64_t POD_STAMP_SELFPAY = 1000000;

struct CPodStamp
{
    int nStampVersion;
    int nType;
    std::vector<unsigned char> vDigest;  // 32 bytes, sha256sum byte order
    std::vector<unsigned char> vLocator; // 34 bytes, or empty
    int nOut;

    CPodStamp() : nStampVersion(0), nType(0), nOut(-1) {}
};

std::string PodTypeName(int nType);

// SHA-256 over the file's bytes, streamed. Byte order as printed by sha256sum.
bool PodHashFile(const std::string& strPath, std::vector<unsigned char>& vDigestOut,
                 std::string& strError);

// Digest the 2018-2026 stamps used: SerializeHash over the file read as a
// vector<char>, i.e. dSHA256(compact-size ‖ bytes).
bool PodLegacyHashFile(const std::string& strPath, uint256& hashOut, std::string& strError);

std::vector<unsigned char> PodBlindDigest(const std::vector<unsigned char>& vDigest,
                                          const std::vector<unsigned char>& vSalt);
std::vector<unsigned char> PodNewSalt();

// CIDv0 ("Qm...", base58 multihash) -> 34-byte locator. False for any other CID form.
bool PodCidToLocator(const std::string& strCid, std::vector<unsigned char>& vLocatorOut);
std::string PodLocatorToCid(const std::vector<unsigned char>& vLocator);

// vLocator may be empty; it is only emitted for POD_TYPE_HYPERFILE.
CScript PodStampScript(int nType, const std::vector<unsigned char>& vDigest,
                       const std::vector<unsigned char>& vLocator);

bool PodParseStampScript(const CScript& script, CPodStamp& stampOut);
bool PodFindStamp(const CTransaction& tx, CPodStamp& stampOut);

// Builds, signs and commits the stamp tx. Returns "" on success, else the reason.
// fFromPool funds it from v2008 notes (requires Boundary B); the stamp names no address.
std::string PodCreateStamp(CWallet* pwallet, int nType,
                           const std::vector<unsigned char>& vDigest,
                           const std::vector<unsigned char>& vLocator,
                           CWalletTx& wtxNew, bool fFromPool = false);

// The RPCs that read a server-side path publish any file the node's user can
// read, so they are off unless -enablefilerpc=1. Throws when not enabled.
void PodRequireFileRpc(const char* pszRpcName);

// Shared help text: what an IPFS upload discloses and to whom.
std::string PodHyperfileDisclosure();

#endif // INNOVA_POD_H
