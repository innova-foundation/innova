// Copyright (c) 2019-2026 The Innova Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pod.h"

#include "base58.h"
#include "core.h"
#include "innovarpc.h"
#include "main.h"
#include "util.h"
#include "wallet.h"

#include <openssl/sha.h>

#include <fstream>

std::string PodTypeName(int nType)
{
    switch (nType)
    {
        case POD_TYPE_PLAIN:     return "plain";
        case POD_TYPE_BLINDED:   return "blinded";
        case POD_TYPE_HYPERFILE: return "hyperfile";
        default:                 return "unknown";
    }
}

static const size_t POD_READ_CHUNK = 64 * 1024;

bool PodHashFile(const std::string& strPath, std::vector<unsigned char>& vDigestOut,
                 std::string& strError)
{
    vDigestOut.clear();

    std::ifstream in(strPath.c_str(), std::ios::binary);
    if (!in.is_open())
    {
        strError = "Cannot open file: " + strPath;
        return false;
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    std::vector<char> vBuf(POD_READ_CHUNK);
    while (in.good())
    {
        in.read(&vBuf[0], (std::streamsize)vBuf.size());
        std::streamsize nRead = in.gcount();
        if (nRead > 0)
            SHA256_Update(&ctx, &vBuf[0], (size_t)nRead);
    }
    if (in.bad())
    {
        strError = "Read error on file: " + strPath;
        return false;
    }

    vDigestOut.resize(POD_DIGEST_SIZE);
    SHA256_Final(&vDigestOut[0], &ctx);
    return true;
}

// Mirrors WriteCompactSize so the streamed digest matches SerializeHash of the
// same bytes read into a vector<char>.
static void PodAppendCompactSize(std::vector<unsigned char>& v, uint64_t n)
{
    if (n < 253)
    {
        v.push_back((unsigned char)n);
    }
    else if (n <= 0xFFFFu)
    {
        v.push_back(253);
        for (int i = 0; i < 2; i++) v.push_back((unsigned char)((n >> (8 * i)) & 0xFF));
    }
    else if (n <= 0xFFFFFFFFu)
    {
        v.push_back(254);
        for (int i = 0; i < 4; i++) v.push_back((unsigned char)((n >> (8 * i)) & 0xFF));
    }
    else
    {
        v.push_back(255);
        for (int i = 0; i < 8; i++) v.push_back((unsigned char)((n >> (8 * i)) & 0xFF));
    }
}

bool PodLegacyHashFile(const std::string& strPath, uint256& hashOut, std::string& strError)
{
    std::ifstream in(strPath.c_str(), std::ios::binary);
    if (!in.is_open())
    {
        strError = "Cannot open file: " + strPath;
        return false;
    }

    in.seekg(0, std::ios::end);
    std::streamoff nSize = in.tellg();
    if (nSize < 0)
    {
        strError = "Cannot size file: " + strPath;
        return false;
    }
    in.seekg(0, std::ios::beg);

    std::vector<unsigned char> vPrefix;
    PodAppendCompactSize(vPrefix, (uint64_t)nSize);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &vPrefix[0], vPrefix.size());

    std::vector<char> vBuf(POD_READ_CHUNK);
    std::streamoff nSeen = 0;
    while (in.good() && nSeen < nSize)
    {
        in.read(&vBuf[0], (std::streamsize)vBuf.size());
        std::streamsize nRead = in.gcount();
        if (nRead <= 0)
            break;
        SHA256_Update(&ctx, &vBuf[0], (size_t)nRead);
        nSeen += nRead;
    }
    if (in.bad() || nSeen != nSize)
    {
        strError = "Read error on file: " + strPath;
        return false;
    }

    unsigned char inner[SHA256_DIGEST_LENGTH];
    SHA256_Final(inner, &ctx);
    unsigned char outer[SHA256_DIGEST_LENGTH];
    SHA256(inner, sizeof(inner), outer);

    memcpy(hashOut.begin(), outer, sizeof(outer));
    return true;
}

std::vector<unsigned char> PodBlindDigest(const std::vector<unsigned char>& vDigest,
                                          const std::vector<unsigned char>& vSalt)
{
    std::vector<unsigned char> vOut;
    if (vDigest.size() != POD_DIGEST_SIZE || vSalt.size() != POD_SALT_SIZE)
        return vOut;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &vDigest[0], vDigest.size());
    SHA256_Update(&ctx, &vSalt[0], vSalt.size());

    vOut.resize(POD_DIGEST_SIZE);
    SHA256_Final(&vOut[0], &ctx);
    return vOut;
}

std::vector<unsigned char> PodNewSalt()
{
    std::vector<unsigned char> vSalt(POD_SALT_SIZE);
    GetRandBytes(&vSalt[0], (int)vSalt.size());
    return vSalt;
}

bool PodCidToLocator(const std::string& strCid, std::vector<unsigned char>& vLocatorOut)
{
    vLocatorOut.clear();

    std::vector<unsigned char> vRaw;
    if (!DecodeBase58(strCid, vRaw))
        return false;
    if (vRaw.size() != POD_LOCATOR_SIZE)
        return false;
    // sha2-256 multihash: code 0x12, length 0x20
    if (vRaw[0] != 0x12 || vRaw[1] != 0x20)
        return false;

    vLocatorOut = vRaw;
    return true;
}

std::string PodLocatorToCid(const std::vector<unsigned char>& vLocator)
{
    if (vLocator.size() != POD_LOCATOR_SIZE || vLocator[0] != 0x12 || vLocator[1] != 0x20)
        return "";
    return EncodeBase58(vLocator);
}

CScript PodStampScript(int nType, const std::vector<unsigned char>& vDigest,
                       const std::vector<unsigned char>& vLocator)
{
    CScript script;
    if (vDigest.size() != POD_DIGEST_SIZE)
        return script;
    if (nType <= 0 || nType > 0xFF)
        return script;

    std::vector<unsigned char> vPayload;
    vPayload.reserve(POD_PAYLOAD_SIZE);
    vPayload.insert(vPayload.end(), POD_STAMP_MAGIC, POD_STAMP_MAGIC + 4);
    vPayload.push_back((unsigned char)POD_STAMP_VERSION);
    vPayload.push_back((unsigned char)nType);
    vPayload.insert(vPayload.end(), vDigest.begin(), vDigest.end());

    script << OP_RETURN << vPayload;

    // The only standard two-push nulldata shape is the interleaved
    // OP_RETURN <push> OP_RETURN <push>; a single OP_RETURN with two pushes
    // matches no template and would not relay.
    if (nType == POD_TYPE_HYPERFILE && vLocator.size() == POD_LOCATOR_SIZE)
        script << OP_RETURN << vLocator;

    return script;
}

bool PodParseStampScript(const CScript& script, CPodStamp& stampOut)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;

    if (!script.GetOp(pc, opcode, vch) || opcode != OP_RETURN)
        return false;
    if (!script.GetOp(pc, opcode, vch))
        return false;
    if (vch.size() != POD_PAYLOAD_SIZE)
        return false;
    if (memcmp(&vch[0], POD_STAMP_MAGIC, 4) != 0)
        return false;

    stampOut.nStampVersion = vch[4];
    stampOut.nType = vch[5];
    stampOut.vDigest.assign(vch.begin() + 6, vch.end());
    stampOut.vLocator.clear();

    // Optional locator push. A malformed tail leaves the digest usable.
    if (script.GetOp(pc, opcode, vch) && opcode == OP_RETURN
        && script.GetOp(pc, opcode, vch) && vch.size() == POD_LOCATOR_SIZE)
    {
        stampOut.vLocator = vch;
    }

    return true;
}

bool PodFindStamp(const CTransaction& tx, CPodStamp& stampOut)
{
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        CPodStamp stamp;
        if (PodParseStampScript(tx.vout[i].scriptPubKey, stamp))
        {
            stamp.nOut = (int)i;
            stampOut = stamp;
            return true;
        }
    }
    return false;
}

std::string PodCreateStamp(CWallet* pwallet, int nType,
                           const std::vector<unsigned char>& vDigest,
                           const std::vector<unsigned char>& vLocator,
                           CWalletTx& wtxNew)
{
    if (!pwallet)
        return "Wallet is not available.";
    if (vDigest.size() != POD_DIGEST_SIZE)
        return "Internal error: stamp digest is not 32 bytes.";

    CScript scriptStamp = PodStampScript(nType, vDigest, vLocator);
    if (scriptStamp.empty())
        return "Internal error: stamp script could not be built.";

    if (pwallet->IsLocked())
        return "Wallet is locked. Unlock it before stamping.";
    if (fWalletUnlockStakingOnly)
        return "Wallet is unlocked for staking only, unable to create transaction.";

    CReserveKey changekey(pwallet);
    CReserveKey stampkey(pwallet);

    // One value output back to this wallet. It keeps nTxnOut >= nDataOut whatever
    // coin selection does, including the exact-fund and folded-change cases where
    // CreateTransaction emits no change at all.
    CPubKey vchPubKey;
    if (!stampkey.GetReservedKey(vchPubKey))
        return "Key pool is empty, run keypoolrefill first.";
    CScript scriptSelf;
    scriptSelf.SetDestination(vchPubKey.GetID());

    std::vector<std::pair<CScript, int64_t> > vecSend;
    vecSend.push_back(std::make_pair(scriptSelf, (int64_t)POD_STAMP_SELFPAY));
    vecSend.push_back(std::make_pair(scriptStamp, (int64_t)0));

    int64_t nFeeRequired = 0;
    int32_t nChangePos = -1;
    if (!pwallet->CreateTransaction(vecSend, wtxNew, changekey, nFeeRequired, nChangePos))
    {
        stampkey.ReturnKey();
        if (POD_STAMP_SELFPAY + nFeeRequired > pwallet->GetBalance())
            return strprintf("Insufficient funds: a stamp needs %s spendable (returned to you) "
                             "plus a fee of at least %s.",
                             FormatMoney(POD_STAMP_SELFPAY).c_str(),
                             FormatMoney(nFeeRequired).c_str());
        return "Transaction creation failed.";
    }

    // Check the relay rule the stamp depends on rather than trusting the builder:
    // IsStandardTx rejects nDataOut > nTxnOut, and counts only nulldata as data.
    unsigned int nDataOut = 0, nTxnOut = 0;
    for (unsigned int i = 0; i < wtxNew.vout.size(); i++)
    {
        txnouttype whichType;
        std::vector<std::vector<unsigned char> > vSolutions;
        if (Solver(wtxNew.vout[i].scriptPubKey, whichType, vSolutions)
            && whichType == TX_NULL_DATA)
            nDataOut++;
        else
            nTxnOut++;
    }
    if (nDataOut > nTxnOut)
    {
        stampkey.ReturnKey();
        return "Transaction creation failed: the stamp would not have relayed.";
    }

    stampkey.KeepKey();

    if (!pwallet->CommitTransaction(wtxNew, changekey))
        return "The transaction was rejected. This can happen if coins in this wallet "
               "were already spent elsewhere.";

    return "";
}

void PodRequireFileRpc(const char* pszRpcName)
{
    if (GetBoolArg("-enablefilerpc", false))
        return;

    throw JSONRPCError(RPC_MISC_ERROR,
        strprintf("%s reads a file from this node's filesystem and publishes what it finds. "
                  "It is disabled by default. Start innovad with -enablefilerpc=1 "
                  "(or set enablefilerpc=1 in innova.conf) to allow it.", pszRpcName));
}

std::string PodHyperfileDisclosure()
{
    return "Hyperfile uploads the file to IPFS. IPFS content is public and, once pinned or "
           "cached by any peer, effectively permanent - it cannot be recalled. The default "
           "endpoint ipfs.innova-foundation.com:5001 is operated by the Innova Foundation, "
           "whose operator sees the file contents and the uploading node's IP address. "
           "Set -hyperfileip to your own IPFS node to avoid that. proofofdata uploads nothing: "
           "it hashes the file locally and publishes only the digest.";
}
