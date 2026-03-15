// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// lock ordering requirements:
//   cs_main -> cs_wallet -> cs_spvutxos (never reverse)
//   LOCK2(cs_main, cs_wallet) is the standard pattern used throughout.
//   cs_wallet alone is acceptable when cs_main is not needed.
//   cs_spvutxos is always acquired last when needed.

#include "txdb.h"
#include "wallet.h"
#include "walletdb.h"
#include "crypter.h"
#include "ui_interface.h"
#include "base58.h"
#include "kernel.h"
#include "coincontrol.h"
#include "spork.h"
#include "collateral.h"
#include "collateralnode.h"
#include "bloom.h"
#include "namecoin.h"
#include "silentpayments.h"
#include "nullstake.h"
#include "curvetree.h"
#include "lelantus.h"
#include <openssl/crypto.h>  
#include <boost/algorithm/string/replace.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/numeric/ublas/matrix.hpp>

#if BOOST_VERSION >= 107300
#include <boost/bind/bind.hpp>
using boost::placeholders::_1;
using boost::placeholders::_2;
#else
#include <boost/bind.hpp>
#endif

using namespace std;

unsigned int nStakeSplitAge = 1 * 24 * 60 * 60;
int64_t nStakeCombineThreshold = 1000 * COIN;
int64_t nStakeMinSplitThreshold = 100 * COIN;

int64_t gcd(int64_t n,int64_t m) { return m == 0 ? n : gcd(m, n % m); }
static uint64_t CoinWeightCost(const COutput &out)
{
    int64_t nTimeWeight = (int64_t)GetTime() - (int64_t)out.tx->nTime;
    CBigNum bnCoinDayWeight = CBigNum(out.tx->vout[out.i].nValue) * nTimeWeight / (24 * 60 * 60);
    return bnCoinDayWeight.getuint64();
}

//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

struct CompareValueOnly
{
    bool operator()(const pair<int64_t, pair<const CWalletTx*, unsigned int> >& t1,
                    const pair<int64_t, pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

CPubKey CWallet::GenerateNewKey()
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    RandAddSeedPerfmon();
    CKey key;
    key.MakeNewKey(fCompressed);

    if (!key.IsValid())
        throw std::runtime_error("CWallet::GenerateNewKey() : MakeNewKey failed");

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = key.GetPubKey();
    if (!pubkey.IsValid())
        throw std::runtime_error("CWallet::GenerateNewKey() : GetPubKey returned invalid key");

    // Create new metadata
    int64_t nCreationTime = GetTime();
    mapKeyMetadata[pubkey.GetID()] = CKeyMetadata(nCreationTime);
    if (!nTimeFirstKey || nCreationTime < nTimeFirstKey)
        nTimeFirstKey = nCreationTime;

    if (!AddKey(key))
        throw std::runtime_error("CWallet::GenerateNewKey() : AddKey failed");
    return key.GetPubKey();
}

bool CWallet::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata

    if (!CCryptoKeyStore::AddKeyPubKey(key, pubkey))
        return false;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey.GetID());
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);

    if (!fFileBacked)
        return true;
    if (!IsCrypted())
        return CWalletDB(strWalletFile).WriteKey(pubkey, key.GetPrivKey(), mapKeyMetadata[pubkey.GetID()]);
    return true;
}

bool CWallet::AddKeyInDBTxn(CWalletDB* pdb, const CKey& key)
{
    LOCK(cs_KeyStore);
    // -- can't use CWallet::AddKey(), as in a db transaction
    //    hack: pwalletdbEncryption CCryptoKeyStore::AddKey calls CWallet::AddCryptedKey
    //    DB Write() uses activeTxn
    CWalletDB *pwalletdbEncryptionOld = pwalletdbEncryption;
    pwalletdbEncryption = pdb;

    if (!CCryptoKeyStore::AddKey(key))
    {
        printf("CCryptoKeyStore::AddKey failed.\n");
        return false;
    };

    CPubKey pubkey = key.GetPubKey();

    pwalletdbEncryption = pwalletdbEncryptionOld;

    if (fFileBacked
        && !IsCrypted())
    {
        if (!pdb->WriteKey(pubkey, key.GetPrivKey(), mapKeyMetadata[pubkey.GetID()]))
        {
            printf("WriteKey() failed.\n");
            return false;
        };
    };
    return true;
};

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}

bool CWallet::LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (meta.nCreateTime && (!nTimeFirstKey || meta.nCreateTime < nTimeFirstKey))
        nTimeFirstKey = meta.nCreateTime;

    mapKeyMetadata[pubkey.GetID()] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

// optional setting to unlock wallet for staking only
// serves to disable the trivial sendmoney when OS account compromised
// provides no real security
bool fWalletUnlockStakingOnly = false;

bool CWallet::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = CBitcoinAddress(redeemScript.GetID()).ToString();
        printf("%s: Warning: This wallet contains a redeemScript of size %" PRIszu" which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n",
            __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr.c_str());
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}

bool CWallet::Lock()
{
    if (IsLocked())
        return true;

    if (fDebug)
        printf("Locking wallet.\n");

    {
        LOCK(cs_wallet);
        CWalletDB wdb(strWalletFile);

        // -- load encrypted spend_secret of stealth addresses
        CStealthAddress sxAddrTemp;
        std::set<CStealthAddress>::iterator it;
        for (it = stealthAddresses.begin(); it != stealthAddresses.end(); ++it)
        {
            if (it->scan_secret.size() < 32)
                continue; // stealth address is not owned
            // -- CStealthAddress are only sorted on spend_pubkey
            CStealthAddress &sxAddr = const_cast<CStealthAddress&>(*it);
            if (fDebug)
                printf("Recrypting stealth key %s\n", sxAddr.Encoded().c_str());

            sxAddrTemp.scan_pubkey = sxAddr.scan_pubkey;
            if (!wdb.ReadStealthAddress(sxAddrTemp))
            {
                printf("Error: Failed to read stealth key from db %s\n", sxAddr.Encoded().c_str());
                continue;
            }
            sxAddr.spend_secret = sxAddrTemp.spend_secret;
        };
    }
    return LockKeyStore();
};

bool CWallet::AddWatchOnly(const CScript &dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    nTimeFirstKey = 1; // No birthday information for watch-only keys.
    NotifyWatchonlyChanged(true);
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteWatchOnly(dest);
}

bool CWallet::RemoveWatchOnly(const CScript &dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (fFileBacked)
        if (!CWalletDB(strWalletFile).EraseWatchOnly(dest))
            return false;

    return true;
}

bool CWallet::LoadWatchOnly(const CScript &dest)
{
    return CCryptoKeyStore::AddWatchOnly(dest);
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        if (!IsLocked())
            return false;

        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (!CCryptoKeyStore::Unlock(vMasterKey))
                return false;

            static const unsigned int MIN_DERIVE_ITERATIONS = 25000;
            if (pMasterKey.second.nDeriveIterations < MIN_DERIVE_ITERATIONS)
            {
                printf("Upgrading legacy wallet encryption from %u to %u iterations\n",
                       pMasterKey.second.nDeriveIterations, MIN_DERIVE_ITERATIONS);

                unsigned int nOldIterations = pMasterKey.second.nDeriveIterations;
                pMasterKey.second.nDeriveIterations = MIN_DERIVE_ITERATIONS;

                CCrypter upgrader;
                if (upgrader.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt,
                                                   pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                {
                    std::vector<unsigned char> vchNewCryptedKey;
                    if (upgrader.Encrypt(vMasterKey, vchNewCryptedKey))
                    {
                        pMasterKey.second.vchCryptedKey = vchNewCryptedKey;
                        CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                        printf("Successfully upgraded and persisted wallet encryption iterations\n");
                    }
                    else
                    {
                        pMasterKey.second.nDeriveIterations = nOldIterations;
                        printf("WARNING: Failed to re-encrypt master key during iteration upgrade\n");
                    }
                }
                else
                {
                    pMasterKey.second.nDeriveIterations = nOldIterations;
                    printf("WARNING: Failed to derive key during iteration upgrade\n");
                }
            }

            break;
        }

        UnlockStealthAddresses(vMasterKey);
		    ProcessLockedAnonOutputs(); //Process Locked Anon Outputs when unlocked, I n n o v a - v3.1
        SecureMsgWalletUnlocked();
        return true;
    }
    return false;
}

void CWallet::LockCoin(COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

bool CWallet::IsSpent(const uint256& hash, unsigned int n) const
{
    AssertLockHeld(cs_wallet);

    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(hash);
    if (it != mapWallet.end())
    {
        if (n >= it->second.vout.size())
            return false;
        return it->second.IsSpent(n);
    }

    if (fHybridSPV)
    {
        // lock ordering: cs_wallet -> cs_spvutxos (never reverse)
        LOCK(cs_spvutxos);
        COutPoint outpoint(hash, n);
        std::map<COutPoint, SPVUtxo>::const_iterator spvIt = mapSPVUtxos.find(outpoint);
        if (spvIt != mapSPVUtxos.end())
        {
            return spvIt->second.fSpent;
        }
    }

    return false;
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();
    bool fResult = false;

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
            {
                if (!vMasterKey.empty())
                    OPENSSL_cleanse(&vMasterKey[0], vMasterKey.size());
                return false;
            }
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
            {
                if (!vMasterKey.empty())
                    OPENSSL_cleanse(&vMasterKey[0], vMasterKey.size());
                return false;
            }
            if (CCryptoKeyStore::Unlock(vMasterKey)
                && UnlockStealthAddresses(vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                printf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                {
                    if (!vMasterKey.empty())
                        OPENSSL_cleanse(&vMasterKey[0], vMasterKey.size());
                    return false;
                }
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                {
                    if (!vMasterKey.empty())
                        OPENSSL_cleanse(&vMasterKey[0], vMasterKey.size());
                    return false;
                }

                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                fResult = true;
            }
            if (!vMasterKey.empty())
                OPENSSL_cleanse(&vMasterKey[0], vMasterKey.size());
            if (fResult)
                return true;
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey(nDerivationMethodIndex);

    RandAddSeedPerfmon();
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    RAND_bytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    printf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin())
                return false;
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked)
                pwalletdbEncryption->TxnAbort();
            return false;
        }

        std::set<CStealthAddress>::iterator it;
        for (it = stealthAddresses.begin(); it != stealthAddresses.end(); ++it)
        {
            if (it->scan_secret.size() < 32)
                continue; // stealth address is not owned
            // -- CStealthAddress is only sorted on spend_pubkey
            CStealthAddress &sxAddr = const_cast<CStealthAddress&>(*it);

            if (fDebug)
                printf("Encrypting stealth key %s\n", sxAddr.Encoded().c_str());

            std::vector<unsigned char> vchCryptedSecret;

            CSecret vchSecret;
            vchSecret.resize(32);
            if (sxAddr.spend_secret.size() != 32)
            {
                printf("EncryptWallet() : stealth spend_secret wrong size %d\n", (int)sxAddr.spend_secret.size());
                continue;
            }
            memcpy(&vchSecret[0], &sxAddr.spend_secret[0], 32);

            uint256 iv = Hash(sxAddr.spend_pubkey.begin(), sxAddr.spend_pubkey.end());
            if (!EncryptSecret(vMasterKey, vchSecret, iv, vchCryptedSecret))
            {
                printf("Error: Failed encrypting stealth key %s\n", sxAddr.Encoded().c_str());
                continue;
            };

            sxAddr.spend_secret = vchCryptedSecret;
            pwalletdbEncryption->WriteStealthAddress(sxAddr);
        };

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit())
            {
                // Keys encrypted in memory but not persisted to disk
                printf("ERROR: EncryptWallet - failed to commit encrypted keys to disk. Wallet may be in inconsistent state.\n");
                delete pwalletdbEncryption;
                pwalletdbEncryption = NULL;
                return false;
            }

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);
        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);

    }
    NotifyStatusChanged(this);

    return true;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

CWallet::TxItems CWallet::OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount, bool fShowCoinstake)
{
    AssertLockHeld(cs_wallet); // mapWallet
    CWalletDB walletdb(strWalletFile);

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-order multimap.
    TxItems txOrdered;

    // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
    // would make this much faster for applications that do this a lot.
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txOrdered.insert(make_pair(wtx->nOrderPos, TxPair(wtx, (CAccountingEntry*)0)));
    }
    acentries.clear();
    walletdb.ListAccountCreditDebit(strAccount, acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txOrdered.insert(make_pair(entry.nOrderPos, TxPair((CWalletTx*)0, &entry)));
    }

    return txOrdered;
}

void CWallet::WalletUpdateSpent(const CTransaction &tx, bool fBlock)
{
    // Anytime a signature is successfully verified, it's proof the outpoint is spent.
    // Update the wallet spent flag if it doesn't know due to wallet.dat being
    // restored from backup or the user making copies of wallet.dat.
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            if (tx.nVersion == ANON_TXN_VERSION
                && txin.IsAnonInput())
            {
                printf("WalletUpdateSpent() : anon input for tx %s\n", tx.GetHash().ToString().c_str());
                continue;
            }

            std::map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
            //map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
            if (mi != mapWallet.end())
            {
                CWalletTx& wtx = (*mi).second;
                if (txin.prevout.n >= wtx.vout.size())
                    printf("WalletUpdateSpent: bad wtx %s\n", wtx.GetHash().ToString().c_str());
                else if (!wtx.IsSpent(txin.prevout.n) && IsMine(wtx.vout[txin.prevout.n]))
                {
                    printf("WalletUpdateSpent found spent coins\n");
                    wtx.MarkSpent(txin.prevout.n);
                    wtx.WriteToDisk();
                    NotifyTransactionChanged(this, txin.prevout.hash, CT_UPDATED);
					vMintingWalletUpdated.push_back(txin.prevout.hash);
                    if (fHybridSPV)
                    {
                        MarkSPVUtxoSpent(txin.prevout);
                    }
                }
            }
        }

        if (fBlock)
        {
            uint256 hash = tx.GetHash();
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(hash);
            if (mi == mapWallet.end())
                return;
            CWalletTx& wtx = (*mi).second;

            BOOST_FOREACH(const CTxOut& txout, tx.vout)
            {
                if (tx.nVersion == ANON_TXN_VERSION
                    && txout.IsAnonOutput())
                {
                    // anon output
                    // TODO
                    continue;
                }
                if (IsMine(txout))
                {
                    wtx.MarkUnspent(&txout - &tx.vout[0]);
                    wtx.WriteToDisk();
                    NotifyTransactionChanged(this, hash, CT_UPDATED);
					vMintingWalletUpdated.push_back(hash);
                }
            }
        }

    }
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
        {
            wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext();

            wtx.nTimeSmart = wtx.nTimeReceived;
            if (wtxIn.hashBlock != 0)
            {
                if (mapBlockIndex.count(wtxIn.hashBlock))
                {
                    unsigned int latestNow = wtx.nTimeReceived;
                    unsigned int latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64_t latestTolerated = latestNow + 300;
                        std::list<CAccountingEntry> acentries;
                        TxItems txOrdered = OrderedTxItems(acentries);
                        for (TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                        {
                            CWalletTx *const pwtx = (*it).second.first;
                            if (pwtx == &wtx)
                                continue;
                            CAccountingEntry *const pacentry = (*it).second.second;
                            int64_t nSmartTime;
                            if (pwtx)
                            {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            }
                            else
                                nSmartTime = pacentry->nTime;
                            if (nSmartTime <= latestTolerated)
                            {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }

                    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(wtxIn.hashBlock);
                    if (mi != mapBlockIndex.end() && mi->second) {
                        unsigned int blocktime = mi->second->nTime;
                        wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                    }
                }
                else
                    printf("AddToWallet() : found %s in block %s not in index\n",
                           wtxIn.GetHash().ToString().substr(0,10).c_str(),
                           wtxIn.hashBlock.ToString().c_str());
            }
        }

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            fUpdated |= wtx.UpdateSpent(wtxIn.vfSpent);
        }

        //// debug print
        printf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString().substr(0,10).c_str(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!wtx.WriteToDisk())
                return false;
#ifndef QT_GUI
        // If default receiving address gets used, replace it with a new one
        if (vchDefaultKey.IsValid()) {
            CScript scriptDefaultKey;
            scriptDefaultKey.SetDestination(vchDefaultKey.GetID());
            BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            {
                if (txout.scriptPubKey == scriptDefaultKey)
                {
                    CPubKey newDefaultKey;
                    if (GetKeyFromPool(newDefaultKey, false))
                    {
                        SetDefaultKey(newDefaultKey);
                        SetAddressBookName(vchDefaultKey.GetID(), "");
                    }
                }
            }
        }
#endif
        // since AddToWallet is called directly for self-originating transactions, check for consumption of own coins
        WalletUpdateSpent(wtx, (wtxIn.hashBlock != 0));

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

		vMintingWalletUpdated.push_back(hash);

        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = GetArg("-walletnotify", "");

        if ( !strCmd.empty())
        {
            boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
            boost::thread t(runCommand, strCmd); // thread runs free
        }

    }
    return true;
}

// Add a transaction to the wallet, or update it.
// pblock is optional, but should be provided if the transaction is known to be in a block.
// If fUpdate is true, existing transactions will be updated.
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fFindBlock)
{
    //printf("AddToWalletIfInvolvingMe() %s\n", hash.ToString().c_str()); // happens often

    uint256 hash = tx.GetHash();
    {
        LOCK(cs_wallet);
        bool fExisted = mapWallet.count(hash);
        if (fExisted && !fUpdate)
        {
            return false;
        };

        mapValue_t mapNarr;
        if (stealthAddresses.size() > 0 && !fDisableStealth) FindStealthTransactions(tx, mapNarr);

        bool fIsMine = false;
        if (tx.nVersion == ANON_TXN_VERSION)
        {
            LOCK(cs_main); // cs_wallet is already locked
            CWalletDB walletdb(strWalletFile, "cr+");
            CTxDB txdb("cr+");

            uint256 blockHash = 0;
            blockHash = pblock ? ((CBlock*)pblock)->GetHash() : 0;

            walletdb.TxnBegin();
            txdb.TxnBegin();
            std::vector<std::map<uint256, CWalletTx>::iterator> vUpdatedTxns;
            if (!ProcessAnonTransaction(&walletdb, &txdb, tx, blockHash, fIsMine, mapNarr, vUpdatedTxns))
            {
                printf("ProcessAnonTransaction failed %s\n", hash.ToString().c_str());
                walletdb.TxnAbort();
                txdb.TxnAbort();
                return false;
            } else
            {
                walletdb.TxnCommit();
                txdb.TxnCommit();
                for (std::vector<std::map<uint256, CWalletTx>::iterator>::iterator it = vUpdatedTxns.begin();
                    it != vUpdatedTxns.end(); ++it)
                    NotifyTransactionChanged(this, (*it)->first, CT_UPDATED);
            };
        };

        bool fShieldedMine = false;
        if (tx.IsShielded())
        {
            LOCK(cs_shielded);
            uint64_t nTreePos = 0;
            uint64_t nCurveLeafPos = 0;
            {
                CTxDB txdb("r");
                txdb.ReadShieldedCommitmentCount(nTreePos);

                int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
                if (nCurrentHeight >= FORK_HEIGHT_FCMP)
                {
                    CCurveTree tmpTree;
                    if (txdb.ReadCurveTree(tmpTree))
                        nCurveLeafPos = tmpTree.nLeafCount;
                }
            }
            if (nTreePos >= tx.vShieldedOutput.size())
                nTreePos -= tx.vShieldedOutput.size();
            if (nCurveLeafPos >= tx.vShieldedOutput.size())
                nCurveLeafPos -= tx.vShieldedOutput.size();

            for (unsigned int i = 0; i < tx.vShieldedOutput.size(); i++)
            {
                CShieldedNote noteOut;
                if (IsShieldedOutputMine(tx.vShieldedOutput[i], noteOut))
                {
                    fShieldedMine = true;
                    fIsMine = true;

                    uint64_t pos = nTreePos + i;
                    bool fDuplicate = false;
                    for (const CShieldedWalletNote& existing : vShieldedNotes)
                    {
                        if (existing.txhash == hash && existing.nPosition == pos)
                        {
                            fDuplicate = true;
                            break;
                        }
                    }
                    if (!fDuplicate)
                    {
                        CShieldedWalletNote wnote;
                        wnote.note = noteOut;
                        wnote.txhash = hash;
                        wnote.nPosition = pos;
                        wnote.fSpent = false;
                        wnote.nHeight = pindexBest ? pindexBest->nHeight : 0;
                        wnote.nLeafIndex = (wnote.nHeight >= FORK_HEIGHT_FCMP) ? (nCurveLeafPos + i) : 0;
                        vShieldedNotes.push_back(wnote);

                        {
                            CWalletDB walletdb(strWalletFile);
                            walletdb.WriteShieldedNote(hash, pos, noteOut, false, wnote.nHeight);
                        }

                        if (fDebug)
                            printf("AddToWalletIfInvolvingMe() : added shielded note in tx %s pos=%u leafIdx=%lu\n",
                                   hash.ToString().substr(0,10).c_str(), (unsigned int)pos, wnote.nLeafIndex);
                    }
                }
            }

            std::map<uint256, size_t> mapNullifierToNoteIndex;
            for (size_t i = 0; i < vShieldedNotes.size(); i++)
            {
                CShieldedWalletNote& wnote = vShieldedNotes[i];
                if (wnote.fSpent)
                    continue;
                for (auto& pair : mapShieldedSpendingKeys)
                {
                    CShieldedFullViewingKey fvk;
                    DeriveShieldedFullViewingKey(pair.second, fvk);
                    uint256 nf = wnote.note.GetNullifier(fvk.nk);
                    mapNullifierToNoteIndex[nf] = i;
                }
            }

            for (const CShieldedSpendDescription& spend : tx.vShieldedSpend)
            {
                std::map<uint256, size_t>::iterator it = mapNullifierToNoteIndex.find(spend.nullifier);
                if (it != mapNullifierToNoteIndex.end())
                {
                    CShieldedWalletNote& wnote = vShieldedNotes[it->second];
                    if (!wnote.fSpent)
                    {
                        wnote.fSpent = true;

                        {
                            CWalletDB walletdb(strWalletFile);
                            walletdb.WriteShieldedNoteSpent(wnote.txhash, wnote.nPosition, true);
                        }

                        if (fDebug)
                            printf("AddToWalletIfInvolvingMe() : shielded note spent by nullifier %s\n",
                                   spend.nullifier.ToString().substr(0,10).c_str());
                    }
                }
            }
        }

        if (fExisted || fIsMine || fShieldedMine || IsMine(tx) || IsFromMe(tx))
        {
            CWalletTx wtx(this, tx);

            if (!mapNarr.empty())
                wtx.mapValue.insert(mapNarr.begin(), mapNarr.end());

            // Get merkle branch if transaction was found in a block
            const CBlock* pcblock = (CBlock*)pblock;
            if (pcblock)
                wtx.SetMerkleBranch(pcblock);

            return AddToWallet(wtx); //AddToWallet(wtx, hash);
        } else
        {
            WalletUpdateSpent(tx);
        };
    }
    return false;
}

bool CWallet::EraseFromWallet(uint256 hash)
{
    if (!fFileBacked)
        return false;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return true;
}


isminetype CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                return IsMine(prev.vout[txin.prevout.n]);
        }
    }
    return MINE_NO;
}

int64_t CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]) & filter)
                    return prev.vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

int64_t CWallet::GetAnonDebit(const CTxIn& txin) const
{
    if (!txin.IsAnonInput())
        return 0;

    // -- amount of owned innova decreased
    // TODO: store links in memory

    {
        LOCK(cs_wallet);

        CWalletDB walletdb(strWalletFile, "r");

        std::vector<uint8_t> vchImage;
        txin.ExtractKeyImage(vchImage);

        COwnedAnonOutput oao;
        if (!walletdb.ReadOwnedAnonOutput(vchImage, oao))
            return 0;
        //return oao.nValue

        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(oao.outpoint.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (oao.outpoint.n < prev.vout.size())
                return prev.vout[oao.outpoint.n].nValue;
        };

    }

    return 0;
};

int64_t CWallet::GetAnonCredit(const CTxOut& txout) const
{
    if (!txout.IsAnonOutput())
        return 0;

    // TODO: store links in memory

    const CScript &s = txout.scriptPubKey;

    {
        LOCK(cs_wallet);

        CWalletDB walletdb(strWalletFile, "r");

        CPubKey pkCoin    = CPubKey(&s[2+1], ec_compressed_size);

        std::vector<uint8_t> vchImage;
        if (!walletdb.ReadOwnedAnonOutputLink(pkCoin, vchImage))
            return 0;

        COwnedAnonOutput oao;
        if (!walletdb.ReadOwnedAnonOutput(vchImage, oao))
            return 0;

        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(oao.outpoint.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (oao.outpoint.n < prev.vout.size())
            {
                return prev.vout[oao.outpoint.n].nValue;
            }
        };

    }

    return 0;
};

bool CWallet::IsDenominated(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size()) return IsDenominatedAmount(prev.vout[txin.prevout.n].nValue);
        }
    }
    return false;
}

bool CWallet::IsDenominatedAmount(int64_t nInputAmount) const
{
    BOOST_FOREACH(int64_t d, colLateralDenominations)
        if(nInputAmount == d)
            return true;
    return false;
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    CTxDestination address;

    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (::IsMine(*this, txout.scriptPubKey))
    {
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address) && txout.scriptPubKey[0] != OP_RETURN) //Fix Null TX Data
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase() || IsCoinStake())
        {
            // Generated block
            if (hashBlock != 0)
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && hashBlock != 0)
                {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(list<COutputEntry>& listReceived,
                           list<COutputEntry>& listSent, int64_t& nFee, string& strSentAccount, const isminefilter& filter, bool ignoreNameTx) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    int64_t nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        int64_t nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    };

    // treat coinstake as a single "recieve" entry
    if (IsCoinStake())
    {
        for (unsigned int i = 0; i < vout.size(); ++i)
        {
            const CTxOut& txout = vout[i];
            isminetype fIsMine = pwallet->IsMine(txout);

            // get my vout with positive output
            if (!(fIsMine & filter) || txout.nValue <= 0)
                        continue;

            // get address
            CTxDestination address = CNoDestination();
            ExtractDestination(txout.scriptPubKey, address);

            // nfee is negative for coinstake generation, because we are gaining money from it
            COutputEntry output = {address, -nFee, (int)i};
            listReceived.push_back(output);
            nFee = 0;
            return;
        }

        // if we reach here there is probably a mistake
        COutputEntry output = {CNoDestination(), 0, 0};
        listReceived.push_back(output);
        return;
    }

	// Sent/received.
    for (unsigned int i = 0; i < vout.size(); ++i)
    {
		const CTxOut& txout = vout[i];
        if (nVersion == ANON_TXN_VERSION
            && txout.IsAnonOutput())
        {
            const CScript &s = txout.scriptPubKey;
            CKeyID ckidD = CPubKey(&s[2+1], 33).GetID();

            bool fIsMine = pwallet->HaveKey(ckidD);

            CTxDestination address = ckidD;

			COutputEntry output = {address, txout.nValue, (int)i};

            // If we are debited by the transaction, add the output as a "sent" entry
            if (nDebit > 0)
                listSent.push_back(output);

            // If we are receiving the output, add it as a "received" entry
            if (fIsMine || (!ignoreNameTx && hooks->IsMine(txout)))
                listReceived.push_back(output);

            continue;
        };

		// Skip special stake out
        if (txout.scriptPubKey.empty())
            continue;

        opcodetype firstOpCode;
        CScript::const_iterator pc = txout.scriptPubKey.begin();
        if (txout.scriptPubKey.GetOp(pc, firstOpCode)
            && firstOpCode == OP_RETURN)
            continue;


        bool fIsMine;
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
            fIsMine = pwallet->IsMine(txout);
        } else
        if (!(fIsMine = pwallet->IsMine(txout)))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
        {
            printf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                this->GetHash().ToString().c_str());
            address = CNoDestination();
        };

		COutputEntry output = {address, txout.nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine || (!ignoreNameTx && hooks->IsMine(txout)))
            listReceived.push_back(output);
    };
}

void CWalletTx::GetAccountAmounts(const string& strAccount, int64_t& nReceived,
                                  int64_t& nSent, int64_t& nFee, const isminefilter& filter) const
{
    nReceived = nSent = nFee = 0;

    int64_t allFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);

    if (strAccount == strSentAccount)
    {
        BOOST_FOREACH(const COutputEntry& s, listSent)
            nSent += s.amount;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        BOOST_FOREACH(const COutputEntry& r, listReceived)
        {
            if (pwallet->mapAddressBook.count(r.destination))
            {
                map<CTxDestination, string>::const_iterator mi = pwallet->mapAddressBook.find(r.destination);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second == strAccount)
                    nReceived += r.amount;
            }
            else if (strAccount.empty())
            {
                nReceived += r.amount;
            }
        }
    }
}

void CWalletTx::AddSupportingTransactions(CTxDB& txdb)
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        BOOST_FOREACH(const CTxIn& txin, vin)
            vWorkQueue.push_back(txin.prevout.hash);

        // This critsect is OK because txdb is already open
        {
            LOCK(pwallet->cs_wallet);
            map<uint256, const CMerkleTx*> mapWalletPrev;
            set<uint256> setAlreadyDone;
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hash = vWorkQueue[i];
                if (setAlreadyDone.count(hash))
                    continue;
                setAlreadyDone.insert(hash);

                CMerkleTx tx;
                map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(hash);
                if (mi != pwallet->mapWallet.end())
                {
                    tx = (*mi).second;
                    BOOST_FOREACH(const CMerkleTx& txWalletPrev, (*mi).second.vtxPrev)
                        mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
                }
                else if (mapWalletPrev.count(hash))
                {
                    tx = *mapWalletPrev[hash];
                }
                else if (txdb.ReadDiskTx(hash, tx))
                {
                    ;
                }
                else
                {
                    printf("ERROR: AddSupportingTransactions() : unsupported transaction\n");
                    continue;
                }

                int nDepth = tx.SetMerkleBranch();
                vtxPrev.push_back(tx);

                if (nDepth < COPY_DEPTH)
                {
                    BOOST_FOREACH(const CTxIn& txin, tx.vin)
                        vWorkQueue.push_back(txin.prevout.hash);
                }
            }
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}

bool CWalletTx::WriteToDisk()
{
    return CWalletDB(pwallet->strWalletFile).WriteTx(GetHash(), *this);
}

// Scan the block chain (starting in pindexStart) for transactions
// from or to us. If fUpdate is true, found transactions that already
// exist in the wallet will be updated.
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    int ret = 0;

    CBlockIndex* pindex = pindexStart;
    {

        int dProgressTop;
        {
            LOCK(cs_main);
            dProgressTop = pindexBest->nHeight;
        }

        int dProgressStart = pindex ? pindex->nHeight : 0;
        int dProgressCurrent = dProgressStart;
        int dProgressTotal =  dProgressTop - dProgressStart;
        double dProgressShow = 0;
        double dProgressShowPrev = 0;

        while (pindex && !fShutdown)
        {
            if (dProgressCurrent > 0)
                dProgressShow = ((static_cast<double>(dProgressCurrent) / dProgressTop) * 100.0);

            if ((pindex->nHeight % 100 == 0) && (dProgressTotal > 0))
            {
                if (dProgressShowPrev != dProgressShow)
                {
                    dProgressShowPrev = dProgressShow;
                    uiInterface.InitMessage(strprintf("%s %d/%d %s... (%.2f%%)",_("Rescanning").c_str(), dProgressCurrent , dProgressTop,_("blocks").c_str(),dProgressShow));
                }
            }
            // no need to read and scan block, if block was created before
            // our wallet birthday (as adjusted for block time variability)
            if (nTimeFirstKey && (pindex->nTime < (nTimeFirstKey - 7200))) {
                pindex = pindex->pnext;
                continue;
            }

            CBlock block;
            block.ReadFromDisk(pindex, true);
            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                LOCK(cs_wallet);
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    ret++;
            }
            pindex = pindex->pnext;

            // Update current height for progress
            if (pindex) dProgressCurrent = pindex->nHeight;

        }

        uiInterface.InitMessage(_("Rescanning complete."));
    }
    return ret;
}

/*
void CWallet::ReacceptWalletTransactions()
{
    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
    {
        const uint256& wtxid = item.first;
        CWalletTx& wtx = item.second;
        if (wtx.GetHash() != wtxid)
        {
            printf("ERROR: ResendWalletTransactions: hash mismatch for tx %s\n", wtxid.ToString().c_str());
            continue;
        }

        int nDepth = wtx.GetDepthInMainChain();

        if (!wtx.IsCoinBase() || wtx.IsCoinStake() && nDepth < 0)
        {
            // Try to add to memory pool
            LOCK(mempool.cs);
            wtx.AcceptToMemoryPool(false);
        }
    }
}*/

void CWallet::ReacceptWalletTransactions()
{
    CTxDB txdb("r");
    bool fRepeat = true;
    while (fRepeat)
    {
        LOCK2(cs_main, cs_wallet);
        fRepeat = false;
        vector<CDiskTxPos> vMissingTx;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if (wtx.IsCoinBase() && wtx.IsSpent(0))
                continue;
            if (wtx.IsCoinStake() && wtx.vout.size() > 1 && wtx.IsSpent(1))
                continue;

            CTxIndex txindex;
            bool fUpdated = false;
            if (txdb.ReadTxIndex(wtx.GetHash(), txindex))
            {
                // Update fSpent if a tx got spent somewhere else by a copy of wallet.dat
                if (txindex.vSpent.size() != wtx.vout.size())
                {
                    printf("ERROR: ReacceptWalletTransactions() : txindex.vSpent.size() %" PRIszu" != wtx.vout.size() %" PRIszu"\n", txindex.vSpent.size(), wtx.vout.size());
                    continue;
                }
                for (unsigned int i = 0; i < txindex.vSpent.size(); i++)
                {
                    if (wtx.IsSpent(i))
                        continue;
                    if (!txindex.vSpent[i].IsNull() && IsMine(wtx.vout[i]))
                    {
                        wtx.MarkSpent(i);
                        fUpdated = true;
                        vMissingTx.push_back(txindex.vSpent[i]);
                        if (fHybridSPV)
                        {
                            COutPoint outpoint(wtx.GetHash(), i);
                            MarkSPVUtxoSpent(outpoint);
                        }
                    }
                }
                if (fUpdated)
                {
                    printf("ReacceptWalletTransactions found spent coins\n");
                    wtx.MarkDirty();
                    wtx.WriteToDisk();
                }
            }
            else
            {
                // Re-accept any txes of ours that aren't already in a block
                if (!(wtx.IsCoinBase() || wtx.IsCoinStake()))
                    wtx.AcceptWalletTransaction(txdb);
            }
        }
        if (!vMissingTx.empty())
        {
            // TODO: optimize this to scan just part of the block chain?
            if (ScanForWalletTransactions(pindexGenesisBlock))
                fRepeat = true;  // Found missing transactions: re-do re-accept.
        }
    }
}


void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
    BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
    {
        if (!(tx.IsCoinBase() || tx.IsCoinStake()))
        {
            uint256 hash = tx.GetHash();
            if (!txdb.ContainsTx(hash))
                RelayTransaction((CTransaction)tx, hash);
        }
    }
    if (!(IsCoinBase() || IsCoinStake()))
    {
        uint256 hash = GetHash();
        if (!txdb.ContainsTx(hash))
        {
            printf("Relaying wtx %s\n", hash.ToString().substr(0,10).c_str());
            RelayTransaction((CTransaction)*this, hash);
        }
    }
}

void CWalletTx::RelayWalletTransaction()
{
   CTxDB txdb("r");
   RelayWalletTransaction(txdb);
}

void CWallet::ResendWalletTransactions(bool fForce)
{
    if (!fForce)
    {
        // Do this infrequently and randomly to avoid giving away
        // that these are our transactions.
        static int64_t nNextTime;
        if (GetTime() < nNextTime)
            return;
        bool fFirst = (nNextTime == 0);
        nNextTime = GetTime() + GetRand(30 * 60);
        if (fFirst)
            return;

        // Only do it if there's been a new block since last time
        static int64_t nLastTime;
        if (nTimeBestReceived < nLastTime)
            return;
        nLastTime = GetTime();
    }

    // Rebroadcast any of our txes that aren't in a block yet
    printf("ResendWalletTransactions()\n");
    CTxDB txdb("r");
    {
        LOCK(cs_wallet);
        // Sort them in chronological order
        multimap<unsigned int, CWalletTx*> mapSorted;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            // Don't rebroadcast until it's had plenty of time that
            // it should have gotten in already by now.
            if (fForce || nTimeBestReceived - (int64_t)wtx.nTimeReceived > 5 * 60)
                mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
        }
        BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
        {
            CWalletTx& wtx = *item.second;
            if (wtx.CheckTransaction())
                wtx.RelayWalletTransaction(txdb);
            else
                printf("ResendWalletTransactions() : CheckTransaction failed for transaction %s\n", wtx.GetHash().ToString().c_str());
        }
    }
}






//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


int64_t CWallet::GetBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
            {
                int64_t nCredit = pcoin->GetAvailableCredit();
                if (nCredit > 0 && nTotal > std::numeric_limits<int64_t>::max() - nCredit)
                {
                    printf("ERROR: GetBalance() : balance overflow detected\n");
                    return std::numeric_limits<int64_t>::max();
                }
                nTotal += nCredit;
            }
        }
    }

    return nTotal;
}

int64_t CWallet::GetAnonBalance() const
{
    int64_t nTotal = 0;

    {
        LOCK2(cs_main, cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted() && pcoin->nVersion == ANON_TXN_VERSION)
            {
                int64_t nCredit = pcoin->GetAvailableAnonCredit();
                if (nCredit > 0 && nTotal > std::numeric_limits<int64_t>::max() - nCredit)
                    return std::numeric_limits<int64_t>::max();
                nTotal += nCredit;
            }
        };
    }

    return nTotal;
};

int64_t CWallet::GetUnlockedBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            if (pcoin->IsTrusted() && pcoin->GetDepthInMainChain() > 0)
            {
                int64_t nCredit = pcoin->GetUnlockedCredit();
                if (nCredit > 0 && nTotal > std::numeric_limits<int64_t>::max() - nCredit)
                    return std::numeric_limits<int64_t>::max();
                nTotal += nCredit;
            }
        }
    }

    return nTotal;
}

int64_t CWallet::GetLockedBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            if (pcoin->IsTrusted() && pcoin->GetDepthInMainChain() > 0)
            {
                int64_t nCredit = pcoin->GetLockedCredit();
                if (nCredit > 0 && nTotal > std::numeric_limits<int64_t>::max() - nCredit)
                    return std::numeric_limits<int64_t>::max();
                nTotal += nCredit;
            }
        }
    }
    return nTotal;
}

int64_t CWallet::GetUnconfirmedBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0))
            {
                int64_t nCredit = pcoin->GetAvailableCredit();
                if (nCredit > 0 && nTotal > std::numeric_limits<int64_t>::max() - nCredit)
                    return std::numeric_limits<int64_t>::max();
                nTotal += nCredit;
            }
        }
    }
    return nTotal;
}

int64_t CWallet::GetImmatureBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0 && pcoin->IsInMainChain())
            {
                int64_t nCredit = pcoin->GetImmatureCredit();
                if (nCredit > 0 && nTotal > std::numeric_limits<int64_t>::max() - nCredit)
                    return std::numeric_limits<int64_t>::max();
                nTotal += nCredit;
            }
        }
    }
    return nTotal;
}

int64_t CWallet::GetWatchOnlyBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
            {
                int64_t nCredit = pcoin->GetAvailableWatchOnlyCredit();
                if (nCredit > 0 && nTotal > std::numeric_limits<int64_t>::max() - nCredit)
                    return std::numeric_limits<int64_t>::max();
                nTotal += nCredit;
            }
        }
    }

    return nTotal;
}

int64_t CWallet::GetUnconfirmedWatchOnlyBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!IsFinalTx(*pcoin) || (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0))
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }
    return nTotal;
}

int64_t CWallet::GetImmatureWatchOnlyBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0 && pcoin->IsInMainChain())
                nTotal += pcoin->GetImmatureWatchOnlyCredit();
        }
    }
    return nTotal;
}

CBloomFilter* CWallet::CreateSPVBloomFilter(double nFPRate, unsigned int nFlags) const
{
    LOCK(cs_wallet);

    unsigned int nElements = 0;
    nElements += setKeyPool.size();
    nElements += mapKeyMetadata.size();
    nElements += mapAddressBook.size();

    if (nElements < 10)
        nElements = 10;

    CBloomFilter* pfilter = new CBloomFilter(nElements, nFPRate, GetRandInt(std::numeric_limits<int>::max()), nFlags);

    std::set<CKeyID> setKeys;
    GetKeys(setKeys);
    for (const CKeyID& keyid : setKeys)
    {
        std::vector<unsigned char> vchPubKeyHash(keyid.begin(), keyid.end());
        pfilter->insert(vchPubKeyHash);
    }

    for (const std::pair<CTxDestination, std::string>& item : mapAddressBook)
    {
        const CTxDestination& dest = item.first;
        if (const CKeyID* keyid = boost::get<CKeyID>(&dest))
        {
            std::vector<unsigned char> vchPubKeyHash(keyid->begin(), keyid->end());
            pfilter->insert(vchPubKeyHash);
        }
        else if (const CScriptID* scriptid = boost::get<CScriptID>(&dest))
        {
            std::vector<unsigned char> vchScriptHash(scriptid->begin(), scriptid->end());
            pfilter->insert(vchScriptHash);
        }
    }

    for (const CStealthAddress& sxAddr : stealthAddresses)
    {
        if (sxAddr.scan_pubkey.size() >= 20)
        {
            uint160 hash = Hash160(sxAddr.scan_pubkey);
            std::vector<unsigned char> vchHash(hash.begin(), hash.end());
            pfilter->insert(vchHash);
        }
    }

    printf("SPV: Created bloom filter with %u elements, FP rate %.6f\n", nElements, nFPRate);
    return pfilter;
}

bool CWallet::ProcessMerkleBlock(const CMerkleBlock& merkleBlock, std::vector<uint256>& vMatch)
{
    CPartialMerkleTree txnCopy = merkleBlock.txn;

    uint256 merkleRoot = txnCopy.ExtractMatches(vMatch);

    if (merkleRoot != merkleBlock.header.hashMerkleRoot)
    {
        printf("SPV: Merkle root mismatch in block\n");
        return false;
    }

    if (fDebug)
        printf("SPV: Merkle block validated with %u matching transactions\n", (unsigned int)vMatch.size());

    return true;
}

void CWallet::RequestSPVTransactions(CNode* pnode, int nStartHeight)
{
    if (!pnode)
        return;

    LOCK(cs_main);

    CBloomFilter* pfilter = CreateSPVBloomFilter(0.0001, BLOOM_UPDATE_ALL);
    if (pfilter)
    {
        pnode->PushMessage("filterload", *pfilter);
        printf("SPV: Sent bloom filter to peer %s\n", pnode->addr.ToString().c_str());

        CBlockIndex* pindex = pindexGenesisBlock;
        if (nStartHeight > 0)
        {
            pindex = pindexBest;
            while (pindex && pindex->nHeight > nStartHeight)
                pindex = pindex->pprev;
        }

        if (pindex)
        {
            pnode->PushGetBlocks(pindex, uint256(0));
            printf("SPV: Requested filtered blocks from height %d\n", pindex->nHeight);
        }

        delete pfilter;
    }
}

// populate vCoins with vector of spendable COutputs
// coin availability is checked under LOCK2(cs_main, cs_wallet).
// Callers that use the result for spending (e.g. CreateTransaction) must also hold
// cs_wallet to prevent TOCTOU race between availability check and coin reservation.
void CWallet::AvailableCoins(vector<COutput>& vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl) const
{
    vCoins.clear();

    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            if (!pcoin->IsFinal())
                continue;

            if (fOnlyConfirmed && !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            if(pcoin->IsCoinStake() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0)
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                // ignore Innova Name TxOut
                if (pcoin->nVersion == NAMECOIN_TX_VERSION && hooks->IsNameScript(pcoin->vout[i].scriptPubKey))
                    continue;

                isminetype mine = IsMine(pcoin->vout[i]);
                if (!(pcoin->IsSpent(i)) && mine != MINE_NO &&
                    !IsLockedCoin((*it).first, i) && pcoin->vout[i].nValue >= nMinimumInputValue &&
                    (!coinControl || !coinControl->HasSelected() || coinControl->IsSelected((*it).first, i)))
                        vCoins.push_back(COutput(pcoin, i, nDepth, (mine & ISMINE_SPENDABLE) != ISMINE_NO));
            }

        }
    }
}

void CWallet::AvailableCoinsMN(vector<COutput>& vCoins, bool fOnlyConfirmed, bool fOnlyUnlocked, const CCoinControl *coinControl, AvailableCoinsType coin_type) const
{
    vCoins.clear();

    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            if (!pcoin->IsFinal())
                continue;

            if (fOnlyConfirmed && !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            if(pcoin->IsCoinStake() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth <= 0) // NOTE: coincontrol fix / ignore 0 confirm
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                bool found = false;
                if(coin_type == ONLY_DENOMINATED) {
                    //should make this a vector

                    found = IsDenominatedAmount(pcoin->vout[i].nValue);
                } else if(coin_type == ONLY_NONDENOMINATED || coin_type == ONLY_NONDENOMINATED_NOTMN) {
                    found = true;
                    if (IsCollateralAmount(pcoin->vout[i].nValue)) continue; // do not use collateral amounts
                    found = !IsDenominatedAmount(pcoin->vout[i].nValue);
                    if(found && coin_type == ONLY_NONDENOMINATED_NOTMN) found = (pcoin->vout[i].nValue != GetMNCollateral()*COIN); // do not use MN funds 25,000 INN
                } else {
                    found = true;
                }
                if(!found) continue;

                if (fOnlyUnlocked)
                {
                    if (IsLockedCoin(pcoin->GetHash(),i))
                        continue;
                }

				        //isminetype mine = IsMine(pcoin->vout[i]);
		            bool mine = IsMine(pcoin->vout[i]);

                    if (!(pcoin->IsSpent(i)) && pcoin->vout[i].nValue > 0 &&
                    (!coinControl || !coinControl->HasSelected() || coinControl->IsSelected((*it).first, i)))
                        vCoins.push_back(COutput(pcoin, i, nDepth, mine));
            }
        }
    }
}

void CWallet::AvailableCoinsForStaking(vector<COutput>& vCoins, unsigned int nSpendTime) const
{
    vCoins.clear();

    {
        AssertLockHeld(cs_main);
        AssertLockHeld(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            // Filtering by tx timestamp instead of block timestamp may give false positives but never false negatives
            if (pcoin->nTime + nStakeMinAge > nSpendTime)
                continue;

            if (pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 1)
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            {
                if (pcoin->nVersion == ANON_TXN_VERSION
                    && pcoin->vout[i].IsAnonOutput())
                    continue;
                if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) && pcoin->vout[i].nValue >= nMinimumInputValue
                        && !IsLockedCoin((*it).first, i) // ignore outputs that are locked for MNs
                        )
					          vCoins.push_back(COutput(pcoin, i, nDepth, true));
            };
        };
    }
}

static void ApproximateBestSubset(vector<pair<int64_t, pair<const CWalletTx*,unsigned int> > >vValue, int64_t nTotalLower, int64_t nTargetValue,
                                  vector<char>& vfBest, int64_t& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64_t nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                if (nPass == 0 ? (GetRandInt(2) == 0) : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

// innova: total coins available for staking - WIP needs updating
int64_t CWallet::GetStakeAmount() const
{
    int64_t nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted() && pcoin->GetDepthInMainChain() > 0) //Just pulls GetBalance() currently
                nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}

int64_t CWallet::GetStake() const
{
    int64_t nTotal = 0;
    LOCK2(cs_main, cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx* pcoin = &(*it).second;
        if (pcoin->IsCoinStake() && pcoin->GetBlocksToMaturity() > 0 && pcoin->GetDepthInMainChain() > 0)
            nTotal += pcoin->GetCredit(ISMINE_SPENDABLE);
    }
    return nTotal;
}

int64_t CWallet::GetNewMint() const
{
    int64_t nTotal = 0;
    LOCK2(cs_main, cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx* pcoin = &(*it).second;
        if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0 && pcoin->GetDepthInMainChain() > 0)
            nTotal += pcoin->GetCredit(ISMINE_SPENDABLE);
    }
    return nTotal;
}


struct LargerOrEqualThanThreshold
{
    int64_t threshold;
    LargerOrEqualThanThreshold(int64_t threshold) : threshold(threshold) {}
    bool operator()(pair<pair<int64_t,int64_t>,pair<const CWalletTx*,unsigned int> > const &v) const { return v.first.first >= threshold; }
};

bool CWallet::SelectCoinsMinConfByCoinAge(int64_t nTargetValue, unsigned int nSpendTime, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    vector<pair<COutput, uint64_t> > mCoins;
    BOOST_FOREACH(const COutput& out, vCoins)
    {
        mCoins.push_back(std::make_pair(out, CoinWeightCost(out)));
    }

    // List of values less than target
    pair<pair<int64_t,int64_t>, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
    coinLowestLarger.first.second = std::numeric_limits<int64_t>::max();
    coinLowestLarger.second.first = NULL;
    vector<pair<pair<int64_t,int64_t>,pair<const CWalletTx*,unsigned int> > > vValue;
    int64_t nTotalLower = 0;
    boost::sort(mCoins, boost::bind(&std::pair<COutput, uint64_t>::second, _1) < boost::bind(&std::pair<COutput, uint64_t>::second, _2));

    BOOST_FOREACH(const PAIRTYPE(COutput, uint64_t)& output, mCoins)
    {
        const CWalletTx *pcoin = output.first.tx;

        if (output.first.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        int i = output.first.i;

        // Follow the timestamp rules
        if (pcoin->nTime > nSpendTime)
            continue;

        int64_t n = pcoin->vout[i].nValue;

        // ignore Innova Name TxOut
        if (pcoin->nVersion == NAMECOIN_TX_VERSION && hooks->IsNameScript(pcoin->vout[i].scriptPubKey))
            continue;

        pair<pair<int64_t,int64_t>,pair<const CWalletTx*,unsigned int> > coin = make_pair(make_pair(n,output.second),make_pair(pcoin, i));

        if (n < nTargetValue + CENT)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (output.second < (uint64_t)coinLowestLarger.first.second)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first.first;
        return true;
    }

    // Calculate dynamic programming matrix
    if (vValue.empty())
        return false;  // Safety check - prevent crash on empty vValue
    int64_t nTotalValue = vValue[0].first.first;
    int64_t nGCD = vValue[0].first.first;
    for (unsigned int i = 1; i < vValue.size(); ++i)
    {
        nGCD = gcd(vValue[i].first.first, nGCD);
        nTotalValue += vValue[i].first.first;
    }
    nGCD = gcd(nTargetValue, nGCD);
    int64_t denom = nGCD;
    const int64_t k = 25;
    int64_t nExcess = nTotalValue - nTargetValue;
    int64_t approx;
    if (nExcess > 0 && (int64_t)vValue.size() <= std::numeric_limits<int64_t>::max() / nExcess)
        approx = int64_t(vValue.size() * nExcess) / k;
    else
        approx = std::numeric_limits<int64_t>::max();
    if (approx > nGCD)
    {
        denom = approx; // apply approximation
    }
    if (fDebug) cerr << "nGCD " << nGCD << " denom " << denom << " k " << k << endl;

    if (nTotalValue == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
        }
        nValueRet = nTotalValue;
        return true;
    }

    size_t nBeginBundles = vValue.size();
    size_t nTotalCoinValues = vValue.size();
    size_t nBeginCoinValues = 0;
    int64_t costsum = 0;
    vector<vector<pair<pair<int64_t,int64_t>,pair<const CWalletTx*,unsigned int> > >::iterator> vZeroValueBundles;
    if (denom != nGCD)
    {
        // All coin outputs that with zero value will always be added by the dynamic programming routine
        // So we collect them into bundles of value denom
        vector<pair<pair<int64_t,int64_t>,pair<const CWalletTx*,unsigned int> > >::iterator itZeroValue = std::stable_partition(vValue.begin(), vValue.end(), LargerOrEqualThanThreshold(denom));
        vZeroValueBundles.push_back(itZeroValue);
        pair<int64_t, int64_t> pBundle = make_pair(0, 0);
        nBeginBundles = itZeroValue - vValue.begin();
        nTotalCoinValues = nBeginBundles;
        while (itZeroValue != vValue.end())
        {
            pBundle.first += itZeroValue->first.first;
            pBundle.second += itZeroValue->first.second;
            itZeroValue++;
            if (pBundle.first >= denom)
            {
                vZeroValueBundles.push_back(itZeroValue);
                vValue[nTotalCoinValues].first = pBundle;
                pBundle = make_pair(0, 0);
                nTotalCoinValues++;
            }
        }
        // We need to recalculate the total coin value due to truncation of integer division
        nTotalValue = 0;
        for (unsigned int i = 0; i < nTotalCoinValues; ++i)
        {
            nTotalValue += vValue[i].first.first / denom;
        }
        // Check if dynamic programming is still applicable with the approximation
        if (nTargetValue/denom >= nTotalValue)
        {
            // We lose too much coin value through the approximation, i.e. the residual of the previous recalculation is too large
            // Since the partitioning of the previously sorted list is stable, we can just pick the first coin outputs in the list until we have a valid target value
            for (; nBeginCoinValues < nTotalCoinValues && (nTargetValue - nValueRet)/denom >= nTotalValue; ++nBeginCoinValues)
            {
                if (nBeginCoinValues >= nBeginBundles)
                {
                    if (fDebug) cerr << "prepick bundle item " << FormatMoney(vValue[nBeginCoinValues].first.first) << " normalized " << vValue[nBeginCoinValues].first.first / denom << " cost " << vValue[nBeginCoinValues].first.second << endl;
                    const size_t nBundle = nBeginCoinValues - nBeginBundles;
                    if (nBundle + 1 < vZeroValueBundles.size()) {
                        for (vector<pair<pair<int64_t,int64_t>,pair<const CWalletTx*,unsigned int> > >::iterator it = vZeroValueBundles[nBundle]; it != vZeroValueBundles[nBundle + 1]; ++it)
                        {
                            setCoinsRet.insert(it->second);
                        }
                    }
                }
                else
                {
                    if (fDebug) cerr << "prepicking " << FormatMoney(vValue[nBeginCoinValues].first.first) << " normalized " << vValue[nBeginCoinValues].first.first / denom << " cost " << vValue[nBeginCoinValues].first.second << endl;
                    setCoinsRet.insert(vValue[nBeginCoinValues].second);
                }
                nTotalValue -= vValue[nBeginCoinValues].first.first / denom;
                nValueRet += vValue[nBeginCoinValues].first.first;
                costsum += vValue[nBeginCoinValues].first.second;
            }
            if (nValueRet >= nTargetValue)
            {
                    if (fDebug) cerr << "Done without dynprog: " << "requested " << FormatMoney(nTargetValue) << "\tnormalized " << nTargetValue/denom + (nTargetValue % denom != 0 ? 1 : 0) << "\tgot " << FormatMoney(nValueRet) << "\tcost " << costsum << endl;
                    return true;
            }
        }
    }
    else
    {
        nTotalValue /= denom;
    }

    uint64_t nAppend = 1;
    if ((nTargetValue - nValueRet) % denom != 0)
    {
        // We need to decrease the capacity because of integer truncation
        nAppend--;
    }

    // The capacity (number of columns) corresponds to the amount of coin value we are allowed to discard
    size_t nMatrixRows = (nTotalCoinValues - nBeginCoinValues) + 1;
    int64_t nColCalc = (nTotalValue - (nTargetValue - nValueRet)/denom) + nAppend;
    size_t nMatrixCols = nColCalc > 0 ? (size_t)nColCalc : 1;

    const size_t nMaxMatrixSize = 5000000;
    if (nMatrixRows * nMatrixCols > nMaxMatrixSize || nMatrixRows == 0 || nMatrixCols == 0) {
        if (fDebug) cerr << "SelectCoinsMinConfByCost: matrix too large or invalid (" << nMatrixRows << "x" << nMatrixCols << "), falling back" << endl;
        return false;
    }

    boost::numeric::ublas::matrix<uint64_t> M(nMatrixRows, nMatrixCols, std::numeric_limits<int64_t>::max());
    boost::numeric::ublas::matrix<unsigned int> B(nMatrixRows, nMatrixCols);
    for (unsigned int j = 0; j < M.size2(); ++j)
    {
        M(0,j) = 0;
    }
    for (unsigned int i = 1; i < M.size1(); ++i)
    {
        uint64_t nWeight = vValue[nBeginCoinValues + i - 1].first.first / denom;
        uint64_t nValue = vValue[nBeginCoinValues + i - 1].first.second;
        //cerr << "Weight " << nWeight << " Value " << nValue << endl;
        for (unsigned int j = 0; j < M.size2(); ++j)
        {
            B(i, j) = j;
            if (nWeight <= j)
            {
                uint64_t nStep = M(i - 1, j - nWeight) + nValue;
                if (M(i - 1, j) >= nStep)
                {
                    M(i, j) = M(i - 1, j);
                }
                else
                {
                    M(i, j) = nStep;
                    B(i, j) = j - nWeight;
                }
            }
            else
            {
                M(i, j) = M(i - 1, j);
            }
        }
    }
    // Trace back optimal solution
    int64_t nPrev = M.size2() - 1;
    for (unsigned int i = M.size1() - 1; i > 0; --i)
    {
        //cerr << i - 1 << " " << vValue[i - 1].second.second << " " << vValue[i - 1].first.first << " " << vValue[i - 1].first.second << " " << nTargetValue << " " << nPrev << " " << (nPrev == B(i, nPrev) ? "XXXXXXXXXXXXXXX" : "") << endl;
        if (nPrev == B(i, nPrev))
        {
            const size_t nValue = nBeginCoinValues + i - 1;
            // Check if this is a bundle
            if (nValue >= nBeginBundles)
            {
                if (fDebug) cerr << "pick bundle item " << FormatMoney(vValue[nValue].first.first) << " normalized " << vValue[nValue].first.first / denom << " cost " << vValue[nValue].first.second << endl;
                const size_t nBundle = nValue - nBeginBundles;
                if (nBundle + 1 < vZeroValueBundles.size()) {
                    for (vector<pair<pair<int64_t,int64_t>,pair<const CWalletTx*,unsigned int> > >::iterator it = vZeroValueBundles[nBundle]; it != vZeroValueBundles[nBundle + 1]; ++it)
                    {
                        setCoinsRet.insert(it->second);
                    }
                }
            }
            else
            {
                if (fDebug) cerr << "pick " << nValue << " value " << FormatMoney(vValue[nValue].first.first) << " normalized " << vValue[nValue].first.first / denom << " cost " << vValue[nValue].first.second << endl;
                setCoinsRet.insert(vValue[nValue].second);
            }
            nValueRet += vValue[nValue].first.first;
            costsum += vValue[nValue].first.second;
        }
        nPrev = B(i, nPrev);
    }
    if (nValueRet < nTargetValue && !vZeroValueBundles.empty())
    {
        // If we get here it means that there are either not sufficient funds to pay the transaction or that there are small coin outputs left that couldn't be bundled
        // We try to fulfill the request by adding these small coin outputs
        for (vector<pair<pair<int64_t,int64_t>,pair<const CWalletTx*,unsigned int> > >::iterator it = vZeroValueBundles.back(); it != vValue.end() && nValueRet < nTargetValue; ++it)
        {
             setCoinsRet.insert(it->second);
             nValueRet += it->first.first;
        }
    }
    if (fDebug) cerr << "requested " << FormatMoney(nTargetValue) << "\tnormalized " << nTargetValue/denom + (nTargetValue % denom != 0 ? 1 : 0) << "\tgot " << FormatMoney(nValueRet) << "\tcost " << costsum << endl;
    if (fDebug) cerr << "M " << M.size1() << "x" << M.size2() << "; vValue.size() = " << vValue.size() << endl;
    return true;
}

// TODO: find appropriate place for this sort function
// move denoms down
bool less_then_denom (const COutput& out1, const COutput& out2)
{
    const CWalletTx *pcoin1 = out1.tx;
    const CWalletTx *pcoin2 = out2.tx;

    bool found1 = false;
    bool found2 = false;
    BOOST_FOREACH(int64_t d, colLateralDenominations) // loop through predefined denoms
    {
        if(pcoin1->vout[out1.i].nValue == d) found1 = true;
        if(pcoin2->vout[out2.i].nValue == d) found2 = true;
    }
    return (!found1 && found2);
}

static bool CmpDepth(const CWalletTx* a, const CWalletTx* b) { return a->nTime > b->nTime; }

bool CWallet::SelectCoinsMinConf(int64_t nTargetValue, unsigned int nSpendTime, int nConfMine, int nConfTheirs, vector<COutput> vCoins, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    pair<int64_t, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<int64_t>::max();
    coinLowestLarger.second.first = NULL;
    vector<pair<int64_t, pair<const CWalletTx*,unsigned int> > > vValue;
    int64_t nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    // move denoms down on the list
    sort(vCoins.begin(), vCoins.end(), less_then_denom);

    // try to find nondenom first to prevent unneeded spending of mixed coins
    for (unsigned int tryDenom = 0; tryDenom < 2; tryDenom++)
    {
        if (fDebug) printf("[selectcoins] tryDenom: %d\n", tryDenom);
        vValue.clear();
        nTotalLower = 0;

    BOOST_FOREACH(const COutput &output, vCoins)
    {
        if (!output.fSpendable)
            continue;

        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;

        // Follow the timestamp rules
        if (pcoin->nTime > nSpendTime)
            continue;

        int64_t n = pcoin->vout[i].nValue;

        // ignore Innova Name TxOut
        if (pcoin->nVersion == NAMECOIN_TX_VERSION && hooks->IsNameScript(pcoin->vout[i].scriptPubKey))
            continue;

        if (tryDenom == 0 && IsDenominatedAmount(n)) continue; // we don't want denom values on first run

        pair<int64_t,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue + CENT)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    vector<char> vfBest;
    int64_t nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        printf("[selectcoins] SelectCoins() best subset: ");
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                printf("%s ", FormatMoney(vValue[i].first).c_str());
        printf("[selectcoins] total %s\n", FormatMoney(nBest).c_str());
    }

    return true;
    }
    return false;
}

bool CWallet::SelectCoins(int64_t nTargetValue, unsigned int nSpendTime, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet, const CCoinControl* coinControl) const
{
    vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected())
    {
        BOOST_FOREACH(const COutput& out, vCoins)
        {
            nValueRet += out.tx->vout[out.i].nValue;
            setCoinsRet.insert(make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    return (SelectCoinsMinConf(nTargetValue, nSpendTime, 1, 10, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, nSpendTime, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, nSpendTime, 0, 1, vCoins, setCoinsRet, nValueRet));
}

bool CWallet::SelectCoins2(int64_t nTargetValue, unsigned int nSpendTime, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet, const CCoinControl* coinControl) const
{
    vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected())
    {
        BOOST_FOREACH(const COutput& out, vCoins)
        {
            nValueRet += out.tx->vout[out.i].nValue;
            setCoinsRet.insert(make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    return (SelectCoinsMinConf(nTargetValue, nSpendTime, 1, 10, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, nSpendTime, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, nSpendTime, 0, 1, vCoins, setCoinsRet, nValueRet));
}

// Select some coins without random shuffle or best subset approximation
bool CWallet::SelectCoinsForStaking(int64_t nTargetValue, unsigned int nSpendTime, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet) const
{
    LOCK2(cs_main, cs_wallet);

    vector<COutput> vCoins;
    AvailableCoinsForStaking(vCoins, nSpendTime);

    setCoinsRet.clear();
    nValueRet = 0;

    BOOST_FOREACH(COutput output, vCoins)
    {
        const CWalletTx *pcoin = output.tx;
        int i = output.i;

        // Stop if we've chosen enough inputs
        if (nValueRet >= nTargetValue)
            break;

        int64_t n = pcoin->vout[i].nValue;

        pair<int64_t,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n >= nTargetValue)
        {
            // If input value is greater or equal to target then simply insert
            //    it into the current subset and exit
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            break;
        }
        else if (n < nTargetValue + CENT)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
        }
    }

    return true;
}

struct CompareByPriority
{
    bool operator()(const COutput& t1,
                    const COutput& t2) const
    {
        return t1.Priority() > t2.Priority();
    }
};

bool CWallet::SelectCoinsCollateral(std::vector<CTxIn>& setCoinsRet, int64_t& nValueRet) const
{
    vector<COutput> vCoins;

    //printf(" selecting coins for collateral\n");
    AvailableCoins(vCoins);

    //printf("found coins %d\n", (int)vCoins.size());

    set<pair<const CWalletTx*,unsigned int> > setCoinsRet2;

    BOOST_FOREACH(const COutput& out, vCoins)
    {
        // collateral inputs will always be a multiple of COLLATERALN_COLLATERAL, up to five
        if(IsCollateralAmount(out.tx->vout[out.i].nValue))
        {
            CTxIn vin = CTxIn(out.tx->GetHash(),out.i);

            vin.prevPubKey = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey
            nValueRet += out.tx->vout[out.i].nValue;
            setCoinsRet.push_back(vin);
            setCoinsRet2.insert(make_pair(out.tx, out.i));
            return true;
        }
    }

    return false;
}

int CWallet::CountInputsWithAmount(int64_t nInputAmount)
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted()){
                int nDepth = pcoin->GetDepthInMainChain();

                for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
					//isminetype mine = IsMine(pcoin->vout[i]);
		    bool mine = IsMine(pcoin->vout[i]);
                    //COutput out = COutput(pcoin, i, nDepth, (mine & ISMINE_SPENDABLE) != ISMINE_NO);
		    COutput out = COutput(pcoin, i, nDepth, mine);
                    CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

                    if(out.tx->vout[out.i].nValue != nInputAmount) continue;
                    if(!IsDenominatedAmount(pcoin->vout[i].nValue)) continue;
                    //if(IsSpent(out.tx->GetHash(), i) || !IsMine(pcoin->vout[i]) || !IsDenominated(vin)) continue;
		    if(pcoin->IsSpent(i) || !IsMine(pcoin->vout[i]) || !IsDenominated(vin)) continue;

                    nTotal++;
                }
            }
        }
    }

    return nTotal;
}

bool CWallet::HasCollateralInputs() const
{
    vector<COutput> vCoins;
    AvailableCoins(vCoins);

    int nFound = 0;
    BOOST_FOREACH(const COutput& out, vCoins)
        if(IsCollateralAmount(out.tx->vout[out.i].nValue)) nFound++;

    return nFound > 1; // should have more than one just in case
}

bool CWallet::IsCollateralAmount(int64_t nInputAmount) const
{
	return nInputAmount != 0 && nInputAmount % COLLATERALN_COLLATERAL == 0 && nInputAmount < COLLATERALN_COLLATERAL * 5 && nInputAmount > COLLATERALN_COLLATERAL;
}

bool CWallet::CreateCollateralTransaction(CTransaction& txCollateral, std::string strReason)
{
    /*
        To doublespend a collateral transaction, it will require a fee higher than this. So there's
        still a significant cost.
    */
    int64_t nFeeRet = 0.01*COIN;

    txCollateral.vin.clear();
    txCollateral.vout.clear();

    CReserveKey reservekey(this);
    int64_t nValueIn2 = 0;
    std::vector<CTxIn> vCoinsCollateral;

    if (!SelectCoinsCollateral(vCoinsCollateral, nValueIn2))
    {
        strReason = "Error: CollateralN requires a collateral transaction and could not locate an acceptable input!";
        return false;
    }

    // make our change address
    CScript scriptChange;
    CPubKey vchPubKey;

    if (!reservekey.GetReservedKey(vchPubKey))
    {
        strReason = "Error: Failed to get reserved key from keypool";
        return false;
    }
    scriptChange =GetScriptForDestination(vchPubKey.GetID());
    reservekey.KeepKey();

    BOOST_FOREACH(CTxIn v, vCoinsCollateral)
        txCollateral.vin.push_back(v);

    if(nValueIn2 - COLLATERALN_COLLATERAL - nFeeRet > 0) {
        //pay collateral charge in fees
        CTxOut vout3 = CTxOut(nValueIn2 - COLLATERALN_COLLATERAL, scriptChange);
        txCollateral.vout.push_back(vout3);
    }

    int vinNumber = 0;
    BOOST_FOREACH(CTxIn v, txCollateral.vin) {
        if(!SignSignature(*this, v.prevPubKey, txCollateral, vinNumber, int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))) {
            BOOST_FOREACH(CTxIn v, vCoinsCollateral)
                UnlockCoin(v.prevout);

            strReason = "CCollaTeralPool::Sign - Unable to sign collateral transaction! \n";
            return false;
        }
        vinNumber++;
    }

    return true;
}

bool CWallet::ConvertList(std::vector<CTxIn> vCoins, std::vector<int64_t>& vecAmounts)
{
    BOOST_FOREACH(CTxIn i, vCoins){
        if (mapWallet.count(i.prevout.hash))
        {
            CWalletTx& wtx = mapWallet[i.prevout.hash];
            if(i.prevout.n < wtx.vout.size()){
                vecAmounts.push_back(wtx.vout[i.prevout.n].nValue);
            }
        } else {
            printf("ConvertList -- Couldn't find transaction\n");
        }
    }
    return true;
}

bool CWallet::CreateTransaction(const vector<pair<CScript, int64_t> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, int64_t& nFeeRet, int32_t& nChangePos, const CCoinControl* coinControl, const CScript* scriptChangeOverride)
{
    int64_t nValue = 0;
    BOOST_FOREACH (const PAIRTYPE(CScript, int64_t)& s, vecSend)
    {
        if (nValue < 0)
            return false;
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
        return false;

    wtxNew.BindWallet(this);

    {
        LOCK2(cs_main, cs_wallet);
        // txdb must be opened before the mapWallet lock
        CTxDB txdb("r");
        {
            nFeeRet = nTransactionFee;
            while (true)
            {
                wtxNew.vin.clear();
                wtxNew.vout.clear();
                wtxNew.fFromMe = true;

                for (std::vector<COutPoint>::iterator it = wtxNew.vReservedCoins.begin();
                     it != wtxNew.vReservedCoins.end(); ++it)
                {
                    UnlockCoin(*it);
                }
                wtxNew.vReservedCoins.clear();

                int64_t nTotalValue = nValue + nFeeRet;
                double dPriority = 0;

                // vouts to the payees with UTXO splitter - I n n o v a
                if(coinControl && !coinControl->fSplitBlock)
                {
                    BOOST_FOREACH (const PAIRTYPE(CScript, int64_t)& s, vecSend)
                    {
                        wtxNew.vout.push_back(CTxOut(s.second, s.first));
                    }
                }
                else //UTXO Splitter Transaction
                {
                    int nSplitBlock;
                    if(coinControl)
                        nSplitBlock = coinControl->nSplitBlock;
                    else
                        nSplitBlock = 1;

                    BOOST_FOREACH (const PAIRTYPE(CScript, int64_t)& s, vecSend)
                    {
                        for(int i = 0; i < nSplitBlock; i++)
                        {
                            if(i == nSplitBlock - 1)
                            {
                                uint64_t nRemainder = s.second % nSplitBlock;
                                wtxNew.vout.push_back(CTxOut((s.second / nSplitBlock) + nRemainder, s.first));
                            }
                            else
                                wtxNew.vout.push_back(CTxOut(s.second / nSplitBlock, s.first));
                        }
                    }
                }

                // Choose coins to use
                set<pair<const CWalletTx*,unsigned int> > setCoins;
                int64_t nValueIn = 0;
                if (!SelectCoins(nTotalValue, wtxNew.nTime, setCoins, nValueIn, coinControl))
                    return false;

                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    COutPoint outpt(pcoin.first->GetHash(), pcoin.second);
                    LockCoin(outpt);
                    wtxNew.vReservedCoins.push_back(outpt);
                }

                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    //Fix priority calculation in CreateTransaction
                    //Make this projection of priority in 1 block match the
                    //calculation in the low priority reject code.
                    int64_t nCredit = pcoin.first->vout[pcoin.second].nValue;
                    //But mempool inputs might still be in the mempool, so their age stays 0
                    int age = pcoin.first->GetDepthInMainChain();
                    if (age != 0)
                        age += 1;
                    //dPriority += (double)nCredit * pcoin.first->GetDepthInMainChain();
                    dPriority += (double)nCredit * age;
                }

                if (nValueIn < nValue + nFeeRet)
                    return false;
                int64_t nChange = nValueIn - nValue - nFeeRet;
                // if sub-cent change is required, the fee must be raised to at least MIN_TX_FEE
                // or until nChange becomes zero
                // NOTE: this depends on the exact behaviour of GetMinFee
                if (nFeeRet < MIN_TX_FEE && nChange > 0 && nChange < CENT)
                {
                    int64_t nMoveToFee = min(nChange, MIN_TX_FEE - nFeeRet);
                    nChange -= nMoveToFee;
                    nFeeRet += nMoveToFee;
                }

                if (nChange > 0)
                {
                    CScript scriptChange;

                    if (scriptChangeOverride && !scriptChangeOverride->empty())
                        scriptChange = *scriptChangeOverride;
                    // coin control: send change to custom address
                    else if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                        scriptChange.SetDestination(coinControl->destChange);

                    // no coin control: send change to newly generated address
                    else
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey;
                    
                        if (!reservekey.GetReservedKey(vchPubKey))
                            return false;

                        scriptChange.SetDestination(vchPubKey.GetID());
                    }

                    if (wtxNew.vout.empty())
                        return false;

                    // Insert change txn at random position:
                    vector<CTxOut>::iterator position = wtxNew.vout.begin()+GetRandInt(wtxNew.vout.size() + 1);

                    // -- don't put change output between value and narration outputs
                    if (position > wtxNew.vout.begin() && position < wtxNew.vout.end())
                    {
                        while (position > wtxNew.vout.begin())
                        {
                            if (position->nValue != 0)
                                break;
                            position--;
                        };
                    };
                    wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
                    nChangePos = std::distance(wtxNew.vout.begin(), position);
                }
                else
                    reservekey.ReturnKey();

                // Fill vin
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

                // Sign
                int nIn = 0;
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    if (!SignSignature(*this, *coin.first, wtxNew, nIn++))
                        return false;

                // Limit size
                unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
                if (nBytes >= MAX_BLOCK_SIZE_GEN/5)
                    return false;
                dPriority /= nBytes;

                // Check that enough fee is included
                int64_t nPayFee = nTransactionFee * (1 + (int64_t)nBytes / 1000);
                int64_t nMinFee = wtxNew.GetMinFee(1, GMF_SEND, nBytes);

                if (nFeeRet < max(nPayFee, nMinFee))
                {
                    nFeeRet = max(nPayFee, nMinFee);
                    continue;
                }

                // Fill vtxPrev by copying from previous transactions vtxPrev
                wtxNew.AddSupportingTransactions(txdb);
                wtxNew.fTimeReceivedIsTxTime = true;

                break;
            }
        }
    }
    return true;
}


bool CWallet::CreateTransaction(CScript scriptPubKey, int64_t nValue, std::string& sNarr, CWalletTx& wtxNew, CReserveKey& reservekey, int64_t& nFeeRet, const CCoinControl* coinControl, const CScript* scriptChangeOverride)
{
    vector< pair<CScript, int64_t> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));

    if (sNarr.length() > 0)
    {
        std::vector<uint8_t> vNarr(sNarr.c_str(), sNarr.c_str() + sNarr.length());
        std::vector<uint8_t> vNDesc;

        vNDesc.resize(2);
        vNDesc[0] = 'n';
        vNDesc[1] = 'p';

        CScript scriptN = CScript() << OP_RETURN << vNDesc << OP_RETURN << vNarr;

        vecSend.push_back(make_pair(scriptN, 0));
    }

    // -- CreateTransaction won't place change between value and narr output.
    //    narration output will be for preceding output

    int nChangePos;

    //bool rv = CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, nChangePos, strFailReason, coinControl);
    bool rv = CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, nChangePos, coinControl, scriptChangeOverride);

    // -- narration will be added to mapValue later in FindStealthTransactions From CommitTransaction
    return rv;
}

bool CWallet::CreateTransactionInner(const vector<pair<CScript, CAmount> >& vecSend, const CWalletTx& wtxNameIn, CAmount nFeeInput,
                                CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl, const CScript* scriptChangeOverride)
{
    CAmount nValue = 0;
    BOOST_FOREACH (const PAIRTYPE(CScript, CAmount)& s, vecSend)
    {
        if (nValue < 0)
        {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
    {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    // innova: define some values used in case of namecoin tx creation
    CAmount nNameTxInCredit = 0;
    unsigned int nNameTxOut = 0;
    if (!wtxNameIn.IsNull())
    {
        nNameTxOut = IndexOfNameOutput(wtxNameIn);
        nNameTxInCredit = wtxNameIn.vout[nNameTxOut].nValue;
        if (!MoneyRange(nNameTxInCredit))
        {
            printf("CreateTransactionInner: ERROR: nNameTxInCredit out of range\n");
            return false;
        }
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CTransaction txNew;
    txNew.nVersion = wtxNew.nVersion; // innova: important for name transactions

    {
        LOCK2(cs_main, cs_wallet);
        {
            nFeeRet = max(nFeeInput, MIN_TX_FEE);  // innova: a good starting point, probably...
            while (true)
            {
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;

                CAmount nTotalValue = nValue + nFeeRet;
                // // vouts to the payees
                // BOOST_FOREACH (const PAIRTYPE(CScript, CAmount)& s, vecSend)
                // {
                //     CTxOut txout(s.second, s.first);
                //     if (txout.IsDust(::minRelayTxFee))
                //     {
                //         strFailReason = _("Transaction amount too small");
                //         return false;
                //     }
                //     txNew.vout.push_back(txout);
                // }

                // vouts to the payees with UTXO splitter - I n n o v a
                if(coinControl && !coinControl->fSplitBlock)
                {
                    BOOST_FOREACH (const PAIRTYPE(CScript, int64_t)& s, vecSend)
                    {
                        txNew.vout.push_back(CTxOut(s.second, s.first));
                    }
                }
                else //UTXO Splitter Transaction
                {
                    int nSplitBlock;
                    if(coinControl)
                        nSplitBlock = coinControl->nSplitBlock;
                    else
                        nSplitBlock = 1;

                    BOOST_FOREACH (const PAIRTYPE(CScript, int64_t)& s, vecSend)
                    {
                        for(int i = 0; i < nSplitBlock; i++)
                        {
                            if(i == nSplitBlock - 1)
                            {
                                uint64_t nRemainder = s.second % nSplitBlock;
                                txNew.vout.push_back(CTxOut((s.second / nSplitBlock) + nRemainder, s.first));
                            }
                            else
                                txNew.vout.push_back(CTxOut(s.second / nSplitBlock, s.first));
                        }
                    }
                }

                // Choose coins to use
                set<pair<const CWalletTx*,unsigned int> > setCoins;
                CAmount nValueIn = 0;

                // innova: in case of namecoin tx we have already supplied input.
                // If we have enough money: skip coin selection, unless we have ordered it with coinControl.
                if (!wtxNameIn.IsNull())
                {
                    if ( (nTotalValue - nNameTxInCredit > 0 || (coinControl && coinControl->HasSelected()))
                        && !SelectCoins(nTotalValue - nNameTxInCredit, wtxNew.nTime, setCoins, nValueIn, coinControl) )
                    {
                        strFailReason = _("Insufficient funds");
                        return false;
                    }
                }
                // otherwise proceed as we normaly would in bitcoin
                else
                if (!SelectCoins(nTotalValue, wtxNew.nTime, setCoins, nValueIn, coinControl))
                {
                    strFailReason = _("Insufficient funds");
                    return false;
                }

		        // innova: name tx always at first position
                if (!wtxNameIn.IsNull())
                {
                    setCoins.insert(setCoins.begin(), make_pair(&wtxNameIn, nNameTxOut));
                    nValueIn += nNameTxInCredit;
                }

                if (nValueIn < nValue + nFeeRet)
                {
                    strFailReason = _("Insufficient funds for fee");
                    return false;
                }
                CAmount nChange = nValueIn - nValue - nFeeRet;
                // if sub-cent change is required, the fee must be raised to at least MIN_TX_FEE
                // or until nChange becomes zero
                // NOTE: this depends on the exact behaviour of GetMinFee
                if (nFeeRet < MIN_TX_FEE && nChange > 0 && nChange < CENT)
                {
                    CAmount nMoveToFee = min(nChange, MIN_TX_FEE - nFeeRet);
                    nChange -= nMoveToFee;
                    nFeeRet += nMoveToFee;
                }

                // ppcoin: sub-cent change is moved to fee
                if (nChange > 0 && nChange < MIN_TXOUT_AMOUNT)
                {
                    nFeeRet += nChange;
                    nChange = 0;
                }

                if (nChange > 0)
                {
                    CScript scriptChange;

                    if (scriptChangeOverride && !scriptChangeOverride->empty())
                        scriptChange = *scriptChangeOverride;
                    // coin control: send change to custom address
                    else if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                        scriptChange = GetScriptForDestination(coinControl->destChange);

                    // no coin control: send change to newly generated address
                    else
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey;
                    
                        if (!reservekey.GetReservedKey(vchPubKey))
                            return false;

                        scriptChange = GetScriptForDestination(vchPubKey.GetID());
                    }

                    CTxOut newTxOut(nChange, scriptChange);

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    // if (newTxOut)
                    // {
                    //     nFeeRet += nChange;
                    //     reservekey.ReturnKey();
                    // }
                    // else
                    // {
                    // Insert change txn at random position:
                    vector<CTxOut>::iterator position = txNew.vout.begin()+GetRandInt(txNew.vout.size()+1);
                    txNew.vout.insert(position, newTxOut);
                    // }
                }
                else
                    reservekey.ReturnKey();

                // Fill vin
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    txNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

                // Sign
                int nIn = 0;
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                {
                    // innova: we sign name tx differently.
                    if (coin.first == &wtxNameIn && coin.second == nNameTxOut)
                    {
                        if (!SignNameSignatureINN(*this, *coin.first, txNew, nIn++))
                        {
                            strFailReason = _("Signing name transaction failed");
                            return false;
                        }
                    }
                    else
                    if (!SignSignature(*this, *coin.first, txNew, nIn++))
                    {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    }
                }

                // Embed the constructed transaction data in wtxNew.
                *static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);

                // Limit size
                unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
                if (nBytes >= MAX_STANDARD_TX_SIZE)
                {
                    strFailReason = _("Transaction too large");
                    return false;
                }

                // Check that enough fee is included (at least MIN_TX_FEE per 1000 bytes)
                CAmount nMinFee = max(nFeeInput, wtxNew.GetMinFee());
                if (nFeeRet < nMinFee)
                {
                    nFeeRet = nMinFee;
                    continue;
                }
                break;
            }
        }
    }
    return true;
}

bool CWallet::CreateNameTx(CScript scriptPubKey, const CAmount& nValue, const CWalletTx& wtxNameIn, CAmount nFeeInput,
                                CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl)
{
    vector< pair<CScript, CAmount> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    return CreateTransactionInner(vecSend, wtxNameIn, nFeeInput, wtxNew, reservekey, nFeeRet, strFailReason, coinControl, NULL);
}

bool CWallet::NewStealthAddress(std::string& sError, std::string& sLabel, CStealthAddress& sxAddr)
{
    ec_secret scan_secret;
    ec_secret spend_secret;

    if (GenerateRandomSecret(scan_secret) != 0
        || GenerateRandomSecret(spend_secret) != 0)
    {
        sError = "GenerateRandomSecret failed.";
        printf("Error CWallet::NewStealthAddress - %s\n", sError.c_str());
        return false;
    };

    ec_point scan_pubkey, spend_pubkey;
    if (SecretToPublicKey(scan_secret, scan_pubkey) != 0)
    {
        sError = "Could not get scan public key.";
        printf("Error CWallet::NewStealthAddress - %s\n", sError.c_str());
        return false;
    };

    if (SecretToPublicKey(spend_secret, spend_pubkey) != 0)
    {
        sError = "Could not get spend public key.";
        printf("Error CWallet::NewStealthAddress - %s\n", sError.c_str());
        return false;
    };

    if (fDebug)
    {
        printf("getnewstealthaddress: new stealth address created\n");
    };


    sxAddr.label = sLabel;
    sxAddr.scan_pubkey = scan_pubkey;
    sxAddr.spend_pubkey = spend_pubkey;

    sxAddr.scan_secret.resize(32);
    memcpy(&sxAddr.scan_secret[0], &scan_secret.e[0], 32);
    sxAddr.spend_secret.resize(32);
    memcpy(&sxAddr.spend_secret[0], &spend_secret.e[0], 32);

    OPENSSL_cleanse(&scan_secret, sizeof(scan_secret));
    OPENSSL_cleanse(&spend_secret, sizeof(spend_secret));

    return true;
}

bool CWallet::AddStealthAddress(CStealthAddress& sxAddr)
{
    LOCK(cs_wallet);

    // must add before changing spend_secret
    stealthAddresses.insert(sxAddr);

    bool fOwned = sxAddr.scan_secret.size() == ec_secret_size;



    if (fOwned)
    {
        // -- owned addresses can only be added when wallet is unlocked
        if (IsLocked())
        {
            printf("Error: CWallet::AddStealthAddress wallet must be unlocked.\n");
            stealthAddresses.erase(sxAddr);
            return false;
        };

        if (IsCrypted())
        {
            std::vector<unsigned char> vchCryptedSecret;
            CSecret vchSecret;
            vchSecret.resize(32);
            if (sxAddr.spend_secret.size() != 32)
            {
                printf("AddStealthAddress() : stealth spend_secret wrong size %d\n", (int)sxAddr.spend_secret.size());
                stealthAddresses.erase(sxAddr);
                return false;
            }
            memcpy(&vchSecret[0], &sxAddr.spend_secret[0], 32);

            uint256 iv = Hash(sxAddr.spend_pubkey.begin(), sxAddr.spend_pubkey.end());
            if (!EncryptSecret(vMasterKey, vchSecret, iv, vchCryptedSecret))
            {
                printf("Error: Failed encrypting stealth key %s\n", sxAddr.Encoded().c_str());
                stealthAddresses.erase(sxAddr);
                return false;
            };
            sxAddr.spend_secret = vchCryptedSecret;
        };
    };


    bool rv = CWalletDB(strWalletFile).WriteStealthAddress(sxAddr);

    if (rv)
        NotifyAddressBookChanged(this, sxAddr, sxAddr.label, fOwned, CT_NEW);

    return rv;
}

bool CWallet::UnlockStealthAddresses(const CKeyingMaterial& vMasterKeyIn)
{
    // -- decrypt spend_secret of stealth addresses
    std::set<CStealthAddress>::iterator it;
    for (it = stealthAddresses.begin(); it != stealthAddresses.end(); ++it)
    {
        if (it->scan_secret.size() < EC_SECRET_SIZE)
            continue; // stealth address is not owned

        // -- CStealthAddress are only sorted on spend_pubkey
        CStealthAddress &sxAddr = const_cast<CStealthAddress&>(*it);

        if (fDebug)
            printf("Decrypting stealth key %s\n", sxAddr.Encoded().c_str());

        CSecret vchSecret;
        uint256 iv = Hash(sxAddr.spend_pubkey.begin(), sxAddr.spend_pubkey.end());
        if (!DecryptSecret(vMasterKeyIn, sxAddr.spend_secret, iv, vchSecret)
            || vchSecret.size() != EC_SECRET_SIZE)
        {
            printf("Error: Failed decrypting stealth key %s\n", sxAddr.Encoded().c_str());
            continue;
        };

        ec_secret testSecret;
        memcpy(&testSecret.e[0], &vchSecret[0], EC_SECRET_SIZE);
        ec_point pkSpendTest;

        if (SecretToPublicKey(testSecret, pkSpendTest) != 0
            || pkSpendTest != sxAddr.spend_pubkey)
        {
            printf("Error: Failed decrypting stealth key, public key mismatch %s\n", sxAddr.Encoded().c_str());
            OPENSSL_cleanse(&testSecret.e[0], EC_SECRET_SIZE);
            continue;
        };

        sxAddr.spend_secret.resize(EC_SECRET_SIZE);
        memcpy(&sxAddr.spend_secret[0], &vchSecret[0], EC_SECRET_SIZE);
        OPENSSL_cleanse(&testSecret.e[0], EC_SECRET_SIZE);
    };

    CryptedKeyMap::iterator mi = mapCryptedKeys.begin();
    for (; mi != mapCryptedKeys.end(); ++mi)
    {
        CPubKey &pubKey = (*mi).second.first;
        std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
        if (vchCryptedSecret.size() != 0)
            continue;

        CKeyID ckid = pubKey.GetID();
        CBitcoinAddress addr(ckid);

        StealthKeyMetaMap::iterator mi = mapStealthKeyMeta.find(ckid);
        if (mi == mapStealthKeyMeta.end())
        {
            // -- could be an anon output
            if (fDebug)
                printf("Warning: No metadata found to add secret for %s\n", addr.ToString().c_str());
            continue;
        };

        CStealthKeyMetadata& sxKeyMeta = mi->second;

        CStealthAddress sxFind;
        sxFind.SetScanPubKey(sxKeyMeta.pkScan);

        std::set<CStealthAddress>::iterator si = stealthAddresses.find(sxFind);
        if (si == stealthAddresses.end())
        {
            printf("No stealth key found to add secret for %s\n", addr.ToString().c_str());
            continue;
        };

        if (fDebug)
            printf("Expanding secret for %s\n", addr.ToString().c_str());

        ec_secret sSpendR;
        ec_secret sSpend;
        ec_secret sScan;

        if (si->spend_secret.size() != EC_SECRET_SIZE
            || si->scan_secret.size() != EC_SECRET_SIZE)
        {
            printf("Stealth address has no secret key for %s\n", addr.ToString().c_str());
            continue;
        };
        memcpy(&sScan.e[0], &si->scan_secret[0], EC_SECRET_SIZE);
        memcpy(&sSpend.e[0], &si->spend_secret[0], EC_SECRET_SIZE);

        ec_point pkEphem;;
        pkEphem.resize(sxKeyMeta.pkEphem.size());
        memcpy(&pkEphem[0], sxKeyMeta.pkEphem.begin(), sxKeyMeta.pkEphem.size());

        if (StealthSecretSpend(sScan, pkEphem, sSpend, sSpendR) != 0)
        {
            printf("StealthSecretSpend() failed.\n");
            OPENSSL_cleanse(&sScan.e[0], EC_SECRET_SIZE);
            OPENSSL_cleanse(&sSpend.e[0], EC_SECRET_SIZE);
            OPENSSL_cleanse(&sSpendR.e[0], EC_SECRET_SIZE);
            continue;
        };

        //CKey ckey;
        //ckey.Set(&sSpendR.e[0], true);

		CKey ckey;
		CSecret vchSecret;
		vchSecret.resize(ec_secret_size);

		ckey.Set(&sSpendR.e[0], &sSpendR.e[0] + ec_secret_size, true);

        if (!ckey.IsValid())
        {
            printf("Reconstructed key is invalid.\n");
            OPENSSL_cleanse(&sScan.e[0], EC_SECRET_SIZE);
            OPENSSL_cleanse(&sSpend.e[0], EC_SECRET_SIZE);
            OPENSSL_cleanse(&sSpendR.e[0], EC_SECRET_SIZE);
            continue;
        };

        CPubKey cpkT = ckey.GetPubKey();

        if (!cpkT.IsValid())
        {
            printf("%s: cpkT is invalid.\n", __func__);
            OPENSSL_cleanse(&sScan.e[0], EC_SECRET_SIZE);
            OPENSSL_cleanse(&sSpend.e[0], EC_SECRET_SIZE);
            OPENSSL_cleanse(&sSpendR.e[0], EC_SECRET_SIZE);
            continue;
        };

        if (cpkT != pubKey)
        {
            printf("%s: Error: Generated secret does not match.\n", __func__);
            if (fDebug)
            {
                printf("cpkT   %s\n", HexStr(cpkT).c_str());
                printf("pubKey %s\n", HexStr(pubKey).c_str());
            };
            OPENSSL_cleanse(&sScan.e[0], EC_SECRET_SIZE);
            OPENSSL_cleanse(&sSpend.e[0], EC_SECRET_SIZE);
            OPENSSL_cleanse(&sSpendR.e[0], EC_SECRET_SIZE);
            continue;
        };

        if (fDebug)
        {
            CKeyID keyID = cpkT.GetID();
            CBitcoinAddress coinAddress(keyID);
            printf("%s: Adding secret to key %s.\n", __func__, coinAddress.ToString().c_str());
        };

        if (!AddKeyPubKey(ckey, cpkT))
        {
            printf("%s: AddKeyPubKey failed.\n", __func__);
            OPENSSL_cleanse(&sScan.e[0], EC_SECRET_SIZE);
            OPENSSL_cleanse(&sSpend.e[0], EC_SECRET_SIZE);
            OPENSSL_cleanse(&sSpendR.e[0], EC_SECRET_SIZE);
            continue;
        };

        if (!CWalletDB(strWalletFile).EraseStealthKeyMeta(ckid))
            printf("EraseStealthKeyMeta failed for %s\n", addr.ToString().c_str());

        OPENSSL_cleanse(&sScan.e[0], EC_SECRET_SIZE);
        OPENSSL_cleanse(&sSpend.e[0], EC_SECRET_SIZE);
        OPENSSL_cleanse(&sSpendR.e[0], EC_SECRET_SIZE);
    };
    return true;
}

bool CWallet::UpdateStealthAddress(std::string &addr, std::string &label, bool addIfNotExist)
{
    if (fDebug)
        printf("UpdateStealthAddress %s\n", addr.c_str());


    CStealthAddress sxAddr;

    if (!sxAddr.SetEncoded(addr))
        return false;

    std::set<CStealthAddress>::iterator it;
    it = stealthAddresses.find(sxAddr);

    ChangeType nMode = CT_UPDATED;
    CStealthAddress sxFound;
    if (it == stealthAddresses.end())
    {
        if (addIfNotExist)
        {
            sxFound = sxAddr;
            sxFound.label = label;
            stealthAddresses.insert(sxFound);
            nMode = CT_NEW;
        } else
        {
            printf("UpdateStealthAddress %s, not in set\n", addr.c_str());
            return false;
        };
    } else
    {
        sxFound = const_cast<CStealthAddress&>(*it);

        if (sxFound.label == label)
        {
            // no change
            return true;
        };

        it->label = label; // update in .stealthAddresses

        if (sxFound.scan_secret.size() == ec_secret_size)
        {
            printf("UpdateStealthAddress: todo - update owned stealth address.\n");
            return false;
        };
    };

    sxFound.label = label;

    if (!CWalletDB(strWalletFile).WriteStealthAddress(sxFound))
    {
        printf("UpdateStealthAddress(%s) Write to db failed.\n", addr.c_str());
        return false;
    };

    bool fOwned = sxFound.scan_secret.size() == ec_secret_size;
    NotifyAddressBookChanged(this, sxFound, sxFound.label, fOwned, nMode);

    return true;
}

bool CWallet::CreateStealthTransaction(CScript scriptPubKey, int64_t nValue, std::vector<uint8_t>& P, std::vector<uint8_t>& narr, std::string& sNarr, CWalletTx& wtxNew, CReserveKey& reservekey, int64_t& nFeeRet, const CCoinControl* coinControl)
{
    vector< pair<CScript, int64_t> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));

    CScript scriptP = CScript() << OP_RETURN << P;
    if (narr.size() > 0)
        scriptP = scriptP << OP_RETURN << narr;

    vecSend.push_back(make_pair(scriptP, 0));

    // -- shuffle inputs, change output won't mix enough as it must be not fully random for plantext narrations
    std::random_shuffle(vecSend.begin(), vecSend.end());

    int nChangePos;

    //bool rv = CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, nChangePos, strFailReason, coinControl);
    bool rv = CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, nChangePos, coinControl);

    // -- the change txn is inserted in a random pos, check here to match narr to output
    if (rv && narr.size() > 0)
    {
        for (unsigned int k = 0; k < wtxNew.vout.size(); ++k)
        {
            if (wtxNew.vout[k].scriptPubKey != scriptPubKey
                || wtxNew.vout[k].nValue != nValue)
                continue;

            char key[64];
            if (snprintf(key, sizeof(key), "n_%u", k) < 1)
            {
                printf("CreateStealthTransaction(): Error creating narration key.");
                break;
            };
            wtxNew.mapValue[key] = sNarr;
            break;
        };
    };

    return rv;
}

string CWallet::SendStealthMoney(CScript scriptPubKey, int64_t nValue, std::vector<uint8_t>& P, std::vector<uint8_t>& narr, std::string& sNarr, CWalletTx& wtxNew, bool fAskFee)
{
    CReserveKey reservekey(this);
    int64_t nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction  ");
        printf("SendStealthMoney() : %s", strError.c_str());
        return strError;
    }
    if (fWalletUnlockStakingOnly)
    {
        string strError = _("Error: Wallet unlocked for staking only, unable to create transaction.");
        printf("SendStealthMoney() : %s", strError.c_str());
        return strError;
    }
    if (!CreateStealthTransaction(scriptPubKey, nValue, P, narr, sNarr, wtxNew, reservekey, nFeeRequired))
    {
        string strError;
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds  "), FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendStealthMoney() : %s", strError.c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired, _("Sending...")))
        return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey))
        return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}

bool CWallet::SendStealthMoneyToDestination(CStealthAddress& sxAddress, int64_t nValue, std::string& sNarr, CWalletTx& wtxNew, std::string& sError, bool fAskFee)
{
    // -- Check amount
    if (nValue <= 0)
    {
        sError = "Invalid amount";
        return false;
    };
    if (nValue + nTransactionFee > GetBalance())
    {
        sError = "Insufficient funds";
        return false;
    };


    ec_secret ephem_secret;
    ec_secret secretShared;
    ec_point pkSendTo;
    ec_point ephem_pubkey;

    if (GenerateRandomSecret(ephem_secret) != 0)
    {
        sError = "GenerateRandomSecret failed.";
        return false;
    };

    if (StealthSecret(ephem_secret, sxAddress.scan_pubkey, sxAddress.spend_pubkey, secretShared, pkSendTo) != 0)
    {
        sError = "Could not generate receiving public key.";
        return false;
    };

    CPubKey cpkTo(pkSendTo);
    if (!cpkTo.IsValid())
    {
        sError = "Invalid public key generated.";
        return false;
    };

    CKeyID ckidTo = cpkTo.GetID();

    CBitcoinAddress addrTo(ckidTo);

    if (SecretToPublicKey(ephem_secret, ephem_pubkey) != 0)
    {
        sError = "Could not generate ephem public key.";
        return false;
    };

    if (fDebug)
    {
        printf("Stealth send to generated pubkey %" PRIszu": %s\n", pkSendTo.size(), HexStr(pkSendTo).c_str());
        printf("hash %s\n", addrTo.ToString().c_str());
        printf("ephem_pubkey %" PRIszu": %s\n", ephem_pubkey.size(), HexStr(ephem_pubkey).c_str());
    };

    std::vector<unsigned char> vchNarr;
    if (sNarr.length() > 0)
    {
        // Max 32 chars (AES-256-CBC padding expands to 48 byte limit)
        if (sNarr.length() > 32)
        {
            sError = "Narration too long (max 32 characters).";
            return false;
        };

        SecMsgCrypter crypter;
        crypter.SetKey(&secretShared.e[0], &ephem_pubkey[0]);

        if (!crypter.Encrypt((uint8_t*)&sNarr[0], sNarr.length(), vchNarr))
        {
            sError = "Narration encryption failed.";
            return false;
        };

        if (vchNarr.size() > 48)
        {
            sError = "Encrypted narration is too long.";
            return false;
        };
    };

    // -- Parse Bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetDestination(addrTo.Get());

    if ((sError = SendStealthMoney(scriptPubKey, nValue, ephem_pubkey, vchNarr, sNarr, wtxNew, fAskFee)) != "")
        return false;


    return true;
}

bool CWallet::FindStealthTransactions(const CTransaction& tx, mapValue_t& mapNarr)
{
    //if (fDebug)
        //printf("FindStealthTransactions() tx: %s\n", tx.GetHash().GetHex().c_str());

    mapNarr.clear();

    LOCK(cs_wallet);
    ec_secret sSpendR;
    ec_secret sSpend;
    ec_secret sScan;
    ec_secret sShared;

    ec_point pkExtracted;

    std::vector<uint8_t> vchEphemPK;
    std::vector<uint8_t> vchDataB;
    std::vector<uint8_t> vchENarr;
    opcodetype opCode;
    char cbuf[256];

    static const size_t MAX_STEALTH_SCAN_OUTPUTS = 500;
    int32_t nOutputIdOuter = -1;
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        nOutputIdOuter++;
        if ((size_t)nOutputIdOuter >= MAX_STEALTH_SCAN_OUTPUTS)
        {
            printf("FindStealthTransactions: skipping remaining outputs (>%zu)\n", MAX_STEALTH_SCAN_OUTPUTS);
            break;
        }
        // -- for each OP_RETURN need to check all other valid outputs

        // -- skip scan anon outputs
        if (tx.nVersion == ANON_TXN_VERSION
            && txout.IsAnonOutput())
            continue;

        //printf("txout scriptPubKey %s\n",  txout.scriptPubKey.ToString().c_str());
        CScript::const_iterator itTxA = txout.scriptPubKey.begin();

        if (!txout.scriptPubKey.GetOp(itTxA, opCode, vchEphemPK)
            || opCode != OP_RETURN)
            continue;
        else
        if (!txout.scriptPubKey.GetOp(itTxA, opCode, vchEphemPK)
            || vchEphemPK.size() != 33)
        {
            // -- look for plaintext narrations
            if (vchEphemPK.size() > 1
                && vchEphemPK[0] == 'n'
                && vchEphemPK[1] == 'p')
            {
                if (txout.scriptPubKey.GetOp(itTxA, opCode, vchENarr)
                    && opCode == OP_RETURN
                    && txout.scriptPubKey.GetOp(itTxA, opCode, vchENarr)
                    && vchENarr.size() > 0)
                {
                    std::string sNarr = std::string(vchENarr.begin(), vchENarr.end());

                    snprintf(cbuf, sizeof(cbuf), "n_%d", nOutputIdOuter-1); // plaintext narration always matches preceding value output
                    mapNarr[cbuf] = sNarr;
                } else
                {
                    printf("Warning: FindStealthTransactions() tx: %s, Could not extract plaintext narration.\n", tx.GetHash().GetHex().c_str());
                };
            }

            continue;
        }

        int32_t nOutputId = -1;
        nStealth++;
        BOOST_FOREACH(const CTxOut& txoutB, tx.vout)
        {
            nOutputId++;

            // -- skip anon outputs
            if (tx.nVersion == ANON_TXN_VERSION
                && txout.IsAnonOutput())
                continue;

            if (&txoutB == &txout)
                continue;

            bool txnMatch = false; // only 1 txn will match an ephem pk
            //printf("txoutB scriptPubKey %s\n",  txoutB.scriptPubKey.ToString().c_str());

            CTxDestination address;
            if (!ExtractDestination(txoutB.scriptPubKey, address))
                continue;

            if (address.type() != typeid(CKeyID))
                continue;

            CKeyID ckidMatch = boost::get<CKeyID>(address);

            if (HaveKey(ckidMatch)) // no point checking if already have key
                continue;

            std::set<CStealthAddress>::iterator it;
            for (it = stealthAddresses.begin(); it != stealthAddresses.end(); ++it)
            {
                if (it->scan_secret.size() != ec_secret_size)
                    continue; // stealth address is not owned

                //printf("it->Encodeded() %s\n",  it->Encoded().c_str());
                memcpy(&sScan.e[0], &it->scan_secret[0], ec_secret_size);

                if (StealthSecret(sScan, vchEphemPK, it->spend_pubkey, sShared, pkExtracted) != 0)
                {
                    printf("StealthSecret failed.\n");
                    continue;
                };
                //printf("pkExtracted %" PRIszu": %s\n", pkExtracted.size(), HexStr(pkExtracted).c_str());

                CPubKey cpkE(pkExtracted);

                if (!cpkE.IsValid())
                    continue;
                CKeyID ckidE = cpkE.GetID();

                if (ckidMatch != ckidE)
                    continue;

                if (fDebug)
                    printf("Found stealth txn to address %s\n", it->Encoded().c_str());

                if (IsLocked())
                {
                    if (fDebug)
                        printf("Wallet is locked, adding key without secret.\n");

                    // -- add key without secret
                    std::vector<uint8_t> vchEmpty;
                    AddCryptedKey(cpkE, vchEmpty);
                    CKeyID keyId = cpkE.GetID();
                    CBitcoinAddress coinAddress(keyId);
                    std::string sLabel = it->Encoded();
                    SetAddressBookName(keyId, sLabel);

                    CPubKey cpkEphem(vchEphemPK);
                    CPubKey cpkScan(it->scan_pubkey);
                    CStealthKeyMetadata lockedSkMeta(cpkEphem, cpkScan);

                    if (!CWalletDB(strWalletFile).WriteStealthKeyMeta(keyId, lockedSkMeta))
                        printf("WriteStealthKeyMeta failed for %s\n", coinAddress.ToString().c_str());

                    mapStealthKeyMeta[keyId] = lockedSkMeta;
                    nFoundStealth++;
                } else
                {
                    if (it->spend_secret.size() != ec_secret_size)
                        continue;
                    memcpy(&sSpend.e[0], &it->spend_secret[0], ec_secret_size);


                    if (StealthSharedToSecretSpend(sShared, sSpend, sSpendR) != 0)
                    {
                        printf("StealthSharedToSecretSpend() failed.\n");
                        continue;
                    };

                    ec_point pkTestSpendR;
                    if (SecretToPublicKey(sSpendR, pkTestSpendR) != 0)
                    {
                        printf("SecretToPublicKey() failed.\n");
                        continue;
                    };

                    CSecret vchSecret;
                    vchSecret.resize(ec_secret_size);

                    memcpy(&vchSecret[0], &sSpendR.e[0], ec_secret_size);
                    CKey ckey;

                    try {
                        ckey.Set(vchSecret.begin(), vchSecret.end(), true);
                        //ckey.SetSecret(vchSecret, true);
                    } catch (std::exception& e) {
                        printf("ckey.SetSecret() threw: %s.\n", e.what());
                        continue;
                    };

                    CPubKey cpkT = ckey.GetPubKey();
                    if (!cpkT.IsValid())
                    {
                        printf("cpkT is invalid.\n");
                        continue;
                    };

                    if (!ckey.IsValid())
                    {
                        printf("Reconstructed key is invalid.\n");
                        continue;
                    };

                    CKeyID keyID = cpkT.GetID();
                    if (fDebug)
                    {
                        CBitcoinAddress coinAddress(keyID);
                        printf("Adding key %s.\n", coinAddress.ToString().c_str());
                    };

                    if (!AddKey(ckey))
                    {
                        printf("AddKey failed.\n");
                        continue;
                    };

                    std::string sLabel = it->Encoded();
                    SetAddressBookName(keyID, sLabel);
                    nFoundStealth++;
                };

                if (txout.scriptPubKey.GetOp(itTxA, opCode, vchENarr)
                    && opCode == OP_RETURN
                    && txout.scriptPubKey.GetOp(itTxA, opCode, vchENarr)
                    && vchENarr.size() > 0)
                {
                    SecMsgCrypter crypter;
                    crypter.SetKey(&sShared.e[0], &vchEphemPK[0]);
                    std::vector<uint8_t> vchNarr;
                    if (!crypter.Decrypt(&vchENarr[0], vchENarr.size(), vchNarr))
                    {
                        printf("Decrypt narration failed.\n");
                        continue;
                    };
                    std::string sNarr = std::string(vchNarr.begin(), vchNarr.end());

                    snprintf(cbuf, sizeof(cbuf), "n_%d", nOutputId);
                    mapNarr[cbuf] = sNarr;
                };

                txnMatch = true;
                break;
            };
            if (txnMatch)
                break;
        };
    };

    return true;
};



// NovaCoin: get current stake weight
bool CWallet::GetStakeWeight(const CKeyStore& keystore, uint64_t& nMinWeight, uint64_t& nMaxWeight, uint64_t& nWeight)
{
    // Choose coins to use
    int64_t nBalance = GetBalance();

    if (nBalance <= nReserveBalance)
        return false;

    vector<const CWalletTx*> vwtxPrev;

    set<pair<const CWalletTx*,unsigned int> > setCoins;
    int64_t nValueIn = 0;

    if (fHybridSPV)
    {
        if (!SelectCoinsForStakingSPV(setCoins))
            return false;
        for (const auto& pcoin : setCoins)
            nValueIn += pcoin.first->vout[pcoin.second].nValue;
    }
    else
    {
        if (!SelectCoinsForStaking(nBalance - nReserveBalance, GetTime(), setCoins, nValueIn))
            return false;
    }

    if (setCoins.empty())
        return false;


    nMinWeight = nMaxWeight = nWeight = 0;

    CTxDB txdb("r");
    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        CTxIndex txindex;
        {
            LOCK2(cs_main, cs_wallet);
            if (!txdb.ReadTxIndex(pcoin.first->GetHash(), txindex))
                continue;
        }

        if ((int64_t)pcoin.first->nTime > GetTime())
            continue;
        int64_t nTimeWeight = GetWeight((int64_t)pcoin.first->nTime, (int64_t)GetTime());
        CBigNum bnCoinDayWeight = CBigNum(pcoin.first->vout[pcoin.second].nValue) * nTimeWeight / COIN / (24 * 60 * 60);

        // Weight is greater than zero
        if (nTimeWeight > 0)
        {
            nWeight += bnCoinDayWeight.getuint64();
        }

        // Weight is greater than zero, but the maximum value isn't reached yet
        if (nTimeWeight > 0 && nTimeWeight < nStakeMaxAge)
        {
            nMinWeight += bnCoinDayWeight.getuint64();
        }

        // Maximum weight was reached
        if (nTimeWeight == nStakeMaxAge)
        {
            nMaxWeight += bnCoinDayWeight.getuint64();
        }
    }

    return true;
}

bool CWallet::CreateCoinStake(const CKeyStore& keystore, unsigned int nBits, int64_t nSearchInterval, int64_t nFees, CTransaction& txNew, CKey& key)
{
    CBlockIndex* pindexPrev = pindexBest;
    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);

    txNew.vin.clear();
    txNew.vout.clear();

    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));

    // Choose coins to use
    int64_t nBalance = GetBalance();

    if (nBalance <= nReserveBalance)
        return false;

    vector<const CWalletTx*> vwtxPrev;

    set<pair<const CWalletTx*,unsigned int> > setCoins;
    int64_t nValueIn = 0;
    int64_t nCredit = 0;

    // Cache staking mode (UI thread may change it concurrently)
    StakingMode eStakingMode;
    {
        LOCK(cs_stakingMode);
        eStakingMode = nStakingMode;
    }

    bool fTryTransparent = (eStakingMode == STAKE_TRANSPARENT || eStakingMode == STAKE_COLD);

    if (fTryTransparent)
    {
    if (fHybridSPV)
    {
        if (!SelectCoinsForStakingSPV(setCoins))
        {
            if (fDebug && GetBoolArg("-printcoinstakedebug"))
                printf("CreateCoinStake() : SPV staking coins not found\n");
        }
        for (const auto& pcoin : setCoins)
            nValueIn += pcoin.first->vout[pcoin.second].nValue;
    }
    else
    {
        if (!SelectCoinsForStaking(nBalance - nReserveBalance, txNew.nTime, setCoins, nValueIn))
        {
            if (fDebug && GetBoolArg("-printcoinstakedebug"))
                printf("CreateCoinStake() : valid staking coins not found\n");
        }
    }
    } // end fTryTransparent coin selection

    CScript scriptPubKeyKernel;
    CTxDB txdb("r");
    // Post-DAG: reduce search interval to match 1-second block time
    // Pre-DAG: 10 timestamps (~0.67 block slots at 15s blocks)
    // Post-DAG: 2 timestamps (2 block slots at 1s blocks)
    int nMaxStakeSearchInterval = 10;
    {
        LOCK(cs_main);
        if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_DAG)
            nMaxStakeSearchInterval = 2;
    }

    if (fTryTransparent && !setCoins.empty())
    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        {
            LOCK(cs_main);
            if (pcoin.first->hashBlock != 0) {
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pcoin.first->hashBlock);
                if (mi != mapBlockIndex.end() && mi->second) {
                    if (mi->second->nTime + nStakeMinAge > txNew.nTime - nMaxStakeSearchInterval)
                        continue;
                }
            }
        }

        if (pcoin.first->IsShielded())
            continue;

        if (eStakingMode == STAKE_COLD)
        {
            if (!IsPayToColdStaking(pcoin.first->vout[pcoin.second].scriptPubKey))
                continue;
        }

        CTxIndex txindex;
        {
            LOCK2(cs_main, cs_wallet);
            if (!txdb.ReadTxIndex(pcoin.first->GetHash(), txindex))
                continue;
        }

        // Read block header
        CBlock block;
        {
            LOCK2(cs_main, cs_wallet);
            if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
                continue;
        }

        if (block.GetBlockTime() + nStakeMinAge > txNew.nTime - nMaxStakeSearchInterval)
            continue; // only count coins meeting min age requirement

        bool fKernelFound = false;
        for (unsigned int n=0; n<min(nSearchInterval,(int64_t)nMaxStakeSearchInterval) && !fKernelFound && !fShutdown && pindexPrev == pindexBest; n++)
        {
            if (fDebug && GetBoolArg("-printcoinstakedebug"))
                printf("CreateCoinStake() : searching backward in time from %ld for %d seconds to %d\n",txNew.nTime,nSearchInterval,nMaxStakeSearchInterval);
            // Search backward in time from the given txNew timestamp
            // Search nSearchInterval seconds back up to nMaxStakeSearchInterval
            uint256 hashProofOfStake = 0, targetProofOfStake = 0;
            COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);
            if (CheckStakeKernelHash(nBits, block, txindex.pos.nTxPos - txindex.pos.nBlockPos, *pcoin.first, prevoutStake, txNew.nTime - n, hashProofOfStake, targetProofOfStake))
            {
                // Found a kernel
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake() : kernel found\n");
                vector<valtype> vSolutions;
                txnouttype whichType;
                CScript scriptPubKeyOut;
                scriptPubKeyKernel = pcoin.first->vout[pcoin.second].scriptPubKey;
                if (!Solver(scriptPubKeyKernel, whichType, vSolutions))
                {
                    if (fDebug && GetBoolArg("-printcoinstake"))
                        printf("CreateCoinStake() : failed to parse kernel\n");
                    break;
                }
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake() : parsed kernel type=%d\n", whichType);
                if (whichType != TX_PUBKEY && whichType != TX_PUBKEYHASH && whichType != TX_COLDSTAKE)
                {
                    printf("CreateCoinStake() : no support for kernel type=%d\n", whichType);
                    break;
                }
                if (whichType == TX_COLDSTAKE)
                {
                    if (vSolutions.size() < 2)
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake() : cold stake missing owner key in vSolutions\n");
                        break;
                    }

                    if (vSolutions[0].size() != 20 || vSolutions[1].size() != 20)
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake() : cold stake vSolutions wrong size (staker=%zu, owner=%zu)\n",
                                   vSolutions[0].size(), vSolutions[1].size());
                        break;
                    }
                    CKeyID stakerKeyID = CKeyID(uint160(vSolutions[0]));
                    CKeyID ownerKeyID = CKeyID(uint160(vSolutions[1]));

                    CKeyID nullKeyID;  // default constructor = all zeros
                    if (stakerKeyID == nullKeyID || ownerKeyID == nullKeyID)
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake() : cold stake has null key (staker=%s, owner=%s)\n",
                                   (stakerKeyID == nullKeyID) ? "null" : "ok", (ownerKeyID == nullKeyID) ? "null" : "ok");
                        break;
                    }

                    if (stakerKeyID == ownerKeyID)
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake() : cold stake staker and owner keys are identical\n");
                        break;
                    }

                    if (!keystore.GetKey(stakerKeyID, key))
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake() : failed to get staker key for cold stake\n");
                        break;
                    }

                    CScript regeneratedScript = GetScriptForColdStaking(stakerKeyID, ownerKeyID);
                    if (regeneratedScript != scriptPubKeyKernel)
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake() : regenerated cold stake script does not match original\n");
                        break;
                    }

                    scriptPubKeyOut = scriptPubKeyKernel;
                }
                else if (whichType == TX_PUBKEYHASH)
                {
                    // convert to pay to public key type
                    if (!keystore.GetKey(uint160(vSolutions[0]), key))
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake() : failed to get key for kernel type=%d\n", whichType);
                        break;  // unable to find corresponding public key
                    }
                    scriptPubKeyOut << key.GetPubKey() << OP_CHECKSIG;
                }
                else if (whichType == TX_PUBKEY)
                {
                    valtype& vchPubKey = vSolutions[0];
                    if (!keystore.GetKey(Hash160(vchPubKey), key))
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake() : failed to get key for kernel type=%d\n", whichType);
                        break;  // unable to find corresponding public key
                    }

                if (key.GetPubKey() != vchPubKey)
                {
                    if (fDebug && GetBoolArg("-printcoinstake"))
                        printf("CreateCoinStake() : invalid key for kernel type=%d\n", whichType);
                        break; // keys mismatch
                    }

                    scriptPubKeyOut = scriptPubKeyKernel;
                }

                txNew.nTime -= n;
                txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
                nCredit += pcoin.first->vout[pcoin.second].nValue;
                vwtxPrev.push_back(pcoin.first);
                txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));

                if (GetWeight(block.GetBlockTime(), (int64_t)txNew.nTime) < nStakeSplitAge && nCredit > nStakeMinSplitThreshold)
                    txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake() : added kernel type=%d\n", whichType);
                fKernelFound = true;
                break;
            }
        }

        if (fKernelFound || fShutdown)
            break; // if kernel is found stop searching
    }



    if (nCredit == 0 || nCredit > nBalance - nReserveBalance)
    {
        bool fTryNullStake = (eStakingMode == STAKE_NULLSTAKE);
        if (fDebug)
            printf("CreateCoinStake() : nCredit=%" PRId64 " height=%d forkNullStake=%d\n",
                   nCredit, pindexPrev->nHeight + 1, FORK_HEIGHT_NULLSTAKE);
        if (fTryNullStake && pindexPrev->nHeight + 1 >= FORK_HEIGHT_NULLSTAKE)
        {
            LOCK(cs_shielded);

            if (mapShieldedSpendingKeys.empty())
                return false;

            const CShieldedPaymentAddress& zAddr = mapShieldedSpendingKeys.begin()->first;
            const CShieldedSpendingKey& sk = mapShieldedSpendingKeys.begin()->second;

            CShieldedFullViewingKey fvk;
            if (!DeriveShieldedFullViewingKey(sk, fvk))
                return false;

            if (fDebug)
                printf("CreateCoinStake() : NullStake trying %d shielded notes\n", (int)vShieldedNotes.size());

            for (size_t ni = 0; ni < vShieldedNotes.size(); ni++)
            {
                // abort if chain tip changed (stale pindexPrev)
                {
                    LOCK(cs_main);
                    if (pindexPrev != pindexBest)
                        return false;
                }

                CShieldedWalletNote& wnote = vShieldedNotes[ni];
                if (fDebug)
                    printf("CreateCoinStake() : NullStake note[%d] spent=%d value=%" PRId64 " height=%d\n",
                           (int)ni, wnote.fSpent, wnote.note.nValue, wnote.nHeight);
                if (wnote.fSpent || wnote.note.nValue <= 0)
                    continue;

                if (wnote.nHeight <= 0)
                    continue;

                std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(wnote.txhash);
                CBlockIndex* pNoteBlock = NULL;
                {
                    CBlockIndex* pTest = pindexPrev;
                    while (pTest && pTest->nHeight > wnote.nHeight)
                        pTest = pTest->pprev;
                    if (pTest && pTest->nHeight == wnote.nHeight)
                        pNoteBlock = pTest;
                }
                if (!pNoteBlock)
                {
                    if (fDebug) printf("CreateCoinStake() : NullStake pNoteBlock not found for height %d\n", wnote.nHeight);
                    continue;
                }

                unsigned int nBlockTimeFrom = pNoteBlock->GetBlockTime();
                if (nBlockTimeFrom + nStakeMinAge > txNew.nTime)
                {
                    if (fDebug) printf("CreateCoinStake() : NullStake note too young blockTime=%u minAge=%u txTime=%u\n", nBlockTimeFrom, nStakeMinAge, txNew.nTime);
                    continue;
                }

                uint64_t nStakeModifier = 0;
                {
                    int nStakeModifierHeight = 0;
                    int64_t nStakeModifierTime = 0;
                    uint256 hashBlock = pNoteBlock->GetBlockHash();
                    if (!GetKernelStakeModifier(hashBlock, nStakeModifier, nStakeModifierHeight, nStakeModifierTime, false))
                    {
                        if (fRegTest && pindexPrev)
                        {
                            nStakeModifier = pindexPrev->nStakeModifier;
                            if (fDebug) printf("CreateCoinStake() : NullStake using fallback stake modifier from best block\n");
                        }
                        else
                        {
                            if (fDebug) printf("CreateCoinStake() : NullStake GetKernelStakeModifier failed\n");
                            continue;
                        }
                    }
                }

                int64_t nWeight = GetWeight((int64_t)nBlockTimeFrom, (int64_t)txNew.nTime);

                bool fShieldedKernelFound = false;
                unsigned int nTxPrevOffset = 0; // Shielded: no offset (uses note position)
                unsigned int nVoutN = wnote.nPosition;

                if (fDebug)
                    printf("CreateCoinStake() : NullStake note ni=%d value=%" PRId64 " weight=%" PRId64 " blockTimeFrom=%u nBits=%08x\n",
                           (int)ni, wnote.note.nValue, nWeight, nBlockTimeFrom, nBits);

                bool fUseNullStakeV2 = (pindexPrev->nHeight + 1 >= FORK_HEIGHT_NULLSTAKE_V2);

                for (unsigned int n = 0; n < min(nSearchInterval, (int64_t)nMaxStakeSearchInterval) && !fShieldedKernelFound && !fShutdown; n++)
                {
                    unsigned int nTimeTx = txNew.nTime - n;

                    bool fKernelOk = false;
                    if (fUseNullStakeV2)
                    {
                        fKernelOk = CheckShieldedStakeKernelHashV2(nBits, nStakeModifier,
                                                                     nBlockTimeFrom, nTxPrevOffset,
                                                                     pNoteBlock->nTime, nVoutN,
                                                                     nTimeTx, wnote.note.nValue, nWeight);
                    }
                    else
                    {
                        fKernelOk = CheckShieldedStakeKernelHash(nBits, nStakeModifier,
                                                                   nBlockTimeFrom, nTxPrevOffset,
                                                                   pNoteBlock->nTime, nVoutN,
                                                                   nTimeTx, wnote.note.nValue, nWeight);
                    }

                    if (fKernelOk)
                    {
                        if (fDebug)
                            printf("CreateCoinStake() : NullStake%s kernel FOUND at n=%u\n",
                                   fUseNullStakeV2 ? " V2" : "", n);
                        fShieldedKernelFound = true;
                        txNew.nTime -= n;

                        txNew.nVersion = fUseNullStakeV2 ? SHIELDED_TX_VERSION_NULLSTAKE_V2 : SHIELDED_TX_VERSION_NULLSTAKE;
                        txNew.nPrivacyMode = PRIVACY_MODE_FULL;

                        txNew.vin.clear();

                        CShieldedSpendDescription stakeSpend;

                        if (wnote.note.vchBlind.empty())
                            wnote.note.GenerateBlindingFactor();

                        if (!wnote.note.GetPedersenCommitment(stakeSpend.cv))
                            continue;

                        if (!CreateBulletproofRangeProof(wnote.note.nValue, wnote.note.vchBlind,
                                                          stakeSpend.cv, stakeSpend.rangeProof))
                            continue;

                        stakeSpend.nullifier = wnote.note.GetNullifier(fvk.nk);

                        {
                            CIncrementalMerkleTree tree;
                            txdb.ReadShieldedTree(tree);
                            stakeSpend.anchor = tree.Root();

                            std::vector<CPedersenCommitment> vAllCommitments;
                            txdb.ReadAllShieldedCommitments(vAllCommitments);

                            CAnonymitySet anonSet;
                            if (!BuildAnonymitySet(stakeSpend.cv, vAllCommitments, stakeSpend.anchor,
                                                    pindexPrev->nHeight, anonSet))
                                continue;

                            int nRealIndex = anonSet.FindIndex(stakeSpend.cv);
                            if (nRealIndex < 0)
                                continue;

                            CLelantusProof lelantusProof;
                            int64_t nGlobalOutputIndex = -1;
                            for (size_t ci = 0; ci < vAllCommitments.size(); ci++)
                            {
                                if (vAllCommitments[ci] == stakeSpend.cv) { nGlobalOutputIndex = (int64_t)ci; break; }
                            }
                            int64_t nSerialIdx = (pindexPrev->nHeight >= FORK_HEIGHT_SERIAL_V2) ? nGlobalOutputIndex : -1;
                            uint256 serial = ComputeLelantusSerial(sk.skSpend, wnote.note.rho, stakeSpend.cv, nSerialIdx);
                            if (!CreateLelantusProof(anonSet, nRealIndex, wnote.note.nValue,
                                                      wnote.note.vchBlind, serial, lelantusProof))
                                continue;

                            stakeSpend.vchLelantusProof = lelantusProof.vchProof;
                            stakeSpend.lelantusSerial = serial;
                            stakeSpend.vAnonSet = anonSet.vCommitments;
                        }

                        {
                            CCurveTree fcmpTree;
                            txdb.ReadCurveTree(fcmpTree);

                            int64_t nLeafIdx = fcmpTree.FindLeafIndex(stakeSpend.cv);
                            if (nLeafIdx < 0)
                                continue;

                            if (!CreateFCMPProof(fcmpTree, (uint64_t)nLeafIdx, wnote.note.vchBlind,
                                                  wnote.note.nValue, stakeSpend.cv, stakeSpend.fcmpProof))
                                continue;

                            stakeSpend.curveTreeRoot = fcmpTree.GetRoot();
                        }

                        txNew.vShieldedSpend.push_back(stakeSpend);
                        if (fUseNullStakeV2)
                        {
                            CNullStakeKernelProofV2 kernelProofV2;
                            if (!CreateNullStakeKernelProofV2(wnote.note.nValue, wnote.note.vchBlind,
                                                              stakeSpend.cv, nBits,
                                                              nStakeModifier, nBlockTimeFrom,
                                                              nTxPrevOffset, pNoteBlock->nTime,
                                                              nVoutN, nTimeTx, kernelProofV2))
                                continue;
                            txNew.nullstakeProofV2 = kernelProofV2;
                        }
                        else
                        {
                            CNullStakeKernelProof kernelProof;
                            if (!CreateNullStakeKernelProof(wnote.note.nValue, wnote.note.vchBlind,
                                                            stakeSpend.cv, nBits, nWeight,
                                                            nStakeModifier, nBlockTimeFrom,
                                                            nTxPrevOffset, pNoteBlock->nTime,
                                                            nVoutN, nTimeTx, kernelProof))
                                continue;
                            txNew.nullstakeProof = kernelProof;
                        }

                        int64_t nTimeWeight = nWeight > 0 ? nWeight : 1;
                        uint64_t nCoinAge = (uint64_t)((wnote.note.nValue / COIN) * nTimeWeight / (24 * 60 * 60));
                        if (nCoinAge == 0) nCoinAge = 1; // Minimum 1 coin-day
                        int64_t nReward = GetProofOfStakeReward(nCoinAge, nFees);
                        if (nReward <= 0)
                            continue;

                        std::vector<std::vector<unsigned char>> vInputBlinds;
                        std::vector<std::vector<unsigned char>> vOutputBlinds;
                        vInputBlinds.push_back(wnote.note.vchBlind);

                        {
                            CShieldedNote returnNote;
                            returnNote.addr = zAddr;
                            returnNote.nValue = wnote.note.nValue;
                            unsigned char rnd[32];
                            RAND_bytes(rnd, 32);
                            memcpy(returnNote.rho.begin(), rnd, 32);
                            RAND_bytes(rnd, 32);
                            memcpy(returnNote.rcm.begin(), rnd, 32);
                            OPENSSL_cleanse(rnd, 32);
                            returnNote.GenerateBlindingFactor();

                            CPedersenCommitment returnCv;
                            returnNote.GetPedersenCommitment(returnCv);
                            CBulletproofRangeProof returnProof;
                            CreateBulletproofRangeProof(returnNote.nValue, returnNote.vchBlind, returnCv, returnProof);

                            CShieldedOutputDescription returnOutput;
                            returnOutput.cv = returnCv;
                            returnOutput.cmu = returnNote.GetCommitment();
                            returnOutput.rangeProof = returnProof;
                            EncryptShieldedNote(returnNote, zAddr, returnOutput.vchEphemeralKey, returnOutput.vchEncCiphertext);
                            EncryptShieldedNoteForSender(returnNote, sk.ovk, returnCv.GetHash(), returnOutput.cmu,
                                                          returnOutput.vchEphemeralKey, returnOutput.vchOutCiphertext);

                            txNew.vShieldedOutput.push_back(returnOutput);
                            vOutputBlinds.push_back(returnNote.vchBlind);
                        }

                        {
                            CShieldedNote rewardNote;
                            rewardNote.addr = zAddr;
                            rewardNote.nValue = nReward;
                            unsigned char rnd[32];
                            RAND_bytes(rnd, 32);
                            memcpy(rewardNote.rho.begin(), rnd, 32);
                            RAND_bytes(rnd, 32);
                            memcpy(rewardNote.rcm.begin(), rnd, 32);
                            OPENSSL_cleanse(rnd, 32);
                            rewardNote.GenerateBlindingFactor();

                            CPedersenCommitment rewardCv;
                            rewardNote.GetPedersenCommitment(rewardCv);
                            CBulletproofRangeProof rewardProof;
                            CreateBulletproofRangeProof(rewardNote.nValue, rewardNote.vchBlind, rewardCv, rewardProof);

                            CShieldedOutputDescription rewardOutput;
                            rewardOutput.cv = rewardCv;
                            rewardOutput.cmu = rewardNote.GetCommitment();
                            rewardOutput.rangeProof = rewardProof;
                            EncryptShieldedNote(rewardNote, zAddr, rewardOutput.vchEphemeralKey, rewardOutput.vchEncCiphertext);
                            EncryptShieldedNoteForSender(rewardNote, sk.ovk, rewardCv.GetHash(), rewardOutput.cmu,
                                                          rewardOutput.vchEphemeralKey, rewardOutput.vchOutCiphertext);

                            txNew.vShieldedOutput.push_back(rewardOutput);
                            vOutputBlinds.push_back(rewardNote.vchBlind);
                        }

                        txNew.nValueBalance = -nReward; // negative = value entering shielded pool

                        {
                            uint256 spendSighash = txNew.GetBindingSigHash();
                            if (!CreateSpendAuthSignature(sk.skSpend, spendSighash,
                                                           txNew.vShieldedSpend[0].vchRk,
                                                           txNew.vShieldedSpend[0].vchSpendAuthSig))
                                continue;
                        }

                        {
                            uint256 sighash = txNew.GetBindingSigHash();
                            CBindingSignature bindingSig;
                            CreateBindingSignature(vInputBlinds, vOutputBlinds, sighash, bindingSig);
                            txNew.bindingSig.bindingSig = bindingSig;
                        }

                        txNew.vShieldedSpend[0].nPlaintextValue = -1;
                        txNew.vShieldedSpend[0].vchPlaintextBlind.clear();
                        txNew.vShieldedOutput[0].nPlaintextValue = -1;
                        txNew.vShieldedOutput[0].vchPlaintextBlind.clear();
                        txNew.vShieldedOutput[1].nPlaintextValue = -1;
                        txNew.vShieldedOutput[1].vchPlaintextBlind.clear();

                        if (fDebug)
                            printf("CreateCoinStake() : NullStake shielded stake found, value=%" PRId64 ", reward=%" PRId64 "\n",
                                   wnote.note.nValue, nReward);

                        {
                            bool bCNPayment = false;
                            if (fTestNet) {
                                if (pindexPrev->nHeight+1 > BLOCK_START_COLLATERALNODE_PAYMENTS_TESTNET)
                                    bCNPayment = true;
                            } else {
                                if (pindexPrev->nHeight+1 > BLOCK_START_COLLATERALNODE_PAYMENTS && pindexPrev->nHeight+1 > 2085000)
                                    bCNPayment = true;
                            }

                            if (bCNPayment)
                            {
                                CScript cnPayee;
                                bool hasCNPayee = false;
                                if (collateralnodePayments.GetBlockPayee(pindexPrev->nHeight+1, cnPayee)) {
                                    hasCNPayee = true;
                                } else {
                                    int winningNode = GetCollateralnodeByRank(1);
                                    if (winningNode >= 0) {
                                        BOOST_FOREACH(PAIRTYPE(int, CCollateralNode*)& s, vecCollateralnodeScores)
                                        {
                                            if (s.first == winningNode) {
                                                cnPayee.SetDestination(s.second->pubkey.GetID());
                                                hasCNPayee = true;
                                                break;
                                            }
                                        }
                                    }
                                    if (!hasCNPayee) {
                                        std::string burnAddr = fTestNet ? "8TestXXXXXXXXXXXXXXXXXXXXXXXXbCvpq" : "INNXXXXXXXXXXXXXXXXXXXXXXXXXZeeDTw";
                                        CBitcoinAddress burnDest;
                                        burnDest.SetString(burnAddr);
                                        cnPayee = GetScriptForDestination(burnDest.Get());
                                        hasCNPayee = true;
                                    }
                                }

                                if (hasCNPayee) {
                                    int64_t cnPayment = GetCollateralnodePayment(pindexPrev->nHeight+1, nReward);
                                    if (cnPayment > 0 && cnPayment < nReward) {
                                        txNew.vout.push_back(CTxOut(cnPayment, cnPayee));
                                        txNew.nValueBalance += cnPayment;

                                        if (fDebug) {
                                            CTxDestination addr1;
                                            ExtractDestination(cnPayee, addr1);
                                            CBitcoinAddress addr2(addr1);
                                            printf("CreateCoinStake() : NullStake CN payment %" PRId64 " to %s\n",
                                                   cnPayment, addr2.ToString().c_str());
                                        }
                                    }
                                }
                            }
                        }

                        wnote.fSpent = true;

                        OPENSSL_cleanse(&fvk, sizeof(fvk));

                        // Sign with skSpend (CheckBlockSignature verifies against vchRk = skSpend*G)
                        key.Set(sk.skSpend.begin(), sk.skSpend.end(), true);
                        if (!key.IsValid()) {
                            printf("CreateCoinStake() : NullStake block signing key invalid\n");
                            continue;
                        }

                        return true;
                    }
                }

                if (fShutdown)
                    return false;
            }
        }

        bool fTryNullStakeCold = (eStakingMode == STAKE_NULLSTAKE_COLD);
        if (fTryNullStakeCold && pindexPrev->nHeight + 1 >= FORK_HEIGHT_NULLSTAKE_V3)
        {
            LOCK2(cs_main, cs_shielded);  // Lock ordering: cs_main before cs_shielded

            if (mapColdStakeDelegations.empty())
            {
                if (fDebug) printf("CreateCoinStake() : NullStake V3 no delegations available\n");
                return false;
            }

            for (std::map<uint256, CColdStakeDelegation>::iterator dit = mapColdStakeDelegations.begin();
                 dit != mapColdStakeDelegations.end(); ++dit)
            {
                const CColdStakeDelegation& deleg = dit->second;
                uint256 delegHash = deleg.GetDelegationHash();

                uint256 skStake;
                if (deleg.vchSkStakeEnc.size() == 32)
                {
                    memcpy(skStake.begin(), deleg.vchSkStakeEnc.data(), 32);
                }
                else
                {
                    if (fDebug) printf("CreateCoinStake() : NullStake V3 cannot decrypt delegation key\n");
                    continue;
                }

                for (size_t ni = 0; ni < vShieldedNotes.size(); ni++)
                {
                    if (pindexPrev != pindexBest)
                        return false;

                    CShieldedWalletNote& wnote = vShieldedNotes[ni];
                    if (wnote.fSpent || wnote.note.nValue <= 0)
                        continue;

                    if (deleg.nDelegateAmount > 0 && wnote.note.nValue > deleg.nDelegateAmount)
                        continue;

                    if (wnote.nHeight <= 0)
                        continue;

                    CBlockIndex* pNoteBlock = NULL;
                    {
                        CBlockIndex* pTest = pindexPrev;
                        while (pTest && pTest->nHeight > wnote.nHeight)
                            pTest = pTest->pprev;
                        if (pTest && pTest->nHeight == wnote.nHeight)
                            pNoteBlock = pTest;
                    }
                    if (!pNoteBlock)
                        continue;

                    unsigned int nBlockTimeFrom = pNoteBlock->GetBlockTime();
                    if (nBlockTimeFrom + nStakeMinAge > txNew.nTime)
                        continue;

                    uint64_t nStakeModifier = 0;
                    {
                        int nStakeModifierHeight = 0;
                        int64_t nStakeModifierTime = 0;
                        uint256 hashBlock = pNoteBlock->GetBlockHash();
                        if (!GetKernelStakeModifier(hashBlock, nStakeModifier, nStakeModifierHeight, nStakeModifierTime, false))
                        {
                            if (fRegTest && pindexPrev)
                                nStakeModifier = pindexPrev->nStakeModifier;
                            else
                                continue;
                        }
                    }

                    int64_t nWeight = GetWeight((int64_t)nBlockTimeFrom, (int64_t)txNew.nTime);
                    unsigned int nTxPrevOffset = 0;
                    unsigned int nVoutN = wnote.nPosition;

                    bool fShieldedKernelFound = false;
                    for (unsigned int n = 0; n < min(nSearchInterval, (int64_t)nMaxStakeSearchInterval) && !fShieldedKernelFound && !fShutdown; n++)
                    {
                        unsigned int nTimeTx = txNew.nTime - n;

                        bool fKernelOk = CheckShieldedStakeKernelHashV3(nBits, nStakeModifier,
                                                                         nBlockTimeFrom, nTxPrevOffset,
                                                                         pNoteBlock->nTime, nVoutN,
                                                                         nTimeTx, wnote.note.nValue, nWeight);
                        if (fKernelOk)
                        {
                            if (fDebug)
                                printf("CreateCoinStake() : NullStake V3 cold stake kernel FOUND at n=%u\n", n);
                            fShieldedKernelFound = true;
                            txNew.nTime -= n;

                            txNew.nVersion = SHIELDED_TX_VERSION_NULLSTAKE_COLD;
                            txNew.nPrivacyMode = PRIVACY_MODE_FULL;
                            txNew.vin.clear();

                            CShieldedSpendDescription stakeSpend;

                            if (wnote.note.vchBlind.empty())
                                wnote.note.GenerateBlindingFactor();
                            if (!wnote.note.GetPedersenCommitment(stakeSpend.cv))
                                continue;
                            if (!CreateBulletproofRangeProof(wnote.note.nValue, wnote.note.vchBlind,
                                                              stakeSpend.cv, stakeSpend.rangeProof))
                                continue;

                            // Derive nullifier from skStake (staker has no skSpend)
                            {
                                CHashWriter ssNk(SER_GETHASH, 0);
                                ssNk << std::string("Innova/ColdStake/Nk/v1");
                                ssNk << skStake;
                                uint256 nkCold = ssNk.GetHash();
                                stakeSpend.nullifier = wnote.note.GetNullifier(nkCold);
                            }

                            if (mapShieldedSpendingKeys.empty())
                                continue;
                            const CShieldedPaymentAddress& zAddr = mapShieldedSpendingKeys.begin()->first;
                            const CShieldedSpendingKey& sk = mapShieldedSpendingKeys.begin()->second;

                            {
                                CIncrementalMerkleTree tree;
                                txdb.ReadShieldedTree(tree);
                                stakeSpend.anchor = tree.Root();

                                std::vector<CPedersenCommitment> vAllCommitments;
                                txdb.ReadAllShieldedCommitments(vAllCommitments);

                                CAnonymitySet anonSet;
                                if (!BuildAnonymitySet(stakeSpend.cv, vAllCommitments, stakeSpend.anchor,
                                                        pindexPrev->nHeight, anonSet))
                                    continue;

                                int nRealIndex = anonSet.FindIndex(stakeSpend.cv);
                                if (nRealIndex < 0)
                                    continue;

                                int64_t nGlobalOutputIndex = -1;
                                for (size_t ci = 0; ci < vAllCommitments.size(); ci++)
                                {
                                    if (vAllCommitments[ci] == stakeSpend.cv) { nGlobalOutputIndex = (int64_t)ci; break; }
                                }
                                int64_t nSerialIdx = (pindexPrev->nHeight >= FORK_HEIGHT_SERIAL_V2) ? nGlobalOutputIndex : -1;
                                uint256 serial = ComputeLelantusSerial(skStake, wnote.note.rho, stakeSpend.cv, nSerialIdx);
                                CLelantusProof lelantusProof;
                                if (!CreateLelantusProof(anonSet, nRealIndex, wnote.note.nValue,
                                                          wnote.note.vchBlind, serial, lelantusProof))
                                    continue;

                                stakeSpend.vchLelantusProof = lelantusProof.vchProof;
                                stakeSpend.lelantusSerial = serial;
                                stakeSpend.vAnonSet = anonSet.vCommitments;
                            }

                            {
                                CCurveTree fcmpTree;
                                txdb.ReadCurveTree(fcmpTree);

                                int64_t nLeafIdx = fcmpTree.FindLeafIndex(stakeSpend.cv);
                                if (nLeafIdx < 0)
                                    continue;

                                if (!CreateFCMPProof(fcmpTree, (uint64_t)nLeafIdx, wnote.note.vchBlind,
                                                      wnote.note.nValue, stakeSpend.cv, stakeSpend.fcmpProof))
                                    continue;

                                stakeSpend.curveTreeRoot = fcmpTree.GetRoot();
                            }

                            txNew.vShieldedSpend.push_back(stakeSpend);

                            std::vector<unsigned char> vchPkOwner = deleg.vchPkOwner;
                            if (vchPkOwner.size() != 33)
                            {
                                printf("CreateCoinStake() : NullStake V3 delegation missing owner pubkey\n");
                                continue;
                            }

                            CNullStakeKernelProofV3 kernelProofV3;
                            if (!CreateNullStakeKernelProofV3(wnote.note.nValue, wnote.note.vchBlind,
                                                              stakeSpend.cv, nBits,
                                                              nStakeModifier, nBlockTimeFrom,
                                                              nTxPrevOffset, pNoteBlock->nTime,
                                                              nVoutN, nTimeTx,
                                                              skStake, vchPkOwner, delegHash,
                                                              kernelProofV3))
                                continue;
                            txNew.nullstakeProofV3 = kernelProofV3;

                            uint64_t nCoinAge = 1;  // Conservative: matches consensus V3 validation
                            int64_t nReward = GetProofOfStakeReward(nCoinAge, nFees);
                            if (nReward <= 0)
                                continue;

                            const CShieldedPaymentAddress& ownerZAddr = deleg.ownerAddr;
                            const uint256& ownerOvk = deleg.ownerOvk;

                            std::vector<std::vector<unsigned char>> vInputBlinds;
                            std::vector<std::vector<unsigned char>> vOutputBlinds;
                            vInputBlinds.push_back(wnote.note.vchBlind);

                            {
                                CShieldedNote returnNote;
                                returnNote.addr = ownerZAddr;
                                returnNote.nValue = wnote.note.nValue;
                                unsigned char rnd[32];
                                RAND_bytes(rnd, 32);
                                memcpy(returnNote.rho.begin(), rnd, 32);
                                RAND_bytes(rnd, 32);
                                memcpy(returnNote.rcm.begin(), rnd, 32);
                                OPENSSL_cleanse(rnd, 32);
                                returnNote.GenerateBlindingFactor();

                                CPedersenCommitment returnCv;
                                returnNote.GetPedersenCommitment(returnCv);
                                CBulletproofRangeProof returnProof;
                                CreateBulletproofRangeProof(returnNote.nValue, returnNote.vchBlind, returnCv, returnProof);

                                CShieldedOutputDescription returnOutput;
                                returnOutput.cv = returnCv;
                                returnOutput.cmu = returnNote.GetCommitment();
                                returnOutput.rangeProof = returnProof;
                                EncryptShieldedNote(returnNote, ownerZAddr, returnOutput.vchEphemeralKey, returnOutput.vchEncCiphertext);
                                EncryptShieldedNoteForSender(returnNote, ownerOvk, returnCv.GetHash(), returnOutput.cmu,
                                                              returnOutput.vchEphemeralKey, returnOutput.vchOutCiphertext);

                                txNew.vShieldedOutput.push_back(returnOutput);
                                vOutputBlinds.push_back(returnNote.vchBlind);
                            }

                            {
                                CShieldedNote rewardNote;
                                rewardNote.addr = ownerZAddr;
                                rewardNote.nValue = nReward;
                                unsigned char rnd[32];
                                RAND_bytes(rnd, 32);
                                memcpy(rewardNote.rho.begin(), rnd, 32);
                                RAND_bytes(rnd, 32);
                                memcpy(rewardNote.rcm.begin(), rnd, 32);
                                OPENSSL_cleanse(rnd, 32);
                                rewardNote.GenerateBlindingFactor();

                                CPedersenCommitment rewardCv;
                                rewardNote.GetPedersenCommitment(rewardCv);
                                CBulletproofRangeProof rewardProof;
                                CreateBulletproofRangeProof(rewardNote.nValue, rewardNote.vchBlind, rewardCv, rewardProof);

                                CShieldedOutputDescription rewardOutput;
                                rewardOutput.cv = rewardCv;
                                rewardOutput.cmu = rewardNote.GetCommitment();
                                rewardOutput.rangeProof = rewardProof;
                                EncryptShieldedNote(rewardNote, ownerZAddr, rewardOutput.vchEphemeralKey, rewardOutput.vchEncCiphertext);
                                EncryptShieldedNoteForSender(rewardNote, ownerOvk, rewardCv.GetHash(), rewardOutput.cmu,
                                                              rewardOutput.vchEphemeralKey, rewardOutput.vchOutCiphertext);

                                txNew.vShieldedOutput.push_back(rewardOutput);
                                vOutputBlinds.push_back(rewardNote.vchBlind);
                            }

                            txNew.nValueBalance = -nReward;

                            // (staker doesn't have owner's skSpend; skStake is the delegated authority)
                            {
                                uint256 spendSighash = txNew.GetBindingSigHash();
                                if (!CreateSpendAuthSignature(skStake, spendSighash,
                                                               txNew.vShieldedSpend[0].vchRk,
                                                               txNew.vShieldedSpend[0].vchSpendAuthSig))
                                    continue;
                            }

                            {
                                uint256 sighash = txNew.GetBindingSigHash();
                                CBindingSignature bindingSig;
                                CreateBindingSignature(vInputBlinds, vOutputBlinds, sighash, bindingSig);
                                txNew.bindingSig.bindingSig = bindingSig;
                            }

                            txNew.vShieldedSpend[0].nPlaintextValue = -1;
                            txNew.vShieldedSpend[0].vchPlaintextBlind.clear();
                            txNew.vShieldedOutput[0].nPlaintextValue = -1;
                            txNew.vShieldedOutput[0].vchPlaintextBlind.clear();
                            txNew.vShieldedOutput[1].nPlaintextValue = -1;
                            txNew.vShieldedOutput[1].vchPlaintextBlind.clear();

                            if (fDebug)
                                printf("CreateCoinStake() : NullStake V3 cold stake found, value=%" PRId64 ", reward=%" PRId64 "\n",
                                       wnote.note.nValue, nReward);

                            wnote.fSpent = true;

                            key.Set(skStake.begin(), skStake.end(), true);
                            if (!key.IsValid()) {
                                printf("CreateCoinStake() : NullStake V3 block signing key invalid\n");
                                continue;
                            }

                            OPENSSL_cleanse(skStake.begin(), 32);
                            return true;
                        }
                    }

                    if (fShutdown)
                        return false;
                }
            }
        }
        return false;
    }

    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        // Attempt to add more inputs
        // Only add coins of the same key/address as kernel
        if (txNew.vout.size() == 2 && ((pcoin.first->vout[pcoin.second].scriptPubKey == scriptPubKeyKernel || pcoin.first->vout[pcoin.second].scriptPubKey == txNew.vout[1].scriptPubKey))
            && pcoin.first->GetHash() != txNew.vin[0].prevout.hash)
        {
            int64_t nTimeWeight = GetWeight((int64_t)pcoin.first->nTime, (int64_t)txNew.nTime);

            // Stop adding more inputs if already too many inputs
            if (txNew.vin.size() >= 100)
                break;
            // Stop adding more inputs if value is already pretty significant
            if (nCredit >= nStakeCombineThreshold)
                break;
            // Stop adding inputs if reached reserve limit
            if (nCredit + pcoin.first->vout[pcoin.second].nValue > nBalance - nReserveBalance)
                break;
            // Do not add additional significant input
            if (pcoin.first->vout[pcoin.second].nValue >= nStakeCombineThreshold)
                continue;
            // Do not add input that is still too young
            if (nTimeWeight < nStakeMinAge)
                continue;

            txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
            nCredit += pcoin.first->vout[pcoin.second].nValue;
            vwtxPrev.push_back(pcoin.first);
        }
    }

    // Calculate coin age reward
    int64_t nReward;
    {
        uint64_t nCoinAge;
        CTxDB txdb("r");
        if (!txNew.GetCoinAge(txdb, nCoinAge))
            return error("CreateCoinStake() : failed to calculate coin age");

        nReward = GetProofOfStakeReward(nCoinAge, nFees);
        if (nReward <= 0)
            return false;

        nCredit += nReward;
    }

	// Collateralnode Payments
    int payments = 1;
    // start collateralnode payments
    bool bCollateralNodePayment = false;

    if (fTestNet) {
        if (pindexPrev->nHeight+1 > BLOCK_START_COLLATERALNODE_PAYMENTS_TESTNET ) {
            bCollateralNodePayment = true;
        }
    } else {
        if (pindexPrev->nHeight+1 > BLOCK_START_COLLATERALNODE_PAYMENTS && pindexPrev->nHeight+1 > 2085000){
            bCollateralNodePayment = true;
        }
    }
    if(fDebug) { printf("CreateCoinStake() : Collateralnode Payments = %i!\n", bCollateralNodePayment); }

    CScript payee;
    bool hasPayment = false;
    if(bCollateralNodePayment) {
        //spork
        if(!collateralnodePayments.GetBlockPayee(pindexPrev->nHeight+1, payee)){
            int winningNode = GetCollateralnodeByRank(1);
                if(winningNode >= 0){
                    BOOST_FOREACH(PAIRTYPE(int, CCollateralNode*)& s, vecCollateralnodeScores)
                    {
                        if (s.first == winningNode)
                        {
                            payee.SetDestination(s.second->pubkey.GetID());
                            break;
                        }
                    }
                } else {
                    if(fDebug) { printf("CreateCoinStake() : Failed to detect collateralnode to pay\n"); }
                    // collateralnodes are in-eligible for payment, burn the coins in-stead
                    std::string burnAddress;
                    if (fTestNet) burnAddress = "8TestXXXXXXXXXXXXXXXXXXXXXXXXbCvpq";
                    else burnAddress = "INNXXXXXXXXXXXXXXXXXXXXXXXXXZeeDTw";
                    CBitcoinAddress burnDestination;
                    burnDestination.SetString(burnAddress);
                    payee = GetScriptForDestination(burnDestination.Get());
                }
        }
        hasPayment = true; // Payment target resolved (CN, winner, or burn)
    }

    if(hasPayment){
        payments = txNew.vout.size() + 1;
        txNew.vout.resize(payments);

        txNew.vout[payments-1].scriptPubKey = payee;
        txNew.vout[payments-1].nValue = 0;

        CTxDestination address1;
        ExtractDestination(payee, address1);
        CBitcoinAddress address2(address1);

        if(fDebug) { printf("CreateCoinStake() : Collateralnode payment to %s\n", address2.ToString().c_str()); }
    }

    int64_t blockValue = nCredit;
    int64_t collateralnodePayment = GetCollateralnodePayment(pindexPrev->nHeight+1, nReward);


    // Set output amount
    if (!hasPayment && txNew.vout.size() == 3) // 2 stake outputs, stake was split, no collateralnode payment
    {
        if(fDebug) { printf("CreateCoinStake() : 2 stake outputs, No MN payment!\n"); }
        txNew.vout[1].nValue = (blockValue / 2 / CENT) * CENT;
        txNew.vout[2].nValue = blockValue - txNew.vout[1].nValue;
    }
    else if(hasPayment && txNew.vout.size() == 4) // 2 stake outputs, stake was split, plus a collateralnode payment
    {
        if(fDebug) { printf("CreateCoinStake() : 2 stake outputs, Split stake, with MN payment\n"); }
        txNew.vout[payments-1].nValue = collateralnodePayment;
        blockValue -= collateralnodePayment;
        txNew.vout[1].nValue = (blockValue / 2 / CENT) * CENT;
        txNew.vout[2].nValue = blockValue - txNew.vout[1].nValue;
    }
    else if(!hasPayment && txNew.vout.size() == 2) // only 1 stake output, was not split, no collateralnode payment
    {
        if(fDebug) { printf("CreateCoinStake() : 1 Stake output, No MN payment!\n"); }
        txNew.vout[1].nValue = blockValue;
    }
    else if(hasPayment && txNew.vout.size() == 3) // only 1 stake output, was not split, plus a collateralnode payment
    {
        if(fDebug) { printf("CreateCoinStake() : 1 stake output, With MN payment!\n"); }
        txNew.vout[payments-1].nValue = collateralnodePayment;
        blockValue -= collateralnodePayment;
        txNew.vout[1].nValue = blockValue;
    }

    // Sign
    int nIn = 0;
    BOOST_FOREACH(const CWalletTx* pcoin, vwtxPrev)
    {
        if (!SignSignature(*this, *pcoin, txNew, nIn++))
            return error("CreateCoinStake() : failed to sign coinstake");
    }

    // Limit size
    unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
    if (nBytes >= MAX_BLOCK_SIZE_GEN/5)
        return error("CreateCoinStake() : exceeded coinstake size limit");

    // Successfully generated coinstake
    return true;
}


// Call after CreateTransaction unless you want to abort
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey)
{

    if (!wtxNew.CheckTransaction())
    {
        printf("CommitTransaction: CheckTransaction() failed %s\n", wtxNew.GetHash().ToString().c_str());
        {
            LOCK(cs_wallet);
            for (std::vector<COutPoint>::iterator it = wtxNew.vReservedCoins.begin();
                 it != wtxNew.vReservedCoins.end(); ++it)
            {
                UnlockCoin(*it);
            }
            wtxNew.vReservedCoins.clear();
        }
        return false;
    };

    mapValue_t mapNarr;
    if (stealthAddresses.size() > 0 && !fDisableStealth) FindStealthTransactions(wtxNew, mapNarr);

    bool fIsMine = false;
    if (wtxNew.nVersion == ANON_TXN_VERSION)
    {
        LOCK2(cs_main, cs_wallet);
        CWalletDB walletdb(strWalletFile, "cr+");
        CTxDB txdb("cr+");

        walletdb.TxnBegin();
        txdb.TxnBegin();
        std::vector<std::map<uint256, CWalletTx>::iterator> vUpdatedTxns;
        if (!ProcessAnonTransaction(&walletdb, &txdb, wtxNew, wtxNew.hashBlock, fIsMine, mapNarr, vUpdatedTxns))
        {
            printf("CommitTransaction: ProcessAnonTransaction() failed %s\n", wtxNew.GetHash().ToString().c_str());
            walletdb.TxnAbort();
            txdb.TxnAbort();
            for (std::vector<COutPoint>::iterator it = wtxNew.vReservedCoins.begin();
                 it != wtxNew.vReservedCoins.end(); ++it)
            {
                UnlockCoin(*it);
            }
            wtxNew.vReservedCoins.clear();
            return false;
        } else
        {
            walletdb.TxnCommit();
            txdb.TxnCommit();
            for (std::vector<std::map<uint256, CWalletTx>::iterator>::iterator it = vUpdatedTxns.begin();
                it != vUpdatedTxns.end(); ++it)
                NotifyTransactionChanged(this, (*it)->first, CT_UPDATED);
        };
    };

    if (!mapNarr.empty())
    {
        BOOST_FOREACH(const PAIRTYPE(string,string)& item, mapNarr)
            wtxNew.mapValue[item.first] = item.second;
    };

    {
        LOCK2(cs_main, cs_wallet);
        printf("CommitTransaction:\n%s", wtxNew.ToString().c_str());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CWalletDB* pwalletdb = fFileBacked ? new CWalletDB(strWalletFile,"r") : NULL;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Mark old coins as spent
            set<CWalletTx*> setCoins;
            BOOST_FOREACH(const CTxIn& txin, wtxNew.vin)
            {
                if (wtxNew.nVersion == ANON_TXN_VERSION
                    && txin.IsAnonInput())
                    continue;
                std::map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
                if (mi == mapWallet.end())
                    continue;
                CWalletTx &coin = mi->second;
                coin.BindWallet(this);
                coin.MarkSpent(txin.prevout.n);
                coin.WriteToDisk();
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
				vMintingWalletUpdated.push_back(coin.GetHash());
            }

            for (std::vector<COutPoint>::iterator it = wtxNew.vReservedCoins.begin();
                 it != wtxNew.vReservedCoins.end(); ++it)
            {
                UnlockCoin(*it);
            }
            wtxNew.vReservedCoins.clear();

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        // Broadcast
        if (!wtxNew.AcceptToMemoryPool())
        {
            // This must not fail. The transaction has already been signed and recorded.
            printf("CommitTransaction() : Error: Transaction not valid\n");
            for (std::vector<COutPoint>::iterator it = wtxNew.vReservedCoins.begin();
                 it != wtxNew.vReservedCoins.end(); ++it)
            {
                UnlockCoin(*it);
            }
            wtxNew.vReservedCoins.clear();
            return false;
        }
        wtxNew.RelayWalletTransaction();
    }
    return true;
}

string CWallet::SendMoney(CScript scriptPubKey, int64_t nValue, std::string& sNarr, CWalletTx& wtxNew, bool fAskFee)
{
    CReserveKey reservekey(this);
    int64_t nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }
    if (fWalletUnlockStakingOnly)
    {
        string strError = _("Error: Wallet unlocked for staking only, unable to create transaction.");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }
    if (!CreateTransaction(scriptPubKey, nValue, sNarr, wtxNew, reservekey, nFeeRequired))
    {
        string strError;
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds  "), FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired, _("Sending...")))
        return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey))
        return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}


string CWallet::SendMoneyToDestination(const CTxDestination& address, int64_t nValue, std::string& sNarr, CWalletTx& wtxNew, bool fAskFee)
{
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    if (nValue + nTransactionFee > GetBalance())
        return _("Insufficient funds");

    if (sNarr.length() > 24)
        return _("Narration must be 24 characters or less.");

    // Parse Bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address);

    return SendMoney(scriptPubKey, nValue, sNarr, wtxNew, fAskFee);
}

int64_t CWallet::GetTotalValue(std::vector<CTxIn> vCoins) {
    int64_t nTotalValue = 0;
    CWalletTx wtx;
    BOOST_FOREACH(CTxIn i, vCoins){
        if (mapWallet.count(i.prevout.hash))
        {
            CWalletTx& wtx = mapWallet[i.prevout.hash];
            if(i.prevout.n < wtx.vout.size()){
                nTotalValue += wtx.vout[i.prevout.n].nValue;
            }
        } else {
            printf("GetTotalValue -- Couldn't find transaction\n");
        }
    }
    return nTotalValue;
}

DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // the requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    NewThread(ThreadFlushWalletDB, &strWalletFile);
    return DB_LOAD_OK;
}

DBErrors CWallet::ZapWalletTx()
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapWalletTxRet = CWalletDB(strWalletFile,"cr+").ZapWalletTx(this);
    if (nZapWalletTxRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // Users will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapWalletTxRet != DB_LOAD_OK)
        return nZapWalletTxRet;

    return DB_LOAD_OK;
}

//I n n o v a
bool CWallet::SetAddressBookName(const CTxDestination& address, const string& strName)
{
    bool fOwned;
    ChangeType nMode;
    {
        LOCK(cs_wallet); // mapAddressBook
        std::map<CTxDestination, std::string>::iterator mi = mapAddressBook.find(address);
        nMode = (mi == mapAddressBook.end()) ? CT_NEW : CT_UPDATED;
        fOwned = ::IsMine(*this, address);

        mapAddressBook[address] = strName;
    }

    if (fOwned)
    {
        const CBitcoinAddress& caddress = address;
        SecureMsgWalletKeyChanged(caddress.ToString(), strName, nMode);
    }
    NotifyAddressBookChanged(this, address, strName, fOwned, nMode);

    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).WriteName(CBitcoinAddress(address).ToString(), strName);
}

bool CWallet::DelAddressBookName(const CTxDestination& address)
{
    {
        LOCK(cs_wallet); // mapAddressBook

        mapAddressBook.erase(address);
    }

    bool fOwned = ::IsMine(*this, address);
    string sName = "";
    if (fOwned)
    {
        const CBitcoinAddress& caddress = address;
        SecureMsgWalletKeyChanged(caddress.ToString(), sName, CT_DELETED);
    }
    NotifyAddressBookChanged(this, address, "", fOwned, CT_DELETED);

    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).EraseName(CBitcoinAddress(address).ToString());
}

/*
void CWallet::PrintWallet(const CBlock& block)
{
    {
        LOCK(cs_wallet);
        if (block.IsProofOfWork() && mapWallet.count(block.vtx[0].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
            printf("    mine:  %d  %d  %" PRId64"", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), FormatMoney(wtx.GetCredit()).c_str());
        }
        if (block.IsProofOfStake() && mapWallet.count(block.vtx[1].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[1].GetHash()];
            printf("    stake: %d  %d  %" PRId64"", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), FormatMoney(wtx.GetCredit()).c_str());
         }

    }
    printf("\n");
}
*/

bool CWallet::GetTransaction(const uint256 &hashTx, CWalletTx& wtx)
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
        {
            wtx = (*mi).second;
            return true;
        }
    }
    return false;
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

bool GetWalletFile(CWallet* pwallet, string &strWalletFileOut)
{
    if (!pwallet->fFileBacked)
        return false;
    strWalletFileOut = pwallet->strWalletFile;
    return true;
}

//
// Mark old keypool keys as used,
// and generate all new keys
//
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64_t nIndex, setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

		    int64_t nKeys;

        nKeys = max(GetArg("-keypool", 100), (int64_t)0);

        for (int i = 0; i < nKeys; i++)
        {
            int64_t nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        printf("CWallet::NewKeyPool wrote %" PRId64" new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool(unsigned int nSize)
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize;

        if (nSize > 0)
            nTargetSize = nSize;
        else
            nTargetSize = max(GetArg("-keypool", 100), (int64_t)0);

        while (setKeyPool.size() < (nTargetSize + 1))
        {
            int64_t nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool() : writing generated key failed");
            setKeyPool.insert(nEnd);
            printf("keypool added key %" PRId64", size=%" PRIszu"\n", nEnd, setKeyPool.size());

			if(!fSuccessfullyLoaded) {
			    double dProgress = nEnd / 10.f;
                std::string strMsg = strprintf(_("Loading Wallet... (Generating Keys: %3.2f %%)"), dProgress);
                uiInterface.InitMessage(strMsg);
			}
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool() : read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool() : unknown key in key pool");
    
        if (!keypool.vchPubKey.IsValid())
            throw runtime_error("ReserveKeyFromKeyPool() : invalid key in key pool");
        if (fDebug && GetBoolArg("-printkeypool"))
            printf("keypool reserve %" PRId64"\n", nIndex);
    }
}

int64_t CWallet::AddReserveKey(const CKeyPool& keypool)
{
    {
        LOCK2(cs_main, cs_wallet);
        CWalletDB walletdb(strWalletFile);

        int64_t nIndex = 1 + *(--setKeyPool.end());
        if (!walletdb.WritePool(nIndex, keypool))
            throw runtime_error("AddReserveKey() : writing added key failed");
        setKeyPool.insert(nIndex);
        return nIndex;
    }
    return -1;
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    if(fDebug)
        printf("keypool keep %" PRId64"\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    if(fDebug)
        printf("keypool return %" PRId64"\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result, bool fAllowReuse)
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (fAllowReuse && vchDefaultKey.IsValid())
            {
                result = vchDefaultKey;
                return true;
            }
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

std::map<CTxDestination, int64_t> CWallet::GetAddressBalances()
{
    map<CTxDestination, int64_t> balances;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
        {
            CWalletTx *pcoin = &walletEntry.second;

            if (!pcoin->IsFinal() || !pcoin->IsTrusted())
                continue;

            if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, addr))
                    continue;

                int64_t n = pcoin->IsSpent(i) ? 0 : pcoin->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

set< set<CTxDestination> > CWallet::GetAddressGroupings()
{
    AssertLockHeld(cs_wallet); // mapWallet
    set< set<CTxDestination> > groupings;
    set<CTxDestination> grouping;

    BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
    {
        CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            BOOST_FOREACH(CTxIn txin, pcoin->vin)
            {
                CTxDestination address;
                if (!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(mapWallet[txin.prevout.hash].vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine) {
            BOOST_FOREACH(CTxOut txout, pcoin->vout)
                if (IsChange(txout))
                {
                    CTxDestination txoutAddr;
                    if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                        continue;
                    grouping.insert(txoutAddr);
                }
            }
            if (grouping.size() > 0) {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            if (IsMine(pcoin->vout[i]))
            {
                CTxDestination address;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    set< set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    map< CTxDestination, set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    BOOST_FOREACH(set<CTxDestination> grouping, groupings)
    {
        // make a set of all the groups hit by this new group
        set< set<CTxDestination>* > hits;
        map< CTxDestination, set<CTxDestination>* >::iterator it;
        BOOST_FOREACH(CTxDestination address, grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        set<CTxDestination>* merged = new set<CTxDestination>(grouping);
        BOOST_FOREACH(set<CTxDestination>* hit, hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        BOOST_FOREACH(CTxDestination element, *merged)
            setmap[element] = merged;
    }

    set< set<CTxDestination> > ret;
    BOOST_FOREACH(set<CTxDestination>* uniqueGrouping, uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

// ppcoin: check 'spent' consistency between wallet and txindex
// ppcoin: fix wallet spent state according to txindex
void CWallet::FixSpentCoins(int& nMismatchFound, int64_t& nBalanceInQuestion, bool fCheckOnly)
{
    nMismatchFound = 0;
    nBalanceInQuestion = 0;

    LOCK(cs_wallet);
    vector<CWalletTx*> vCoins;
    vCoins.reserve(mapWallet.size());
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        vCoins.push_back(&(*it).second);

    CTxDB txdb("r");
    BOOST_FOREACH(CWalletTx* pcoin, vCoins)
    {
        // Find the corresponding transaction index
        CTxIndex txindex;
        if (!txdb.ReadTxIndex(pcoin->GetHash(), txindex))
            continue;
        for (unsigned int n=0; n < pcoin->vout.size(); n++)
        {
            if (IsMine(pcoin->vout[n]) && pcoin->IsSpent(n) && (txindex.vSpent.size() <= n || txindex.vSpent[n].IsNull()))
            {
                printf("FixSpentCoins found lost coin %s INN %s[%d], %s\n",
                    FormatMoney(pcoin->vout[n].nValue).c_str(), pcoin->GetHash().ToString().c_str(), n, fCheckOnly? "repair not attempted" : "repairing");
                nMismatchFound++;
                nBalanceInQuestion += pcoin->vout[n].nValue;
                if (!fCheckOnly)
                {
                    pcoin->MarkUnspent(n);
                    pcoin->WriteToDisk();
                }
            }
            else if (IsMine(pcoin->vout[n]) && !pcoin->IsSpent(n) && (txindex.vSpent.size() > n && !txindex.vSpent[n].IsNull()))
            {
                printf("FixSpentCoins found spent coin %s INN %s[%d], %s\n",
                    FormatMoney(pcoin->vout[n].nValue).c_str(), pcoin->GetHash().ToString().c_str(), n, fCheckOnly? "repair not attempted" : "repairing");
                nMismatchFound++;
                nBalanceInQuestion += pcoin->vout[n].nValue;
                if (!fCheckOnly)
                {
                    pcoin->MarkSpent(n);
                    pcoin->WriteToDisk();
                }
            }
        }
    }
}

// ppcoin: disable transaction (only for coinstake)
void CWallet::DisableTransaction(const CTransaction &tx)
{
    if (!tx.IsCoinStake() || !IsFromMe(tx))
        return; // only disconnecting coinstake requires marking input unspent

    LOCK(cs_wallet);
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        if (tx.nVersion == ANON_TXN_VERSION
            && txin.IsAnonInput())
            continue;
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size() && IsMine(prev.vout[txin.prevout.n]))
            {
                prev.MarkUnspent(txin.prevout.n);
                prev.WriteToDisk();
            }
        }
    }
}

bool CReserveKey::GetReservedKey(CPubKey& pubkey)
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else {
            if (pwallet->vchDefaultKey.IsValid()) {
                printf("CReserveKey::GetReservedKey(): Warning: Using default key instead of a new key, top up your keypool!");
                vchPubKey = pwallet->vchDefaultKey;
            } else
                return false;
        }
    }

    if (!vchPubKey.IsValid())
        return false;
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set<CKeyID>& setAddress) const
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(const int64_t& id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes() : read failed");
    
        if (!keypool.vchPubKey.IsValid())
            throw runtime_error("GetAllReserveKeyHashes() : invalid key in key pool");
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes() : unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CWallet::UpdatedTransaction(const uint256 &hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
			vMintingWalletUpdated.push_back(hashTx);
    }
}

void CWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const {
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (std::map<CKeyID, CKeyMetadata>::const_iterator it = mapKeyMetadata.begin(); it != mapKeyMetadata.end(); it++)
        if (it->second.nCreateTime)
            mapKeyBirth[it->first] = it->second.nCreateTime;

    // map in which we'll infer heights of other keys
    CBlockIndex *pindexMax = FindBlockByHeight(std::max(0, nBestHeight - 144)); // the tip can be reorganised; use a 144-block safety margin
    std::map<CKeyID, CBlockIndex*> mapKeyFirstBlock;
    std::set<CKeyID> setKeys;
    GetKeys(setKeys);
    BOOST_FOREACH(const CKeyID &keyid, setKeys) {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }
    setKeys.clear();

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); it++) {
        // iterate over all wallet transactions...
        const CWalletTx &wtx = (*it).second;
        std::map<uint256, CBlockIndex*>::const_iterator blit = mapBlockIndex.find(wtx.hashBlock);
        if (blit != mapBlockIndex.end() && blit->second->IsInMainChain()) {
            // ... which are already in a block
            int nHeight = blit->second->nHeight;
            BOOST_FOREACH(const CTxOut &txout, wtx.vout) {
                // iterate over all their outputs
                ::ExtractAffectedKeys(*this, txout.scriptPubKey, vAffected);
                BOOST_FOREACH(const CKeyID &keyid, vAffected) {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex*>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->nHeight)
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (std::map<CKeyID, CBlockIndex*>::const_iterator it = mapKeyFirstBlock.begin(); it != mapKeyFirstBlock.end(); it++)
        mapKeyBirth[it->first] = it->second->nTime - 7200; // block times can be 2h off
}

bool CWallet::AddAdrenalineNodeConfig(CAdrenalineNodeConfig nodeConfig)
{
    bool rv = CWalletDB(strWalletFile).WriteAdrenalineNodeConfig(nodeConfig.sAddress, nodeConfig);
    if(rv)
	uiInterface.NotifyAdrenalineNodeChanged(nodeConfig);

    return rv;
}

static int GetRingSigSize(int rsType, int nRingSize)
{
    switch(rsType)
    {
        case RING_SIG_1:
            return 2 + (ec_compressed_size + ec_secret_size + ec_secret_size) * nRingSize;
        case RING_SIG_2:
            return 2 + ec_secret_size + (ec_compressed_size + ec_secret_size) * nRingSize;
        default:
            printf("Unknown ring signature type.\n");
            return 0;
    };
};

static uint8_t *GetRingSigPkStart(int rsType, int nRingSize, uint8_t *pStart)
{
    switch(rsType)
    {
        case RING_SIG_1:
            return pStart + 2;
        case RING_SIG_2:
            return pStart + 2 + ec_secret_size + ec_secret_size * nRingSize;
        default:
            printf("Unknown ring signature type.\n");
            return 0;
    };
}

static int GetBlockHeightFromHash(const uint256& blockHash)
{
    if (blockHash == 0)
        return 0;

    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(blockHash);
    if (mi == mapBlockIndex.end())
        return 0;
    return mi->second->nHeight;

    return 0;
}

bool CWallet::UpdateAnonTransaction(CTxDB* ptxdb, const CTransaction& tx, const uint256& blockHash)
{
    uint256 txnHash = tx.GetHash();
    if (fDebugRingSig)
        printf("UpdateAnonTransaction() tx: %s\n", txnHash.GetHex().c_str());

    // -- update txns not received in a block

    //LOCK2(cs_main, cs_wallet);

    int nNewHeight = GetBlockHeightFromHash(blockHash);

    CKeyImageSpent spentKeyImage;
    for (uint32_t i = 0; i < tx.vin.size(); ++i)
    {
        const CTxIn& txin = tx.vin[i];

        if (!txin.IsAnonInput())
            continue;

        const CScript &s = txin.scriptSig;

        std::vector<uint8_t> vchImage;
        txin.ExtractKeyImage(vchImage);

        // -- get nCoinValue by reading first ring element
        CPubKey pkRingCoin;
        CAnonOutput ao;
        CTxIndex txindex;
        const unsigned char* pPubkeys = &s[2];
        pkRingCoin = CPubKey(&pPubkeys[0 * ec_compressed_size], ec_compressed_size);
        if (!ptxdb->ReadAnonOutput(pkRingCoin, ao))
        {
            printf("UpdateAnonTransaction(): Error input %u AnonOutput %s not found.\n", i, HexStr(pkRingCoin.Raw()).c_str());
            return false;
        };

        int64_t nCoinValue = ao.nValue;


        spentKeyImage.txnHash = txnHash;
        spentKeyImage.inputNo = i;
        spentKeyImage.nValue = nCoinValue;

        if (!ptxdb->WriteKeyImage(vchImage, spentKeyImage))
        {
            printf("UpdateAnonTransaction(): Error input %d WriteKeyImage failed %s .\n", i, HexStr(vchImage).c_str());
            return false;
        };

    };

    for (uint32_t i = 0; i < tx.vout.size(); ++i)
    {
        const CTxOut& txout = tx.vout[i];

        if (!txout.IsAnonOutput())
            continue;

        const CScript &s = txout.scriptPubKey;

        CPubKey pkCoin    = CPubKey(&s[2+1], ec_compressed_size);
        CAnonOutput ao;
        if (!ptxdb->ReadAnonOutput(pkCoin, ao))
        {
            printf("ReadAnonOutput %d failed.\n", i);
            return false;
        };

        ao.nBlockHeight = nNewHeight;

        if (!ptxdb->WriteAnonOutput(pkCoin, ao))
        {
            printf("ReadAnonOutput %d failed.\n", i);
            return false;
        };

        mapAnonOutputStats[ao.nValue].updateDepth(nNewHeight, ao.nValue);
    };

    return true;
};


bool CWallet::UndoAnonTransaction(const CTransaction& tx)
{
    if (fDebugRingSig)
        printf("UndoAnonTransaction() tx: %s\n", tx.GetHash().GetHex().c_str());
    // -- undo transaction - used if block is unlinked / txn didn't commit

    LOCK2(cs_main, cs_wallet);

    uint256 txnHash = tx.GetHash();

    CWalletDB walletdb(strWalletFile, "cr+");
    CTxDB txdb("cr+");

    for (unsigned int i = 0; i < tx.vin.size(); ++i)
    {
        const CTxIn& txin = tx.vin[i];

        if (!txin.IsAnonInput())
            continue;

        ec_point vchImage;
        txin.ExtractKeyImage(vchImage);

        CKeyImageSpent spentKeyImage;

        bool fInMempool;
        if (!GetKeyImage(&txdb, vchImage, spentKeyImage, fInMempool))
        {
            if (fDebugRingSig)
                printf("Error: keyImage for input %d not found.\n", i);
            continue;
        };

        // Possible?
        if (spentKeyImage.txnHash != txnHash)
        {
            printf("Error: spentKeyImage for %s does not match txn %s.\n", HexStr(vchImage).c_str(), txnHash.ToString().c_str());
            continue;
        };

        if (!txdb.EraseKeyImage(vchImage))
        {
            printf("EraseKeyImage %d failed.\n", i);
            continue;
        };

        mapAnonOutputStats[spentKeyImage.nValue].decSpends(spentKeyImage.nValue);


        COwnedAnonOutput oao;
        if (walletdb.ReadOwnedAnonOutput(vchImage, oao))
        {
            if (fDebugRingSig)
                printf("UndoAnonTransaction(): input %d keyimage %s found in wallet (owned).\n", i, HexStr(vchImage).c_str());

            std::map<uint256, CWalletTx>::iterator mi = mapWallet.find(oao.outpoint.hash);
            if (mi == mapWallet.end())
            {
                printf("UndoAnonTransaction(): Error input %d prev txn not in mapwallet %s .\n", i, oao.outpoint.hash.ToString().c_str());
                return false;
            };

            CWalletTx& inTx = (*mi).second;
            if (oao.outpoint.n >= inTx.vout.size())
            {
                printf("UndoAnonTransaction(): bad wtx %s\n", oao.outpoint.hash.ToString().c_str());
                return false;
            } else
            if (inTx.IsSpent(oao.outpoint.n))
            {
                printf("UndoAnonTransaction(): found spent coin %s\n", oao.outpoint.hash.ToString().c_str());


                inTx.MarkUnspent(oao.outpoint.n);
                if (!walletdb.WriteTx(oao.outpoint.hash, inTx))
                {
                    printf("UndoAnonTransaction(): input %d WriteTx failed %s.\n", i, HexStr(vchImage).c_str());
                    return false;
                };
                inTx.MarkDirty(); // recalc balances
                NotifyTransactionChanged(this, oao.outpoint.hash, CT_UPDATED);
            };

            oao.fSpent = false;
            if (!walletdb.WriteOwnedAnonOutput(vchImage, oao))
            {
                printf("UndoAnonTransaction(): input %d WriteOwnedAnonOutput failed %s.\n", i, HexStr(vchImage).c_str());
                return false;
            };
        };
    };


    for (uint32_t i = 0; i < tx.vout.size(); ++i)
    {
        const CTxOut& txout = tx.vout[i];

        if (!txout.IsAnonOutput())
            continue;

        const CScript &s = txout.scriptPubKey;

        CPubKey pkCoin    = CPubKey(&s[2+1], ec_compressed_size);
        CKeyID  ckCoinId  = pkCoin.GetID();

        CAnonOutput ao;
        if (!txdb.ReadAnonOutput(pkCoin, ao)) // read only to update mapAnonOutputStats
        {
            printf("ReadAnonOutput(): %u failed.\n", i);
            return false;
        };

        mapAnonOutputStats[ao.nValue].decExists(ao.nValue);

        if (!txdb.EraseAnonOutput(pkCoin))
        {
            printf("EraseAnonOutput(): %u failed.\n", i);
            continue;
        };

        // -- only in db if owned
        walletdb.EraseLockedAnonOutput(ckCoinId);

        std::vector<uint8_t> vchImage;

        if (!walletdb.ReadOwnedAnonOutputLink(pkCoin, vchImage))
        {
            printf("ReadOwnedAnonOutputLink(): %u failed - output wasn't owned.\n", i);
            continue;
        };

        if (!walletdb.EraseOwnedAnonOutput(vchImage))
        {
            printf("EraseOwnedAnonOutput(): %u failed.\n", i);
            continue;
        };

        if (!walletdb.EraseOwnedAnonOutputLink(pkCoin))
        {
            printf("EraseOwnedAnonOutputLink(): %u failed.\n", i);
            continue;
        };
    };


    if (!walletdb.EraseTx(txnHash))
    {
        printf("UndoAnonTransaction() EraseTx %s failed.\n", txnHash.ToString().c_str());
        return false;
    };

    mapWallet.erase(txnHash);

    return true;
};

bool CWallet::ProcessAnonTransaction(CWalletDB* pwdb, CTxDB* ptxdb, const CTransaction& tx, const uint256& blockHash, bool& fIsMine, mapValue_t& mapNarr, std::vector<std::map<uint256, CWalletTx>::iterator>& vUpdatedTxns)
{
    uint256 txnHash = tx.GetHash();

    if (fDebugRingSig)
        printf("ProcessAnonTransaction() tx: %s\n", txnHash.GetHex().c_str());

    // -- must hold cs_main and cs_wallet lock
    //    txdb and walletdb must be in a transaction (no commit if fail)

    for (uint32_t i = 0; i < tx.vin.size(); ++i)
    {
        const CTxIn& txin = tx.vin[i];

        if (!txin.IsAnonInput())
            continue;

        const CScript &s = txin.scriptSig;

        std::vector<uint8_t> vchImage;
        txin.ExtractKeyImage(vchImage);

        CKeyImageSpent spentKeyImage;

        bool fInMempool;
        if (GetKeyImage(ptxdb, vchImage, spentKeyImage, fInMempool))
        {
            if (spentKeyImage.txnHash == txnHash
                && spentKeyImage.inputNo == i)
            {
                if (fDebugRingSig)
                    printf("found matching spent key image - txn has been processed before\n");
                return UpdateAnonTransaction(ptxdb, tx, blockHash);
            };

            if (TxnHashInSystem(ptxdb, spentKeyImage.txnHash))
            {
                printf("ProcessAnonTransaction(): Error input %d keyimage %s already spent.\n", i, HexStr(vchImage).c_str());
                return false;
            };

            if (fDebugRingSig)
                printf("Input %d keyimage %s matches unknown txn %s, continuing.\n", i, HexStr(vchImage).c_str(), spentKeyImage.txnHash.ToString().c_str());

            // -- keyimage is in db, but invalid as does not point to a known transaction
            //    could be an old mempool keyimage
            //    continue
        };


        COwnedAnonOutput oao;
        if (pwdb->ReadOwnedAnonOutput(vchImage, oao))
        {
            if (fDebugRingSig)
                printf("ProcessAnonTransaction(): input %d keyimage %s found in wallet (owned).\n", i, HexStr(vchImage).c_str());

            std::map<uint256, CWalletTx>::iterator mi = mapWallet.find(oao.outpoint.hash);
            if (mi == mapWallet.end())
            {
                printf("ProcessAnonTransaction(): Error input %d prev txn not in mapwallet %s .\n", i, oao.outpoint.hash.ToString().c_str());
                return false;
            };

            CWalletTx& inTx = (*mi).second;
            if (oao.outpoint.n >= inTx.vout.size())
            {
                printf("ProcessAnonTransaction(): bad wtx %s\n", oao.outpoint.hash.ToString().c_str());
                return false;
            } else
            if (!inTx.IsSpent(oao.outpoint.n))
            {
                printf("ProcessAnonTransaction(): found spent coin %s\n", oao.outpoint.hash.ToString().c_str());

                inTx.MarkSpent(oao.outpoint.n);
                if (!pwdb->WriteTx(oao.outpoint.hash, inTx))
                {
                    printf("ProcessAnonTransaction(): input %d WriteTx failed %s.\n", i, HexStr(vchImage).c_str());
                    return false;
                };

                inTx.MarkDirty();           // recalc balances
                vUpdatedTxns.push_back(mi); // notify updates outside db txn
            };

            oao.fSpent = true;
            if (!pwdb->WriteOwnedAnonOutput(vchImage, oao))
            {
                printf("ProcessAnonTransaction(): input %d WriteOwnedAnonOutput failed %s.\n", i, HexStr(vchImage).c_str());
                return false;
            };
        };

        int nRingSize = txin.ExtractRingSize();
        if (nRingSize < (int)MIN_RING_SIZE
            || nRingSize > (int)MAX_RING_SIZE)
        {
            printf("ProcessAnonTransaction(): Error input %d ringsize %d not in range [%d, %d].\n", i, nRingSize, MIN_RING_SIZE, MAX_RING_SIZE);
            return false;
        };

        if (s.size() < 2 + (ec_compressed_size + ec_secret_size + ec_secret_size) * nRingSize)
        {
            printf("ProcessAnonTransaction(): Error input %d scriptSig too small.\n", i);
            return false;
        };

        int64_t nCoinValue = -1;

        CPubKey pkRingCoin;
        CAnonOutput ao;
        CTxIndex txindex;
        const unsigned char* pPubkeys = &s[2];
        for (uint32_t ri = 0; ri < (uint32_t)nRingSize; ++ri)
        {
            pkRingCoin = CPubKey(&pPubkeys[ri * ec_compressed_size], ec_compressed_size);
            if (!ptxdb->ReadAnonOutput(pkRingCoin, ao))
            {
                printf("ProcessAnonTransaction(): Error input %u AnonOutput %s not found.\n", i, HexStr(pkRingCoin.Raw()).c_str());
                return false;
            };

            if (nCoinValue == -1)
            {
                nCoinValue = ao.nValue;
            } else
            if (nCoinValue != ao.nValue)
            {
                printf("ProcessAnonTransaction(): Error input %u ring amount mismatch %" PRId64 ", %" PRId64 ".\n", i, nCoinValue, ao.nValue);
                return false;
            };

            if (ao.nBlockHeight == 0
                || nBestHeight - ao.nBlockHeight < MIN_ANON_SPEND_DEPTH)
            {
                printf("ProcessAnonTransaction(): Error input %u ring coin %u depth < MIN_ANON_SPEND_DEPTH.\n", i, ri);
                return false;
            };

            // -- ring sig validation is done in CTransaction::CheckAnonInputs()
        };

        spentKeyImage.txnHash = txnHash;
        spentKeyImage.inputNo = i;
        spentKeyImage.nValue = nCoinValue;

        if (blockHash != 0)
        {
            if (!ptxdb->WriteKeyImage(vchImage, spentKeyImage))
            {
                printf("ProcessAnonTransaction(): Error input %d WriteKeyImage failed %s .\n", i, HexStr(vchImage).c_str());
                return false;
            };
        } else
        {
            // -- add keyImage to mempool, will be added to txdb in UpdateAnonTransaction
            mempool.insertKeyImage(vchImage, spentKeyImage);
        };

        mapAnonOutputStats[spentKeyImage.nValue].incSpends(spentKeyImage.nValue);
    };

    ec_secret sSpendR;
    ec_secret sSpend;
    ec_secret sScan;
    ec_secret sShared;

    ec_point pkExtracted;

    std::vector<uint8_t> vchEphemPK;
    std::vector<uint8_t> vchDataB;
    std::vector<uint8_t> vchENarr;

    std::vector<std::vector<uint8_t> > vPrevMatch;
    char cbuf[256];

    try { vchEphemPK.resize(ec_compressed_size); } catch (std::exception& e)
    {
        printf("Error: vchEphemPK.resize threw: %s.\n", e.what());
        return false;
    };

    int nBlockHeight = GetBlockHeightFromHash(blockHash);

    for (uint32_t i = 0; i < tx.vout.size(); ++i)
    {
        const CTxOut& txout = tx.vout[i];

        if (!txout.IsAnonOutput())
            continue;

        const CScript &s = txout.scriptPubKey;

        CPubKey pkCoin    = CPubKey(&s[2+1], ec_compressed_size);
        CKeyID  ckCoinId  = pkCoin.GetID();

        COutPoint outpoint = COutPoint(tx.GetHash(), i);

        // -- add all anon outputs to txdb
        CAnonOutput ao;

        if (ptxdb->ReadAnonOutput(pkCoin, ao)) // check if exists
        {
            if (blockHash != 0)
            {
                if (fDebugRingSig)
                    printf("Found existing anon output - assuming txn has been processed before.\n");
                return UpdateAnonTransaction(ptxdb, tx, blockHash);
            };
            printf("Error: Found duplicate anon output.\n");
            return false;
        };

        ao = CAnonOutput(outpoint, txout.nValue, nBlockHeight, 0);

        if (!ptxdb->WriteAnonOutput(pkCoin, ao))
        {
            printf("WriteAnonOutput failed for coin %s.\n", pkCoin.GetHash().ToString().c_str());
            return false;
        };

        mapAnonOutputStats[txout.nValue].addCoin(nBlockHeight, txout.nValue);

        memcpy(&vchEphemPK[0], &s[2+ec_compressed_size+2], ec_compressed_size);

        bool fOwnOutput = false;
        CPubKey cpkE;
        std::set<CStealthAddress>::iterator it;
        for (it = stealthAddresses.begin(); it != stealthAddresses.end(); ++it)
        {
            if (it->scan_secret.size() != ec_secret_size)
                continue; // stealth address is not owned

            memcpy(&sScan.e[0], &it->scan_secret[0], ec_secret_size);

            if (StealthSecret(sScan, vchEphemPK, it->spend_pubkey, sShared, pkExtracted) != 0)
            {
                printf("StealthSecret failed.\n");
                continue;
            };

            cpkE = CPubKey(pkExtracted);

            if (!cpkE.IsValid()
                || cpkE != pkCoin)
                continue;
            fOwnOutput = true;
            break;
        };

        if (!fOwnOutput)
            continue;

        if (fDebugRingSig)
            printf("anon output match tx, no %s, %u\n", txnHash.GetHex().c_str(), i);

        fIsMine = true; // mark tx to be added to wallet

        int lenENarr = 0;
        if (s.size() > MIN_ANON_OUT_SIZE)
            lenENarr = s[2+ec_compressed_size+1 + ec_compressed_size+1];

        if (lenENarr > 0)
        {
            if (fDebugRingSig)
                printf("Processing encrypted narration of %d bytes\n", lenENarr);

            try { vchENarr.resize(lenENarr); } catch (std::exception& e)
            {
                printf("Error: vchENarr.resize threw: %s.\n", e.what());
                continue;
            };
            memcpy(&vchENarr[0], &s[2+ec_compressed_size+1+ec_compressed_size+2], lenENarr);

            SecMsgCrypter crypter;
            crypter.SetKey(&sShared.e[0], &vchEphemPK[0]);
            std::vector<uint8_t> vchNarr;
            if (!crypter.Decrypt(&vchENarr[0], vchENarr.size(), vchNarr))
            {
                printf("Decrypt narration failed.\n");
                continue;
            };
            std::string sNarr = std::string(vchNarr.begin(), vchNarr.end());

            snprintf(cbuf, sizeof(cbuf), "n_%u", i);
            mapNarr[cbuf] = sNarr;
        };

        if (IsLocked())
        {
            std::vector<uint8_t> vchEmpty;
            CWalletDB *pwalletdbEncryptionOld = pwalletdbEncryption;
            pwalletdbEncryption = pwdb; // HACK, pass pdb to AddCryptedKey
            AddCryptedKey(cpkE, vchEmpty);
            pwalletdbEncryption = pwalletdbEncryptionOld;

            if (fDebugRingSig)
                printf("Wallet locked, adding key without secret.\n");

            std::string sSxAddr = it->Encoded();
            std::string sLabel = std::string("ao ") + sSxAddr.substr(0, 16) + "...";
            SetAddressBookName(ckCoinId, sLabel);

            CPubKey cpkEphem(vchEphemPK);
            CPubKey cpkScan(it->scan_pubkey);
            CLockedAnonOutput lockedAo(cpkEphem, cpkScan, COutPoint(txnHash, i));
            if (!pwdb->WriteLockedAnonOutput(ckCoinId, lockedAo))
            {
                CBitcoinAddress coinAddress(ckCoinId);
                printf("WriteLockedAnonOutput failed for %s\n", coinAddress.ToString().c_str());
            };
        } else
        {
            if (it->spend_secret.size() != ec_secret_size)
                continue;
            memcpy(&sSpend.e[0], &it->spend_secret[0], ec_secret_size);


            if (StealthSharedToSecretSpend(sShared, sSpend, sSpendR) != 0)
            {
                printf("StealthSharedToSecretSpend() failed.\n");
                continue;
            };


            ec_point pkTestSpendR;
            if (SecretToPublicKey(sSpendR, pkTestSpendR) != 0)
            {
                printf("SecretToPublicKey() failed.\n");
                continue;
            };

            CSecret vchSecret;
            vchSecret.resize(ec_secret_size);

            memcpy(&vchSecret[0], &sSpendR.e[0], ec_secret_size);
            CKey ckey;

            try {
                ckey.Set(vchSecret.begin(), vchSecret.end(), true);
                //ckey.SetSecret(vchSecret, true);
            } catch (std::exception& e)
            {
                printf("ckey.SetSecret() threw: %s.\n", e.what());
                continue;
            };

            if (!ckey.IsValid())
            {
                printf("Reconstructed key is invalid.\n");
                continue;
            };

            CPubKey cpkT = ckey.GetPubKey();
            if (!cpkT.IsValid()
                || cpkT != pkCoin)
            {
                printf("cpkT is invalid.\n");
                continue;
            };

            if (fDebugRingSig)
            {
                CBitcoinAddress coinAddress(ckCoinId);
                printf("Adding key %s.\n", coinAddress.ToString().c_str());
            };

            if (!AddKeyInDBTxn(pwdb, ckey))
            {
                printf("AddKeyInDBTxn failed.\n");
                continue;
            };

            // TODO: groupings?
            std::string sSxAddr = it->Encoded();
            std::string sLabel = std::string("ao ") + sSxAddr.substr(0, 16) + "...";
            SetAddressBookName(ckCoinId, sLabel);


            // -- store keyImage
            ec_point pkImage;
            if (generateKeyImage(pkTestSpendR, sSpendR, pkImage) != 0)
            {
                printf("generateKeyImage() failed.\n");
                continue;
            };

            bool fSpentAOut = false;
            bool fInMemPool;
            CKeyImageSpent kis;
            if (GetKeyImage(ptxdb, pkImage, kis, fInMemPool)
                && !fInMemPool) // shouldn't be possible for kis to be in mempool here
            {
                fSpentAOut = true;
            };

            COwnedAnonOutput oao(outpoint, fSpentAOut);

            if (!pwdb->WriteOwnedAnonOutput(pkImage, oao)
                || !pwdb->WriteOwnedAnonOutputLink(pkCoin, pkImage))
            {
                printf("WriteOwnedAnonOutput() failed.\n");
                continue;
            };

            if (fDebugRingSig)
                printf("Adding anon output to wallet: %s.\n", HexStr(pkImage).c_str());
        };
    };


    return true;
};

bool CWallet::GetAnonChangeAddress(CStealthAddress& sxAddress)
{
    // return owned stealth address to send anon change to.
    // TODO: make an option

    std::set<CStealthAddress>::iterator it;
    for (it = stealthAddresses.begin(); it != stealthAddresses.end(); ++it)
    {
        if (it->scan_secret.size() < 1)
            continue; // stealth address is not owned

        sxAddress = *it;
        return true;
    };

    return false;
};


bool CWallet::CreateStealthOutput(CStealthAddress* sxAddress, int64_t nValue, std::string& sNarr, std::vector<std::pair<CScript, int64_t> >& vecSend, std::map<int, std::string>& mapNarr, std::string& sError)
{
    if (fDebugRingSig)
        printf("CreateAnonOutputs()\n");

    if (!sxAddress)
    {
        sError = "!sxAddress, todo.";
        return false;
    };

    ec_secret ephem_secret;
    ec_secret secretShared;
    ec_point pkSendTo;
    ec_point ephem_pubkey;

    if (GenerateRandomSecret(ephem_secret) != 0)
    {
        sError = "GenerateRandomSecret failed.";
        return false;
    };

    if (StealthSecret(ephem_secret, sxAddress->scan_pubkey, sxAddress->spend_pubkey, secretShared, pkSendTo) != 0)
    {
        sError = "Could not generate receiving public key.";
        return false;
    };

    CPubKey cpkTo(pkSendTo);
    if (!cpkTo.IsValid())
    {
        sError = "Invalid public key generated.";
        return false;
    };

    CKeyID ckidTo = cpkTo.GetID();

    CBitcoinAddress addrTo(ckidTo);

    if (SecretToPublicKey(ephem_secret, ephem_pubkey) != 0)
    {
        sError = "Could not generate ephem public key.";
        return false;
    };

    if (fDebug)
    {
        printf("CreateStealthOutput() to generated pubkey %" PRIszu": %s\n", pkSendTo.size(), HexStr(pkSendTo).c_str());
        printf("hash %s\n", addrTo.ToString().c_str());
        printf("ephem_pubkey %" PRIszu": %s\n", ephem_pubkey.size(), HexStr(ephem_pubkey).c_str());
    };

    std::vector<unsigned char> vchENarr;
    if (sNarr.length() > 0)
    {
        SecMsgCrypter crypter;
        crypter.SetKey(&secretShared.e[0], &ephem_pubkey[0]);

        if (!crypter.Encrypt((uint8_t*)&sNarr[0], sNarr.length(), vchENarr))
        {
            sError = "Narration encryption failed.";
            return false;
        };

        if (vchENarr.size() > MAX_STEALTH_NARRATION_SIZE)
        {
            sError = "Encrypted narration is too long.";
            return false;
        };
    };


    CScript scriptPubKey;
    scriptPubKey.SetDestination(addrTo.Get());

    vecSend.push_back(make_pair(scriptPubKey, nValue));

    CScript scriptP = CScript() << OP_RETURN << ephem_pubkey;
    if (vchENarr.size() > 0)
        scriptP = scriptP << OP_RETURN << vchENarr;

    vecSend.push_back(make_pair(scriptP, 0));

    // TODO: shuffle change later?
    if (vchENarr.size() > 0)
    {
        for (unsigned int k = 0; k < vecSend.size(); ++k)
        {
            if (vecSend[k].first != scriptPubKey
                || vecSend[k].second != nValue)
                continue;

            mapNarr[k] = sNarr;
            break;
        };
    };

    return true;
};

bool CWallet::CreateAnonOutputs(CStealthAddress* sxAddress, int64_t nValue, std::string& sNarr, std::vector<std::pair<CScript, int64_t> >& vecSend, CScript& scriptNarration)
{
    if (fDebugRingSig)
        printf("CreateAnonOutputs()\n");

    ec_secret scEphem;
    ec_secret scShared;
    ec_point  pkSendTo;
    ec_point  pkEphem;

    CPubKey   cpkTo;

    // -- output scripts OP_RETURN ANON_TOKEN pkTo R enarr
    //    Each outputs split from the amount must go to a unique pk, or the key image would be the same
    //    Only the first output of the group carries the enarr (if present)


    std::vector<int64_t> vOutAmounts;
    if (splitAmount(nValue, vOutAmounts) != 0)
    {
        printf("splitAmount() failed.\n");
        return false;
    };

    for (uint32_t i = 0; i < vOutAmounts.size(); ++i)
    {
        if (GenerateRandomSecret(scEphem) != 0)
        {
            printf("GenerateRandomSecret failed.\n");
            return false;
        };

        if (sxAddress) // NULL for test only
        {
            if (StealthSecret(scEphem, sxAddress->scan_pubkey, sxAddress->spend_pubkey, scShared, pkSendTo) != 0)
            {
                printf("Could not generate receiving public key.\n");
                return false;
            };

            cpkTo = CPubKey(pkSendTo);
            if (!cpkTo.IsValid())
            {
                printf("Invalid public key generated.\n");
                return false;
            };

            if (SecretToPublicKey(scEphem, pkEphem) != 0)
            {
                printf("Could not generate ephem public key.\n");
                return false;
            };
        };

        CScript scriptSendTo;
        scriptSendTo.push_back(OP_RETURN);
        scriptSendTo.push_back(OP_ANON_MARKER);
        scriptSendTo << cpkTo;
        scriptSendTo << pkEphem;

        if (i == 0 && sNarr.length() > 0)
        {
            std::vector<unsigned char> vchNarr;
            SecMsgCrypter crypter;
            crypter.SetKey(&scShared.e[0], &pkEphem[0]);

            if (!crypter.Encrypt((uint8_t*)&sNarr[0], sNarr.length(), vchNarr))
            {
                printf("Narration encryption failed.\n");
                return false;
            };

            if (vchNarr.size() > MAX_STEALTH_NARRATION_SIZE)
            {
                printf("Encrypted narration is too long.\n");
                return false;
            };
            scriptSendTo << vchNarr;
            scriptNarration = scriptSendTo;
        };

        if (fDebug)
        {
            CKeyID ckidTo = cpkTo.GetID();
            CBitcoinAddress addrTo(ckidTo);

            printf("CreateAnonOutput to generated pubkey %" PRIszu": %s\n", pkSendTo.size(), HexStr(pkSendTo).c_str());
            if (!sxAddress)
                printf("Test Mode\n");
            printf("hash %s\n", addrTo.ToString().c_str());
            printf("ephemeral pubkey %" PRIszu ": %s\n", pkEphem.size(), HexStr(pkEphem).c_str());

            printf("scriptPubKey %s\n", scriptSendTo.ToString().c_str());
        };
        vecSend.push_back(make_pair(scriptSendTo, vOutAmounts[i]));
    };

    OPENSSL_cleanse(&scShared.e[0], ec_secret_size);

    return true;
};

static bool checkCombinations(int64_t nReq, int m, std::vector<COwnedAnonOutput*>& vData, std::vector<int>& v)
{
    // -- m of n combinations, check smallest coins first

    if (fDebugRingSig)
        printf("checkCombinations() %d, %" PRIszu "\n", m, vData.size());

    int n = vData.size();

    try { v.resize(m); } catch (std::exception& e)
    {
        printf("Error: checkCombinations() v.resize(%d) threw: %s.\n", m, e.what());
        return false;
    };


    int64_t nCount = 0;

    if (m > n) // ERROR
    {
        printf("Error: checkCombinations() m > n\n");
        return false;
    };

    int i, l, startL = 0;

    // -- pick better start point
    //    lAvailableCoins is sorted, if coin i * m < nReq, no combinations of lesser coins will be < either
    for (l = m; l <= n; ++l)
    {
        if (vData[l-1]->nValue * m < nReq)
            continue;
        startL = l;
        break;
    };

    if (fDebugRingSig)
        printf("Starting at level %d\n", startL);

    if (startL == 0)
    {
        printf("checkCombinations() No possible combinations.\n");
        return false;
    };


    for (l = startL; l <= n; ++l)
    {
        for (i = 0; i < m; ++i)
            v[i] = (m - i)-1;
        v[0] = l-1;

        // -- m must be > 2 to use coarse seeking
        bool fSeekFine = m > 2 ? false : true;

        // -- coarse
        while(!fSeekFine && v[1] < v[0]-1)
        {
            for (i = 1; i < m; ++i)
                v[i] = v[i]+1;

            int64_t nTotal = 0;

            for (i = 0; i < m; ++i)
                nTotal += vData[v[i]]->nValue;

            nCount++;

            if (nTotal == nReq)
            {
                if (fDebugRingSig)
                {
                    printf("Found match of total %" PRId64 ", in %" PRId64 " tries\n", nTotal, nCount);
                    for (i = m; i--;) printf("%d%c", v[i], i ? ' ': '\n');
                };
                return true;
            };
            if (nTotal > nReq)
            {
                for (i = 1; i < m; ++i) // rewind
                    v[i] = v[i]-1;

                if (fDebugRingSig)
                {
                    printf("Found coarse match of total %" PRId64 ", in %" PRId64 " tries\n", nTotal, nCount);
                    for (i = m; i--;) printf("%d%c", v[i], i ? ' ': '\n');
                };
                fSeekFine = true;
            };
        };

        if (!fSeekFine)
            continue;

        // -- fine
        i = m-1;
        for (;;)
        {
            if (v[0] == l-1) // otherwise get duplicate combinations
            {
                int64_t nTotal = 0;

                for (i = 0; i < m; ++i)
                    nTotal += vData[v[i]]->nValue;

                nCount++;

                if (nTotal >= nReq)
                {
                    if (fDebugRingSig)
                    {
                        printf("Found match of total %" PRId64 ", in %" PRId64 " tries\n", nTotal, nCount);
                        for (i = m; i--;) printf("%d%c", v[i], i ? ' ': '\n');
                    };
                    return true;
                };

                if (fDebugRingSig && !(nCount % 500))
                {
                    printf("checkCombinations() nCount: %" PRId64" - l: %d, n: %d, m: %d, i: %d, nReq: %" PRId64", v[0]: %d, nTotal: %" PRId64" \n", nCount, l, n, m, i, nReq, v[0], nTotal);
                    for (i = m; i--;) printf("%d%c", v[i], i ? ' ': '\n');
                };
            };

            for (i = 0; v[i] >= l - i;) // 0 is largest element
            {
                if (++i >= m)
                    goto EndInner;
            };

            // -- fill the set with the next values
            for (v[i]++; i; i--)
                v[i-1] = v[i] + 1;
        };
        EndInner:
        if (i+1 > n)
            break;
    };

    return false;
}

int CWallet::PickAnonInputs(int rsType, int64_t nValue, int64_t& nFee, int nRingSize, CWalletTx& wtxNew, int nOutputs, int nSizeOutputs, int& nExpectChangeOuts, std::list<COwnedAnonOutput>& lAvailableCoins, std::vector<COwnedAnonOutput*>& vPickedCoins, std::vector<std::pair<CScript, int64_t> >& vecChange, bool fTest, std::string& sError)
{
    if (fDebugRingSig)
        printf("PickAnonInputs(), ChangeOuts %d\n", nExpectChangeOuts);
    // - choose the smallest coin that can cover the amount + fee
    //   or least no. of smallest coins


    int64_t nAmountCheck = 0;

    std::vector<COwnedAnonOutput*> vData;
    try { vData.resize(lAvailableCoins.size()); } catch (std::exception& e)
    {
        printf("Error: PickAnonInputs() vData.resize threw: %s.\n", e.what());
        return false;
    };

    uint32_t vi = 0;
    for (std::list<COwnedAnonOutput>::iterator it = lAvailableCoins.begin(); it != lAvailableCoins.end(); ++it)
    {
        vData[vi++] = &(*it);
        nAmountCheck += it->nValue;
    };

    uint32_t nByteSizePerInCoin;
    switch(rsType)
    {
        case RING_SIG_1:
            nByteSizePerInCoin = (sizeof(COutPoint) + sizeof(unsigned int)) // CTxIn
                + GetSizeOfCompactSize(2 + (33 + 32 + 32) * nRingSize)
                + 2 + (33 + 32 + 32) * nRingSize;
            break;
        case RING_SIG_2:
            nByteSizePerInCoin = (sizeof(COutPoint) + sizeof(unsigned int)) // CTxIn
                + GetSizeOfCompactSize(2 + 32 + (33 + 32) * nRingSize)
                + 2 + 32 + (33 + 32) * nRingSize;
            break;
        default:
            sError = "Unknown ring signature type.";
            return false;
    };

    if (fDebugRingSig)
        printf("nByteSizePerInCoin: %d\n", nByteSizePerInCoin);

    // -- repeat until all levels are tried (1 coin, 2 coins, 3 coins etc)
    for (uint32_t i = 0; i < lAvailableCoins.size(); ++i)
    {
        if (fDebugRingSig)
            printf("Input loop %u\n", i);

        uint32_t nTotalBytes = (4 + 4 + 4) // Ctx: nVersion, nTime, nLockTime
            + GetSizeOfCompactSize(nOutputs + nExpectChangeOuts)
            + nSizeOutputs
            + (GetSizeOfCompactSize(MIN_ANON_OUT_SIZE) + MIN_ANON_OUT_SIZE + sizeof(int64_t)) * nExpectChangeOuts
            + GetSizeOfCompactSize((i+1))
            + nByteSizePerInCoin * (i+1);

        nFee = wtxNew.GetMinFee(0, GMF_ANON, nTotalBytes);

        if (fDebugRingSig)
            printf("nValue + nFee: %d, nValue: %d, nAmountCheck: %d, nTotalBytes: %u\n", nValue + nFee, nValue, nAmountCheck, nTotalBytes);

        if (nValue + nFee > nAmountCheck)
        {
            sError = "Not enough mature coins with requested ring size.";
            return 3;
        };

        vPickedCoins.clear();
        vecChange.clear();

        std::vector<int> vecInputIndex;
        if (checkCombinations(nValue + nFee, i+1, vData, vecInputIndex))
        {
            if (fDebugRingSig)
            {
                printf("Found combination %u, ", i+1);
                for (int ic = vecInputIndex.size(); ic--;)
                    printf("%d%c", vecInputIndex[ic], ic ? ' ': '\n');

                printf("nTotalBytes %u\n", nTotalBytes);
                printf("nFee %d\n", nFee);
            };

            int64_t nTotalIn = 0;
            vPickedCoins.resize(vecInputIndex.size());
            for (uint32_t ic = 0; ic < vecInputIndex.size(); ++ic)
            {
                vPickedCoins[ic] = vData[vecInputIndex[ic]];
                nTotalIn += vPickedCoins[ic]->nValue;
            };

            int64_t nChange = nTotalIn - (nValue + nFee);


            CStealthAddress sxChange;
            if (!GetAnonChangeAddress(sxChange))
            {
                sError = "GetAnonChangeAddress() change failed.";
                return 3;
            };

            std::string sNone;
            sNone.clear();
            CScript scriptNone;
            if (!CreateAnonOutputs(fTest ? NULL : &sxChange, nChange, sNone, vecChange, scriptNone))
            {
                sError = "CreateAnonOutputs() change failed.";
                return 3;
            };


            // -- get nTotalBytes again, using actual no. of change outputs
            uint32_t nTotalBytes = (4 + 4 + 4) // Ctx: nVersion, nTime, nLockTime
                + GetSizeOfCompactSize(nOutputs + vecChange.size())
                + nSizeOutputs
                + (GetSizeOfCompactSize(MIN_ANON_OUT_SIZE) + MIN_ANON_OUT_SIZE + sizeof(int64_t)) * vecChange.size()
                + GetSizeOfCompactSize((i+1))
                + nByteSizePerInCoin * (i+1);

            int64_t nTestFee = wtxNew.GetMinFee(0, GMF_ANON, nTotalBytes);

            if (nTestFee > nFee)
            {
                if (fDebugRingSig)
                    printf("Try again - nTestFee > nFee %d, %d, nTotalBytes %u\n", nTestFee, nFee, nTotalBytes);
                nExpectChangeOuts = vecChange.size();
                return 2; // up changeOutSize
            };

            nFee = nTestFee;
            return 1; // found
        };
    };

    return 0; // not found
};

int CWallet::GetTxnPreImage(CTransaction& txn, uint256& hash)
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << txn.nVersion;
    ss << txn.nTime;
    for (uint32_t i = 0; i < txn.vin.size(); ++i)
    {
        const CTxIn& txin = txn.vin[i];
        ss << txin.prevout; // keyimage only

        int ringSize = txin.ExtractRingSize();

        if (txin.scriptSig.size() < 2 + ringSize * ec_compressed_size)
        {
            printf("scriptSig is too small, input %u, ring size %d.\n", i, ringSize);
            return 1;
        };
        ss.write((const char*)&txin.scriptSig[2], ringSize * ec_compressed_size);
    };

    for (uint32_t i = 0; i < txn.vout.size(); ++i)
        ss << txn.vout[i];
    ss << txn.nLockTime;

    hash = ss.GetHash();

    return 0;
};

int CWallet::PickHidingOutputs(int64_t nValue, int nRingSize, CPubKey& pkCoin, int skip, uint8_t* p)
{
    if (fDebug)
        printf("PickHidingOutputs() %" PRId64 ", %d\n", nValue, nRingSize);

    // TODO: process multiple inputs in 1 db loop?

    // -- offset skip is pre filled with the real coin

    LOCK(cs_main);
    CTxDB txdb("r");

    leveldb::DB* pdb = txdb.GetInstance();
    if (!pdb)
        throw runtime_error("CWallet::PickHidingOutputs() : cannot get leveldb instance");

    leveldb::Iterator *iterator = pdb->NewIterator(leveldb::ReadOptions());

    std::vector<CPubKey> vHideKeys;

    // Seek to start key.
    CPubKey pkZero;
    pkZero.SetZero();

    CDataStream ssStartKey(SER_DISK, CLIENT_VERSION);
    ssStartKey << make_pair(string("ao"), pkZero);
    iterator->Seek(ssStartKey.str());

    CPubKey pkAo;
    CAnonOutput anonOutput;
    while (iterator->Valid())
    {
        // Unpack keys and values.
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.write(iterator->key().data(), iterator->key().size());
        string strType;
        ssKey >> strType;

        if (strType != "ao")
            break;

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.write(iterator->value().data(), iterator->value().size());


        ssKey >> pkAo;

        if (pkAo != pkCoin
            && pkAo.IsValid())
        {
            ssValue >> anonOutput;

            if ((anonOutput.nBlockHeight > 0 && nBestHeight - anonOutput.nBlockHeight >= MIN_ANON_SPEND_DEPTH)
                && anonOutput.nValue == nValue
                && anonOutput.nCompromised == 0)
                try { vHideKeys.push_back(pkAo); } catch (std::exception& e)
                {
                    printf("Error: PickHidingOutputs() vHideKeys.push_back threw: %s.\n", e.what());
                    return 1;
                };

        };

        iterator->Next();
    };

    delete iterator;

    if ((int)vHideKeys.size() < nRingSize-1)
    {
        printf("Not enough keys found.\n");
        return 1;
    };

    for (int i = 0; i < nRingSize; ++i)
    {
        if (i == skip)
            continue;

        if (vHideKeys.size() < 1)
        {
            printf("vHideKeys.size() < 1\n");
            return 1;
        };

        uint32_t pick = GetRand(vHideKeys.size());

        memcpy(p + i * 33, vHideKeys[pick].begin(), 33);

        vHideKeys.erase(vHideKeys.begin()+pick);
    };


    return 0;
};

bool CWallet::AreOutputsUnique(CWalletTx& wtxNew)
{
    LOCK(cs_main);
    CTxDB txdb;

    for (uint32_t i = 0; i < wtxNew.vout.size(); ++i)
    {
        const CTxOut& txout = wtxNew.vout[i];

        if (txout.IsAnonOutput())
            continue;

        const CScript &s = txout.scriptPubKey;

        CPubKey pkCoin = CPubKey(&s[2+1], ec_compressed_size);
        CAnonOutput ao;

        if (txdb.ReadAnonOutput(pkCoin, ao))
        {
            //printf("AreOutputsUnique() pk %s is not unique.\n", pkCoin);
            return false;
        };
    };

    return true;
};

int CWallet::ListUnspentAnonOutputs(std::list<COwnedAnonOutput>& lUAnonOutputs, bool fMatureOnly)
{
    CWalletDB walletdb(strWalletFile, "r");

    Dbc* pcursor = walletdb.GetAtCursor();
    if (!pcursor)
        throw runtime_error("CWallet::ListUnspentAnonOutputs() : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    while (true)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << std::string("oao");
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = walletdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
        {
            break;
        } else
        if (ret != 0)
        {
            pcursor->close();
            throw runtime_error("CWallet::ListUnspentAnonOutputs() : error scanning DB");
        };

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "oao")
            break;
        COwnedAnonOutput oao;
        ssKey >> oao.vchImage;

        ssValue >> oao;

        if (oao.fSpent)
            continue;

        std::map<uint256, CWalletTx>::iterator mi = mapWallet.find(oao.outpoint.hash);
        if (mi == mapWallet.end()
            || mi->second.nVersion != ANON_TXN_VERSION
            || mi->second.vout.size() <= oao.outpoint.n
            || mi->second.IsSpent(oao.outpoint.n))
            continue;

        // -- txn must be in MIN_ANON_SPEND_DEPTH deep in the blockchain to be spent
        if (fMatureOnly
            && mi->second.GetDepthInMainChain() < MIN_ANON_SPEND_DEPTH)
        {
            continue;
        };

        // TODO: check ReadAnonOutput?

        oao.nValue = mi->second.vout[oao.outpoint.n].nValue;


        // -- insert by nValue asc
        bool fInserted = false;
        for (std::list<COwnedAnonOutput>::iterator it = lUAnonOutputs.begin(); it != lUAnonOutputs.end(); ++it)
        {
            if (oao.nValue > it->nValue)
                continue;
            lUAnonOutputs.insert(it, oao);
            fInserted = true;
            break;
        };
        if (!fInserted)
            lUAnonOutputs.push_back(oao);
    };

    pcursor->close();
    return 0;
};

int CWallet::CountAnonOutputs(std::map<int64_t, int>& mOutputCounts, bool fMatureOnly)
{
    LOCK(cs_main);
    CTxDB txdb("r");

    leveldb::DB* pdb = txdb.GetInstance();
    if (!pdb)
        throw runtime_error("CWallet::CountAnonOutputs() : cannot get leveldb instance");

    leveldb::Iterator *iterator = pdb->NewIterator(leveldb::ReadOptions());


    // Seek to start key.
    CPubKey pkZero;
    pkZero.SetZero();

    CDataStream ssStartKey(SER_DISK, CLIENT_VERSION);
    ssStartKey << make_pair(string("ao"), pkZero);
    iterator->Seek(ssStartKey.str());


    while (iterator->Valid())
    {
        // Unpack keys and values.
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.write(iterator->key().data(), iterator->key().size());
        string strType;
        ssKey >> strType;

        if (strType != "ao")
            break;

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.write(iterator->value().data(), iterator->value().size());

        CAnonOutput anonOutput;
        ssValue >> anonOutput;

        if (!fMatureOnly
            || (anonOutput.nBlockHeight > 0 && nBestHeight - anonOutput.nBlockHeight >= MIN_ANON_SPEND_DEPTH))
        {
            std::map<int64_t, int>::iterator mi = mOutputCounts.find(anonOutput.nValue);
            if (mi != mOutputCounts.end())
                mi->second++;
        };

        iterator->Next();
    };

    delete iterator;

    return 0;
};

int CWallet::CountAllAnonOutputs(std::list<CAnonOutputCount>& lOutputCounts, bool fMatureOnly)
{
    if (fDebugRingSig)
        printf("CountAllAnonOutputs()\n");

    // TODO: there are few enough possible coin values to preinitialise a vector with all of them

    LOCK(cs_main);
    CTxDB txdb("r");

    leveldb::DB* pdb = txdb.GetInstance();
    if (!pdb)
        throw runtime_error("CWallet::CountAnonOutputs() : cannot get leveldb instance");

    leveldb::Iterator *iterator = pdb->NewIterator(leveldb::ReadOptions());


    // Seek to start key.
    CPubKey pkZero;
    pkZero.SetZero();

    CDataStream ssStartKey(SER_DISK, CLIENT_VERSION);
    ssStartKey << make_pair(string("ao"), pkZero);
    iterator->Seek(ssStartKey.str());


    while (iterator->Valid())
    {
        // Unpack keys and values.
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.write(iterator->key().data(), iterator->key().size());
        string strType;
        ssKey >> strType;

        if (strType != "ao")
            break;

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.write(iterator->value().data(), iterator->value().size());

        CAnonOutput ao;
        ssValue >> ao;

        int nHeight = ao.nBlockHeight > 0 ? nBestHeight - ao.nBlockHeight : 0;


        if (fMatureOnly
            && nHeight < MIN_ANON_SPEND_DEPTH)
        {
            // -- skip
        } else
        {
            // -- insert by nValue asc
            bool fProcessed = false;
            for (std::list<CAnonOutputCount>::iterator it = lOutputCounts.begin(); it != lOutputCounts.end(); ++it)
            {
                if (ao.nValue == it->nValue)
                {
                    it->nExists++;
                    if (it->nLeastDepth > nHeight)
                        it->nLeastDepth = nHeight;
                    fProcessed = true;
                    break;
                };
                if (ao.nValue > it->nValue)
                    continue;
                lOutputCounts.insert(it, CAnonOutputCount(ao.nValue, 1, 0, 0, nHeight));
                fProcessed = true;
                break;
            };
            if (!fProcessed)
                lOutputCounts.push_back(CAnonOutputCount(ao.nValue, 1, 0, 0, nHeight));
        };

        iterator->Next();
    };

    delete iterator;


    // -- count spends

    iterator = pdb->NewIterator(leveldb::ReadOptions());
    ssStartKey.clear();
    ssStartKey << make_pair(string("ki"), pkZero);
    iterator->Seek(ssStartKey.str());

    while (iterator->Valid())
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.write(iterator->key().data(), iterator->key().size());
        string strType;
        ssKey >> strType;

        if (strType != "ki")
            break;

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.write(iterator->value().data(), iterator->value().size());

        CKeyImageSpent kis;
        ssValue >> kis;


        bool fProcessed = false;
        for (std::list<CAnonOutputCount>::iterator it = lOutputCounts.begin(); it != lOutputCounts.end(); ++it)
        {
            if (kis.nValue != it->nValue)
                continue;
            it->nSpends++;
            fProcessed = true;
            break;
        };
        if (!fProcessed)
            printf("WARNING: CountAllAnonOutputs found keyimage without matching anon output value.\n");

        iterator->Next();
    };

    delete iterator;

    return 0;
};

int CWallet::CountOwnedAnonOutputs(std::map<int64_t, int>& mOwnedOutputCounts, bool fMatureOnly)
{
    if (fDebugRingSig)
        printf("CountOwnedAnonOutputs()\n");

    CWalletDB walletdb(strWalletFile, "r");

    Dbc* pcursor = walletdb.GetAtCursor();
    if (!pcursor)
        throw runtime_error("CWallet::CountOwnedAnonOutputs() : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    while (true)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << std::string("oao");
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = walletdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
        {
            break;
        } else
        if (ret != 0)
        {
            pcursor->close();
            throw runtime_error("CWallet::CountOwnedAnonOutputs() : error scanning DB");
        };

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "oao")
            break;
        COwnedAnonOutput oao;
        ssKey >> oao.vchImage;

        ssValue >> oao;

        if (oao.fSpent)
            continue;

        std::map<uint256, CWalletTx>::iterator mi = mapWallet.find(oao.outpoint.hash);
        if (mi == mapWallet.end()
            || mi->second.nVersion != ANON_TXN_VERSION
            || mi->second.vout.size() <= oao.outpoint.n
            || mi->second.IsSpent(oao.outpoint.n))
            continue;

        //printf("[rem] mi->second.GetDepthInMainChain() %d \n", mi->second.GetDepthInMainChain());
        //printf("[rem] mi->second.hashBlock %s \n", mi->second.hashBlock.ToString().c_str());
        // -- txn must be in MIN_ANON_SPEND_DEPTH deep in the blockchain to be spent
        if (fMatureOnly
            && mi->second.GetDepthInMainChain() < MIN_ANON_SPEND_DEPTH)
        {
            continue;
        };

        // TODO: check ReadAnonOutput?

        oao.nValue = mi->second.vout[oao.outpoint.n].nValue;

        mOwnedOutputCounts[oao.nValue]++;
    };

    pcursor->close();
    return 0;
};

bool CWallet::EraseAllAnonData()
{
    printf("EraseAllAnonData()\n");

    LOCK2(cs_main, cs_wallet);
    CWalletDB walletdb(strWalletFile, "cr+");
    CTxDB txdb("cr+");

    string strType;
    txdb.TxnBegin();
    leveldb::DB* pdb = txdb.GetInstance();
    if (!pdb)
        throw runtime_error("EraseAllAnonData() : cannot get leveldb instance");

    leveldb::Iterator *iterator = pdb->NewIterator(leveldb::ReadOptions());

    iterator->SeekToFirst();
    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    while (iterator->Valid())
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.write(iterator->key().data(), iterator->key().size());

        ssKey >> strType;

        if (strType == "ao"
            || strType == "ki")
        {
            printf("Erasing from txdb %s\n", strType.c_str());
            leveldb::Status s = pdb->Delete(writeOptions, iterator->key());

            if (!s.ok())
                printf("EraseAllAnonData() erase failed: %s\n", s.ToString().c_str());
        };

        iterator->Next();
    };

    delete iterator;
    txdb.TxnCommit();


    walletdb.TxnBegin();
    Dbc* pcursor = walletdb.GetTxnCursor();

    if (!pcursor)
        throw runtime_error("EraseAllAnonData() : cannot create DB cursor");
    unsigned int fFlags = DB_NEXT;
    while (true)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = walletdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
        {
            break;
        } else
        if (ret != 0)
        {
            pcursor->close();
            throw runtime_error("EraseAllAnonData() : error scanning DB");
        };

        ssKey >> strType;
        if (strType == "lao"
            || strType == "oao"
            || strType == "oal")
        {
            printf("Erasing from walletdb %s\n", strType.c_str());
            //continue;
            if ((ret = pcursor->del(0)) != 0)
               printf("Delete failed %d, %s\n", ret, db_strerror(ret));
        };
    };

    pcursor->close();

    walletdb.TxnCommit();


    return true;
};

bool CWallet::CacheAnonStats()
{
    if (fDebugRingSig)
        printf("CacheAnonStats()\n");

    mapAnonOutputStats.clear();

    std::list<CAnonOutputCount> lOutputCounts;
    if (CountAllAnonOutputs(lOutputCounts, false) != 0)
    {
        printf("Error: CountAllAnonOutputs() failed.\n");
    } else
    {
        for (std::list<CAnonOutputCount>::iterator it = lOutputCounts.begin(); it != lOutputCounts.end(); ++it)
            mapAnonOutputStats[it->nValue].set(
                it->nValue, it->nExists, it->nSpends, it->nOwned,
                it->nLeastDepth < 1 ? 0 : nBestHeight - it->nLeastDepth); // mapAnonOutputStats stores height in chain instead of depth
    };

    return true;
};


bool CWallet::SendINNToAnon(CStealthAddress& sxAddress, int64_t nValue, std::string& sNarr, CWalletTx& wtxNew, std::string& sError, bool fAskFee)
{
    if (fDebugRingSig)
        printf("SendINNToAnon()\n");

    if (IsLocked())
    {
        sError = _("Error: Wallet locked, unable to create transaction.");
        return false;
    };

    if (fWalletUnlockStakingOnly)
    {
        sError = _("Error: Wallet unlocked for staking, unable to create transaction.");
        return false;
    };

    if (nBestHeight < GetNumBlocksOfPeers()-1)
    {
        sError = _("Error: Blockchain must be fully synced first.");
        return false;
    };

    if (vNodes.empty())
    {
        sError = _("Error: Innova is not connected!");
        return false;
    };


    // -- Check amount
    if (nValue <= 0)
    {
        sError = "Invalid amount";
        return false;
    };

    if (nValue + nTransactionFee > GetBalance())
    {
        sError = "Insufficient funds";
        return false;
    };

    wtxNew.nVersion = ANON_TXN_VERSION;

    CScript scriptNarration; // needed to match output id of narr
    std::vector<std::pair<CScript, int64_t> > vecSend;
    CReserveKey reservekey(this);

    if (!CreateAnonOutputs(&sxAddress, nValue, sNarr, vecSend, scriptNarration))
    {
        sError = "CreateAnonOutputs() failed.";
        return false;
    };

    if (scriptNarration.size() > 0)
    {
        vecSend.push_back(make_pair(scriptNarration, 0));
    };

    // -- shuffle outputs
    std::random_shuffle(vecSend.begin(), vecSend.end());

    int64_t nFeeRequired;
    int32_t nChangePos = -1;
    if (!CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePos, NULL))
    {
        sError = "CreateTransaction() failed.";
        return false;
    };

    if (scriptNarration.size() > 0)
    {
        for (uint32_t k = 0; k < wtxNew.vout.size(); ++k)
        {
            if (wtxNew.vout[k].scriptPubKey != scriptNarration)
                continue;
            char key[64];
            if (snprintf(key, sizeof(key), "n_%u", k) < 1)
            {
                sError = "Error creating narration key.";
                return false;
            };
            wtxNew.mapValue[key] = sNarr;
            break;
        };
    };

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired, _("Sending...")))
    {
        sError = "ABORTED";
        return false;
    };

    // -- check if new coins already exist (in case random is broken ?)
    if (!AreOutputsUnique(wtxNew))
    {
        sError = "Error: Anon outputs are not unique - is random working!.";
        return false;
    };


    if (!CommitTransaction(wtxNew, reservekey))
    {
        sError = "Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.";
        UndoAnonTransaction(wtxNew);
        return false;
    };


    return true;
};

bool CWallet::SendAnonToAnon(CStealthAddress& sxAddress, int64_t nValue, int nRingSize, std::string& sNarr, CWalletTx& wtxNew, std::string& sError, bool fAskFee)
{
    if (fDebugRingSig)
        printf("SendAnonToAnon()\n");

    if (IsLocked())
    {
        sError = _("Error: Wallet locked, unable to create transaction.");
        return false;
    };

    if (fWalletUnlockStakingOnly)
    {
        sError = _("Error: Wallet unlocked for staking only, unable to create transaction.");
        return false;
    };

    if (nBestHeight < GetNumBlocksOfPeers()-1)
    {
        sError = _("Error: Blockchain must be fully synced first.");
        return false;
    };

    if (vNodes.empty())
    {
        sError = _("Error: Innova is not connected!");
        return false;
    };

    // -- Check amount
    if (nValue <= 0)
    {
        sError = "Invalid amount";
        return false;
    };

    if (nValue + nTransactionFee > GetAnonBalance())
    {
        sError = "Insufficient Anonymous INN funds";
        return false;
    };

    wtxNew.nVersion = ANON_TXN_VERSION;

    CScript scriptNarration; // needed to match output id of narr
    std::vector<std::pair<CScript, int64_t> > vecSend;
    std::vector<std::pair<CScript, int64_t> > vecChange;


    if (!CreateAnonOutputs(&sxAddress, nValue, sNarr, vecSend, scriptNarration))
    {
        sError = "CreateAnonOutputs() failed.";
        return false;
    };

    // -- shuffle outputs (any point?)
    //std::random_shuffle(vecSend.begin(), vecSend.end());
    CReserveKey reservekey(this);
    int64_t nFeeRequired;
    std::string sError2;

    if (!AddAnonInputs(nRingSize == 1 ? RING_SIG_1 : RING_SIG_2, nValue, nRingSize, vecSend, vecChange, wtxNew, nFeeRequired, false, sError2))
    {
        printf("SendAnonToAnon() AddAnonInputs failed %s.\n", sError2.c_str());
        sError = "AddAnonInputs() failed : " + sError2;
        return false;
    };


    if (scriptNarration.size() > 0)
    {
        for (uint32_t k = 0; k < wtxNew.vout.size(); ++k)
        {
            if (wtxNew.vout[k].scriptPubKey != scriptNarration)
                continue;
            char key[64];
            if (snprintf(key, sizeof(key), "n_%u", k) < 1)
            {
                sError = "Error creating narration key.";
                return false;
            };
            wtxNew.mapValue[key] = sNarr;
            break;
        };
    };

    if (!CommitTransaction(wtxNew, reservekey))
    {
        sError = "Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.";
        UndoAnonTransaction(wtxNew);
        return false;
    };

    return true;
};

bool CWallet::SendAnonToINN(CStealthAddress& sxAddress, int64_t nValue, int nRingSize, std::string& sNarr, CWalletTx& wtxNew, std::string& sError, bool fAskFee)
{
    if (fDebug)
        printf("SendAnonToINN()\n");

    if (IsLocked())
    {
        sError = _("Error: Wallet locked, unable to create transaction.");
        return false;
    };

    if (fWalletUnlockStakingOnly)
    {
        sError = _("Error: Wallet unlocked for staking only, unable to create transaction.");
        return false;
    };

    if (nBestHeight < GetNumBlocksOfPeers()-1)
    {
        sError = _("Error: Blockchain must be fully synced first.");
        return false;
    };

    if (vNodes.empty())
    {
        sError = _("Error: Innova is not connected!");
        return false;
    };

    // -- Check amount
    if (nValue <= 0)
    {
        sError = "Invalid amount";
        return false;
    };

    if (nValue + nTransactionFee > GetAnonBalance())
    {
        sError = "Insufficient Anonymous INN Funds";
        return false;
    };

    wtxNew.nVersion = ANON_TXN_VERSION;

    std::vector<std::pair<CScript, int64_t> > vecSend;
    std::vector<std::pair<CScript, int64_t> > vecChange;
    std::map<int, std::string> mapStealthNarr;
    if (!CreateStealthOutput(&sxAddress, nValue, sNarr, vecSend, mapStealthNarr, sError))
    {
        printf("SendCoinsAnon() CreateStealthOutput failed %s.\n", sError.c_str());
        return false;
    };
    std::map<int, std::string>::iterator itN;
    for (itN = mapStealthNarr.begin(); itN != mapStealthNarr.end(); ++itN)
    {
        int pos = itN->first;
        char key[64];
        if (snprintf(key, sizeof(key), "n_%u", pos) < 1)
        {
            printf("SendCoinsAnon(): Error creating narration key.");
            continue;
        };
        wtxNew.mapValue[key] = itN->second;
    };

    // -- get anon inputs
    CReserveKey reservekey(this);
    int64_t nFeeRequired;
    std::string sError2;
    if (!AddAnonInputs(nRingSize == 1 ? RING_SIG_1 : RING_SIG_2, nValue, nRingSize, vecSend, vecChange, wtxNew, nFeeRequired, false, sError2))
    {
        printf("SendAnonToINN() AddAnonInputs failed %s.\n", sError2.c_str());
        sError = "AddAnonInputs() failed: " + sError2;
        return false;
    };

    if (!CommitTransaction(wtxNew, reservekey))
    {
        sError = "Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.";
        UndoAnonTransaction(wtxNew);
        return false;
    };

    return true;
};

bool CWallet::AddAnonInputs(int rsType, int64_t nTotalOut, int nRingSize, std::vector<std::pair<CScript, int64_t> >&vecSend, std::vector<std::pair<CScript, int64_t> >&vecChange, CWalletTx& wtxNew, int64_t& nFeeRequired, bool fTestOnly, std::string& sError)
{
    if (fDebugRingSig)
        printf("AddAnonInputs() %d, %d, rsType:%d\n", nTotalOut, nRingSize, rsType);

    std::list<COwnedAnonOutput> lAvailableCoins;
    if (ListUnspentAnonOutputs(lAvailableCoins, true) != 0)
    {
        sError = "ListUnspentAnonOutputs() failed";
        return false;
    };

    std::map<int64_t, int> mOutputCounts;
    for (std::list<COwnedAnonOutput>::iterator it = lAvailableCoins.begin(); it != lAvailableCoins.end(); ++it)
        mOutputCounts[it->nValue] = 0;

    if (CountAnonOutputs(mOutputCounts, true) != 0)
    {
        sError = "CountAnonOutputs() failed";
        return false;
    };

    if (fDebugRingSig)
    {
        for (std::map<int64_t, int>::iterator it = mOutputCounts.begin(); it != mOutputCounts.end(); ++it)
            printf("mOutputCounts %ld %d\n", it->first, it->second);
    };

    int64_t nAmountCheck = 0;
    // -- remove coins that don't have enough same value anonoutputs in the system for the ring size
    std::list<COwnedAnonOutput>::iterator it = lAvailableCoins.begin();
    while (it != lAvailableCoins.end())
    {
        std::map<int64_t, int>::iterator mi = mOutputCounts.find(it->nValue);
        if (mi == mOutputCounts.end()
            || mi->second < nRingSize)
        {
            // -- not enough coins of same value, drop coin
            lAvailableCoins.erase(it++);
            continue;
        };

        nAmountCheck += it->nValue;
        ++it;
    };

    if (fDebugRingSig)
        printf("%u coins available with ring size %d, total %d\n", lAvailableCoins.size(), nRingSize, nAmountCheck);

    // -- estimate fee

    uint32_t nSizeOutputs = 0;
    for (uint32_t i = 0; i < vecSend.size(); ++i) // need to sum due to narration
        nSizeOutputs += GetSizeOfCompactSize(vecSend[i].first.size()) + vecSend[i].first.size() + sizeof(int64_t); // CTxOut

    bool fFound = false;
    int64_t nFee;
    int nExpectChangeOuts = 1;
    std::string sPickError;
    std::vector<COwnedAnonOutput*> vPickedCoins;
    for (int k = 0; k < 50; ++k) // safety
    {
        // -- nExpectChangeOuts is raised if needed (rv == 2)
        int rv = PickAnonInputs(rsType, nTotalOut, nFee, nRingSize, wtxNew, vecSend.size(), nSizeOutputs, nExpectChangeOuts, lAvailableCoins, vPickedCoins, vecChange, false, sPickError);
        if (rv == 0)
            break;
        if (rv == 3)
        {
            nFeeRequired = nFee; // set in PickAnonInputs()
            sError = sPickError;
            return false;
        };
        if (rv == 1)
        {
            fFound = true;
            break;
        };
    };

    if (!fFound)
    {
        sError = "No combination of coins matches amount and ring size.";
        return false;
    };

    nFeeRequired = nFee; // set in PickAnonInputs()
    int nSigSize = GetRingSigSize(rsType, nRingSize);

    // -- need hash of tx without signatures
    std::vector<int> vCoinOffsets;
    uint32_t ii = 0;
    wtxNew.vin.resize(vPickedCoins.size());
    vCoinOffsets.resize(vPickedCoins.size());
    for (std::vector<COwnedAnonOutput*>::iterator it = vPickedCoins.begin(); it != vPickedCoins.end(); ++it)
    {
        CTxIn& txin = wtxNew.vin[ii];
        if (fDebugRingSig)
            printf("pickedCoin %s %d\n", HexStr((*it)->vchImage).c_str(), (*it)->nValue);

        // -- overload prevout to hold keyImage
        memcpy(txin.prevout.hash.begin(), &(*it)->vchImage[0], EC_SECRET_SIZE);

        txin.prevout.n = 0 | (((*it)->vchImage[32]) & 0xFF) | (int32_t)(((int16_t) nRingSize) << 16);

        // -- size for full signature, signature is added later after hash
        try { txin.scriptSig.resize(nSigSize); } catch (std::exception& e)
        {
            printf("Error: AddAnonInputs() txin.scriptSig.resize threw: %s.\n", e.what());
            sError = "resize failed.\n";
            return false;
        };

        txin.scriptSig[0] = OP_RETURN;
        txin.scriptSig[1] = OP_ANON_MARKER;

        if (fTestOnly)
            continue;

        int nCoinOutId = (*it)->outpoint.n;
        WalletTxMap::iterator mi = mapWallet.find((*it)->outpoint.hash);
        if (mi == mapWallet.end()
            || mi->second.nVersion != ANON_TXN_VERSION
            || (int)mi->second.vout.size() < nCoinOutId)
        {
            printf("Error: AddAnonInputs() picked coin not in wallet, %s version %d.\n", (*it)->outpoint.hash.ToString().c_str(), (*mi).second.nVersion);
            sError = "picked coin not in wallet.\n";
            return false;
        };

        CWalletTx& wtxAnonCoin = mi->second;

        const CTxOut& txout = wtxAnonCoin.vout[nCoinOutId];
        const CScript &s = txout.scriptPubKey;

        if (!txout.IsAnonOutput())
        {
            sError = "picked coin not an anon output.\n";
            return false;
        };

        CPubKey pkCoin = CPubKey(&s[2+1], EC_COMPRESSED_SIZE);

        if (!pkCoin.IsValid())
        {
            sError = "pkCoin is invalid.\n";
            return false;
        };

        vCoinOffsets[ii] = GetRand(nRingSize);

        uint8_t *pPubkeyStart = GetRingSigPkStart(rsType, nRingSize, &txin.scriptSig[0]);

        memcpy(pPubkeyStart + vCoinOffsets[ii] * EC_COMPRESSED_SIZE, pkCoin.begin(), EC_COMPRESSED_SIZE);
        if (PickHidingOutputs((*it)->nValue, nRingSize, pkCoin, vCoinOffsets[ii], pPubkeyStart) != 0)
        {
            sError = "PickHidingOutputs() failed.\n";
            return false;
        };
        ii++;
    };

    for (uint32_t i = 0; i < vecSend.size(); ++i)
        wtxNew.vout.push_back(CTxOut(vecSend[i].second, vecSend[i].first));
    for (uint32_t i = 0; i < vecChange.size(); ++i)
        wtxNew.vout.push_back(CTxOut(vecChange[i].second, vecChange[i].first));

    std::sort(wtxNew.vout.begin(), wtxNew.vout.end());

    if (fTestOnly)
        return true;

    uint256 preimage;
    if (GetTxnPreImage(wtxNew, preimage) != 0)
    {
        sError = "GetPreImage() failed.\n";
        return false;
    };

    for (uint32_t i = 0; i < wtxNew.vin.size(); ++i)
    {
        CTxIn& txin = wtxNew.vin[i];

        // Test
        std::vector<uint8_t> vchImageTest;
        txin.ExtractKeyImage(vchImageTest);

        int nTestRingSize = txin.ExtractRingSize();
        if (nTestRingSize != nRingSize)
        {
            sError = "nRingSize embed error.";
            return false;
        };

        if (txin.scriptSig.size() < nSigSize)
        {
            sError = "Error: scriptSig too small.";
            return false;
        };

        int nSecretOffset = vCoinOffsets[i];

        uint8_t *pPubkeyStart = GetRingSigPkStart(rsType, nRingSize, &txin.scriptSig[0]);

        // -- get secret
        CPubKey pkCoin = CPubKey(pPubkeyStart + EC_COMPRESSED_SIZE * nSecretOffset, EC_COMPRESSED_SIZE);
        CKeyID pkId = pkCoin.GetID();

        CKey key;
        if (!GetKey(pkId, key))
        {
            sError = "Error: don't have key for output.";
            return false;
        };

        ec_secret ecSecret;
        if (key.size() != EC_SECRET_SIZE)
        {
            sError = "Error: key.size() != EC_SECRET_SIZE.";
            return false;
        };

        memcpy(&ecSecret.e[0], key.begin(), key.size());

        switch(rsType)
        {
            case RING_SIG_1:
                {
                uint8_t *pPubkeys = &txin.scriptSig[2];
                uint8_t *pSigc    = &txin.scriptSig[2 + EC_COMPRESSED_SIZE * nRingSize];
                uint8_t *pSigr    = &txin.scriptSig[2 + (EC_COMPRESSED_SIZE + EC_SECRET_SIZE) * nRingSize];
                if (generateRingSignature(vchImageTest, preimage, nRingSize, nSecretOffset, ecSecret, pPubkeys, pSigc, pSigr) != 0)
                {
                    sError = "Error: generateRingSignature() failed.";
                    return false;
                };
                // -- test verify
                if (verifyRingSignature(vchImageTest, preimage, nRingSize, pPubkeys, pSigc, pSigr) != 0)
                {
                    sError = "Error: verifyRingSignature() failed.";
                    return false;
                };
                }
                break;
            case RING_SIG_2:
                {
                ec_point pSigC;
                uint8_t *pSigS    = &txin.scriptSig[2 + EC_SECRET_SIZE];
                uint8_t *pPubkeys = &txin.scriptSig[2 + EC_SECRET_SIZE + EC_SECRET_SIZE * nRingSize];
                if (generateRingSignatureAB(vchImageTest, preimage, nRingSize, nSecretOffset, ecSecret, pPubkeys, pSigC, pSigS) != 0)
                {
                    sError = "Error: generateRingSignatureAB() failed.";
                    return false;
                };
                if (pSigC.size() == EC_SECRET_SIZE)
                    memcpy(&txin.scriptSig[2], &pSigC[0], EC_SECRET_SIZE);
                else
                    printf("pSigC.size() : %d Invalid!!\n", pSigC.size());

                // -- test verify
                if (verifyRingSignatureAB(vchImageTest, preimage, nRingSize, pPubkeys, pSigC, pSigS) != 0)
                {
                    sError = "Error: verifyRingSignatureAB() failed.";
                    return false;
                };
                }
                break;
            default:
                sError = "Unknown ring signature type.";
                return false;
        };

        OPENSSL_cleanse(&ecSecret.e[0], EC_SECRET_SIZE);
    };

    // -- check if new coins already exist (in case random is broken ?)
    if (!AreOutputsUnique(wtxNew))
    {
        sError = "Error: Anon outputs are not unique - is random working!.";
        return false;
    };

    return true;
};

bool CWallet::EstimateAnonFee(int64_t nValue, int nRingSize, std::string& sNarr, CWalletTx& wtxNew, int64_t& nFeeRet, std::string& sError)
{
    if (fDebugRingSig)
        printf("EstimateAnonFee()\n");

    nFeeRet = 0;

    // -- Check amount
    if (nValue <= 0)
    {
        sError = "Invalid amount";
        return false;
    };

    if (nValue + nTransactionFee > GetAnonBalance())
    {
        sError = "Insufficient Anonymous INN funds";
        return false;
    };

    CScript scriptNarration; // needed to match output id of narr
    std::vector<std::pair<CScript, int64_t> > vecSend;
    std::vector<std::pair<CScript, int64_t> > vecChange;

    if (!CreateAnonOutputs(NULL, nValue, sNarr, vecSend, scriptNarration))
    {
        sError = "CreateAnonOutputs() failed.";
        return false;
    };

    int64_t nFeeRequired;
	if (!AddAnonInputs(nRingSize == 1 ? RING_SIG_1 : RING_SIG_2, nValue, nRingSize, vecSend, vecChange, wtxNew, nFeeRequired, true, sError))
    {
        printf("EstimateAnonFee() AddAnonInputs failed %s.\n", sError.c_str());
        sError = "AddAnonInputs() failed.";
        return false;
    };

    nFeeRet = nFeeRequired;

    return true;
};

bool CWallet::ExpandLockedAnonOutput(CWalletDB *pwdb, CKeyID &ckeyId, CLockedAnonOutput &lao, std::set<uint256> &setUpdated)
{
    if (fDebugRingSig)
    {
        CBitcoinAddress addrTo(ckeyId);
        printf("%s %s\n", __func__, addrTo.ToString().c_str());
        AssertLockHeld(cs_main);
        AssertLockHeld(cs_wallet);
    };

    CStealthAddress sxFind;
    //sxFind.SetScanPubKey(lao.pkScan);

    bool fFound = false;
    ec_secret sSpendR;
    ec_secret sSpend;
    ec_secret sScan;

    ec_point pkEphem;


    std::set<CStealthAddress>::iterator si = stealthAddresses.find(sxFind);
    if (si != stealthAddresses.end())
    {
        fFound = true;

        if (si->spend_secret.size() != EC_SECRET_SIZE
         || si->scan_secret .size() != EC_SECRET_SIZE)
            return error("%s: Stealth address has no secret.", __func__);

        memcpy(&sScan.e[0], &si->scan_secret[0], EC_SECRET_SIZE);
        memcpy(&sSpend.e[0], &si->spend_secret[0], EC_SECRET_SIZE);

        pkEphem.resize(lao.pkEphem.size());
        memcpy(&pkEphem[0], lao.pkEphem.begin(), lao.pkEphem.size());

        if (StealthSecretSpend(sScan, pkEphem, sSpend, sSpendR) != 0)
            return error("%s: StealthSecretSpend() failed.", __func__);

    };
	/*
    // - check ext account stealth keys
    ExtKeyAccountMap::const_iterator mi;
    if (!fFound)
    for (mi = mapExtAccounts.begin(); mi != mapExtAccounts.end(); ++mi)
    {
        fFound = true;

        CExtKeyAccount *ea = mi->second;

        CKeyID sxId = lao.pkScan.GetID();

        AccStealthKeyMap::const_iterator miSk = ea->mapStealthKeys.find(sxId);
        if (miSk == ea->mapStealthKeys.end())
            continue;

        const CEKAStealthKey &aks = miSk->second;
        if (ea->IsLocked(aks))
            return error("%s: Stealth is locked.", __func__);

        ec_point pkExtracted;
        ec_secret sShared;

        pkEphem.resize(lao.pkEphem.size());
        memcpy(&pkEphem[0], lao.pkEphem.begin(), lao.pkEphem.size());
        memcpy(&sScan.e[0], aks.skScan.begin(), EC_SECRET_SIZE);

        // - need sShared to extract key
        if (StealthSecret(sScan, pkEphem, aks.pkSpend, sShared, pkExtracted) != 0)
            return error("%s: StealthSecret() failed.", __func__);

        CKey kChild;

        if (0 != ea->ExpandStealthChildKey(&aks, sShared, kChild))
            return error("%s: ExpandStealthChildKey() failed %s.", __func__, aks.ToStealthAddress().c_str());

        memcpy(&sSpendR.e[0], kChild.begin(), EC_SECRET_SIZE);
    };
	*/


    if (!fFound)
        return error("%s: No stealth key found.", __func__);

    ec_point pkTestSpendR;
    if (SecretToPublicKey(sSpendR, pkTestSpendR) != 0)
        return error("%s: SecretToPublicKey() failed.", __func__);


    //CKey key;
    CKey key;
  	CSecret vchSecret;
  	vchSecret.resize(ec_secret_size);

   	key.Set(&vchSecret[0], &sSpendR.e[0], true);

    if (!key.IsValid())
        return error("%s: Reconstructed key is invalid.", __func__);

    CPubKey pkCoin = key.GetPubKey();
    if (!pkCoin.IsValid())
        return error("%s: pkCoin is invalid.", __func__);

    CKeyID keyIDTest = pkCoin.GetID();
    if (keyIDTest != ckeyId)
    {
        printf("%s: Error: Generated secret does not match.\n", __func__);
        if (fDebugRingSig)
        {
            printf("test   %s\n", keyIDTest.ToString().c_str());
            printf("gen    %s\n", ckeyId.ToString().c_str());
        };
        return false;
    };

    if (fDebugRingSig)
    {
        CBitcoinAddress coinAddress(keyIDTest);
        printf("Adding secret to key %s.\n", coinAddress.ToString().c_str());
    };

    if (!AddKeyInDBTxn(pwdb, key))
        return error("%s: AddKeyInDBTxn failed.", __func__);

    // -- store keyimage
    ec_point pkImage;
    ec_point pkOldImage;
    getOldKeyImage(pkCoin, pkOldImage);
    if (generateKeyImage(pkTestSpendR, sSpendR, pkImage) != 0)
        return error("%s: generateKeyImage failed.", __func__);

    bool fSpentAOut = false;


    setUpdated.insert(lao.outpoint.hash);

    {
        // -- check if this output is already spent
        CTxDB txdb;

        CKeyImageSpent kis;

        bool fInMemPool;
        CAnonOutput ao;
        txdb.ReadAnonOutput(pkCoin, ao);
        if ((GetKeyImage(&txdb, pkImage, kis, fInMemPool) && !fInMemPool)
          ||(GetKeyImage(&txdb, pkOldImage, kis, fInMemPool) && !fInMemPool)) // shouldn't be possible for kis to be in mempool here
        {
            fSpentAOut = true;

            WalletTxMap::iterator miw = mapWallet.find(lao.outpoint.hash);
            if (miw != mapWallet.end())
            {
                CWalletTx& wtx = (*miw).second;
                wtx.MarkSpent(lao.outpoint.n);

                if (!pwdb->WriteTx(lao.outpoint.hash, wtx))
                    return error("%s: WriteTx %s failed.", __func__, wtx.ToString().c_str());

                wtx.MarkDirty();
            };
        };
    } // txdb

    COwnedAnonOutput oao(lao.outpoint, fSpentAOut);
    if (!pwdb->WriteOwnedAnonOutput(pkImage, oao)
      ||!pwdb->WriteOldOutputLink(pkOldImage, pkImage)
      ||!pwdb->WriteOwnedAnonOutputLink(pkCoin, pkImage))
    {
        return error("%s: WriteOwnedAnonOutput() failed.", __func__);
    };

    if (fDebugRingSig)
        printf("Adding anon output to wallet: %s.\n", HexStr(pkImage).c_str());

    return true;
};

bool CWallet::ProcessLockedAnonOutputs()
{
    if (fDebugRingSig)
    {
        printf("%s\n", __func__);
        AssertLockHeld(cs_main);
        AssertLockHeld(cs_wallet);
    };
    // -- process owned anon outputs received when wallet was locked.


    std::set<uint256> setUpdated;

    CWalletDB walletdb(strWalletFile, "cr+");
    walletdb.TxnBegin();
    Dbc *pcursor = walletdb.GetTxnCursor();

    if (!pcursor)
        throw runtime_error(strprintf("%s : cannot create DB cursor.", __func__).c_str());
    unsigned int fFlags = DB_SET_RANGE;
    while (true)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << std::string("lao");
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = walletdb.ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
        {
            break;
        } else
        if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(strprintf("%s : error scanning DB.", __func__).c_str());
        };

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "lao")
            break;
        CLockedAnonOutput lockedAnonOutput;
        CKeyID ckeyId;
        ssKey >> ckeyId;
        ssValue >> lockedAnonOutput;

        if (ExpandLockedAnonOutput(&walletdb, ckeyId, lockedAnonOutput, setUpdated))
        {
            if ((ret = pcursor->del(0)) != 0)
               printf("%s : Delete failed %d, %s\n", __func__, ret, db_strerror(ret));
        };
    };

    pcursor->close();

    walletdb.TxnCommit();

    std::set<uint256>::iterator it;
    for (it = setUpdated.begin(); it != setUpdated.end(); ++it)
    {
        WalletTxMap::iterator miw = mapWallet.find(*it);
        if (miw == mapWallet.end())
            continue;
        CWalletTx& wtx = (*miw).second;
        wtx.MarkDirty();
        wtx.fDebitCached = 2; // force update

        NotifyTransactionChanged(this, *it, CT_UPDATED);
    };

    return true;
};

extern CWallet* pwalletMain;
void SendMoneyCheck(CAmount nValue)
{
    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > pwalletMain->GetBalance())
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    string strError;
    if (pwalletMain->IsLocked())
    {
        strError = "Error: Wallet locked, unable to create transaction!";
        printf("SendMoney() : %s", strError.c_str());
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    if (fWalletUnlockStakingOnly)
    {
        string strError = ("Error: Wallet unlocked for block minting only, unable to create transaction.");
        printf("SendMoney() : %s", strError.c_str());
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
}

void SendName(CScript scriptPubKey, CAmount nValue, CWalletTx& wtxNew, const CWalletTx& wtxNameIn, CAmount nFeeInput)
{
    SendMoneyCheck(nValue);

    // Create and send the transaction
    string strError;
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    if (!pwalletMain->CreateNameTx(scriptPubKey, nValue, wtxNameIn, nFeeInput, wtxNew, reservekey, nFeeRequired, strError))
    {
        if (nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired).c_str());
        printf("SendMoney() : %s\n", strError.c_str());
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
}

static const int64_t MIN_COLD_STAKE_AMOUNT = 100 * COIN; // 100 min

bool CWallet::CreateColdStakeDelegation(const CKeyID& stakerKeyID, const CKeyID& ownerKeyID,
                                        int64_t nValue, CWalletTx& wtxNew, std::string& strError)
{
    if (nValue <= 0)
    {
        strError = "Invalid amount";
        return false;
    }

    if (nValue < MIN_COLD_STAKE_AMOUNT)
    {
        strError = strprintf("Minimum cold stake delegation is %s INN", FormatMoney(MIN_COLD_STAKE_AMOUNT).c_str());
        return false;
    }

    if (nValue + nTransactionFee > GetBalance())
    {
        strError = "Insufficient funds";
        return false;
    }

    CScript scriptColdStake = GetScriptForColdStaking(stakerKeyID, ownerKeyID);

    CReserveKey reservekey(this);
    int64_t nFeeRequired;
    int32_t nChangePos;

    vector<pair<CScript, int64_t> > vecSend;
    vecSend.push_back(make_pair(scriptColdStake, nValue));

    if (!CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePos))
    {
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf("Error: This transaction requires a fee of at least %s", FormatMoney(nFeeRequired).c_str());
        else
            strError = "Transaction creation failed";
        return false;
    }

    if (!CommitTransaction(wtxNew, reservekey))
    {
        strError = "Error: The transaction was rejected";
        return false;
    }

    return true;
}

int64_t CWallet::GetColdStakingBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || !pcoin->IsTrusted())
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            {
                if (pcoin->IsSpent(i))
                    continue;
                if (IsPayToColdStaking(pcoin->vout[i].scriptPubKey))
                {
                    isminetype mine = IsMine(pcoin->vout[i]);
                    if (mine != MINE_NO)
                    {
                        if (pcoin->vout[i].nValue > 0 && nTotal <= MAX_MONEY - pcoin->vout[i].nValue)
                            nTotal += pcoin->vout[i].nValue;
                    }
                }
            }
        }
    }
    return nTotal;
}

bool CWallet::NeedsStakingPreparation() const
{
    StakingMode eMode;
    {
        LOCK(cs_stakingMode);
        eMode = nStakingMode;
    }
    if (eMode == STAKE_NULLSTAKE)
        return (GetBalance() > 0 && GetShieldedBalance() == 0);
    if (eMode == STAKE_COLD)
        return (GetColdStakingBalance() == 0 && GetBalance() > 0);
    if (eMode == STAKE_NULLSTAKE_COLD)
        return (GetShieldedBalance() == 0 && GetBalance() > 0);
    return false;
}

bool CWallet::AddColdStakeDelegation(const CColdStakeDelegation& deleg)
{
    LOCK(cs_shielded);
    mapColdStakeDelegations[deleg.hashOwner] = deleg;
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.WriteColdStakeDelegation(deleg.hashOwner, deleg);
    }
    return true;
}

bool CWallet::ImportColdStakeDelegation(const CColdStakeDelegation& deleg)
{
    if (deleg.IsNull())
        return false;
    if (deleg.vchPkStake.size() != 33)
        return false;

    return AddColdStakeDelegation(deleg);
}

bool CWallet::RevokeColdStakeDelegation(const uint256& hashOwner)
{
    LOCK(cs_shielded);
    std::map<uint256, CColdStakeDelegation>::iterator it = mapColdStakeDelegations.find(hashOwner);
    if (it == mapColdStakeDelegations.end())
        return false;

    mapColdStakeDelegations.erase(it);
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.EraseColdStakeDelegation(hashOwner);
    }
    return true;
}

std::vector<CWallet::CShieldedWalletNote> CWallet::SelectShieldedNotesForColdStaking(const CColdStakeDelegation& deleg) const
{
    std::vector<CShieldedWalletNote> vSelected;
    LOCK(cs_shielded);
    for (size_t i = 0; i < vShieldedNotes.size(); i++)
    {
        const CShieldedWalletNote& wnote = vShieldedNotes[i];
        if (wnote.fSpent || wnote.note.nValue <= 0)
            continue;
        if (deleg.nDelegateAmount > 0 && wnote.note.nValue > deleg.nDelegateAmount)
            continue;
        vSelected.push_back(wnote);
    }
    return vSelected;
}


static const int64_t SPV_BLOCK_REQUEST_INTERVAL = 30;
static size_t GetSPVUtxoCacheMaxSize()
{
    return (size_t)GetArg("-spvutxocachesize", 10000);
}

void CWallet::UpdateSPVUtxo(const COutPoint& outpoint, const SPVUtxo& utxo)
{
    LOCK(cs_spvutxos);

    SPVUtxo verifiedUtxo = utxo;

    if (!utxo.vMerkleBranch.empty())
    {
        verifiedUtxo.fVerified = verifiedUtxo.VerifyMerkleProof();
        if (!verifiedUtxo.fVerified)
        {
            printf("SPV: Rejected UTXO %s:%d - merkle proof verification failed\n",
                   outpoint.hash.ToString().c_str(), outpoint.n);
            return;
        }
    }
    else if (utxo.fVerified)
    {
        LOCK(cs_main);
        if (!mapBlockIndex.count(utxo.hashBlock))
        {
            printf("SPV: Rejected UTXO %s:%d - claimed verified but block %s not in index\n",
                   outpoint.hash.ToString().c_str(), outpoint.n,
                   utxo.hashBlock.ToString().c_str());
            verifiedUtxo.fVerified = false;
        }
    }

    mapSPVUtxos[outpoint] = verifiedUtxo;

    if (mapSPVUtxos.size() > GetSPVUtxoCacheMaxSize())
    {
        PruneSPVUtxos();
    }
}

void CWallet::RemoveSPVUtxo(const COutPoint& outpoint)
{
    LOCK(cs_spvutxos);
    mapSPVUtxos.erase(outpoint);
}

void CWallet::MarkSPVUtxoSpent(const COutPoint& outpoint)
{
    LOCK(cs_spvutxos);
    auto it = mapSPVUtxos.find(outpoint);
    if (it != mapSPVUtxos.end())
    {
        it->second.fSpent = true;
    }
}

bool CWallet::IsSPVUtxoSpent(const COutPoint& outpoint) const
{
    LOCK(cs_spvutxos);
    auto it = mapSPVUtxos.find(outpoint);
    if (it != mapSPVUtxos.end())
    {
        return it->second.fSpent;
    }
    return IsSpent(outpoint.hash, outpoint.n);
}

void CWallet::PruneSPVUtxos()
{
    size_t nMaxSize = GetSPVUtxoCacheMaxSize();

    std::vector<COutPoint> toRemove;
    for (const auto& item : mapSPVUtxos)
    {
        if (item.second.fSpent)
        {
            toRemove.push_back(item.first);
        }
    }
    for (const COutPoint& outpoint : toRemove)
    {
        mapSPVUtxos.erase(outpoint);
    }

    if (mapSPVUtxos.size() > nMaxSize)
    {
        std::vector<std::pair<int, COutPoint>> vecByPriority; // (priority, outpoint)
        for (const auto& item : mapSPVUtxos)
        {
            int nPriority = item.second.fVerified ? 1000000 : 0;
            nPriority += item.second.nHeight;
            vecByPriority.push_back(std::make_pair(nPriority, item.first));
        }
        std::sort(vecByPriority.begin(), vecByPriority.end());

        size_t nToEvict = mapSPVUtxos.size() - nMaxSize;
        for (size_t i = 0; i < nToEvict && i < vecByPriority.size(); i++)
        {
            mapSPVUtxos.erase(vecByPriority[i].second);
        }

        if (fDebug)
            printf("SPV: LRU-evicted %zu UTXOs from cache (limit: %zu)\n", nToEvict, nMaxSize);
    }

    if (!toRemove.empty() && fDebug)
    {
        printf("SPV: Pruned %zu spent UTXOs from cache\n", toRemove.size());
    }
}

void CWallet::PopulateSPVUtxosFromWallet()
{
    LOCK2(cs_main, cs_wallet);
    LOCK(cs_spvutxos);

    printf("SPV: Populating UTXO cache from wallet...\n");
    int nCount = 0;
    int nVerified = 0;

    std::map<uint256, CBlock> mapBlockCache;

    for (const auto& item : mapWallet)
    {
        const CWalletTx& wtx = item.second;
        const uint256& txhash = item.first;

        if (wtx.GetDepthInMainChain() < 1)
            continue;

        if (wtx.GetBlocksToMaturity() > 0)
            continue;

        uint256 hashBlock = wtx.hashBlock;
        int nHeight = 0;
        CBlockIndex* pindex = NULL;
        if (mapBlockIndex.count(hashBlock))
        {
            pindex = mapBlockIndex[hashBlock];
            nHeight = pindex->nHeight;
        }

        for (unsigned int i = 0; i < wtx.vout.size(); i++)
        {
            if (wtx.IsSpent(i))
                continue;

            if (!IsMine(wtx.vout[i]))
                continue;

            if (wtx.nVersion == ANON_TXN_VERSION && wtx.vout[i].IsAnonOutput())
                continue;

            if (IsLockedCoin(txhash, i))
                continue;

            COutPoint outpoint(txhash, i);

            SPVUtxo utxo;
            utxo.txhash = txhash;
            utxo.n = i;
            utxo.nValue = wtx.vout[i].nValue;
            utxo.nHeight = nHeight;
            utxo.hashBlock = hashBlock;
            utxo.nTime = wtx.nTime;
            utxo.scriptPubKey = wtx.vout[i].scriptPubKey;
            utxo.fHaveBlock = true;
            utxo.fSpent = false;
            utxo.fVerified = false;
            utxo.nLastBlockRequest = 0;
            utxo.nTxIndex = -1;

            if (pindex && pindex->nFile > 0)
            {
                if (mapBlockCache.find(hashBlock) == mapBlockCache.end())
                {
                    CBlock block;
                    if (block.ReadFromDisk(pindex, true))
                    {
                        block.BuildMerkleTree();
                        mapBlockCache[hashBlock] = block;
                    }
                }

                if (mapBlockCache.count(hashBlock))
                {
                    CBlock& block = mapBlockCache[hashBlock];

                    int nTxIndex = -1;
                    for (size_t j = 0; j < block.vtx.size(); j++)
                    {
                        if (block.vtx[j].GetHash() == txhash)
                        {
                            nTxIndex = j;
                            break;
                        }
                    }

                    if (nTxIndex >= 0)
                    {
                        utxo.nTxIndex = nTxIndex;
                        utxo.hashMerkleRoot = block.hashMerkleRoot;
                        utxo.vMerkleBranch = block.GetMerkleBranch(nTxIndex);
                        utxo.fVerified = utxo.VerifyMerkleProof();
                        if (utxo.fVerified)
                            nVerified++;
                    }
                }
            }

            if (!utxo.fVerified)
            {
                utxo.fVerified = true;
            }

            mapSPVUtxos[outpoint] = utxo;
            nCount++;
        }
    }

    printf("SPV: Populated %d UTXOs into cache (%d with merkle proofs)\n", nCount, nVerified);
}

bool CWallet::SaveSPVUtxoCache()
{
    if (!fHybridSPV)
        return true;

    LOCK(cs_spvutxos);

    boost::filesystem::path pathCache = GetDataDir() / "spvutxos.dat";
    FILE* file = fopen(pathCache.string().c_str(), "wb");
    if (!file)
    {
        printf("SPV: Failed to open %s for writing\n", pathCache.string().c_str());
        return false;
    }

    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);

    try {
        fileout << (uint32_t)mapSPVUtxos.size();
        for (const auto& item : mapSPVUtxos)
        {
            fileout << item.first;
            fileout << item.second.txhash;
            fileout << item.second.n;
            fileout << item.second.nValue;
            fileout << item.second.nHeight;
            fileout << item.second.hashBlock;
            fileout << item.second.hashMerkleRoot;
            fileout << item.second.vMerkleBranch;
            fileout << item.second.nTxIndex;
            fileout << item.second.fHaveBlock;
            fileout << item.second.fSpent;
            fileout << item.second.fVerified;
            fileout << item.second.nTime;
            fileout << item.second.scriptPubKey;
        }
    }
    catch (std::exception& e) {
        printf("SPV: Error saving UTXO cache: %s\n", e.what());
        return false;
    }

    printf("SPV: Saved %zu UTXOs to cache file\n", mapSPVUtxos.size());
    return true;
}

bool CWallet::LoadSPVUtxoCache()
{
    if (!fHybridSPV)
        return true;

    boost::filesystem::path pathCache = GetDataDir() / "spvutxos.dat";
    if (!boost::filesystem::exists(pathCache))
    {
        printf("SPV: No cached UTXO file found, will rebuild from wallet\n");
        return false;
    }

    FILE* file = fopen(pathCache.string().c_str(), "rb");
    if (!file)
        return false;

    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);

    LOCK(cs_spvutxos);
    mapSPVUtxos.clear();

    try {
        uint32_t nCount;
        filein >> nCount;

        for (uint32_t i = 0; i < nCount; i++)
        {
            COutPoint outpoint;
            SPVUtxo utxo;

            filein >> outpoint;
            filein >> utxo.txhash;
            filein >> utxo.n;
            filein >> utxo.nValue;
            filein >> utxo.nHeight;
            filein >> utxo.hashBlock;
            filein >> utxo.hashMerkleRoot;
            filein >> utxo.vMerkleBranch;
            filein >> utxo.nTxIndex;
            filein >> utxo.fHaveBlock;
            filein >> utxo.fSpent;
            filein >> utxo.fVerified;
            filein >> utxo.nTime;
            filein >> utxo.scriptPubKey;

            utxo.nLastBlockRequest = 0;
            mapSPVUtxos[outpoint] = utxo;
        }
    }
    catch (std::exception& e) {
        printf("SPV: Error loading UTXO cache: %s\n", e.what());
        mapSPVUtxos.clear();
        return false;
    }

    printf("SPV: Loaded %zu UTXOs from cache file\n", mapSPVUtxos.size());
    return true;
}

void CWallet::AvailableCoinsForStakingSPV(std::vector<COutPoint>& vCoins) const
{
    vCoins.clear();
    unsigned int nSpendTime = GetAdjustedTime();

    LOCK(cs_spvutxos);
    for (const auto& item : mapSPVUtxos)
    {
        const SPVUtxo& utxo = item.second;

        if (utxo.fSpent)
            continue;

        if (utxo.nTime + nStakeMinAge > nSpendTime)
            continue;

        if (utxo.nValue < nMinimumInputValue)
            continue;

        if (!utxo.fVerified && !utxo.fHaveBlock)
        {
            continue;
        }

        vCoins.push_back(item.first);
    }
}

void CWallet::MarkSPVBlockAvailable(const uint256& hashBlock)
{
    LOCK(cs_spvutxos);
    for (auto& item : mapSPVUtxos)
    {
        if (item.second.hashBlock == hashBlock)
        {
            item.second.fHaveBlock = true;
            item.second.fVerified = true;
        }
    }
}

bool CWallet::RequestBlockForStaking(const uint256& hashBlock, bool fWait)
{
    int64_t nNow = GetTime();

    {
        LOCK(cs_spvutxos);
        for (auto& item : mapSPVUtxos)
        {
            if (item.second.hashBlock == hashBlock)
            {
                if (nNow - item.second.nLastBlockRequest < SPV_BLOCK_REQUEST_INTERVAL)
                {
                    return false;
                }
                item.second.nLastBlockRequest = nNow;
                break;
            }
        }
    }

    extern bool FetchBlockForStaking(const uint256& hashBlock);
    bool fRequested = FetchBlockForStaking(hashBlock);

    if (fWait && fRequested)
    {
        int64_t nWaitUntil = GetTime() + 10;
        while (GetTime() < nWaitUntil)
        {
            MilliSleep(100);

            {
                LOCK(cs_main);
                if (mapBlockIndex.count(hashBlock))
                {
                    CBlockIndex* pindex = mapBlockIndex[hashBlock];
                    if (pindex->nFile > 0)
                    {
                        MarkSPVBlockAvailable(hashBlock);
                        return true;
                    }
                }
            }
        }
        return false;
    }

    return fRequested;
}

bool CWallet::SelectCoinsForStakingSPV(std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet) const
{
    std::vector<COutPoint> vSPVCoins;
    AvailableCoinsForStakingSPV(vSPVCoins);

    setCoinsRet.clear();

    LOCK2(cs_main, cs_wallet);

    std::vector<uint256> vBlocksNeeded;

    for (const COutPoint& outpoint : vSPVCoins)
    {
        if (IsSpent(outpoint.hash, outpoint.n))
        {
            const_cast<CWallet*>(this)->MarkSPVUtxoSpent(outpoint);
            continue;
        }

        std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(outpoint.hash);
        if (it != mapWallet.end())
        {
            const CWalletTx* pcoin = &(it->second);
            if (outpoint.n < pcoin->vout.size())
            {
                if (pcoin->hashBlock != 0 && mapBlockIndex.count(pcoin->hashBlock))
                {
                    CBlockIndex* pindex = mapBlockIndex[pcoin->hashBlock];
                    if (pindex->nFile > 0)
                    {
                        setCoinsRet.insert(std::make_pair(pcoin, outpoint.n));
                    }
                    else
                    {
                        vBlocksNeeded.push_back(pcoin->hashBlock);
                    }
                }
            }
        }
        else
        {
            LOCK(cs_spvutxos);
            auto spvIt = mapSPVUtxos.find(outpoint);
            if (spvIt != mapSPVUtxos.end())
            {
                if (spvIt->second.fHaveBlock && spvIt->second.fVerified)
                {
                    if (mapBlockIndex.count(spvIt->second.hashBlock))
                    {
                        CBlockIndex* pindex = mapBlockIndex[spvIt->second.hashBlock];
                        if (pindex->nFile > 0)
                        {
                            CBlock block;
                            if (block.ReadFromDisk(pindex, true))
                            {
                                for (const CTransaction& tx : block.vtx)
                                {
                                    if (tx.GetHash() == outpoint.hash)
                                    {
                                        CWalletTx wtx(const_cast<CWallet*>(this), tx);
                                        wtx.hashBlock = spvIt->second.hashBlock;
                                        wtx.nTime = spvIt->second.nTime;
                                        const_cast<CWallet*>(this)->AddToWallet(wtx);

                                        auto newIt = mapWallet.find(outpoint.hash);
                                        if (newIt != mapWallet.end())
                                        {
                                            const CWalletTx* pcoin = &(newIt->second);
                                            if (outpoint.n < pcoin->vout.size())
                                                setCoinsRet.insert(std::make_pair(pcoin, outpoint.n));
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                else if (!spvIt->second.fHaveBlock)
                {
                    vBlocksNeeded.push_back(spvIt->second.hashBlock);
                }
            }
        }
    }

    for (const uint256& hashBlock : vBlocksNeeded)
    {
        const_cast<CWallet*>(this)->RequestBlockForStaking(hashBlock, false);
    }

    return !setCoinsRet.empty();
}

CShieldedPaymentAddress CWallet::GenerateNewShieldedAddress()
{
    LOCK(cs_shielded);

    CShieldedSpendingKey sk;
    if (!GenerateShieldedSpendingKey(sk))
        throw std::runtime_error("GenerateNewShieldedAddress() : failed to generate spending key");

    CShieldedFullViewingKey fvk;
    if (!DeriveShieldedFullViewingKey(sk, fvk))
        throw std::runtime_error("GenerateNewShieldedAddress() : failed to derive full viewing key");

    CShieldedIncomingViewingKey ivk;
    if (!DeriveShieldedIncomingViewingKey(fvk, ivk))
        throw std::runtime_error("GenerateNewShieldedAddress() : failed to derive incoming viewing key");

    std::vector<unsigned char> d;
    if (!GenerateShieldedDiversifier(d))
        throw std::runtime_error("GenerateNewShieldedAddress() : failed to generate diversifier");

    CShieldedPaymentAddress addr;
    if (!DeriveShieldedPaymentAddress(ivk, d, addr))
        throw std::runtime_error("GenerateNewShieldedAddress() : failed to derive payment address");

    mapShieldedSpendingKeys[addr] = sk;
    mapShieldedViewingKeys[addr] = ivk;

    {
        CWalletDB walletdb(strWalletFile);
        walletdb.WriteShieldedKey(addr, sk);
        walletdb.WriteShieldedViewingKey(addr, ivk);
    }

    if (fDebug)
        printf("GenerateNewShieldedAddress() : generated new shielded address\n");

    return addr;
}

bool CWallet::AddShieldedSpendingKey(const CShieldedPaymentAddress& addr, const CShieldedSpendingKey& key)
{
    LOCK(cs_shielded);
    mapShieldedSpendingKeys[addr] = key;

    CShieldedFullViewingKey fvk;
    DeriveShieldedFullViewingKey(key, fvk);
    CShieldedIncomingViewingKey ivk;
    DeriveShieldedIncomingViewingKey(fvk, ivk);
    mapShieldedViewingKeys[addr] = ivk;

    {
        CWalletDB walletdb(strWalletFile);
        walletdb.WriteShieldedKey(addr, key);
        walletdb.WriteShieldedViewingKey(addr, ivk);
    }

    return true;
}

bool CWallet::AddShieldedViewingKey(const CShieldedPaymentAddress& addr, const CShieldedIncomingViewingKey& ivk)
{
    LOCK(cs_shielded);
    mapShieldedViewingKeys[addr] = ivk;
    return true;
}

bool CWallet::HaveShieldedSpendingKey(const CShieldedPaymentAddress& addr) const
{
    LOCK(cs_shielded);
    return mapShieldedSpendingKeys.count(addr) > 0;
}

bool CWallet::HaveShieldedViewingKey(const CShieldedPaymentAddress& addr) const
{
    LOCK(cs_shielded);
    return mapShieldedViewingKeys.count(addr) > 0;
}

bool CWallet::IsShieldedOutputMine(const CShieldedOutputDescription& output, CShieldedNote& noteOut) const
{
    LOCK(cs_shielded);

    // DSP public receiver mode: check plaintext recipient
    if (!output.vchRecipientScript.empty())
    {
        try {
            CDataStream ss(output.vchRecipientScript, SER_NETWORK, PROTOCOL_VERSION);
            CShieldedNote plainNote;
            ss >> plainNote;

            if (mapShieldedViewingKeys.count(plainNote.addr) > 0)
            {
                uint256 expectedCmu = plainNote.GetCommitment();
                if (expectedCmu == output.cmu)
                {
                    noteOut = plainNote;
                    return true;
                }
            }
        } catch (...) {
        }
        return false;
    }

    for (const auto& pair : mapShieldedViewingKeys)
    {
        if (DecryptShieldedNote(output.vchEncCiphertext, output.vchEphemeralKey,
                                pair.first.vchPkD, pair.first.vchDiversifier,
                                pair.second, noteOut))
        {
            uint256 expectedCmu = noteOut.GetCommitment();
            if (expectedCmu == output.cmu)
                return true;
        }
    }
    return false;
}

int64_t CWallet::GetShieldedBalance() const
{
    LOCK(cs_shielded);
    int64_t nBalance = 0;
    for (const CShieldedWalletNote& wnote : vShieldedNotes)
    {
        if (!wnote.fSpent)
        {
            if (wnote.note.nValue > 0 && nBalance > std::numeric_limits<int64_t>::max() - wnote.note.nValue)
                return std::numeric_limits<int64_t>::max();
            nBalance += wnote.note.nValue;
        }
    }
    return nBalance;
}

void CWallet::ScanBlockForShieldedNotes(const CBlock& block, int nHeight)
{
    // Deferred key imports (after cs_shielded release to preserve lock ordering)
    struct SPendingKeyImport {
        CKey key;
        CPubKey pubkey;
        uint32_t idx;
    };
    std::vector<SPendingKeyImport> vKeysToImport;

    // Lock ordering: cs_wallet before cs_shielded
    { // Scope for locks
    LOCK2(cs_wallet, cs_shielded);

    uint64_t nTreePosition = 0;
    uint64_t nCurveLeafCount = 0;
    {
        CTxDB txdb("r");
        txdb.ReadShieldedCommitmentCount(nTreePosition);

        if (nHeight >= FORK_HEIGHT_FCMP)
        {
            CCurveTree tmpTree;
            if (txdb.ReadCurveTree(tmpTree))
                nCurveLeafCount = tmpTree.nLeafCount;
        }
    }
    uint64_t nBlockOutputs = 0;
    for (const CTransaction& tx : block.vtx)
    {
        if (tx.IsShielded())
            nBlockOutputs += tx.vShieldedOutput.size();
    }
    if (nTreePosition >= nBlockOutputs)
        nTreePosition -= nBlockOutputs;
    else
        nTreePosition = 0;

    uint64_t nCurveLeafPosition = 0;
    if (nHeight >= FORK_HEIGHT_FCMP)
    {
        if (nCurveLeafCount >= nBlockOutputs)
            nCurveLeafPosition = nCurveLeafCount - nBlockOutputs;
    }

    for (const CTransaction& tx : block.vtx)
    {
        if (!tx.IsShielded())
            continue;

        for (unsigned int i = 0; i < tx.vShieldedOutput.size(); i++)
        {
            CShieldedNote noteOut;
            if (IsShieldedOutputMine(tx.vShieldedOutput[i], noteOut))
            {
                uint256 txhash = tx.GetHash();
                uint64_t pos = nTreePosition + i;
                bool fDuplicate = false;
                for (const CShieldedWalletNote& existing : vShieldedNotes)
                {
                    if (existing.txhash == txhash && existing.nPosition == pos)
                    {
                        fDuplicate = true;
                        break;
                    }
                }
                if (!fDuplicate)
                {
                    CShieldedWalletNote wnote;
                    wnote.note = noteOut;
                    wnote.txhash = txhash;
                    wnote.nPosition = pos;
                    wnote.fSpent = false;
                    wnote.nHeight = nHeight;
                    wnote.nLeafIndex = (nHeight >= FORK_HEIGHT_FCMP) ? (nCurveLeafPosition + i) : 0;
                    vShieldedNotes.push_back(wnote);

                    {
                        CWalletDB walletdb(strWalletFile);
                        walletdb.WriteShieldedNote(txhash, pos, noteOut, false, nHeight);
                    }

                    if (fDebug)
                        printf("ScanBlockForShieldedNotes() : found note value=%" PRId64 " at height=%d pos=%u leafIndex=%lu\n",
                               noteOut.nValue, nHeight, (unsigned int)pos, wnote.nLeafIndex);
                }
            }
        }

        nTreePosition += tx.vShieldedOutput.size();
        if (nHeight >= FORK_HEIGHT_FCMP)
            nCurveLeafPosition += tx.vShieldedOutput.size();

        for (const CShieldedSpendDescription& spend : tx.vShieldedSpend)
        {
            for (CShieldedWalletNote& wnote : vShieldedNotes)
            {
                if (wnote.fSpent)
                    continue;
                for (const auto& keypair : mapShieldedSpendingKeys)
                {
                    CShieldedFullViewingKey fvk;
                    DeriveShieldedFullViewingKey(keypair.second, fvk);
                    uint256 nf = wnote.note.GetNullifier(fvk.nk);
                    if (nf == spend.nullifier)
                    {
                        wnote.fSpent = true;

                        {
                            CWalletDB walletdb(strWalletFile);
                            walletdb.WriteShieldedNoteSpent(wnote.txhash, wnote.nPosition, true);
                        }

                        break;
                    }
                }
            }
        }

        if (!vSilentPaymentKeys.empty() && tx.vin.size() > 0)
        {
            std::vector<std::vector<unsigned char>> vInputPubKeys;
            for (const CTxIn& txin : tx.vin)
            {
                CTransaction prevTx;
                uint256 hashBlock = 0;
                if (::GetTransaction(txin.prevout.hash, prevTx, hashBlock))
                {
                    if (txin.prevout.n < prevTx.vout.size())
                    {
                        const CScript& scriptPubKey = prevTx.vout[txin.prevout.n].scriptPubKey;
                        if (txin.scriptSig.size() > 0)
                        {
                            CScript::const_iterator pc = txin.scriptSig.begin();
                            opcodetype opcode;
                            std::vector<unsigned char> vchData;
                            txin.scriptSig.GetOp(pc, opcode, vchData);
                            if (txin.scriptSig.GetOp(pc, opcode, vchData))
                            {
                                if (vchData.size() == 33)
                                {
                                    vInputPubKeys.push_back(vchData);
                                }
                                else if (vchData.size() == 65 && vchData[0] == 0x04)
                                {
                                    std::vector<unsigned char> vchCompressed(33);
                                    vchCompressed[0] = (vchData[64] & 1) ? 0x03 : 0x02;
                                    memcpy(&vchCompressed[1], &vchData[1], 32);
                                    vInputPubKeys.push_back(vchCompressed);
                                }
                            }
                        }
                    }
                }
            }

            if (!vInputPubKeys.empty())
            {
                std::vector<unsigned char> vchSenderPubKeySum;
                if (ComputeInputPubKeySum(vInputPubKeys, vchSenderPubKeySum))
                {
                    std::vector<std::vector<unsigned char>> vTxOutputPubKeys;
                    for (const CTxOut& txout : tx.vout)
                    {
                        CTxDestination dest;
                        if (ExtractDestination(txout.scriptPubKey, dest))
                        {
                            opcodetype opcode;
                            std::vector<unsigned char> vchPubKey;
                            CScript::const_iterator pc = txout.scriptPubKey.begin();
                            if (txout.scriptPubKey.GetOp(pc, opcode, vchPubKey) && vchPubKey.size() == 33)
                            {
                                vTxOutputPubKeys.push_back(vchPubKey);
                            }
                            else
                            {
                                vTxOutputPubKeys.push_back(std::vector<unsigned char>());
                            }
                        }
                        else
                        {
                            vTxOutputPubKeys.push_back(std::vector<unsigned char>());
                        }
                    }

                    for (const CSilentPaymentKey& spKey : vSilentPaymentKeys)
                    {
                        std::vector<uint32_t> vMatched;
                        if (ScanForSilentPayments(spKey, vchSenderPubKeySum, vTxOutputPubKeys, vMatched))
                        {
                            for (uint32_t idx : vMatched)
                            {
                                if (fDebug)
                                    printf("ScanBlockForShieldedNotes() : found silent payment output idx=%u in tx %s at height=%d\n",
                                           idx, tx.GetHash().ToString().c_str(), nHeight);

                                std::vector<unsigned char> vchSpendPrivKey;
                                if (DeriveSilentPaymentSpendKey(spKey, vchSenderPubKeySum, idx, vchSpendPrivKey))
                                {
                                    CKey spendKey;
                                    spendKey.Set(vchSpendPrivKey.begin(), vchSpendPrivKey.end(), true);
                                    OPENSSL_cleanse(vchSpendPrivKey.data(), vchSpendPrivKey.size());

                                    if (spendKey.IsValid())
                                    {
                                        SPendingKeyImport imp;
                                        imp.key = spendKey;
                                        imp.pubkey = spendKey.GetPubKey();
                                        imp.idx = idx;
                                        vKeysToImport.push_back(imp);
                                    }
                                }
                                else
                                {
                                    printf("WARNING: ScanBlockForShieldedNotes() : failed to derive silent payment spend key for idx=%u\n", idx);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    } // End cs_shielded scope

    // Import SP keys after releasing cs_shielded (lock ordering)
    for (const SPendingKeyImport& imp : vKeysToImport)
    {
        if (!HaveKey(imp.pubkey.GetID()))
        {
            AddKeyPubKey(imp.key, imp.pubkey);
            if (fDebug)
                printf("ScanBlockForShieldedNotes() : imported silent payment spend key for output idx=%u\n", imp.idx);
        }
    }
}

bool CWallet::AddSilentPaymentKey(CSilentPaymentKey&& key)
{
    LOCK(cs_shielded);
    vSilentPaymentKeys.push_back(std::move(key));
    return true;
}

bool CWallet::GenerateNewSilentPaymentKey(CSilentPaymentAddress& addrOut)
{
    CSilentPaymentKey key;
    if (!CSilentPaymentKey::Generate(key))
        return false;
    if (!key.GetAddress(addrOut))
        return false;
    AddSilentPaymentKey(std::move(key));
    return true;
}
