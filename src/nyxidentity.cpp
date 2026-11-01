// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxidentity.h"
#include "nyxsession.h"
#include "privacy_vnext/rust/include/nyx_pq.h"

#include "base58.h"
#include "init.h"
#include "smessage.h"
#include "util.h"
#include "wallet.h"

#include <boost/lexical_cast.hpp>

#include <algorithm>
#include <fstream>

#include <openssl/crypto.h>
#include <string.h>
#include <unistd.h>

using namespace json_spirit;

static const int64_t NYX_KR_REFRESH = 60 * 60 * 20;
static const int64_t NYX_KR_RENEW_SLOT = 60 * 60;    // x device rank (< 16), below NYX_KR_REFRESH
static const char NYX_DB_SK[] = "nyxsk";
static const char NYX_DB_DEV[] = "nyd";
static const char NYX_DB_PIN[] = "nyp";

static CCriticalSection cs_nyxid;
static bool fSkLoaded = false;
static uint8_t skCache[32];
static std::map<std::string, NyxOwnDevice> mapDev;  // addrHash20 -> this node's device
static std::map<std::string, NyxPin> mapPin;        // addrHash20 -> contact pin

static uint256 StorageKeyIV()
{
    static const char tag[] = "NYX-STORAGE-KEY-v1";
    uint8_t h[32];
    NyxHash(NyxBytes((const uint8_t*)tag, (const uint8_t*)tag + sizeof(tag) - 1), h);
    uint256 iv;
    memcpy(iv.begin(), h, 32);
    return iv;
}

bool NyxStorageKeyResolve(CCryptoKeyStore* ks, const std::string& rec, uint8_t sk[32], std::string& newRec,
                          std::string& sError)
{
    newRec.clear();
    const bool fCrypted = ks && ks->IsCrypted();
    if (fCrypted && ks->IsLocked())
    {
        sError = "Wallet is locked; unlock it to use the messenger keys.";
        return false;
    }
    if (rec.empty())
    {
        if (nyx_random(sk, 32) != 0)
        {
            sError = "No randomness for the storage key.";
            return false;
        }
    }
    else if (rec[0] == 0 && rec.size() == 33)
        memcpy(sk, rec.data() + 1, 32);
    else if (rec[0] == 1 && fCrypted)
    {
        CSecret plain;
        if (!ks->UnwrapSecret(std::vector<unsigned char>(rec.begin() + 1, rec.end()), StorageKeyIV(), plain)
            || plain.size() != 32)
        {
            sError = "Storage key does not unwrap under the wallet master key.";
            return false;
        }
        memcpy(sk, &plain[0], 32);
        return true;
    }
    else
    {
        sError = "Storage key record is unreadable.";
        return false;
    }
    if (fCrypted)
    {
        CSecret plain(sk, sk + 32);
        std::vector<unsigned char> ct;
        if (!ks->WrapSecret(plain, StorageKeyIV(), ct))
        {
            sError = "Could not wrap the storage key.";
            return false;
        }
        newRec = std::string(1, (char)1) + std::string(ct.begin(), ct.end());
    }
    else if (rec.empty())
        newRec = std::string(1, (char)0) + std::string((const char*)sk, 32);
    return true;
}

static bool DbRead(const std::string& key, std::string& v)
{
    LOCK(cs_smsgDB);
    SecMsgDB db;
    if (!db.Open("cw"))
        return false;
    return db.pdb->Get(leveldb::ReadOptions(), key, &v).ok();
}

static bool DbWrite(const std::string& key, const std::string& v)
{
    LOCK(cs_smsgDB);
    SecMsgDB db;
    if (!db.Open("cw"))
        return false;
    return db.pdb->Put(leveldb::WriteOptions(), key, v).ok();
}

static void HostFp(uint8_t out[32])
{
    std::string s = GetDataDir().string();
    char host[256] = {0};
    if (gethostname(host, sizeof(host) - 1) == 0)
        s += std::string("|") + host;
    std::ifstream f("/etc/machine-id");
    std::string mid;
    if (f && std::getline(f, mid))
        s += "|" + mid;
    NyxHash(NyxBytes(s.begin(), s.end()), out);
}

static bool Ready(std::string& sError);
static void SessHousekeeping(std::vector<NyxBytes>& vPub);

static void Forget()
{
    OPENSSL_cleanse(skCache, sizeof(skCache));
    fSkLoaded = false;
    mapDev.clear();
    mapPin.clear();
}

void NyxIdOnWalletEncrypted(CCryptoKeyStore* ks)
{
    LOCK(cs_nyxid);
    std::string rec, newRec, sError;
    {
        LOCK(cs_smsgDB);
        SecMsgDB db;
        if (!db.Open("r") || !db.pdb->Get(leveldb::ReadOptions(), NYX_DB_SK, &rec).ok())
            return;
    }
    if (rec.size() != 33 || rec[0] != 0)
        return;
    uint8_t sk[32];
    if (NyxStorageKeyResolve(ks, rec, sk, newRec, sError) && !newRec.empty())
        DbWrite(NYX_DB_SK, newRec);
    OPENSSL_cleanse(sk, sizeof(sk));
    OPENSSL_cleanse(&rec[0], rec.size());
}

void NyxIdTryLoad()
{
    LOCK(cs_nyxid);
    std::string sError;
    if (fSecMsgEnabled && fNyxV2 && pwalletMain && !fSkLoaded)
        Ready(sError);
}

void NyxIdForget()
{
    LOCK(cs_nyxid);
    Forget();
}

static bool SaveDev(const std::string& addr)
{
    std::string sealed;
    const std::string key = NYX_DB_DEV + addr;
    std::string plain = mapDev[addr].Serialize();
    const bool fOk = NyxStoreSeal(skCache, key, plain, sealed);
    OPENSSL_cleanse(&plain[0], plain.size());
    return fOk && DbWrite(key, sealed);
}

static bool SavePin(const std::string& addr)
{
    std::string sealed;
    const std::string key = NYX_DB_PIN + addr;
    return NyxStoreSeal(skCache, key, mapPin[addr].Serialize(), sealed) && DbWrite(key, sealed);
}

static void LoadPrefix(const char* prefix, std::vector<std::pair<std::string, std::string> >& out)
{
    LOCK(cs_smsgDB);
    SecMsgDB db;
    if (!db.Open("cw"))
        return;
    leveldb::Iterator* it = db.pdb->NewIterator(leveldb::ReadOptions());
    const size_t n = strlen(prefix);
    for (it->Seek(prefix); it->Valid() && it->key().starts_with(prefix); it->Next())
        if (it->key().size() == n + 20)
            out.push_back(std::make_pair(it->key().ToString(), it->value().ToString()));
    delete it;
}

// cs_nyxid held.
static bool Ready(std::string& sError)
{
    if (!fSecMsgEnabled || !fNyxV2)
    {
        sError = "Nyx v2 is not enabled (-nyxv2=1).";
        return false;
    }
    if (!pwalletMain)
    {
        sError = "No wallet.";
        return false;
    }
    if (fSkLoaded)
    {
        if (pwalletMain->IsCrypted() && pwalletMain->IsLocked())
        {
            Forget();
            sError = "Wallet is locked; unlock it to use the messenger keys.";
            return false;
        }
        return true;
    }
    std::string rec, newRec;
    DbRead(NYX_DB_SK, rec);
    if (!NyxStorageKeyResolve(pwalletMain, rec, skCache, newRec, sError))
        return false;
    if (!newRec.empty() && !DbWrite(NYX_DB_SK, newRec))
    {
        sError = "Could not store the storage key.";
        return false;
    }
    fSkLoaded = true;

    uint8_t fp[32];
    HostFp(fp);
    std::vector<std::pair<std::string, std::string> > v;
    LoadPrefix(NYX_DB_DEV, v);
    for (size_t i = 0; i < v.size(); ++i)
    {
        std::string plain;
        NyxOwnDevice d;
        const bool fOk = NyxStoreOpen(skCache, v[i].first, v[i].second, plain) && d.Deserialize(plain);
        if (!plain.empty())
            OPENSSL_cleanse(&plain[0], plain.size());
        if (!fOk)
            continue;
        const std::string addr = v[i].first.substr(strlen(NYX_DB_DEV));
        const std::string why = NyxCloneCheck(d, fp, NULL);
        mapDev[addr] = d;
        if (!why.empty() && !d.fCloneAlarm && !d.certBody.empty())
        {
            mapDev[addr].fCloneAlarm = true;
            mapDev[addr].cloneReason = why;
            SaveDev(addr);
        }
    }
    v.clear();
    LoadPrefix(NYX_DB_PIN, v);
    for (size_t i = 0; i < v.size(); ++i)
    {
        std::string plain;
        NyxPin p;
        if (NyxStoreOpen(skCache, v[i].first, v[i].second, plain) && p.Deserialize(plain))
            mapPin[v[i].first.substr(strlen(NYX_DB_PIN))] = p;
    }
    return true;
}

static bool ParseAddr(const std::string& s, std::string& addr20, CKey* pKey, std::string& sError)
{
    CBitcoinAddress a(s);
    CKeyID id;
    if (!a.IsValid() || !a.GetKeyID(id))
    {
        sError = "Invalid address.";
        return false;
    }
    addr20.assign((const char*)id.begin(), 20);
    if (pKey && !pwalletMain->GetKey(id, *pKey))
    {
        sError = "The wallet does not hold the key for this address.";
        return false;
    }
    return true;
}

struct OwnTip
{
    bool fHave;
    bool fConflict;
    NyxKeyring kr;
    NyxBytes body;
    uint8_t hash[32];
    OwnTip() : fHave(false), fConflict(false) {}
};

static void Tip(const std::string& addr, OwnTip& t)
{
    NyxPinInput in;
    SecureMsgPoCollect((const uint8_t*)addr.data(), in);
    for (size_t i = 0; i < in.keyrings.size(); ++i)
    {
        NyxKeyring k;
        const NyxBytes& b = in.keyrings[i];
        if (NyxParseKeyring(&b[0], b.size(), k) != 0)
            continue;
        if (!t.fHave || k.epoch > t.kr.epoch || (k.epoch == t.kr.epoch && k.seq > t.kr.seq))
        {
            t.fHave = true;
            t.fConflict = false;
            t.kr = k;
            t.body = b;
            NyxHash(b, t.hash);
        }
        else if (k.epoch == t.kr.epoch && k.seq == t.kr.seq && b != t.body)
            t.fConflict = true;
    }
}

static bool OwnKeyring(const NyxOwnDevice& d, NyxKeyring& kr, uint8_t hash[32])
{
    if (d.keyringBody.empty() || NyxParseKeyring(&d.keyringBody[0], d.keyringBody.size(), kr) != 0)
        return false;
    NyxHash(d.keyringBody, hash);
    return true;
}

// Follows the network tip when it lists this device with its current cert. cs_nyxid held.
static bool RefreshOwn(const std::string& addr, NyxOwnDevice& d)
{
    if (d.certBody.empty())
        return false;
    OwnTip t;
    Tip(addr, t);
    if (!t.fHave || t.fConflict)
        return false;
    const NyxKeyringEntry* e = t.kr.Find(d.deviceId);
    uint8_t ch[32];
    NyxHash(d.certBody, ch);
    if (!e || memcmp(e->certHash, ch, 32) != 0)
        return false;
    NyxKeyring own;
    uint8_t ownHash[32];
    if (OwnKeyring(d, own, ownHash)
        && (own.epoch > t.kr.epoch || (own.epoch == t.kr.epoch && own.seq >= t.kr.seq)))
        return false;
    d.keyringBody = t.body;
    SaveDev(addr);
    return true;
}

static void Publish(const std::vector<NyxBytes>& v)
{
    for (size_t i = 0; i < v.size(); ++i)
    {
        std::string sError;
        if (SecureMsgV2PublishPublic(v[i], sError) != 0)
            printf("Nyx identity: publish failed: %s\n", sError.c_str());
    }
}

static std::string Hex(const uint8_t* p, size_t n)
{
    return HexStr(p, p + n);
}

static Array DevicesJson(const NyxKeyring& kr, const NyxDeviceMap* pCerts, int64_t now)
{
    Array a;
    for (size_t i = 0; i < kr.live.size(); ++i)
    {
        Object o;
        o.push_back(Pair("device", Hex(kr.live[i].deviceId, 16)));
        o.push_back(Pair("cert_hash", Hex(kr.live[i].certHash, 32)));
        if (pCerts)
        {
            NyxDeviceMap::const_iterator it = pCerts->find(NyxId(kr.live[i].deviceId));
            if (it != pCerts->end())
            {
                o.push_back(Pair("expiry", (int64_t)it->second.cert.expiry));
                o.push_back(Pair("usable", it->second.cert.expiry > (uint64_t)now));
            }
        }
        a.push_back(o);
    }
    return a;
}

static NyxDeviceMap CertsFor(const std::string& addr, const NyxKeyring& kr)
{
    NyxPinInput in;
    SecureMsgPoCollect((const uint8_t*)addr.data(), in);
    NyxDeviceMap m;
    for (size_t i = 0; i < in.certs.size(); ++i)
    {
        NyxPinDevice d;
        d.body = in.certs[i];
        if (NyxParseCert(&d.body[0], d.body.size(), d.cert) != 0)
            continue;
        NyxHash(d.body, d.certHash);
        const NyxKeyringEntry* e = kr.Find(d.cert.deviceId);
        if (e && memcmp(e->certHash, d.certHash, 32) == 0)
            m[NyxId(d.cert.deviceId)] = d;
    }
    return m;
}

static void AddKeyringJson(Object& o, const NyxKeyring& kr, const uint8_t hash[32])
{
    o.push_back(Pair("epoch", (int64_t)kr.epoch));
    o.push_back(Pair("seq", (int64_t)kr.seq));
    o.push_back(Pair("mode", kr.mode == NYX_MODE_PQ ? "pq" : "classical"));
    o.push_back(Pair("keyring_hash", Hex(hash, 32)));
    o.push_back(Pair("ts", (int64_t)kr.ts));
}

// cs_nyxid held; returns the bodies to publish.
static bool StartIdentity(const std::string& addr, const CKey& key, uint8_t mode, uint32_t epoch,
                          const uint8_t prevHash[32], std::vector<NyxBytes>& vPub, std::string& sError)
{
    uint8_t fp[32];
    HostFp(fp);
    NyxOwnDevice d;
    if (!NyxDeviceCreate(d, (const uint8_t*)addr.data(), mode, fp))
    {
        sError = "Could not create device keys.";
        return false;
    }
    const int64_t now = GetTime();
    NyxCert c;
    if (!NyxBuildCert(d, key, now, 1, NULL, c))
    {
        sError = "Could not sign the device cert.";
        return false;
    }
    d.certBody = c.Serialize();
    NyxKeyring kr;
    memcpy(kr.addrHash, addr.data(), 20);
    kr.epoch = epoch;
    kr.seq = 1;
    memcpy(kr.prevHash, prevHash, 32);
    kr.ts = now;
    kr.mode = mode;
    NyxKeyringEntry e;
    memcpy(e.deviceId, d.deviceId, 16);
    NyxHash(d.certBody, e.certHash);
    kr.live.push_back(e);
    NyxDeviceTopUpOpks(d, GetTime());
    NyxDeviceRotateSpk(d, GetTime());
    NyxBundle b;
    if (!NyxBuildKeyring(kr, key, NULL) || !NyxBuildBundle(d, key, now, b))
    {
        sError = "Could not sign the keyring or bundle.";
        return false;
    }
    d.keyringBody = kr.Serialize();
    mapDev[addr] = d;
    if (!SaveDev(addr))
    {
        sError = "Could not store the device.";
        return false;
    }
    vPub.push_back(d.keyringBody);
    vPub.push_back(d.certBody);
    vPub.push_back(d.lastBundle);
    return true;
}

bool NyxIdKeyringInit(const std::string& sAddr, uint8_t mode, Object& out, std::string& sError)
{
    std::vector<NyxBytes> vPub;
    {
        LOCK(cs_nyxid);
        std::string addr;
        CKey key;
        if (!Ready(sError) || !ParseAddr(sAddr, addr, &key, sError))
            return false;
        if (mapDev.count(addr))
        {
            sError = "This node already has a device for the address; use keyring show, reset or device commands.";
            return false;
        }
        OwnTip t;
        Tip(addr, t);
        if (t.fHave)
        {
            sError = "The address already has a keyring (epoch " + boost::lexical_cast<std::string>(t.kr.epoch)
                   + ", seq " + boost::lexical_cast<std::string>(t.kr.seq)
                   + "); pair this node from an existing device, or use keyring reset.";
            return false;
        }
        uint8_t zero[32] = {0};
        if (!StartIdentity(addr, key, mode, 1, zero, vPub, sError))
            return false;
        const NyxOwnDevice& d = mapDev[addr];
        NyxKeyring kr;
        uint8_t h[32];
        OwnKeyring(d, kr, h);
        AddKeyringJson(out, kr, h);
        out.push_back(Pair("device", Hex(d.deviceId, 16)));
    }
    Publish(vPub);
    return true;
}

bool NyxIdKeyringReset(const std::string& sAddr, uint8_t mode, Object& out, std::string& sError)
{
    std::vector<NyxBytes> vPub;
    {
        LOCK(cs_nyxid);
        std::string addr;
        CKey key;
        if (!Ready(sError) || !ParseAddr(sAddr, addr, &key, sError))
            return false;
        OwnTip t;
        Tip(addr, t);
        NyxKeyring own;
        uint8_t ownHash[32];
        uint32_t epoch = 1;
        uint8_t prev[32] = {0};
        if (t.fHave)
        {
            epoch = t.kr.epoch + 1;
            memcpy(prev, t.hash, 32);
        }
        if (mapDev.count(addr) && OwnKeyring(mapDev[addr], own, ownHash) && own.epoch + 1 > epoch)
        {
            epoch = own.epoch + 1;
            memcpy(prev, ownHash, 32);
        }
        if (epoch == 0)
        {
            sError = "Reset epoch is exhausted.";
            return false;
        }
        mapDev.erase(addr);
        if (!StartIdentity(addr, key, mode, epoch, prev, vPub, sError))
            return false;
        const NyxOwnDevice& d = mapDev[addr];
        NyxKeyring kr;
        uint8_t h[32];
        OwnKeyring(d, kr, h);
        AddKeyringJson(out, kr, h);
        out.push_back(Pair("device", Hex(d.deviceId, 16)));
        out.push_back(Pair("note", "Identity reset published. Contacts see a reset warning and must accept it; "
                                   "every other device of this address is replaced."));
    }
    Publish(vPub);
    return true;
}

bool NyxIdKeyringShow(const std::string& sAddr, Object& out, std::string& sError)
{
    LOCK(cs_nyxid);
    std::string addr;
    if (!Ready(sError) || !ParseAddr(sAddr, addr, NULL, sError))
        return false;
    std::map<std::string, NyxOwnDevice>::iterator it = mapDev.find(addr);
    if (it == mapDev.end())
    {
        sError = "No device for this address on this node; run keyring init or device pair.";
        return false;
    }
    RefreshOwn(addr, it->second);
    const NyxOwnDevice& d = it->second;
    out.push_back(Pair("device", Hex(d.deviceId, 16)));
    out.push_back(Pair("device_mode", d.mode == NYX_MODE_PQ ? "pq" : "classical"));
    out.push_back(Pair("paired", !d.certBody.empty()));
    out.push_back(Pair("bundle_seq", (int64_t)d.bundleSeq));
    out.push_back(Pair("clone_alarm", d.fCloneAlarm));
    if (d.fCloneAlarm)
        out.push_back(Pair("alarm_reason", d.cloneReason));
    NyxKeyring kr;
    uint8_t h[32];
    if (OwnKeyring(d, kr, h))
    {
        Object k;
        AddKeyringJson(k, kr, h);
        const NyxDeviceMap certs = CertsFor(addr, kr);
        k.push_back(Pair("devices", DevicesJson(kr, &certs, GetTime())));
        k.push_back(Pair("safety_number", NyxSafetyNumber((const uint8_t*)addr.data(), kr.epoch, certs)));
        out.push_back(Pair("keyring", k));
    }
    OwnTip t;
    Tip(addr, t);
    if (t.fHave)
    {
        Object n;
        AddKeyringJson(n, t.kr, t.hash);
        n.push_back(Pair("conflict", t.fConflict));
        out.push_back(Pair("network_tip", n));
    }
    return true;
}

bool NyxIdDevices(const std::string& sAddr, Array& out, std::string& sError)
{
    LOCK(cs_nyxid);
    std::string addr;
    if (!Ready(sError) || !ParseAddr(sAddr, addr, NULL, sError))
        return false;
    OwnTip t;
    Tip(addr, t);
    if (!t.fHave)
    {
        sError = "No keyring is known for this address.";
        return false;
    }
    const NyxDeviceMap certs = CertsFor(addr, t.kr);
    out = DevicesJson(t.kr, &certs, GetTime());
    std::map<std::string, NyxOwnDevice>::const_iterator it = mapDev.find(addr);
    for (size_t i = 0; i < out.size(); ++i)
    {
        Object& o = out[i].get_obj();
        const bool fThis = it != mapDev.end() && Hex(it->second.deviceId, 16) == o[0].value_.get_str();
        o.push_back(Pair("this_node", fThis));
    }
    return true;
}

bool NyxIdPairRequest(const std::string& sAddr, uint8_t mode, Object& out, std::string& sError)
{
    LOCK(cs_nyxid);
    std::string addr;
    if (!Ready(sError) || !ParseAddr(sAddr, addr, NULL, sError))
        return false;
    std::map<std::string, NyxOwnDevice>::iterator it = mapDev.find(addr);
    if (it != mapDev.end() && !it->second.certBody.empty())
    {
        sError = "This node is already a paired device for the address.";
        return false;
    }
    if (it == mapDev.end())
    {
        uint8_t fp[32];
        HostFp(fp);
        NyxOwnDevice d;
        if (!NyxDeviceCreate(d, (const uint8_t*)addr.data(), mode, fp))
        {
            sError = "Could not create device keys.";
            return false;
        }
        mapDev[addr] = d;
        if (!SaveDev(addr))
        {
            sError = "Could not store the device.";
            return false;
        }
    }
    const NyxOwnDevice& d = mapDev[addr];
    NyxBytes req(1, d.mode);
    req.insert(req.end(), d.deviceId, d.deviceId + 16);
    req.insert(req.end(), d.ik, d.ik + 32);
    req.insert(req.end(), d.dsaPk.begin(), d.dsaPk.end());
    NyxBytes fpIn(d.ik, d.ik + 32);
    fpIn.insert(fpIn.end(), d.dsaPk.begin(), d.dsaPk.end());
    uint8_t h[32];
    NyxHash(fpIn, h);
    out.push_back(Pair("device", Hex(d.deviceId, 16)));
    out.push_back(Pair("pairing_code", Hex(d.deviceId, 16) + Hex(h, 8)));
    out.push_back(Pair("request", HexStr(req.begin(), req.end())));
    return true;
}

bool NyxIdApprove(const std::string& sAddr, const std::string& requestHex, Object& out, std::string& sError)
{
    std::vector<NyxBytes> vPub;
    {
        LOCK(cs_nyxid);
        std::string addr;
        CKey key;
        if (!Ready(sError) || !ParseAddr(sAddr, addr, &key, sError))
            return false;
        std::map<std::string, NyxOwnDevice>::iterator it = mapDev.find(addr);
        if (it == mapDev.end() || it->second.certBody.empty())
        {
            sError = "This node has no paired device for the address.";
            return false;
        }
        NyxOwnDevice& d = it->second;
        RefreshOwn(addr, d);
        if (d.fCloneAlarm)
        {
            sError = "Clone alarm is set on this device; run keyring confirm first.";
            return false;
        }
        const std::vector<unsigned char> req = ParseHex(requestHex);
        if (req.size() < 49 || req[0] > NYX_MODE_PQ
            || req.size() != 49 + (req[0] == NYX_MODE_PQ ? (size_t)NYX_MLDSA65_PK : 0))
        {
            sError = "Malformed pairing request.";
            return false;
        }
        NyxKeyring kr;
        uint8_t h[32];
        OwnTip t;
        Tip(addr, t);
        if (!OwnKeyring(d, kr, h) || t.fConflict || (t.fHave && memcmp(t.hash, h, 32) != 0))
        {
            sError = "This device's keyring is not the network tip, or the tip is in conflict; run keyring confirm.";
            return false;
        }
        if (req[0] != kr.mode)
        {
            sError = "The new device's mode does not match the keyring mode.";
            return false;
        }
        if (kr.IsLive(&req[1]) || kr.live.size() >= NYX_KR_MAX_LIVE)
        {
            sError = "Device already live, or the keyring is full.";
            return false;
        }
        const NyxBytes dsaPk(req.begin() + 49, req.end());
        const int64_t now = GetTime();
        NyxCert c;
        if (!NyxBuildCertFor(req[0], (const uint8_t*)addr.data(), &req[1], &req[17], dsaPk, key, now, kr.seq + 1,
                             &d, c))
        {
            sError = "Could not sign the new device cert.";
            return false;
        }
        const NyxBytes certBody = c.Serialize();
        NyxKeyring next = kr;
        next.seq = kr.seq + 1;
        memcpy(next.prevHash, h, 32);
        next.ts = now;
        next.revoked.clear();
        NyxKeyringEntry e;
        memcpy(e.deviceId, &req[1], 16);
        NyxHash(certBody, e.certHash);
        next.live.push_back(e);
        if (!NyxBuildKeyring(next, key, &d))
        {
            sError = "Could not sign the keyring.";
            return false;
        }
        d.keyringBody = next.Serialize();
        SaveDev(addr);
        vPub.push_back(certBody);
        vPub.push_back(d.keyringBody);
        uint8_t nh[32];
        NyxHash(d.keyringBody, nh);
        AddKeyringJson(out, next, nh);
        out.push_back(Pair("cert", HexStr(certBody.begin(), certBody.end())));
    }
    Publish(vPub);
    return true;
}

bool NyxIdInstall(const std::string& sAddr, const std::string& certHex, Object& out, std::string& sError)
{
    std::vector<NyxBytes> vPub;
    {
        LOCK(cs_nyxid);
        std::string addr;
        CKey key;
        if (!Ready(sError) || !ParseAddr(sAddr, addr, &key, sError))
            return false;
        std::map<std::string, NyxOwnDevice>::iterator it = mapDev.find(addr);
        if (it == mapDev.end() || !it->second.certBody.empty())
        {
            sError = "No pending pairing request for this address on this node.";
            return false;
        }
        NyxOwnDevice& d = it->second;
        const NyxBytes body = ParseHex(certHex);
        NyxCert c;
        if (body.empty() || NyxParseCert(&body[0], body.size(), c) != 0 || !NyxCertAddrValid(c)
            || memcmp(c.deviceId, d.deviceId, 16) != 0 || memcmp(c.ik, d.ik, 32) != 0 || c.dsaPk != d.dsaPk
            || c.mode != d.mode || memcmp(c.addrHash, addr.data(), 20) != 0)
        {
            sError = "The cert does not match this node's pairing request.";
            return false;
        }
        d.certBody = body;
        OwnTip t;
        Tip(addr, t);
        if (t.fHave && t.kr.IsLive(d.deviceId))
            d.keyringBody = t.body;
        NyxDeviceTopUpOpks(d, GetTime());
        NyxDeviceRotateSpk(d, GetTime());
        NyxBundle b;
        if (!NyxBuildBundle(d, key, GetTime(), b))
        {
            sError = "Could not sign the bundle.";
            return false;
        }
        SaveDev(addr);
        vPub.push_back(body);
        if (!d.keyringBody.empty())
            vPub.push_back(d.keyringBody);
        vPub.push_back(d.lastBundle);
        out.push_back(Pair("device", Hex(d.deviceId, 16)));
        out.push_back(Pair("in_keyring", !d.keyringBody.empty()));
    }
    Publish(vPub);
    return true;
}

// Publishes seq+1 from this device; replaces oldId with the device's new cert when rekeying. cs_nyxid held.
static bool NextKeyring(const std::string& addr, const CKey& key, NyxOwnDevice& d, const NyxKeyring& base,
                        const uint8_t baseHash[32], const std::vector<std::string>& vRevoke,
                        const NyxBytes* pReplaceCert, std::vector<NyxBytes>& vPub, std::string& sError)
{
    NyxKeyring next = base;
    next.seq = base.seq + 1;
    memcpy(next.prevHash, baseHash, 32);
    next.ts = GetTime();
    next.revoked.clear();
    std::vector<NyxKeyringEntry> live;
    for (size_t i = 0; i < base.live.size(); ++i)
        if (std::find(vRevoke.begin(), vRevoke.end(), NyxId(base.live[i].deviceId)) == vRevoke.end())
            live.push_back(base.live[i]);
    next.revoked = vRevoke;
    if (pReplaceCert)
    {
        NyxCert c;
        NyxParseCert(&(*pReplaceCert)[0], pReplaceCert->size(), c);
        bool fFound = false;
        for (size_t i = 0; i < live.size(); ++i)
            if (memcmp(live[i].deviceId, c.deviceId, 16) == 0)
            {
                NyxHash(*pReplaceCert, live[i].certHash);
                fFound = true;
            }
        if (!fFound)
        {
            NyxKeyringEntry e;
            memcpy(e.deviceId, c.deviceId, 16);
            NyxHash(*pReplaceCert, e.certHash);
            live.push_back(e);
        }
    }
    if (live.empty())
    {
        sError = "The keyring would have no live device.";
        return false;
    }
    next.live = live;
    if (!NyxBuildKeyring(next, key, &d))
    {
        sError = "Could not sign the keyring.";
        return false;
    }
    if (pReplaceCert)
        vPub.push_back(*pReplaceCert);
    d.keyringBody = next.Serialize();
    vPub.push_back(d.keyringBody);
    return true;
}

bool NyxIdRevoke(const std::string& sAddr, const std::string& deviceIdHex, Object& out, std::string& sError)
{
    std::vector<NyxBytes> vPub;
    {
        LOCK(cs_nyxid);
        std::string addr;
        CKey key;
        if (!Ready(sError) || !ParseAddr(sAddr, addr, &key, sError))
            return false;
        std::map<std::string, NyxOwnDevice>::iterator it = mapDev.find(addr);
        if (it == mapDev.end() || it->second.certBody.empty() || it->second.fCloneAlarm)
        {
            sError = "This node has no usable device for the address.";
            return false;
        }
        NyxOwnDevice& d = it->second;
        RefreshOwn(addr, d);
        const std::vector<unsigned char> id = ParseHex(deviceIdHex);
        NyxKeyring kr;
        uint8_t h[32];
        if (id.size() != 16 || !OwnKeyring(d, kr, h) || !kr.IsLive(&id[0]))
        {
            sError = "Device id is not live in this device's keyring.";
            return false;
        }
        if (memcmp(&id[0], d.deviceId, 16) == 0)
        {
            sError = "Revoke this device from another device.";
            return false;
        }
        if (!NextKeyring(addr, key, d, kr, h, std::vector<std::string>(1, std::string(id.begin(), id.end())), NULL,
                         vPub, sError))
            return false;
        SaveDev(addr);
        NyxKeyring next;
        uint8_t nh[32];
        OwnKeyring(d, next, nh);
        AddKeyringJson(out, next, nh);
    }
    Publish(vPub);
    return true;
}

bool NyxIdKeyringConfirm(const std::string& sAddr, Object& out, std::string& sError)
{
    std::vector<NyxBytes> vPub;
    {
        LOCK(cs_nyxid);
        std::string addr;
        CKey key;
        if (!Ready(sError) || !ParseAddr(sAddr, addr, &key, sError))
            return false;
        std::map<std::string, NyxOwnDevice>::iterator it = mapDev.find(addr);
        if (it == mapDev.end() || it->second.certBody.empty())
        {
            sError = "This node has no paired device for the address.";
            return false;
        }
        NyxOwnDevice& d = it->second;
        RefreshOwn(addr, d);
        NyxKeyring kr;
        uint8_t h[32];
        if (!OwnKeyring(d, kr, h) || !kr.IsLive(d.deviceId))
        {
            sError = "This device is not live in its keyring.";
            return false;
        }
        OwnTip t;
        Tip(addr, t);
        if (t.fHave && (t.kr.epoch > kr.epoch || t.kr.seq > kr.seq + 1))
        {
            sError = "The network keyring moved past this device; it cannot confirm.";
            return false;
        }
        const bool fClone = d.fCloneAlarm && d.cloneReason.find("conflict") == std::string::npos;
        if (fClone)
        {
            // Leave the shared id: fresh keys, cert co-signed by the old id, which this keyring revokes.
            NyxOwnDevice fresh;
            if (!NyxDeviceCreate(fresh, (const uint8_t*)addr.data(), d.mode, d.hostFp))
            {
                sError = "Could not create device keys.";
                return false;
            }
            HostFp(fresh.hostFp);
            NyxCert c;
            if (!NyxBuildCert(fresh, key, GetTime(), kr.seq + 1, d.mode == NYX_MODE_PQ ? &d : NULL, c))
            {
                sError = "Could not sign the new cert.";
                return false;
            }
            fresh.certBody = c.Serialize();
            const std::vector<std::string> vRev(1, NyxId(d.deviceId));
            if (!NextKeyring(addr, key, d, kr, h, vRev, &fresh.certBody, vPub, sError))
                return false;
            fresh.keyringBody = d.keyringBody;
            NyxDeviceTopUpOpks(fresh, GetTime());
            NyxDeviceRotateSpk(fresh, GetTime());
            NyxBundle b;
            if (!NyxBuildBundle(fresh, key, GetTime(), b))
            {
                sError = "Could not sign the bundle.";
                return false;
            }
            vPub.push_back(fresh.lastBundle);
            mapDev[addr] = fresh;
        }
        else
        {
            if (!NextKeyring(addr, key, d, kr, h, std::vector<std::string>(), NULL, vPub, sError))
                return false;
            d.fCloneAlarm = false;
            d.cloneReason.clear();
        }
        SaveDev(addr);
        NyxKeyring next;
        uint8_t nh[32];
        OwnKeyring(mapDev[addr], next, nh);
        AddKeyringJson(out, next, nh);
        out.push_back(Pair("device", Hex(mapDev[addr].deviceId, 16)));
        out.push_back(Pair("rekeyed", fClone));
    }
    Publish(vPub);
    return true;
}

static void PinJson(const std::string& addr, const NyxPin& p, int flags, Object& out)
{
    const int64_t now = GetTime();
    out.push_back(Pair("pinned", p.fPinned));
    out.push_back(Pair("pq_seen", p.fPqSeen));
    out.push_back(Pair("frozen", p.fFrozen));
    out.push_back(Pair("reset_pending", p.fResetPending));
    out.push_back(Pair("can_send", NyxPinCanSend(p)));
    out.push_back(Pair("result", NyxPinFlagsText(flags)));
    if (p.fPinned)
    {
        Object k;
        AddKeyringJson(k, p.kr, p.krHash);
        k.push_back(Pair("devices", DevicesJson(p.kr, &p.devices, now)));
        out.push_back(Pair("keyring", k));
        out.push_back(Pair("safety_number", NyxSafetyNumber((const uint8_t*)addr.data(), p.kr.epoch, p.devices)));
    }
    if (p.fFrozen)
        out.push_back(Pair("warning", "Keyring conflict: two valid keyrings exist at the same sequence. Sending is "
                                      "stopped until the owner confirms on exactly one device."));
    if (p.fResetPending)
    {
        NyxKeyring r;
        if (!p.resetBody.empty() && NyxParseKeyring(&p.resetBody[0], p.resetBody.size(), r) == 0)
        {
            NyxPinInput in;
            in.certs = p.resetCerts;
            NyxDeviceMap devs;
            for (size_t i = 0; i < p.resetCerts.size(); ++i)
            {
                NyxPinDevice d;
                d.body = p.resetCerts[i];
                if (NyxParseCert(&d.body[0], d.body.size(), d.cert) == 0)
                    devs[NyxId(d.cert.deviceId)] = d;
            }
            Object rs;
            uint8_t h[32];
            NyxHash(p.resetBody, h);
            AddKeyringJson(rs, r, h);
            rs.push_back(Pair("new_safety_number", NyxSafetyNumber((const uint8_t*)addr.data(), r.epoch, devs)));
            out.push_back(Pair("reset", rs));
        }
        out.push_back(Pair("warning", "Identity reset: all devices of this address were replaced. This is what a "
                                      "stolen wallet key looks like. Compare the new safety number with the owner, "
                                      "then run keyring accept."));
    }
}

bool NyxIdContact(const std::string& sAddr, Object& out, std::string& sError)
{
    LOCK(cs_nyxid);
    std::string addr;
    if (!Ready(sError) || !ParseAddr(sAddr, addr, NULL, sError))
        return false;
    SecureMsgPoGet(std::vector<unsigned char>(addr.begin(), addr.end()));
    NyxPin& p = mapPin[addr];
    memcpy(p.addrHash, addr.data(), 20);
    NyxPinInput in;
    SecureMsgPoCollect((const uint8_t*)addr.data(), in);
    const int flags = NyxPinApply(p, in, GetTime());
    const NyxPin shown = p.fPinned ? p : NyxPin();
    if (p.fPinned || p.fResetPending)
        SavePin(addr);
    else
        mapPin.erase(addr);
    PinJson(addr, shown, flags, out);
    return true;
}

bool NyxIdAcceptReset(const std::string& sAddr, bool fAllowDowngrade, Object& out, std::string& sError)
{
    LOCK(cs_nyxid);
    std::string addr;
    if (!Ready(sError) || !ParseAddr(sAddr, addr, NULL, sError))
        return false;
    std::map<std::string, NyxPin>::iterator it = mapPin.find(addr);
    if (it == mapPin.end() || !NyxPinAcceptReset(it->second, fAllowDowngrade, GetTime(), sError))
    {
        if (sError.empty())
            sError = "No pin for this address.";
        return false;
    }
    SavePin(addr);
    PinJson(addr, it->second, NYX_PIN_UPDATED, out);
    return true;
}

void NyxIdOnPublic(const NyxPoInfo& info, const std::vector<uint8_t>& body, bool fRemote)
{
    LOCK(cs_nyxid);
    if (!fSkLoaded)
        return;
    const std::string addr((const char*)info.addrHash, 20);
    std::map<std::string, NyxOwnDevice>::iterator itD = mapDev.find(addr);
    if (itD != mapDev.end() && !itD->second.certBody.empty())
    {
        NyxOwnDevice& d = itD->second;
        std::string why;
        if (info.type == NYX_PO_BUNDLE && fRemote)
        {
            uint8_t fp[32];
            memcpy(fp, d.hostFp, 32);
            why = NyxCloneCheck(d, fp, &body);
        }
        else if (info.type == NYX_PO_KEYRING)
        {
            NyxKeyring k, own;
            uint8_t h[32], ownHash[32];
            NyxHash(body, h);
            if (NyxParseKeyring(&body[0], body.size(), k) == 0 && OwnKeyring(d, own, ownHash))
            {
                if (k.epoch == own.epoch && k.seq == own.seq && memcmp(h, ownHash, 32) != 0)
                    why = "keyring conflict at seq " + boost::lexical_cast<std::string>(k.seq);
                else if (k.epoch == own.epoch && memcmp(k.prevHash, ownHash, 32) == 0 && k.seq > own.seq)
                {
                    d.keyringBody = body;
                    if (!k.IsLive(d.deviceId))
                        why = "this device was revoked";
                    SaveDev(addr);
                }
            }
            if (why.empty())
                RefreshOwn(addr, d);
        }
        if (!why.empty() && !d.fCloneAlarm)
        {
            d.fCloneAlarm = true;
            d.cloneReason = why;
            printf("Nyx identity: clone alarm for %s: %s\n", HexStr(addr.begin(), addr.end()).c_str(), why.c_str());
            SaveDev(addr);
        }
    }
    std::map<std::string, NyxPin>::iterator itP = mapPin.find(addr);
    if (itP != mapPin.end() && info.type != NYX_PO_BUNDLE)
    {
        NyxPinInput in;
        SecureMsgPoCollect(info.addrHash, in);
        const int flags = NyxPinApply(itP->second, in, GetTime());
        if (flags & (NYX_PIN_UPDATED | NYX_PIN_FROZEN | NYX_PIN_RESET | NYX_PIN_UNFROZEN))
            SavePin(addr);
    }
}

void NyxIdHousekeeping()
{
    std::vector<NyxBytes> vPub;
    {
        LOCK(cs_nyxid);
        std::string sError;
        if (!fSkLoaded || !pwalletMain || (pwalletMain->IsCrypted() && pwalletMain->IsLocked()))
        {
            if (fSkLoaded)
                Forget();
            return;
        }
        const int64_t now = GetTime();
        for (std::map<std::string, NyxOwnDevice>::iterator it = mapDev.begin(); it != mapDev.end(); ++it)
        {
            NyxOwnDevice& d = it->second;
            NyxKeyring kr;
            uint8_t h[32];
            if (d.certBody.empty() || d.fCloneAlarm || !OwnKeyring(d, kr, h) || !kr.IsLive(d.deviceId))
                continue;
            OwnTip t;
            Tip(it->first, t);
            if (!t.fHave || t.fConflict || memcmp(t.hash, h, 32) != 0)
                continue;
            NyxCert c;
            const bool fRenew = NyxParseCert(&d.certBody[0], d.certBody.size(), c) == 0
                             && now > (int64_t)(c.created + (c.expiry - c.created) * 4 / 5);
            if (!fRenew && now - (int64_t)kr.ts < NYX_KR_REFRESH)
                continue;
            // One publisher per slot: the lowest id refreshes, renewals wait rank slots past the tip.
            int64_t nRank = 0;
            for (size_t i = 0; i < kr.live.size(); ++i)
                nRank += memcmp(kr.live[i].deviceId, d.deviceId, 16) < 0;
            if (fRenew ? now - (int64_t)kr.ts < nRank * NYX_KR_RENEW_SLOT : nRank != 0)
                continue;
            CKeyID id;
            memcpy(id.begin(), it->first.data(), 20);
            CKey key;
            if (!pwalletMain->GetKey(id, key))
                continue;
            NyxBytes newCert;
            if (fRenew)
            {
                NyxCert rc;
                if (!NyxBuildCert(d, key, now, kr.seq + 1, d.mode == NYX_MODE_PQ ? &d : NULL, rc))
                    continue;
                newCert = rc.Serialize();
            }
            if (!NextKeyring(it->first, key, d, kr, h, std::vector<std::string>(), fRenew ? &newCert : NULL, vPub,
                             sError))
                continue;
            if (fRenew)
                d.certBody = newCert;
            NyxBundle b;
            if (NyxBuildBundle(d, key, now, b))
                vPub.push_back(d.lastBundle);
            SaveDev(it->first);
        }
        SessHousekeeping(vPub);
    }
    Publish(vPub);
}

// ---------------------------------------------------------------- 1:1 sessions

static const char NYX_DB_SESS[] = "nys";    // local20 || remoteDev16
static const char NYX_DB_SEEN[] = "nye";    // local20
static const char NYX_DB_INBOX[] = "nyi";   // local20 || time BE8 || logicalId16
static const size_t NYX_HELD_MAX = 32;
static const int64_t NYX_HELD_UNPINNED = 60 * 60;
static const int64_t NYX_HELD_FROZEN = 60 * 60 * 48;
static const size_t NYX_SEEN_MAX = 4096;

struct NyxHeld
{
    std::string local;
    NyxBytes body;
    int64_t until;
    std::string why;
};
static std::vector<NyxHeld> vHeld;

enum { NYX_RX_DONE, NYX_RX_HOLD, NYX_RX_DROP };

static void PrefixScan(const std::string& prefix, std::vector<std::pair<std::string, std::string> >& out)
{
    LOCK(cs_smsgDB);
    SecMsgDB db;
    if (!db.Open("cw"))
        return;
    leveldb::Iterator* it = db.pdb->NewIterator(leveldb::ReadOptions());
    for (it->Seek(prefix); it->Valid() && it->key().starts_with(prefix); it->Next())
        out.push_back(std::make_pair(it->key().ToString(), it->value().ToString()));
    delete it;
}

static void DbErase(const std::vector<std::string>& keys)
{
    if (keys.empty())
        return;
    LOCK(cs_smsgDB);
    SecMsgDB db;
    if (!db.Open("cw"))
        return;
    for (size_t i = 0; i < keys.size(); ++i)
        db.pdb->Delete(leveldb::WriteOptions(), keys[i]);
    std::string lo = keys.front(), hi = keys.front();
    for (size_t i = 1; i < keys.size(); ++i)
    {
        lo = std::min(lo, keys[i]);
        hi = std::max(hi, keys[i]);
    }
    leveldb::Slice a(lo), b(hi);
    db.pdb->CompactRange(&a, &b);
}

static bool SealPut(const std::string& key, std::string& plain)
{
    std::string sealed;
    const bool fOk = NyxStoreSeal(skCache, key, plain, sealed) && DbWrite(key, sealed);
    if (!plain.empty())
        OPENSSL_cleanse(&plain[0], plain.size());
    return fOk;
}

static bool OpenGet(const std::string& key, std::string& plain)
{
    std::string sealed;
    return DbRead(key, sealed) && NyxStoreOpen(skCache, key, sealed, plain);
}

static std::string SessKey(const std::string& local, const uint8_t dev[16])
{
    return NYX_DB_SESS + local + std::string((const char*)dev, 16);
}

static bool LoadSess(const std::string& local, const uint8_t dev[16], NyxSession& s)
{
    std::string plain;
    s.states.clear();
    const bool fOk = OpenGet(SessKey(local, dev), plain) && s.Deserialize(plain);
    if (!plain.empty())
        OPENSSL_cleanse(&plain[0], plain.size());
    return fOk;
}

static bool SaveSess(const std::string& local, const uint8_t dev[16], const NyxSession& s)
{
    std::string plain = s.Serialize();
    return SealPut(SessKey(local, dev), plain);
}

// Seen handshake ids of one local address: id32 -> first seen.
static void LoadSeen(const std::string& local, std::map<std::string, int64_t>& m)
{
    m.clear();
    std::string plain;
    if (!OpenGet(NYX_DB_SEEN + local, plain))
        return;
    for (size_t off = 0; off + 40 <= plain.size(); off += 40)
    {
        int64_t t;
        memcpy(&t, plain.data() + off + 32, 8);
        m[plain.substr(off, 32)] = t;
    }
}

static void SaveSeen(const std::string& local, std::map<std::string, int64_t>& m, int64_t now)
{
    std::string plain;
    for (std::map<std::string, int64_t>::iterator it = m.begin(); it != m.end();)
        if (now - it->second > NYX_HS_WINDOW)
            m.erase(it++);
        else
            ++it;
    while (m.size() > NYX_SEEN_MAX)
    {
        std::map<std::string, int64_t>::iterator oldest = m.begin();
        for (std::map<std::string, int64_t>::iterator it = m.begin(); it != m.end(); ++it)
            if (it->second < oldest->second)
                oldest = it;
        m.erase(oldest);
    }
    for (std::map<std::string, int64_t>::const_iterator it = m.begin(); it != m.end(); ++it)
    {
        plain += it->first;
        plain.append((const char*)&it->second, 8);
    }
    SealPut(NYX_DB_SEEN + local, plain);
}

static void StoreInbox(const std::string& local, bool fOut, const uint8_t peer[20], const uint8_t dev[16],
                       int64_t t, const NyxEnvelope& env, uint8_t mode)
{
    std::string key = NYX_DB_INBOX + local;
    for (int i = 7; i >= 0; --i)
        key.push_back((char)(t >> (8 * i)));
    key.append((const char*)env.logicalId, 16);
    std::string probe;
    if (DbRead(key, probe))
        return;
    std::string v;
    v.reserve(70 + env.text.size());
    v.push_back((char)fOut);
    v.append((const char*)peer, 20);
    v.append((const char*)dev, 16);
    v.append((const char*)&t, 8);
    v.append((const char*)env.logicalId, 16);
    v.push_back((char)mode);
    v.append(env.text);
    SealPut(key, v);
}

// Pin for addr, refreshed from the public store; a first pin is made here (TOFU). cs_nyxid held.
static NyxPin* PinFor(const std::string& addr, bool fRefresh)
{
    std::map<std::string, NyxPin>::iterator it = mapPin.find(addr);
    if (it != mapPin.end() && it->second.fPinned && !fRefresh)
        return &it->second;
    NyxPin& p = mapPin[addr];
    memcpy(p.addrHash, addr.data(), 20);
    NyxPinInput in;
    SecureMsgPoCollect((const uint8_t*)addr.data(), in);
    const int flags = NyxPinApply(p, in, GetTime());
    if (p.fPinned || p.fResetPending)
    {
        if (flags)
            SavePin(addr);
        return &p;
    }
    mapPin.erase(addr);
    return NULL;
}

static bool PinDevice(const NyxPin& p, const uint8_t dev[16], int64_t now, const NyxPinDevice** out)
{
    const std::vector<std::string> v = NyxPinUsable(p, now);
    const std::string id = NyxId(dev);
    if (std::find(v.begin(), v.end(), id) == v.end() || !p.kr.IsLive(dev))
        return false;
    NyxDeviceMap::const_iterator it = p.devices.find(id);
    if (it == p.devices.end())
        return false;
    *out = &it->second;
    return true;
}

static std::string PinRefusal(const NyxPin* p, uint8_t mode)
{
    if (!p || !p->fPinned)
        return "No pinned keyring for the recipient; a key fetch was started, retry shortly.";
    if (p->fFrozen)
        return "Recipient keyring is frozen: two valid keyrings exist at one sequence. Sending stops until the "
               "owner confirms on one device.";
    if (p->fResetPending)
        return "Recipient identity was reset; review it and run nyx keyring accept first.";
    if (p->kr.mode != mode)
        return mode == NYX_MODE_PQ ? "Recipient is classical-only while this device is PQ; refusing to downgrade."
                                   : "Recipient is PQ while this device is classical; upgrade this identity first.";
    return std::string();
}

// This node's paired, live device for local; NULL with sError otherwise. cs_nyxid held.
static NyxOwnDevice* LiveDevice(const std::string& local, NyxLocalSide& me, NyxKeyring& kr, std::string& sError)
{
    std::map<std::string, NyxOwnDevice>::iterator it = mapDev.find(local);
    uint8_t h[32];
    if (it == mapDev.end() || it->second.certBody.empty())
    {
        sError = "No paired device for this address on this node; run nyx keyring init or device pair.";
        return NULL;
    }
    NyxOwnDevice& d = it->second;
    RefreshOwn(local, d);
    if (d.fCloneAlarm)
    {
        sError = "Clone alarm is set on this device; run nyx keyring confirm first.";
        return NULL;
    }
    if (!OwnKeyring(d, kr, h) || !kr.IsLive(d.deviceId))
    {
        sError = "This device is not live in its keyring.";
        return NULL;
    }
    me.dev = &d;
    NyxHash(d.certBody, me.certHash);
    me.epoch = kr.epoch;
    me.seq = kr.seq;
    me.addrKey = NULL;
    return &d;
}

static void RebuildBundle(const std::string& local, NyxOwnDevice& d, std::vector<NyxBytes>& vPub)
{
    CKeyID id;
    memcpy(id.begin(), local.data(), 20);
    CKey key;
    NyxBundle b;
    if (pwalletMain->GetKey(id, key) && NyxBuildBundle(d, key, GetTime(), b))
        vPub.push_back(d.lastBundle);
    SaveDev(local);
}

static int Deliver(const std::string& local, const NyxRatchet& r, const NyxBytes& pt)
{
    NyxEnvelope env;
    if (!env.Parse(pt) || env.ctype != 0 || memcmp(env.convAddr, r.remoteAddr, 20) != 0)
        return NYX_RX_DROP;
    StoreInbox(local, false, r.remoteAddr, r.remoteDev, GetTime(), env, r.mode);
    return NYX_RX_DONE;
}

static void RxLog(const std::string& why)
{
    printf("Nyx session: %s\n", why.c_str());
}

// One private session body for local. cs_nyxid held.
static int SessRx(const std::string& local, const NyxBytes& body, std::string& why, std::vector<NyxBytes>& vPub)
{
    const int64_t now = GetTime();
    NyxLocalSide me;
    NyxKeyring kr;
    NyxOwnDevice* d = LiveDevice(local, me, kr, why);
    if (!d)
        return NYX_RX_DROP;
    if (body[0] == NYX_BODY_RATCHET)
    {
        NyxRatchetMsg m;
        if (NyxParseRatchetMsg(&body[0], body.size(), m) != 0 || memcmp(m.devB, d->deviceId, 16) != 0)
        {
            why = "ratchet message malformed or for another device";
            return NYX_RX_DROP;
        }
        NyxSession s;
        if (!LoadSess(local, m.devA, s) || s.states.empty())
        {
            why = "no session with the sending device";
            return NYX_RX_DROP;
        }
        const std::string peer((const char*)s.states[0].remoteAddr, 20);
        std::map<std::string, NyxPin>::iterator itP = mapPin.find(peer);
        if (itP == mapPin.end() || !itP->second.fPinned)
        {
            why = "sender is no longer pinned";
            return NYX_RX_DROP;
        }
        const NyxPinDevice* pd;
        if (itP->second.fFrozen || itP->second.fResetPending)
        {
            why = "sender keyring frozen or reset pending";
            return NYX_RX_HOLD;
        }
        if (!PinDevice(itP->second, m.devA, now, &pd))
        {
            why = "sending device is not live in the sender's pinned keyring";
            return NYX_RX_DROP;
        }
        NyxBytes pt;
        const int r = s.Decrypt(m.tail, now, pt);
        if (r != NYX_DR_OK)
        {
            why = "ratchet message refused (" + boost::lexical_cast<std::string>(r) + ")";
            return NYX_RX_DROP;
        }
        SaveSess(local, m.devA, s);
        const int rv = Deliver(local, s.states[0], pt);
        if (!pt.empty())
            OPENSSL_cleanse(&pt[0], pt.size());
        return rv;
    }

    NyxHandshake hs;
    if (NyxParseHandshake(&body[0], body.size(), hs) != 0 || memcmp(hs.devB, d->deviceId, 16) != 0)
    {
        why = "handshake malformed or for another device";
        return NYX_RX_DROP;
    }
    const std::string peer((const char*)hs.addrA, 20);
    NyxPin* p = PinFor(peer, mapPin.count(peer) == 0 || mapPin[peer].kr.seq < hs.seqA
                                 || mapPin[peer].kr.epoch < hs.epochA);
    if (!p || !p->fPinned)
    {
        SecureMsgPoGet(std::vector<unsigned char>(peer.begin(), peer.end()));
        why = "initiator not pinned yet";
        return NYX_RX_HOLD;
    }
    if (p->fFrozen || p->fResetPending)
    {
        why = "initiator keyring frozen or reset pending";
        return NYX_RX_HOLD;
    }
    if (p->kr.mode != d->mode || hs.mode != d->mode)
    {
        why = "initiator mode differs from this device (downgrade refused)";
        return NYX_RX_DROP;
    }
    if (hs.epochA > p->kr.epoch || (hs.epochA == p->kr.epoch && hs.seqA > p->kr.seq))
    {
        SecureMsgPoGet(std::vector<unsigned char>(peer.begin(), peer.end()));
        why = "initiator keyring ahead of the pin";
        return NYX_RX_HOLD;
    }
    const NyxPinDevice* pd;
    if (!PinDevice(*p, hs.devA, now, &pd))
    {
        why = "initiating device is not live in its pinned keyring";
        return NYX_RX_DROP;
    }
    uint8_t hsId[32];
    NyxHsId(hs, hsId);
    NyxSession s;
    LoadSess(local, hs.devA, s);
    NyxBytes pt;
    if (s.FindHs(hsId) >= 0)
    {
        const int r = s.Decrypt(hs.tail, now, pt);
        if (r != NYX_DR_OK)
        {
            why = "repeated handshake message refused (" + boost::lexical_cast<std::string>(r) + ")";
            return NYX_RX_DROP;
        }
    }
    else
    {
        std::map<std::string, int64_t> seen;
        LoadSeen(local, seen);
        const std::string sid((const char*)hsId, 32);
        if (seen.count(sid))
        {
            why = "handshake replay";
            return NYX_RX_DROP;
        }
        NyxPeerSide ps;
        ps.cert = &pd->cert;
        memcpy(ps.certHash, pd->certHash, 32);
        ps.epoch = p->kr.epoch;
        ps.seq = p->kr.seq;
        NyxRatchet r;
        uint32_t opk = NYX_OPK_NONE;
        if (!NyxHsRespond(me, ps, hs, now, r, opk, why))
            return NYX_RX_DROP;
        const int dr = NyxRatchetDecrypt(r, hs.tail, now, pt);
        if (dr != NYX_DR_OK)
        {
            why = "handshake message refused (" + boost::lexical_cast<std::string>(dr) + ")";
            return NYX_RX_DROP;
        }
        seen[sid] = now;
        SaveSeen(local, seen, now);
        s.Push(r);
        if (opk != NYX_OPK_NONE)
        {
            NyxDeviceEraseOpk(*d, opk);
            NyxDeviceTopUpOpks(*d, now);
            RebuildBundle(local, *d, vPub);
        }
    }
    SaveSess(local, hs.devA, s);
    const int rv = Deliver(local, s.states[0], pt);
    if (!pt.empty())
        OPENSSL_cleanse(&pt[0], pt.size());
    return rv;
}

static void Hold(const std::string& local, const NyxBytes& body, const std::string& why)
{
    NyxHeld h;
    h.local = local;
    h.body = body;
    h.until = GetTime() + (why.find("frozen") != std::string::npos ? NYX_HELD_FROZEN : NYX_HELD_UNPINNED);
    h.why = why;
    if (vHeld.size() >= NYX_HELD_MAX)
        vHeld.erase(vHeld.begin());
    vHeld.push_back(h);
}

// cs_nyxid held.
static void RetryHeld(std::vector<NyxBytes>& vPub)
{
    if (vHeld.empty())
        return;
    std::vector<NyxHeld> v;
    v.swap(vHeld);
    const int64_t now = GetTime();
    for (size_t i = 0; i < v.size(); ++i)
    {
        if (v[i].until < now)
            continue;
        std::string why;
        const int r = SessRx(v[i].local, v[i].body, why, vPub);
        if (r == NYX_RX_HOLD)
            vHeld.push_back(v[i]);
        else if (r == NYX_RX_DROP)
            RxLog("held message dropped: " + why);
    }
}

void NyxSessOnPrivate(const std::string& sAddrTo, const std::vector<uint8_t>& body)
{
    if (body.empty() || (body[0] != NYX_BODY_HANDSHAKE && body[0] != NYX_BODY_RATCHET))
        return;
    std::vector<NyxBytes> vPub;
    {
        LOCK(cs_nyxid);
        std::string sError, local;
        if (!Ready(sError) || !ParseAddr(sAddrTo, local, NULL, sError))
        {
            RxLog("cannot process a session message for " + sAddrTo + ": " + sError);
            return;
        }
        std::string why;
        const int r = SessRx(local, body, why, vPub);
        if (r == NYX_RX_HOLD)
        {
            Hold(local, body, why);
            RxLog("held: " + why);
        }
        else if (r == NYX_RX_DROP)
            RxLog("dropped: " + why);
    }
    Publish(vPub);
}

static void EnsureSmsgKey(const std::string& sAddrTo, const NyxPin& p)
{
    CBitcoinAddress a(sAddrTo);
    CKeyID id;
    CPubKey pk;
    if (!a.GetKeyID(id) || SecureMsgGetStoredKey(id, pk) == 0 || SecureMsgGetLocalKey(id, pk) == 0)
        return;
    if (NyxAddrRecover(NYX_TAG_KEYRING, p.kr.Signed(), p.kr.addrSig, pk) && pk.GetID() == id)
        SecureMsgInsertAddress(id, pk);
}

bool NyxSessSend(const std::string& sFrom, const std::string& sTo, const std::string& text, Object& out,
                 std::string& sError)
{
    std::vector<NyxBytes> vBodies, vPub;
    NyxPin pinCopy;
    {
        LOCK(cs_nyxid);
        std::string local, peer;
        CKey key;
        if (!Ready(sError) || !ParseAddr(sFrom, local, &key, sError) || !ParseAddr(sTo, peer, NULL, sError))
            return false;
        if (text.empty() || text.size() > (size_t)nNyxMaxParts * NYX_PART_BODY_MAX - NYX_HS_FIXED_PQ - 200)
        {
            sError = "Message is empty or too long.";
            return false;
        }
        NyxLocalSide me;
        NyxKeyring kr;
        NyxOwnDevice* d = LiveDevice(local, me, kr, sError);
        if (!d)
            return false;
        me.addrKey = &key;
        NyxPin* p = PinFor(peer, true);
        sError = PinRefusal(p, d->mode);
        if (!sError.empty())
        {
            SecureMsgPoGet(std::vector<unsigned char>(peer.begin(), peer.end()));
            return false;
        }
        const int64_t now = GetTime();
        const std::vector<std::string> usable = NyxPinUsable(*p, now);
        NyxPinInput in;
        std::vector<NyxBytes> vb;
        SecureMsgPoCollect((const uint8_t*)peer.data(), in, &vb);
        std::map<std::string, NyxBundle> bundles;
        for (size_t i = 0; i < vb.size(); ++i)
        {
            NyxBundle b;
            if (NyxParseBundle(&vb[i][0], vb[i].size(), b) == 0
                && (!bundles.count(NyxId(b.deviceId)) || bundles[NyxId(b.deviceId)].seq < b.seq))
                bundles[NyxId(b.deviceId)] = b;
        }
        NyxEnvelope env;
        env.ctype = 0;
        GetRandBytes(env.logicalId, 16);
        memcpy(env.convAddr, local.data(), 20);
        env.text = text;
        NyxBytes pt = env.Serialize();
        Array devs;
        for (size_t i = 0; i < usable.size(); ++i)
        {
            const NyxPinDevice& pd = p->devices[usable[i]];
            if (!p->kr.IsLive(pd.cert.deviceId))
                continue;
            Object o;
            o.push_back(Pair("device", Hex(pd.cert.deviceId, 16)));
            NyxSession s;
            LoadSess(local, pd.cert.deviceId, s);
            bool fNew = s.states.empty() || !s.states[0].fCKs
                     || (s.states[0].fInitiator && !s.states[0].fAcked && now - s.states[0].created > NYX_HS_WINDOW);
            if (fNew)
            {
                std::map<std::string, NyxBundle>::iterator itB = bundles.find(usable[i]);
                NyxPeerSide ps;
                ps.cert = &pd.cert;
                memcpy(ps.certHash, pd.certHash, 32);
                ps.epoch = p->kr.epoch;
                ps.seq = p->kr.seq;
                NyxRatchet r;
                std::string why;
                if (itB == bundles.end())
                    why = "no bundle published";
                else if (!NyxHsInitiate(me, ps, itB->second, now, r, why))
                    why = "handshake: " + why;
                if (!why.empty())
                {
                    o.push_back(Pair("error", why));
                    devs.push_back(o);
                    continue;
                }
                s.Push(r);
            }
            NyxBytes body;
            if (!NyxSessionSeal(s.states[0], pt, now, body))
            {
                o.push_back(Pair("error", "could not seal"));
                devs.push_back(o);
                continue;
            }
            SaveSess(local, pd.cert.deviceId, s);
            o.push_back(Pair("handshake", body[0] == NYX_BODY_HANDSHAKE));
            o.push_back(Pair("opk", s.states[0].fOpk));
            o.push_back(Pair("bytes", (int)body.size()));
            devs.push_back(o);
            vBodies.push_back(body);
        }
        OPENSSL_cleanse(&pt[0], pt.size());
        if (vBodies.empty())
        {
            SecureMsgPoGet(std::vector<unsigned char>(peer.begin(), peer.end()));
            sError = "No session could be started with any recipient device (no verified bundle yet); a key fetch "
                     "was started, retry shortly.";
            return false;
        }
        StoreInbox(local, true, (const uint8_t*)peer.data(), d->deviceId, now, env, d->mode);
        pinCopy = *p;
        out.push_back(Pair("logical_id", Hex(env.logicalId, 16)));
        out.push_back(Pair("mode", d->mode == NYX_MODE_PQ ? "pq" : "classical"));
        out.push_back(Pair("devices", devs));
    }
    EnsureSmsgKey(sTo, pinCopy);
    Array ids;
    for (size_t i = 0; i < vBodies.size(); ++i)
    {
        std::string msgid, err;
        if (SecureMsgV2SendPrivate(sTo, vBodies[i], msgid, err) != 0)
        {
            sError = "Sealed but not sent: " + err;
            return false;
        }
        ids.push_back(msgid);
    }
    out.push_back(Pair("msgids", ids));
    return true;
}

static std::string AddrStr(const uint8_t h[20])
{
    CKeyID id;
    memcpy(id.begin(), h, 20);
    return CBitcoinAddress(id).ToString();
}

bool NyxSessList(const std::string& sAddr, Array& out, std::string& sError)
{
    LOCK(cs_nyxid);
    std::string local;
    if (!Ready(sError) || !ParseAddr(sAddr, local, NULL, sError))
        return false;
    std::vector<std::pair<std::string, std::string> > v;
    PrefixScan(NYX_DB_SESS + local, v);
    for (size_t i = 0; i < v.size(); ++i)
    {
        std::string plain;
        NyxSession s;
        const bool fOk = NyxStoreOpen(skCache, v[i].first, v[i].second, plain) && s.Deserialize(plain);
        if (!plain.empty())
            OPENSSL_cleanse(&plain[0], plain.size());
        if (!fOk || s.states.empty())
            continue;
        const NyxRatchet& r = s.states[0];
        Object o;
        o.push_back(Pair("peer", AddrStr(r.remoteAddr)));
        o.push_back(Pair("peer_device", Hex(r.remoteDev, 16)));
        o.push_back(Pair("mode", r.mode == NYX_MODE_PQ ? "pq" : "classical"));
        o.push_back(Pair("suite", r.mode == NYX_MODE_PQ ? "PQXDH ML-KEM-768 + X25519, ML-DSA-65 handshake"
                                                        : "X3DH X25519, ECDSA handshake"));
        o.push_back(Pair("opk", r.fOpk));
        o.push_back(Pair("initiator", r.fInitiator));
        o.push_back(Pair("acked", r.fAcked));
        o.push_back(Pair("sent", (int64_t)r.Ns));
        o.push_back(Pair("received", (int64_t)r.Nr));
        o.push_back(Pair("skipped_keys", (int64_t)r.skipped.size()));
        o.push_back(Pair("states", (int64_t)s.states.size()));
        o.push_back(Pair("transcript", Hex(r.T, 32)));
        o.push_back(Pair("created", r.created));
        o.push_back(Pair("last_used", r.lastUsed));
        out.push_back(o);
    }
    size_t nHeld = 0;
    for (size_t i = 0; i < vHeld.size(); ++i)
        nHeld += vHeld[i].local == local;
    if (nHeld)
    {
        Object o;
        o.push_back(Pair("held_inbound", (int64_t)nHeld));
        o.push_back(Pair("held_reason", vHeld.back().why));
        out.push_back(o);
    }
    return true;
}

bool NyxSessMessages(const std::string& sAddr, const std::string& sPeer, Array& out, std::string& sError)
{
    LOCK(cs_nyxid);
    std::string local, peer;
    if (!Ready(sError) || !ParseAddr(sAddr, local, NULL, sError)
        || (!sPeer.empty() && !ParseAddr(sPeer, peer, NULL, sError)))
        return false;
    std::vector<std::pair<std::string, std::string> > v;
    PrefixScan(NYX_DB_INBOX + local, v);
    for (size_t i = 0; i < v.size(); ++i)
    {
        std::string plain;
        if (!NyxStoreOpen(skCache, v[i].first, v[i].second, plain) || plain.size() < 62)
            continue;
        if (!peer.empty() && plain.compare(1, 20, peer) != 0)
            continue;
        int64_t t;
        memcpy(&t, plain.data() + 37, 8);
        Object o;
        o.push_back(Pair("direction", plain[0] ? "out" : "in"));
        o.push_back(Pair("peer", AddrStr((const uint8_t*)plain.data() + 1)));
        o.push_back(Pair(plain[0] ? "from_device" : "peer_device", Hex((const uint8_t*)plain.data() + 21, 16)));
        o.push_back(Pair("time", t));
        o.push_back(Pair("logical_id", Hex((const uint8_t*)plain.data() + 45, 16)));
        o.push_back(Pair("mode", plain[61] == NYX_MODE_PQ ? "pq" : "classical"));
        o.push_back(Pair("text", plain.substr(62)));
        out.push_back(o);
        OPENSSL_cleanse(&plain[0], plain.size());
    }
    return true;
}

bool NyxSessDelete(const std::string& sAddr, const std::string& sPeer, Object& out, std::string& sError)
{
    LOCK(cs_nyxid);
    std::string local, peer;
    if (!Ready(sError) || !ParseAddr(sAddr, local, NULL, sError) || !ParseAddr(sPeer, peer, NULL, sError))
        return false;
    std::vector<std::pair<std::string, std::string> > v;
    PrefixScan(NYX_DB_SESS + local, v);
    std::vector<std::string> vErase;
    for (size_t i = 0; i < v.size(); ++i)
    {
        std::string plain;
        NyxSession s;
        if (NyxStoreOpen(skCache, v[i].first, v[i].second, plain) && s.Deserialize(plain) && !s.states.empty()
            && memcmp(s.states[0].remoteAddr, peer.data(), 20) == 0)
            vErase.push_back(v[i].first);
        if (!plain.empty())
            OPENSSL_cleanse(&plain[0], plain.size());
    }
    DbErase(vErase);
    out.push_back(Pair("deleted", (int64_t)vErase.size()));
    return true;
}

// SPK rotation, OPK top-up and held-message retries, from NyxIdHousekeeping. cs_nyxid held.
static void SessHousekeeping(std::vector<NyxBytes>& vPub)
{
    const int64_t now = GetTime();
    for (std::map<std::string, NyxOwnDevice>::iterator it = mapDev.begin(); it != mapDev.end(); ++it)
    {
        NyxOwnDevice& d = it->second;
        if (d.certBody.empty() || d.fCloneAlarm)
            continue;
        const int64_t created = d.spkCreated;
        const bool fRot = NyxDeviceRotateSpk(d, now);
        const bool fTop = NyxDeviceTopUpOpks(d, now);
        if (fRot || fTop)
            RebuildBundle(it->first, d, vPub);
        else if (created != d.spkCreated)
            SaveDev(it->first);
    }
    RetryHeld(vPub);
}
