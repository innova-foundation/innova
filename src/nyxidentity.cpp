// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxidentity.h"
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

static void Forget()
{
    OPENSSL_cleanse(skCache, sizeof(skCache));
    fSkLoaded = false;
    mapDev.clear();
    mapPin.clear();
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
    if (p.fPinned || p.fResetPending)
        SavePin(addr);
    else
        mapPin.erase(addr);
    NyxPin shown = p.fPinned ? p : NyxPin();
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
    }
    Publish(vPub);
}
