// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_NYXIDENTITY_H
#define INNOVA_NYXIDENTITY_H

#include "nyxkeyring.h"
#include "nyxpo.h"
#include "json/json_spirit_value.h"

#include <string>

class CCryptoKeyStore;

/** Resolves the messenger storage key from its record ("" when absent), wrapping it under the
 *  wallet master key when the wallet is encrypted; newRec is set when the record must be written. */
bool NyxStorageKeyResolve(CCryptoKeyStore* ks, const std::string& rec, uint8_t sk[32], std::string& newRec,
                          std::string& sError);

/** Called by the public object channel for every verified object it stores. */
void NyxIdOnPublic(const NyxPoInfo& info, const std::vector<uint8_t>& body, bool fRemote);
/** Keyring refresh and clone checks, from the SMSG thread. */
void NyxIdHousekeeping();
void NyxIdForget();
/** Rewraps a raw storage key record under the wallet master key; ks must be unlocked. */
void NyxIdOnWalletEncrypted(CCryptoKeyStore* ks);
/** Opens the storage key and loads devices and pins when the wallet allows it. */
void NyxIdTryLoad();

// RPC surface; each returns false with sError on failure.
bool NyxIdKeyringInit(const std::string& addr, uint8_t mode, json_spirit::Object& out, std::string& sError);
bool NyxIdKeyringShow(const std::string& addr, json_spirit::Object& out, std::string& sError);
bool NyxIdKeyringReset(const std::string& addr, uint8_t mode, json_spirit::Object& out, std::string& sError);
bool NyxIdKeyringConfirm(const std::string& addr, json_spirit::Object& out, std::string& sError);
bool NyxIdDevices(const std::string& addr, json_spirit::Array& out, std::string& sError);
bool NyxIdPairRequest(const std::string& addr, uint8_t mode, json_spirit::Object& out, std::string& sError);
bool NyxIdApprove(const std::string& addr, const std::string& requestHex, json_spirit::Object& out, std::string& sError);
bool NyxIdInstall(const std::string& addr, const std::string& certHex, json_spirit::Object& out, std::string& sError);
bool NyxIdRevoke(const std::string& addr, const std::string& deviceIdHex, json_spirit::Object& out, std::string& sError);
bool NyxIdContact(const std::string& addr, json_spirit::Object& out, std::string& sError);
bool NyxIdAcceptReset(const std::string& addr, bool fAllowDowngrade, json_spirit::Object& out, std::string& sError);


// 1:1 sessions.
/** A completed {2,0} body of type 0x10/0x11 for a local address; held, dropped or stored in the inbox. */
void NyxSessOnPrivate(const std::string& addrTo, const std::vector<uint8_t>& body);
bool NyxSessSend(const std::string& from, const std::string& to, const std::string& text, json_spirit::Object& out,
                 std::string& sError);
bool NyxSessList(const std::string& addr, json_spirit::Array& out, std::string& sError);
bool NyxSessMessages(const std::string& addr, const std::string& peer, json_spirit::Array& out, std::string& sError);
/** Session, seen-handshake and OPK commits are synced before anything is sent. */
bool NyxIdSyncWrites();
/** Inbox record key: one record per (time, logicalId, direction, peer). */
std::string NyxInboxKey(const std::string& local, int64_t t, const uint8_t logicalId[16], bool fOut,
                        const uint8_t peer[20]);
bool NyxSessDelete(const std::string& addr, const std::string& peer, json_spirit::Object& out, std::string& sError);

// v2 groups over 1:1 sessions.
bool NyxGroupCreate2(const std::string& from, const std::string& name, const std::vector<std::string>& members,
                     json_spirit::Object& out, std::string& sError);
bool NyxGroupSend2(const std::string& from, const std::string& gid, const std::string& text, json_spirit::Object& out,
                   std::string& sError);
/** op: add|remove (owner, with addr) or leave. */
bool NyxGroupChange2(const std::string& op, const std::string& from, const std::string& gid, const std::string& addr,
                     json_spirit::Object& out, std::string& sError);
bool NyxGroupList2(const std::string& addr, json_spirit::Array& out, std::string& sError);
bool NyxGroupMessages2(const std::string& addr, const std::string& gid, json_spirit::Array& out, std::string& sError);

#endif // INNOVA_NYXIDENTITY_H
