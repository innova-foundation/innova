// Copyright (c) 2014 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef SEC_MESSAGE_H
#define SEC_MESSAGE_H

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

#include "net.h"
#include "db.h"
#include "wallet.h"
#include "lz4/lz4.h"


const unsigned int SMSG_HDR_LEN         = 104;               // length of unencrypted header, 4 + 2 + 1 + 8 + 16 + 33 + 32 + 4 +4
const unsigned int SMSG_PL_HDR_LEN      = 1+20+65+4;         // length of encrypted header in payload

const unsigned int SMSG_BUCKET_LEN      = 60 * 10;           // in seconds
const unsigned int SMSG_RETENTION       = 60 * 60 * 48;      // in seconds
const unsigned int SMSG_SEND_DELAY      = 2;                 // in seconds, SecureMsgSendData will delay this long between firing
const unsigned int SMSG_THREAD_DELAY    = 20;

const unsigned int SMSG_TIME_LEEWAY     = 60;
const unsigned int SMSG_TIME_IGNORE     = 90;                // seconds that a peer is ignored for if they fail to deliver messages for a smsgWant


const unsigned int SMSG_MAX_MSG_BYTES   = 4096;              // the user input part

// max size of payload worst case compression
const unsigned int SMSG_MAX_MSG_WORST = LZ4_COMPRESSBOUND(SMSG_MAX_MSG_BYTES+SMSG_PL_HDR_LEN);

// Dandelion++ for smsg: stem relay timeout before fluff fallback
const unsigned int SMSG_STEM_TIMEOUT = 45;  // seconds — shorter than tx stem (messages are less frequent)



#define SMSG_MASK_UNREAD            (1 << 0)



extern bool fSecMsgEnabled;

class SecMsgStored;

// Inbox db changed, called with lock cs_smsgDB held.
extern boost::signals2::signal<void (SecMsgStored& inboxHdr)> NotifySecMsgInboxChanged;

// Outbox db changed, called with lock cs_smsgDB held.
extern boost::signals2::signal<void (SecMsgStored& outboxHdr)> NotifySecMsgOutboxChanged;

// Wallet Unlocked, called after all messages received while locked have been processed.
extern boost::signals2::signal<void ()> NotifySecMsgWalletUnlocked;

// Typing notification received from a peer.
extern boost::signals2::signal<void (std::string senderAddr)> NotifySecMsgTyping;


class SecMsgBucket;
class SecMsgAddress;
class SecMsgOptions;

extern std::map<int64_t, SecMsgBucket>  smsgBuckets;
extern std::vector<SecMsgAddress>       smsgAddresses;
extern SecMsgOptions                    smsgOptions;

extern CCriticalSection cs_smsg;            // all except inbox and outbox
extern CCriticalSection cs_smsgDB;



#pragma pack(push, 1)
class SecureMessage
{
public:
    SecureMessage()
    {
        nPayload = 0;
        pPayload = NULL;
    };

    ~SecureMessage()
    {
        if (pPayload)
            delete[] pPayload;
        pPayload = NULL;
    };

    unsigned char   hash[4];
    unsigned char   version[2];
    unsigned char   flags;
    int64_t         timestamp;
    unsigned char   iv[16];
    unsigned char   cpkR[33];
    unsigned char   mac[32];
    unsigned char   nonse[4];
    uint32_t        nPayload;
    unsigned char*  pPayload;

};
#pragma pack(pop)


class MessageData
{
// -- Decrypted SecureMessage data
public:
    int64_t                     timestamp;
    std::string                 sToAddress;
    std::string                 sFromAddress;
    std::vector<unsigned char>  vchMessage;         // null terminated plaintext
};


class SecMsgToken
{
public:
    SecMsgToken(int64_t ts, unsigned char* p, int np, long int o, uint16_t fileNo=1)
    {
        timestamp = ts;
        fileId = fileNo;

        if (np < 8) // payload will always be > 8, just make sure
            memset(sample, 0, 8);
        else
            memcpy(sample, p, 8);
        offset = o;
    };

    SecMsgToken()
    {
        timestamp = 0;
        fileId = 1;
        memset(sample, 0, 8);
        offset = 0;
    };

    ~SecMsgToken() {};

    bool operator <(const SecMsgToken& y) const
    {
        // pack and memcmp from timesent?
        if (timestamp == y.timestamp)
            return memcmp(sample, y.sample, 8) < 0;
        return timestamp < y.timestamp;
    }

    int64_t                     timestamp;    // doesn't need to be full 64 bytes?
    uint16_t                    fileId;
    unsigned char               sample[8];    // first 8 bytes of payload - a hash
    int64_t                     offset;       // offset

};


class SecMsgBucket
{
public:
    SecMsgBucket()
    {
        timeChanged     = 0;
        hash            = 0;
        nLockCount      = 0;
        nLockPeerId     = 0;
        nTokenCount     = 0;
        fCompacted      = false;
    };
    ~SecMsgBucket() {};

    void hashBucket();

    bool compact(int64_t nBucketTime);
    bool expand(int64_t nBucketTime);
    bool isCompacted() const { return fCompacted; }
    uint32_t getTokenCount() const { return fCompacted ? nTokenCount : (uint32_t)setTokens.size(); }

    int64_t                     timeChanged;
    uint32_t                    hash;           // token set should get ordered the same on each node
    uint32_t                    nLockCount;     // set when smsgWant first sent, unset at end of smsgMsg, ticks down in ThreadSecureMsg()
    uint32_t                    nLockPeerId;    // id of peer that bucket is locked for
    std::set<SecMsgToken>       setTokens;

private:
    uint32_t                    nTokenCount;    // Token count when compacted (memory optimization)
    bool                        fCompacted;     // True if setTokens has been cleared to save memory

};


// -- get at the data
class CBitcoinAddress_B : public CBitcoinAddress
{
public:
    unsigned char getVersion()
    {
        return nVersion;
    }
};

class CKeyID_B : public CKeyID
{
public:
    unsigned int* GetPPN()
    {
        return pn;
    }
};


class SecMsgAddress
{
public:
    SecMsgAddress() {};
    SecMsgAddress(std::string sAddr, bool receiveOn, bool receiveAnon)
    {
        sAddress            = sAddr;
        fReceiveEnabled     = receiveOn;
        fReceiveAnon        = receiveAnon;
    };

    std::string     sAddress;
    bool            fReceiveEnabled;
    bool            fReceiveAnon;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->sAddress);
        READWRITE(this->fReceiveEnabled);
        READWRITE(this->fReceiveAnon);
    );
};

class SecMsgOptions
{
public:
    SecMsgOptions()
    {
        // -- default options
        fNewAddressRecv = true;
        fNewAddressAnon = true;
    }

    bool fNewAddressRecv;
    bool fNewAddressAnon;
};


class SecMsgCrypter
{
private:
    unsigned char chKey[32];
    unsigned char chIV[16];
    bool fKeySet;
public:

    SecMsgCrypter()
    {
        // Try to keep the key data out of swap (and be a bit over-careful to keep the IV that we don't even use out of swap)
        // Note that this does nothing about suspend-to-disk (which will put all our key data on disk)
        // Note as well that at no point in this program is any attempt made to prevent stealing of keys by reading the memory of the running process.
        LockedPageManager::instance.LockRange(&chKey[0], sizeof chKey);
        LockedPageManager::instance.LockRange(&chIV[0], sizeof chIV);
        fKeySet = false;
    }

    ~SecMsgCrypter()
    {
        // clean key
        memset(&chKey, 0, sizeof chKey);
        memset(&chIV, 0, sizeof chIV);
        fKeySet = false;

        LockedPageManager::instance.UnlockRange(&chKey[0], sizeof chKey);
        LockedPageManager::instance.UnlockRange(&chIV[0], sizeof chIV);
    }

    bool SetKey(const std::vector<unsigned char>& vchNewKey, unsigned char* chNewIV);
    bool SetKey(const unsigned char* chNewKey, unsigned char* chNewIV);
    bool Encrypt(unsigned char* chPlaintext, uint32_t nPlain, std::vector<unsigned char> &vchCiphertext);
    bool Decrypt(unsigned char* chCiphertext, uint32_t nCipher, std::vector<unsigned char>& vchPlaintext);
};


class SecMsgStored
{
public:
    int64_t                         timeReceived;
    char                            status;         // read etc
    uint16_t                        folderId;
    std::string                     sAddrTo;        // when in owned addr, when sent remote addr
    std::string                     sAddrOutbox;    // owned address this copy was encrypted with
    std::vector<unsigned char>      vchMessage;     // message header + encryped payload

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->timeReceived);
        READWRITE(this->status);
        READWRITE(this->folderId);
        READWRITE(this->sAddrTo);
        READWRITE(this->sAddrOutbox);
        READWRITE(this->vchMessage);
    );
};

class SecMsgDB
{
public:
    SecMsgDB()
    {
        activeBatch = NULL;
    };

    ~SecMsgDB()
    {
        // -- deletes only data scoped to this TxDB object.

        if (activeBatch)
            delete activeBatch;
    };

    bool Open(const char* pszMode="r+");

    bool ScanBatch(const CDataStream& key, std::string* value, bool* deleted) const;

    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort();

    bool ReadPK(CKeyID& addr, CPubKey& pubkey);
    bool WritePK(CKeyID& addr, CPubKey& pubkey);
    bool ExistsPK(CKeyID& addr);

    bool NextSmesg(leveldb::Iterator* it, std::string& prefix, unsigned char* vchKey, SecMsgStored& smsgStored);
    bool NextSmesgKey(leveldb::Iterator* it, std::string& prefix, unsigned char* vchKey);
    bool ReadSmesg(unsigned char* chKey, SecMsgStored& smsgStored);
    bool WriteSmesg(unsigned char* chKey, SecMsgStored& smsgStored);
    bool ExistsSmesg(unsigned char* chKey);
    bool EraseSmesg(unsigned char* chKey);

    leveldb::DB *pdb;       // points to the global instance
    leveldb::WriteBatch *activeBatch;

};

std::string getTimeString(int64_t timestamp, char *buffer, size_t nBuffer);
std::string fsReadable(uint64_t nBytes);


int SecureMsgBuildBucketSet();
int SecureMsgAddWalletAddresses();

int SecureMsgReadIni();
int SecureMsgWriteIni();

bool SecureMsgStart(bool fDontStart, bool fScanChain);
bool SecureMsgShutdown();

bool SecureMsgEnable();
bool SecureMsgDisable();

bool SecureMsgReceiveData(CNode* pfrom, std::string strCommand, CDataStream& vRecv);
bool SecureMsgSendData(CNode* pto, bool fSendTrickle);


bool SecureMsgScanBlock(CBlock& block);
bool ScanChainForPublicKeys(CBlockIndex* pindexStart);
bool SecureMsgScanBlockChain();
bool SecureMsgScanBuckets();


int SecureMsgWalletUnlocked();
int SecureMsgWalletKeyChanged(std::string sAddress, std::string sLabel, ChangeType mode);

int SecureMsgScanMessage(unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload, bool reportToGui);

int SecureMsgGetStoredKey(CKeyID& ckid, CPubKey& cpkOut);
int SecureMsgGetLocalKey(CKeyID& ckid, CPubKey& cpkOut);
int SecureMsgGetLocalPublicKey(std::string& strAddress, std::string& strPublicKey);

int SecureMsgAddAddress(std::string& address, std::string& publicKey);

int SecureMsgRetrieve(SecMsgToken &token, std::vector<unsigned char>& vchData);

int SecureMsgReceive(CNode* pfrom, std::vector<unsigned char>& vchData);

int SecureMsgStoreUnscanned(unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload);
int SecureMsgStore(unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload, bool fUpdateBucket);
int SecureMsgStore(SecureMessage& smsg, bool fUpdateBucket);



int SecureMsgSend(std::string& addressFrom, std::string& addressTo, std::string& message, std::string& sError);

/** Dandelion++ stem relay for a single PoW'd message.
 *  Returns true if stem relay succeeded, false if should fluff immediately. */
bool SecureMsgStemRelay(unsigned char* pHeader, unsigned char* pPayload, uint32_t nPayload);

/** Process an incoming smsgStem message (Dandelion++ stem phase). */
bool SecureMsgHandleStem(CNode* pfrom, std::vector<unsigned char>& vchData);

/** Check stem timeouts and fluff expired messages. */
void SecureMsgCheckStemTimeouts();

/** Stem state: tracks messages in the Dandelion++ stem phase */
struct SmsgStemEntry {
    std::vector<unsigned char> vchMessage;  // header + payload
    int64_t nStemStartTime;
    bool fRelayed;  // true if we've already relayed to our stem peer
};

extern CCriticalSection cs_smsgStem;
extern std::map<uint256, SmsgStemEntry> mapSmsgStemState;

/** Send an ephemeral typing notification via P2P. */
bool SecureMsgSendTyping(const std::string& addrFrom, const std::string& addrTo);

/** Handle incoming smsgTyping message. Returns the sender address if valid. */
bool SecureMsgHandleTyping(CNode* pfrom, std::vector<unsigned char>& vchData, std::string& senderAddrOut);

int SecureMsgValidate(unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload);
int SecureMsgSetHash(unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload);

int SecureMsgEncrypt(SecureMessage& smsg, std::string& addressFrom, std::string& addressTo, std::string& message);

int SecureMsgDecrypt(bool fTestOnly, std::string& address, unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload, MessageData& msg);
int SecureMsgDecrypt(bool fTestOnly, std::string& address, SecureMessage& smsg, MessageData& msg);



#endif // SEC_MESSAGE_H
