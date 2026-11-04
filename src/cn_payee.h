#ifndef INNOVA_CN_PAYEE_H
#define INNOVA_CN_PAYEE_H

#include "main.h"

struct CCNRegistration
{
    uint8_t version = 2;
    COutPoint collateral;
    CPubKey pubkey;
    uint256 inputsHash;
    uint64_t sequence = 0;
    std::vector<unsigned char> signature;
    IMPLEMENT_SERIALIZE(READWRITE(version); READWRITE(collateral); READWRITE(pubkey); READWRITE(inputsHash); READWRITE(sequence); READWRITE(signature);)
};

enum CNRegistrationDecode { CN_REG_NONE, CN_REG_INVALID, CN_REG_VALID };
uint256 CNRegistrationHash(const CCNRegistration& registration);
uint256 CNRegistrationInputsHash(const CTransaction& tx);
CScript CNRegistrationScript(const CCNRegistration& registration);
CNRegistrationDecode DecodeCNRegistration(const CScript& script, CCNRegistration& registration);
bool VerifyCNRegistration(const CCNRegistration& registration, const CScript& collateralScript,
                          const CTransaction& tx);

struct CCNPayeeCoin
{
    int height = -1;
    CScript script;
    int registrationHeight = -1;
    CPubKey pubkey;
    uint64_t sequence = 0;
    IMPLEMENT_SERIALIZE(READWRITE(height); READWRITE(script); READWRITE(registrationHeight); READWRITE(pubkey); READWRITE(sequence);)
    bool operator==(const CCNPayeeCoin& other) const
    {
        return height == other.height && script == other.script &&
               registrationHeight == other.registrationHeight && pubkey == other.pubkey &&
               sequence == other.sequence;
    }
};

typedef std::map<COutPoint, CCNPayeeCoin> CNPayeeCoins;
struct CCNPayeeState
{
    uint256 hashTip;
    CNPayeeCoins coins;
    IMPLEMENT_SERIALIZE(READWRITE(hashTip); READWRITE(coins);)
};

// A negative height restores an absent output.
struct CCNPayeeUndo
{
    CNPayeeCoins previous;
    IMPLEMENT_SERIALIZE(READWRITE(previous);)
};

bool CheckCNRegistrationTx(const CCNPayeeState& state, const CTransaction& tx);
void ApplyCNPayeeTx(CCNPayeeState& state, const CTransaction& tx, int nHeight,
                    CCNPayeeUndo* undo = NULL);
bool SelectCNPayee(const CCNPayeeState& state, int nParentHeight, CScript& payee);
bool LoadCNPayeeState(CTxDB& txdb, const CBlockIndex* parent, CCNPayeeState& state);
bool UndoCNPayeeState(CTxDB& txdb, const CBlockIndex* index);
bool CheckCNPayeePayment(int nHeight, const CTransaction& reward, const CScript& payee,
                         int64_t nPayment, const std::vector<CTxOut>& reserved);

#endif
