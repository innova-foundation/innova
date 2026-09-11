// One 24-word phrase for both key systems: its 256-bit BIP39 entropy IS the shielded
// seed, and the BIP39 seed gives the BIP32 master for m/44'/116'/0', so any BIP44
// wallet restores the same transparent addresses.

#ifndef INN_HDROOT_H
#define INN_HDROOT_H

#include "key.h"

#include <string>
#include <vector>

// BIP44: m / purpose' / coin_type' / account' / change / index
static const unsigned int BIP32_HARDENED = 0x80000000u;
static const unsigned int BIP44_PURPOSE = 44u;
static const unsigned int HD_COIN_TYPE_MAINNET = 116u;   // Innova's registered slot
static const unsigned int HD_COIN_TYPE_TESTNET = 1u;     // SLIP-44's test-network slot
static const unsigned int HD_ACCOUNT = 0u;
static const unsigned int HD_CHAIN_EXTERNAL = 0u;        // addresses handed out
static const unsigned int HD_CHAIN_INTERNAL = 1u;        // change

/** The coin type in force on this network. */
unsigned int HDCoinType();

/** The account node, m/44'/<coin>'/0', from a phrase's entropy. Hardened the whole way,
 *  so an extended public key for the account cannot expose its siblings or its parent. */
bool HDAccountKeyFromEntropy(const std::vector<unsigned char>& vEntropy,
                             CExtKey& accountKeyOut,
                             std::string& strErrorOut);

/** One transparent key, m/44'/<coin>'/0'/<chain>/<index>. nChain is HD_CHAIN_EXTERNAL or
 *  HD_CHAIN_INTERNAL; nIndex must be non-hardened, which is what BIP44 specifies for the
 *  address level and what lets a watch-only wallet follow the same chain. */
bool HDDeriveTransparentKey(const CExtKey& accountKey,
                            unsigned int nChain,
                            unsigned int nIndex,
                            CKey& keyOut,
                            std::string& strErrorOut);

/** The shielded seed a phrase names: the entropy itself. Present as a function so the
 *  identity is stated once, in the place the rest of the wallet reads it from. */
bool HDShieldedSeedFromEntropy(const std::vector<unsigned char>& vEntropy,
                               std::vector<unsigned char>& vSeedOut,
                               std::string& strErrorOut);

/** The BIP44 path of a transparent key, for logging and key metadata. */
std::string HDKeyPath(unsigned int nChain, unsigned int nIndex);

#endif // INN_HDROOT_H
