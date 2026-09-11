// BIP-0039 mnemonic for a wallet's root entropy. 24 words only: 256 bits is exactly
// the 32-byte IV5 seed; shorter forms are refused.

#ifndef INN_BIP39_H
#define INN_BIP39_H

#include <string>
#include <vector>

static const size_t BIP39_ENTROPY_BYTES = 32;   // 256 bits
static const size_t BIP39_WORD_COUNT = 24;      // 256 + 8 checksum bits, 11 bits per word
static const size_t BIP39_SEED_BYTES = 64;      // PBKDF2 output, the BIP32 master input

/** Render 32 bytes of entropy as 24 space-separated lowercase words.
 *  Fails only if the entropy is not exactly BIP39_ENTROPY_BYTES. */
bool BIP39EntropyToMnemonic(const std::vector<unsigned char>& vEntropy,
                            std::string& strMnemonicOut,
                            std::string& strErrorOut);

/** Recover the 32 bytes a phrase names. Refuses a wrong word count, unknown word or bad
 *  checksum. Only case and whitespace are normalised. */
bool BIP39MnemonicToEntropy(const std::string& strMnemonic,
                            std::vector<unsigned char>& vEntropyOut,
                            std::string& strErrorOut);

/** Whether a phrase is well formed, including its checksum. */
bool BIP39CheckMnemonic(const std::string& strMnemonic, std::string& strErrorOut);

/** PBKDF2-HMAC-SHA512(phrase, "mnemonic" + passphrase, 2048 rounds). Innova always passes
 *  an empty passphrase; the argument exists for the standard's test vectors. */
bool BIP39MnemonicToSeed(const std::string& strMnemonic,
                         const std::string& strPassphrase,
                         std::vector<unsigned char>& vSeedOut,
                         std::string& strErrorOut);

/** Normalised word split: lowercased, whitespace collapsed. Exposed for tests. */
std::vector<std::string> BIP39SplitWords(const std::string& strMnemonic);

#endif // INN_BIP39_H
