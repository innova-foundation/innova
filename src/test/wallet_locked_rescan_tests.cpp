// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Startup rescan of an encrypted IV5 wallet: a locked seed degrades the scan to a
// durable gap that refuses spends until an unlock closes it.

#include <boost/test/unit_test.hpp>

#include "../crypter.h"
#include "../curvetree.h"
#include "../db.h"
#include "../hooks.h"
#include "../innovarpc.h"
#include "../key.h"
#include "../main.h"
#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../privacy_vnext_wallet.h"
#include "../shielded.h"
#include "../txdb.h"
#include "../util.h"
#include "../wallet.h"
#include "../walletdb.h"

#include <boost/thread.hpp>
#include <openssl/rand.h>

#include <atomic>
#include <cstring>
#include <string>
#include <vector>

// The RPC acts on the global, and so do the threads it starts.
extern CWallet* pwalletMain;

BOOST_AUTO_TEST_SUITE(wallet_locked_rescan_tests)

namespace {

// A run of on-disk blocks with the per-block snapshots the wallet's shielded scan reads,
// removed again when the case ends so the shared chain globals are unchanged.
struct RescanChain
{
    std::vector<uint256> vHashes;
    std::vector<CBlockIndex*> vIndex;
    CBigNum bnSavedLimit;
    CBlockIndex* pSavedBest;
    CBlockIndex* pSavedGenesis;
    int nSavedBestHeight;
    CHooks* pSavedHooks;

    RescanChain()
        : bnSavedLimit(bnProofOfWorkLimit),
          pSavedBest(pindexBest),
          pSavedGenesis(pindexGenesisBlock),
          nSavedBestHeight(nBestHeight),
          pSavedHooks(hooks)
    {
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        // The transparent half of the scan consults the name hooks, which only
        // init.cpp installs and which test_innova links out.
        if (!hooks)
            hooks = InitHook();
    }

    ~RescanChain()
    {
        if (!pSavedHooks && hooks)
        {
            delete hooks;
            hooks = pSavedHooks;
        }
        pindexBest = pSavedBest;
        pindexGenesisBlock = pSavedGenesis;
        nBestHeight = nSavedBestHeight;
        CTxDB txdb("r+");
        for (size_t i = vHashes.size(); i-- > 0; )
        {
            txdb.EraseShieldedTreeAtBlock(vHashes[i]);
            txdb.EraseCurveTreeAtBlock(vHashes[i]);
            mapBlockIndex.erase(vHashes[i]);
            delete vIndex[i];
        }
        bnProofOfWorkLimit = bnSavedLimit;
    }

    CBlockIndex* Head() const { return vIndex.front(); }
    CBlockIndex* Tip() const { return vIndex.back(); }
    const uint256& HashAt(size_t i) const { return vHashes[i]; }

    // Heights start past FORK_HEIGHT_SHIELDED so the activation-only position bases are
    // not in play, and stay below FORK_HEIGHT_DAG so no connect-time sibling skip set is
    // required; both would only add setup the rule under test does not read.
    CBlockIndex* Add(int nHeight, const std::vector<CTransaction>& vExtra)
    {
        return AddAt(nHeight, vIndex.empty() ? NULL : vIndex.back(), vExtra);
    }

    // A block on an explicit parent, made the best chain: with a parent below the
    // current tip this is the connect half of a reorg.
    CBlockIndex* AddAt(int nHeight, CBlockIndex* pprev,
                       const std::vector<CTransaction>& vExtra)
    {
        CBlock block;
        block.nVersion = 1;
        block.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
        // Inside the wallet-birthday window, or the scan skips the block before it
        // reaches the shielded step.
        block.nTime = (unsigned int)(GetTime() - 600 + nHeight);
        block.nBits = bnProofOfWorkLimit.GetCompact();
        block.nNonce = 0;

        CTransaction coinbase;
        coinbase.nTime = block.nTime;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript() << nHeight;
        coinbase.vout.push_back(CTxOut(0, CScript() << OP_TRUE));
        block.vtx.push_back(coinbase);
        for (size_t i = 0; i < vExtra.size(); ++i)
            block.vtx.push_back(vExtra[i]);
        block.hashMerkleRoot = block.BuildMerkleTree();
        while (!CheckProofOfWork(block.GetPoWHash(), block.nBits))
            ++block.nNonce;

        unsigned int nFile = 0;
        unsigned int nBlockPos = 0;
        BOOST_REQUIRE(block.WriteToDisk(nFile, nBlockPos));

        const uint256 hash = block.GetHash();
        CBlockIndex* pindex = new CBlockIndex(nFile, nBlockPos, block);
        pindex->nHeight = nHeight;
        pindex->pprev = pprev;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(hash, pindex));
        BOOST_REQUIRE(ins.second);
        pindex->phashBlock = &ins.first->first;
        if (pprev)
            pprev->pnext = pindex;

        {
            CTxDB txdb("r+");
            BOOST_REQUIRE(txdb.WriteShieldedTreeAtBlock(hash,
                                                        CIncrementalMerkleTree()));
            BOOST_REQUIRE(txdb.WriteCurveTreeAtBlock(hash, CCurveTree()));
        }

        vHashes.push_back(hash);
        vIndex.push_back(pindex);
        pindexBest = pindex;
        nBestHeight = nHeight;
        return pindex;
    }

    void Add(int nHeight) { Add(nHeight, std::vector<CTransaction>()); }

    // Drops the snapshot the shielded scan needs, which is a scan failure that has
    // nothing to do with a locked seed.
    void RemoveShieldedSnapshot(size_t i)
    {
        CTxDB txdb("r+");
        BOOST_REQUIRE(txdb.EraseShieldedTreeAtBlock(vHashes[i]));
    }
};

// A v2008 transaction carrying a payload. Only presence matters here: the scan reaches
// the locked seed before it ever looks at the bytes.
CTransaction PayloadTx(unsigned char nSeed)
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_DSP;
    tx.nTime = (unsigned int)GetTime();
    tx.privacyVNext.vchPayload.assign(64, nSeed);
    tx.privacyVNext.SetPresent();
    return tx;
}

// bitdb runs mock in the unit harness and backs every wallet name with one in-memory
// database, so a second file name is not a second wallet. Every case uses this one and
// resets the state it reads.
const char* const kWalletFile = "iv5rescan.dat";

// A canonical seed record with no seed bytes: exactly what LoadWallet leaves behind for
// an encrypted wallet, and what the daemon holds while the startup rescan runs.
CPrivacyVNextSeedRecord LockedSeedRecord()
{
    CPrivacyVNextSeedRecord record;
    record.nGeneration = PRIVACY_VNEXT_WALLET_SEED_GENERATION;
    record.vchCryptedSeed.assign(PRIVACY_VNEXT_WALLET_SEED_CIPHERTEXT_SIZE, 0x5a);
    record.hashSeedCommitment = uint256(0x1234abcdULL);
    record.nNextAddressIndex = 1;
    return record;
}

// A file-backed wallet on its own mock database file, so later "r+" opens succeed.
// Returns the key the transparent scan must find. LoadWallet is not called, to avoid
// depending on other suites' data in the shared mock database.
void OpenWallet(CWallet& wallet)
{
    BOOST_REQUIRE(wallet.fFileBacked);
    wallet.ClearPrivacyVNextScanGap(0);
    BOOST_REQUIRE_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), -1);
    BOOST_REQUIRE(wallet.PrivacyVNextScanGapIsPersisted());
}

CPubKey OpenLockedWallet(CWallet& wallet)
{
    OpenWallet(wallet);
    std::string strError;
    BOOST_REQUIRE_MESSAGE(wallet.LoadPrivacyVNextSeedRecord(LockedSeedRecord(),
                                                            strError),
                          strError);
    BOOST_REQUIRE(wallet.HasPrivacyVNextSeed());
    BOOST_REQUIRE(!wallet.IsPrivacyVNextSeedUnlocked());

    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(wallet.AddKeyPubKey(key, pubkey));
    return pubkey;
}

CTransaction PaymentTo(const CPubKey& pubkey, unsigned char nSeed)
{
    CTransaction tx;
    tx.nVersion = 1;
    tx.nTime = (unsigned int)GetTime();
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = uint256(0x5150000ULL + nSeed);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    CScript scriptPubKey;
    scriptPubKey.SetDestination(pubkey.GetID());
    tx.vout.push_back(CTxOut(1 * COIN, scriptPubKey));
    return tx;
}

} // namespace

// A locked wallet rescanning past a payload block records the gap and continues,
// still picking up a transparent payment in a later block.
BOOST_AUTO_TEST_CASE(a_locked_seed_leaves_a_recorded_gap_and_does_not_fail_the_rescan)
{
    RescanChain chain;
    CWallet wallet(kWalletFile);
    const CPubKey pubkey = OpenLockedWallet(wallet);

    chain.Add(3);
    chain.Add(4, std::vector<CTransaction>(1, PayloadTx(0x11)));
    chain.Add(5, std::vector<CTransaction>(1, PaymentTo(pubkey, 1)));
    chain.Add(6);

    int nFound = -1;
    std::string strError;
    BOOST_CHECK_MESSAGE(wallet.ScanForWalletTransactionsChecked(chain.Head(), true,
                                                                nFound, strError),
                        "locked-seed rescan failed: " + strError);
    BOOST_CHECK_EQUAL(strError, std::string(""));
    BOOST_CHECK_EQUAL(nFound, 1);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), 4);
    BOOST_CHECK(wallet.PrivacyVNextScanGapIsPersisted());

    // Durable, not merely in memory: the wallet file itself carries the height.
    int nOnDisk = -99;
    BOOST_CHECK(CWalletDB(kWalletFile, "r").ReadPrivacyVNextScanGap(nOnDisk));
    BOOST_CHECK_EQUAL(nOnDisk, 4);
}

// The same wallet over a span with no payloads: nothing to leave unscanned, so no gap.
BOOST_AUTO_TEST_CASE(a_payload_free_span_leaves_no_gap_on_a_locked_wallet)
{
    RescanChain chain;
    CWallet wallet(kWalletFile);
    const CPubKey pubkey = OpenLockedWallet(wallet);

    chain.Add(3);
    chain.Add(4, std::vector<CTransaction>(1, PaymentTo(pubkey, 2)));
    chain.Add(5);

    int nFound = -1;
    std::string strError;
    BOOST_CHECK_MESSAGE(wallet.ScanForWalletTransactionsChecked(chain.Head(), true,
                                                                nFound, strError),
                        "payload-free rescan failed: " + strError);
    BOOST_CHECK_EQUAL(nFound, 1);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), -1);
}

// Degrading is for the locked seed and nothing else. A missing per-block snapshot is a
// damaged chain database, and a gap already standing from an earlier block must not turn
// it into a skipped block.
BOOST_AUTO_TEST_CASE(a_failure_that_is_not_a_locked_seed_still_fails_the_rescan)
{
    RescanChain chain;
    CWallet wallet(kWalletFile);
    OpenLockedWallet(wallet);

    chain.Add(3);
    chain.Add(4, std::vector<CTransaction>(1, PayloadTx(0x22)));  // records the gap
    chain.Add(5);
    chain.RemoveShieldedSnapshot(2);                              // damages height 5

    int nFound = -1;
    std::string strError;
    BOOST_CHECK(!wallet.ScanForWalletTransactionsChecked(chain.Head(), true, nFound,
                                                         strError));
    BOOST_CHECK_MESSAGE(
        strError.find("predecessor shielded-tree snapshot") != std::string::npos,
        "expected the snapshot failure to be reported, got: " + strError);
    BOOST_CHECK_MESSAGE(strError.find("at height 5") != std::string::npos,
                        "expected the failure to name height 5, got: " + strError);
}

// A gap that never reached the wallet file is not a gap. The locator is written at the
// tip right after the rescan, so a start that degraded on an unpersisted mark would come
// back believing the block was scanned. Fail closed instead.
BOOST_AUTO_TEST_CASE(a_gap_that_could_not_be_persisted_fails_the_rescan_closed)
{
    RescanChain chain;
    CWallet wallet(kWalletFile);
    OpenLockedWallet(wallet);

    // Marking reports whether the write landed, and a wallet file that took it says so.
    BOOST_CHECK(wallet.MarkPrivacyVNextScanGap(4));
    BOOST_CHECK(wallet.PrivacyVNextScanGapIsPersisted());

    // The state a failed wallet write leaves behind: the gap is known to this process
    // and to nothing else. Set directly, because the mock database this harness runs on
    // has no failing write to provoke.
    wallet.fPrivacyVNextScanGapPersisted = false;

    chain.Add(3);
    chain.Add(4, std::vector<CTransaction>(1, PayloadTx(0x33)));
    chain.Add(5);

    int nFound = -1;
    std::string strError;
    BOOST_CHECK(!wallet.ScanForWalletTransactionsChecked(chain.Head(), true, nFound,
                                                         strError));
    BOOST_CHECK_MESSAGE(strError.find("IV5 seed is locked") != std::string::npos,
                        "expected the locked-seed failure, got: " + strError);
    // Re-marking the same height must not silently upgrade the mark to persisted.
    BOOST_CHECK(!wallet.PrivacyVNextScanGapIsPersisted());
}

// A wallet with no file behind it has nothing to persist to and nothing to lose across a
// restart, so its mark is durable by construction.
BOOST_AUTO_TEST_CASE(a_memory_only_wallet_records_its_gap_as_persisted)
{
    CWallet wallet;
    BOOST_REQUIRE(!wallet.fFileBacked);
    std::string strSeedError;
    BOOST_REQUIRE(wallet.LoadPrivacyVNextSeedRecord(LockedSeedRecord(), strSeedError));
    BOOST_CHECK(wallet.MarkPrivacyVNextScanGap(7));
    BOOST_CHECK(wallet.PrivacyVNextScanGapIsPersisted());
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), 7);
    // Lowest height wins, and the answer stays the recorded one.
    BOOST_CHECK(wallet.MarkPrivacyVNextScanGap(9));
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), 7);
}

// While the gap stands the note view is incomplete, so the wallet refuses to build an
// IV5 spend over it -- an unlocked seed is not enough. Clearing the gap lets the builder
// move on to its next check.
BOOST_AUTO_TEST_CASE(an_iv5_spend_is_refused_while_a_scan_gap_is_recorded)
{
    CWallet wallet(kWalletFile);
    OpenWallet(wallet);
    // Unlocked: the seed bytes are present, which is what a spend normally needs.
    wallet.vchPrivacyVNextSeed.assign(32, 0x77);
    BOOST_REQUIRE(wallet.IsPrivacyVNextSeedUnlocked());

    BOOST_CHECK(wallet.MarkPrivacyVNextScanGap(4));
    std::string strGapError;
    BOOST_CHECK(wallet.PrivacyVNextScanGapBlocksSpend(strGapError));
    BOOST_CHECK_MESSAGE(
        strGapError == "an IV5 scan gap is recorded at height 4; run z_rescaniv5",
        "unexpected gap message: " + strGapError);

    CWalletTx wtx;
    int64_t nFee = 0;
    size_t nNotes = 0;
    std::string strError;
    BOOST_CHECK(!wallet.CreatePrivacyVNextTransfer("iv5address", 1 * COIN, 0, false,
                                                   wtx, nFee, nNotes, strError));
    BOOST_CHECK_MESSAGE(strError == strGapError,
                        "expected the spend to be refused for the gap, got: " + strError);

    // Only a rescan that covered the gap clears it; the builder then gets past this check
    // and fails on something else.
    wallet.ClearPrivacyVNextScanGap(0);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), -1);
    BOOST_CHECK(!wallet.PrivacyVNextScanGapBlocksSpend(strGapError));

    strError.clear();
    BOOST_CHECK(!wallet.CreatePrivacyVNextTransfer("iv5address", 1 * COIN, 0, false,
                                                   wtx, nFee, nNotes, strError));
    BOOST_CHECK_MESSAGE(strError != strGapError && !strError.empty(),
                        "expected a different refusal once the gap was cleared, got: " +
                            strError);
    BOOST_CHECK_MESSAGE(strError.find("scan gap") == std::string::npos,
                        "the gap refusal outlived the gap: " + strError);
}

// A wallet with no IV5 seed records no scan gap: it owns no note, and a gap it cannot
// close would block startup.
BOOST_AUTO_TEST_CASE(a_wallet_with_no_iv5_seed_records_no_gap)
{
    CWallet wallet(kWalletFile);
    OpenWallet(wallet);
    BOOST_REQUIRE(!wallet.HasPrivacyVNextSeed());
    BOOST_REQUIRE(!wallet.IsPrivacyVNextSeedUnlocked());

    BOOST_CHECK(wallet.MarkPrivacyVNextScanGap(329));
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), -1);
    BOOST_CHECK(wallet.PrivacyVNextScanGapIsPersisted());

    // And nothing reached the wallet file either, so a restart finds no gap to close.
    int nOnDisk = -99;
    if (CWalletDB(kWalletFile, "r").ReadPrivacyVNextScanGap(nOnDisk))
        BOOST_CHECK_EQUAL(nOnDisk, -1);
}

// An unlock only marks the gap closable and reads no block: it runs under the RPC
// dispatcher's cs_main and cs_wallet.
BOOST_AUTO_TEST_CASE(requesting_a_gap_close_reads_no_block)
{
    RescanChain chain;
    CWallet wallet(kWalletFile);
    OpenWallet(wallet);
    wallet.vchPrivacyVNextSeed.assign(32, 0x33);
    BOOST_REQUIRE(wallet.IsPrivacyVNextSeedUnlocked());

    chain.Add(3);
    chain.Add(4);
    chain.Add(5);
    pindexGenesisBlock = chain.Head();

    BOOST_CHECK(wallet.MarkPrivacyVNextScanGap(3));

    int nGap = -1;
    std::string strError;
    BOOST_CHECK_MESSAGE(wallet.RequestPrivacyVNextScanGapClose(nGap, strError),
                        "gap close request refused: " + strError);
    BOOST_CHECK_EQUAL(nGap, 3);
    // Nothing was reprocessed: the gap still stands and the job is only queued.
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), 3);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapCloseStatus(), std::string("pending"));
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapCloseBlocks(), 0);
    BOOST_CHECK(wallet.PrivacyVNextScanGapCloseIsPending());

    // A request with no gap outstanding queues nothing.
    wallet.ClearPrivacyVNextScanGap(0);
    nGap = 0;
    BOOST_CHECK(wallet.RequestPrivacyVNextScanGapClose(nGap, strError));
    BOOST_CHECK_EQUAL(nGap, -1);
    BOOST_CHECK(!wallet.PrivacyVNextScanGapCloseIsPending());
}

// The half that reads, which is what the closer thread runs. Init's own close can never
// fire for an encrypted wallet, so this is the only route back to a note in the gap.
BOOST_AUTO_TEST_CASE(the_closer_reprocesses_the_recorded_gap_and_clears_it)
{
    RescanChain chain;
    CWallet wallet(kWalletFile);
    OpenWallet(wallet);
    wallet.vchPrivacyVNextSeed.assign(32, 0x33);
    BOOST_REQUIRE(wallet.IsPrivacyVNextSeedUnlocked());

    chain.Add(3);
    chain.Add(4);
    chain.Add(5);
    pindexGenesisBlock = chain.Head();

    BOOST_CHECK(wallet.MarkPrivacyVNextScanGap(3));
    int nGap = -1;
    std::string strError;
    BOOST_REQUIRE(wallet.RequestPrivacyVNextScanGapClose(nGap, strError));

    int nBlocks = -1;
    BOOST_CHECK_MESSAGE(wallet.RunPrivacyVNextScanGapClose(nGap, nBlocks, strError),
                        "gap close failed: " + strError);
    BOOST_CHECK_EQUAL(nGap, 3);
    BOOST_CHECK_EQUAL(nBlocks, 3);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), -1);
    // What an operator reads to know it finished, without going through the log.
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapCloseStatus(),
                      std::string("complete"));
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapCloseBlocks(), 3);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapCloseError(), std::string(""));
    BOOST_CHECK(!wallet.PrivacyVNextScanGapCloseIsPending());

    // Nothing outstanding: a second run is a no-op rather than a rescan.
    nGap = 0;
    nBlocks = -1;
    BOOST_CHECK(wallet.RunPrivacyVNextScanGapClose(nGap, nBlocks, strError));
    BOOST_CHECK_EQUAL(nGap, -1);
    BOOST_CHECK_EQUAL(nBlocks, 0);
}

// A close without a seed fails and leaves the gap where it was; the next unlock
// requests it again.
BOOST_AUTO_TEST_CASE(a_gap_close_without_a_seed_fails_and_leaves_the_gap_standing)
{
    RescanChain chain;
    CWallet wallet(kWalletFile);
    OpenLockedWallet(wallet);
    BOOST_REQUIRE(!wallet.IsPrivacyVNextSeedUnlocked());

    chain.Add(3);
    chain.Add(4);
    pindexGenesisBlock = chain.Head();

    BOOST_CHECK(wallet.MarkPrivacyVNextScanGap(3));

    // A locked wallet cannot even queue the close.
    int nGap = -1;
    std::string strError;
    BOOST_CHECK(!wallet.RequestPrivacyVNextScanGapClose(nGap, strError));
    BOOST_CHECK_MESSAGE(strError.find("must be unlocked") != std::string::npos,
                        "expected the locked-seed refusal, got: " + strError);
    BOOST_CHECK(!wallet.PrivacyVNextScanGapCloseIsPending());

    // And a close driven anyway -- the wallet relocking after the request, which is
    // exactly what a short unlock timeout does -- fails without dropping the gap.
    int nBlocks = -1;
    BOOST_CHECK(!wallet.RunPrivacyVNextScanGapClose(nGap, nBlocks, strError));
    BOOST_CHECK_MESSAGE(strError.find("must be unlocked") != std::string::npos,
                        "expected the locked-seed refusal, got: " + strError);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), 3);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapCloseStatus(), std::string("failed"));
    BOOST_CHECK(!wallet.GetPrivacyVNextScanGapCloseError().empty());

    // The next unlock re-arms it, and the close then completes over the same span.
    wallet.vchPrivacyVNextSeed.assign(32, 0x44);
    BOOST_REQUIRE(wallet.IsPrivacyVNextSeedUnlocked());
    BOOST_CHECK(wallet.RequestPrivacyVNextScanGapClose(nGap, strError));
    BOOST_CHECK_EQUAL(nGap, 3);
    BOOST_CHECK(wallet.PrivacyVNextScanGapCloseIsPending());
    BOOST_CHECK_MESSAGE(wallet.RunPrivacyVNextScanGapClose(nGap, nBlocks, strError),
                        "re-armed gap close failed: " + strError);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), -1);
}

namespace {

// walletpassphrase acts on the pwalletMain global and spawns detached threads that read
// it after the call returns, so the wallet those cases install is never destroyed and
// the global is put back when the case ends.
struct MainWalletSwap
{
    CWallet* pSaved;
    explicit MainWalletSwap(CWallet* pNew) : pSaved(pwalletMain) { pwalletMain = pNew; }
    ~MainWalletSwap() { pwalletMain = pSaved; }
};

// A genuinely encrypted wallet, built without EncryptWallet: that rewrites the wallet
// file, and every case in this binary shares one mock database. Unlock() needs only a
// master key the passphrase opens and one crypted key to verify it against.
CWallet* NewCryptedWallet(const SecureString& strPass,
                          CKeyingMaterial& vMasterKeyOut)
{
    CWallet* pwallet = new CWallet(kWalletFile);

    CKeyingMaterial vMasterKey(WALLET_CRYPTO_KEY_SIZE);
    BOOST_REQUIRE(RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE) == 1);

    CMasterKey kMasterKey(0);
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    BOOST_REQUIRE(RAND_bytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE) == 1);
    // The floor CWallet::Unlock enforces; anything lower triggers its rewrite path.
    kMasterKey.nDeriveIterations = 25000;
    kMasterKey.nDerivationMethod = 0;

    CCrypter crypter;
    BOOST_REQUIRE(crypter.SetKeyFromPassphrase(strPass, kMasterKey.vchSalt,
                                               kMasterKey.nDeriveIterations,
                                               kMasterKey.nDerivationMethod));
    BOOST_REQUIRE(crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey));
    pwallet->mapMasterKeys[++pwallet->nMasterKeyMaxID] = kMasterKey;

    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    CSecret secret(key.begin(), key.end());
    std::vector<unsigned char> vchCrypted;
    BOOST_REQUIRE(EncryptSecret(vMasterKey, secret, pubkey.GetHash(), vchCrypted));
    BOOST_REQUIRE(pwallet->LoadCryptedKey(pubkey, vchCrypted));

    BOOST_REQUIRE(pwallet->IsCrypted());
    BOOST_REQUIRE(pwallet->IsLocked());
    vMasterKeyOut = vMasterKey;
    return pwallet;
}

// The IV the wallet seals an IV5 seed under. Recomputed here because the wallet's own
// copy is file-local; a change to the domain string breaks Unlock() in these cases
// loudly rather than silently.
uint256 Iv5SeedEncryptionIV()
{
    CHashWriter writer(SER_GETHASH, 0);
    writer << std::string("Innova/IV5/WalletSeedEncryption/v1");
    return writer.GetHash();
}

// Seal a fresh IV5 seed under the master key and load it in memory. Not via
// CreatePrivacyVNextSeed: the shared mock database may already hold an "iv5seed".
void AddSealedIv5Seed(CWallet& wallet, CKeyingMaterial& vMasterKey)
{
    CSecret seed(32, 0);
    BOOST_REQUIRE(RAND_bytes(&seed[0], seed.size()) == 1);

    CPrivacyVNextSeedRecord record;
    record.nGeneration = PRIVACY_VNEXT_WALLET_SEED_GENERATION;
    record.hashSeedCommitment = Hash(seed.begin(), seed.end());
    record.nNextAddressIndex = 0;
    BOOST_REQUIRE(EncryptSecret(vMasterKey, seed, Iv5SeedEncryptionIV(),
                                record.vchCryptedSeed));
    BOOST_REQUIRE_EQUAL(record.vchCryptedSeed.size(),
                        PRIVACY_VNEXT_WALLET_SEED_CIPHERTEXT_SIZE);
    OPENSSL_cleanse(&seed[0], seed.size());

    std::string strError;
    BOOST_REQUIRE_MESSAGE(wallet.LoadPrivacyVNextSeedRecord(record, strError),
                          strError);
}

const char* const kRpcPassphrase = "rescancasepass";

// One encrypted wallet for both RPC cases, built on first use and never destroyed. Two
// would not work: the seed record is written no-overwrite, and every wallet name in this
// binary is backed by the same mock database. Comes back locked, as one starts.
CWallet* CryptedRpcWallet()
{
    static CWallet* pwallet = NULL;
    if (pwallet)
    {
        // A case that aborted part way could have left it open.
        pwallet->Lock();
        return pwallet;
    }
    const SecureString strPass(kRpcPassphrase);
    CKeyingMaterial vMasterKey;
    pwallet = NewCryptedWallet(strPass, vMasterKey);
    AddSealedIv5Seed(*pwallet, vMasterKey);
    BOOST_REQUIRE(pwallet->HasPrivacyVNextSeed());
    BOOST_REQUIRE(!pwallet->IsPrivacyVNextSeedUnlocked());
    return pwallet;
}

json_spirit::Array UnlockParams(const json_spirit::Value& timeout)
{
    json_spirit::Array params;
    params.push_back(std::string(kRpcPassphrase));
    params.push_back(timeout);
    return params;
}

// Stop the relock timer the unlock armed and wait for the threads it spawned to run
// out, so nothing is still touching the global when the case ends.
void QuiesceUnlockThreads()
{
    walletlock(json_spirit::Array(), false);
    MilliSleep(1500);
}

} // namespace

// The promptness pin, at the RPC itself. The chain below is one the close walks
// successfully, so an unlock that did the reading would come back with the gap already
// cleared. It must come back with the gap still recorded and the job merely queued.
BOOST_AUTO_TEST_CASE(unlocking_queues_the_gap_close_instead_of_running_it)
{
    RescanChain chain;
    CWallet* pwallet = CryptedRpcWallet();
    MainWalletSwap swap(pwallet);
    pwallet->ClearPrivacyVNextScanGap(0);

    chain.Add(3);
    chain.Add(4);
    chain.Add(5);
    pindexGenesisBlock = chain.Head();
    BOOST_REQUIRE(pwallet->MarkPrivacyVNextScanGap(3));

    // One key, so the keypool thread the unlock starts is over at once.
    const std::string strSavedKeypool = mapArgs.count("-keypool") ? mapArgs["-keypool"]
                                                                  : std::string();
    const bool fHadKeypool = mapArgs.count("-keypool") > 0;
    mapArgs["-keypool"] = "0";

    walletpassphrase(UnlockParams(json_spirit::Value((int64_t)1)), false);

    BOOST_CHECK(!pwallet->IsLocked());
    BOOST_CHECK(pwallet->IsPrivacyVNextSeedUnlocked());
    // The reading did not happen on this thread.
    BOOST_CHECK_EQUAL(pwallet->GetPrivacyVNextScanGapHeight(), 3);
    BOOST_CHECK_EQUAL(pwallet->GetPrivacyVNextScanGapCloseStatus(),
                      std::string("pending"));
    BOOST_CHECK_EQUAL(pwallet->GetPrivacyVNextScanGapCloseBlocks(), 0);
    BOOST_CHECK(pwallet->PrivacyVNextScanGapCloseIsPending());

    // And the queued job is real work: the closer thread's own step closes it.
    int nGap = -1;
    int nBlocks = -1;
    std::string strError;
    BOOST_CHECK_MESSAGE(pwallet->RunPrivacyVNextScanGapClose(nGap, nBlocks, strError),
                        "queued gap close failed: " + strError);
    BOOST_CHECK_EQUAL(nGap, 3);
    BOOST_CHECK_EQUAL(nBlocks, 3);
    BOOST_CHECK_EQUAL(pwallet->GetPrivacyVNextScanGapHeight(), -1);

    QuiesceUnlockThreads();
    if (fHadKeypool)
        mapArgs["-keypool"] = strSavedKeypool;
    else
        mapArgs.erase("-keypool");
}

// An unlock that throws after the seed reached memory leaves the wallet locked. A
// non-integer timeout is the reachable throw.
BOOST_AUTO_TEST_CASE(an_unlock_that_throws_leaves_the_wallet_locked)
{
    const SecureString strPass(kRpcPassphrase);
    CWallet* pwallet = CryptedRpcWallet();
    MainWalletSwap swap(pwallet);

    const bool fStakingOnlyBefore = fWalletUnlockStakingOnly;

    BOOST_CHECK_THROW(
        walletpassphrase(UnlockParams(json_spirit::Value(std::string("later"))), false),
        std::exception);

    BOOST_CHECK(pwallet->IsLocked());
    BOOST_CHECK(!pwallet->IsPrivacyVNextSeedUnlocked());
    BOOST_CHECK_EQUAL(fWalletUnlockStakingOnly, fStakingOnlyBefore);

    // The wallet is usable again afterwards: the relock is a rollback, not damage.
    BOOST_CHECK(pwallet->Unlock(strPass));
    BOOST_CHECK(pwallet->IsPrivacyVNextSeedUnlocked());
    BOOST_CHECK(pwallet->Lock());
}

// Unlock paths other than walletpassphrase (Qt dialogs, collateralnode RPCs) also arm
// the gap close.
BOOST_AUTO_TEST_CASE(an_unlock_outside_the_rpc_still_arms_the_gap_close)
{
    RescanChain chain;
    const SecureString strPass(kRpcPassphrase);
    CWallet* pwallet = CryptedRpcWallet();
    MainWalletSwap swap(pwallet);
    pwallet->ClearPrivacyVNextScanGap(0);
    BOOST_REQUIRE_EQUAL(pwallet->GetPrivacyVNextScanGapHeight(), -1);

    chain.Add(3);
    chain.Add(4);
    chain.Add(5);
    pindexGenesisBlock = chain.Head();
    BOOST_REQUIRE(pwallet->MarkPrivacyVNextScanGap(3));

    // Not walletpassphrase: the call the Qt dialogs and the collateralnode RPCs make.
    BOOST_REQUIRE(pwallet->Unlock(strPass));
    BOOST_CHECK(pwallet->IsPrivacyVNextSeedUnlocked());

    BOOST_CHECK_EQUAL(pwallet->GetPrivacyVNextScanGapCloseStatus(),
                      std::string("pending"));
    BOOST_CHECK(pwallet->PrivacyVNextScanGapCloseIsPending());
    // Still only a request: the unlock did no reading on its own thread.
    BOOST_CHECK_EQUAL(pwallet->GetPrivacyVNextScanGapHeight(), 3);
    BOOST_CHECK_EQUAL(pwallet->GetPrivacyVNextScanGapCloseBlocks(), 0);

    // And the queued job is the real work.
    int nGap = -1;
    int nBlocks = -1;
    std::string strError;
    BOOST_CHECK_MESSAGE(pwallet->RunPrivacyVNextScanGapClose(nGap, nBlocks, strError),
                        "queued gap close failed: " + strError);
    BOOST_CHECK_EQUAL(nGap, 3);
    BOOST_CHECK_EQUAL(pwallet->GetPrivacyVNextScanGapHeight(), -1);

    BOOST_CHECK(pwallet->Lock());
}

// A gap recorded by block connection during the walk survives the walk's clear; only
// the covered range is retired.
BOOST_AUTO_TEST_CASE(a_gap_recorded_during_the_walk_survives_the_clear)
{
    CWallet wallet(kWalletFile);
    OpenWallet(wallet);
    wallet.vchPrivacyVNextSeed.assign(32, 0x55);
    BOOST_REQUIRE(wallet.IsPrivacyVNextSeedUnlocked());

    BOOST_REQUIRE(wallet.MarkPrivacyVNextScanGap(3));
    {
        // The window the walk runs in, opened exactly as RescanPrivacyVNextBlocks
        // opens it.
        CWallet::CPrivacyVNextScanGapWalk walk(wallet);
        BOOST_REQUIRE(wallet.PrivacyVNextScanGapWalkIsActive());

        // A block connected while the walk reads, whose payloads went unscanned.
        BOOST_CHECK(wallet.MarkPrivacyVNextScanGap(9));
        // The recorded height does not move: 3 is already lower, so nothing but the
        // walk record is holding height 9.
        BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), 3);
        BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapWalkMark(), 9);

        // The walk covered from 3. It did not cover 9.
        wallet.ClearPrivacyVNextScanGap(3);
        BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), 9);
    }
    BOOST_CHECK(!wallet.PrivacyVNextScanGapWalkIsActive());
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), 9);

    // Durable, and still refusing spends: an in-memory survivor would die with the
    // process and the next start would call height 9 scanned.
    BOOST_CHECK(wallet.PrivacyVNextScanGapIsPersisted());
    int nOnDisk = -99;
    BOOST_CHECK(CWalletDB(kWalletFile, "r").ReadPrivacyVNextScanGap(nOnDisk));
    BOOST_CHECK_EQUAL(nOnDisk, 9);
    std::string strGapError;
    BOOST_CHECK(wallet.PrivacyVNextScanGapBlocksSpend(strGapError));

    // A walk that covered everything still clears everything.
    wallet.ClearPrivacyVNextScanGap(0);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), -1);
}

namespace {

// Blocks the wallet's seed reads by holding the lock they take, so a case can put a
// concurrent walk at a known point instead of racing it. cs_wallet is what
// CWallet::Lock() clears the seed under and what a scan copies it under.
struct SeedLockHold
{
    CWallet& wallet;
    explicit SeedLockHold(CWallet& walletIn) : wallet(walletIn)
    {
        ENTER_CRITICAL_SECTION(wallet.cs_wallet);
    }
    ~SeedLockHold() { LEAVE_CRITICAL_SECTION(wallet.cs_wallet); }
};

// Spin until the walk is inside its window, which it enters before its first seed read.
// Bounded so a case fails rather than hangs.
bool WaitForWalk(CWallet& wallet)
{
    for (int i = 0; i < 2000; ++i)
    {
        if (wallet.PrivacyVNextScanGapWalkIsActive())
            return true;
        MilliSleep(5);
    }
    return false;
}

struct GapCloseResult
{
    std::atomic<bool> fDone;
    bool fOk;
    int nGap;
    int nBlocks;
    std::string strError;
    GapCloseResult() : fDone(false), fOk(false), nGap(-1), nBlocks(-1) {}
};

void RunGapClose(CWallet* pwallet, GapCloseResult* pResult)
{
    pResult->fOk = pwallet->RunPrivacyVNextScanGapClose(
        pResult->nGap, pResult->nBlocks, pResult->strError);
    pResult->fDone = true;
}

} // namespace

// Same failure via the closer thread. Holding cs_wallet parks the walk on its first
// seed read, so the mark lands inside its window by construction.
BOOST_AUTO_TEST_CASE(a_gap_recorded_while_the_closer_walks_survives_the_close)
{
    RescanChain chain;
    CWallet wallet(kWalletFile);
    OpenWallet(wallet);
    wallet.vchPrivacyVNextSeed.assign(32, 0x66);
    BOOST_REQUIRE(wallet.IsPrivacyVNextSeedUnlocked());

    chain.Add(3);
    chain.Add(4);
    chain.Add(5);
    pindexGenesisBlock = chain.Head();
    BOOST_REQUIRE(wallet.MarkPrivacyVNextScanGap(3));

    GapCloseResult result;
    boost::thread closer;
    {
        SeedLockHold hold(wallet);
        closer = boost::thread(RunGapClose, &wallet, &result);
        BOOST_REQUIRE_MESSAGE(WaitForWalk(wallet),
                              "the close never entered its walk window");
        BOOST_REQUIRE(!result.fDone.load());

        // Block connection, running beside the walk. It needs no lock this hold
        // covers, which is exactly why it can land here.
        BOOST_CHECK(wallet.MarkPrivacyVNextScanGap(9));
        BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapWalkMark(), 9);
    }
    closer.join();

    BOOST_CHECK_MESSAGE(result.fOk, "gap close failed: " + result.strError);
    BOOST_CHECK_EQUAL(result.nGap, 3);
    BOOST_CHECK_EQUAL(result.nBlocks, 3);
    // The walk covered 3 to 5 and retired that. Height 9 it never read.
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), 9);
    int nOnDisk = -99;
    BOOST_CHECK(CWalletDB(kWalletFile, "r").ReadPrivacyVNextScanGap(nOnDisk));
    BOOST_CHECK_EQUAL(nOnDisk, 9);

    // And it is not reported finished with work outstanding: the job re-arms so the
    // closer thread takes another pass, without an operator having to notice.
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapCloseStatus(), std::string("pending"));
    BOOST_CHECK(wallet.PrivacyVNextScanGapCloseIsPending());
    std::string strGapError;
    BOOST_CHECK(wallet.PrivacyVNextScanGapBlocksSpend(strGapError));

    wallet.ClearPrivacyVNextScanGap(0);
}

namespace {

struct ApplyBlockResult
{
    std::atomic<bool> fDone;
    bool fOk;
    bool fSeedLocked;
    std::string strError;
    ApplyBlockResult() : fDone(false), fOk(false), fSeedLocked(false) {}
};

void RunApplyBlock(CWallet* pwallet, const CBlock* pblock, const CBlockIndex* pindex,
                   ApplyBlockResult* pResult)
{
    std::set<uint256> setNoneSkipped;
    pResult->fOk = pwallet->ApplyPrivacyVNextBlock(*pblock, setNoneSkipped, pindex,
                                                   pResult->strError,
                                                   &pResult->fSeedLocked);
    pResult->fDone = true;
}

} // namespace

// The scan's seed read takes cs_wallet, the lock CWallet::Lock() clears the seed under,
// so the copy is whole or refused.
BOOST_AUTO_TEST_CASE(the_scans_seed_read_waits_on_the_lock_that_clears_it)
{
    RescanChain chain;
    CWallet wallet(kWalletFile);
    OpenLockedWallet(wallet);

    CBlockIndex* pindex = chain.Add(4, std::vector<CTransaction>(1, PayloadTx(0x44)));
    CBlock block;
    BOOST_REQUIRE(block.ReadFromDisk(pindex, true));

    ApplyBlockResult result;
    boost::thread scanner;
    {
        SeedLockHold hold(wallet);
        scanner = boost::thread(RunApplyBlock, &wallet, &block, pindex, &result);
        MilliSleep(500);
        BOOST_CHECK_MESSAGE(!result.fDone.load(),
                            "the scan read the seed without the lock that clears it");
    }
    scanner.join();

    // And once it does read: a clean refusal naming the block, with the gap recorded.
    BOOST_CHECK(result.fDone.load());
    BOOST_CHECK(!result.fOk);
    BOOST_CHECK(result.fSeedLocked);
    BOOST_CHECK_MESSAGE(result.strError.find("IV5 seed is locked") != std::string::npos,
                        "expected the locked-seed refusal, got: " + result.strError);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), 4);

    wallet.ClearPrivacyVNextScanGap(0);
}

// A relock during a close, with the walk parked on its first seed read: the close is a
// clean refusal and the gap stands.
BOOST_AUTO_TEST_CASE(a_relock_during_the_close_is_a_clean_refusal)
{
    RescanChain chain;
    const SecureString strPass(kRpcPassphrase);
    CWallet* pwallet = CryptedRpcWallet();
    MainWalletSwap swap(pwallet);
    pwallet->ClearPrivacyVNextScanGap(0);

    chain.Add(3);
    chain.Add(4);
    chain.Add(5);
    pindexGenesisBlock = chain.Head();
    BOOST_REQUIRE(pwallet->MarkPrivacyVNextScanGap(3));
    BOOST_REQUIRE(pwallet->Unlock(strPass));
    BOOST_REQUIRE(pwallet->IsPrivacyVNextSeedUnlocked());
    BOOST_REQUIRE(pwallet->PrivacyVNextScanGapCloseIsPending());

    GapCloseResult result;
    boost::thread closer;
    {
        SeedLockHold hold(*pwallet);
        closer = boost::thread(RunGapClose, pwallet, &result);
        BOOST_REQUIRE_MESSAGE(WaitForWalk(*pwallet),
                              "the close never entered its walk window");
        BOOST_REQUIRE(!result.fDone.load());
        // The relock a short unlock timeout performs, while the walk waits on it.
        BOOST_REQUIRE(pwallet->Lock());
        BOOST_REQUIRE(!pwallet->IsPrivacyVNextSeedUnlocked());
    }
    closer.join();

    BOOST_CHECK(!result.fOk);
    BOOST_CHECK_MESSAGE(result.strError.find("must be unlocked") != std::string::npos,
                        "expected the locked-seed refusal, got: " + result.strError);
    BOOST_CHECK_EQUAL(pwallet->GetPrivacyVNextScanGapHeight(), 3);
    BOOST_CHECK_EQUAL(pwallet->GetPrivacyVNextScanGapCloseStatus(), std::string("failed"));
    BOOST_CHECK(!pwallet->GetPrivacyVNextScanGapCloseError().empty());

    // Nothing was lost: the next unlock re-arms the same work.
    BOOST_REQUIRE(pwallet->Unlock(strPass));
    BOOST_CHECK(pwallet->PrivacyVNextScanGapCloseIsPending());
    int nGap = -1;
    int nBlocks = -1;
    std::string strError;
    BOOST_CHECK_MESSAGE(pwallet->RunPrivacyVNextScanGapClose(nGap, nBlocks, strError),
                        "re-armed gap close failed: " + strError);
    BOOST_CHECK_EQUAL(nGap, 3);
    BOOST_CHECK_EQUAL(pwallet->GetPrivacyVNextScanGapHeight(), -1);
    BOOST_CHECK(pwallet->Lock());
}

namespace {

PrivacyVNextDigest FilledDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

// Canonical scalars: a small value, not a repeated byte, which overflows the order.
PrivacyVNextDigest SmallScalar(unsigned char low)
{
    PrivacyVNextDigest d;
    d.fill(0);
    d[0] = low;
    return d;
}

PrivacyVNextDigest ScanGenesis()
{
    PrivacyVNextDigest d;
    PrivacyVNextLocalGenesis(d.data());
    return d;
}

uint8_t ScanNetwork()
{
    return PrivacyVNextLocalNetworkId();
}

// What a carrier with no transparent side commits to.
PrivacyVNextDigest NoTransparentSide()
{
    PrivacyVNextDigest d;
    const uint256 binding = GetPrivacyVNextTransparentBinding(CTransaction());
    std::memcpy(d.data(), binding.begin(), 32);
    return d;
}

// Notes of one seed, placed in a tree and ready to be spent. A payload spending one of
// them carries its key image and pays the sender's change to an index the sender's own
// scan opens: the two writes a wallet makes when it applies the block.
struct FundedNotes
{
    PrivacyVNextDigest genesis;
    PrivacyVNextDerivedKeys keys;
    std::vector<PrivacyVNextSpendNote> vNotes;
    std::vector<PrivacyVNextDigest> vKeyImages;
    PrivacyVNextDigest finalizedRoot;
    uint64_t nTreeSize;
    uint64_t nAmount;
    FundedNotes() : nTreeSize(0), nAmount(8000) {}
};

void FundNotes(CTxDB& txdb, size_t nCount, const PrivacyVNextDigest& seed,
               FundedNotes& funded)
{
    std::string error;
    funded.genesis = ScanGenesis();
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(seed, funded.genesis, 0, ScanNetwork(), 0,
                               funded.keys, error),
        error);

    std::vector<PrivacyVNextEncryptedOutput> vFunding(nCount);
    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    for (size_t i = 0; i < nCount; ++i)
    {
        BOOST_REQUIRE_MESSAGE(
            EncryptPrivacyVNextNote(
                ScanNetwork(), 0, (uint32_t)i, funded.genesis,
                funded.keys.spendPublic, funded.keys.viewPublic,
                funded.keys.outgoingViewSecret,
                SmallScalar((unsigned char)(31 + i)),
                SmallScalar((unsigned char)(61 + i)), funded.nAmount,
                SmallScalar((unsigned char)(91 + i)),
                SmallScalar((unsigned char)(121 + i)), vFunding[i], error),
            error);
        vLeaves.push_back(vFunding[i].leaf);
    }

    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    BOOST_REQUIRE_MESSAGE(TrimPrivacyVNextTreeStore(txdb, 0, treeState, error), error);
    BOOST_REQUIRE_MESSAGE(GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, error),
                          error);

    std::vector<unsigned char> vchRoot;
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(treeState, vchRoot, funded.nTreeSize, error),
        error);
    BOOST_REQUIRE_EQUAL(funded.nTreeSize, (uint64_t)nCount);
    std::memcpy(funded.finalizedRoot.data(), &vchRoot[0], 32);

    std::vector<uint64_t> vTargets(nCount);
    for (size_t i = 0; i < nCount; ++i)
        vTargets[i] = (uint64_t)i;
    std::vector<unsigned char> vchPaths;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, funded.nTreeSize, treeState, vTargets,
                                  vchPaths, error),
        error);
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths,
                                            vWitnesses, treeRoot, error),
        error);

    funded.vNotes.resize(nCount);
    funded.vKeyImages.resize(nCount);
    for (size_t i = 0; i < nCount; ++i)
    {
        PrivacyVNextEncryptedNote onChain;
        onChain.nOutputIndex = (uint32_t)i;
        onChain.genesis = funded.genesis;
        onChain.leafO = vFunding[i].leaf.owner;
        onChain.leafC = vFunding[i].leaf.commitment;
        onChain.noteEphemeral = vFunding[i].noteEphemeral;
        onChain.tweakEphemeral = vFunding[i].tweakEphemeral;
        onChain.vchCiphertext = vFunding[i].vchRecipientCiphertext;
        PrivacyVNextScannedNote scanned;
        BOOST_REQUIRE_MESSAGE(
            ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, ScanNetwork(), 0, onChain,
                                 funded.keys.viewSecret, funded.keys.spendSecret,
                                 scanned, error),
            error);
        funded.vNotes[i].spendSecret = scanned.spendSecret;
        funded.vNotes[i].y = scanned.y;
        funded.vNotes[i].mask = scanned.mask;
        funded.vNotes[i].nAmount = scanned.nAmount;
        funded.vNotes[i].leaf = vFunding[i].leaf;
        funded.vNotes[i].vchWitnessRecord = vWitnesses[i].vchRecord;
        funded.vKeyImages[i] = scanned.keyImage;
    }
}

// A transfer of funded note `nNote` to a stranger, change back to the sender at the
// self-pay index the wallet's spend path would draw. The carrier the block holds.
CTransaction SpendWithChange(const FundedNotes& funded, size_t nNote,
                             const PrivacyVNextDigest& senderSeed)
{
    std::string error;
    PrivacyVNextDerivedKeys payee;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(FilledDigest(0x2e), funded.genesis, 0, ScanNetwork(),
                               0, payee, error),
        error);
    const std::vector<PrivacyVNextDigest> vSpent(1, funded.vKeyImages[nNote]);
    const uint32_t nChangeIndex = PrivacyVNextChangeIndexFor(
        funded.genesis, ScanNetwork(), NoTransparentSide(), vSpent);
    PrivacyVNextDerivedKeys change;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextChangeKeys(senderSeed, funded.genesis, ScanNetwork(),
                                     nChangeIndex, change, error),
        error);

    const uint64_t nPaid = 1500;
    const uint64_t nFee = 100;
    std::vector<PrivacyVNextNewOutput> outs(2);
    outs[0].recipient.nNetwork = ScanNetwork();
    outs[0].recipient.nAddressType = 0;
    outs[0].recipient.spendPublic = payee.spendPublic;
    outs[0].recipient.viewPublic = payee.viewPublic;
    outs[0].nAmount = nPaid;
    outs[1].recipient.nNetwork = ScanNetwork();
    outs[1].recipient.nAddressType = 0;
    outs[1].recipient.spendPublic = change.spendPublic;
    outs[1].recipient.viewPublic = change.viewPublic;
    outs[1].nAmount = funded.nAmount - nPaid - nFee;

    std::vector<unsigned char> payload;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextTransferPayload(
            ScanNetwork(), 7, funded.genesis, change.outgoingViewSecret,
            funded.finalizedRoot, funded.nTreeSize, NoTransparentSide(), nFee,
            std::vector<PrivacyVNextSpendNote>(1, funded.vNotes[nNote]), outs,
            payload, error),
        error);

    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_DSP;
    tx.privacyVNext.vchPayload = payload;
    tx.privacyVNext.SetPresent();
    return tx;
}

// A note the wallet already holds, known by its key image: what a spend in a scanned
// block marks spent.
CPrivacyVNextWalletNote HeldNote(const PrivacyVNextDigest& keyImage)
{
    CPrivacyVNextWalletNote note;
    note.txhash = uint256(0x4e07e0ULL);
    note.nOutputIndex = 0;
    note.nHeight = 0;
    note.fSpent = false;
    note.nAmount = 8000;
    note.vchKeyImage.assign(keyImage.begin(), keyImage.end());
    return note;
}

size_t NotesFromTx(const CWallet& wallet, const uint256& hashTx)
{
    size_t n = 0;
    for (size_t i = 0; i < wallet.vPrivacyVNextNotes.size(); ++i)
        if (wallet.vPrivacyVNextNotes[i].txhash == hashTx)
            ++n;
    return n;
}

const CPrivacyVNextWalletNote* NoteFromTx(const CWallet& wallet, const uint256& hashTx)
{
    for (size_t i = 0; i < wallet.vPrivacyVNextNotes.size(); ++i)
        if (wallet.vPrivacyVNextNotes[i].txhash == hashTx)
            return &wallet.vPrivacyVNextNotes[i];
    return NULL;
}

// Spin until the walk stands at `nHeight`. Bounded so a case fails rather than hangs.
bool WaitForWalkHeight(const CWallet& wallet, int nHeight)
{
    for (int i = 0; i < 2000; ++i)
    {
        if (wallet.GetPrivacyVNextScanGapWalkHeight() == nHeight)
            return true;
        MilliSleep(5);
    }
    return false;
}

} // namespace

// A block disconnected between the walk's membership check and apply is not applied.
// The interval is reached deterministically by holding cs_wallet (taken after cs_main
// here, safe because the walk never holds cs_main while waiting on cs_wallet).
BOOST_AUTO_TEST_CASE(a_block_disconnected_under_the_walk_is_not_applied)
{
    RescanChain chain;
    CTxDB txdb("r+");
    const PrivacyVNextDigest senderSeed = FilledDigest(0x6b);
    FundedNotes funded;
    FundNotes(txdb, 2, senderSeed, funded);

    // Memory-only: the mock database is shared with every other suite in the binary.
    CWallet wallet;
    wallet.vchPrivacyVNextSeed.assign(senderSeed.begin(), senderSeed.end());
    BOOST_REQUIRE(wallet.IsPrivacyVNextSeedUnlocked());
    wallet.vPrivacyVNextNotes.push_back(HeldNote(funded.vKeyImages[0]));
    const uint256 hashHeld = wallet.vPrivacyVNextNotes[0].txhash;

    // The block the reorg will remove spends the held note; its replacement spends the
    // other. Both pay change the wallet's scan opens, so a scan that ran on either
    // leaves a note naming that block's transaction.
    const CTransaction txStale = SpendWithChange(funded, 0, senderSeed);
    const CTransaction txReplacement = SpendWithChange(funded, 1, senderSeed);
    const uint256 hashStale = txStale.GetHash();
    const uint256 hashReplacement = txReplacement.GetHash();
    BOOST_REQUIRE(hashStale != hashReplacement);

    // Height 0 sits below the shielded fork, so the walk passes it without an apply
    // and its height reads distinctly from the block under test.
    chain.Add(0);
    CBlockIndex* pStale = chain.Add(1, std::vector<CTransaction>(1, txStale));
    pindexGenesisBlock = chain.Head();
    CBlock blockStale;
    BOOST_REQUIRE(blockStale.ReadFromDisk(pStale, true));

    BOOST_REQUIRE(wallet.MarkPrivacyVNextScanGap(0));
    int nGap = -1;
    std::string strError;
    BOOST_REQUIRE(wallet.RequestPrivacyVNextScanGapClose(nGap, strError));
    BOOST_REQUIRE_EQUAL(wallet.GetPrivacyVNextDisconnectCount(), (uint64_t)0);

    GapCloseResult result;
    boost::thread closer;
    {
        // Start held: the walk passes its seed check and waits to position itself.
        ENTER_CRITICAL_SECTION(cs_main);
        closer = boost::thread(RunGapClose, &wallet, &result);
        const bool fStarted = WaitForWalkHeight(wallet, 0);
        if (!fStarted)
            LEAVE_CRITICAL_SECTION(cs_main);
        BOOST_REQUIRE_MESSAGE(fStarted, "the walk never passed its seed check");
        // Now the seed reads inside the applies are the only ones left to park on.
        ENTER_CRITICAL_SECTION(wallet.cs_wallet);
        LEAVE_CRITICAL_SECTION(cs_main);

        // The walk checked block 1 was in the main chain and is now parked on the seed
        // read inside its apply, the disconnect count already snapshotted.
        const bool fAtStale = WaitForWalkHeight(wallet, 1);
        if (!fAtStale)
            LEAVE_CRITICAL_SECTION(wallet.cs_wallet);
        BOOST_REQUIRE_MESSAGE(fAtStale, "the walk never reached the block under test");
        BOOST_REQUIRE(!result.fDone.load());

        // The reorg, as SetBestChain performs it under cs_main: block 1 is disconnected
        // and the wallet told, then a different block 1 is connected on block 0.
        {
            LOCK(cs_main);
            std::set<uint256> setNoneSkipped;
            std::string strDisconnectError;
            BOOST_CHECK_MESSAGE(
                wallet.DisconnectPrivacyVNextBlock(blockStale, setNoneSkipped, pStale,
                                                   strDisconnectError),
                strDisconnectError);
            chain.AddAt(1, chain.Head(),
                        std::vector<CTransaction>(1, txReplacement));
            BOOST_REQUIRE(!pStale->IsInMainChain());
        }
        BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextDisconnectCount(), (uint64_t)1);
        LEAVE_CRITICAL_SECTION(wallet.cs_wallet);
    }
    closer.join();

    // The guard. The block that left the chain under the walk was not applied: no
    // note names its transaction, and the note it spent is still unspent.
    BOOST_CHECK_MESSAGE(NotesFromTx(wallet, hashStale) == 0,
                        "a block disconnected under the walk was applied: it left a "
                        "phantom note");
    const CPrivacyVNextWalletNote* pHeld = NoteFromTx(wallet, hashHeld);
    BOOST_REQUIRE(pHeld != NULL);
    BOOST_CHECK_MESSAGE(!pHeld->fSpent,
                        "a block disconnected under the walk was applied: it left a "
                        "phantom spent mark");

    // And the walk finished on the chain that replaced it: the replacement block's
    // change note was found, which is also what shows the scan above would have
    // found the stale block's note had it applied it.
    BOOST_CHECK_MESSAGE(result.fOk, "gap close failed: " + result.strError);
    BOOST_CHECK_EQUAL(NotesFromTx(wallet, hashReplacement), (size_t)1);
    BOOST_CHECK_EQUAL(result.nBlocks, 1);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapHeight(), -1);
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapCloseStatus(),
                      std::string("complete"));
    BOOST_CHECK_EQUAL(wallet.GetPrivacyVNextScanGapWalkHeight(), -1);
}

BOOST_AUTO_TEST_SUITE_END()
