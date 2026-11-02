// Copyright (c) 2025 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BOOTSTRAP_H
#define BOOTSTRAP_H

#include <string>
#include <functional>
#include <vector>
#include <boost/filesystem.hpp>

namespace Bootstrap {

static const std::string GITHUB_API_LATEST = "https://api.github.com/repos/innova-foundation/innova/releases/latest";

static const std::string BOOTSTRAP_FILENAME = "innovabootstrap.zip";

static const std::string GITHUB_API_RELEASES = "https://api.github.com/repos/innova-foundation/innova/releases?per_page=15";

// sha256sum-format list of the split parts (innovabootstrap.zip.001, ...) and the joined zip
static const std::string BOOTSTRAP_MANIFEST = "innovabootstrap.sha256";

typedef std::function<void(int64_t, int64_t)> ProgressCallback;

// Point a curl handle at a CA store that exists on this machine
void SetupCurlTls(void* curl);

std::string FetchLatestBootstrapUrl();

std::string FetchLatestManifestUrl();

// Every release manifest, newest first
std::vector<std::string> FetchManifestUrls();

bool ApplyManifest(const std::string& manifestUrl,
                   const boost::filesystem::path& dataDir,
                   ProgressCallback progressCallback = nullptr,
                   bool* pfTryOlder = nullptr);

bool Download(const std::string& url,
              const boost::filesystem::path& destPath,
              ProgressCallback progressCallback = nullptr);

bool ExtractZip(const boost::filesystem::path& zipPath,
                const boost::filesystem::path& destDir);

bool DownloadAndApply(const std::string& url,
                      const boost::filesystem::path& dataDir,
                      ProgressCallback progressCallback = nullptr);

std::string GetDefaultUrl();

bool IsNeeded(const boost::filesystem::path& dataDir);

void CleanupTempFiles(const boost::filesystem::path& dataDir);

// Set by the GUI or RPC; the next start applies the bootstrap over the existing chain
static const std::string REQUEST_FILENAME = "bootstrap.request";
static const int64_t STALE_TIP_SECONDS = 2 * 24 * 60 * 60;
static const int FAR_BEHIND_BLOCKS = 10000;

enum Offer { OFFER_NONE, OFFER_EMPTY, OFFER_BEHIND };

// nManifestHeight < 0 = unknown: only an empty datadir is offered
Offer Decide(bool fEmpty, int nLocalHeight, int64_t nTipTime, int nManifestHeight, int64_t nNow);

// Best-chain height and tip time read straight from txleveldb, before the block index loads
bool ReadLocalTip(const boost::filesystem::path& dataDir, int& nHeight, int64_t& nTipTime);

// '# height N' in the manifest, -1 if absent
int ParseManifestHeight(const std::string& manifest);
// Height of the manifest at url (empty = latest release); -1 for a plain zip or no height
int FetchManifestHeight(const std::string& url = "", long nTimeoutSecs = 30);

// False when the local chain is at or past nManifestHeight (unknown height = true)
bool IsNewerThanLocal(const boost::filesystem::path& dataDir, int nManifestHeight);

// Set after a bootstrap over an existing chain; cleared once the wallet rescan completes
static const std::string RESCAN_FILENAME = "bootstrap.rescan";

// Reads the local tip and, only for a stale tip, the published height
Offer Evaluate(const boost::filesystem::path& dataDir, int64_t nNow, int* pnLocalHeight = nullptr, int* pnManifestHeight = nullptr,
               const std::string& url = "", long nTimeoutSecs = 30);

bool WriteRequest(const boost::filesystem::path& dataDir, const std::string& url);
bool ReadRequest(const boost::filesystem::path& dataDir, std::string& url);
void ClearRequest(const boost::filesystem::path& dataDir);

static const std::string JOURNAL_FILENAME = "bootstrap.journal";

// Moves the staged chain into dataDir. Existing targets and blk*.dat the stage lacks go aside
// as *.bootstrap-old and come back on any failure; a fsync'd journal covers a crash.
// strFailOn forces a failure, nCrashAt stops dead at that step (tests).
bool SwapInStaged(const boost::filesystem::path& stage, const boost::filesystem::path& dataDir,
                  const std::string& strFailOn = "", int nCrashAt = -1);

// Rolls an interrupted apply back, or finishes it once committed. False if no journal.
bool RecoverJournal(const boost::filesystem::path& dataDir);

}

#endif
