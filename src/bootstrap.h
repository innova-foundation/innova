// Copyright (c) 2025 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BOOTSTRAP_H
#define BOOTSTRAP_H

#include <string>
#include <functional>
#include <boost/filesystem.hpp>

namespace Bootstrap {

static const std::string GITHUB_API_LATEST = "https://api.github.com/repos/innova-foundation/innova/releases/latest";

static const std::string BOOTSTRAP_FILENAME = "innovabootstrap.zip";

static const std::string FALLBACK_BOOTSTRAP_URL = "https://github.com/innova-foundation/innova/releases/download/v5.0.0.0/innovabootstrap.zip";

typedef std::function<void(int64_t, int64_t)> ProgressCallback;

std::string FetchLatestBootstrapUrl();

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

}

#endif
