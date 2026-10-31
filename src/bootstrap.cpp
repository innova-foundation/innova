// Copyright (c) 2025 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bootstrap.h"
#include "util.h"
#include "ui_interface.h"

#include <curl/curl.h>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <algorithm>
#include <map>
#include <vector>

#include <openssl/evp.h>

#include "minizip/unzip.h"

namespace Bootstrap {

static size_t WriteFileCallback(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return fwrite(ptr, size, nmemb, stream);
}

struct ProgressData {
    ProgressCallback callback;
    int64_t lastReportedPercent;
};

static int CurlProgressCallback(void* clientp, curl_off_t dltotal, curl_off_t dlnow,
                                 curl_off_t ultotal, curl_off_t ulnow)
{
    ProgressData* data = static_cast<ProgressData*>(clientp);
    if (data && data->callback && dltotal > 0) {
        data->callback(dlnow, dltotal);
    }
    return 0;
}

static const std::vector<std::string> ALLOWED_DOMAINS = {
    "github.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com"
};

static bool IsUrlAllowed(const std::string& url)
{
    if (url.compare(0, 8, "https://") != 0) {
        printf("Bootstrap: SECURITY - URL must use HTTPS: %s\n", url.c_str());
        return false;
    }

    size_t domainStart = 8;
    size_t domainEnd = url.find('/', domainStart);
    if (domainEnd == std::string::npos) {
        domainEnd = url.length();
    }

    std::string domain = url.substr(domainStart, domainEnd - domainStart);

    size_t portPos = domain.find(':');
    if (portPos != std::string::npos) {
        domain = domain.substr(0, portPos);
    }

    std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

    for (const auto& allowed : ALLOWED_DOMAINS) {
        if (domain == allowed ||
            (domain.length() > allowed.length() &&
             domain.compare(domain.length() - allowed.length() - 1, allowed.length() + 1, "." + allowed) == 0)) {
            return true;
        }
    }

    printf("Bootstrap: SECURITY - Domain not in allowed list: %s\n", domain.c_str());
    return false;
}

static std::string ExtractJsonString(const std::string& json, const std::string& key)
{
    std::string searchKey = "\"" + key + "\"";
    size_t keyPos = json.find(searchKey);
    if (keyPos == std::string::npos) return "";

    size_t colonPos = json.find(':', keyPos);
    if (colonPos == std::string::npos) return "";

    size_t startQuote = json.find('"', colonPos);
    if (startQuote == std::string::npos) return "";

    size_t endQuote = startQuote + 1;
    while (endQuote < json.length()) {
        endQuote = json.find('"', endQuote);
        if (endQuote == std::string::npos) return "";

        size_t backslashes = 0;
        size_t pos = endQuote;
        while (pos > startQuote + 1 && json[pos - 1 - backslashes] == '\\') {
            backslashes++;
        }

        if (backslashes % 2 == 1) {
            endQuote++;
            continue;
        }
        break;
    }

    if (endQuote >= json.length()) return "";

    return json.substr(startQuote + 1, endQuote - startQuote - 1);
}

static const size_t MAX_API_RESPONSE_SIZE = 4194304;

static size_t WriteStringCallbackLimited(void* ptr, size_t size, size_t nmemb, void* userdata)
{
    std::string* data = static_cast<std::string*>(userdata);
    size_t totalSize = size * nmemb;

    if (data->size() + totalSize > MAX_API_RESPONSE_SIZE) {
        printf("Bootstrap: SECURITY - API response exceeded size limit\n");
        return 0;
    }

    data->append((char*)ptr, totalSize);
    return totalSize;
}

static bool FetchString(const std::string& url, std::string& response, bool fGitHubApi)
{
    CURL* curl = curl_easy_init();
    if (!curl) {
        printf("Bootstrap: Failed to initialize CURL\n");
        return false;
    }

    response.clear();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteStringCallbackLimited);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Innova-Core");
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    struct curl_slist* headers = NULL;
    if (fGitHubApi) {
        headers = curl_slist_append(headers, "Accept: application/vnd.github.v3+json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        printf("Bootstrap: Request failed for %s: %s\n", url.c_str(), curl_easy_strerror(res));
        return false;
    }
    return true;
}

std::string FetchLatestManifestUrl()
{
    std::string response;
    if (!FetchString(GITHUB_API_RELEASES, response, true))
        return "";

    // Releases come newest first; take the first one that carries a manifest
    const std::string suffix = "/" + BOOTSTRAP_MANIFEST;
    size_t pos = 0;
    while ((pos = response.find("\"browser_download_url\"", pos)) != std::string::npos) {
        std::string url = ExtractJsonString(response.substr(pos, 1024), "browser_download_url");
        pos++;
        if (url.size() > suffix.size() && url.compare(url.size() - suffix.size(), suffix.size(), suffix) == 0) {
            if (!IsUrlAllowed(url))
                return "";
            printf("Bootstrap: Found manifest %s\n", url.c_str());
            return url;
        }
    }
    printf("Bootstrap: No release carries %s\n", BOOTSTRAP_MANIFEST.c_str());
    return "";
}

std::string FetchLatestBootstrapUrl()
{
    std::string response;
    if (!FetchString(GITHUB_API_LATEST, response, true))
        return "";

    size_t pos = 0;
    while ((pos = response.find(BOOTSTRAP_FILENAME, pos)) != std::string::npos) {
        size_t assetStart = response.rfind('{', pos);
        if (assetStart == std::string::npos) {
            pos++;
            continue;
        }

        size_t assetEnd = response.find('}', pos);
        if (assetEnd == std::string::npos) {
            pos++;
            continue;
        }

        std::string assetJson = response.substr(assetStart, assetEnd - assetStart + 1);

        std::string downloadUrl = ExtractJsonString(assetJson, "browser_download_url");
        const std::string suffix = "/" + BOOTSTRAP_FILENAME;
        if (downloadUrl.size() > suffix.size() &&
            downloadUrl.compare(downloadUrl.size() - suffix.size(), suffix.size(), suffix) == 0) {
            if (!IsUrlAllowed(downloadUrl)) {
                printf("Bootstrap: SECURITY - Extracted URL failed validation\n");
                return "";
            }
            printf("Bootstrap: Found latest release URL: %s\n", downloadUrl.c_str());
            return downloadUrl;
        }

        pos++;
    }

    printf("Bootstrap: Could not find %s in latest release\n", BOOTSTRAP_FILENAME.c_str());
    return "";
}

std::string GetDefaultUrl()
{
    return FetchLatestBootstrapUrl();
}

bool Download(const std::string& url,
              const boost::filesystem::path& destPath,
              ProgressCallback progressCallback)
{
    if (!IsUrlAllowed(url)) {
        printf("Bootstrap: SECURITY - Download URL failed validation: %s\n", url.c_str());
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        printf("Bootstrap: Failed to initialize CURL for download\n");
        return false;
    }

    FILE* fp = fopen(destPath.string().c_str(), "wb");
    if (!fp) {
        printf("Bootstrap: Failed to open destination file: %s\n", destPath.string().c_str());
        curl_easy_cleanup(curl);
        return false;
    }

    ProgressData progressData;
    progressData.callback = progressCallback;
    progressData.lastReportedPercent = -1;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFileCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Innova-Core");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 0L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 60L);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    if (progressCallback) {
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, CurlProgressCallback);
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &progressData);
    }

    printf("Bootstrap: Downloading from %s\n", url.c_str());

    CURLcode res = curl_easy_perform(curl);

    fclose(fp);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        printf("Bootstrap: Download failed: %s\n", curl_easy_strerror(res));
        boost::filesystem::remove(destPath);
        return false;
    }

    if (!boost::filesystem::exists(destPath) || boost::filesystem::file_size(destPath) == 0) {
        printf("Bootstrap: Downloaded file is empty or missing\n");
        return false;
    }

    printf("Bootstrap: Download complete (%lld bytes)\n",
           (long long)boost::filesystem::file_size(destPath));
    return true;
}

static bool IsPathSafe(const boost::filesystem::path& basePath,
                       const boost::filesystem::path& targetPath)
{
    boost::filesystem::path canonicalBase = boost::filesystem::canonical(basePath);
    std::string baseStr = canonicalBase.string();

    boost::filesystem::path current = targetPath;
    boost::filesystem::path suffix;

    while (!current.empty() && !boost::filesystem::exists(current)) {
        suffix = current.filename() / suffix;
        current = current.parent_path();
    }

    if (current.empty()) {
        boost::filesystem::path absTarget = boost::filesystem::absolute(targetPath);
        std::string targetStr = absTarget.string();

        if (targetStr.find("..") != std::string::npos) {
            return false;
        }
        return targetStr.compare(0, baseStr.length(), baseStr) == 0;
    }

    boost::filesystem::path canonicalAncestor = boost::filesystem::canonical(current);
    boost::filesystem::path canonicalTarget = canonicalAncestor / suffix;
    std::string targetStr = canonicalTarget.string();

    if (targetStr.length() > baseStr.length()) {
        return targetStr.compare(0, baseStr.length(), baseStr) == 0 &&
               (targetStr[baseStr.length()] == '/' || targetStr[baseStr.length()] == '\\');
    }

    return targetStr == baseStr;
}

static std::string SanitizeZipFilename(const std::string& filename)
{
    std::string result;
    result.reserve(filename.length());

    size_t i = 0;
    while (i < filename.length() && (filename[i] == '/' || filename[i] == '\\')) {
        i++;
    }

    bool lastWasSlash = false;
    while (i < filename.length()) {
        char c = filename[i];

        if (c == '\\') c = '/';

        if (c == '.' && i + 1 < filename.length() && filename[i + 1] == '.') {
            i += 2;
            if (i < filename.length() && (filename[i] == '/' || filename[i] == '\\')) {
                i++;
            }
            continue;
        }

        if (c == '/') {
            if (!lastWasSlash && !result.empty()) {
                result += c;
                lastWasSlash = true;
            }
        } else {
            result += c;
            lastWasSlash = false;
        }

        i++;
    }

    return result;
}

bool ExtractZip(const boost::filesystem::path& zipPath,
                const boost::filesystem::path& destDir)
{
    unzFile zf = unzOpen64(zipPath.string().c_str());
    if (!zf) {
        printf("Bootstrap: Failed to open zip file: %s\n", zipPath.string().c_str());
        return false;
    }

    unz_global_info64 gi;
    if (unzGetGlobalInfo64(zf, &gi) != UNZ_OK) {
        printf("Bootstrap: Failed to read zip info\n");
        unzClose(zf);
        return false;
    }

    if (gi.number_entry > 10000) {
        printf("Bootstrap: Zip contains too many files (%llu), aborting\n", (unsigned long long)gi.number_entry);
        unzClose(zf);
        return false;
    }

    printf("Bootstrap: Extracting %llu files...\n", (unsigned long long)gi.number_entry);

    char filename[512];
    char buf[8192];

    for (ZPOS64_T i = 0; i < gi.number_entry; i++) {
        unz_file_info64 fi;
        if (unzGetCurrentFileInfo64(zf, &fi, filename, sizeof(filename),
                                   NULL, 0, NULL, 0) != UNZ_OK) {
            printf("Bootstrap: Failed to get file info\n");
            unzClose(zf);
            return false;
        }

        std::string safeFilename = SanitizeZipFilename(filename);
        if (safeFilename.empty()) {
            printf("Bootstrap: Skipping invalid filename in zip\n");
            if (i + 1 < gi.number_entry && unzGoToNextFile(zf) != UNZ_OK) {
                unzClose(zf);
                return false;
            }
            continue;
        }

        boost::filesystem::path outPath = destDir / safeFilename;

        try {
            if (!IsPathSafe(destDir, outPath)) {
                printf("Bootstrap: SECURITY - Blocked path traversal attempt: %s\n", filename);
                unzClose(zf);
                return false;
            }
        } catch (const boost::filesystem::filesystem_error& e) {
            printf("Bootstrap: Path validation error: %s\n", e.what());
            unzClose(zf);
            return false;
        }

        size_t filenameLen = safeFilename.length();

        if (filenameLen > 0 && safeFilename[filenameLen - 1] == '/') {
            boost::filesystem::create_directories(outPath);
        } else {
            if (fi.uncompressed_size > 10737418240ULL) { // 10GB max per file
                printf("Bootstrap: File too large in zip: %s (%lu bytes)\n",
                       safeFilename.c_str(), (unsigned long)fi.uncompressed_size);
                unzClose(zf);
                return false;
            }

            boost::filesystem::create_directories(outPath.parent_path());

            if (unzOpenCurrentFile(zf) != UNZ_OK) {
                printf("Bootstrap: Failed to open file in zip: %s\n", safeFilename.c_str());
                unzClose(zf);
                return false;
            }

            FILE* fout = fopen(outPath.string().c_str(), "wb");
            if (!fout) {
                printf("Bootstrap: Failed to create output file: %s\n", outPath.string().c_str());
                unzCloseCurrentFile(zf);
                unzClose(zf);
                return false;
            }

            int len;
            uint64_t totalWritten = 0;
            bool writeError = false;
            while ((len = unzReadCurrentFile(zf, buf, sizeof(buf))) > 0) {
                size_t written = fwrite(buf, 1, len, fout);
                if (written != (size_t)len) {
                    printf("Bootstrap: Write error (disk full?): %s\n", safeFilename.c_str());
                    writeError = true;
                    break;
                }
                totalWritten += len;
            
                if (totalWritten > 10737418240ULL) {
                    printf("Bootstrap: Extraction exceeded size limit, aborting\n");
                    fclose(fout);
                    unzCloseCurrentFile(zf);
                    unzClose(zf);
                    boost::filesystem::remove(outPath);
                    return false;
                }
            }

            if (writeError) {
                fclose(fout);
                unzCloseCurrentFile(zf);
                unzClose(zf);
                boost::filesystem::remove(outPath);
                return false;
            }

            fclose(fout);
            unzCloseCurrentFile(zf);

            if (len < 0) {
                printf("Bootstrap: Error reading file from zip: %s\n", safeFilename.c_str());
                unzClose(zf);
                return false;
            }

            printf("Bootstrap: Extracted %s\n", safeFilename.c_str());
        }

        if (i + 1 < gi.number_entry) {
            if (unzGoToNextFile(zf) != UNZ_OK) {
                printf("Bootstrap: Failed to move to next file in zip\n");
                unzClose(zf);
                return false;
            }
        }
    }

    unzClose(zf);
    printf("Bootstrap: Extraction complete\n");
    return true;
}

// Extract to a staging dir so a failed run leaves the datadir untouched
static bool ExtractStaged(const boost::filesystem::path& zipPath,
                          const boost::filesystem::path& dataDir)
{
    boost::filesystem::path stage = dataDir / "bootstrap_extract";
    boost::system::error_code ec;
    boost::filesystem::remove_all(stage, ec);
    boost::filesystem::create_directories(stage);

    bool fOk = ExtractZip(zipPath, stage);
    if (fOk) {
        for (boost::filesystem::directory_iterator it(stage), end; it != end; ++it) {
            boost::filesystem::path target = dataDir / it->path().filename();
            boost::filesystem::remove_all(target, ec);
            boost::filesystem::rename(it->path(), target, ec);
            if (ec) {
                printf("Bootstrap: Could not move %s into place: %s\n",
                       target.string().c_str(), ec.message().c_str());
                fOk = false;
                break;
            }
        }
    }
    boost::filesystem::remove_all(stage, ec);
    return fOk;
}

bool IsNeeded(const boost::filesystem::path& dataDir)
{
    boost::filesystem::path blkFile = dataDir / "blk0001.dat";
    boost::filesystem::path txdbDir = dataDir / "txleveldb";

    bool hasBlkFile = boost::filesystem::exists(blkFile);
    bool hasTxDb = boost::filesystem::exists(txdbDir);

    return !hasBlkFile && !hasTxDb;
}

void CleanupTempFiles(const boost::filesystem::path& dataDir)
{
    boost::filesystem::remove(dataDir / "bootstrap_temp.zip");
    boost::filesystem::remove(dataDir / "bootstrap_part.tmp");
    boost::system::error_code ec;
    boost::filesystem::remove_all(dataDir / "bootstrap_extract", ec);
}

static std::string Sha256File(const boost::filesystem::path& path)
{
    FILE* f = fopen(path.string().c_str(), "rb");
    if (!f)
        return "";
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    std::vector<unsigned char> buf(1 << 20);
    size_t n;
    while ((n = fread(buf.data(), 1, buf.size(), f)) > 0)
        EVP_DigestUpdate(ctx, buf.data(), n);
    bool fError = ferror(f) != 0;
    fclose(f);
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    EVP_DigestFinal_ex(ctx, md, &mdLen);
    EVP_MD_CTX_free(ctx);
    if (fError)
        return "";
    return HexStr(md, md + mdLen);
}

static bool AppendFile(const boost::filesystem::path& from, const boost::filesystem::path& to)
{
    FILE* in = fopen(from.string().c_str(), "rb");
    FILE* out = fopen(to.string().c_str(), "ab");
    bool fOk = in && out;
    std::vector<char> buf(1 << 20);
    size_t n;
    while (fOk && (n = fread(buf.data(), 1, buf.size(), in)) > 0)
        fOk = fwrite(buf.data(), 1, n, out) == n;
    if (fOk && ferror(in))
        fOk = false;
    if (in)
        fclose(in);
    if (out && fclose(out) != 0)
        fOk = false;
    return fOk;
}

static bool IsPartName(const std::string& name)
{
    // innovabootstrap.zip.NNN
    if (name.size() != BOOTSTRAP_FILENAME.size() + 4 || name.compare(0, BOOTSTRAP_FILENAME.size(), BOOTSTRAP_FILENAME) != 0)
        return false;
    return name[BOOTSTRAP_FILENAME.size()] == '.' && isdigit((unsigned char)name[name.size() - 3]) &&
           isdigit((unsigned char)name[name.size() - 2]) && isdigit((unsigned char)name[name.size() - 1]);
}

bool ApplyManifest(const std::string& manifestUrl,
                   const boost::filesystem::path& dataDir,
                   ProgressCallback progressCallback)
{
    if (!IsUrlAllowed(manifestUrl))
        return false;

    std::string manifest;
    if (!FetchString(manifestUrl, manifest, false)) {
        printf("Bootstrap: Could not download the manifest\n");
        return false;
    }

    std::map<std::string, std::string> mapParts;
    std::string strZipHash;
    std::vector<std::string> vLines;
    boost::split(vLines, manifest, boost::is_any_of("\n"));
    for (std::string line : vLines) {
        boost::trim(line);
        if (line.empty() || line[0] == '#')
            continue;
        size_t sp = line.find(' ');
        if (sp != 64 || !IsHex(line.substr(0, 64))) {
            printf("Bootstrap: Malformed manifest line: %s\n", line.c_str());
            return false;
        }
        std::string name = line.substr(sp);
        boost::trim_left_if(name, boost::is_any_of(" *"));
        std::string hash = boost::to_lower_copy(line.substr(0, 64));
        if (name == BOOTSTRAP_FILENAME)
            strZipHash = hash;
        else if (IsPartName(name))
            mapParts[name] = hash;
        else {
            printf("Bootstrap: Unexpected file in manifest: %s\n", name.c_str());
            return false;
        }
    }

    if (mapParts.empty() || strZipHash.empty() || mapParts.size() > 999) {
        printf("Bootstrap: Manifest must list the parts and the joined zip\n");
        return false;
    }
    int nExpected = 1;
    for (const auto& item : mapParts) {
        if (item.first != strprintf("%s.%03d", BOOTSTRAP_FILENAME.c_str(), nExpected++)) {
            printf("Bootstrap: Manifest parts are not numbered 001..%03d\n", (int)mapParts.size());
            return false;
        }
    }

    const std::string base = manifestUrl.substr(0, manifestUrl.rfind('/') + 1);
    boost::filesystem::path tempZip = dataDir / "bootstrap_temp.zip";
    boost::filesystem::path tempPart = dataDir / "bootstrap_part.tmp";
    CleanupTempFiles(dataDir);

    int nPart = 0;
    const int nParts = mapParts.size();
    int64_t nPartSize = 0;
    for (const auto& item : mapParts) {
        ++nPart;
        uiInterface.InitMessage(strprintf(_("Downloading blockchain bootstrap (part %d of %d)..."), nPart, nParts));
        printf("Bootstrap: Part %d of %d: %s\n", nPart, nParts, item.first.c_str());

        auto partProgress = [&](int64_t downloaded, int64_t total) {
            if (!progressCallback || total <= 0)
                return;
            const int64_t nFull = nPartSize > 0 ? nPartSize : total;
            const int64_t nAll = (int64_t)(nParts - 1) * nFull + (nPart == nParts ? total : nFull);
            progressCallback((int64_t)(nPart - 1) * nFull + downloaded, nAll);
        };

        if (!Download(base + item.first, tempPart, partProgress)) {
            CleanupTempFiles(dataDir);
            return false;
        }
        if (Sha256File(tempPart) != item.second) {
            printf("Bootstrap: Checksum mismatch on %s\n", item.first.c_str());
            CleanupTempFiles(dataDir);
            return false;
        }
        if (!AppendFile(tempPart, tempZip)) {
            printf("Bootstrap: Could not join %s (disk full?)\n", item.first.c_str());
            CleanupTempFiles(dataDir);
            return false;
        }
        if (nPart == 1) {
            // The joined zip and the extracted copy are on disk together
            nPartSize = boost::filesystem::file_size(tempPart);
            const uint64_t nNeed = (uint64_t)nPartSize * nParts * 2 + 1073741824ULL;
            if (boost::filesystem::space(dataDir).available < nNeed) {
                printf("Bootstrap: Not enough disk space, need about %llu MB free\n",
                       (unsigned long long)(nNeed / 1048576));
                uiInterface.InitMessage(_("Not enough disk space for the bootstrap."));
                CleanupTempFiles(dataDir);
                return false;
            }
        }
        boost::filesystem::remove(tempPart);
    }

    uiInterface.InitMessage(_("Verifying blockchain bootstrap..."));
    if (Sha256File(tempZip) != strZipHash) {
        printf("Bootstrap: Checksum mismatch on the joined zip\n");
        CleanupTempFiles(dataDir);
        return false;
    }

    uiInterface.InitMessage(_("Extracting blockchain bootstrap..."));
    bool fOk = ExtractStaged(tempZip, dataDir);
    CleanupTempFiles(dataDir);
    if (fOk) {
        uiInterface.InitMessage(_("Bootstrap applied successfully."));
        printf("Bootstrap: Applied successfully to %s\n", dataDir.string().c_str());
    }
    return fOk;
}

bool DownloadAndApply(const std::string& url,
                      const boost::filesystem::path& dataDir,
                      ProgressCallback progressCallback)
{
    if (!boost::filesystem::exists(dataDir)) {
        boost::filesystem::create_directories(dataDir);
    }

    const std::string manifestSuffix = "/" + BOOTSTRAP_MANIFEST;
    std::string manifestUrl;
    if (url.empty()) {
        printf("Bootstrap: Looking for the newest release with a bootstrap...\n");
        manifestUrl = FetchLatestManifestUrl();
    } else if (url.size() > manifestSuffix.size() &&
               url.compare(url.size() - manifestSuffix.size(), manifestSuffix.size(), manifestSuffix) == 0) {
        manifestUrl = url;
    }
    if (!manifestUrl.empty())
        return ApplyManifest(manifestUrl, dataDir, progressCallback);

    std::string downloadUrl = url;
    if (downloadUrl.empty()) {
        downloadUrl = GetDefaultUrl();
    }

    if (downloadUrl.empty()) {
        printf("Bootstrap: No valid download URL available\n");
        return false;
    }

    boost::filesystem::path tempZip = dataDir / "bootstrap_temp.zip";

    CleanupTempFiles(dataDir);

    uiInterface.InitMessage(_("Downloading blockchain bootstrap..."));

    if (!Download(downloadUrl, tempZip, progressCallback)) {
        return false;
    }

    uiInterface.InitMessage(_("Extracting blockchain bootstrap..."));

    if (!ExtractStaged(tempZip, dataDir)) {
        CleanupTempFiles(dataDir);
        return false;
    }

    CleanupTempFiles(dataDir);

    uiInterface.InitMessage(_("Bootstrap applied successfully."));
    printf("Bootstrap: Applied successfully to %s\n", dataDir.string().c_str());

    return true;
}

}
