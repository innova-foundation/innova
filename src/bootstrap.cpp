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
#include <vector>

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

static const size_t MAX_API_RESPONSE_SIZE = 1048576;

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

std::string FetchLatestBootstrapUrl()
{
    CURL* curl = curl_easy_init();
    if (!curl) {
        printf("Bootstrap: Failed to initialize CURL\n");
        return "";
    }

    std::string response;
    response.reserve(65536);

    curl_easy_setopt(curl, CURLOPT_URL, GITHUB_API_LATEST.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteStringCallbackLimited);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Innova-Core");

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/vnd.github.v3+json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        printf("Bootstrap: GitHub API request failed: %s\n", curl_easy_strerror(res));
        return "";
    }

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
        if (!downloadUrl.empty()) {
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
    std::string url = FetchLatestBootstrapUrl();
    if (url.empty()) {
        printf("Bootstrap: Using fallback URL\n");
        return FALLBACK_BOOTSTRAP_URL;
    }
    return url;
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
    unzFile zf = unzOpen(zipPath.string().c_str());
    if (!zf) {
        printf("Bootstrap: Failed to open zip file: %s\n", zipPath.string().c_str());
        return false;
    }

    unz_global_info gi;
    if (unzGetGlobalInfo(zf, &gi) != UNZ_OK) {
        printf("Bootstrap: Failed to read zip info\n");
        unzClose(zf);
        return false;
    }

    if (gi.number_entry > 10000) {
        printf("Bootstrap: Zip contains too many files (%lu), aborting\n", gi.number_entry);
        unzClose(zf);
        return false;
    }

    printf("Bootstrap: Extracting %lu files...\n", gi.number_entry);

    char filename[512];
    char buf[8192];

    for (uLong i = 0; i < gi.number_entry; i++) {
        unz_file_info fi;
        if (unzGetCurrentFileInfo(zf, &fi, filename, sizeof(filename),
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
    boost::filesystem::path tempZip = dataDir / "bootstrap_temp.zip";
    if (boost::filesystem::exists(tempZip)) {
        boost::filesystem::remove(tempZip);
    }
}

bool DownloadAndApply(const std::string& url,
                      const boost::filesystem::path& dataDir,
                      ProgressCallback progressCallback)
{
    std::string downloadUrl = url;
    if (downloadUrl.empty()) {
        printf("Bootstrap: Fetching latest release URL...\n");
        downloadUrl = GetDefaultUrl();
    }

    if (downloadUrl.empty()) {
        printf("Bootstrap: No valid download URL available\n");
        return false;
    }

    if (!boost::filesystem::exists(dataDir)) {
        boost::filesystem::create_directories(dataDir);
    }

    boost::filesystem::path tempZip = dataDir / "bootstrap_temp.zip";

    CleanupTempFiles(dataDir);

    uiInterface.InitMessage(_("Downloading blockchain bootstrap..."));

    if (!Download(downloadUrl, tempZip, progressCallback)) {
        return false;
    }

    uiInterface.InitMessage(_("Extracting blockchain bootstrap..."));

    if (!ExtractZip(tempZip, dataDir)) {
        CleanupTempFiles(dataDir);
        return false;
    }

    CleanupTempFiles(dataDir);

    uiInterface.InitMessage(_("Bootstrap applied successfully."));
    printf("Bootstrap: Applied successfully to %s\n", dataDir.string().c_str());

    return true;
}

}
