// Copyright (c) 2025 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bootstrap.h"
#include "util.h"
#include "ui_interface.h"
#include "main.h"

#include <leveldb/db.h>
#include <set>

#include <curl/curl.h>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <algorithm>
#include <map>
#include <vector>

#ifndef WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "minizip/unzip.h"

#ifdef WIN32
#include "minizip/ioapi.h"
#endif

namespace Bootstrap {

static const std::string LATEST_MANIFEST_URL =
    "https://github.com/INNOVA-FOUNDATION/INNOVA/releases/latest/download/innovabootstrap.sha256";

// path.string() is the ANSI code page on Windows
static FILE* OpenFile(const boost::filesystem::path& path, const char* mode)
{
#ifdef WIN32
    std::wstring wmode(mode, mode + strlen(mode));
    return _wfopen(path.wstring().c_str(), wmode.c_str());
#else
    return fopen(path.string().c_str(), mode);
#endif
}

#ifdef WIN32
static voidpf ZCALLBACK WideOpenFunc(voidpf opaque, const void* filename, int mode)
{
    (void)opaque;
    if (!filename || (mode & ZLIB_FILEFUNC_MODE_READWRITEFILTER) != ZLIB_FILEFUNC_MODE_READ)
        return NULL;
    return _wfopen((const wchar_t*)filename, L"rb");
}
#endif

static unzFile OpenZip(const boost::filesystem::path& path)
{
#ifdef WIN32
    zlib_filefunc64_def ff;
    fill_fopen64_filefunc(&ff);
    ff.zopen64_file = WideOpenFunc;
    std::wstring w = path.wstring();
    return unzOpen2_64(w.c_str(), &ff);
#else
    return unzOpen64(path.string().c_str());
#endif
}

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

static bool PathExists(const char* p)
{
    boost::system::error_code ec;
    return p && *p && boost::filesystem::exists(p, ec);
}

void SetupCurlTls(void* handle)
{
    CURL* curl = static_cast<CURL*>(handle);
#ifdef WIN32
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_NATIVE_CA);
#else
    const char* caFile = NULL;
    const char* caPath = NULL;
#if LIBCURL_VERSION_NUM >= 0x075400
    curl_easy_getinfo(curl, CURLINFO_CAINFO, &caFile);
    curl_easy_getinfo(curl, CURLINFO_CAPATH, &caPath);
#endif
    if (!caFile && !caPath) {
        const char* env = getenv(X509_get_default_cert_file_env());
        caFile = env ? env : X509_get_default_cert_file();
        caPath = X509_get_default_cert_dir();
    }
    if (PathExists(caFile) || PathExists(caPath))
        return;
    static const char* const FALLBACK[] = {
        "/etc/ssl/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem"
    };
    for (const char* f : FALLBACK) {
        if (PathExists(f)) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, f);
            return;
        }
    }
#endif
}

static const std::vector<std::string> ALLOWED_DOMAINS = {
    "github.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
    "release-assets.githubusercontent.com"
};

static bool IsUrlAllowed(const std::string& url);

static void SetHttpsOnlyRedirects(CURL* curl)
{
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
#else
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, (long)CURLPROTO_HTTPS);
#endif
}

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

static bool FetchString(const std::string& url, std::string& response, bool fGitHubApi, long nTimeoutSecs = 30)
{
    CURL* curl = curl_easy_init();
    if (!curl) {
        printf("Bootstrap: Failed to initialize CURL\n");
        return false;
    }

    response.clear();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    SetupCurlTls(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteStringCallbackLimited);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    SetHttpsOnlyRedirects(curl);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, nTimeoutSecs);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, nTimeoutSecs);
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

std::vector<std::string> FetchManifestUrls()
{
    std::vector<std::string> vUrls;
    std::string response;
    if (!FetchString(GITHUB_API_RELEASES, response, true)) {
        // API is rate limited per IP; the latest-release redirect is not
        printf("Bootstrap: Release list unavailable, trying %s\n", LATEST_MANIFEST_URL.c_str());
        vUrls.push_back(LATEST_MANIFEST_URL);
        return vUrls;
    }

    // Releases come newest first
    const std::string suffix = "/" + BOOTSTRAP_MANIFEST;
    size_t pos = 0;
    while ((pos = response.find("\"browser_download_url\"", pos)) != std::string::npos) {
        std::string url = ExtractJsonString(response.substr(pos, 1024), "browser_download_url");
        pos++;
        if (url.size() > suffix.size() && url.compare(url.size() - suffix.size(), suffix.size(), suffix) == 0 &&
            IsUrlAllowed(url) && std::find(vUrls.begin(), vUrls.end(), url) == vUrls.end()) {
            printf("Bootstrap: Found manifest %s\n", url.c_str());
            vUrls.push_back(url);
        }
    }
    if (vUrls.empty())
        printf("Bootstrap: No release carries %s\n", BOOTSTRAP_MANIFEST.c_str());
    return vUrls;
}

std::string FetchLatestManifestUrl()
{
    std::vector<std::string> vUrls = FetchManifestUrls();
    return vUrls.empty() ? "" : vUrls[0];
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

    FILE* fp = OpenFile(destPath, "wb");
    if (!fp) {
        printf("Bootstrap: Failed to open destination file: %s\n", destPath.string().c_str());
        curl_easy_cleanup(curl);
        return false;
    }

    int64_t nResume = 0;
    ProgressData progressData;
    progressData.callback = progressCallback;
    progressData.lastReportedPercent = -1;
    if (progressCallback) {
        progressData.callback = [&](int64_t now, int64_t total) {
            progressCallback(nResume + now, nResume + total);
        };
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    SetupCurlTls(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFileCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    SetHttpsOnlyRedirects(curl);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
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
    for (int nRetry = 1; res != CURLE_OK && nRetry <= 3 && !fShutdown; ++nRetry) {
        if (fflush(fp) != 0 || res == CURLE_WRITE_ERROR)
            break;
        if (res == CURLE_HTTP_RETURNED_ERROR) {
            long nCode = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &nCode);
            // 416 on a resume means the part was already complete; the hash check decides
            if (nCode == 416 && nResume > 0)
                res = CURLE_OK;
            break;
        }
        nResume = (int64_t)boost::filesystem::file_size(destPath);
        printf("Bootstrap: Download interrupted (%s), resuming at %lld (retry %d)\n",
               curl_easy_strerror(res), (long long)nResume, nRetry);
        MilliSleep(5000 * nRetry);
        curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)nResume);
        res = curl_easy_perform(curl);
    }

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
    unzFile zf = OpenZip(zipPath);
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

            FILE* fout = OpenFile(outPath, "wb");
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

static bool IsBlkName(const std::string& name)
{
    // blkNNNN.dat
    return name.size() == 11 && name.compare(0, 3, "blk") == 0 && name.compare(7, 4, ".dat") == 0 &&
           std::all_of(name.begin() + 3, name.begin() + 7, [](char c) { return isdigit((unsigned char)c); });
}

static void SyncDir(const boost::filesystem::path& dir)
{
#ifndef WIN32
    int fd = open(dir.string().c_str(), O_RDONLY);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }
#endif
}

static bool WriteJournal(const boost::filesystem::path& dataDir, const std::string& body)
{
    boost::filesystem::path tmp = dataDir / (JOURNAL_FILENAME + ".tmp");
    FILE* f = OpenFile(tmp, "wb");
    if (!f)
        return false;
    bool fOk = fwrite(body.data(), 1, body.size(), f) == body.size();
    FileCommit(f);
    fOk = fclose(f) == 0 && fOk;
    if (fOk)
        fOk = RenameOver(tmp, dataDir / JOURNAL_FILENAME);
    SyncDir(dataDir);
    return fOk;
}

static void UndoEntries(const boost::filesystem::path& stage, const boost::filesystem::path& dataDir,
                        const std::vector<std::pair<std::string, bool> >& vEntries)
{
    namespace fs = boost::filesystem;
    boost::system::error_code ec;
    for (auto it = vEntries.rbegin(); it != vEntries.rend(); ++it) {
        fs::path target = dataDir / it->first;
        fs::path old = target.string() + ".bootstrap-old";
        // rename is atomic: a staged item gone from the stage is the one at target
        if (it->second && !fs::exists(stage / it->first))
            fs::remove_all(target, ec);
        if (fs::exists(old)) {
            fs::remove_all(target, ec);
            fs::rename(old, target, ec);
            if (ec)
                printf("Bootstrap: Could not restore %s: %s\n", target.string().c_str(), ec.message().c_str());
        }
    }
    SyncDir(dataDir);
}

static void DropBackups(const boost::filesystem::path& dataDir,
                        const std::vector<std::pair<std::string, bool> >& vEntries)
{
    boost::system::error_code ec;
    for (const auto& e : vEntries)
        boost::filesystem::remove_all(dataDir / (e.first + ".bootstrap-old"), ec);
    SyncDir(dataDir);
}

bool RecoverJournal(const boost::filesystem::path& dataDir)
{
    namespace fs = boost::filesystem;
    boost::system::error_code ec;
    fs::remove(dataDir / (JOURNAL_FILENAME + ".tmp"), ec);
    FILE* f = OpenFile(dataDir / JOURNAL_FILENAME, "rb");
    if (!f)
        return false;
    std::string body;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        body.append(buf, n);
    fclose(f);

    fs::path stage;
    bool fCommit = false;
    std::vector<std::pair<std::string, bool> > vEntries;
    std::vector<std::string> vLines;
    boost::split(vLines, body, boost::is_any_of("\n"));
    for (const auto& line : vLines) {
        size_t sp = line.find(' ');
        std::string op = line.substr(0, sp), arg = sp == std::string::npos ? "" : line.substr(sp + 1);
        if (op == "stage")
            stage = arg;
        else if ((op == "aside" || op == "place") && !arg.empty() && arg.find('/') == std::string::npos &&
                 arg.find('\\') == std::string::npos && arg != "." && arg != ".." && arg != "wallet.dat")
            vEntries.push_back(std::make_pair(arg, op == "place"));
        else if (op == "commit")
            fCommit = true;
    }
    if (stage.empty())
        stage = dataDir / "bootstrap_extract";
    if (fCommit) {
        printf("Bootstrap: finishing an interrupted apply\n");
        DropBackups(dataDir, vEntries);
    } else {
        printf("Bootstrap: rolling back an interrupted apply\n");
        UndoEntries(stage, dataDir, vEntries);
    }
    fs::remove(dataDir / JOURNAL_FILENAME, ec);
    SyncDir(dataDir);
    return true;
}

// Built from the old chain; stale against the new one
static bool IsDerivedName(const std::string& name)
{
    return name == "spvutxos.dat" || name == "cnannounce.dat" || name == "txleveldb_backup";
}

bool SwapInStaged(const boost::filesystem::path& stage, const boost::filesystem::path& dataDir,
                  const std::string& strFailOn, int nCrashAt)
{
    namespace fs = boost::filesystem;
    boost::system::error_code ec;
    std::vector<fs::path> vItems;
    std::set<std::string> setNames;
    for (fs::directory_iterator it(stage), end; it != end; ++it) {
        std::string name = it->path().filename().string();
        bool fChain = (IsBlkName(name) && fs::is_regular_file(it->path())) ||
                      (name == "txleveldb" && fs::is_directory(it->path()));
        if (!fChain) {
            printf("Bootstrap: Skipping archive entry %s, not chain data\n", name.c_str());
            continue;
        }
        vItems.push_back(it->path());
        setNames.insert(it->path().filename().string());
    }
    // txleveldb last: IsNeeded() keys on it, so a partial move is retried next start
    std::stable_partition(vItems.begin(), vItems.end(),
        [](const fs::path& p) { return p.filename() != "txleveldb"; });

    // Block files past the bootstrap's last one would not match its index
    std::vector<fs::path> vStale;
    for (fs::directory_iterator it(dataDir), end; it != end; ++it) {
        std::string name = it->path().filename().string();
        if ((IsBlkName(name) && !setNames.count(name)) || IsDerivedName(name))
            vStale.push_back(it->path());
    }

    std::vector<std::pair<std::string, bool> > vEntries;
    std::string strJournal = "stage " + fs::absolute(stage).string() + "\n";
    for (const auto& p : vStale) {
        vEntries.push_back(std::make_pair(p.filename().string(), false));
        strJournal += "aside " + p.filename().string() + "\n";
    }
    for (const auto& p : vItems) {
        vEntries.push_back(std::make_pair(p.filename().string(), true));
        strJournal += "place " + p.filename().string() + "\n";
    }

    int nStep = 0;
    auto crash = [&]() { return nCrashAt >= 0 && nStep++ == nCrashAt; };

    if (crash())
        return false;
    if (!WriteJournal(dataDir, strJournal)) {
        printf("Bootstrap: Could not write %s\n", JOURNAL_FILENAME.c_str());
        return false;
    }
    std::vector<std::pair<std::string, bool> > vTouched;
    auto rollback = [&]() {
        UndoEntries(stage, dataDir, vTouched);
        fs::remove(dataDir / JOURNAL_FILENAME, ec);
        SyncDir(dataDir);
    };
    auto aside = [&](const fs::path& target) {
        fs::path backup = target.string() + ".bootstrap-old";
        fs::remove_all(backup, ec);
        if (!fs::exists(target))
            return true;
        fs::rename(target, backup, ec);
        if (ec) {
            printf("Bootstrap: Could not move %s aside: %s\n", target.string().c_str(), ec.message().c_str());
            return false;
        }
        return true;
    };

    for (const auto& target : vStale) {
        if (crash())
            return false;
        vTouched.push_back(std::make_pair(target.filename().string(), false));
        if (!aside(target)) {
            rollback();
            return false;
        }
    }
    for (const auto& item : vItems) {
        fs::path target = dataDir / item.filename();
        if (crash())
            return false;
        vTouched.push_back(std::make_pair(item.filename().string(), true));
        if (!aside(target)) {
            rollback();
            return false;
        }
        if (crash())
            return false;
        if (item.filename().string() == strFailOn) {
            ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
        } else {
            for (int nTry = 0; nTry < 10; ++nTry) {
                fs::rename(item, target, ec);
                if (!ec)
                    break;
                MilliSleep(500);
            }
        }
        if (ec) {
            printf("Bootstrap: Could not move %s into place: %s\n",
                   target.string().c_str(), ec.message().c_str());
            rollback();
            return false;
        }
    }
    SyncDir(dataDir);
    if (crash())
        return false;
    if (!WriteJournal(dataDir, strJournal + "commit\n")) {
        printf("Bootstrap: Could not commit %s\n", JOURNAL_FILENAME.c_str());
        rollback();
        return false;
    }
    if (crash())
        return false;
    DropBackups(dataDir, vEntries);
    if (crash())
        return false;
    fs::remove(dataDir / JOURNAL_FILENAME, ec);
    SyncDir(dataDir);
    if (!vStale.empty())
        printf("Bootstrap: Removed %u block files past the bootstrap\n", (unsigned)vStale.size());
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
    if (fOk && !boost::filesystem::exists(stage / "txleveldb")) {
        printf("Bootstrap: Archive has no txleveldb\n");
        fOk = false;
    }
    if (fOk)
        fOk = SwapInStaged(stage, dataDir);
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

Offer Decide(bool fEmpty, int nLocalHeight, int64_t nTipTime, int nManifestHeight, int64_t nNow)
{
    if (fEmpty)
        return OFFER_EMPTY;
    if (nNow - nTipTime <= STALE_TIP_SECONDS || nManifestHeight < 0)
        return OFFER_NONE;
    if (nLocalHeight >= nManifestHeight - FAR_BEHIND_BLOCKS)
        return OFFER_NONE;
    return OFFER_BEHIND;
}

bool ReadLocalTip(const boost::filesystem::path& dataDir, int& nHeight, int64_t& nTipTime)
{
    nHeight = 0;
    nTipTime = 0;
    boost::filesystem::path dir = dataDir / "txleveldb";
    if (!boost::filesystem::exists(dir / "CURRENT"))
        return false;
    leveldb::Options options;
    options.create_if_missing = false;
    options.max_open_files = 64;
    leveldb::DB* db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, dir.string(), &db);
    if (!status.ok()) {
        printf("Bootstrap: Could not read the local chain: %s\n", status.ToString().c_str());
        return false;
    }
    bool fOk = false;
    try {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey << std::string("hashBestChain");
        std::string strValue;
        if (db->Get(leveldb::ReadOptions(), leveldb::Slice(&ssKey[0], ssKey.size()), &strValue).ok()) {
            uint256 hashBest;
            CDataStream ssHash(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
            ssHash >> hashBest;
            CDataStream ssIndexKey(SER_DISK, CLIENT_VERSION);
            ssIndexKey << std::make_pair(std::string("blockindex"), hashBest);
            if (db->Get(leveldb::ReadOptions(), leveldb::Slice(&ssIndexKey[0], ssIndexKey.size()), &strValue).ok()) {
                CDataStream ssIndex(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
                CDiskBlockIndex diskindex;
                ssIndex >> diskindex;
                nHeight = diskindex.nHeight;
                nTipTime = diskindex.nTime;
                fOk = true;
            }
        }
    } catch (const std::exception& e) {
        printf("Bootstrap: Could not decode the local tip: %s\n", e.what());
    }
    delete db;
    return fOk;
}

int ParseManifestHeight(const std::string& manifest)
{
    std::vector<std::string> vLines;
    boost::split(vLines, manifest, boost::is_any_of("\n"));
    for (std::string line : vLines) {
        boost::trim(line);
        if (line.compare(0, 9, "# height ") != 0)
            continue;
        std::string num = line.substr(9);
        boost::trim(num);
        if (num.empty() || num.size() > 9 || !std::all_of(num.begin(), num.end(), [](char c) { return isdigit((unsigned char)c); }))
            return -1;
        return atoi(num.c_str());
    }
    return -1;
}

int FetchManifestHeight(const std::string& url, long nTimeoutSecs)
{
    std::string manifestUrl = url.empty() ? LATEST_MANIFEST_URL : url;
    const std::string suffix = "/" + BOOTSTRAP_MANIFEST;
    if (manifestUrl.size() <= suffix.size() ||
        manifestUrl.compare(manifestUrl.size() - suffix.size(), suffix.size(), suffix) != 0 ||
        !IsUrlAllowed(manifestUrl))
        return -1;
    std::string manifest;
    if (!FetchString(manifestUrl, manifest, false, nTimeoutSecs))
        return -1;
    return ParseManifestHeight(manifest);
}

Offer Evaluate(const boost::filesystem::path& dataDir, int64_t nNow, int* pnLocalHeight, int* pnManifestHeight,
               const std::string& url, long nTimeoutSecs)
{
    int nLocal = 0, nManifest = -1;
    int64_t nTipTime = 0;
    bool fEmpty = IsNeeded(dataDir);
    if (!fEmpty)
        ReadLocalTip(dataDir, nLocal, nTipTime);
    if (!fEmpty && nNow - nTipTime > STALE_TIP_SECONDS)
        nManifest = FetchManifestHeight(url, nTimeoutSecs);
    if (pnLocalHeight)
        *pnLocalHeight = nLocal;
    if (pnManifestHeight)
        *pnManifestHeight = nManifest;
    Offer o = Decide(fEmpty, nLocal, nTipTime, nManifest, nNow);
    printf("Bootstrap: local height %d, tip age %llds, bootstrap height %d -> %s\n", nLocal,
           (long long)(nNow - nTipTime), nManifest, o == OFFER_EMPTY ? "empty" : o == OFFER_BEHIND ? "behind" : "current");
    return o;
}

bool WriteRequest(const boost::filesystem::path& dataDir, const std::string& url)
{
    FILE* f = OpenFile(dataDir / REQUEST_FILENAME, "wb");
    if (!f)
        return false;
    bool fOk = fwrite(url.data(), 1, url.size(), f) == url.size();
    return fclose(f) == 0 && fOk;
}

bool ReadRequest(const boost::filesystem::path& dataDir, std::string& url)
{
    url.clear();
    FILE* f = OpenFile(dataDir / REQUEST_FILENAME, "rb");
    if (!f)
        return false;
    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    url.assign(buf, n);
    boost::trim(url);
    return true;
}

void ClearRequest(const boost::filesystem::path& dataDir)
{
    boost::system::error_code ec;
    boost::filesystem::remove(dataDir / REQUEST_FILENAME, ec);
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
    FILE* f = OpenFile(path, "rb");
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
    FILE* in = OpenFile(from, "rb");
    FILE* out = OpenFile(to, "ab");
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

static int64_t RemoteSize(const std::string& url)
{
    CURL* curl = curl_easy_init();
    if (!curl)
        return -1;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    SetupCurlTls(curl);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    SetHttpsOnlyRedirects(curl);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Innova-Core");
    curl_off_t nSize = -1;
    if (curl_easy_perform(curl) == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &nSize);
    curl_easy_cleanup(curl);
    return nSize;
}

// The joined zip and the extracted copy are on disk together
static bool HasSpaceFor(const boost::filesystem::path& dataDir, int64_t nPartSize, int nParts)
{
    const uint64_t nNeed = (uint64_t)nPartSize * nParts * 2 + 1073741824ULL;
    boost::system::error_code ec;
    boost::filesystem::space_info si = boost::filesystem::space(dataDir, ec);
    if (!ec && si.available < nNeed) {
        printf("Bootstrap: Not enough disk space, need about %llu MB free\n",
               (unsigned long long)(nNeed / 1048576));
        uiInterface.InitMessage(_("Not enough disk space for the bootstrap."));
        return false;
    }
    return true;
}

bool IsNewerThanLocal(const boost::filesystem::path& dataDir, int nManifestHeight)
{
    if (nManifestHeight < 0 || IsNeeded(dataDir))
        return true;
    int nLocal = 0;
    int64_t nTipTime = 0;
    ReadLocalTip(dataDir, nLocal, nTipTime);
    if (nManifestHeight > nLocal)
        return true;
    printf("Bootstrap: bootstrap height %d is not above the local height %d, keeping the local chain\n",
           nManifestHeight, nLocal);
    return false;
}

bool ApplyManifest(const std::string& manifestUrl,
                   const boost::filesystem::path& dataDir,
                   ProgressCallback progressCallback,
                   bool* pfTryOlder)
{
    // Only a fault in this release's files is worth retrying on an older one
    bool fDummy;
    bool& fTryOlder = pfTryOlder ? *pfTryOlder : fDummy;
    fTryOlder = true;
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

    if (!IsNewerThanLocal(dataDir, ParseManifestHeight(manifest))) {
        fTryOlder = false;
        return false;
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
    int64_t nPartSize = RemoteSize(base + mapParts.begin()->first);
    fTryOlder = false;
    if (nPartSize > 0 && !HasSpaceFor(dataDir, nPartSize, nParts))
        return false;
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
            fTryOlder = true;
            CleanupTempFiles(dataDir);
            return false;
        }
        if (!AppendFile(tempPart, tempZip)) {
            printf("Bootstrap: Could not join %s (disk full?)\n", item.first.c_str());
            CleanupTempFiles(dataDir);
            return false;
        }
        if (nPart == 1) {
            nPartSize = boost::filesystem::file_size(tempPart);
            if (!HasSpaceFor(dataDir, nPartSize, nParts)) {
                CleanupTempFiles(dataDir);
                return false;
            }
        }
        boost::filesystem::remove(tempPart);
    }

    uiInterface.InitMessage(_("Verifying blockchain bootstrap..."));
    if (Sha256File(tempZip) != strZipHash) {
        printf("Bootstrap: Checksum mismatch on the joined zip\n");
        fTryOlder = true;
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
        std::vector<std::string> vUrls = FetchManifestUrls();
        for (const auto& u : vUrls) {
            bool fTryOlder = false;
            if (ApplyManifest(u, dataDir, progressCallback, &fTryOlder))
                return true;
            if (fShutdown || !fTryOlder)
                return false;
        }
        if (!vUrls.empty())
            return false;
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
