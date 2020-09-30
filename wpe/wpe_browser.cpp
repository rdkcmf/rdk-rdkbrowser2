/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include "wpe_browser.h"
#include "logger.h"

#ifdef WPEBACKEND2
#include <wpe/wpe.h>
#else
#include <wpe/view-backend.h>
#endif

#include <WebKit/WKCookie.h>
#include <WebKit/WKCookieManager.h>
#include <WebKit/WKProxy.h>
#include <WebKit/WKData.h>
#include <WebKit/WKSerializedScriptValue.h>
#include <WebKit/WKUserMediaPermissionRequest.h>
#include <WebKit/WKPageConfigurationRef.h>
#include <WebKit/WKPreferencesRefPrivate.h>

// TODO(em): fix generation of forwarding header
#include <WebKit/UIProcess/API/C/WKContextPrivate.h>
#include <WebKit/UIProcess/API/C/WKPagePrivate.h>
#include <WebKit/UIProcess/API/C/WKWebsiteDataStoreRef.h>
#include <WebKit/UIProcess/API/C/WKResourceCacheManager.h>
#include <WebKit/UIProcess/API/C/WKAuthenticationDecisionListener.h>
#include <WebKit/UIProcess/API/C/WKAuthenticationChallenge.h>
#include <WebKit/UIProcess/API/C/soup/WKSoupSession.h>

#if defined(ENABLE_LOCALSTORAGE_ENCRYPTION)
#include <WebKit/UIProcess/API/C/WKLocalStorageEncryptionExtensionClient.h>
#endif

#include <libsoup/soup.h>

#include <stdio.h>
#include <string.h>

#include <functional>
#include <tuple>
#include <vector>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <mutex>

#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib/gstdio.h>

#include <sys/sysinfo.h>
#include <sched.h>

#if defined(USE_PLABELS)
#include "pbnj_utils.hpp"
#endif

#ifdef USE_BREAKPAD
#include <common/linux/guid_creator.h>
#endif

using namespace JSUtils;

namespace
{

constexpr char cleanExitEnvVar[]              = "RDKBROWSER2_CLEAN_EXIT_WEBPROCESS";
constexpr char disableInjectedBundleEnvVar[]  = "RDKBROWSER2_DISABLE_INJECTED_BUNDLE";
constexpr char indexedDbEnvVar[]              = "RDKBROWSER2_INDEXED_DB_DIR";
constexpr char injectedBundleEnvVar[]         = "RDKBROWSER2_INJECTED_BUNDLE_LIB";
constexpr char testHangDetectorEnvVar[]       = "RDKBROWSER2_TEST_HANG_DETECTOR";
constexpr char disableWebWatchdogEnvVar[]     = "RDKBROWSER2_DISABLE_WEBPROCESS_WATCHDOG";
constexpr char ignoreTLSErrorsEnvVar[]        = "RDKBROWSER2_IGNORE_TLS_ERRORS";
constexpr char deleteEncryptedStorageEnvVar[] = "RDKBROWSER2_DELETE_ENCRYPTED_LOCALSTORAGE";
constexpr char wpeAccessibilityEnvVar[]       = "WPE_ACCESSIBILITY";
constexpr char recycleOnWebGLRenderModeChangeEnvVar[] = "RDKBROWSER2_RECYCLE_ON_WEBGL_RENDER_MODE_CHANGE";
constexpr char enableEphemeralModeEnvVar[]    = "RDKBROWSER2_ENABLE_EPHEMERAL_MODE";
constexpr char enableWebautomationEnvVar[]    = "RFC_ENABLE_WEBAUTOMATION";
constexpr char maxMemoryUsageInSuspendedEnvVar[] = "RDKBROWSER2_MAX_MEMORY_USAGE_IN_SUSPENDED";

constexpr char receiverOrgName[]       = "Comcast";
constexpr char receiverAppName[]       = "NativeXREReceiver";
constexpr char ariaAccessibilityMode[] = "accessibility";
constexpr char synthesisMode[]         = "synthesis";

JSGlobalContextRef gJSContext = nullptr;

static guint64 navigationTimingsRequestId = 0;

std::string toStdString(const WKStringRef& stringRef)
{
    RDKLOG_TRACE("Function entered");
    if (!stringRef)
        return std::string();
    size_t bufferSize = WKStringGetMaximumUTF8CStringSize(stringRef);
    if (!bufferSize)
        return std::string();
    auto buffer = std::vector<char>(bufferSize);
    WKStringGetUTF8CString(stringRef, buffer.data(), bufferSize);
    return std::string(buffer.data());
}

typedef std::tuple<std::string, RDK::WPEBrowser*, bool, std::string> CallJSData;

WKCookieRef toWKCookie(SoupCookie* cookie)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(nullptr != cookie);
    SoupDate* expires = soup_cookie_get_expires(cookie);
    return WKCookieCreate(adoptWK(WKStringCreateWithUTF8CString(soup_cookie_get_name(cookie))).get(),
                          adoptWK(WKStringCreateWithUTF8CString(soup_cookie_get_value(cookie))).get(),
                          adoptWK(WKStringCreateWithUTF8CString(soup_cookie_get_domain(cookie))).get(),
                          adoptWK(WKStringCreateWithUTF8CString(soup_cookie_get_path(cookie))).get(),
                          expires ? static_cast<double>(soup_date_to_time_t(expires)) * 1000 : 0,
                          soup_cookie_get_http_only(cookie),
                          soup_cookie_get_secure(cookie),
                          !expires);
}

SoupCookie* toSoupCookie(WKCookieRef cookie)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(nullptr != cookie);
    SoupCookie* soupCookie = soup_cookie_new(
        toStdString(adoptWK(WKCookieGetName(cookie)).get()).c_str(),
        toStdString(adoptWK(WKCookieGetValue(cookie)).get()).c_str(),
        toStdString(adoptWK(WKCookieGetDomain(cookie)).get()).c_str(),
        toStdString(adoptWK(WKCookieGetPath(cookie)).get()).c_str(),
        -1);

    if (!WKCookieGetSession(cookie))
    {
        SoupDate* expires = soup_date_new_from_time_t(WKCookieGetExpires(cookie) / 1000.0);
        soup_cookie_set_expires(soupCookie, expires);
        soup_date_free(expires);
    }
    soup_cookie_set_http_only(soupCookie, WKCookieGetHttpOnly(cookie));
    soup_cookie_set_secure(soupCookie, WKCookieGetSecure(cookie));

    return soupCookie;
}

void printLocalStorageDirectory()
{
    gchar* localstoragePath = g_build_filename(g_get_user_data_dir(), "data", receiverOrgName, receiverAppName, nullptr);
    RDKLOG_INFO("Local storage directory = %s", localstoragePath);
    g_free(localstoragePath);
}

bool shouldEnableScrollToFocused(const char* url)
{
    // HACK!! (disabling "scroll to focused" on youtube to avoid weird performance-related artifacts)
    if (strcasestr(url, "youtube.com/tv"))
        return false;

    return true;
}

std::string getPageActiveURL(WKPageRef page)
{
    std::string activeURL;
    auto wk_url = adoptWK(WKPageCopyActiveURL(page));
    if (wk_url)
    {
        WKRetainPtr<WKStringRef> wk_str = adoptWK(WKURLCopyString(wk_url.get()));
        activeURL = toStdString(wk_str.get());
    }
    return activeURL;
}

std::string getPageActiveHost(WKPageRef page)
{
    std::string activeURL;
    auto wk_url = adoptWK(WKPageCopyActiveURL(page));
    if (wk_url)
    {
        WKRetainPtr<WKStringRef> wk_str = adoptWK(WKURLCopyHostName(wk_url.get()));
        activeURL = toStdString(wk_str.get());
    }
    return activeURL;
}

std::string getPageProvisionalURL(WKPageRef page)
{
    std::string provisionalURL;
    auto wk_url = adoptWK(WKPageCopyProvisionalURL(page));
    if (wk_url)
    {
        WKRetainPtr<WKStringRef> wk_str = adoptWK(WKURLCopyString(wk_url.get()));
        provisionalURL = toStdString(wk_str.get());
    }
    return provisionalURL;
}

struct GCharDeleter
{
    void operator()(gchar* ptr) const { g_free(ptr); }
};

// WKContextConfiguration utilities
std::unique_ptr<gchar, GCharDeleter> escapedStringFromFilename(const char* fileName)
{
    std::unique_ptr<gchar, GCharDeleter> escapedString(g_uri_escape_string(fileName, "/:", FALSE));
    return escapedString;
}

std::unique_ptr<gchar, GCharDeleter> defaultWebSQLDatabaseDirectory()
{
    std::unique_ptr<gchar, GCharDeleter> databaseDir(g_build_filename(g_get_user_data_dir(), "wpe", "databases", nullptr));
    return escapedStringFromFilename(databaseDir.get());
}

std::unique_ptr<gchar, GCharDeleter> defaultIndexedDBDatabaseDirectory()
{
    const char* path_start = g_get_user_data_dir();
    if (const char* indexedDbDir = getenv(indexedDbEnvVar))
    {
        path_start = indexedDbDir;
    }
    std::unique_ptr<gchar, GCharDeleter> indexedDBDatabaseDirectory(g_build_filename(path_start, "wpe", "databases", "indexeddb", nullptr));
    return escapedStringFromFilename(indexedDBDatabaseDirectory.get());
}

std::unique_ptr<gchar, GCharDeleter> defaultLocalStorageDirectory()
{
    std::unique_ptr<gchar, GCharDeleter> storageDir(g_build_filename(g_get_user_data_dir(), "data", receiverOrgName, receiverAppName, nullptr));
    return escapedStringFromFilename(storageDir.get());
}

std::unique_ptr<gchar, GCharDeleter> defaultMediaKeysStorageDirectory()
{
    std::unique_ptr<gchar, GCharDeleter> mediaKeysStorageDir(g_build_filename(g_get_user_data_dir(), "wpe", "mediakeys", nullptr));
    return escapedStringFromFilename(mediaKeysStorageDir.get());
}

std::unique_ptr<gchar, GCharDeleter> defaultNetworkCacheDirectory()
{
    std::unique_ptr<gchar, GCharDeleter> diskCacheDir(g_build_filename(g_get_user_cache_dir(), "wpe", "cache", nullptr));
    return escapedStringFromFilename(diskCacheDir.get());
}

std::unique_ptr<gchar, GCharDeleter> defaultApplicationCacheDirectory()
{
    std::unique_ptr<gchar, GCharDeleter> appCacheDir(g_build_filename(g_get_user_cache_dir(), "wpe", "appcache", nullptr));
    return escapedStringFromFilename(appCacheDir.get());
}

std::unique_ptr<gchar, GCharDeleter> defaultMediaCacheDirectory()
{
    std::unique_ptr<gchar, GCharDeleter> mediaCacheDir(g_build_filename(g_get_user_cache_dir(), "wpe", "mediacache", nullptr));
    return escapedStringFromFilename(mediaCacheDir.get());
}

void initWkConfiguration(WKContextConfigurationRef configuration)
{
#define WKSTRING_FROM_UNIQUE_PTR(x) adoptWK(WKStringCreateWithUTF8CString(x.get())).get()
    WKContextConfigurationSetApplicationCacheDirectory(configuration,
           WKSTRING_FROM_UNIQUE_PTR(defaultApplicationCacheDirectory()));
    WKContextConfigurationSetDiskCacheDirectory(configuration,
           WKSTRING_FROM_UNIQUE_PTR(defaultNetworkCacheDirectory()));
    WKContextConfigurationSetIndexedDBDatabaseDirectory(configuration,
           WKSTRING_FROM_UNIQUE_PTR(defaultIndexedDBDatabaseDirectory()));
    WKContextConfigurationSetLocalStorageDirectory(configuration,
           WKSTRING_FROM_UNIQUE_PTR(defaultLocalStorageDirectory()));
    WKContextConfigurationSetWebSQLDatabaseDirectory(configuration,
           WKSTRING_FROM_UNIQUE_PTR(defaultWebSQLDatabaseDirectory()));
    WKContextConfigurationSetMediaKeysStorageDirectory(configuration,
           WKSTRING_FROM_UNIQUE_PTR(defaultMediaKeysStorageDirectory()));
    WKContextConfigurationSetMediaCacheDirectory(configuration,
           WKSTRING_FROM_UNIQUE_PTR(defaultMediaCacheDirectory()));
#undef WKSTRING_FROM_UNIQUE_PTR

    const char* injectedBundleLib = getenv(injectedBundleEnvVar);

    if (!!getenv(disableInjectedBundleEnvVar))
    {
        injectedBundleLib = nullptr;
    }

    if (injectedBundleLib)
    {
        WKContextConfigurationSetInjectedBundlePath(configuration, adoptWK(WKStringCreateWithUTF8CString(injectedBundleLib)).get());
    }
}

void logProcPath(const std::string& path)
{
    std::ifstream fileStream(path);
    if (!fileStream.is_open())
    {
        RDKLOG_INFO("Cannot read file, path=%s", path.c_str());
        return;
    }
    RDKLOG_INFO("-== %s ==-", path.c_str());
    std::string line;
    while (std::getline(fileStream, line))
    {
        RDKLOG_INFO("%s", line.c_str());
    }
}

void logProcStatus(pid_t pid)
{
    logProcPath("/proc/meminfo");
    logProcPath("/proc/loadavg");

    std::string procPath = std::string("/proc/") + std::to_string(pid) + "/status";
    logProcPath(procPath);
}

void killHelper(pid_t pid, int sig)
{
    if (pid < 1)
    {
        RDKLOG_ERROR("Cannot send signal=%d to process=%u", sig, pid);
        return;
    }

    logProcStatus(pid);

    if (syscall(__NR_tgkill, pid, pid, sig) == -1)
    {
        RDKLOG_ERROR("tgkill failed, signal=%d process=%u errno=%d (%s)", sig, pid, errno, strerror(errno));
    }
}

static const int kWebProcessRestorePrioTimeoutInSeconds = 30;

// How often to check WebProcess responsiveness
static const int kWebProcessWatchDogTimeoutInSeconds = 10;

// How many unresponsive replies to handle before declaring WebProcess hang state
//
// Note: We'll try to kill hanging WebProcess after
// (kWebProcessWatchDogTimeoutInSeconds * kWebProcessUnresponsiveReplyDefaultLimit) seconds
static const int kWebProcessUnresponsiveReplyDefaultLimit = 3;
static const int kWebProcessUnresponsiveReplyAVELimit = 9;

static const int WebKitNetworkErrorCancelled = 302;

constexpr char kWebProcessCrashedMessage[]  = "WebProcess crashed";
constexpr char kWebProcessKilledDueHangMessage[] = "WebProcess is killed due to hang";
constexpr char kWebProcessKilledForciblyDueHangMessage[] = "WebProcess is forcibly killed due to hang";
constexpr char kWebProcessKilledDueToMemoryMessage[] = "WebProcess is killed due to memory pressure";

std::string getCrashReasonMessageBySignalNum(int sig)
{
    if (sig == SIGFPE)
        return kWebProcessKilledDueHangMessage;
    else if (sig == SIGKILL)
        return kWebProcessKilledForciblyDueHangMessage;
    return kWebProcessCrashedMessage;
}

uint32_t getMaxMemoryUsageInSupsended()
{
    static uint32_t gMaxMemUsageInSuspendedInBytes = 250 * 1024 * 1024;
    static std::once_flag flag;

    std::call_once(flag, [](){
       const char* env = getenv(maxMemoryUsageInSuspendedEnvVar);
       if (env) {
           uint32_t val = std::stoul(env);
           if (val < 512) {
               gMaxMemUsageInSuspendedInBytes = val * 1024 * 1024;
               RDKLOG_INFO("Max memory usage in background: %u bytes", gMaxMemUsageInSuspendedInBytes);
           }
       }
    });

    return gMaxMemUsageInSuspendedInBytes;
}

std::vector<std::string> splitString(const std::string &s, char delim)
{
    std::vector<std::string> elems;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(std::move(item));
    }
    return elems;
}

bool readStatmLine(pid_t pid, std::string &statmLine)
{
    if (pid <= 1)
    {
        RDKLOG_INFO("Cannot get stats for process id = %u", pid);
        return false;
    }
    std::string procPath = std::string("/proc/") + std::to_string(pid) + "/statm";
    std::ifstream statmStream(procPath);
    if (!statmStream.is_open() || !std::getline(statmStream, statmLine))
    {
        RDKLOG_WARNING("Cannot read process 'statm' file for process id = %u", pid);
        return false;
    }
    return true;
}

bool parseRssFromStatmLine(const std::string &statmLine, uint32_t &inBytes)
{
    std::vector<std::string> items = splitString(statmLine, ' ');
    if (items.size() < 7)
    {
        RDKLOG_WARNING("Unexpected size(%u) of 'statm' line.", items.size());
        return false;
    }
    static const long PageSize = sysconf(_SC_PAGE_SIZE);
    unsigned long rssPageNum = std::stoul(items[1]);
    inBytes = rssPageNum * PageSize;
    return true;
}

bool getProcessMemoryUsage(pid_t pid, uint32_t &inBytes)
{
    std::string statmLine;
    return readStatmLine(pid, statmLine) && parseRssFromStatmLine(statmLine, inBytes);
}

bool isAmazonOrigin(const std::string& origin)
{
    return
        origin.find("atv-ext.amazon.com") != std::string::npos ||
        origin.find("ccast.api.amazonvideo.com") != std::string::npos ||
        origin.find("ccast.api.av-gamma.com") != std::string::npos;
}

void walkLocalStorageDirectory(std::function<bool (const char *dir, const char *name)> handler)
{
    const std::unique_ptr<gchar, GCharDeleter> localstoragePath(g_build_filename(g_get_user_data_dir(), "data", receiverOrgName, receiverAppName, nullptr));

    GError *error = nullptr;
    GDir *dir = g_dir_open(localstoragePath.get(), 0, &error);
    if (!dir)
    {
        RDKLOG_WARNING("Cannot open local storage dir, error=%s", error ? error->message : "unknown");
        if (error)
            g_error_free(error);
        return;
    }

    while (const char* name = g_dir_read_name(dir))
        if (!handler(localstoragePath.get(), name))
            break;

    g_dir_close (dir);
}

void removeEncryptedLocalStorageFiles()
{
#ifndef SQLITE_FILE_HEADER
#  define SQLITE_FILE_HEADER "SQLite format 3"
#endif

    const std::unique_ptr<gchar, GCharDeleter> checkFlagPath(g_build_filename(g_get_user_runtime_dir(), ".rdkbrowser2_storage_check_done", nullptr));
    if (g_file_test(checkFlagPath.get(), G_FILE_TEST_EXISTS))
        return;

    walkLocalStorageDirectory([](const char *dir, const char *name) -> bool {
        // only local storage files
        if (!g_str_has_suffix(name, ".localstorage"))
            return true;

        // only Amazon domains for now
        if (!isAmazonOrigin(name))
            return true;

        RDKLOG_INFO("Checking local storage file '%s'", name);
        std::unique_ptr<gchar, GCharDeleter> storageDBPath(g_build_filename(dir, name, nullptr));
        FILE* fp = fopen(storageDBPath.get(), "r");
        if (!fp)
        {
            RDKLOG_WARNING("Failed to open local storage, file='%s', errno=%d (%s)", storageDBPath.get(), errno, strerror(errno));
            return true;
        }

        size_t headerSize = sizeof(SQLITE_FILE_HEADER) - 1;
        std::unique_ptr<gchar, GCharDeleter> headerData((char *)g_malloc(headerSize));
        if (fread(headerData.get(), headerSize, 1, fp) != 1)
        {
            int err = ferror(fp);
            RDKLOG_WARNING("Failed to read local storage, file='%s', errno=%d (%s)", storageDBPath.get(), err, strerror(err));
        }
        else if (memcmp(headerData.get(), SQLITE_FILE_HEADER, headerSize) != 0)
        {
            RDKLOG_WARNING("Removing encrypted local storage, file='%s'", storageDBPath.get());
            g_unlink(storageDBPath.get());

            std::unique_ptr<gchar, GCharDeleter> walDBPath(g_strconcat(storageDBPath.get(), "-wal", nullptr));
            if (g_file_test(walDBPath.get(), G_FILE_TEST_EXISTS))
                g_unlink(walDBPath.get());

            std::unique_ptr<gchar, GCharDeleter> shmDBPath(g_strconcat(storageDBPath.get(), "-shm", nullptr));
            if (g_file_test(shmDBPath.get(), G_FILE_TEST_EXISTS))
                g_unlink(shmDBPath.get());
        }
        else
        {
            RDKLOG_INFO("Local storage is clear, file='%s'", storageDBPath.get());
        }
        fclose(fp);
        return true;
    });

    // Touch the flag file so we don't try again
    g_close(g_creat(checkFlagPath.get(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH), nullptr);
}

void printLocalStorageDirectorySize()
{
    static std::chrono::system_clock::time_point lastLogTime = std::chrono::system_clock::now() - std::chrono::seconds(6);
    if(std::chrono::system_clock::now() < lastLogTime + std::chrono::seconds(5))
        return;

    std::string result = "{";
    size_t totalSizeInBytes = 0;

    walkLocalStorageDirectory([&result, &totalSizeInBytes](const char *dir, const char *name) -> bool {
        struct stat file_stat;
        std::unique_ptr<gchar, GCharDeleter> storageDBPath(g_build_filename(dir, name, nullptr));
        if (stat(storageDBPath.get(), &file_stat) == 0) {
            std::unique_ptr<gchar, GCharDeleter> rstring(g_strdup_printf("%s%s:%ld", totalSizeInBytes ? ", " : "", name, file_stat.st_size));
            totalSizeInBytes += file_stat.st_size;
            result += rstring.get();
        }
        return true;
    });

    result += "}, LocalStorageTotalSize:" + std::to_string(totalSizeInBytes);

    RDKLOG_WARNING("%s\n", result.c_str());
    lastLogTime = std::chrono::system_clock::now();
}

}

namespace RDK
{

/* WPEBrowser static functions */

void WPEBrowser::userMediaPermissionRequestCallBack(WKPageRef, WKFrameRef, WKSecurityOriginRef, WKSecurityOriginRef, WKUserMediaPermissionRequestRef permissionRequest, const void* /* clientInfo */)
{
    RDKLOG_TRACE("Function entered");
    WKRetainPtr<WKArrayRef> videoUIDs = WKUserMediaPermissionRequestVideoDeviceUIDs(permissionRequest);
    WKRetainPtr<WKStringRef> videoUID = (WKArrayGetSize(videoUIDs.get()) != 0)
        ? reinterpret_cast<WKStringRef>(WKArrayGetItemAtIndex(videoUIDs.get(), 0))
        : WKStringCreateWithUTF8CString("");

    WKRetainPtr<WKArrayRef> audioUIDs = WKUserMediaPermissionRequestAudioDeviceUIDs(permissionRequest);
    WKRetainPtr<WKStringRef> audioUID = (WKArrayGetSize(audioUIDs.get()) != 0)
        ? reinterpret_cast<WKStringRef>(WKArrayGetItemAtIndex(audioUIDs.get(), 0))
        : WKStringCreateWithUTF8CString("");

    WKUserMediaPermissionRequestAllow(permissionRequest, audioUID.get(), videoUID.get());
}

void WPEBrowser::willAddDetailedMessageToConsole(WKPageRef, WKStringRef source, WKStringRef, uint64_t line,
        uint64_t, WKStringRef message, WKStringRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if ((nullptr != browser) && (nullptr != browser->m_browserClient))
    {
        browser->m_browserClient->onConsoleLog(toStdString(source), line, toStdString(message));
    }
}

void WPEBrowser::runBeforeUnloadConfirmPanel(WKPageRef, WKStringRef, WKFrameRef, WKPageRunBeforeUnloadConfirmPanelResultListenerRef listner, const void *)
{
    WKPageRunBeforeUnloadConfirmPanelResultListenerCall(listner, true);  // continue unload
}

void WPEBrowser::closeRequest(WKPageRef page, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if ((nullptr != browser) && (nullptr != browser->m_browserClient))
    {
        if ((WKViewGetPage(browser->m_view.get()) == page))
            browser->m_browserClient->onWindowCloseRequest();
    }
}

void WPEBrowser::nullJavaScriptCallback(WKSerializedScriptValueRef scriptValue, WKErrorRef error, void* context)
{
    RDKLOG_TRACE("Function entered");
    (void)scriptValue;
    (void)error;
    (void)context;
}

void WPEBrowser::didStartProgress(WKPageRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if( (nullptr != browser) && (nullptr != browser->m_browserClient))
    {
        browser->m_httpStatusCode = 0;
        browser->m_loadProgress = 0;
        browser->m_loadFailed = false;
        browser->m_loadCanceled = false;
        browser->m_browserClient->onLoadStarted();
    }
}

void WPEBrowser::didChangeProgress(WKPageRef page, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    int progress = WKPageGetEstimatedProgress(page) * 100;
    if( (nullptr != browser) && (nullptr != browser->m_browserClient))
    {
        browser->m_loadProgress = progress;
        browser->m_browserClient->onLoadProgress(progress);
    }
}

void WPEBrowser::didFinishProgress(WKPageRef page, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if (nullptr == browser || nullptr == browser->m_browserClient)
    {
        return;
    }

    bool loadSucceeded = !browser->m_loadFailed;
    uint32_t httpStatusCode = browser->m_httpStatusCode;
    std::string activeURL = (browser->m_loadFailed && !browser->m_provisionalURL.empty())
        ? browser->m_provisionalURL
        : getPageActiveURL(page);

    if (browser->m_loadCanceled)
    {
        RDKLOG_WARNING("Skip onLoadFinished notification, load canceled, current progress=%u url=%s", browser->m_loadProgress, activeURL.c_str());
    }
    else if (loadSucceeded && browser->m_loadProgress < 100)
    {
        RDKLOG_WARNING("Skip onLoadFinished notification, load not finished yet, current progress=%u url=%s", browser->m_loadProgress, activeURL.c_str());
    }
    else
    {
        browser->restoreWebProcessPrio();
        browser->collectMetricsOnLoadEnd();
        browser->m_browserClient->onLoadFinished(loadSucceeded, httpStatusCode, activeURL);
        browser->m_webProcessState = WebProcessHot;
    }

    browser->m_httpStatusCode = 0;
    browser->m_loadProgress = 0;
    browser->m_loadFailed = false;
    browser->m_loadCanceled = false;
    browser->m_provisionalURL.clear();
}

void WPEBrowser::didStartProvisionalNavigation(WKPageRef page, WKNavigationRef, WKTypeRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if ((nullptr != browser) && (nullptr != browser->m_browserClient))
    {
        browser->m_provisionalURL = getPageProvisionalURL(page);
        RDKLOG_INFO("provisionalURL=%s", browser->m_provisionalURL.c_str());
    }
}

void WPEBrowser::didFailProvisionalNavigation(WKPageRef page, WKNavigationRef, WKErrorRef error, WKTypeRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if ((nullptr != browser) && (nullptr != browser->m_browserClient))
    {
        browser->m_loadFailed = true;

        std::string failedURL = browser->m_provisionalURL.empty()
            ? getPageActiveURL(page)
            : browser->m_provisionalURL;
        auto errorDomain = adoptWK(WKErrorCopyDomain(error));
        auto errorDescription = adoptWK(WKErrorCopyLocalizedDescription(error));

        if (toStdString(errorDomain.get()) == "WebKitNetworkError" && WebKitNetworkErrorCancelled == WKErrorGetErrorCode(error))
            browser->m_loadCanceled = true;

        RDKLOG_ERROR("Load Failed with error(code=%d, domain=%s, message=%s) url=%s\n",
                     WKErrorGetErrorCode(error),
                     toStdString(errorDomain.get()).c_str(),
                     toStdString(errorDescription.get()).c_str(),
                     failedURL.c_str());
    }
}

void WPEBrowser::didFailNavigation(WKPageRef page, WKNavigationRef, WKErrorRef error, WKTypeRef, const void *clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if ((nullptr != browser) && (nullptr != browser->m_browserClient))
    {
        browser->m_loadFailed = true;

        std::string failedURL = browser->m_provisionalURL.empty()
            ? getPageActiveURL(page)
            : browser->m_provisionalURL;
        auto errorDomain = adoptWK(WKErrorCopyDomain(error));
        auto errorDescription = adoptWK(WKErrorCopyLocalizedDescription(error));

        if (toStdString(errorDomain.get()) == "WebKitNetworkError" && WebKitNetworkErrorCancelled == WKErrorGetErrorCode(error))
            browser->m_loadCanceled = true;

        RDKLOG_ERROR("Load Failed with error(code=%d, domain=%s, message=%s) url=%s\n",
                     WKErrorGetErrorCode(error),
                     toStdString(errorDomain.get()).c_str(),
                     toStdString(errorDescription.get()).c_str(),
                     failedURL.c_str());
    }
}

void WPEBrowser::didCommitNavigation(WKPageRef page, WKNavigationRef, WKTypeRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    auto wk_url = adoptWK(WKPageCopyCommittedURL(page));
    WKRetainPtr<WKStringRef>string = adoptWK(WKURLCopyString(wk_url.get()));

    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if ((nullptr != browser) && (nullptr != browser->m_browserClient))
    {
        browser->m_browserClient->onUrlChanged(toStdString(string.get()));
    }
}

void WPEBrowser::didSameDocumentNavigation(WKPageRef page, WKNavigationRef, WKSameDocumentNavigationType navigationType, WKTypeRef, const void*)
{
    std::string activeURL = getPageActiveURL(page);
    RDKLOG_INFO("navigationType=%d url=%s", navigationType, activeURL.c_str());
    if (navigationType == kWKSameDocumentNavigationAnchorNavigation)
        fprintf(stderr, "Url changed: %s\n", activeURL.c_str());
}

void WPEBrowser::decidePolicyForNavigationAction(WKPageRef, WKNavigationActionRef, WKFramePolicyListenerRef listener,
        WKTypeRef, const void*)
{
    WKFramePolicyListenerUse(listener);
}

#ifdef ENABLE_WEB_AUTOMATION
WKPageRef WPEBrowser::onAutomationSessionRequestNewPage(WKWebAutomationSessionRef , const void* clientInfo)
{
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if ((nullptr != browser) || (nullptr != browser->m_browserClient)){
        return WKViewGetPage(browser->m_view.get());
    }
    else
        return nullptr;
}

WKStringRef WPEBrowser::browserVersion(WKContextRef , const void*)
{
    return WKStringCreateWithUTF8CString("1.0");
}

bool WPEBrowser::allowsRemoteAutomation(WKContextRef , const void* )
{
    return true;
}

WKStringRef WPEBrowser::browserName(WKContextRef , const void*)
{
    return WKStringCreateWithUTF8CString("rdkbrowser2");
}

void WPEBrowser::didRequestAutomationSession(WKContextRef context, WKStringRef sessionID, const void* clientInfo)
{
    RDKLOG_TRACE("Request for automation session to enable");
    WKWebAutomationsessionClientV0 handlerAutomationSession;
    memset(&handlerAutomationSession, 0, sizeof(handlerAutomationSession));
    handlerAutomationSession.base.version = 0;
    handlerAutomationSession.base.clientInfo =  clientInfo ;
    handlerAutomationSession.requestNewPage = WPEBrowser::onAutomationSessionRequestNewPage;
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    browser->m_webAutomationSession = adoptWK(WKWebAutomationSessionCreate(sessionID));
    WKWebAutomationSessionSetClient(browser->m_webAutomationSession.get(), &handlerAutomationSession.base);
    WKContextSetAutomationSession(context, browser->m_webAutomationSession.get());
}
#endif

void WPEBrowser::decidePolicyForNavigationResponse(WKPageRef, WKNavigationResponseRef navigationResponse,
        WKFramePolicyListenerRef listener, WKTypeRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if (nullptr != browser && WKNavigationResponseIsMainFrame(navigationResponse))
    {
        WKRetainPtr<WKURLResponseRef> response = adoptWK(WKNavigationResponseGetURLResponse(navigationResponse));
        browser->m_httpStatusCode = WKURLResponseHTTPStatusCode(response.get());
    }

    WKFramePolicyListenerUse(listener);
}

void WPEBrowser::webProcessDidCrash(WKPageRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if( (nullptr != browser) && (nullptr != browser->m_browserClient) && (!browser->m_crashed) )
    {
        std::string reason = getCrashReasonMessageBySignalNum(browser->m_signalSentToWebProcess);
        browser->m_browserClient->onRenderProcessTerminated(reason);
        browser->stopWebProcessWatchDog();
        browser->m_crashed = true;

        //clearing intentionally until Initialize
        browser->m_crashId.clear();
    }
}

void WPEBrowser::didReceiveAuthenticationChallenge(WKPageRef, WKAuthenticationChallengeRef challenge, const void*)
{
    RDKLOG_TRACE("Function entered");
    auto listener = WKAuthenticationChallengeGetDecisionListener(challenge);
    WKAuthenticationDecisionListenerUseCredential(listener, nullptr);
}

WPEBrowser::WPEBrowser()
{
    m_unresponsiveReplyMaxNum = kWebProcessUnresponsiveReplyDefaultLimit;

    static std::once_flag flag;
    std::call_once(flag, [](){
#if defined(ENABLE_LOCALSTORAGE_ENCRYPTION)
        bool shouldDeleteEncryptedStorage = !!getenv(deleteEncryptedStorageEnvVar);
#else
        bool shouldDeleteEncryptedStorage = true;
#endif
        if (shouldDeleteEncryptedStorage)
            ::removeEncryptedLocalStorageFiles();
    });
}

WPEBrowser::~WPEBrowser()
{
    RDKLOG_TRACE("Function entered");
    WKCookieManagerStopObservingCookieChanges(WKContextGetCookieManager(m_context.get()));
    WKCookieManagerSetClient(WKContextGetCookieManager(m_context.get()), nullptr);

    if(getenv(injectedBundleEnvVar) && !!m_view)
        WKPageSetPageInjectedBundleClient(WKViewGetPage(m_view.get()), nullptr);

    closePage();

    WKPageConfigurationSetPageGroup(m_pageConfiguration.get(), nullptr);
    WKPageConfigurationSetContext(m_pageConfiguration.get(), nullptr);
    if(m_webDataStore) {
        WKPageConfigurationSetWebsiteDataStore(m_pageConfiguration.get(), nullptr);
        m_webDataStore = nullptr;
    }

    m_view = nullptr;
    m_context = nullptr;
    m_pageConfiguration = nullptr;
    m_pageGroup = nullptr;
    m_pageGroupIdentifier = nullptr;

#ifdef ENABLE_WEB_AUTOMATION
    m_webAutomationSession = nullptr;
#endif

    stopWebProcessWatchDog();
}

WKRetainPtr<WKContextRef> WPEBrowser::getOrCreateContext(bool useSingleContext)
{
    if (getenv(testHangDetectorEnvVar))
    {
        sleep(1000);
    }
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner(g_main_context_default()));

    static WKRetainPtr<WKContextRef> g_context {nullptr};

    if (useSingleContext && g_context)
        return g_context;

    static auto createRawContextPtr = [] () -> WKContextRef {
        auto configuration = adoptWK(WKContextConfigurationCreate());
        initWkConfiguration(configuration.get());

        WKContextRef ctx = WKContextCreateWithConfiguration(configuration.get());

        // Cache mode specifies the in memory and disk cache sizes,
        // for details see Source/WebKit2/Shared/CacheModel.cpp
        WKContextSetCacheModel(ctx, kWKCacheModelPrimaryWebBrowser);  // kWKCacheModelDocumentBrowser

        RDKLOG_INFO("Created a new browser context %p", ctx);
        return ctx;
    };

    WKRetainPtr<WKContextRef> new_context;
    new_context = adoptWK(createRawContextPtr());
    if (useSingleContext)
    {
        RDKLOG_INFO("Using single context(NetworkProcess) mode");
        g_context = new_context;
        WKContextSetMaximumNumberOfProcesses(new_context.get(), -1);
    } else {
        RDKLOG_INFO("Using multiple context(NetworkProcess) mode");
    }

    return new_context;
}

RDKBrowserError WPEBrowser::Initialize(bool useSingleContext, bool nonCompositedWebGLEnabled /*= false */)
{
    RDKLOG_TRACE("Function entered");
    const char* injectedBundleLib = getenv(injectedBundleEnvVar);
    if (!m_context)
    {
        m_ephemeralMode = !!getenv(enableEphemeralModeEnvVar);
        m_useSingleContext = useSingleContext;
        m_context = getOrCreateContext(useSingleContext);
        // WebKit ignores TLS errors by default, we by default turn off this ignoring
        WKSoupSessionSetIgnoreTLSErrors(m_context.get(), getenv(ignoreTLSErrorsEnvVar));

        m_pageGroupIdentifier = adoptWK(WKStringCreateWithUTF8CString("WPERDKPageGroup"));
        m_pageGroup = adoptWK(WKPageGroupCreateWithIdentifier(m_pageGroupIdentifier.get()));
        m_pageConfiguration = adoptWK(WKPageConfigurationCreate());
        WKPageConfigurationSetContext(m_pageConfiguration.get(), m_context.get());
        WKPageConfigurationSetPageGroup(m_pageConfiguration.get(), m_pageGroup.get());
        if (m_useSingleContext || m_ephemeralMode)
        {
            m_webDataStore = adoptWK(WKWebsiteDataStoreCreateNonPersistentDataStore());
            WKPageConfigurationSetWebsiteDataStore(m_pageConfiguration.get(), m_webDataStore.get());
        }
    }

    generateCrashId();

#ifdef WPE_WEBKIT1
    // Disable ICE Candidate filter
    WKPreferencesSetICECandidateFilteringEnabled(getPreferences(), false);
#endif

    WKPreferencesSetNonCompositedWebGLEnabled(getPreferences(), nonCompositedWebGLEnabled);
    if (nonCompositedWebGLEnabled)
        RDKLOG_INFO("Initializing web page with non composited WebGL enabled");

    static bool enableDeveloperExtras = !!getenv("WEBKIT_INSPECTOR_SERVER");
    WKPreferencesSetDeveloperExtrasEnabled(getPreferences(), enableDeveloperExtras);

    printLocalStorageDirectory();
    setLocalStorageEnabled(false);
    setConsoleLogEnabled(true);
    enableScrollToFocused(false);

    // Enable WebSecurity (must be executed after creating a view)
    enableWebSecurity(m_webSecurityEnabled); // m_pageGroup must be initialized before this call

    WKPreferencesSetPageCacheEnabled(getPreferences(), false);

    //FIXME remove when Roger 4k and others are fully migrated to HTTPS
    WKPreferencesSetAllowRunningOfInsecureContent(getPreferences(), true);
    WKPreferencesSetAllowDisplayOfInsecureContent(getPreferences(), true);

#ifdef WPE_WEBKIT1
    m_view = adoptWK(WKViewCreate(wpe_view_backend_create(), m_pageConfiguration.get())); // WebSecurity is being disabled here
#else
    m_view = adoptWK(WKViewCreateWithViewBackend(wpe_view_backend_create(), m_pageConfiguration.get())); // WebSecurity is being disabled here
#endif
    auto page = WKViewGetPage(m_view.get());

    setTransparentBackground(true); // by default background should be transparent

    if (injectedBundleLib)
    {
        WKPageInjectedBundleClientV0 bundleClient;
        bundleClient.base.version = 0;
        bundleClient.base.clientInfo = this;
        bundleClient.didReceiveMessageFromInjectedBundle = WPEBrowser::didReceiveMessageFromInjectedBundle;
        bundleClient.didReceiveSynchronousMessageFromInjectedBundle = nullptr;
        WKPageSetPageInjectedBundleClient(page, &bundleClient.base);
    }

    WKPageUIClientV8 pageUIClient;
    memset(&pageUIClient, 0, sizeof(pageUIClient));
    pageUIClient.base.version = 8;
    pageUIClient.base.clientInfo = this;
    pageUIClient.decidePolicyForUserMediaPermissionRequest = WPEBrowser::userMediaPermissionRequestCallBack;
    pageUIClient.willAddDetailedMessageToConsole = WPEBrowser::willAddDetailedMessageToConsole;
    pageUIClient.runBeforeUnloadConfirmPanel = WPEBrowser::runBeforeUnloadConfirmPanel;
    pageUIClient.close = WPEBrowser::closeRequest;
    WKPageSetPageUIClient(page, &pageUIClient.base);

    WKPageNavigationClientV0 pageNavigationClient;
    memset(&pageNavigationClient, 0, sizeof(pageNavigationClient));
    pageNavigationClient.base.version = 0;
    pageNavigationClient.base.clientInfo = this;
    pageNavigationClient.didStartProvisionalNavigation = WPEBrowser::didStartProvisionalNavigation;
    pageNavigationClient.didFailProvisionalNavigation = WPEBrowser::didFailProvisionalNavigation;
    pageNavigationClient.didFailNavigation = WPEBrowser::didFailNavigation;
    pageNavigationClient.didCommitNavigation = WPEBrowser::didCommitNavigation;
    pageNavigationClient.didSameDocumentNavigation = WPEBrowser::didSameDocumentNavigation;
    pageNavigationClient.decidePolicyForNavigationAction = WPEBrowser::decidePolicyForNavigationAction;
    pageNavigationClient.decidePolicyForNavigationResponse = WPEBrowser::decidePolicyForNavigationResponse;
    pageNavigationClient.webProcessDidCrash = WPEBrowser::webProcessDidCrash;
    pageNavigationClient.didReceiveAuthenticationChallenge = WPEBrowser::didReceiveAuthenticationChallenge;
    WKPageSetPageNavigationClient(page, &pageNavigationClient.base);

    WKPageLoaderClientV6 pageLoadClient;
    memset(&pageLoadClient, 0, sizeof(pageLoadClient));
    pageLoadClient.base.version = 6;
    pageLoadClient.base.clientInfo = this;
    pageLoadClient.didStartProgress = WPEBrowser::didStartProgress;
    pageLoadClient.didChangeProgress = WPEBrowser::didChangeProgress;
    pageLoadClient.didFinishProgress = WPEBrowser::didFinishProgress;
    pageLoadClient.processDidBecomeResponsive = WPEBrowser::processDidBecomeResponsive;
    WKPageSetPageLoaderClient(page, &pageLoadClient.base);

    WKCookieManagerClientV0 wkCookieManagerClient =
    {
        { 0, this },
        cookiesDidChange
    };
    WKCookieManagerSetClient(WKContextGetCookieManager(m_context.get()), &wkCookieManagerClient.base);
    WKCookieManagerStartObservingCookieChanges(WKContextGetCookieManager(m_context.get()));

    if (m_ephemeralMode)
        WKCookieManagerSetHTTPCookieAcceptPolicy(WKContextGetCookieManager(m_context.get()), kWKHTTPCookieAcceptPolicyAlways);

    //Setting default user-agent string for WPE
    RDKLOG_TRACE("Appending NativeXREReceiver to the WPE standard useragent string");
    m_defaultUserAgent = toStdString(adoptWK(WKPageCopyUserAgent(WKViewGetPage(m_view.get()))).get());
    m_defaultUserAgent.append(" NativeXREReceiver");
    setUserAgent(m_defaultUserAgent.c_str());

    m_isKilledDueToMemoryPressure = false;
    m_signalSentToWebProcess = -1;
    m_gettingCookies = false;
    m_dirtyCookies = false;
    m_webProcessState = WebProcessCold;
    m_cookieJar.clear();
    m_provisionalURL.clear();
    stopWebProcessWatchDog();

    WKPageIsWebProcessResponsive(WKViewGetPage(m_view.get()), this, [](bool isWebProcessResponsive, void* context) {
        WPEBrowser& self = *static_cast<WPEBrowser*>(context);
        if (isWebProcessResponsive && self.m_webProcessState == WebProcessCold)
            self.m_webProcessState = WebProcessHot;
    });

#if defined(ENABLE_LOCALSTORAGE_ENCRYPTION)
    static std::once_flag flag;
    std::call_once(flag, [](){
        WKLocalStorageEncryptionExtensionClientV0 encryptionExtensionClient =
        {
            { 0, nullptr },
            [](WKSecurityOriginRef securityOrigin, WKDataRef *returnData, const void*)
            {
                if (!returnData)
                    return;

                WKRetainPtr<WKStringRef> wkOriginStr = adoptWK(WKSecurityOriginCopyToString(securityOrigin));
                std::string origin = toStdString(wkOriginStr.get());
                *returnData = nullptr;

                // Only Amazon for now.
                if (!isAmazonOrigin(origin))
                    return;

                #if defined(USE_PLABELS)
                bool result = pbnj_utils::prepareBufferForOrigin(origin, [&returnData](const std::vector<uint8_t>& buffer) {
                    if (buffer.size())
                        *returnData = WKDataCreate(buffer.data(), buffer.size());
                });
                if (!result && *returnData)
                    *returnData = nullptr;
                #endif
            }
        };
        WKLocalStorageEncryptionExtensionSetClient(&encryptionExtensionClient.base);
    });
#endif

    m_httpStatusCode = 0;
    m_loadProgress = 0;
    m_loadFailed = false;
    m_loadCanceled = false;
    m_voiceGuidanceEnabled = false;
    m_voiceGuidanceMode = synthesisMode;

    m_pageLoadNum = 0;
    m_idleStart = g_get_monotonic_time();

    return RDKBrowserSuccess;
}

void WPEBrowser::increaseWebProcessPrio()
{
    RDKLOG_TRACE("Function entered");
    if (!m_view || !m_canIncreasePrio)
        return;
    pid_t webprocessPID = WKPageGetProcessIdentifier(WKViewGetPage(m_view.get()));
    if (webprocessPID)
    {
        struct sched_param param;
        param.sched_priority = 1;
        int r = sched_setscheduler(webprocessPID, SCHED_RR | SCHED_RESET_ON_FORK, &param);
        if (r != 0)
        {
            RDKLOG_ERROR("Failed to set RR sched policy, errno=%d (%s)", errno, strerror(errno));
        }
        else
        {
            m_didIncreasePrio = true;
            RDKLOG_TRACE("Increased prio");
        }
    }

    if (m_didIncreasePrio)
    {
        if (m_restorePrioTag)
            g_source_remove(m_restorePrioTag);

        m_restorePrioTag = g_timeout_add_seconds_full(G_PRIORITY_DEFAULT_IDLE,
            kWebProcessRestorePrioTimeoutInSeconds, [](gpointer data) -> gboolean {
                static_cast<WPEBrowser*>(data)->restoreWebProcessPrio();
                return G_SOURCE_REMOVE;
        }, this, nullptr);

        m_canIncreasePrio = false;
    }
}

void WPEBrowser::restoreWebProcessPrio()
{
    RDKLOG_TRACE("Function entered");
    if (!m_view || !m_didIncreasePrio)
        return;
    m_didIncreasePrio = false;
    pid_t webprocessPID = WKPageGetProcessIdentifier(WKViewGetPage(m_view.get()));
    if (webprocessPID)
    {
        struct sched_param param;
        param.sched_priority = 0;  // must be zero
        int r = sched_setscheduler(webprocessPID, SCHED_OTHER, &param);
        if (r != 0)
        {
            RDKLOG_ERROR("Failed to set OTHER sched policy, errno=%d (%s)", errno, strerror(errno));
        }
        else
        {
            RDKLOG_TRACE("Restored prio");
        }
    }

    if (m_restorePrioTag)
    {
        g_source_remove(m_restorePrioTag);
        m_restorePrioTag = 0;
    }
}

RDKBrowserError WPEBrowser::LoadURL(const char* url)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner(g_main_context_default()));

    if (m_isSuspended)
    {
        // Mark view visible to avoid possible throttle on load
        setVisible(true);
        m_isSuspended = false;
    }

    enableScrollToFocused(shouldEnableScrollToFocused(url));

    // Enable ARIA based accessibility
    bool ariaAccessibilityEnabled = false;
    if(getenv(wpeAccessibilityEnvVar) &&
            m_voiceGuidanceEnabled &&
            m_voiceGuidanceMode == ariaAccessibilityMode) {
        ariaAccessibilityEnabled = true;
    }
    WKPreferencesSetAccessibilityEnabled(getPreferences(), ariaAccessibilityEnabled);

    m_provisionalURL.clear();
    m_pageLoadStart = g_get_monotonic_time();

    WKRetainPtr<WKURLRef> wkUrl = adoptWK(WKURLCreateWithUTF8CString(url));
    WKPageLoadURL(WKViewGetPage(m_view.get()), wkUrl.get());

    if (url && *url && strcmp("about:blank", url) != 0)
    {
        ++m_pageLoadNum;
        increaseWebProcessPrio();
        collectMetricsOnLoadStart();
    }

    startWebProcessWatchDog();
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::SetHTML(const char* html)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner(g_main_context_default()));

    if (m_isSuspended)
    {
        // Mark view visible to avoid possible throttle on load
        setVisible(true);
        m_isSuspended = false;
    }

    m_provisionalURL.clear();

    WKRetainPtr<WKStringRef> wkHtml = adoptWK(WKStringCreateWithUTF8CString(html));
    WKRetainPtr<WKURLRef> wkBaseUrl = adoptWK(WKURLCreateWithUTF8CString(nullptr));
    WKPageLoadHTMLString(WKViewGetPage(m_view.get()), wkHtml.get(), wkBaseUrl.get());
    return RDKBrowserSuccess;
}

WKPreferencesRef WPEBrowser::getPreferences() const
{
    RDKLOG_TRACE("Function entered");
    g_main_context_is_owner(g_main_context_default());

    WKPreferencesRef preferences = WKPageGroupGetPreferences(m_pageGroup.get());
    if (!preferences)
    {
        RDKLOG_FATAL("preferences ptr is null");
        return nullptr;
    }

    return preferences;
}

bool WPEBrowser::enableScrollToFocused(bool enable)
{
    RDKLOG_TRACE("Function entered");
    WKPreferencesRef preferences = getPreferences();
    if (!preferences)
        return false;

    RDKLOG_INFO("[%s], was: [%s]",
                enable ? "true" : "false",
                WKPreferencesGetScrollToFocusedElementEnabled(preferences) ? "true" : "false");
    WKPreferencesSetScrollToFocusedElementEnabled(preferences, enable);

    return true;
}

bool WPEBrowser::enableWebSecurity(bool on)
{
    RDKLOG_TRACE("Function entered");
    WKPreferencesRef preferences = getPreferences();
    if (!preferences)
        return false;

    m_webSecurityEnabled = on;
    RDKLOG_INFO("[%s], was: [%s]",
                on ? "true" : "false",
                WKPreferencesGetWebSecurityEnabled(preferences) ? "true" : "false");
    WKPreferencesSetWebSecurityEnabled(preferences, on);

    return true;
}

void WPEBrowser::sendJavaScriptResponse(WKSerializedScriptValueRef scriptValue, WKErrorRef error, NeedResult respType)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner (g_main_context_default()));

    if (!m_browserClient)
    {
        // Client might be already dead but called within callback invalidating.
        return;
    }

    if (m_callIds.empty())
    {
        RDKLOG_ERROR("Call id queue is empty, but expected to have at least on pending call there");
        return;
    }

    std::string callGUID = m_callIds.front();
    m_callIds.pop();

    int statusCode = error ? WKErrorGetErrorCode(error) : 0;
    std::string message;

    if (statusCode)
    {
        WKRetainPtr<WKStringRef> wkDescr = adoptWK(WKErrorCopyLocalizedDescription(error));
        message = toStdString(wkDescr.get());
    }

    if (respType == NeedResult::DontNeed)
    {
        m_browserClient->onEvaluateJavaScript(statusCode, callGUID, message, !error);
        return;
    }

    if (!gJSContext)
    {
        gJSContext = JSGlobalContextCreate(nullptr);
    }

    if (!scriptValue)
    {
        RDKLOG_ERROR("ScriptValue is invalid.");
        m_browserClient->onCallJavaScriptWithResult(statusCode, callGUID, message, gJSContext, nullptr);
        return;
    }

    JSValueRef exc = nullptr;
    JSValueRef jsVal = WKSerializedScriptValueDeserialize(scriptValue, gJSContext, &exc);
    if (exc)
    {
        RDKLOG_ERROR("Converting script value");
        m_browserClient->onCallJavaScriptWithResult(statusCode, callGUID, message, gJSContext, nullptr);
        return;
    }
    m_browserClient->onCallJavaScriptWithResult(statusCode, callGUID, message, gJSContext, jsVal);
}

RDKBrowserError WPEBrowser::evaluateJavaScript(const std::string& javascript, const std::string& callId, bool needResult)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner (g_main_context_default()));

    m_callIds.emplace(callId);

    WKRetainPtr<WKStringRef> wkScriptString = adoptWK(WKStringCreateWithUTF8CString(javascript.c_str()));

    CallJSData* data = new CallJSData(callId, this, needResult, javascript);

    WKPageRunJavaScriptInMainFrame(WKViewGetPage(m_view.get()), wkScriptString.get(), data,
        [](WKSerializedScriptValueRef scriptValue, WKErrorRef error, void* context)
        {
            rdk_assert(g_main_context_is_owner (g_main_context_default()));

            CallJSData* data = reinterpret_cast<CallJSData*>(context);
            WPEBrowser* browser;
            std::string callId, javascript;
            bool needResult;

            std::tie(callId, browser, needResult, javascript) = *data;

            NeedResult type = needResult ? NeedResult::Need : NeedResult::DontNeed;
            browser->sendJavaScriptResponse(scriptValue, error, type);

            delete data;
        }
    );

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::scrollTo(double x, double y)
{
    RDKLOG_TRACE("Function entered");
    char scrollString[64];
    memset(scrollString, 0, sizeof(scrollString));
    sprintf(scrollString, "window.scrollTo(%f,%f); null", x, y);

    return executeJs(scrollString);
}

RDKBrowserError WPEBrowser::scrollBy(double x, double y)
{
    RDKLOG_TRACE("Function entered");
    char scrollString[64];
    memset(scrollString, 0, sizeof(scrollString));
    sprintf(scrollString, "window.scrollBy(%f,%f); null", x, y);

    return executeJs(scrollString);
}

RDKBrowserError WPEBrowser::setSpatialNavigation(bool enabled)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner(g_main_context_default()));

    WKPreferencesRef preferences = getPreferences();
    g_return_val_if_fail(preferences, RDKBrowserFailed);

    WKPreferencesSetSpatialNavigationEnabled(preferences, enabled);
    WKPreferencesSetTabsToLinks(preferences, enabled);

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setWebSecurityEnabled(bool enabled)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner(g_main_context_default()));
    enableWebSecurity(enabled);

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::getWebSecurityEnabled(bool &enabled) const
{
    RDKLOG_TRACE("Function entered");
    WKPreferencesRef preferences = getPreferences();
    if (!preferences) {
        enabled = false;
        return RDKBrowserFailed;
    }

    enabled = WKPreferencesGetWebSecurityEnabled(preferences);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setIgnoreResize(bool enabled)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner(g_main_context_default()));

    if (WKViewGetIgnoreResize(m_view.get()) != enabled)
    {
        RDKLOG_INFO("should ignore resize = %s", enabled ? "yes": "no");
        WKViewSetIgnoreResize(m_view.get(), enabled);
    }

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::getIgnoreResize(bool &enabled) const
{
    RDKLOG_TRACE("Function entered");

    enabled = WKViewGetIgnoreResize(m_view.get());

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setAllowScriptsToCloseWindow(bool enabled)
{
    RDKLOG_TRACE("Function entered");
    WKPreferencesRef preferences = getPreferences();
    if (!preferences)
        return RDKBrowserFailed;

    if (WKPreferencesGetAllowScriptsToCloseWindow(preferences) != enabled)
    {
        RDKLOG_INFO("AllowScriptsToCloseWindow = %s", enabled ? "yes": "no");
        WKPreferencesSetAllowScriptsToCloseWindow(getPreferences(), enabled);
    }
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::getAllowScriptsToCloseWindow(bool &enabled) const
{
    RDKLOG_TRACE("Function entered");
    WKPreferencesRef preferences = getPreferences();
    if (!preferences) {
        enabled = false;
        return RDKBrowserFailed;
    }
    enabled = WKPreferencesGetAllowScriptsToCloseWindow(preferences);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setAVEEnabled(bool enabled)
{
    RDKLOG_TRACE("Function entered");

    if (enabled && m_unresponsiveReplyMaxNum != kWebProcessUnresponsiveReplyAVELimit)
    {
        m_unresponsiveReplyMaxNum = kWebProcessUnresponsiveReplyAVELimit;
        RDKLOG_INFO("Increased the max num of unresponsive replies to %d for AVE context", m_unresponsiveReplyMaxNum);
    }

    WKPagePostMessageToInjectedBundle(
        WKViewGetPage(m_view.get()),
        WKRetainPtr<WKStringRef>(adoptWK(WKStringCreateWithUTF8CString("setAVEEnabled"))).get(),
        WKRetainPtr<WKBooleanRef>(adoptWK(WKBooleanCreate(enabled))).get()
        );

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setAVESessionToken(const char* token)
{
    RDKLOG_TRACE("Function entered");
  rdk_assert(g_main_context_is_owner(g_main_context_default()));
  WKPagePostMessageToInjectedBundle(
      WKViewGetPage(m_view.get()),
      WKRetainPtr<WKStringRef>(adoptWK(WKStringCreateWithUTF8CString("setAVESessionToken"))).get(),
      WKRetainPtr<WKStringRef>(adoptWK(WKStringCreateWithUTF8CString(token))).get()
      );
  return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setAVELogLevel(uint64_t level)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner(g_main_context_default()));

    if (!m_view)
        return RDKBrowserFailed;
    WKPagePostMessageToInjectedBundle(
        WKViewGetPage(m_view.get()),
        WKRetainPtr<WKStringRef>(adoptWK(WKStringCreateWithUTF8CString("setAVELogLevel"))).get(),
        WKRetainPtr<WKUInt64Ref>(adoptWK(WKUInt64Create(level))).get()
    );

    return RDKBrowserSuccess;
}

void WPEBrowser::registerClient(RDKBrowserClient* client)
{
    RDKLOG_TRACE("Function entered");
    m_browserClient = client;
}

RDKBrowserError WPEBrowser::executeJs(const char* jsCode)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner(g_main_context_default()));
    WKRetainPtr<WKStringRef> wkScriptString = adoptWK(WKStringCreateWithUTF8CString(jsCode));
    WKPageRunJavaScriptInMainFrame(WKViewGetPage(m_view.get()), wkScriptString.get(), this, nullJavaScriptCallback);

    RDKBrowserError retval = RDKBrowserSuccess;

    return retval;
}

RDKBrowserError WPEBrowser::sendJavaScriptBridgeResponse(uint64_t callID, bool success, const char* message)
{
    RDKLOG_TRACE("Function entered");

    const int argc = 3;
    WKRetainPtr<WKUInt64Ref> callIDRef = adoptWK(WKUInt64Create(callID));
    WKRetainPtr<WKBooleanRef> successRef = adoptWK(WKBooleanCreate(success));
    WKRetainPtr<WKStringRef> messageRef = adoptWK(WKStringCreateWithUTF8CString(message));
    WKTypeRef params[argc] = {callIDRef.get(), successRef.get(), messageRef.get()};
    WKRetainPtr<WKArrayRef> arrRef = adoptWK(WKArrayCreate(params, argc));
    WKPagePostMessageToInjectedBundle(
        WKViewGetPage(m_view.get()),
        WKRetainPtr<WKStringRef>(adoptWK(WKStringCreateWithUTF8CString("onJavaScriptBridgeResponse"))).get(),
        arrRef.get()
        );

    return RDKBrowserSuccess;
}

void WPEBrowser::didReceiveMessageFromInjectedBundle(WKPageRef page, WKStringRef messageName, WKTypeRef messageBody, const void *clientInfo)
{
    RDKLOG_TRACE("Function entered, messageName %p, messageBody %p, clientInfo %p", messageName, messageBody, clientInfo);
    auto browser = (WPEBrowser*) clientInfo;
    auto client = browser ? browser->m_browserClient : nullptr;
    if (!client)
    {
        RDKLOG_ERROR("No browser client found!");
        return;
    }

    if (WKGetTypeID(messageBody) != WKArrayGetTypeID())
    {
        RDKLOG_ERROR("Message body must be an array!");
        return;
    }

    size_t size = WKStringGetMaximumUTF8CStringSize(messageName);
    auto name = std::make_unique<char[]>(size);
    size = WKStringGetUTF8CString(messageName, name.get(), size);

    if (strncmp(name.get(), "onNavigationTiming", size) == 0)
    {
        WKArrayRef responseArray = (WKArrayRef) messageBody;
        if (WKArrayGetSize(responseArray) != 2)
        {
            RDKLOG_ERROR("Incorrect message body size in 'onNavigationTiming' response");
            return;
        }

        uint64_t callID = WKUInt64GetValue((WKUInt64Ref) WKArrayGetItemAtIndex(responseArray, 0));
        if (navigationTimingsRequestId != callID)
        {
            RDKLOG_WARNING("Ignore timing response for callID = %llu, waiting for = %llu", callID, navigationTimingsRequestId);
            return;
        }

        WKStringRef bodyRef = (WKStringRef) WKArrayGetItemAtIndex(responseArray, 1);
        browser->m_launchMetricsMetrics["webTiming"] = toStdString(bodyRef);
        browser->reportLaunchMetrics();
        return;
    }


    if (strncmp(name.get(), "onAVELog", size) == 0)
    {
        if (WKArrayGetSize((WKArrayRef) messageBody) != 3)
        {
            RDKLOG_ERROR("Wrong array size!");
            return;
        }

        WKStringRef prefixRef = (WKStringRef) WKArrayGetItemAtIndex((WKArrayRef) messageBody, 0);
        size = WKStringGetMaximumUTF8CStringSize(prefixRef);
        auto prefix = std::make_unique<char[]>(size);
        (void) WKStringGetUTF8CString(prefixRef, prefix.get(), size);

        uint64_t level = WKUInt64GetValue((WKUInt64Ref) WKArrayGetItemAtIndex((WKArrayRef) messageBody, 1));
        WKStringRef dataRef = (WKStringRef) WKArrayGetItemAtIndex((WKArrayRef) messageBody, 2);

        size = WKStringGetMaximumUTF8CStringSize(dataRef);
        auto data = std::make_unique<char[]>(size);
        (void) WKStringGetUTF8CString(dataRef, data.get(), size);

        client->onAVELog(prefix.get(), level, data.get());
        return;
    }

    if (WKArrayGetSize((WKArrayRef) messageBody) != 2)
    {
        RDKLOG_ERROR("Wrong array size!");
        return;
    }

    uint64_t callID = WKUInt64GetValue((WKUInt64Ref) WKArrayGetItemAtIndex((WKArrayRef) messageBody, 0));
    WKStringRef bodyRef = (WKStringRef) WKArrayGetItemAtIndex((WKArrayRef) messageBody, 1);

    size = WKStringGetMaximumUTF8CStringSize(bodyRef);
    auto data = std::make_unique<char[]>(size);
    (void) WKStringGetUTF8CString(bodyRef, data.get(), size);

    client->onJavaScriptBridgeRequest(name.get(), callID, data.get());

    // Reset watchdog when we receive a message from JS bridge
    if (browser->m_unresponsiveReplyNum > 0)
    {
        std::string activeURL = getPageActiveURL(page);
        pid_t webprocessPID = WKPageGetProcessIdentifier(page);
        RDKLOG_WARNING("WebProcess recovered after %d unresponsive replies, pid=%u, url=%s\n", browser->m_unresponsiveReplyNum, webprocessPID, activeURL.c_str());
        browser->m_unresponsiveReplyNum = 0;
        browser->m_webProcessCheckInProgress = false;
    }
}

void WPEBrowser::cookiesDidChange(WKCookieManagerRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered, clientInfo %p", clientInfo);
    WPEBrowser* browser = const_cast<WPEBrowser*>(static_cast<const WPEBrowser*>(clientInfo));
    if (browser->m_ephemeralMode)
    {
        RDKLOG_TRACE("Ignoring cookies change in ephemeral mode");
        return;
    }
    if (browser->m_gettingCookies)
    {
        browser->m_dirtyCookies = true;
        return;
    }
    browser->m_gettingCookies = true;
    WKCookieManagerGetCookies(WKContextGetCookieManager(browser->m_context.get()), browser, didGetAllCookies);
}

void WPEBrowser::didGetAllCookies(WKArrayRef cookies, WKErrorRef error, void* context)
{
    RDKLOG_TRACE("Function entered, cookies %p, context %p", cookies, context);
    WPEBrowser* browser = static_cast<WPEBrowser*>(context);

    if (!browser || !browser->m_context)
    {
        RDKLOG_TRACE("WK context is null, probably browser is destroying");
        return;
    }

    if (browser->m_ephemeralMode)
    {
        RDKLOG_TRACE("Ignoring cookies update in ephemeral mode");
        return;
    }

    if (error)
    {
        auto errorDomain = adoptWK(WKErrorCopyDomain(error));
        auto errorDescription = adoptWK(WKErrorCopyLocalizedDescription(error));
        RDKLOG_ERROR("GetCookies failed, error(code=%d, domain=%s, message=%s)",
                     WKErrorGetErrorCode(error),
                     toStdString(errorDomain.get()).c_str(),
                     toStdString(errorDescription.get()).c_str());
        return;
    }

    if (browser->m_dirtyCookies)
    {
        browser->m_dirtyCookies = false;
        WKCookieManagerGetCookies(WKContextGetCookieManager(browser->m_context.get()), browser, didGetAllCookies);
        return;
    }
    browser->m_gettingCookies = false;

    size_t size = cookies ? WKArrayGetSize(cookies) : 0;
    if (size > 0)
    {
        std::vector<std::string> cookieVector;
        cookieVector.reserve(size);
        for (size_t i = 0; i < size; ++i)
        {
            WKCookieRef cookie = static_cast<WKCookieRef>(WKArrayGetItemAtIndex(cookies, i));
            if (WKCookieGetSession(cookie))
            {
                auto cookieName = adoptWK(WKCookieGetName(cookie));
                RDKLOG_TRACE("Ignore session cookie: %s", toStdString(cookieName.get()).c_str());
                continue;
            }
            SoupCookie* soupCookie = toSoupCookie(cookie);
            gchar *cookieHeader = soup_cookie_to_set_cookie_header(soupCookie);
            cookieVector.push_back(cookieHeader);
            soup_cookie_free(soupCookie);
            g_free(cookieHeader);
        }
        cookieVector.shrink_to_fit();
        browser->m_cookieJar = std::move(cookieVector);
    }
    else
    {
        browser->m_cookieJar.clear();
    }

    if (browser->m_browserClient)
        browser->m_browserClient->onCookiesChanged();
}

RDKBrowserError WPEBrowser::setProxies(const ProxyPatterns& proxies)
{
    RDKLOG_TRACE("Function entered, proxy patterns count %d", proxies.size());
    if (!m_view)
        return RDKBrowserFailed;
    size_t size = proxies.size();

    auto proxyArray = std::unique_ptr<WKTypeRef[]>(new WKTypeRef[size]);
    for (size_t i = 0; i < size; ++i)
        proxyArray[i] = WKProxyCreate(adoptWK(WKStringCreateWithUTF8CString(proxies[i].first.c_str())).get(),
                                      adoptWK(WKStringCreateWithUTF8CString(proxies[i].second.c_str())).get());

    WKRetainPtr<WKArrayRef> wkProxyArray(AdoptWK, WKArrayCreateAdoptingValues(proxyArray.get(), size));
    WKPageSetProxies(WKViewGetPage(m_view.get()), wkProxyArray.get());

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setWebFilters(const WebFilters& filters)
{
    RDKLOG_TRACE("Function entered, web filters count %d", filters.size());
    if (!m_view)
        return RDKBrowserFailed;

    size_t size = filters.size();
    auto filterArray = std::unique_ptr<WKTypeRef[]>(new WKTypeRef[size]);
    size_t i = 0;
    for (const auto& f : filters)
    {
        WKTypeRef patternArray[3] = {
            WKStringCreateWithUTF8CString(f.scheme.c_str()),
            WKStringCreateWithUTF8CString(f.host.c_str()),
            WKBooleanCreate(f.block)
        };
        filterArray[i++] = WKArrayCreateAdoptingValues(patternArray, 3);
    }

    auto wkWebFilterArray = adoptWK(WKArrayCreateAdoptingValues(filterArray.get(), size));
    WKPagePostMessageToInjectedBundle(
        WKViewGetPage(m_view.get()),
        adoptWK(WKStringCreateWithUTF8CString("webfilters")).get(),
        wkWebFilterArray.get());

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setCookieJar(const std::vector<std::string>& cookieJar_)
{
    RDKLOG_TRACE("Function entered, cookie count %d", cookieJar_.size());
    m_cookieJar = cookieJar_;

    if (m_ephemeralMode)
    {
        RDKLOG_INFO("Ignoring persistent cookiejar in ephemeral mode");
        return RDKBrowserSuccess;
    }

    size_t size = m_cookieJar.size();
    size_t ind = 0;

    auto cookieJar = std::unique_ptr<WKTypeRef[]>(new WKTypeRef[size]);
    for (const auto& cookie : m_cookieJar)
    {
        std::unique_ptr<SoupCookie, void(*)(SoupCookie*)> sc(soup_cookie_parse(cookie.c_str(), nullptr), soup_cookie_free);

        if (!sc)
            continue;

        const char* scDomain = soup_cookie_get_domain(sc.get());
        if (!scDomain)
            continue;

        if (strlen(scDomain) > 1 && scDomain[0] == '.')
        {
            static GRegex* domainCheckRegex = g_regex_new(";\\s*domain\\s*=\\s*(.)", (GRegexCompileFlags)G_REGEX_CASELESS, (GRegexMatchFlags)0, nullptr);
            GMatchInfo *matchInfo;
            g_regex_match(domainCheckRegex, cookie.c_str(), (GRegexMatchFlags)0, &matchInfo);

            if (g_match_info_matches(matchInfo) && g_match_info_get_match_count(matchInfo) == 2)
            {
                gchar* startOfDomain = g_match_info_fetch(matchInfo, 1);

                if (startOfDomain && *startOfDomain && *startOfDomain != '.' && *startOfDomain != ';')
                {
                    char* adjustedDomain = g_strdup(sc->domain + 1);
                    g_free(sc->domain);
                    sc->domain = adjustedDomain;
                }

                g_free(startOfDomain);
            }
            g_match_info_free(matchInfo);
        }
        rdk_assert(ind < size);
        cookieJar[ind++] = toWKCookie(sc.get());
    }

    WKRetainPtr<WKArrayRef> cookieArray(AdoptWK, WKArrayCreateAdoptingValues(cookieJar.get(), ind));
    WKCookieManagerSetCookies(WKContextGetCookieManager(m_context.get()), cookieArray.get());

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::getCookieJar(std::vector<std::string>& cookieJar) const
{
    RDKLOG_TRACE("Function entered, cookie count %d", m_cookieJar.size());
    cookieJar = m_cookieJar;
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setUserAgent(const char* useragent)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner(g_main_context_default()));
    if (!m_view)
        return RDKBrowserFailed;
    if (useragent && strlen(useragent))
    {
        RDKLOG_TRACE("Custom useragent - %s", useragent);
        WKRetainPtr<WKStringRef> customUserAgent = adoptWK(WKStringCreateWithUTF8CString(useragent));
        WKPageSetCustomUserAgent(WKViewGetPage(m_view.get()), customUserAgent.get());
    }
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setTransparentBackground(bool transparent)
{
    if (!m_view)
        return RDKBrowserFailed;
    WKPageSetDrawsBackground(WKViewGetPage(m_view.get()), !transparent);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setVisible(bool visible)
{
    WKViewState state = visible
        ? (kWKViewStateIsVisible | kWKViewStateIsInWindow)
        : (m_isSuspended ? 0 : kWKViewStateIsInWindow);

    WKViewSetViewState(m_view.get(), state);

    m_isSuspended = (state == 0);

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setWebAutomationEnabled(bool enabled)
{
    static bool webAutomationFlag = !!getenv(enableWebautomationEnvVar);

    if(webAutomationFlag && !m_webAutomationStarted && enabled )
    {
#ifdef ENABLE_WEB_AUTOMATION
         RDKLOG_INFO("WebAutomation is Enabled\n");
         WKContextAutomationClientV0 handlerAutomation;
         memset(&handlerAutomation, 0, sizeof(handlerAutomation));
         handlerAutomation.base.version = 0;
         handlerAutomation.base.clientInfo = this;
         handlerAutomation.allowsRemoteAutomation = WPEBrowser::allowsRemoteAutomation ;
         handlerAutomation.browserVersion =  WPEBrowser::browserVersion;
         handlerAutomation.browserName = WPEBrowser::browserName;
         handlerAutomation.didRequestAutomationSession = WPEBrowser::didRequestAutomationSession;
         WKContextSetAutomationClient(m_context.get() ,&handlerAutomation.base);
         m_webAutomationStarted = true;
#endif
    }
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::getLocalStorageEnabled(bool &enabled) const
{
    WKPreferencesRef preferences = getPreferences();
    if (!preferences) {
        enabled = false;
        return RDKBrowserFailed;
    }

    enabled = WKPreferencesGetLocalStorageEnabled(preferences);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setLocalStorageEnabled(bool enabled)
{
    WKPreferencesRef preferences = getPreferences();
    if (!preferences)
        return RDKBrowserFailed;

    if (m_ephemeralMode) {
        enabled = true;
        RDKLOG_INFO("Enable local storage by default in ephemeral mode");
    }

    WKPreferencesSetLocalStorageEnabled(preferences, enabled);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::getConsoleLogEnabled(bool &enabled) const
{
    WKPreferencesRef preferences = getPreferences();
    if (!preferences) {
        enabled = false;
        return RDKBrowserFailed;
    }

    enabled = WKPreferencesGetConsoleLogWithPrivateBrowsingEnabled(preferences);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setConsoleLogEnabled(bool enabled)
{
    WKPreferencesRef preferences = getPreferences();
    if (!preferences)
        return RDKBrowserFailed;

    WKPreferencesSetConsoleLogWithPrivateBrowsingEnabled(preferences, enabled);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setHeaders(const Headers& headers)
{
    RDKLOG_TRACE("Function entered, headers count %d", headers.size());

    if (!m_view)
        return RDKBrowserFailed;
    size_t size = headers.size();
    auto keys = std::unique_ptr<WKTypeRef[]>(new WKTypeRef[size]);
    auto values = std::unique_ptr<WKTypeRef[]>(new WKTypeRef[size]);
    for (size_t i = 0; i < size; ++i)
    {
        keys[i] = WKStringCreateWithUTF8CString(headers[i].first.c_str());
        values[i] = WKStringCreateWithUTF8CString(headers[i].second.c_str());
    }

    WKTypeRef array[] = {
        WKArrayCreateAdoptingValues(keys.get(), size),
        WKArrayCreateAdoptingValues(values.get(), size)
    };

    WKRetainPtr<WKArrayRef> result = adoptWK(WKArrayCreate(array, 2));
    WKPagePostMessageToInjectedBundle(
        WKViewGetPage(m_view.get()),
        adoptWK(WKStringCreateWithUTF8CString("headers")).get(),
        result.get());

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::reset()
{
    if (!m_view)
    {
        return Initialize(m_useSingleContext);
    }

    if (m_signalSentToWebProcess != -1 || m_crashed)
    {
        RDKLOG_ERROR("Cannot 'reset()' page because web process crashed...");
        return RDKBrowserFailed;
    }

    if (m_unresponsiveReplyNum > 1)
    {
        WKPageRef page = WKViewGetPage(m_view.get());
        std::string activeURL = getPageActiveURL(page);
        pid_t webprocessPID = WKPageGetProcessIdentifier(page);
        RDKLOG_ERROR("Cannot 'reset()' page because web process is unresponsive, pid=%u, url=%s",
                     webprocessPID, activeURL.c_str());
        return RDKBrowserFailed;
    }

    restoreWebProcessPrio();

    setNonCompositedWebGLEnabled(false);
    setIgnoreResize(false);
    setAllowScriptsToCloseWindow(false);
    printLocalStorageDirectorySize();

    m_voiceGuidanceMode = synthesisMode;
    m_voiceGuidanceEnabled = false;

    LoadURL("about:blank");

    setLocalStorageEnabled(false);
    setTransparentBackground(true);
    setConsoleLogEnabled(true);
    enableWebSecurity(true);

    Headers emptyHeaders;
    setHeaders(emptyHeaders);

    WebFilters emptyWebFilter;
    setWebFilters(emptyWebFilter);

    ProxyPatterns emptyProxyPatterns;
    setProxies(emptyProxyPatterns);

    std::vector<std::string> emptyCookieJar;
    setCookieJar(emptyCookieJar);

    setSpatialNavigation(false);
    setUserAgent(m_defaultUserAgent.c_str());

    WKViewSetViewState(m_view.get(), static_cast<WKViewState>(0));
    WKPreferencesSetResourceUsageOverlayVisible(getPreferences(), false);
    WKCookieManagerSetHTTPCookieAcceptPolicy(WKContextGetCookieManager(m_context.get()), kWKHTTPCookieAcceptPolicyOnlyFromMainDocumentDomain);

    m_canIncreasePrio = true;
    m_isSuspended = true;
    m_httpStatusCode = 0;
    m_loadProgress = 0;
    m_loadFailed = false;
    m_loadCanceled = false;
    m_didSendLaunchMetrics = false;
    m_launchMetricsMetrics.clear();

    m_idleStart = g_get_monotonic_time();

#ifdef ENABLE_WEB_AUTOMATION
    m_webAutomationSession =nullptr;
#endif

    stopWebProcessWatchDog();
    startWebProcessWatchDog();

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setVoiceGuidanceEnabled(bool enabled)
{
    m_voiceGuidanceEnabled = enabled;
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setVoiceGuidanceMode(const std::string &mode)
{
    m_voiceGuidanceMode = mode.empty() ? synthesisMode : mode;
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setLanguage(const std::string& language)
{
    WKRetainPtr<WKStringRef> lan = adoptWK(WKStringCreateWithUTF8CString(language.c_str()));
    WKTypeRef languages[] = {lan.get()};
    WKRetainPtr<WKArrayRef> languageArrayRef = adoptWK(WKArrayCreate(languages, sizeof(languages) / sizeof(languages[0])));
    WKSoupSessionSetPreferredLanguages(m_context.get(), languageArrayRef.get());

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::getMemoryUsage(uint32_t &inBytes) const
{
    if (!m_view)
    {
        inBytes = static_cast<uint32_t>(-1);
        return RDKBrowserFailed;
    }
    pid_t webprocessPID = WKPageGetProcessIdentifier(WKViewGetPage(m_view.get()));

    if (!getProcessMemoryUsage(webprocessPID, inBytes))
    {
        inBytes = static_cast<uint32_t>(-1);
        return RDKBrowserFailed;
    }

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::deleteAllCookies()
{
    if(m_useSingleContext)
        WKHTTPCookieStorageDeleteAllCookies(WKPageGetHTTPCookieStorage(WKViewGetPage(m_view.get())));
    else
        WKCookieManagerDeleteAllCookies(WKContextGetCookieManager(m_context.get()));
    RDKLOG_WARNING("deleteAllCookies() - %s() is done", m_useSingleContext ? "WKHTTPCookieStorageDeleteAllCookies" : "WKCookieManagerDeleteAllCookies");

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::clearWholeCache()
{
    WKResourceCacheManagerRef cacheManager = WKContextGetResourceCacheManager(m_context.get());
    if(!cacheManager)
    {
        RDKLOG_ERROR("clearWholeCache() - WKContextGetResourceCacheManager failed");
        return RDKBrowserFailed;
    }

    WKResourceCacheManagerClearCacheForAllOrigins(cacheManager, WKResourceCachesToClearAll);
    RDKLOG_WARNING("clearWholeCache() - WKResourceCacheManagerClearCacheForAllOrigins() is done");

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::restartRenderer()
{
    if(m_useSingleContext)
        WKHTTPCookieStorageStopObservingCookieChanges(WKPageGetHTTPCookieStorage(WKViewGetPage(m_view.get())));
    else
        WKCookieManagerStopObservingCookieChanges(WKContextGetCookieManager(m_context.get()));

    closePage();

    return Initialize(m_useSingleContext);
}

RDKBrowserError WPEBrowser::collectGarbage()
{
    WKContextGarbageCollectJavaScriptObjects(m_context.get());
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::releaseMemory()
{
    WKContextReleaseMemory(m_context.get());
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::getCookieAcceptPolicy(std::string &) const
{
    RDKLOG_WARNING("Not implemented");
    return RDKBrowserFailed;
}

RDKBrowserError WPEBrowser::setCookieAcceptPolicy(const std::string& policyStr)
{
    WKHTTPCookieAcceptPolicy policy = kWKHTTPCookieAcceptPolicyOnlyFromMainDocumentDomain;
    const char* debugStr = "OnlyFromMainDocumentDomain";

    if (policyStr == "always") {
        policy = kWKHTTPCookieAcceptPolicyAlways;
        debugStr = "Always";
    } else if (policyStr == "never") {
        policy = kWKHTTPCookieAcceptPolicyNever;
        debugStr = "Never";
    }

    RDKLOG_WARNING("cookie accept policy = %s (%d)", debugStr, policy);

    WKCookieManagerSetHTTPCookieAcceptPolicy(WKContextGetCookieManager(m_context.get()), policy);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::suspend()
{
    if (m_signalSentToWebProcess != -1 || m_crashed)
    {
        RDKLOG_ERROR("Cannot 'suspend()' page because web process crashed...");
        return RDKBrowserFailed;
    }
    if (!m_view)
    {
        RDKLOG_ERROR("Cannot 'suspend()' page because there is no WK view...");
        return RDKBrowserFailed;
    }
    if (m_unresponsiveReplyNum > 0)
    {
        WKPageRef page = WKViewGetPage(m_view.get());
        std::string activeURL = getPageActiveURL(page);
        pid_t webprocessPID = WKPageGetProcessIdentifier(page);
        RDKLOG_ERROR("Cannot 'suspend()' page because web process is unresponsive, pid=%u, url=%s",
                     webprocessPID, activeURL.c_str());
        closePage();
        stopWebProcessWatchDog();
        return RDKBrowserFailed;
    }
    restoreWebProcessPrio();
    WKViewSetViewState(m_view.get(), static_cast<WKViewState>(0));
    releaseMemory();
    m_isSuspended = true;
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::resume()
{
    if (m_signalSentToWebProcess != -1 || m_crashed)
    {
        RDKLOG_ERROR("Cannot 'resume()' page because web process crashed...");
        return RDKBrowserFailed;
    }
    if (!m_view)
    {
        RDKLOG_ERROR("Cannot 'resume()' page because there is no WK view...");
        return RDKBrowserFailed;
    }
    setVisible(true);
    m_isSuspended = false;
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::getActiveURL(std::string &url) const
{
    if (!m_view)
        return RDKBrowserFailed;

    WKPageRef page = WKViewGetPage(m_view.get());
    url = getPageActiveURL(page);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::getNonCompositedWebGLEnabled(bool &enabled) const
{
    WKPreferencesRef preferences = getPreferences();
    if (!preferences) {
        enabled = false;
        return RDKBrowserFailed;
    }

    enabled = WKPreferencesGetNonCompositedWebGLEnabled(preferences);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setNonCompositedWebGLEnabled(bool enable)
{
    WKPreferencesRef preferences = getPreferences();
    if (!preferences)
        return RDKBrowserFailed;

    if (WKPreferencesGetNonCompositedWebGLEnabled(preferences) == enable)
        return RDKBrowserSuccess;

    static bool recycleOnChange = !!getenv(recycleOnWebGLRenderModeChangeEnvVar);
    if (recycleOnChange) {
        closePage();
        return Initialize(m_useSingleContext, enable);
    }

    WKPreferencesSetNonCompositedWebGLEnabled(preferences, enable);
    return RDKBrowserSuccess;
}

void WPEBrowser::startWebProcessWatchDog()
{
    if (m_watchDogTag == 0)
    {
        m_watchDogTag = g_timeout_add_seconds_full(G_PRIORITY_DEFAULT_IDLE,
            kWebProcessWatchDogTimeoutInSeconds, [](gpointer data) -> gboolean {
                static_cast<WPEBrowser*>(data)->checkWebProcess();
                return G_SOURCE_CONTINUE;
        }, this, nullptr);
    }
}

void WPEBrowser::stopWebProcessWatchDog()
{
    m_unresponsiveReplyNum = 0;
    m_webProcessCheckInProgress = false;
    if (m_watchDogTag)
    {
        g_source_remove(m_watchDogTag);
        m_watchDogTag = 0;
    }
}

void WPEBrowser::checkWebProcess()
{
    if (m_isSuspended && m_view && !m_crashed && m_signalSentToWebProcess == -1)
    {
        uint32_t memUsageInBytes = 0;

        if (getMemoryUsage(memUsageInBytes) != RDKBrowserSuccess || memUsageInBytes > getMaxMemoryUsageInSupsended())
        {
            WKPageRef page = WKViewGetPage(m_view.get());
            std::string activeURL = getPageActiveURL(page);
            pid_t webprocessPID = WKPageGetProcessIdentifier(page);

            RDKLOG_ERROR("Closing WebProcess(suspend) due to memory pressure, usage=%f MB, pid=%u, url=%s",
                         (static_cast<float>(memUsageInBytes) / 1024.0 / 1024.0), webprocessPID, activeURL.c_str());
            closePage();
            stopWebProcessWatchDog();
            m_isKilledDueToMemoryPressure = true;
            m_browserClient->onRenderProcessTerminated(kWebProcessKilledDueToMemoryMessage);
            return;
        }
    }

    checkIfWebProcessResponsive();
}

void WPEBrowser::checkIfWebProcessResponsive()
{
    if (m_webProcessCheckInProgress || !m_view)
        return;
    m_webProcessCheckInProgress = true;

    WKPageIsWebProcessResponsive(WKViewGetPage(m_view.get()), this, [](bool isWebProcessResponsive, void* context) {
        WPEBrowser& self = *static_cast<WPEBrowser*>(context);
        self.didReceiveWebProcessResponsivenessReply(isWebProcessResponsive);
    });
}

void WPEBrowser::didReceiveWebProcessResponsivenessReply(bool isWebProcessResponsive)
{
    if (!m_browserClient)
    {
        RDKLOG_ERROR("WPEBrowser::didReceiveWebProcessResponsivenessReply: No browser client found!");
        return;
    }
    if (!m_webProcessCheckInProgress || !m_view)
        return;
    m_webProcessCheckInProgress = false;

    if (isWebProcessResponsive && m_unresponsiveReplyNum == 0)
        return;

    WKPageRef page = WKViewGetPage(m_view.get());
    std::string activeURL = getPageActiveURL(page);
    pid_t webprocessPID = WKPageGetProcessIdentifier(page);

    if (isWebProcessResponsive)
    {
        RDKLOG_WARNING("WebProcess recovered after %d unresponsive replies, pid=%u, url=%s\n", m_unresponsiveReplyNum, webprocessPID, activeURL.c_str());
        m_unresponsiveReplyNum = 0;
    }
    else if (m_browserClient->isRemoteClientHanging())
    {
        RDKLOG_WARNING("WebProcess is unresponsive and remote client is hanging too, pid=%u, reply num=%d(max=%d), url=%s\n", webprocessPID, m_unresponsiveReplyNum, m_unresponsiveReplyMaxNum, activeURL.c_str());
    }
    else
    {
        ++m_unresponsiveReplyNum;
        RDKLOG_WARNING("WebProcess is unresponsive, pid=%u, reply num=%d(max=%d), url=%s\n", webprocessPID, m_unresponsiveReplyNum, m_unresponsiveReplyMaxNum, activeURL.c_str());
    }

    static bool disableWebProcessWatchdog = !!getenv(disableWebWatchdogEnvVar);
    if (disableWebProcessWatchdog)
        return;

    if (m_unresponsiveReplyNum == m_unresponsiveReplyMaxNum && m_signalSentToWebProcess == -1)
    {
        RDKLOG_ERROR("WebProcess hang detected, pid=%u, url=%s\n", webprocessPID, activeURL.c_str());
        m_signalSentToWebProcess = SIGFPE;
        killHelper(webprocessPID, SIGFPE);
    }
    else if (m_unresponsiveReplyNum >= (m_unresponsiveReplyMaxNum + kWebProcessUnresponsiveReplyDefaultLimit))
    {
        RDKLOG_ERROR("WebProcess is being killed due to unrecover hang, pid=%u, url=%s\n", webprocessPID, activeURL.c_str());
        m_signalSentToWebProcess = SIGKILL;
        killHelper(webprocessPID, SIGKILL);
        m_crashed = true;
        m_browserClient->onRenderProcessTerminated(getCrashReasonMessageBySignalNum(m_signalSentToWebProcess));
        stopWebProcessWatchDog();
    }
}

void WPEBrowser::processDidBecomeResponsive(WKPageRef page, const void* clientInfo)
{
    WPEBrowser& self = *const_cast<WPEBrowser*>(static_cast<const WPEBrowser*>(clientInfo));

    if (self.m_webProcessState == WebProcessCold)
    {
        self.m_webProcessState = WebProcessHot;
    }

    if (self.m_unresponsiveReplyNum > 0)
    {
        std::string activeURL = getPageActiveURL(page);
        pid_t webprocessPID = WKPageGetProcessIdentifier(page);
        RDKLOG_WARNING("WebProcess recovered after %d unresponsive replies, pid=%u, url=%s\n", self.m_unresponsiveReplyNum, webprocessPID, activeURL.c_str());
        self.m_unresponsiveReplyNum = 0;
    }
}

bool WPEBrowser::isCrashed(std::string &reason)
{
    if (m_crashed)
    {
        reason = getCrashReasonMessageBySignalNum(m_signalSentToWebProcess);
        return true;
    }
    if (m_isKilledDueToMemoryPressure)
    {
        reason = kWebProcessKilledDueToMemoryMessage;
        return true;
    }
    return false;
}

void WPEBrowser::collectMetricsOnLoadStart()
{
    if (m_didSendLaunchMetrics)
        return;

    auto getProcessLaunchStateString = [&]() -> std::string
    {
        switch(m_webProcessState)
        {
            case WebProcessCold: return "Cold";
            case WebProcessHot:  return "Hot";
        }
        return "Unknown";
    };

    auto addSystemInfo = [&](std::map<std::string, std::string> &metrics)
    {
        struct sysinfo info;
        if (sysinfo(&info) != 0)
        {
            RDKLOG_INFO("Failed to get sysinfo error=%d.", errno);
            return;
        }
        static const long NPROC_ONLN = sysconf(_SC_NPROCESSORS_ONLN);
        static const float LA_SCALE = static_cast<float>(1 << SI_LOAD_SHIFT);
        metrics["MemTotal"] = std::to_string(info.totalram * info.mem_unit);
        metrics["MemFree"] = std::to_string(info.freeram * info.mem_unit);
        metrics["MemSwapped"] = std::to_string((info.totalswap - info.freeswap) * info.mem_unit);
        metrics["Uptime"] = std::to_string(info.uptime);
        metrics["LoadAvg"] = std::to_string(info.loads[0] / LA_SCALE) + " " +
                             std::to_string(info.loads[1] / LA_SCALE) + " " +
                             std::to_string(info.loads[2] / LA_SCALE);
        metrics["NProc"] = std::to_string(NPROC_ONLN);
    };

    auto addProcessInfo = [&](std::map<std::string, std::string> &metrics)
    {
        WKPageRef page = WKViewGetPage(m_view.get());

        pid_t webprocessPID = WKPageGetProcessIdentifier(page);
        uint32_t rssInBytes = 0;
        std::string statmLine;
        if (readStatmLine(webprocessPID, statmLine))
        {
            parseRssFromStatmLine(statmLine, rssInBytes);
        }

        metrics["ProcessRSS"] = std::to_string(rssInBytes);
        metrics["ProcessPID"] = std::to_string(webprocessPID);
        metrics["AppName"] = getPageActiveHost(page);
        metrics["webProcessStatmLine"] = statmLine;
    };

    std::map<std::string, std::string> metrics;
    metrics["LaunchState"] = getProcessLaunchStateString();
    metrics["AppType"] = "Web";
    addSystemInfo(metrics);
    addProcessInfo(metrics);

    gint64 idleTime = 0;
    if (m_idleStart > 0) {
        idleTime = (g_get_monotonic_time() - m_idleStart) / G_USEC_PER_SEC;
        m_idleStart = -1;
    }
    metrics["webProcessIdleTime"] =  std::to_string(idleTime);

    std::swap(m_launchMetricsMetrics, metrics);
}

void WPEBrowser::collectMetricsOnLoadEnd()
{
    if (m_didSendLaunchMetrics || m_launchMetricsMetrics.empty() || !m_browserClient)
        return;

    gint64 pageLoadTimeMs = (g_get_monotonic_time() - m_pageLoadStart) / 1000;
    m_launchMetricsMetrics["LaunchTime"] = std::to_string(pageLoadTimeMs);
    m_launchMetricsMetrics["AppLoadSuccess"] = std::to_string(!m_loadFailed);
    m_launchMetricsMetrics["webPageLoadNum"] = std::to_string(m_pageLoadNum);

    static bool canRequestNavTiming = !!getenv(injectedBundleEnvVar) && !getenv(disableInjectedBundleEnvVar);
    if (!canRequestNavTiming) {
        reportLaunchMetrics();
        return;
    }

    ++navigationTimingsRequestId;
    WKRetainPtr<WKUInt64Ref> messageBody = adoptWK(WKUInt64Create(navigationTimingsRequestId));
    WKRetainPtr<WKStringRef> messageName = adoptWK(WKStringCreateWithUTF8CString("getNavigationTiming"));
    WKPagePostMessageToInjectedBundle(WKViewGetPage(m_view.get()), messageName.get(), messageBody.get());
}

void WPEBrowser::reportLaunchMetrics()
{
    if (m_didSendLaunchMetrics || m_launchMetricsMetrics.empty() || !m_browserClient)
        return;

    m_browserClient->onReportLaunchMetrics(m_launchMetricsMetrics);
    m_launchMetricsMetrics.clear();
    m_pageLoadStart = -1;
    m_didSendLaunchMetrics = true;
}

RDKBrowserError WPEBrowser::toggleResourceUsageOverlay()
{
    bool overlayVisible=WKPreferencesGetResourceUsageOverlayVisible(getPreferences());
    WKPreferencesSetResourceUsageOverlayVisible(getPreferences(), !overlayVisible);
    return RDKBrowserSuccess;
}

void WPEBrowser::closePage()
{
    if (!m_view)
        return;

    if (!m_crashed)
    {
        pid_t pid_webprocess = WKPageGetProcessIdentifier(WKViewGetPage(m_view.get()));
        WKPageClose(WKViewGetPage(m_view.get()));
        if(!getenv(cleanExitEnvVar) && pid_webprocess > 1)
        {
            struct timespec sleepTime;
            sleepTime.tv_sec = 0;
            sleepTime.tv_nsec = 100000000;
            nanosleep(&sleepTime, nullptr);
            kill(pid_webprocess, SIGTERM); // This is a temporary workaround
        }
    }

    WKViewSetViewClient(m_view.get(), nullptr);
    m_view = nullptr;
    m_crashed = false;

    if (m_restorePrioTag)
    {
        g_source_remove(m_restorePrioTag);
        m_restorePrioTag = 0;
    }

    printLocalStorageDirectorySize();
}

void WPEBrowser::generateCrashId()
{
#ifdef USE_BREAKPAD
    GUID guid;
    CreateGUID(&guid);

    m_crashId.resize(kGUIDStringLength);
    GUIDToString(&guid, &m_crashId[0], kGUIDStringLength + 1);

    //for now same minidump guid for both WPEWebProcess and WPENetworkProcess
    setenv("BREAKPAD_GUID", m_crashId.c_str(), 1);
    RDKLOG_INFO("Generated BREAKPAD_GUID = %s", m_crashId.c_str());
#endif
}

std::string WPEBrowser::getCrashId() const
{
    if (m_isKilledDueToMemoryPressure)
        return { };

    RDKLOG_INFO("signal: [%d] crash-id: [%s]", m_signalSentToWebProcess, m_crashId.c_str());

    return (m_signalSentToWebProcess == SIGKILL) ? std::string() : m_crashId;
}

}
