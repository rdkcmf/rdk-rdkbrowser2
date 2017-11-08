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

#include <wpe/view-backend.h>

#include <WebKit/WKCookie.h>
#include <WebKit/WKCookieManager.h>
#include <WebKit/WKHTTPCookieStorageRef.h>
#include <WebKit/WKProxy.h>
#include <WebKit/WKSerializedScriptValue.h>
#include <WebKit/WKUserMediaPermissionRequest.h>
#include <WebKit/WKPageConfigurationRef.h>
#include <WebKit/WKPreferencesRefPrivate.h>

// TODO(em): fix generation of forwarding header
#include <WebKit2/UIProcess/API/C/WKContextPrivate.h>
#include <WebKit2/UIProcess/API/C/WKPagePrivate.h>
#include <WebKit2/UIProcess/API/C/WKWebsiteDataStoreRef.h>

#include <libsoup/soup.h>

#include <stdio.h>
#include <string.h>

#include <functional>
#include <tuple>
#include <vector>

#include <sys/types.h>
#include <signal.h>
#include <time.h>

using namespace JSUtils;

namespace
{

constexpr char cleanExitEnvVar[]              = "RDKBROWSER2_CLEAN_EXIT_WEBPROCESS";
constexpr char disableInjectedBundleEnvVar[]  = "RDKBROWSER2_DISABLE_INJECTED_BUNDLE";
constexpr char enableIndexedDbEnvVar[]        = "RDKBROWSER2_ENABLE_INDEXED_DB";
constexpr char indexedDbEnvVar[]              = "RDKBROWSER2_INDEXED_DB_DIR";
constexpr char injectedBundleEnvVar[]         = "RDKBROWSER2_INJECTED_BUNDLE_LIB";
constexpr char testHangDetectorEnvVar[]       = "RDKBROWSER2_TEST_HANG_DETECTOR";

constexpr char receiverOrgName[]       = "Comcast";
constexpr char receiverAppName[]       = "NativeXREReceiver";

JSGlobalContextRef gJSContext = JSGlobalContextCreate(nullptr);

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

// WKContextConfiguration utilities
std::unique_ptr<char> escapedStringFromFilename(const char* fileName)
{
    std::unique_ptr<char> escapedString(g_uri_escape_string(fileName, "/:", FALSE));
    return escapedString;
}

std::unique_ptr<char> defaultWebSQLDatabaseDirectory()
{
    std::unique_ptr<char> databaseDir(g_build_filename(g_get_user_data_dir(), "wpe", "databases", nullptr));
    return escapedStringFromFilename(databaseDir.get());
}

std::unique_ptr<char> defaultIndexedDBDatabaseDirectory()
{
    const char* path_start = g_get_user_data_dir();
    if (const char* indexedDbDir = getenv(indexedDbEnvVar))
    {
        path_start = indexedDbDir;
    }
    std::unique_ptr<char> indexedDBDatabaseDirectory(g_build_filename(path_start, "wpe", "databases", "indexeddb", nullptr));
    RDKLOG_INFO("[IndexedDB] Database path is %s", indexedDBDatabaseDirectory.get());
    return escapedStringFromFilename(indexedDBDatabaseDirectory.get());
}

std::unique_ptr<char> defaultLocalStorageDirectory()
{
    std::unique_ptr<char> storageDir(g_build_filename(g_get_user_data_dir(), "data", receiverOrgName, receiverAppName, nullptr));
    return escapedStringFromFilename(storageDir.get());
}

std::unique_ptr<char> defaultMediaKeysStorageDirectory()
{
    std::unique_ptr<char> mediaKeysStorageDir(g_build_filename(g_get_user_data_dir(), "wpe", "mediakeys", nullptr));
    return escapedStringFromFilename(mediaKeysStorageDir.get());
}

std::unique_ptr<char> defaultNetworkCacheDirectory()
{
    std::unique_ptr<char> diskCacheDir(g_build_filename(g_get_user_cache_dir(), "wpe", "cache", nullptr));
    return escapedStringFromFilename(diskCacheDir.get());
}

std::unique_ptr<char> defaultApplicationCacheDirectory()
{
    std::unique_ptr<char> appCacheDir(g_build_filename(g_get_user_cache_dir(), "wpe", "appcache", nullptr));
    return escapedStringFromFilename(appCacheDir.get());
}

std::unique_ptr<char> defaultMediaCacheDirectory()
{
    std::unique_ptr<char> mediaCacheDir(g_build_filename(g_get_user_cache_dir(), "wpe", "mediacache", nullptr));
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

// How often to check WebProcess responsiveness
static const int kWebProcessWatchDogTimeoutInSeconds = 10;

// How many unresponsive replies to handle before declaring WebProcess hang state
//
// Note: We'll try to kill hanging WebProcess after
// (kWebProcessWatchDogTimeoutInSeconds * kMaxWebProcessUnresponsiveReplyNum + 3) seconds,
// where 3 seconds is timeout of 'WKPageIsWebProcessResponsive' reply, see ResponsivenessTimer.cpp
static const int kMaxWebProcessUnresponsiveReplyNum = 3;

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
    if ((nullptr != browser) && (nullptr != browser->m_browserClient))
    {
        std::string activeURL = getPageActiveURL(page);

        if(browser->m_loadFailed)
        {
            browser->m_browserClient->onLoadFinished(false, 0, activeURL);
        }
        else
        {
            browser->m_browserClient->onLoadFinished((browser->m_loadProgress == 100), browser->m_httpStatusCode, activeURL);
        }

        browser->m_httpStatusCode = 0;
        browser->m_loadProgress = 0;
        browser->m_loadFailed = false;
    }
}

void WPEBrowser::didFailProvisionalNavigation(WKPageRef, WKNavigationRef, WKErrorRef error, WKTypeRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if ((nullptr != browser) && (nullptr != browser->m_browserClient))
    {
        browser->m_loadFailed = true;
        RDKLOG_ERROR("Load Failed with (%d - %s)\n",
                WKErrorGetErrorCode(error), toStdString(WKErrorCopyLocalizedDescription(error)).c_str());
    }
}

void WPEBrowser::didFailNavigation(WKPageRef, WKNavigationRef, WKErrorRef error, WKTypeRef, const void *clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if ((nullptr != browser) && (nullptr != browser->m_browserClient))
    {
        browser->m_loadFailed = true;
        RDKLOG_ERROR("Load Failed with (%d - %s)\n",
                WKErrorGetErrorCode(error), toStdString(WKErrorCopyLocalizedDescription(error)).c_str());
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

void WPEBrowser::decidePolicyForNavigationAction(WKPageRef, WKNavigationActionRef, WKFramePolicyListenerRef listener,
        WKTypeRef, const void*)
{
    WKFramePolicyListenerUse(listener);
}

void WPEBrowser::decidePolicyForNavigationResponse(WKPageRef, WKNavigationResponseRef navigationResponse,
        WKFramePolicyListenerRef listener, WKTypeRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if (nullptr != browser && WKNavigationResponseIsMainFrame(navigationResponse))
    {
        auto response =  WKNavigationResponseGetURLResponse(navigationResponse);
        browser->m_httpStatusCode = WKURLResponseHTTPStatusCode(response);
    }

    WKFramePolicyListenerUse(listener);
}

void WPEBrowser::webProcessDidCrash(WKPageRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered");
    WPEBrowser* browser = (WPEBrowser*)clientInfo;
    if( (nullptr != browser) && (nullptr != browser->m_browserClient) && (!browser->m_crashed) )
    {
        browser->m_browserClient->onRenderProcessTerminated();
        browser->stopWebProcessWatchDog();
        browser->m_crashed = true;
    }
}



WPEBrowser::WPEBrowser()
{
}

WPEBrowser::~WPEBrowser()
{
    RDKLOG_TRACE("Function entered");
    if(m_useSingleContext)
        WKHTTPCookieStorageStopObservingCookieChanges(WKPageGetHTTPCookieStorage(WKViewGetPage(m_view.get())));
    else
    {
        WKCookieManagerStopObservingCookieChanges(WKContextGetCookieManager(m_context.get()));
        WKCookieManagerSetClient(WKContextGetCookieManager(m_context.get()), nullptr);
    }

    if(getenv(injectedBundleEnvVar))
        WKPageSetPageInjectedBundleClient(WKViewGetPage(m_view.get()), nullptr);

    pid_t pid_webprocess = WKPageGetProcessIdentifier(WKViewGetPage(m_view.get()));

    enableWebSecurity(false);

    WKPageClose(WKViewGetPage(m_view.get()));
    if(!getenv(cleanExitEnvVar))
    {
        struct timespec sleepTime;
        sleepTime.tv_sec = 0;
        sleepTime.tv_nsec = 100000000;
        nanosleep(&sleepTime, nullptr);
        kill(pid_webprocess, SIGTERM); // This is a temporary workaround
    }

    WKViewSetViewClient(m_view.get(), nullptr);

    WKPageConfigurationSetPageGroup(m_pageConfiguration.get(), nullptr);
    WKPageConfigurationSetContext(m_pageConfiguration.get(), nullptr);
    if(m_useSingleContext) {
        WKPageConfigurationSetWebsiteDataStore(m_pageConfiguration.get(), nullptr);
        m_webDataStore = nullptr;
    }

    m_view = nullptr;
    m_context = nullptr;
    m_pageConfiguration = nullptr;
    m_pageGroup = nullptr;
    m_pageGroupIdentifier = nullptr;

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
        WKContextSetCacheModel(ctx, kWKCacheModelDocumentBrowser);

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

RDKBrowserError WPEBrowser::Initialize(bool useSingleContext)
{
    RDKLOG_TRACE("Function entered");
    const char* injectedBundleLib = getenv(injectedBundleEnvVar);
    m_useSingleContext = useSingleContext;
    m_context = getOrCreateContext(useSingleContext);

    m_pageGroupIdentifier = adoptWK(WKStringCreateWithUTF8CString("WPERDKPageGroup"));
    m_pageGroup = adoptWK(WKPageGroupCreateWithIdentifier(m_pageGroupIdentifier.get()));
    m_pageConfiguration = adoptWK(WKPageConfigurationCreate());
    WKPageConfigurationSetContext(m_pageConfiguration.get(), m_context.get());
    WKPageConfigurationSetPageGroup(m_pageConfiguration.get(), m_pageGroup.get());
    if(m_useSingleContext) {
        m_webDataStore = adoptWK(WKWebsiteDataStoreCreateNonPersistentDataStore());
        WKPageConfigurationSetWebsiteDataStore(m_pageConfiguration.get(), m_webDataStore.get());
    }

    m_view = adoptWK(WKViewCreateWithViewBackend(wpe_view_backend_create(), m_pageConfiguration.get())); // WebSecurity is being disabled here
    auto page = WKViewGetPage(m_view.get());

    setTransparentBackground(true); // by default background should be transparent

    printLocalStorageDirectory();
    setLocalStorageEnabled(false);
    setIndexedDbEnabled(false);
    setConsoleLogEnabled(true);

    // Enable WebSecurity (must be executed after creating a view)
    enableWebSecurity(m_webSecurityEnabled); // m_pageGroup must be initialized before this call

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
    WKPageSetPageUIClient(page, &pageUIClient.base);

    WKPageNavigationClientV0 pageNavigationClient;
    memset(&pageNavigationClient, 0, sizeof(pageNavigationClient));
    pageNavigationClient.base.version = 0;
    pageNavigationClient.base.clientInfo = this;
    pageNavigationClient.didFailProvisionalNavigation = WPEBrowser::didFailProvisionalNavigation;
    pageNavigationClient.didFailNavigation = WPEBrowser::didFailNavigation;
    pageNavigationClient.didCommitNavigation = WPEBrowser::didCommitNavigation;
    pageNavigationClient.decidePolicyForNavigationAction = WPEBrowser::decidePolicyForNavigationAction;
    pageNavigationClient.decidePolicyForNavigationResponse = WPEBrowser::decidePolicyForNavigationResponse;
    pageNavigationClient.webProcessDidCrash = WPEBrowser::webProcessDidCrash;
    WKPageSetPageNavigationClient(page, &pageNavigationClient.base);

    if(m_useSingleContext)
    {
        WKPageLoaderClientV7 pageLoadClient;
        memset(&pageLoadClient, 0, sizeof(pageLoadClient));
        pageLoadClient.base.version = 7;
        pageLoadClient.base.clientInfo = this;
        pageLoadClient.didStartProgress = WPEBrowser::didStartProgress;
        pageLoadClient.didChangeProgress = WPEBrowser::didChangeProgress;
        pageLoadClient.didFinishProgress = WPEBrowser::didFinishProgress;
        pageLoadClient.cookiesDidChange = WPEBrowser::cookiesDidChange;
        pageLoadClient.processDidBecomeResponsive = WPEBrowser::processDidBecomeResponsive;
        WKPageSetPageLoaderClient(page, &pageLoadClient.base);
        WKHTTPCookieStorageStartObservingCookieChanges(WKPageGetHTTPCookieStorage(page));
    }
    else
    {
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
    }


    //Setting default user-agent string for WPE
    RDKLOG_TRACE("Appending NativeXREReceiver to the WPE standard useragent string");
    m_defaultUserAgent = toStdString(adoptWK(WKPageCopyUserAgent(WKViewGetPage(m_view.get()))).get());
    m_defaultUserAgent.append(" NativeXREReceiver");
    setUserAgent(m_defaultUserAgent.c_str());

    WKPreferencesSetLogsPageMessagesToSystemConsoleEnabled(getPreferences(), true);
    WKPreferencesSetPageCacheEnabled(getPreferences(), false);

    //FIXME remove when Roger 4k and others are fully migrated to HTTPS
    WKPreferencesSetAllowRunningOfInsecureContent(getPreferences(), true);

    m_httpStatusCode = 0;
    m_loadProgress = 0;
    m_loadFailed = false;

    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::LoadURL(const char* url)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner(g_main_context_default()));

    if (m_isHiddenOnReset)
    {
        // Mark view visible to avoid possible throttle on load
        setVisible(true);
        m_isHiddenOnReset = false;
    }

    enableScrollToFocused(shouldEnableScrollToFocused(url));

    WKRetainPtr<WKURLRef> wkUrl = adoptWK(WKURLCreateWithUTF8CString(url));
    WKPageLoadURL(WKViewGetPage(m_view.get()), wkUrl.get());
    startWebProcessWatchDog();
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::SetHTML(const char* html)
{
    RDKLOG_TRACE("Function entered");
    rdk_assert(g_main_context_is_owner(g_main_context_default()));
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

RDKBrowserError WPEBrowser::setIndexedDbEnabled(bool enabled)
{
    RDKLOG_TRACE("Function entered");

    static char* enabledEnvVar = getenv(enableIndexedDbEnvVar);
    if (enabledEnvVar)
    {
        enabled = std::atoi(enabledEnvVar);
        RDKLOG_WARNING("Overriding IndexedDB setting with environment variable. Unconditionally %s.", enabled ? "enabling" : "disabling");
    }

    RDKLOG_INFO("[%s], was: [%s]",
                enabled ? "true" : "false",
                m_indexedDbEnabled ? "true" : "false");

    m_indexedDbEnabled = enabled;
    WKPreferencesRef preferences = getPreferences();
    g_return_val_if_fail(preferences, RDKBrowserFailed);

    WKPreferencesSetDatabasesEnabled(preferences, m_indexedDbEnabled);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setAVEEnabled(bool enabled)
{
    RDKLOG_TRACE("Function entered");

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

void WPEBrowser::didReceiveMessageFromInjectedBundle(WKPageRef, WKStringRef messageName, WKTypeRef messageBody, const void *clientInfo)
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
    (void) WKStringGetUTF8CString(messageName, name.get(), size);

    if (strcmp(name.get(), "onAVELog") == 0)
    {
        if (WKArrayGetSize((WKArrayRef) messageBody) != 3)
        {
            RDKLOG_ERROR("Wrong array size!");
            return;
        }

        WKStringRef prefixRef = (WKStringRef) WKArrayGetItemAtIndex((WKArrayRef) messageBody, 2);
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
}

void WPEBrowser::cookiesDidChange(WKCookieManagerRef, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered, clientInfo %p", clientInfo);
    WPEBrowser* browser = const_cast<WPEBrowser*>(static_cast<const WPEBrowser*>(clientInfo));
    if (browser->m_gettingCookies)
    {
        browser->m_dirtyCookies = true;
        return;
    }
    browser->m_gettingCookies = true;
    WKCookieManagerGetCookies(WKContextGetCookieManager(browser->m_context.get()), browser, didGetAllCookies);
}

void WPEBrowser::cookiesDidChange(WKPageRef page, const void* clientInfo)
{
    RDKLOG_TRACE("Function entered, clientInfo %p", clientInfo);
    WPEBrowser* browser = const_cast<WPEBrowser*>(static_cast<const WPEBrowser*>(clientInfo));
    if (browser->m_gettingCookies)
    {
        browser->m_dirtyCookies = true;
        return;
    }
    browser->m_gettingCookies = true;
    WKHTTPCookieStorageGetCookies(WKPageGetHTTPCookieStorage(page), browser, didGetAllCookies);
}

void WPEBrowser::didGetAllCookies(WKArrayRef cookies, WKErrorRef, void* context)
{
    RDKLOG_TRACE("Function entered, cookies %p, context %p", cookies, context);
    WPEBrowser* browser = static_cast<WPEBrowser*>(context);
    if (browser->m_dirtyCookies)
    {
        browser->m_dirtyCookies = false;
        if(browser->m_useSingleContext)
            WKHTTPCookieStorageGetCookies(WKPageGetHTTPCookieStorage
                (WKViewGetPage(browser->m_view.get())), browser, didGetAllCookies);
        else
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
    if(m_useSingleContext)
        WKHTTPCookieStorageSetCookies(WKPageGetHTTPCookieStorage(WKViewGetPage(m_view.get())), cookieArray.get());
    else
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
    WKPageSetDrawsBackground(WKViewGetPage(m_view.get()), !transparent);
    return RDKBrowserSuccess;
}

RDKBrowserError WPEBrowser::setVisible(bool visible)
{
    WKViewSetViewState(m_view.get(), (visible ? kWKViewStateIsVisible | kWKViewStateIsInWindow : 0));
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
    LoadURL("about:blank");

    setLocalStorageEnabled(false);
    setIndexedDbEnabled(false);
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

    setVisible(false);

    m_isHiddenOnReset = true;
    m_httpStatusCode = 0;
    m_loadProgress = 0;
    m_loadFailed = false;
    return RDKBrowserSuccess;
}

void WPEBrowser::startWebProcessWatchDog()
{
    if (m_watchDogTag == 0)
    {
        m_watchDogTag = g_timeout_add_seconds(
            kWebProcessWatchDogTimeoutInSeconds, [](gpointer data) -> gboolean {
                static_cast<WPEBrowser*>(data)->checkIfWebProcessResponsive();
                return G_SOURCE_CONTINUE;
        }, this);
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
        RDKLOG_WARNING("WebProcess is unresponsive and remote client is hanging too, pid=%u, reply num=%d, url=%s\n", webprocessPID, m_unresponsiveReplyNum, activeURL.c_str());
    }
    else
    {
        ++m_unresponsiveReplyNum;
        RDKLOG_WARNING("WebProcess is unresponsive, pid=%u, reply num=%d, url=%s\n", webprocessPID, m_unresponsiveReplyNum, activeURL.c_str());
    }

    if (m_unresponsiveReplyNum >= kMaxWebProcessUnresponsiveReplyNum)
    {
        RDKLOG_ERROR("WebProcess hang detected, pid=%u, url=%s\n", webprocessPID, activeURL.c_str());
        if (!m_unresponsiveReplyNumReset)
        {
            kill(webprocessPID, SIGFPE);
            m_unresponsiveReplyNum = 0;
            m_unresponsiveReplyNumReset = true;
        }
        else
        {
            RDKLOG_ERROR("WebProcess is being killed due to unrecover hang, pid=%u, url=%s\n", webprocessPID, activeURL.c_str());
            kill(webprocessPID, SIGKILL);
            m_unresponsiveReplyNumReset = false;
            m_crashed = true;
            m_browserClient->onRenderProcessTerminated();
            stopWebProcessWatchDog();
        }
    }
}

void WPEBrowser::processDidBecomeResponsive(WKPageRef page, const void* clientInfo)
{
    WPEBrowser& self = *const_cast<WPEBrowser*>(static_cast<const WPEBrowser*>(clientInfo));
    if (self.m_unresponsiveReplyNum > 0)
    {
        std::string activeURL = getPageActiveURL(page);
        pid_t webprocessPID = WKPageGetProcessIdentifier(page);
        RDKLOG_WARNING("WebProcess recovered after %d unresponsive replies, pid=%u, url=%s\n", self.m_unresponsiveReplyNum, webprocessPID, activeURL.c_str());
        self.m_unresponsiveReplyNum = 0;
    }
}

bool WPEBrowser::isCrashed()
{
    return m_crashed;
}

}
