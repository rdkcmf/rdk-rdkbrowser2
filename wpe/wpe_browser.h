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
#ifndef WPE_BROWSER_H
#define WPE_BROWSER_H

#include "rdkbrowser_interface.h"

#include <JavaScriptCore/JSContextRef.h>
#include <JavaScriptCore/JSRetainPtr.h>

#include <WebKit2/Shared/API/c/wpe/WebKit.h>

#include <WebKit/WKRetainPtr.h>

#include <glib.h>
#include <mutex>
#include <semaphore.h>
#include <queue>
#include <map>

namespace RDK
{

enum WebProcessLaunchState
{
    WebProcessCold,  // the process is launching
    WebProcessHot    // the process is up and ready
};

struct AccessibilitySettings
{
    std::string m_ttsEndPoint;
    std::string m_ttsEndPointSecured;
    std::string m_language;
    std::string m_mode;
    uint8_t m_speechRate;
    bool m_enableVoiceGuidance;
};

class WPEBrowser: public RDKBrowserInterface
{
public:
    WPEBrowser();
    RDKBrowserError Initialize(bool singleContext, bool nonCompositedWebGLEnabled = false) override;
    RDKBrowserError LoadURL(const char*) override;
    RDKBrowserError SetHTML(const char*) override;
    RDKBrowserError evaluateJavaScript(const std::string&, const std::string&, bool needResult) override;
    RDKBrowserError setSpatialNavigation(bool) override;
    RDKBrowserError setWebSecurityEnabled(bool) override;
    RDKBrowserError getWebSecurityEnabled(bool &enabled) const override;
    RDKBrowserError setAVEEnabled(bool) override;
    RDKBrowserError setAVESessionToken(const char*) override;
    RDKBrowserError setAVELogLevel(uint64_t) override;
    RDKBrowserError scrollTo(double, double) override;
    RDKBrowserError scrollBy(double, double) override;
    RDKBrowserError setProxies(const ProxyPatterns& proxies) override;
    RDKBrowserError setWebFilters(const WebFilters& filters) override;
    RDKBrowserError setCookieJar(const std::vector<std::string>& cookieJar) override;
    RDKBrowserError getCookieJar(std::vector<std::string>& cookieJar) const override;
    RDKBrowserError setUserAgent(const char*) override;
    RDKBrowserError setTransparentBackground(bool transparent) override;
    RDKBrowserError setVisible(bool visible) override;
    RDKBrowserError getLocalStorageEnabled(bool &enabled) const override;
    RDKBrowserError setLocalStorageEnabled(bool enabled) override;
    RDKBrowserError getConsoleLogEnabled(bool &enabled) const override;
    RDKBrowserError setConsoleLogEnabled(bool enabled) override;
    RDKBrowserError setHeaders(const Headers& headers) override;
    RDKBrowserError reset() override;
    RDKBrowserError toggleResourceUsageOverlay() override;
    RDKBrowserError setVoiceGuidanceEnabled(bool enabled) override;
    RDKBrowserError setVoiceGuidanceMode(const std::string& mode) override;
    RDKBrowserError setSpeechRate(uint8_t rate) override;
    RDKBrowserError setLanguage(const std::string& language) override;
    RDKBrowserError setTTSEndPoint(const std::string& url) override;
    RDKBrowserError setTTSEndPointSecured(const std::string& url) override;
    RDKBrowserError getMemoryUsage(uint32_t &) const override;
    RDKBrowserError deleteAllCookies() override;
    RDKBrowserError clearWholeCache() override;
    RDKBrowserError restartRenderer() override;
    RDKBrowserError collectGarbage() override;
    RDKBrowserError releaseMemory() override;
    RDKBrowserError getNonCompositedWebGLEnabled(bool &enabled) const override;
    RDKBrowserError setNonCompositedWebGLEnabled(bool enabled) override;
    RDKBrowserError getCookieAcceptPolicy(std::string &) const final;
    RDKBrowserError setCookieAcceptPolicy(const std::string&) final;

    /* etc */
    virtual ~WPEBrowser();
    virtual void registerClient(RDKBrowserClient*) override;

    /**
     * @copydoc RDKBrowserInterface::sendJavaScriptBridgeResponse(uint64_t, bool, const char*)
     */
    virtual RDKBrowserError sendJavaScriptBridgeResponse(uint64_t callID, bool success, const char* message) override;

    /* static callback functions */
    static void nullJavaScriptCallback(WKSerializedScriptValueRef scriptValue, WKErrorRef error, void* context);
    static void returnJavaScriptCallback(WKSerializedScriptValueRef scriptValue, WKErrorRef error, void* context);

    /* page ui client */
    static void userMediaPermissionRequestCallBack(WKPageRef, WKFrameRef, WKSecurityOriginRef, WKSecurityOriginRef,
            WKUserMediaPermissionRequestRef permissionRequest, const void* clientInfo);
    static void willAddDetailedMessageToConsole(WKPageRef page, WKStringRef source, WKStringRef level, uint64_t line,
            uint64_t column, WKStringRef message, WKStringRef url, const void* clientInfo);
    static void runBeforeUnloadConfirmPanel(WKPageRef page, WKStringRef message, WKFrameRef frame, WKPageRunBeforeUnloadConfirmPanelResultListenerRef listener, const void *clientInfo);

    /* page load client */
    static void didStartProgress(WKPageRef page, const void* clientInfo);
    static void didChangeProgress(WKPageRef page, const void* clientInfo);
    static void didFinishProgress(WKPageRef page, const void* clientInfo);

    /* page navigation client */
    static void didStartProvisionalNavigation(WKPageRef page, WKNavigationRef, WKTypeRef, const void*);
    static void didFailProvisionalNavigation(WKPageRef page, WKNavigationRef navigation,
            WKErrorRef error, WKTypeRef userData, const void* clientInfo);
    static void didFailNavigation(WKPageRef, WKNavigationRef, WKErrorRef, WKTypeRef, const void*);
    static void didCommitNavigation(WKPageRef page, WKNavigationRef, WKTypeRef, const void* clientInfo);
    static void didSameDocumentNavigation(WKPageRef page, WKNavigationRef, WKSameDocumentNavigationType navigationType, WKTypeRef, const void* clientInfo);
    static void decidePolicyForNavigationAction(WKPageRef page, WKNavigationActionRef navigationAction,
            WKFramePolicyListenerRef listener, WKTypeRef userData, const void*clientInfo);
    static void decidePolicyForNavigationResponse(WKPageRef page, WKNavigationResponseRef navigationResponse,
            WKFramePolicyListenerRef listener, WKTypeRef userData, const void* clientInfo);
    static void webProcessDidCrash(WKPageRef page, const void* clientInfo);
    static void didReceiveAuthenticationChallenge(WKPageRef, WKAuthenticationChallengeRef challenge, const void*);

    static gboolean CallJavaScript(gpointer);

    bool isCrashed(std::string &reason) override;

    std::string getCrashId() const override;

private:
    enum class NeedResult { Need, DontNeed };

    /* internal functions */
    static WKRetainPtr<WKContextRef> getOrCreateContext(bool singleContext);
    WKPreferencesRef getPreferences() const;
    bool enableWebSecurity(bool on);
    bool enableScrollToFocused(bool enable);
    void sendJavaScriptResponse(WKSerializedScriptValueRef scriptValue, WKErrorRef error, NeedResult needResult);
    RDKBrowserError executeJs(const char*);

    void sendAccessibilitySettings();
    void startWebProcessWatchDog();
    void stopWebProcessWatchDog();
    void checkIfWebProcessResponsive();
    void didReceiveWebProcessResponsivenessReply(bool isWebProcessResponsive);
    void collectMetricsOnLoadStart();
    void collectMetricsOnLoadEnd();
    void reportLaunchMetrics();
    void closePage();
    void generateCrashId();
    void increaseWebProcessPrio();
    void restoreWebProcessPrio();

    /* Callback to handle messages received from injected bundle. */
    static void didReceiveMessageFromInjectedBundle(WKPageRef,
        WKStringRef messageName, WKTypeRef messageBody, const void *clientInfo);

    static void cookiesDidChange(WKCookieManagerRef, const void* clientInfo);
    static void didGetAllCookies(WKArrayRef cookies, WKErrorRef, void* context);
    static void processDidBecomeResponsive(WKPageRef page, const void* clientInfo);

private:
    /* WPE Webkit specific data */
    WKRetainPtr<WKContextRef> m_context;
    WKRetainPtr<WKViewRef>  m_view;
    WKRetainPtr<WKStringRef> m_pageGroupIdentifier;
    WKRetainPtr<WKPageGroupRef> m_pageGroup;
    WKRetainPtr<WKPageConfigurationRef> m_pageConfiguration;
    WKRetainPtr<WKWebsiteDataStoreRef> m_webDataStore;

    /* RDK specific data */
    RDKBrowserClient* m_browserClient { nullptr };

    /* Add more WPE private data if required */
    std::string m_provisionalURL;
    uint32_t m_httpStatusCode { 0 };
    uint32_t m_loadProgress { 0 };
    bool m_loadFailed { false };
    bool m_loadCanceled { false };

    bool m_webProcessCheckInProgress { false };
    uint32_t m_unresponsiveReplyNum { 0 };
    uint32_t m_unresponsiveReplyMaxNum { 0 };
    guint m_watchDogTag { 0 };
    bool m_didIncreasePrio { false };

    std::queue<std::string> m_callIds;

    std::vector<std::string> m_cookieJar;
    bool m_gettingCookies { false };
    bool m_dirtyCookies { false };
    bool m_webSecurityEnabled { true };
    bool m_useSingleContext { false };
    bool m_isHiddenOnReset { false };
    bool m_ephemeralMode { false };
    std::string m_defaultUserAgent;
    int  m_signalSentToWebProcess { -1 };
    bool m_crashed { false };
    WebProcessLaunchState m_webProcessState { WebProcessCold };
    bool m_didSendLaunchMetrics { false };
    gint64 m_pageLoadStart { -1 };
    gint64 m_idleStart { -1 };
    guint m_pageLoadNum { 0 };
    std::map<std::string, std::string> m_launchMetricsMetrics;
    AccessibilitySettings m_accessibilitySettings;

    std::string m_crashId;
};

}

#endif // WPE_BROWSER_H
