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

namespace RDK
{

class WPEBrowser: public RDKBrowserInterface
{
public:
    WPEBrowser();
    RDKBrowserError Initialize(bool singleContext) override;
    RDKBrowserError LoadURL(const char*) override;
    RDKBrowserError SetHTML(const char*) override;
    RDKBrowserError evaluateJavaScript(const std::string&, const std::string&, bool needResult) override;
    RDKBrowserError setSpatialNavigation(bool) override;
    RDKBrowserError setWebSecurityEnabled(bool) override;
    RDKBrowserError setAVEEnabled(bool) override;
    RDKBrowserError setAVESessionToken(const char*) override;
    RDKBrowserError scrollTo(double,double) override;
    RDKBrowserError setProxies(const ProxyPatterns& proxies) override;
    RDKBrowserError setWebFilters(const WebFilters& filters) override;
    RDKBrowserError setCookieJar(const std::vector<std::string>& cookieJar) override;
    RDKBrowserError getCookieJar(std::vector<std::string>& cookieJar) const override;
    RDKBrowserError setUserAgent(const char*) override;
    RDKBrowserError setTransparentBackground(bool transparent) override;

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

    /* page load client */
    static void didStartProgress(WKPageRef page, const void* clientInfo);
    static void didChangeProgress(WKPageRef page, const void* clientInfo);
    static void didFinishProgress(WKPageRef page, const void* clientInfo);

    /* page navigation client */
    static void didFailProvisionalNavigation(WKPageRef page, WKNavigationRef navigation,
            WKErrorRef error, WKTypeRef userData, const void* clientInfo);
    static void didFailNavigation(WKPageRef, WKNavigationRef, WKErrorRef, WKTypeRef, const void*);
    static void didCommitNavigation(WKPageRef page, WKNavigationRef, WKTypeRef, const void* clientInfo);
    static void decidePolicyForNavigationAction(WKPageRef page, WKNavigationActionRef navigationAction,
            WKFramePolicyListenerRef listener, WKTypeRef userData, const void*clientInfo);
    static void decidePolicyForNavigationResponse(WKPageRef page, WKNavigationResponseRef navigationResponse,
            WKFramePolicyListenerRef listener, WKTypeRef userData, const void* clientInfo);
    static void webProcessDidCrash(WKPageRef page, const void* clientInfo);

    static gboolean CallJavaScript(gpointer);
private:
    enum class NeedResult { Need, DontNeed };

    /* internal functions */
    static WKRetainPtr<WKContextRef> getOrCreateContext(bool singleContext);
    WKPreferencesRef getPreferences() const;
    bool enableWebSecurity(bool on);
    void sendJavaScriptResponse(WKSerializedScriptValueRef scriptValue, WKErrorRef error, NeedResult needResult);
    RDKBrowserError executeJs(const char*);

    /* Callback to handle messages received from injected bundle. */
    static void didReceiveMessageFromInjectedBundle(WKPageRef,
        WKStringRef messageName, WKTypeRef messageBody, const void *clientInfo);

    static void cookiesDidChange(WKCookieManagerRef, const void* clientInfo);
    static void didGetAllCookies(WKArrayRef cookies, WKErrorRef, void* context);

private:
    /* WPE Webkit specific data */
    WKRetainPtr<WKContextRef> m_context;
    WKRetainPtr<WKViewRef>  m_view;
    WKRetainPtr<WKStringRef> m_pageGroupIdentifier;
    WKRetainPtr<WKPageGroupRef> m_pageGroup;
    WKRetainPtr<WKPageConfigurationRef> m_pageConfiguration;
    WKRetainPtr<WKURLRef> m_shellURL;
    WKRetainPtr<WKWebsiteDataStoreRef> m_webDataStore;

    /* RDK specific data */
    RDKBrowserClient* m_browserClient { nullptr };

    /* Add more WPE private data if required */
    uint32_t m_httpStatusCode { 0 };
    uint32_t m_loadProgress { 0 };
    bool m_loadFailed { false };

    std::queue<std::string> m_callIds;

    std::vector<std::string> m_cookieJar;
    bool m_gettingCookies { false };
    bool m_dirtyCookies { false };
    bool m_webSecurityEnabled { true };
    bool m_useSingleContext { false };
};

}

#endif // WPE_BROWSER_H
