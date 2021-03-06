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
#ifndef RDKBROWSER_INTERFACE_H
#define RDKBROWSER_INTERFACE_H

#include <js_utils.h>
#include <string>
#include <vector>
#include <map>

namespace RDK
{

enum RDKBrowserError
{
    /* Errorcodes specific to browser */
    RDKBrowserSuccess = 0,
    RDKBrowserFailed = 1,
    RDKBrowserNotInitialized = 2
};

class RDKBrowserClient
{
public:

    /**
     * Called when page loading started.
     */
    virtual void onLoadStarted() = 0;

    /**
     * Called during the progressiong of page load.
     * @param Progress of loading in percentage.
     */
    virtual void onLoadProgress(int) = 0;

    /**
     * Called on load completion.
     * @param Success status of the load process.
     * @param HTTP Status Code of the load process.
     * @param URL of the page loaded.
     */
    virtual void onLoadFinished(bool, uint32_t, const std::string&) = 0;

    /**
     * Called on any page navigation.
     * @param New URL set to the page.
     */
    virtual void onUrlChanged(const std::string&) = 0;

    /**
     * Called when any console log is made through script/page.
     * @param Source of the message.
     * @param Line number of the message log in script.
     * @param Log Message.
     */
    virtual void onConsoleLog(const std::string&, uint64_t, const std::string&) = 0;

    /**
     * Called when webProcess of wpe-webkit terminates abnormally.
     */
    virtual void onRenderProcessTerminated(const std::string& reason) = 0;

    /**
     * Called when cookies changed
     */
    virtual void onCookiesChanged() = 0;

    /**
     * Called when JavaScript bridge request message is received.
     * @param Name of the message.
     * @param Call ID to handle response callbacks in JavaScript context.
     * @param Message.
     */
    virtual void onJavaScriptBridgeRequest(const char*, uint64_t, const char*) = 0;
    virtual void onCallJavaScriptWithResult(int statusCode, const std::string& callGUID, const std::string& message, JSGlobalContextRef ctx, JSValueRef valueRef) = 0;
    virtual void onEvaluateJavaScript(int statusCode, const std::string& callGUID, const std::string& message, bool success) = 0;
    virtual void onAVELog(const char*, uint64_t, const char*) = 0;

    /**
     * Informs about the the remote client side hanging state
     */
    virtual bool isRemoteClientHanging() const = 0;

    /**
     * Reports system and web process metrics at web app 'launch' time
     */
    virtual void onReportLaunchMetrics(const std::map<std::string, std::string>& metrics) = 0;

    /**
     * Called on window.close()
     */
    virtual void onWindowCloseRequest() = 0;
};

class RDKBrowserInterface
{
public:
    struct WebFilterPattern
    {
        std::string scheme;
        std::string host;
        bool block;
    };
    typedef std::vector<std::pair<std::string, std::string>> ProxyPatterns;
    typedef std::vector<WebFilterPattern> WebFilters;
    typedef std::vector<std::pair<std::string, std::string>> Headers;

    static RDKBrowserInterface* create(bool useSingleContext, bool nonCompositedWebGLEnabled);

    virtual RDKBrowserError Initialize(bool useSingleContext, bool nonCompositedWebGLEnabled = false) = 0;
    virtual RDKBrowserError LoadURL(const char*) = 0;
    virtual RDKBrowserError SetHTML(const char*) = 0;
    virtual RDKBrowserError evaluateJavaScript(const std::string& javascript, const std::string& callGUID, bool needResult = false) = 0;
    virtual RDKBrowserError setSpatialNavigation(bool) = 0;
    virtual RDKBrowserError setWebSecurityEnabled(bool) = 0;
    virtual RDKBrowserError getWebSecurityEnabled(bool &enabled) const = 0;
    virtual RDKBrowserError setAVEEnabled(bool) = 0;
    virtual RDKBrowserError setAVESessionToken(const char*) = 0;
    virtual RDKBrowserError setAVELogLevel(uint64_t) = 0;
    virtual RDKBrowserError scrollTo(double, double) = 0;
    virtual RDKBrowserError scrollBy(double, double) = 0;
    virtual void registerClient(RDKBrowserClient*) = 0;
    virtual RDKBrowserError toggleResourceUsageOverlay() = 0;

    /**
     * Sends response to injected bundle that produced by previously received request.
     * @param Call id to handle JavaScript callbacks.
     * @param Succeed or not.
     * @param Message from client.
     */
    virtual RDKBrowserError sendJavaScriptBridgeResponse(uint64_t callID, bool success, const char* message) = 0;
    virtual RDKBrowserError setProxies(const ProxyPatterns&) = 0;
    virtual RDKBrowserError setWebFilters(const WebFilters&) = 0;
    virtual RDKBrowserError setCookieJar(const std::vector<std::string>&) = 0;
    virtual RDKBrowserError getCookieJar(std::vector<std::string>&) const = 0;
    virtual RDKBrowserError setUserAgent(const char*) = 0;
    virtual RDKBrowserError setTransparentBackground(bool) = 0;
    virtual RDKBrowserError setVisible(bool) = 0;
    virtual RDKBrowserError setWebAutomationEnabled(bool) = 0;
    virtual RDKBrowserError getLocalStorageEnabled(bool &enabled) const = 0;
    virtual RDKBrowserError setLocalStorageEnabled(bool enabled) = 0;
    virtual RDKBrowserError getConsoleLogEnabled(bool &enabled) const = 0;
    virtual RDKBrowserError setConsoleLogEnabled(bool enabled) = 0;
    virtual RDKBrowserError setHeaders(const Headers&) = 0;
    virtual RDKBrowserError reset() = 0;
    virtual RDKBrowserError setVoiceGuidanceEnabled(bool enabled) = 0;
    virtual RDKBrowserError setVoiceGuidanceMode(const std::string& mode) = 0;
    virtual RDKBrowserError setLanguage(const std::string& language) = 0;
    virtual bool isCrashed(std::string &reason) = 0;
    virtual RDKBrowserError getMemoryUsage(uint32_t &) const = 0;
    virtual RDKBrowserError deleteAllCookies() = 0;
    virtual RDKBrowserError clearWholeCache() = 0;
    virtual RDKBrowserError restartRenderer() = 0;
    virtual RDKBrowserError collectGarbage() = 0;
    virtual RDKBrowserError releaseMemory() = 0;
    virtual RDKBrowserError suspend() = 0;
    virtual RDKBrowserError resume() = 0;
    virtual std::string getCrashId() const = 0;
    virtual RDKBrowserError getNonCompositedWebGLEnabled(bool &enabled) const = 0;
    virtual RDKBrowserError setNonCompositedWebGLEnabled(bool enabled) = 0;
    virtual RDKBrowserError getCookieAcceptPolicy(std::string &) const = 0;
    virtual RDKBrowserError setCookieAcceptPolicy(const std::string&) = 0;
    virtual RDKBrowserError getActiveURL(std::string &) const = 0;
    virtual RDKBrowserError setIgnoreResize(bool) = 0;
    virtual RDKBrowserError getIgnoreResize(bool &enabled) const = 0;
    virtual RDKBrowserError setAllowScriptsToCloseWindow(bool) = 0;
    virtual RDKBrowserError getAllowScriptsToCloseWindow(bool &enabled) const = 0;

    virtual ~RDKBrowserInterface() { }
    /* TODO: Add more api's here */
};

}
#endif // RDKBROWSER_INTERFACE_H
