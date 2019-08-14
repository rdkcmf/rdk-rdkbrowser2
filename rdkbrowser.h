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
#ifndef RDKBROWSER_H
#define RDKBROWSER_H

#include "rdkbrowser_interface.h"
#include "rtObject.h"

#include <semaphore.h>
#include <glib.h>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <wayland-client.h>

namespace RDK
{

class RDKBrowserEmit: public rtEmit
{
public:
    virtual rtError Send(int numArgs,const rtValue* args,rtValue* result) override;
};

class Event
{
protected:
    rtObjectRef m_object;
    rtString name() const
    {
        return m_object.get<rtString>("name");
    }
    rtObjectRef object() const
    {
        return m_object;
    }
    Event(const char* eventName) : m_object(new rtMapObject)
    {
        m_object.set("name", eventName);
    }
public:
    friend class EventEmitter;
};

class EventEmitter
{
public:
    EventEmitter()
        : m_emit(new RDKBrowserEmit)
        , m_timeoutId(0)
        , m_isRemoteClientHanging(false)
    { }
    ~EventEmitter()
    {
        if (m_timeoutId != 0)
            g_source_remove(m_timeoutId);
    }

    rtError setListener(const char* eventName, rtIFunction* f)
    {
        return m_emit->setListener(eventName, f);
    }
    rtError delListener(const char* eventName, rtIFunction* f)
    {
        return m_emit->delListener(eventName, f);
    }
    rtError send(Event&& event);
    bool isRemoteClientHanging() const { return m_isRemoteClientHanging; }
    void clear();
private:
    rtEmitRef m_emit;
    std::queue<rtObjectRef> m_eventQueue;
    int m_timeoutId;
    bool m_isRemoteClientHanging;
};


class RDKBrowser : public rtObject,public RDKBrowserClient
{
public:
    RDKBrowser(const rtString& displayName, bool useSingleContext);
    virtual ~RDKBrowser();
    bool isInitialized();

    rtDeclareObject(RDKBrowser, rtObject);

    /* Declare object functions */
    rtMethod1ArgAndNoReturn("setHTML", setHTML, rtString);
    rtMethod2ArgAndNoReturn("on", setListener, rtString, rtFunctionRef);
    rtMethod2ArgAndNoReturn("delListener", delListener, rtString, rtFunctionRef);
    rtMethod2ArgAndNoReturn("callJavaScriptWithResult", callJavaScriptWithResult, rtString, rtFunctionRef);
    rtMethod2ArgAndNoReturn("evaluateJavaScript", evaluateJavaScript, rtString, rtFunctionRef);
    rtMethod1ArgAndNoReturn("setSpatialNavigation", setSpatialNavigation, bool);
    rtMethod1ArgAndNoReturn("setWebSecurityEnabled", setWebSecurityEnabled, rtValue);
    rtMethod2ArgAndNoReturn("scrollTo", scrollTo, double, double);
    rtMethod2ArgAndNoReturn("scrollBy", scrollBy, double, double);
    rtMethod3ArgAndNoReturn("sendJavaScriptBridgeResponse", sendJavaScriptBridgeResponse, uint64_t, bool, rtString);

    rtMethod1ArgAndNoReturn("setAVEEnabled", setAVEEnabled, bool);
    rtMethod1ArgAndNoReturn("setAVESessionToken", setAVESessionToken, rtString);
    rtMethod1ArgAndNoReturn("setAVELogLevel", setAVELogLevel, uint64_t);
    rtMethodNoArgAndNoReturn("toggleResourceUsageOverlay", toggleResourceUsageOverlay);
    rtMethodNoArgAndNoReturn("reset", reset);
    rtMethodNoArgAndNoReturn("deleteAllCookies", deleteAllCookies);
    rtMethodNoArgAndNoReturn("clearWholeCache", clearWholeCache);
    rtMethodNoArgAndNoReturn("restartRenderer", restartRenderer);
    rtMethodNoArgAndNoReturn("close", close);
    rtMethodNoArgAndNoReturn("gc", gc);
    rtMethodNoArgAndNoReturn("releaseMemory", releaseMemory);
    rtMethodNoArgAndReturn("suspend", suspend, bool);
    rtMethodNoArgAndReturn("resume", resume, bool);

    /* Declare object properties */
    rtProperty(url, getURL, setURL, rtString);
    rtProperty(cookieJar, getCookieJar, setCookieJar, rtObjectRef);
    rtProperty(proxies, getProxies, setProxies, rtObjectRef);
    rtProperty(webfilter, getWebFilters, setWebFilters, rtObjectRef);
    rtProperty(userAgent, getUserAgent, setUserAgent, rtString);
    rtProperty(transparentBackground, getTransparentBackground, setTransparentBackground, rtValue);
    rtProperty(visible, getVisible, setVisible, rtValue);
    rtProperty(localStorageEnabled, getLocalStorageEnabled, setLocalStorageEnabled, rtValue);
    rtProperty(consoleLogEnabled, getConsoleLogEnabled, setConsoleLogEnabled, rtValue);
    rtProperty(headers, getHeaders, setHeaders, rtObjectRef);
    rtProperty(enableVoiceGuidance, getVoiceGuidanceEnabled, setVoiceGuidanceEnabled, rtString);
    rtProperty(speechRate, getSpeechRate, setSpeechRate, rtValue);
    rtProperty(voiceGuidanceLanguage, getVoiceGuidanceLanguage, setVoiceGuidanceLanguage, rtString);
    rtProperty(language, getLanguage, setLanguage, rtString);
    rtProperty(ttsEndPoint, getTTSEndPoint, setTTSEndPoint, rtString);
    rtProperty(ttsEndPointSecured, getTTSEndPointSecured, setTTSEndPointSecured, rtString);
    rtProperty(voiceGuidanceMode, getVoiceGuidanceMode, setVoiceGuidanceMode, rtString);
    rtReadOnlyProperty(memoryUsage, getMemoryUsage, rtValue);
    rtProperty(nonCompositedWebGLEnabled, getNonCompositedWebGLEnabled, setNonCompositedWebGLEnabled, rtValue);
    rtProperty(webSecurityEnabled, getWebSecurityEnabled, setWebSecurityEnabled, rtValue);
    rtProperty(cookieAcceptPolicy, getCookieAcceptPolicy, setCookieAcceptPolicy, rtString);

    /* rtObject property functions */
    // set property functions
    virtual rtError setURL(const rtString& url);
    virtual rtError setCookieJar(const rtObjectRef& cookieJar);
    virtual rtError setProxies(const rtObjectRef& proxies);
    virtual rtError setWebFilters(const rtObjectRef& filters);
    virtual rtError setUserAgent(const rtString& userAgent);
    virtual rtError setTransparentBackground(const rtValue& transparent);
    virtual rtError setVisible(const rtValue& visible);
    virtual rtError setLocalStorageEnabled(const rtValue& enabled);
    virtual rtError setConsoleLogEnabled(const rtValue& enabled);
    virtual rtError setHeaders(const rtObjectRef& headers);
    virtual rtError setVoiceGuidanceEnabled(const rtString& enabled);
    virtual rtError setSpeechRate(const rtValue& rate);
    virtual rtError setVoiceGuidanceLanguage(const rtString& language);
    virtual rtError setLanguage(const rtString& language);
    virtual rtError setTTSEndPoint(const rtString& url);
    virtual rtError setTTSEndPointSecured(const rtString& url);
    virtual rtError setVoiceGuidanceMode(const rtString& mode);
    virtual rtError setNonCompositedWebGLEnabled(const rtValue& enabled);
    virtual rtError setCookieAcceptPolicy(const rtString& policy);

   // get property functions
    virtual rtError getURL(rtString& s) const;
    virtual rtError getCookieJar(rtObjectRef& cookieJar) const;
    virtual rtError getProxies(rtObjectRef& proxies) const;
    virtual rtError getWebFilters(rtObjectRef& filters) const;
    virtual rtError getUserAgent(rtString& s) const;
    virtual rtError getTransparentBackground(rtValue& transparent) const;
    virtual rtError getVisible(rtValue& visible) const;
    virtual rtError getLocalStorageEnabled(rtValue& enabled) const;
    virtual rtError getConsoleLogEnabled(rtValue& enabled) const;
    virtual rtError getHeaders(rtObjectRef& headers) const;
    virtual rtError getVoiceGuidanceEnabled(rtString& enabled) const;
    virtual rtError getSpeechRate(rtValue& rate) const;
    virtual rtError getVoiceGuidanceLanguage(rtString& language) const;
    virtual rtError getLanguage(rtString& language) const;
    virtual rtError getTTSEndPoint(rtString& url) const;
    virtual rtError getTTSEndPointSecured(rtString& url) const;
    virtual rtError getVoiceGuidanceMode(rtString& enabled) const;
    virtual rtError getMemoryUsage(rtValue& ) const;
    virtual rtError getNonCompositedWebGLEnabled(rtValue& enabled) const;
    virtual rtError getWebSecurityEnabled(rtValue& enabled) const;
    virtual rtError getCookieAcceptPolicy(rtString& policy) const;

    /* rtObject function handlers */
    virtual rtError setHTML(const rtString& html);
    virtual rtError setListener(rtString eventName, const rtFunctionRef& f);
    virtual rtError delListener(rtString  eventName, const rtFunctionRef& f);
    virtual rtError callJavaScriptWithResult(const rtString& params, const rtFunctionRef& func);
    virtual rtError evaluateJavaScript(const rtString& params, const rtFunctionRef& func);
    virtual rtError setSpatialNavigation(const bool& on);
    virtual rtError setWebSecurityEnabled(const rtValue& on);
    virtual rtError setAVEEnabled(const bool& on);
    virtual rtError setAVESessionToken(const rtString&);
    virtual rtError setAVELogLevel(uint64_t);
    virtual rtError scrollTo(const double& dx, const double& dy);
    virtual rtError scrollBy(const double& dx, const double& dy);
    virtual rtError reset();
    virtual rtError toggleResourceUsageOverlay();
    virtual rtError deleteAllCookies();
    virtual rtError clearWholeCache();
    virtual rtError restartRenderer();
    virtual rtError close();
    virtual rtError gc();
    virtual rtError releaseMemory();
    virtual rtError suspend(bool& b);
    virtual rtError resume(bool& b);

    /**
     * Sends response to injected bundle that produced by previously received request.
     * @param Call id to handle JavaScript callbacks.
     * @param Succeed or not.
     * @param Message from client.
     */
    virtual rtError sendJavaScriptBridgeResponse(uint64_t callID, bool success, const rtString& message);

    /* RDKBrowserClient override functions */
    virtual void onLoadStarted() override;
    virtual void onLoadProgress(int) override;
    virtual void onLoadFinished(bool, uint32_t, const std::string&) override;
    virtual void onUrlChanged(const std::string&) override;
    virtual void onConsoleLog(const std::string&, uint64_t, const std::string&) override;
    virtual void onRenderProcessTerminated(const std::string& reason) override;
    virtual void onCookiesChanged() override;

    /**
     * @copydoc RDKBrowserClient::onJavaScriptBridgeRequest(const char*,uint64_t,const char*)
     */
    virtual void onJavaScriptBridgeRequest(const char* name, uint64_t callID, const char* message) override;
    virtual void onCallJavaScriptWithResult(int statusCode, const std::string& callId, const std::string& message, JSGlobalContextRef ctx, JSValueRef valueRef) override;
    virtual void onEvaluateJavaScript(int statusCode, const std::string& callId, const std::string& message, bool success) override;
    virtual void onAVELog(const char* prefix, const uint64_t level, const char* data) override;

    /**
     * @copydoc RDKBrowserClient::isRemoteClientHanging() const
     */
    virtual bool isRemoteClientHanging() const { return m_eventEmitter.isRemoteClientHanging(); }

    virtual void onReportLaunchMetrics(const std::map<std::string, std::string>& metrics) override;

    static void registryHandleGlobal(void *data, struct wl_registry *registry, uint32_t id, const char *interface, uint32_t);
    static void registryHandleGlobalRemove(void *, struct wl_registry *, uint32_t);

    void onWaylandConnectionClosed();

private:
    bool checkBrowser(const char* logPrefix) const;
    enum class NeedResult { DontNeed, Need };
    rtError callJavaScript(const rtString& javascript, const rtFunctionRef& func, NeedResult needResult);
    void sendJavaScriptResult(int statusCode, const std::string& callId, rtObjectRef params, const std::string& message);
    void cleanup();
    rtError updateDisplayEnvVar();

    std::unique_ptr<RDKBrowserInterface>  m_browser;

    std::map<std::string, rtFunctionRef> m_uids;

    rtString m_url;
    rtString m_userAgent;
    rtString m_displayName;
    bool m_useSingleContext;
    EventEmitter m_eventEmitter;

    struct timespec m_pageLoadStart { 0, 0 };
    struct wl_display* m_display;
    struct wl_registry* m_registry;
    struct wl_compositor* m_compositor;
    GSource *m_source;
    bool mBrowserInitialized;
};

}

#endif // RDKBROWSER_H
