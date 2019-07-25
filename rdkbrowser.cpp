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
#include "rdkbrowser.h"
#include "cookiejar_utils.h"
#include "logger.h"
#include "overrides.h"

#include <stdio.h>
#include <uuid/uuid.h>

#include <fstream>

#define RETURN_IF_FAIL(x) do { if ((x) != RT_OK) return RT_FAIL; } while(0)

namespace RDK
{
struct OnHTMLDocumentLoadedEvent: public Event
{
  OnHTMLDocumentLoadedEvent(bool success, int httpStatus) : Event("onHTMLDocumentLoaded")
  {
      m_object.set("success", success);
      m_object.set("httpStatus", httpStatus);
  }
};

struct OnHTMLLinkClickedEvent: public Event
{
  OnHTMLLinkClickedEvent(const std::string& url) : Event("onHTMLLinkClicked")
  {
      m_object.set("value", rtString(url.c_str()));
  }
};

struct OnConsoleLog: public Event
{
  OnConsoleLog(const std::string& msg) : Event("onConsoleLog")
  {
      m_object.set("logMessage", rtString(msg.c_str()));
  }
};

struct OnError: public Event
{
    OnError(const char *errorType, const char *description) : Event("onError")
    {
        m_object.set("errorType", errorType);
        m_object.set("description", description);
    }
};

struct OnJavaScriptBridgeRequestEvent: public Event
{
  OnJavaScriptBridgeRequestEvent(uint64_t callID, const char* message) : Event("onJavaScriptBridgeRequest")
  {
      m_object.set("message", message);
      m_object.set("callID", callID);
  }
};

struct OnAVELogEvent: public Event
{
  OnAVELogEvent(const char* prefix, uint64_t level, const char* data) : Event("onAVELog")
  {
      m_object.set("prefix", prefix);
      m_object.set("level", level);
      m_object.set("data", data);
  }
};

struct OnJavaScriptServiceManagerRequestEvent: public Event
{
  OnJavaScriptServiceManagerRequestEvent(uint64_t callID, const char* message) : Event("onJavaScriptServiceManagerRequest")
  {
      m_object.set("message", message);
      m_object.set("callID", callID);
  }
};

struct OnCookieJarChangedEvent: public Event
{
    OnCookieJarChangedEvent() : Event("onCookieJarChanged")
    {
    }
};

struct OnLaunchMetrics: public Event
{
    OnLaunchMetrics(const std::map<std::string, std::string>& metrics) : Event("onLaunchMetrics")
    {
        for (const auto& p : metrics)
        {
            m_object.set(p.first.c_str(), p.second.c_str());
        }
    }
};

rtError RDKBrowserEmit::Send(int numArgs,const rtValue* args,rtValue* result)
{
    (void)result;
    rtError error = RT_OK;
    if (numArgs > 0)
    {
        rtString eventName = args[0].toString();
        RDKLOG_TRACE("RDKBrowserEmit::Send %s", eventName.cString());

        std::vector<_rtEmitEntry>::iterator itr = mEntries.begin();
        while (itr != mEntries.end())
        {
            _rtEmitEntry& entry = (*itr);
            if (entry.n == eventName)
            {
                rtValue discard;
                // SYNC EVENTS
#ifndef DISABLE_SYNC_EVENTS
                // SYNC EVENTS ... enables stopPropagation() ...
                //
                error = entry.f->Send(numArgs-1, args+1, &discard);
#else

#warning "  >>>>>>  No SYNC EVENTS... stopPropagation() will be broken !!"

                error = entry.f->Send(numArgs-1, args+1, NULL);
#endif
                if (error != RT_OK)
                    RDKLOG_INFO("failed to send. %s", rtStrError(error));

                // EPIPE means it's disconnected
                if (error == rtErrorFromErrno(EPIPE) || error == RT_ERROR_STREAM_CLOSED)
                {
                    RDKLOG_INFO("Broken entry in mEntries");
                }
                // there can be only one listener for a event as of now
                break;
            }
            else
            {
                ++itr;
            }
        }
    }
    return error;
}

rtError EventEmitter::send(Event&& event) {
    auto handleEvent = [](gpointer data) -> gboolean {
        EventEmitter& self = *static_cast<EventEmitter*>(data);

        if (!self.m_eventQueue.empty())
        {
            rtObjectRef obj = self.m_eventQueue.front();
            self.m_eventQueue.pop();

            rtError rc = self.m_emit.send(obj.get<rtString>("name"), obj);
            if (RT_OK != rc)
            {
                RDKLOG_ERROR("Can't send event{name=%s}, error code: %d", obj.get<rtString>("name").cString(), rc);
            }

            // if timeout occurs do not increment hang detector or stream is closed disable hang detection.
            if (RT_ERROR_TIMEOUT == rc || rc == rtErrorFromErrno(EPIPE) || rc == RT_ERROR_STREAM_CLOSED)
            {
                if (!self.m_isRemoteClientHanging)
                {
                    self.m_isRemoteClientHanging = true;
                    RDKLOG_WARNING("Remote client is entered to a hanging state");
                }
                if (rc == rtErrorFromErrno(EPIPE) || rc == RT_ERROR_STREAM_CLOSED)
                {
                    RDKLOG_WARNING("Remote client connection seems to be closed/broken");
                    // Clear the listeners here
                    self.m_emit->clearListeners();
                }
            }
            else if (RT_OK == rc)
            {
                if (self.m_isRemoteClientHanging)
                {
                    self.m_isRemoteClientHanging = false;
                    RDKLOG_WARNING("Remote client is recovered after the hanging state");
                }
            }

            if (!self.m_eventQueue.empty())
            {
                return G_SOURCE_CONTINUE;
            }
        }

        self.m_timeoutId = 0;
        return G_SOURCE_REMOVE;
    };

    m_eventQueue.push(event.object());

    if (m_timeoutId == 0) {
        m_timeoutId = g_timeout_add(0, handleEvent, (void*) this);
    }

    return RT_OK;
}

void EventEmitter::clear()
{
    if (m_timeoutId != 0)
    {
        g_source_remove(m_timeoutId);
        m_timeoutId = 0;
    }
    m_eventQueue = std::queue<rtObjectRef>();
    m_emit->clearListeners();
}

//Define RDKBrowser object
rtDefineObject(RDKBrowser, rtObject);

//Define RDKBrowser object properties
rtDefineProperty(RDKBrowser, url);
rtDefineProperty(RDKBrowser, cookieJar);
rtDefineProperty(RDKBrowser, proxies);
rtDefineProperty(RDKBrowser, webfilter);
rtDefineProperty(RDKBrowser, userAgent);
rtDefineProperty(RDKBrowser, transparentBackground);
rtDefineProperty(RDKBrowser, visible);
rtDefineProperty(RDKBrowser, localStorageEnabled);
rtDefineProperty(RDKBrowser, consoleLogEnabled);
rtDefineProperty(RDKBrowser, headers);
rtDefineProperty(RDKBrowser, enableVoiceGuidance);
rtDefineProperty(RDKBrowser, voiceGuidanceMode);
rtDefineProperty(RDKBrowser, speechRate);
rtDefineProperty(RDKBrowser, voiceGuidanceLanguage);
rtDefineProperty(RDKBrowser, language);
rtDefineProperty(RDKBrowser, ttsEndPoint);
rtDefineProperty(RDKBrowser, ttsEndPointSecured);
rtDefineProperty(RDKBrowser, memoryUsage);
rtDefineProperty(RDKBrowser, nonCompositedWebGLEnabled);
rtDefineProperty(RDKBrowser, webSecurityEnabled);

//Define RDKBrowser object methods
rtDefineMethod(RDKBrowser, setHTML);
rtDefineMethod(RDKBrowser, setListener);
rtDefineMethod(RDKBrowser, delListener);
rtDefineMethod(RDKBrowser, callJavaScriptWithResult);
rtDefineMethod(RDKBrowser, evaluateJavaScript);
rtDefineMethod(RDKBrowser, setSpatialNavigation);
rtDefineMethod(RDKBrowser, setWebSecurityEnabled);
rtDefineMethod(RDKBrowser, scrollTo);
rtDefineMethod(RDKBrowser, scrollBy);
rtDefineMethod(RDKBrowser, sendJavaScriptBridgeResponse);

rtDefineMethod(RDKBrowser, setAVEEnabled);
rtDefineMethod(RDKBrowser, setAVESessionToken)
rtDefineMethod(RDKBrowser, setAVELogLevel)
rtDefineMethod(RDKBrowser, reset);
rtDefineMethod(RDKBrowser, toggleResourceUsageOverlay);
rtDefineMethod(RDKBrowser, deleteAllCookies);
rtDefineMethod(RDKBrowser, clearWholeCache);
rtDefineMethod(RDKBrowser, restartRenderer);
rtDefineMethod(RDKBrowser, close);
rtDefineMethod(RDKBrowser, gc);
rtDefineMethod(RDKBrowser, releaseMemory);

namespace
{
std::string uuid_readable()
{
    uuid_t uuid;
    uuid_generate(uuid);
    const char kUnparsedUuidSize = 37;
    char unparsed[kUnparsedUuidSize];
    uuid_unparse(uuid, unparsed);

    return std::string(unparsed);
}
}

struct DisplayEventSource
{
    GSource     m_source;
    GPollFD     m_pfd;
    RDKBrowser* m_browser;
};

GSourceFuncs DisplayEventSourceFunctions = {
    // prepare
    [](GSource*, gint* timeout) -> gboolean
    {
        *timeout = -1;
        return FALSE;
    },
    // check
    [](GSource* base) -> gboolean
    {
        auto* source = reinterpret_cast<DisplayEventSource*>(base);
        return !!source->m_pfd.revents;
    },
    // dispatch
    [](GSource* base, GSourceFunc, gpointer) -> gboolean
    {
        auto* source = reinterpret_cast<DisplayEventSource*>(base);

        if (source->m_pfd.revents & (G_IO_ERR | G_IO_HUP))
        {
            if(source->m_browser)
            {
                RDKBrowser* browser = source->m_browser;
                source->m_browser = nullptr;

                RDKLOG_INFO("wayland connection closed, rdkbrowser=%p", browser);
                browser->onWaylandConnectionClosed();
                browser->Release();
            }
            return FALSE;
        }

        source->m_pfd.revents = 0;
        return TRUE;
    },
    // finalize
    [](GSource* base) {
        auto* source = reinterpret_cast<DisplayEventSource*>(base);
        if (source->m_browser) {
            RDKBrowser* browser = source->m_browser;
            source->m_browser = nullptr;
            browser->Release();
        }
    },
    nullptr, // closure_callback
    nullptr, // closure_marshall
};

void RDKBrowser::registryHandleGlobal(void *data, struct wl_registry *registry, uint32_t id, const char *interface, uint32_t)
{
    RDKBrowser* browser = (RDKBrowser *)data;

    if ( strcmp(interface, "wl_compositor") == 0 ) {
        browser->m_compositor = (wl_compositor *) wl_registry_bind(registry, id, &wl_compositor_interface, 1);
    }
}

void RDKBrowser::registryHandleGlobalRemove(void *, struct wl_registry *, uint32_t)
{
}

static struct wl_registry_listener registryListener =
{
    RDKBrowser::registryHandleGlobal,
    RDKBrowser::registryHandleGlobalRemove
};

RDKBrowser::RDKBrowser(const rtString& displayName, bool useSingleContext)
    : m_browser(RDK::RDKBrowserInterface::create(useSingleContext))
    , m_displayName(displayName)
    , m_useSingleContext(useSingleContext)
    , m_display(nullptr)
    , m_registry(nullptr)
    , m_compositor(nullptr)
    , m_source(nullptr)
    , mBrowserInitialized(false)
{
    if(m_browser)
    {
        m_browser->registerClient(this);

        m_display = wl_display_connect(displayName.cString());
        if(!m_display)
        {
            return;
        }

        m_registry = wl_display_get_registry(m_display);
        wl_registry_add_listener(m_registry, &registryListener, (void *)this);
        wl_display_roundtrip(m_display);
        wl_display_flush(m_display);

        m_source = g_source_new(&DisplayEventSourceFunctions, sizeof(DisplayEventSource));
        auto source = reinterpret_cast<DisplayEventSource*>(m_source);
        source->m_pfd.fd = wl_display_get_fd(m_display);
        source->m_pfd.events = G_IO_HUP | G_IO_ERR;
        source->m_pfd.revents = 0;
        source->m_browser = this;
        source->m_browser->AddRef();

        g_source_add_poll(m_source, &source->m_pfd);
        g_source_set_name(m_source, "rdkbrowser monitor thread");
        g_source_set_priority(m_source, G_PRIORITY_HIGH + 30);
        g_source_set_can_recurse(m_source, TRUE);
        g_source_attach(m_source, g_main_context_get_thread_default());
        mBrowserInitialized = true;
    }

    CookieJarUtils::initialize();
}

RDKBrowser::~RDKBrowser()
{
    cleanup();
}

bool RDKBrowser::isInitialized()
{
    return mBrowserInitialized;
}

rtError RDKBrowser::getURL(rtString& s) const
{
    s = m_url;
    return RT_OK;
}

rtError RDKBrowser::setURL(const rtString& url)
{
    RDKLOG_INFO("URL: %s", url.cString());
    m_url = url;

    if(!checkBrowser(__func__))
        return RT_FAIL;

    if (overridesEnabled())
    {
        loadOverrides(url.cString(), this);
        // URL overridden
        if (m_url != url)
            return RT_OK;
    }

    std::ofstream urlfile("/opt/logs/last_url.txt");
    if (urlfile.is_open())
    {
        rtString urlTruncated = url;
        if (urlTruncated.length() > 80)
        {
            urlTruncated = url.substring(0, 80);
        }

        //crashportal uses a second word as a url (parsing)
        urlfile << "#uri\n" << urlTruncated.cString();
        urlfile.close();
    }

    if(m_browser->LoadURL(url.cString()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    if (-1 == clock_gettime(CLOCK_MONOTONIC, &m_pageLoadStart))
    {
        RDKLOG_ERROR("clock_gettime failed with code %d", errno);
        m_pageLoadStart.tv_sec = 0;
    }

    return RT_OK;
}

rtError RDKBrowser::getWebFilters(rtObjectRef&) const
{
    // do nothing as currently it's not necessary
    return RT_OK;
}

rtError RDKBrowser::setWebFilters(const rtObjectRef& filters)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    uint32_t length;

    if (!filters || filters.get("length", length) != RT_OK)
        return RT_FAIL;

    RDKBrowserInterface::WebFilters webFilters;
    webFilters.reserve(length);

    for (uint32_t i = 0; i < length; ++i)
    {
        rtObjectRef filterObj;
        RETURN_IF_FAIL(filters.get(i, filterObj));
        rtString block;
        RETURN_IF_FAIL(filterObj.get("block", block));
        rtString scheme;
        rtString host;
        filterObj.get("scheme", scheme);
        filterObj.get("host", host);
        webFilters.emplace_back(RDKBrowserInterface::WebFilterPattern{scheme.cString(), host.cString(), block == "1"});
    }

    if (m_browser->setWebFilters(webFilters) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}


rtError RDKBrowser::getProxies(rtObjectRef& proxies) const
{
    // do nothing as currently it's not necessary
    (void)proxies;
    return RT_OK;
}

rtError RDKBrowser::setProxies(const rtObjectRef& proxies)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    uint32_t length;

    if (!proxies || proxies.get("length", length) != RT_OK)
        return RT_FAIL;

    RDKBrowserInterface::ProxyPatterns passProxies(length);

    for (uint32_t i = 0; i < length; ++i)
    {
        rtObjectRef proxyObj;
        RETURN_IF_FAIL(proxies.get(i, proxyObj));
        rtString pattern;
        rtString proxy;
        RETURN_IF_FAIL(proxyObj.get("pattern", pattern));
        RETURN_IF_FAIL(proxyObj.get("useproxy", proxy));
        passProxies[i] = std::make_pair(pattern.cString(), proxy.cString());
    }

    if (m_browser->setProxies(passProxies) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::getUserAgent(rtString& s) const
{
    s = m_userAgent;
    return RT_OK;
}

rtError RDKBrowser::setUserAgent(const rtString& userAgent)
{
    m_userAgent = userAgent;

    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setUserAgent(userAgent.cString()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::getTransparentBackground(rtValue& transparent) const
{
    (void)transparent;
    return RT_OK;
}

rtError RDKBrowser::setTransparentBackground(const rtValue& transparent)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setTransparentBackground(transparent.toBool()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::getVisible(rtValue& visible) const
{
    (void)visible;
    return RT_OK;
}

rtError RDKBrowser::setVisible(const rtValue& visible)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setVisible(visible.toBool()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::getLocalStorageEnabled(rtValue& result) const
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    bool enabled = false;

    if(m_browser->getLocalStorageEnabled(enabled) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    result = enabled;

    return RT_OK;
}

rtError RDKBrowser::setLocalStorageEnabled(const rtValue& enabled)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setLocalStorageEnabled(enabled.toBool()) != RDK::RDKBrowserSuccess)
    {
        RDKLOG_ERROR("Failed to set 'localStorageEnabled=%s'", enabled.toBool() ? "yes" : "no");
        return RT_FAIL;
    }

    RDKLOG_INFO("Successfully %s local storage", enabled.toBool() ? "enabled" : "disabled");
    return RT_OK;
}

rtError RDKBrowser::getConsoleLogEnabled(rtValue& result) const
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    bool enabled = false;

    if (m_browser->getConsoleLogEnabled(enabled) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    result = enabled;

    return RT_OK;
}

rtError RDKBrowser::setConsoleLogEnabled(const rtValue& enabled)
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    if (m_browser->setConsoleLogEnabled(enabled.toBool()) != RDK::RDKBrowserSuccess)
    {
        RDKLOG_ERROR("Failed to set 'consoleLogEnabled=%s'", enabled.toBool() ? "yes" : "no");
        return RT_FAIL;
    }

    RDKLOG_INFO("Successfully %s console log", enabled.toBool() ? "enabled" : "disabled");
    return RT_OK;
}


rtError RDKBrowser::setHTML(const rtString& html)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->SetHTML(html.cString()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::callJavaScriptWithResult(const rtString& javascript, const rtFunctionRef& func)
{
    return callJavaScript(javascript, func, NeedResult::Need);
}

rtError RDKBrowser::evaluateJavaScript(const rtString& javascript, const rtFunctionRef& func)
{
    return callJavaScript(javascript, func, NeedResult::DontNeed);
}

rtError RDKBrowser::setSpatialNavigation(const bool& on)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setSpatialNavigation(on) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::setWebSecurityEnabled(const rtValue& on)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setWebSecurityEnabled(on.toBool()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::getWebSecurityEnabled(rtValue& result) const
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    bool enabled = false;

    if(m_browser->getWebSecurityEnabled(enabled) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    result = enabled;

    return RT_OK;
}

rtError RDKBrowser::setAVEEnabled(const bool& on)
{
    RDKLOG_INFO("[%s]", on ? "true" : "false");
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setAVEEnabled(on) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::setAVESessionToken(const rtString& token)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setAVESessionToken(token.cString()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::setAVELogLevel(uint64_t level)
{
    RDKLOG_INFO("[%llu]", level);
    if (!checkBrowser(__func__))
        return RT_FAIL;

    if (m_browser->setAVELogLevel(level) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::scrollTo(const double& dx, const double& dy)
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    if (m_browser->scrollTo(dx, dy) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::scrollBy(const double& dx, const double& dy)
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    if (m_browser->scrollBy(dx, dy) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::reset()
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    m_eventEmitter.clear();
    m_uids.clear();
    m_userAgent = rtString();
    m_url = "about:blank";

    // Update display env var in case impl recycles the web process
    if (updateDisplayEnvVar() != RT_OK)
    {
        cleanup();
        return RT_FAIL;
    }

    if (m_browser->reset() != RDK::RDKBrowserSuccess)
    {
        cleanup();
        return RT_FAIL;
    }

    return RT_OK;
}

rtError RDKBrowser::toggleResourceUsageOverlay()
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->toggleResourceUsageOverlay() != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::deleteAllCookies()
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->deleteAllCookies() != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::clearWholeCache()
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->clearWholeCache() != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::restartRenderer()
{
    if (updateDisplayEnvVar() != RT_OK)
    {
        return RT_FAIL;
    }

    if (m_browser && m_browser->restartRenderer() == RDK::RDKBrowserSuccess)
    {
        return RT_OK;
    }

    if (m_browser)
    {
        m_browser->registerClient(nullptr);
        m_browser = nullptr;
    }

    m_browser.reset(RDK::RDKBrowserInterface::create(m_useSingleContext));

    if (!m_browser)
    {
        RDKLOG_ERROR("Failed to create browser instance");
        return RT_FAIL;
    }

    m_eventEmitter.clear();
    m_uids.clear();
    m_userAgent = rtString();
    m_url = "about:blank";
    m_browser->registerClient(this);

    return RT_OK;
}

rtError RDKBrowser::close()
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    cleanup();
    return RT_OK;
}

rtError RDKBrowser::gc()
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    return m_browser->collectGarbage() == RDK::RDKBrowserSuccess ? RT_OK : RT_FAIL;
}

rtError RDKBrowser::releaseMemory()
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    return m_browser->releaseMemory() == RDK::RDKBrowserSuccess ? RT_OK : RT_FAIL;
}

rtError RDKBrowser::setListener(rtString eventName, const rtFunctionRef& f)
{
    rtError rc = m_eventEmitter.setListener(eventName, f);

    if (rc == RT_OK && strcmp(eventName.cString(), "onError") == 0 && m_browser)
    {
        std::string crashedReason;
        if (m_browser->isCrashed(crashedReason))
        {
            onRenderProcessTerminated(crashedReason);
        }
    }

    return rc;
}

rtError RDKBrowser::delListener(rtString  eventName, const rtFunctionRef& f)
{
    return m_eventEmitter.delListener(eventName, f);
}

bool RDKBrowser::checkBrowser(const char* logPrefix) const
{
    if(!m_browser)
    {
        RDKLOG_ERROR("%s failed. Browser not created.", logPrefix);
        return false;
    }
    return true;
}

rtError RDKBrowser::callJavaScript(const rtString& javascript, const rtFunctionRef& func, NeedResult result)
{
    bool needsResult = result == NeedResult::Need;
    RDKLOG_VERBOSE("[%s] needResult: %s", javascript.cString(), needsResult ? "true" : "false");
    if(!checkBrowser(__func__))
        return RT_FAIL;

    std::string uuid_str(uuid_readable());

    m_uids[uuid_str] = func;

    if (RDK::RDKBrowserSuccess !=  m_browser->evaluateJavaScript(javascript.cString(), uuid_str, needsResult))
    {
        RDKLOG_ERROR("m_browser->evaluateJavaScript failed");
        return RT_FAIL;
    }

    return RT_OK;
}

void RDKBrowser::onLoadStarted()
{
    RDKLOG_INFO("");
}

void RDKBrowser::onLoadProgress(int progress)
{
    (void)progress;
}

void RDKBrowser::onLoadFinished(bool success, uint32_t httpStatusCode, const std::string& url)
{
    // There is no need to send documentLoaded event for about:blank page
    if (url.compare("about:blank") == 0)
        return;

    RDKLOG_INFO("[success: %s] %s statusCode = %d", success ? "true" : "false", url.c_str(), httpStatusCode);
    //Adding this fprintf for one Automation test case.
    fprintf(stderr, "success:%d url:%s\n", success, url.c_str());

    m_eventEmitter.send(OnHTMLDocumentLoadedEvent(success, httpStatusCode));

    //excludes internal url navigation, redirects etc
    if (m_pageLoadStart.tv_sec && success)
    {
        struct timespec pageLoadFinish;
        if (-1 == clock_gettime(CLOCK_MONOTONIC, &pageLoadFinish))
            RDKLOG_ERROR("clock_gettime failed with code %d", errno);
        else
        {
            long ms =
                1000.0 * (pageLoadFinish.tv_sec - m_pageLoadStart.tv_sec) +
                0.000001 * (pageLoadFinish.tv_nsec - m_pageLoadStart.tv_nsec) +
                0.5;
            RDKLOG_INFO("TELEMETRY_TIME2LOAD_URL_%s:%lu", m_url.cString(), ms);   //in ms
        }
        m_pageLoadStart.tv_sec = 0;
    }
}

void RDKBrowser::onUrlChanged(const std::string &url)
{
    RDKLOG_INFO("URL: %s", url.c_str());
    fprintf(stderr,"Url changed: %s\n", url.c_str());
    m_eventEmitter.send(OnHTMLLinkClickedEvent(url));
}

void RDKBrowser::onConsoleLog(const std::string& src, uint64_t line, const std::string& msg)
{
    RDKLOG_INFO("[%s:%llu]: %s", src.c_str(), line, msg.c_str());
    m_eventEmitter.send(OnConsoleLog("console [" + src + ":" + std::to_string(line) +"]: " + msg));
}

void RDKBrowser::onRenderProcessTerminated(const std::string& reason)
{
    const std::string& crashId = m_browser->getCrashId();

    RDKLOG_INFO("crash-id: [%s] url: [%s]", crashId.c_str(), m_url.cString());

    std::string description = reason;
    if (crashId.size())
    {
        description += " (crash-id: " + crashId + ")";
    }

    RDKLOG_INFO("description: [%s]", description.c_str());
    m_eventEmitter.send(OnError("RDKBROWSER_RENDER_PROCESS_CRASHED", description.c_str()));
}

void RDKBrowser::onCookiesChanged()
{
    m_eventEmitter.send(OnCookieJarChangedEvent());
}

rtError RDKBrowser::sendJavaScriptBridgeResponse(uint64_t callID, bool success, const rtString& message)
{
    RDKLOG_VERBOSE("callID: %llu, success: %d, message: '%s'", callID, success, message.cString());
    if (!checkBrowser(__func__))
        return RT_FAIL;

    if (RDKBrowserSuccess != m_browser->sendJavaScriptBridgeResponse(callID, success, message.cString()))
        return RT_FAIL;

    return RT_OK;
}

void RDKBrowser::onJavaScriptBridgeRequest(const char* name, uint64_t callID, const char* message)
{
    RDKLOG_VERBOSE("name: %s, callID: %llu, message: '%s'", name, callID, message);
    std::string event(name);
    if (event == "onJavaScriptBridgeRequest")
    {
        m_eventEmitter.send(OnJavaScriptBridgeRequestEvent(callID, message));
    }
    else if (event == "onJavaScriptServiceManagerRequest")
    {
        m_eventEmitter.send(OnJavaScriptServiceManagerRequestEvent(callID, message));
    }
    else
    {
        RDKLOG_ERROR("Wrong message name: %s", name);
    }
}

void RDKBrowser::onAVELog(const char* prefix, uint64_t level, const char* data)
{
    RDKLOG_VERBOSE("prefix: %s, level: %llu, data: '%s'", prefix, level, data);
    m_eventEmitter.send(OnAVELogEvent(prefix, level, data));
}

void RDKBrowser::onCallJavaScriptWithResult(int statusCode, const std::string& callId, const std::string& message, JSGlobalContextRef ctx, JSValueRef valueRef)
{
    RDKLOG_VERBOSE("statusCode: %d, message: '%s'", statusCode, message.c_str());
    rtObjectRef params = new rtMapObject;
    rtValue result;
    if (!JSUtils::toRTValue(ctx, valueRef, result))
    {
        RDKLOG_ERROR("Unable to convert value from JavaScript.");
        result.setEmpty();
    }
    params.set("result", result);
    sendJavaScriptResult(statusCode, callId, params, message);
}

void RDKBrowser::onEvaluateJavaScript(int statusCode, const std::string& callGUID, const std::string& message, bool success)
{
    RDKLOG_VERBOSE("success: %s, statusCode: %d, message: '%s'", success ? "true" : "false", statusCode, message.c_str());
    rtObjectRef params = new rtMapObject;
    params.set("success", success);
    sendJavaScriptResult(statusCode, callGUID, params, message);
}

void RDKBrowser::onReportLaunchMetrics(const std::map<std::string, std::string>& metrics)
{
    m_eventEmitter.send(OnLaunchMetrics(metrics));
}

void RDKBrowser::sendJavaScriptResult(int statusCode, const std::string& callId, rtObjectRef params, const std::string& message)
{
    rtObjectRef p = new rtMapObject;
    p.set("statusCode", statusCode);
    p.set("params", params);
    p.set("message", message.c_str());

    if (m_uids.find(callId) == m_uids.end())
    {
        RDKLOG_ERROR("Can't find related callUUID %s.", callId.c_str());
        for(auto pair : m_uids)
        {
            RDKLOG_INFO("UUID: %s", pair.first.c_str());
        }
        return;
    }

    rtFunctionRef func = m_uids[callId];
    m_uids.erase(callId);

    if (func)
        func.send(p);
}

rtError RDKBrowser::setCookieJar(const rtObjectRef& cookieJar)
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    using namespace CookieJarUtils;
    rtValue rtVersion;
    cookieJar.get(kFieldVersion, rtVersion);

    RDKLOG_INFO("Got cookiejar version %d", rtVersion.toUInt32());

    rtValue rtChecksum;
    cookieJar.get(kFieldChecksum, rtChecksum);
    int expectedChecksum = rtChecksum.toInt32();

    rtValue rtCookies;
    cookieJar.get(kFieldCookies, rtCookies);

    std::string serialized = uncompress(decrypt(fromBase64(rtCookies.toString().cString()), rtVersion.toUInt32()));

    int actualChecksum = checksum(serialized);
    if (actualChecksum != expectedChecksum)
    {
        RDKLOG_ERROR("Checksum does not match: actual=%d expected=%d", actualChecksum, expectedChecksum);
        return RT_FAIL;
    }

    std::vector<std::string> cookies;
    unserialize<kDefaultCookieJarVersion>(serialized, cookies);
    RDKLOG_INFO("Found %d cookies.", cookies.size());

    if (m_browser->setCookieJar(cookies) != RDK::RDKBrowserSuccess)
    {
        RDKLOG_ERROR("Could not set cookie jar to browser");
        return RT_FAIL;
    }

    return RT_OK;
}

rtError RDKBrowser::getCookieJar(rtObjectRef& result) const
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    std::vector<std::string> cookies;
    if (m_browser->getCookieJar(cookies) != RDK::RDKBrowserSuccess)
    {
        RDKLOG_ERROR("Could not get cookie jar from browser");
        return RT_FAIL;
    }

    RDKLOG_INFO("Found %d cookies.", cookies.size());

    using namespace CookieJarUtils;
    std::string serialized = serialize<kDefaultCookieJarVersion>(cookies);

    unsigned int version = kDefaultCookieJarVersion;
    std::string encrypted;

    std::tie(encrypted, version) = encrypt(compress(serialized));

    result = new rtMapObject;

    result.set(kFieldChecksum, checksum(serialized));
    result.set(kFieldCookies, rtString(toBase64(encrypted).c_str()));
    result.set(kFieldVersion, version);

    return RT_OK;
}

void RDKBrowser::onWaylandConnectionClosed()
{
    cleanup();
}

void RDKBrowser::cleanup()
{
    if(m_source)
    {
        g_source_destroy(m_source);
        g_source_unref(m_source);
        m_source = nullptr;
    }

    if(m_compositor)
    {
        wl_compositor_destroy(m_compositor);
        m_compositor = nullptr;
    }

    if(m_registry)
    {
        wl_registry_destroy(m_registry);
        m_registry = nullptr;
    }

    if (m_display)
    {
        wl_display_disconnect(m_display);
        m_display = nullptr;
    }

    if(m_browser)
    {
        m_browser->registerClient(nullptr);
        m_browser = nullptr;
    }
}

rtError RDKBrowser::getHeaders(rtObjectRef&) const
{
    return RT_OK;
}

rtError RDKBrowser::setHeaders(const rtObjectRef& obj)
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    rtObjectRef allKeys;
    RETURN_IF_FAIL(obj.get("allKeys", allKeys));

    uint32_t length;
    RETURN_IF_FAIL(allKeys.get("length", length));

    RDKBrowserInterface::Headers headers(length);
    for (uint32_t i = 0; i < length; ++i)
    {
        rtString key;
        rtString value;
        RETURN_IF_FAIL(allKeys.get(i, key));
        RETURN_IF_FAIL(obj.get(key.cString(), value));
        RDKLOG_INFO("Set header: %s:%s", key.cString(), value.cString());
        headers[i] = std::make_pair(key.cString(), value.cString());
    }

    if (m_browser->setHeaders(headers) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::setVoiceGuidanceEnabled(const rtString& enabled)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setVoiceGuidanceEnabled(enabled=="true") != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::getVoiceGuidanceEnabled(rtString&) const
{
    return RT_OK;
}

rtError RDKBrowser::setSpeechRate(const rtValue& rate)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setSpeechRate(rate.toUInt8()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::getSpeechRate(rtValue&) const
{
    return RT_OK;
}

rtError RDKBrowser::setVoiceGuidanceLanguage(const rtString& language)
{
    return setLanguage(language);
}

rtError RDKBrowser::getVoiceGuidanceLanguage(rtString&) const
{
    return RT_OK;
}

rtError RDKBrowser::setLanguage(const rtString& language)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setLanguage(language.cString()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::getLanguage(rtString&) const
{
    return RT_OK;
}

rtError RDKBrowser::setTTSEndPoint(const rtString& url)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setTTSEndPoint(url.cString()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::getTTSEndPoint(rtString&) const
{
    return RT_OK;
}

rtError RDKBrowser::setTTSEndPointSecured(const rtString& url)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setTTSEndPointSecured(url.cString()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::getTTSEndPointSecured(rtString&) const
{
    return RT_OK;
}

rtError RDKBrowser::setVoiceGuidanceMode(const rtString& mode)
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    if(m_browser->setVoiceGuidanceMode(mode.cString()) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    return RT_OK;
}

rtError RDKBrowser::getVoiceGuidanceMode(rtString&) const
{
    return RT_OK;
}

rtError RDKBrowser::getMemoryUsage(rtValue& result) const
{
    if(!checkBrowser(__func__))
        return RT_FAIL;

    uint32_t inBytes;
    if(m_browser->getMemoryUsage(inBytes) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    result = inBytes;
    return RT_OK;
}

rtError RDKBrowser::updateDisplayEnvVar()
{
    int rv = setenv("WAYLAND_DISPLAY", m_displayName.cString(), 1);
    if (rv != 0)
    {
        RDKLOG_ERROR("Failed to set 'WAYLAND_DISPLAY', errno=%d, display='%s'", errno, m_displayName.cString());
        return RT_FAIL;
    }
    return RT_OK;
}

rtError RDKBrowser::getNonCompositedWebGLEnabled(rtValue& result) const
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    bool enabled = false;

    if (m_browser->getNonCompositedWebGLEnabled(enabled) != RDK::RDKBrowserSuccess)
        return RT_FAIL;

    result = enabled;

    return RT_OK;
}

rtError RDKBrowser::setNonCompositedWebGLEnabled(const rtValue& enabled)
{
    if (!checkBrowser(__func__))
        return RT_FAIL;

    // Update display env var in case impl recycles the web process
    if (updateDisplayEnvVar() != RT_OK)
        return RT_FAIL;

    if (m_browser->setNonCompositedWebGLEnabled(enabled.toBool()) != RDK::RDKBrowserSuccess)
    {
        RDKLOG_ERROR("Failed to set 'nonCompositedWebGLEnabled=%s'", enabled.toBool() ? "yes" : "no");
        return RT_FAIL;
    }

    RDKLOG_INFO("Successfully %s non composited WebGL", enabled.toBool() ? "enabled" : "disabled");
    return RT_OK;
}

}
