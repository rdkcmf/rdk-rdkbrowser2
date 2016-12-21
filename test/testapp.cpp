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
#include "testapp.h"
#include "testconv.h"
#include "testlog.h"

#include <stdio.h>

pxContext context;

int pxMain(int, char*[])
{
    RBTLOGD("pxMain - enter");
    return 0;
}

namespace RDKTest
{

App App::app;

App::App()
{
    RBTLOGD("App constructor - enter");
    m_loop = g_main_loop_new(g_main_context_default(), FALSE);

    setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    m_wayland->AddRef();
    m_wayland->setEvents(this);
    m_wayland->setCmd("/usr/bin/rdkbrowser2");
    m_wayland->onSize(800, 400);
    m_wayland->onInit();

    RBTLOGD("App constructor - exit");
}

App::~App()
{
    RBTLOGD("App destructor - enter");
    m_wayland->setEvents(nullptr);
    m_wayland->Release();
    g_main_loop_unref(m_loop);
    RBTLOGD("App destructor - exit");
}

void App::loadConf(const std::string& filename)
{
    m_conf.load(filename);
    m_maximumLoop = conf().maximumLoop();
}

void App::add(Item* item)
{
    if (conf().use(item->id()))
        m_items.push_back(std::shared_ptr<Item>(item));
    else
        delete item;
}

void App::run()
{
    RBTLOGD("App::run - enter");
    g_main_loop_run(m_loop);
    RBTLOGD("App::run - exit");
}

void App::start(bool exec)
{
    if (exec && g_main_context_is_owner(g_main_context_default()))
    {
        RBTLOGD("App::start - enter");
        if (m_items.empty())
        {
            RBTLOGW("App::start - WARN: no items");
            stop();
        }
        else if
        (
            (RT_OK != subscribeTo("onHTMLLinkClicked")) ||
            (RT_OK != subscribeTo("onHTMLDocumentLoaded")) ||
            (RT_OK != subscribeTo("onCookieJarChanged"))
        )
        {
            RBTLOGF("App::start - ERROR: subscribe to event failed");
            stop();
        }
        else
        {
            m_currentLoop = 0;
            m_currentItem = 0;
            init();
        }
        RBTLOGD("App::start - exit");
    }
    else
    {
        g_idle_add_full(G_PRIORITY_DEFAULT, [](gpointer) -> gboolean
        {
            App::app.start(true);
            return G_SOURCE_REMOVE;
        }, nullptr, nullptr);
    }
}

void App::test(const rtObjectRef& event, bool exec)
{
    if (exec && g_main_context_is_owner(g_main_context_default()))
    {
        //RBTLOGD("App::test - enter");
        RBTLOGD("App::test:\"%s\" - test the current item", m_items[m_currentItem]->id());
        Item::TestResult result = m_items[m_currentItem]->test(event);
        switch (result)
        {
            case Item::TestResult::DONE:
                RBTLOGD("App::test:\"%s\" - DONE: init the next item", m_items[m_currentItem]->id());
                next();
                break;
            case Item::TestResult::WAIT:
                RBTLOGD("App::test:\"%s\" - WAIT: do nothing", m_items[m_currentItem]->id());
                break;
            case Item::TestResult::FAIL:
                RBTLOGF("App::test:\"%s\" - FAIL: terminate the main loop", m_items[m_currentItem]->id());
                stop();
                break;
        }
        //RBTLOGD("App::test - exit");
    }
    else
    {
        g_idle_add_full(G_PRIORITY_DEFAULT, [](gpointer data) -> gboolean
        {
            //RBTLOGD("App::test - callback enter");
            rtObjectRef* event = (rtObjectRef*)data;
            App::app.test(*event, true);
            delete event;
            //RBTLOGD("App::test - callback exit");
            return G_SOURCE_REMOVE;
        }, new rtObjectRef(event), nullptr);
    }
}

void App::skip(bool exec)
{
    if (exec && g_main_context_is_owner(g_main_context_default()))
    {
        //RBTLOGD("App::skip - enter");
        RBTLOGD("App::skip:\"%s\" - skip the current item", m_items[m_currentItem]->id());
        next();
        //RBTLOGD("App::skip - exit");
    }
    else
    {
        g_idle_add_full(G_PRIORITY_DEFAULT, [](gpointer) -> gboolean
        {
            App::app.skip(true);
            return G_SOURCE_REMOVE;
        }, nullptr, nullptr);
    }
}

void App::stop(bool exec)
{
    if (exec && g_main_context_is_owner(g_main_context_default()))
    {
        RBTLOGD("App::stop - enter");
        g_main_loop_quit(m_loop);
        m_callbacks.clear();
        m_wayland->setEvents(nullptr);
        RBTLOGD("App::stop - exit");
    }
    else
    {
        g_idle_add_full(G_PRIORITY_HIGH, [](gpointer) -> gboolean
        {
            App::app.stop(true);
            return G_SOURCE_REMOVE;
        }, nullptr, nullptr);
    }
}

void App::init(bool exec)
{
    if (exec && g_main_context_is_owner(g_main_context_default()))
    {
        //RBTLOGD("App::init - enter");
        RBTLOGD("App::init:\"%s\" - init the item (%u.%u)", m_items[m_currentItem]->id(), m_currentLoop, m_currentItem);
        if (!m_items[m_currentItem]->init())
        {
            RBTLOGF("App::init:\"%s\" - ERROR: init item (%u/%u) failed", m_items[m_currentItem]->id(), m_currentLoop, m_currentItem);
            stop();
        }
        //RBTLOGD("App::init - exit");
    }
    else
    {
        static guint interval = 5;
        g_timeout_add_seconds(1, [](gpointer data) -> gboolean
        {
            RBTLOGD("----------------------------------------");
            RBTLOGD("Wait for %u seconds...", *(guint*)data);
            RBTLOGD("----------------------------------------");
            return G_SOURCE_REMOVE;
        }, &interval);
        g_timeout_add_seconds(interval, [](gpointer) -> gboolean
        {
            App::app.init(true);
            return G_SOURCE_REMOVE;
        }, nullptr);
    }
}

void App::next(bool exec)
{
    if (exec && g_main_context_is_owner(g_main_context_default()))
    {
        ++m_currentItem;
        if (m_currentItem >= m_items.size())
        {
            m_currentItem = 0;
            ++m_currentLoop;
            if (m_currentLoop == m_maximumLoop)
            {
                RBTLOGD("----------------------------------------");
                RBTLOGD("App::next - ALL DONE");
                stop();
                return;
            }
        }
        init();
    }
    else
    {
        g_idle_add_full(G_PRIORITY_DEFAULT, [](gpointer) -> gboolean
        {
            App::app.next(true);
            return G_SOURCE_REMOVE;
        }, nullptr, nullptr);
    }
}

void App::clientStarted(int pid)
{
    RBTLOGD("App::clientStarted - [pid: %d]", pid);
    m_clientPid = pid;
}

void App::clientConnected(int pid)
{
    RBTLOGD("App::clientConnected - [pid: %d]", pid);
}

void App::clientDisconnected(int pid)
{
    RBTLOGD("App::clientDisconnected - [pid: %d]", pid);

    if (m_clientPid == pid)
    {
        //TODO: handle wayland connection break, when client still alive
    }
}

void App::clientStoppedNormal(int pid, int exitCode)
{
    RBTLOGD("App::clientStoppedNormal - [pid: %d, exitCode: %d]", pid, exitCode);
    // validate if pid matches to m_clientPid before taking necessary action
    if (m_clientPid == pid)
        m_clientPid = 0;
    stop();
}

void App::clientStoppedAbnormal( int pid, int signo )
{
    RBTLOGD("App::clientStoppedAbnormal - [pid: %d, signo: %d]", pid, signo);
    // validate if pid matches to m_clientPid before taking necessary action
    if (m_clientPid == pid)
        m_clientPid = 0;
    stop();
}

void App::isRemoteReady(bool ready)
{
    RBTLOGD("App::isRemoteReady - enter [ready: %s]", ready ? "true" : "false");
    m_remoteEnabled = ready;

    if (ready)
    {
        // get remote object before processing
        rtValue tmpVal;
        rtError rc = m_wayland->api(tmpVal);
        if (RT_OK == rc)
        {
            m_remoteObject = tmpVal.toObject();
            start();
        }
    }
    else
        stop();

    RBTLOGD("App::isRemoteReady - exit");
}

rtError App::subscribeTo(const rtString& appEventName)
{
    RBTLOGD("App::subscribeTo - enter [%s]", appEventName.cString());
    for (auto i = m_callbacks.begin(); i != m_callbacks.end(); ++i)
    {
        if ((*i)->getEventName() == appEventName)
        {
            RBTLOGW("App::subscribeTo - WARN: Already subscribed to '%s', ignore.", appEventName.cString());
            return RT_OK;
        }
    }

    EventCallbackRef eventCallback = new EventCallback(appEventName);
    rtError rc = eventCallback->initialize(m_remoteObject);
    if (RT_OK != rc)
    {
        RBTLOGF("App::subscribeTo - subscribe to '%s' failed: %d", appEventName.cString(), rc);
        return rc;
    }

    m_callbacks.push_back(eventCallback);

    RBTLOGD("App::subscribeTo - exit");
    return RT_OK;
}

void App::handleAppEvent(const rtObjectRef& event)
{
    RBTLOGD("App::handleAppEvent - enter [%s]", toJSON(event).c_str());

    if (!m_remoteEnabled)
    {
        RBTLOGW("App::handleAppEvent - WARN: no remote connection established");
        return;
    }

    app.test(event);

    RBTLOGD("App::handleAppEvent - exit");
}

rtError App::setProperty(rtString name, rtValue value)
{
    RBTLOGD("App::setProperty - enter [\"%s\": %s]", name.cString(), toJSON(value).c_str());
    if (!m_remoteEnabled)
    {
        RBTLOGF("App::setProperty - ERROR: no remote connection established");
        return RT_OBJECT_NOT_INITIALIZED;
    }
    rtError rc = m_remoteObject.set(name, value);
    RBTLOGD("App::setProperty - exit [%d]", rc);
    return rc;
}

rtError App::getProperty(rtString name, rtValue& value)
{
    RBTLOGD("App::getProperty - enter [\"%s\"]", name.cString());
    if (!m_remoteEnabled)
    {
        RBTLOGF("App::getProperty - ERROR: no remote connection established");
        return RT_OBJECT_NOT_INITIALIZED;
    }
    rtError rc = m_remoteObject.get(name, value);
    if (rc != RT_OK)
        RBTLOGF("App::getProperty - ERROR: get() has returned %d", rc);
    else
        RBTLOGD("App::getProperty - exit ['%c': %s]", value.getType(), toJSON(value).c_str());
    return rc;
}

rtError App::callMethod(const char* method, int numArgs, const rtValue* args)
{
    RBTLOGD("App::callMethod - enter [\"%s\"]", method);
    //std::lock_guard<std::recursive_mutex> guard(*mStateMutex.get());
    if (!m_remoteEnabled)
    {
        RBTLOGF("App::callMethod - ERROR: no remote connection established");
        return RT_OBJECT_NOT_INITIALIZED;
    }
    //rtError rc = m_wayland->callMethod(method, numArgs, args);
    rtError rc = m_remoteObject.Send(method, numArgs, args);
    RBTLOGD("App::callMethod - exit [%d]", rc);
    return rc;
}

// Class App::EventCallback implementation

App::EventCallback::EventCallback(const rtString& eventName)
    : rtFunctionCallback(onEvent, this)
    , mEventName(eventName)
{
}

rtError App::EventCallback::initialize(rtObjectRef remoteObject)
{
    return remoteObject.send("on", mEventName, this);
}

rtError App::EventCallback::onEvent(int numArgs, const rtValue* args, rtValue* result, void* context)
{
    rtError rc = RT_FAIL;
    if (context && (numArgs == 1) && (RT_objectType == args[0].getType()))
    {
        App::app.handleAppEvent(args[0].toObject());
        rc = RT_OK;
    }
    if (result)
        *result = rtValue(RT_OK == rc);
    return rc;
}

} // namespace RDKTest
