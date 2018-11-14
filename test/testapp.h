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
#ifndef RDKBROWSER_TEST_APP_H
#define RDKBROWSER_TEST_APP_H

#include "testitem.h"
#include "testconf.h"

#include <pxWayland.h>
#include <glib.h>

#include <memory>
#include <mutex>

namespace RDKTest
{

class App : public pxWaylandEvents
{
public:
    static App app;

    App();
    ~App();

    void loadConf(const std::string& filename);
    const Conf& conf() const { return m_conf; }

    void add(Item* item);
    void run();

    void start(bool exec = false);
    void test(const rtObjectRef& event, bool exec = false);
    void skip(bool exec = false);
    void stop(bool exec = false);

    rtError setProperty(rtString name, rtValue value);
    rtError getProperty(rtString name, rtValue& value);
    rtError callMethod(const char* method, int numArgs, const rtValue* args);
    void handleAppEvent(const rtObjectRef& event);

protected:
    class EventCallback : public rtFunctionCallback
    {
    public:
        EventCallback(const rtString& eventName);
        rtError initialize(rtObjectRef remoteObject);
        rtString getEventName() const { return mEventName; }

    protected:
        static rtError onEvent(int numArgs, const rtValue* args, rtValue* result, void* context);

    private:
        rtString mEventName;
    };

    rtError subscribeTo(const rtString& appEventName);
    void init(bool exec = false);
    void next(bool exec = false);

    // pxWaylandEvents
    //virtual void invalidate(pxRect* /*r*/) override;
    //virtual void hidePointer(bool /*hide*/) override {}
    virtual void clientStarted(int /*pid*/) override;
    virtual void clientConnected(int /*pid*/) override;
    virtual void clientDisconnected(int /*pid*/) override;
    virtual void clientStoppedNormal(int /*pid*/, int /*exitCode*/) override;
    virtual void clientStoppedAbnormal(int /*pid*/, int /*signo*/) override;
    virtual void isRemoteReady(bool ready) override;
    //virtual void isReady(bool /*ready*/) override {}

private:
    typedef std::shared_ptr<Item> ItemPtr;
    typedef rtRefT<EventCallback> EventCallbackRef;

    GMainLoop* m_loop;
    pxWaylandRef m_wayland { new pxWayland };
    rtObjectRef m_remoteObject;
    std::vector<ItemPtr> m_items;
    size_t m_currentLoop { 0 };
    size_t m_currentItem { 0 };
    size_t m_maximumLoop { 1 };
    std::list<EventCallbackRef> m_callbacks;
    bool m_remoteEnabled { false };
    int m_clientPid { 0 };

    Conf m_conf;
};

} // namespace RDKTest

#endif // RDKBROWSER_TEST_APP_H
