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
#include "rdkbrowser_server.h"
#include "rdkbrowser.h"
#include "logger.h"

#include <unistd.h>

namespace RDK
{

rtDefineObject(RDKBrowserServer, rtObject);
rtDefineMethod(RDKBrowserServer, createWindow);
rtDefineProperty(RDKBrowserServer, pid);

rtError RDKBrowserServer::pid(uint32_t &pid) const
{
    pid = getpid();
    return RT_OK;
}

rtError RDKBrowserServer::createWindow(const rtString& displayName, rtObjectRef &out)
{
    RDKLOG_INFO("Got request for new RDKBrowser for display='%s'", displayName.cString());

    int rv = setenv("WAYLAND_DISPLAY", displayName.cString(), 1);
    if (rv != 0) {
        RDKLOG_ERROR("Failed to set 'WAYLAND_DISPLAY', errno=%d, display='%s'", errno, displayName.cString());
        return RT_FAIL;
    }

    RDKBrowser* browser = new RDKBrowser(displayName);
    if(nullptr == browser) {
        RDKLOG_ERROR("Failed to create new RDKBrowser");
        return RT_FAIL;
    }

    out = browser;

    RDKLOG_INFO("Successfully created new RDKBrowser for target display='%s', current display='%s'",
                displayName.cString(), getenv("WAYLAND_DISPLAY"));

    return RT_OK;
}

}  // namespace RDK
