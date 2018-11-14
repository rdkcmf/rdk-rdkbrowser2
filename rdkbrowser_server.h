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
#ifndef RDKBROWSER_SERVER_H
#define RDKBROWSER_SERVER_H

#include <rtObject.h>

#define RDK_BROWSER_SERVER_OBJECT_NAME "wl-rdkbrowser2-server"

namespace RDK
{

class RDKBrowserServer : public rtObject
{
public:
    rtDeclareObject(RDKBrowserServer, rtObject);
    rtReadOnlyProperty(pid, pid, uint32_t);
    rtMethod2ArgAndReturn("createWindow", createWindow, rtString, bool, rtObjectRef);

    rtError pid(uint32_t &pid) const;
    rtError createWindow(const rtString& displayName, bool useSingleContext /*= false*/, rtObjectRef &out);
};

}  // namespace RDK

#endif  // RDKBROWSER_SERVER_H
