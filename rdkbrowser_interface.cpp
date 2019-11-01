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
#include "rdkbrowser_interface.h"

#ifdef BROWSER_BACKEND_WPE
#include "wpe_browser.h"
#endif

namespace RDK
{

RDKBrowserInterface* RDKBrowserInterface::create(bool useSingleContext, bool nonCompositedWebGLEnabled)
{
#ifdef BROWSER_BACKEND_WPE
    WPEBrowser *browser = new WPEBrowser();
    if (RDK::RDKBrowserSuccess == browser->Initialize(useSingleContext, nonCompositedWebGLEnabled))
        return browser;
    delete browser;
#endif

    /* To add more browser backend add code here */
    return nullptr;
}

}
