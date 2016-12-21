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
#ifndef RDKBROWSER_UTIL_H
#define RDKBROWSER_UTIL_H

#include <JavaScriptCore/JSContextRef.h>
#include <JavaScriptCore/JSValueRef.h>

class rtValue;

namespace JSUtils
{

/* toRTValue is called from rdkbrowser level, which has access to rtRemote, but does
 * not have access to JSValueRef internals.
 * This is an abstraction that lets to convert JSValueRef to RTRemote's rtValue type.
  */
bool toRTValue(JSGlobalContextRef ctx, JSValueRef valueRef, rtValue& result);

} // namespace RDKUtils

#endif // RDKBROWSER_UTIL_H
