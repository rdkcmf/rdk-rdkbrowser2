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
#include "js_utils.h"

#include <rtObject.h>

#include <JavaScriptCore/JSRetainPtr.h>
#include <JavaScriptCore/JSObjectRef.h>

#include <stddef.h>
#include <glib.h>
#include <memory>

using namespace JSUtils;

namespace
{

std::string toStdString(const JSStringRef& stringRef)
{
    size_t bufferSize = JSStringGetMaximumUTF8CStringSize(stringRef);
    auto buffer = std::vector<char>(bufferSize);
    JSStringGetUTF8CString(stringRef, buffer.data(), bufferSize);
    return std::string(buffer.data());
}

void convertValue(JSGlobalContextRef, JSValueRef, rtValue&, JSValueRef&);

void convertArray(JSGlobalContextRef ctx, JSValueRef valueRef, rtValue &result, JSValueRef &exc)
{
    if (exc)
        return;

    std::unique_ptr<rtArrayObject> array(new rtArrayObject);
    JSObjectRef objectRef = JSValueToObject(ctx, valueRef, &exc);
    if (exc)
        return;

    JSPropertyNameArrayRef namesRef = JSObjectCopyPropertyNames(ctx, objectRef);
    size_t size = JSPropertyNameArrayGetCount(namesRef);

    for (size_t i = 0; i < size; ++i)
    {
        JSValueRef valueRef = JSObjectGetPropertyAtIndex(ctx, objectRef, i, &exc);
        if (exc)
            break;

        rtValue converted;
        convertValue(ctx, valueRef, converted, exc);
        if (exc)
            break;

        array->pushBack(converted);
    }
    JSPropertyNameArrayRelease(namesRef);

    if (!exc)
        result.setObject(array.release());
}

void convertObject(JSGlobalContextRef ctx, JSValueRef valueRef, rtValue &result, JSValueRef &exc)
{
    if (exc)
        return;

    rtObjectRef object = new rtMapObject;
    JSObjectRef objectRef = JSValueToObject(ctx, valueRef, &exc);
    if (exc)
        return;

    JSPropertyNameArrayRef namesRef = JSObjectCopyPropertyNames(ctx, objectRef);
    size_t size = JSPropertyNameArrayGetCount(namesRef);
    for (size_t i = 0; i < size; ++i)
    {
        JSStringRef namePtr = JSPropertyNameArrayGetNameAtIndex(namesRef, i);
        JSValueRef valueRef = JSObjectGetProperty(ctx, objectRef, namePtr, &exc);
        if (exc)
            break;

        std::string name = toStdString(namePtr);
        rtValue converted;
        convertValue(ctx, valueRef, converted, exc);
        if (exc)
            break;

        object.set(name.c_str(), converted);
    }
    JSPropertyNameArrayRelease(namesRef);
    if (!exc)
        result.setObject(object);
}

void convertValue(JSGlobalContextRef ctx, JSValueRef valueRef, rtValue &result, JSValueRef &exc)
{
    JSType type = JSValueGetType(ctx, valueRef);
    switch (type)
    {
        case kJSTypeUndefined:
            // FALL THROUGH
        case kJSTypeNull:
            result.setEmpty();
            break;
        case kJSTypeBoolean:
            result.setBool(JSValueToBoolean(ctx, valueRef));
            break;
        case kJSTypeNumber:
            result.setDouble(JSValueToNumber(ctx, valueRef, &exc));
            break;
        case kJSTypeString:
        {
            JSRetainPtr<JSStringRef> jsString = adopt(JSValueToStringCopy(ctx, valueRef, &exc));
            result.setString(toStdString(jsString.get()).c_str());
            break;
        }
        case kJSTypeObject:
            if (JSValueIsDate(ctx, valueRef))
                result.setEmpty();
            else if (JSValueIsArray(ctx, valueRef))
                convertArray(ctx, valueRef, result, exc);
            else
                convertObject(ctx, valueRef, result, exc);
            break;
        default:
            JSRetainPtr<JSStringRef> str = adopt(JSStringCreateWithUTF8CString("Unknown value type!"));
            exc = JSValueMakeString(ctx, str.get());
    }
}

}

namespace JSUtils
{

bool toRTValue(JSGlobalContextRef ctx, JSValueRef valueRef, rtValue& result)
{
    if (valueRef == nullptr || ctx == nullptr)
        return false;

    JSValueRef exc = nullptr;

    convertValue(ctx, valueRef, result, exc);

    if (exc)
    {
        // TODO: print exception content
    }

    return !exc;
}

} // namespace JSUtils
