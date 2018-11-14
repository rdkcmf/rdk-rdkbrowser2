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
#include "testconv.h"
//#include "testlog.h"
#include "../cookiejar_utils.h"

#include <glib.h>

#include <cassert>

namespace RDKTest
{

std::string toJSON(const rtString& string)
{
    std::string result = "\"";
    std::string source = string.cString();
    size_t size = source.size();
    size_t offset = 0;
    while (offset < size)
    {
        size_t pos = source.find('"', offset);
        if (string::npos == pos)
        {
            result += source.substr(offset);
            break;
        }
        if (pos > offset)
            result += source.substr(offset, pos - offset);
        result += "\\\"";
        offset = pos + 1;
    }
    result += "\"";
    return result;
}

std::string toJSON(const rtObjectRef& object)
{
    //RBTLOGD("toJSON(rtObjectRef) - enter");
    std::string result;
    if (object)
    {
        //rtValue vAllKeys;
        //if ((RT_OK == object->Get("allKeys", &vAllKeys)) && (RT_objectType == vAllKeys.getType()))
        rtObjectRef allKeys;
        uint32_t length;
        if (RT_OK == object.get("allKeys", allKeys))
        {
            //RBTLOGD("toJSON(rtObjectRef) - object is a map");
            result = "{";
            uint32_t length = allKeys.get<uint32_t>("length");
            //RBTLOGD("toJSON(rtObjectRef) - object length is %u", length);
            for (uint32_t i = 0; i < length; ++i)
            {
                rtString key;
                rtError rc1 = allKeys.get(i, key);
                //RBTLOGD("toJSON(rtObjectRef) - %d, key[%u]: \"%s\"", rc1, i, key.cString());
                assert(RT_OK == rc1);

                rtValue value;
                rtError rc2 = object->Get(key.cString(), &value);
                //RBTLOGD("toJSON(rtObjectRef) - %d, value[%u] is of type '%c'", rc2, i, value.getType());
                assert(RT_OK == rc2);

                if (i)
                    result += ",";
                result += std::string("\"") + key.cString() + "\":" + toJSON(value);
            }
            result += "}";
        }
        else if (RT_OK == object.get("length", length))
        {
            //RBTLOGD("toJSON(rtObjectRef) - object is an array");
            result = "[";
            for (uint32_t i = 0; i < length; ++i)
            {
                rtValue value;
                assert(RT_OK == object.get(i, value));
                if (i)
                    result += ",";
                result += toJSON(value);
            }
            result += "]";
        }
    }
    //RBTLOGD("toJSON(rtObjectRef) - exit [%s]", result.data());
    return result;
}

// Convert numbers : "0.000000" => "0"
static std::string formatNumber(std::string source)
{
    if (!source.empty())
    {
        size_t pos = source.find('.');
        if (pos != std::string::npos)
        {
            while (!source.empty())
            {
                char last = *source.rbegin();
                if ((last != '0') && (last != '.'))
                    break;
                source.resize(source.size() - 1);
                if (last == '.')
                    break;
            }
        }
    }
    return source;
}

std::string toJSON(const rtValue& value)
{
    std::string result;
    switch (value.getType())
    {
        case RT_voidType:
            result = "undefined";
            break;
        case RT_boolType:
            result = value.toBool() ? "true" : "false";
            break;
        case RT_int8_tType:
            result = formatNumber(std::to_string(value.toInt8()));
            break;
        case RT_uint8_tType:
            result = formatNumber(std::to_string(value.toUInt8()));
            break;
        case RT_int32_tType:
            result = formatNumber(std::to_string(value.toInt32()));
            break;
        case RT_uint32_tType:
            result = formatNumber(std::to_string(value.toUInt32()));
            break;
        case RT_int64_tType:
            result = formatNumber(std::to_string(value.toInt64()));
            break;
        case RT_uint64_tType:
            result = formatNumber(std::to_string(value.toUInt64()));
            break;
        case RT_floatType:
            result = formatNumber(std::to_string(value.toFloat()));
            break;
        case RT_doubleType:
            result = formatNumber(std::to_string(value.toDouble()));
            break;
        case RT_stringType:
            result = toJSON(value.toString());
            break;
        case RT_objectType:
            result = toJSON(value.toObject());
            break;
        case RT_functionType:
            result = "function(){}";
            break;
        case RT_voidPtrType:
            result = "null";
            break;
    }
    return result.data();
}

std::string addQuotes(const std::string& text)
{
    return toJSON(rtString(text.c_str()));
}

using namespace CookieJarUtils;

uint32_t cookieVersion()
{
    return kDefaultCookieJarVersion;
}

int cookieChecksum(const std::string& str)
{
    return checksum(str);
}

std::string cookieEncode(const std::string& cookies)
{
    return toBase64(encrypt(compress(cookies)));
}

std::string cookieEncode(const std::vector<std::string>& cookies)
{
    return cookieEncode(serialize<kDefaultCookieJarVersion>(cookies));
}

std::string cookieDecode(const std::string& text)
{
    return uncompress(decrypt(fromBase64(text)));
}

void cookieDecode(const std::string& text, std::vector<std::string>& cookies)
{
    unserialize<kDefaultCookieJarVersion>(cookieDecode(text), cookies);
}

} // namespace RDKTest
