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
#include "testitem.h"
#include "testapp.h"
#include "testconv.h"
#include "testlog.h"

#include "../cookiejar_utils.h"

#include <rtObject.h>

namespace RDKTest
{

// Class Item implementation

Item::~Item()
{
    killTimer();
}

void Item::killTimer()
{
    if (m_source)
    {
        g_source_remove(m_source);
        m_source = 0;
    }
}

bool Item::init()
{
    RBTLOGD("Item::init:\"%s\" - enter", id());
    killTimer();

    if (!doInit())
    {
        RBTLOGD("Item::init:\"%s\" - ERROR: initialization failed", id());
        return false;
    }

    if (m_timeout)
    {
        m_source = g_timeout_add_seconds(m_timeout, [](gpointer data) -> gboolean
        {
            Item* item = (Item*)data;
            RBTLOGF("Item::timeout:\"%s\" - ERROR: time is out", item->id());
            item->m_source = 0;
            App::app.stop();
            RBTLOGF("Item::timeout:\"%s\" - exit", item->id());
            return G_SOURCE_REMOVE;
        }, this);
    }

    RBTLOGD("Item::init:\"%s\" - exit", id());
    return true;
}

Item::TestResult Item::test(const rtObjectRef& event)
{
    std::string text = toJSON(event);
    RBTLOGD("Item::test:\"%s\" - enter [%s]", id(), text.data());

    if (!event)
    {
        RBTLOGF("Item::test:\"%s\" - ERROR: event is empty", id());
        return TestResult::FAIL;
    }

    rtString name;
    if (RT_OK != event.get("name", name))
    {
        RBTLOGF("Item::test:\"%s\" - ERROR: No \"name\" string property found in event.params", id());
        return TestResult::FAIL;
    }

    TestResult result = doTest(name, event);

    if (result != TestResult::WAIT)
        killTimer();

    RBTLOGD("Item::test:\"%s\" - exit [%d]", id(), result);
    return result;
}

Item::TestResult Item::checkDocumentLoaded(const rtString& name, const rtObjectRef& event, const char* context)
{
    if (name != "onHTMLDocumentLoaded")
        return TestResult::WAIT;

    bool success;
    if (RT_OK != event.get("success", success))
    {
        RBTLOGF("%s - ERROR: No \"success\" boolean property found in event", context);
        return TestResult::FAIL;
    }

    if (!success)
    {
        RBTLOGF("%s - ERROR: success property is false in event", context);
        return TestResult::FAIL;
    }

    return TestResult::DONE;
}

// Class ItemCustomLoadURL implementation

ItemCustomLoadURL::ItemCustomLoadURL(const std::string& id, const std::string& url, guint timeout)
: ItemCustom
(
    id,
    [url]()
    {
        return (RT_OK == App::app.setProperty("url", url.c_str()));
    },
    [this](rtString name, const rtObjectRef& params)
    {
        std::string ID("ItemCustomLoadURL::doTest:");
        ID += this->id();
        return checkDocumentLoaded(name, params, ID.data());
    },
    timeout
)
{
}

// Class ItemLoadURL implementation

bool ItemLoadURL::doInit()
{
    m_event1 = false;
    RBTLOGN("ItemLoadURL::doInit [%s]", m_url.cString());
    return (RT_OK == App::app.setProperty("url", m_url));
}

Item::TestResult ItemLoadURL::doTest(const rtString& name, const rtObjectRef& event)
{
    std::string ID("ItemLoadURL::doTest:");
    ID += id();

    if (name == "onHTMLLinkClicked")
    {
        if (m_event1)
        {
            RBTLOGF("%s - ERROR: event %s is duplicated", ID.data(), name.cString());
            return TestResult::FAIL;
        }
        m_event1 = true;
        return TestResult::WAIT;
    }

    if (name == "onHTMLDocumentLoaded")
    {
        if (!m_event1)
        {
            RBTLOGF("%s - ERROR: event \"onHTMLLinkClicked\" was not received", ID.data());
            return TestResult::FAIL;
        }
        return checkDocumentLoaded(name, event, ID.data());
    }

    RBTLOGW("%s - WARN: event %s is unknown", ID.data(), name.cString());
    return TestResult::WAIT;
}

// Class ItemSetHTML implementation

bool ItemSetHTML::doInit()
{
    rtValue args[] = { m_html, rtFunctionRef() };
    RBTLOGN("ItemSetHTML::doInit\n%s", m_html.cString());
    return (RT_OK == App::app.callMethod("setHTML", sizeof(args) / sizeof(*args), args));
}

Item::TestResult ItemSetHTML::doTest(const rtString& name, const rtObjectRef& event)
{
    return checkDocumentLoaded(name, event, (std::string("ItemSetHTML::doTest:") + id()).data());
}

// Class ItemSetProp implementation

ItemSetProp::ItemSetProp(const std::string& id, const rtString& name, const rtValue& value)
: ItemCustom(id, [this]()
    {
        RBTLOGN("ItemSetProp::doInit [\"%s\" : %s]", m_name.cString(), toJSON(m_value).c_str());
        if (RT_OK != App::app.setProperty(m_name, m_value))
            return false;
        App::app.skip();
        return true;
    }, nullptr, 0) // 0 disables the timer
, m_name(name)
, m_value(value)
{
}

// Class ItemCheckProp implementation

ItemCheckProp::ItemCheckProp(const std::string& id, const rtString& name, const rtValue& value)
: ItemCustom(id, [this]()
    {
        RBTLOGN("ItemCheckProp::doInit");
        rtValue value;
        if (RT_OK != App::app.getProperty(m_name, value))
            return false;
        if (value.getType() != m_value.getType())
        {
            RBTLOGN("ERROR: value type ('%c') differs from expected ('%c')", value.getType(), m_value.getType());
            return false;
        }
        if (value != m_value)
        {
            RBTLOGN("ERROR: value (%s) differs from expected (%s)", toJSON(value).c_str(), toJSON(m_value).c_str());
            return false;
        }
        App::app.skip();
        return true;
    }, nullptr, 0) // 0 disables the timer
, m_name(name)
, m_value(value)
{
}

// Class ItemSetPropCookieJar implementation

ItemSetPropCookieJar::ItemSetPropCookieJar(const std::string& id, const std::string& cookies)
: ItemCustom(id, [this]()
    {
        RBTLOGN("ItemSetPropCookieJar::doInit");
        rtObjectRef cookieJar(new rtMapObject());
        cookieJar.set(CookieJarUtils::kFieldVersion, cookieVersion());
        cookieJar.set(CookieJarUtils::kFieldChecksum, m_md5sum);
        cookieJar.set(CookieJarUtils::kFieldCookies, m_cookies.c_str());
        if (RT_OK != App::app.setProperty("cookieJar", cookieJar))
            return false;
        App::app.skip();
        return true;
    }, nullptr, 0) // 0 disables the timer
, m_md5sum(cookieChecksum(cookies))
, m_cookies(cookieEncode(cookies))
{
    //RBTLOGD("md5sum: %d", m_md5sum);
    //RBTLOGD("cookies: \"%s\"", cookies.c_str());
    //RBTLOGD("encoded: \"%s\"", m_cookies.c_str());
    //RBTLOGD("decoded: \"%s\"", cookieDecode(m_cookies).c_str());
}

// Class ItemCheckPropCookieJar implementation

ItemCheckPropCookieJar::ItemCheckPropCookieJar(const std::string& id, const std::string& cookies)
: ItemCustom(id, [this]()
    {
        RBTLOGN("ItemCheckPropCookieJar::doInit");
        // Retrieve cookieJar property value
        rtValue cookieJar;
        if (RT_OK != App::app.getProperty("cookieJar", cookieJar))
            return false;
        if (RT_objectType != cookieJar.getType())
        {
            RBTLOGF("ERROR: Invalid \"cookieJar\" property value type: '%c'", cookieJar.getType());
            return false;
        }

        bool result = true;
        rtObjectRef object = cookieJar.toObject();

        // Retrieve and test version field
        rtValue version;
        if (RT_OK != object.get(CookieJarUtils::kFieldVersion, version))
        {
            RBTLOGF("ERROR: No \"%s\" field found", CookieJarUtils::kFieldVersion);
            result = false;
        }
        else if (RT_uint32_tType != version.getType())
        {
            RBTLOGF("ERROR: Invalid \"%s\" field data type: '%c'", CookieJarUtils::kFieldVersion, version.getType());
            result = false;
        }
        else if (version.toUInt32() != CookieJarUtils::kDefaultCookieJarVersion)
        {
            RBTLOGF("ERROR: Invalid \"%s\" field value: %u", CookieJarUtils::kFieldVersion, version.toUInt32());
            result = false;
        }

        // Retrieve and test md5sum field
        rtValue md5sum;
        if (RT_OK != object.get(CookieJarUtils::kFieldChecksum, md5sum))
        {
            RBTLOGF("ERROR: No \"%s\" field found", CookieJarUtils::kFieldChecksum);
            result = false;
        }
        else if (RT_int32_tType != md5sum.getType())
        {
            RBTLOGF("ERROR: Invalid \"%s\" field data type: '%c'", CookieJarUtils::kFieldChecksum, md5sum.getType());
            result = false;
        }
        else if (md5sum.toInt32() != m_md5sum)
        {
            RBTLOGF("ERROR: Invalid \"%s\" field value: %d (expected: %d)", CookieJarUtils::kFieldChecksum, md5sum.toInt32(), m_md5sum);
            result = false;
        }

        // Retrieve and test cookies field
        rtValue cookies;
        if (RT_OK != object.get(CookieJarUtils::kFieldCookies, cookies))
        {
            RBTLOGF("ERROR: No \"%s\" field found", CookieJarUtils::kFieldCookies);
            result = false;
        }
        else if (RT_stringType != cookies.getType())
        {
            RBTLOGF("ERROR: Invalid \"%s\" field data type: '%c'", CookieJarUtils::kFieldCookies, cookies.getType());
            result = false;
        }
        else
        {
            std::string sCookies = cookieDecode(cookies.toString().cString());
            //RBTLOGD("Decoded cookies:\n%s", sCookies.c_str());
            if (sCookies != m_cookies)
            {
                RBTLOGF("ERROR: Invalid \"%s\" field value: \"%s\" (expected: \"%s\")", CookieJarUtils::kFieldCookies, sCookies.c_str(), m_cookies.c_str());
                result = false;
            }
        }

        if (result)
        {
            // Test is OK
            App::app.skip();
        }

        return result;
    }, nullptr, 0) // 0 disables the timer
, m_md5sum(cookieChecksum(cookies))
, m_cookies(cookies)
{
}

// Class ItemWithCallGUID implementation

Item::TestResult ItemWithCallGUID::checkCallGUID(const rtObjectRef& event)
{
    rtString callGUID;
    if (RT_OK != event.get("callGUID", callGUID))
    {
        RBTLOGD("ItemWithCallGUID::checkCallGUID:\"%s\" - ERROR: No \"callGUID\" string property found in event", id());
        return TestResult::FAIL;
    }
    if (callGUID != m_callGUID)
    {
        RBTLOGD("ItemWithCallGUID::checkCallGUID:\"%s\" - ERROR: The \"callGUID\" property in event is unexpected: \"%s\" instead of \"%s\"", id(), callGUID.cString(), m_callGUID.cString());
        return TestResult::WAIT;
    }
    return TestResult::DONE;
}

// Class ItemMethod implementation

ItemMethod::ItemMethod(const std::string& id, const rtString& method, guint timeout)
: ItemWithCallGUID(id, timeout)
, m_method(method)
, m_args()
{
    m_args.push_back(new Callback(*this));
}

rtError ItemMethod::Callback::onEvent(int numArgs, const rtValue* args, rtValue* result, void* context)
{
    rtError rc = RT_FAIL;
    if (context && numArgs == 1)
    {
        Callback* callback = reinterpret_cast<Callback*>(context);
        rtObjectRef event = args[0].toObject();
        event.set("name", "onCallResult");
        event.set("callGUID", callback->m_owner.getCallGUID());
        App::app.handleAppEvent(event);
        rc = RT_OK;
    }
    if (result)
        *result = rtValue(RT_OK == rc);
    return rc;
}

bool ItemMethod::doInit()
{
    return (RT_OK == App::app.callMethod(m_method, m_args.size(), &m_args[0]));
}

void ItemMethod::addParam(const rtValue& value)
{
    m_args.insert(m_args.end() - 1, value);
}

Item::TestResult ItemMethod::doTest(const rtString& name, const rtObjectRef& event)
{
    if (name != "onCallResult")
    {
        RBTLOGD("ItemMethod::doTest:\"%s\" - WAIT: event name is not \"onCallResult\" but \"%s\"", id(), name.cString());
        return TestResult::WAIT;
    }

    TestResult result = checkCallGUID(event);
    if (TestResult::DONE != result)
        return result;

    rtValue vStatusCode, vMessage, vParams;
    if (RT_OK != event->Get("statusCode", &vStatusCode))
    {
        RBTLOGF("ItemMethod::doTest:\"%s\" - ERROR: No \"statusCode\" property found in event", id());
    }
    else if (RT_intType != vStatusCode.getType())
    {
        RBTLOGF("ItemMethod::doTest:\"%s\" - ERROR: The \"statusCode\" property in event is not an int32: type is '%c'", id(), vStatusCode.getType());
    }
    else if (RT_OK != event->Get("message", &vMessage))
    {
        RBTLOGF("ItemMethod::doTest:\"%s\" - ERROR: No \"message\" property found in event", id());
    }
    else if (RT_stringType != vMessage.getType())
    {
        RBTLOGF("ItemMethod::doTest:\"%s\" - ERROR: The \"message\" property in event is not a string: type is '%c'", id(), vMessage.getType());
    }
    else if (RT_OK != event->Get("params", &vParams))
    {
        RBTLOGF("ItemMethod::doTest:\"%s\" - ERROR: No \"params\" property found in event", id());
    }
    else if (RT_objectType != vParams.getType())
    {
        RBTLOGF("ItemMethod::doTest:\"%s\" - ERROR: The \"params\" property in event is not an object: type is '%c'", id(), vParams.getType());
    }
    else
    {
        int statusCode = vStatusCode.toInt32();
        rtString message = vMessage.toString();
        rtObjectRef paramsRef = vParams.toObject();
        std::string text = toJSON(paramsRef);
        RBTLOGD("ItemMethod::doTest:\"%s\" - [statusCode: %d, message: \"%s\", params: %s]", id(), statusCode, message.cString(), text.data());
        result = checkCallResult(statusCode, message, paramsRef);
    }

    return result;
}

// Class ItemMethodNoResult implementation

ItemMethodNoResult::ItemMethodNoResult(const std::string& id, const rtString& method, const std::vector<rtValue>& params)
: ItemMethod(id, method, 0) // 0 disables the timer
{
    for (const rtValue& v : params)
        addParam(v);
}

bool ItemMethodNoResult::doInit()
{
    if (!ItemMethod::doInit())
        return false;
    App::app.skip();
    return true;
}

// Class ItemEvalJS implementation

ItemEvalJS::ItemEvalJS(const std::string& id, const std::string& javascript, guint timeout)
: ItemMethod(id, "evaluateJavaScript", timeout)
, m_javascript(javascript)
{
    addParam(javascript.data());
}

bool ItemEvalJS::doInit()
{
    RBTLOGD("ItemEvalJS::doInit:\n%s", m_javascript.c_str());
    return ItemMethod::doInit();
}

Item::TestResult ItemEvalJS::checkCallResult(int statusCode, rtString message, const rtObjectRef& params)
{
    if (!message.isEmpty())
        RBTLOGD("ItemEvalJS::checkCallResult:\"%s\" - WARN: message property is \"%s\" in event.params", id(), message.cString());

    if (statusCode)
    {
        RBTLOGF("ItemEvalJS::checkCallResult:\"%s\" - ERROR: statusCode property is %d in event.params", id(), statusCode);
        return TestResult::FAIL;
    }

    bool success;
    if (RT_OK != params.get("success", success))
    {
        RBTLOGF("ItemEvalJS::checkCallResult:\"%s\" - ERROR: No \"success\" boolean property found in event.params", id());
        return TestResult::FAIL;
    }

    if (!success)
    {
        RBTLOGF("ItemEvalJS::checkCallResult:\"%s\" - ERROR: success property is false in event.params", id());
        return TestResult::FAIL;
    }

    return TestResult::DONE;
}

// Class ItemCallJS implementation

ItemCallJS::ItemCallJS(const std::string& id, const std::string& javascript, const std::string& response, guint timeout)
: ItemMethod(id, "callJavaScriptWithResult", timeout)
, m_javascript(javascript)
, m_response(response)
{
    addParam(javascript.data());
}

bool ItemCallJS::doInit()
{
    RBTLOGD("ItemCallJS::doInit:\n%s", m_javascript.c_str());
    return ItemMethod::doInit();
}

Item::TestResult ItemCallJS::checkCallResult(int statusCode, rtString message, const rtObjectRef& params)
{
    if (!message.isEmpty())
        RBTLOGD("ItemCallJS::checkCallResult:\"%s\" - WARN: message property is \"%s\" in event.params", id(), message.cString());

    if (statusCode)
    {
        RBTLOGF("ItemCallJS::checkCallResult:\"%s\" - ERROR: statusCode property is %d in event.params", id(), statusCode);
        return TestResult::FAIL;
    }

    rtValue result;
    if (RT_OK != params->Get("result", &result))
    {
        RBTLOGF("ItemCallJS::checkCallResult:\"%s\" - ERROR: No \"result\" property found in event.params", id());
        return TestResult::FAIL;
    }

    std::string response = toJSON(result);
    if (response != m_response)
    {
        RBTLOGD("ItemCallJS::checkCallResult:\"%s\" - ERROR: The \"result\" property in event.params is unexpected: \"%s\" instead of \"%s\"", id(), response.data(), m_response.data());
        return TestResult::FAIL;
    }

    return TestResult::DONE;
}

// Class ItemCheckUrl implementation

ItemCheckUrl::ItemCheckUrl(const std::string& id, const std::string& url)
: ItemCallJS(id, "document.location.href", addQuotes(url))
{
}

} // namespace RDKTest
