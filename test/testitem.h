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
#ifndef RDKBROWSER_TEST_ITEM_H
#define RDKBROWSER_TEST_ITEM_H

#include <rtObject.h>

#include <glib.h>

#include <string>
#include <functional>

namespace RDKTest
{

class Item
{
public:
    enum class TestResult : char
    {
        DONE,
        WAIT,
        FAIL
    };

    Item(const std::string& id, guint timeout)
    : m_id(id)
    , m_timeout(timeout)
    {
    }

    virtual ~Item();

    const char* id() const { return m_id.c_str(); }

    bool init();
    TestResult test(const rtObjectRef& event);

    static TestResult checkDocumentLoaded(const rtString& name, const rtObjectRef& event, const char* context);

protected:
    void killTimer();

    virtual bool doInit() { return true; }
    virtual TestResult doTest(const rtString& name, const rtObjectRef& event) = 0;

private:
    std::string m_id;
    guint m_timeout;
    guint m_source { 0 };
};

class ItemCustom : public Item
{
public:
    typedef std::function<bool()> FuncInit;
    typedef std::function<TestResult(const rtString& name, const rtObjectRef& event)> FuncTest;

    ItemCustom(const std::string& id, const FuncInit& onInit, const FuncTest& onTest, guint timeout = 30)
    : Item(id, timeout)
    , m_onInit(onInit)
    , m_onTest(onTest)
    {
    }

    virtual bool doInit() override
    {
        return m_onInit();
    }

protected:
    virtual TestResult doTest(const rtString& name, const rtObjectRef& event) override
    {
        return m_onTest(name, event);
    }

private:
    FuncInit m_onInit;
    FuncTest m_onTest;
};

class ItemCustomLoadURL : public ItemCustom
{
public:
    ItemCustomLoadURL(const std::string& id, const std::string& url, guint timeout = 30);
};

class ItemLoadURL : public Item
{
public:
    ItemLoadURL(const std::string& id, const std::string& url, guint timeout = 30)
    : Item(id, timeout)
    , m_url(url.c_str())
    {
    }

    virtual bool doInit() override;

protected:
    virtual TestResult doTest(const rtString& name, const rtObjectRef& event) override;

private:
    rtString m_url;
    bool m_event1 { false };
};

class ItemSetHTML : public Item
{
public:
    ItemSetHTML(const std::string& id, const std::string& html, guint timeout = 10)
    : Item(id, timeout)
    , m_html(html.c_str())
    {
    }

    virtual bool doInit() override;

protected:
    virtual TestResult doTest(const rtString& name, const rtObjectRef& event) override;

private:
    rtString m_html;
};

class ItemSetProp : public ItemCustom
{
public:
    ItemSetProp(const std::string& id, const rtString& name, const rtValue& value);

private:
    const rtString m_name;
    const rtValue m_value;
};

class ItemCheckProp : public ItemCustom
{
public:
    ItemCheckProp(const std::string& id, const rtString& name, const rtValue& value);

private:
    const rtString m_name;
    const rtValue m_value;
};

class ItemSetPropCookieJar : public ItemCustom
{
public:
    ItemSetPropCookieJar(const std::string& id, const std::string& cookies);

private:
    const int m_md5sum;
    const std::string m_cookies;
};

class ItemCheckPropCookieJar : public ItemCustom
{
public:
    ItemCheckPropCookieJar(const std::string& id, const std::string& cookies);

private:
    const int m_md5sum;
    const std::string m_cookies;
};

class ItemWithCallGUID : public Item
{
public:
    ItemWithCallGUID(const std::string& id, const rtString& callGUID, guint timeout)
    : Item(id, timeout)
    , m_callGUID(callGUID)
    {
    }

    ItemWithCallGUID(const std::string& id, guint timeout)
    : Item(id, timeout)
    , m_callGUID(("guid-" + id).c_str())
    {
    }

protected:
    rtString getCallGUID() const { return m_callGUID; }
    TestResult checkCallGUID(const rtObjectRef& event);

private:
    rtString m_callGUID;
};

class ItemMethod : public ItemWithCallGUID
{
    class Callback : public rtFunctionCallback
    {
    public:
        Callback(const ItemMethod& owner)
            : rtFunctionCallback(onEvent, this)
            , m_owner(owner)
        {
        }

    protected:
        static rtError onEvent(int numArgs, const rtValue* args, rtValue* result, void* context);

    private:
        const ItemMethod& m_owner;
    };

public:
    ItemMethod(const std::string& id, const rtString& method, guint timeout);

protected:
    virtual bool doInit() override;
    void addParam(const rtValue& value);
    virtual TestResult doTest(const rtString& name, const rtObjectRef& event) override;
    virtual TestResult checkCallResult(int statusCode, rtString message, const rtObjectRef& params) = 0;

private:
    rtString m_method;
    std::vector<rtValue> m_args;
};

class ItemMethodNoResult : public ItemMethod
{
public:
    ItemMethodNoResult(const std::string& id, const rtString& method, const std::vector<rtValue>& params);

protected:
    virtual bool doInit() override;
    virtual TestResult checkCallResult(int, rtString, const rtObjectRef&) override
    {
        return TestResult::DONE;
    }
};

class ItemEvalJS : public ItemMethod
{
public:
    ItemEvalJS(const std::string& id, const std::string& javascript, guint timeout = 10);

protected:
    virtual bool doInit() override;
    virtual TestResult checkCallResult(int statusCode, rtString message, const rtObjectRef& params) override;

private:
    std::string m_javascript;
};

class ItemCallJS : public ItemMethod
{
public:
    ItemCallJS(const std::string& id, const std::string& javascript, const std::string& response, guint timeout = 10);

protected:
    virtual bool doInit() override;
    virtual TestResult checkCallResult(int statusCode, rtString message, const rtObjectRef& params) override;

private:
    std::string m_javascript;
    std::string m_response;
};

class ItemCheckUrl : public ItemCallJS
{
public:
    ItemCheckUrl(const std::string& id, const std::string& url);
};

} // namespace RDKTest

#endif // RDKBROWSER_TEST_ITEM_H
