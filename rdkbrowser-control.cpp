#include <glib.h>
#include <rtRemote.h>
#include <stdio.h>
#include <unistd.h>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <readline/history.h>
#include <readline/readline.h>

#include <JavaScriptCore/JSContextRef.h>
#include <JavaScriptCore/JSContextRefPrivate.h>
#include <JavaScriptCore/JSObjectRef.h>
#include <JavaScriptCore/JSStringRef.h>
#include <JavaScriptCore/JSValueRef.h>

#include "js_utils.h"

#define LOG_INFO(fmt, ...) printf("%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("*** Error: %s: " fmt "\n", __func__, ##__VA_ARGS__)

static JSGlobalContextRef gJSContext = nullptr;
static GMainLoop *gLoop = nullptr;

static JSValueRef rtObjectWrapper_wrapObject(JSContextRef context, rtObjectRef obj);
static JSValueRef rtFunctionWrapper_wrapFunction(JSContextRef context, rtFunctionRef func);
static rtString jscToRtString(JSStringRef str);
static bool jscToRtValue(JSContextRef context, JSObjectRef thisObject, JSValueRef value, rtValue &rtval);
static JSValueRef rtToJSCValue(JSContextRef context, const rtValue &rtval);

static gboolean dispatchRtRemoteItems(gpointer data)
{
    rtError err;
    GSource *source = (GSource *)data;
    do {
        g_source_set_ready_time(source, -1);
        err = rtRemoteProcessSingleItem();
    } while (err == RT_OK);
    if (err != RT_OK && err != RT_ERROR_QUEUE_EMPTY) {
        LOG_ERROR("rtRemoteProcessSingleItem() returned %d", err);
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

static GSource *attachRtRemoteSource()
{
    static GSourceFuncs g_sourceFuncs =
        {
            nullptr, // prepare
            nullptr, // check
            [](GSource *source, GSourceFunc callback, gpointer data) -> gboolean // dispatch
            {
                if (g_source_get_ready_time(source) != -1) {
                    g_source_set_ready_time(source, -1);
                    return callback(data);
                }
                return G_SOURCE_CONTINUE;
            },
            nullptr, // finalize
            nullptr, // closure_callback
            nullptr, // closure_marshall
        };
    GSource *source = g_source_new(&g_sourceFuncs, sizeof(GSource));
    g_source_set_name(source, "RT Remote Event dispatcher");
    g_source_set_can_recurse(source, TRUE);
    g_source_set_callback(source, dispatchRtRemoteItems, source, nullptr);
    g_source_set_priority(source, G_PRIORITY_HIGH);

    rtRemoteEnvironment *env = rtEnvironmentGetGlobal();
    rtError e = rtRemoteRegisterQueueReadyHandler(env, [](void *data) -> void {
        GSource *source = (GSource *)data;
        g_source_set_ready_time(source, 0);
    }, source);

    if (e != RT_OK)
    {
        LOG_ERROR("Failed to register queue handler: %d", e);
        g_source_destroy(source);
        return nullptr;
    }
    g_source_attach(source, g_main_context_default());
    return source;
}

class JSCallbackWrapper : public rtFunctionCallback
{
    static rtError onEventCB(int numArgs, const rtValue *args, rtValue *result, void *context)
    {
        rtError rc = RT_FAIL;
        if (context && result)
        {
            JSCallbackWrapper &self = *static_cast<JSCallbackWrapper *>(context);
            rc = self.call(numArgs, args);
            *result = rc;
        }
        return rc;
    }

    rtError call(int numArgs, const rtValue *args)
    {
        std::vector<JSValueRef> jsArgs;
        jsArgs.reserve(numArgs);
        for (int i = 0; i < numArgs; ++i)
        {
            const rtValue &rtVal = args[i];
            jsArgs.push_back(rtToJSCValue(gJSContext, rtVal));
        }
        JSValueRef exception = nullptr;
        JSObjectCallAsFunction(gJSContext, m_funcObj, m_thisObject, numArgs, jsArgs.data(), &exception);
        if (exception)
        {
            JSStringRef exceptStr =
                JSValueToStringCopy(gJSContext, exception, nullptr);
            rtString errorStr = jscToRtString(exceptStr);
            JSStringRelease(exceptStr);
            LOG_ERROR("Event call failed, error='%s'", errorStr.cString());
        }
        return RT_OK;
    }

    JSObjectRef m_thisObject;
    JSObjectRef m_funcObj;

public:
    JSCallbackWrapper(JSObjectRef thisObject, JSObjectRef funcObj)
        : rtFunctionCallback(onEventCB, this)
        , m_thisObject(thisObject)
        , m_funcObj(funcObj)
    {
        JSValueProtect(gJSContext, m_thisObject);
        JSValueProtect(gJSContext, m_funcObj);
    }
    ~JSCallbackWrapper()
    {
        JSValueUnprotect(gJSContext, m_thisObject);
        JSValueUnprotect(gJSContext, m_funcObj);
    }
};

static rtString jscToRtString(JSStringRef str)
{
    if (!str)
        return rtString();
    size_t len = JSStringGetMaximumUTF8CStringSize(str);
    std::unique_ptr<char[]> buffer(new char[len]);
    len = JSStringGetUTF8CString(str, buffer.get(), len);
    return rtString(buffer.get(), len); // does a copy
}

static bool jscToRtValue(JSContextRef context, JSObjectRef thisObject, JSValueRef value, rtValue &rtval)
{
    if (JSValueIsObject(context, value))
    {
        JSValueRef exception = nullptr;
        JSObjectRef funcObj = JSValueToObject(context, value, &exception);
        if (!exception && JSObjectIsFunction(context, funcObj))
        {
            rtFunctionRef callback = new JSCallbackWrapper(thisObject, funcObj);
            rtval = rtValue(callback);
            return true;
        }
    }
    return JSUtils::toRTValue(context, value, rtval);
}

static JSValueRef rtToJSCValue(JSContextRef context, const rtValue &v)
{
    if (v.getType() == RT_objectType)
    {
        return rtObjectWrapper_wrapObject(context, v.toObject());
    }
    else if (v.getType() == RT_functionType)
    {
        return rtFunctionWrapper_wrapFunction(context, v.toFunction());
    }
    JSStringRef jsStr = JSStringCreateWithUTF8CString(v.toString().cString());
    JSValueRef jsVal = JSValueMakeString(context, jsStr);
    JSStringRelease(jsStr);
    return jsVal;
}

static JSValueRef rtFunctionWrapper_callAsFunction(JSContextRef context, JSObjectRef function, JSObjectRef thisObject, size_t argumentCount, const JSValueRef arguments[], JSValueRef *exception)
{
    rtIFunction *f = (rtIFunction *)JSObjectGetPrivate(function);
    if (!f)
    {
        LOG_ERROR("No remote object");
        return JSValueMakeUndefined(context);
    }
    rtFunctionRef funcRef = f;

    std::vector<rtValue> args;
    if (argumentCount > 0)
    {
        args.reserve(argumentCount);
        for (size_t i = 0; i < argumentCount; ++i)
        {
            rtValue val;
            if (jscToRtValue(gJSContext, thisObject, arguments[i], val))
            {
                args.push_back(val);
            }
            else
            {
                LOG_ERROR("Cannot convert to js to rt value");
                JSStringRef errStr = JSStringCreateWithUTF8CString("Cannot convert args from js to rt");
                *exception = JSValueMakeString(context, errStr);
                JSStringRelease(errStr);
                return nullptr;
            }
        }
    }
    rtValue result;
    funcRef.SendReturns(argumentCount, args.data(), result);
    return rtToJSCValue(context, result);
}

static void rtFunctionWrapper_finalize(JSObjectRef thisObject)
{
    rtIFunction *o = (rtIFunction *)JSObjectGetPrivate(thisObject);
    JSObjectSetPrivate(thisObject, nullptr);
    o->Release();
}

static const JSClassDefinition rtFunctionWrapper_class_def =
{
    0,                                // version
    kJSClassAttributeNone,            // attributes
    "__rtFunction__class",            // className
    nullptr,                          // parentClass
    nullptr,                          // staticValues
    nullptr,                          // staticFunctions
    nullptr,                          // initialize
    rtFunctionWrapper_finalize,       // finalize
    nullptr,                          // hasProperty
    nullptr,                          // getProperty
    nullptr,                          // setProperty
    nullptr,                          // deleteProperty
    nullptr,                          // getPropertyNames
    rtFunctionWrapper_callAsFunction, // callAsFunction
    nullptr,                          // callAsConstructor
    nullptr,                          // hasInstance
    nullptr                           // convertToType
};

static JSValueRef rtFunctionWrapper_wrapFunction(JSContextRef context, rtFunctionRef func)
{
    if (!func)
        return JSValueMakeNull(context);
    static JSClassRef classRef = JSClassCreate(&rtFunctionWrapper_class_def);
    rtIFunction *f = func.ptr();
    f->AddRef();
    return JSObjectMake(context, classRef, f);
}

static bool rtObjectWrapper_setProperty(JSContextRef context, JSObjectRef thisObject, JSStringRef propertyName, JSValueRef value, JSValueRef *exception)
{
    rtIObject *o = (rtIObject *)JSObjectGetPrivate(thisObject);
    if (!o)
    {
        JSStringRef errStr = JSStringCreateWithUTF8CString("No remote object");
        *exception = JSValueMakeString(context, errStr);
        JSStringRelease(errStr);
        return false;
    }
    rtObjectRef objectRef = o;
    rtValue val;
    if (!jscToRtValue(gJSContext, thisObject, value, val))
    {
        JSStringRef errStr = JSStringCreateWithUTF8CString("Cannot convert to js to rt value");
        *exception = JSValueMakeString(context, errStr);
        JSStringRelease(errStr);
        return false;
    }
    rtString name = jscToRtString(propertyName);
    rtError e = objectRef.set(name, val);
    if (e != RT_OK)
    {
        JSStringRef errStr = JSStringCreateWithUTF8CString("Failed to set property");
        *exception = JSValueMakeString(context, errStr);
        JSStringRelease(errStr);
        return false;
    }
    return true;
}

static JSValueRef rtObjectWrapper_getProperty(JSContextRef context, JSObjectRef thisObject, JSStringRef propertyName, JSValueRef *exception)
{
    rtIObject *o = (rtIObject *)JSObjectGetPrivate(thisObject);
    if (!o)
    {
        JSStringRef errStr = JSStringCreateWithUTF8CString("No remote object");
        *exception = JSValueMakeString(context, errStr);
        JSStringRelease(errStr);
        return nullptr;
    }
    rtObjectRef objectRef = o;

    rtString propName = jscToRtString(propertyName);
    if (propName.isEmpty())
    {
        return JSValueMakeUndefined(context);
    }
    if (!strcmp(propName.cString(), "Symbol.toPrimitive") ||
        !strcmp(propName.cString(), "toString") ||
        !strcmp(propName.cString(), "valueOf"))
    {
        JSStringRef script =
            JSStringCreateWithUTF8CString("return '[object __rtObject_class]'");
        return JSObjectMakeFunction(context, nullptr, 0, nullptr, script, nullptr, 1, exception);
    }
    if (!strcmp(propName.cString(), "toJSON"))
    {
        JSStringRef script = JSStringCreateWithUTF8CString("return {}");
        return JSObjectMakeFunction(context, nullptr, 0, nullptr, script, nullptr, 1, exception);
    }
    if (!strcmp(propName.cString(), "then"))
    {
        return JSValueMakeUndefined(context);
    }

    rtValue v;
    rtError e = RT_OK;
    if (std::isdigit(*propName.cString()))
    {
        uint32_t idx = std::stoul(propName.cString());
        e = objectRef.get(idx, v);
    }
    else
    {
        e = objectRef.get(propName.cString(), v);
    }

    if (e != RT_OK)
    {
        JSStringRef errStr = JSStringCreateWithUTF8CString("Failed to get property");
        *exception = JSValueMakeString(context, errStr);
        JSStringRelease(errStr);
        return nullptr;
    }
    return rtToJSCValue(context, v);
}

static void rtObjectWrapper_finalize(JSObjectRef thisObject)
{
    rtIObject *o = (rtIObject *)JSObjectGetPrivate(thisObject);
    JSObjectSetPrivate(thisObject, nullptr);
    o->Release();
}

static const JSClassDefinition rtObjectWrapper_class_def =
{
    0,                              // version
    kJSClassAttributeNone,          // attributes
    "__rtObject__class",             // className
    nullptr,                        // parentClass
    nullptr,                        // staticValues
    nullptr,                        // staticFunctions
    nullptr,                        // initialize
    rtObjectWrapper_finalize,       // finalize
    nullptr,                        // hasProperty
    rtObjectWrapper_getProperty,    // getProperty
    rtObjectWrapper_setProperty,    // setProperty
    nullptr,                        // deleteProperty
    nullptr,                        // getPropertyNames
    nullptr,                        // callAsFunction
    nullptr,                        // callAsConstructor
    nullptr,                        // hasInstance
    nullptr                         // convertToType
};

static JSValueRef rtObjectWrapper_wrapObject(JSContextRef context, rtObjectRef obj)
{
    if (!obj)
        return JSValueMakeNull(context);
    static JSClassRef classRef = JSClassCreate(&rtObjectWrapper_class_def);
    rtIObject *o = obj.ptr();
    o->AddRef();
    return JSObjectMake(context, classRef, o);
}

static JSValueRef printCallback(JSContextRef ctx, JSObjectRef, JSObjectRef, size_t argumentCount, const JSValueRef arguments[], JSValueRef *exception)
{
    for (size_t i = 0; i < argumentCount; ++i)
    {
        JSStringRef resStr = JSValueToStringCopy(ctx, arguments[i], exception);
        if (*exception)
            break;
        printf("%s ", jscToRtString(resStr).cString());
        JSStringRelease(resStr);
    }
    if (argumentCount)
        printf("\n");
    return JSValueMakeUndefined(ctx);
}

static JSValueRef Locator_locate(JSContextRef context, JSObjectRef, JSObjectRef, size_t argumentCount, const JSValueRef arguments[], JSValueRef *exception)
{
    rtString objectName = "wl-rdkbrowser2-standalone";
    if (argumentCount == 1)
    {
        rtValue val;
        if (JSUtils::toRTValue(context, arguments[0], val))
        {
            objectName = val.toString();
        }
        else
        {
            JSStringRef errStr = JSStringCreateWithUTF8CString("Cannot locate object");
            *exception = JSValueMakeString(context, errStr);
            JSStringRelease(errStr);
            return nullptr;
        }
    }
    LOG_INFO("Locating %s...", objectName.cString());
    rtError e = RT_OK;
    rtObjectRef browserObj;
    e = rtRemoteLocateObject(objectName.cString(), browserObj);
    if (e != RT_OK)
    {
        LOG_ERROR("Failed to locate remote object: err=%d", e);
        JSStringRef errStr = JSStringCreateWithUTF8CString("Failed to locate remote object");
        *exception = JSValueMakeString(context, errStr);
        JSStringRelease(errStr);
        return nullptr;
    }
    LOG_INFO("Found %s!", objectName.cString());
    return rtObjectWrapper_wrapObject(context, browserObj);
}

static JSValueRef Locator_getestbmac(JSContextRef context, JSObjectRef, JSObjectRef, size_t, const JSValueRef[], JSValueRef *)
{
    gchar *contents = nullptr;
    gsize length = 0;
    GError *error = nullptr;
    if (g_file_get_contents("/tmp/.estb_mac", &contents, &length, &error))
    {
        if (length > 1)
        {
            --length;
            while (!g_ascii_isxdigit(contents[length])) {
                contents[length] = '\0';
                --length;
            }
            JSStringRef jsStr = JSStringCreateWithUTF8CString(contents);
            JSValueRef resVal = JSValueMakeString(context, jsStr);
            JSStringRelease(jsStr);
            g_free(contents);
            return resVal;
        }
    }
    return JSValueMakeUndefined(context);
}

static const JSStaticFunction Locator_staticfunctions[] =
{
    {"locate", Locator_locate, kJSPropertyAttributeDontDelete | kJSPropertyAttributeReadOnly},
    {"estbmac", Locator_getestbmac, kJSPropertyAttributeDontDelete | kJSPropertyAttributeReadOnly},
    {nullptr, nullptr, 0}
};

static const JSClassDefinition Locator_class_def =
{
    0,
    kJSClassAttributeNone,
    "__Locator__class",
    nullptr,
    nullptr,
    Locator_staticfunctions,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr
};

void injectFuncs(JSGlobalContextRef jsContext)
{
    JSClassRef classRef = JSClassCreate(&Locator_class_def);
    JSObjectRef classObj = JSObjectMake(jsContext, classRef, nullptr);
    JSObjectRef globalObj = JSContextGetGlobalObject(jsContext);
    JSStringRef str = JSStringCreateWithUTF8CString("rt");
    JSObjectSetProperty(jsContext, globalObj, str, classObj, kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete, nullptr);
    JSClassRelease(classRef);
    JSStringRelease(str);

    JSStringRef funcName = JSStringCreateWithUTF8CString("print");
    JSObjectRef funcObj = JSObjectMakeFunctionWithCallback(jsContext, funcName, printCallback);
    JSObjectSetProperty(jsContext, globalObj, funcName, funcObj, kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete, nullptr);
    JSStringRelease(funcName);
}

void evaluateScript(const char *script)
{
    JSValueRef exception = nullptr;
    JSStringRef jsstr = JSStringCreateWithUTF8CString(script);
    JSObjectRef globalObj = JSContextGetGlobalObject(gJSContext);
    JSValueRef result = JSEvaluateScript(gJSContext, jsstr, globalObj, nullptr, 0, &exception);
    JSStringRelease(jsstr);

    if (exception)
    {
        JSStringRef exceptStr = JSValueToStringCopy(gJSContext, exception, nullptr);
        rtString errorStr = jscToRtString(exceptStr);
        JSStringRelease(exceptStr);
        LOG_ERROR("Failed to eval, \n\terror='%s'\n\tscript='%s'", errorStr.cString(), script);
    }
    else if (result)
    {
        JSStringRef jscStr = JSValueToStringCopy(gJSContext, result, nullptr);
        rtString resultStr = jscToRtString(jscStr);
        JSStringRelease(jscStr);
        LOG_INFO("Eval result=%s", resultStr.cString());
    }
}

void readlineThread()
{
    static std::condition_variable gREPLCondition;
    static std::mutex gREPLMutex;
    static bool gREPLDone = true;
    char *buf;
    while ((buf = readline(">> ")))
    {
        if (strlen(buf) > 0)
        {
            add_history(buf);
            std::unique_lock<std::mutex> lock(gREPLMutex);
            gREPLDone = false;
            g_main_context_invoke(nullptr, [](gpointer data) -> gboolean {
                char *buf = (char *)data;
                evaluateScript(buf);
                free(buf);
                std::unique_lock<std::mutex> lock(gREPLMutex);
                gREPLDone = true;
                gREPLCondition.notify_all();
                return G_SOURCE_REMOVE;
            }, buf);
            gREPLCondition.wait(lock, [] { return gREPLDone; });
        }
        else
        {
            free(buf);
        }
    }
    g_main_loop_quit(gLoop);
}

int main(int argc, char *argv[])
{
    rtError e;

    e = rtRemoteInit();
    if (e != RT_OK)
    {
        LOG_ERROR("Failed to initialize rtRemoteInit: %d", e);
        return e;
    }

    gLoop = g_main_loop_new(g_main_context_default(), FALSE);

    GSource *remoteSource = attachRtRemoteSource();
    if (!remoteSource)
    {
        LOG_ERROR("Failed to attach rt remote source");
        return -1;
    }

    gJSContext = JSGlobalContextCreate(nullptr);

    injectFuncs(gJSContext);

    if (argc > 1)
    {
        for (int i = 1; i < argc; ++i)
        {
            gchar *contents = nullptr;
            gsize length = 0;
            GError *error = nullptr;
            if (g_file_get_contents(argv[i], &contents, &length, &error))
            {
                evaluateScript(contents);
                g_free(contents);
            }
            else
            {
                LOG_ERROR("Falied to read: %s, error %s", argv[i], error ? error->message : nullptr);
            }
        }
    }

    std::thread replThread(readlineThread);

    g_main_loop_run(gLoop);

    replThread.join();
    g_source_unref(remoteSource);
    e = rtRemoteShutdown();
    if (e != RT_OK)
    {
        LOG_ERROR("rtRemoteShutdown failed: %d", e);
        return e;
    }
    LOG_INFO("rtRemoteShutdown succeeded: %d", e);

    JSGlobalContextRelease(gJSContext);
    return 0;
}
