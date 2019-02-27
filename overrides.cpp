#include "overrides.h"
#include "logger.h"

#include <glib.h>
#include <JavaScriptCore/JavaScript.h>
#include "js_utils.h"

namespace RDK
{

static const char enableOverridesEnvVar[] = "RDKBROWSER2_ENABLE_OVERRIDES";

bool convertToRtValue(const rtString& str, rtValue& result)
{
    if (str == "false" || str == "0")
    {
        result = rtValue{false};
        return true;
    }

    if (str.beginsWith("{") || str.beginsWith("["))
    {
        // Please note JSC parses in strict mode
        // which means you need to use double quotes for strings
        auto ctx = JSGlobalContextCreate(nullptr);
        JSStringRef jsStr = JSStringCreateWithUTF8CString(str.cString());
        auto jsonVal = JSValueMakeFromJSONString(ctx, jsStr);
        JSStringRelease(jsStr);
        bool rc = JSUtils::toRTValue(ctx, jsonVal, result);
        JSGlobalContextRelease(ctx);
        return rc;
    }

    result = rtValue{str};
    return true;
}

bool overridesEnabled()
{
    static bool enableOverrides = !!getenv(enableOverridesEnvVar);
    return enableOverrides;
}

void loadOverrides(std::string url, rtObjectRef browser)
{
    if (!overridesEnabled())
        return;

    g_autoptr(GError) error = nullptr;
    g_autoptr(GKeyFile) keyFile = g_key_file_new();
    if (!g_key_file_load_from_file(keyFile, "/tmp/rdkbrowser2_overrides.ini", G_KEY_FILE_NONE, &error))
    {
        if (!g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            RDKLOG_WARNING ("Failed to load overrides key file, error=%s", error ? error->message : "unknown");
        return;
    }

    g_autofree gchar *overrideGroup = nullptr;
    gsize groupsLength = 0;
    gchar **groups = g_key_file_get_groups(keyFile, &groupsLength);
    if (groups == nullptr)
    {
        RDKLOG_TRACE("No overrides for %s", url.c_str());
        return;
    }
    for (gsize i = 0; i < groupsLength; ++i)
    {
        gchar *group = groups[i];
        if (g_strrstr(url.c_str(), group) != nullptr)
        {
            overrideGroup = g_strdup(group);
            break;
        }
    }
    g_strfreev(groups);

    if (!overrideGroup)
    {
        RDKLOG_TRACE("No overrides for %s", url.c_str());
        return;
    }
    RDKLOG_INFO("Using overrides from %s", overrideGroup);

    gsize keysLength = 0;
    gchar **keys = g_key_file_get_keys(keyFile, overrideGroup, &keysLength, &error);
    if (keys == nullptr)
    {
        RDKLOG_WARNING ("Failed to read '%s' overrides, error=%s", overrideGroup, error ? error->message : "unknown");
        return;
    }

    for (gsize i = 0; i < keysLength; ++i)
    {
        gchar* key = keys[i];
        g_autofree gchar *overrideVal = g_key_file_get_string (keyFile, overrideGroup, key, &error);
        if (overrideVal == nullptr)
        {
            if (!g_error_matches (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND))
                RDKLOG_WARNING ("Failed to read key('%s') value, error=%s", key, error ? error->message : "unknown");
            continue;
        }

        rtValue val;
        bool converted = convertToRtValue(rtString {overrideVal}, val);
        if (!converted)
        {
            RDKLOG_WARNING("Failed to convert '%s'", overrideVal);
            continue;
        }

        rtError rc = browser.set(key, val);
        if (rc != RT_OK)
        {
            RDKLOG_WARNING("Failed to override %s, rc=%d", key, rc);
        }
    }

    g_strfreev(keys);
}

}  // namespace RDK
