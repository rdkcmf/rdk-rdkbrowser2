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
#include "testconf.h"
#include "testlog.h"

namespace RDKTest
{

Conf::Conf()
: m_file(g_key_file_new())
{
}

Conf::~Conf()
{
    g_key_file_free(m_file);
}

void Conf::load(const std::string& filename)
{
    GError* error = nullptr;
    m_valid = (TRUE == g_key_file_load_from_file(m_file, filename.c_str(), G_KEY_FILE_NONE, &error));
    if (!m_valid)
    {
        RBTLOGW("No config file loaded (\"%s\") %s", filename.c_str(), error ? error->message : nullptr);
        RBTLOGN("Use config file like the following example:"
            "\n"
            "\n# Config file for rdkbrowsertest"
            "\n"
            "\n[general]"
            "\nmaximumLoop=2"
            "\n"
            "\n[use]"
            "\n#init=false"
            "\njstest=false"
            "\ninline=false"
            "\nfile1=false"
            "\nfile2=false"
            "\nfile3=false"
            "\ncookiejar=false"
            "\nstartup=false"
            "\n"
        );
    }
    else
        RBTLOGN("Conf::load - Loaded from file \"%s\"", filename.c_str());
}

size_t Conf::maximumLoop(int def) const
{
    return getInteger("general", "maximumLoop", def);
}

bool Conf::use(const char* name, bool def) const
{
    return getBoolean("use", name, def);
}

static std::string inline keyPair(const char* group, const char* key)
{
    return std::string(group) + "\n" + std::string(key);
}

static bool inline isErrorCritical(const GError* error)
{
    if (!error)
        return false;
    if (G_KEY_FILE_ERROR == error->domain)
    {
        if (G_KEY_FILE_ERROR_KEY_NOT_FOUND == error->code)
            return false;
        if (G_KEY_FILE_ERROR_GROUP_NOT_FOUND == error->code)
            return false;
    }
    return true;
}

std::string Conf::getString(const char* group, const char* key, const char* def) const
{
    if (!m_valid)
        return def;

    std::string pair = keyPair(group, key);
    StringCache::const_iterator it = m_stringCache.find(pair);
    if (it != m_stringCache.end())
        return it->second;

    GError* error = nullptr;
    std::string result = g_key_file_get_string(m_file, group, key, &error);
    if (error)
        result = def;
    if (isErrorCritical(error))
        RBTLOGW("Conf::getString(\"%s\", \"%s\") - ERROR: [%u|%u] %s", group, key, error->domain, error->code, error->message);
    else
        RBTLOGN("Conf::getString(\"%s\", \"%s\") - [ \"%s\" ] ", group, key, result.c_str());

    ((Conf*)this)->m_stringCache[pair] = result;

    return result;
}

int Conf::getInteger(const char* group, const char* key, int def) const
{
    if (!m_valid)
        return def;

    std::string pair = keyPair(group, key);
    IntegerCache::const_iterator it = m_integerCache.find(pair);
    if (it != m_integerCache.end())
        return it->second;

    GError* error = nullptr;
    int result = g_key_file_get_integer(m_file, group, key, &error);
    if (error)
        result = def;
    if (isErrorCritical(error))
        RBTLOGW("Conf::getInteger(\"%s\", \"%s\") - ERROR: [%u|%u] %s", group, key, error->domain, error->code, error->message);
    else
        RBTLOGN("Conf::getInteger(\"%s\", \"%s\") - [ %d ] ", group, key, result);

    ((Conf*)this)->m_integerCache[pair] = result;

    return result;
}

bool Conf::getBoolean(const char* group, const char* key, bool def) const
{
    if (!m_valid)
        return def;

    std::string pair = keyPair(group, key);
    BooleanCache::const_iterator it = m_booleanCache.find(pair);
    if (it != m_booleanCache.end())
        return it->second;

    GError* error = nullptr;
    bool result = (TRUE == g_key_file_get_boolean(m_file, group, key, &error));
    if (error)
        result = def;
    if (isErrorCritical(error))
        RBTLOGW("Conf::getBoolean(\"%s\", \"%s\") - ERROR: [%u|%u] %s", group, key, error->domain, error->code, error->message);
    else
        RBTLOGN("Conf::getBoolean(\"%s\", \"%s\") - [ %s ] ", group, key, result ? "true" : "false");

    ((Conf*)this)->m_booleanCache[pair] = result;

    return result;
}

} // namespace RDKTest
