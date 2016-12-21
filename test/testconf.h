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
#ifndef RDKBROWSER_TEST_CONF_H
#define RDKBROWSER_TEST_CONF_H

#include <glib.h>

#include <string>
#include <map>

namespace RDKTest
{

class Conf
{
public:
    Conf();
    virtual ~Conf();

    void load(const std::string& filename);
    bool valid() const { return m_valid; }

    size_t maximumLoop(int def = 1) const;
    bool use(const char* name, bool def = true) const;

protected:
    std::string getString(const char* group, const char* key, const char* def = nullptr) const;
    int getInteger(const char* group, const char* key, int def = 0) const;
    bool getBoolean(const char* group, const char* key, bool def = false) const;

private:
    GKeyFile* m_file;
    bool m_valid { false };

    typedef std::map<std::string, std::string> StringCache;
    typedef std::map<std::string, int> IntegerCache;
    typedef std::map<std::string, bool> BooleanCache;

    StringCache m_stringCache;
    IntegerCache m_integerCache;
    BooleanCache m_booleanCache;
};

} // namespace RDKTest

#endif // RDKBROWSER_TEST_CONF_H
