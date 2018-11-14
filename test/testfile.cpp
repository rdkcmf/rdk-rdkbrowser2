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
#include "testfile.h"
#include "testlog.h"

#include <fcntl.h>
#include <unistd.h>

static const std::string tmpdir /*__attribute__((init_priority(200)))*/ ("/tmp/");
static const std::string scheme /*__attribute__((init_priority(200)))*/ ("file://");

namespace RDKTest
{

File::File(const std::string& name, const std::string& content)
: m_name(name)
, m_content(content)
{
    if (!create(name, content))
        RBTLOGF("File constructor - ERROR: Can't create file \"%s\", error: %d", path().c_str(), errno);
}

File::~File()
{
    if (!unlink())
        RBTLOGF("File destructor - ERROR: Can't delete file \"%s\", error: %d", path().c_str(), errno);
}

bool File::create(const std::string& name, const std::string& content)
{
    m_name = name;
    m_content = content;
    int f = open(path().c_str(), O_CREAT | O_TRUNC | O_WRONLY);
    if (-1 == f)
        return false;
    write(f, m_content.c_str(), m_content.size());
    close(f);
    RBTLOGN("File::create - file \"%s\" is created", path().c_str());
    return true;
}

bool File::unlink()
{
    if (name().empty())
        return true;
    if (-1 == ::unlink(path().c_str()))
        return false;
    RBTLOGN("File::unlink - file \"%s\" is deleted", path().c_str());
    return true;
}

std::string File::path() const
{
    return tmpdir + name();
}

std::string File::url() const
{
    return scheme + path();
}

} // namespace RDKTest
