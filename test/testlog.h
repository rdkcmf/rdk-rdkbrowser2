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
#ifndef RDKBROWSER_TEST_LOG_H
#define RDKBROWSER_TEST_LOG_H

#include "../logger.h"

#define RBTLOGD(...) RDKLOG_VERBOSE(__VA_ARGS__)
#define RBTLOGN(...) RDKLOG_INFO(__VA_ARGS__)
#define RBTLOGW(...) RDKLOG_WARNING(__VA_ARGS__)
#define RBTLOGF(...) RDKLOG_ERROR(__VA_ARGS__)

#endif // RDKBROWSER_TEST_LOG_H
