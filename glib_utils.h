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
#ifndef GLIB_UTILS_H
#define GLIB_UTILS_H

#include <glib.h>


constexpr int eintr_maximum_attempts =100;
#define HANDLE_EINTR_EAGAIN(x) ({            \
  unsigned char _attempts = 0;               \
                                             \
  decltype(x) _result;                       \
                                             \
  do                                         \
  {                                          \
    _result = (x);                           \
  }                                          \
  while (_result == -1                       \
         && (errno == EINTR ||               \
             errno == EAGAIN ||              \
             errno == EWOULDBLOCK)           \
         && _attempts++ < eintr_maximum_attempts); \
                                             \
  _result;                                   \
})

constexpr int PIPE_LISTEN = 0, PIPE_WRITE = 1;
typedef void (*PipeSourceCallback)(void* ctx);

GSource* pipe_source_new(int pipefd[2], PipeSourceCallback cb, void* ctx);

#endif // GLIB_UTILS_H
