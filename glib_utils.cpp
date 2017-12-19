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
#include "glib_utils.h"

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>

class EventSource {
public:
  static GSourceFuncs sourceFuncs;
  GSource src;
  GPollFD pfd;
  PipeSourceCallback cb;
  void* ctx;
};

gboolean g_prepare  (GSource*, gint *timeout_)
{
  *timeout_ = -1;
  return FALSE;
}
gboolean g_check    (GSource    *base)
{
  auto* source = reinterpret_cast<EventSource*>(base);
  return !!source->pfd.revents;
}
gboolean g_dispatch (GSource    *base,
                    GSourceFunc /*callback*/,
                    gpointer    /*user_data*/)
{
  auto* source = reinterpret_cast<EventSource*>(base);
  if (source->pfd.revents & G_IO_IN)
  {
    // read one byte from file
    // and fire callback
    // thread will not block here.
    static char discard[1];
    int ret = HANDLE_EINTR_EAGAIN(read(source->pfd.fd, discard, 1));
    if (-1 == ret)
      perror("unable to read from pipe");

    source->cb(source->ctx);
  }

  if (source->pfd.revents & (G_IO_ERR | G_IO_HUP))
  {
    // TODO: improve logging?
    puts("ERROR during read from file descriptor");
    return FALSE;
  }

  source->pfd.revents = 0;
  return TRUE;
}

GSourceFuncs EventSource::sourceFuncs =
{
  g_prepare,
  g_check,
  g_dispatch,
  NULL,
  NULL, // closure_callback
  NULL //closure_marshal;
};

GSource* pipe_source_new(int pipefd[2], PipeSourceCallback cb, void* ctx)
{
  // create source
  auto* Esource = (EventSource*)g_source_new(&EventSource::sourceFuncs, sizeof(EventSource));

  auto* source = (GSource*) Esource;

  // create pipe
  int ret = pipe2(pipefd, O_CLOEXEC);
  if (ret == -1)
    perror("can't create pipe");

  // attach pipe out FD to source
  Esource->pfd.fd = pipefd[PIPE_LISTEN];
  Esource->pfd.events = G_IO_IN | G_IO_ERR | G_IO_HUP;
  Esource->pfd.revents = 0;
  Esource->cb = cb;
  Esource->ctx = ctx;
  g_source_add_poll(source, &Esource->pfd);

  g_source_set_name(source, "rtRemoteSource");
  g_source_set_priority(source, G_PRIORITY_DEFAULT);
  g_source_set_can_recurse(source, TRUE);

  return source;
}
