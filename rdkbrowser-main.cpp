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
#ifdef USE_BREAKPAD
#include <client/linux/handler/exception_handler.h>
#endif
#include "rdkbrowser.h"
#include "logger.h"
#include "glib_utils.h"
#include "rdkbrowser_server.h"
#include "hangdetector_utils.h"

#include <rtRemote.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <map>


#if defined(HAS_SYSTEMD_JOURNAL) && HAS_SYSTEMD_JOURNAL
#include <systemd/sd-journal.h>
#endif

#include <glib-unix.h>

#ifndef RT_ASSERT
#define RT_ASSERT(E) if ((E) != RT_OK) { printf("failed: %d, %d\n", (E), __LINE__); assert(false); }
#endif

using namespace RDK;

GMainLoop* gLoop;
int gPipefd[2];

/**
 * Callback for rtRemote logs.
 */
static void rtRemoteLogHandler(rtLogLevel level, const char* file, int line, int threadID, char* message)
{
    LogLevel logLevel;
    switch (level)
    {
        case RT_LOG_DEBUG:
            logLevel = VERBOSE_LEVEL;
            break;
        case RT_LOG_INFO:
            logLevel = INFO_LEVEL;
            break;
        case RT_LOG_WARN:
            logLevel = WARNING_LEVEL;
            break;
        case RT_LOG_ERROR:
            logLevel = ERROR_LEVEL;
            break;
        case RT_LOG_FATAL:
            logLevel = FATAL_LEVEL;
            break;
        default:
            logLevel = INFO_LEVEL;
            break;
    }

    RDK::log(logLevel, "rtLog", file, line, threadID, "%s", message);
}

// only in standalone mode
static rtError onWindowCloseRequest(int /*numArgs*/, const rtValue* /*args*/, rtValue* /*result*/, void* context)
{
    RDKLOG_WARNING("Got window.close request... closing the page and exiting");
    rtObjectRef browserObj = (rtIObject*)context;
    browserObj.send("close");
    g_timeout_add(0, [](gpointer) -> gboolean {
       g_main_loop_quit(gLoop);
       return G_SOURCE_REMOVE;
    }, nullptr);
    return RT_OK;
}

void rtMainLoopCb(void*)
{
  rtError err;
  err = rtRemoteProcessSingleItem();
  if (err == RT_ERROR_QUEUE_EMPTY)
   RDKLOG_TRACE("queue was empty upon processing event");
  else if (err != RT_OK)
   RDKLOG_WARNING("rtRemoteProcessSingleItem() returned %d", err);
}

void rtRemoteCallback(void*)
{
  RDKLOG_TRACE("queueReadyHandler entered");
  static char temp[1];
  int ret = HANDLE_EINTR_EAGAIN(write(gPipefd[PIPE_WRITE], temp, 1));
  if (ret == -1)
    perror("can't write to pipe");
}

gboolean handleStdOutCrash(gint fd, GIOCondition condition, gpointer)
{
    if (fd != STDOUT_FILENO)
        return TRUE;

    if (!(condition & (G_IO_ERR | G_IO_HUP)))
        return TRUE;

    int newfd = -1;

#if defined(HAS_SYSTEMD_JOURNAL) && HAS_SYSTEMD_JOURNAL
    newfd = sd_journal_stream_fd(nullptr, LOG_INFO, 0);
#endif

    if (newfd < 0)
        newfd = open("/dev/null", O_WRONLY);

    if (newfd > 0)
    {
        dup3(newfd, STDOUT_FILENO, 0);
        dup3(newfd, STDERR_FILENO, 0);
        g_unix_fd_add(STDOUT_FILENO, static_cast<GIOCondition>(G_IO_ERR | G_IO_HUP), handleStdOutCrash, nullptr);
    }

    return FALSE;
}

int main(int argc, char** argv)
{
    g_unix_fd_add(STDOUT_FILENO, static_cast<GIOCondition>(G_IO_ERR | G_IO_HUP), handleStdOutCrash, nullptr);

    Utils::HangDetector hangDetector;
    hangDetector.start();

#ifdef USE_BREAKPAD
    google_breakpad::MinidumpDescriptor descriptor("/opt/minidumps");
    google_breakpad::ExceptionHandler eh(descriptor, NULL,
        [](const google_breakpad::MinidumpDescriptor&, void*, bool succeeded)
        { return succeeded; },
        NULL, true, -1);
#endif
    logger_init();
    rtLogSetLogHandler(rtRemoteLogHandler);

    rtLogWarn("rdkbrowser2 started");

    rtError e = RT_OK;
    const char* objectName = getenv("PX_WAYLAND_CLIENT_REMOTE_OBJECT_NAME");

    bool nonCompositedWebGLEnabled = false;
    bool startServer = false;
    const char* url = nullptr;
    for (int i = 1; !startServer && i < argc; ++i)
    {
        static const std::string serverArgName = "--server";
        startServer = (0 == serverArgName.compare(argv[i]));

        static const std::string nonCompositedWebGLEnabledArgName = "--nonCompositedWebGLEnabled";
        nonCompositedWebGLEnabled = (0 == nonCompositedWebGLEnabledArgName.compare(argv[i]));

        static const std::string urlArgName = "--url";
        if (urlArgName.compare(argv[i]) == 0 && i + 1 < argc)
        {
            url = argv[++i];
            objectName = "wl-rdkbrowser2-standalone";
        }
    }

    if (objectName == nullptr && startServer == false && url == nullptr)
    {
        RDKLOG_ERROR("Invalid arguments. Cannot start.");
        return 1;
    }

    /* start the gmain loop */
    gLoop = g_main_loop_new(g_main_context_default(), FALSE);


    auto *source = pipe_source_new(gPipefd, rtMainLoopCb, nullptr);
    g_source_attach(source, g_main_loop_get_context(gLoop));

    rtRemoteRegisterQueueReadyHandler( rtEnvironmentGetGlobal(), rtRemoteCallback, nullptr );

    e = rtRemoteInit();
    if (e != RT_OK)
    {
        rtLogError("failed to initialize rtRemoteInit: %d", e);
        return 1;
    }

    rtObject *hostObject = nullptr;
    if (startServer)
    {
        rtLogInfo("starting RDKBrowser server");
        objectName = RDK_BROWSER_SERVER_OBJECT_NAME;
        hostObject = new RDKBrowserServer();
    }
    else
    {
        const char* displayName = getenv("WAYLAND_DISPLAY");
        if( displayName == nullptr)
        {
            RDKLOG_ERROR("Wayland Display name empty.");
            return 1;
        }
        hostObject = new RDKBrowser(displayName, false, nonCompositedWebGLEnabled);
    }

    if(nullptr == hostObject)
    {
        rtLogError("failed to instantiate RDKBrowser");
        return 1;
    }

    rtObjectRef obj(hostObject);
    e = rtRemoteRegisterObject(objectName, obj);
    if (e != RT_OK)
    {
        rtLogError("failed to register remote object rtRemoteRegisterObject: %d", e);
        return 1;
    }

    if (url != nullptr)
    {
        // We're running in standalone mode
        obj.set("localStorageEnabled", true);
        obj.set("url", url);
        obj.set("webAutomationEnabled", true);
        obj.set("allowScriptsToCloseWindow", true);
        obj.send("on", "onWindowCloseRequest", new rtFunctionCallback(onWindowCloseRequest, obj.getPtr()));
    }

    g_main_loop_run(gLoop);
    rtRemoteShutdown();
    g_source_unref(source);

    return 0;
}
