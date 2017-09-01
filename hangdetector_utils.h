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
#ifndef HANGDETECTOR_UTILS_H
#define HANGDETECTOR_UTILS_H

#include <glib.h>
#include "logger.h"

#include <thread>
#include <atomic>
#include <sys/types.h>
#include <unistd.h>

namespace Utils
{

class HangDetector
{
    std::unique_ptr<std::thread> m_thread;
    std::atomic_bool m_running {false};
    std::atomic_int  m_resetCount {0};
    std::atomic_int m_threshold {30};
    guint m_timerSource {0};

    void runWatchDog()
    {
        while(m_running)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (m_resetCount > m_threshold)
            {
                printf("hang detected\n"); fflush(stdout);
                kill(getpid(), SIGFPE);
            }
            ++m_resetCount;
        }
    }

    void resetWatchDog()
    {
        m_resetCount = 0;
    }

    void initThreshold()
    {
        const char* var = getenv("RDKBROWSER2_HANG_DETECTOR_THRESHOLD_SEC");
        if (var)
        {
            try
            {
                int tmp = std::atoi(var);
                if (tmp > 5)
                {
                    m_threshold = tmp;
                }
            } catch (...) {}
        }
    }

public:
    ~HangDetector()
    {
        stop();
    }

    void start()
    {
        if (m_thread)
            return;
        initThreshold();

        m_running = true;

        gint priority = getenv("RDKBROWSER2_HANG_DETECTOR_PRIORITY_DEFAULT") ? G_PRIORITY_DEFAULT : G_PRIORITY_HIGH;
        m_timerSource = g_timeout_add_seconds_full
        (
            priority,
            1, // Timeout in seconds
            [](gpointer data) -> gboolean
            {
                static_cast<HangDetector*>(data)->resetWatchDog();
                return G_SOURCE_CONTINUE;
            },
            this,
            nullptr
        );

        m_thread.reset(new std::thread(&HangDetector::runWatchDog, this));
    }

    void stop()
    {
        m_running = false;
        g_source_remove(m_timerSource);
        m_timerSource = 0;
        m_thread->join();
        m_thread.reset(nullptr);
    }
};

} // namespace utils

#endif // HANGDETECTOR_H
