#!/bin/bash
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
# Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

. /etc/device.properties

if [ "$HDD_ENABLED" = "true" ]; then
    XFS_MOUNT_PATH=`cat /proc/mounts | grep -m 1 rtdev | awk '{print $2}'`

    if [ "$XFS_MOUNT_PATH" != "" ]; then
        echo "[IndexedDB] XFS_MOUNT_PATH = $XFS_MOUNT_PATH"
        if [ -d "$XFS_MOUNT_PATH/data" ]; then
            RDKBROWSER2_INDEXED_DB_DIR="$XFS_MOUNT_PATH/data"
        else
            RDKBROWSER2_INDEXED_DB_DIR="$XFS_MOUNT_PATH"
        fi
        echo "[IndexedDB] HDD enabled, RDKBROWSER2_INDEXED_DB_DIR = $RDKBROWSER2_INDEXED_DB_DIR"
        export RDKBROWSER2_INDEXED_DB_DIR
    fi
fi
