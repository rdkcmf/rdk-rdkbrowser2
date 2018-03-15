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
    if [ -f /usr/bin/indexeddb_xfs_setpath.sh ]; then
        . /usr/bin/indexeddb_xfs_setpath.sh
    fi

    if [ "$RDKBROWSER2_INDEXED_DB_DIR" != "" ]; then
        XFS_INDEXEDDB_PATH="$RDKBROWSER2_INDEXED_DB_DIR/wpe/databases"
        if [ -d "$XFS_INDEXEDDB_PATH" ]; then
            echo "[IndexedDB] Deleting database folder $XFS_INDEXEDDB_PATH in XFS partition"
            rm -rf "$XFS_INDEXEDDB_PATH"
        fi
        if [ ! -d "$XFS_INDEXEDDB_PATH" ]; then
            echo "[IndexedDB] Recreating database folder $XFS_INDEXEDDB_PATH in XFS partition"
            mkdir -p "$XFS_INDEXEDDB_PATH"
            xfs_io -c 'chattr +t' "$XFS_INDEXEDDB_PATH"
        fi
    fi
fi
