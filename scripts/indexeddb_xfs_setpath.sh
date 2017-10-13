#!/bin/bash

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
