#!/bin/bash

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
