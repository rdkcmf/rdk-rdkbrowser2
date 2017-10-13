#/bin/bash

. /etc/device.properties

if [ -f /etc/device.runXRE.properties ]; then
    . /etc/device.runXRE.properties
fi

export XDG_RUNTIME_DIR=/tmp
export LD_PRELOAD=/usr/lib/libwayland-client.so.0:/usr/lib/libwayland-egl.so.0
export WAYLAND_DISPLAY=main0
export WEBKIT_INSPECTOR_SERVER=:::9222
export PREDEFINED_CODEC_SET=1
export OPENSSL_armcap=0

export XDG_CONFIG_HOME=/opt/.config
export XDG_DATA_HOME=/opt/QT/home
export XDG_CACHE_HOME=/opt/QT/cache

if [ "$SD_CARD_MOUNT_PATH" = "" ]; then
    SD_CARD_MOUNT_PATH=`cat  /proc/mounts | grep mmcblk0p1 | awk '{print $2}' `
fi
if [ "$SD_CARD_MOUNT_PATH" != "" ]; then
    isSDCardMounted=`cat  /proc/mounts | grep "$SD_CARD_MOUNT_PATH" `
    if [ "$isSDCardMounted" != "" ]; then
        export XDG_CACHE_HOME="${SD_CARD_MOUNT_PATH}/QT/cache"
        export RDKBROWSER2_INDEXED_DB_DIR=$SD_CARD_MOUNT_PATH
    fi
fi

if [ "$HDD_ENABLED" = "true" ]; then
    if [ -f /usr/bin/indexeddb_xfs_setpath.sh ]; then
        . /usr/bin/indexeddb_xfs_setpath.sh
    fi
fi

systemctl stop lxc xre-receiver
killall westeros WPEWebProcess WPENetworkProcess rdkbrowser2

trap 'killall westeros WPEWebProcess WPENetworkProcess rdkbrowser2' EXIT


url=http://www.example.com

if [ -n "$1" ]; then
    url="$1"
fi

if [ "$MODEL_NUM" = "PX001AN" ]; then
    WESTEROS_LIB=libwesteros_render_gl.so.0.0.0
else
    WESTEROS_LIB=libwesteros_render_nexus.so.0.0.0
fi

westeros --renderer $WESTEROS_LIB --framerate 60 --display "${WAYLAND_DISPLAY}" >> /opt/logs/westeros.log 2>&1 &

# let Westeros initialize
if [ -n "${SLEEP_AFTER_WESTEROS_START}" ]; then
    sleep 1
fi

time rdkbrowser2 --url "$url" 2>&1
