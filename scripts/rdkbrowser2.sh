#!/bin/bash
#
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
# Copyright 2016 RDK Management
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
#

. /etc/device.properties

if [ -f /etc/device.runXRE.properties ]; then
    . /etc/device.runXRE.properties
fi

if [ -f /opt/SetEnv.sh ] && [ "$BUILD_TYPE" != "prod" ]; then
    . /opt/SetEnv.sh
fi

#check for certificate revocation (OCSP stapling)
export G_TLS_OPENSSL_OCSP_ENABLED=1

export XDG_RUNTIME_DIR=/tmp
export LD_PRELOAD=/usr/lib/libwayland-client.so.0:/usr/lib/libwayland-egl.so.0
export WAYLAND_DISPLAY=main0
export PREDEFINED_CODEC_SET=1
export OPENSSL_armcap=0

export XDG_CONFIG_HOME=/opt/.config
export XDG_DATA_HOME=/opt/QT/home
export XDG_CACHE_HOME=/opt/QT/cache

export JSC_useOSREntryToDFG=false

export WEBKIT_LEGACY_INSPECTOR_SERVER=${WEBKIT_LEGACY_INSPECTOR_SERVER:-':::9224'}
export WPE_DISK_CACHE_SIZE=${WPE_DISK_CACHE_SIZE:-10m}
export WPE_RAM_SIZE=${WPE_RAM_SIZE:-192m}
export WPE_POLL_MAX_MEMORY=${WPE_POLL_MAX_MEMORY:-'WPEWebProcess:200M,*Process:50M'}

#export RDKBROWSER2_CLEAN_EXIT_WEBPROCESS=1
#export RDKBROWSER2_DISABLE_INJECTED_BUNDLE=1
#export RDKBROWSER2_TEST_HANG_DETECTOR=1
#export RDKBROWSER2_DISABLE_WEBPROCESS_WATCHDOG=1
#export RDKBROWSER2_IGNORE_TLS_ERRORS=1
#export RDKBROWSER2_ENABLE_EPHEMERAL_MODE=1

if [ "$SD_CARD_MOUNT_PATH" = "" ]; then
    SD_CARD_MOUNT_PATH=`cat  /proc/mounts | grep mmcblk0p1 | awk '{print $2}' `
fi
if [ "$SD_CARD_MOUNT_PATH" != "" ]; then
    isSDCardMounted=`cat  /proc/mounts | grep "$SD_CARD_MOUNT_PATH" `
    if [ "$isSDCardMounted" != "" ]; then
        export XDG_CACHE_HOME="${SD_CARD_MOUNT_PATH}/QT/cache"
    fi
fi

if [ -f /lib/rdk/getRFC.sh ]; then
    . /lib/rdk/getRFC.sh WPEWidevine
fi

if [ -f /lib/rdk/getRFC.sh ]; then
    . /lib/rdk/getRFC.sh AAMP_WESTEROS_SINK
fi

# enable Widevine support in WPE if RFC param is set
if [ "xtrue" = "x$RFC_ENABLE_WPEWidevine" ]; then
    echo "Enabling Widevine support in WPE!"
    export WPE_ENABLE_WIDEVINE=1
fi


if [ -f /lib/rdk/rdkbrowser2_init.sh ]; then
    . /lib/rdk/rdkbrowser2_init.sh
fi

if [ ! -z "$RFC_ENABLE_AAMP_WESTEROS_SINK" ]; then
    export AAMP_ENABLE_WESTEROS_SINK=$(echo $RFC_ENABLE_AAMP_WESTEROS_SINK)
    echo "AAMP_ENABLE_WESTEROS_SINK=$AAMP_ENABLE_WESTEROS_SINK !"
fi

# WPE extension library
export RDKBROWSER2_INJECTED_BUNDLE_LIB=${RDKBROWSER2_INJECTED_BUNDLE_LIB:-'libComcastInjectedBundle.so'}

# AAMP
export ENABLE_AAMP=${ENABLE_AAMP:-'TRUE'}

# Web-inspector rdm
export WEBKIT_INSPECTOR_RESOURCES_PATH=/media/apps/web-inspector-plugin/usr/lib:/tmp/web-inspector-plugin/usr/lib
export WEBKIT_INSPECTOR_RESOURCES_PATH=$WEBKIT_INSPECTOR_RESOURCES_PATH:/media/apps/web-inspector-plugin/usr/lib/wpe-webkit-0.1
export WEBKIT_INSPECTOR_RESOURCES_PATH=$WEBKIT_INSPECTOR_RESOURCES_PATH:/tmp/web-inspector-plugin/usr/lib/wpe-webkit-0.1

systemctl stop lxc xre-receiver
killall westeros WPEWebProcess WPENetworkProcess rdkbrowser2

trap 'killall westeros WPEWebProcess WPENetworkProcess rdkbrowser2' EXIT


url=http://www.example.com

if [ -n "$1" ]; then
    url="$1"
fi

if [ "$MODEL_NUM" = "PX001AN" ]; then
    WESTEROS_LIB=libwesteros_render_gl.so.0.0.0
elif [ "$BOX_TYPE" = "pi" ]; then
    WESTEROS_LIB=libwesteros_render_dispmanx.so.0
else
    WESTEROS_LIB=libwesteros_render_nexus.so.0.0.0
fi

if [ "$SOC" = "RTK" ]; then
    export LD_PRELOAD=/usr/lib/libwesteros_gl.so.0:$LD_PRELOAD
    WESTEROS_LIB=libwesteros_render_gl.so.0
fi

westeros --renderer $WESTEROS_LIB --framerate 60 --display "${WAYLAND_DISPLAY}" >> /opt/logs/westeros.log 2>&1 &

# let Westeros initialize
if [ -n "${SLEEP_AFTER_WESTEROS_START}" ]; then
    sleep 1
fi

time rdkbrowser2 --url "$url" 2>&1
