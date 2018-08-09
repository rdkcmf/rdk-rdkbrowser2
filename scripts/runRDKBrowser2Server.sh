#!/bin/sh
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

killall rdkbrowser2 WPEWebProcess WPENetworkProcess

if [ -f /etc/soc.runXRE.properties ]; then
    source /etc/soc.runXRE.properties
fi

source /etc/device.properties

#TODO review if brcm only?
export NUM_SURFACE_PERCLIENT=2

export CAIRO_GL_COMPOSITOR=noaa
export WAYLAND_EGL_PRELOAD=/usr/lib/libwayland-client.so.0:/usr/lib/libwayland-egl.so.0

#inherited from runXRE
export WESTEROS_FORWARD_CLIENT_STDOUT=1

export XDG_CACHE_HOME=/opt/QT/cache
export XDG_CONFIG_HOME=/opt/.config
export XDG_DATA_HOME=/opt/QT/home
export XDG_RUNTIME_DIR=/tmp

export LOG4C_RCPATH=/etc
export FONTCONFIG_PATH=/etc/fonts

#resource management
export WPE_DISK_CACHE_SIZE=10m
export WPE_RAM_SIZE=192m
export WPE_POLL_MAX_MEMORY='WPEWebProcess:200M,*Process:50M'

export RDKBROWSER2_WEBPROCESS_START_DELAY=5000

export JSC_useOSREntryToDFG=false

export GST_REGISTRY_FORK=no
export GST_REGISTRY="/opt/.gstreamer/registry.bin"

# let xre receiver update gst registry
export GST_REGISTRY_UPDATE=no


#update XDG_CACHE_HOME for Xi devices
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


if [ -f /lib/rdk/getRFC.sh ]; then
    . /lib/rdk/getRFC.sh WEBKIT_INSPECTOR
fi

if [ -f /opt/SetEnv.sh ] && [ "$BUILD_TYPE" != "prod" ]; then
    . /opt/SetEnv.sh
fi

if [ -f /opt/webprocess_clean_exit ] ; then
    export RDKBROWSER2_CLEAN_EXIT_WEBPROCESS=1
fi

if [ -z "$RDKBROWSER2_INJECTED_BUNDLE_LIB" ]; then
    export RDKBROWSER2_INJECTED_BUNDLE_LIB=libComcastInjectedBundle.so
fi

if [ -n "$WAYLAND_EGL_PRELOAD" ]; then
    export LD_PRELOAD=$WAYLAND_EGL_PRELOAD
fi

if [ "xtrue" = "x$RFC_ENABLE_WEBKIT_INSPECTOR" -o "x1" = "x$RFC_ENABLE_WEBKIT_INSPECTOR" ]; then
    echo "Using WEBKIT_INSPECTOR remote feature config: RFC_ENABLE_WEBKIT_INSPECTOR=$RFC_ENABLE_WEBKIT_INSPECTOR"
    export WEBKIT_INSPECTOR_SERVER=:::9224
else
    unset WEBKIT_INSPECTOR_SERVER
fi

#Enabling core dump generation.
ulimit -c unlimited

#limiting stack size
ulimit -S -s 260


while [ ! -e '/opt/disable_rdkbrowser2_server' ]; do
    if [ ! -e '/usr/bin/rdkbrowser2' ]; then
        exit 0;
    fi
    if [ -f /opt/wpe_debug_media ]; then
        export GST_DEBUG='*wpe*:7,3'
        export WEBKIT_DEBUG='Media,MediaSource,ResourceLoading'
        /usr/bin/rdkbrowser2 --server >> /opt/logs/wpe.log 2>&1
    else
        /usr/bin/rdkbrowser2 --server
    fi
done
