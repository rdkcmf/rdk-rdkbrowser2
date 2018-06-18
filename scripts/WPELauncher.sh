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

. /etc/common.properties
. /etc/device.properties

XDG_CONFIG_HOME=$PERSISTENT_PATH/.config
XDG_DATA_HOME=$PERSISTENT_PATH/QT/home
XDG_CACHE_HOME=$CACHE_PATH/QT/cache

if [ -f /etc/device.runXRE.properties ]; then
    . /etc/device.runXRE.properties
fi

export XDG_RUNTIME_DIR=/tmp
export LD_PRELOAD=/usr/lib/libwayland-client.so.0:/usr/lib/libwayland-egl.so.0
export WAYLAND_DISPLAY=main0
export WEBKIT_INSPECTOR_SERVER=:::9222
export PREDEFINED_CODEC_SET=1
export OPENSSL_armcap=0

systemctl stop lxc xre-receiver
killall westeros WPEWebProcess WPENetworkProcess WPEDatabaseProcess

trap 'killall westeros WPEWebProcess WPENetworkProcess WPEDatabaseProcess' EXIT


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

time WPELauncher "$url" 2>&1

