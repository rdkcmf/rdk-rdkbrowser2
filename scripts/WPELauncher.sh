#/bin/bash

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

time WPELauncher "$url" 2>&1 | tee -a /opt/logs/wpe.log

