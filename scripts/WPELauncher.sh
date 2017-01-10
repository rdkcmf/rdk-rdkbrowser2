#/bin/bash

export XDG_RUNTIME_DIR=/tmp
export LD_PRELOAD=/usr/lib/libwayland-client.so.0:/usr/lib/libwayland-egl.so.0
export WAYLAND_DISPLAY=main0
export WEBKIT_INSPECTOR_SERVER=0.0.0.0:9222
export PREDEFINED_CODEC_SET=1
export OPENSSL_armcap=0

systemctl stop lxc xre-receiver
killall westeros WPEWebProcess WPENetworkProcess

trap 'killall westeros WPEWebProcess WPENetworkProcess' EXIT


url=http://www.example.com

if [ -n "$1" ]; then
    url="$1"
fi

westeros --renderer libwesteros_render_nexus.so.0.0.0 --framerate 60 --display "${WAYLAND_DISPLAY}" >> /opt/logs/westeros.log 2>&1 &
WPELauncher "$url" 2>&1 | tee -a /opt/logs/wpe.log