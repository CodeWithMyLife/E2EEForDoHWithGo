#!/system/bin/sh
# Magisk customize.sh：安装时检查架构并设置权限
ui_print "- 安装 Fastime 模块"

if [ "$ARCH" != "arm64" ]; then
  abort "! 仅支持 arm64 设备，当前架构: $ARCH"
fi

set_perm "$MODPATH/fastime" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
ui_print "- 完成，重启后自动启动"
