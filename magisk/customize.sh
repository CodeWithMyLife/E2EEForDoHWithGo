#!/system/bin/sh
# Magisk customize.sh：安装时检查架构并设置权限
ui_print "- 安装 Fastime 模块"

if [ "$ARCH" != "arm64" ]; then
  abort "! 仅支持 arm64 设备，当前架构: $ARCH"
fi

set_perm "$MODPATH/fastime" 0 0 0755
set_perm "$MODPATH/start.sh" 0 0 0755
set_perm "$MODPATH/stop.sh" 0 0 0755
# Java 层 DNS 助手 dex（root 探测系统 DNS 用），与二进制同目录即被自动加载
[ -f "$MODPATH/fastime-dns.dex" ] && set_perm "$MODPATH/fastime-dns.dex" 0 0 0644
ui_print "- 完成（本模块不开机自启，仅安装文件）"
ui_print "- 手动启动: sh /data/adb/modules/fastime/start.sh"
ui_print "- 手动停止: sh /data/adb/modules/fastime/stop.sh"
