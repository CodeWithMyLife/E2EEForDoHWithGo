#!/system/bin/sh
# Magisk service.sh：开机 late-start 阶段以 root 执行
MODDIR=${0%/*}
BIN=$MODDIR/fastime

# 等网络就绪再启动（最多等 60 秒）
i=0
while [ $i -lt 30 ]; do
  if ping -c 1 -W 2 223.5.5.5 >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 2
done

chmod 755 "$BIN"
# 日志输出到模块目录，logcat 无需 root 也能查问题时用
nohup "$BIN" > "$MODDIR/fastime.log" 2>&1 &
