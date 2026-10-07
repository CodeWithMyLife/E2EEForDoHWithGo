#!/system/bin/sh
# Fastime 手动启动脚本（Magisk / root 环境，带状态反馈）
#
# 用法：
#   sh start.sh                    # 用编译注入的默认配置启动
#   sh start.sh -log debug         # 追加任意 fastime 参数，原样传给 fastime
#
# root 启动时自动代管 /system/etc/resolv.conf（bind mount 运行目录下的
# fastime-resolv.conf，内容为当前在用网络的真实 DNS，切网/每 5 分钟更新），
# 正常停止时自动卸载。
#
# 环境变量（可选）：
#   FASTIME_BIN=/sdcard/fastime/fastime  覆盖二进制位置（默认 = 脚本同目录/fastime）
#   FASTIME_LOG=/sdcard/fastime.log      覆盖日志位置（默认 = 脚本同目录/fastime.log）

MODDIR=${0%/*}
BIN=${FASTIME_BIN:-$MODDIR/fastime}
LOG=${FASTIME_LOG:-$MODDIR/fastime.log}

if [ ! -f "$BIN" ]; then
  echo "[FAIL] 找不到二进制: $BIN（可用 FASTIME_BIN 指定）"
  exit 1
fi

if [ "$(id -u)" != "0" ]; then
  echo "[WARN] 当前不是 root：resolv.conf 代管不可用（服务本身照常运行）"
fi

NAME=${BIN##*/}
if pidof "$NAME" >/dev/null 2>&1; then
  echo "[SKIP] fastime 已在运行 PID=$(pidof "$NAME")"
  exit 0
fi

chmod 755 "$BIN" 2>/dev/null
cd "$MODDIR" || exit 1   # 缓存/IP 段表/resolv 源文件都写在运行目录下
nohup "$BIN" "$@" > "$LOG" 2>&1 &
sleep 2

if pidof "$NAME" >/dev/null 2>&1; then
  PID=$(pidof "$NAME")
  echo "[OK] 启动成功 PID=$PID"
  grep -m1 '监听于' "$LOG" 2>/dev/null | sed 's/^/[OK] /'
  echo "[OK] 日志: tail -f $LOG"
  echo "[OK] 停止: sh $MODDIR/stop.sh"
else
  echo "[FAIL] 启动失败，最近日志："
  tail -n 20 "$LOG" 2>/dev/null || echo "(日志文件为空或不存在)"
  exit 1
fi
