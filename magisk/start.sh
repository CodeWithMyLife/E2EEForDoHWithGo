#!/system/bin/sh
# Fastime 手动启动脚本（带状态反馈）
MODDIR=${0%/*}
BIN=$MODDIR/fastime
LOG=$MODDIR/fastime.log

if pidof fastime >/dev/null 2>&1; then
  echo "[SKIP] fastime 已在运行 PID=$(pidof fastime)"
  exit 0
fi

chmod 755 "$BIN"
nohup "$BIN" > "$LOG" 2>&1 &
sleep 1

if pidof fastime >/dev/null 2>&1; then
  echo "[OK] 启动成功 PID=$(pidof fastime)"
  echo "[OK] 日志: tail -f $LOG"
else
  echo "[FAIL] 启动失败，最近日志："
  tail -n 20 "$LOG" 2>/dev/null || echo "(日志文件为空或不存在)"
  exit 1
fi
