#!/system/bin/sh
# Fastime 手动停止脚本（带状态反馈）
if ! pidof fastime >/dev/null 2>&1; then
  echo "[SKIP] fastime 未在运行"
  exit 0
fi

OLD_PID=$(pidof fastime)
pkill -x fastime
sleep 1

if pidof fastime >/dev/null 2>&1; then
  echo "[FAIL] 停止失败，仍在运行 PID=$(pidof fastime)，尝试强制结束..."
  kill -9 $(pidof fastime) 2>/dev/null
  sleep 1
  if pidof fastime >/dev/null 2>&1; then
    echo "[FAIL] 强制结束也失败，请手动处理 PID=$(pidof fastime)"
    exit 1
  fi
fi

echo "[OK] 已停止 (原 PID=$OLD_PID)"
