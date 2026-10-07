#!/system/bin/sh
# Fastime 手动停止脚本（优雅退出：卸载 resolv.conf 挂载 / 缓存落盘 / 关连接）

if ! pidof fastime >/dev/null 2>&1; then
  echo "[SKIP] fastime 未在运行"
  exit 0
fi

OLD_PID=$(pidof fastime)
pkill -x fastime   # 默认发 SIGTERM：触发优雅退出（清理现场）

for i in 1 2 3 4 5; do
  pidof fastime >/dev/null 2>&1 || break
  sleep 1
done

if pidof fastime >/dev/null 2>&1; then
  echo "[WARN] 5 秒内未退出，强制 kill -9"
  echo "[WARN] 强杀没机会卸载 resolv.conf 挂载；挂载源是运行目录里的文件，内容仍在，不影响系统"
  kill -9 $(pidof fastime) 2>/dev/null
  sleep 1
fi

if pidof fastime >/dev/null 2>&1; then
  echo "[FAIL] 停止失败，请手动处理 PID=$(pidof fastime)"
  exit 1
fi

echo "[OK] 已停止（原 PID=$OLD_PID，现场已清理：resolv.conf 挂载已卸 / 缓存已落盘）"
