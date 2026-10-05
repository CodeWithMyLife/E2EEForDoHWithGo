#!/system/bin/sh
# Fastime 手动停止脚本（优雅退出：撤 53 劫持 iptables 规则 / 恢复系统 DNS / 缓存落盘）

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
  echo "[WARN] 强杀不会清理现场：若开过 -hijack-dns true，残留的 iptables 规则会让 53 端口断流"
  echo "[WARN] 恢复办法：重新启动一次 fastime 再正常停止，或重启手机"
  kill -9 $(pidof fastime) 2>/dev/null
  sleep 1
fi

if pidof fastime >/dev/null 2>&1; then
  echo "[FAIL] 停止失败，请手动处理 PID=$(pidof fastime)"
  exit 1
fi

echo "[OK] 已停止（原 PID=$OLD_PID，现场已清理：iptables 规则已撤 / 缓存已落盘）"
