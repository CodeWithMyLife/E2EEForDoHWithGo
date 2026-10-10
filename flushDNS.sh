#!/system/bin/sh
# mihomo DNS 缓存清理脚本（Android root 环境）
# 用法: sh flush_dns.sh [--fakeip]

# ====== 按实际情况修改这三项 ======
API_HOST="127.0.0.1"
API_PORT="9090"
SECRET=""          # external-controller 的 secret，没设就留空
# =================================

FLUSH_FAKEIP=0
[ "$1" = "--fakeip" ] && FLUSH_FAKEIP=1

AUTH_HEADER=""
[ -n "$SECRET" ] && AUTH_HEADER="Authorization: Bearer ${SECRET}"

# POST 一个路径，打印结果；返回 0 表示成功
api_post() {
    _path="$1"

    if command -v curl >/dev/null 2>&1; then
        # 方式一：curl（部分 Magisk 模块自带，或你装了 curl）
        _code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
            -X POST ${SECRET:+-H "$AUTH_HEADER"} \
            "http://${API_HOST}:${API_PORT}${_path}")
        [ "$_code" = "204" ] || [ "$_code" = "200" ]

    elif command -v wget >/dev/null 2>&1; then
        # 方式二：wget（busybox/toybox 常见）
        wget -q -T 5 -O /dev/null \
            --method=POST ${SECRET:+--header="$AUTH_HEADER"} \
            "http://${API_HOST}:${API_PORT}${_path}"

    elif command -v nc >/dev/null 2>&1; then
        # 方式三：纯 nc 发 HTTP 请求（无外部依赖兜底）
        _resp=$(printf 'POST %s HTTP/1.1\r\nHost: %s:%s\r\n%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
            "$_path" "$API_HOST" "$API_PORT" "$AUTH_HEADER" \
            | nc -w 5 "$API_HOST" "$API_PORT" | head -n 1)
        echo "$_resp" | grep -qE " 20[04] "

    else
        echo "[-] 找不到 curl/wget/nc，无法发送请求"
        return 1
    fi
}

echo "[*] 清空 DNS 解析缓存..."
if api_post "/cache/dns/flush"; then
    echo "[+] DNS 缓存已清空"
else
    echo "[-] 清空失败：请检查 external-controller 地址/端口/secret，以及核心是否在运行"
    exit 1
fi

if [ "$FLUSH_FAKEIP" = "1" ]; then
    echo "[*] 清空 fake-ip 映射缓存..."
    if api_post "/cache/fakeip/flush"; then
        echo "[+] fake-ip 缓存已清空"
    else
        echo "[-] fake-ip 清空失败"
        exit 1
    fi
fi

exit 0
