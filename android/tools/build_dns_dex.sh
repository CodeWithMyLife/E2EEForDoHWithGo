#!/bin/bash
# 编译 FastimeDns.java → classes.dex → base64（单行输出到 stdout）。
# 供 CI 在构建 Android 二进制前执行，结果经 -ldflags -X fastime/core.cfgDnsDexB64 注入。
# 依赖：JDK（javac）+ Android SDK（$ANDROID_HOME 下的 platforms 与 build-tools/d8）。
#
# 注意：失败必须非零退出让 CI 红掉——历史上「找不到工具就静默 exit 0」
# 会导致 dex 悄悄缺失，Android root 的 Java 层 DNS 探测退化不可用。
set -eo pipefail

AJAR=$(ls "$ANDROID_HOME"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1 || true)
D8=$(ls "$ANDROID_HOME"/build-tools/*/d8 2>/dev/null | sort -V | tail -1 || true)
if [ -z "$AJAR" ] || [ -z "$D8" ]; then
  echo "build_dns_dex: 未找到 android.jar 或 d8（ANDROID_HOME=$ANDROID_HOME）" >&2
  exit 1
fi
command -v javac >/dev/null || { echo "build_dns_dex: 未找到 javac（需要 JDK）" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SRC="$(cd "$(dirname "$0")" && pwd)/FastimeDns.java"

javac -source 8 -target 8 -nowarn -d "$TMP/classes" "$SRC" 2>/dev/null \
  || javac -nowarn -d "$TMP/classes" "$SRC"
"$D8" --min-api 21 --lib "$AJAR" --output "$TMP/dex" "$TMP"/classes/*.class

B64=$(base64 -w0 "$TMP/dex/classes.dex" 2>/dev/null || base64 "$TMP/dex/classes.dex" | tr -d '\n')
[ -n "$B64" ] || { echo "build_dns_dex: base64 输出为空" >&2; exit 1; }
printf '%s' "$B64"
