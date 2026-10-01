#!/bin/bash
# 编译 FastimeDns.java → classes.dex → base64（单行输出到 stdout）。
# 供 CI 在构建 Android 二进制前执行，结果经 -ldflags -X fastime/core.cfgDnsDexB64 注入。
# 依赖：JDK（javac）+ Android SDK（$ANDROID_HOME 下的 platforms 与 build-tools/d8）。
set -eo pipefail

AJAR=$(ls "$ANDROID_HOME"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1)
D8=$(ls "$ANDROID_HOME"/build-tools/*/d8 2>/dev/null | sort -V | tail -1)
if [ -z "$AJAR" ] || [ -z "$D8" ]; then
  echo "build_dns_dex: 未找到 android.jar 或 d8，跳过（Android root 的 Java 层 DNS 将不可用）" >&2
  exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SRC="$(cd "$(dirname "$0")" && pwd)/FastimeDns.java"

javac -source 8 -target 8 -nowarn -d "$TMP/classes" "$SRC" 2>/dev/null \
  || javac -nowarn -d "$TMP/classes" "$SRC"
"$D8" --min-api 21 --lib "$AJAR" --output "$TMP/dex" "$TMP"/classes/*.class

base64 -w0 "$TMP/dex/classes.dex" 2>/dev/null || base64 "$TMP/dex/classes.dex" | tr -d '\n'
