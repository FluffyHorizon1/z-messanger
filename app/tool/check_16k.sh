#!/usr/bin/env bash
# Verifies that every 64-bit native library in an APK or AAB is built for
# 16 KB memory pages (Android 15+ devices; a Play requirement for apps
# targeting Android 15 since 2025-11): each ELF PT_LOAD segment must be
# aligned to at least 0x4000, and, for uncompressed libraries, the zip
# entries themselves must be 16 KB aligned (AGP does that; zipalign checks).
#
#   tool/check_16k.sh build/app/outputs/flutter-apk/app-release.apk
#   tool/check_16k.sh build/app/outputs/bundle/release/app-release.aab
#
# Needs readelf (binutils); zipalign from the Android build-tools is used
# when it can be found. Exit 1 on any unaligned library.
set -euo pipefail

artifact="${1:?apk or aab path}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# APKs keep libraries under lib/<abi>/, bundles under base/lib/<abi>/.
unzip -q -o "$artifact" 'lib/*' 'base/lib/*' -d "$tmp" 2>/dev/null || true

bad=0
checked=0
while IFS= read -r so; do
  abi="$(basename "$(dirname "$so")")"
  # 16 KB pages exist on 64-bit devices only; 32-bit ABIs are exempt.
  case "$abi" in arm64-v8a|x86_64) ;; *) continue ;; esac
  checked=$((checked + 1))
  min=$(readelf -lW "$so" | awk '$1=="LOAD"{print $NF}' | sort -u | \
        while read -r a; do printf '%d\n' "$a"; done | sort -n | head -1)
  if [ "${min:-0}" -lt 16384 ]; then
    printf 'UNALIGNED %s (PT_LOAD align %s)\n' "${so#"$tmp"/}" "$min"
    bad=$((bad + 1))
  else
    printf 'ok        %s (0x%x)\n' "${so#"$tmp"/}" "$min"
  fi
done < <(find "$tmp" -name '*.so' | sort)

if [ "$checked" -eq 0 ]; then
  echo "no 64-bit native libraries found in $artifact" >&2
  exit 1
fi

case "$artifact" in
  *.apk)
    zipalign="$(ls "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/opt/android-sdk}}"/build-tools/*/zipalign 2>/dev/null | sort -V | tail -1 || true)"
    if [ -n "$zipalign" ]; then
      if "$zipalign" -c -P 16 4 "$artifact" >/dev/null; then
        echo "ok        zip entries 16 KB aligned (zipalign -P 16)"
      else
        echo "UNALIGNED zip entries (zipalign -c -P 16 4 failed)"
        bad=$((bad + 1))
      fi
    fi
    ;;
esac

if [ "$bad" -ne 0 ]; then
  echo "$bad native librar(y/ies) not 16 KB aligned" >&2
  exit 1
fi
echo "all $checked 64-bit native libraries are 16 KB aligned"
