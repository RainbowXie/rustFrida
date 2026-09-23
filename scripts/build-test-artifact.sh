#!/usr/bin/env bash
# 构建真机故障测试专用 test artifact（ISSUE-029）。
#
# 为什么单独脚本：fault-injection feature 会把测试控制面（RUSTFRIDA_FAULT_STAGE/
# FAULT@ 字符串与 rust_set_hide_fault_stage 导出）编进产物，这类产物只能用于
# 受控真机故障测试，绝不能当作正式发布物（release.sh 会拒绝带控制串的产物）。
#
# 产物命名刻意带 -faulttest 后缀，避免与正式 rustfrida 混淆。
# 输出：target/aarch64-linux-android/{debug,release}/rustfrida-faulttest
#       及同目录 libagent.so（含 HIDE_FAULT_INJECTION 判定）。
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
profile="release"
ndk=""

while (($#)); do
  case "$1" in
    --ndk) ndk=${2:?missing value for --ndk}; shift 2 ;;
    --debug) profile="debug"; shift ;;
    -h|--help)
      echo "Usage: build-test-artifact.sh [--ndk PATH] [--debug]"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$ndk" ]]; then
  for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}" "${NDK_PATH:-}"; do
    [[ -n "$candidate" && -f "$candidate/source.properties" ]] && ndk=$candidate && break
  done
fi
[[ -z "$ndk" ]] && for base in "$HOME/Android/Sdk/ndk" "$HOME/Android/sdk/ndk"; do
  [[ -d "$base" ]] || continue
  ndk=$(find "$base" -mindepth 1 -maxdepth 1 -type d -name '*.*' | sort -V | tail -1)
  [[ -n "$ndk" ]] && break
done
[[ -z "$ndk" || ! -f "$ndk/source.properties" ]] && { echo "Android NDK not found; pass --ndk" >&2; exit 1; }
ndk=$(realpath "$ndk")

toolchain="$ndk/toolchains/llvm/prebuilt/linux-x86_64"
export PATH="$toolchain/bin:$PATH"
export ANDROID_NDK_HOME="$ndk" ANDROID_NDK_ROOT="$ndk" NDK_PATH="$ndk"
export CARGO_BUILD_TARGET="aarch64-linux-android"
export BINDGEN_EXTRA_CLANG_ARGS="--target=aarch64-linux-android33 --sysroot=$toolchain/sysroot"

cd "$repo"
[[ -f quickjs-hook/quickjs-src/quickjs.c ]] || git submodule update --init --recursive quickjs-hook/quickjs-src
if [[ ! -f loader/build/loader.bin || loader/loader.c -nt loader/build/loader.bin ]]; then
  python3 loader/loader.py --ndk "$ndk" --api 33
fi
if [[ ! -f loader/build/empty.so || loader/empty_so.c -nt loader/build/empty.so ]]; then
  python3 loader/build_empty_so.py --ndk "$ndk" --api 33
fi
if [[ ! -f loader/build/probe.so || loader/probe_so.c -nt loader/build/probe.so ]]; then
  python3 loader/build_probe_so.py --ndk "$ndk" --api 33
fi

profile_flag=(--release)
[[ "$profile" == "debug" ]] && profile_flag=()

echo "== 构建 fault-injection test artifact（$profile）=="
cargo build -p agent --no-default-features --features quickjs,qbdi,fault-injection "${profile_flag[@]}"
cargo build -p rust_frida --features qbdi,fault-injection "${profile_flag[@]}"

out_dir="$repo/target/aarch64-linux-android/$profile"
src_bin="$out_dir/rustfrida"
test_bin="$out_dir/rustfrida-faulttest"
[[ -f "$src_bin" ]] || { echo "missing $src_bin" >&2; exit 1; }
install -m 0755 "$src_bin" "$test_bin"

# 自证身份：test artifact 必须带故障标记，否则测试会退化为“故障从未命中”。
# 用 grep -c（读完全部输入）而非 grep -q：后者命中即关管道，strings 收 SIGPIPE
# 返回 141，pipefail 下会让整个管道误报非零。
marker_count=$(strings "$test_bin" | grep -c 'RUSTFRIDA_FAULT_STAGE' || true)
[[ "$marker_count" -gt 0 ]] || {
  echo "test artifact lacks RUSTFRIDA_FAULT_STAGE marker: $test_bin" >&2; exit 1; }

head=$(git -C "$repo" rev-parse HEAD)
sha=$(sha256sum "$test_bin" | cut -d' ' -f1)
echo
echo "artifact: $test_bin"
echo "sha256:   $sha"
echo "head:     $head"
echo "build:    cargo build -p agent --no-default-features --features quickjs,qbdi,fault-injection ${profile_flag[*]:-} && cargo build -p rust_frida --features qbdi,fault-injection ${profile_flag[*]:-}"
