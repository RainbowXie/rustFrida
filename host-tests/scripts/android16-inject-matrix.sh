#!/usr/bin/env bash
# Android 16 Pixel 6 分层注入 RED/回归门禁。
# 现版本合同：ptrace-only 与 memfd-only 成功；so-only 与完整注入必须失败
# （PC 在 linker64、LR 在 rustFrida /memfd:wwb_so）。so-empty 在 EMPTY_SO
# 仍为 loader.bin 时也会失败，不能当作 linker 基线。
set -euo pipefail

SERIAL="${SERIAL:-192.168.123.235:5555}"
REMOTE_BIN="${REMOTE_BIN:-/data/local/tmp/rustfrida/rustfrida}"
PACKAGE="${PACKAGE:-com.android.settings}"
TIMEOUT_SEC="${TIMEOUT_SEC:-25}"
EXPECT_RED="${EXPECT_RED:-1}"

log() { printf '[matrix] %s\n' "$*"; }
die() { printf '[matrix] ERROR: %s\n' "$*" >&2; exit 1; }

adb -s "$SERIAL" get-state >/dev/null || die "device $SERIAL not connected"
sdk=$(adb -s "$SERIAL" shell getprop ro.build.version.sdk | tr -d '\r')
[[ "$sdk" == "36" ]] || die "expected Android 16 (SDK 36), got SDK $sdk"

adb -s "$SERIAL" shell su -c "test -x $REMOTE_BIN" || die "missing $REMOTE_BIN"

launch_target() {
  adb -s "$SERIAL" shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  adb -s "$SERIAL" shell am start -W "$PACKAGE" >/dev/null
  local pid=""
  for _ in $(seq 1 20); do
    pid=$(adb -s "$SERIAL" shell pidof "$PACKAGE" | tr -d '\r' | awk '{print $1}')
    [[ -n "$pid" ]] && break
    sleep 0.2
  done
  [[ -n "$pid" ]] || die "failed to start $PACKAGE"
  printf '%s' "$pid"
}

run_mode() {
  local mode="$1"
  local pid="$2"
  local out
  out=$(mktemp)
  set +e
  timeout "$TIMEOUT_SEC" adb -s "$SERIAL" shell su -c \
    "$REMOTE_BIN --pid $pid --debug-inject $mode --verbose" >"$out" 2>&1
  local rc=$?
  set -e
  printf '%s' "$out|$rc"
}

assert_success() {
  local mode="$1" out="$2" rc="$3"
  if grep -Eqi '函数执行异常|android_dlopen_ext 失败|bad ELF magic|Debug 注入失败' "$out"; then
    die "$mode expected success, diagnostic failure in log"
  fi
  if [[ "$rc" -ne 0 ]]; then
    die "$mode expected success, exit $rc"
  fi
  log "$mode OK"
}

assert_fail_so_load() {
  local mode="$1" out="$2"
  if grep -Eqi 'PC=0x[0-9a-f]+ \[.*/linker64' "$out" && grep -Eqi 'LR=0x[0-9a-f]+ \[.*/memfd:wwb_so' "$out"; then
    log "$mode failed on linker64 with LR in rustFrida wwb_so (expected RED)"
    return 0
  fi
  if grep -Eqi 'bad ELF magic|android_dlopen_ext 失败|函数执行异常' "$out"; then
    log "$mode failed during ELF/linker load (expected RED for current build)"
    return 0
  fi
  die "$mode expected load/hide failure, got success or unrelated error"
}

pid=$(launch_target)
log "target pid=$pid serial=$SERIAL"

declare -A RESULTS
for mode in ptrace-only memfd-only so-empty so-only so+fd+thread; do
  packed=$(run_mode "$mode" "$pid")
  out=${packed%|*}
  rc=${packed##*|}
  log "----- $mode exit=$rc -----"
  sed -e "s/^/[matrix:$mode] /" "$out" | tail -n 40
  RESULTS["$mode"]="$out:$rc"
  if [[ "$mode" == "so-only" || "$mode" == "so+fd+thread" ]]; then
    # 完整注入崩溃后进程可能已死，后续模式需要重新拉起。
    if ! adb -s "$SERIAL" shell pidof "$PACKAGE" | grep -q .; then
      pid=$(launch_target)
      log "relaunched target pid=$pid"
    fi
  fi
done

ptrace_out=${RESULTS[ptrace-only]%%:*}; ptrace_rc=${RESULTS[ptrace-only]##*:}
memfd_out=${RESULTS[memfd-only]%%:*}; memfd_rc=${RESULTS[memfd-only]##*:}
empty_out=${RESULTS[so-empty]%%:*}; empty_rc=${RESULTS[so-empty]##*:}
so_out=${RESULTS[so-only]%%:*}; so_rc=${RESULTS[so-only]##*:}
full_out=${RESULTS[so+fd+thread]%%:*}; full_rc=${RESULTS[so+fd+thread]##*:}

assert_success ptrace-only "$ptrace_out" "$ptrace_rc"
assert_success memfd-only "$memfd_out" "$memfd_rc"

if [[ "$EXPECT_RED" == "1" ]]; then
  assert_fail_so_load so-only "$so_out"
  assert_fail_so_load so+fd+thread "$full_out"
  log "RED contract held: ptrace/memfd ok; so-only/full inject failed"
else
  assert_success so-empty "$empty_out" "$empty_rc"
  assert_success so-only "$so_out" "$so_rc"
  assert_success so+fd+thread "$full_out" "$full_rc"
  log "GREEN contract held: all isolation layers succeeded"
fi
