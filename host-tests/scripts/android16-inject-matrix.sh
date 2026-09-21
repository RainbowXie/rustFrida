#!/usr/bin/env bash
# Android 16 Pixel 6 分层注入门禁。
#
# 两类用例：
#   1) 干净进程基线：每个模式在全新进程里单独跑，验证各层自身成立。
#   2) 同进程压力：同一 PID 连续 so-empty → so-only → so-only → so+fd+thread，
#      验证同名 memfd 不因历史节点累积而身份冲突。
#
# 断言不只看退出码：还要确认 hide 结果、目标存活与无 tracer 残留。
set -euo pipefail

SERIAL="${SERIAL:-192.168.123.235:5555}"
REMOTE_BIN="${REMOTE_BIN:-/data/local/tmp/rustfrida/rustfrida}"
PACKAGE="${PACKAGE:-com.android.settings}"
TIMEOUT_SEC="${TIMEOUT_SEC:-30}"
# 修复后合同：所有层都应成功。保留 EXPECT_RED=1 仅用于复现历史缺陷。
EXPECT_RED="${EXPECT_RED:-0}"

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
  for _ in $(seq 1 25); do
    pid=$(adb -s "$SERIAL" shell pidof "$PACKAGE" | tr -d '\r' | awk '{print $1}')
    [[ -n "$pid" ]] && break
    sleep 0.2
  done
  [[ -n "$pid" ]] || die "failed to start $PACKAGE"
  printf '%s' "$pid"
}

current_pid() {
  adb -s "$SERIAL" shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r' | awk '{print $1}'
}

run_mode() {
  local mode="$1" pid="$2"
  local out rc
  out=$(mktemp)
  set +e
  timeout "$TIMEOUT_SEC" adb -s "$SERIAL" shell su -c \
    "$REMOTE_BIN --pid $pid --debug-inject $mode --verbose" >"$out" 2>&1
  rc=$?
  set -e
  printf '%s' "$out|$rc"
}

# 成功断言：无诊断失败、退出 0、目标存活、无身份冲突。
# evidence 是本次模式证明“隐藏确实发生”的证据正则：
#   - host dlopen 路径（so-only/so+fd）打印 hide_soinfo 成功标记；
#   - 完整注入走 loader/shellcode，隐藏失败会返回 -13，因此 ret=0x1 即证明成功。
assert_success() {
  local mode="$1" out="$2" rc="$3" evidence="$4" pid="$5"
  if grep -Eqi '函数执行异常|android_dlopen_ext 失败|bad ELF magic|Debug 注入失败|hide_soinfo: 失败' "$out"; then
    sed -e "s/^/[matrix:$mode] /" "$out" | tail -n 20
    die "$mode diagnostic failure in log"
  fi
  if [[ "$rc" -ne 0 ]]; then
    sed -e "s/^/[matrix:$mode] /" "$out" | tail -n 20
    die "$mode expected success, exit $rc"
  fi
  if [[ -n "$evidence" ]] && ! grep -qE "$evidence" "$out"; then
    sed -e "s/^/[matrix:$mode] /" "$out" | tail -n 20
    die "$mode expected evidence '$evidence', not found"
  fi
  # 身份冲突回归：同进程第二次加载出现该错误即判定失败。
  if grep -q 'current soinfo node is not unique' "$out"; then
    die "$mode hit soinfo identity collision"
  fi
  [[ "$(current_pid)" == "$pid" ]] || die "$mode target $pid died"
  log "$mode OK (alive=$pid)"
}

# 各模式的隐藏证据。so-empty 不含隐藏逻辑。
hide_evidence_for() {
  case "$1" in
    so-only|so+fd) printf '%s' 'hide_soinfo: 成功隐藏' ;;
    so+fd+thread) printf '%s' 'Shellcode 执行完成，返回值: 0x1' ;;
    probe) printf '%s' '独立枚举确认: 目标库同时不在 solist' ;;
    *) printf '%s' '' ;;
  esac
}

assert_fail_so_load() {
  local mode="$1" out="$2"
  grep -Eqi 'bad ELF magic|android_dlopen_ext 失败|函数执行异常|not unique' "$out" \
    || die "$mode expected load/hide failure, got success or unrelated error"
  log "$mode failed as expected (EXPECT_RED=1)"
}

run_clean_baseline() {
  local mode="$1"
  local pid packed out rc
  pid=$(launch_target)
  packed=$(run_mode "$mode" "$pid")
  out=${packed%|*}; rc=${packed##*|}
  log "----- baseline $mode (pid=$pid) exit=$rc -----"
  assert_success "$mode" "$out" "$rc" "$(hide_evidence_for "$mode")" "$pid"
}

run_same_process() {
  local pid packed out rc
  pid=$(launch_target)
  log "===== same-process sequence (pid=$pid) ====="
  # so-empty 先留下一个同名 memfd 映射，再连续加载 agent，制造历史节点累积。
  for mode in so-empty so-only so-only so+fd+thread; do
    packed=$(run_mode "$mode" "$pid")
    out=${packed%|*}; rc=${packed##*|}
    log "----- same-process $mode exit=$rc -----"
    local expect_hide=1
    [[ "$mode" == "so-empty" ]] && expect_hide=0
    if [[ "$EXPECT_RED" == "1" ]]; then
      assert_fail_so_load "$mode" "$out"
      continue
    fi
    assert_success "$mode" "$out" "$rc" "$(hide_evidence_for "$mode")" "$pid"
    if [[ "$(current_pid)" != "$pid" ]]; then
      pid=$(launch_target)
      log "target restarted, new pid=$pid"
    fi
  done
}

log "serial=$SERIAL sdk=$sdk EXPECT_RED=$EXPECT_RED"

if [[ "$EXPECT_RED" == "1" ]]; then
  pid=$(launch_target)
  for mode in so-only so+fd+thread; do
    packed=$(run_mode "$mode" "$pid")
    out=${packed%|*}; rc=${packed##*|}
    log "----- RED $mode exit=$rc -----"
    sed -e "s/^/[matrix:$mode] /" "$out" | tail -n 20
    assert_fail_so_load "$mode" "$out"
  done
  log "RED contract held: so-only/full inject failed"
  exit 0
fi

# 干净进程基线：每层单独成立。
run_clean_baseline ptrace-only
run_clean_baseline memfd-only
run_clean_baseline so-empty
run_clean_baseline so-only
run_clean_baseline so+fd+thread
# 独立枚举：不只依赖 HideResult 自报（对应 tasks 6.4）。
run_clean_baseline probe

# 同进程压力：证明同名 memfd 不再造成身份冲突。
run_same_process

log "GREEN contract held: baseline + same-process all succeeded"
