#!/usr/bin/env bash
# 6.5：attach 与 spawn 的重复运行与失败后重试，验证无偶发时序依赖、无残留。
#
# 证据设计的两条原则：
#   1) 故障必须发生在“资源获取之后”。用 RUSTFRIDA_FAULT_STAGE 精确命中注入阶段，
#      断言错误码前缀 FAULT@stage，而不是用 CLI 参数错误替代（那不会进入注入路径）。
#   2) fd 泄漏判定必须先扣除应用自身的 fd churn。实测 Settings 在零注入下 3 次采样
#      就出现目标不一致（114/115/117/5 号 fd 反复 GC/reopen），严格集合相等必然误报。
#      因此先采噪声全集，只把超出噪声的新增链接目标判为泄漏。
set -euo pipefail

SERIAL="${SERIAL:-192.168.123.235:5555}"
REMOTE_BIN="${REMOTE_BIN:-/data/local/tmp/rustfrida/rustfrida}"
PACKAGE="${PACKAGE:-com.android.settings}"
TIMEOUT_SEC="${TIMEOUT_SEC:-40}"
REPEAT="${REPEAT:-3}"
NOISE_SAMPLES="${NOISE_SAMPLES:-3}"

log() { printf '[repeat] %s\n' "$*"; }
die() { printf '[repeat] ERROR: %s\n' "$*" >&2; exit 1; }

adb -s "$SERIAL" get-state >/dev/null || die "device $SERIAL not connected"
adb -s "$SERIAL" shell su -c "test -x $REMOTE_BIN" || die "missing $REMOTE_BIN"
# 待测二进制必须真的带故障注入点，否则第 2 节会退化成“没有命中注入路径”的假验证。
adb -s "$SERIAL" shell su -c "strings $REMOTE_BIN | grep -q FAULT@" || die "$REMOTE_BIN lacks FAULT@ fault hooks (stale binary?)"

current_pid() { adb -s "$SERIAL" shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r' | awk '{print $1}'; }

launch_target() {
  adb -s "$SERIAL" shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  adb -s "$SERIAL" shell am start -W "$PACKAGE" >/dev/null
  local pid=""
  for _ in $(seq 1 25); do
    pid=$(current_pid)
    [[ -n "$pid" ]] && break
    sleep 0.2
  done
  [[ -n "$pid" ]] || die "failed to start $PACKAGE"
  printf '%s' "$pid"
}

# 链接目标（不含 fd 号）：fd 号会被应用复用，链接目标才代表“新的开放文件”。
fd_targets() {
  local pid="$1"
  adb -s "$SERIAL" shell "su -c 'for f in /proc/$pid/fd/*; do readlink \$f; done 2>/dev/null'" | tr -d '\r'
}

# 零注入噪声全集：多次采样取并集，覆盖应用自身的 GC/reopen churn。
noise_baseline() {
  local pid="$1" i buf=""
  for i in $(seq 1 "$NOISE_SAMPLES"); do
    buf+="$(fd_targets "$pid")"$'\n'
    sleep 1
  done
  printf '%s' "$buf" | LC_ALL=C sort -u
}

# 断言注入后无超出噪声基线的新增链接目标；allow 为空表示零白名单（故障路径）。
assert_no_leaked_fds() {
  local label="$1" pid="$2" noise="$3" allow="${4:-}"
  local after new_targets wwb_count
  after=$(fd_targets "$pid")

  # wwb_so memfd 残留：create_and_fill_memfd 失败分支与成功后都必须关闭 target_memfd。
  wwb_count=$(grep -c 'wwb_so' <<<"$after" || true)
  [[ "$wwb_count" == "0" ]] || die "$label: target $pid leaked $wwb_count wwb_so memfd fd(s)"

  # comm 按 locale 排序规则比较，必须与输入侧 LC_ALL=C sort 同 locale，否则把已排序
  # 输入判为未排序并报错；且不得吞错误——比较失败要让脚本失败，而不是产出空结果
  # 使断言空转通过。
  new_targets=$(LC_ALL=C comm -13 \
    <(printf '%s\n' "$noise" | LC_ALL=C sort -u) \
    <(printf '%s\n' "$after" | LC_ALL=C sort -u))

  if [[ -n "${new_targets//[[:space:]]/}" && -n "$allow" ]]; then
    new_targets=$(grep -Ev "$allow" <<<"$new_targets" || true)
  fi
  if [[ -n "${new_targets//[[:space:]]/}" ]]; then
    log "$label: leaked fd target(s):"
    printf '%s\n' "$new_targets" | sed 's/^/  /'
    die "$label: target $pid leaked fd target(s)"
  fi
  log "$label: no leaked fd (wwb_so=0, no new target outside noise/allow)"
}

assert_clean_after() {
  local label="$1" pid="$2"
  local leftover state tracer

  leftover=$(adb -s "$SERIAL" shell "su -c 'pidof rustfrida 2>/dev/null | wc -w'" | tr -d '\r')
  [[ "$leftover" == "0" ]] || die "$label: rustfrida still running ($leftover)"

  if [[ -n "$pid" ]]; then
    state=$(adb -s "$SERIAL" shell "su -c 'awk \"{print \\\$3}\" /proc/$pid/stat 2>/dev/null'" | tr -d '\r')
    [[ "$state" != "T" && "$state" != "t" ]] || die "$label: target $pid left stopped (state=$state)"
    tracer=$(adb -s "$SERIAL" shell "su -c 'awk \"/^TracerPid:/ {print \\\$2}\" /proc/$pid/status 2>/dev/null'" | tr -d '\r')
    [[ "$tracer" == "0" ]] || die "$label: target $pid still traced (TracerPid=$tracer)"
  fi
  log "$label: clean (no rustfrida leftover, target not stopped, TracerPid=0)"
}

# 成功注入：断言隐藏成功、目标存活、无未入账 fd。
run_once() {
  local label="$1" pid="$2" mode="${3:-so-only}" allow="${4:-}"
  local noise out_file rc
  noise=$(noise_baseline "$pid")
  out_file=$(mktemp)
  set +e
  timeout "$TIMEOUT_SEC" adb -s "$SERIAL" shell su -c \
    "$REMOTE_BIN --pid $pid --debug-inject $mode --verbose" >"$out_file" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]] || ! grep -q 'hide_soinfo: 成功隐藏' "$out_file"; then
    sed -e "s/^/[repeat:$label] /" "$out_file" | tail -n 20
    die "$label: attach run failed (exit $rc)"
  fi
  if grep -q 'current soinfo node is not unique' "$out_file"; then
    die "$label: soinfo identity collision on repeat"
  fi
  assert_no_leaked_fds "$label" "$pid" "$noise" "$allow"
  assert_clean_after "$label" "$pid"
  log "$label OK"
}

# 真实目标故障注入：断言 FAULT@stage 命中注入点，且失败后无残留。
run_fault() {
  local label="$1" pid="$2" stage="$3" mode="$4" allow="${5:-}"
  local noise out_file rc
  noise=$(noise_baseline "$pid")
  out_file=$(mktemp)
  set +e
  timeout "$TIMEOUT_SEC" adb -s "$SERIAL" shell su -c \
    "RUSTFRIDA_FAULT_STAGE=$stage $REMOTE_BIN --pid $pid --debug-inject $mode --verbose" >"$out_file" 2>&1
  rc=$?
  set -e
  [[ "$rc" -ne 0 ]] || die "$label: fault $stage expected nonzero exit, got success"
  if ! grep -q "FAULT@$stage" "$out_file"; then
    sed -e "s/^/[repeat:$label] /" "$out_file" | tail -n 20
    die "$label: expected FAULT@$stage in error output (stage $stage)"
  fi
  assert_no_leaked_fds "$label" "$pid" "$noise" "$allow"
  assert_clean_after "$label" "$pid"
  log "$label: fault $stage hit with expected error (exit $rc)"
}

log "=== 1. attach 同进程连续重复运行（$REPEAT 次）==="
pid=$(launch_target)
log "target pid=$pid"
for i in $(seq 1 "$REPEAT"); do
  run_once "attach#$i" "$pid"
  [[ "$(current_pid)" == "$pid" ]] || die "target died during repeat #$i"
done

log "=== 2. 真实目标故障注入与同 PID 恢复重试 ==="
# 故障路径必须零残留（不给任何白名单）；成功路径 so+fd 会刻意保留 agent 用的
# socketpair fd1，因此列入白名单。so-only 不保留任何 fd。
run_fault "fault-attach-done" "$pid" "attach_done" "so-only" ""
run_fault "fault-memfd-created" "$pid" "memfd_created" "so-only" ""
run_fault "fault-dlopen-done" "$pid" "dlopen_done" "so-only" ""
run_fault "fault-hide-partial" "$pid" "hide_partial" "so-only" ""
run_fault "fault-socketpair-created" "$pid" "socketpair_created" "so+fd" ""

# 全部故障之后：同一 PID 仍必须能成功注入（不是重启目标掩盖问题）。
run_once "retry-on-same-target" "$pid" "so-only" ""
[[ "$(current_pid)" == "$pid" ]] || die "target died after retries"

log "=== 3. spawn 模式状态检查 ==="
# 注：Android 16 上的 spawn 依赖 Zymbiote 注入 boot heap，因系统兼容性当前不可用（与改动前 v0.1.0 表现一致），
# 这里记录状态而不伪造通过。
set +e
out_file=$(mktemp)
timeout 15 adb -s "$SERIAL" shell su -c \
  "$REMOTE_BIN --spawn $PACKAGE --debug-inject so-only" >"$out_file" 2>&1
set -e
if grep -q '未在 boot heap 中找到 setArgV0 指针' "$out_file"; then
  log "spawn failed at Zymbiote boot heap check as expected for current Android 16 (pre-existing limitation)"
else
  log "spawn returned without the known Zymbiote signature"
fi
assert_clean_after "after-spawn-check" "$(current_pid)"

log "6.5 OK: attach repeat, real-target fault retry per stage, clean teardown verified"
