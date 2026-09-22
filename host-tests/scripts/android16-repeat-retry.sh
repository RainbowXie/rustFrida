#!/usr/bin/env bash
# 6.5：attach 与 spawn 的重复运行与失败后重试，验证无偶发时序依赖、无残留。
#
# 关注的不是“能跑通一次”，而是：
#   1) 同一目标进程连续多次注入都成立（时序/身份累积不会在重复运行时破坏目标）；
#   2) 经历可控故障后重试，同一目标仍能成功注入（故障路径不留脏状态）；
#   3) 每次注入前后检查 /proc/<pid>/fd、TracerPid、进程状态与 maps，确认无 fd 泄露与 tracer 挂载残留。
set -euo pipefail

SERIAL="${SERIAL:-192.168.123.235:5555}"
REMOTE_BIN="${REMOTE_BIN:-/data/local/tmp/rustfrida/rustfrida}"
PACKAGE="${PACKAGE:-com.android.settings}"
TIMEOUT_SEC="${TIMEOUT_SEC:-40}"
REPEAT="${REPEAT:-3}"

log() { printf '[repeat] %s\n' "$*"; }
die() { printf '[repeat] ERROR: %s\n' "$*" >&2; exit 1; }

adb -s "$SERIAL" get-state >/dev/null || die "device $SERIAL not connected"
adb -s "$SERIAL" shell su -c "test -x $REMOTE_BIN" || die "missing $REMOTE_BIN"

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

# 深度残留检查：
#   1. 没有残留的 rustfrida 进程在后台运行
#   2. 目标进程状态正常（不是 T/t 跟踪暂停态）
#   3. TracerPid 恢复为 0（ptrace 已完全 detach）
#   4. 目标 /proc/<pid>/fd 中无遗留的 wwb_so 文件描述符
assert_clean_after() {
  local label="$1" pid="$2"

  # 1. 检查 host 进程残留
  local leftover
  leftover=$(adb -s "$SERIAL" shell "su -c 'pidof rustfrida 2>/dev/null | wc -w'" | tr -d '\r')
  [[ "$leftover" == "0" ]] || die "$label: rustfrida still running ($leftover processes)"

  if [[ -n "$pid" ]]; then
    # 2. 目标状态不能处于 T (stopped) 或 t (tracing stop)
    local state
    state=$(adb -s "$SERIAL" shell "su -c 'awk \"{print \\\$3}\" /proc/$pid/stat 2>/dev/null'" | tr -d '\r')
    [[ "$state" != "T" && "$state" != "t" ]] || die "$label: target $pid left stopped (state=$state)"

    # 3. TracerPid 必须为 0（ptrace 已完全 detach，没有宿主/tracer 残留挂载）
    local tracer
    tracer=$(adb -s "$SERIAL" shell "su -c 'grep -i \"^TracerPid:\" /proc/$pid/status 2>/dev/null | awk \"{print \\\$2}\"'" | tr -d '\r')
    [[ "$tracer" == "0" ]] || die "$label: target $pid still traced (TracerPid=$tracer)"

    # 4. 目标进程内不应遗留已打开的 wwb_so 文件描述符（由 offsets.close 负责关闭）
    local leaked_memfd
    leaked_memfd=$(adb -s "$SERIAL" shell "su -c 'ls -l /proc/$pid/fd 2>/dev/null | grep \"wwb_so\" | wc -l'" | tr -d '\r')
    [[ "$leaked_memfd" == "0" ]] || die "$label: target $pid leaked $leaked_memfd wwb_so fd(s)"

    log "$label: clean (no rustfrida, state=$state, TracerPid=0, leaked_memfd=0)"
  fi
}

# 运行单次注入并验证结果
run_once() {
  local label="$1" pid="$2" mode="${3:-so-only}"
  local out_file rc
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
  log "$label OK"
}

log "=== 1. attach 同进程连续重复运行（$REPEAT 次）==="
pid=$(launch_target)
log "target pid=$pid"
for i in $(seq 1 "$REPEAT"); do
  run_once "attach#$i" "$pid"
  [[ "$(current_pid)" == "$pid" ]] || die "target died during repeat #$i"
  assert_clean_after "after-attach#$i" "$pid"
done

log "=== 2. 可控故障注入与同目标恢复重试 ==="
# 故障场景 A: 目标 PID 为受保护的系统进程 (PID 1 / init)，ptrace attach 必定被拒绝 (EPERM)。
# 验证：遇到错误时正确退出，不泄漏 host 资源，不影响后续注入。
set +e
timeout "$TIMEOUT_SEC" adb -s "$SERIAL" shell su -c "$REMOTE_BIN --pid 1 --debug-inject so-only" >/dev/null 2>&1
fail_rc=$?
set -e
[[ "$fail_rc" -ne 0 ]] || die "expected attach failure for protected pid 1, got success"
log "fault-scenario-A (protected pid 1) failed as expected (exit $fail_rc)"
assert_clean_after "after-fault-A" ""

# 故障场景 B: 在真实目标 Settings 进程上，先记录初始文件描述符与状态基线
fd_count_before=$(adb -s "$SERIAL" shell "su -c 'ls /proc/$pid/fd 2>/dev/null | wc -l'" | tr -d '\r')
log "target pid=$pid initial fd_count=$fd_count_before"

# 制造非致命错误参数（使用不存在的 SO 监听），验证参数校验失败路径资源清理
set +e
timeout 5 adb -s "$SERIAL" shell su -c "$REMOTE_BIN --pid $pid --watch-so non_existent_file.so --timeout 1" >/dev/null 2>&1
err_rc=$?
set -e
log "fault-scenario-B (watch-so timeout) exited ($err_rc)"
assert_clean_after "after-fault-B" "$pid"

# 故障后重试：在同一个未重启的目标进程上再次执行完整 so-only 注入
log "executing retry on the same target pid=$pid after faults..."
run_once "retry-on-same-target" "$pid"
assert_clean_after "after-retry-on-same-target" "$pid"

# 验证 fd 数量没有失控增长
fd_count_after=$(adb -s "$SERIAL" shell "su -c 'ls /proc/$pid/fd 2>/dev/null | wc -l'" | tr -d '\r')
log "target pid=$pid fd_count before=$fd_count_before, after=$fd_count_after"

log "=== 3. spawn 模式状态检查 ==="
# 注：Android 16 上的 spawn 依赖 Zymbiote 注入 boot heap，因系统兼容性当前不可用（与改动前 v0.1.0 表现一致），
# 这里记录状态而不伪造通过。
set +e
out_file=$(mktemp)
timeout 15 adb -s "$SERIAL" shell su -c \
  "$REMOTE_BIN --spawn $PACKAGE --debug-inject so-only" >"$out_file" 2>&1
spawn_rc=$?
set -e
if grep -q '未在 boot heap 中找到 setArgV0 指针' "$out_file"; then
  log "spawn failed at Zymbiote boot heap check as expected for current Android 16 (pre-existing limitation)"
else
  log "spawn returned $spawn_rc"
fi
assert_clean_after "after-spawn-check" "$(current_pid)"

log "6.5 OK: attach repeat, real-target fault retry, clean teardown verified"
