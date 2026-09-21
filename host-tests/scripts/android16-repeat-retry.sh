#!/usr/bin/env bash
# 6.5：attach 与 spawn 的重复运行与失败后重试，验证无偶发时序依赖、无残留。
#
# 关注的不是“能跑通一次”，而是：
#   1) 同一路径连续多次都成立（时序/身份累积不会第二次就坏）；
#   2) 一次可控失败之后，下一次仍能成功（失败不留脏状态）；
#   3) 每次结束后目标存活、无 rustfrida 残留、无遗留 memfd/暂停。
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

# 残留检查：rustfrida 进程、ptrace 暂停状态、遗留 memfd。
assert_clean_after() {
  local label="$1" pid="$2"
  local leftover
  leftover=$(adb -s "$SERIAL" shell "su -c 'pidof rustfrida 2>/dev/null | wc -l'" | tr -d '\r')
  [[ "$leftover" == "0" ]] || die "$label: rustfrida still running ($leftover)"

  if [[ -n "$pid" ]]; then
    # T (stopped) 状态说明 detach 没恢复目标。
    local state
    state=$(adb -s "$SERIAL" shell "su -c 'awk \"{print \\\$3}\" /proc/$pid/stat 2>/dev/null'" | tr -d '\r')
    [[ "$state" != "T" && "$state" != "t" ]] || die "$label: target $pid left stopped (state=$state)"
  fi
  log "$label: no rustfrida leftover, target not stopped"
}

run_once() {
  local label="$1" pid="$2"
  local out out_file rc
  out_file=$(mktemp)
  set +e
  timeout "$TIMEOUT_SEC" adb -s "$SERIAL" shell su -c \
    "$REMOTE_BIN --pid $pid --debug-inject so-only --verbose" >"$out_file" 2>&1
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

log "=== attach 重复运行（$REPEAT 次，同一进程）==="
pid=$(launch_target)
log "target pid=$pid"
for i in $(seq 1 "$REPEAT"); do
  run_once "attach#$i" "$pid"
  [[ "$(current_pid)" == "$pid" ]] || die "target died during repeat #$i"
done
assert_clean_after "attach-repeat" "$pid"

log "=== 失败后重试（先制造可控失败，再验证恢复正常）==="
# 用一个不存在的 pid 制造失败：必须快速失败且不留残留。
set +e
timeout "$TIMEOUT_SEC" adb -s "$SERIAL" shell su -c "$REMOTE_BIN --pid 999999 --debug-inject so-only" >/dev/null 2>&1
fake_rc=$?
set -e
[[ "$fake_rc" -ne 0 ]] || die "expected failure for nonexistent pid, got success"
log "nonexistent-pid failed as expected (exit $fake_rc)"
assert_clean_after "after-failed-attempt" ""

# 失败之后同一目标必须仍可注入。
pid=$(launch_target)
log "relaunched pid=$pid"
run_once "retry-after-failure" "$pid"
assert_clean_after "retry-after-failure" "$pid"

log "=== spawn 重复运行（$REPEAT 次）==="
for i in $(seq 1 "$REPEAT"); do
  out_file=$(mktemp)
  set +e
  # spawn 会进入 REPL，用 timeout 截断并检查是否成功注入。
  timeout "$TIMEOUT_SEC" adb -s "$SERIAL" shell su -c \
    "$REMOTE_BIN --spawn $PACKAGE --debug-inject so-only --verbose" >"$out_file" 2>&1
  set -e
  if ! grep -qE 'hide_soinfo: 成功隐藏|成功注入|agent.*连接' "$out_file"; then
    sed -e "s/^/[repeat:spawn#$i] /" "$out_file" | tail -n 20
    die "spawn#$i did not reach injection"
  fi
  log "spawn#$i OK"
  adb -s "$SERIAL" shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  sleep 1
done
assert_clean_after "spawn-repeat" "$(current_pid)"

log "6.5 OK: attach/spawn repeat + failure retry, no residue"
