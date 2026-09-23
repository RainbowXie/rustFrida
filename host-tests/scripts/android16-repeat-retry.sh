#!/usr/bin/env bash
# 6.5：attach 与 spawn 的重复运行与失败后重试，验证无偶发时序依赖、无残留。
#
# 证据设计原则：
#   1) 故障必须发生在“资源获取之后”。用 RUSTFRIDA_FAULT_STAGE 精确命中注入阶段，
#      断言错误码前缀 FAULT@stage，而不是 CLI 参数错误替代（那不会进入注入路径）。
#   2) fd 泄漏判定先扣除应用自身 fd churn（Settings 零注入下 3 次采样即出现目标
#      不一致），先采噪声全集，只把超出噪声的新增链接目标判为泄漏。
#   3) 失败残留判定不能只看 fd/ptrace：dlopen 之后的失败若不 dlclose，会永久留下
#      已加载库。每个故障阶段都用 maps（/memfd:wwb 映射数）+ 独立双链探针
#      （solist/r_map 匹配数）确认目标回到可恢复状态。
#   4) 待测二进制必须与本地产物逐字节一致（SHA-256 绑定），否则真机收据无法
#      机械绑定到最终 HEAD。
set -euo pipefail

SERIAL="${SERIAL:-192.168.123.235:5555}"
REMOTE_BIN="${REMOTE_BIN:-/data/local/tmp/rustfrida/rustfrida}"
LOCAL_BIN="${LOCAL_BIN:-}"
PACKAGE="${PACKAGE:-com.android.settings}"
TIMEOUT_SEC="${TIMEOUT_SEC:-40}"
REPEAT="${REPEAT:-3}"
NOISE_SAMPLES="${NOISE_SAMPLES:-3}"

log() { printf '[repeat] %s\n' "$*"; }
die() { printf '[repeat] ERROR: %s\n' "$*" >&2; exit 1; }

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
head_at_start=$(git -C "$repo" rev-parse HEAD)

adb -s "$SERIAL" get-state >/dev/null || die "device $SERIAL not connected"
adb -s "$SERIAL" shell su -c "test -x $REMOTE_BIN" || die "missing $REMOTE_BIN"
# 待测二进制必须真的带故障注入点，否则故障段会退化成“没有命中注入路径”的假验证。
adb -s "$SERIAL" shell su -c "strings $REMOTE_BIN | grep -q FAULT@" || die "$REMOTE_BIN lacks FAULT@ fault hooks (stale or release binary?)"

# ---- 收据头：HEAD / 构建命令 / 双端哈希 / 设备信息（ISSUE-030） ----
remote_sha=$(adb -s "$SERIAL" shell "su -c 'sha256sum $REMOTE_BIN'" | tr -d '\r' | awk '{print $1}')
log "head:         $head_at_start"
log "remote bin:   $REMOTE_BIN"
log "remote sha:   $remote_sha"
log "device:       $(adb -s "$SERIAL" shell getprop ro.build.version.release | tr -d '\r') sdk $(adb -s "$SERIAL" shell getprop ro.build.version.sdk | tr -d '\r') $(adb -s "$SERIAL" shell getprop ro.product.model | tr -d '\r')"
if [[ -n "$LOCAL_BIN" ]]; then
  [[ -f "$LOCAL_BIN" ]] || die "LOCAL_BIN not found: $LOCAL_BIN"
  local_sha=$(sha256sum "$LOCAL_BIN" | cut -d' ' -f1)
  log "local bin:    $LOCAL_BIN"
  log "local sha:    $local_sha"
  log "build:        scripts/build-test-artifact.sh（fault-injection test artifact）"
  # 逐字节一致性：不一致则本轮真机收据无法绑定到本地 HEAD 产物。
  [[ "$local_sha" == "$remote_sha" ]] || die "remote binary mismatch: local=$local_sha remote=$remote_sha"
  log "sha256 bound: local artifact == remote binary"
else
  die "LOCAL_BIN is required: pass the local fault-test artifact path to bind receipts to HEAD"
fi

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

# maps 中注入库映射条目数（/memfd:wwb_so）。dlopen 后失败若不 dlclose 会永久残留。
maps_wwb_count() {
  local pid="$1"
  adb -s "$SERIAL" shell "su -c 'grep -c \"/memfd:wwb\" /proc/$pid/maps 2>/dev/null'" | tr -d '\r' | grep -E '^[0-9]+$' || echo 0
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

  # wwb_so memfd fd 残留：create_and_fill_memfd 成功后与失败分支都必须关闭 target_memfd。
  wwb_count=$(grep -c 'wwb_so' <<<"$after" || true)
  [[ "$wwb_count" == "0" ]] || die "$label: target $pid leaked $wwb_count wwb_so memfd fd(s)"

  # comm 的 locale 必须与输入侧 LC_ALL=C sort 一致，否则已排序输入被判未排序；
  # 且不吞错误——比较失败让脚本失败，而不是空结果使断言空转通过。
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

# 独立双链验证：探针报告 solist 与 r_map 的 wwb 匹配数必须为 0。
# 探针自身按 load bias 排除并自卸（dlclose），重复运行不累积。
assert_probe_clean() {
  local label="$1" pid="$2"
  local out_file rc
  out_file=$(mktemp)
  set +e
  timeout "$TIMEOUT_SEC" adb -s "$SERIAL" shell su -c \
    "$REMOTE_BIN --pid $pid --debug-inject probe-only --verbose" >"$out_file" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]] || ! grep -q '独立枚举确认' "$out_file"; then
    sed -e "s/^/[repeat:$label] /" "$out_file" | tail -n 25
    die "$label: independent probe found residue or failed (exit $rc)"
  fi
  log "$label: independent probe clean (solist=0 r_map=0)"
}

# maps 残留验证：注入库映射条目数不得超过采样基线（strict: 与 before 相等）。
assert_maps_level() {
  local label="$1" pid="$2" before="$3"
  local after
  after=$(maps_wwb_count "$pid")
  [[ "$after" == "$before" ]] || die "$label: maps wwb entries changed $before -> $after (loaded library left behind)"
  log "$label: maps wwb entries stable at $after"
}

# 成功注入：断言隐藏成功、目标存活、无未入账 fd、独立双链确认隐藏。
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

# 真实目标故障注入：断言 FAULT@stage 命中、失败后无残留。
# maps_mode: strict=故障前后 /memfd:wwb 映射数相等；loaded=注入已成功仅上报失败
#（sender_error 语义：agent 已加载隐藏，验证的是上报失败后的清理，不判残留）。
run_fault() {
  local label="$1" pid="$2" stage="$3" mode="$4" allow="${5:-}" maps_mode="${6:-strict}"
  local noise out_file rc maps_before
  noise=$(noise_baseline "$pid")
  maps_before=$(maps_wwb_count "$pid")
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
  if [[ "$maps_mode" == "strict" ]]; then
    assert_maps_level "$label" "$pid" "$maps_before"
    assert_probe_clean "$label" "$pid"
  else
    log "$label: maps/probe skipped ($maps_mode semantics: load succeeded, only report path failed)"
  fi
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
# 故障路径零残留（不给白名单）；socketpair 阶段用 so+fd（fd1 保留是该模式语义，
# 因此在 allow 中放行 socket 链接目标）。
run_fault "fault-attach-done" "$pid" "attach_done" "so-only" ""
run_fault "fault-memfd-created" "$pid" "memfd_created" "so-only" ""
run_fault "fault-dlopen-done" "$pid" "dlopen_done" "so-only" ""
run_fault "fault-hide-partial" "$pid" "hide_partial" "so-only" ""
run_fault "fault-socketpair-created" "$pid" "socketpair_created" "so+fd" ""

log "--- 正常注入路径失败分支覆盖（ISSUE-028）---"
# shellcode 非 1：截断 blob 迫使 loader dlopen 真实失败 → 零残留。
run_fault "fault-shellcode-ret" "$pid" "shellcode_ret" "so+fd+thread" "" strict
# 远程调用异常：shellcode 未执行 → 零残留。
run_fault "fault-remote-call" "$pid" "remote_call" "so+fd+thread" "" strict
# sender 错误：blob 已送达、agent 已加载隐藏并合法接管 fd1（socketpair），
# 仅上报路径失败 → 放行 socket 链接目标（agent 线程持有是预期），不判 maps/probe 残留。
run_fault "fault-sender-error" "$pid" "sender_error" "so+fd+thread" "socket:" loaded

# 全部故障之后：同一 PID 仍必须能成功注入（不是重启目标掩盖问题），
# 并在最终重试后再运行独立 probe 确认双链无历史故障残留。
run_once "retry-on-same-target" "$pid" "so-only" ""
[[ "$(current_pid)" == "$pid" ]] || die "target died after retries"
assert_probe_clean "final-probe" "$pid"

log "=== 3. spawn 重复运行与失败后重试 ==="
# spawn 全流程（启动新进程 + 注入 + 15s 存活监控 + Zygote patch 还原）耗时约 25s，
# 超时必须给足：截断输出会把成功误判为“未知返回”。
run_spawn_once() {
  local label="$1" mode="${2:-so-only}" out_file rc
  out_file=$(mktemp)
  set +e
  timeout 40 adb -s "$SERIAL" shell su -c \
    "$REMOTE_BIN --spawn $PACKAGE --debug-inject $mode" >"$out_file" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]] || ! grep -q '进程在 15 秒监控期内持续存活' "$out_file" \
      || ! grep -q 'patch 已还原' "$out_file"; then
    sed -e "s/^/[repeat:$label] /" "$out_file" | tail -n 25
    die "$label: spawn run failed (exit $rc)"
  fi
  if grep -q 'setArgV0' "$out_file"; then
    sed -e "s/^/[repeat:$label] /" "$out_file" | tail -n 25
    die "$label: spawn hit Zymbiote boot-heap failure"
  fi
  log "$label OK (injected, 15s alive, zygote patch restored)"
}

for i in $(seq 1 "$REPEAT"); do
  run_spawn_once "spawn#$i"
done

# spawn 失败后重试：先用故障注入迫使 shellcode 返回非 1（新进程当场失败），
# 再正常 spawn 必须成功——不是靠新 PID 掩盖问题。
# 注意：shellcode_ret 位于正常注入路径（sender/loader），必须用 so+fd+thread；
# so-only 是 debug dlopen 路径，根本不经过 shellcode，故障不会命中。
set +e
out_file=$(mktemp)
timeout 40 adb -s "$SERIAL" shell su -c \
  "RUSTFRIDA_FAULT_STAGE=shellcode_ret $REMOTE_BIN --spawn $PACKAGE --debug-inject so+fd+thread" >"$out_file" 2>&1
rc=$?
set -e
[[ "$rc" -ne 0 ]] || die "spawn fault shellcode_ret expected nonzero exit, got success"
grep -q 'FAULT@shellcode_ret' "$out_file" || die "spawn fault: expected FAULT@shellcode_ret in output"
log "spawn fault shellcode_ret hit with expected error (exit $rc)"
run_spawn_once "spawn-retry-after-fault"
assert_clean_after "after-spawn-check" "$(current_pid)"

head_at_end=$(git -C "$repo" rev-parse HEAD)
[[ "$head_at_start" == "$head_at_end" ]] || die "HEAD changed during run: $head_at_start -> $head_at_end"
log "head stable:  $head_at_end"
log "6.5 OK: attach repeat, per-stage fault retry with maps+probe receipts, sha256-bound artifact, clean teardown verified"
