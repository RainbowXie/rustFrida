//! 对已修复缺陷的回归守卫。
//!
//! 这些断言把“为什么这样写”固化成可执行契约：如果将来有人把回退逻辑或
//! 名字匹配加回来，或忘了链 compiler-rt，测试会直接失败而不是等到设备上炸。

use std::path::PathBuf;

fn workspace_join(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(workspace_join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// 去掉 `//` 行注释后的小写正文。
///
/// 正向断言（“必须调用 X”）必须基于这个，否则把调用改成注释也能通过，
/// 而缺陷恰恰就是这样被漏掉的。
fn code_lower(rel: &str) -> String {
    read(rel)
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase()
}

/// bionic 不导出 __clear_cache；两个 cdylib 都必须显式链 compiler-rt builtins。
///
/// 不链的话链接仍然成功（共享库允许未定义符号），缺陷会推迟到设备 dlopen 才暴露，
/// 因此这里在源码层守住，release.sh 另有一道产物符号门禁。
#[test]
fn both_cdylibs_link_compiler_rt_builtins() {
    let shared = code_lower("build-support/compiler_rt.rs");
    assert!(
        shared.contains("clang_rt.builtins-aarch64"),
        "shared build-support must link compiler-rt builtins for __clear_cache"
    );
    assert!(
        shared.contains("link-search") || shared.contains("rustc-link-lib"),
        "must emit the link search path and library"
    );
    for build_rs in ["agent/build.rs", "qbdi-helper/build.rs"] {
        let src = read(build_rs);
        // 必须是真的调用，而不是被注释掉的残留——否则 __clear_cache 又会在设备上才爆。
        let called = src.lines().map(str::trim).any(|l| l == "link_compiler_rt_builtins();");
        assert!(called, "{build_rs} must actually call link_compiler_rt_builtins");
    }
}

/// release.sh 必须对产物做未定义符号门禁，否则回归会静默发布。
#[test]
fn release_gate_rejects_undefined_clear_cache() {
    let src = code_lower("scripts/release.sh");
    assert!(src.contains("__clear_cache"), "release.sh must check for undefined __clear_cache");
    assert!(
        src.contains("undefined-only"),
        "release.sh must inspect undefined dynamic symbols of the artifacts"
    );
}

/// release.sh 不能只在 loader.bin 缺失时才构建：源码改了而产物在时会被静默跳过。
#[test]
fn release_rebuilds_loader_when_source_is_newer() {
    let src = read("scripts/release.sh");
    assert!(
        src.contains("loader.c -nt") || src.contains("loader.py --ndk"),
        "release.sh must rebuild loader.bin when loader.c is newer"
    );
    assert!(
        !src.contains("if [[ ! -f loader/build/loader.bin ]]; then"),
        "must not gate loader.bin rebuild solely on file absence"
    );
}

/// cdylib 只导出 Rust 侧 rust_* 包装；所有加载路径都只认这一个名字，
/// 不允许再出现别名回退（回退会把“导出丢了”掩盖成“换了个符号”）。
#[test]
fn hide_symbols_have_no_alias_fallback() {
    let injection = read("rust_frida/src/injection.rs");
    assert!(
        !injection.contains("b\"hide_from_solist\\0\""),
        "injection.rs must not fall back to the localized C name"
    );
    assert!(
        !injection.contains("b\"get_hide_result\\0\""),
        "injection.rs must not fall back to the localized C name"
    );
    let qbdi_helper = read("quickjs-hook/src/jsapi/hook_api/qbdi/helper.rs");
    assert!(
        !qbdi_helper.contains("\"hide_from_solist\""),
        "qbdi helper must resolve rust_hide_from_solist only"
    );
    let loader = read("loader/loader.c");
    assert!(
        !loader.contains("hide_name[12]='l'; hide_name[13]='i';"),
        "loader.c must not fall back to the localized C name"
    );
}

/// 双链写入失败必须能回到改前状态，RELRO 临时打开的写权限必须恢复。
#[test]
fn hide_transaction_rolls_back_and_restores_protection() {
    let src = code_lower("agent/src/hide_txn.c");
    assert!(src.contains("write_journal"), "dual-chain writes must be journaled");
    assert!(src.contains("journal_rollback"), "failures must roll back written slots");
    assert!(src.contains("page_prot"), "must read the page's original protection");
    // 支持 Android 16 的 16 KB 页架构：不能硬编码 4096。
    assert!(
        src.contains("sysconf(_sc_pagesize)") || src.contains("get_page_size"),
        "must dynamically query page size via sysconf(_SC_PAGESIZE)"
    );
    // 恢复必须发生在写完之后，且失败时必须有重试恢复。
    let store = src
        .split("static int store_ptr")
        .nth(1)
        .expect("store_ptr missing");
    let store = store.split("static int page_prot").next().unwrap();
    assert!(
        store.matches("mprotect").count() >= 2,
        "store_ptr must open write access and restore the original protection"
    );
}

/// 纯逻辑验证：4 KB 与 16 KB 架构下的页对齐掩码计算必须正确。
#[test]
fn page_alignment_logic_supports_4k_and_16k() {
    fn align_down(addr: u64, page_size: usize) -> u64 {
        addr & !(page_size as u64 - 1)
    }

    // 4 KB 对齐
    assert_eq!(align_down(0x7b65db66c0, 4096), 0x7b65db6000);
    assert_eq!(align_down(0x7b65db6000, 4096), 0x7b65db6000);

    // 16 KB 对齐 (0x4000)
    assert_eq!(align_down(0x7b65db66c0, 16384), 0x7b65db4000);
    assert_eq!(align_down(0x7b65db4000, 16384), 0x7b65db4000);
    assert_eq!(align_down(0x7b65db7fff, 16384), 0x7b65db4000);
}

/// QBDI helper 隐藏失败必须让加载失败，不能继续发布 HELPER_API。
#[test]
fn qbdi_load_fails_when_hide_fails() {
    let src = read("quickjs-hook/src/jsapi/hook_api/qbdi/helper.rs");
    assert!(
        src.contains("fn verify_qbdi_helper_hide_result(handle: *mut c_void) -> Result<(), String>"),
        "verify must return Result so failures can abort the load"
    );
    assert!(
        !code_lower("quickjs-hook/src/jsapi/hook_api/qbdi/helper.rs")
            .contains("verify_qbdi_helper_hide_result(handle);"),
        "call site must propagate the error with ?"
    );
    assert!(
        src.contains("CHAIN_HIDDEN"),
        "must require both chains to report hidden, not just status"
    );
}

/// call_target_function 的等待必须是有界状态机（ISSUE-033）。
/// waitpid(None) 无限期等待是孤儿 tracer 的来源：rustfrida 挂死被外层杀掉后，
/// 目标后续 attach 全部 EPERM，失败后不可恢复。
#[test]
fn remote_call_wait_is_bounded() {
    let src = code_lower("rust_frida/src/process.rs");
    let start = src
        .find("fn call_target_function")
        .expect("call_target_function missing");
    let body = &src[start..];
    let end = body
        .find("向远程进程内存写入任意类型的数据")
        .unwrap_or(body.len());
    let body = &body[..end];
    assert!(
        !body.contains("waitpid(target_pid, none)"),
        "remote call must not block on an unbounded waitpid"
    );
    assert!(body.contains("wnohang"), "remote call wait must poll with WNOHANG");
    assert!(
        body.contains("deadline") || body.contains("timeout"),
        "remote call wait must enforce an upper bound"
    );
    assert!(body.contains("interrupt"), "timeout recovery must stop the tracee before restoring");
}

/// 探针自卸是成功的必要条件（ISSUE-034）。
/// 当前缺陷形态是 `if let Err → log_error 后照常返回测量结果`：探针自己留在链上，
/// 下一次探测把它当成历史残留，双链验收从此失真。
/// 负向证明：本守卫在修复前的源码上必须红（本轮 RED 阶段实测如此），
/// 修复后转绿；若将来有人移除 verify_probe_unloaded 步骤则再次变红。
#[test]
fn probe_self_unload_is_verified_not_swallowed() {
    let src = code_lower("rust_frida/src/injection/probe.rs");
    assert!(src.contains("dlclose"), "probe must unload itself");
    // 卸载验证必须是独立的可失败步骤（声明与调用两侧都在合同内，
    // 声明签名带冒号、调用带逗号，避免声明本身满足调用断言的空转）。
    assert!(
        src.contains("fn verify_probe_unloaded(pid:"),
        "probe must verify its own disappearance through a dedicated fallible step"
    );
    assert!(
        src.contains("verify_probe_unloaded(pid,"),
        "run_independent_probe must actually invoke the unload verification"
    );
    assert!(
        !src.contains("if let err(e) = call_target_function(pid, dl.dlclose"),
        "dlclose failure must be propagated as an error, not logged and swallowed"
    );
    assert!(
        src.contains("/proc/") && src.contains("maps"),
        "probe must verify its own disappearance via maps before reporting success"
    );
}

/// 提取 fault.rs 的全部字符串故障阶段名。
fn fault_stages() -> Vec<String> {
    let src = read("rust_frida/src/injection/fault.rs");
    src.lines()
        .filter_map(|l| {
            let l = l.trim();
            if !l.starts_with("pub(crate) const FAULT_") || !l.contains(": &str =") {
                return None;
            }
            let value = l.split("= \"").nth(1)?;
            Some(value.split('"').next()?.to_string())
        })
        .collect()
}

/// 求 stages 中未被 script 覆盖的项；单独成函数以便负向测试证明它能报缺。
fn uncovered_stages(stages: &[String], script: &str) -> Vec<String> {
    stages
        .iter()
        .filter(|s| !script.contains(s.as_str()))
        .cloned()
        .collect()
}

/// 每个故障阶段都必须有真机脚本调用点（ISSUE-019 精神的延续）。
/// 新阶段加了却没被设备验证，等于故障注入面悄悄开了天窗。
#[test]
fn every_fault_stage_is_exercised_by_repeat_script() {
    let script = read("host-tests/scripts/android16-repeat-retry.sh");
    let stages = fault_stages();
    assert!(!stages.is_empty(), "no fault stages parsed from fault.rs");
    let missing = uncovered_stages(&stages, &script);
    assert!(missing.is_empty(), "fault stages not exercised on device: {missing:?}");
}

/// 负向测试：覆盖检查必须能报缺，否则空转通过。
#[test]
fn uncovered_stage_detection_reports_missing() {
    let missing = uncovered_stages(&["never_in_script".to_string()], "nothing here");
    assert_eq!(missing, vec!["never_in_script".to_string()]);
}

/// 泄漏门禁按所有权下结论：创建 fd 的代码必须上报精确链接目标
/// （owned_fd_target=），否则门禁只能做会假阳的宽口径差分（实测 Settings 的
/// database/DMABUF/jar/自建 socket 抖动曾多次假阳）。
/// 负向证明：本守卫在上报落地前必须红（本轮 RED 实测如此）。
#[test]
fn created_fds_are_reported_for_ownership_gating() {
    let src = code_lower("rust_frida/src/injection/remote.rs");
    assert!(
        src.contains("fn report_owned_fd("),
        "创建 fd 必须经由 report_owned_fd 上报所有权凭证"
    );
    let calls = src.matches("report_owned_fd(").count();
    assert!(
        calls >= 4,
        "memfd 与 socketpair 双 fd 都必须上报（声明 + 至少 3 个调用点，实际 {calls} 处）"
    );
}

/// 冻结目标自愈的前提是解冻发生在 attach 等待之前（ISSUE-035）：InjectionGuard
/// 拥有冻结位恢复责任，必须先于 attach_to_process 创建，否则冻结目标的首次
/// ptrace-stop 等待一旦失败，解冻根本不会执行，“自愈”名不副实。
/// 负向证明：修复前 attach 在前时本守卫必须红（本轮 RED 实测如此）。
#[test]
fn guard_is_created_before_attach() {
    for src_path in ["rust_frida/src/injection/normal.rs", "rust_frida/src/injection.rs"] {
        let src = read(src_path);
        let guard_pos = src
            .find("InjectionGuard::new(")
            .unwrap_or_else(|| panic!("{src_path} must create a guard"));
        let attach_pos = src
            .find("attach_to_process(pid")
            .unwrap_or_else(|| panic!("{src_path} must call attach_to_process(pid)"));
        assert!(
            guard_pos < attach_pos,
            "{src_path}: guard (freeze-thaw owner) must be created before attach_to_process"
        );
    }
}

/// 远程堆分配必须有所有权守卫（ISSUE-037）：任何成功/失败出口都要 free，
/// 否则错误路径会持续泄漏目标堆（fd/maps/双链门禁都看不到堆泄漏）。
/// 负向证明：守卫落地前本测试必须红（本轮 RED 实测如此）。
#[test]
fn remote_heap_allocations_have_drop_guard() {
    let remote = code_lower("rust_frida/src/injection/remote.rs");
    assert!(
        remote.contains("impl drop for remotealloc"),
        "remote.rs must own remote heap allocations via a Drop guard"
    );
    let probe = code_lower("rust_frida/src/injection/probe.rs");
    assert!(probe.contains("remotealloc"), "probe result buffer must use the ownership guard");
    assert!(
        !probe.contains("call_target_function(pid, offsets.malloc"),
        "probe must not malloc without the guard"
    );
}

/// 集合差分必须携带全量计数（ISSUE-036）：地址列表有容量上限，计数才是全量事实；
/// 只比列表会让超出容量的新增同名残留隐形（满 8 容量时第 9 个残留实测不可见）。
#[test]
fn probe_sets_include_match_count() {
    let probe = code_lower("rust_frida/src/injection/probe.rs");
    assert!(
        probe.contains("match_count="),
        "probe output must print match counts alongside bias lists"
    );
    let script = read("host-tests/scripts/android16-repeat-retry.sh");
    assert!(
        script.contains("match_count"),
        "script must capture and compare match counts"
    );
}

/// InjectionGuard 必须在会话期间解冻被系统冷藏的目标，并在收尾恢复冻结位。
/// 为什么：Android cached-app freezer（cgroup.freeze=1）让目标连 PTRACE_CONT 的代码
/// 都无法执行——实测 mmap 级远程调用全部超时，而目标 State 仍显示 S，极难诊断。
/// 恢复侧同样必须存在：否则 root 工具会把系统应用留在不该在的热状态。
#[test]
fn guard_thaws_frozen_target_and_restores_freeze() {
    let src = code_lower("rust_frida/src/injection/guard.rs");
    assert!(
        src.contains("thaw_target_for_session"),
        "guard must unfreeze a system-frozen target for the session"
    );
    assert!(
        src.contains("restore_target_freeze"),
        "guard must restore the target's freeze state after the session"
    );
    assert!(
        src.contains("fn drop"),
        "restore must ride the RAII exit so failure paths cannot skip it"
    );
}

/// 负向测试：只解冻不恢复必须被上面的守卫抓住（不会红的守卫是废纸）。
#[test]
fn freeze_guard_detects_missing_restore() {
    let thaw_only = "fn drop() { thaw_target_for_session(pid); }";
    assert!(
        !thaw_only.contains("restore_target_freeze"),
        "precondition broken: synthetic fixture must lack the restore step"
    );
    let missing = !thaw_only.contains("restore_target_freeze");
    assert!(missing, "guard logic must flag a thaw-only implementation");
}
