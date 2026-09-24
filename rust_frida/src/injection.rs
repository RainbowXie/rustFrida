//! 注入模块入口：提供生产注入流程、Debug 分层注入与独立枚举探针。

mod guard;
mod fault;
mod normal;
mod probe;
mod remote;

use std::os::fd::RawFd;

use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::process::{attach_to_process, call_target_function, get_lib_base, read_memory, write_bytes};
use crate::types::{DlOffsets, LibcOffsets};
use crate::{log_error, log_info, log_success, log_warn};

pub(crate) use guard::InjectionGuard;
pub(crate) use normal::{inject_to_process, watch_and_inject, AGENT_SO, SHELLCODE};
#[cfg(feature = "qbdi")]
pub(crate) use normal::QBDI_HELPER_SO;
pub(crate) use probe::{confirm_identity, run_independent_probe, verify_hidden, ProbeResult, PROBE_SO};
pub(crate) use remote::{
    alloc_and_write_struct, create_and_fill_memfd, create_memfd_in_target,
    create_socketpair_in_target, dlopen_agent_via_ptrace, extract_fd_from_target, remote_dlsym,
    AndroidDlextinfo,
};

/// 最小化空 SO（无符号、无 .init_array），用于隔离 memfd 映射检测
pub(crate) const EMPTY_SO: &[u8] = include_bytes!("../../loader/build/empty.so");

/// Debug 注入模式
#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
pub(crate) enum DebugInjectMode {
    /// 仅 ptrace attach + 调用 malloc + detach（测试 ptrace 痕迹检测）
    PtraceOnly,
    /// 仅创建 memfd + 写入 SO + 关闭（不 dlopen，测试 memfd fd 暴露）
    MemfdOnly,
    /// 仅 dlopen agent.so（测试 memfd 映射检测）
    SoOnly,
    /// 仅 dlopen qbdi-helper.so（隔离验证 QBDI helper hide_soinfo）
    #[cfg(feature = "qbdi")]
    #[value(name = "qbdi-helper")]
    QbdiHelper,
    /// dlopen 空 SO（测试 memfd 映射本身是否被检测，排除 SO 内容因素）
    SoEmpty,
    /// dlopen + socketpair（测试 maps + fd 检测）
    #[value(name = "so+fd")]
    SoFd,
    /// 完整注入（等价于正常注入，但不启动 REPL）
    #[value(name = "so+fd+thread")]
    SoFdThread,
    /// 仅创建 socketpair（测试纯 fd 暴露）
    FdOnly,
    /// 先按 so-only 隐藏，再用独立 dl_iterate_phdr 探针从外部确认不在链上。
    #[value(name = "probe")]
    Probe,
    /// 不加载任何业务库，只跑独立枚举探针；用于故障后验证目标已回到干净状态。
    #[value(name = "probe-only")]
    ProbeOnly,
}

impl DebugInjectMode {
    pub(crate) fn description(&self) -> &'static str {
        match self {
            Self::PtraceOnly => "仅 ptrace attach + malloc + detach",
            Self::MemfdOnly => "仅 memfd_create + 写入 + 关闭（不 dlopen）",
            Self::SoOnly => "仅 dlopen agent.so",
            #[cfg(feature = "qbdi")]
            Self::QbdiHelper => "仅 dlopen qbdi-helper.so",
            Self::SoEmpty => "dlopen 空 SO（排除内容检测）",
            Self::SoFd => "dlopen + socketpair",
            Self::SoFdThread => "完整注入（不启动 REPL）",
            Self::FdOnly => "仅创建 socketpair",
            Self::Probe => "so-only 隐藏 + 独立 dl_iterate_phdr 探针",
            Self::ProbeOnly => "仅独立 dl_iterate_phdr 探针（不加载业务库）",
        }
    }

    pub(crate) fn needs_dlopen(&self) -> bool {
        if matches!(
            self,
            Self::SoOnly | Self::SoEmpty | Self::SoFd | Self::SoFdThread | Self::Probe
        ) {
            return true;
        }
        #[cfg(feature = "qbdi")]
        if matches!(self, Self::QbdiHelper) {
            return true;
        }
        false
    }

    pub(crate) fn needs_socketpair(&self) -> bool {
        matches!(self, Self::SoFd | Self::SoFdThread | Self::FdOnly)
    }

    /// 是否使用空 SO 代替 agent.so
    pub(crate) fn use_empty_so(&self) -> bool {
        matches!(self, Self::SoEmpty)
    }

    #[cfg(feature = "qbdi")]
    pub(crate) fn use_qbdi_helper_so(&self) -> bool {
        matches!(self, Self::QbdiHelper)
    }

    /// probe 模式在隐藏成功后额外跑一次独立枚举。
    pub(crate) fn needs_independent_probe(&self) -> bool {
        matches!(self, Self::Probe | Self::ProbeOnly)
    }

    /// probe-only 只跑探针，不加载业务库。
    pub(crate) fn probe_only(&self) -> bool {
        matches!(self, Self::ProbeOnly)
    }

    /// 探针自身的 dlopen/dlclose 需要 libdl offsets，与业务加载无关。
    pub(crate) fn needs_dl_offsets(&self) -> bool {
        self.needs_dlopen() || self.probe_only()
    }
}

/// hide_soinfo 调试结果，与 hide_soinfo.h 中的 struct hide_result ABI 一致
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct HideResult {
    pub(crate) version: i32,
    pub(crate) stage: i32,
    pub(crate) status: i32,
    pub(crate) next_offset: i32,
    pub(crate) entries_scanned: i32,
    pub(crate) sym_matched: i32,
    pub(crate) soinfo_state: i32,
    pub(crate) link_map_state: i32,
    pub(crate) wrote: i32,
    pub(crate) _pad: i32,
    pub(crate) head_ptr: u64,
    pub(crate) target_ptr: u64,
    pub(crate) error: [u8; 128],
    pub(crate) target_path: [u8; 128],
    pub(crate) head_path: [u8; 128],
}

impl Default for HideResult {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl HideResult {
    pub(crate) fn cstr(buf: &[u8]) -> &str {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        std::str::from_utf8(&buf[..end]).unwrap_or("")
    }
}

fn log_hide_result(r: &HideResult) {
    let tp_str = HideResult::cstr(&r.target_path);
    let hp_str = HideResult::cstr(&r.head_path);
    let err_str = HideResult::cstr(&r.error);
    if r.status == 1 {
        log_success!("hide_soinfo: 成功隐藏 \"{}\"", tp_str);
    } else {
        log_error!(
            "hide_soinfo: 失败 status={} stage={} wrote=0x{:x} soinfo={} link_map={}",
            r.status,
            r.stage,
            r.wrote,
            r.soinfo_state,
            r.link_map_state
        );
        if !err_str.is_empty() {
            log_error!("  error: {}", err_str);
        }
    }
    log_info!(
        "  next_offset=0x{:x} scanned={} syms_matched={}",
        r.next_offset,
        r.entries_scanned,
        r.sym_matched
    );
    log_info!("  head=\"{}\" target=0x{:x}", hp_str, r.target_ptr);
}

fn invoke_hide_from_solist(
    pid: i32,
    handle: usize,
    offsets: &LibcOffsets,
    dl: &DlOffsets,
) -> Result<HideResult, String> {
    // 故障注入：把阶段写入目标进程内的 g_hide_fault_stage，
    // 让 hide 事务在 soinfo 摘除后、link_map 写入前失败，
    // 用来验证部分写入能被完整回滚（见 agent/src/hide_txn.c）。
    if fault::wants_stage(fault::FAULT_HIDE_PARTIAL) {
        let setter_ptr = remote_dlsym(pid, dl, offsets, handle, b"rust_set_hide_fault_stage\0")?;
        if setter_ptr == 0 {
            return Err("dlsym(rust_set_hide_fault_stage) 返回 NULL".to_string());
        }
        call_target_function(
            pid,
            setter_ptr,
            &[fault::FAULT_STAGE_HIDE_PARTIAL as usize],
            None,
        )
        .map_err(|e| format!("调用 rust_set_hide_fault_stage 失败: {}", e))?;
    }

    // cdylib 只导出 Rust 侧的 rust_* 包装（C 同名函数被 localize）。
    // 只认这一个名字：回退到别名会把“导出丢了”掩盖成“换了个符号”。
    let hide_ptr = remote_dlsym(pid, dl, offsets, handle, b"rust_hide_from_solist\0")?;
    if hide_ptr == 0 {
        return Err("dlsym(rust_hide_from_solist) 返回 NULL".to_string());
    }
    let hide_status = call_target_function(pid, hide_ptr, &[handle], None)
        .map_err(|e| format!("调用 hide_from_solist 失败: {}", e))? as i32;
    let result_ptr = remote_dlsym(pid, dl, offsets, handle, b"rust_get_hide_result\0")?;
    if result_ptr == 0 {
        return Err("dlsym(rust_get_hide_result) 返回 NULL".to_string());
    }
    let result_addr = call_target_function(pid, result_ptr, &[], None)
        .map_err(|e| format!("调用 get_hide_result 失败: {}", e))?;
    if result_addr == 0 {
        return Err("get_hide_result 返回 NULL".to_string());
    }
    let r = read_memory::<HideResult>(pid, result_addr)?;
    log_hide_result(&r);
    if hide_status != 1 || r.status != 1 {
        return Err(format!(
            "加载成功但隐藏失败: status={} stage={} error={}",
            r.status,
            r.stage,
            HideResult::cstr(&r.error)
        ));
    }
    Ok(r)
}

/// Debug 注入：根据模式选择性注入组件，用于隔离测试检测向量
/// 返回 Option<RawFd>：有 socketpair 时返回 host_fd，否则 None
pub(crate) fn inject_debug(
    pid: i32,
    mode: DebugInjectMode,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<Option<RawFd>, String> {
    // so+fd+thread 模式直接复用完整注入流程
    if mode == DebugInjectMode::SoFdThread {
        log_info!("Debug 模式 so+fd+thread: 执行完整注入流程");
        return inject_to_process(pid, string_overrides).map(Some);
    }

    log_info!("正在附加到进程 PID: {} (debug 模式: {})", pid, mode.description());

    // 计算 offsets
    let self_base = get_lib_base(None, "libc.so")?;
    let target_base = get_lib_base(Some(pid), "libc.so")?;

    let offsets = LibcOffsets::calculate(self_base, target_base)?;

    // 需要 libdl 的模式：业务 dlopen 或探针自装卸载。
    let dl_offsets = if mode.needs_dl_offsets() {
        let self_dl_base = get_lib_base(None, "libdl.so")?;
        let target_dl_base = get_lib_base(Some(pid), "libdl.so")?;
        Some(DlOffsets::calculate(self_dl_base, target_dl_base)?)
    } else {
        None
    };

    if crate::logger::is_verbose() {
        offsets.print_offsets();
        if let Some(ref dl) = dl_offsets {
            dl.print_offsets();
        }
    }

    attach_to_process(pid)?;
    let mut guard = InjectionGuard::new(pid, -1);
    guard.set_offsets(&offsets);
    if let Some(dl) = dl_offsets.as_ref() {
        guard.set_dl_offsets(dl);
    }
    // 故障注入点：attach 之后、资源获取之前。
    fault::maybe_fail(fault::FAULT_ATTACH_DONE)?;

    // 故障注入点（ISSUE-033 反证）：构造永不返回的远程调用，验证 call_target_function
    // 的有界等待与恢复序列。两种形态都覆盖：纯用户态自旋（b . 桩）与阻塞在系统调用
    // 等待（socket read）。中止后目标必须完全健康：会话可继续远程调用、堆可分配。
    if fault::wants_stage(fault::FAULT_REMOTE_HANG) {
        fault::note_marker(fault::FAULT_REMOTE_HANG, "构造永不返回的远程调用，验证有界等待与现场恢复");
        // 形态 1：纯用户态自旋（b .，不进内核）。
        let stub = call_target_function(
            pid,
            offsets.mmap,
            &[
                0,
                4096,
                (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as usize,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize,
                !0usize,
                0,
            ],
            None,
        )
        .map_err(|e| format!("自旋桩 mmap 失败: {}", e))?;
        // ARM64 `b .`（0x14000000 小端）：永不返回的自旋跳转。
        write_bytes(pid, stub, &[0x00, 0x00, 0x00, 0x14])?;
        let spin_outcome = call_target_function(pid, stub, &[], None);
        // 恢复后会话必须仍可用：远程 munmap 成功即证明 ptrace 会话恢复正常。
        call_target_function(pid, offsets.munmap, &[stub, 4096], None)
            .map_err(|e| format!("{}；自旋桩回收失败: {}", "自旋桩中止后会话不可用", e))?;
        let spin_err = match spin_outcome {
            Err(ref e) if e.contains("超时") => e.clone(),
            Ok(ret) => return Err(format!("自旋桩应超时却返回 0x{:x}（有界等待未生效）", ret)),
            Err(ref e) => return Err(format!("自旋桩等待异常但非超时: {}", e)),
        };
        // 形态 2：阻塞在系统调用等待的远程调用（socket read，对端不写入）。
        // 中止这类调用必须抑制 -ERESTARTSYS 重启，否则内核会拿还原后的寄存器
        // 重放系统调用，目标状态被粘性破坏（实测：中止后 malloc 永久挂死）。
        let (fd0, fd1) =
            create_socketpair_in_target(pid, &offsets).map_err(|e| format!("socketpair 创建失败: {}", e))?;
        let buf = call_target_function(pid, offsets.malloc, &[64], None)
            .map_err(|e| format!("read 缓冲区分配失败: {}", e))?;
        let read_outcome = call_target_function(pid, offsets.read, &[fd1 as usize, buf, 1], None);
        let _ = call_target_function(pid, offsets.free, &[buf], None);
        let _ = call_target_function(pid, offsets.close, &[fd0 as usize], None);
        let _ = call_target_function(pid, offsets.close, &[fd1 as usize], None);
        let read_err = match read_outcome {
            Err(ref e) if e.contains("超时") => e.clone(),
            Ok(ret) => return Err(format!("阻塞 read 应超时却返回 {}（有界等待未生效）", ret)),
            Err(ref e) => return Err(format!("阻塞 read 等待异常但非超时: {}", e)),
        };
        // 中止后堆必须完好：malloc/free 正常才能证明回卷没有留下粘性破坏。
        let probe_alloc = call_target_function(pid, offsets.malloc, &[64], None)
            .map_err(|e| format!("中止后 malloc 失败（目标堆可能已被破坏）: {}", e))?;
        call_target_function(pid, offsets.free, &[probe_alloc], None)
            .map_err(|e| format!("中止后 free 失败: {}", e))?;
        fault::note_marker(
            fault::FAULT_REMOTE_HANG,
            "反证通过：自旋桩与阻塞系统调用均超时恢复，目标 malloc/free 正常",
        );
        return Err(format!(
            "远程调用超时反证通过（自旋桩：{}；阻塞 read：{}）；恢复后 malloc/free 正常",
            spin_err, read_err
        ));
    }

    if mode == DebugInjectMode::PtraceOnly {
        let ptr =
            call_target_function(pid, offsets.malloc, &[64], None).map_err(|e| format!("调用 malloc 失败: {}", e))?;
        log_success!("malloc(64) = 0x{:x}", ptr);
        let _ = call_target_function(pid, offsets.free, &[ptr], None);
        log_success!("free(0x{:x}) 完成", ptr);
        let _ = guard.into_fd();
        if let Err(e) = ptrace::detach(Pid::from_raw(pid), None) {
            log_error!("分离目标进程失败: {}", e);
        } else {
            log_success!("已分离目标进程");
        }
        return Ok(None);
    }

    if mode == DebugInjectMode::MemfdOnly {
        let target_memfd = create_and_fill_memfd(pid, &offsets, EMPTY_SO, "empty.so")?;
        guard.own_target_fd(target_memfd);
        // 故障注入点：memfd 已创建但尚未关闭。
        fault::maybe_fail(fault::FAULT_MEMFD_CREATED)?;
        log_success!("memfd 创建并写入完成: target_fd={}", target_memfd);
        let _ = call_target_function(pid, offsets.close, &[target_memfd as usize], None);
        guard.release_target_fd(target_memfd);
        log_success!("memfd 已关闭");
        let _ = guard.into_fd();
        if let Err(e) = ptrace::detach(Pid::from_raw(pid), None) {
            log_error!("分离目标进程失败: {}", e);
        } else {
            log_success!("已分离目标进程");
        }
        return Ok(None);
    }

    let mut host_fd: Option<RawFd> = None;
    if mode.needs_socketpair() {
        let (fd0, fd1) = create_socketpair_in_target(pid, &offsets)?;
        // 目标 fd 立即入账：后续任一失败分支都由 guard 补偿关闭。
        guard.own_target_fd(fd0);
        guard.own_target_fd(fd1);
        // 故障注入点：socketpair 已创建但尚未提取。
        fault::maybe_fail(fault::FAULT_SOCKETPAIR_CREATED)?;
        let extracted = extract_fd_from_target(pid, fd0)?;
        let _ = call_target_function(pid, offsets.close, &[fd0 as usize], None);
        guard.release_target_fd(fd0);
        log_success!("socketpair 创建成功: host_fd={}, target_fd1={}", extracted, fd1);
        host_fd = Some(extracted);
        guard.set_host_fd(extracted);
        if mode == DebugInjectMode::FdOnly {
            log_info!("fd-only 模式: socketpair fd1={} 保留在目标进程中", fd1);
        }
    }

    if mode.needs_dlopen() {
        let dl = dl_offsets.as_ref().unwrap();
        let (so_data, label): (&[u8], &str) = if mode.use_empty_so() {
            (EMPTY_SO, "empty.so")
        } else {
            #[cfg(feature = "qbdi")]
            if mode.use_qbdi_helper_so() {
                (QBDI_HELPER_SO, "qbdi_helper.so")
            } else {
                (AGENT_SO, "agent.so")
            }
            #[cfg(not(feature = "qbdi"))]
            {
                (AGENT_SO, "agent.so")
            }
        };
        let target_memfd = create_and_fill_memfd(pid, &offsets, so_data, label)?;
        guard.own_target_fd(target_memfd);
        // 故障注入点：memfd 已创建并入账但尚未 dlopen/关闭。
        // 覆盖 needs_dlopen 分支，使真实目标的 memfd 泄漏清理可被验证。
        if let Err(e) = fault::maybe_fail(fault::FAULT_MEMFD_CREATED) {
            return Err(e);
        }
        let handle = match dlopen_agent_via_ptrace(pid, target_memfd, &offsets, dl, label) {
            Ok(h) => h,
            Err(e) => {
                let _ = call_target_function(pid, offsets.close, &[target_memfd as usize], None);
                guard.release_target_fd(target_memfd);
                return Err(e);
            }
        };
        // handle 立即入账：dlopen 之后的任一失败（含故障注入与隐藏失败）都必须
        // 把已加载对象从目标里卸掉，否则失败残留会被后续枚举当成真实库。
        guard.own_handle(handle);
        // 故障注入点：dlopen 成功后、隐藏之前。此时 guard 持有 handle，
        // 返回 Err 会触发 Drop 远程 dlclose，目标回到未加载状态。
        if let Err(e) = fault::maybe_fail(fault::FAULT_DLOPEN_DONE) {
            return Err(e);
        }
        let _ = call_target_function(pid, offsets.close, &[target_memfd as usize], None);
        guard.release_target_fd(target_memfd);
        log_success!("{} dlopen 完成", label);
        // 身份采集（ISSUE-032）：拿目标库内一个符号地址，让探针在隐藏前独立核对出
        // 确定身份（load bias）。隐藏后的验收只看这个身份是否还在两条链上，
        // 同名的合法保留载荷（如测试空 SO）不参与判定。
        let mut identity: Option<(usize, u64)> = None;
        if mode.needs_independent_probe() && !mode.use_empty_so() && handle != 0 {
            let sym = remote_dlsym(pid, dl, &offsets, handle, b"rust_get_hide_result\0")?;
            if sym == 0 {
                return Err("dlsym(rust_get_hide_result) 返回 NULL，无法建立身份锚点".to_string());
            }
            let pre = run_independent_probe(pid, &offsets, dl, Some((sym, 0)))?;
            identity = Some((sym, confirm_identity(&pre)?));
        }
        if !mode.use_empty_so() && handle != 0 {
            if fault::wants_stage(fault::FAULT_HIDE_SKIP) {
                // 负向测试：跳过隐藏事务，探针必须仍能按身份检出未摘链的目标。
                fault::note_marker(fault::FAULT_HIDE_SKIP, "跳过隐藏事务，验证探针按身份检出未摘链目标");
            } else {
                invoke_hide_from_solist(pid, handle, &offsets, dl)?;
            }
        }
        // 隐藏被外部观测确认后才解除 handle 清理责任；
        // 失败分支（含负向测试）由 Drop 远程 dlclose，不留未摘链目标。
        if let Some((sym, bias)) = identity {
            let post = run_independent_probe(pid, &offsets, dl, Some((sym, bias)))?;
            verify_hidden(&post, bias)?;
        }
        guard.release_handle(handle);
    }

    // probe-only：纯测量模式。同名载荷按地址列出，验收裁决由调用方按身份做，
    // 探针不按名字下结论——合法保留的同名空 SO 不是残留（ISSUE-032）。
    if mode.probe_only() {
        let dl = dl_offsets.as_ref().expect("probe 模式需要 libdl offsets");
        run_independent_probe(pid, &offsets, dl, None)?;
    }

    // detach 前检查 maps 中 memfd/wwb 条目（调试用）
    if let Ok(raw) = std::fs::read(format!("/proc/{}/maps", pid)) {
        let maps = String::from_utf8_lossy(&raw);
        let memfd_lines: Vec<&str> = maps
            .lines()
            .filter(|l| l.contains("memfd") || l.contains("wwb"))
            .collect();
        if memfd_lines.is_empty() {
            log_info!("maps 中无 memfd/wwb 条目（KPM 隐藏生效）");
        } else {
            log_warn!("maps 中仍有 memfd 条目:");
            for l in &memfd_lines {
                log_warn!("  {}", l);
            }
        }
    }

    guard.disarm();
    if let Err(e) = ptrace::detach(Pid::from_raw(pid), None) {
        log_error!("分离目标进程失败: {}", e);
    } else {
        log_success!("已分离目标进程");
    }

    Ok(host_fd)
}
