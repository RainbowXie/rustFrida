//! 注入模块入口：提供生产注入流程、Debug 分层注入与独立枚举探针。

mod guard;
mod normal;
mod probe;
mod remote;

use std::os::fd::RawFd;

use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::process::{attach_to_process, call_target_function, get_lib_base, read_memory};
use crate::types::{DlOffsets, LibcOffsets};
use crate::{log_error, log_info, log_success, log_warn};

pub(crate) use guard::InjectionGuard;
pub(crate) use normal::{inject_to_process, watch_and_inject, AGENT_SO, SHELLCODE};
#[cfg(feature = "qbdi")]
pub(crate) use normal::QBDI_HELPER_SO;
pub(crate) use probe::{run_independent_probe, ProbeResult, PROBE_SO};
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
        matches!(self, Self::Probe)
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

    // ptrace-only 不需要 libdl
    let dl_offsets = if mode.needs_dlopen() {
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
        log_success!("memfd 创建并写入完成: target_fd={}", target_memfd);
        let _ = call_target_function(pid, offsets.close, &[target_memfd as usize], None);
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
        let extracted = extract_fd_from_target(pid, fd0)?;
        let _ = call_target_function(pid, offsets.close, &[fd0 as usize], None);
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
        let handle = match dlopen_agent_via_ptrace(pid, target_memfd, &offsets, dl, label) {
            Ok(h) => h,
            Err(e) => {
                let _ = call_target_function(pid, offsets.close, &[target_memfd as usize], None);
                return Err(e);
            }
        };
        let _ = call_target_function(pid, offsets.close, &[target_memfd as usize], None);
        log_success!("{} dlopen 完成", label);
        if !mode.use_empty_so() && handle != 0 {
            invoke_hide_from_solist(pid, handle, &offsets, dl)?;
        }
    }

    // probe 模式：隐藏后再用独立枚举从外部确认，不依赖 HideResult 自报。
    if mode.needs_independent_probe() {
        let dl = dl_offsets.as_ref().expect("probe 模式需要 libdl offsets");
        let probe = run_independent_probe(pid, &offsets, dl)?;
        if probe.wwb_matches != 0 || probe.rmap_wwb_matches != 0 {
            return Err(format!(
                "独立枚举仍能看到目标库（solist={} r_map={}），隐藏未被外部观测确认",
                probe.wwb_matches, probe.rmap_wwb_matches
            ));
        }
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
