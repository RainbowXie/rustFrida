//! 独立枚举探针：通过 dl_iterate_phdr 与 _r_debug.r_map 双链外部验证隐藏事实。

use std::mem::size_of;

use crate::process::{call_target_function, read_memory, write_bytes};
use crate::types::{DlOffsets, LibcOffsets};
use crate::{log_error, log_info, log_success};

use super::remote::{create_and_fill_memfd, dlopen_agent_via_ptrace, remote_dlsym};

/// 独立枚举探针：只调 bionic 公开的 dl_iterate_phdr，不引用 hide 代码，
/// 用于从外部确认注入库是否真的不在 soinfo 链上。
pub(crate) const PROBE_SO: &[u8] = include_bytes!("../../../loader/build/probe.so");

/// 独立枚举探针的返回结构，必须与 loader/probe_so.c 的 probe_result 一致。
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ProbeResult {
    pub(crate) version: i32,
    pub(crate) total: i32,
    pub(crate) wwb_matches: i32,
    pub(crate) self_skipped: i32,
    pub(crate) self_addr: u64,
    pub(crate) rmap_total: i32,
    pub(crate) rmap_wwb_matches: i32,
    pub(crate) matched_name: [u8; 256],
}

/// read_memory 要求 T: Default；[u8; 256] 不满足，所以手写全零默认值。
impl Default for ProbeResult {
    fn default() -> Self {
        Self {
            version: 0,
            total: 0,
            wwb_matches: 0,
            self_skipped: 0,
            self_addr: 0,
            rmap_total: 0,
            rmap_wwb_matches: 0,
            matched_name: [0u8; 256],
        }
    }
}

/// 在 host 侧解析目标 linker64 的 `_r_debug` 绝对地址。
///
/// `_r_debug` 是 LOCAL 符号，运行时 dlsym 查不到，只能读符号表。
/// 基址选取与 C 侧 find_linker64 保持一致（第一条 linker64 的 r--p 映射），
/// 否则算出的地址会偏移。
pub(crate) fn resolve_r_debug_addr(pid: i32) -> Result<usize, String> {
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))
        .map_err(|e| format!("读取目标 maps 失败: {}", e))?;

    let mut linker_path: Option<String> = None;
    let mut linker_base = 0usize;
    for line in maps.lines() {
        if !line.contains("linker64") || line.contains(".so") {
            continue;
        }
        let Some(addr_range) = line.split_whitespace().next() else { continue };
        let Some(perms) = line.split_whitespace().nth(1) else { continue };
        if !perms.starts_with("r--p") {
            continue;
        }
        let Some(start) = addr_range.split('-').next() else { continue };
        if let Some(path) = line.split_whitespace().last() {
            if path.ends_with("linker64") {
                linker_base = usize::from_str_radix(start, 16)
                    .map_err(|e| format!("解析 linker 基址失败: {}", e))?;
                linker_path = Some(path.to_string());
                break;
            }
        }
    }
    let path = linker_path.ok_or("未找到目标 linker64")?;
    let data = std::fs::read(&path).map_err(|e| format!("读取 {} 失败: {}", path, e))?;
    let elf = goblin::elf::Elf::parse(&data).map_err(|e| format!("解析 linker ELF 失败: {}", e))?;

    // 计算 load bias：第一个 PT_LOAD 的 p_vaddr 与映射起始的差。
    let mut bias = linker_base as u64;
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD {
            bias = linker_base as u64 - ph.p_vaddr;
            break;
        }
    }

    // bionic linker 把 r_debug 改名成 __dl__r_debug（C 侧 hide_linker.c 用同名），
    // 它是 LOCAL HIDDEN，只能读符号表。
    let sym = elf
        .syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some("__dl__r_debug"))
        .or_else(|| {
            elf.dynsyms
                .iter()
                .find(|s| elf.dynstrtab.get_at(s.st_name) == Some("__dl__r_debug"))
        })
        .ok_or("linker 符号表中未找到 __dl__r_debug")?;
    Ok((bias + sym.st_value) as usize)
}

/// 注入探针 SO，在目标进程内用 dl_iterate_phdr 与 _r_debug.r_map 枚举已加载库。
///
/// 这是独立证据：探针不引用 hide 代码，走的是 bionic 公开 API 与调试器链。
/// 若探针在两条链上均看不到 wwb_so，说明“不在链上”是外部可观测事实，
/// 而不是 HideResult 自报。
///
/// 探针自身也叫 wwb_so（同一个 memfd 名），所以：读完结果必须自卸（dlclose），
/// 否则下一次探测会把本次探针当成残留库，双链匹配数永远 >= 1。
pub(crate) fn run_independent_probe(
    pid: i32,
    offsets: &LibcOffsets,
    dl: &DlOffsets,
) -> Result<ProbeResult, String> {
    let memfd = create_and_fill_memfd(pid, offsets, PROBE_SO, "probe.so")?;
    let handle = match dlopen_agent_via_ptrace(pid, memfd, offsets, dl, "probe.so") {
        Ok(h) => h,
        Err(e) => {
            let _ = call_target_function(pid, offsets.close, &[memfd as usize], None);
            return Err(e);
        }
    };
    let _ = call_target_function(pid, offsets.close, &[memfd as usize], None);

    let outcome = probe_with_handle(pid, offsets, dl, handle);
    // 无论读取成败都自卸探针：测量工具不能把自己留在枚举结果里。
    if let Err(e) = call_target_function(pid, dl.dlclose, &[handle], None) {
        log_error!("探针 dlclose 失败: {}", e);
    }
    outcome
}

/// 已加载探针后的测量流程；handle 的卸载由调用方负责。
fn probe_with_handle(
    pid: i32,
    offsets: &LibcOffsets,
    dl: &DlOffsets,
    handle: usize,
) -> Result<ProbeResult, String> {
    // 结果缓冲区分配在目标进程，探针填完由 host 读回。
    let size = size_of::<ProbeResult>();
    let buf_addr = call_target_function(pid, offsets.malloc, &[size], None)
        .map_err(|e| format!("探针结果缓冲区分配失败: {}", e))?;
    for off in (0..size).step_by(8) {
        write_bytes(pid, buf_addr + off, &[0u8; 8])?;
    }

    // r_map 头地址：读目标 linker 符号表得到，传给探针走第二条链。
    let r_debug_addr = resolve_r_debug_addr(pid)?;
    // struct r_debug { int r_version; struct link_map *r_map; ... }，r_map 在 +8。
    let r_map_head = read_memory::<u64>(pid, r_debug_addr + 8)? as usize;
    log_info!(
        "_r_debug=0x{:x} r_map_head=0x{:x}",
        r_debug_addr, r_map_head
    );

    let fn_ptr = remote_dlsym(pid, dl, offsets, handle, b"probe_solist_visibility\0")?;
    if fn_ptr == 0 {
        let _ = call_target_function(pid, offsets.free, &[buf_addr], None);
        return Err("dlsym(probe_solist_visibility) 返回 NULL".to_string());
    }
    let rc = call_target_function(pid, fn_ptr, &[r_map_head, buf_addr], None)
        .map_err(|e| format!("调用 probe_solist_visibility 失败: {}", e))? as i32;
    let result = read_memory::<ProbeResult>(pid, buf_addr)?;
    let _ = call_target_function(pid, offsets.free, &[buf_addr], None);
    if rc != 0 {
        return Err(format!("probe_solist_visibility 返回 {}", rc));
    }
    if result.version != 1 {
        return Err(format!(
            "探针与 host 结构不一致: version={} (期望 1)",
            result.version
        ));
    }
    let name = {
        let end = result.matched_name.iter().position(|&c| c == 0).unwrap_or(result.matched_name.len());
        String::from_utf8_lossy(&result.matched_name[..end]).into_owned()
    };
    log_info!(
        "独立枚举: solist 共 {} 个库/匹配 {}；r_map 共 {} 个节点/匹配 {}（跳过自身 {}）",
        result.total,
        result.wwb_matches,
        result.rmap_total,
        result.rmap_wwb_matches,
        result.self_skipped
    );
    // self_skipped 必须为 1：否则说明探针没正确识别自身，匹配数就不可信。
    if result.self_skipped != 1 {
        return Err(format!(
            "探针自身隔离异常: self_skipped={} (期望 1)，枚举结果不可信",
            result.self_skipped
        ));
    }
    // r_map 至少要能读到节点，否则说明 host 解析的 r_map_head 有问题。
    if result.rmap_total == 0 {
        return Err("r_map 链节点数为 0：host 解析的 r_map_head 不可信".to_string());
    }
    if result.wwb_matches == 0 && result.rmap_wwb_matches == 0 {
        log_success!(
            "独立枚举确认: 目标库同时不在 solist（{} 个）与 r_map（{} 个）中",
            result.total,
            result.rmap_total
        );
    } else {
        log_error!(
            "独立枚举发现残留: solist_matches={} r_map_matches={} name=\"{}\"",
            result.wwb_matches,
            result.rmap_wwb_matches,
            name
        );
    }
    Ok(result)
}
