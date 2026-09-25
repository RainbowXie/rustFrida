//! 独立枚举探针：通过 dl_iterate_phdr 与 _r_debug.r_map 双链外部验证隐藏事实。

use std::mem::{offset_of, size_of};

use crate::process::{call_target_function, read_memory, write_bytes};
use crate::types::{DlOffsets, LibcOffsets};
use crate::{log_error, log_info, log_success};

use super::fault;
use super::remote::{create_and_fill_memfd, dlopen_agent_via_ptrace, remote_dlsym, unique_load_name, RemoteAlloc};

/// 独立枚举探针：只调 bionic 公开的 dl_iterate_phdr，不引用 hide 代码，
/// 用于从外部确认注入库是否真的不在 soinfo 链上。
pub(crate) const PROBE_SO: &[u8] = include_bytes!("../../../loader/build/probe.so");

/// 与 loader/probe_so.c 的 PROBE_VERSION 一致：v3 = bias 列表扩容至 32（布局变更）。
pub(crate) const PROBE_VERSION: i32 = 3;

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
    pub(crate) target_sym: u64,
    pub(crate) target_bias: u64,
    pub(crate) target_present_sol: i32,
    pub(crate) target_present_rmap: i32,
    pub(crate) matched_count: i32,
    pub(crate) rmap_matched_count: i32,
    pub(crate) matched_base: [u64; 32],
    pub(crate) rmap_matched_base: [u64; 32],
}

/// read_memory 要求 T: Default；数组字段不满足自动派生，所以手写全零默认值。
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
            target_sym: 0,
            target_bias: 0,
            target_present_sol: 0,
            target_present_rmap: 0,
            matched_count: 0,
            rmap_matched_count: 0,
            matched_base: [0u64; 32],
            rmap_matched_base: [0u64; 32],
        }
    }
}

impl ProbeResult {
    /// 同名匹配的 load bias 集合，稳定排序后输出，供脚本按地址集合差分。
    fn bias_list(bases: &[u64], count: i32) -> String {
        let n = (count as usize).min(bases.len());
        let mut items: Vec<String> = bases[..n].iter().map(|b| format!("0x{:x}", b)).collect();
        items.sort();
        items.join(",")
    }

    /// 机器可读的身份/集合输出；脚本的验收断言直接解析这些行。
    /// 计数是全量事实、列表受容量上限（32）约束：两者必须一起比较，
    /// 否则超出容量的新增同名残留会让列表逐字不变而漏检（ISSUE-036）。
    pub(crate) fn dump_sets(&self) {
        log_info!(
            "solist_biases={} solist_match_count={}",
            Self::bias_list(&self.matched_base, self.matched_count),
            self.matched_count
        );
        log_info!(
            "rmap_biases={} rmap_match_count={}",
            Self::bias_list(&self.rmap_matched_base, self.rmap_matched_count),
            self.rmap_matched_count
        );
    }
}

/// 身份核对：探针必须认出 host 指定的目标库（target_bias != 0），
/// 否则后续“已消失”没有参照物，无法与“从未找到”区分。
pub(crate) fn confirm_identity(result: &ProbeResult) -> Result<u64, String> {
    if result.target_bias == 0 {
        return Err(
            "身份核对失败：探针在双链上找不到 target_sym 所属的库，无法确定待验证身份".to_string(),
        );
    }
    log_success!("身份核对: target_sym=0x{:x} -> target_bias=0x{:x}", result.target_sym, result.target_bias);
    Ok(result.target_bias)
}

/// 隐藏验收（按身份，不按名字）：待验证库的 load bias 必须同时不在
/// solist 遍历与 _r_debug.r_map 上。同名的合法保留载荷（如测试空 SO）
/// 不参与判定——这正是 ISSUE-032 名字合并计数误判的修复点。
pub(crate) fn verify_hidden(result: &ProbeResult, expected_bias: u64) -> Result<(), String> {
    if result.target_bias != expected_bias {
        return Err(format!(
            "身份漂移：探针核对出 target_bias=0x{:x}，与隐藏前确认的 0x{:x} 不一致",
            result.target_bias, expected_bias
        ));
    }
    if result.target_present_sol != 0 || result.target_present_rmap != 0 {
        log_error!(
            "独立枚举发现残留: 身份 0x{:x} 仍在链上（solist={} r_map={}）",
            expected_bias, result.target_present_sol, result.target_present_rmap
        );
        return Err(format!(
            "隐藏未被外部观测确认：身份 0x{:x} 仍在 solist={} r_map={}",
            expected_bias, result.target_present_sol, result.target_present_rmap
        ));
    }
    log_success!("独立枚举确认: 身份 0x{:x} 已同时不在 solist 与 r_map", expected_bias);
    Ok(())
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

/// 目标 maps 中 /memfd:wwb 映射条目数；探针卸载前后差分必须为 0。
fn count_memfd_wwb(pid: i32) -> Result<usize, String> {
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))
        .map_err(|e| format!("读取目标 maps 失败: {}", e))?;
    Ok(maps.lines().filter(|l| l.contains("/memfd:wwb")).count())
}

/// 每次探测用唯一加载名。
/// 为什么：bionic 按 soname 缓存已加载库（probe.so 的 -Wl,-soname,probe.so 与
/// dlopen 名同名）。复用同一加载名会让一次泄漏的引用计数把探针变成永久驻留实例，
/// 后续每次“加载”都命中缓存复用它、“自卸”只减计数永不真正卸载，而且它永远被
/// 自身排除规则隐彤——实测泄漏后 total 不变、self_skipped 恒 1、集合差分恒为空。
/// 唯一名强制每次全新实例：泄漏实例才能以名字身份落进 bias 集合被检出。
fn unique_probe_name() -> String {
    unique_load_name("probe")
}

/// 注入探针 SO，在目标进程内用 dl_iterate_phdr 与 _r_debug.r_map 枚举已加载库。
///
/// 这是独立证据：探针不引用 hide 代码，走的是 bionic 公开 API 与调试器链。
/// `target` 是待验证库的身份锚点（目标库内一个地址 + 可选已确认 bias）：
/// 隐藏前的确认运行传 (sym, 0)，探针用 dladdr + 枚举包含关系独立核对出
/// load bias；隐藏后的验收运行传 (sym, 已确认 bias)——此时目标已不在 solist，
/// dladdr 反查不到，预填 bias 让探针仍能在 r_map 上按身份判定，同名载荷不参与
/// 判定（ISSUE-032）。
///
/// 探针自身也叫 wwb_so（同一个 memfd 名），所以：读完结果必须自卸（dlclose），
/// 且卸载成功是本函数返回 Ok 的必要条件（ISSUE-034）——卸载失败必须响亮报错，
/// 否则探针自己留在枚举结果里，下一次探测会把它当成历史残留。
pub(crate) fn run_independent_probe(
    pid: i32,
    offsets: &LibcOffsets,
    dl: &DlOffsets,
    target: Option<(usize, u64)>,
) -> Result<ProbeResult, String> {
    let maps_before = count_memfd_wwb(pid)?;
    let probe_label = unique_probe_name();
    let memfd = create_and_fill_memfd(pid, offsets, PROBE_SO, &probe_label)?;
    let handle = match dlopen_agent_via_ptrace(pid, memfd, offsets, dl, &probe_label) {
        Ok(h) => h,
        Err(e) => {
            let _ = call_target_function(pid, offsets.close, &[memfd as usize], None);
            return Err(e);
        }
    };
    let _ = call_target_function(pid, offsets.close, &[memfd as usize], None);

    let outcome = probe_with_handle(pid, offsets, dl, handle, target);
    // 卸载与测量结果都必须交代：任何一侧失败都不能把“成功”交出去。
    let unload = verify_probe_unloaded(pid, offsets, dl, handle, maps_before);
    match (outcome, unload) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(measure), Ok(())) => Err(measure),
        (Ok(_), Err(unload)) => Err(unload),
        (Err(measure), Err(unload)) => Err(format!("{}；{}", measure, unload)),
    }
}

/// 探针自卸并验证确已消失（ISSUE-034）。
///
/// 顺序契约：先远程 dlclose 并检查返回码，再用 maps 差分确认探针映射已消失，
/// 才允许调用方把测量结果当真。任一步失败都返回 Err，绝不记日志后照常成功。
fn verify_probe_unloaded(pid: i32, offsets: &LibcOffsets, dl: &DlOffsets, handle: usize, maps_before: usize) -> Result<(), String> {
    // 故障注入点：跳过真实 dlclose，模拟卸载远程调用失败分支。
    // 断言方向：本函数必须响亮报错，且后续探测能按地址检出被留下的探针。
    if fault::wants_stage(fault::FAULT_PROBE_DLCLOSE_FAIL) {
        fault::note_marker(fault::FAULT_PROBE_DLCLOSE_FAIL, "跳过探针 dlclose，模拟卸载失败分支");
        return Err("探针卸载失败：测试故障注入跳过了 dlclose（探针将留在目标中）".to_string());
    }
    let rc = call_target_function(pid, dl.dlclose, &[handle], None)
        .map_err(|e| format!("探针卸载失败: dlclose 远程调用异常: {}", e))?;
    if rc as i32 != 0 {
        return Err(format!("探针卸载失败: dlclose 返回 {}", rc as i32));
    }
    let maps_after = count_memfd_wwb(pid)?;
    if maps_after != maps_before {
        return Err(format!(
            "探针卸载失败: maps 仍有映射残留（卸载前 {} 条，卸载后 {} 条 /memfd:wwb）",
            maps_before, maps_after
        ));
    }
    log_success!("探针已自卸并确认消失（maps {} 条 /memfd:wwb 不变）", maps_after);
    Ok(())
}

/// 已加载探针后的测量流程；不做验收裁决，只校验结构可信并回填结果。
fn probe_with_handle(
    pid: i32,
    offsets: &LibcOffsets,
    dl: &DlOffsets,
    handle: usize,
    target: Option<(usize, u64)>,
) -> Result<ProbeResult, String> {
    // 结果缓冲区分配在目标进程，探针填完由 host 读回。
    // RemoteAlloc 守卫接管回收：本函数任一 `?` 出口都不能漏 free（ISSUE-037）。
    let size = size_of::<ProbeResult>();
    let buf = RemoteAlloc::alloc(pid, offsets, size)?;
    let buf_addr = buf.addr();
    for off in (0..size).step_by(8) {
        write_bytes(pid, buf_addr + off, &[0u8; 8])?;
    }
    // 故障注入点（ISSUE-037 反证）：分配后任意步骤失败都必须回收目标堆缓冲区。
    fault::maybe_fail(fault::FAULT_PROBE_MEASURE_FAIL)?;
    // target_sym / target_bias 是传给探针的输入（身份锚点），在清零后写入对应字段；
    // 隐藏后 dladdr 反查不到目标，预填 bias 才能让探针按身份判定 r_map。
    if let Some((sym, bias)) = target {
        write_bytes(pid, buf_addr + offset_of!(ProbeResult, target_sym), &(sym as u64).to_ne_bytes())?;
        write_bytes(pid, buf_addr + offset_of!(ProbeResult, target_bias), &bias.to_ne_bytes())?;
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
        return Err("dlsym(probe_solist_visibility) 返回 NULL".to_string());
    }
    let rc = call_target_function(pid, fn_ptr, &[r_map_head, buf_addr], None)
        .map_err(|e| format!("调用 probe_solist_visibility 失败: {}", e))? as i32;
    let result = read_memory::<ProbeResult>(pid, buf_addr)?;
    if rc != 0 {
        return Err(format!("probe_solist_visibility 返回 {}", rc));
    }
    if result.version != PROBE_VERSION {
        return Err(format!(
            "探针与 host 结构不一致: version={} (期望 {})",
            result.version, PROBE_VERSION
        ));
    }
    let name = {
        let end = result.matched_name.iter().position(|&c| c == 0).unwrap_or(result.matched_name.len());
        String::from_utf8_lossy(&result.matched_name[..end]).into_owned()
    };
    log_info!(
        "独立枚举: solist 共 {} 个库/同名匹配 {}；r_map 共 {} 个节点/同名匹配 {}（跳过自身 {}）",
        result.total,
        result.wwb_matches,
        result.rmap_total,
        result.rmap_wwb_matches,
        result.self_skipped
    );
    result.dump_sets();
    if result.wwb_matches != 0 || result.rmap_wwb_matches != 0 {
        log_info!(
            "同名载荷在场（仅诊断，不参与验收）: solist={} r_map={} name=\"{}\"",
            result.wwb_matches,
            result.rmap_wwb_matches,
            name
        );
    }
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
    Ok(result)
}
