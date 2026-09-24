#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{c_int, c_void, iovec, pid_t, PTRACE_CONT, PTRACE_GETREGSET, PTRACE_SETREGSET};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::fs::File;
use std::mem::size_of_val;
use std::path::Path;
use std::process;

use crate::log_success;
use crate::log_warn;
use crate::types::UserRegs;

/// 获取指定库的基址
///
/// # 参数
/// * `pid`      - 进程ID，`None` 表示查询当前进程
/// * `lib_name` - 要查找的库名称（如 "libc.so"、"libdl.so"）
pub(crate) fn get_lib_base(pid: Option<i32>, lib_name: &str) -> Result<usize, String> {
    let maps_path = match pid {
        Some(pid) => format!("/proc/{}/maps", pid),
        None => "/proc/self/maps".to_string(),
    };

    if !Path::new(&maps_path).exists() {
        return Err(format!("进程 {} 不存在", pid.unwrap_or(-1)));
    }

    let mut file = File::open(&maps_path).map_err(|e| format!("无法打开maps文件: {}", e))?;
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut raw).map_err(|e| format!("读取maps文件失败: {}", e))?;

    for line in String::from_utf8_lossy(&raw).lines() {
        if line.contains(lib_name) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr_range) = parts.get(0) {
                if let Some(start_addr) = addr_range.split('-').next() {
                    return usize::from_str_radix(start_addr, 16).map_err(|e| format!("解析地址失败: {}", e));
                }
            }
        }
    }

    Err(format!("未找到进程 {} 的{}加载地址", pid.unwrap_or(-1), lib_name))
}

fn find_map_line_for_addr(pid: i32, addr: u64) -> Option<String> {
    let maps_path = format!("/proc/{}/maps", pid);
    let mut file = File::open(&maps_path).ok()?;
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut raw).ok()?;

    for line in String::from_utf8_lossy(&raw).lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let mut it = range.split('-');
        let start = u64::from_str_radix(it.next()?, 16).ok()?;
        let end = u64::from_str_radix(it.next()?, 16).ok()?;
        if addr >= start && addr < end {
            return Some(line.to_string());
        }
    }
    None
}

pub(crate) fn attach_to_process(pid: i32) -> Result<(), String> {
    let target_pid = Pid::from_raw(pid);

    // PTRACE_SEIZE + INTERRUPT 取代 PTRACE_ATTACH + SIGSTOP。
    // 为什么：ATTACH 注入的 SIGSTOP 在反复 attach/detach 后会累积成 pending
    // group-stop（实测 SigPnd=0x40000），后续 attach 的 waitpid 永久等不到新的
    // stop 通知而挂死；rustfrida 被外层 timeout 杀掉后又留下孤儿 tracer，
    // 目标后续 attach 全部 EPERM。SEIZE 不注入任何信号，INTERRUPT 产生
    // PTRACE_EVENT_STOP，无信号残留。
    if let Err(errno) = ptrace_request(PTRACE_SEIZE, target_pid) {
        return Err(attach_errmsg(errno));
    }
    if let Err(errno) = ptrace_request(PTRACE_INTERRUPT, target_pid) {
        let _ = ptrace::detach(target_pid, None);
        return Err(attach_errmsg(errno));
    }
    log_success!("成功附加到进程 {}，等待 PTRACE_EVENT_STOP...", pid);

    // waitpid 必须带超时：挂死时自行 detach，绝不把 rustfrida 留成孤儿 tracer
    // （孤儿 tracer 会让目标后续所有 attach 失败，违反失败后可恢复）。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match waitpid(target_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if std::time::Instant::now() >= deadline {
                    let _ = ptrace::detach(target_pid, None);
                    return Err("等待 PTRACE_EVENT_STOP 超时（已自行 detach，不留孤儿 tracer）".to_string());
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Ok(WaitStatus::Stopped(_, _)) | Ok(WaitStatus::PtraceEvent(_, _, _)) => {
                log_success!("进程已停止，可以操作寄存器");
                return Ok(());
            }
            other => {
                let _ = ptrace::detach(target_pid, None);
                return Err(format!("waitpid 状态异常: {:?}", other));
            }
        }
    }
}

fn attach_errmsg(errno: Errno) -> String {
    match errno {
        Errno::EPERM => "权限不足，请使用root权限运行".to_string(),
        Errno::ESRCH => "目标进程不存在".to_string(),
        _ => "附加失败，未知错误".to_string(),
    }
}

// nix 只在 target_os=linux 暴露 seize/interrupt（android 被 cfg 排除），
// 但 bionic 的 ptrace(2) 完全支持这两个请求。直接封装同一系统调用，
// 避免退回注入 SIGSTOP 的 ATTACH 路径（SIGSTOP 残留会累积挂死后续 attach）。
const PTRACE_SEIZE: libc::c_int = 0x4206;
const PTRACE_INTERRUPT: libc::c_int = 0x4207;

fn ptrace_request(request: libc::c_int, pid: Pid) -> Result<(), Errno> {
    let ret = unsafe {
        libc::ptrace(
            request,
            pid.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret == -1 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

/// 获取进程寄存器
fn get_registers(pid: i32) -> Result<UserRegs, String> {
    let mut regs = UserRegs::default();
    let mut iov = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: size_of_val(&mut regs),
    };
    let result = unsafe {
        libc::ptrace(
            PTRACE_GETREGSET,
            pid as pid_t,
            1, // 通用寄存器
            &mut iov as *mut _ as *mut c_void,
        )
    };

    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("获取寄存器失败，错误码: {}", errno));
    }
    Ok(regs)
}

/// 设置进程寄存器
fn set_registers(pid: i32, regs: &UserRegs) -> Result<(), String> {
    let mut iov = iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: size_of_val(regs),
    };
    let result = unsafe { libc::ptrace(PTRACE_SETREGSET, pid as pid_t, 1, &mut iov as *mut _ as *mut c_void) };
    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("设置寄存器失败，错误码: {}", errno));
    }
    Ok(())
}

/// 目标 cgroup v2 冻结位路径；None 表示该目标没有可操作的冻结位（如宿主非 cgroup v2）。
fn freeze_path(pid: i32) -> Option<String> {
    let cgroups = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
    let rel = cgroups.lines().find_map(|l| l.strip_prefix("0::"))?;
    let path = format!("/sys/fs/cgroup{}/cgroup.freeze", rel);
    std::fs::metadata(&path).ok()?;
    Some(path)
}

/// 会话期间解冻被系统冷藏的目标；返回冻结位路径供收尾恢复（未冻结返回 None）。
/// 为什么：Android cached-app freezer（cgroup.freeze=1）让目标连 PTRACE_CONT 的
/// 代码都无法执行——实测 mmap 级远程调用全部超时，而目标 State 仍显示 S，
/// 极难诊断。root 工具要对目标做注入，目标必须能跑起来。
pub(crate) fn thaw_target_for_session(pid: i32) -> Option<String> {
    let path = freeze_path(pid)?;
    let frozen = std::fs::read_to_string(&path).ok()?;
    if frozen.trim() != "1" {
        return None;
    }
    std::fs::write(&path, "0").ok()?;
    log_warn!("目标 {} 被系统冻结（cached freezer），会话期间已临时解冻", pid);
    Some(path)
}

/// 把冻结位恢复到会话前状态：系统记账里目标仍是冻结态，工具不能留下状态漂移。
pub(crate) fn restore_target_freeze(path: &str) {
    if let Err(e) = std::fs::write(path, "1") {
        log_warn!("恢复目标冻结位失败 {}: {}", path, e);
    }
}

/// 调用目标进程的 libc 函数
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `func_addr` - 要调用的函数地址
/// * `args` - 函数参数列表
///
/// # 返回值
/// * `Ok(usize)` - 函数返回值
/// * `Err(String)` - 错误信息
pub(crate) fn call_target_function(
    pid: i32,
    func_addr: usize,
    args: &[usize],
    debug: Option<bool>,
) -> Result<usize, String> {
    // 获取当前寄存器状态
    let orig_regs = get_registers(pid)?;

    // 设置新的寄存器状态
    let mut new_regs = orig_regs;

    // 设置参数寄存器（ARM64 使用 X0-X7 寄存器传递参数）
    for (i, &arg) in args.iter().enumerate() {
        if i < 8 {
            new_regs.regs[i] = arg as u64;
        } else {
            break;
        }
    }

    // 设置返回地址为 0x340
    new_regs.regs[30] = 0x340; // X30 是链接寄存器 (LR)

    // 设置 PC 指向函数地址
    new_regs.pc = func_addr as u64;

    // 写入新寄存器值
    set_registers(pid, &new_regs)?;

    // 继续执行
    if debug.unwrap_or(false) {
        let _ = ptrace::cont(Pid::from_raw(pid), Some(Signal::SIGSTOP));
        process::exit(1);
    }

    let target_pid = Pid::from_raw(pid);

    // 重试循环：处理 spawn 模式下的 pending SIGSTOP
    // 子进程 raise(SIGSTOP) + ptrace attach 的 SIGSTOP 会产生 pending 信号，
    // 导致 PTRACE_CONT 后进程立即被 SIGSTOP 再次停止。
    // 遇到 SIGSTOP 时吞掉信号并重新 CONT，最多重试 3 次。
    let max_sigstop_retries = 3;
    for attempt in 0..=max_sigstop_retries {
        let result = unsafe { libc::ptrace(PTRACE_CONT as c_int, pid as pid_t, 0, 0) };

        if result == -1 {
            return Err(format!("继续执行失败，错误码: {}", unsafe {
                *libc::__errno()
            }));
        }

        // 有界等待目标停止（ISSUE-033）：无限期 waitpid 是挂死与孤儿 tracer 的来源。
        let stop_status = match wait_for_stop_bounded(target_pid, REMOTE_CALL_TIMEOUT_SECS)? {
            Some(status) => status,
            None => return abort_hung_remote_call(pid, target_pid, &orig_regs),
        };
        match stop_status {
            WaitStatus::Stopped(_, Signal::SIGSEGV) => {
                // 获取寄存器，检查 PC 是否为预期值
                let regs = get_registers(pid)?;

                if regs.pc == 0x340 {
                    // 函数执行完成，获取返回值（ARM64 使用 X0 寄存器返回值）
                    let return_value = regs.regs[0] as usize;

                    // 恢复原始寄存器状态
                    set_registers(pid, &orig_regs)?;

                    return Ok(return_value);
                } else {
                    let pc_map =
                        find_map_line_for_addr(pid, regs.pc).unwrap_or_else(|| "<unknown mapping>".to_string());
                    let lr_map =
                        find_map_line_for_addr(pid, regs.regs[30]).unwrap_or_else(|| "<unknown mapping>".to_string());
                    let _ = set_registers(pid, &orig_regs);
                    return Err(format!(
                        concat!(
                            "函数执行异常，",
                            "PC=0x{:x} [{}], ",
                            "LR=0x{:x} [{}], ",
                            "SP=0x{:x}, ",
                            "X0=0x{:x}, X1=0x{:x}, X2=0x{:x}, X3=0x{:x}"
                        ),
                        regs.pc,
                        pc_map,
                        regs.regs[30],
                        lr_map,
                        regs.sp,
                        regs.regs[0],
                        regs.regs[1],
                        regs.regs[2],
                        regs.regs[3]
                    ));
                }
            }
            WaitStatus::Stopped(_, Signal::SIGSTOP) => {
                // spawn 模式下 pending SIGSTOP：吞掉信号，重新 CONT
                if attempt < max_sigstop_retries {
                    log_warn!("检测到 pending SIGSTOP (第{}次)，跳过并重试", attempt + 1);
                    continue;
                } else {
                    return Err("多次 SIGSTOP 中断，无法执行目标函数".to_string());
                }
            }
            status => return Err(format!("进程异常停止: {:?}", status)),
        }
    }
    Err("call_target_function: 超出重试次数".to_string())
}

/// 远程调用等待上限（ISSUE-033）：超过即认定目标函数不会返回，走恢复序列。
/// 没有这个上限，rustfrida 会永久阻塞在 waitpid 上，被外层杀掉后留下孤儿 tracer，
/// 目标后续 attach 全部 EPERM——失败后不可恢复。
const REMOTE_CALL_TIMEOUT_SECS: u64 = 15;
/// 超时恢复序列里等待目标停住（PTRACE_EVENT_STOP）的上限。
const STOP_CONFIRM_TIMEOUT_SECS: u64 = 5;

/// 有界等待目标进入 ptrace 停止态；Ok(None) 表示超时内没有停止事件。
fn wait_for_stop_bounded(pid: Pid, timeout_secs: u64) -> Result<Option<WaitStatus>, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if std::time::Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Ok(status) => return Ok(Some(status)),
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(format!("等待进程失败: {}", e)),
        }
    }
}

/// 超时恢复序列（顺序契约）：先 INTERRUPT 让目标离开运行态，确认停住后恢复
/// 寄存器现场，最后把错误交还调用方。恢复是无条件不变量——任何前置步骤失败
/// 都不允许跳过它，否则线程会留在被劫持的调用体里（实测：留在自旋桩上把主线程
/// 拖死，目标被 ANR 杀掉）。本函数不 detach——detach 归 Guard/注入流程统一收尾。
///
/// 为什么恢复寄存器就足以安全中止阻塞在系统调用里的调用：内核的 -ERESTARTSYS
/// 重启开关（do_signal）判断的是返回值寄存器 x0 是否为 -ERESTART* 码，而恢复
/// orig 寄存器已把 x0 改回调用前的值（用户参数，不可能是重启码），重启随之解除
/// 武装，目标回到调用前的精确现场。若被中止的函数在用户态临界区中途（如持有
/// 堆锁时陷入等待），回卷无法回退它已做的用户态修改，目标可能需要重启——这是
/// 已知边界；纯用户态自旋与阻塞在系统调用等待两种形态已在真机反证中验证可恢复。
/// 若目标连 INTERRUPT 都停不下来（不可中断睡眠），则不恢复现场、直接报错：
/// 此时 rustfrida 退出后内核会自动 detach，比留下半恢复现场更安全。
fn abort_hung_remote_call(
    pid: i32,
    target_pid: Pid,
    orig_regs: &UserRegs,
) -> Result<usize, String> {
    if let Err(e) = ptrace_request(PTRACE_INTERRUPT, target_pid) {
        return Err(format!("远程调用超时，且中断请求失败: {}（不恢复现场）", e));
    }
    match wait_for_stop_bounded(target_pid, STOP_CONFIRM_TIMEOUT_SECS)? {
        Some(_) => {
            set_registers(pid, orig_regs)?;
            Err("远程调用超时未返回（已中断并恢复现场）".to_string())
        }
        None => Err("远程调用超时，目标未能停住（不恢复现场，由进程退出自动 detach）".to_string()),
    }
}

/// 向远程进程内存写入任意类型的数据
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的数据指针
/// * `size` - 数据大小（字节数）
fn write_remote_mem(pid: i32, addr: usize, data: *const u8, size: usize) -> Result<(), String> {
    // 去掉 MTE 标签位（高 byte），ptrace 不支持带标签的地址
    let addr = addr & 0x00FFFFFFFFFFFFFF;
    let mut offset = 0;
    while offset < size {
        let remaining = size - offset;
        let write_size = if remaining >= 8 { 8 } else { remaining };

        // 非对齐尾部（< 8 字节）：先 PEEKTEXT 读取原始 8 字节，再 merge 新字节，
        // 避免 POKETEXT 始终写满 8 字节时覆盖紧随其后的数据。
        let mut word: u64 = if write_size < 8 {
            unsafe { *libc::__errno() = 0 };
            let existing = unsafe {
                libc::ptrace(
                    libc::PTRACE_PEEKTEXT,
                    pid as pid_t,
                    (addr + offset) as *mut c_void,
                    std::ptr::null_mut::<c_void>(),
                )
            };
            let errno_val = unsafe { *libc::__errno() };
            if existing == -1 && errno_val != 0 {
                return Err(format!(
                    "读取内存失败(PEEKTEXT) addr=0x{:x} offset={} errno={}",
                    addr, offset, errno_val
                ));
            }
            existing as u64
        } else {
            0
        };

        // 合并新字节到 word（低字节 → 低地址，ARM64 小端序）
        unsafe {
            std::ptr::copy_nonoverlapping(data.add(offset), &mut word as *mut u64 as *mut u8, write_size);
        }

        // 写入目标进程
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_POKETEXT,
                pid as pid_t,
                (addr + offset) as *mut c_void,
                word as usize as *mut c_void,
            )
        };

        if result == -1 {
            let errno = unsafe { *libc::__errno() };
            return Err(format!(
                "写入内存失败 addr=0x{:x} offset={} size={} errno={}",
                addr, offset, size, errno
            ));
        }

        offset += write_size;
    }

    Ok(())
}

/// 向远程进程内存写入任意类型的数据的泛型包装
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的数据（任意类型）
pub(crate) fn write_memory<T>(pid: i32, addr: usize, data: &T) -> Result<(), String> {
    write_remote_mem(pid, addr, data as *const T as *const u8, size_of_val(data))
}

/// 向远程进程内存写入字节数组
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的字节数组
pub(crate) fn write_bytes(pid: i32, addr: usize, data: &[u8]) -> Result<(), String> {
    write_remote_mem(pid, addr, data.as_ptr(), data.len())
}

/// 从远程进程内存读取数据
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `size` - 读取字节数
fn read_remote_mem(pid: i32, addr: usize, size: usize) -> Result<Vec<u8>, String> {
    let addr = addr & 0x00FFFFFFFFFFFFFF; // 去掉 MTE 标签位
    let mut result = vec![0u8; size];
    let mut offset = 0;
    while offset < size {
        unsafe { *libc::__errno() = 0 };
        let word = unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKTEXT,
                pid as pid_t,
                (addr + offset) as *mut c_void,
                std::ptr::null_mut::<c_void>(),
            )
        };
        let errno_val = unsafe { *libc::__errno() };
        if word == -1 && errno_val != 0 {
            return Err(format!(
                "读取内存失败(PEEKTEXT) addr=0x{:x} offset={} errno={}",
                addr, offset, errno_val
            ));
        }
        let remaining = size - offset;
        let copy_size = remaining.min(8);
        unsafe {
            std::ptr::copy_nonoverlapping(
                &word as *const i64 as *const u8,
                result.as_mut_ptr().add(offset),
                copy_size,
            );
        }
        offset += 8;
    }
    Ok(result)
}

/// 从远程进程读取任意类型的数据
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址（目标进程中的内存地址）
pub(crate) fn read_memory<T: Default>(pid: i32, addr: usize) -> Result<T, String> {
    let bytes = read_remote_mem(pid, addr, std::mem::size_of::<T>())?;
    let mut val = T::default();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), &mut val as *mut T as *mut u8, std::mem::size_of::<T>());
    }
    Ok(val)
}

/// maps 条目结构
#[derive(Debug, Clone)]
pub(crate) struct MapEntry {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) perms: String,
    pub(crate) offset: u64,
    pub(crate) path: String,
}

impl MapEntry {
    pub(crate) fn is_readable(&self) -> bool {
        self.perms.starts_with('r')
    }

    pub(crate) fn is_writable(&self) -> bool {
        self.perms.len() >= 2 && self.perms.as_bytes()[1] == b'w'
    }

    pub(crate) fn is_executable(&self) -> bool {
        self.perms.len() >= 3 && self.perms.as_bytes()[2] == b'x'
    }

    pub(crate) fn is_shared(&self) -> bool {
        self.perms.contains('s')
    }
}

/// 结构化解析 /proc/<pid>/maps
pub(crate) fn parse_proc_maps(pid: u32) -> Result<Vec<MapEntry>, String> {
    let maps_path = format!("/proc/{}/maps", pid);
    let mut file = File::open(&maps_path).map_err(|e| format!("无法打开 {}: {}", maps_path, e))?;
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut raw).map_err(|e| format!("读取 {} 失败: {}", maps_path, e))?;
    let mut entries = Vec::new();

    for line in String::from_utf8_lossy(&raw).lines() {
        let line = line.to_string();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            continue;
        }

        let start = u64::from_str_radix(addr_parts[0], 16).map_err(|e| format!("解析地址失败: {}", e))?;
        let end = u64::from_str_radix(addr_parts[1], 16).map_err(|e| format!("解析地址失败: {}", e))?;

        let perms = parts[1].to_string();
        let offset = if parts.len() > 2 {
            u64::from_str_radix(parts[2], 16).unwrap_or(0)
        } else {
            0
        };
        let path = if parts.len() >= 6 {
            parts[5..].join(" ")
        } else {
            String::new()
        };

        entries.push(MapEntry {
            start,
            end,
            perms,
            offset,
            path,
        });
    }

    Ok(entries)
}

/// 读取 /proc/<pid>/stat 判断进程是否处于 stopped 状态
pub(crate) fn is_process_stopped(pid: u32) -> bool {
    let stat_path = format!("/proc/{}/stat", pid);
    if let Ok(data) = std::fs::read_to_string(&stat_path) {
        // /proc/pid/stat 格式: pid (comm) state ...
        // state 在最后一个 ')' 之后的第一个非空字符
        if let Some(pos) = data.rfind(')') {
            let rest = &data[pos + 1..];
            let state = rest.trim().chars().next().unwrap_or('?');
            return state == 'T' || state == 't';
        }
    }
    false
}

/// 递增延迟轮询等待进程停止（0/1/2/5/10/20/50/250ms），5s 超时
pub(crate) fn wait_until_stopped(pid: u32) -> Result<(), String> {
    let delays = [0, 1, 2, 5, 10, 20, 50, 250];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut idx = 0;

    loop {
        if is_process_stopped(pid) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("等待进程 {} 停止超时 (5s)", pid));
        }
        let delay = delays[idx.min(delays.len() - 1)];
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
        idx += 1;
    }
}

/// 通过读 /proc/*/cmdline 按进程名查找 PID。
/// 精确匹配（含末路径组件）；多匹配列出并返回错误。
pub(crate) fn find_pid_by_name(name: &str) -> Result<i32, String> {
    use std::fs;

    let mut matches: Vec<i32> = Vec::new();
    let proc_dir = fs::read_dir("/proc").map_err(|e| format!("读取 /proc 失败: {}", e))?;

    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();
        if !fname_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: i32 = match fname_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(data) = fs::read(&cmdline_path) {
            let proc_name = data
                .split(|&b| b == 0)
                .next()
                .and_then(|s| std::str::from_utf8(s).ok())
                .unwrap_or("");
            let base_name = proc_name.rsplit('/').next().unwrap_or(proc_name);
            if proc_name == name || base_name == name {
                matches.push(pid);
            }
        }
    }

    match matches.len() {
        0 => Err(format!("未找到进程名匹配 '{}'", name)),
        1 => Ok(matches[0]),
        _ => {
            log_warn!("找到多个匹配进程，请使用 --pid 指定:");
            for pid in &matches {
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                let display = if let Ok(data) = std::fs::read(&cmdline_path) {
                    data.split(|&b| b == 0)
                        .filter(|s| !s.is_empty())
                        .take(2)
                        .flat_map(|s| std::str::from_utf8(s))
                        .collect::<Vec<_>>()
                        .join(" ")
                } else {
                    "?".to_string()
                };
                println!("  PID {:6}: {}", pid, display);
            }
            Err(format!("找到 {} 个匹配进程，请使用 --pid <n> 精确指定", matches.len()))
        }
    }
}
