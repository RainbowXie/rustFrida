#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{c_void, close, write as libc_write};
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::mem::size_of;
use std::os::unix::io::RawFd;

use crate::process::{attach_to_process, call_target_function, get_lib_base, read_memory, write_bytes, write_memory};
use crate::types::{write_string_table, AgentArgs, DlOffsets, LibcOffsets};
use crate::{log_error, log_info, log_success, log_verbose, log_verbose_addr, log_warn};

pub(crate) const SHELLCODE: &[u8] = include_bytes!("../../loader/build/loader.bin");

#[cfg(debug_assertions)]
pub(crate) const AGENT_SO: &[u8] = include_bytes!("../../target/aarch64-linux-android/debug/libagent.so");

#[cfg(not(debug_assertions))]
pub(crate) const AGENT_SO: &[u8] = include_bytes!("../../target/aarch64-linux-android/release/libagent.so");

#[cfg(feature = "qbdi")]
pub(crate) const QBDI_HELPER_SO: &[u8] = include_bytes!(env!("QBDI_HELPER_SO_PATH"));

/// 最小化空 SO（无符号、无 .init_array），用于隔离 memfd 映射检测
const EMPTY_SO: &[u8] = include_bytes!("../../loader/build/empty.so");

/// 在目标进程中分配内存并写入结构体，返回远程地址。
fn alloc_and_write_struct<T>(pid: i32, malloc_addr: usize, data: &T, name: &str) -> Result<usize, String> {
    let size = size_of::<T>();
    let addr =
        call_target_function(pid, malloc_addr, &[size], None).map_err(|e| format!("分配{}内存失败: {}", name, e))?;
    log_verbose!("分配{}内存", name);
    log_verbose_addr!("地址", addr);
    write_memory(pid, addr, data)?;
    log_verbose!("{}写入成功", name);
    log_verbose_addr!("地址", addr);
    Ok(addr)
}

/// 在目标进程中调用 socketpair()，返回 (fd0, fd1)
fn create_socketpair_in_target(pid: i32, offsets: &LibcOffsets) -> Result<(i32, i32), String> {
    // 在目标进程中分配 8 字节存放 int[2]
    let sv_addr = call_target_function(pid, offsets.malloc, &[8], None)
        .map_err(|e| format!("分配 socketpair 缓冲区失败: {}", e))?;

    // 调用 socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, sv_ptr)
    let ret = call_target_function(pid, offsets.socketpair, &[1, 1, 0, sv_addr], None)
        .map_err(|e| format!("调用 socketpair 失败: {}", e))?;

    if ret as isize != 0 {
        return Err(format!("socketpair 返回错误: {}", ret as isize));
    }

    // 读回 fd0, fd1
    let sv: [i32; 2] = read_memory(pid, sv_addr)?;
    log_verbose!("socketpair 创建成功: fd0={}, fd1={}", sv[0], sv[1]);

    // 释放临时缓冲区
    let _ = call_target_function(pid, offsets.free, &[sv_addr], None);

    Ok((sv[0], sv[1]))
}

// aarch64 syscall numbers
const SYS_PIDFD_OPEN: i64 = 434;
const SYS_PIDFD_GETFD: i64 = 438;

/// 通过 pidfd_getfd 从目标进程提取文件描述符到 host
fn extract_fd_from_target(pid: i32, target_fd: i32) -> Result<RawFd, String> {
    // pidfd_open(pid, flags=0)
    let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0) };
    if pidfd < 0 {
        return Err(format!("pidfd_open({}) 失败: {}", pid, std::io::Error::last_os_error()));
    }

    // pidfd_getfd(pidfd, target_fd, flags=0)
    let host_fd = unsafe { libc::syscall(SYS_PIDFD_GETFD, pidfd as i32, target_fd, 0u32) };
    unsafe { close(pidfd as i32) };

    if host_fd < 0 {
        return Err(format!(
            "pidfd_getfd(pid={}, fd={}) 失败: {}",
            pid,
            target_fd,
            std::io::Error::last_os_error()
        ));
    }

    log_verbose!("pidfd_getfd: pid={} target_fd={} → host_fd={}", pid, target_fd, host_fd);
    Ok(host_fd as RawFd)
}

/// 在目标进程中调用 memfd_create()，返回目标进程内的 fd 号
fn create_memfd_in_target(pid: i32, offsets: &LibcOffsets) -> Result<i32, String> {
    let name = b"wwb_so\0";
    let name_addr = call_target_function(pid, offsets.malloc, &[name.len()], None)
        .map_err(|e| format!("分配 memfd name 内存失败: {}", e))?;
    write_bytes(pid, name_addr, name)?;

    // 调用 memfd_create(name, flags=0)
    let ret = call_target_function(pid, offsets.memfd_create, &[name_addr, 0], None)
        .map_err(|e| format!("调用 memfd_create 失败: {}", e))?;

    // 释放临时 name 缓冲区
    let _ = call_target_function(pid, offsets.free, &[name_addr], None);

    let fd = ret as i32;
    if fd < 0 {
        return Err(format!("memfd_create 返回错误: {}", fd));
    }

    log_verbose!("目标进程 memfd_create 成功: fd={}", fd);
    Ok(fd)
}

/// RAII guard: 注入失败时自动关闭 host_fd 并 detach 目标进程
struct InjectionGuard {
    pid: i32,
    host_fd: RawFd,
    disarmed: bool,
}

impl InjectionGuard {
    fn new(pid: i32, host_fd: RawFd) -> Self {
        Self {
            pid,
            host_fd,
            disarmed: false,
        }
    }

    fn set_host_fd(&mut self, host_fd: RawFd) {
        self.host_fd = host_fd;
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }

    /// 注入成功，取走 host_fd，不再自动清理
    fn into_fd(mut self) -> RawFd {
        self.disarmed = true;
        self.host_fd
    }
}

impl Drop for InjectionGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            if self.host_fd >= 0 {
                unsafe { close(self.host_fd) };
            }
            let _ = ptrace::detach(Pid::from_raw(self.pid), None);
        }
    }
}

fn spawn_agent_blob_sender(host_fd: RawFd) -> Result<std::thread::JoinHandle<Result<(), String>>, String> {
    let fd = unsafe { libc::dup(host_fd) };
    if fd < 0 {
        return Err(format!(
            "dup(host_fd={}) 失败: {}",
            host_fd,
            std::io::Error::last_os_error()
        ));
    }

    let payload = AGENT_SO.to_vec();
    Ok(std::thread::spawn(move || {
        let len = (payload.len() as u64).to_le_bytes();
        let mut written = 0usize;
        while written < len.len() {
            let n = unsafe { libc_write(fd, len[written..].as_ptr() as *const c_void, len.len() - written) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                unsafe { close(fd) };
                return Err(format!("发送 agent 长度失败: {}", err));
            }
            written += n as usize;
        }

        let mut written = 0usize;
        while written < payload.len() {
            let n = unsafe {
                libc_write(
                    fd,
                    payload[written..].as_ptr() as *const c_void,
                    payload.len() - written,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                unsafe { close(fd) };
                return Err(format!("发送 agent.so 失败: {}", err));
            }
            written += n as usize;
        }

        unsafe { close(fd) };
        Ok(())
    }))
}

/// 注入 agent 到目标进程，返回 host_fd（socketpair 的 host 端）
pub(crate) fn inject_to_process(
    pid: i32,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<RawFd, String> {
    log_info!("正在附加到进程 PID: {}", pid);

    // 获取自身和目标进程的 libc / libdl 基址
    let self_base = get_lib_base(None, "libc.so")?;
    let target_base = get_lib_base(Some(pid), "libc.so")?;
    let self_dl_base = get_lib_base(None, "libdl.so")?;
    let target_dl_base = get_lib_base(Some(pid), "libdl.so")?;

    log_verbose!("自身 libc.so 基址: 0x{:x}", self_base);
    log_verbose!("目标进程 libc.so 基址: 0x{:x}", target_base);
    log_verbose!("自身 libdl.so 基址: 0x{:x}", self_dl_base);
    log_verbose!("目标进程 libdl.so 基址: 0x{:x}", target_dl_base);

    // 计算目标进程中的函数地址
    let offsets = LibcOffsets::calculate(self_base, target_base)?;
    let dl_offsets = DlOffsets::calculate(self_dl_base, target_dl_base)?;

    // 打印所有函数地址（仅 verbose 模式）
    if crate::logger::is_verbose() {
        offsets.print_offsets();
        dl_offsets.print_offsets();
    }

    // 附加到目标进程
    attach_to_process(pid)?;

    // === socketpair 通道建立 ===
    // 1. 在目标进程中创建 socketpair
    let (fd0, fd1) = create_socketpair_in_target(pid, &offsets)?;

    // 2. 通过 pidfd_getfd 提取 fd0 到 host
    let host_fd = extract_fd_from_target(pid, fd0)?;
    // RAII guard: 后续任何 ? 返回都会自动 close(host_fd) + detach
    let guard = InjectionGuard::new(pid, host_fd);

    // 3. 在目标进程中关闭 fd0（host 已复制，目标只保留 fd1）
    let _ = call_target_function(pid, offsets.close, &[fd0 as usize], None);
    log_verbose!("目标进程 fd0={} 已关闭，fd1={} 保留给 agent", fd0, fd1);

    // === 分配并写入注入数据 ===
    log_verbose!("开始分配内存");

    // 写入字符串表
    let string_table_addr = write_string_table(pid, offsets.malloc, string_overrides)?;
    log_verbose!("字符串表写入成功");
    log_verbose_addr!("地址", string_table_addr);

    // 分配并写入 AgentArgs
    let agent_args = AgentArgs {
        table: string_table_addr as u64,
        ctrl_fd: fd1,
        agent_memfd: -1,
    };
    let agent_args_addr = alloc_and_write_struct(pid, offsets.malloc, &agent_args, "AgentArgs")?;

    let page_size = 4096;
    let shellcode_len = ((SHELLCODE.len() + page_size - 1) / page_size) * page_size;
    let mmap_prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    let mmap_flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let shellcode_addr = call_target_function(
        pid,
        offsets.mmap,
        &[0, shellcode_len, mmap_prot as usize, mmap_flags as usize, !0usize, 0],
        None,
    )
    .map_err(|e| format!("调用 mmap 失败: {}", e))?;
    log_verbose!("分配shellcode内存");
    log_verbose_addr!("地址", shellcode_addr);

    write_bytes(pid, shellcode_addr, SHELLCODE)?;
    log_verbose!("Shellcode写入成功");
    log_verbose_addr!("地址", shellcode_addr);

    let offsets_addr = alloc_and_write_struct(pid, offsets.malloc, &offsets, "offsets")?;
    let dloffset_addr = alloc_and_write_struct(pid, offsets.malloc, &dl_offsets, "dloffsets")?;
    let sender = spawn_agent_blob_sender(host_fd)?;

    match call_target_function(
        pid,
        shellcode_addr,
        &[offsets_addr, dloffset_addr, string_table_addr, agent_args_addr],
        None,
    ) {
        Ok(return_value) => {
            let ret = return_value as u32 as i32 as isize;
            log_verbose!("Shellcode 执行完成，返回值: 0x{:x}", ret);
            if ret != 1 {
                let reason = match ret {
                    -3 => "（已废弃，不应出现）",
                    -5 => "android_dlopen_ext 失败（SO 加载失败）",
                    -6 => "pthread_create 失败（无法创建 agent 线程）",
                    -7 => "dlsym 失败（未找到 hello_entry 符号）",
                    -8 => "loader memfd_create 失败",
                    -9 => "loader 读取 agent 长度失败",
                    -10 => "loader 接收 agent blob 失败",
                    -11 => "loader 写入 memfd 失败",
                    -12 => "dlsym(hide_from_solist) 失败",
                    -13 => "加载成功但隐藏事务失败",
                    _ => "未知错误",
                };
                let _ = call_target_function(pid, offsets.munmap, &[shellcode_addr, shellcode_len], None);
                let _ = ptrace::detach(Pid::from_raw(pid), None);
                let fd = guard.into_fd();
                unsafe { close(fd) };
                return Err(format!("Shellcode 执行失败 ({}): {}", ret, reason));
            }

            match sender.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let _ = ptrace::detach(Pid::from_raw(pid), None);
                    let fd = guard.into_fd();
                    unsafe { close(fd) };
                    return Err(e);
                }
                Err(_) => {
                    let _ = ptrace::detach(Pid::from_raw(pid), None);
                    let fd = guard.into_fd();
                    unsafe { close(fd) };
                    return Err("agent 发送线程 panic".to_string());
                }
            }

            log_verbose!("正在释放shellcode内存...");
            match call_target_function(pid, offsets.munmap, &[shellcode_addr, shellcode_len], None) {
                Ok(_) => log_verbose!("Shellcode内存释放成功"),
                Err(e) => log_error!("释放shellcode内存失败: {}", e),
            }

            if let Err(e) = ptrace::detach(Pid::from_raw(pid), None) {
                log_error!("分离目标进程失败: {}", e);
            } else {
                log_success!("已分离目标进程");
            }
            Ok(guard.into_fd())
        }
        Err(e) => {
            log_error!("执行 shellcode 失败: {}", e);
            let fd = guard.into_fd();
            unsafe { close(fd) };
            let _ = ptrace::detach(Pid::from_raw(pid), None);
            Err(e)
        }
    }
}

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
        }
    }

    pub(crate) fn needs_dlopen(&self) -> bool {
        if matches!(self, Self::SoOnly | Self::SoEmpty | Self::SoFd | Self::SoFdThread) {
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
}

/// hide_soinfo 调试结果，与 hide_soinfo.h 中的 struct hide_result ABI 一致
#[repr(C)]
#[derive(Clone, Copy)]
struct HideResult {
    version: i32,
    stage: i32,
    status: i32,
    next_offset: i32,
    entries_scanned: i32,
    sym_matched: i32,
    soinfo_state: i32,
    link_map_state: i32,
    wrote: i32,
    _pad: i32,
    head_ptr: u64,
    target_ptr: u64,
    error: [u8; 128],
    target_path: [u8; 128],
    head_path: [u8; 128],
}

impl Default for HideResult {
    fn default() -> Self {
        // Safety: all-zero is valid for this struct (ints=0, u64s=0, arrays=zeroed)
        unsafe { std::mem::zeroed() }
    }
}

impl HideResult {
    fn cstr(buf: &[u8]) -> &str {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        std::str::from_utf8(&buf[..end]).unwrap_or("")
    }
}

/// android_dlextinfo 结构体，与 NDK <android/dlext.h> ABI 一致 (aarch64)
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct AndroidDlextinfo {
    flags: u64,             // ANDROID_DLEXT_USE_LIBRARY_FD = 0x10
    reserved_addr: u64,     // 0
    reserved_size: u64,     // 0
    relro_fd: i32,          // 0
    library_fd: i32,        // memfd
    library_fd_offset: u64, // 0
    library_namespace: u64, // 0
}

/// 在目标进程中创建 memfd 并从 host 写入 SO 数据
fn create_and_fill_memfd(pid: i32, offsets: &LibcOffsets, so_data: &[u8], label: &str) -> Result<i32, String> {
    let target_memfd = create_memfd_in_target(pid, offsets)?;
    let host_memfd = extract_fd_from_target(pid, target_memfd)?;
    log_verbose!("已提取目标 memfd: target_fd={} → host_fd={}", target_memfd, host_memfd);

    // 写入 SO 数据到 host_memfd
    let mut written = 0usize;
    while written < so_data.len() {
        let ret = unsafe {
            libc_write(
                host_memfd,
                so_data[written..].as_ptr() as *const c_void,
                so_data.len() - written,
            )
        };
        if ret >= 0 {
            written += ret as usize;
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            unsafe { close(host_memfd) };
            return Err(format!("写入 {} 到 memfd 失败: {}", label, err));
        }
    }
    unsafe { close(host_memfd) };
    log_verbose!("{} ({} bytes) 已写入目标进程 memfd", label, so_data.len());
    Ok(target_memfd)
}

/// 通过 ptrace 直接调用 android_dlopen_ext 加载 memfd 中的 agent.so（不走 shellcode/agent 线程）
/// 返回 dlopen handle（非零表示成功）
fn dlopen_agent_via_ptrace(
    pid: i32,
    target_memfd: i32,
    offsets: &LibcOffsets,
    dl_offsets: &DlOffsets,
    lib_name: &str,
) -> Result<usize, String> {
    // 在目标进程中先通过 dlopen+dlsym 解析真实 android_dlopen_ext 地址，
    // 避免用本进程 libdl 偏移平移后落到错误地址。
    let libdl_name = b"libdl.so\0";
    let libdl_name_addr = call_target_function(pid, offsets.malloc, &[libdl_name.len()], None)
        .map_err(|e| format!("分配 libdl 名称失败: {}", e))?;
    write_bytes(pid, libdl_name_addr, libdl_name)?;
    let libdl_handle = call_target_function(pid, dl_offsets.dlopen, &[libdl_name_addr, 2], None)
        .map_err(|e| format!("调用 dlopen(libdl.so) 失败: {}", e))?;
    let _ = call_target_function(pid, offsets.free, &[libdl_name_addr], None);
    if libdl_handle == 0 {
        return Err("dlopen(libdl.so) 返回 NULL".to_string());
    }

    let sym_name = b"android_dlopen_ext\0";
    let sym_name_addr = call_target_function(pid, offsets.malloc, &[sym_name.len()], None)
        .map_err(|e| format!("分配 android_dlopen_ext 符号名失败: {}", e))?;
    write_bytes(pid, sym_name_addr, sym_name)?;
    let android_dlopen_ext_addr = call_target_function(pid, dl_offsets.dlsym, &[libdl_handle, sym_name_addr], None)
        .map_err(|e| format!("调用 dlsym(android_dlopen_ext) 失败: {}", e))?;
    let _ = call_target_function(pid, offsets.free, &[sym_name_addr], None);
    if android_dlopen_ext_addr == 0 {
        return Err("dlsym(android_dlopen_ext) 返回 NULL".to_string());
    }
    log_verbose!("目标进程 android_dlopen_ext = 0x{:x}", android_dlopen_ext_addr);

    // 在目标进程中分配并写入 lib name 字符串
    let mut lib_name_buf = lib_name.as_bytes().to_vec();
    lib_name_buf.push(0);
    let name_addr = call_target_function(pid, offsets.malloc, &[lib_name_buf.len()], None)
        .map_err(|e| format!("分配 lib_name 内存失败: {}", e))?;
    write_bytes(pid, name_addr, &lib_name_buf)?;

    // 构造 android_dlextinfo
    let ext_info = AndroidDlextinfo {
        flags: 0x10, // ANDROID_DLEXT_USE_LIBRARY_FD
        library_fd: target_memfd,
        ..Default::default()
    };
    let ext_info_addr = alloc_and_write_struct(pid, offsets.malloc, &ext_info, "android_dlextinfo")?;

    // 调用目标进程里真实解析出来的 android_dlopen_ext(name, RTLD_NOW=2, &ext_info)
    let handle = call_target_function(pid, android_dlopen_ext_addr, &[name_addr, 2, ext_info_addr], None)
        .map_err(|e| format!("调用 android_dlopen_ext 失败: {}", e))?;

    // 释放临时内存
    let _ = call_target_function(pid, offsets.free, &[name_addr], None);
    let _ = call_target_function(pid, offsets.free, &[ext_info_addr], None);

    if handle == 0 {
        // 尝试获取 dlerror
        if let Ok(err_ptr) = call_target_function(pid, dl_offsets.dlerror, &[], None) {
            if err_ptr != 0 {
                // 读取错误字符串（用 strlen 获取长度，最多读 256 字节）
                if let Ok(len) = call_target_function(pid, offsets.strlen, &[err_ptr], None) {
                    let read_len = len.min(256);
                    // 逐 8 字节读取拼接
                    let mut buf = Vec::with_capacity(read_len);
                    let mut off = 0;
                    while off < read_len {
                        if let Ok(word) = read_memory::<u64>(pid, err_ptr + off) {
                            let bytes = word.to_le_bytes();
                            let remaining = read_len - off;
                            buf.extend_from_slice(&bytes[..remaining.min(8)]);
                        } else {
                            break;
                        }
                        off += 8;
                    }
                    if !buf.is_empty() {
                        let msg = String::from_utf8_lossy(&buf[..buf.len().min(read_len)]);
                        return Err(format!("android_dlopen_ext 失败: {}", msg));
                    }
                }
            }
        }
        return Err("android_dlopen_ext 返回 NULL".to_string());
    }

    log_success!("android_dlopen_ext 成功，handle=0x{:x}", handle);
    Ok(handle)
}

fn remote_dlsym(pid: i32, dl: &DlOffsets, offsets: &LibcOffsets, handle: usize, name: &[u8]) -> Result<usize, String> {
    let name_addr = call_target_function(pid, offsets.malloc, &[name.len()], None)
        .map_err(|e| format!("分配符号名失败: {}", e))?;
    write_bytes(pid, name_addr, name)?;
    let ptr = call_target_function(pid, dl.dlsym, &[handle, name_addr], None);
    let _ = call_target_function(pid, offsets.free, &[name_addr], None);
    ptr.map_err(|e| format!("dlsym 失败: {}", e))
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
            r.status, r.stage, r.wrote, r.soinfo_state, r.link_map_state
        );
        if !err_str.is_empty() {
            log_error!("  error: {}", err_str);
        }
    }
    log_info!(
        "  version={} next_offset=0x{:x} scanned={} syms={}",
        r.version, r.next_offset, r.entries_scanned, r.sym_matched
    );
    log_info!("  head=\"{}\" target=0x{:x}", hp_str, r.target_ptr);
}

fn invoke_hide_from_solist(
    pid: i32,
    handle: usize,
    offsets: &LibcOffsets,
    dl: &DlOffsets,
) -> Result<HideResult, String> {
    let hide_ptr = match remote_dlsym(pid, dl, offsets, handle, b"rust_hide_from_solist\0") {
        Ok(ptr) if ptr != 0 => ptr,
        _ => remote_dlsym(pid, dl, offsets, handle, b"hide_from_solist\0")?,
    };
    if hide_ptr == 0 {
        return Err("dlsym(hide_from_solist) 返回 NULL".to_string());
    }
    let hide_status = call_target_function(pid, hide_ptr, &[handle], None)
        .map_err(|e| format!("调用 hide_from_solist 失败: {}", e))? as i32;
    let result_ptr = remote_dlsym(pid, dl, offsets, handle, b"rust_get_hide_result\0").or_else(|_| {
        remote_dlsym(pid, dl, offsets, handle, b"get_hide_result\0")
    })?;
    if result_ptr == 0 {
        return Err("dlsym(get_hide_result) 返回 NULL".to_string());
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

/// 根据 UID 查找 /data/data/ 目录下对应的应用数据目录
fn find_data_dir_by_uid(uid: u32) -> Option<String> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let data_dir = "/data/data";

    match fs::read_dir(data_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.uid() == uid {
                        if let Some(path) = entry.path().to_str() {
                            return Some(path.to_string());
                        }
                    }
                }
            }
            None
        }
        Err(e) => {
            log_error!("读取 /data/data 目录失败: {}", e);
            None
        }
    }
}

/// 使用 eBPF 监听 SO 加载并自动附加
#[cfg(feature = "watch-so")]
pub(crate) fn watch_and_inject(
    so_pattern: &str,
    timeout_secs: Option<u64>,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<RawFd, String> {
    use ldmonitor::DlopenMonitor;
    use std::time::Duration;

    log_info!("正在启动 eBPF 监听器，等待加载: {}", so_pattern);

    let monitor = DlopenMonitor::new(None).map_err(|e| format!("启动 eBPF 监听失败: {}", e))?;

    let info = if let Some(secs) = timeout_secs {
        log_info!("超时时间: {} 秒", secs);
        monitor.wait_for_path_timeout(so_pattern, Duration::from_secs(secs))
    } else {
        log_info!("无超时限制，持续监听中...");
        monitor.wait_for_path(so_pattern)
    };

    monitor.stop();

    match info {
        Some(dlopen_info) => {
            let pid = dlopen_info.pid();
            if let Some(ns_pid) = dlopen_info.ns_pid {
                if ns_pid != dlopen_info.host_pid {
                    log_success!(
                        "检测到 SO 加载: pid={} (host_pid={}), uid={}, path={}",
                        ns_pid,
                        dlopen_info.host_pid,
                        dlopen_info.uid,
                        dlopen_info.path
                    );
                } else {
                    log_success!(
                        "检测到 SO 加载: pid={}, uid={}, path={}",
                        pid,
                        dlopen_info.uid,
                        dlopen_info.path
                    );
                }
            } else {
                log_success!(
                    "检测到 SO 加载: host_pid={}, uid={}, path={}",
                    dlopen_info.host_pid,
                    dlopen_info.uid,
                    dlopen_info.path
                );
            }

            // 克隆 string_overrides 以便修改
            let mut overrides = string_overrides.clone();

            // 根据 uid 自动检测 /data/data/ 目录
            if let Some(data_dir) = find_data_dir_by_uid(dlopen_info.uid) {
                log_info!("自动检测到应用数据目录: {}", data_dir);
                overrides.insert("output_path".to_string(), data_dir);
            } else {
                log_warn!("未能找到 uid {} 对应的 /data/data/ 目录", dlopen_info.uid);
            }

            inject_to_process(pid as i32, &overrides)
        }
        None => Err("监听超时，未检测到匹配的 SO 加载".to_string()),
    }
}

#[cfg(not(feature = "watch-so"))]
pub(crate) fn watch_and_inject(
    _so_pattern: &str,
    _timeout_secs: Option<u64>,
    _string_overrides: &std::collections::HashMap<String, String>,
) -> Result<RawFd, String> {
    Err("当前 rustfrida 未启用 watch-so feature（需要 bpf-linker / ldmonitor eBPF）".to_string())
}
