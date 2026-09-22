//! 正常注入流程（Shellcode 路径 + REPL 通道建立）与 eBPF 监听注入。

use std::ffi::c_void;
use std::os::fd::RawFd;

use nix::sys::ptrace;
use nix::unistd::{close, Pid};

use crate::process::{attach_to_process, call_target_function, get_lib_base, write_bytes};
use crate::types::{write_string_table, AgentArgs, DlOffsets, LibcOffsets};
use crate::{log_error, log_info, log_success, log_verbose, log_verbose_addr, log_warn};

use super::guard::InjectionGuard;
use super::remote::{alloc_and_write_struct, create_socketpair_in_target, extract_fd_from_target};

extern "C" {
    #[link_name = "write"]
    fn libc_write(fd: RawFd, buf: *const c_void, count: usize) -> isize;
}

pub(crate) const SHELLCODE: &[u8] = include_bytes!("../../../loader/build/loader.bin");

#[cfg(debug_assertions)]
pub(crate) const AGENT_SO: &[u8] = include_bytes!("../../../target/aarch64-linux-android/debug/libagent.so");

#[cfg(not(debug_assertions))]
pub(crate) const AGENT_SO: &[u8] = include_bytes!("../../../target/aarch64-linux-android/release/libagent.so");

#[cfg(feature = "qbdi")]
pub(crate) const QBDI_HELPER_SO: &[u8] = include_bytes!(env!("QBDI_HELPER_SO_PATH"));

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

    let self_base = get_lib_base(None, "libc.so")?;
    let target_base = get_lib_base(Some(pid), "libc.so")?;
    let self_dl_base = get_lib_base(None, "libdl.so")?;
    let target_dl_base = get_lib_base(Some(pid), "libdl.so")?;

    log_verbose!("自身 libc.so 基址: 0x{:x}", self_base);
    log_verbose!("目标进程 libc.so 基址: 0x{:x}", target_base);
    log_verbose!("自身 libdl.so 基址: 0x{:x}", self_dl_base);
    log_verbose!("目标进程 libdl.so 基址: 0x{:x}", target_dl_base);

    let offsets = LibcOffsets::calculate(self_base, target_base)?;
    let dl_offsets = DlOffsets::calculate(self_dl_base, target_dl_base)?;

    if crate::logger::is_verbose() {
        offsets.print_offsets();
        dl_offsets.print_offsets();
    }

    attach_to_process(pid)?;
    // 故障注入点：attach 之后、资源获取之前。
    if let Err(e) = super::fault::maybe_fail(super::fault::FAULT_ATTACH_DONE) {
        return Err(e);
    }

    let mut guard = InjectionGuard::new(pid, -1);

    let (fd0, fd1) = create_socketpair_in_target(pid, &offsets)?;
    // 目标 fd 立即入账：后续任一失败分支都由 guard 补偿关闭。
    guard.set_offsets(&offsets);
    guard.own_target_fd(fd0);
    guard.own_target_fd(fd1);
    // 故障注入点：socketpair 创建后、提取 host_fd 之前。
    if let Err(e) = super::fault::maybe_fail(super::fault::FAULT_SOCKETPAIR_CREATED) {
        return Err(e);
    }
    let host_fd = extract_fd_from_target(pid, fd0)?;
    guard.set_host_fd(host_fd);

    let _ = call_target_function(pid, offsets.close, &[fd0 as usize], None);
    guard.release_target_fd(fd0);
    log_verbose!("目标进程 fd0={} 已关闭，fd1={} 保留给 agent", fd0, fd1);

    log_verbose!("开始分配内存");

    let string_table_addr = write_string_table(pid, offsets.malloc, string_overrides)?;
    log_verbose!("字符串表写入成功");
    log_verbose_addr!("地址", string_table_addr);

    let agent_args = AgentArgs {
        table: string_table_addr as u64,
        ctrl_fd: fd1,
        agent_memfd: -1,
    };
    let agent_args_addr = alloc_and_write_struct(pid, offsets.malloc, &agent_args, "AgentArgs")?;
    // 故障注入点：AgentArgs 写入后、shellcode 执行之前。
    if let Err(e) = super::fault::maybe_fail(super::fault::FAULT_MEMFD_CREATED) {
        return Err(e);
    }

    // 页大小必须是正数、2 的幂且在合理范围；不能假设 4096：
    // 在 16 KB 页设备上猜错会让 mmap/munmap 操作错误范围。
    let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size_raw <= 0 || page_size_raw > (1 << 20) {
        return Err(format!("sysconf(_SC_PAGESIZE) 返回非法值: {}", page_size_raw));
    }
    let page_size = page_size_raw as usize;
    if (page_size & (page_size - 1)) != 0 {
        return Err(format!("页大小 {} 不是 2 的幂", page_size));
    }
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

            let mut overrides = string_overrides.clone();

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
