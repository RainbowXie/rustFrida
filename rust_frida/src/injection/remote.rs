//! 远程目标进程基础调用与内存/文件描述符管理。

use std::ffi::c_void;
use std::mem::size_of;
use std::os::fd::RawFd;

use nix::unistd::close;

use crate::process::{call_target_function, read_memory, write_bytes, write_memory};
use crate::types::{DlOffsets, LibcOffsets};
use crate::{log_success, log_verbose, log_verbose_addr};

extern "C" {
    #[link_name = "write"]
    fn libc_write(fd: RawFd, buf: *const c_void, count: usize) -> isize;
}

// aarch64 syscall numbers
const SYS_PIDFD_OPEN: i64 = 434;
const SYS_PIDFD_GETFD: i64 = 438;

/// 在目标进程中分配内存并写入结构体，返回远程地址。
pub(crate) fn alloc_and_write_struct<T>(
    pid: i32,
    malloc_addr: usize,
    data: &T,
    name: &str,
) -> Result<usize, String> {
    let size = size_of::<T>();
    let addr = call_target_function(pid, malloc_addr, &[size], None)
        .map_err(|e| format!("分配{}内存失败: {}", name, e))?;
    log_verbose!("分配{}内存", name);
    log_verbose_addr!("地址", addr);
    write_memory(pid, addr, data)?;
    log_verbose!("{}写入成功", name);
    log_verbose_addr!("地址", addr);
    Ok(addr)
}

/// 在目标进程中调用 socketpair()，返回 (fd0, fd1)
pub(crate) fn create_socketpair_in_target(pid: i32, offsets: &LibcOffsets) -> Result<(i32, i32), String> {
    let sv_addr = call_target_function(pid, offsets.malloc, &[8], None)
        .map_err(|e| format!("分配 socketpair 缓冲区失败: {}", e))?;

    let ret = call_target_function(pid, offsets.socketpair, &[1, 1, 0, sv_addr], None)
        .map_err(|e| format!("调用 socketpair 失败: {}", e))?;

    if ret as isize != 0 {
        return Err(format!("socketpair 返回错误: {}", ret as isize));
    }

    let sv: [i32; 2] = read_memory(pid, sv_addr)?;
    log_verbose!("socketpair 创建成功: fd0={}, fd1={}", sv[0], sv[1]);

    let _ = call_target_function(pid, offsets.free, &[sv_addr], None);
    Ok((sv[0], sv[1]))
}

/// 通过 pidfd_getfd 从目标进程提取文件描述符到 host
pub(crate) fn extract_fd_from_target(pid: i32, target_fd: i32) -> Result<RawFd, String> {
    let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0) };
    if pidfd < 0 {
        return Err(format!("pidfd_open({}) 失败: {}", pid, std::io::Error::last_os_error()));
    }

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
pub(crate) fn create_memfd_in_target(pid: i32, offsets: &LibcOffsets) -> Result<i32, String> {
    let name = b"wwb_so\0";
    let name_addr = call_target_function(pid, offsets.malloc, &[name.len()], None)
        .map_err(|e| format!("分配 memfd name 内存失败: {}", e))?;
    write_bytes(pid, name_addr, name)?;

    let ret = call_target_function(pid, offsets.memfd_create, &[name_addr, 0], None)
        .map_err(|e| format!("调用 memfd_create 失败: {}", e))?;

    let _ = call_target_function(pid, offsets.free, &[name_addr], None);

    let fd = ret as i32;
    if fd < 0 {
        return Err(format!("memfd_create 返回错误: {}", fd));
    }

    log_verbose!("目标进程 memfd_create 成功: fd={}", fd);
    Ok(fd)
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct AndroidDlextinfo {
    pub flags: u64,             // ANDROID_DLEXT_USE_LIBRARY_FD = 0x10
    pub reserved_addr: u64,     // 0
    pub reserved_size: u64,     // 0
    pub relro_fd: i32,          // 0
    pub library_fd: i32,        // memfd
    pub library_fd_offset: u64, // 0
    pub library_namespace: u64, // 0
}

/// 在目标进程中创建 memfd 并从 host 写入 SO 数据
pub(crate) fn create_and_fill_memfd(
    pid: i32,
    offsets: &LibcOffsets,
    so_data: &[u8],
    label: &str,
) -> Result<i32, String> {
    let target_memfd = create_memfd_in_target(pid, offsets)?;
    let host_memfd = extract_fd_from_target(pid, target_memfd)?;
    log_verbose!("已提取目标 memfd: target_fd={} → host_fd={}", target_memfd, host_memfd);

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
pub(crate) fn dlopen_agent_via_ptrace(
    pid: i32,
    target_memfd: i32,
    offsets: &LibcOffsets,
    dl_offsets: &DlOffsets,
    lib_name: &str,
) -> Result<usize, String> {
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
    let android_dlopen_ext_addr =
        call_target_function(pid, dl_offsets.dlsym, &[libdl_handle, sym_name_addr], None)
            .map_err(|e| format!("调用 dlsym(android_dlopen_ext) 失败: {}", e))?;
    let _ = call_target_function(pid, offsets.free, &[sym_name_addr], None);
    if android_dlopen_ext_addr == 0 {
        return Err("dlsym(android_dlopen_ext) 返回 NULL".to_string());
    }
    log_verbose!("目标进程 android_dlopen_ext = 0x{:x}", android_dlopen_ext_addr);

    let mut lib_name_buf = lib_name.as_bytes().to_vec();
    lib_name_buf.push(0);
    let name_addr = call_target_function(pid, offsets.malloc, &[lib_name_buf.len()], None)
        .map_err(|e| format!("分配 lib_name 内存失败: {}", e))?;
    write_bytes(pid, name_addr, &lib_name_buf)?;

    let ext_info = AndroidDlextinfo {
        flags: 0x10, // ANDROID_DLEXT_USE_LIBRARY_FD
        library_fd: target_memfd,
        ..Default::default()
    };
    let ext_info_addr = alloc_and_write_struct(pid, offsets.malloc, &ext_info, "android_dlextinfo")?;

    let handle = call_target_function(pid, android_dlopen_ext_addr, &[name_addr, 2, ext_info_addr], None)
        .map_err(|e| format!("调用 android_dlopen_ext 失败: {}", e))?;

    let _ = call_target_function(pid, offsets.free, &[name_addr], None);
    let _ = call_target_function(pid, offsets.free, &[ext_info_addr], None);

    if handle == 0 {
        if let Ok(err_ptr) = call_target_function(pid, dl_offsets.dlerror, &[], None) {
            if err_ptr != 0 {
                if let Ok(len) = call_target_function(pid, offsets.strlen, &[err_ptr], None) {
                    let read_len = len.min(256);
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

pub(crate) fn remote_dlsym(
    pid: i32,
    dl: &DlOffsets,
    offsets: &LibcOffsets,
    handle: usize,
    name: &[u8],
) -> Result<usize, String> {
    let name_addr = call_target_function(pid, offsets.malloc, &[name.len()], None)
        .map_err(|e| format!("分配符号名失败: {}", e))?;
    write_bytes(pid, name_addr, name)?;
    let ptr = call_target_function(pid, dl.dlsym, &[handle, name_addr], None);
    let _ = call_target_function(pid, offsets.free, &[name_addr], None);
    ptr.map_err(|e| format!("dlsym 失败: {}", e))
}
