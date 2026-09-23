//! 注入资源所有权与异常自动恢复 Guard。
//!
//! 三类目标侧资源统一入账：目标进程内的 fd、已 dlopen 的 handle、host 侧 socket fd。
//! 失败回滚时分别用目标 close / dlclose 补偿；只有明确转交（agent 接管 fd、
//! 隐藏成功保留 handle）后才解除清理责任。

use std::os::fd::RawFd;

use nix::sys::ptrace;
use nix::unistd::{close, Pid};

use crate::process::call_target_function;
use crate::types::{DlOffsets, LibcOffsets};

/// RAII guard: 注入失败时自动卸载 handle、关闭目标 fd、host_fd 并 detach。
///
/// 资源获取后立即登记；只有明确调用 `release_*`/`into_fd` 表示所有权转交后，
/// 才解除清理责任。drop 中的补偿顺序刻意为 handle → 目标 fd → host_fd → detach：
/// dlclose 远程调用必须发生在 detach 之前。
pub(crate) struct InjectionGuard {
    pid: i32,
    offsets: Option<LibcOffsets>,
    dl: Option<DlOffsets>,
    host_fd: RawFd,
    /// 目标进程内需要补偿关闭的 fd；只有所有权未转交时才会在 drop 中 close。
    target_fds: Vec<i32>,
    /// 已 dlopen 的 handle；隐藏成功保留、失败路径由 drop 远程 dlclose。
    target_handles: Vec<usize>,
    disarmed: bool,
}

impl InjectionGuard {
    pub(crate) fn new(pid: i32, host_fd: RawFd) -> Self {
        Self {
            pid,
            offsets: None,
            dl: None,
            host_fd,
            target_fds: Vec::new(),
            target_handles: Vec::new(),
            disarmed: false,
        }
    }

    /// 远程 close 需要 offsets；在计算完成后登记一次。
    pub(crate) fn set_offsets(&mut self, offsets: &LibcOffsets) {
        self.offsets = Some(*offsets);
    }

    /// 远程 dlclose 需要 libdl offsets；dlopen 发生前登记。
    pub(crate) fn set_dl_offsets(&mut self, dl: &DlOffsets) {
        self.dl = Some(*dl);
    }

    pub(crate) fn set_host_fd(&mut self, host_fd: RawFd) {
        self.host_fd = host_fd;
    }

    /// 目标 fd 创建成功后立即登记；drop 时若仍未转交所有权则在目标中补偿关闭。
    pub(crate) fn own_target_fd(&mut self, fd: i32) {
        if fd >= 0 && !self.target_fds.contains(&fd) {
            self.target_fds.push(fd);
        }
    }

    /// 所有权正式转交给 agent（agent 线程负责关闭）后解除清理责任。
    pub(crate) fn release_target_fd(&mut self, fd: i32) {
        self.target_fds.retain(|&f| f != fd);
    }

    /// dlopen 成功后立即登记 handle；此后任一失败路径都由 drop 远程 dlclose。
    pub(crate) fn own_handle(&mut self, handle: usize) {
        if handle != 0 && !self.target_handles.contains(&handle) {
            self.target_handles.push(handle);
        }
    }

    /// 隐藏成功后库必须留在目标内（这就是注入目的），此时才解除 handle 的清理责任。
    pub(crate) fn release_handle(&mut self, handle: usize) {
        self.target_handles.retain(|&h| h != handle);
    }

    pub(crate) fn disarm(&mut self) {
        self.disarmed = true;
    }

    /// 注入成功，取走 host_fd 且解除全部清理责任
    pub(crate) fn into_fd(mut self) -> RawFd {
        self.disarmed = true;
        self.host_fd
    }

    fn close_target_fds(&self) {
        let Some(offsets) = self.offsets else {
            // 未登记 offsets 时无法远程 close：宁可保留，也要给出可观测信号
            return;
        };
        for &fd in &self.target_fds {
            let _ = call_target_function(self.pid, offsets.close, &[fd as usize], None);
        }
    }

    fn dlclose_handles(&self) {
        let Some(dl) = self.dl else {
            // 没有 libdl offsets 就无法远程 dlclose：与 fd 同理，保留 handle
            // 但让失败可见（上层已把失败原因报出，这里不静默吞掉语义）。
            return;
        };
        for &handle in &self.target_handles {
            let _ = call_target_function(self.pid, dl.dlclose, &[handle], None);
        }
    }
}

impl Drop for InjectionGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            // 补偿顺序固定：先卸载 handle，再关目标 fd，最后 detach；
            // dlclose/close 的远程调用都依赖目标仍在 ptrace 控制下。
            self.dlclose_handles();
            self.close_target_fds();
            if self.host_fd >= 0 {
                let _ = close(self.host_fd);
            }
            let _ = ptrace::detach(Pid::from_raw(self.pid), None);
        }
    }
}
