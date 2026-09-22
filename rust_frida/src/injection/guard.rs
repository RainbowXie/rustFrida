//! 注入生命周期与异常自动恢复 Guard。

use std::os::fd::RawFd;

use nix::sys::ptrace;
use nix::unistd::{close, Pid};

/// RAII guard: 注入失败时自动关闭 host_fd 并 detach 目标进程
pub(crate) struct InjectionGuard {
    pid: i32,
    host_fd: RawFd,
    disarmed: bool,
}

impl InjectionGuard {
    pub(crate) fn new(pid: i32, host_fd: RawFd) -> Self {
        Self {
            pid,
            host_fd,
            disarmed: false,
        }
    }

    pub(crate) fn set_host_fd(&mut self, host_fd: RawFd) {
        self.host_fd = host_fd;
    }

    pub(crate) fn disarm(&mut self) {
        self.disarmed = true;
    }

    /// 注入成功，取走 host_fd，不再自动清理
    pub(crate) fn into_fd(mut self) -> RawFd {
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
