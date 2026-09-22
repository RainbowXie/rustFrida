//! 注入资源所有权与异常自动恢复 Guard。
//!
//! 同时拥有 host 侧 fd 与目标进程内的 fd：目标 fd 由本结构登记，
//! 失败回滚时在目标中调用 close 补偿，避免 socketpair/memfd 泄漏。

use std::os::fd::RawFd;

use nix::sys::ptrace;
use nix::unistd::{close, Pid};

use crate::process::call_target_function;
use crate::types::LibcOffsets;

/// RAII guard: 注入失败时自动关闭目标 fd、host_fd 并 detach 目标进程。
///
/// 资源获取后立即登记；只有明确调用 `release_target_fd`/`into_fd` 表示
/// 所有权转交给 agent 后，才解除清理责任。
pub(crate) struct InjectionGuard {
    pid: i32,
    offsets: Option<LibcOffsets>,
    host_fd: RawFd,
    /// 目标进程内需要补偿关闭的 fd；只有所有权未转交时才会在 drop 中 close。
    target_fds: Vec<i32>,
    disarmed: bool,
}

impl InjectionGuard {
    pub(crate) fn new(pid: i32, host_fd: RawFd) -> Self {
        Self {
            pid,
            offsets: None,
            host_fd,
            target_fds: Vec::new(),
            disarmed: false,
        }
    }

    /// 远程 close 需要 offsets；在计算完成后登记一次。
    pub(crate) fn set_offsets(&mut self, offsets: &LibcOffsets) {
        self.offsets = Some(*offsets);
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
}

impl Drop for InjectionGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            self.close_target_fds();
            if self.host_fd >= 0 {
                let _ = close(self.host_fd);
            }
            let _ = ptrace::detach(Pid::from_raw(self.pid), None);
        }
    }
}
