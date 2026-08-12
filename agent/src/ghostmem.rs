//! GhostMem - VMA-Less 幽灵内存分配器（对接 mkpms/ghostmem KPM 模块）
//!
//! 内核侧：`kpms/ghostmem/`（mkpms 仓库）通过 prctl 暴露 VMA-Less 内存：
//! - `PR_GHOSTMEM_ALLOC 0x47474d01`：prctl(opt, 0, nr_pages, prot, 0) -> VA
//! - `PR_GHOSTMEM_FREE  0x47474d02`：prctl(opt, 0, va, 0, 0)
//! - `PR_GHOSTMEM_INFO  0x47474d03`：prctl(opt, pid, buf, len, 0)
//! - `PR_GHOSTMEM_WRITE 0x47474d04` / `READ 0x47474d05`：prctl(opt, pid, va, buf, len) 跨进程读写
//!
//! 该内存不登记 VMA，`/proc/<pid>/maps` 不可见。用于 stealth trampoline
//! （`gum_set_stealth_alloc`）与自定义 Linker 的代码存放。
//!
//! 设计（见 mkpms/docs/stealth-trampolines.md Phase 2）：
//! - 模块未加载时 prctl 返回负值 -> 调用方回退 mmap（本模块不自动回退，
//!   由调用方决定，避免掩盖"幽灵模式未生效"的事实）

use libc::{c_int, c_ulong};
use std::io::Error;
use std::ptr;

/// 与内核 ghostmem.h 对齐的 prctl 选项
const PR_GHOSTMEM_ALLOC: c_int = 0x47474d01;
const PR_GHOSTMEM_FREE: c_int = 0x47474d02;
const PR_GHOSTMEM_INFO: c_int = 0x47474d03;
const PR_GHOSTMEM_WRITE: c_int = 0x47474d04;
const PR_GHOSTMEM_READ: c_int = 0x47474d05;

/// PROT_* 位（与内核 GHOSTMEM_PROT_* 对齐）
const PROT_READ: c_ulong = 0x1;
const PROT_WRITE: c_ulong = 0x2;
const PROT_EXEC: c_ulong = 0x4;
const PROT_RWX: c_ulong = PROT_READ | PROT_WRITE | PROT_EXEC;

const PAGE_SIZE: usize = 4096;
/// 单次分配页数上限（与内核 GHOSTMEM_MAX_PAGES 对齐）
const MAX_PAGES: usize = 64;

/// INFO 返回的统计结构（与内核 struct ghostmem_stats 布局一致）
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct GhostmemStats {
    pub nr_blocks: u64,
    pub nr_pages: u64,
}

/// 幽灵内存块：内核分配的 VMA-Less 映射
#[derive(Debug)]
pub struct GhostMem {
    ptr: *mut u8,
    pages: usize,
}

impl GhostMem {
    /// 分配 nr_pages 页幽灵内存（RWX）。失败返回 Err（如模块未加载）。
    pub fn alloc(pages: usize) -> Result<Self, String> {
        if pages == 0 || pages > MAX_PAGES {
            return Err(format!("ghostmem: pages {} out of range [1, {}]", pages, MAX_PAGES));
        }
        let ret = unsafe {
            libc::prctl(
                PR_GHOSTMEM_ALLOC,
                0,            // pid=0：当前进程
                pages as c_ulong,
                PROT_RWX,
                0,
            )
        };
        if ret < 0 {
            return Err(format!(
                "ghostmem: PR_GHOSTMEM_ALLOC failed: {}",
                Error::last_os_error()
            ));
        }
        Ok(GhostMem {
            ptr: ret as *mut u8,
            pages,
        })
    }

    /// 按 size 字节分配（向上取整到页）
    pub fn alloc_size(size: usize) -> Result<Self, String> {
        let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        Self::alloc(pages)
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.pages * PAGE_SIZE
    }

    /// 写入数据并返回目标地址（调用方负责确保容量足够）
    pub fn write_at(&self, offset: usize, data: &[u8]) -> Result<*mut u8, String> {
        if offset + data.len() > self.len() {
            return Err("ghostmem: write out of bounds".to_string());
        }
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len());
            // 幽灵内存可能被作为代码执行：dcache/icache 同步。
            // 内核侧分配时已做 dcache clean；写入后若立即执行需调用方
            // 自行 __builtin___clear_cache（与 ExecMem 行为一致）。
            Ok(self.ptr.add(offset))
        }
    }

    /// 查询幽灵内存统计（任意 pid；缓冲在当前进程，内核 PTE 拷贝）
    pub fn stats(pid: libc::pid_t) -> Result<GhostmemStats, String> {
        let mut st = GhostmemStats::default();
        let ret = unsafe {
            libc::prctl(
                PR_GHOSTMEM_INFO,
                pid as c_ulong,
                &mut st as *mut GhostmemStats as c_ulong,
                std::mem::size_of::<GhostmemStats>() as c_ulong,
                0,
            )
        };
        if ret < 0 {
            return Err(format!("ghostmem: INFO failed: {}", Error::last_os_error()));
        }
        Ok(st)
    }

    /// 跨进程读目标 pid 的幽灵内存（内核 PTE 读写，无 ptrace 依赖）
    pub fn read_at_cross(pid: libc::pid_t, va: *mut u8, len: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; len];
        let ret = unsafe {
            libc::prctl(PR_GHOSTMEM_READ, pid as c_ulong, va as c_ulong,
                        buf.as_mut_ptr() as c_ulong, len as c_ulong)
        };
        if ret < 0 {
            return Err(format!("ghostmem: READ failed: {}", Error::last_os_error()));
        }
        Ok(buf)
    }

    /// 跨进程写目标 pid 的幽灵内存（内核 PTE 读写，无 ptrace 依赖）
    pub fn write_at_cross(pid: libc::pid_t, va: *mut u8, data: &[u8]) -> Result<(), String> {
        let ret = unsafe {
            libc::prctl(PR_GHOSTMEM_WRITE, pid as c_ulong, va as c_ulong,
                        data.as_ptr() as c_ulong, data.len() as c_ulong)
        };
        if ret < 0 {
            return Err(format!("ghostmem: WRITE failed: {}", Error::last_os_error()));
        }
        Ok(())
    }
}

impl Drop for GhostMem {
    fn drop(&mut self) {
        let ret = unsafe { libc::prctl(PR_GHOSTMEM_FREE, 0, self.ptr as c_ulong, 0, 0) };
        if ret < 0 {
            eprintln!("ghostmem: FREE 0x{:x} failed: {}", self.ptr as usize, Error::last_os_error());
        }
    }
}

// 幽灵内存是内核页表映射，不经过 Rust 分配器；Send/Sync 由调用方约束。
unsafe impl Send for GhostMem {}

/* ---- frida-gum stealth allocator 对接（gum 17.x 提供 gum_set_stealth_alloc）----
 * 当前仓库锁定 frida-gum 16.7.18（无该 API）。升级到 17.x 后：
 *   gum_set_stealth_alloc(stealth_alloc, stealth_free);
 * 这两个 extern "C" 函数签名与 GumStealthAlloc/GumStealthFree 一致，
 * 可直接作为回调注册。 */

/// Stealth 分配回调：size 字节 -> 幽灵内存地址（模块未加载返回 NULL）。
/// 签名对齐 frida-gum `GumStealthAlloc`（gpointer (*)(gsize)）。
#[no_mangle]
pub extern "C" fn stealth_alloc(size: usize) -> *mut std::ffi::c_void {
    match GhostMem::alloc_size(size) {
        Ok(m) => m.as_ptr() as *mut std::ffi::c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Stealth 释放回调：gum 侧释放跳板内存。
/// 签名对齐 frida-gum `GumStealthFree`（void (*)(gpointer)）。
/// 注意：GhostMem 在 Drop 时释放；此回调用于提前释放场景。
#[no_mangle]
pub extern "C" fn stealth_free(mem: *mut std::ffi::c_void) {
    if mem.is_null() {
        return;
    }
    unsafe {
        libc::prctl(PR_GHOSTMEM_FREE, 0, mem as c_ulong, 0, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_layout_is_16_bytes() {
        // 与内核 struct ghostmem_stats（两个 u64）布局一致
        assert_eq!(std::mem::size_of::<GhostmemStats>(), 16);
    }

    #[test]
    fn alloc_out_of_range_rejected() {
        assert!(GhostMem::alloc(0).is_err());
        assert!(GhostMem::alloc(MAX_PAGES + 1).is_err());
    }

    #[test]
    fn alloc_without_module_fails_cleanly() {
        // host 上无 ghostmem 内核模块：prctl 返回负值 -> Err（不 panic）
        assert!(GhostMem::alloc(1).is_err());
    }
}

#[cfg(test)]
mod stealth_tests {
    use super::*;

    #[test]
    fn stealth_alloc_without_module_returns_null() {
        assert!(stealth_alloc(4096).is_null());
    }

    #[test]
    fn stealth_free_null_is_noop() {
        stealth_free(std::ptr::null_mut());
    }
}
