#![cfg(all(target_os = "android", target_arch = "aarch64"))]

/// 生成 UnsafeCell 包装结构体，自动实现 Send + Sync。
/// 用于将非 Send/Sync 类型安全地存入 OnceLock 全局变量。
#[cfg(any(feature = "frida-gum", feature = "qbdi"))]
macro_rules! define_sync_cell {
    ($name:ident, $inner:ty) => {
        struct $name(std::cell::UnsafeCell<$inner>);
        unsafe impl Sync for $name {}
        unsafe impl Send for $name {}
    };
}

mod arm64_relocator;
mod communication;
mod crash_handler;
mod exec_mem;
mod ghostmem;
mod gumlibc;
mod trace;
mod vma_name;

#[cfg(feature = "frida-gum")]
mod memory_dump;
#[cfg(feature = "quickjs")]
mod quickjs_loader;
#[cfg(feature = "frida-gum")]
mod stalker;

use crate::communication::{
    flush_cached_logs, is_cmd_frame, is_qbdi_helper_frame, log_msg, read_frame, register_stream_fd, send_complete,
    send_eval_err, send_eval_ok, send_hello, shutdown_stream, write_stream, GLOBAL_STREAM,
};
use crate::crash_handler::{install_crash_handlers, install_panic_hook};
use libc::{kill, pid_t, SIGSTOP};
use std::ffi::c_void;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::process;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

// hide_soinfo.c 中的调试结果函数（.init_array 构造函数填充）
// 通过 Rust #[no_mangle] 重导出到动态符号表，供 host 端 dlsym 查询
extern "C" {
    fn get_hide_result() -> *const c_void;
}

#[no_mangle]
pub extern "C" fn rust_get_hide_result() -> *const c_void {
    unsafe { get_hide_result() }
}

// 定义我们自己的Result类型，错误统一为String
type Result<T> = std::result::Result<T, String>;

// StringTable 结构定义（需要和 main.rs 中的定义完全一致）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StringTable {
    pub sym_name: u64,
    pub sym_name_len: u32,
    pub pthread_err: u64,
    pub pthread_err_len: u32,
    pub dlsym_err: u64,
    pub dlsym_err_len: u32,
    pub cmdline: u64,
    pub cmdline_len: u32,
    pub output_path: u64,
    pub output_path_len: u32,
}

impl StringTable {
    /// 从指针地址读取字符串（不包含末尾的 NULL）
    unsafe fn read_string(&self, addr: u64, len: u32) -> Option<String> {
        if addr == 0 || len == 0 {
            return None;
        }
        let ptr = addr as *const u8;
        let slice = std::slice::from_raw_parts(ptr, len as usize);
        // 去掉末尾的 NULL 字符
        let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        String::from_utf8(slice[..end].to_vec()).ok()
    }

    /// 获取 cmdline
    pub unsafe fn get_cmdline(&self) -> Option<String> {
        self.read_string(self.cmdline, self.cmdline_len)
    }

    /// 获取 output_path
    pub unsafe fn get_output_path(&self) -> Option<String> {
        self.read_string(self.output_path, self.output_path_len)
    }
}

static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);
pub static OUTPUT_PATH: OnceLock<String> = OnceLock::new();

/// 注入参数结构体（与 rust_frida/src/types.rs 和 loader.c 完全一致）
#[repr(C)]
pub struct AgentArgs {
    pub table: u64,       // *const StringTable（目标进程内地址）
    pub ctrl_fd: i32,     // socketpair fd1（agent 端）
    pub agent_memfd: i32, // 目标进程内的 agent.so memfd
}

#[no_mangle]
pub extern "C" fn hello_entry(args_ptr: *mut c_void) -> *mut c_void {
    // 安装Rust panic hook（需要在最前面，捕获Rust层面的panic）
    install_panic_hook();
    install_crash_handlers();

    // 从 AgentArgs 读取 ctrl_fd 和 StringTable 指针
    let (ctrl_fd, table) = unsafe {
        let args = &*(args_ptr as *const AgentArgs);
        (args.ctrl_fd, &*(args.table as *const StringTable))
    };

    unsafe {
        // 读取 output_path 并保存到全局变量
        if let Some(output) = table.get_output_path() {
            if output != "novalue" {
                let _ = OUTPUT_PATH.set(output.clone());
            }
        }

        // 读取 cmdline 参数
        if let Some(cmd) = table.get_cmdline() {
            if cmd != "novalue" {
                process_cmd(&cmd);
            }
        }
    }

    // 不设置线程名，保持继承的进程名，避免被安全 SDK 通过 /proc/self/task/*/comm 检测

    // 使用 ctrl_fd（socketpair 的 agent 端），已通过 socketpair 连接到 host
    let sock = unsafe { UnixStream::from_raw_fd(ctrl_fd) };
    let write_half = sock.try_clone().expect("stream clone failed");
    register_stream_fd(&write_half);
    GLOBAL_STREAM.set(std::sync::Mutex::new(write_half)).unwrap();
    send_hello();
    std::thread::sleep(Duration::from_millis(100));
    flush_cached_logs();

    let mut reader = sock;
    loop {
        match read_frame(&mut reader) {
            Ok((kind, payload)) => {
                if is_cmd_frame(kind) {
                    let cmd = String::from_utf8_lossy(&payload).trim().to_string();
                    if !cmd.is_empty() {
                        process_cmd(&cmd);
                    }
                } else if is_qbdi_helper_frame(kind) {
                    #[cfg(feature = "quickjs")]
                    quickjs_loader::install_qbdi_helper(payload);
                } else {
                    write_stream(format!("未知 frame kind: {}", kind).as_bytes());
                }
                if SHOULD_EXIT.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                // 读取错误
                write_stream(format!("读取命令错误: {}", e).as_bytes());
                break;
            }
        }
    }
    // 关闭 socket，host 收到 EOF 自然退出
    shutdown_stream();
    null_mut()
}

/// 执行 JS 脚本并通过 EVAL:/EVAL_ERR: 协议返回结果。
/// loadjs 和 jseval 共用此逻辑。
#[cfg(feature = "quickjs")]
fn eval_and_respond(script: &str, empty_err: &[u8]) {
    if script.is_empty() {
        send_eval_err(std::str::from_utf8(empty_err).unwrap_or("[quickjs] empty script"));
    } else if !quickjs_loader::is_initialized() {
        send_eval_err("[quickjs] JS 引擎未初始化，请先执行 jsinit");
    } else {
        match quickjs_loader::execute_script(script) {
            Ok(result) => send_eval_ok(&result),
            Err(e) => {
                let e = e.replace('\n', "\r");
                send_eval_err(&e);
            }
        }
    }
}

fn process_cmd(command: &str) {
    match command.split_whitespace().next() {
        Some("trace") => {
            let tid = command
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            std::thread::spawn(move || {
                match trace::gum_modify_thread(tid) {
                    Ok(pid) => {
                        write_stream(format!("clone success {}", pid).as_bytes());
                    }
                    Err(e) => {
                        write_stream(format!("error: {}", e).as_bytes());
                    }
                }
                unsafe { kill(process::id() as pid_t, SIGSTOP) }
            });
        }
        #[cfg(feature = "frida-gum")]
        Some("stalker") => {
            let tid = command
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            stalker::follow(tid)
        }
        #[cfg(feature = "frida-gum")]
        Some("hfl") => {
            let mut cmds = command.split_whitespace();
            let md = cmds.nth(1).unwrap();
            let offset = cmds
                .next()
                .and_then(|s| {
                    let s = s.strip_prefix("0x").unwrap_or(s);
                    usize::from_str_radix(s, 16).ok()
                })
                .unwrap_or(0);
            stalker::hfollow(md, offset)
        }
        #[cfg(feature = "quickjs")]
        Some("jsinit") => match quickjs_loader::init() {
            Ok(_) => send_eval_ok("initialized"),
            Err(e) => send_eval_err(&e),
        },
        #[cfg(feature = "quickjs")]
        Some("loadjs") => {
            let script = command.strip_prefix("loadjs").unwrap_or("").trim();
            eval_and_respond(script, b"EVAL_ERR:[quickjs] Error: empty script\n");
        }
        #[cfg(feature = "quickjs")]
        Some("jseval") => {
            let expr = command.strip_prefix("jseval").unwrap_or("").trim();
            eval_and_respond(expr, "EVAL_ERR:[quickjs] 用法: jseval <expression>\n".as_bytes());
        }
        #[cfg(feature = "quickjs")]
        Some("jscomplete") => {
            let prefix = command.strip_prefix("jscomplete").unwrap_or("").trim();
            let result = quickjs_loader::complete(prefix);
            send_complete(&result);
        }
        #[cfg(feature = "quickjs")]
        Some("jsclean") => {
            if !quickjs_loader::is_initialized() {
                send_eval_err("[quickjs] JS 引擎未初始化");
            } else {
                quickjs_loader::cleanup();
                send_eval_ok("cleaned up");
            }
        }
        // shutdown — 先完整清理并输出日志，最后由 agent 主动关闭 socket
        Some("shutdown") => {
            log_msg("收到 shutdown，开始退出清理\n".to_string());
            #[cfg(feature = "quickjs")]
            if quickjs_loader::is_initialized() {
                quickjs_loader::cleanup();
            }
            log_msg("退出清理完成，准备关闭 socket\n".to_string());
            SHOULD_EXIT.store(true, Ordering::Relaxed);
        }
        _ => {
            let cmd_name = command.split_whitespace().next().unwrap_or("(empty)");
            log_msg(format!("无效命令 '{}'，在 REPL 中输入 help 查看可用命令\n", cmd_name));
        }
    }
}
