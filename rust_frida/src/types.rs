#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{
    c_void, close, dlerror, dlopen, dlsym, free, malloc, memfd_create, mmap, munmap, pthread_create, pthread_detach,
    read, socketpair, strlen, write,
};
use paste::paste;
use std::os::raw::c_int;

use crate::log_step;
use crate::process::{call_target_function, write_bytes, write_memory};

extern "C" {
    fn android_dlopen_ext(filename: *const std::os::raw::c_char, flag: c_int, extinfo: *const c_void) -> *mut c_void;
}

/// 定义需要获取偏移的函数列表
macro_rules! define_libc_functions {
    ($($name:ident),*) => {
        #[derive(Debug, Default, Clone, Copy)]
        pub(crate) struct LibcOffsets {
            $(pub(crate) $name: usize),*
        }

        impl LibcOffsets {
            pub(crate) fn calculate(self_base: usize, target_base: usize) -> Result<Self, String> {
                $(
                    let sym_addr = $name as *const () as usize;
                    if sym_addr < self_base {
                        return Err(format!(
                            "符号 {} 地址(0x{:x}) 小于 libc 基址(0x{:x})，请确认 libc 版本匹配",
                            stringify!($name), sym_addr, self_base
                        ));
                    }
                    let $name = target_base + (sym_addr - self_base);
                )*
                Ok(Self { $($name),* })
            }

            pub(crate) fn print_offsets(&self) {
                log_step!("目标进程函数地址列表:");
                $(println!("     {}: 0x{:x}", stringify!($name), self.$name);)*
            }
        }
    };
}

macro_rules! define_dl_functions {
    ($($name:ident),*) => {
        #[derive(Debug, Default, Clone, Copy)]
        pub(crate) struct DlOffsets {
            $(pub(crate) $name: usize),*
        }

        impl DlOffsets {
            pub(crate) fn calculate(self_base: usize, target_base: usize) -> Result<Self, String> {
                $(
                    let sym_addr = $name as *const () as usize;
                    if sym_addr < self_base {
                        return Err(format!(
                            "符号 {} 地址(0x{:x}) 小于 libdl 基址(0x{:x})，请确认 libdl 版本匹配",
                            stringify!($name), sym_addr, self_base
                        ));
                    }
                    let $name = target_base + (sym_addr - self_base);
                )*
                Ok(Self { $($name),* })
            }

            pub(crate) fn print_offsets(&self) {
                log_step!("libdl.so 函数地址列表:");
                $(println!("     {}: 0x{:x}", stringify!($name), self.$name);)*
            }
        }
    };
}

// 定义字符串表宏
// 支持通过 overrides HashMap 覆盖默认值，格式：name=value
macro_rules! define_string_table {
    ($(($name:ident, $value:expr)),* $(,)?) => {
        paste! {
            #[repr(C)]
            pub(crate) struct StringTable {
                $(
                    pub(crate) $name: u64,
                    pub(crate) [<$name _len>]: u32,
                )*
            }

            // 获取所有可用的字符串名称
            pub(crate) fn get_string_table_names() -> Vec<&'static str> {
                vec![$(stringify!($name)),*]
            }

            #[allow(unused_assignments)]
            pub(crate) fn write_string_table(pid: i32, malloc_addr: usize, overrides: &std::collections::HashMap<String, String>) -> Result<usize, String> {
                $(
                    // 检查是否有覆盖值
                    let mut $name = if let Some(override_val) = overrides.get(stringify!($name)) {
                        override_val.as_bytes().to_vec()
                    } else {
                        $value.to_vec()
                    };
                    $name.push(0); // 添加 NULL 结尾
                )*

                let strings_len = 0 $(+ $name.len())*;
                let table_size = std::mem::size_of::<StringTable>();
                let total_size = table_size + strings_len;

                // 通过 call_target_function 用目标进程的 malloc 分配内存
                let table_addr = call_target_function(pid, malloc_addr, &[total_size], None)?;
                let mut string_addr = table_addr + table_size;

                let mut table = StringTable {
                    $(
                        $name: 0,
                        [<$name _len>] : 0,
                    )*
                };

                $(
                    table.$name = string_addr as u64;
                    // 长度包含最后的 NULL 结尾
                    table.[<$name _len>] = $name.len() as u32;
                    write_bytes(pid, string_addr, &$name)?;
                    string_addr += $name.len();
                )*

                write_memory(pid, table_addr, &table)?;
                Ok(table_addr)
            }
        }
    };
}

// 使用宏定义字符串表
define_string_table!(
    (sym_name, b"hello_entry"),
    (pthread_err, b"pthreadded"),
    (dlsym_err, b"dlsymFail"),
    (cmdline, b"novalue"),
    (output_path, b"novalue"),
    // 未来添加字符串只需在这里添加新行即可
);

// 使用宏定义函数列表
define_libc_functions!(
    malloc,       // 用于分配内存
    free,         // 用于释放内存
    socketpair,   // 用于创建已连接的套接字对
    read,         // 用于从 socket 读取 agent blob
    write,        // 用于发送数据
    close,        // 用于关闭套接字
    mmap,         // 用于内存映射
    munmap,       // 用于释放内存映射
    memfd_create, // 用于创建匿名内存文件
    pthread_create,
    pthread_detach,
    strlen
);

define_dl_functions!(
    dlopen, // 动态加载
    dlsym,  // 动态符号查找
    dlerror,
    android_dlopen_ext // fd-based dlopen (绕过 SELinux)
);

/// 注入参数结构体，传递给 shellcode → agent
/// ABI 关键：必须与 loader.c 和 agent/src/lib.rs 中的定义完全一致
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct AgentArgs {
    pub(crate) table: u64,       // *const StringTable（目标进程内地址）
    pub(crate) ctrl_fd: i32,     // socketpair fd1（agent 端）
    pub(crate) agent_memfd: i32, // 目标进程内的 agent.so memfd
}

/// 用户空间寄存器结构体
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct UserRegs {
    pub(crate) regs: [u64; 31], // X0-X30 寄存器
    pub(crate) sp: u64,         // SP 栈指针
    pub(crate) pc: u64,         // PC 程序计数器
    pub(crate) pstate: u64,     // 处理器状态
}
