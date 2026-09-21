#![cfg(feature = "qbdi")]

// 本模块只保留共享类型定义与子模块接线；实现分别放在子模块里。
use libc::{c_char, c_int, c_void};
use std::sync::OnceLock;

// 与 agent/src/hide_soinfo.h 的 HIDE_RESULT_VERSION / CHAIN_HIDDEN 保持一致。
pub(crate) const HIDE_RESULT_VERSION: i32 = 1;
pub(crate) const CHAIN_HIDDEN: i32 = 1;

pub(crate) type LastErrorFn = unsafe extern "C" fn() -> *const c_char;
pub(crate) type ShutdownFn = unsafe extern "C" fn();
pub(crate) type GetHideResultFn = unsafe extern "C" fn() -> *const HideResult;
pub(crate) type HideFromSolistFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type VmNewFn = unsafe extern "C" fn() -> u64;
type VmUnaryFn = unsafe extern "C" fn(u64) -> c_int;
type VmRangeFn = unsafe extern "C" fn(u64, u64, u64) -> c_int;
type VmModuleFn = unsafe extern "C" fn(u64, *const c_char) -> c_int;
type VmAddrFn = unsafe extern "C" fn(u64, u64) -> c_int;
type VmRecordMemoryAccessFn = unsafe extern "C" fn(u64, u32) -> c_int;
type VmStackAllocFn = unsafe extern "C" fn(u64, u32) -> c_int;
type VmSimulateCallFn = unsafe extern "C" fn(u64, u64, *const u64, u32) -> c_int;
type VmRunFn = unsafe extern "C" fn(u64, u64, u64) -> c_int;
type VmCallFn = unsafe extern "C" fn(u64, u64, *const u64, u32, *mut u64) -> c_int;
type VmSwitchStackAndCallFn = unsafe extern "C" fn(u64, u64, u32, *const u64, u32, *mut u64) -> c_int;
type VmGetGprFn = unsafe extern "C" fn(u64, u32, *mut u64) -> c_int;
type VmSetGprFn = unsafe extern "C" fn(u64, u32, u64) -> c_int;
type VmGetFprFn = unsafe extern "C" fn(u64, u32, *mut u64, *mut u64) -> c_int;
type VmSetFprFn = unsafe extern "C" fn(u64, u32, u64, u64) -> c_int;
type VmGetErrnoFn = unsafe extern "C" fn(u64, *mut u32) -> c_int;
type VmSetErrnoFn = unsafe extern "C" fn(u64, u32) -> c_int;
type VmTraceRegisterFn = unsafe extern "C" fn(u64, u64, *const c_char) -> c_int;
type TraceBundleMetadataFn = unsafe extern "C" fn(*const c_char, u64) -> c_int;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct HideResult {
    pub(crate) version: i32,
    pub(crate) stage: i32,
    pub(crate) status: i32,
    pub(crate) next_offset: i32,
    pub(crate) entries_scanned: i32,
    pub(crate) sym_matched: i32,
    pub(crate) soinfo_state: i32,
    pub(crate) link_map_state: i32,
    pub(crate) wrote: i32,
    pub(crate) _pad: i32,
    pub(crate) head_ptr: u64,
    pub(crate) target_ptr: u64,
    pub(crate) error: [u8; 128],
    pub(crate) target_path: [u8; 128],
    pub(crate) head_path: [u8; 128],
}

impl HideResult {
    pub(crate) fn cstr(buf: &[u8]) -> &str {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        std::str::from_utf8(&buf[..end]).unwrap_or("")
    }
}

pub(crate) struct HelperApi {
    last_error: LastErrorFn,
    shutdown: Option<ShutdownFn>,
    vm_new: VmNewFn,
    vm_destroy: VmUnaryFn,
    vm_add_instrumented_range: VmRangeFn,
    vm_add_instrumented_module: VmModuleFn,
    vm_add_instrumented_module_from_addr: VmAddrFn,
    vm_instrument_all_executable_maps: VmUnaryFn,
    vm_remove_instrumented_range: VmRangeFn,
    vm_remove_all_instrumented_ranges: VmUnaryFn,
    vm_delete_all_instrumentations: VmUnaryFn,
    vm_record_memory_access: VmRecordMemoryAccessFn,
    vm_allocate_virtual_stack: VmStackAllocFn,
    vm_clear_virtual_stacks: VmUnaryFn,
    vm_simulate_call: VmSimulateCallFn,
    vm_run: VmRunFn,
    vm_call: VmCallFn,
    vm_switch_stack_and_call: VmSwitchStackAndCallFn,
    vm_get_gpr: VmGetGprFn,
    vm_set_gpr: VmSetGprFn,
    vm_get_fpr: VmGetFprFn,
    vm_set_fpr: VmSetFprFn,
    vm_get_errno: VmGetErrnoFn,
    vm_set_errno: VmSetErrnoFn,
    trace_set_bundle_metadata: TraceBundleMetadataFn,
    vm_register_trace_callbacks: VmTraceRegisterFn,
    vm_unregister_trace_callbacks: VmUnaryFn,
}

pub(crate) static HELPER_API: OnceLock<HelperApi> = OnceLock::new();
pub(crate) static QBDI_HELPER_HANDLE: OnceLock<usize> = OnceLock::new();


// 子模块共享的 JS 方法包装宏（textual scope：必须在 mod 声明之前）。
macro_rules! js_bool_method {
    ($name:ident, $argc_min:expr, |$ctx:ident, $argc:ident, $argv:ident| $body:block) => {
        pub(crate) unsafe extern "C" fn $name(
            $ctx: *mut ffi::JSContext,
            _this: ffi::JSValue,
            $argc: i32,
            $argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            if $argc < $argc_min {
                return ffi::JS_ThrowTypeError(
                    $ctx,
                    concat!(stringify!($name), " invalid argc\0").as_ptr() as *const _,
                );
            }
            $body
        }
    };
}

mod helper;
mod js_args;
mod js_state;
mod js_vm;
mod register;

pub use helper::{preload_qbdi_helper, shutdown_qbdi_helper};
pub use register::register_qbdi_api;
