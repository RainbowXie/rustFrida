//! QBDI helper 的动态加载与 hide_soinfo 校验。
#![allow(unused_imports)]

use super::{GetHideResultFn, HelperApi, HideResult, HideFromSolistFn, CHAIN_HIDDEN, HELPER_API, HIDE_RESULT_VERSION, QBDI_HELPER_HANDLE};
use crate::jsapi::console::output_message;
use crate::jsapi::module::memfd_dlopen;
use crate::{qbdi_helper_blob, qbdi_output_dir};
use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::sync::OnceLock;

/// 解析 helper 的规范化导出。
///
/// cdylib 只会导出 Rust 侧 #[no_mangle] 的 rust_* 包装（C 侧同名函数被
/// localize），所以唯一合法名字是 rust_*；不接受别名回退。
pub(crate) unsafe fn resolve_symbol(handle: *mut c_void, name: &str) -> *mut c_void {
    let sym = CString::new(name).unwrap();
    libc::dlsym(handle, sym.as_ptr())
}

/// hide_soinfo 是 QBDI helper 可用的前提：helper 仍在 linker 枚举里时，
/// 继续发布 HELPER_API 会把隐藏失败悄悄降级成“功能可用”。
fn verify_qbdi_helper_hide_result(handle: *mut c_void) -> Result<(), String> {
    let hide_ptr = unsafe { resolve_symbol(handle, "rust_hide_from_solist") };
    if hide_ptr.is_null() {
        return Err("qbdi helper missing symbol rust_hide_from_solist".to_string());
    }
    let hide_status = unsafe {
        let hide_from_solist: HideFromSolistFn = std::mem::transmute(hide_ptr);
        hide_from_solist(handle)
    };

    let fn_ptr = unsafe { resolve_symbol(handle, "rust_get_hide_result") };
    if fn_ptr.is_null() {
        return Err("qbdi helper missing symbol rust_get_hide_result".to_string());
    }

    let result_ptr = unsafe {
        let get_hide_result: GetHideResultFn = std::mem::transmute(fn_ptr);
        get_hide_result()
    };
    if result_ptr.is_null() {
        return Err("qbdi helper hide result pointer is NULL".to_string());
    }

    let result = unsafe { *result_ptr };
    if result.version != HIDE_RESULT_VERSION {
        return Err(format!(
            "qbdi helper hide result version mismatch: {} != {}",
            result.version, HIDE_RESULT_VERSION
        ));
    }

    let target_path = HideResult::cstr(&result.target_path);
    let head_path = HideResult::cstr(&result.head_path);
    // 三条都成立才算双链真的不可见；只看 status 会放过“soinfo 摘了但 r_map 没摘”。
    if hide_status != 1 || result.status != 1 {
        let error = HideResult::cstr(&result.error);
        return Err(format!(
            "qbdi helper hide_soinfo failed: hide_status={} status={} stage={} soinfo={} link_map={} wrote=0x{:x} error=\"{}\"",
            hide_status,
            result.status,
            result.stage,
            result.soinfo_state,
            result.link_map_state,
            result.wrote,
            error
        ));
    }
    if result.soinfo_state != CHAIN_HIDDEN || result.link_map_state != CHAIN_HIDDEN {
        return Err(format!(
            "qbdi helper hide_soinfo incomplete: soinfo={} link_map={} (expected {} both)",
            result.soinfo_state, result.link_map_state, CHAIN_HIDDEN
        ));
    }

    output_message(&format!(
        "[qbdi] qbdi-helper hide_soinfo ok: target=\"{}\" next_offset=0x{:x} scanned={} syms={} target=0x{:x} stage={}",
        target_path, result.next_offset, result.entries_scanned, result.sym_matched, result.target_ptr, result.stage
    ));
    if !head_path.is_empty() {
        output_message(&format!(
            "[qbdi] qbdi-helper hide_soinfo head: \"{}\" ({:#x})",
            head_path, result.head_ptr
        ));
    }
    Ok(())
}

pub(crate) unsafe fn build_helper_api(handle: *mut c_void) -> Result<HelperApi, String> {
    let required = |name: &str| {
        let ptr = resolve_symbol(handle, name);
        if ptr.is_null() {
            Err(format!("qbdi helper missing symbol {}", name))
        } else {
            Ok(ptr)
        }
    };

    Ok(HelperApi {
        last_error: std::mem::transmute(required("qbdi_trace_last_error")?),
        shutdown: {
            let ptr = resolve_symbol(handle, "qbdi_trace_shutdown");
            (!ptr.is_null()).then(|| std::mem::transmute(ptr))
        },
        vm_new: std::mem::transmute(required("qbdi_vm_new")?),
        vm_destroy: std::mem::transmute(required("qbdi_vm_destroy")?),
        vm_add_instrumented_range: std::mem::transmute(required("qbdi_vm_add_instrumented_range")?),
        vm_add_instrumented_module: std::mem::transmute(required("qbdi_vm_add_instrumented_module")?),
        vm_add_instrumented_module_from_addr: std::mem::transmute(required(
            "qbdi_vm_add_instrumented_module_from_addr",
        )?),
        vm_instrument_all_executable_maps: std::mem::transmute(required("qbdi_vm_instrument_all_executable_maps")?),
        vm_remove_instrumented_range: std::mem::transmute(required("qbdi_vm_remove_instrumented_range")?),
        vm_remove_all_instrumented_ranges: std::mem::transmute(required("qbdi_vm_remove_all_instrumented_ranges")?),
        vm_delete_all_instrumentations: std::mem::transmute(required("qbdi_vm_delete_all_instrumentations")?),
        vm_record_memory_access: std::mem::transmute(required("qbdi_vm_record_memory_access")?),
        vm_allocate_virtual_stack: std::mem::transmute(required("qbdi_vm_allocate_virtual_stack")?),
        vm_clear_virtual_stacks: std::mem::transmute(required("qbdi_vm_clear_virtual_stacks")?),
        vm_simulate_call: std::mem::transmute(required("qbdi_vm_simulate_call")?),
        vm_run: std::mem::transmute(required("qbdi_vm_run")?),
        vm_call: std::mem::transmute(required("qbdi_vm_call")?),
        vm_switch_stack_and_call: std::mem::transmute(required("qbdi_vm_switch_stack_and_call")?),
        vm_get_gpr: std::mem::transmute(required("qbdi_vm_get_gpr")?),
        vm_set_gpr: std::mem::transmute(required("qbdi_vm_set_gpr")?),
        vm_get_fpr: std::mem::transmute(required("qbdi_vm_get_fpr")?),
        vm_set_fpr: std::mem::transmute(required("qbdi_vm_set_fpr")?),
        vm_get_errno: std::mem::transmute(required("qbdi_vm_get_errno")?),
        vm_set_errno: std::mem::transmute(required("qbdi_vm_set_errno")?),
        trace_set_bundle_metadata: std::mem::transmute(required("qbdi_trace_set_bundle_metadata")?),
        vm_register_trace_callbacks: std::mem::transmute(required("qbdi_vm_register_trace_callbacks")?),
        vm_unregister_trace_callbacks: std::mem::transmute(required("qbdi_vm_unregister_trace_callbacks")?),
    })
}

pub(crate) fn load_qbdi_helper() -> Result<&'static HelperApi, String> {
    if let Some(api) = HELPER_API.get() {
        return Ok(api);
    }

    let helper_blob = qbdi_helper_blob().ok_or_else(|| "qbdi helper blob not configured".to_string())?;
    let memfd_name = CString::new("wwb_so").unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create as libc::c_long, memfd_name.as_ptr(), 0) as c_int };
    if fd < 0 {
        return Err(format!(
            "memfd_create(qbdi_helper) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    {
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(&helper_blob)
            .map_err(|e| format!("write helper blob to memfd failed: {}", e))?;
        file.flush()
            .map_err(|e| format!("flush helper blob memfd failed: {}", e))?;
        let _ = file.into_raw_fd();
    }
    let handle = unsafe { memfd_dlopen("qbdi_helper.so", fd) };
    if handle.is_null() {
        let msg = unsafe {
            let err = libc::dlerror();
            if err.is_null() {
                "android_dlopen_ext(qbdi helper) failed".to_string()
            } else {
                CStr::from_ptr(err).to_string_lossy().into_owned()
            }
        };
        unsafe { libc::close(fd) };
        return Err(format!("failed to load qbdi helper from memfd: {}", msg));
    }
    unsafe { libc::close(fd) };

    verify_qbdi_helper_hide_result(handle)?;
    let _ = QBDI_HELPER_HANDLE.set(handle as usize);
    let api = unsafe { build_helper_api(handle)? };
    let _ = HELPER_API.set(api);
    Ok(HELPER_API.get().expect("helper api set"))
}

pub fn preload_qbdi_helper() -> Result<(), String> {
    let _ = load_qbdi_helper()?;
    Ok(())
}

pub fn shutdown_qbdi_helper() {
    if let Some(api) = HELPER_API.get() {
        if let Some(shutdown) = api.shutdown {
            unsafe { shutdown() };
        }
    }
}

