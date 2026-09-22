//! VM 生命周期与内存访问相关的 JS 方法。
#![allow(unused_imports)]

use super::js_args::{bool_from_rc, collect_u64_args, extract_string_arg_owned, extract_u32_arg, extract_u64_arg, value_or_null};
use super::helper::load_qbdi_helper;
use crate::ffi;
use crate::jsapi::callback_util::throw_internal_error;
use crate::value::JSValue;
use libc::{c_int, c_void};
use std::ffi::CString;

pub(crate) unsafe extern "C" fn js_qbdi_new_vm(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = (api.vm_new)();
    if handle == 0 {
        return JSValue::null().raw();
    }
    if handle <= (1u64 << 53) {
        ffi::qjs_new_int64(ctx, handle as i64)
    } else {
        ffi::JS_NewBigUint64(ctx, handle)
    }
}


js_bool_method!(js_qbdi_destroy_vm, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.destroyVM") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_destroy)(handle))
});

js_bool_method!(js_qbdi_add_instrumented_range, 3, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.addInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let start = match extract_u64_arg(ctx, argv, 1, "qbdi.addInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let end = match extract_u64_arg(ctx, argv, 2, "qbdi.addInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_add_instrumented_range)(handle, start, end))
});

js_bool_method!(js_qbdi_add_instrumented_module, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.addInstrumentedModule") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = match extract_string_arg_owned(ctx, argv, 1, "qbdi.addInstrumentedModule") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let c_name = CString::new(name).unwrap();
    bool_from_rc((api.vm_add_instrumented_module)(handle, c_name.as_ptr()))
});

js_bool_method!(js_qbdi_add_instrumented_module_from_addr, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.addInstrumentedModuleFromAddr") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let addr = match extract_u64_arg(ctx, argv, 1, "qbdi.addInstrumentedModuleFromAddr") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_add_instrumented_module_from_addr)(handle, addr))
});

js_bool_method!(js_qbdi_instrument_all_executable_maps, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.instrumentAllExecutableMaps") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_instrument_all_executable_maps)(handle))
});

js_bool_method!(js_qbdi_remove_instrumented_range, 3, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.removeInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let start = match extract_u64_arg(ctx, argv, 1, "qbdi.removeInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let end = match extract_u64_arg(ctx, argv, 2, "qbdi.removeInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_remove_instrumented_range)(handle, start, end))
});

js_bool_method!(js_qbdi_remove_all_instrumented_ranges, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.removeAllInstrumentedRanges") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_remove_all_instrumented_ranges)(handle))
});

js_bool_method!(js_qbdi_delete_all_instrumentations, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.deleteAllInstrumentations") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_delete_all_instrumentations)(handle))
});

js_bool_method!(js_qbdi_record_memory_access, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.recordMemoryAccess") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let access_type = match extract_u32_arg(ctx, argv, 1, "qbdi.recordMemoryAccess") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_record_memory_access)(handle, access_type))
});

js_bool_method!(js_qbdi_allocate_virtual_stack, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.allocateVirtualStack") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let stack_size = match extract_u32_arg(ctx, argv, 1, "qbdi.allocateVirtualStack") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_allocate_virtual_stack)(handle, stack_size))
});

js_bool_method!(js_qbdi_clear_virtual_stacks, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.clearVirtualStacks") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_clear_virtual_stacks)(handle))
});

js_bool_method!(js_qbdi_simulate_call, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.simulateCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let return_addr = match extract_u64_arg(ctx, argv, 1, "qbdi.simulateCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let args = match collect_u64_args(ctx, argc, argv, 2, "qbdi.simulateCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_simulate_call)(
        handle,
        return_addr,
        args.as_ptr(),
        args.len() as u32,
    ))
});

js_bool_method!(js_qbdi_run, 3, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.run") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let start = match extract_u64_arg(ctx, argv, 1, "qbdi.run") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let stop = match extract_u64_arg(ctx, argv, 2, "qbdi.run") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_run)(handle, start, stop))
});
