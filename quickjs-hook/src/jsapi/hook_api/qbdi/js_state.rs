//! 寄存器、错误与关闭相关的 JS 方法。
#![allow(unused_imports)]

use super::js_args::{bool_from_rc, collect_u64_args, extract_string_arg_owned, extract_u32_arg, extract_u64_arg, helper_last_error, value_or_null};
use super::helper::shutdown_qbdi_helper;
use super::helper::load_qbdi_helper;
use super::HelperApi;
use crate::ffi;
use crate::jsapi::callback_util::throw_internal_error;
use crate::value::JSValue;
use crate::qbdi_output_dir;
use libc::{c_int, c_void};
use std::ffi::CString;

pub(crate) unsafe fn js_call_like(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    func_name: &str,
    invoker: impl FnOnce(&HelperApi, u64, u64, &[u64], *mut u64) -> i32,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            CString::new(format!("{}() requires vm and target", func_name))
                .unwrap()
                .as_ptr(),
        );
    }
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, func_name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match extract_u64_arg(ctx, argv, 1, func_name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let args = match collect_u64_args(ctx, argc, argv, 2, func_name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut result = 0u64;
    value_or_null(ctx, invoker(api, handle, target, &args, &mut result), result)
}

pub(crate) unsafe extern "C" fn js_qbdi_call(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_call_like(ctx, argc, argv, "qbdi.call", |api, handle, target, args, result_out| {
        (api.vm_call)(handle, target, args.as_ptr(), args.len() as u32, result_out)
    })
}

pub(crate) unsafe extern "C" fn js_qbdi_switch_stack_and_call(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"qbdi.switchStackAndCall() requires vm, target, stackSize\0".as_ptr() as *const _,
        );
    }
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.switchStackAndCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match extract_u64_arg(ctx, argv, 1, "qbdi.switchStackAndCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let stack_size = match extract_u32_arg(ctx, argv, 2, "qbdi.switchStackAndCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let args = match collect_u64_args(ctx, argc, argv, 3, "qbdi.switchStackAndCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut result = 0u64;
    value_or_null(
        ctx,
        (api.vm_switch_stack_and_call)(
            handle,
            target,
            stack_size,
            args.as_ptr(),
            args.len() as u32,
            &mut result,
        ),
        result,
    )
}

pub(crate) unsafe extern "C" fn js_qbdi_get_gpr(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"qbdi.getGPR() requires vm and reg\0".as_ptr() as *const _);
    }
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.getGPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let reg = match extract_u32_arg(ctx, argv, 1, "qbdi.getGPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut value = 0u64;
    value_or_null(ctx, (api.vm_get_gpr)(handle, reg, &mut value), value)
}

js_bool_method!(js_qbdi_set_gpr, 3, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.setGPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let reg = match extract_u32_arg(ctx, argv, 1, "qbdi.setGPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match extract_u64_arg(ctx, argv, 2, "qbdi.setGPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_set_gpr)(handle, reg, value))
});

pub(crate) unsafe extern "C" fn js_qbdi_get_fpr(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"qbdi.getFPR() requires vm and reg\0".as_ptr() as *const _);
    }
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.getFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let reg = match extract_u32_arg(ctx, argv, 1, "qbdi.getFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut lo = 0u64;
    let mut hi = 0u64;
    if (api.vm_get_fpr)(handle, reg, &mut lo, &mut hi) != 0 {
        return JSValue::null().raw();
    }
    let obj = JSValue(ffi::JS_NewObject(ctx));
    let _ = obj.set_property(ctx, "lo", JSValue(ffi::JS_NewBigUint64(ctx, lo)));
    let _ = obj.set_property(ctx, "hi", JSValue(ffi::JS_NewBigUint64(ctx, hi)));
    obj.raw()
}

js_bool_method!(js_qbdi_set_fpr, 4, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.setFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let reg = match extract_u32_arg(ctx, argv, 1, "qbdi.setFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let lo = match extract_u64_arg(ctx, argv, 2, "qbdi.setFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let hi = match extract_u64_arg(ctx, argv, 3, "qbdi.setFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_set_fpr)(handle, reg, lo, hi))
});

pub(crate) unsafe extern "C" fn js_qbdi_get_errno(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"qbdi.getErrno() requires vm\0".as_ptr() as *const _);
    }
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.getErrno") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut value = 0u32;
    if (api.vm_get_errno)(handle, &mut value) != 0 {
        return JSValue::null().raw();
    }
    JSValue::int(value as i32).raw()
}

js_bool_method!(js_qbdi_set_errno, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.setErrno") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match extract_u32_arg(ctx, argv, 1, "qbdi.setErrno") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_set_errno)(handle, value))
});

js_bool_method!(js_qbdi_set_trace_bundle_metadata, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let module_path = match extract_string_arg_owned(ctx, argv, 0, "qbdi.setTraceBundleMetadata") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let module_base = match extract_u64_arg(ctx, argv, 1, "qbdi.setTraceBundleMetadata") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let c_path = CString::new(module_path).unwrap();
    bool_from_rc((api.trace_set_bundle_metadata)(c_path.as_ptr(), module_base))
});

js_bool_method!(js_qbdi_register_trace_callbacks, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.registerTraceCallbacks") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match extract_u64_arg(ctx, argv, 1, "qbdi.registerTraceCallbacks") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let output_dir = if argc >= 3 {
        match extract_string_arg_owned(ctx, argv, 2, "qbdi.registerTraceCallbacks") {
            Ok(v) => v,
            Err(e) => return e,
        }
    } else {
        qbdi_output_dir().unwrap_or("").to_string()
    };
    if output_dir.is_empty() {
        return throw_internal_error(ctx, "qbdi output dir not configured");
    }
    let c_output = CString::new(output_dir).unwrap();
    bool_from_rc((api.vm_register_trace_callbacks)(handle, target, c_output.as_ptr()))
});

js_bool_method!(js_qbdi_unregister_trace_callbacks, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.unregisterTraceCallbacks") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_unregister_trace_callbacks)(handle))
});

pub(crate) unsafe extern "C" fn js_qbdi_last_error(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(_) => return JSValue::null().raw(),
    };
    match helper_last_error(api) {
        Some(err) => JSValue::string(ctx, &err).raw(),
        None => JSValue::null().raw(),
    }
}

pub(crate) unsafe extern "C" fn js_qbdi_shutdown(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    shutdown_qbdi_helper();
    JSValue::bool(true).raw()
}

