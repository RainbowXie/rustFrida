//! JavaScript 参数提取与返回值转换辅助。
#![allow(unused_imports)]

use super::{HelperApi, HELPER_API};
use crate::ffi;
use crate::jsapi::callback_util::extract_pointer_address;
use crate::value::JSValue;
use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};

pub(crate) unsafe fn helper_last_error(api: &HelperApi) -> Option<String> {
    let ptr = (api.last_error)();
    if ptr.is_null() {
        None
    } else {
        Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
    }
}

pub(crate) unsafe fn extract_u64_arg(
    ctx: *mut ffi::JSContext,
    argv: *mut ffi::JSValue,
    index: usize,
    func: &str,
) -> Result<u64, ffi::JSValue> {
    extract_pointer_address(ctx, JSValue(*argv.add(index)), func)
}

pub(crate) unsafe fn extract_u32_arg(
    ctx: *mut ffi::JSContext,
    argv: *mut ffi::JSValue,
    index: usize,
    func: &str,
) -> Result<u32, ffi::JSValue> {
    let value = JSValue(*argv.add(index))
        .to_i64(ctx)
        .filter(|v| *v >= 0 && *v <= u32::MAX as i64)
        .map(|v| v as u32);
    value.ok_or_else(|| {
        ffi::JS_ThrowTypeError(
            ctx,
            CString::new(format!("{}() argument {} must be u32", func, index))
                .unwrap()
                .as_ptr(),
        )
    })
}

pub(crate) unsafe fn extract_string_arg_owned(
    ctx: *mut ffi::JSContext,
    argv: *mut ffi::JSValue,
    index: usize,
    func: &str,
) -> Result<String, ffi::JSValue> {
    JSValue(*argv.add(index)).to_string(ctx).ok_or_else(|| {
        ffi::JS_ThrowTypeError(
            ctx,
            CString::new(format!("{}() argument {} must be string", func, index))
                .unwrap()
                .as_ptr(),
        )
    })
}

pub(crate) unsafe fn collect_u64_args(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    start: usize,
    func: &str,
) -> Result<Vec<u64>, ffi::JSValue> {
    let argc = argc.max(0) as usize;
    let mut args = Vec::with_capacity(argc.saturating_sub(start));
    for i in start..argc {
        args.push(extract_pointer_address(ctx, JSValue(*argv.add(i)), func)?);
    }
    Ok(args)
}

pub(crate) unsafe fn bool_from_rc(rc: i32) -> ffi::JSValue {
    JSValue::bool(rc == 0).raw()
}

pub(crate) unsafe fn value_or_null(ctx: *mut ffi::JSContext, rc: i32, value: u64) -> ffi::JSValue {
    if rc == 0 {
        if value <= (1u64 << 53) {
            ffi::qjs_new_int64(ctx, value as i64)
        } else {
            ffi::JS_NewBigUint64(ctx, value)
        }
    } else {
        JSValue::null().raw()
    }
}
