#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod data;
mod state;
mod trace_api;
mod vm_api;
mod writer;

use std::ffi::c_void;

extern "C" {
    fn get_hide_result() -> *const c_void;
    fn hide_from_solist(handle: *mut c_void) -> i32;
}

#[no_mangle]
pub extern "C" fn rust_get_hide_result() -> *const c_void {
    unsafe { get_hide_result() }
}

#[no_mangle]
pub extern "C" fn rust_hide_from_solist(handle: *mut c_void) -> i32 {
    unsafe { hide_from_solist(handle) }
}
