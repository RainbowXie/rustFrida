//! 把 QBDI 方法注册到 JS 对象上。
#![allow(unused_imports)]

use super::js_state::*;
use super::js_vm::*;
use crate::ffi;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;

pub fn register_qbdi_api(ctx: *mut ffi::JSContext, qbdi_obj: ffi::JSValue) {
    unsafe {
        add_cfunction_to_object(ctx, qbdi_obj, "newVM", js_qbdi_new_vm, 0);
        add_cfunction_to_object(ctx, qbdi_obj, "destroyVM", js_qbdi_destroy_vm, 1);
        add_cfunction_to_object(ctx, qbdi_obj, "addInstrumentedRange", js_qbdi_add_instrumented_range, 3);
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "addInstrumentedModule",
            js_qbdi_add_instrumented_module,
            2,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "addInstrumentedModuleFromAddr",
            js_qbdi_add_instrumented_module_from_addr,
            2,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "instrumentAllExecutableMaps",
            js_qbdi_instrument_all_executable_maps,
            1,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "removeInstrumentedRange",
            js_qbdi_remove_instrumented_range,
            3,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "removeAllInstrumentedRanges",
            js_qbdi_remove_all_instrumented_ranges,
            1,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "deleteAllInstrumentations",
            js_qbdi_delete_all_instrumentations,
            1,
        );
        add_cfunction_to_object(ctx, qbdi_obj, "recordMemoryAccess", js_qbdi_record_memory_access, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "allocateVirtualStack", js_qbdi_allocate_virtual_stack, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "clearVirtualStacks", js_qbdi_clear_virtual_stacks, 1);
        add_cfunction_to_object(ctx, qbdi_obj, "simulateCall", js_qbdi_simulate_call, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "run", js_qbdi_run, 3);
        add_cfunction_to_object(ctx, qbdi_obj, "call", js_qbdi_call, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "switchStackAndCall", js_qbdi_switch_stack_and_call, 3);
        add_cfunction_to_object(ctx, qbdi_obj, "getGPR", js_qbdi_get_gpr, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "setGPR", js_qbdi_set_gpr, 3);
        add_cfunction_to_object(ctx, qbdi_obj, "getFPR", js_qbdi_get_fpr, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "setFPR", js_qbdi_set_fpr, 4);
        add_cfunction_to_object(ctx, qbdi_obj, "getErrno", js_qbdi_get_errno, 1);
        add_cfunction_to_object(ctx, qbdi_obj, "setErrno", js_qbdi_set_errno, 2);
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "setTraceBundleMetadata",
            js_qbdi_set_trace_bundle_metadata,
            2,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "registerTraceCallbacks",
            js_qbdi_register_trace_callbacks,
            2,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "unregisterTraceCallbacks",
            js_qbdi_unregister_trace_callbacks,
            1,
        );
        add_cfunction_to_object(ctx, qbdi_obj, "lastError", js_qbdi_last_error, 0);
        add_cfunction_to_object(ctx, qbdi_obj, "shutdown", js_qbdi_shutdown, 0);
    }

    let obj = JSValue(qbdi_obj);
    let _ = obj.set_property(ctx, "MEMORY_READ", JSValue::int(1));
    let _ = obj.set_property(ctx, "MEMORY_WRITE", JSValue::int(2));
    let _ = obj.set_property(ctx, "MEMORY_READ_WRITE", JSValue::int(3));
    let _ = obj.set_property(ctx, "REG_RETURN", JSValue::int(0));
    let _ = obj.set_property(ctx, "REG_BP", JSValue::int(29));
    let _ = obj.set_property(ctx, "REG_LR", JSValue::int(30));
    let _ = obj.set_property(ctx, "REG_SP", JSValue::int(31));
    let _ = obj.set_property(ctx, "REG_FLAG", JSValue::int(32));
    let _ = obj.set_property(ctx, "REG_PC", JSValue::int(33));
}
