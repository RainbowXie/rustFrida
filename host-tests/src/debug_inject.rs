//! Debug 注入模式的阶段合同与失败清理门禁。
//! rust_frida 仅在 Android 目标编译，因此这里用源码合同锁定行为，
//! 避免 host 测试链去链接 ptrace/NDK。

use std::fs;
use std::path::PathBuf;

fn injection_src() -> String {
    fs::read_to_string(workspace_join("rust_frida/src/injection.rs")).unwrap()
}

fn process_src() -> String {
    fs::read_to_string(workspace_join("rust_frida/src/process.rs")).unwrap()
}

fn workspace_join(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
}

fn fn_body<'a>(src: &'a str, marker: &str) -> &'a str {
    let start = src.find(marker).unwrap_or_else(|| panic!("missing {marker}"));
    let after = &src[start..];
    let brace = after.find('{').unwrap();
    let mut depth = 0i32;
    for (i, ch) in after[brace..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &after[brace..=brace + i];
                }
            }
            _ => {}
        }
    }
    panic!("unclosed function {marker}");
}

#[test]
fn debug_modes_declare_isolated_stages() {
    let src = injection_src();
    let needs_dlopen = fn_body(&src, "fn needs_dlopen");
    let needs_socketpair = fn_body(&src, "fn needs_socketpair");
    let use_empty_so = fn_body(&src, "fn use_empty_so");

    assert!(needs_dlopen.contains("SoOnly") && needs_dlopen.contains("SoEmpty"));
    assert!(!needs_dlopen.contains("PtraceOnly") && !needs_dlopen.contains("MemfdOnly"));
    assert!(needs_socketpair.contains("SoFd") && needs_socketpair.contains("FdOnly"));
    assert!(!needs_socketpair.contains("PtraceOnly"));
    assert!(use_empty_so.contains("SoEmpty"));
    assert!(!use_empty_so.contains("SoOnly"));
}

#[test]
fn empty_so_must_not_embed_loader_shellcode() {
    let src = injection_src();
    let empty = src
        .split("const EMPTY_SO")
        .nth(1)
        .expect("EMPTY_SO missing")
        .split(';')
        .next()
        .unwrap();
    assert!(
        !empty.contains("loader.bin"),
        "so-empty still embeds loader.bin; ELF magic will fail on android_dlopen_ext"
    );
    assert!(
        empty.contains("empty.so"),
        "EMPTY_SO must point at a dedicated empty shared object"
    );
}

#[test]
fn inject_debug_must_use_injection_guard() {
    let src = injection_src();
    let body = fn_body(&src, "pub(crate) fn inject_debug");
    assert!(
        body.contains("InjectionGuard"),
        "inject_debug has no InjectionGuard; a failed android_dlopen_ext leaves ptrace attached"
    );
}

#[test]
fn remote_call_fault_must_restore_registers() {
    let src = process_src();
    let body = fn_body(&src, "pub(crate) fn call_target_function");
    let sigsegv = body
        .split("WaitStatus::Stopped(_, Signal::SIGSEGV)")
        .nth(1)
        .expect("SIGSEGV arm missing");
    let else_arm = sigsegv
        .split("if regs.pc == 0x340")
        .nth(1)
        .and_then(|rest| rest.split("else {").nth(1))
        .expect("SIGSEGV else arm missing");
    // 非 0x340 的 SIGSEGV 仍持有被改写的 PC/LR；不恢复 orig_regs 会把目标留在断在 linker 的状态。
    assert!(
        else_arm.contains("set_registers(pid, &orig_regs)"),
        "call_target_function fault path does not restore orig_regs"
    );
}

#[test]
fn inject_debug_error_must_not_leave_wwb_so_fd() {
    let src = injection_src();
    let body = fn_body(&src, "pub(crate) fn inject_debug");
    assert!(
        body.contains("offsets.close") && body.contains("target_memfd"),
        "inject_debug must close the target wwb_so memfd"
    );
    // `?` 在 dlopen 失败时会跳过 close；guard 或显式 catch 才能保证 fd 不泄漏。
    assert!(
        body.contains("InjectionGuard")
            || body.contains("cleanup_debug_inject")
            || body.contains("close_memfd"),
        "no deterministic memfd cleanup on inject_debug error"
    );
}

#[test]
fn android16_matrix_script_exists() {
    let path = workspace_join("host-tests/scripts/android16-inject-matrix.sh");
    let src = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    for mode in ["ptrace-only", "memfd-only", "so-empty", "so-only", "so+fd+thread"] {
        assert!(src.contains(mode), "matrix script missing mode {mode}");
    }
    assert!(src.contains("192.168.123.235:5555"));
}
