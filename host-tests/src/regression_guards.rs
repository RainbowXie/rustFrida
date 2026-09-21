//! 对已修复缺陷的回归守卫。
//!
//! 这些断言把“为什么这样写”固化成可执行契约：如果将来有人把回退逻辑或
//! 名字匹配加回来，或忘了链 compiler-rt，测试会直接失败而不是等到设备上炸。

use std::path::PathBuf;

fn workspace_join(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(workspace_join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// 去掉 `//` 行注释后的小写正文。
///
/// 正向断言（“必须调用 X”）必须基于这个，否则把调用改成注释也能通过，
/// 而缺陷恰恰就是这样被漏掉的。
fn code_lower(rel: &str) -> String {
    read(rel)
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase()
}

/// bionic 不导出 __clear_cache；两个 cdylib 都必须显式链 compiler-rt builtins。
///
/// 不链的话链接仍然成功（共享库允许未定义符号），缺陷会推迟到设备 dlopen 才暴露，
/// 因此这里在源码层守住，release.sh 另有一道产物符号门禁。
#[test]
fn both_cdylibs_link_compiler_rt_builtins() {
    let shared = code_lower("build-support/compiler_rt.rs");
    assert!(
        shared.contains("clang_rt.builtins-aarch64"),
        "shared build-support must link compiler-rt builtins for __clear_cache"
    );
    assert!(
        shared.contains("link-search") || shared.contains("rustc-link-lib"),
        "must emit the link search path and library"
    );
    for build_rs in ["agent/build.rs", "qbdi-helper/build.rs"] {
        let src = read(build_rs);
        // 必须是真的调用，而不是被注释掉的残留——否则 __clear_cache 又会在设备上才爆。
        let called = src.lines().map(str::trim).any(|l| l == "link_compiler_rt_builtins();");
        assert!(called, "{build_rs} must actually call link_compiler_rt_builtins");
    }
}

/// release.sh 必须对产物做未定义符号门禁，否则回归会静默发布。
#[test]
fn release_gate_rejects_undefined_clear_cache() {
    let src = code_lower("scripts/release.sh");
    assert!(src.contains("__clear_cache"), "release.sh must check for undefined __clear_cache");
    assert!(
        src.contains("undefined-only"),
        "release.sh must inspect undefined dynamic symbols of the artifacts"
    );
}

/// release.sh 不能只在 loader.bin 缺失时才构建：源码改了而产物在时会被静默跳过。
#[test]
fn release_rebuilds_loader_when_source_is_newer() {
    let src = read("scripts/release.sh");
    assert!(
        src.contains("loader.c -nt") || src.contains("loader.py --ndk"),
        "release.sh must rebuild loader.bin when loader.c is newer"
    );
    assert!(
        !src.contains("if [[ ! -f loader/build/loader.bin ]]; then"),
        "must not gate loader.bin rebuild solely on file absence"
    );
}

/// cdylib 只导出 Rust 侧 rust_* 包装；所有加载路径都只认这一个名字，
/// 不允许再出现别名回退（回退会把“导出丢了”掩盖成“换了个符号”）。
#[test]
fn hide_symbols_have_no_alias_fallback() {
    let injection = read("rust_frida/src/injection.rs");
    assert!(
        !injection.contains("b\"hide_from_solist\\0\""),
        "injection.rs must not fall back to the localized C name"
    );
    assert!(
        !injection.contains("b\"get_hide_result\\0\""),
        "injection.rs must not fall back to the localized C name"
    );
    let qbdi_helper = read("quickjs-hook/src/jsapi/hook_api/qbdi/helper.rs");
    assert!(
        !qbdi_helper.contains("\"hide_from_solist\""),
        "qbdi helper must resolve rust_hide_from_solist only"
    );
    let loader = read("loader/loader.c");
    assert!(
        !loader.contains("hide_name[12]='l'; hide_name[13]='i';"),
        "loader.c must not fall back to the localized C name"
    );
}

/// 双链写入失败必须能回到改前状态，RELRO 临时打开的写权限必须恢复。
#[test]
fn hide_transaction_rolls_back_and_restores_protection() {
    let src = code_lower("agent/src/hide_txn.c");
    assert!(src.contains("write_journal"), "dual-chain writes must be journaled");
    assert!(src.contains("journal_rollback"), "failures must roll back written slots");
    assert!(src.contains("page_prot"), "must read the page's original protection");
    // 恢复必须发生在写完之后，否则 RELRO 页会永久可写。
    let store = src
        .split("static int store_ptr")
        .nth(1)
        .expect("store_ptr missing");
    let store = store.split("static int page_prot").next().unwrap();
    assert_eq!(
        store.matches("mprotect").count(),
        2,
        "store_ptr must open write access and restore the original protection"
    );
}

/// QBDI helper 隐藏失败必须让加载失败，不能继续发布 HELPER_API。
#[test]
fn qbdi_load_fails_when_hide_fails() {
    let src = read("quickjs-hook/src/jsapi/hook_api/qbdi/helper.rs");
    assert!(
        src.contains("fn verify_qbdi_helper_hide_result(handle: *mut c_void) -> Result<(), String>"),
        "verify must return Result so failures can abort the load"
    );
    assert!(
        !code_lower("quickjs-hook/src/jsapi/hook_api/qbdi/helper.rs")
            .contains("verify_qbdi_helper_hide_result(handle);"),
        "call site must propagate the error with ?"
    );
    assert!(
        src.contains("CHAIN_HIDDEN"),
        "must require both chains to report hidden, not just status"
    );
}
