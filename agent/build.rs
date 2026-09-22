//! agent cdylib 的构建脚本。
//!
//! 除编译 C 源外还要固定保留 `hide_soinfo` 整组符号（host 通过 dlsym 查找），
//! 并补上 bionic 不提供的 compiler-rt 符号（见 build-support/compiler_rt.rs）。

include!("../build-support/compiler_rt.rs");

fn main() -> anyhow::Result<()> {
    cc::Build::new().file("src/transform.c").compile("my_c_lib");

    cc::Build::new()
        .include("src")
        .file("src/hide_soinfo.c")
        .file("src/hide_linker.c")
        .file("src/hide_txn.c")
        .compile("hide_soinfo");

    // cdylib 只导出 Rust 侧 rust_* 包装，C 同名函数会被 localize。
    // -u 防止隐藏事务与故障注入入口被 gc-sections 丢掉；host 侧只按 rust_* 查找。
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,get_hide_result,-u,hide_from_solist,-u,set_hide_fault_stage,-u,rust_hide_from_solist,-u,rust_set_hide_fault_stage,--export-dynamic-symbol=rust_get_hide_result,--export-dynamic-symbol=rust_hide_from_solist,--export-dynamic-symbol=rust_set_hide_fault_stage");

    link_compiler_rt_builtins();

    println!("cargo:rerun-if-changed=src/transform.c");
    println!("cargo:rerun-if-changed=src/hide_soinfo.c");
    println!("cargo:rerun-if-changed=src/hide_soinfo.h");
    println!("cargo:rerun-if-changed=src/hide_linker.c");
    println!("cargo:rerun-if-changed=src/hide_txn.c");
    println!("cargo:rerun-if-changed=../build-support/compiler_rt.rs");
    Ok(())
}
