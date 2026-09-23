//! agent cdylib 的构建脚本。
//!
//! 除编译 C 源外还要固定保留 `hide_soinfo` 整组符号（host 通过 dlsym 查找），
//! 并补上 bionic 不提供的 compiler-rt 符号（见 build-support/compiler_rt.rs）。

include!("../build-support/compiler_rt.rs");

fn main() -> anyhow::Result<()> {
    cc::Build::new().file("src/transform.c").compile("my_c_lib");

    // 基础构建不定义 HIDE_FAULT_INJECTION：发布产物不携带故障注入判定与控制串。
    let fault_injection = std::env::var_os("CARGO_FEATURE_FAULT_INJECTION").is_some();
    let mut hide_build = cc::Build::new();
    hide_build.include("src").file("src/hide_soinfo.c").file("src/hide_linker.c").file("src/hide_txn.c");
    if fault_injection {
        hide_build.define("HIDE_FAULT_INJECTION", None);
    }
    hide_build.compile("hide_soinfo");

    // cdylib 只导出 Rust 侧 rust_* 包装，C 同名函数会被 localize。
    // -u 防止隐藏事务被 gc-sections 丢掉；host 侧只按 rust_* 查找。
    // 故障注入入口仅在 fault-injection feature 下保留：发布构建不得导出
    // set_hide_fault_stage/rust_set_hide_fault_stage，否则可被外部调用方
    // 主动令隐藏事务部分写入后回滚。
    let mut link_args = String::from(
        "-Wl,-u,get_hide_result,-u,hide_from_solist,-u,rust_hide_from_solist,--export-dynamic-symbol=rust_get_hide_result,--export-dynamic-symbol=rust_hide_from_solist",
    );
    if fault_injection {
        link_args.push_str(
            ",-u,set_hide_fault_stage,-u,rust_set_hide_fault_stage,--export-dynamic-symbol=rust_set_hide_fault_stage",
        );
    }
    println!("cargo:rustc-cdylib-link-arg={}", link_args);

    link_compiler_rt_builtins();

    println!("cargo:rerun-if-changed=src/transform.c");
    println!("cargo:rerun-if-changed=src/hide_soinfo.c");
    println!("cargo:rerun-if-changed=src/hide_soinfo.h");
    println!("cargo:rerun-if-changed=src/hide_linker.c");
    println!("cargo:rerun-if-changed=src/hide_txn.c");
    println!("cargo:rerun-if-changed=../build-support/compiler_rt.rs");
    Ok(())
}
