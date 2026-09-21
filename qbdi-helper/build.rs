include!("../build-support/compiler_rt.rs");

fn main() {
    cc::Build::new()
        .include("../agent/src")
        .file("../agent/src/hide_soinfo.c")
        .file("../agent/src/hide_linker.c")
        .file("../agent/src/hide_txn.c")
        .compile("hide_soinfo");

    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir
        .parent()
        .expect("qbdi-helper must live under the workspace root");
    let qbdi_archive = workspace_root.join("qbdi/libQBDI.a");

    println!("cargo:rustc-cdylib-link-arg={}", qbdi_archive.display());
    println!("cargo:rustc-link-lib=log");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os == "android" && target_arch == "aarch64" {
        // 不设默认 NDK：写死路径会在他人机器上静默解析到不存在的目录。
        let ndk_path = std::env::var("NDK_PATH")
            .or_else(|_| std::env::var("ANDROID_NDK_HOME"))
            .expect("NDK_PATH or ANDROID_NDK_HOME required to link libc++ for aarch64 android");
        let cxx_lib_dir = std::path::PathBuf::from(&ndk_path)
            .join("toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android");
        let cxx_static = cxx_lib_dir.join("libc++_static.a");
        let cxxabi = cxx_lib_dir.join("libc++abi.a");

        println!("cargo:rustc-cdylib-link-arg={}", cxx_static.display());
        println!("cargo:rustc-cdylib-link-arg={}", cxxabi.display());
        println!("cargo:rustc-link-lib=dylib=c");
        println!("cargo:rustc-link-lib=dylib=dl");
        println!("cargo:rustc-link-lib=dylib=m");
    } else {
        println!("cargo:rustc-link-lib=c++");
    }

    link_compiler_rt_builtins();

    // 与 agent 一致：cdylib 只导出 Rust 侧 rust_* 包装，C 同名函数会被 localize。
    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,-u,get_hide_result,-u,rust_get_hide_result,-u,hide_from_solist,-u,rust_hide_from_solist,--export-dynamic-symbol=rust_get_hide_result,--export-dynamic-symbol=rust_hide_from_solist"
    );
    println!("cargo:rerun-if-changed=../agent/src/hide_soinfo.c");
    println!("cargo:rerun-if-changed=../agent/src/hide_soinfo.h");
    println!("cargo:rerun-if-changed=../agent/src/hide_linker.c");
    println!("cargo:rerun-if-changed=../agent/src/hide_txn.c");
    println!("cargo:rerun-if-changed={}", qbdi_archive.display());
    println!("cargo:rerun-if-changed=../build-support/compiler_rt.rs");
}
