// 交叉编译到 aarch64 Android 时的 compiler-rt 链接补充。
//
// 本文件由 agent/build.rs 与 qbdi-helper/build.rs 用 include! 引入，
// 因此只能用普通注释，不能用内层文档注释。
//
// `__builtin___clear_cache` 在 aarch64 展开成编译器运行库符号 `__clear_cache`，
// 而 bionic 不导出它。不显式链接 compiler-rt builtins 时，cdylib 会带着未定义符号
// 链接成功，直到设备上 dlopen 才报 `cannot locate symbol "__clear_cache"`。

use std::path::{Path, PathBuf};

fn ndk_root() -> Option<PathBuf> {
    for key in ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_PATH"] {
        if let Ok(v) = std::env::var(key) {
            if Path::new(&v).join("source.properties").is_file() {
                return Some(PathBuf::from(v));
            }
        }
    }
    None
}

/// 在 NDK 中定位 compiler-rt builtins 归档及对应静态库名称。
///
/// 目录布局与库名随 NDK 版本变化：
/// - NDK 28/29: 位于 `lib/linux/`，名为 `libclang_rt.builtins-aarch64-android.a`
/// - NDK 27: 同时包含 `lib/linux/libclang_rt.builtins-aarch64-android.a` 与
///   `lib/baremetal/libclang_rt.builtins-aarch64.a`
/// 优先选择 Android 平台专用的 -android 归档；按文件名匹配避免硬编码。
fn find_builtins(ndk: &Path) -> Option<(PathBuf, String)> {
    let clang_lib = ndk.join("toolchains/llvm/prebuilt/linux-x86_64/lib/clang");
    let mut versions: Vec<PathBuf> = std::fs::read_dir(&clang_lib)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    // 多个 clang 版本时取编号最大的，与工具链默认版本一致。
    versions.sort_by_key(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.parse::<u32>().ok())
            .unwrap_or(0)
    });
    let ver_dir = versions.pop()?;
    let candidates = [
        ("linux", "clang_rt.builtins-aarch64-android"),
        ("baremetal", "clang_rt.builtins-aarch64"),
    ];
    for (sub, lib_name) in candidates {
        let candidate = ver_dir.join("lib").join(sub).join(format!("lib{lib_name}.a"));
        if candidate.is_file() {
            return Some((candidate, lib_name.to_string()));
        }
    }
    None
}

/// 为当前 cdylib 补上 compiler-rt builtins；只在 aarch64 Android 目标下生效。
///
/// 找不到归档时必须直接失败：静默跳过会让缺陷推迟到设备 dlopen 才暴露。
pub fn link_compiler_rt_builtins() {
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_ROOT");
    println!("cargo:rerun-if-env-changed=NDK_PATH");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os != "android" || target_arch != "aarch64" {
        return;
    }

    let ndk = ndk_root().expect(
        "ANDROID_NDK_HOME / ANDROID_NDK_ROOT / NDK_PATH must point at an NDK for aarch64 android",
    );
    let (builtins_path, lib_name) = find_builtins(&ndk).unwrap_or_else(|| {
        panic!(
            "compiler-rt builtins archive not found under {}; \
             __clear_cache would stay undefined and only fail at dlopen time",
            ndk.display()
        )
    });
    println!(
        "cargo:rustc-link-search=native={}",
        builtins_path.parent().expect("builtins archive has no parent").display()
    );
    println!("cargo:rustc-link-lib=static={lib_name}");
    println!("cargo:rerun-if-changed={}", builtins_path.display());
}
