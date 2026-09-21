// 交叉编译到 aarch64 Android 时的 compiler-rt 链接补充。
//
// 本文件由 agent/build.rs 与 qbdi-helper/build.rs 用 include! 引入，
// 因此只能用普通注释，不能用内层文档注释。
//
// `__builtin___clear_cache` 在 aarch64 展开成编译器运行库符号 `__clear_cache`，
// 而 bionic 不导出它。不显式链接 compiler-rt builtins 时，cdylib 会带着未定义符号
// 链接成功，直到设备上 dlopen 才报 `cannot locate symbol "__clear_cache"`。

use std::path::{Path, PathBuf};

/// bionic 不提供、必须静态链入的编译器运行库归档名。
const COMPILER_RT_BUILTINS: &str = "clang_rt.builtins-aarch64";

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

/// 在 NDK 中定位 compiler-rt builtins 归档。
///
/// 目录布局随 NDK 版本变化：NDK 27 的 `lib/clang/<ver>/lib/` 下同时有 `baremetal/`
/// 与 `linux/`，NDK 28+ 只有 `linux/`。因此按文件名搜索，不拼固定路径。
fn find_builtins(ndk: &Path) -> Option<PathBuf> {
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
    for sub in ["linux", "baremetal"] {
        let candidate = ver_dir.join("lib").join(sub).join(format!("lib{COMPILER_RT_BUILTINS}.a"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// 为当前 cdylib 补上 compiler-rt builtins；只在 aarch64 Android 目标下生效。
///
/// 找不到归档时必须直接失败：静默跳过会让缺陷推迟到设备 dlopen 才暴露。
pub fn link_compiler_rt_builtins() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os != "android" || target_arch != "aarch64" {
        return;
    }

    let ndk = ndk_root().expect(
        "ANDROID_NDK_HOME / ANDROID_NDK_ROOT / NDK_PATH must point at an NDK for aarch64 android",
    );
    let builtins = find_builtins(&ndk).unwrap_or_else(|| {
        panic!(
            "lib{COMPILER_RT_BUILTINS}.a not found under {}; \
             __clear_cache would stay undefined and only fail at dlopen time",
            ndk.display()
        )
    });
    println!(
        "cargo:rustc-link-search=native={}",
        builtins.parent().expect("builtins archive has no parent").display()
    );
    println!("cargo:rustc-link-lib=static={COMPILER_RT_BUILTINS}");
    println!("cargo:rerun-if-changed={}", builtins.display());
}
