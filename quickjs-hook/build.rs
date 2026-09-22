use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let src_path = PathBuf::from(&manifest_dir).join("src");

    // Compile hook_engine.c, arm64_writer.c, and arm64_relocator.c
    cc::Build::new()
        .file(src_path.join("hook_engine.c"))
        .file(src_path.join("hook_engine_mem.c"))
        .file(src_path.join("hook_engine_inline.c"))
        .file(src_path.join("hook_engine_redir.c"))
        .file(src_path.join("hook_engine_art.c"))
        .file(src_path.join("arm64_writer.c"))
        .file(src_path.join("arm64_relocator.c"))
        .include(&src_path)
        .opt_level(2)
        .flag("-fPIC")
        .flag("-fno-exceptions")
        .warnings(false)
        .compile("hook_engine");

    // Compile QuickJS sources
    let quickjs_src = PathBuf::from(&manifest_dir).join("quickjs-src");
    let quickjs_c = quickjs_src.join("quickjs.c");
    let quickjs_h = quickjs_src.join("quickjs.h");
    if quickjs_c.exists() && quickjs_h.exists() {
        let quickjs_version = std::fs::read_to_string(quickjs_src.join("VERSION"))
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_owned());
        let has_libbf = quickjs_src.join("libbf.c").exists();

        let mut build = cc::Build::new();
        build
            .file(&quickjs_c)
            .file(quickjs_src.join("dtoa.c"))
            .file(quickjs_src.join("libregexp.c"))
            .file(quickjs_src.join("libunicode.c"))
            .file(quickjs_src.join("cutils.c"))
            .file(src_path.join("quickjs_wrapper.c"))
            .include(&quickjs_src)
            .include(&src_path)
            .opt_level(2)
            .flag("-fPIC")
            .flag("-fno-exceptions")
            .flag(&format!("-DCONFIG_VERSION=\"{}\"", quickjs_version))
            .flag("-D_GNU_SOURCE")
            .flag_if_supported("-Wno-implicit-const-int-float-conversion")
            .warnings(false);

        if has_libbf {
            build.file(quickjs_src.join("libbf.c"));
            build.flag("-DCONFIG_BIGNUM");
        }

        // Android-specific flags
        let target = env::var("TARGET").unwrap_or_default();
        let is_android = target.contains("android");
        if is_android {
            build.flag("-DANDROID");
        }

        build.compile("quickjs");

        // 解析 Android 交叉编译所需 sysroot，防止 bindgen 读取宿主机 /usr/include 导致 __GLIBC_USE 报错。
        let mut android_clang_args = Vec::new();
        if is_android {
            println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
            println!("cargo:rerun-if-env-changed=ANDROID_NDK_ROOT");
            println!("cargo:rerun-if-env-changed=NDK_PATH");
            println!("cargo:rerun-if-env-changed=BINDGEN_EXTRA_CLANG_ARGS");

            if env::var("BINDGEN_EXTRA_CLANG_ARGS").is_err() {
                let ndk_opt = env::var("ANDROID_NDK_HOME")
                    .or_else(|_| env::var("ANDROID_NDK_ROOT"))
                    .or_else(|_| env::var("NDK_PATH"))
                    .ok()
                    .filter(|p| Path::new(p).join("source.properties").is_file())
                    .or_else(|| {
                        let path_var = env::var("PATH").unwrap_or_default();
                        for dir in env::split_paths(&path_var) {
                            if dir.join("aarch64-linux-android33-clang").is_file()
                                || dir.join("aarch64-linux-android-clang").is_file()
                            {
                                let toolchain_prebuilt = dir.parent()?;
                                let toolchains = toolchain_prebuilt.parent()?;
                                let ndk = toolchains.parent()?;
                                if ndk.join("source.properties").is_file() {
                                    return Some(ndk.to_string_lossy().to_string());
                                }
                            }
                        }
                        None
                    });

                if let Some(ndk_str) = ndk_opt {
                    let sysroot = PathBuf::from(ndk_str)
                        .join("toolchains/llvm/prebuilt/linux-x86_64/sysroot");
                    if sysroot.is_dir() {
                        android_clang_args.push("--target=aarch64-linux-android33".to_string());
                        android_clang_args.push(format!("--sysroot={}", sysroot.display()));
                    }
                }
            }
        }

        // Generate bindings for QuickJS + wrapper
        let mut bindings_builder = bindgen::Builder::default()
            .header(quickjs_src.join("quickjs.h").to_string_lossy().to_string())
            .header(src_path.join("quickjs_wrapper.h").to_string_lossy().to_string())
            .clang_arg(format!("-I{}", quickjs_src.display()))
            .clang_arg(format!("-I{}", src_path.display()))
            .clang_arg("-xc")
            .generate_comments(true)
            .derive_debug(true)
            .derive_default(true)
            .layout_tests(false)
            .allowlist_function("JS_.*")
            .allowlist_function("js_.*")
            .allowlist_function("__JS_.*")
            .allowlist_function("qjs_.*")
            .allowlist_type("JS.*")
            .allowlist_var("JS_.*")
            .use_core();

        for arg in &android_clang_args {
            bindings_builder = bindings_builder.clang_arg(arg);
        }

        let bindings = bindings_builder
            .generate()
            .expect("Unable to generate QuickJS bindings");

        bindings
            .write_to_file(out_path.join("quickjs_bindings.rs"))
            .expect("Couldn't write QuickJS bindings!");

        println!("cargo:rustc-link-lib=static=quickjs");
    } else {
        // QuickJS source not found - generate empty bindings
        std::fs::write(
            out_path.join("quickjs_bindings.rs"),
            "// QuickJS source not found - run setup script to download\n",
        )
        .expect("Failed to write placeholder bindings");

        println!("cargo:warning=QuickJS source not initialized at {:?}", quickjs_src);
        println!("cargo:warning=Run: git submodule update --init --recursive quickjs-hook/quickjs-src");
        println!("cargo:warning=Or run: cd quickjs-hook && ./setup_quickjs.sh");
    }

    // Generate bindings for hook_engine (includes arm64_writer and arm64_relocator)
    let target = env::var("TARGET").unwrap_or_default();
    let is_android = target.contains("android");
    let mut hook_android_args = Vec::new();
    if is_android && env::var("BINDGEN_EXTRA_CLANG_ARGS").is_err() {
        let ndk_opt = env::var("ANDROID_NDK_HOME")
            .or_else(|_| env::var("ANDROID_NDK_ROOT"))
            .or_else(|_| env::var("NDK_PATH"))
            .ok()
            .filter(|p| Path::new(p).join("source.properties").is_file())
            .or_else(|| {
                let path_var = env::var("PATH").unwrap_or_default();
                for dir in env::split_paths(&path_var) {
                    if dir.join("aarch64-linux-android33-clang").is_file()
                        || dir.join("aarch64-linux-android-clang").is_file()
                    {
                        let toolchain_prebuilt = dir.parent()?;
                        let toolchains = toolchain_prebuilt.parent()?;
                        let ndk = toolchains.parent()?;
                        if ndk.join("source.properties").is_file() {
                            return Some(ndk.to_string_lossy().to_string());
                        }
                    }
                }
                None
            });

        if let Some(ndk_str) = ndk_opt {
            let sysroot = PathBuf::from(ndk_str)
                .join("toolchains/llvm/prebuilt/linux-x86_64/sysroot");
            if sysroot.is_dir() {
                hook_android_args.push("--target=aarch64-linux-android33".to_string());
                hook_android_args.push(format!("--sysroot={}", sysroot.display()));
            }
        }
    }

    let mut hook_builder = bindgen::Builder::default()
        .header(src_path.join("hook_engine.h").to_string_lossy().to_string())
        .header(src_path.join("arm64_writer.h").to_string_lossy().to_string())
        .header(src_path.join("arm64_relocator.h").to_string_lossy().to_string())
        .clang_arg(format!("-I{}", src_path.display()))
        .clang_arg("-xc")
        .generate_comments(true)
        .derive_debug(true)
        .derive_default(true)
        .layout_tests(false)
        .allowlist_function("hook_.*")
        .allowlist_function("arm64_writer_.*")
        .allowlist_function("arm64_relocator_.*")
        .allowlist_type("Hook.*")
        .allowlist_type("Arm64.*")
        .allowlist_var("ARM64_.*")
        .use_core();

    for arg in &hook_android_args {
        hook_builder = hook_builder.clang_arg(arg);
    }

    let hook_bindings = hook_builder
        .generate()
        .expect("Unable to generate hook_engine bindings");

    hook_bindings
        .write_to_file(out_path.join("hook_bindings.rs"))
        .expect("Couldn't write hook_engine bindings!");

    println!("cargo:rustc-link-lib=static=hook_engine");
    println!("cargo:rerun-if-changed=src/hook_engine.c");
    println!("cargo:rerun-if-changed=src/hook_engine.h");
    println!("cargo:rerun-if-changed=src/hook_engine_internal.h");
    println!("cargo:rerun-if-changed=src/hook_engine_mem.c");
    println!("cargo:rerun-if-changed=src/hook_engine_inline.c");
    println!("cargo:rerun-if-changed=src/hook_engine_redir.c");
    println!("cargo:rerun-if-changed=src/hook_engine_art.c");
    println!("cargo:rerun-if-changed=src/arm64_writer.c");
    println!("cargo:rerun-if-changed=src/arm64_writer.h");
    println!("cargo:rerun-if-changed=src/arm64_relocator.c");
    println!("cargo:rerun-if-changed=src/arm64_relocator.h");
    println!("cargo:rerun-if-changed=quickjs-src/VERSION");
    println!("cargo:rerun-if-changed=quickjs-src/quickjs.c");
    println!("cargo:rerun-if-changed=quickjs-src/quickjs.h");
    println!("cargo:rerun-if-changed=quickjs-src/dtoa.c");
    println!("cargo:rerun-if-changed=quickjs-src/libregexp.c");
    println!("cargo:rerun-if-changed=quickjs-src/libunicode.c");
    println!("cargo:rerun-if-changed=quickjs-src/cutils.c");
    println!("cargo:rerun-if-changed=quickjs-src/libbf.c");
    println!("cargo:rerun-if-changed=src/quickjs_wrapper.c");
    println!("cargo:rerun-if-changed=src/quickjs_wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");
}
