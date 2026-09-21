use std::path::PathBuf;
use std::process::Command;

fn workspace_join(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
}

fn ndk_path() -> Option<PathBuf> {
    for key in ["NDK_PATH", "ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"] {
        if let Ok(v) = std::env::var(key) {
            let p = PathBuf::from(v);
            if p.join("source.properties").exists() {
                return Some(p);
            }
        }
    }
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("Android/Sdk/ndk");
    let mut versions: Vec<_> = std::fs::read_dir(home).ok()?.flatten().map(|e| e.path()).collect();
    versions.sort();
    versions.into_iter().rev().find(|p| p.join("source.properties").exists())
}

#[test]
fn empty_so_is_elf64_aarch64_dyn() {
    let ndk = ndk_path().expect("Android NDK required to build empty.so");
    let script = workspace_join("loader/build_empty_so.py");
    let out = workspace_join("loader/build/empty.so");
    let status = Command::new("python3")
        .arg(&script)
        .arg("--ndk")
        .arg(&ndk)
        .arg("--output")
        .arg(&out)
        .status()
        .expect("spawn build_empty_so.py");
    assert!(status.success(), "build_empty_so.py failed");
    let data = std::fs::read(&out).unwrap();
    assert_eq!(&data[..4], b"\x7fELF");
    assert_eq!(data[4], 2, "ELF64");
    let e_type = u16::from_le_bytes([data[16], data[17]]);
    let e_machine = u16::from_le_bytes([data[18], data[19]]);
    assert_eq!(e_machine, 183, "EM_AARCH64");
    assert_eq!(e_type, 3, "ET_DYN");
}

#[test]
fn constructor_must_not_call_solist_remove() {
    let src = std::fs::read_to_string(workspace_join("agent/src/hide_soinfo.c")).unwrap();
    let ctor = src
        .split("static void hide_soinfo_register")
        .nth(1)
        .expect("constructor missing");
    let ctor = ctor.split("int hide_from_solist").next().unwrap();
    assert!(!ctor.contains("solist_remove_soinfo"), "constructor still calls solist_remove_soinfo");
    assert!(!ctor.contains("r_map"), "constructor still writes _r_debug.r_map");
}

#[test]
fn hide_identity_must_not_rely_only_on_handle_pointer() {
    let src = std::fs::read_to_string(workspace_join("agent/src/hide_txn.c")).unwrap();
    assert!(
        src.contains("solist_get_head 实际返回 sonext") || src.contains("sonext 尾指针"),
        "must not treat Android 16 solist_get_head as list head"
    );
    // 身份改用 linker 自己的地址区间反查：同名 memfd 不会再把历史节点算进来。
    assert!(
        src.contains("find_containing_library"),
        "must resolve current library by address via find_containing_library"
    );
    assert!(
        src.contains("&g_identity_marker"),
        "must anchor the address lookup on this library's own marker"
    );
    // 按名字累计匹配正是被修掉的身份冲突来源，不能再出现。
    assert!(
        !src.contains("path_is_self"),
        "must not fall back to name matching, which collides on repeated same-named memfd loads"
    );
}

#[test]
fn hide_from_solist_is_exported_transaction() {
    let src = std::fs::read_to_string(workspace_join("agent/src/hide_soinfo.c")).unwrap();
    assert!(src.contains("int hide_from_solist(void *handle)"));
    assert!(src.contains("hide_prepare") && src.contains("hide_commit"));
    // qbdi.rs 已按职责拆成子模块，改掉实现文件仍只允许有一个。
    for path in [
        "loader/loader.c",
        "rust_frida/src/injection.rs",
        "quickjs-hook/src/jsapi/hook_api/qbdi/helper.rs",
    ] {
        let body = std::fs::read_to_string(workspace_join(path)).unwrap();
        assert!(body.contains("hide_from_solist"), "{path} must share hide_from_solist");
        assert!(
            !body.contains("HIDE_STATUS_OK") && !body.contains("#define HIDE_OK"),
            "{path} must not invent a second status constant set"
        );
    }
}

#[test]
fn loader_hides_after_android_dlopen_ext_returns() {
    let src = std::fs::read_to_string(workspace_join("loader/loader.c")).unwrap();
    let entry = src.split("int shellcode_entry").nth(1).expect("shellcode_entry missing");
    let dlopen_pos = entry.find("handle = android_dlopen_ext").expect("dlopen missing");
    let hide_pos = entry.find("hide_fn(handle)").expect("hide call missing");
    let thread_pos = entry.find("pthread_create(&tid").expect("pthread_create missing");
    assert!(dlopen_pos < hide_pos && hide_pos < thread_pos);
    assert!(src.contains("return -13"), "loader must report hide failure separately from dlopen");
}
