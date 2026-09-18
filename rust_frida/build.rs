use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let empty_so = manifest.join("../loader/build/empty.so");
    println!("cargo:rerun-if-changed=../loader/build/empty.so");
    println!("cargo:rerun-if-changed=../loader/empty_so.c");
    println!("cargo:rerun-if-changed=../loader/build_empty_so.py");

    if !empty_so.exists() {
        let ndk = std::env::var("NDK_PATH")
            .or_else(|_| std::env::var("ANDROID_NDK_HOME"))
            .expect("NDK_PATH or ANDROID_NDK_HOME required to build empty.so");
        let status = Command::new("python3")
            .arg(manifest.join("../loader/build_empty_so.py"))
            .arg("--ndk")
            .arg(&ndk)
            .status()
            .expect("spawn build_empty_so.py");
        if !status.success() {
            panic!("loader/build_empty_so.py failed");
        }
    }

    let data = std::fs::read(&empty_so).unwrap_or_else(|e| panic!("read {}: {e}", empty_so.display()));
    if data.len() < 20 || data[..4] != *b"\x7fELF" {
        panic!("{} is not ELF", empty_so.display());
    }
    if data[4] != 2 {
        panic!("{} is not ELF64", empty_so.display());
    }
    let e_type = u16::from_le_bytes([data[16], data[17]]);
    let e_machine = u16::from_le_bytes([data[18], data[19]]);
    if e_machine != 183 || e_type != 3 {
        panic!(
            "{} is not AArch64 ET_DYN (machine={e_machine} type={e_type})",
            empty_so.display()
        );
    }
}
