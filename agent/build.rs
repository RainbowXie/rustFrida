fn main() -> anyhow::Result<()> {
    cc::Build::new().file("src/transform.c").compile("my_c_lib");

    // 拆文件后仍用 -u get_hide_result 把隐藏事务整组拉进 cdylib。
    cc::Build::new()
        .include("src")
        .file("src/hide_soinfo.c")
        .file("src/hide_linker.c")
        .file("src/hide_txn.c")
        .compile("hide_soinfo");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,get_hide_result,-u,hide_from_solist,-u,rust_hide_from_solist,--export-dynamic-symbol=get_hide_result,--export-dynamic-symbol=hide_from_solist,--export-dynamic-symbol=rust_hide_from_solist");
    println!("cargo:rerun-if-changed=src/hide_soinfo.c");
    println!("cargo:rerun-if-changed=src/hide_soinfo.h");
    println!("cargo:rerun-if-changed=src/hide_linker.c");
    println!("cargo:rerun-if-changed=src/hide_txn.c");
    Ok(())
}
