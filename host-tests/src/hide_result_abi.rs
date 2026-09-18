//! HideResult C/Rust ABI 合同。
//!
//! 版本化阶段结果必须由 C 与 Rust 共用同一布局；任一侧漏字段或改 offset
//! 都会让 host 把“加载成功但隐藏失败”误读成旧的 status 整数。
//! 本测试直接解析源码结构体，避免只测 host-tests 自己的副本。

use std::collections::HashMap;
use std::path::PathBuf;

const C_STRUCT: &str = "hide_result";
const RUST_STRUCT: &str = "HideResult";

/// 设计约定的版本化 ABI。offset 含显式 pad，保证 u64 自然对齐。
const REQUIRED_FIELDS: &[(&str, usize)] = &[
    ("version", 0),
    ("stage", 4),
    ("status", 8),
    ("next_offset", 12),
    ("entries_scanned", 16),
    ("sym_matched", 20),
    ("soinfo_state", 24),
    ("link_map_state", 28),
    ("wrote", 32),
    ("head_ptr", 40),
    ("target_ptr", 48),
    ("error", 56),
    ("target_path", 184),
    ("head_path", 312),
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn parse_c_fields(src: &str, struct_name: &str) -> HashMap<String, usize> {
    let marker = format!("struct {struct_name} {{");
    let start = src
        .find(&marker)
        .unwrap_or_else(|| panic!("missing C struct {struct_name}"));
    let body = &src[start + marker.len()..];
    let end = body.find('}').unwrap_or_else(|| panic!("unclosed C struct {struct_name}"));
    parse_c_members(&body[..end])
}

fn strip_c_comments(line: &str) -> String {
    let without_line = line.split("//").next().unwrap();
    let mut out = String::new();
    let mut rest = without_line;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        match rest[start + 2..].find("*/") {
            Some(end) => rest = &rest[start + 2 + end + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

fn parse_c_members(body: &str) -> HashMap<String, usize> {
    let mut fields = HashMap::new();
    let mut offset = 0usize;
    for raw in body.lines() {
        let line = strip_c_comments(raw);
        let line = line.trim().trim_end_matches(';').trim();
        if line.is_empty() {
            continue;
        }
        let (name, size, align) = c_member_layout(line);
        offset = align_up(offset, align);
        if !name.starts_with('_') {
            fields.insert(name, offset);
        }
        offset += size;
    }
    fields
}

fn c_member_layout(line: &str) -> (String, usize, usize) {
    if let Some(rest) = line.strip_prefix("char ") {
        let (name, len) = parse_array(rest);
        return (name, len, 1);
    }
    if let Some(rest) = line.strip_prefix("uint64_t ") {
        return (rest.trim().to_string(), 8, 8);
    }
    if let Some(rest) = line.strip_prefix("int64_t ") {
        return (rest.trim().to_string(), 8, 8);
    }
    if let Some(rest) = line.strip_prefix("uint32_t ") {
        return (rest.trim().to_string(), 4, 4);
    }
    if let Some(rest) = line.strip_prefix("int32_t ") {
        let name = rest.trim();
        if name.starts_with('_') {
            return (name.to_string(), 4, 4);
        }
        return (name.to_string(), 4, 4);
    }
    if let Some(rest) = line.strip_prefix("int ") {
        let rest = rest.trim();
        if rest.contains('[') {
            let (name, len) = parse_array(rest);
            return (name, len * 4, 4);
        }
        return (rest.to_string(), 4, 4);
    }
    panic!("unsupported C member: {line}");
}

fn parse_rust_fields(src: &str, struct_name: &str) -> HashMap<String, usize> {
    let marker = format!("struct {struct_name} {{");
    let start = src
        .find(&marker)
        .unwrap_or_else(|| panic!("missing Rust struct {struct_name}"));
    let body = &src[start + marker.len()..];
    let end = body.find('}').unwrap_or_else(|| panic!("unclosed Rust struct {struct_name}"));
    let mut fields = HashMap::new();
    let mut offset = 0usize;
    for raw in body[..end].lines() {
        let line = raw.split("//").next().unwrap().trim().trim_end_matches(',').trim();
        if line.is_empty() {
            continue;
        }
        let (name, ty) = line.split_once(':').unwrap_or_else(|| panic!("bad Rust field: {line}"));
        let name = name.trim();
        let (size, align) = rust_type_layout(ty.trim());
        offset = align_up(offset, align);
        if !name.starts_with('_') {
            fields.insert(name.to_string(), offset);
        }
        offset += size;
    }
    fields
}

fn rust_type_layout(ty: &str) -> (usize, usize) {
    match ty {
        "i32" | "u32" => (4, 4),
        "i64" | "u64" => (8, 8),
        "[u8; 128]" => (128, 1),
        other if other.starts_with('_') => (4, 4),
        other => panic!("unsupported Rust field type: {other}"),
    }
}

fn parse_array(rest: &str) -> (String, usize) {
    let name_end = rest.find('[').unwrap_or_else(|| panic!("expected array: {rest}"));
    let len_end = rest.find(']').unwrap_or_else(|| panic!("unclosed array: {rest}"));
    let name = rest[..name_end].trim().to_string();
    let len: usize = rest[name_end + 1..len_end].trim().parse().expect("array length");
    (name, len)
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) / align * align
}

fn assert_contract(fields: &HashMap<String, usize>, origin: &str) {
    for (name, offset) in REQUIRED_FIELDS {
        let got = fields
            .get(*name)
            .unwrap_or_else(|| panic!("{origin} missing field `{name}` (ABI drift)"));
        assert_eq!(
            got, offset,
            "{origin} field `{name}` offset {got} != expected {offset}"
        );
    }
}

#[test]
fn c_hide_result_matches_versioned_abi() {
    let path = workspace_root().join("agent/src/hide_soinfo.h");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let fields = parse_c_fields(&src, C_STRUCT);
    assert_contract(&fields, "hide_soinfo.c");
}

#[test]
fn rust_injection_hide_result_matches_versioned_abi() {
    let path = workspace_root().join("rust_frida/src/injection.rs");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let fields = parse_rust_fields(&src, RUST_STRUCT);
    assert_contract(&fields, "injection.rs");
}

#[test]
fn qbdi_helper_hide_result_matches_versioned_abi() {
    let path = workspace_root().join("quickjs-hook/src/jsapi/hook_api/qbdi.rs");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let fields = parse_rust_fields(&src, RUST_STRUCT);
    assert_contract(&fields, "qbdi.rs");
}

#[test]
fn c_and_rust_hide_result_offsets_match() {
    let c_src = std::fs::read_to_string(workspace_root().join("agent/src/hide_soinfo.h")).unwrap();
    let rust_src = std::fs::read_to_string(workspace_root().join("rust_frida/src/injection.rs")).unwrap();
    let c_fields = parse_c_fields(&c_src, C_STRUCT);
    let rust_fields = parse_rust_fields(&rust_src, RUST_STRUCT);
    for (name, offset) in REQUIRED_FIELDS {
        let c_off = c_fields.get(*name).copied();
        let rust_off = rust_fields.get(*name).copied();
        assert_eq!(c_off, Some(*offset), "C missing or drifted `{name}`");
        assert_eq!(rust_off, Some(*offset), "Rust missing or drifted `{name}`");
        assert_eq!(c_off, rust_off, "C/Rust offset mismatch for `{name}`");
    }
}
