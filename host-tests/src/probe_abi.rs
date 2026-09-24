//! ProbeResult C/Rust ABI 合同（v2：身份核对 + 匹配 bias 列表）。
//!
//! 探针按地址身份裁决“本次待验证的 agent”是否仍在双链上（ISSUE-032）：
//! host 填 target_sym（目标库内一个地址），探针用枚举包含关系独立核对出
//! target_bias，并报告两条链上是否仍存在该身份。C/Rust 布局漂移会让 host
//! 把身份字段读错位置，名字合并计数的缺陷会以另一种形式回归，所以这里
//! 直接解析两侧源码结构体，而不是只测 host-tests 自己的副本。

use std::collections::HashMap;
use std::path::PathBuf;

const C_STRUCT: &str = "probe_result";
const RUST_STRUCT: &str = "ProbeResult";

/// v2 身份协议布局。offset 含显式 pad，保证 u64 自然对齐。
/// matched_base 列表让 host 按地址集合差分，而不是把所有同名 memfd 合并计数。
const REQUIRED_FIELDS: &[(&str, usize)] = &[
    ("version", 0),
    ("total", 4),
    ("wwb_matches", 8),
    ("self_skipped", 12),
    ("self_addr", 16),
    ("rmap_total", 24),
    ("rmap_wwb_matches", 28),
    ("matched_name", 32),
    ("target_sym", 288),
    ("target_bias", 296),
    ("target_present_sol", 304),
    ("target_present_rmap", 308),
    ("matched_count", 312),
    ("rmap_matched_count", 316),
    ("matched_base", 320),
    ("rmap_matched_base", 384),
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
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

fn parse_c_fields(src: &str, struct_name: &str) -> HashMap<String, usize> {
    let marker = format!("struct {struct_name} {{");
    let start = src
        .find(&marker)
        .unwrap_or_else(|| panic!("missing C struct {struct_name}"));
    let body = &src[start + marker.len()..];
    let end = body.find('}').unwrap_or_else(|| panic!("unclosed C struct {struct_name}"));
    let mut fields = HashMap::new();
    let mut offset = 0usize;
    for raw in body[..end].lines() {
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
    if let Some(rest) = line.strip_prefix("unsigned long long ") {
        let rest = rest.trim();
        if rest.contains('[') {
            let (name, len) = parse_array(rest);
            return (name, len * 8, 8);
        }
        return (rest.to_string(), 8, 8);
    }
    if let Some(rest) = line.strip_prefix("uint64_t ") {
        return (rest.trim().to_string(), 8, 8);
    }
    if let Some(rest) = line.strip_prefix("int ") {
        return (rest.trim().to_string(), 4, 4);
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
        let name = name.trim().strip_prefix("pub(crate) ").unwrap_or(name.trim()).trim();
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
        "[u8; 256]" => (256, 1),
        "[u64; 8]" => (64, 8),
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
fn c_probe_result_matches_v2_abi() {
    let path = workspace_root().join("loader/probe_so.c");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let fields = parse_c_fields(&src, C_STRUCT);
    assert_contract(&fields, "probe_so.c");
}

#[test]
fn rust_probe_result_matches_v2_abi() {
    let path = workspace_root().join("rust_frida/src/injection/probe.rs");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let fields = parse_rust_fields(&src, RUST_STRUCT);
    assert_contract(&fields, "probe.rs");
}

#[test]
fn c_and_rust_probe_result_offsets_match() {
    let c_src = std::fs::read_to_string(workspace_root().join("loader/probe_so.c")).unwrap();
    let rust_src = std::fs::read_to_string(workspace_root().join("rust_frida/src/injection/probe.rs")).unwrap();
    let c_fields = parse_c_fields(&c_src, C_STRUCT);
    let rust_fields = parse_rust_fields(&rust_src, RUST_STRUCT);
    for (name, offset) in REQUIRED_FIELDS {
        assert_eq!(c_fields.get(*name), Some(offset), "C missing or drifted `{name}`");
        assert_eq!(rust_fields.get(*name), Some(offset), "Rust missing or drifted `{name}`");
    }
}

#[test]
fn probe_version_is_two_on_both_sides() {
    let c_src = std::fs::read_to_string(workspace_root().join("loader/probe_so.c")).unwrap();
    let rust_src = std::fs::read_to_string(workspace_root().join("rust_frida/src/injection/probe.rs")).unwrap();
    assert!(
        c_src.contains("#define PROBE_VERSION 2"),
        "probe_so.c must declare PROBE_VERSION 2 (v2 identity protocol)"
    );
    assert!(
        rust_src.contains("const PROBE_VERSION: i32 = 2"),
        "probe.rs must pin PROBE_VERSION to 2 and verify the probe's self-report"
    );
}

/// 负向测试：布局漂移必须被合同抓住。不会失败的守卫是废纸（本项目实测踩过
/// comm 空转通过的坑），所以 ABI 合同本身要先证明它能红。
#[test]
fn abi_contract_detects_offset_drift() {
    let mut drifted: HashMap<String, usize> = REQUIRED_FIELDS
        .iter()
        .map(|(n, o)| (n.to_string(), *o))
        .collect();
    // 模拟 target_bias 与 target_present_sol 互换位置的典型漂移。
    drifted.insert("target_bias".to_string(), 304);
    drifted.insert("target_present_sol".to_string(), 296);
    let result = std::panic::catch_unwind(|| assert_contract(&drifted, "synthetic"));
    assert!(result.is_err(), "ABI contract failed to detect a swapped identity pair");
}
