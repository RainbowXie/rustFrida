//! `soinfo::next` 推导。Android 16 在空链表快路径上先 RET，真实
//! `old_tail->next = si` 写在第一条 RET 之后；停在 RET 会把 0x28 误判为失败。

const MAX_OFFSET: i32 = 0x400;

/// Android 14 mido `solist_add_soinfo`：经典 ADRP/LDR/STR/STR/RET，next=0x28。
/// Android 15 AOSP 同一函数仍是该五指令形态；无 API 35 真机时用此序列作为 7-15 基线。
const ANDROID15_CLASSIC: &[u8] = &[
    0x88, 0x02, 0x00, 0xd0, // ADRP x8
    0x09, 0x8d, 0x44, 0xf9, // LDR x9, [x8, #0x918]
    0x00, 0x8d, 0x04, 0xf9, // STR x0, [x8, #0x918]  sonext = si
    0x20, 0x15, 0x00, 0xf9, // STR x0, [x9, #0x28]   tail->next = si
    0xc0, 0x03, 0x5f, 0xd6, // RET
];

/// Pixel 6 Android 16 `solist_add_soinfo`：空链表分支在第一条 RET 结束，
/// 非空路径的 `STR x0, [x9, #0x28]` 位于 RET 之后。
const ANDROID16_PIXEL6: &[u8] = &[
    0xc8, 0x0a, 0x00, 0x90, // ADRP x8
    0x09, 0xf1, 0x40, 0xf9, // LDR x9, [x8, #0x1e0]
    0xa9, 0x00, 0x00, 0xb5, // CBNZ x9, non_empty
    0xc9, 0x0a, 0x00, 0x90, // ADRP x9
    0x20, 0xf5, 0x00, 0xf9, // STR x0, [x9, #0x1e8]  空链表辅助写，不是 next
    0x00, 0xf1, 0x00, 0xf9, // STR x0, [x8, #0x1e0]
    0xc0, 0x03, 0x5f, 0xd6, // RET
    0x20, 0x15, 0x00, 0xf9, // STR x0, [x9, #0x28]   tail->next = si
    0x00, 0xf1, 0x00, 0xf9, // STR x0, [x8, #0x1e0]
    0xc0, 0x03, 0x5f, 0xd6, // RET
];

const UNKNOWN_NOPS: &[u8] = &[
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5,
];

/// 过大 next：STR x0, [x1, #0x408]，应在校验阶段拒绝而不是写入链表。
const HUGE_STR: &[u8] = &[
    0x02, 0x00, 0x00, 0x90, // ADRP x2  (page_reg=2)
    0x20, 0x04, 0x02, 0xf9, // STR x0, [x1, #0x408]
    0xc0, 0x03, 0x5f, 0xd6,
];

/// 目标算法：越过空链表快路径上的 RET，取最后一次 STR X0,[Rn≠page_reg]。
pub fn derive_next_offset(code: &[u8]) -> i32 {
    let insns = code.chunks_exact(4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let mut page_reg = -1i32;
    let mut next_offset = -1i32;
    for insn in insns {
        if (insn & 0x9F00_0000) == 0x9000_0000 && page_reg < 0 {
            page_reg = (insn & 0x1F) as i32;
            continue;
        }
        if (insn & 0xFFC0_0000) == 0xF900_0000 {
            let rt = (insn & 0x1F) as i32;
            let rn = ((insn >> 5) & 0x1F) as i32;
            if rt == 0 && rn != page_reg {
                let imm12 = ((insn >> 10) & 0xFFF) as i32;
                next_offset = imm12 * 8;
            }
        }
    }
    next_offset
}

pub fn validate_next_offset(offset: i32) -> Result<i32, i32> {
    if offset < 0 || offset > MAX_OFFSET {
        Err(offset)
    } else {
        Ok(offset)
    }
}

#[test]
fn android15_classic_derives_next_0x28() {
    assert_eq!(derive_next_offset(ANDROID15_CLASSIC), 0x28);
    assert_eq!(validate_next_offset(0x28), Ok(0x28));
}

#[test]
fn android16_pixel6_derives_next_0x28() {
    assert_eq!(derive_next_offset(ANDROID16_PIXEL6), 0x28);
}

#[test]
fn unknown_instruction_pattern_is_rejected() {
    assert_eq!(derive_next_offset(UNKNOWN_NOPS), -1);
    assert!(validate_next_offset(-1).is_err());
}

#[test]
fn huge_next_offset_is_rejected() {
    let derived = derive_next_offset(HUGE_STR);
    assert!(derived > MAX_OFFSET, "fixture must produce an out-of-range offset, got {derived}");
    assert!(validate_next_offset(derived).is_err());
}

#[test]
fn production_c_must_not_stop_at_first_ret() {
    let src = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../agent/src/hide_linker.c"),
    )
    .unwrap();
    let fn_src = src
        .split("int derive_next_offset")
        .nth(1)
        .expect("derive_next_offset missing");
    let fn_src = fn_src.split("uint64_t map_start_containing").next().unwrap();
    // 第一条 RET 只结束空链表快路径；break 会丢掉 Android 16 的 next 存储。
    assert!(
        !fn_src.contains("if (insn == 0xd65f03c0)") && !fn_src.contains("if (insn == 0xD65F03C0)"),
        "derive_next_offset still stops at the first RET"
    );
}
