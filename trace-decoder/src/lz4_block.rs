//! LZ4 块压缩（LZ4 block format）
//!
//! 用于 trace 数据落盘前的实时压缩（对齐视频方案 #8：Stalker trace + LZ4）。
//! 实现 LZ4 块格式（无外部依赖，host 可单测）：
//!   - 序列 = [token][字面量][偏移(2B)][匹配长度]
//!   - token 高 4 位 = 字面量长度（15 时续 255 字节），低 4 位 = 匹配长度 - 4
//!   - 匹配偏移 16 位小端，回指距离
//!
//! 输出为若干块拼接；解压函数与之对称。压缩率不追求极限（启发式：哈希表 + 前向扫描）。

/// 压缩 `input` 为 LZ4 块序列，追加到 `out`。返回写入字节数。
pub fn compress_into(input: &[u8], out: &mut Vec<u8>) -> usize {
    let start = out.len();
    let n = input.len();
    if n == 0 {
        return 0;
    }

    // 简单哈希表：键 = 3 字节首值，值 = 最近出现位置
    const TABLE_SIZE: usize = 1 << 12;
    let mut table = vec![0usize; TABLE_SIZE];
    let hash = |b: &[u8]| -> usize {
        (((b[0] as usize) << 8) | (b[1] as usize)) & (TABLE_SIZE - 1)
    };

    let mut ip = 0usize; // 当前输入位置
    let mut lit_start = 0usize; // 本序列字面量起点

    // 匹配长度 >= 4 才值得编码（offset 占 2 字节）
    let min_match = 4usize;
    let max_match = 65535 + 4usize; // 延长字节上限

    while ip + min_match <= n {
        let h = hash(&input[ip..]);
        let cand = table[h];
        table[h] = ip;

        let matched = if cand < ip && ip - cand <= 65535 {
            // 从 ip 与 cand 起比较公共前缀
            let mut len = 0usize;
            while ip + len < n && input[cand + len] == input[ip + len] && len < max_match {
                len += 1;
            }
            len
        } else {
            0
        };

        if matched >= min_match && ip + matched <= n {
            // 字面量：lit_start..ip
            let lit_len = ip - lit_start;
            out.push(encode_token(lit_len, matched));
            push_len(out, lit_len);
            out.extend_from_slice(&input[lit_start..ip]);
            out.extend_from_slice(&((ip - cand) as u16).to_le_bytes());
            push_len(out, matched - min_match);

            ip += matched;
            lit_start = ip;
        } else {
            ip += 1;
        }
    }

    // 尾部字面量
    let lit_len = n - lit_start;
    out.push(encode_token(lit_len, 0));
    push_len(out, lit_len);
    out.extend_from_slice(&input[lit_start..]);

    out.len() - start
}

fn encode_token(lit_len: usize, match_len: usize) -> u8 {
    let lit = lit_len.min(15) as u8;
    /* 匹配长度字段 = match_len - 4；无匹配（0）时编码 0 */
    let m = if match_len >= 4 {
        (match_len - 4).min(15) as u8
    } else {
        0
    };
    (lit << 4) | m
}

fn push_len(out: &mut Vec<u8>, mut len: usize) {
    if len >= 15 {
        len -= 15;
        while len >= 255 {
            out.push(255);
            len -= 255;
        }
        out.push(len as u8);
    }
}

/// 解压 LZ4 块序列（与 compress_into 对称），返回解压字节数或 Err。
pub fn decompress(input: &[u8], expected_len: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(expected_len);
    let mut ip = 0usize;
    let n = input.len();

    while ip < n {
        let token = input[ip];
        ip += 1;

        // 字面量长度
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if ip >= n {
                    return Err("truncated literal".into());
                }
                let b = input[ip];
                ip += 1;
                lit_len += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        if ip + lit_len > n {
            return Err("literal overrun".into());
        }
        out.extend_from_slice(&input[ip..ip + lit_len]);
        ip += lit_len;

        if ip >= n {
            break; // 最后一块无匹配
        }
        if ip + 2 > n {
            return Err("truncated offset".into());
        }
        let offset = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
        ip += 2;
        if offset == 0 || offset > out.len() {
            return Err(format!("bad offset {}", offset));
        }

        let mut match_len = (token & 0xF) as usize + 4;
        if (token & 0xF) == 15 {
            loop {
                if ip >= n {
                    return Err("truncated match".into());
                }
                let b = input[ip];
                ip += 1;
                match_len += b as usize;
                if b != 255 {
                    break;
                }
            }
        }

        // 复制匹配（可能重叠，逐字节）
        for _ in 0..match_len {
            let idx = out.len() - offset;
            let b = out[idx];
            out.push(b);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8]) {
        let mut enc = Vec::new();
        compress_into(data, &mut enc);
        let dec = decompress(&enc, data.len()).unwrap();
        assert_eq!(dec, data, "roundtrip mismatch for {} bytes", data.len());
    }

    #[test]
    fn empty_input() {
        roundtrip(b"");
    }

    #[test]
    fn incompressible_data() {
        // 伪随机：无重复，压缩率 ~1.0
        let mut d = Vec::new();
        for i in 0..4096u32 {
            d.push(((i.wrapping_mul(2654435761u32)) >> 24) as u8);
        }
        roundtrip(&d);
    }

    #[test]
    fn repetitive_data_compresses() {
        let d = b"AAAAABBBBBCCCCCDDDDD".repeat(128);
        let mut enc = Vec::new();
        let sz = compress_into(&d, &mut enc);
        assert!(sz < d.len() / 4, "expected compression, got {} vs {}", sz, d.len());
        roundtrip(&d);
    }

    #[test]
    fn trace_like_mixed() {
        // 模拟 trace 数据：指令地址 + 重复前缀
        let mut d = Vec::new();
        for i in 0..2000 {
            d.extend_from_slice(&(0x78aabbcc0000u64 + i * 4).to_le_bytes());
            d.push((i & 0xFF) as u8);
        }
        roundtrip(&d);
    }

    #[test]
    fn offset_overlap_case() {
        // 匹配与字面量重叠（如 "abcabcabc"）
        roundtrip(b"abcabcabcabcabcabcabcabc");
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn throughput_meets_trace_average() {
        // 性能验收（仅 release 模式；debug 无优化，速率无意义）：
        // 压缩速率须远超视频 trace 平均速率（2936 万指令/7.45s
        // = 394 万 insns/s ≈ 31.5 MB/s 原始地址流）。断言 >100 MB/s（~3x 余量）。
        let mut batch = Vec::with_capacity(4096 * 8);
        let base: u64 = 0x78aabbcc0000;
        for i in 0..4096u64 {
            batch.extend_from_slice(&(base + i * 4).to_le_bytes());
        }
        let total = 16 * 1024 * 1024usize; // 16MB
        let mut out = Vec::new();
        let t0 = std::time::Instant::now();
        let mut written = 0usize;
        while written < total {
            out.clear();
            compress_into(&batch, &mut out);
            written += batch.len();
        }
        let el = t0.elapsed();
        let mbps = (written as f64 / 1048576.0) / el.as_secs_f64();
        assert!(mbps > 100.0, "compress too slow: {:.0} MB/s (need >100)", mbps);
    }
}
