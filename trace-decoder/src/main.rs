//! Trace 解码器 —— 读取 rustFrida stalker 落盘的 LZ4 块流。
//!
//! 落盘格式（agent/src/stalker.rs）：
//!   块序列 = { [u32 LE 解压后字节数][u32 LE 压缩后字节数][LZ4 压缩数据] }*
//!   每块解压后是 8 字节小端指令地址的连续序列。
//!
//! 用法：
//!   trace-decoder trace.pb            # 解码，逐行输出 0x 地址
//!   trace-decoder trace.pb --count    # 只输出统计（块数/指令数/地址范围）
//!
//! 供 Chronos 风格 TTD 分析 / AI MCP 的宿主侧解析（方案 #8 分析侧闭环）。

mod lz4_block;

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// LZ4 解压（块格式，与 agent 端 compress_into 对称）
fn lz4_decompress(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut ip = 0usize;
    let n = input.len();

    while ip < n {
        let token = input[ip];
        ip += 1;

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
            break;
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
        for _ in 0..match_len {
            let idx = out.len() - offset;
            let b = out[idx];
            out.push(b);
        }
    }
    Ok(out)
}

/// LZ4 压缩（用于测试与重打包；与 agent 端 compress_into 同构的简化版）
fn lz4_compress_simple(input: &[u8]) -> Vec<u8> {
    // 测试用最小实现：字面量 + 无匹配（token=0xF0, len 延长）
    let mut out = Vec::new();
    let n = input.len();
    let mut lit = 0usize;
    while lit < n {
        let chunk = (n - lit).min(255);
        if chunk <= 15 {
            out.push((chunk as u8) << 4);
        } else {
            out.push(0xF0);
            out.push((chunk - 15) as u8);
        }
        out.extend_from_slice(&input[lit..lit + chunk]);
        lit += chunk;
    }
    out
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <trace.pb> [--count|--range]", args[0]);
        std::process::exit(2);
    }

    let mut f = File::open(Path::new(&args[1]))?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    let mode = args.iter().find(|a| a.starts_with("--")).map(|s| s.as_str());

    let mut total_insns: u64 = 0;
    let mut blocks = 0usize;
    let mut min_addr = u64::MAX;
    let mut max_addr = 0u64;
    let mut ip = 0usize;

    while ip + 8 <= data.len() {
        let raw_len = u32::from_le_bytes([data[ip], data[ip + 1], data[ip + 2], data[ip + 3]]) as usize;
        let comp_len = u32::from_le_bytes([data[ip + 4], data[ip + 5], data[ip + 6], data[ip + 7]]) as usize;
        ip += 8;
        if ip + comp_len > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "block overrun"));
        }

        let block = lz4_decompress(&data[ip..ip + comp_len]).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("lz4: {}", e))
        })?;
        ip += comp_len;

        if block.len() != raw_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("block {} len mismatch: raw {} vs decoded {}", blocks, raw_len, block.len()),
            ));
        }
        blocks += 1;
        for ch in block.chunks_exact(8) {
            let addr = u64::from_le_bytes(ch.try_into().unwrap());
            total_insns += 1;
            if addr < min_addr {
                min_addr = addr;
            }
            if addr > max_addr {
                max_addr = addr;
            }
            if mode != Some("--count") && mode != Some("--range") {
                println!("0x{:016x}", addr);
            }
        }
    }

    match mode {
        Some("--count") | Some("--range") => {
            println!("blocks={} insns={} min=0x{:x} max=0x{:x}",
                     blocks, total_insns,
                     if min_addr == u64::MAX { 0 } else { min_addr },
                     max_addr);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_block_roundtrip() {
        // 模拟 agent 端：3 块，每块 8 条指令地址
        let mut trace = Vec::new();
        for blk in 0..3u32 {
            let mut raw = Vec::new();
            for i in 0..8u64 {
                raw.extend_from_slice(&(0x1000 + blk as u64 * 0x100 + i * 4).to_le_bytes());
            }
            let comp = lz4_compress_simple(&raw);
            trace.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            trace.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            trace.extend_from_slice(&comp);
        }
        // 用解码核心路径验证
        let mut ip = 0usize;
        let mut insns = Vec::new();
        while ip + 8 <= trace.len() {
            let raw_len = u32::from_le_bytes(trace[ip..ip + 4].try_into().unwrap()) as usize;
            let comp_len = u32::from_le_bytes(trace[ip + 4..ip + 8].try_into().unwrap()) as usize;
            ip += 8;
            let block = lz4_decompress(&trace[ip..ip + comp_len]).unwrap();
            assert_eq!(block.len(), raw_len);
            for ch in block.chunks_exact(8) {
                insns.push(u64::from_le_bytes(ch.try_into().unwrap()));
            }
            ip += comp_len;
        }
        assert_eq!(insns.len(), 24);
        assert_eq!(insns[0], 0x1000);
        assert_eq!(insns[23], 0x1000 + 2 * 0x100 + 7 * 4);
    }
}

/// 端到端：真实编码器（lz4_block，含匹配压缩）→ 解码器
#[cfg(test)]
mod e2e_real_encoder {
    use super::lz4_decompress;
    use crate::lz4_block::compress_into;

    fn build_trace_file(blocks: usize) -> Vec<u8> {
        let mut trace = Vec::new();
        for blk in 0..blocks as u64 {
            // 高重复流：同模块顺序执行（地址高字节恒定）
            let mut raw = Vec::new();
            for i in 0..4096u64 {
                raw.extend_from_slice(&(0x78aabbcc0000 + blk * 0x100000 + i * 4).to_le_bytes());
            }
            let mut comp = Vec::new();
            compress_into(&raw, &mut comp);
            trace.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            trace.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            trace.extend_from_slice(&comp);
        }
        trace
    }

    fn decode_all(trace: &[u8]) -> (usize, u64, u64) {
        let mut ip = 0usize;
        let mut insns = 0usize;
        let mut min = u64::MAX;
        let mut max = 0u64;
        while ip + 8 <= trace.len() {
            let raw_len = u32::from_le_bytes(trace[ip..ip + 4].try_into().unwrap()) as usize;
            let comp_len = u32::from_le_bytes(trace[ip + 4..ip + 8].try_into().unwrap()) as usize;
            ip += 8;
            let block = lz4_decompress(&trace[ip..ip + comp_len]).unwrap();
            assert_eq!(block.len(), raw_len);
            ip += comp_len;
            for ch in block.chunks_exact(8) {
                let a = u64::from_le_bytes(ch.try_into().unwrap());
                insns += 1;
                if a < min { min = a; }
                if a > max { max = a; }
            }
        }
        (insns, min, max)
    }

    #[test]
    fn multi_block_real_compression_roundtrip() {
        let trace = build_trace_file(4); // 4 块 × 4096 条
        let (insns, min, max) = decode_all(&trace);
        assert_eq!(insns, 4 * 4096);
        assert_eq!(min, 0x78aabbcc0000);
        assert_eq!(max, 0x78aabbcc0000 + 3 * 0x100000 + 4095 * 4);
    }

    #[test]
    fn compression_actually_reduces_size() {
        let trace = build_trace_file(1);
        // 块头 8 字节 + 压缩数据；高重复流应显著小于 32KB 原始
        assert!(trace.len() < 4096 * 8 * 60 / 100, "expected <60%, got {}", trace.len());
    }
}
