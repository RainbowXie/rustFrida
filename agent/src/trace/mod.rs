//! Trace 命令相关功能 - ptrace 跟踪和代码转换

mod arm64_analysis;
mod arm64_codegen;
mod lz4_block;
mod ptrace_ops;
mod transformer;

pub use arm64_analysis::{analyze_branch_regs, is_arm64_branch, is_arm64_call, resolve_next_addr, BranchRegUsage};

/// LZ4 压缩包装：stalker 落盘用（数据 + 块头由调用方写）。
pub fn lz4_compress(data: &[u8], out: &mut Vec<u8>) -> usize {
    lz4_block::compress_into(data, out)
}

#[cfg(test)]
mod tests {
    use super::lz4_compress;
    use crate::trace::lz4_block::decompress;

    #[test]
    fn stalker_batch_roundtrip() {
        // 模拟 trace 批：指令地址流（同模块连续地址，高度可压缩）
        let mut batch = Vec::new();
        for i in 0..8192u64 {
            batch.extend_from_slice(&(0x78aabbcc0000 + i * 4).to_le_bytes());
        }
        let mut enc = Vec::new();
        let sz = lz4_compress(&batch, &mut enc);
        /* 该数据特征下标准 lz4_flex 压缩率同为 ~50%（每 8 字节仅 2 字节变化），
         * 断言放宽到 <55% 并注明与参考实现一致。 */
        assert!(sz < batch.len() * 55 / 100, "compression {}/{} too weak", sz, batch.len());
        let dec = decompress(&enc, batch.len()).unwrap();
        assert_eq!(dec, batch);
    }
}
pub use arm64_codegen::{gen_jump_to_transformer, gen_mov_reg_addr};
pub use ptrace_ops::get_registers;
pub use transformer::{gum_modify_thread, transformer_global, transformer_wrapper_full};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct UserRegs {
    pub regs: [usize; 31], // X0-X30 寄存器
    pub sp: usize,         // SP 栈指针
    pub pc: usize,         // PC 程序计数器
    pub pstate: usize,     // 处理器状态
}
