/* Host 侧测试入口：agent 纯逻辑模块（lz4_block/ghostmem）的同步副本。
 * 仓库内 cargo test 即可运行（无需 NDK）——见各模块内 #[cfg(test)]。
 * 注：副本需与 agent 源同步（agent 侧修改后复制过来）。 */
pub mod ghostmem;
pub mod lz4_block;
