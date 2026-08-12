# trace-decoder

Host 侧指令 trace 解码工具：读取 rustFrida `agent` 的 Stalker 落盘文件，解出指令地址流。供 Chronos 风格 TTD 分析 / AI MCP 的宿主侧解析（方案 #8 分析侧闭环）。

## 落盘格式

`agent/src/stalker.rs` 写入的块流：

```
块序列 = { [u32 LE 解压后字节数][u32 LE 压缩后字节数][LZ4 压缩数据] }*
每块解压后是 8 字节小端指令地址的连续序列（4096 条/块）
```

- 块头 8 字节（raw + comp 长度），`comp` 用于定位下一块边界
- LZ4 为块格式（无内建长度，依赖头字段）
- 压缩算法与 `agent/src/trace/lz4_block.rs` 对称（已与标准 `lz4_flex` 互操作验证）

## 构建与使用

```bash
# 独立于 agent 的 Android 构建链（纯 host 工具）
cargo build -p trace-decoder

./target/debug/trace-decoder trace.pb            # 逐行输出 0x 指令地址
./target/debug/trace-decoder trace.pb --count    # 统计：块数/指令数/地址范围
```

示例输出：

```
$ trace-decoder trace.pb --count
blocks=3 insns=24 min=0x1000 max=0x121c
```

## 集成到 AI MCP

解码后的地址流可直接喂给分析管线：

- 地址 → `Module.findExportByAddress` / 符号化
- 连续区间 → 函数边界 / VMP 核心块热点
- 结合 `--count` 的 min/max 定位加密热点范围

## 测试

```bash
cargo test -p trace-decoder   # 需 host target（非 android）；含多块 roundtrip 单测
```

端到端验证：
- 3 块 × 8 指令（简化编码）→ `blocks=3 insns=24 min=0x1000 max=0x121c` 精确还原
- **真实编码器**（`lz4_block` 含匹配压缩）：4 块 × 4096 条高重复地址流 roundtrip 精确还原 + 压缩率 <60%（Iteration 22 新增，8 测试全过）

## 关联

- `agent/src/trace/lz4_block.rs` — 编码端压缩实现
- `agent/src/stalker.rs` — 落盘写路径（16 字节块头）
- mkpms `docs/PLAN.md` — 方案 #8 状态
