# Proposal

## Why

rustFrida 在 Android 16 Pixel 6 上进入 `android_dlopen_ext()` 加载 `agent.so` 时稳定异常，而 `ptrace-only` 与 `memfd-only` 均成功。现场寄存器显示 PC 位于 `linker64`、LR 位于 rustFrida 自己创建的 `/memfd:wwb_so`，结合当前 `.init_array` 中立即摘除自身 `soinfo` 和 `link_map` 的实现，说明现有 Android 7-15 隐藏路径不能安全覆盖 Android 16 加载生命周期。

## What Changes

- 保留 `hide_from_solist` 提供的 `soinfo` 与 `_r_debug.r_map` 隐藏能力，不以删除、禁用或绕过该能力作为修复方案。
- 将隐藏执行时机与 `android_dlopen_ext()` 的内部构造阶段解耦，使 linker 完成库加载后再执行隐藏事务。
- 为 Android linker 内部符号、`soinfo::next` 推导结果、目标节点身份和链表一致性增加执行前验证；验证失败时返回可诊断错误，不写入未验证的 linker 状态。
- 让 loader、agent 与 host 明确传递“库已加载”和“隐藏已完成”两个独立状态，保证 agent 线程只在隐藏结果可判定后进入正常通信。
- 修复 `so-empty` 调试模式错误嵌入裸 shellcode 的问题，提供真实的最小 ARM64 Android ELF shared object，恢复其作为“仅验证 linker/memfd 加载”的基线价值。
- 增加 host 侧结构与解析测试、构建产物检查，以及 Android 15/16 真机注入和枚举隐藏回归矩阵。

## Capabilities

### New Capabilities

- `runtime/soinfo-hiding`: 定义 rustFrida 在 Android linker 完成加载后安全隐藏注入库、报告隐藏结果并维持跨版本兼容的行为。
- `diagnostics/injection-isolation`: 定义 debug injection 模式使用有效测试载荷并能区分 ptrace、memfd、ELF 加载、隐藏和 agent 启动故障层。

### Modified Capabilities

无。

## Impact

- 主要影响 `agent/src/hide_soinfo.c`、`agent/src/lib.rs`、`loader/loader.c`、`rust_frida/src/injection.rs`、`rust_frida/src/process.rs`、`agent/build.rs` 与 `qbdi-helper/build.rs`。
- 新增一个真实的最小 ARM64 Android 空 SO 构建输入或受控构建产物，并更新 host 测试与真机验证脚本/文档。
- `rust_get_hide_result`/`HideResult` 的状态表达需要扩展，但应保持 C/Rust ABI 明确、版本化且可测试。
- 不改变用户侧 PID、进程名、spawn、QuickJS Hook 等 CLI 使用方式。
