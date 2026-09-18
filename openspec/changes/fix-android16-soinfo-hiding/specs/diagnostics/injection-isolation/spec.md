# Spec Delta

## Purpose

规定 rustFrida 的 debug injection 模式使用类型正确的测试载荷，并提供能够区分 ptrace、memfd、ELF 加载、隐藏事务和 agent 启动阶段的诊断结果。

## ADDED Requirements

### Requirement: 每种调试模式必须使用符合用途的载荷
系统 MUST 为需要动态链接器加载的调试模式提供有效的 ARM64 Android ELF shared object，不得将裸 shellcode 或其他非 ELF 数据标记为空 SO。

#### Scenario: so-empty 加载基线
- **WHEN** 用户运行 `--debug-inject so-empty`
- **THEN** 系统将真实的最小 ARM64 Android shared object 写入 memfd，并使用 `android_dlopen_ext()` 加载该对象

#### Scenario: 构建产物类型错误
- **WHEN** so-empty 所使用的文件不是 AArch64 ELF shared object
- **THEN** 构建或测试必须失败，且不得生成可部署的 rustfrida host

### Requirement: 调试模式必须隔离故障阶段
系统 SHALL 使 `ptrace-only`、`memfd-only`、`so-empty`、`so-only` 和完整注入模式分别验证不同阶段，并输出当前模式实际执行和未执行的阶段。

#### Scenario: ptrace 与 memfd 成功但 so-empty 失败
- **WHEN** `ptrace-only` 与 `memfd-only` 成功而 `so-empty` 失败
- **THEN** 诊断结果将故障范围收敛到 ELF/linker 加载阶段，不归因于目标应用对抗或 memfd 创建

#### Scenario: so-empty 成功但 so-only 失败
- **WHEN** 有效空 SO 可以加载而 agent SO 加载或隐藏失败
- **THEN** 诊断结果将故障范围收敛到 agent 内容、构造过程或隐藏事务

### Requirement: 异常报告必须标识地址归属和当前阶段
系统 MUST 在远程函数异常时报告 PC、LR、对应映射、关键参数寄存器以及正在执行的注入阶段，并明确 rustFrida 创建的 memfd 映射归属。

#### Scenario: LR 位于 rustFrida memfd
- **WHEN** 异常 LR 位于由 rustFrida 创建的 `/memfd:wwb_so` 映射
- **THEN** 诊断输出明确将该映射标识为本次 rustFrida 载荷，而不得仅凭名称归因于外部框架

### Requirement: 调试失败必须可恢复目标状态
系统 SHALL 在非交互调试模式失败后关闭本次创建的 host/target fd、恢复寄存器、结束 ptrace 控制并使目标进程回到可运行或明确终止状态。

#### Scenario: android_dlopen_ext 中发生异常
- **WHEN** debug injection 在 `android_dlopen_ext()` 或隐藏事务中异常停止
- **THEN** rustFrida 执行确定性的清理流程，且后续测试不需要依赖残留暂停进程或遗留 memfd
