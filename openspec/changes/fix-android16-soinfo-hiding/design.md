# Design

## Context

完整故障证据见 `proposal.md`。当前 agent 和 QBDI helper 都把 `hide_soinfo.c` 链入 `.init_array`；构造函数在 linker 持有加载锁、`android_dlopen_ext()` 尚未返回时，定位路径包含 `wwb_so` 的当前节点并立即调用 `solist_remove_soinfo()`，随后手工修改 `_r_debug.r_map`。该方式在 Android 16 Pixel 6 上使 linker 在构造函数返回后继续加载流程时异常。

当前完整 loader 同时承担 agent blob 接收、memfd 建立、`android_dlopen_ext()`、符号解析和 agent 线程启动。host 只在 shellcode 整体返回后获得一个合并结果，因此不能区分“ELF 已加载但隐藏失败”和“ELF 本身加载失败”。`so-empty` 又错误复用了 `loader.bin`，无法提供独立的 linker 基线。

## Goals / Non-Goals

**Goals:**

- 保留 `hide_from_solist` 的实际隐藏职责，使 agent 与 QBDI helper 在支持的 Android 版本仍从 `soinfo` 和 `_r_debug.r_map` 两个枚举面消失。
- 让任何 linker 链表写入发生在 `android_dlopen_ext()` 返回之后，并在写入前完成结构验证。
- 把加载、隐藏和 agent 启动变成可分别观察、可分别失败、可清理的阶段。
- 用真实 ELF 空 SO 建立可重复的 Android 15/16 linker 加载基线。

**Non-Goals:**

- 不删除 `hide_from_solist`，不增加“关闭隐藏”的运行时开关，也不把隐藏失败静默当作成功。
- 不在本变更中重写整个 Android linker、改为手工 ELF 映射器或改变现有 CLI 注入入口。
- 不承诺未经过真机矩阵验证的 Android 版本兼容性。
- 不把 `/proc/maps` 的 VMA 隐藏纳入本变更；该能力属于 ghostmem/内核侧路径。

## Decisions

### 1. 构造函数只登记上下文，隐藏事务在加载返回后显式触发

保留 `hide_from_solist` 作为隐藏事务入口，但不再让 `.init_array` 在 linker 的构造阶段直接修改链表。构造阶段只允许记录当前库可安全取得的身份信息和“待隐藏”状态，不调用 `solist_remove_soinfo()`，也不写 `_r_debug.r_map`。

`android_dlopen_ext()` 返回有效 handle 后，loader 通过该 handle 查找导出的隐藏入口并显式调用。隐藏入口执行完成并返回结构化结果后，loader 才解析并启动 `hello_entry`。QBDI helper 使用同一显式握手，在 helper 完成加载后调用其隐藏入口，再将 helper API 暴露给 QuickJS。

选择该方案的原因是它保留现有 linker 原生加载、构造函数执行和 soinfo 隐藏能力，同时消除“当前 soinfo 尚被 linker 使用时摘除”的生命周期冲突。

备选方案：

- 在 `.init_array` 末尾延迟若干毫秒或创建线程：线程调度不能证明 `android_dlopen_ext()` 已返回，存在时序竞态，因此不采用。
- 完全移除构造函数或隐藏能力：违反本变更约束，也失去现有反枚举能力，因此不采用。
- 手工映射 ELF 绕开 linker：工作面过大，会引入 TLS、重定位、构造顺序和 namespace 新问题，因此不在本变更采用。

### 2. 隐藏操作采用“解析与校验 → 双链写入 → 结果确认”的事务模型

隐藏入口分三个阶段：

1. **解析与校验**：定位 linker、解析所需符号、推导 `soinfo::next`、根据加载 handle/唯一身份确认当前目标节点，校验前后节点与尾指针关系，并定位对应 `link_map`。
2. **双链写入**：先保存计划修改的所有指针和旧值，再执行 `soinfo` 链和 `_r_debug.r_map` 链更新。写入过程不得重新进入公开 dl API。
3. **结果确认**：使用保存的链表视图和安全的直接遍历确认两个枚举链均不再包含目标；仅在两侧都完成时返回成功。

若第一阶段失败，不进行任何写入。若写入阶段出现可检测的不一致，结果必须指出具体链和旧值，供 host 将此次注入判为失败；实现任务需要评估哪些写入能够安全回滚，并以测试固定该边界。

目标身份不再只依赖字符串包含 `wwb_so`。memfd 名称可以保留用于日志，但隐藏入口必须结合当前加载 handle 对应 soinfo、加载基址或唯一 token，避免误删同名历史映射。

### 3. 扩展 HideResult 为版本化阶段结果

C 与 Rust 共享的结果结构增加版本、当前阶段、各链状态和是否发生写入等字段。状态至少区分：

- 尚未请求隐藏
- 解析失败且未写入
- `soinfo` 隐藏失败
- `link_map` 隐藏失败
- 两侧隐藏成功

loader 通过控制 socket 将加载和隐藏阶段结果返回 host；debug direct-dlopen 路径继续通过导出函数读取同一 ABI。ABI 布局由静态断言和 host 测试验证，禁止 C/Rust 两边独立漂移。

### 4. loader 在同一远程调用内完成加载后隐藏握手

正常注入仍由 shellcode 执行，以避免在 host 侧新增多个脆弱的 ptrace 调用窗口。shellcode 的顺序调整为：

1. 接收并写入 agent blob。
2. 调用 `android_dlopen_ext()`，等待其完整返回。
3. 使用返回 handle 查找隐藏入口与 `hello_entry`。
4. 调用隐藏入口并检查结构化结果。
5. 仅在隐藏成功后创建 agent 线程。

这保证隐藏明确发生在加载返回之后，又不会让 host 在中间阶段恢复目标线程。debug `so-only` 路径则复用相同的“加载后显式隐藏”协议，避免正常与调试实现分叉。

### 5. so-empty 使用源码构建的真实最小 shared object

新增最小 C 源文件，通过现有 Android NDK 工具链生成 `ET_DYN`/AArch64 shared object。最终 host 嵌入该 SO，而不是嵌入裸 `loader.bin`。构建脚本验证 ELF magic、class、machine 和 type；缺失或类型错误时构建失败。

空 SO 不链接 `hide_soinfo.c`，不包含业务构造函数，仅用于确认 memfd + `android_dlopen_ext()` 基线。这样 `so-empty` 成功而 `so-only` 失败时，差异才真正指向 agent 内容或隐藏事务。

### 6. 以分层门禁和真机矩阵证明修复

自动化门禁包括：

- `HideResult` C/Rust 大小、偏移和版本一致性。
- linker 指令模式解析的已知 Android 15/16 fixture 测试与拒绝未知模式测试。
- 空 SO 构建产物 ELF 类型检查。
- debug 模式到载荷和阶段的映射测试。
- 失败路径 fd、ptrace 和寄存器恢复测试。

真机验收在至少一台 Android 15 ARM64 设备和 Pixel 6 Android 16 上依次运行 `ptrace-only`、`memfd-only`、`so-empty`、`so-only`、完整 attach 和 spawn。完整成功还需要独立枚举探针证明目标库不在 `dl_iterate_phdr` 和 `_r_debug.r_map` 中，而不只依赖 rustFrida 自报状态。

## Risks / Trade-offs

- [Android 16 linker 内部符号或指令模式继续变化] → 将解析器设计为可拒绝的版本适配层；未知模式不写链表，并以 fixture 和真机证据增加支持。
- [加载完成后到隐藏完成前存在短暂可枚举窗口] → loader 在同一 shellcode 调用内立即执行隐藏，agent 业务线程和目标恢复均在隐藏成功后发生；明确验收该窗口内没有用户代码继续执行。
- [双链写入中途失败造成状态不一致] → 写前保存完整旧值、缩小写入集合，并为可回滚字段实现恢复；无法证明安全回滚的路径必须在写前校验阶段被阻止。
- [显式隐藏入口依赖 dlsym，而摘除后公开 dlsym 已不安全] → 所有入口解析必须在摘除前基于刚返回的 handle 完成，隐藏后继续使用已有函数指针和仓库的 unrestricted linker API。
- [QBDI helper 与 agent 产生两套行为] → 共享同一 `hide_soinfo.c` 协议和结果 ABI，分别只负责触发时机，不复制隐藏算法。
- [真机矩阵不足导致兼容声明过宽] → 文档只声明实际验证的 Android 版本；新增版本必须先增加 fixture 和设备收据。

## Migration Plan

1. 先增加结果 ABI、真实空 SO 和自动化门禁，不改变生产隐藏时机。
2. 改造隐藏入口为可显式调用的事务，并让 `.init_array` 仅登记上下文。
3. 更新 normal loader、debug direct loader 和 QBDI helper 的加载后握手。
4. 在 Android 15 完成回归，再在 Pixel 6 Android 16 完成分层模式、attach、spawn 和枚举验证。
5. 更新 `hide_soinfo.md` 与 README 的兼容范围、阶段语义和失败诊断。

回滚时恢复到变更前提交，而不是提供运行时关闭隐藏的降级路径；回滚版本仍只声明其既有 Android 7-15 支持范围。
