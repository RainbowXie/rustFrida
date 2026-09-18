# Spec Delta

## Purpose

规定 rustFrida 在 Android linker 完成动态库加载后安全隐藏注入库，并以可验证、可诊断的方式维持 Android 15 与 Android 16 的运行兼容性。

## ADDED Requirements

### Requirement: 隐藏只能在动态库完成加载后执行
系统 SHALL 保留注入库从 linker `soinfo` 枚举链和 `_r_debug.r_map` 链隐藏的能力，但隐藏事务 MUST 在 `android_dlopen_ext()` 已成功返回、当前库构造过程已经结束之后执行。

#### Scenario: Android 16 成功加载后隐藏
- **WHEN** rustFrida 在 Android 16 ARM64 进程中成功加载 agent 动态库
- **THEN** 系统在加载调用返回后执行隐藏事务，并且目标进程不得因 linker 加载状态被提前修改而异常停止

#### Scenario: 构造阶段不修改 linker 链表
- **WHEN** linker 正在执行 agent 动态库的构造函数
- **THEN** 系统不得从 `soinfo` 或 `_r_debug.r_map` 链表摘除当前库

### Requirement: 隐藏事务必须先验证后写入
系统 MUST 在修改 linker 状态前验证所需内部符号、推导出的字段偏移、目标节点身份、相邻链表关系和目标路径；任何验证失败 MUST 阻止本次隐藏写入并产生明确结果。

#### Scenario: Android linker 内部布局不匹配
- **WHEN** 当前 Android 版本的 linker 符号或指令模式不能支持可信的 `soinfo::next` 推导
- **THEN** 系统返回带阶段和原因的隐藏失败结果，并保持 linker 链表未被修改

#### Scenario: 目标节点不是当前注入库
- **WHEN** 路径或加载身份检查不能唯一确认待隐藏节点属于当前注入库
- **THEN** 系统不得删除任何 `soinfo` 或 `link_map` 节点

### Requirement: 隐藏结果必须可由 host 判定
系统 SHALL 将库加载结果与隐藏结果作为两个独立状态报告给 host；隐藏结果 MUST 至少包含执行阶段、成功或失败状态、错误原因、匹配符号数量、推导偏移、目标节点和扫描数量。

#### Scenario: 加载成功且隐藏成功
- **WHEN** agent 动态库加载成功且两个 linker 枚举链均完成隐藏
- **THEN** host 能明确报告“库已加载”和“隐藏已完成”，然后继续 agent 通信

#### Scenario: 加载成功但隐藏验证失败
- **WHEN** agent 动态库已经加载但隐藏事务在写入前验证失败
- **THEN** host 能明确区分该状态与 `android_dlopen_ext()` 失败，并输出隐藏失败的阶段和原因

### Requirement: 成功结果必须对应完整隐藏
系统 MUST 仅在目标注入库同时不再出现在 `dl_iterate_phdr`/`soinfo` 枚举和 `_r_debug.r_map` 枚举中时报告隐藏成功。

#### Scenario: 仅一个枚举链完成摘除
- **WHEN** `soinfo` 链或 `_r_debug.r_map` 链中仍有一个可以枚举到目标库
- **THEN** 系统不得报告完整隐藏成功，并必须标识未完成的链

### Requirement: 支持的 Android 版本必须经过回归验证
系统 SHALL 对 Android 15 和 Android 16 ARM64 设备验证加载、隐藏、agent 连接与目标进程存活；版本兼容声明 MUST 以该验证结果为依据。

#### Scenario: Android 15 回归
- **WHEN** 在 Android 15 ARM64 设备运行完整注入
- **THEN** agent 成功连接、目标进程保持存活且注入库不可被规定的 linker 枚举接口发现

#### Scenario: Android 16 回归
- **WHEN** 在 Pixel 6 Android 16 ARM64 设备运行完整注入
- **THEN** agent 成功连接、目标进程保持存活且注入库不可被规定的 linker 枚举接口发现
