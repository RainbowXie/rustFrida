# Tasks

## 1. 建立可失败的回归门禁

- [x] 1.1 为 Android 16 当前崩溃链路增加 RED 验收脚本，依次运行 `ptrace-only`、`memfd-only`、`so-empty`、`so-only` 和完整注入，并验证现版本在 Pixel 6 的 `so-only`/完整注入阶段失败而前两层成功
- [x] 1.2 增加 `HideResult` C/Rust ABI 布局测试，覆盖版本、阶段、链状态、写入标记、错误字段和关键 offset，并验证任一侧布局漂移会使测试失败
- [x] 1.3 提取 Android 15 与 Android 16 linker 相关符号/指令 fixture，增加 `soinfo::next` 推导成功、未知模式拒绝和错误偏移拒绝测试
- [x] 1.4 增加 debug 模式阶段映射和失败清理测试，验证每个模式只执行声明的阶段，并验证异常后寄存器、ptrace 和 fd 状态被恢复

## 2. 修复 so-empty 基线载荷

- [x] 2.1 新增无业务构造函数的最小 ARM64 Android shared object 源文件和构建步骤，并通过 `readelf`/自动测试验证产物为 ELF64、AArch64、`ET_DYN`
- [x] 2.2 将 `EMPTY_SO` 从 `loader.bin` 改为嵌入最小 shared object，并验证 `--debug-inject so-empty` 不再出现 `bad ELF magic`
- [x] 2.3 在 host 构建入口增加空 SO 产物存在性和 ELF 类型门禁，并验证错误或缺失产物会阻止 `rustfrida` 构建

## 3. 版本化隐藏结果协议

- [x] 3.1 扩展 `hide_result`/`HideResult` 为版本化阶段结果，定义加载、解析、写入 `soinfo`、写入 `link_map`、确认和完成状态，并通过 ABI 测试
- [x] 3.2 增加未写入失败、部分链失败和完整成功的结果编码，验证 host 日志能区分 `android_dlopen_ext` 失败与加载后隐藏失败
- [x] 3.3 让正常 loader、debug direct-dlopen 和 QBDI helper 共用同一结果协议，验证三条路径不会复制或解释不同的状态常量

## 4. 将 hide_from_solist 改为加载后显式事务

- [x] 4.1 保留 `.init_array` 入口但限制其只登记当前库身份和待隐藏状态，增加测试或二进制检查证明构造阶段不调用 `solist_remove_soinfo` 且不写 `_r_debug.r_map`
- [x] 4.2 将 `hide_from_solist` 重构为可由 loader 在 `android_dlopen_ext()` 返回后显式调用的导出事务入口，并验证隐藏函数仍实际执行而非被删除、禁用或跳过
- [x] 4.3 在解析阶段验证 linker 符号、`next` 偏移、链表边界、尾指针和目标节点身份，验证任一条件不成立时零写入并返回具体失败阶段
- [x] 4.4 将目标识别从仅匹配 `wwb_so` 路径改为结合当前加载 handle、基址或唯一加载 token，增加同名 memfd 反例测试以证明不会误删其他节点
- [x] 4.5 实现 `soinfo` 与 `_r_debug.r_map` 双链更新、旧值保存和结果确认，验证仅在两个枚举链都不可见时报告成功，并覆盖可安全回滚的中途失败路径

## 5. 更新 loader 与注入状态机

- [x] 5.1 调整 `loader.c` 顺序为“加载返回 → 解析隐藏入口与 hello_entry → 执行隐藏 → 启动 agent 线程”，并通过调用顺序测试证明隐藏发生在 `android_dlopen_ext()` 返回后
- [x] 5.2 让隐藏失败阻止 agent 线程启动并把结构化阶段结果送回 host，验证不会把加载成功但隐藏失败误报为 agent 连接超时
- [x] 5.3 让 `so-only` 与 QBDI helper 加载复用同一加载后隐藏握手，验证其结果与正常注入一致
- [x] 5.4 修复远程调用异常路径的资源所有权和恢复流程，验证 debug 模式失败后无暂停目标、无遗留 `wwb_so` fd、无残留 rustfrida ptrace 控制

## 6. 自动化验证与真机矩阵

- [x] 6.1 运行 host-tests、trace-decoder 测试、相关 crate 构建和新增 ABI/parser/ELF 门禁，并记录所有命令与结果
- [ ] 6.2 在 Android 15 ARM64 设备依次验证 `ptrace-only`、`memfd-only`、`so-empty`、`so-only`、完整 attach 和 spawn，确认 agent 连接、目标存活和失败清理
      （阻塞：本机无 Android 15 设备；现有设备为 A10/A13/A14/A16。需补设备或用 SDK-35 linker fixture 替代）
- [x] 6.3 在 Pixel 6 `192.168.123.235:5555` Android 16 上执行同一矩阵，确认不再出现 PC 位于 `linker64`、LR 位于 rustFrida `wwb_so` 的加载异常
- [x] 6.4 使用独立枚举探针验证成功注入后目标库同时不出现在 `dl_iterate_phdr`/`soinfo` 和 `_r_debug.r_map` 中，不以 `HideResult` 自报成功替代外部证据
      （已实现 `loader/probe_so.c` + `--debug-inject probe`：DL 两条链各自枚举，排除探针自身。
      正向：solist 356/0、r_map 356/0；反向：只摘 solist 不摘 r_map 时 `HideResult` 仍报成功，
      而探针报 r_map 357/1 并让注入失败——证明外部证据能拆穿假成功。）
- [ ] 6.5 对 attach 与 spawn 各执行重复运行和失败后重试，验证没有偶发时序依赖、Zygote patch 残留或 fd/暂停进程污染
      （attach 部分已完成：`host-tests/scripts/android16-repeat-retry.sh` 同进程 3 次全过；
      不存在 PID 失败后同一目标重试成功；每轮结束无 rustfrida 残留、目标非 T 状态。
      spawn 部分阻塞：本机 Android 16 在 Zymbiote 阶段失败（boot heap 找不到 setArgV0 指针），
      已用改动前 v0.1.0 二进制复现同样失败，确认 pre-existing 且与本次改动无关；
      spawn 重复/重试验收需先解决 Zymbiote 兼容性，因此本项不勾选。）

## 7. 文档与审计收口

- [x] 7.1 更新 `agent/src/hide_soinfo.md` 和 README，说明加载后显式隐藏协议、Android 15/16 已验证范围、`wwb_so` 归属和 debug 模式分层含义
- [ ] 7.2 执行代码审查、前提反证与收据审计，重点验证没有通过删除/禁用 `hide_from_solist`、静默跳过隐藏或伪造空 SO 来使测试通过
- [ ] 7.3 提交实现前运行 GitNexus 变更影响分析和循环检查，并确认最终 Git 提交只包含本 change 的代码、测试和文档
