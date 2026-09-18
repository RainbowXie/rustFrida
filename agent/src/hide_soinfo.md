# hide_soinfo — 加载后显式隐藏

注入库必须从 linker `soinfo` 链和 `_r_debug.r_map` 同时消失。隐藏不得发生在 `.init_array` 里：Android 16 的 `android_dlopen_ext()` 在构造函数返回后仍持有当前 soinfo。

## 协议

```
android_dlopen_ext(agent)
  └─ 构造函数 hide_soinfo_register() 只登记身份和待隐藏状态
android_dlopen_ext 返回 handle
  └─ loader / debug so-only / QBDI helper 调用 hide_from_solist(handle)
       ├─ 解析 linker 符号并推导 soinfo::next（越过空链表快路径 RET）
       ├─ 用本次 handle + 映射基址确认节点，拒绝仅靠 wwb_so 字符串
       ├─ 双链写入并确认两侧均不可见
       └─ 仅在 HideResult.status==1 后启动 hello_entry
```

`HideResult` 版本 1：`version/stage/status/next_offset/entries_scanned/sym_matched/soinfo_state/link_map_state/wrote/head_ptr/target_ptr/error/target_path/head_path`。`status=1` 表示双链完成；负数是阶段失败。loader 返回 `-5` 表示 `android_dlopen_ext` 失败，`-13` 表示加载成功但隐藏失败。

`/memfd:wwb_so` 是 rustFrida 自己的 memfd 名，不是外部框架。

## 已验证范围

- Pixel 6 Android 16 (`192.168.123.235:5555`)：`ptrace-only`、`memfd-only`、`so-empty`、`so-only`、`so+fd+thread` 均成功；`so-only` 报告隐藏 `/memfd:wwb_so (deleted)`，目标进程存活。
- Android 16 注意：`android_dlopen_ext` handle 不是 `soinfo*`；`solist_get_head` 返回 `solist_tail`；内部符号带 `.llvm.<id>` 后缀。隐藏入口用 `dladdr` 路径 + `solist_head` 遍历定位节点，必要时 `mprotect` RELRO 后再写链表。
- Android 15 ARM64 矩阵尚未在本 change 跑完。未知 linker 模式必须拒绝写入。

## Debug 分层

| 模式 | 验证层 |
| --- | --- |
| `ptrace-only` | attach/malloc/detach |
| `memfd-only` | 创建并关闭 `wwb_so` memfd |
| `so-empty` | 真实空 ELF `ET_DYN` 的 `android_dlopen_ext` |
| `so-only` | agent 加载 + 显式隐藏，不启线程 |
| `so+fd+thread` | 完整注入 |
