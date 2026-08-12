# hide_soinfo — soinfo 链摘除（dl_iterate_phdr 对抗）

`.init_array` 构造器：dlopen 加载后**自动从 linker 的 soinfo 全局链表摘除自身**，使 `dl_iterate_phdr` / `solist_get_head` 遍历枚举不到注入的库。绕过 V-OS 等安全 SDK 的模块枚举检测。

## 原理

```
dlopen(我们的 .so)
  └─ .init_array 执行 hide_soinfo 构造器
       ├─ 解析 solist_add_soinfo 机器码 → 推导 soinfo::next 字段偏移（版本无关）
       ├─ 找到 solist 头与自身 soinfo 节点
       └─ 调用 linker 自己的 solist_remove_soinfo → 从链表摘除（含 sonext 尾指针）
```

- **版本无关**：不依赖硬编码偏移，通过解析 `solist_add_soinfo` 的指令模式自动推导 `soinfo::next` 偏移，兼容 Android 7-15。
- **安全约束**：`.init_array` 在 linker 持有 `g_dl_mutex` 期间执行——不能调用 `dl_iterate_phdr` 或再次 lock `g_dl_mutex`（会死锁）。摘除通过解析出的函数指针完成，不触碰 mutex。

## 关键符号（__dl_ 前缀，Android linker 内部）

| 符号 | 用途 |
|------|------|
| `solist_get_head` | 链表头 |
| `solist` | fallback 头变量 |
| `solist_add_soinfo` | 推导 next 偏移的模板 |
| `solist_remove_soinfo` | 摘除自身 |
| `soinfo_get_path` | 确认目标节点 |

## 用途与关联

- 与方案 #9（Zygote 注入）组合：注入库加载后立即从 soinfo 链摘除，App 侧枚举不到
- 与方案 #6（ART 隐蔽）互补：`art_controller.rs` 隐藏 ArtMethod，本文件隐藏库模块本身
- 内核侧对应：ghostmem 的 VMA-Less 内存（`/proc/maps` 不可见）——用户态 soinfo 链 + 内核态 maps 双重不可见

## 验证

- host 语法检查通过（`gcc -fsyntax-only`）
- 真机验证：`dlopen` 后 `dl_iterate_phdr` 回调计数不含本库；`/proc/self/maps` 无对应映射（配合 ghostmem）

## 限制

- 仅对 **dlopen 加载路径**生效（`.init_array` 触发）；若库通过其他方式装载需手动调用
- 摘除后 `dladdr`/`dl_iterate_phdr` 查不到本库——主动定位需保留自身句柄
