# rustFrida JS API 使用说明

本文档只说明 `rust_frida` 里可直接使用的 JavaScript API。当前实现面向 `Android + ARM64`，JS 运行时为内嵌 `QuickJS`。

## 0. 最近更新
- 仓库现在使用 `Git LFS` 管理 `qbdi/libQBDI.a`
  - 首次克隆后需要执行：

```bash
git lfs install
git lfs pull
```

- JS 全局对象新增 `qbdi`
  - 用于在设备侧直接创建 QBDI VM、配置插桩范围、模拟调用、执行 `run()` 和读取寄存器返回值。
- `agent/src/ghostmem.rs`（Phase 2）—— VMA-Less 幽灵内存分配器 + stealth alloc/free 回调
  - 对接 mkpms `ghostmem` KPM 模块的 prctl 接口（`0x47474d01/02/03`），`/proc/maps` 不可见。
  - 依赖 frida-gum 17.x 的 `gum_set_stealth_alloc` 注册（当前锁定 16.7.18 无此 API）。
- `agent/src/trace/lz4_block.rs` + `trace-decoder/`（Phase 3）—— Stalker trace LZ4 压缩落盘与 host 解码
  - 落盘块格式 `[u32 raw][u32 comp][LZ4]`；`trace-decoder` 解回指令地址流（见 `trace-decoder/README.md`）。

## 1. 进入 JS 环境

注入成功后，在 `rust_frida` 的交互界面里可用下面几个命令：

- `jsinit`
  - 初始化 QuickJS 引擎。
- `loadjs <script>`
  - 执行一段 JS 代码。
- `jseval <expr>`
  - 求值一个 JS 表达式并打印结果。
- `jsrepl`
  - 进入交互式 JS REPL，支持 Tab 补全。
- `jsclean`
  - 清理 QuickJS 引擎和已安装的 JS hook。

常见用法：

```text
jsinit
jseval Module.findBaseAddress("libart.so").toString()
loadjs console.log("hello from quickjs")
jsrepl
```

如果是 `spawn` 模式，涉及应用类的 Java hook 建议放在 `Java.ready(() => { ... })` 里执行。

## 2. 全局对象一览

初始化后，JS 全局可直接使用这些对象/函数：

- `console`
- `ptr()`
- `Memory`
- `Module`
- `hook()`
- `unhook()`
- `callNative()`
- `qbdi`
- `Java`
- `Jni`

## 3. 类型速查

### 3.1 常用类型别名

| 类型名 | 实际含义 |
| --- | --- |
| `AddressLike` | `NativePointer \| number \| bigint \| "0x..."` |
| `NativePointer` | `ptr()` 创建出来的指针对象 |
| `JsNumber` | JS `number` |
| `JsBigInt` | JS `bigint` |
| `JavaObjectProxy` | `Java.use()` / Java hook 中返回的 Java 对象代理 |
| `ArrayBuffer` | `Memory.readByteArray()` 返回的字节数组 |

补充说明：

- 地址参数基本都可以写成 `AddressLike`
- 64 位值在 JS 里可能表现为 `number` 或 `bigint`，取决于实现是否需要避免精度丢失
- `NativePointer.toString()` / `JSON.stringify()` 时会输出十六进制字符串

### 3.2 API 参数 / 返回值速查

#### console

| API | 参数类型 | 返回类型 |
| --- | --- | --- |
| `console.log(...args)` | `any[]` | `undefined` |
| `console.info(...args)` | `any[]` | `undefined` |
| `console.warn(...args)` | `any[]` | `undefined` |
| `console.error(...args)` | `any[]` | `undefined` |
| `console.debug(...args)` | `any[]` | `undefined` |

#### ptr / NativePointer

| API | 参数类型 | 返回类型 |
| --- | --- | --- |
| `ptr(value)` | `number \| bigint \| string \| NativePointer` | `NativePointer` |
| `p.add(offset)` | `number \| bigint \| "0x..." \| NativePointer` | `NativePointer` |
| `p.sub(offset)` | `number \| bigint \| "0x..." \| NativePointer` | `NativePointer` |
| `p.toString()` | 无 | `string` |
| `p.toJSON()` | 无 | `string` |
| `p.toNumber()` | 无 | `bigint` |
| `p.toInt()` | 无 | `bigint` |

#### Memory

| API | 参数类型 | 返回类型 |
| --- | --- | --- |
| `Memory.readU8(addr)` | `AddressLike` | `number` |
| `Memory.readU16(addr)` | `AddressLike` | `number` |
| `Memory.readU32(addr)` | `AddressLike` | `bigint` |
| `Memory.readU64(addr)` | `AddressLike` | `bigint` |
| `Memory.readPointer(addr)` | `AddressLike` | `NativePointer` |
| `Memory.readCString(addr)` | `AddressLike` | `string` |
| `Memory.readUtf8String(addr)` | `AddressLike` | `string` |
| `Memory.readByteArray(addr, len)` | `AddressLike, number` | `ArrayBuffer` |
| `Memory.writeU8(addr, value)` | `AddressLike, number` | `undefined` |
| `Memory.writeU16(addr, value)` | `AddressLike, number` | `undefined` |
| `Memory.writeU32(addr, value)` | `AddressLike, number` | `undefined` |
| `Memory.writeU64(addr, value)` | `AddressLike, bigint \| number` | `undefined` |
| `Memory.writePointer(addr, value)` | `AddressLike, AddressLike` | `undefined` |

#### Module

| API | 参数类型 | 返回类型 |
| --- | --- | --- |
| `Module.findExportByName(moduleName, symbolName)` | `string \| null, string` | `NativePointer \| null` |
| `Module.findBaseAddress(moduleName)` | `string` | `NativePointer \| null` |
| `Module.findByAddress(addr)` | `AddressLike` | `ModuleInfo \| null` |
| `Module.enumerateModules()` | 无 | `ModuleInfo[]` |

#### Native hook

| API | 参数类型 | 返回类型 |
| --- | --- | --- |
| `hook(target, callback, stealth?)` | `AddressLike, (ctx: NativeHookContext) => any, boolean?` | `boolean` |
| `unhook(target)` | `AddressLike` | `boolean` |
| `callNative(func, ...args)` | `AddressLike, up to 6 x (number \| bigint \| NativePointer)` | `number \| bigint` |

#### qbdi

| API | 参数类型 | 返回类型 |
| --- | --- | --- |
| `qbdi.newVM()` | 无 | `number` |
| `qbdi.destroyVM(vm)` | `number` | `boolean` |
| `qbdi.addInstrumentedModuleFromAddr(vm, addr)` | `number, AddressLike` | `boolean` |
| `qbdi.addInstrumentedRange(vm, start, end)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.removeInstrumentedRange(vm, start, end)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.removeAllInstrumentedRanges(vm)` | `number` | `boolean` |
| `qbdi.allocateVirtualStack(vm, size)` | `number, number` | `boolean` |
| `qbdi.clearVirtualStacks(vm)` | `number` | `boolean` |
| `qbdi.simulateCall(vm, returnAddr, ...args)` | `number, AddressLike, ...AddressLike[]` | `boolean` |
| `qbdi.call(vm, target, ...args)` | `number, AddressLike, ...AddressLike[]` | `NativePointer \| null` |
| `qbdi.run(vm, start, stop)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.getGPR(vm, reg)` | `number, number` | `NativePointer` |
| `qbdi.setGPR(vm, reg, value)` | `number, number, AddressLike` | `boolean` |
| `qbdi.getErrno(vm)` | `number` | `number` |
| `qbdi.setErrno(vm, value)` | `number, number` | `boolean` |
| `qbdi.recordMemoryAccess(vm, accessType)` | `number, number` | `boolean` |
| `qbdi.registerTraceCallbacks(vm, target, outputDir?)` | `number, AddressLike, string?` | `boolean` |
| `qbdi.unregisterTraceCallbacks(vm)` | `number` | `boolean` |
| `qbdi.lastError()` | 无 | `string` |
| `qbdi.shutdown()` | 无 | `undefined` |

补充说明：

- `vm` 是 `qbdi.newVM()` 返回的句柄，不是 JS 对象。
- 常用寄存器常量包括：
  - `qbdi.REG_RETURN`
  - `qbdi.REG_BP`
  - `qbdi.REG_LR`
  - `qbdi.REG_SP`
  - `qbdi.REG_FLAG`
  - `qbdi.REG_PC`
- 常见最小流程：

```js
var vm = qbdi.newVM();
qbdi.addInstrumentedModuleFromAddr(vm, target);
qbdi.allocateVirtualStack(vm, 0x100000);
qbdi.simulateCall(vm, 0, arg0, arg1);
qbdi.run(vm, target, 0);
var ret = qbdi.getGPR(vm, qbdi.REG_RETURN);
qbdi.destroyVM(vm);
```

#### Java

| API | 参数类型 | 返回类型 |
| --- | --- | --- |
| `Java.use(className)` | `string` | `JavaClassWrapper` |
| `Class.$new(...args)` | 任意，运行时按重载解析 | `JavaObjectProxy` |
| `Class.method(...args)` | 任意，运行时按重载解析 | `any` |
| `Class.method.overload(...types)` | `string...` 或 `string[]...` | `MethodWrapper` |
| `Class.method.impl = fn` | `(ctx: JavaHookContext) => any` | setter，无返回值 |
| `Class.method.impl = null` | `null` | setter，无返回值 |
| `Java.ready(fn)` | `() => void` | `void` |
| `Java.deopt()` | 无 | `boolean` |
| `Java.setStealth(enabled)` | `boolean` | `boolean` |
| `Java.getStealth()` | 无 | `boolean` |
| `Java.getField(objPtr, className, fieldName, fieldSig)` | `AddressLike, string, string, string` | `any` |

#### Jni

| API | 参数类型 | 返回类型 |
| --- | --- | --- |
| `Jni.addr(name)` | `string` | `NativePointer` |
| `Jni.addr(env, name)` | `AddressLike, string` | `NativePointer` |
| `Jni.find(name)` | `string` | `JniEntry` |
| `Jni.find(env, name)` | `AddressLike, string` | `JniEntry` |
| `Jni.entries()` | 无 | `JniEntry[]` |
| `Jni.entries(env)` | `AddressLike` | `JniEntry[]` |
| `Jni.table` | 无 | `Record<string, JniEntry>` |
| `Jni.FindClass` | 无 | `NativePointer` |
| `Jni.helper.env.ptr` | 无 | `NativePointer` |
| `Jni.helper.env.getObjectClass(obj)` | `AddressLike` | `NativePointer` |
| `Jni.helper.env.getSuperclass(clazz)` | `AddressLike` | `NativePointer` |
| `Jni.helper.env.isSameObject(a, b)` | `AddressLike, AddressLike` | `boolean` |
| `Jni.helper.env.isInstanceOf(obj, clazz)` | `AddressLike, AddressLike` | `boolean` |
| `Jni.helper.env.exceptionCheck()` | 无 | `boolean` |
| `Jni.helper.env.exceptionOccurred()` | 无 | `NativePointer` |
| `Jni.helper.env.exceptionClear()` | 无 | `boolean` |
| `Jni.helper.env.readJString(jstr)` | `AddressLike` | `string \| null` |
| `Jni.helper.env.getClassName(clazz)` | `AddressLike` | `string \| null` |
| `Jni.helper.env.getObjectClassName(obj)` | `AddressLike` | `string \| null` |
| `Jni.helper.structs.JNINativeMethod.read(addr)` | `AddressLike` | `JNINativeMethodInfo` |
| `Jni.helper.structs.JNINativeMethod.readArray(addr, count)` | `AddressLike, number` | `JNINativeMethodInfo[]` |
| `Jni.helper.structs.jvalue.read(addr, jniType)` | `AddressLike, string` | `any` |
| `Jni.helper.structs.jvalue.readArray(addr, typesOrSig)` | `AddressLike, string \| string[]` | `any[]` |

### 3.3 结构体 / 上下文对象速查

#### ModuleInfo

```ts
type ModuleInfo = {
  name: string
  base: NativePointer
  size: number
  path: string
}
```

#### NativeHookContext

```ts
type NativeHookContext = {
  x0: number | bigint
  x1: number | bigint
  x2: number | bigint
  x3: number | bigint
  x4: number | bigint
  x5: number | bigint
  x6: number | bigint
  x7: number | bigint
  x8: number | bigint
  x9: number | bigint
  x10: number | bigint
  x11: number | bigint
  x12: number | bigint
  x13: number | bigint
  x14: number | bigint
  x15: number | bigint
  x16: number | bigint
  x17: number | bigint
  x18: number | bigint
  x19: number | bigint
  x20: number | bigint
  x21: number | bigint
  x22: number | bigint
  x23: number | bigint
  x24: number | bigint
  x25: number | bigint
  x26: number | bigint
  x27: number | bigint
  x28: number | bigint
  x29: number | bigint
  x30: number | bigint
  sp: number | bigint
  pc: number | bigint
  trampoline: number | bigint
  orig(): number | bigint
}
```

说明：

- native hook 改返回值时，修改的是 `ctx.x0`
- `ctx.orig()` 会调用原函数并同步写回 `ctx.x0`

#### JavaHookContext

```ts
type JavaHookContext = {
  thisObj?: JavaObjectProxy
  args: any[]
  env: number | bigint
  orig(...args: any[]): any
}
```

说明：

- `thisObj` 仅实例方法存在，静态方法没有
- Java hook 的 `return` 值就是方法返回值
- `ctx.orig()` 不传参时使用原始参数；传参时用新参数调用原方法

#### JniEntry

```ts
type JniEntry = {
  name: string
  index: number
  address: NativePointer
}
```

#### JNINativeMethodInfo

```ts
type JNINativeMethodInfo = {
  address: NativePointer
  namePtr: NativePointer
  sigPtr: NativePointer
  fnPtr: NativePointer
  name: string | null
  sig: string | null
}
```

## 4. console

支持：

```javascript
console.log(...)
console.info(...)
console.warn(...)
console.error(...)
console.debug(...)
```

示例：

```javascript
console.log("base =", Module.findBaseAddress("libart.so"))
```

## 5. ptr 和 NativePointer

### 4.1 创建指针

`ptr(value)` 支持：

- 数字
- `BigInt`
- 十六进制字符串，如 `"0x7f12345678"`
- 已经是 `NativePointer` 的对象

示例：

```javascript
var p = ptr("0x7f12345678")
console.log(p.toString())   // 0x7f12345678
```

### 4.2 NativePointer 方法

- `p.add(offset)`
- `p.sub(offset)`
- `p.toString()`
- `p.toJSON()`
- `p.toNumber()`
- `p.toInt()`

说明：

- `offset` 可以是数字、`BigInt`、`0x...` 字符串或另一个 `NativePointer`
- `toNumber()` / `toInt()` 返回 `BigInt`

示例：

```javascript
var base = Module.findBaseAddress("libart.so")
var target = base.add(0x1234)
console.log(target.toString())
```

## 6. Memory

### 5.1 读取

- `Memory.readU8(ptr)`
- `Memory.readU16(ptr)`
- `Memory.readU32(ptr)`
- `Memory.readU64(ptr)`
- `Memory.readPointer(ptr)`
- `Memory.readCString(ptr)`
- `Memory.readUtf8String(ptr)`
- `Memory.readByteArray(ptr, length)`

说明：

- 无效地址会抛 `RangeError`，不会直接崩进程
- `readCString()` 最多读取 `4096` 字节
- `readByteArray()` 返回 `ArrayBuffer`
- `readPointer()` 返回 `NativePointer`
- `readU32()` / `readU64()` 返回 `BigInt`

示例：

```javascript
var sym = Module.findExportByName("libc.so", "dlopen")
console.log(Memory.readPointer(sym).toString())
```

### 5.2 写入

- `Memory.writeU8(ptr, value)`
- `Memory.writeU16(ptr, value)`
- `Memory.writeU32(ptr, value)`
- `Memory.writeU64(ptr, value)`
- `Memory.writePointer(ptr, value)`

说明：

- 写入前会检查地址可访问性
- 必要时内部会临时尝试修改页面权限
- 成功时返回 `undefined`

示例：

```javascript
var p = ptr("0x12345678")
Memory.writeU32(p, 0x90909090)
```

## 7. Module

支持：

- `Module.findExportByName(moduleName, symbolName)`
- `Module.findBaseAddress(moduleName)`
- `Module.findByAddress(address)`
- `Module.enumerateModules()`

返回值：

- `findExportByName()` / `findBaseAddress()` 找不到时返回 `null`
- `findByAddress()` 找不到时返回 `null`
- `enumerateModules()` 返回：

```javascript
[
  {
    name: "libart.so",
    base: ptr("0x7f..."),
    size: 123456,
    path: "/apex/..."
  }
]
```

示例：

```javascript
var art = Module.findBaseAddress("libart.so")
var info = Module.findByAddress(art)
console.log(JSON.stringify(info))
```

## 8. Native Hook API

### 7.1 安装和移除 hook

- `hook(target, callback[, stealth])`
- `unhook(target)`

参数说明：

- `target` 必须是地址，可传 `NativePointer`、数字、`BigInt` 或十六进制字符串
- `callback` 必须是 JS 函数
- `stealth` 是可选布尔值，`true` 时优先使用 stealth 模式安装 inline hook

示例：

```javascript
var openPtr = Module.findExportByName("libc.so", "open")

hook(openPtr, function(ctx) {
  console.log("open called, x0 =", ptr(ctx.x0).toString())
  ctx.orig()
})
```

### 7.2 native hook 回调上下文

native hook 的 `ctx` 里可用：

- `ctx.x0` ~ `ctx.x30`
- `ctx.sp`
- `ctx.pc`
- `ctx.trampoline`
- `ctx.orig()`

关键行为：

- `ctx.orig()` 会调用原函数，并把返回值写回 `ctx.x0`
- native hook 的 JS `return` 值本身不会作为返回值使用
- 如果你想改返回值，要显式修改 `ctx.x0`

改返回值示例：

```javascript
hook(Module.findExportByName("libc.so", "getpid"), function(ctx) {
  ctx.orig()
  ctx.x0 = 12345
})
```

### 7.3 直接调用 native 函数

签名：

```javascript
callNative(funcPtr, arg0?, arg1?, arg2?, arg3?, arg4?, arg5?)
```

说明：

- 最多传 6 个参数，按 `ARM64 x0 ~ x5` 传入
- 适合整数/指针参数
- 返回值会自动转成 `number` 或 `BigInt`

示例：

```javascript
var getpidPtr = Module.findExportByName("libc.so", "getpid")
console.log(callNative(getpidPtr))
```

## 9. Java API

`Java` 提供的是偏 Frida 风格的接口，但实现细节以当前仓库代码为准。

### 8.1 Java.use

```javascript
var Activity = Java.use("android.app.Activity")
```

类包装对象支持：

- `Class.$new(...args)` 创建对象
- `Class.method(...args)` 调用静态方法
- `Class.method.overload(...)` 指定重载
- `Class.method.impl = function(ctx) { ... }` 安装 hook
- `Class.method.impl = null` 卸载 hook

实例对象支持：

- `obj.fieldName` 直接读字段
- `obj.method(...args)` 调实例方法
- `obj.$call(name, sig, ...args)` 按显式签名调用
- `obj.$className`

示例：

```javascript
var Process = Java.use("android.os.Process")
console.log(Process.myPid())

var JString = Java.use("java.lang.String")
var s = JString.$new("hello")
console.log(s.length())
```

### 8.2 overload 用法

支持三种写法：

```javascript
Activity.onResume.overload("int")
Activity.onResume.overload("(I)V")
SomeClass.foo.overload(["int", "java.lang.String"], ["long"])
```

说明：

- 传 Java 类型名时，会自动转 JNI 签名
- 传 JNI 签名时必须是 `"(...)..."` 形式
- 传多个数组时，可一次选择多个 overload 进行 hook

### 8.3 Java hook 回调

Java hook 的回调上下文 `ctx` 里常用字段：

- `ctx.thisObj`
- `ctx.args`
- `ctx.env`
- `ctx.orig()`

关键行为：

- Java hook 的 `return` 值会作为方法返回值
- `ctx.orig()` 可调用原方法
- `ctx.thisObj` 和 `ctx.args` 里的 Java 对象会自动包装成可直接访问的代理对象

示例：

```javascript
var Activity = Java.use("android.app.Activity")

Activity.onResume.impl = function(ctx) {
  console.log("Activity.onResume:", ctx.thisObj.$className)
  return ctx.orig()
}
```

修改参数再调用原方法：

```javascript
var JString = Java.use("java.lang.String")
var Demo = Java.use("com.example.demo.MainActivity")

Demo.test.overload("java.lang.String").impl = function(ctx) {
  return ctx.orig(JString.$new("patched"))
}
```

### 8.4 Java.ready

`spawn` 模式下注入过早时，应用 `ClassLoader` 还没准备好。此时建议：

```javascript
Java.ready(function() {
  var Main = Java.use("com.example.app.MainActivity")
  Main.onResume.impl = function(ctx) {
    console.log("ready hook hit")
    return ctx.orig()
  }
})
```

如果已经是 attach 到运行中的进程，`Java.ready(fn)` 会立即执行。

### 8.5 其他 Java API

- `Java.deopt()`
  - 尝试清空 JIT 缓存。
- `Java.setStealth(true | false)`
  - 设置 Java hook 使用 stealth 模式。
- `Java.getStealth()`
  - 查看当前 stealth 开关。
- `Java.getField(objPtr, className, fieldName, fieldSig)`
  - 通过原始对象指针读字段。

`Java.getField()` 示例：

```javascript
var objPtr = ptr("0x12345678")
var value = Java.getField(objPtr, "com.example.Test", "mCount", "I")
console.log(value)
```

## 10. Jni API

`Jni` 主要用于定位 JNI 函数地址，以及辅助解析 `JNIEnv`、`jvalue`、`JNINativeMethod`。

### 9.1 直接取 JNI 函数地址

下面几种写法都可以：

```javascript
Jni.FindClass
Jni.addr("FindClass")
Jni.find("FindClass")
Jni.table.FindClass
```

如果需要指定某个 `JNIEnv*`：

```javascript
Jni.addr(envPtr, "FindClass")
Jni.find(envPtr, "FindClass")
Jni.entries(envPtr)
```

说明：

- `Jni.FindClass` / `Jni.RegisterNatives` 这类属性值是函数地址
- `Jni.find(...)` 返回 `{ name, index, address }`
- `Jni.entries(...)` 返回整个 JNI 表数组
- `Jni.table` 返回按名字索引的整张表

### 9.2 Jni.helper

常用辅助：

- `Jni.helper.pointerSize`
- `Jni.helper.env.ptr`
- `Jni.helper.env.getObjectClass(obj)`
- `Jni.helper.env.getSuperclass(clazz)`
- `Jni.helper.env.isSameObject(a, b)`
- `Jni.helper.env.isInstanceOf(obj, clazz)`
- `Jni.helper.env.exceptionCheck()`
- `Jni.helper.env.exceptionOccurred()`
- `Jni.helper.env.exceptionClear()`
- `Jni.helper.env.readJString(jstr)`
- `Jni.helper.env.getClassName(clazz)`
- `Jni.helper.env.getObjectClassName(obj)`

结构体辅助：

- `Jni.helper.structs.JNINativeMethod.read(ptr)`
- `Jni.helper.structs.JNINativeMethod.readArray(ptr, count)`
- `Jni.helper.structs.jvalue.read(ptr, jniType)`
- `Jni.helper.structs.jvalue.readArray(ptr, typesOrSig)`

示例：读取 `RegisterNatives` 的方法表

```javascript
hook(Jni.addr("RegisterNatives"), function(ctx) {
  var methods = Jni.helper.structs.JNINativeMethod.readArray(
    ptr(ctx.x2),
    Number(ctx.x3)
  )
  console.log(JSON.stringify(methods))
  ctx.orig()
})
```

示例：观察 `FindClass`

```javascript
hook(Jni.addr("FindClass"), function(ctx) {
  console.log("FindClass:", Memory.readCString(ptr(ctx.x1)))
  ctx.orig()
})
```

## 11. 推荐示例

### 10.1 hook libc 导出函数

```javascript
var dlopenPtr = Module.findExportByName("libdl.so", "dlopen")

hook(dlopenPtr, function(ctx) {
  console.log("dlopen:", Memory.readCString(ptr(ctx.x0)))
  ctx.orig()
})
```

### 10.2 hook Java 方法

```javascript
Java.ready(function() {
  var Activity = Java.use("android.app.Activity")

  Activity.onResume.impl = function(ctx) {
    console.log("onResume hit")
    return ctx.orig()
  }
})
```

### 10.3 调用 native 函数

```javascript
var getpidPtr = Module.findExportByName("libc.so", "getpid")
console.log("pid =", callNative(getpidPtr))
```

## 12. 注意事项

- native hook 和 Java hook 的返回语义不同：
  - native hook 需要改 `ctx.x0`
  - Java hook 直接 `return` 即可
- `callNative()` 当前主要面向整数/指针参数，不适合复杂 ABI 封送
- `Java.ready()` 主要解决 spawn 场景下 app `ClassLoader` 尚未就绪的问题
- 需要稳定 hook Java 层时，优先先 `Java.ready(...)` 再 `Java.use(...)`

## 13. 仓库内测试（无需 NDK）

```bash
# host-tests：agent 纯逻辑（ghostmem 分配器 + LZ4 压缩）—— 10 测试
cd host-tests && cargo test

# trace-decoder：trace 块流解码 —— 8 测试（多块 roundtrip + 真实编码器 e2e）
cd trace-decoder && cargo test
```

- 两个 crate 用独立 `[workspace]` + 子目录 `.cargo/config.toml` 覆盖根配置的
  android target，在宿主机直接编译测试（根 `.cargo/config.toml` 强制
  `aarch64-linux-android` + NDK linker，本仓库开发机无 NDK）。
- `host-tests/src/` 是 agent 模块的同步副本：修改 `agent/src/{ghostmem.rs,
  trace/lz4_block.rs}` 后运行 `host-tests/sync.sh` 再提交。
