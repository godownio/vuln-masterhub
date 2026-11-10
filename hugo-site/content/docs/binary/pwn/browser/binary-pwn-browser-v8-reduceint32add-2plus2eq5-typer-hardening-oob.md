---
id: binary-pwn-browser-v8-reduceint32add-2plus2eq5-typer-hardening-oob
title: V8 TurboFan ReduceInt32Add 注入 2+2=>5 错误常量折叠 + simplified-lowering 边界检查恒假：JS 数组短距越界泄露 map/properties
type: scenario
domain: binary
path: binary/pwn/browser
technique: turbofan-int32add-wrong-constant-folding-bounds-check-elimination-oob
tags:
- binary
- pwn
- browser
- v8
- turbofan
- jit
- constant-folding
- bounds-check-elimination
- oob
- type-confusion
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-6
  verified_at: '2026-11-08T01:17:23+08:00'
  notes: '已对照原文（content.md 715 行 + 逐张核对 15 图）核对：图 03 显示 code TURBOFAN_JS、图 05 的 %DebugPrint 显示 length: 5 与泄露值 5 745001882fd（JSArray 的 map/properties），证明 2+2=5 优化 bug + 边界检查恒假产生短距 OOB 泄露这一环节确有 d8 实际运行证据；图 15 为 ./d8 script.js 运行完整 EXP 后真 getshell 的终端，整条链打通。本卡仅为完整 RCE 链中『优化 bug → OOB 泄露』这一已验证的前置环节，结论未写成 RCE（severity medium、tags 无 rce），未夸大、不是理论链。dedup 复查除自身外 top 候选（wasm-frame-state-type-confusion、cve-2024-12695、fake-array-jstypedarray-dataptr、quickjs、eBPF 等）verdict 全为 new、无同 sink/同链卡，cards.json dedup_review 理由成立。路径 binary/pwn/browser 合法。未验证点：卡内无 sources/source/source_url 字段（本库卡片统一如此）；未打该 CTF patch 的官方 V8 不成立（卡内已注明边界）。'
url: /docs/binary/pwn/browser/binary-pwn-browser-v8-reduceint32add-2plus2eq5-typer-hardening-oob/
draft: false
kb_aliases:
- 2+2=5
- ReduceInt32Add
- machine-operator-reducer.cc
- turbo_typer_hardening 恒假
- kAbortOnOutOfBounds 被去掉
- UMDCTF2025 literally-1984/1985
- 数组越界泄露 map 与 properties
---

## 一句话结论

给 V8 TurboFan 的 `MachineOperatorReducer::ReduceInt32Add` 注入一条 "2+2=>5" 的错误常量折叠，同时把 `simplified-lowering.cc` 里启用 `CheckBoundsFlag::kAbortOnOutOfBounds` 的条件改成 `turbo_typer_hardening && 2+2==5`（C++ 源码常量恒为假），JS 里 `let a=2,b=2; idx=a+b` 经 JIT 变成 5 而编译器仍按 4 推断索引范围，配合被去掉的越界 abort，即可用长度 4 的数组 `victim[idx]` 短距越界读到相邻对象内存（map/properties）。

## 原理

- **错误常量折叠**：patch 在 `ReduceInt32Add` 里加 `if (m.left().Is(2) && m.right().Is(2)) return ReplaceInt32(5);`，使 TurboFan 优化 JS 的 `Int32Add(2,2)` 时直接折叠成常量 5。优化器结果与 JS 语义不一致。
- **边界检查被关闭**：`simplified-lowering.cc` 的 `RepresentationSelector` 原在 `turbo_typer_hardening` 时给边界检查加 `CheckBoundsFlag::kAbortOnOutOfBounds`（索引越界立即 abort，而非返回默认值/继续解释执行）；patch 把条件改成 `v8_flags.turbo_typer_hardening && 2 + 2 == 5`。这里的 `2+2` 是 C++ 源码常量、不受 JS 层 patch 影响，恒为 4 != 5 → 条件恒假 → `new_flags` 永远不带 `kAbortOnOutOfBounds`，越界时不再终止。
- **为什么产生 OOB**：TurboFan 基于类型/范围推断决定数组访问是否保留边界检查；当 JS 层 `a+b` 被错误折叠成 5，编译器对 `idx` 的范围推断仍按 `2+2=4`（落在合法 `[0, length)` 内）来做，认为边界检查冗余；叠加上面的 abort 被关闭，`victim[5]` 越界访问既不拦截也不 abort，直接读到 elements 之后的内存。
- **泄露内容**：`victim = [1.1,2.2,3.3,4.4]`（长度 4）时 `idx=5` 读到相邻对象；返回 `[idx, victim[idx], victim]` 观察到 idx=5 与泄露值，正是 JSArray 的 `map` 与 `properties` 等压缩指针组合（调试输出中的小浮点值即这些字段），构成信息泄露。
- **短距越界可放大**：按 `idx = (a+b-2)*2` 得到 6，可越界更远（用于后续改写相邻数组对象字段）。
- **为什么成立（本质）**：JIT 优化器常量折叠结果与运行时语义不一致 + 编译器基于错误推断消除边界检查 + 边界检查失败不再 abort，三者叠加让"编译器认为安全"的数组访问实际越界；这是 V8 CTF patch 题常用的"优化 bug → OOB"模式。
- **已验证**：`%DebugPrint(foo)` 显示 `code: TURBOFAN_JS` 确认 JIT 优化；返回数组观察到 idx=5 与泄露的内存值，OOB 读成立。

## 触发条件

- 打过该 patch 的 V8/d8（TurboFan 优化启用，`simplified-lowering.cc` 边界检查恒假）。
- JS 中构造能被 `ReduceInt32Add` 折叠成常量 5 的加法（`a=2,b=2` 循环热化触发优化）。
- 目标数组长度小于折叠后的索引（如长度 4 用 idx=5）。
- 复现观察用 `--allow-natives-syntax` 的 `%DebugPrint`/`%SystemBreak`；真实利用只需数组越界读能力。

## 利用步骤

1. 写 `function foo(){ let a=2,b=2,idx; let victim=[1.1,2.2,3.3,4.4]; for(let i=0;i<10000;i++) idx=a+b; return victim[idx]; }`，外层循环调用 10000 次触发 TurboFan 优化。
2. `idx` 优化后为 5，`victim[5]` 越界读；返回 `[idx, victim[idx], victim]` 观察泄露值（map/properties）。
3. 用 `idx=(a+b-2)*2` 之类算术把越界下标放大到 6，配合写操作 `victim[idx]=target` 可越界写。
4. 以该 OOB 为起点进入后续原语构造（改 length 绕过 CHECK、JSTypedArray AAR/AAW、Wasm 劫持）。

## PoC

```javascript
function foo() {
  let idx, a = 2, b = 2;
  let victim = [1.1, 2.2, 3.3, 4.4];
  for (let i = 0; i < 10000; i++) idx = a + b;   // JIT: 2+2 => 5
  return [idx, victim[idx], victim];              // victim[5] 越界读
}
for (let i = 0; i < 10000; i++) foo();
console.log(foo());  // idx = 5，第 2 项为相邻对象内存（map/properties）
```

放大越界：`idx = (a + b - 2) * 2;` → 6。

## 变体与关联

- **常量折叠变体**：任何让 TurboFan 折叠结果与运行时不一致的改写（错误 `ReplaceInt32`、范围推断错误、类型混淆）都可产生类似 OOB；本题用 `2+2=>5`。
- **范围放大**：用减法/乘法把折叠常量变成更大的越界下标（`5-2=3; 3*2=6`），但直接改 elements 指针会受 elements map CHECK 限制，需改用"改 length"路线。
- **关联**：与"改 length 而非 elements 指针绕过 elements map CHECK 得到稳定 OOB"卡、JSTypedArray data_ptr AAR/AAW 卡、Wasm jump_table_start 劫持卡串成同一条 RCE 链；本卡只负责"优化 bug 产生 OOB"这一环。
- **边界**：未打 patch 的官方 V8（无错误折叠、边界检查正常）不成立；`turbo_typer_hardening` 关闭时行为不同。

## 检测与防御

- **修复**：不要引入与源码语义不一致的常量折叠；边界检查消除必须基于可信范围推断，且 `kAbortOnOutOfBounds` 等关键标志不能被恒假条件短路。
- **检测**：编译器 reducer 中出现可疑常量替换；CI 对优化器做差分测试（优化前后结果一致性）；运行时对数组索引做最终边界校验而非仅依赖编译期推断。
- **加固**：生产构建保留边界检查、启用 `turbo_typer_hardening`；对 JIT 优化结果做验证（如 `--verify-heap`、范围断言）；限制 `%DebugPrint` 等 natives 语法在生产暴露。
