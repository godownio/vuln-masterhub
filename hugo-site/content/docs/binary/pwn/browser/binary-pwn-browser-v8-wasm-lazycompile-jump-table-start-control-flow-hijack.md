---
id: binary-pwn-browser-v8-wasm-lazycompile-jump-table-start-control-flow-hijack
title: V8 劫持 Wasm LazyCompile：首次调用前篡改 WasmTrustedInstanceData.jump_table_start，使编译完成后跳入错位 shellcode
type: scenario
domain: binary
path: binary/pwn/browser
technique: wasm-lazycompile-jump-table-start-hijack-control-flow
tags:
- binary
- pwn
- browser
- v8
- wasm
- lazy-compilation
- jump-table-start
- control-flow-hijack
- jit-spray
- shellcode
- aar-aaw
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-4
  verified_at: '2026-11-07T21:42:18+08:00'
  notes: 已对照原文及 20 张图核对；图11-18 逐段反汇编验证 JSToWasmWrapper→Builtins_WasmCompileLazy→jump_table_start→jmp r15 机制，图19 在 jump_table_start+0x89c 处定位到错位 shellcode(push 0x3b/pop rax)，原文给出完整可复现 JS 模板与 PoC，机制解释充分；dedup 除自身外无同链候选，与同批 AAR/AAW 卡互判 new 非同链；非 DoS/未打通/理论链，保留；未验证点：图20 仅为空终端提示符、本文未附 shellcode 最终执行成功截图(无 shell/execve/id 输出)，最终危害为机制推断+错位载荷定位，未在文内看到执行结果；要求 Wasm 首次调用、已有 AAR/AAW、去除 Sandbox、固定偏移按版本实测，未独立复现；V8 通用手法无明确受影响版本，不设 affected_versions；路径合法、frontmatter 无 sources 违规字段
url: /docs/binary/pwn/browser/binary-pwn-browser-v8-wasm-lazycompile-jump-table-start-control-flow-hijack/
draft: false
kb_aliases:
- Wasm Lazy Compilation 劫持
- Builtins_WasmCompileLazy 劫持
- jump_table_start 覆盖
- WasmTrustedInstanceData 篡改
- 通用控制流劫持
- JIT-Spray 错位执行
---

## 一句话结论

V8 的 Wasm 函数首次调用会经 `JSToWasmWrapper → Builtins_JSToWasmWrapperAsm → jump_table_start` 的延迟编译桩，进入 `Builtins_WasmCompileLazy` 编译真实代码；由于该流程**只在编译结束时**才从 `WasmInstanceObject → trusted_data → jump_table_start` 取跳转目标，而 Wrapper 前半段用的是另一来源的地址，因此可在首次调用前用 AAR/AAW 把对象内的 `jump_table_start` 改成"真实代码地址 + 固定偏移"处的错位 shellcode，编译完成后 `jmp r15` 即跳入 shellcode，实现通用控制流劫持。

## 原理

- **Wasm 首次调用链**：函数调用先走 `Function.Code.instruction_start`，此时 Code 是 `BUILTIN JSToWasmWrapper`（负责 JS 传参类型转换、内联缓冲、调用真实 Wasm 函数、处理返回值/异常）。经多次 `CheckObjectType()` 后进入 `Builtins_JSToWasmWrapperAsm`，其中 `call qword ptr [r10 + rdi*8]` 跳到 `jump_table_start` 对应的延迟编译桩（如 `0x6116a603000: jmp 0x6116a603800`）。
- **Lazy Compilation 类似动态链接的 Lazy Binding**：桩里 `push 0`（送入 wasm 函数索引，第一个函数为 0）后跳入 `Builtins_WasmCompileLazy`；它把真实 Wasm 代码写入内存，并把 `jump_table_start` 处的 `jmp` 改为直接跳转真实代码地址（如 `jmp 0x6116a604040`）。流程末尾 `add r15, qword ptr [rsi + 0x27]` 从 `WasmTrustedInstanceData` 的 `jump_table_start` 字段取出内容，再 `jmp r15` 进入真实代码。
- **可利用的错位（为什么篡改不影响前半流程）**：
  - `JSToWasmWrapper` 虽然会用到与 `jump_table_start` 相同的地址，但**并非从 `WasmInstanceObject` 读取**，因此篡改对象内指针不会破坏 Wrapper 的正常调用与 LazyCompile 的触发。
  - LazyCompile 生成汇编时只需要 `push 0` 送入的索引，前期流程同样不依赖我们改动的指针。
  - 只有当 LazyCompile 完成时，才从 `WasmInstanceObject` 读 `jump_table_start` 并跳转——此时读到的已是被篡改的值。
- **偏移固定**：真实 Wasm 代码相对 `jump_table_start` 的位置是固定的（文中为 `0x840`，含 JIT-Spray 载荷的完整偏移为 `0x89c`）；把 `jump_table_start` 指向"基址 + 该偏移"处的错位指令，即可让最终跳转落到攻击者布置的 shellcode（浮点立即数汇编码中错位出的 `push 0x3b; pop rax; nop; ...` 序列）。
- **载荷**：`shell_wasm_code` 是一段复制了 Turbofan 优化后 JIT-Spray 汇编的 Wasm 模块，靠从浮点立即数返回汇编码附近错位执行得到可用指令序列。
- **完整性**：文章给出从定位 `WasmInstanceObject`、读 `trusted_data`、读 `jump_table_start`、计算 `shell_code_addr`、AAR/AAW 改写、到 `shell_func()` 触发的完整可复现 PoC 与逐段反汇编验证，属于已打通的完整控制流劫持手法。

## 触发条件

- 已具备稳定的 AAR/AAW（如通过 [[binary-pwn-browser-v8-fake-array-jstypedarray-dataptr-aar-aaw]] 构造），可读写任意地址。
- 目标 Wasm 导出函数**必须是首次调用**：非初次调用时 Wrapper 外层会直接把程序流导向真实代码地址，不再经过 `jump_table_start`，篡改无效。
- 已知 `WasmInstanceObject → trusted_data(+0x8, 高 32 位) → jump_table_start(+0x28)` 的对象布局，以及真实代码/JIT-Spray 载荷相对 `jump_table_start` 的固定偏移（需按版本实测，文中 `0x89c`）。
- 环境为去除 Sandbox 或已完成沙盒逃逸，且 Wasm 代码页可执行（JIT-Spray 载荷可用）。

## 利用步骤

1. 构造含 JIT-Spray 浮点立即数汇编的 Wasm 模块，取 `shell_wasm_instance.exports.main` 作为待首次调用的函数（先不要调用）。
2. `addrof(shell_wasm_instance)` 得到实例对象地址；`aar(instance_addr + 0x8)` 取高 32 位得到 `WasmTrustedInstanceData` 地址。
3. `aar(trusted_data_addr + 0x28)` 读出 `jump_table_start`。
4. 计算错位 shellcode 地址 `shell_code_addr = jump_table_start + 0x89c`（偏移按实测调整）。
5. `aaw(trusted_data_addr + 0x28, shell_code_addr)` 把对象内的 `jump_table_start` 指针改成 shellcode 地址。
6. 调用 `shell_func()`（必须初次调用）：Wrapper 正常走 LazyCompile，编译完成后从被篡改的字段取目标并 `jmp`，落入错位 shellcode，控制流被劫持。

## PoC

```javascript
// 前置：已有 addrof()/aar()/aaw()/f2i()，且 shell_wasm_instance.exports.main 尚未调用
let inst = addrof(shell_wasm_instance);
let trusted = f2i(aar(inst + 0x8n)) >> 32n;
let jump_table_start = f2i(aar(trusted + 0x28n));
let shell_code_addr = jump_table_start + 0x89cn;   // 固定偏移按版本实测
aaw(trusted + 0x28n, shell_code_addr);
shell_func();   // 一定是初次调用
```

其中 `shell_wasm_code` 为包含 `0x00,0x61,0x73,0x6d` 魔数、以 `f64.const` 浮点立即数承载 JIT-Spray 字节序列的 Wasm 模块，`main` 为导出函数。最小载荷即上述定位—改写—首次调用三步；无自动化利用脚本（依赖具体版本偏移与已有 AAR/AAW）。

## 变体与关联

- **旧方法对比**：过去常通过向 Wasm RWX 空间写 shellcode、或篡改 `Function → Code → instruction_start` 走 JIT-Spray；随版本演进这些手法受限，本卡利用的是"Wrapper 与 CompileLazy 读取 jump_table_start 来源不同"这一时序/来源差异。
- **前置依赖**：与"覆盖 WasmTrustedInstanceData.jump_table_start 控制执行流"同源思路，本卡进一步解释了为什么改该字段不破坏 JSToWasmWrapper 与 LazyCompile 的正常流程，以及为何必须首次调用。
- **载荷变体**：JIT-Spray 字节可换成其它可执行片段；只要保证错位入口落在 `jump_table_start + 固定偏移` 处，并让编译后的跳转目标指向它。
- **关联卡**：读写原语见 [[binary-pwn-browser-v8-fake-array-jstypedarray-dataptr-aar-aaw]]。

## 检测与防御

- **完整性校验**：对 `WasmTrustedInstanceData.jump_table_start` 及编译后的跳转目标做来源/范围校验，确保指向 V8 分配的 jump table 或已编译代码区，而非任意地址。
- **W^X 与 CFI**：Wasm/JIT 代码页严格 W^X，配合 CFI/CET/影子栈，降低"跳入错位字节序列"可执行的风险。
- **隔离与随机化**：把 trusted data 放在受保护/隔离区域、随机化 jump table 与代码相对偏移，破坏"固定偏移可预测"这一前提。
- **Sandbox**：沙盒隔离使外部无法直接改写 trusted instance 数据；沙盒逃逸本身是独立前置条件。
- **检测**：监控 Wasm 实例 trusted data 字段被异常写入、首次调用前 jump_table 目标被改写、以及从 JIT 代码区非函数入口处开始执行的异常控制流。
