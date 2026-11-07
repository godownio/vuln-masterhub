---
id: code-analysis-reverse-obfuscation-llvm-pass-implementation
title: LLVM 混淆 Pass 实现：基本块分割、控制流平坦化、虚假/随机控制流与指令/常量替代
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: llvm-obfuscation-pass-implementation
tags:
- obfuscation
- llvm
- ollvm
- control-flow-flattening
- bogus-control-flow
- instruction-substitution
- constant-substitution
- pass
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V121
  verified_at: '2026-11-06T04:11:29+08:00'
  notes: 已对照原文及56张图核对：splitBasicBlock 分割、dispatch/return+switch 平坦化、DemotePHIToStack/DemoteRegToStack、BCF 不透明谓词与 clone 块、rdrand 随机控制流、指令/常量替代公式均与原文一致；原文 TEA 常量笔误 0x9e3779b 已注明（实际 delta 0x9e3779b9，示例表达式对应 7 位值）；LLVM 4.0/OLLVM 为工具链环境，无受影响版本；Pass 未本机编译执行
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-llvm-pass-implementation/
draft: false
kb_aliases:
- LLVM 混淆 Pass
- 基本块分割
- 控制流平坦化实现
- 虚假控制流实现
- 随机控制流
- 指令替代
- 常量替代
- OLLVM Pass
---

## 一句话结论

在 LLVM IR 层用 `FunctionPass` 可以系统化实现基本块分割、控制流平坦化（dispatch/return + switch 状态变量）、虚假控制流（不透明谓词 + 克隆块）、随机控制流（rdrand + 等价变换）以及指令/常量替代；这些变换保持语义不变，却显著增加 CFG 复杂度与静态分析成本，是 OLLVM 及其变体的核心实现思路。

## 原理

- **基本块分割**：把一个大基本块按指令数切成若干等价块，块间加无条件跳转；块数越多，后续平坦化/虚假控制流的复杂度越高。含 PHI 的块需跳过或先降级，否则前驱关系被破坏。
- **控制流平坦化（CFF）**：保存除入口块外的所有原基本块；创建 `dispatchBB` 与 `returnBB`；入口块 `alloca` 一个 switch 变量并初始化为随机 case；`dispatchBB` 用 `switch` 分发；每个原基本块末尾把 switch 变量改成后继块的 case 并跳到 `returnBB`；条件跳转用 `select` 选择 true/false 后继的 case。
- **PHI/逃逸变量修复**：平坦化后所有原基本块的前驱都变成分发块，PHI 失效；用 `DemotePHIToStack` 把 PHI 降级为 `alloca/store/load`，用 `DemoteRegToStack` 把跨块引用的逃逸变量降级到栈，并把 `alloca` 统一放到入口块。
- **虚假控制流（BCF）**：把基本块拆成 entry/body/end 三块，克隆 body 得 cloneBB；把 entry→body、body→end 的无条件跳转改成条件跳转，条件为恒真不透明谓词（如 `y < 10 || x*(x+1)%2 == 0`）；cloneBB 跳回 body，形成永不执行的假路径。
- **随机控制流**：与 BCF 类似拆分/克隆，但用 `rdrand` 生成随机数，经恒等变换（如 `x*(x+1)-x^2`）后按奇偶随机跳转到 body 或 cloneBB；不存在不可达块/不透明谓词，因此“消除不透明谓词/符号执行删不可达块”的反混淆失效。
- **指令替代**：把 `a+b` 换成 `a-(-b)`、`a^b` 换成 `(~a&b)|(a&~b)` 等等价序列，可叠加随机数恒等变换；仅对整数做，避免浮点舍入误差。
- **常量替代**：把 32 位常量换成复杂表达式（原文示例：常量 `0x9e3779b` → `12167*16715+18858*32146-643678438`；TEA delta 实为 `0x9e3779b9`，原文示例少写一位），可扩展为常量数组/字符串替代，抹去 AES/DES 特征表与明文字符串。

## 触发条件

- 能修改/扩展 LLVM 工具链（OLLVM、Hikari、Pluto 或自写 Pass），并在构建流程中用 `opt -load <pass>.so -<pass>` 应用。
- 目标为 C/C++ 等编译到 LLVM IR 的项目；需要保护的是核心函数而非全部代码（体积/性能约束）。
- 反混淆方主要依赖静态 CFG/签名/常量特征，缺少动态行为监控。
- 目标函数不含无法降级的 PHI/异常表/调试元数据依赖，或已做相应修复。

## 利用步骤

1. 实现 `FunctionPass`：缓存原基本块，跳过/降级含 PHI 的块，按 `split_num` 分割。
2. 实现 CFF：创建 dispatch/return 块，入口块 `alloca` + `store` 随机 case，`switch` 分发；每个原块末尾 `store` 后继 case 并跳 return；条件跳转用 `select`。
3. 调用 `DemotePHIToStack`/`DemoteRegToStack` 修复 PHI 与逃逸变量，所有 `alloca` 移到入口块。
4. 实现 BCF：拆分 entry/body/end，克隆 body 并修复 VMap 操作数；插入恒真不透明谓词，构造 body↔clone 的假跳转。
5. 实现随机控制流：`Intrinsic::x86_rdrand_32` 生成随机数，恒等变换后按奇偶跳转 body/clone；用 `llc -mattr=+rdrnd` 编译。
6. 实现指令/常量替代：遍历 `BinaryOperator`，按操作码替换为等价序列；常量替换仅处理 32 位整数。
7. 注册 Pass、编译 `.so`，用 `opt -load` 应用，IDA/Ghidra 对比 CFG 与常量特征。

## PoC

```cpp
// 基本块分割核心
int splitSize = (BB->size() + splitNum - 1) / splitNum;
BasicBlock *curBB = BB;
for (int i = 1; i < splitNum; i++) {
    int cnt = 0;
    for (Instruction &I : *curBB) {
        if (cnt++ == splitSize) { curBB = curBB->splitBasicBlock(&I); break; }
    }
}
```

```cpp
// 平坦化：分发块 + switch 状态变量
BasicBlock *dispatchBB = BasicBlock::Create(F.getContext(), "dispatchBB", &F, &entryBB);
BasicBlock *returnBB   = BasicBlock::Create(F.getContext(), "returnBB", &F, &entryBB);
BranchInst::Create(dispatchBB, returnBB);
entryBB.moveBefore(dispatchBB);
entryBB.getTerminator()->eraseFromParent();
BranchInst *brDispatchBB = BranchInst::Create(dispatchBB, &entryBB);
int randNumCase = rand();
AllocaInst *swVarPtr = new AllocaInst(TYPE_I32, 0, "swVar.ptr", brDispatchBB);
new StoreInst(CONST_I32(randNumCase), swVarPtr, brDispatchBB);
LoadInst *swVar = new LoadInst(TYPE_I32, swVarPtr, "swVar", false, dispatchBB);
BasicBlock *swDefault = BasicBlock::Create(F.getContext(), "swDefault", &F, returnBB);
BranchInst::Create(returnBB, swDefault);
SwitchInst *swInst = SwitchInst::Create(swVar, swDefault, 0, dispatchBB);
for (BasicBlock *BB : origBB) {
    BB->moveBefore(returnBB);
    swInst->addCase(CONST_I32(randNumCase), BB);
    randNumCase = rand();
}
```

```cpp
// 虚假控制流的不透明谓词：y < 10 || x*(x+1)%2 == 0
ICmpInst *cond1 = new ICmpInst(*insertAfter, CmpInst::ICMP_SLT, y, CONST_I32(10));
BinaryOperator *op1 = BinaryOperator::CreateAdd(x, CONST_I32(1), "", insertAfter);
BinaryOperator *op2 = BinaryOperator::CreateMul(op1, x, "", insertAfter);
BinaryOperator *op3 = BinaryOperator::CreateURem(op2, CONST_I32(2), "", insertAfter);
ICmpInst *cond2 = new ICmpInst(*insertAfter, CmpInst::ICMP_EQ, op3, CONST_I32(0));
return BinaryOperator::CreateOr(cond1, cond2, "", insertAfter);
```

## 变体与关联

- OLLVM 命令行开关：`-mllvm -fla`（平坦化）、`-mllvm -bcf`（虚假控制流）、`-mllvm -sub`（指令替代）、`-mllvm -split`/`-split_num`。
- 进阶：虚拟机混淆（VMProtect）、常量数组/字符串替代、控制流伪随机化（Hikari/Pluto）。
- 关联：[[code-analysis-reverse-obfuscation-ollvm-cff-bcf-substitution]]（OLLVM 使用层）、[[code-analysis-reverse-obfuscation-ollvm-cff-frida-trace]]（Frida 追踪平坦化）、[[code-analysis-reverse-obfuscation-ollvm-instruction-substitution-frida-register]]（指令替代逆向）。

## 检测与防御

- 检测：CFG 出现集中分发块 + switch 状态变量、长条状虚假路径、恒真不透明谓词、等价指令序列、被替换的常量表。
- 反混淆：符号执行/约束求解识别不透明谓词与不可达块；CFG 恢复/去平坦化；常量折叠与指令化简；动态 trace 辅助。
- 防御：对核心函数做多层混淆并配合反调试/完整性校验；不要把混淆当唯一防线，运行时行为仍会暴露。
