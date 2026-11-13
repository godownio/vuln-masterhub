---
id: code-analysis-reverse-obfuscation-jsr-ret-pop-swap-decompiler-deception
title: JSR/RET 叠加 POP/SWAP 的控制流欺骗：JVM 运行时执行真实代码，IDEA/FernFlower 反编译展示虚假代码
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: jsr-ret-pop-swap-decompiler-deception
aliases:
- JSR RET 混淆
- POP SWAP 反编译欺骗
- 运行时真码反编译假码
- FernFlower JSR 处理缺陷
- Y4Calculator 原理
tags:
- java
- bytecode
- asm
- obfuscation
- anti-decompilation
- jsr
- ret
- control-flow
- fernflower
- supply-chain
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V616
  verified_at: '2026-11-12T20:49:22+08:00'
  notes: 已通读原文 content.md 并逐张核对 61 张图片：jsr 压栈返回地址、astore/ret 回跳与两段 jsr+pop 构造（图 39/42/43-45）一致；运行时 POP 弹掉 RA2 后 RET 回 RA1 执行 Real Code、IDEA 分析走 Fake Code（图 45-47）与原文动画/描述一致；Y4Calculator 反编译显示 6+6=?+(var0+var1) 而实际输出 Y4tacker666（图 40/48）吻合；SWAP 变体交换 RA1/RA2 并导致新版 IDEA 反编译失败（图 49-51 $FF Couldn't be decompiled）一致；ControlFlowGraph.setSubroutineEdges 仅维护 jsrstack、不建模 pop/swap 的源码依据见图 41；JVMS §3.13 class 版本 50.0 及以下支持 jsr 的表述见图 38。dedup 报告 recommendation=new，top 候选（JSP useBean 注入、JSRPC 签名等）非同链；dup-scan 无涉及 pair。未验证点：未在本机复现；原文称 IDEA 所有版本均可，未逐一版本测试。
---

## 一句话结论

`jsr` 会把下一条指令的返回地址压栈、`ret` 从局部变量取出地址跳回；在两条 `jsr/ret` 子程序之间插入 `pop`（或 `swap`），JVM 真实执行时会弹掉后压入的返回地址 RA2、`ret` 回到 RA1 执行**真实代码**，而 IDEA/FernFlower 的 `ControlFlowGraph.setSubroutineEdges` 只按 `jsr`/`ret` 配对维护 `jsrstack`、不模拟 `pop`/`swap` 的栈操作，反编译视图按未被弹出的 RA2 返回、展示**虚假代码**，实现"看反编译是 A、运行是 B"的定向投毒效果。

## 原理

- **JSR/RET 语义**：`jsr label` 跳转并把"下一条指令地址"压栈；子程序开头用 `astore` 把该地址存入局部变量，末尾 `ret var` 跳回该地址。旧版 `finally` 实现依赖此机制；JVM 为向下兼容仍支持（class 版本 50.0 及以下，见 JVMS §3.13）。
- **构造方式**：`jsr L1; real_code; return; L1: jsr L2; fake_code; return; L2: pop; astore 0; ret 0`。运行时第一次 `jsr` 压入 RA1（real_code 前）、第二次压入 RA2（fake_code 前）；`pop` 弹出 RA2、`astore 0` 保存 RA1、`ret` 跳回 RA1，于是真实执行 `real_code`，`fake_code` 永不执行。
- **反编译器缺陷**：FernFlower 在构建 CFG 时对 `opc_jsr` 把当前块压入 `jsrstack`，对 `opc_ret` 取栈顶对应块的 `exit` 建立子程序边并把 `enter→exit` 记入 `subroutines`；它没有对 `pop`/`swap` 等操作数栈指令建模，仍认为最后一次 `jsr` 的返回地址 RA2 生效，因此把 `fake_code` 当作返回后的正常路径输出，`real_code` 因 `return` 被当作不可达/隐藏。
- **SWAP 变体**：两条 `jsr` 后用 `swap` 交换栈顶两个返回地址再 `astore/ret`，真实执行方向与反编译器分析方向同样相反；在新版 IDEA 中可出现反编译报错/无法反编译。
- **为什么成立**：反编译器的控制流恢复假设"`jsr/ret` 严格成对且两指令之间没有其它栈操作"；手写字节码打破假设后，分析结果与实际执行分歧。JVM 校验器接受该字节码（原文中该构造可正常运行），说明分歧发生在语义层而非非法字节码层。

## 触发条件

- 攻击者可构造/分发 class 或 jar（插件、依赖、补丁包、样本）；
- 受害者用 IDEA/FernFlower（原文称 IDEA 所有版本均受影响）反编译阅读；
- 真实恶意逻辑与展示的虚假逻辑在字节码层面都合法可执行（JVM 校验通过）。

## 利用步骤

1. 用 ASM 生成方法体：`MethodVisitor mv = cw.visitMethod(ACC_PUBLIC|ACC_STATIC, "calc", "()V", null, null);`，`mv.visitCode();`。
2. 写入 `visitJumpInsn(JSR, label1);` → 真实代码 → `visitInsn(RETURN);` → `visitLabel(label1);`。
3. 写入 `visitJumpInsn(JSR, label2);` → 虚假代码 → `visitInsn(RETURN);` → `visitLabel(label2);`。
4. 写入 `visitInsn(POP);`（弹掉 RA2）→ `visitVarInsn(ASTORE, 0);`（保存 RA1）→ `visitVarInsn(RET, 0);`，`visitMaxs(10, 10);`。
5. 用 `ClassWriter.COMPUTE_FRAMES` 生成并保存 class；运行验证执行的是真实代码，反编译查看显示的是虚假代码。
6. 变体：把 `POP` 换成 `SWAP`（两条 `jsr` 后交换 RA1/RA2），按需调整 `astore/ret`，制造反编译报错或另一种展示/执行分歧。

## PoC

```java
// ASM 方法体骨架：运行时执行 Real Code，反编译显示 Fake Code
mv.visitCode();
mv.visitJumpInsn(JSR, label1);
// Real Code Here（真实逻辑，例如命令执行）
mv.visitInsn(RETURN);
mv.visitLabel(label1);
mv.visitJumpInsn(JSR, label2);
// Fake Code Here（给反编译看的无害逻辑）
mv.visitInsn(RETURN);
mv.visitLabel(label2);
mv.visitInsn(POP);              // 运行时弹掉 RA2
mv.visitVarInsn(ASTORE, 0);     // 保存 RA1
mv.visitVarInsn(RET, 0);        // 跳回 RA1 -> Real Code
mv.visitMaxs(10, 10);
mv.visitEnd();
```

```text
// 效果示例（原文 Y4Calculator）
// 反编译视图：System.out.println("6+6=?" + (var0 + var1));  // 展示为 12
// 实际运行输出：Y4tacker666
```

## 变体与关联

- 变体：`swap` 交换返回地址，真实执行顺序与反编译结果再次相反；某些版本直接导致反编译器报错/拒绝反编译。
- 变体：继续调整 `start/end/handler` 标签顺序、交叉 try-catch 结构，制造更多分析器/执行器分歧（可与异常表结构结合）。
- 关联：[[code-analysis-reverse-obfuscation-java-hidden-members-methodparameters]]（隐藏方法/伪造参数名的同类反反编译手法，二者可叠加）、[[code-analysis-reverse-obfuscation-broken-code-alignment-opcode-swallow]]（另一类指令级反分析构造）。

## 检测与防御

- 分析方：遇到含 `jsr/ret` 的现代 class（class 版本 50+ 本不应由 javac 生成）立即警惕；用 `javap -c -v` 逐指令核对，确认 `jsr` 与 `ret` 之间是否存在 `pop/swap` 等栈操作；用 JVM 实际运行/插桩验证真实路径，不要只依赖反编译视图。
- 工具方：反编译器应对非标准 `jsr/ret` 序列（两条 jsr 之间无 astore、存在 pop/swap）报"无法可靠恢复控制流"而不是给出误导性输出。
- 检测：扫描分发包中同时含 `JSR` 指令与非编译器生成模式（无 `finally` 对应结构、`jsr` 后直接业务指令）的类；对高风险插件做动态执行与行为监控。
