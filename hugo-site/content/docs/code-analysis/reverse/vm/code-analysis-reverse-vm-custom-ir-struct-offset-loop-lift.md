---
id: code-analysis-reverse-vm-custom-ir-struct-offset-loop-lift
title: 自定义反编译器 IR 中间代码语义还原：结构体偏移、临时变量与循环模式机械化提升为 C 伪代码
type: scenario
domain: code-analysis
path: code-analysis/reverse/vm
technique: custom-ir-textual-semantics-lift
tags:
- reverse-engineering
- ctf
- ir
- intermediate-representation
- decompiler
- bytecode
- pattern-recognition
- vm
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V586
  verified_at: '2026-11-12T14:09:33+08:00'
  notes: 已对照原文(5844字符)与唯一截图核对：截图菜单 1.get IR/2.get asm/3.get bin/4.input code/5.exit 与卡片触发条件一致；原文 STRUCT exp 为 key(int)[24]<+0>、L(int)[8]<+192>、R(int)[8]<+256>、X(int)[8]<+320>，卡内原误写 R<+192>，已修正；地址算术中的 <+8> 原文仅注释为'获得 exp 结构体数组的起始地址'（其后的 <+488> 为 var22 栈槽、<+tempa>=i*8 为下标），原卡把 <+8> 当作加法并入地址，已改写为元素大小相关地址描述项以免误导；循环结构原文本例为'条件 GOTO 进入循环体、末尾无条件 GOTO 回跳、不满足时 GOTO 出口'，已修正原卡'向回跳转的条件 GOTO'表述。第一循环 key[23-i]=input[i]、第二循环 key[i]-=key[i-1] 与原文一致；8 轮 L/R/X 定点加减（key[L[i]]+=X[i], key[R[i]]-=X[i]）与内置密文按 key[i*3] 加减、前缀和、逐字节比较均与原文伪代码一致；int 8 字节/char 1 字节与原文一致。原文未给出最终 flag、未附附件内容，卡内 PoC 为模式示意与等价伪代码（卡内已注明非逐行拷贝），不虚构 flag。dedup top 候选（Binary Ninja 自定义 ISA、Unity Compute Shader VM、各类自定义字节码 VM 等）均为具体题解/插件实现，与本卡'文本 IR 语义提升方法论'不同链，new 成立；dup-scan.json 不含本卡。原文无受影响版本/CVE，versions 保持空。未执行任何二进制或 PoC。
url: /docs/code-analysis/reverse/vm/code-analysis-reverse-vm-custom-ir-struct-offset-loop-lift/
draft: false
kb_aliases:
- Syclang IR 分析
- 2023 SCTF Syclang
- 中间指令分析
- 自定义 IR 逆向
- 反编译器中间代码
- IR 提升为 C 伪代码
---

## 一句话结论

面对题目自带反编译器输出的自定义文本 IR（结构体/数组带字节偏移、`#常量`、临时变量、`<+off>` 栈槽、`::=` 赋值、`@struct.field[0]` 取基址、`IF/GOTO` 循环、`CALL`），只要把“偏移算术=数组下标 × 元素大小”“label+条件 GOTO=循环”“栈槽偏移=变量身份”这三条映射规则机械化套用，就能把数百行 IR 逐段提升为等价 C 伪代码并还原出校验算法；2023 SCTF Syclang 即用该法还原出 24 字节输入的“逆序拷贝→差分→8 轮定点加减→前缀和”加密流程。

## 原理

- **IR 的变量模型**：函数声明为 `FUNCTION name - frame_size`，每个局部变量用 `<+偏移>` 标识栈帧位置（如 `var15<+56>`、`var22<+488>`）；同一偏移始终对应同一变量，因此可先建立“偏移 → 变量”映射表，忽略临时变量名。
- **结构体/数组模型**：`STRUCT exp : ARRAY .key(int)[24]<+0> ... ARRAY .L(int)[8]<+192> ... ARRAY .R(int)[8]<+256> ... ARRAY .X(int)[8]<+320>` 给出字段相对基址的字节偏移；本例 `int` 占 8 字节、`char` 占 1 字节，字段偏移与元素大小决定后续一切地址计算。
- **地址算术**：形如 `tempa := {#8}*{var16<+64>}` 的临时变量就是“下标 × 8”；随后 `var22(@exp.key[0])<+8><+488><+tempa>` 由三部分构成：`@exp.key[0]` 定位 key 数组首元素（`<+8>` 是元素大小相关的地址描述项，原文注释称其“获得 exp 结构体数组的起始地址”）、`<+488>` 是 var22 的栈槽基址、`<+tempa>`（i*8）是下标偏移，整体即 `&var22.key[i]`。识别出该模式即可把难读的偏移链还原为数组访问。
- **控制流模型**：IR 用 `LABEL` + `IF 条件 GOTO` 表达分支/循环；本例为“条件 GOTO 进入循环体、末尾无条件 GOTO 回跳、条件不满足时 GOTO 到出口”的结构，把初始化、条件、步进三段抄出即得 `for`。
- **调用与常量**：`temp := CALL read` 对应 `read()` 取输入；`#n` 是立即数，负数常量常以 `#0 - #13` 形式出现，需要折叠。
- **为什么可机械化**：编译器的 IR 由有限模板反复生成，同类循环/数组访问的指令序列高度一致；先识别模板再套语义，比逐条指令硬读更可靠，也便于用差分验证（实现伪代码、加密已知输入、对比密文）。
- **本例还原结果**：第一循环把输入逆序存入 `key[23-i]`；第二循环做相邻差分 `key[i]-=key[i-1]`；初始化 L/R/X 三组索引与增量后，8 轮 `key[L[i]]+=X[i]`、`key[R[i]]-=X[i]`，再做前缀和；对内置密文数组做同样的差分、按 `key[i*3]` 定点加减、前缀和，最后逐字节比较。

## 触发条件

- 逆向目标使用自定义 IR/中间语言或自带反编译器输出（本题提供 `get IR`/`get asm`/`get bin`/`input code` 菜单）。
- IR 语法可读且变量以固定栈偏移表达，无强混淆（无控制流平坦化、无指令编码加密）。
- 已知或可取得一段“输入→输出”对照（本题密文内置），用于验证提升后的伪代码。

## 利用步骤

1. 导出 IR，先抽出 `STRUCT/ARRAY` 定义与 `FUNCTION main - frame`，建立字段偏移表与栈槽表。
2. 逐段扫描 `#!tempa := {#size}*{var}` 模式，标记数组下标计算，把 `<+tempa>` 的偏移链折叠成 `array[i]`。
3. 用 `LABEL`/条件 `GOTO` 切分基本块，识别向回跳转的循环，抄出初始化、条件、步进。
4. 把每个循环提升为 C 伪代码，保留临时变量名并加注释。
5. 用内置密文/已知输入做差分验证：实现伪代码并正向加密，结果应与密文一致；不一致则回到偏移或循环边界修正。
6. 对验证通过的流程逐步求逆（前缀和→差分、定点加减→反向加减、逆序拷贝→逆序），恢复输入（flag）。
7. 若遇到复杂结构，可先写脚本解析 IR 为 AST，再按模板生成伪代码，减少手工错误。

## PoC

```text
# 典型 IR 片段（模式示意）
LABEL label4 :
  temp4 := #24
  IF var15<+56> < temp4 GOTO label3
  GOTO label2
LABEL label3 :
  var16<+64> := var15<+56>
#!tempa := {#1}*{var16<+64>}          // tempa = i * sizeof(char)
  var12<+32> ::= var11<+1><+tempa>    // var12 = input[i]
  temp6 := #23
  temp7 := temp6 - var15<+56>
  var18<+80> := temp7
#!tempa := {#8}*{var18<+80>}          // tempa = (23-i) * 8
  var22(@exp.key[0])<+8><+488><+tempa> := var12<+32>
```

```c
/* 提升后的核心算法（等价伪代码，非原文逐行拷贝） */
for (int i = 0; i < 24; i++)  key[23 - i] = input[i];          // 逆序拷贝
for (int i = 23; i > 0; i--)  key[i] = key[i] - key[i - 1];    // 相邻差分
for (int i = 0; i < 8; i++) {                                  // 8 轮定点加减
    key[L[i]] += X[i];
    key[R[i]] -= X[i];
}
for (int i = 1; i < 24; i++)  key[i] += key[i - 1];            // 前缀和

/* 对内置密文做同样的逆运算后逐字节比较，可解出输入 */
```

## 变体与关联

- 变体：IR 若为二进制字节码而非文本，可先写反汇编器把 opcode 还原成同样可读的三地址码，再套本方法（见关联卡）。
- 变体：遇到控制流平坦化时，先用支配树/数据流恢复真实循环，再进行提升；否则 `LABEL/GOTO` 模式会被分发器打散。
- 关联：[[code-analysis-reverse-vm-binary-ninja-custom-isa-architecture-plugin]]（自定义 ISA 的反编译视图）、[[code-analysis-reverse-vm-unity-compute-shader-bytecode-il2cpp]]（自定义 VM 字节码 + 加密逆推）、[[code-analysis-reverse-php-vld-opcode-llm-decompile]]（另一类中间表示还原）。
- 边界：IR 含指令编码加密、语义等价的指令替换或多层虚拟化时，模板识别会失效，需要先脱敏/解密再到本步骤。

## 检测与防御

- 本节为逆向分析方法，无网络侧检测面。
- 软件保护视角：不要在发布程序中附带输出详细 IR/反编译结果的功能；对中间代码做指令编码加密、控制流平坦化与变量重命名；移除或裁剪符号与调试信息，增加语义还原成本。
- 分析视角：提升后的伪代码务必用输入输出对照做差分验证，避免“看起来合理”的错误还原。
