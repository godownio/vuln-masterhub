---
id: code-analysis-reverse-unpacking-v8-bytecode-register-semantics-to-js
title: 读懂 V8 字节码反汇编的伪 JS：参数/寄存器/累加器模型与 LdaNamedProperty、Star/Mov、CallWithSpread 的还原规则
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: v8-bytecode-register-semantics-to-js
aliases:
- V8 伪汇编还原 JS
- 寄存器 r0 a0 ACC
- LdaNamedProperty 还原
- CallWithSpread 还原
- View8 输出阅读
- Ignition 字节码语义
tags:
- v8
- bytenode
- bytecode
- disassembly
- ignition
- reverse
- unpacking
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:52:55+08:00'
  notes: '已对照原文核对：Parameter count 2/Register count 7/Frame size、CreateRestParameter 8d、Star2、LdaImmutableCurrentContextSlot [2]、GetNamedProperty r4,[1],[0] 与常量池 1=#ipcRenderer、CallWithSpread r3,r4-r6,[4]、常量池 #send 均与图 20 反汇编一致，还原规则与原文 View8 输出（图 22）吻合。未验证点：寄存器语义为读图归纳，未逐条执行验证。'
---

## 一句话结论

改过的 V8 打印出来的每一行形如 `偏移 : 操作码 操作数 助记符`，要还原成 JS 只需抓住三件事：`Parameter count/Register count` 决定形参区（`a0`、`a1`…）与局部寄存器（`r0`、`r1`…）的划分，`ACC` 是隐式累加器（大多数 `Lda*` 往它写、`Star*` 读它），名字化的 `GetNamedProperty r4, [1], [0]` 对应 `寄存器[常量池[1]]` 的属性读、`CallWithSpread r3, r4-r6, [4]` 对应 `r3.call(r4, ...r5, ...)`；把这三条映射做成一张表，就能把几百行伪汇编手工或脚本还原成 `r0 = "path"; r1 = r9["app"]; ...` 这样的可读 JS。

## 原理

- 反汇编头部的 `Parameter count 2` / `Register count 7` 定义了两段寄存器空间：参数区 `a0..a(N-1)` 与局部区 `r0..r(M-1)`；`Frame size` 是栈帧字节数。参数区是调用方传入的实参（`VN` 闭包还会多一个 context），局部区是函数体内赋值的变量。
- `ACC`（累加器）是隐式的：`LdaUndefined`、`LdaImmutableCurrentContextSlot [k]`、`LdaNamedProperty`、`LdaGlobal` 等都是「写 ACC」；`Star0..StarN` 是「ACC → rN」；`Mov rX, rY`（含 `Mov a0, r0`）是寄存器间复制。因此 `Mov a0, r0` + `Star2` 这类组合常在函数序言里搬运实参。
- `GetNamedProperty r4, [1], [0]`：第一操作数是承载对象的寄存器，第二个 `[1]` 是**常量池索引**（不是立即数），第三个 `[0]` 是反馈槽（内联缓存的位置，还原时可忽略）；常量池里 `1: <String[11]: #ipcRenderer>` 说明这是 `r4["ipcRenderer"]`（`#` 前缀表示内部化字符串/私有名）。
- `CallWithSpread r3, r4-r6, [4]`：`r3` 是被调函数，`r4-r6` 是实参寄存器区间，`[4]` 是反馈槽；语义是 `r3(r4, ...r5)`（区间里最后一个带 `...` 由 `CreateRestParameter`/spread 决定），返回值落 ACC（随后被 `Star*` 存下）。
- `LdaImmutableCurrentContextSlot [k]` / `ThrowReferenceErrorIfHole [0]` 成对出现，是闭包读取当前上下文的槽位（`let/const` 的 TDZ 检查），说明这时在解构/引用外层变量。
- `Constant pool (size = n)` 后逐条列出被抓取的对象：字符串、`SharedFunctionInfo`（内联函数）、`ObjectBoilerplateDescription`（对象字面量，即图里返回的 `r10 = new r2({...})` 的骨架）、`FixedArray` 等；还原字面量必须靠这张表。
- 还原顺序建议：先按 `Star/Mov` 建立「寄存器 ← 表达式」的 SSA 式映射，再按源码位置（`155 E>` 这类 `source position`）对齐控制流；遇到 `CreateRestParameter` 就把它当 `...args` 展开。
- 为什么这值得单独成卡：不同版本 V8 的操作码编号会变（`8d` 是 `CreateRestParameter` 在 10.4 的编码，别的版本可能不同），但「操作数怎么读、哪个是常量池索引、ACC 怎么流」这套语义是稳定的；学会读语义，换成 `d8 --print-bytecode` 或别的工具输出也能直接读。

## 触发条件

- 已拿到一份字节码反汇编文本（自己编译的 V8 输出、官方 d8 的 `--print-bytecode`、或第三方解析器的中间产物）。
- 需要把伪汇编还原成高层 JS（判断某函数拼的是哪个 URL/path、调了哪个 IPC channel、校验逻辑是什么）。
- 手头有该版本的 V8 源码（`src/interpreter/bytecodes.h` 可查操作码编号与操作数类型），用于确认不认识的 opcode。

## 利用步骤

1. 记下头部 `Parameter count`/`Register count`，画一张寄存器表：`a0..a(N-1)` 为形参，`r0..r(M-1)` 为局部变量。
2. 顺序扫指令，遇到 `Lda*` 就往 ACC 写、遇 `Star*` 就把 ACC 落到寄存器、遇 `Mov` 就复制；把每条写成一行伪 JS 并保留源码位置列作为行号。
3. 遇到 `GetNamedProperty rX, [k], [f]`：查 `Constant pool` 的第 k 项，写成 `rX.<名字>` 或 `rX["名字"]`（`#name` 去掉 `#`）。
4. 遇到 `Call*/CallWithSpread`：按「第一个寄存器 = 被调方，区间 = 实参」写成 `被调(...实参)`，返回值为 ACC。
5. 遇到 `CreateObjectLiteral [k]` / `new r2({...})` 时，从常量池的 `ObjectBoilerplateDescription` 里补齐字段名与默认值（默认值常是 `null`，运行时再用 `r12 = ...` 逐个覆写）。
6. 用 `src/interpreter/bytecodes.h` 对照不认识的 opcode（编号与版本绑定），必要时换成同版本的 `d8` 复现。
7. 还原完后用「函数名/文件名」标注每个片段（如 `func_unknown_10` 实际是 `index.js` 的 `func_start_0`），再按调用关系统一成一条数据流。

## PoC

```text
# 原文样本片段（V8 10.4 字节码）→ 还原规则映射
Parameter count 2 ; Register count 7
  0 : 8d              CreateRestParameter          ; => r? = ...rest
  1 : c8              Star2                        ; => r2 = ACC
  8 : 17 02           LdaImmutableCurrentContextSlot [2]   ; => 读闭包槽位 2
 13 : af              Return                        ; => return ACC

# 属性读 + 调用
180 E> ... 2f f5 01 00  GetNamedProperty r4, [1], [0]  ; Constant pool [1] = <String[11]: #ipcRenderer>
     => r4["ipcRenderer"]
     67 f6 f5 03 04     CallWithSpread r3, r4-r6, [4]  ; => r3(r4, ...r5)

# 对应还原出的 JS（摘自样本 index.js）
# r0 = "path"; r1 = r9["app"]; r10 = "./launcher.js"; r11 = r1["getPath"]("appData");
# r12 = r1["getName"](); r9 = r0["join"](r11, r12); ...
```

## 变体与关联

- 变体：用 View8 一类工具自动做「伪汇编 → 伪 JS」，工具内部就是这套寄存器/常量池映射；遇到它输出 `func_unknown_N` 时按本卡规则人工补名。
- 变体：`--print-bytecode` 的官方输出带 `ACC` 显式注释，不用自己推累加器，但要拿到同样的反汇编仍需源码。
- 变体：闭包函数（`SharedFunctionInfo` 出现在常量池里）会以 `[k]` 引用内联函数，需递归展开，不能只读一层。
- 关联：[[code-analysis-reverse-unpacking-v8-code-cache-disassembler-patch]]（怎么产出这份反汇编）、[[code-analysis-reverse-unpacking-v8-bytecodeinfo-embedded-code-cache-extract]]（字节码从哪来）。
- 边界：不同 V8 版本的 opcode 编号与操作数编码会变（例如 `LdaNamedProperty` 的反馈槽参数布局在各版本间调整过），跨版本照抄编号必错；`Mov a0, r0` 之类的搬参在寄存器分配变化后形态也会变。

## 检测与防御

- 检测（分析方）：反汇编里出现 `CreateRestParameter`/`CallWithSpread`/`#ipcRenderer`/`#send` 这类 Electron IPC 特征时，说明该客户端把渲染进程通信与路径拼装逻辑放在了字节码里。
- 防御（开发方）：即便用字节码保护，字符串常量名（`#ipcRenderer`、channel 名）依然明文可见；不要把「channel 名即权限」当作安全设计，主进程侧必须独立校验来源与服务。
- 加固：敏感逻辑上移服务端；客户端只暴露受控 API，且对来自渲染进程的 IPC 做白名单与参数校验。
