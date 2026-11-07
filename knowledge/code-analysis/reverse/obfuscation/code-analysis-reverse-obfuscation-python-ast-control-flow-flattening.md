---
id: code-analysis-reverse-obfuscation-python-ast-control-flow-flattening
title: Python AST 控制流平坦化：py2cfg + 状态机 switchVar 重写函数体
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: python-ast-control-flow-flattening
aliases:
- Python 控制流平坦化
- OLLVM Python
- py2cfg
- switchVar 状态机
- AST CFF
- 控制流混淆
tags:
- python
- ast
- obfuscation
- control-flow-flattening
- py2cfg
- ollvm
- cff
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:50:07+08:00'
  notes: 已对照原文核对：py2cfg CFG、LCG状态值、while/for/break/continue归一化、state状态机、random.shuffle均一致；原文代码未运行，卡内confidence=medium。
---

## 一句话结论

用 `py2cfg` 构建 Python 函数的控制流图，把每个基本块分配唯一状态值并改写成 `state = 初始块; while True: if state == 块ID: ...; state = 后继块` 的状态机，同时把 `while`/`for`/`break`/`continue` 归一化，可把原始控制流打散并按随机顺序排列，形成 OLLVM 风格的控制流平坦化，显著增加静态阅读和 CFG 恢复成本。

## 原理

- `py2cfg` 把函数解析成基本块（statements、exits、predecessors）；每个基本块可以分配一个随机/唯一 ID，作为 OLLVM 中的 `switchVar`。
- 目标是把“块之间直接跳转”改成“一个无限循环 + 状态变量分派”：函数入口先 `state = 初始块ID`，循环第一句检查 `state == 结束状态` 则 `break`，之后每个块对应一个 `if state == 块ID:`，执行块语句后把 `state` 设为后继块 ID；有两个后继的块用原 `if` 条件决定 `state` 走哪一支。
- 循环需要先归一化，否则状态机难以正确表达：
  - 条件 `while`：生成一个与原条件相同的 `If` 块，复制跳转关系，并增加指向循环结束块的边。
  - `while True`：调整前驱/后继边，把循环体最后一个块直接连回循环体第一个块。
  - `for`：改写为 `iter_var = iter(iterable)` → `step_var = next(iter_var, None)` → `if step_var is not None` → `target = step_var` → 循环体；结束条件用 `if` 的相反分支指向循环结束块。
  - `break`/`continue`：从基本块中删除 `break`/`continue` 语句，或删除只有一个语句的块并把前驱重新连到后继，保留条件跳转关系。
- 分配 ID 可用自定义 LCG（线性同余）生成唯一数，避免 ID 规律泄露块顺序；最后 `random.shuffle(loop_body)` 打乱 `if` 块的排列，使文本顺序不再对应执行顺序。
- 用 `ast.fix_missing_locations` + `ast.unparse` 输出新函数体；原始语句被保留在 `if state == 块ID` 分支中，语义不变。

## 触发条件

- 目标为 Python 源码，函数可被 `py2cfg` 正常构建 CFG；代码中的控制流结构（if/while/for/break/continue）能被解析。
- 运行环境安装 `py2cfg`，Python 3.9+ 可用 `ast.unparse`（文章使用 `ast.unparse`）。
- 函数体不能包含 `py2cfg` 无法建模的动态控制流（如 `exec` 生成代码、异常驱动的复杂跳转）；异常处理/`try` 结构可能需要额外处理。
- 混淆后的函数仍需保持语义正确，需有测试用例验证。

## 利用步骤

1. 用 `py2cfg.CFGBuilder().build_from_file` 构建模块 CFG，按 `functioncfgs` 遍历每个函数的基本块。
2. 为每个基本块分配唯一状态值（自定义 LCG 或随机数），同时处理循环头、循环结束块和 `break`/`continue`。
3. 归一化 `while`/`for`：条件 while 生成 `If` 块；`while True` 重连前驱/后继；`for` 改写成 `iter`/`next`/`if`/赋值四段。
4. 生成状态机：`state = 初始块ID`；`while True` 第一句 `if state == 结束ID: break`；每个块一个 `if state == 块ID:`，块语句后更新 `state`；双后继块用原条件生成 `if/else` 更新 `state`。
5. `random.shuffle` 打乱各 `if` 块的顺序，降低文本可读性。
6. 用新的函数体替换 `FunctionDef.body`，`fix_missing_locations` 后 `ast.unparse` 输出，运行测试用例验证。
7. 可与变量/属性重命名叠加，进一步混淆；见 [[code-analysis-reverse-obfuscation-python-ast-identifier-attribute-rename]]。

## PoC

手写的最小状态机形态（说明平坦化后的结构，非生成器输出）：

```python
def f(x):
    state = 1
    while True:
        if state == 1:
            if x > 0:
                state = 2
            else:
                state = 3
        elif state == 2:
            return x
        elif state == 3:
            return -x
        else:
            break
```

文章生成器的关键逻辑（示意）：

```python
switch_assign = Assign(targets=[Name(id='state', ctx=Store())],
                       value=Constant(value=blocks_state[blocks[0]]))
end_case_stmt = If(test=Compare(left=Name(id='state', ctx=Load()),
                                ops=[Eq()],
                                comparators=[Constant(value=end_case_state)]),
                   body=[Break()], orelse=[])
# 每个 block 生成 if state == blocks_state[block]: <statements>; state = 后继ID
loop = While(test=Constant(value=True), body=loop_body, orelse=[])
func_new_bodys[func_name] = [switch_assign, loop]
```

## 变体与关联

- 变体：原生 OLLVM 的 LLVM IR 层控制流平坦化（基本块分割、dispatch/return、虚假控制流、指令替换）；见 [[code-analysis-reverse-obfuscation-llvm-pass-implementation]]、[[code-analysis-reverse-obfuscation-ollvm-cff-bcf-substitution]]。
- 变体：用 `switch`/字典分派、增加不透明谓词、克隆块、随机控制流，进一步提高 CFG 复杂度。
- 变体：只做 AST 标识符重命名，不做控制流平坦化（更轻量）；见 [[code-analysis-reverse-obfuscation-python-ast-identifier-attribute-rename]]。
- 关联：[[code-analysis-reverse-obfuscation-go-ast-cross-file-obfuscation]]（AST 层混淆的另一语言实现）。
- 边界：`try/except/finally`、生成器、`yield`、异常控制流和动态 `exec` 可能无法被简单状态机正确建模；`py2cfg` 对复杂语法支持有限时需退回手工处理。

## 检测与防御

- 检测：函数体出现 `state = 常量; while True: if state == 常量: ...` 的重复结构，块顺序与业务逻辑不一致；大量随机状态值与 `random.shuffle` 痕迹；CFG 中基本块数量异常但语义简单。
- 防御：用符号执行/CFG 恢复/去平坦化工具还原状态机；动态执行并记录实际路径；对 `while True` + 状态变量 + 大量 `if` 的模式做规则告警。
- 加固：混淆只提高分析成本，不能替代行为监控；对 Python 代码做完整性校验，防止被篡改后重新分发；分析侧可结合 AST 规范化与动态 trace 交叉验证。
