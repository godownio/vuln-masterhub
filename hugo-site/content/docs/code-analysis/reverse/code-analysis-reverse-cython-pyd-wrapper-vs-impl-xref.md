---
id: code-analysis-reverse-cython-pyd-wrapper-vs-impl-xref
title: Cython pyd 双层交叉引用定位：对 "<模块>.<函数>" 取 xref 得两处，第二处 __pyx_pf_* 才是实现体
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: cython-pyd-wrapper-vs-impl-xref
tags:
- reverse
- python
- cython
- pyd
- ida
- cross-reference
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-07T22:51:51+08:00'
  notes: 已对照 content.md 与 img/01-05 核对：img/04 对 aRand0mCheck 取 xref 得两条(sub_...CB17E0+3B / sub_...CB1960+BC3)，与两层(wrapper/实现体)一致；pw/pf 判定特征、cpdef 三处引用等属 Cython 模板知识，未在本机 IDA 复现；本卡无 PoC(定位手法无危害)。
url: /docs/code-analysis/reverse/code-analysis-reverse-cython-pyd-wrapper-vs-impl-xref/
draft: false
kb_aliases:
- Cython 双层引用
- __pyx_pf_ 实现体
- pyd 包装函数
- cython 函数定位
---

## 一句话结论

Cython 编译出的 pyd 里，一个 Python 函数会生成**两层**原生实体：一层是负责参数解析/异常转换的包装函数，另一层是 `__pyx_pf_*` 形式的真正实现体；对字符串窗里的 `"<模块>.<函数>"` 取交叉引用会同时命中这两处，只看第一处（包装层）会误判逻辑，必须跟进第二处。

## 原理

- Cython 用一套固定模板为每个可调用的 Python 函数生成 `__pyx_pw_*`（wrapper）与 `__pyx_pf_*`（实现）两个 C 函数。wrapper 负责把 Python 元组参数拆成 C 变量、校验个数与关键字、把异常转成 Python 异常；真正的算法逻辑只出现在 pf 层。
- 两层之间通过一张字符串常量建立可搜索的联系：模块初始化时会构造 `"模块名.函数名"` 这样的 qualified name 字符串（例如 `rand0m.check`），wrapper 用它做 `PyArg_ParseTuple` 的错误信息与 `__qualname__`，pf 层的引用则来自 Cython 生成的自省结构。因此对这个字符串取 xref 必然得到 ≥2 条，且**第一条通常是 pw、第二条是 pf**（顺序由生成模板决定，不应硬信"一定是第二条"，而应按"哪个函数体里出现真正的 C-API 运算"来判定）。
- 判定 pf 而非 pw 的特征：pw 里几乎只有 `PyTuple_GET_ITEM`、`PyArg_ParseTuple`、`PyErr_SetString`、对 pf 的一次调用；pf 里才出现 `PyList_New`/`PyTuple_New`、`PyNumber_*`、`PyLong_From*`、`Py_Dealloc` 这类真正做数据变换的调用。
- 同理，同名模块的字符串常量（`"rand0m"`、`"rand0m.c"`、`"rand0m.pyx"`）会指向模块初始化与元数据构建代码，不是业务逻辑入口，不能作为逆向起点。

## 触发条件

- 目标是 Cython 编译的原生扩展（文件名含 ABI tag，符号区/字符串窗可见 `*.pyx`、`*.c`、`__pyx_` 或模块全名）。
- 反汇编器里能按字符串交叉引用（IDA 的 `x`、Ghidra 的 References to）。
- 已知要分析的 Python 函数名（驱动脚本里 `import 模块; 模块.函数(...)` 可读）。

## 利用步骤

1. 从驱动脚本读出真实调用点，确认模块名与函数名（例如 `rand0m.check`）。
2. 进入字符串窗口，找到完整 qualified name（不是单独的模块名，也不是 `"check"`），列表通常呈现 `模块.c`、`模块.pyx`、`模块`、`模块.函数`、`函数` 这一串，选最长的那条。
3. 对该字符串取交叉引用，得到 N 条（N≥2）。逐条进入函数体，按"是否出现真正的 C-API 数据变换调用"区分 wrapper 与实现体。
4. 选定实现体后，再在实现体内部做下一步（常量槽回溯或 C-API 序列翻译）。
5. 若 xref 只出现 1 条，说明该函数被内联或已被剥离符号，改用"从 wrapper 的调用目标往下跟一层"取得 pf。

## PoC

无 PoC（本原子为定位手法，无危害可演示；效果体现为"能正确进入实现体而非包装层"）。

## 变体与关联

- 变体：`cdef`/`cpdef` 函数与 `def` 函数的生成模板不同，cpdef 还会额外生成 C 层入口，可能得到 3 处引用，需按同样特征挑出真正实现体。
- 变体：`staticmethod`/`classmethod` 的 qualified name 形如 `模块.类.方法`，字符串更长，同样可直接搜。
- 变体：开了 `-DCYTHON_REFNANNY` 或 profiling 后，模板会多出一层间接调用，wrapper 与 pf 之间可能还夹一个 trace 函数。
- 关联：拿到实现体之后通常接着做常量槽回溯（`off_XXX` 槽取值）与 C-API 序列翻译；两者都需要先完成本步。

## 检测与防御

- 检测：pyd 里成对出现的 `__pyx_pw_*`/`__pyx_pf_*` 符号；`*.pyx` 字符串残留。
- 防御：不要在客户端 pyd 中承担判定逻辑；去掉 `.pyx`/`.c` 文件名残留与调试符号只能提高成本，不能阻止本定位手法。
