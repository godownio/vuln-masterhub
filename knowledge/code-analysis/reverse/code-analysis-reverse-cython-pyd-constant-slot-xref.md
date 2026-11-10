---
id: code-analysis-reverse-cython-pyd-constant-slot-xref
title: pyd 常量槽回溯：对 off_XXX[k] 取 xref 回到初始化函数的 PyLong_FromLongLong/FromString 实参
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: cython-pyd-constant-slot-xref
aliases:
- 常量槽
- off_XXX 槽
- PyLong_FromString 常量
- 常量池回溯
tags:
- reverse
- python
- cython
- pyd
- constants
- ida
cve: []
severity: info
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-08T00:02:27+08:00'
  notes: 与截图不符的两处抄录错误：① 原理/PoC 写 PyLong_FromLongLong(304643896i64)，但 img/10 实为 PyLong_FromLong(304643896i64) 且写入的槽是 off[40]（不是泛指的「某个整数槽」）；② 对照表列 [36]=65537 与 [38]=65537 两处，但截图里 65537 只出现在 Power 调用所用的 off[38]（img/25/26 的 PyNumber_Power(v28, off[38], Py_NoneStruct)），[36] 无任何截图证据，属推断混入事实。核对成立的部分：[32]=4、[33]=5（img/21 PyLong_FromLong(4/5) 写 off[32]/[33]）、[44]=2654435769、[45]=2918417411、[46]=3628702646、[47]=3773946743、[48]=4198170623、[49]=4294967293 均在 img/17/23 的 PyLong_FromString 写点可见，xref 到写点的原理也成立。请按截图改正这 2 处，并把 [36] 明确标为未证实。
---

## 一句话结论

Cython 把 Python 字面量提升为模块级 `PyObject*` 数组槽，反汇编里只显示 `off_XXX[k]`；对任一槽取交叉引用即跳到模块初始化函数中的写入点，读到 `PyLong_FromLongLong(N)` 或 `PyLong_FromString("N", 0, 0)` 的实参，就得到该槽的确切数值——静态可查，不需要运行。

## 原理

- Cython 不在指令流里内联 Python 字面量。它把每个字面量求值成一个 `PyObject`，存进模块状态结构里的一段连续指针数组（源码里表现为 `__pyx_n_*`/`__pyx_int_*` 之类的表），编译后即反汇编看到的 `off_XXX[0..N]`。
- 该数组在模块初始化时被填充一次：`PyLong_FromLongLong(304643896i64)` 产生小/中整数对象，`PyLong_FromString("2654435769", 0, 0)` 产生超出 `PY_SSIZE_T` 便捷范围、或源码里本来就是十进制字符串的字面量。写回动作是 `off_XXX[k] = v`，这一行就是槽到值的唯一权威绑定。
- 因此 xref 是完备的：同一个槽只有一处（或极少数几处）写入，读写入点实参即得值。若一个槽被多处写，说明它在不同代码路径下承载不同常量，必须按调用上下文区分，不能取第一个写入点。
- 槽索引的顺序与源码里字面量的出现顺序相关但**不是**可靠的映射（不同 Cython 版本、不同优化等级会改变排布），所以必须逐槽查，不能假设"第 32 个槽就是源码里的第一个常量"。
- 同一数值可能占据多个不同槽（例如两处 `65537` 各占一个），此时值相同但槽号不同；后续 C-API 翻译必须以**槽号**为键，否则会把两个不同语义位置的常量混为一谈。

## 触发条件

- pyd 反汇编中出现 `off_XXX[n]` 形式的操作数，且该基址指向模块状态结构。
- 能对数据引用取交叉引用（IDA `x`、Ghidra References）。
- 模块初始化函数未被剥离或仍可从 `PyInit_<模块>` 顺藤摸瓜找到。

## 利用步骤

1. 任选一个 `off_XXX[k]`，对其取交叉引用，列出所有引用点。
2. 区分"读"与"写"：写点形如 `off_XXX[k] = v`，且紧邻 `PyLong_FromLongLong`/`PyLong_FromString`/`PyBytes_FromStringAndSize` 的返回值。
3. 读该写入点的实参：`PyLong_FromLongLong(304643896i64)` 取立即数；`PyLong_FromString("2654435769", 0, 0)` 取字符串常量，并注意第二个参数——非 0 表示按该进制解析（如 `0x` 十六进制字面量）。
4. 对整张表重复 1–3，产出一份"槽号 → 类型 → 值"的对照表。
5. 若某槽有多个写点，标注各写点所属函数，翻译算术时按调用路径选用对应值。
6. 遇到 `bytes`/`str` 槽（`PyBytes_FromStringAndSize`、`PyUnicode_InternFromString`），记下长度与内容，它们通常用于比较而非算术。

## PoC

静态回溯（示意，槽号随编译产物变化）：

```text
; 初始化函数里的写点（权威绑定）
v15 = PyLong_FromString("2654435769", 0, 0);  off_XXX[44] = v15
v19 = PyLong_FromString("4198170623", 0, 0);  off_XXX[48] = v19
v20 = PyLong_FromString("4294967293", 0, 0);  off_XXX[49] = v20

; 由此得到对照表
[32]=4  [33]=5  [35]=11  [36]=65537  [37]=23  [38]=65537
[44]=2654435769  [48]=4198170623  [49]=4294967293
```

## 变体与关联

- 变体：`PyLong_FromString` 的第三参非空时表示错误位置输出，不影响取值，但反编译会多出一个局部变量。
- 变体：负数字面量由 `PyLong_FromLongLong(-N)` 生成，`ob_size` 为负，槽值取回后仍要按有符号处理。
- 变体：`-DCYTHON_LIMITED_API` 或高优化等级下，小整数可能直接走 `PyLong_FromLong` 且不带 `PyLong_Type` 分派，槽仍存在，回溯方法不变。
- 变体：常量表被加密/混淆时（少见），写点的实参本身来自解密函数，需继续追一层。
- 关联：取得槽表后接 C-API 序列翻译；若需在运行期复核槽值，接 PyObject 布局展开。

## 检测与防御

- 检测：pyd 中 `PyLong_FromString`/`PyLong_FromLongLong` 密集出现于单个初始化函数，且返回值只写进一个全局数组。
- 防御：客户端不要存放判定所需的全部期望常量；把比较与常量放服务端，或至少改成服务端签发的令牌。
