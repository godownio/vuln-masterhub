---
id: code-analysis-reverse-cython-pyd-py-number-api-translation
title: Cython pyd 的 PyNumber_* 调用序列翻译：按实参顺序还原运算符，识别移位辅助函数、in-place 末参与 32 位收窄
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: cython-pyd-py-number-api-translation
tags:
- reverse
- python
- cython
- cpython-c-api
- arithmetic
- ida
cve: []
severity: info
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-08T00:07:00+08:00'
  notes: 反汇编片段与截图不符：img/25 为 v27 = shift(v6, off[35]=11, 11i64, 1) 后 v30 = PyNumber_Power(v28, off[38]=65537, Py_NoneStruct)，而卡内写成 PyNumber_Power(v13, off_XXX[36], Py_NoneStruct) 并注 t7a=t1**65537：既漏掉 >>11 一步、槽号也写成 36（截图为 38），与同卡 Python 结果里的 (t1>>11) 自相矛盾；另 img/22 的 PyNumber_And 实际是 4 实参 PyNumber_And(v12, v16[48], v17, v18)，卡内写成两实参 PyNumber_And(v15, off_XXX[48])。核对成立部分：img/14 的 PyNumber_Xor(v12, off[44])、img/21 的 sub_shift(v12, off[32]=4, 5i64, 0) 与 PyNumber_Lshift、img/24 的 sub_shift(v3, off[37], 23i64, 0) 与 PyNumber_Add、img/26 的 PyNumber_Remainder(v30, off[49]) 与卡内一致；移位辅助函数「a2=对象、a3=立即数移位量、a4=0/1 选 in-place、a1 为旧值/临时」的读法在 img/21 的 src=off[32]=4、n=5、inplace=0 处成立；16*v20 收窄与 15/62/80 等行号亦与截图一致。请按 img/25 重写 Power 行并区分 And 的 2/4 实参形态。
url: /docs/code-analysis/reverse/code-analysis-reverse-cython-pyd-py-number-api-translation/
draft: false
kb_aliases:
- PyNumber_Xor 翻译
- PyNumber_Power Remainder
- 移位辅助函数
- in-place 变体
- 16 * v20 收窄
---

## 一句话结论

pyd 里的算术不是指令级运算而是 `PyNumber_*` 函数调用；把每个调用按"第一个实参是左操作数、第二个是右操作数（通常是常量槽）"翻译，并识别三类陷阱——移位/幂走包装过的辅助函数、末参为 1 表示 in-place、`PyLong_FromLongLong(16 * v20)` 表示结果被收窄成 32 位——即可逐行还原出等价 Python 表达式。

## 原理

- Cython 保留 Python 语义（大整数、溢出回绕、异常），所以每个运算符都变成对抽象层 API 的调用：`^`→`PyNumber_Xor`，`&`→`PyNumber_And`，`|`→`PyNumber_Or`，`+`→`PyNumber_Add`，`-`→`PyNumber_Subtract`，`*`→`PyNumber_Multiply`，`**`→`PyNumber_Power`（第三参固定为 `Py_NoneStruct`），`%`→`PyNumber_Remainder`。
- 移位没有直接暴露成 `PyNumber_Rshift`：Cython 生成一个内联辅助函数（反汇编里是 `sub_XXX`），内部再按对象类型分派到 `PyNumber_Rshift` 或 `PyNumber_InPlaceRshift`。因此看到 `sub_XXX(a, off_XXX[k], 5i64, 0)` 时，**第 2 参才是参与运算的常量槽/对象，第 3 参是立即数形式的移位量**，第 4 参（0/1）选择非 in-place / in-place 版本——把第 2、3 参读反而会得到"对一个常量做移位"的错误结论。
- `PyLong_FromLongLong(16 * v20)`、`PyLong_FromLong((unsigned int)(...))` 这类紧跟在算术调用之后的构造，是 Cython 把 Python 大整数结果**收窄**成 C 的 32 位无符号（或重新装箱成新对象）的动作；它说明后续运算是在 32 位无符号域内进行，等价 Python 里必须显式写 `& 0xffffffff` 或按无符号语义解释。
- 临时变量的生命周期给出数据流：每个 `PyNumber_*` 返回新引用，引用计数归零处出现 `Py_Dealloc`；因此"谁消费了上一调用的返回值"就是表达式树的连线，`Py_Dealloc` 只挂在不再被使用的中间量上。
- `*(v + 8) != PyLong_Type[0]` 之类的分支把代码分成两条路：类型是 `PyLong` 时走快速路径直接按 `ob_digit` 算（反编译为裸 C 算术），否则回落到 `PyNumber_*`。两条路结果等价，但快速路径分支里看不到 `PyNumber_*`，容易漏读。

## 触发条件

- 已定位到实现体（不是 wrapper），函数体内出现 `PyNumber_*` 或形如 `sub_XXX(..., 立即数, ...)` 的辅助调用。
- 常量槽已可解析（`off_XXX[k]` 能取回值），否则第二个实参无法确定。
- 目标表达式由可逆/可翻译的算术构成；涉及自定义 `__xor__` 等重载方法时只能部分还原。

## 利用步骤

1. 按调用顺序列一张表：左侧临时变量 ← `PyNumber_X(左, 右)`，右侧把 `off_XXX[k]` 替换成已解析的常量值。
2. 遇到 `sub_XXX(a, off_XXX[k], 立即数, 0|1)`：把它读成 `a <移位方向> 立即数`，其中方向由函数内部分派到 Lshift 还是 Rshift 决定（进函数看它调用哪个 `PyNumber_*`）；第 2 参若与"移位量"无关则确认是否被误读。
3. 遇到 `PyNumber_Power(x, slot, Py_NoneStruct)` 后紧跟 `PyNumber_Remainder(结果, slot2)`：还原为 `(x ** slot值) % slot2值`，不要拆成两行独立表达式。
4. 遇到 `PyLong_FromLongLong(16 * v20)` / `(unsigned int)` 强转：在该步骤之后补上 32 位无符号收窄语义（等价 `& 0xffffffff`）。
5. 沿 `Py_Dealloc` 标记剪掉已消费的中间量，把剩余链条串成最终返回表达式；形如 `PyList_New(n)`/`PyTuple_New(n)` 的 n 说明返回值元素个数。
6. 写等价 Python 实现，并用多组输入调用原 pyd 与自写函数做差分比对；全部一致才认为翻译正确。

## PoC

反汇编片段与逐行翻译（示意）：

```text
v13 = PyNumber_Xor(v10, off_XXX[44])                    ; t1 = v10 ^ 2654435769
v14 = sub_shift(v10, off_XXX[33], 5, 0)                 ; t2  = v10 >> 5
v15 = PyNumber_Lshift(v10, off_XXX[32])                 ; t3  = v10 << 4         (槽32=4)
v16 = PyNumber_And(v15, off_XXX[48])                    ; t4  = t3 & 4198170623
v17 = sub_shift(v14, off_XXX[37], 23, 0)                ; t5  = t2 >> 23
v18 = PyNumber_Add(v16, v17)                            ; t6  = t4 + t5
v19 = PyNumber_Power(v13, off_XXX[36], Py_NoneStruct)   ; t7a = t1 ** 65537
v20 = PyNumber_Remainder(v19, off_XXX[49])              ; t7  = t7a % 4294967293
```

```python
def recovered(v):
    t1 = v ^ 2654435769
    t2 = v >> 5
    t3 = v << 4
    t4 = t3 & 4198170623
    t5 = t2 >> 23
    t6 = t4 + t5
    t7 = ((t1 >> 11) ** 65537) % 4294967293
    return (t7, t6)
```

差分比对（原文以 `0x12345678` 输入，还原实现与原 pyd 输出一致，均为 `(2351013443, 570451841)`）。

## 变体与关联

- 变体：`PyNumber_InPlaceXor`/`InPlaceAnd` 表示结果写回同一对象，语义与普通版本相同，只是末参为 1。
- 变体：`PyNumber_Multiply` + 后续 `PyNumber_Remainder` 组合常见于快速幂/模运算，等价于 `pow(a, b, m)`。
- 变体：`PyNumber_TrueDivide`（真除）与 `PyNumber_FloorDivide` 在 pyd 中分别对应 `/` 与 `//`，不能互换。
- 变体：`PyNumber_Negative`/`PyNumber_Invert` 为一元运算，只带一个实参，容易与二元运算混淆。
- 关联：本卡依赖常量槽取值与实现体定位；翻译结果的正确性依赖差分比对。

## 检测与防御

- 检测：pyd 中 `PyNumber_*` 与 `PyLong_FromLongLong(16 * ...)` 交替出现，说明校验逻辑是"逐位算术后收窄"的可逆变换。
- 防御：不要把可逆变换的常量与结构暴露在客户端；改用服务端校验或带时间与身份绑定的签名令牌。
