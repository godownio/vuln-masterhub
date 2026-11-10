---
id: code-analysis-reverse-cython-pyd-pyobject-layout-dq
title: pyd 内 CPython 对象布局识别：按 dq 标志/类型/长度/数据 展开，用 PyLong_Type 区分小整数快速路径
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: cython-pyd-pyobject-layout-dq
aliases:
- PyObject 内存布局
- dq 标志 类型 长度 数据
- PyLong_Type 快速路径
- python312_PyLong_Type
tags:
- reverse
- python
- cpython-c-api
- pyd
- layout
- ida
cve: []
severity: info
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-08T00:07:55+08:00'
  notes: 两处布局错误：① PyLong 第三槽语义：img/15 连续四个 python312 PyLong 对象头均为 1/type/8(h)/值 或 1/type/10h/值，第二个对象是 dq 10h 后跟 38 位的 0x5513615AB80h，可见该槽是 3.12 的 lv_tag(=ob_size<<3)，8=ob_size 1（一个 30 位 digit）、10h=ob_size 2，不是卡内所写「长度/位宽=8 ⇒ 32 位宽」；第四槽对单 digit PyLong 恰等于内联值，结果对但原理错。② PyUnicode：img/13 为 1/python312_PyUnicode_Type/8/0FFFFFFFFFFFFFFFh(hash=-1)/0x3010 处一槽/字符 flag{123 在 0x3018，卡内「第四槽就是数据指针、需再跳一次才见字符」不成立，第四槽是 hash；字符实际出现在 0x3018，中间还隔 0x3010 一槽（该槽语义原文未说明，不能断言是内联）。请按这两张截图修正。其余（PyObject* 按 dq 展开、ob_refcnt/ob_type 两字段、python312 版本线索、PyLong_Type 比较分派、误把指针当值会读到像地址的异常值）核对成立。
---

## 一句话结论

pyd 里传进函数的不是裸整数而是 `PyObject*`，把该指针按 `dq 标志 / dq 类型(Py_TYPE) / dq 长度 / dq 数据指针（或内联值）` 四个 8 字节槽展开，就能在反汇编视图里直接读出"这是不是 Python 整数、位宽多少、值是多少"，从而不必 attach 也能确认常量与实参。

## 原理

- CPython 对象头固定为 `ob_refcnt`（引用计数）+ `ob_type`（类型指针）两个 8 字节字段；此后是类型各自的私有布局。`PyLongObject` 在其上是 `ob_size`（以 30 位为一个 digit 的个数，负数表示负值）与 `ob_digit[]`（内联存储，不是指针）。
- 因此在 64 位进程里对 `PyObject*` 做 `d`→`dq` 展开，典型形态是：
  `dq 1`（refcnt）、`dq offset python312_PyLong_Type`（类型）、`dq 8`（长度/位宽标志）、`dq <值>`（数据）。
  第三槽显示 `8`、第四槽显示 `0x12345678` 一类，就是这个对象是 32 位宽的整数且值为 `0x12345678`。
- Cython 对整数运算做两层分派：`*(v + 8) != PyLong_Type[0]` 之类的比较说明对象类型不是 `PyLong`（走通用 `PyNumber_*` 路径）；相等则走小整数快速路径，直接按 `ob_digit` 取值运算，反编译里表现为 `PyLong_FromLong((unsigned int)(...))` 这类就地计算。
- 类型指针的符号名（`python312_PyLong_Type`）同时给出目标解释器的 ABI 版本线索（`python312` = CPython 3.12），可用于反推该 pyd 能被哪个版本导入。
- 长度/数据槽的语义随类型变化：`PyLong` 是 `ob_size` + 内联 digits；`PyBytes`/`PyUnicode` 是长度 + 数据指针（需二次解引用）；`PyList`/`PyTuple` 是长度 + `ob_item` 数组指针。误把指针当值读会得到"看起来像地址"的异常数值，这是区分布局的最快信号。

## 触发条件

- 反汇编视图里能定位到一个被当作实参传递的 `PyObject*`（通常来自 `PyLong_From*` 返回值或函数参数）。
- 调试器/静态视图支持按 8 字节粒度展开内存（IDA 的 `d`/`dq`、Ghidra 的 `QWORD`）。
- 目标对象是整数或字节串这类布局可预测的类型；自定义类型需先找其 `tp_basicsize` 与成员偏移。

## 利用步骤

1. 定位实参指针（`PyLong_FromLongLong`/`PyLong_FromString` 的返回值被存进 `off_XXX[k]` 或局部变量处）。
2. 切到内存视图，把该地址从 `db` 改成 `dq`，得到 4 个连续的 8 字节槽。
3. 读第一槽为引用计数（正常是 1 或更大），第二槽为类型指针；对第二槽取交叉引用/跟随，符号名会显示 `python3xx_PyLong_Type` 等。
4. 按类型决定第三/第四槽语义：`PyLong` 直接把第四槽当值（注意 `ob_size` 的符号与 30 位 digit 分组）；`PyBytes`/`PyUnicode` 把第四槽当指针再跳一次读内容。
5. 把"槽号 → 类型 → 值"记成表，供后续 C-API 序列翻译时对照。
6. 若第四槽看起来像地址而值应该是小数，说明这是指针型布局，不要直接当值使用。

## PoC

静态展开（示意）：

```text
dq 1                              ; ob_refcnt
dq offset python312_PyLong_Type   ; ob_type  -> CPython 3.12 的 PyLong
dq 8                              ; 位宽/长度标志
dq 12345678h                      ; 内联值 = 0x12345678
```

对照：同一位置若为 `PyUnicode`，第四槽是数据指针，需再跳一次才见到字符内容。

## 变体与关联

- 变体：CPython 3.12 起小整数仍有 immortal/refcnt 优化，refcnt 槽可能显示极大常数而非 1，不影响第三/第四槽解读。
- 变体：`PyLong` 超过 30 位时 `ob_digit` 有多个元素，"第四槽只有一个值"的直觉会失效，需按 `ob_size` 循环读 digit 并重新拼装。
- 变体：`CYTHON_LIMITED_API` 构建不再做 `PyLong_Type` 比较，快速路径分派消失，只能全部按 digits 读。
- 关联：本步产出的槽表是常量回溯与 C-API 序列翻译的输入；定位到实现体后优先做本步。

## 检测与防御

- 检测：pyd 中存在大量 `PyLong_Type`/`PyBytes_Type` 直接比较，说明代码走 CPython 对象级运算而非纯 C 运算。
- 防御：把敏感常量与会话状态放到服务端；客户端只保留不泄露判定所需的对象结构。
