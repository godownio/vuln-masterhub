---
id: code-analysis-reverse-cython-pyd-check-function-recovery-chain
title: Cython pyd 校验函数静态还原链：实现体定位 → PyObject 布局 → 常量槽回溯 → PyNumber 翻译 → 差分验证
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: cython-pyd-check-function-recovery-chain
aliases:
- Cython 校验函数还原
- pyd 手撕流程
- cython 逆向链路
- 差分验证还原
tags:
- reverse
- python
- cython
- pyd
- chain
- methodology
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-07T22:51:52+08:00'
  notes: 已对照 content.md 与 img/01-27 核对：五段顺序契约与四张原子卡一致，末端差分值 (2351013443, 570451841) 在 img/27 有回显截图(py3125 3.12.5)；PoC 仅引用原子卡、无独立端到端示例，属 chain 卡的已知弱点；未在本机复现。
---

## 一句话结论

把一个 Cython pyd 的校验函数静态还原成等价 Python，是一条固定顺序的五段串联：先定位真正的实现体，再认对象布局，再回溯常量槽，再翻译 C-API 序列，最后用差分比对确认等价；顺序不可乱——跳过任一步都会得到"看起来合理但常量或运算符错位"的错误实现。

## 原理

- 五段之间存在严格的数据依赖，这也解释了为什么顺序不能交换：
  1. **实现体定位**决定后续分析的作用域（wrapper 层没有业务逻辑，在 wrapper 里找常量槽只会找到参数解析相关的槽）。
  2. **布局识别**决定"一个 `PyObject*` 的哪一槽是值、哪一槽是指针"，没有它就无法区分"常量 0x12345678"与"指向 0x12345678 的指针"。
  3. **常量槽回溯**给出 `off_XXX[k]` 的真实数值，是第 4 步唯一的常量来源。
  4. **C-API 序列翻译**把调用序列拼成表达式树，使用第 3 步的表与第 2 步的布局知识。
  5. **差分验证**是唯一的正确性判据：前四步都是静态推断，只有用同一批输入同时跑原 pyd 与自写实现、逐项比对返回，才能排除"表达式等价但常量取错"。
- 串联的收益是乘法式的：实现体定位错了，后面全废；常量错一个，整个表达式错；翻译漏掉一次 32 位收窄，结果在高位分岔。所以链路卡的价值不在单点技巧，而在这五段的**顺序与交接契约**。

## 触发条件

- 交付物为 `.py` + `.pyd`，`.py` 仅 `import` 并调用 pyd 中的校验函数。
- 目标解释器版本可确定（pyd 的 ABI tag），能成功导入以便可能的动态复核。
- 校验逻辑由可逆算术（异或、移位、与、幂、取模、加）与常量表构成。

## 利用步骤

1. 从驱动脚本取 `模块.函数`，在字符串窗对该 qualified name 取 xref，按"函数体内是否有真正的 C-API 数据变换"选出实现体。
2. 在实现体内定位被当作实参传递的 `PyObject*`，按 `dq` 四个槽展开，确定类型与值是内联还是指针。
3. 对每个 `off_XXX[k]` 取 xref 回到初始化函数的 `PyLong_FromLongLong/FromString` 写点，整理"槽号 → 值"表。
4. 按调用顺序翻译 `PyNumber_*`；处理三类陷阱：移位/幂辅助函数的第 2/3 参与末参语义、`16 * v20` 收窄、`Py_Dealloc` 标示的中间量边界。
5. 写出等价 Python，用多组输入同时调用原 pyd 与自写实现，逐项比对返回值；一致后如有后续比较分支，按同一方法继续追常量表。
6. 任一步卡住时按依赖回退：翻译结果可疑 → 回查常量表；常量表可疑 → 回查布局；布局可疑 → 回确认实现体。

## PoC

见各原子卡的 PoC：实现体定位的两处 xref、`dq` 四槽布局、常量槽对照表、`PyNumber_*` 逐行翻译；最终差分以同一输入得到相同的 `(2351013443, 570451841)`。

## 变体与关联

- 变体：该校验函数若还调用了后续比较（逐字节 `PyObject_RichCompare`），需在链路末尾追加"比较分支追踪"。
- 变体：`CYTHON_LIMITED_API` 或高优化等级下小整数分派消失，第 4 步需全部按 `ob_digit` 读，链路其余部分不变。
- 变体：若常量表被加密，第 3 步与第 4 步之间插入一层解密函数分析。
- 关联：PyInstaller 打包的 pyd、自定义 Python VM 字节码、PyArmor 保护都是"Python 逻辑落到原生层"的不同形态，本链路的第 4、5 步可迁移。

## 检测与防御

- 检测：pyd 中成对的 `__pyx_pw_*`/`__pyx_pf_*`、密集的 `PyNumber_*` 与 `PyLong_FromString`、伴随 `PyLong_FromLongLong(16 * ...)` 收窄。
- 防御：判定逻辑与期望值不要放在客户端；客户端保留接口，校验在服务端完成，或使用服务端签发、带身份与时效绑定的令牌。
