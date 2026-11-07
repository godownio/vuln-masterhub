---
id: ctf-misc-short-circuit-expensive-expression-quaternary-timing
title: 短路求值 + 昂贵表达式构造四态时间侧信道：50 次查询四叉搜索 100-bit 随机数
type: scenario
domain: ctf
path: ctf/misc
technique: short-circuit-expensive-expression-quaternary-timing
tags:
- ctf
- misc
- side-channel
- timing
- short-circuit
- expression-evaluator
- search
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:57:57+08:00'
  notes: 已对照原文核对：短路求值、2**(2**25) 昂贵分支、四态表达式与区间映射、50 次四叉覆盖 2^100、基线阈值均与原文一致；未复跑 PoC。
url: /docs/ctf/misc/ctf-misc-short-circuit-expensive-expression-quaternary-timing/
draft: false
kb_aliases:
- 四叉搜索时间侧信道
- 短路求值侧信道
- 昂贵表达式 oracle
- Guess The Number
- Yes/No + 快/慢
- 时间侧信道二分变四叉
---

## 一句话结论

服务端只有 50 次机会猜一个 100-bit 随机数，正常二分需要约 100 次；但表达式求值器支持 `and/or` 短路和 `**` 幂运算。攻击者构造一个表达式，使四个区间分别对应“Yes+快 / No+快 / Yes+慢 / No+慢”四种可区分结果（2×2 状态），每次查询把候选区间缩为 1/4，50 次即可覆盖 `4^50 = 2^100`。

## 原理

- **短路求值**：`A and B` 在 A 为 False 时不计算 B；`A or B` 在 A 为 True 时不计算 B。求值器按 AST 递归，未走到的分支不会产生副作用/耗时。
- **昂贵表达式**：表达式语言支持 `**`，可构造 `2 ** (2**25)` 这类巨大整数幂，计算耗时明显（数秒级），形成“慢分支”。
- **四态 oracle**：对当前区间 `[L,R]` 取三个分割点 `q1,q2,q3`，构造：
  ```text
  (x < q1)
  OR (x >= q2 AND x < q3 AND EXPENSIVE_TRUE)
  OR (x >= q3 AND EXPENSIVE_TRUE AND False)
  ```
  - `x < q1` → True，短路，快；
  - `q1 <= x < q2` → 第一项 False，第二/三项的前置条件 False，整体 False，快；
  - `q2 <= x < q3` → 第二项前置 True，计算 `EXPENSIVE`，整体 True，慢；
  - `x >= q3` → 第三项前置 True，先算 `EXPENSIVE` 再 `AND False`，整体 False，慢。
- **信息量**：每次查询得到 2 bit（Yes/No × 快/慢），四叉搜索；`4^50 = 2^100`，刚好覆盖 100-bit 空间（实际可留少量余量）。
- **基线校准**：网络抖动会影响时间判定；先测一个“必快”表达式的中位延迟，用 `slow = dt > baseline*5 + 0.05` 等自适应阈值判定慢分支。
- **为什么不是普通二分**：二分每次只有 1 bit；四态利用“输出值 + 是否执行昂贵分支”两个维度，把每次查询信息量翻倍。

## 触发条件

- 服务端允许用户提交表达式（AST/字符串），并按语言语义短路求值；支持幂运算或其它可构造长耗时操作的算子。
- 查询次数受限（示例 50 次）但小于正常二分所需（100 次）；随机数范围约 100 bit。
- 响应时间可观测，且慢分支耗时远大于网络抖动（示例巨大幂运算）；可多次校准基线。
- 表达式长度/嵌套深度限制允许构造三层嵌套；服务端未做超时/复杂度限制。

## 利用步骤

1. **测基线**：提交一个必快表达式（如 `x < -1`），记录响应时间；取中位数作为 baseline。
2. **构造四叉表达式**：按当前 `[L,R]` 计算 `q1,q2,q3`，用 `or/and` 与 `EXPENSIVE()` 构造上述表达式。
3. **提交并分类**：记录 `Yes/No` 与 `dt`；`slow = dt > baseline*5 + 0.05`（按环境调整）。
4. **更新区间**：
   - Yes+快 → `[L,q1)`
   - No+快 → `[q1,q2)`
   - Yes+慢 → `[q2,q3)`
   - No+慢 → `[q3,R]`
5. **重复 50 次**：区间宽度按 1/4 缩小；50 次后宽度应 ≤1。
6. **提交最终猜测**：发送 `L`，拿到 flag/成功响应。
7. **调参**：若时间抖动大，增加 `EXPENSIVE` 规模/重复次数，或每轮多次采样取中位数；若表达式长度受限，减少嵌套/用等价逻辑。

## PoC

```python
def EXPENSIVE():
    return {"op": "**", "arg1": 2, "arg2": int(2**25)}

def expr_quarter(q1, q2, q3):
    return {
        "op": "or",
        "arg1": {"op": "<", "arg1": "x", "arg2": q1},
        "arg2": {
            "op": "or",
            "arg1": {"op": "and",
                     "arg1": {"op": ">=", "arg1": "x", "arg2": q2},
                     "arg2": {"op": "and",
                              "arg1": {"op": "<", "arg1": "x", "arg2": q3},
                              "arg2": EXPENSIVE()}},
            "arg2": {"op": "and",
                     "arg1": {"op": ">=", "arg1": "x", "arg2": q3},
                     "arg2": {"op": "and", "arg1": EXPENSIVE(), "arg2": False}}
        }
    }

L, R = 0, 1 << 100
baseline = max(measure_fast(), 0.03)
for _ in range(50):
    width = R - L + 1
    if width <= 1: break
    q1, q2, q3 = L + width//4, L + width//2, L + 3*width//4
    out, dt = send_expr(expr_quarter(q1, q2, q3))
    yes, slow = b"Yes" in out, dt > baseline*5 + 0.05
    if   yes and not slow: R = q1 - 1
    elif not yes and not slow: L, R = q1, q2 - 1
    elif yes and slow: L, R = q2, q3 - 1
    else: L = q3
guess(L)
```

原文在 50 次配额下成功恢复 100-bit 随机数；`EXPENSIVE` 规模与阈值需按服务端性能调整。本卡不执行 PoC。

## 变体与关联

- **更多状态**：若表达式支持多个昂贵分支/不同耗时等级，可构造 2^k 态 oracle，进一步减少查询次数；但时间分辨率/抖动限制实际可用状态数。
- **其它侧信道**：内存分配（大数组/字符串）、递归深度、异常类型、日志/错误码都可替代时间；关键是把“区间判断”编码成可观测的副作用。
- **其它求值器**：Python `eval`、JSON 表达式、模板表达式、SQL CASE 等只要支持短路与可控耗时操作，都可尝试。
- **关联**：[[ctf-misc-xargs-argmax-split-argv-key-injection]]（服务端逻辑侧信道）、[[web-generic-auth-username-enumeration-timing-lockout]]（时间侧信道）、[[crypto-ecc-ecdsa-time-side-channel-hnp]]（时间侧信道密码分析）。
- **边界**：需要可观测响应时间且慢分支远大于抖动；服务端若加超时、限制表达式复杂度、使用常数时间求值或固定 100 次配额，攻击失效。

## 检测与防御

- **限制表达式**：禁止 `**` 等可构造超大整数的算子，限制数字位宽/嵌套深度/求值步数；对表达式做复杂度分析。
- **常数时间/超时**：为求值设置严格 CPU/时间上限，超时直接拒绝；不要让“是否执行某分支”影响可观测响应时间。
- **配额与随机性**：增加查询配额或使用不可预测的随机数；对同一会话的查询频率/模式做限制。
- **检测**：大量包含 `**`、超大指数、`and/or` 嵌套的表达式；查询间隔/响应时间呈现四态分布；同一会话在 50 次内提交长表达式。
- **响应**：阻断异常表达式、审计是否已泄露随机数、修复求值器复杂度限制。
