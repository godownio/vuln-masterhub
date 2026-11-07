---
id: ctf-misc-interactive-checker-missing-index-upper-bound
title: 交互题 checker 未校验查询下标上界：直接查询 A_n 每一位
type: scenario
domain: ctf
path: ctf/misc
technique: interactive-checker-missing-index-upper-bound
tags:
- misc
- interactive
- checker
- logic-flaw
- bitwise
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:29:52+08:00'
  notes: 已对照原文与图23核对：题面限制 1<=i<=n-1 但 checker 未拦 i=n、发送 ? n (1<<k) 返回 0/1、32 次查询按位恢复 A_n、! ans 提交、12 组后返回 kashiCTF{d8b4ea850c6d4d34f74f66f60efd2904e0WKz30Pmp}} 均一致。未验证点：无远程环境，PoC 未复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/misc/ctf-misc-interactive-checker-missing-index-upper-bound/
draft: false
kb_aliases:
- 交互题越界查询
- checker 缺少上界
- 按位恢复 A_n
- 查询下标 i=n
---

## 一句话结论

交互题题面声称查询只能选 `1 ≤ i ≤ n-1`、目标是求最后一个元素 `A_n`，但 checker 实际没有拒绝 `i = n`；直接发送 `? n (1<<k)` 并观察返回 0/1，32 次查询即可按位恢复 `A_n`，再提交答案。

## 原理

- 交互题通常用 `? i x` 查询第 `i` 个元素与 `x` 的某种关系；题面把 `i` 限制在 `1..n-1`，意图是让选手通过前缀/集合关系间接推导 `A_n`。
- 如果 checker 只解析参数、未校验 `1 <= i <= n-1`，那么 `i = n` 会被当作合法下标，直接返回 `A_n` 与 `x` 的比较/位测试结果。
- 利用返回值的二进制语义：查询 `x = 1<<k`，若返回 1 说明 `A_n` 的第 k 位为 1；对 k=0..31 循环即可恢复 32 位整数。
- 为什么可行：题面约束与代码校验不一致（logic flaw）；交互协议没有对越界下标做拒绝/惩罚，攻击者可以绕过预期解题路径。
- 若 `A_n` 超过 32 位，按实际位宽扩展；若返回的是比较而非位测试，可改用二分/逐位构造。

## 触发条件

- 交互式 checker 接受 `i` 作为查询下标，但只校验格式/类型，未校验上界。
- 查询返回值能区分 `A_n` 的位/大小（如返回 0/1 或比较结果）。
- 目标 `A_n` 的位宽已知或可推断（如 32 位整数）。
- 交互次数/超时允许约 32 次查询。

## 利用步骤

1. 阅读题面与协议，确认查询格式（如 `? i x`）和返回语义。
2. 先用合法下标测试协议；再尝试 `i = n`，观察是否被拒绝。
3. 若未被拒绝，发送 `? n (1<<k)`，记录返回值；k 从 0 到 31。
4. 按返回值置位，拼出 `A_n`；必要时用已知样例/小 n 验证位序。
5. 发送 `! ans` 提交；若 checker 还要求其他字段，按协议补齐。
6. 若 `i=n` 被拒绝，尝试 `i=n+1`、负数、极大值、类型混淆等边界，寻找其他校验缺口。

## PoC

```python
from pwn import *
context.log_level = "info"

io = remote("target", 19442)
t = int(io.recvline())
for _ in range(t):
    n = int(io.recvline())
    ans = 0
    for k in range(32):
        io.sendline(f"? {n} {1 << k}".encode())
        if int(io.recvline()) == 1:
            ans |= 1 << k
    io.sendline(f"! {ans}".encode())
print(io.recvall(timeout=3).decode(errors="ignore"))
```

说明：PoC 为原文 exp 的结构化精简，未在本机执行；原文通过 `? n (1<<k)` 恢复 12 组 `A_n` 后拿到 flag。

## 变体与关联

- 变体（越界类型）：`i=0`、`i=n`、`i>n`、负数、超大整数、非整数；不同 checker 的校验缺口不同。
- 变体（返回值）：位测试、比较结果、距离、哈希/随机化；可按语义改造成二分/逐位/统计 oracle。
- 变体（协议）：多轮交互、批量查询、带权查询；先找“题面约束 vs 代码校验”的差异。
- 关联：[[ctf-misc-tupper-self-referential-formula-decode]]（按位/大整数解码）；[[ctf-pwn-bytecode-sandbox-header-memsize-stack-oob-rop]]（边界取自输入头部的同类逻辑缺陷）。
- 边界：checker 严格校验下标、查询有次数/惩罚限制、返回值不携带位信息时，本方法不成立。

## 检测与防御

- 检测：交互协议中 `i` 未做 `1 <= i <= n-1` 校验；返回 0/1 的位测试接口可被逐位枚举；题面约束与实现不一致。
- 防御：checker 对所有输入做严格范围/类型校验；对越界查询返回错误/终止；不要用单个 bit 直接暴露目标值，加入随机化/批量约束。
- 加固：题面与实现保持一致；对交互次数/异常模式做限制；用 property-based testing 覆盖边界下标。
