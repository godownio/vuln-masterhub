---
id: binary-pwn-signed-int-add-overflow-negative-check-bypass
title: 32 位有符号整数加法溢出：两个正数相加回绕为负数绕过“正数且和负”校验拿 shell
type: scenario
domain: binary
path: binary/pwn
technique: signed-int-add-overflow-negative-check-bypass
tags:
- pwn
- integer-overflow
- signedness
- logic-bug
- linux
- 32bit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V372
  verified_at: '2026-11-09T06:20:39+08:00'
  notes: 已对照原文'整数溢出漏洞'节与图20-23核对：pwn105 scanf 两整数到[rbp-0x14]/[rbp-0x10]、test/js 正数检查、add eax,edx 存[rbp-0xc]、test/js 负数取shell 与图23汇编逐条一致；0x7fffffff(INT_MAX)+1=0x80000000 负数、Payload str(0x7fffffff)+str(1) 与原文一致。未验证点：原文该节未给出成功截图/flag，卡内'原文远程验证成功拿到 shell'属推断（PoC 语义由反汇编可证，实际未复跑）；与 ctf-pwn-signed-int-wrap-range-check-system(cos0.887，常量比较/范围绕过)入口条件不同，非同一链；dedup=new；dup-scan早于建卡；无sources；非组件--clear。
url: /docs/binary/pwn/binary-pwn-signed-int-add-overflow-negative-check-bypass/
draft: false
kb_aliases:
- 整数溢出 pwn105
- INT_MAX + 1
- 正数相加变负数
- 有符号加法回绕
- 整数溢出绕过判断
---

## 一句话结论

程序要求两个输入都为正数、且它们的和小于 0 才给 shell（`if (a>0 && b>0 && a+b<0) system("/bin/sh")`）时，利用 32 位有符号整数加法回绕：输入 `2147483647`（`0x7fffffff`）与 `1`，两者都是正数，相加溢出为 `0x80000000`（有符号即 `-2147483648`），同时满足全部条件进入 shell 分支。

## 原理

- **32 位有符号表示**：`int` 为 4 字节补码，最高位是符号位；`0x7fffffff` 是最大正数，`0x80000000` 是最小负数。
- **加法回绕**：`0x7fffffff + 1` 在 32 位中结果为 `0x80000000`，最高位由 0 变 1；按有符号解释就是负数。C 标准把这视为有符号溢出（未定义行为），但目标编译器在 x86 上生成普通 `add` 指令，硬件按模 2³² 回绕，实际结果稳定为负数。
- **校验逻辑被同时满足**：
  - `a > 0`：`2147483647 > 0` 成立；
  - `b > 0`：`1 > 0` 成立；
  - `a + b < 0`：相加结果 `0x80000000`，`test eax,eax; js` 判定符号位为 1，成立 → 进入 `system("/bin/sh")`。
- **为什么开发者想不到**：开发者默认“两个正数相加一定为正”，但忽略固定宽度整数的上界；判断链中没有任何“和是否上溢”的检查。
- **原文程序**（pwn105）流程：`scanf("%d")` 读两个整数到 `[rbp-0x14]`/`[rbp-0x10]`；分别 `test; js` 检查正数；`add eax, edx` 存入 `[rbp-0xc]`；`test eax,eax; js` 为负则打印 shell 提示并调用 `system("/bin/sh")`。
- **与有符号/无符号常量比较的区别**：本卡利用“加法结果上溢越过符号位”，不是常量 `0xFFFFFFF0` 被当作负数、也不是范围判断的符号混用；两类的入口条件与 PoC 不同。

## 触发条件

- 目标用 32 位 `int` 读取两个数值（`scanf("%d")`、`atoi` 等），并做“两者为正 + 和 < 0 / 和为负”这类逻辑判断。
- 求和结果存回 32 位 `int`，且编译器未因未定义行为优化掉判断（常见于 -O0/-O1 的 CTF 二进制）。
- 进入该分支后直接执行 `system("/bin/sh")`、读 flag 或其它敏感操作。
- 输入解析允许 `2147483647` 与 `1`（没有被范围上限/正数校验提前拦截）。

## 利用步骤

1. 反编译确认三个变量与两次 `scanf`，记录“两个正数”和“和 < 0”的检查位置与分支目标。
2. 计算满足条件的值：取 `a = INT_MAX = 2147483647`，`b = 1`；或 `a = 0x7fffffff`、`b = 0x7fffffff`（和为 `0xfffffffe`，同样为负）。
3. 按程序期望的格式发送（十进制字符串、换行分隔）。
4. 观察是否跳过“good try”失败分支并打印 shell 提示；在 shell 中读取 flag。
5. 若 `%d` 解析拒绝/截断，改用 `-2147483648` 与 `-1` 等其它回绕组合（需同时满足正数检查时不可行，优先 INT_MAX+1）。

## PoC

```python
from pwn import *
sh = process('./pwn105')
sh.sendline(b'2147483647')   # 0x7fffffff，正数
sh.sendline(b'1')            # 相加 -> 0x80000000（负数）
sh.interactive()
```

等价：`sh.sendline(str(0x7fffffff).encode()); sh.sendline(b'1')`。原文远程验证成功拿到 shell。

## 变体与关联

- 变体：`0x7fffffff + 0x7fffffff = 0xfffffffe`（负）；64 位 `int64` 用 `INT64_MAX + 1`；用乘法（`0x10000 * 0x10000 = 0`）或减法下溢触发类似判断；无符号与有符号混用导致 `> 0` 判断被绕过。
- 关联：[[ctf-pwn-signed-int-wrap-range-check-system]]（有符号常量比较/范围判断绕过，非加法溢出）、[[binary-pwn-heap-custom-allocator-negative-size-alignment-overflow]]（长度整数溢出导致堆溢出）、[[binary-pwn-kernel-kqueue-maxentries-intwrap-seqops-ret2usr]]（内核整数回绕）。
- 边界：编译器在 -O2 下可能利用“有符号溢出是 UB”删除/改写判断，导致利用失败；输入被解析为无符号或 64 位时需重新计算；程序若额外检查 `a+b > a` 等上溢标志则失效。

## 检测与防御

- **代码层**：对用户输入做范围限制（如 `0 < x <= 1000000`）；求和使用更宽类型（`int64_t`/`long long`）并检查上溢；或在加法前判断 `a > INT_MAX - b`。
- **编译层**：启用 `-ftrapv`（有符号溢出陷阱）或使用编译器内建 `__builtin_add_overflow`；避免依赖未定义行为。
- **检测**：审计 `scanf("%d")` 后的 `add` 与 `js`/`<0` 判断；对极端值（INT_MAX/INT_MIN）做输入测试；日志中出现 `2147483647` 等边界值后直接进入敏感分支即告警。
