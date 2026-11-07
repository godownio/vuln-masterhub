---
id: ctf-pwn-hexfloat-strtoull-parser-differential
title: CTF Pwn 数值校验绕过：strtod 十六进制浮点与 strtoull 解析差异
type: scenario
domain: ctf
path: ctf/pwn
technique: hexfloat-strtoull-parser-differential
tags:
- ctf
- pwn
- parser-differential
- strtod
- strtoull
- hex-float
- input-validation-bypass
- glibc
- c
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V93
  verified_at: '2026-11-05T19:42:57+08:00'
  notes: 已对照原文全文（无图片）核对：strtod(0X04p-2)=1、strtoull(...,16)停在p得4、judge1/!judge取反逻辑、大写X绕过strchr('x')、0X74p1=0xe8均与原文一致；修正了PoC注释中0X60p-1应为48(0x30)而非96的笔误；未复跑exp
url: /docs/ctf/pwn/ctf-pwn-hexfloat-strtoull-parser-differential/
draft: false
kb_aliases:
- 0X04p-2
- 十六进制浮点绕过数值校验
- strtod 与 strtoull 解析差异
- 大写 X 绕过 strchr('x')
- judge 逻辑取反
- 浮点数校验绕过
- parser differential
---

## 一句话结论

当程序对同一段输入先用 `strtod` 解析成浮点/整数、再用 `strtoull(..., 16)` 解析成十六进制整数做校验，并且把校验函数的返回值取反时，用 `0X..p..` 十六进制浮点写法可以让两个解析器得到不同数值——`strtod` 得到目标整数、`strtoull` 只读到 `0X..` 前缀得到另一个值，从而通过“校验”；大写 `X` 还能绕过只过滤小写 `x` 的检查。

## 原理

- C99/C11 支持十六进制浮点字面量：`0x` 后跟十六进制尾数，可选小数点，再跟 `p`/`P` 和十进制指数，值为“尾数 × 2^指数”。例如 `0X04p-2 = 4 × 2^-2 = 1`，`0X30p-1 = 0x30 × 2^-1 = 24`，`0X60p-1 = 96`，`0X74p1 = 0x74 × 2 = 232 (0xe8)`。
- `strtod("0X04p-2", NULL)` 按十六进制浮点解析得到 `1.0`；而 `strtoull("0X04p-2", &end, 16)` 只按十六进制整数解析 `0X04` 得到 `4`，遇到 `p` 停止。同一个字符串在两个解析器下含义不同，这是典型的解析器差异（parser differential）。
- 例子中的校验逻辑：
  - `judge1(heap, num2)` 把输入字符标记为哈希桶，再检查十进制字符串 `num2` 的每个字符是否出现在输入中，防止字符重叠；
  - `judge(heap, num)` 要求输入以 `0x`/`0X` + 十六进制数字开头，用 `strtoull` 解析后与 `num` 相等；
  - 调用处却是 `judge1(...) == 1 && !judge(...)`：`judge` 返回 1 表示“解析一致”，取反后反而要求“不一致”才通过。逻辑取反使解析器差异直接成为绕过。
- 输出值 `num` 来自 `strtod` 的结果：`0X04p-2` 得到 1，于是菜单选项 1 被选中；`0X74p1` 得到 232，正好是 `draft` 允许的最大长度 `0xE8`，可把栈缓冲区写满/溢出。`0X..p..` 的指数部分可以自由调节，把同一个十六进制尾数映射到不同的目标整数。
- 只过滤小写 `x` 的 `strchr(heap, 'x')` 对大写 `X` 无效；输入长度上限（如 19 字节）也足够容纳 `0X74p1` 这类短串。

## 触发条件

- 程序对同一输入使用两个不同解析器（`strtod`/`atof`/`sscanf("%lf")` 与 `strtoull`/`strtoul`/`atoi`/`sscanf("%x")`），且校验逻辑允许或主动要求两者结果不一致（如返回值被 `!` 取反）。
- 输入过滤只检查小写 `x`，未统一大小写/未拒绝十六进制浮点指数。
- 目标值可以表示为 `0x<hex>p<exp>` 形式，且十六进制尾数/十进制表示不触发字符重叠检查。
- 输入长度限制足以放下该字符串；后续存在可利用的栈溢出/越界等内存问题。

## 利用步骤

1. 反编译定位数值解析与校验：`strtod`/`atof` 的返回值如何转成整数、`strtoull(...,16)` 在哪里比较、`judge1`/`judge` 的返回值在调用处是否被取反、是否有 `strchr(...,'x')`。
2. 枚举目标整数 N（菜单项、分配大小、溢出长度）。选择十六进制尾数 H 与指数 E，使 `H × 2^E = N`；优先让 H 的十六进制字符不出现在 N 的十进制表示中（满足字符不重叠检查）。
3. 确认 `strtoull` 解析 H 得到的整数与 N 不同（这样 `!judge` 才为真）；若校验未取反，则需要寻找其他逻辑缺陷或让两个解析器在边界/符号/空白上产生差异。
4. 发送 `0X<H>p<E>`（大写 X），观察程序进入的目标分支/分配大小是否符合预期。
5. 用该技巧选择菜单/溢出长度，进入后续栈溢出，泄露 canary/PIE/libc 并构造 ROP（见关联卡）。

## PoC

```python
# 目标整数 -> 十六进制尾数/指数（尾数取 2 的幂附近，便于凑整）
def hexfloat(prefix: int, exp: int) -> bytes:
    return f"0X{prefix:02x}p{exp}".encode()

print(hexfloat(0x04, -2))   # b'0X04p-2'  -> strtod = 1.0，进入选项 1
print(hexfloat(0x30, -1))   # b'0X30p-1'  -> 24
print(hexfloat(0x54, -2))   # b'0X54p-2'  -> 21
print(hexfloat(0x60, -1))   # b'0X60p-1'  -> 48 (0x30)
print(hexfloat(0x74, 1))    # b'0X74p1'   -> 232 (0xe8)，可写满 draft 缓冲区
```

```c
/* 解析差异示意 */
strtod("0X04p-2", NULL);                 /* 1.0  */
strtoull("0X04p-2", &end, 16);           /* 4，停在 'p' */
/* 若校验为 judge1(...) == 1 && !judge(...)，则 1 != 4 反而通过 */
```

## 变体与关联

- 变体：`atof`/`sscanf("%lf")` 与 `atoi`/`strtol` 的组合同理；也可利用 `nan`/`inf`、前导空白、正负号、溢出截断、`0x` 前缀大小写等解析差异。
- 变体：若校验没有取反，可寻找“校验解析器与使用解析器不是同一个”的路径（TOCTOU/重复解析），或让校验通过后再用另一个字段影响实际长度。
- 关联：[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]（同一题中绕过数值校验后进入的栈溢出/RBP 校验/ORW 链）、[[binary-pwn-format-string-canary-libc-leak-rop-system]]（后续泄露与 ROP 的通用流程）。
- 边界：十六进制浮点需要 C99 及支持它的 libc；`strtod` 的 `p` 指数只在 `0x` 前缀下生效；输入长度/字符过滤/日志可能暴露异常串；该技巧只解决“进入漏洞分支”，不等于最终利用。

## 检测与防御

- 检测：代码审计中搜索同一输入被 `strtod` 与 `strtoull`/`atoi` 重复解析、校验函数返回值被 `!` 取反、只过滤小写 `x` 的逻辑；对十六进制浮点串（`0[xX][0-9a-fA-F]+(\.[0-9a-fA-F]*)?[pP][+-]?[0-9]+`）做输入告警。
- 修复：只解析一次并统一成规范整数；比较范围而不是比较字符串；拒绝不需要的十六进制浮点、指数、空白、正负号与超大长度；不要取反校验结果；对菜单/长度字段用白名单枚举。
- 加固：编译告警与单元测试覆盖解析器等价性；输入日志记录原始串；对关键分支做服务端/二次校验；不要把“数值校验通过”当作内存安全保证。
