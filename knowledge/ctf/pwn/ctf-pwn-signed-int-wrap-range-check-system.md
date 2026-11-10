---
id: ctf-pwn-signed-int-wrap-range-check-system
title: scanf 有符号整数回绕绕过上下界校验：输入 -2 使 v+16 落到 0..14 的合法区间触发 system("/bin/sh")
type: scenario
domain: ctf
path: ctf/pwn
technique: signed-int-wrap-bounds-check-bypass
aliases:
- 负数绕过范围判断
- 整数回绕 条件判断
- 有符号比较 无符号常量
- 0xFFFFFFF0 边界
tags:
- pwn
- integer
- signedness
- logic-bug
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:48:29+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文 main 中 v5=16 与 if(v4[0]>0xFFFFFFF0 && v4[0]+v5<=14) system('/bin/sh')、PoC 发送 -2 均在正文，%uld 格式串亦保留；仅原理正确性依赖 32 位有符号常量取值，已在卡内边界段说明 64 位失效
---

## 一句话结论

`if (v4[0] > 0xFFFFFFF0 && v4[0] + 16 <= 14) system("/bin/sh");` 这类把有符号 int 与无符号常量比较、并对加法结果另做有符号比较的写法，输入 `-2` 同时满足两个条件（`-2 > -16` 成立、`-2+16=14 <= 14` 成立），直接落到 `system("/bin/sh")`。

## 原理

- `0xFFFFFFF0` 作为常量在 32 位下是有符号 `int` 的 `-16`（C 里十六进制常量先按能容纳的类型取，`0xFFFFFFF0` 在 32 位 int 中即负数），所以 `v4[0] > 0xFFFFFFF0` 实际是 `v4[0] > -16`，对 `-2` 成立——编译器并没有把它当成“接近 INT_MAX 的上界”。
- 第二个条件 `v4[0] + v5 <= 14`（`v5=16`）在 `v4[0] = -2` 时为 `14 <= 14`，成立。
- 编译器认为这是“数值必须很大且加 16 后很小”的矛盾条件，但负数让两个不等式同时为真，构成典型的有符号/无符号混用 + 溢出回绕逻辑错误。

## 触发条件

- 程序用 `scanf("%d")`/`atoi` 读取有符号整数并与大十六进制常量比较。
- 进入受保护分支后直接调用 `system`/`execve` 等敏感 sink，且没有其他校验。

## 利用步骤

1. 反编译定位比较语句，判断常量在 32/64 位下的符号（`0xFFFFFFF0`、`0xFFFFFFxx` 类）。
2. 解不等式：找 `<0` 且 `x + 16 <= 14` 的值，得 `x ∈ [-16, -2]`，取 `-2`。
3. 发送 `-2`（注意 `%uld`/`%d` 的解析格式），程序进入分支执行 `/bin/sh`。

## PoC

```python
from pwn import *
context(arch='i386', os='linux')
p = process('./rhg4')
p.sendline(b'-2')     # 满足 v4[0] > -16 且 v4[0]+16 <= 14
p.interactive()
```

## 变体与关联

- 变体：`if (len > 0x7fffffff)` 之类永假判断；`int` 与 `size_t` 混合比较导致负数变成巨大无符号数通过上界检查。
- 变体：`scanf("%uld")` 这类格式串错误会被解析成 `%u`+`ld`，可能改变读入语义，逆向时需留意。
- 关联：[[binary-pwn-stack-abs-intmin-negative-remainder-stack-overflow]]（INT_MIN 取绝对值回绕导致长度放大）、[[ctf-pwn-signed-length-unsigned-param-amplify-password-blank-ret2libc]]（有符号长度被无符号参数放大）。
- 边界：常量在不同位宽下有不同符号，64 位下 `0xFFFFFFF0` 是正数 `4294967280`，此构造失效，必须按实际类型重新求不等式。

## 检测与防御

- 检测：`clang -Wtautological-constant-out-of-range-compare`、CodeQL `cpp/unsigned-comparison`、Coverity 的 INTEGER_OVERFLOW。
- 修复：用同类型、明确语义的常量（如 `INT_MIN`/长度上界），在加法前先校验范围并强制转换为无符号；开启 `-ftrapv`/UBSan `signed-integer-overflow`。
- 加固：敏感调用前做完整性判断，不要依赖单一比较表达式。
