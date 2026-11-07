---
id: binary-pwn-stack-abs-intmin-negative-remainder-stack-overflow
title: abs(INT_MIN) 负数取模绕过长度检查：0x30 栈缓冲区被 read 到 0xe0 字节
type: scenario
domain: binary
path: binary/pwn/stack
technique: abs-intmin-negative-remainder-stack-overflow
tags:
- pwn
- stack
- integer-overflow
- signedness
- abs
- int-min
- stack-overflow
- ret2libc
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V151
  verified_at: '2026-11-06T07:31:49+08:00'
  notes: 已对照原文核对：源码 abs(size)%0x30&0xff、INT_MIN=-2147483648、-32 余数、&0xff=0xe0=224、0x30 缓冲区溢出 176 字节、编译保护参数均一致；原文仅给长度绕过与 gdb 断点，未展开完整 ret2libc 链，卡内已注明，PoC 未复跑；无受影响版本，未设 versions；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/binary/pwn/stack/binary-pwn-stack-abs-intmin-negative-remainder-stack-overflow/
draft: false
kb_aliases:
- abs(INT_MIN)
- INT_MIN 取绝对值溢出
- 负数取模
- -2147483648
- read 长度绕过
- 0x30 栈缓冲区溢出
- 2025 安徽省赛 abs
---

## 一句话结论

`get_size()` 用 `abs(size) % 0x30 & 0xff` 计算读取长度，看起来把输入变成非负；但 `abs(INT_MIN)` 在 32 位补码下溢出回 `INT_MIN`，`INT_MIN % 0x30` 得到负余数 -32，`& 0xff` 后变成 224（0xe0）；`read(0, buf, 224)` 写进 `char buf[0x30]`，造成 176 字节的栈溢出，覆盖返回地址进入 ROP。

## 原理

- **源码**：
  ```c
  int get_size() {
      int size;
      scanf("%d", &size);
      size = abs(size);
      return (size % 0x30) & 0xff;
  }
  int main() {
      char buf[0x30];
      int size = get_size();
      read(0, buf, size);
      puts(buf);
  }
  ```
  设计意图是先把输入取绝对值，再对 `0x30` 取模，把读取长度限制在 `0..0x2f`，不会超过 `buf[0x30]`。
- **`abs(INT_MIN)` 溢出**：32 位 `int` 的范围是 `-2147483648..2147483647`，负数比正数多一个。`abs` 的典型实现是 `x < 0 ? -x : x`；对 `INT_MIN = 0x80000000`，`-INT_MIN` 在数学上是 `2147483648`，但 32 位补码放不下，结果仍是 `0x80000000`，即 `abs(INT_MIN) == INT_MIN`，仍为负数。
- **负数取模**：C 的整数除法向 0 截断，余数与被除数同号。`-2147483648 % 48` 的商是 `-44739242`（向 0 截断），余数为 `-32`；`-32` 的 32 位补码是 `0xffffffe0`，低 8 位 `0xe0`。
- **零扩展**：函数最后 `& 0xff`（汇编常见 `movzx eax, dl`）把 `0xe0` 零扩展成 224，返回给调用方。`read` 的第三个参数是 `size_t`，但这里已经是正数 224，不会变成超大无符号数；溢出量是 `224 - 0x30 = 176` 字节。
- **利用面**：`read` 之后还有 `puts(buf)`，可以用它泄露栈/缓冲区内容；返回地址位于 `buf + 0x30 + 8`（saved rbp 之后），224 字节足够覆盖返回地址并布置 ROP。
- **编译环境**：原文用 `gcc -fno-stack-protector -z execstack -no-pie -fno-PIE -Wl,-z,norelro -D_FORTIFY_SOURCE=0 -O0 abs.c -o abs` 编译，无 canary、无 PIE、栈可执行；因此既可 ret2libc，也可 ret2shellcode（原文称“简单的 ret2libc”，但未给出完整链条）。
- **为什么容易漏判**：静态审查看到 `abs` 就认为长度非负，忽略 `INT_MIN` 是 `abs` 的唯一边界；`% 0x30` 又让负余数通过 `& 0xff` 变成一个看似合法的正长度。

## 触发条件

- 程序用有符号 `int` 接收长度，先 `abs` 再取模/掩码，最后把结果传给 `read`/`memcpy` 等按无符号长度处理的函数。
- 缓冲区小于 `0xe0`（本题为 0x30），且返回值经过 `& 0xff` 等截断后仍大于缓冲区。
- 输入可送达 `-2147483648`（或任何使 `abs` 溢出/取模为负的边界值）。
- 目标无 canary 或可先泄露 canary；栈可执行或能构造 ret2libc/ROP（取决于保护）。

## 利用步骤

1. 确认长度计算路径：`scanf("%d")` → `abs` → `% 0x30` → `& 0xff` → `read`。
2. 发送 `-2147483648`，让 `get_size()` 返回 `0xe0 = 224`；用 gdb 在 `read` 前确认第三个参数为 224、`buf` 距返回地址 0x38。
3. 构造 payload：`0x30` 字节缓冲区 + 8 字节 saved rbp + 返回地址链。
4. 若栈可执行（`-z execstack`），可把 shellcode 放在缓冲区并返回到栈；若 NX 开启，按目标二进制/泄露的 libc 构造 ret2libc（`pop rdi; ret` + `/bin/sh` + `system`）。
5. 用 `puts(buf)` 的输出来确认偏移/泄露（如需要）。
6. 触发返回，执行 shell/读取 flag。

## PoC

最小触发（原文 exp 的核心，仅演示长度绕过）：

```python
from pwn import *
io = process('./abs')
io.sendline(str(-2147483648).encode())   # get_size() -> 224
# 之后按 0x30 buffer + 8 saved rbp + ROP 构造
```

栈溢出骨架（具体 gadget/libc 偏移按附件）：

```python
payload  = b'A' * 0x30          # buf
payload += b'B' * 0x08          # saved rbp
payload += p64(ret_gadget)      # 栈对齐
payload += p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
io.send(payload)
```

原文只给出了 `-2147483648` 的发送与 gdb 断点，未展开完整 ret2libc 链；本卡不执行 PoC。若目标没有可用的 libc 泄露/`/bin/sh`，可改走 `-z execstack` 的栈上 shellcode。

## 变体与关联

- **堆上同源**：同一 `abs(INT_MIN)` 根因也可用于堆溢出；见 [[binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got]]（`abs(INT_MIN) % 0x18 = -8` → 超大无符号长度 → tcache 投毒）。
- **其他边界值**：`INT_MIN` 之外，任何 `abs` 溢出/有符号取模为负的值都可能绕过；若返回值直接转 `size_t` 而不 `& 0xff`，会变成接近 `SIZE_MAX` 的超大长度。
- **其他长度函数**：`strlen`、`snprintf` 返回值、`atoi` 溢出等也会造成“计算长度与实际缓冲区不一致”。
- **利用变体**：ret2libc、ret2shellcode、SROP、栈迁移；按目标保护选择。
- 关联：[[binary-pwn-stack-snprintf-return-length-read-overflow]]（返回值当长度）、[[binary-pwn-stack-ret2libc]]（ret2libc 基础）。

## 检测与防御

- **代码审计**：任何 `abs()`/取模/位掩码参与缓冲区长度计算的地方，都要检查 `INT_MIN`、负数取模和 `& 0xff` 的语义；长度应与目标缓冲区大小比较，而不是只做模运算。
- **修复**：使用无符号类型并在读取前做 `if (size < 0 || size > sizeof(buf))` 检查；避免 `abs` 后再取模；对 `read` 的长度使用 `size_t` 且显式上限。
- **编译加固**：开启 stack canary、NX、PIE/Full RELRO；即使长度被绕过，也能提高利用成本。
- **检测**：输入 `-2147483648` 等边界值后出现异常大的 `read` 长度/栈破坏；崩溃栈显示 `read` 写入超过局部缓冲区；对菜单/协议中的长度字段做边界 fuzz。
