---
id: binary-pwn-format-string-sequential-leak-appended-target-address
title: 禁用 $ 的顺序格式化字符串泄漏：%p 走栈定位后把目标地址追加到格式串尾部成为第 15 个参数，%s 读出远端 flag
type: scenario
domain: binary
path: binary/pwn/format-string
technique: sequential-format-string-appended-address-leak
aliases:
- 无 $ 格式化字符串
- 顺序 %p 泄漏栈
- 格式串尾部追加地址
- 第 15 个参数 %s
- fmt 题 flag 泄漏
tags:
- pwn
- format-string
- stack
- leak
- aslr
- remote
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V432
  verified_at: '2026-11-09T19:17:23+08:00'
  notes: 已对照原文 fmt 题及 17 张图核对：scanf %100s 两次、wrap_printf 栈缓冲区、禁用 $、%p 顺序泄漏第 7 个栈地址+0x470 得 flag 地址、13 个 %p+%s+追加 p64 的 payload 与作者 exp 一致；官方 exp(%llx*18+%llx+%s__) 亦与卡内说明相符。小注：文章称追加地址落在第 15 个参数槽，而作者 exp 的 %s 为第 14 个转换符，属原文表述与实际 payload 的细微出入，已按原文保留。未给版本，已 clear。dedup 仅 related（scanf 越界覆盖 printf 参数、%hn 写返回地址等不同链）。
---

## 一句话结论

程序过滤了 `$` 且只允许 100 字节输入、flag 字符串远在栈高地址时，可先用连续 `%p` 读 64 位调用约定的寄存器参数与栈参数，定位第 7 个参数处的栈地址并算出 flag 地址；第二次把该 flag 地址以 8 字节追加在格式串末尾，使格式串缓冲区自身充当可变参数区，让 `%s` 的参数槽正好落在追加地址上，从而读出 flag。

## 原理

- 64 位 SysV 调用约定下，格式化函数的可变参数前 6 个在寄存器（rsi/rdx/rcx/r8/r9 等），第 7 个起从栈上取；因此 `%p` 连续输出可以看到寄存器值、栈地址与栈上内容。
- 本题 `wrap_printf(v1)` 的格式串就是栈上缓冲区 `v1`：输入 100 字节以内无法用 `%p` 走完到 flag（flag 在 rbp+0x10de 附近），但格式串缓冲区在 printf 调用时同时处于可变参数区，格式串末尾追加的 8 字节会被当作某个参数槽读取。
- 第一次输入 `%p%p%p%p%p%p%p`：前 6 个输出寄存器值，第 7 个输出一个栈地址；按调试偏移 `+0x470` 得到 flag 字符串地址。
- 第二次输入：先放足量 `%p` 消耗前面的参数槽，再放 `%s`，最后追加 `p64(flag_addr)`。由于缓冲区本身在参数区，追加的 8 字节正好落到 `%s` 对应的参数槽（本例第 15 个），`%s` 将该槽内容当作指针，把 flag 字符串打印出来。
- 为什么必须在尾部追加：`%s` 需要一个“指向字符串的指针”作为参数；格式串的前 100 字节都被格式字符占用，唯一能精确控制某个参数槽 8 字节值的方式，是把目标地址写进缓冲区并让它与参数槽对齐。`$` 被禁用时无法直接用 `%15$s` 指定槽位，只能通过前面的 `%p` 数量调整。

## 触发条件

- 程序存在 `printf(用户输入)`（或包装函数）的格式化字符串漏洞，输入长度有限（本例 100 字节）；
- 过滤/禁用 `$` 位置参数语法，但仍允许 `%p/%s` 等普通转换；
- flag 或目标字符串位于栈上较远位置，无法靠连续 `%p` 直接走到；
- 需要已知或可泄漏的栈地址（第一次输入泄漏）与相对偏移（本地调试确定）。

## 利用步骤

1. 本地 gdb 调试（`stack 200` 查看更大栈范围），确认 flag 字符串相对泄漏栈地址的偏移（本例 0x470）。
2. 第一次发送 7 个 `%p`，接收输出并解析第 7 个值（栈地址），加上偏移得到 flag 地址。
3. 统计远端格式化参数槽与格式串缓冲区的对齐关系：从第一个 payload 确认第 7 个参数是栈地址，再按缓冲区偏移递增调整 `%p` 数量。
4. 构造第二段 payload：`%p`×N（消耗到目标槽前）+ `%s` + 少量 `%p`，末尾追加 `p64(flag_addr)`；发送后从输出中截取 flag。
5. 若远端与本地栈布局/环境不同导致偏移变化，按输出中栈地址与已知指针重新计算，或调整 `%p` 数量重试。

## PoC

```python
from pwn import *
context(os='linux', arch='amd64')
io = remote('target', 20160)

io.recvuntil(b'what is your name?\n')
io.sendline(b'%p%p%p%p%p%p%p')          # 6 个寄存器 + 第 7 个栈地址
# 解析第 7 个值为栈地址（示例：recvuntil 到已知第 6 个值后取 14 字节）
stack = int(io.recv(14), 16) + 0x470   # 偏移由本地 gdb 确定
io.recvuntil(b'have anything else to say?\n')

payload = b'%p'*13 + b'%s' + b'%p%p' + p64(stack)
io.sendline(payload)                   # 追加地址成为 %s 的参数槽
io.interactive()
```

官方 exp 使用 `%llx` 连续输出并用 `__` 分隔，解析栈地址后同样以 `18 个 %llx + %llx + %s__ + p64(flag)` 的形式读出 flag，说明参数槽数量需按目标实际布局微调。

## 变体与关联

- 变体：`$` 被过滤时可用 `\x25\x24` 还原 `%$`（见 [[binary-pwn-format-string-decode-after-filter-bypass]]），或按本卡用顺序参数。
- 变体：需要写内存时把目标地址追加到尾部并用 `%n/%hn` 写入（见 [[binary-pwn-format-string-stack-pointer-chain-return-address-backdoor]]）。
- 关联：[[ctf-pwn-blind-format-string-dump-binary-got-hijack]]（用 `%7$s`+追加地址 dump 任意内存，本卡因禁用 `$` 改走顺序参数）。

## 检测与防御

- 开发侧：禁止把用户输入直接作为 printf 格式串，统一 `printf("%s", buf)`；对格式串做白名单。
- 检测：输出中出现大量 `0x7f...`/`0x55...` 指针、`%p`/`%s` 引发的异常读取；WAF/输入侧过滤 `%` 与位置参数。
- CTF 侧：远端栈布局与本地不一致时，先泄漏栈地址再按输出校准参数槽，不要硬编码本地偏移。
