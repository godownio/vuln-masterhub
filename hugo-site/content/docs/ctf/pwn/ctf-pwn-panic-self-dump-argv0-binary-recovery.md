---
id: ctf-pwn-panic-self-dump-argv0-binary-recovery
title: 无附件远程 pwn：超长密码触发自带 panic 逻辑，fopen(argv[0]) 读出自身 ELF 回显以恢复二进制
type: scenario
domain: ctf
path: ctf/pwn
technique: panic-self-dump-argv0-binary-recovery
tags:
- ctf
- pwn
- no-file
- binary-dump
- info-leak
- panic
- argv0
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V433
  verified_at: '2026-11-09T20:08:42+08:00'
  notes: '已对照原文与截图核对：main 中 fpath=*argv、for(i=0;i<=2;++) 最多3次登录、overflow_detected 后 panic；panic 反编译 puts("Panic: system halted\nCore dumped")、fopen(fpath,"r")、fread 0x19000、fwrite 回显并 exit；超长密码触发 s1[40] 检测后实际回吐 ELF（0x7fELF 分片）与 flag 打通均与原文一致。未验证点：dump 完整性依赖 fread 上限覆盖文件大小，不同目标需自行校验 ELF 尾部。'
url: /docs/ctf/pwn/ctf-pwn-panic-self-dump-argv0-binary-recovery/
draft: false
kb_aliases:
- 远程二进制恢复
- panic dump
- Core dumped 泄露
- argv[0] 自读
- 无附件 pwn
- self dump
---

## 一句话结论

远程 pwn 不提供二进制时，若程序在异常/溢出检测路径里调用了“core dump”式 panic 例程——`fopen(argv[0])` 打开自身、`fread` 整个文件、再把内容写回客户端——故意发送超长密码触发溢出检测，就能让服务端把自身 ELF 完整回吐，恢复二进制后离线分析漏洞与后门。

## 原理

- `argv[0]` 是进程的启动路径，服务进程通常读得到自己的可执行文件。panic 例程把 `fpath = argv[0]` 交给 `fopen(fpath, "r")`，用 `fread(&buf, 1, 0x19000, stream)` 读入整个文件，再把读到的字节数 `fwrite` 到标准输出/连接，最后 `exit(1)`。
- 触发链：登录函数把密码 `fgets` 进 `s1[48]`，并用 `if (s1[40])` 作为溢出检测；写入超出缓冲后打印 “Stack smashing detected” 并置 `overflow_detected`；main 的循环里 `if (overflow_detected) panic(...)`。于是“检测到溢出”不是终止，而是先把手里的二进制倾倒给客户端再退出。
- 之所以有效：所谓 “Core dumped” 并没有真的生成 core 文件，而是程序自己 `fopen` + `fread` + `fwrite` 模拟；读到的是磁盘上原始 ELF（未压缩、未加密），客户端把按 0x1000 左右分片的字节流收齐拼接，即得到完整可分析的文件。
- 该服务给了平台 token 入口与最多 3 次登录，但触发泄露只需要一次超长密码；“3 次登录机会”实际被用来触发崩溃而不是爆破口令。

## 触发条件

- 服务端异常处理/panic 路径会读取 `argv[0]` 或 `/proc/self/exe` 并把内容输出到连接（或任何攻击者可达的 fd）。
- 攻击者能触发该路径：本例密码超过 40 字节即触发 `s1[40]` 溢出检测。
- `fread` 的上限覆盖整个文件（0x19000 对该 ELF 足够），否则只能拿到前缀，需要结合文件大小判断完整性。

## 利用步骤

1. 连接服务，按题目提供值发送入口 token。
2. 用户名发送 `admin`（长度 <20，绕过 `if (s[20])` 的用户名长度检查）。
3. 密码发送 42 个字符（>40），得到 “Stack smashing detected” → “Panic: system halted” → “Core dumped”。
4. 从 `Core dumped\n` 之后循环 `recv` 收集所有分片（截图里每片约 0x1000 字节），直到 EOF 或超时。
5. 校验首 4 字节为 `\x7fELF`，保存为本地文件；用 readelf/IDA 恢复符号与偏移，定位 login 的 `fgets(..., 800, ...)` 溢出与 `system("/bin/bash")` 后门。
6. 用恢复出的二进制计算溢出偏移与后门地址，构造下一阶段 exploit（见关联卡）。

## PoC

```python
from pwn import *
context(log_level='info')

p = remote('target', 10004)
p.sendlineafter(b'token: ', TOKEN)          # 平台入口 token，按题目提供值填写
p.sendlineafter(b'Username: ', b'admin')
p.sendlineafter(b'Password: ', b'A' * 42)   # 超过 s1[40]，触发溢出检测 -> panic

p.recvuntil(b'Core dumped\n')
data = bytearray()
while True:
    chunk = p.recv(timeout=1)
    if not chunk:
        break
    data += chunk

assert data[:4] == b'\x7fELF', data[:16]
open('dump_bin', 'wb').write(bytes(data))
```

若输出分片之间夹杂提示文案，可按 ELF 结构（`e_shoff`/`e_shnum`）或直接过滤非二进制行后再拼接；dump 长度上限不够时要检查 ELF 尾部是否齐全。

## 变体与关联

- 关联 [[ctf-pwn-blind-format-string-dump-binary-got-hijack]]：同为无附件远程 pwn 的二进制恢复，但那张卡靠格式化字符串 `%n$s` 任意读内存逐段 dump；本卡是程序自带的 panic 逻辑 `fopen(argv[0])` 直接读文件回显，触发方式与数据来源都不同。
- 变体：`/proc/self/exe` 打开自身、崩溃时把 core 上传到远端、错误处理把配置文件内容带入报错等；只要异常路径把“自身文件内容”写回连接，就是同类泄露。
- 变体：若 panic 输出经过换行/长度处理导致截断，可按 ELF program header 逐段请求或结合已知偏移重建；截断严重时改用格式化字符串/任意读补全。
- 关联 [[binary-pwn-stack-login-fgets-unbounded-password-ret2backdoor]]：同一题拿到二进制后的利用链。

## 检测与防御

- 服务端错误处理只输出固定文案，禁止把文件内容（尤其是自身可执行文件）写给客户端；panic 例程不要 `fopen(argv[0])` 或任何可被影响的路径。
- 文件权限最小化挡不住“进程读自身可执行文件”，必须从代码层面移除该能力；panic 分支应直接 `_exit`。
- 监控出站流量中出现 `\x7fELF` 魔数或大段高熵二进制；CTF 场景中，服务端回吐 ELF 基本可判定为二进制泄露，应立即保存并离线分析。
