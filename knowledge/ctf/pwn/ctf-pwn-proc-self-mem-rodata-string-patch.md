---
id: ctf-pwn-proc-self-mem-rodata-string-patch
title: /proc/self/mem 任意内存写：把文件编辑器变成 .rodata 改写器，篡改硬编码黑名单首字节绕过 /secret.txt 拦截
type: scenario
domain: ctf
path: ctf/pwn
technique: proc-self-mem-rodata-blacklist-string-patch
aliases:
- /proc/self/mem
- 内存文件任意读写
- .rodata 改写
- 硬编码字符串绕过
- hex editor pwn
- 只读段改写
tags:
- ctf
- pwn
- linux
- proc-self-mem
- arbitrary-memory-write
- rodata
- path-blacklist
- file-editor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T06:26:11+08:00'
  notes: 已对照原文 hex-editor-xtended-v2 核对：realpath+strncmp 黑名单、fopen(r+) /proc/self/mem、set 0x49704E 两次写 0、get 读 flag 均与原文一致；PoC 片段省略了原文的 sela 等辅助函数定义，未实际执行。
---

## 一句话结论

一个允许 `open` 任意路径并用 `set/get` 读写文件字节的十六进制编辑器，虽然用 `realpath` + `strncmp(path, "/secret.txt", strlen("/secret.txt"))` 禁止访问 `/secret.txt`，但允许打开 `/proc/self/mem`；把它当作普通文件 `fopen("r+")` 后按虚拟地址 `fseek` + `fputc`，即可改写进程内存中只读 `.rodata` 里的 `/secret.txt` 字符串首字节为 `\x00`，使 `strncmp` 比较失败，再正常 `open /secret.txt` 读 flag。

## 原理

- **`/proc/self/mem` 是进程自己的内存文件**：Linux 中 `/proc/<pid>/mem` 暴露进程虚拟地址空间；`/proc/self/mem` 指向当前进程。用 `fopen("r+")`、`fseek(addr)`、`fputc/ fgetc` 可以按虚拟地址读写本进程内存，内核负责地址翻译与访问检查；对程序自身来说，这提供了一种绕过页权限（如 `.rodata` 只读）的读写原语。
- **程序把“任意文件编辑”暴露给用户**：`do_open_command` 只做 `realpath`、拒绝 `//` 开头和 `/secret.txt` 前缀，然后 `fopen(path,"r+")`；`do_set`/`do_get` 直接 `fseek` 到用户给出的位置读写。攻击者因此可以 `open /proc/self/mem`，把编辑器变成任意内存读写器。
- **黑名单字符串在内存中**：`strncmp(path, "/secret.txt", strlen("/secret.txt"))` 的第二个参数是 `.rodata` 中的字符串常量（原文地址示例 `0x49704E` / `.rodata:0x204E`），虽然段只读，但通过 `/proc/self/mem` 可写。
- **为什么改首字节有效**：编译器把 `strlen("/secret.txt")` 优化为常量 11（反汇编 `mov edx, 0Bh`），所以 `strncmp` 的长度仍是 11；把字符串首字节改为 `\x00` 后，比较变成 `path[0]` 与 0 比较，正常路径首字节非 0，`strncmp != 0`，检查被绕过；随后 `fopen("/secret.txt","r+")` 成功。
- **写入缓冲**：`fputc` 后数据可能还在 `FILE` 缓冲区，不一定立即落到内存；原文连续写两次 `\x00` 确保生效（也可 `fflush`/`fclose`）。
- **根因**：把“路径黑名单”这种安全判断放在可被同一程序任意写的内存里，并允许用户打开 `/proc/self/mem` 这类特殊文件。

## 触发条件

- 程序以较高权限运行（或 flag 文件权限允许其读取），并向用户暴露“打开任意文件 + 按偏移读写”的功能。
- 程序依赖内存中的硬编码字符串/常量做路径/权限检查，且没有在打开前拒绝 `/proc/self/mem`、`/proc/self/maps` 等特殊文件。
- 用户能提供任意 `open` 路径与 `set` 偏移/字节。
- 二进制无 PIE 或可预测 `.rodata` 地址（原文 No PIE，地址固定）；PIE 下可先读 `/proc/self/maps` 泄露基址。

## 利用步骤

1. 逆向后找到黑名单字符串在 `.rodata` 的地址（原文 `0x49704E`），确认 `strncmp` 长度是编译期常量。
2. 发送 `open /proc/self/mem`，确认程序允许打开（`fopen("r+")` 成功）。
3. 发送 `set <addr> 0` 两次（或写一次后 `fflush`），把 `/secret.txt` 首字节改为 `\x00`。
4. 发送 `open /secret.txt`；此时 `strncmp` 比较失败，程序不再拒绝，`fopen` 成功。
5. 用 `get 0..N` 逐字节读取文件内容，拼接出 flag。
6. 若地址不固定，先 `open /proc/self/maps` 读取映射找 `.rodata` 基址，再计算字符串地址。

## PoC

```python
from pwn import *

p = process("./pwn")
# p = remote("challs.watctf.org", 2022)  # 原文远程为 ssh 型，按实际调整

sela(b"> ", b"open /proc/self/mem")
sela(b"> ", b"set " + str(0x49704E).encode() + b" " + hex(0).encode())
sela(b"> ", b"set " + str(0x49704E).encode() + b" " + hex(0).encode())
sela(b"> ", b"open /secret.txt")
for i in range(50):
    sela(b"> ", b"get " + str(i).encode())
    print(chr(int(p.recv(2), 16)), end="")
p.interactive()
```

要点：`set` 的偏移是虚拟地址（`fseek` 到该地址），两次写 0 解决缓冲区延迟。

## 变体与关联

- 特殊文件变体：`/proc/self/mem`、`/proc/self/maps`、`/proc/self/environ`、`/proc/self/cmdline`、`/proc/self/fd/*`。
- 改写目标变体：硬编码路径/权限字符串、GOT/函数指针、返回地址、全局布尔标志、`__stack_chk_fail` 等；`/proc/self/mem` 提供任意读写原语。
- 绕过方式变体：改字符串首字节为 NUL、改比较常量为 0、改分支条件、改 `strncmp` GOT。
- 关联卡片：[[ctf-pwn-vfs-inode-link-permission-srop-orw]]、[[binary-pwn-libc-got-plt-hijack-full-relro-bypass]]、[[binary-pwn-stack-arbitrary-null-byte-return-redirect-shellcode]]、[[ctf-pwn-command-injection-filename-shell-quote-bypass]]。
- 边界：程序若拒绝 `/proc`、使用 `openat2`/`O_PATH` 限制、或黑名单字符串在运行时从只读映射/远程配置读取，本手法失效；flag 文件权限不允许程序读取时也无效。

## 检测与防御

- **拒绝特殊文件**：文件编辑器/上传/预览功能应拒绝 `/proc`、`/sys`、`/dev` 等路径，使用 `openat2` + `RESOLVE_BENEATH`/`RESOLVE_NO_SYMLINKS` 限制在允许目录内。
- **不要用可写内存做安全检查**：路径/权限判断使用服务端不可变配置或编译进只读段且不暴露任意写原语；关键校验在独立服务/内核层完成。
- **最小权限**：编辑器进程使用低权限账号，flag/敏感文件不可读；用 seccomp/AppArmor 限制 `open` 路径。
- **检测**：监控对 `/proc/self/mem` 的打开与按地址 `fseek` 的异常读写；对文件编辑器的超大偏移、非文件地址写入告警。
