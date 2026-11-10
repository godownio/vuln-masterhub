---
id: code-analysis-dynamic-debugging-php-extension-apache-gdbserver-zif-symbols
title: PHP 扩展 pwn 远程调试：gdbserver 附加 Apache mod_php 进程，等 vuln.so 加载后按 zif_ 符号下断
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: php-extension-remote-debug-apache-gdbserver-zif-symbols
tags:
- debugging
- gdb
- pwndbg
- gdbserver
- php
- php-extension
- zif
- remote-debugging
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:39:47+08:00'
  notes: 已对照原文与全部12张图核对：PHP_FUNCTION展开为zif_函数（图01-03）、gdbserver附加Apache而非CLI php、vuln.so加载点call qword ptr [rdx+0x10]（图05/06）、b _start/__libc_start_main+128/__libc_start_call_main+120、pwndbg断点与zif_addHacker等符号（图09-12）、exp.py的remote('172.17.0.2',80)+gdb.attach(...,1234)（图04）均一致。未验证点：未实际搭建调试环境；加载点地址随版本变化。
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-php-extension-apache-gdbserver-zif-symbols/
draft: false
kb_aliases:
- PHP pwn 调试
- PHP 扩展 gdb 附加
- zif_ 断点
- gdbserver 调试 Apache PHP
- PHP_FUNCTION 宏
---

## 一句话结论

调试 PHP 扩展 pwn 时，直接对 `php exp.php` 起 gdbserver 只能调 CLI，打不到 Apache 处理的 Web 请求；正确做法是把 gdbserver 附加到 Apache/mod_php 的工作进程（或直接 `gdbserver --attach` 该 pid），先在扩展加载调用点 `call qword ptr [rdx+0x10]` 停下，等 `vuln.so` 被 dlopen 后再对 `zif_<函数名>` 符号下断，之后用 pwndbg 检查堆/栈与寄存器。

## 原理

- **宏与符号**：扩展源码里的 `PHP_FUNCTION(array_change_key_case)` 经宏展开后是 `void zif_array_change_key_case(zend_execute_data *execute_data, zval *return_value)`；因此用户态调用的每个扩展函数在二进制里对应 `zif_` 前缀符号（如 `zif_addHacker`、`zif_editHacker`、`zif_removeHacker`、`zif_Minclude`），调试时按这些符号下断即可停在函数入口。
- **符号的可见时机**：扩展 `.so` 通常不是 PHP 主程序启动时静态链接，而是在请求处理/模块初始化阶段由 PHP 动态加载；在 `vuln.so` 载入前 `info functions zif_...` 找不到符号，断点设不上。原文在 `call qword ptr [rdx+0x10]` 处观察到模块加载（该调用返回后 `vuln.so` 已映射），先在此处断住，再设置 `zif_` 断点。
- **为什么不能调 CLI**：Web 请求由 Apache 的 mod_php 工作进程执行，CLI 起的 `php /var/www/html/exp.php` 是另一个进程；gdbserver 挂在 CLI 进程上时，浏览器/exp.py 发到 `172.17.0.2:80` 的请求不会经过它。
- **远程调试链路**：目标容器内 gdbserver 监听 1234/6666 端口，Kali 侧 pwndbg 通过 `target remote` 连接；pwntools 的 `gdb.attach(('172.17.0.2',1234), exe='/usr/local/bin/php')` 可自动拉起 gdb 并加载 `php` 的符号（`exe=` 只用于取符号，实际进程是 Apache 工作进程）。
- **断点组合**：原文还使用 `b _start`、`b *&__libc_start_main+128`、`b *&__libc_start_call_main+120`、`b pie+0x247a61`（具体偏移随 PHP/libc 版本变化），用于在进入请求处理前后停下来，避免错过一次性的扩展调用。
- **调试与泄露配合**：利用脚本里 `ob_start()` + 扩展函数读 `/proc/self/maps` 的泄露逻辑，可在 gdb 中直接对照 maps 基址与寄存器/堆地址，验证 libc/模块偏移和堆布局。

## 触发条件

- 目标为容器化 Apache + PHP（mod_php）环境，扩展 `vuln.so` 在请求处理时加载；容器内可运行 gdbserver 并开放调试端口（或可 attach 到 Apache 工作进程 pid）。
- Kali/分析机可访问目标 Web 端口与 gdbserver 端口；pwndbg 已安装。
- 已知道/能定位扩展加载调用点（原文为 `call qword ptr [rdx+0x10]`，版本相关），或可用 `catch load`/`set stop-on-solib-events 1` 替代。
- 调试端口未被防火墙隔离；WSL 直连 Docker 网络可能不通，原文最终在 Kali 虚拟机内完成连接。

## 利用步骤

1. 目标容器启动 Apache+PHP 与 `vuln.so`，容器内启动 gdbserver 附加到 Apache 工作进程（或 `gdbserver :1234 --attach <pid>`）；确认 Kali 能连通 `172.17.0.2:1234`。
2. exp.py 先 `sh = remote('172.17.0.2', 80)`，在发送触发请求前 `pause()`，再 `gdb.attach(('172.17.0.2', 1234), exe='/usr/local/bin/php')`，随后 `pause()` 等待手动下断。
3. 在 gdb 中对扩展加载调用点下断（原文 `b *<地址>` 于 `call qword ptr [rdx+0x10]`），`continue` 到请求触发、模块载入。
4. 确认符号出现：`info functions zif_`；按需 `b zif_addHacker`、`b zif_editHacker`、`b zif_removeHacker`、`b zif_Minclude`（或 `b *zif_addHacker`）。
5. 继续执行并在断点处检查参数 `$rdi`（zend_execute_data*）、`$rsi`（zval*）、栈帧、堆块地址；配合 maps 基址核对偏移，再回到 exp.py 继续构造利用。
6. 需要停更早时使用 `b _start`、`b *&__libc_start_main+128`、`b *&__libc_start_call_main+120`；模块加载也可用 `set stop-on-solib-events 1`。

## PoC

exp.py 调试骨架（原文）：

```python
from pwn import *
sh = remote('172.17.0.2', 80)
pause()
gdb.attach(('172.17.0.2', 1234), exe='/usr/local/bin/php')
pause()
sh.interactive()
```

gdb 侧常用命令：

```
# 扩展加载点（地址需按目标版本确认）
b *0x7ffff460a54d          # 原文停在 call qword ptr [rdx+0x10]
continue
info functions zif_
b zif_addHacker
b zif_editHacker
b zif_removeHacker
# 或按符号地址
b *zif_addHacker
```

要点：`exe=/usr/local/bin/php` 只提供符号，真正被调的是 Apache 工作进程；必须先等 `vuln.so` 加载，`zif_` 断点才生效。

## 变体与关联

- **PHP-FPM**：若目标用 php-fpm 而非 mod_php，应附加到 fpm worker 的 php 进程（或 master 下的子进程），思路相同；CLI 调试只适用于纯命令行题目。
- **静态加载/内置扩展**：若扩展编译进 PHP 或启动即加载，`zif_` 符号一开始就在，可直接下断，无需等加载点。
- **替代停点**：`catch load`、`set stop-on-solib-events 1`、`rbreak zif_` 可在不知道加载地址时捕获模块映射；`info sharedlibrary` 确认 `vuln.so` 基址。
- **关联利用**：调试后可配合 `/proc/self/maps` 泄露（mixture 栈溢出、PwnShell 堆利用）验证 libc/模块基址与堆布局。

## 检测与防御

- 调试端口（gdbserver 1234/6666、gdb stub）不应暴露在业务网络；容器编排中关闭调试 sidecar、限制容器间访问。
- 生产环境不加载调试版 PHP/扩展，关闭 `xdebug` 等远程调试能力；对 Apache/PHP 进程启用最小权限与只读文件系统。
- 安全监控：容器内出现 gdbserver 监听、异常 `ptrace`/`process_vm_readv`、Web 请求伴随长连接调试端口，可作为入侵/调试痕迹排查。
