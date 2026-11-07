---
id: web-php-file-inclusion-proc-self-fd-open-handle-read
title: PHP LFI 读取 /dev/fd 已打开文件描述符绕过路径长度限制
type: scenario
domain: web
path: web/php/file-inclusion
technique: dev-fd-open-handle-read
aliases:
- /proc/self/fd 读取
- /dev/fd 文件描述符
- fopen 未关闭句柄读取
- PHP LFI 读 flag 文件
- fd 遍历
tags:
- php
- lfi
- file-descriptor
- procfs
- file-read
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:34:37+08:00'
  notes: 已对照原文源码与 fd 枚举截图核对；/dev/fd/3 回显 flag 已确认；PoC 未复跑。
---

## 一句话结论

当 PHP 代码先用 `fopen()` 打开敏感文件却从不读取/关闭，随后又把用户可控的 `filename` 交给 `readfile()` 时，即使不知道文件路径、参数还有长度限制，也可以遍历 `/dev/fd/N`（或 `/proc/self/fd/N`）读取该进程已打开的文件描述符，直接拿到文件内容。

## 原理

- Linux 为每个进程维护文件描述符表；`/proc/self/fd/N` 是指向该进程第 N 个打开文件的符号链接，`/dev/fd/N` 通常是指向 `/proc/self/fd` 的兼容入口。对它们调用 `readfile()`/`file_get_contents()` 会打开同一个已打开文件描述（或重新打开其目标），从当前偏移读取内容。
- 进程启动时 0/1/2 分别是 stdin/stdout/stderr；之后 `fopen()` 打开的文件通常从 3 开始递增。PHP-FPM/Apache 环境下还可能先打开了日志、socket、临时文件等，因此目标文件的 fd 不一定是 3，需要遍历。
- 本例源码是 `$flag = fopen('/my_secret.txt', 'r'); if (strlen($_GET['filename']) < 11) { readfile($_GET['filename']); }`。`fopen` 只打开不读取也不关闭，文件偏移仍在 0；`readfile` 通过 fd 路径读取时，读到的是同一打开文件描述的当前内容。
- 参数长度限制 `< 11` 使 `/proc/self/fd/13`（15 字符）不可用，但 `/dev/fd/13`（10 字符）刚好可用；`/dev/fd/0` 到 `/dev/fd/9` 为 9 字符，`/dev/fd/10` 到 `/dev/fd/99` 为 10 字符，均在限制内。
- 遍历 0–99 即可覆盖绝大多数 PHP 进程同时打开的文件数量；命中目标 fd 时响应长度/内容会与其他 fd 明显不同（目录 fd 通常报错，普通 fd 返回文件内容）。

## 触发条件

- 目标 PHP 进程在请求处理期间打开了敏感文件（`fopen`、`file`、`SplFileObject` 等），且没有关闭。
- 存在用户可控路径的 `readfile`/`file_get_contents`/`include` 等文件读取函数。
- 路径长度限制允许 `/dev/fd/N`（至少能容纳 9–10 个字符）。
- 目标为 Linux（procfs/devfs 可用），PHP 未禁用 `/dev` 或 `/proc` 路径（`open_basedir` 未覆盖时通常可用）。

## 利用步骤

1. 通过报错、源码泄露或目录扫描拿到读取脚本源码，确认敏感文件在读取前已被 `fopen` 打开且未关闭。
2. 先请求 `filename=aa__^^.php` 或源码自身路径确认 LFI 可用。
3. 遍历 `/dev/fd/0` 到 `/dev/fd/99`，记录每个响应的状态码与长度；跳过 0/1/2（可能读取请求体/阻塞）。
4. 找到长度异常（如 179 字节）或内容为 flag 的 fd，即为 `fopen` 打开的敏感文件。
5. 若 `/dev/fd` 被过滤，改用 `/proc/self/fd/N`、`/proc/thread-self/fd/N`；若长度不足，尝试缩短路径或用其他入口。

## PoC

```python
import requests

base = "http://target/aa__%5E%5E.php"
for fd in range(3, 100):
    url = f"{base}?filename=/dev/fd/{fd}"
    try:
        r = requests.get(url, timeout=3)
    except Exception:
        continue
    if r.status_code == 200 and len(r.content) not in (0, 343):
        print(fd, len(r.content), r.text[:200])
```

```bash
# Burp Intruder：payload 设为 /dev/fd/§3§，数字 3-99，按响应长度排序
curl -s "http://target/aa__%5E%5E.php?filename=/dev/fd/13"
```

## 变体与关联

- 变体：`/proc/self/fd/N`、`/proc/thread-self/fd/N`、`/dev/fd/N` 三种等价路径，按长度限制选择。
- 变体：目标打开的是目录 fd 时，可继续用 `/dev/fd/N/文件名` 访问目录内文件（若长度允许）。
- 变体：文件已被读取过时偏移在 EOF，可尝试重新打开（`php://filter` 不适用 fd）或让应用重新执行 `fopen`；若应用使用 `file()` 一次性读完，则 fd 读取可能为空。
- 关联：[[web-php-file-inclusion-access-log-poisoning-webshell]]（另一类 LFI 利用）、[[web-php-open-basedir-bypass-classic-methods]]（路径限制绕过）；Java 侧同类见 `web-java-component-tomcat-multipart-tempfile-fd`。
- 边界：`open_basedir` 限制包含 `/dev`/`/proc`、`readfile` 被禁用、PHP 以非 Linux 运行、或敏感文件在读取前已关闭时，本手法失效。

## 检测与防御

- 打开敏感文件后立即读取并 `fclose()`，不要让句柄在请求生命周期内保持打开；不要把用户输入直接传给 `readfile`/`file_get_contents`。
- 对文件读取参数做白名单（固定文件名或 ID 映射），使用 `realpath()` 校验并拒绝 `/proc`、`/dev`、`php://` 等路径。
- 用 `open_basedir` 限制可访问目录（注意其解析行为和绕过历史），Web 进程降权，敏感文件权限最小化。
- 检测：请求路径出现 `/dev/fd/`、`/proc/self/fd/`、连续数字遍历；同一 IP 短时间内对同一脚本发起大量 3–99 的 fd 请求；响应长度异常或返回 `/proc` 相关错误。
