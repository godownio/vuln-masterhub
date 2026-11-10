---
id: web-php-file-inclusion-manage-file-param-wfuzz-traversal
title: 登录后 manage.php "File does not exist"：wfuzz 爆破出 LFI 参数 file，用 ../ 目录穿越读任意系统文件
type: scenario
domain: web
path: web/php/file-inclusion
technique: lfi-param-fuzz-directory-traversal-file-read
aliases:
- File does not exist LFI 参数爆破
- wfuzz 爆文件包含参数名
- ../../ 目录穿越读 /etc/passwd
- manage.php file 参数 LFI
tags:
- php
- lfi
- file-inclusion
- directory-traversal
- wfuzz
- parameter-fuzzing
- pentest
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-13
  verified_at: '2026-11-08T07:35:06+08:00'
  notes: 已对照原文与图核对：图16 登录后 manage.php 回显 File does not exist；图19 wfuzz -z file,common.txt --hh 1341 "manage.php?FUZZ=../../../../../etc/passwd" 命中 Payload=file(200,93L)；图21 ?file=../../../../etc/passwd 读出 passwd 全部用户；图22 用同一参数读 /etc/knockd.conf——卡片『wfuzz 爆参数名 file + 目录穿越任意文件读』与图逐项一致。与同篇 session-upload 卡的区分：本卡是参数发现+任意文件读(读取型)，后者是同一点的条件竞争包含 getshell(执行型)，sink 使用方式与危害不同，且 dedup 复跑把后者判为 new(cos 0.8788)，不构成同链重复。未验证点：原文对『读文件还是 include』自承先误判、后由解法二证实可包含(卡片已在原理中写明)；靶场未复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

登录后台后页面回显 "File does not exist"，说明存在把用户输入拼进文件路径的功能；用 wfuzz 对参数名做字典爆破（`?FUZZ=../../../../etc/passwd`，按响应长度/字数过滤基线）可发现隐藏的 LFI 参数 `file`，进而用 `../../../../` 目录穿越读取 `/etc/passwd`、`/etc/knockd.conf`、站点 `config.php` 等任意文件；若底层是 `include` 而非纯读取，还能包含含 PHP 代码的文件执行。

## 原理

- 后台"管理/记录"类页面（如 `manage.php`）常把 GET 参数作为模板/文件路径交给 `include`、`require`、`file_get_contents`、`readfile` 等，且未做白名单、未过滤 `../`、未做 `realpath` 前缀校验，构成 LFI。
- 参数名未知时，用 wfuzz/ffuf 对参数名做字典爆破：构造 `?FUZZ=../../../../etc/passwd`，逐个替换 `FUZZ`；绝大多数参数名不改变响应（仍是 "File does not exist" 基线页），只有正确的参数名会返回 `/etc/passwd` 内容，从而使响应行数/字数/字符数显著变化。用 `--hh <基线字符数>`（按响应字符数隐藏基线）过滤噪声，命中项即为参数名（本题为 `file`）。
- `File does not exist` 是文件不存在时的固定错误串，正好可作为隐藏基线；wfuzz 的 `--hh`/`--hl`/`--hw` 按 Chars/Lines/Words 过滤。
- 目录穿越：拼接 N 个 `../` 回到根目录后接目标绝对路径（如 `../../../../etc/passwd`）；读取系统账号、服务配置、应用源码/配置文件。
- 若拼接的是 `include` 而非 `readfile`，被包含文件里的 `<?php ... ?>` 会被执行——本题解法一作者误以为是纯文件读取，解法二证实同一 `file` 参数可包含 session 文件 getshell（见关联卡）。

## 触发条件

- 目标页面把用户可控参数拼进文件路径，且未做路径规范化/白名单；
- 参数名未直接出现在 HTML/JS 中（需爆破）；
- 存在可用于区分"命中/未命中"的稳定错误回显或响应长度差异；
- Web 进程对目标文件有读权限；若为 include，还需 session 文件等可写 PHP 文件位置。

## 利用步骤

1. 登录后观察异常提示（"File does not exist"），确认存在文件路径拼接。
2. 抓取带会话 Cookie 的请求，用 wfuzz 对参数名爆破：`-w common.txt --hh <基线字符数> "http://target/manage.php?FUZZ=../../../../etc/passwd"`，带 `-b 'PHPSESSID=...'` 保持登录。
3. 从命中结果得到参数名（file），访问 `?file=../../../../etc/passwd` 读取账号列表。
4. 继续读 `/etc/knockd.conf`、应用 `config.php` 等敏感文件，为后续敲门/连库/提权收集信息。

## PoC

```bash
# 1) 爆破参数名（隐藏基线响应）
wfuzz -w /usr/share/wfuzz/wordlist/general/common.txt \
      -b 'PHPSESSID=<已登录会话>' --hh <基线字符数> \
      "http://<target>/manage.php?FUZZ=../../../../etc/passwd"

# 2) 命中后读取任意文件
curl -b 'PHPSESSID=<已登录会话>' \
  "http://<target>/manage.php?file=../../../../etc/passwd"
curl -b 'PHPSESSID=<已登录会话>' \
  "http://<target>/manage.php?file=../../../../etc/knockd.conf"
```

说明：结构复现的通用命令，参数名/穿越层数/Cookie 按目标调整；不访问、不执行。

## 变体与关联

- 变体：参数名也可从 JS/HTML 注释、备份源码、报错信息直接获得；爆破工具可用 ffuf/Burp Intruder。
- 变体：`../` 被过滤时用 `....//`、`..%2f`、双写编码、绝对路径直接包含、PHP 流包装器 `php://filter` 读源码。
- 变体：同一 LFI 点可用于包含 `/var/lib/php/sessions/sess_*`（见关联卡）、`/proc/self/environ`、日志文件等 getshell。
- 关联：[[web-php-file-inclusion-session-poisoning-sess-file]]（session 文件包含）；[[web-php-file-inclusion-user-ini-session-save-path-webshell]]；[[pentest-initial-access-knockd-conf-port-knocking-ssh]]（读 knockd.conf 后的敲门）。

## 检测与防御

- 检测：请求中出现大量 `FUZZ`/字典参数名枚举、URL 里出现 `../` 或 `etc/passwd`/`knockd.conf`/`config.php` 等敏感路径；日志中同一会话对文件路径参数的异常高频访问。
- 检测：Web 进程读取 /etc/passwd、/etc/knockd.conf、其它 Web 根目录外文件。
- 防御：文件路径用白名单映射（ID→固定文件），禁止直接拼接用户输入；用 `realpath()` 校验结果必须在允许目录内；过滤 `..` 与空字节。
- 防御：敏感配置（knockd.conf、DB 口令文件）限制 Web 进程读权限；关闭不必要的文件包含参数；WAF 拦截目录穿越特征。
