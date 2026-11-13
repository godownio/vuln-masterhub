---
id: web-php-rce-kitecms-template-fileedit-path-traversal-write-read
title: KiteCMS 后台模板编辑 fileEdit 的 path 穿越：任意文件写入（可覆盖 WebShell）与任意文件读取
type: scenario
domain: web
path: web/php/rce
technique: kitecms-template-fileedit-pregmatch-theme-traversal-file-write-read
tags:
- php
- kitecms
- thinkphp
- path-traversal
- arbitrary-file-write
- arbitrary-file-read
- cms
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V644
  verified_at: '2026-11-13T03:32:28+08:00'
  notes: 已对照原文与截图 img18-30 核对：fileEdit 拼接 rootpath、拦截条件 !file_exists && !preg_match(#/theme/#)、POST file_put_contents+htmlspecialchars_decode、GET file_get_contents+htmlspecialchars+base64_decode(name)（img19/25/30）；img21 POST path=../../robots.txt&html=ceshi 返回200；img23/30 GET 同路径回显 ceshi；img26 前端 operate() AJAX POST。已修正 is_file()→file_exists 并把 && 短路放行逻辑写准确；getshell 为能力推论（原文只实测覆盖 robots.txt），卡内已注明需目标存在可写 PHP 文件。未验证点：未复跑；未实测覆盖 PHP 文件。
url: /docs/web/php/rce/web-php-rce-kitecms-template-fileedit-path-traversal-write-read/
draft: false
kb_aliases:
- KiteCMS 任意文件写入
- KiteCMS 任意文件读取
- admin/template/fileedit
- 模板编辑 /theme/ 校验绕过
---

# 一句话结论

KiteCMS 后台模板编辑接口 `admin/template/fileedit` 用 `$rootpath = root_path.'theme/'.$template.'/'.$path` 拼接路径，只用 `if (!file_exists($rootpath) && !preg_match('#/theme/#', $rootpath)) throw ...` 作拦截、未做 `realpath` 归一化：`file_exists` 为真即短路放行，传入 `path=../../robots.txt` 即可穿越出模板目录。POST 时 `html` 参数经 `htmlspecialchars_decode()` 后 `file_put_contents($rootpath, ...)` 可写入任意已存在的可写文件（覆盖 Web 目录 PHP 文件即 getshell）；非 POST（GET）时 `file_get_contents($rootpath)` 读取任意可读文件并渲染回显。

# 原理

- **路径拼接**：`fileEdit()` 取 `Request::param('path')`，从站点配置取当前 `$template`，拼接 `Env::get('root_path').'theme'.DIRECTORY_SEPARATOR.$template.DIRECTORY_SEPARATOR.$path`；`path` 完全用户可控。
- **校验缺陷**：只检查 `file_exists($rootpath)` 与 `preg_match('#/theme/#', $rootpath)`，且写成 `if (!file_exists($rootpath) && !preg_match('#/theme/#', $rootpath))` 才抛异常：只要目标文件已存在（`theme/<tpl>/../../robots.txt` 即如此）或路径串含 `/theme/` 就放行，`../` 完全未过滤、也未用 `realpath` 归一化，实际读写落在归一化后的 Web 根目录文件。
- **写分支**：`Request::isPost()` 为真时，若 `is_writable($rootpath)`，执行 `file_put_contents($rootpath, htmlspecialchars_decode(Request::param('html')))`；写入内容完全可控，`htmlspecialchars_decode` 只是还原实体，不影响 PHP 代码。
- **读分支**：非 POST 时，若 `is_readable($rootpath)`，`file_get_contents` 读取内容，`htmlspecialchars` 后连同 `path`、`name=base64_decode(param)` 传给 `fetch('fileedit')` 模板渲染，前端编辑器展示文件内容。
- **为什么是漏洞**：模板编辑功能本应只允许改 `theme/<模板>/` 下的文件，但校验基于 `file_exists` 与字符串包含而非规范化后的路径前缀；`..` 穿越加上写权限，等价于后台任意文件写入（前端 JS 也直接用 AJAX POST 到该 URL，见原文截图）。
- **利用价值**：可覆盖任意已存在的可写文件；若目标目录有可写的 `.php` 文件（模板缓存、已有脚本），写入 PHP 代码即可执行；读分支可直接读取配置文件、数据库配置等敏感文件。

# 触发条件

- 已进入 KiteCMS 后台（管理员会话）。
- 目标文件已存在且 Web 进程可写（写分支）或可读（读分支），路径中可包含 `../`。
- 模板目录 `theme/<template>` 存在（用于通过拼接与正则校验）。

# 利用步骤

1. 进入后台“系统-模板”，打开任意文件的编辑页，抓取 `admin/template/fileedit` 请求。
2. 写文件：`POST path=../../robots.txt&html=ceshi`，响应 `code:200` 即写入成功；原文即用该方式覆盖 Web 根 `robots.txt`。
3. 读文件：`GET /admin/template/fileedit.html?path=../../robots.txt`，响应 HTML 的编辑器区域显示文件内容（原文显示 `ceshi`）。
4. getshell：把 `path` 指向 Web 目录下任意已存在且可写的 `.php` 文件（如可写模板/脚本），`html` 填入 `<?php ... ?>`；或先把可写文本文件改名为 PHP 的场景另作探测。
5. 读取敏感文件：`path=../../config/database.php`、`../../.env` 等（需可读）。

# PoC

```http
POST /admin/template/fileedit HTTP/1.1
Content-Type: application/x-www-form-urlencoded

path=../../robots.txt&html=ceshi
```

```http
GET /admin/template/fileedit.html?path=../../robots.txt HTTP/1.1
```

# 变体与关联

- `name` 参数经 `base64_decode` 后传给模板作为显示名，可控制编辑页标题等展示内容。
- 同一 `$rootpath` 既用于写也用于读，POST/GET 方法决定分支；前端 `CodeMirror` 编辑器 `operate()` 即向 `admin/template/fileedit` POST。
- 与通用模板写马类漏洞（如 DedeCMS 模板保存穿越）原理相同，但本卡是 KiteCMS 的具体入口与校验绕过。

# 检测与防御

- 检测：审计 `admin/template/fileedit` 请求的 `path` 参数中出现 `../`、绝对路径或换行；监控模板目录外文件被写入/读取；Web 目录文件完整性监控。
- 防御：用 `realpath()` 归一化后校验前缀必须位于 `theme/<template>/` 内，拒绝 `..`、绝对路径与空字节；模板编辑器只允许编辑模板后缀文件；后台最小权限与操作审计；Web 进程对非模板目录只读。
