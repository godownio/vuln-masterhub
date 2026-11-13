---
id: web-php-rce-joomla-language-pack-zip-webshell
title: Joomla 后台扩展安装篡改语言包 ZIP：administrator/language/<tag>/ 下植入 PHP 后访问执行 WebShell（4.2.7 实测）
type: scenario
domain: web
path: web/php/rce
technique: joomla-language-pack-zip-installer-webshell
aliases:
- Joomla 语言包 getshell
- Joomla 后台扩展安装 getshell
- joomla language pack webshell
- com_installer 语言包
- administrator/language shell.php
tags:
- php
- joomla
- cms
- backend
- rce
- webshell
- language-pack
- zip
- com_installer
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V567
  verified_at: '2026-11-12T09:14:10+08:00'
  notes: 已对照原文与21张截图核对：官方zh-CN语言包内administrator/zh-CN/放shell.php重打包→后台com_installer上传提示应用安装成功(图17)→访问/administrator/language/zh-CN/shell.php得phpinfo(图18,PHP8.1.16)；卡内包结构/manifest/落地路径/触发条件与原文一致；媒体上传加php扩展后400未打通、模板error.php替代路径(图20/21)均如实记录。affected_versions未设置：原文仅说明靶场为4.2.7且该利用不依赖特定版本区间，符合brief不猜版本。dedup：最高相关为web-php-rce-joomla-admin-template-editor-webshell(cos 0.911, related)，入口(com_installer语言包ZIP)与落地路径(administrator/language)不同，非重复；与CMS addon info.php ZIP安装器/pluck主题ZIP为不同CMS/不同包类型。worker merge核对：CVE-2023-23752→web-php-joomla-api-config-application-public-db-credential-leak、DB改密→web-php-joomla-db-root-reset-admin-password-hash、模板error.php→web-php-rce-joomla-admin-template-editor-webshell，三张既有卡均verified且同场景，merge成立；媒体上传400未打通排除正确；登录明文密码劫持(源码改动)/MFA配置锁死/表结构/扫描工具非攻击场景不建卡合理。未验证点：未实机复现
---

## 一句话结论

获取 Joomla 管理员会话后，下载官方语言包（如 zh-CN 完整包），在包内 `administrator/zh-CN/`（安装后对应 `administrator/language/zh-CN/`）放入 `shell.php` 并重新打包，通过后台「系统 → 安装 → 扩展安装 → 上传文件安装」上传；安装器不检查包内 PHP 内容即解压语言文件，随后访问 `/administrator/language/zh-CN/shell.php` 即可执行代码（原文在 Joomla 4.2.7 实测 phpinfo）。

## 原理

- **安装入口即写文件能力**：Joomla 后台的扩展安装（com_installer）接受上传的 ZIP 包，按包内 manifest/语言包结构把文件解压到站点目录；语言包的文件被安装到 `administrator/language/<语言标签>/`（后台）与 `language/<语言标签>/`（前台）。
- **缺少内容检查**：语言包安装不会校验包内是否夹带 `.php` 可执行文件，也不会把语言目录设为不可解析；只要 zip 结构与官方语言包一致（顶层 `administrator/zh-CN/...`、`language/zh-CN/...`、manifest xml），即可通过安装。
- **为什么能执行**：安装后的语言文件位于 Web 根下的 `administrator/language/zh-CN/`，Apache/PHP 容器会按路径解析 PHP；攻击者追加的 `shell.php` 可直接访问执行，权限即 Web 服务账号。
- **与模板/模块安装的区别**：语言包安装不需要触发模板渲染或修改现有模板，文件直接落在可访问目录，稳定性较高；原文同时演示模板编辑 error.php 的方式作为替代。
- **媒体上传路径的限制**：原文还尝试在「全局配置 → 媒体文件 → 允许的扩展」中加入 php 后上传 shell，但 4.2.7 返回 HTTP 400（请求日志可见 `com_media&format=json...400`），说明该版本对媒体上传有额外限制；语言包安装未受此限制。

## 触发条件

- 攻击者已取得 Joomla 超级管理员/具备扩展安装权限的后台会话（如通过 CVE-2023-23752 泄露 DB 口令后改管理员密码）。
- 后台「扩展安装」可用，上传目录可写，`administrator/language/` 目录可写且允许 PHP 解析（默认 Apache + PHP 环境成立）。
- 安装器未对上传包做内容扫描/签名校验（默认 Joomla 行为）。

## 利用步骤

1. 从 Joomla 官方下载与目标版本匹配的语言包（如 zh-CN 完整包），解压。
2. 在包内 `administrator/zh-CN/` 目录放入 `shell.php`（内容可为 `<?php phpinfo();?>` 或一句话），保持其它语言文件与 manifest 不变。
3. 重新打包为 zip（保持官方包目录结构；文件名任意）。
4. 登录后台，系统 → 安装 → 扩展安装 → 上传文件安装，上传该 zip；页面提示「应用安装成功」。
5. 访问 `/administrator/language/zh-CN/shell.php`，确认代码执行；随后可替换为功能更完整的 WebShell。
6. 若语言包路径不通，可改用「模板管理 → 编辑模板 → error.php 插入 PHP」后访问 `/templates/<template>/error.php`（原文同样实测成功）。

## PoC

篡改后的语言包结构示意：

```text
zh-CN_joomla_lang_full_x.y.z/
├── administrator/zh-CN/
│   ├── ...（官方语言文件）
│   └── shell.php          # <?php phpinfo(); ?>
├── language/zh-CN/
│   └── ...
└── zh-CN.xml（语言包 manifest）
```

安装后访问：

```http
GET /administrator/language/zh-CN/shell.php HTTP/1.1
Host: target:18081
```

原文返回 phpinfo 页面（PHP Version 8.1.16），证明语言目录内 PHP 被执行。上传安装请求为后台表单提交（含 CSRF token），原文未给出原始 multipart 报文。

## 变体与关联

- 模板编辑器：后台编辑当前模板 `error.php`，首行插入 `<?php phpinfo();?>`，访问 `/templates/cassiopeia/error.php`；与库中「Joomla 后台 com_templates 模板编辑写 WebShell」卡同属后台文件写，入口文件不同（error.php vs 新建 cmd.php）。
- 媒体文件上传：在媒体选项允许 php 扩展后上传，但 4.2.7 实测返回 400，未打通。
- 前置链：CVE-2023-23752 未授权泄露 DB 账号口令 → 连库覆盖管理员 password 哈希 → 登入后台 → 本卡 getshell。
- 通用 CMS addon zip 安装器 RCE 卡描述 templates/modules 的 info.php 校验绕过；本卡是 Joomla 语言包安装这一具体包类型。

## 检测与防御

- 限制扩展安装权限给超级管理员，最小化后台暴露与弱口令；及时修复 CVE-2023-23752 等前置漏洞。
- 对 `administrator/language/`、`language/`、`templates/` 做文件完整性/新增文件监控，出现 `.php` 视为高危。
- 安装包内容扫描/签名校验；安装目录禁止 PHP 解析（如用 `php_flag engine off`/Nginx location 禁止 language 目录执行 php）。
- 日志排查：com_installer 上传非官方语言包、`administrator/language/*/*.php` 访问（404 后的 phpinfo 页面）、上传后紧跟的异常 PHP 请求。
