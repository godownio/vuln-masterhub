---
id: web-php-framework-yii-oa-saveupload-commented-extension-unauth-upload
title: Yii OA SaveUpload::saveFile 扩展名白名单被整段注释 + 依赖忽略路由未授权：/salary/record/upload 等接口任意 PHP 上传 getshell
type: scenario
domain: web
path: web/php/framework
technique: yii-oa-saveupload-commented-extension-unauth-upload
aliases:
- SaveUpload::saveFile
- Yii OA 任意文件上传
- 扩展名校验被注释
- dependIgnoreValueList 未授权
- dependIgnoreList 依赖忽略路由
- disableCsrfAction upload
- move_uploaded_file 审计
tags:
- php
- yii
- oa
- file-upload
- unrestricted-upload
- webshell
- code-audit
- auth-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V522
  verified_at: '2026-11-11T13:24:32+08:00'
  notes: 已通读原文并逐张核对33张截图：图10 SaveUpload::saveFile 中 getExtension 后白名单 if(!in_array(strtolower(self::$ext),['jpg','jpeg','png','gif'])) 确实被 /*...*/ 整段注释，随后 generateFileName + saveAs；图11 UploadedFile::saveAs 无校验；图12/16 RecordController 实际属性为 $disableCsrfAction=['upload','ajax','batch-import'] 与 $dependIgnoreList（含 salary/record/upload），原文正文写作 $dependIgnoreValueList 与截图不符，已按截图修正卡片并注明；图13-16 调用点为 \system\modules\main|party\extend\Upload::className()；图17 另一控制器 dependIgnoreList；原文 PoC POST /index.php/salary/record/upload 上传 1.php 与卡片一致。未验证点：原文未给出该上传请求的成功回显或木马访问截图，最终 getshell 依据完整代码链（白名单注释+saveAs 无二次校验+作者称这些路由存在未授权访问）判断，未实机复现。dedup 推荐 new，top 候选 web-php-framework-yii2-uploadedfile-saveas-unfiltered 是 Yii2 框架层 saveAs 无校验（入口为业务拼接 name 后调用），本卡是应用自定义 SaveUpload 白名单被注释+依赖忽略未授权路由，入口/代码依据不同，非同链；dup-scan.json 无涉及本篇 pair。
---

## 一句话结论

某 Yii 框架 OA 系统的上传封装 `SaveUpload::saveFile()` 把扩展名白名单 `if (!in_array(strtolower(self::$ext), ['jpg', 'jpeg', 'png', 'gif'])) { return false; }` 整段注释掉，随后直接 `$fileObj->saveAs($absolutePath)`；全局搜索调用点后发现 `contacts/default/upload`、`salary/record/upload`、`knowledge/default/upload` 等 action 在免鉴权配置（`$disableCsrfAction`/`$dependIgnoreList`）中，未登录即可向 Web 目录上传 `1.php` 并执行。

## 原理

- **上传封装自身失效**：`system/modules/main/extend/SaveUpload.php::saveFile()` 先 `getExtension()` 取扩展名，但本该拒绝非图片扩展名的 `in_array` 判断被 `/* ... */` 注释；后续 `generateFileName()` 与 `$fileObj->saveAs()` 都不做二次校验（Yii 的 `UploadedFile::saveAs` 本身也只负责移动文件），于是任意扩展名都会落到服务器。
- **为什么扩展名注释很隐蔽**：注释后的代码仍保留 `self::$ext` 赋值，静态看像“取了扩展名”，但实际没有任何比较；只有逐行读注释块才能发现。文中作者正是全局搜 `move_uploaded_file` 找到 `SaveUpload.php` 的 `saveAs` 封装后才注意到。
- **调用点通过命名空间隐藏**：`SaveUpload::saveFile(` 的调用分散在 `system/modules/main/extend/Upload.php`、`modules/party/extend/Upload.php` 等文件中，控制器通过 `'class' => \system\modules\<module>\extend\Upload::className()` 配置上传行为；因此不能只搜类名，要搜 `SaveUpload::saveFile(`、`Upload::className()` 及其命名空间形式。
- **未授权来自路由配置**：Yii 的 `$disableCsrfAction` 关闭 CSRF 校验、`$dependIgnoreList` 列出不参与权限依赖检查的路由（如 `salary/record/upload`；原文正文写作 `$dependIgnoreValueList`，但代码截图中实际属性名为 `$dependIgnoreList`），本质上暴露了免登录/免权限的 upload action；配合 `basename`/`iconv` 处理后文件名仍可控，攻击者只要找到这些 action 就能匿名上传。
- **落点可执行**：`Upload.php` 把 `dir` 设为模块目录（如 `salary/template/import`），文件被写到 Web 可达目录且保留 `.php` 后缀，PHP-FPM/Apache 按扩展名解析即 getshell。

## 触发条件

- 目标为使用该 `SaveUpload` 封装的 Yii OA 系统（原文为未公开 0day，产品名未披露）。
- `SaveUpload::saveFile` 的扩展名白名单被注释/缺失，且 `saveAs` 前无其他校验。
- 存在调用该封装的 `upload` action，且该 action 位于 `$disableCsrfAction`/`$dependIgnoreList` 等免鉴权配置中，或本身未做权限校验。
- 上传目录在 Web 根下且允许 PHP 解析。

## 利用步骤

1. 源码审计：全局搜索 `move_uploaded_file` / `saveAs(`，定位 `SaveUpload::saveFile`，确认扩展名检查被注释。
2. 全局搜索 `SaveUpload::saveFile(` 与 `\system\modules\...\extend\Upload::className()`，列出所有上传 action 及 `dir` 配置。
3. 在各控制器里找 `$disableCsrfAction`、`$dependIgnoreList`（原文正文写作 `$dependIgnoreValueList`）、`$ignoreList`，筛出未鉴权的 upload 路由（原文命中 `contacts/default/upload`、`salary/record/upload`、`knowledge/default/upload`）。
4. 构造 multipart 请求上传 `1.php`（`filename="1.php"`，Content-Type 伪装 `image/png`），发送到 `/index.php/salary/record/upload`。
5. 根据响应/目录规则拼接访问 URL（如 `/upload/.../1.php`），确认 PHP 执行后替换为功能更完整的 WebShell。

## PoC

```http
POST /index.php/salary/record/upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQayVsySyhSwgpmLk

------WebKitFormBoundaryQayVsySyhSwgpmLk
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/png

<?php phpinfo();?>
------WebKitFormBoundaryQayVsySyhSwgpmLk--
```

## 变体与关联

- 变体：`directory`/`file_name`/`resetSize` 等配置由 `Upload.php` 传入，若文件名做了 `iconv` 转换仍不影响 `.php` 后缀；也可上传 `.phtml`、`.php5` 等可解析后缀。
- 变体：不同模块的 `Upload` 封装实现不同（`main`/`party`/`performance`），但最终都调用 `SaveUpload::saveFile`；任意一个未鉴权 action 即可。
- 关联：[[web-php-framework-yii2-uploadedfile-saveas-unfiltered]]（Yii2 `UploadedFile::saveAs` 不做校验的框架层根因）、[[web-generic-file-upload-feehicms-ad-upload-saveas-rce]]（Yii2 saveAs 保留 php 后缀的同类产品案例）。
- 边界：若部署方补回扩展名白名单、上传目录禁 PHP 或 upload action 全部鉴权，利用失败；Yii 路由大小写/连字符差异会影响 action 命中（见 Yii 路由规则）。

## 检测与防御

- 检测：审计时关注被注释的 `in_array(...['jpg','png'...])` 校验、`saveAs` 前的空校验、`$disableCsrfAction`/`$dependIgnoreList` 中的 upload 路由；运行时监控上传目录新增 `.php` 文件与 `move_uploaded_file` 写入 Web 根的行为。
- 防御：恢复服务端扩展名/魔数白名单，重命名为随机文件名并在 Web 根外存储；上传目录关闭 PHP 解析；所有 upload action 强制鉴权并移除不必要的免鉴权配置；对上传接口做内容检测与审计。
- 加固：定期做源码审计（重点搜 `move_uploaded_file`、`saveAs`、`$disableCsrfAction`），把上传封装改为统一安全组件，禁止业务自行实现。
