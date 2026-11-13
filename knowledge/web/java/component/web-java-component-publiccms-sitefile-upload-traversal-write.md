---
id: web-java-component-publiccms-sitefile-upload-traversal-write
title: PublicCMS 站点模板上传 originalFilename 目录穿越：-site.zip 后缀约束下的任意路径文件写入
type: scenario
domain: web
path: web/java/component
technique: publiccms-sitefile-upload-filename-traversal
aliases:
- PublicCMS doUploadSitefile
- sysSite/sitefile 上传穿越
- originalFilename 目录穿越
- -site.zip 后缀
- CmsFileUtils.getSafeFileName
tags:
- java
- publiccms
- file-upload
- path-traversal
- arbitrary-write
- filename
- cms
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: PublicCMS V4.0.202302.c（原文分析版本）
verification:
  verified_by: verifier-V587
  verified_at: '2026-11-12T14:06:13+08:00'
  notes: 已对照原文及全部13张截图核对：POST /admin/sysSite/doUploadSitefile 的 multipart filename=../../../../../../1.jpg-site.zip、doUploadSitefile 仅 endsWith("-site.zip") 校验、File dest=new File(getSiteFilePath(),originalName)、dest.mkdirs()+transferTo、修复版 getSiteFilePath(String) 套 getSafeFileName replace("..","") 均与截图一致；@Csrf/管理员后台前提属实。原文未展示落点响应与最终利用，仅有任意写原语且文件名须以 -site.zip 结尾，卡片 confidence=medium 已如实标注；dedup 与同后台模板替换 RCE 卡、generic originalFilename 上传卡非同链。
---

## 一句话结论

PublicCMS 后台站点模板上传接口 `/admin/sysSite/doUploadSitefile` 只校验原始文件名以 `-site.zip` 结尾，随后把该文件名直接拼到站点备份目录后 `transferTo()` 落盘；文件名中的 `../` 未被规范化，攻击者可把任意内容写到进程有权限的任意路径（最终文件名必须以 `-site.zip` 结尾），文章分析版本为 V4.0.202302.c，新版通过 `getSafeFileName` 删除 `..` 修复。

## 原理

- **入口与校验**：`SysSiteAdminController.doUploadSitefile` 接收 `MultipartFile file`，取 `file.getOriginalFilename()`；唯一校验是 `originalName.endsWith("-site.zip")`，不检查 `..`、路径分隔符、绝对路径或内容类型。
- **路径拼接**：通过校验后执行 `File dest = new File(siteComponent.getSiteFilePath(), originalName)`（原文截图）。漏洞版本调用无参 `getSiteFilePath()` 取站点备份目录（rootPath + BACKUP_PATH + SITE_FILE_PATH），原始文件名原样作为 `new File` 的第二个参数；修复版新增 `getSiteFilePath(String path)` 重载，在目录末尾追加 `CmsFileUtils.getSafeFileName(path)`（对含 `..` 的路径 `replace("..", "")`）。`new File` 本身不规范化 `.` 与 `..`，它们只在实际打开文件时由文件系统解析，因此 `../` 会逐级跳出备份目录。
- **为什么能任意写**：`dest.mkdirs()` 与 `file.transferTo(dest)` 把上传字节原样写入目标路径；`overwrite` 为 true（或目标不存在）时覆盖已有文件。Web 进程权限决定可写范围，数据目录、Web 目录、脚本目录通常可写。
- **后缀约束的含义**：目标文件名必须以 `-site.zip` 结尾，因此不能直接落 `.jsp`/`.sh`/`.bat`；但仍可写入/覆盖任意目录下以 `-site.zip` 命名的文件（如站点备份包），具体危害取决于目标环境是否有消费这些 zip 的功能或其他文件命名技巧，不能默认等同于无限制上传。
- **修复原理**：新版在路径拼接前套用 `CmsFileUtils.getSafeFileName()`，当路径含 `..` 时用 `replace("..", "")` 删除，阻断目录穿越；同时该修复也用于模板替换等同类文件操作。
- **鉴权前提**：接口位于 `/admin/` 后台并带 `@Csrf`，需要管理员会话与 CSRF token；不属于未授权漏洞。

## 触发条件

- 目标为 PublicCMS 受影响版本（原文分析 V4.0.202302.c）；后台 `/admin/sysSite/doUploadSitefile` 可达。
- 攻击者持有管理员会话与有效 `_csrf` token。
- 目标路径对 Web 进程可写，且目标文件名可以以 `-site.zip` 结尾。
- 修复版部署了 `getSafeFileName` 或对文件名做了规范化/白名单时失效。

## 利用步骤

1. 登录 PublicCMS 后台，打开“站点 → 站点模板 → 上传”，抓取 multipart 请求，记录 `_csrf` 与会话 Cookie。
2. 修改 multipart 中的 `filename`，插入 `../` 上溯到目标目录，并保持以 `-site.zip` 结尾，例如 `../../../../../../1.jpg-site.zip`。
3. 发送请求：`POST /admin/sysSite/doUploadSitefile?callbackType=closeCurrent&navTabId=sysSite/sitefile`。
4. 根据服务器数据目录结构确认落点（`getSiteFilePath` 基于 rootPath + BACKUP_PATH + SITE_FILE_PATH），必要时调整 `../` 层数与目标文件名。
5. 写入后按业务场景评估后续利用：覆盖备份 zip、配合备份/导入功能或写其他 `*-site.zip` 文件；若目标还有其他文件操作缺陷可组合。
6. 清理写入文件并在后台操作日志（`upload.sitefile`）中核对痕迹。

## PoC

```http
POST /admin/sysSite/doUploadSitefile?callbackType=closeCurrent&navTabId=sysSite/sitefile HTTP/1.1
Host: target:8080
Cookie: <admin session>
Content-Type: multipart/form-data; boundary=----b

------b
Content-Disposition: form-data; name="_csrf"

<token>
------b
Content-Disposition: form-data; name="overwrite"

true
------b
Content-Disposition: form-data; name="file"; filename="../../../../../../1.jpg-site.zip"
Content-Type: image/jpeg

<zip 内容>
------b--
```

```java
// 漏洞代码（原文 V4.0.202302.c 形态）
if (originalName.endsWith("-site.zip")) {
    File dest = new File(siteComponent.getSiteFilePath(), originalName); // originalName 含 ../
    if (overwrite || !dest.exists()) { dest.mkdirs(); file.transferTo(dest); }
}
// 修复：CmsFileUtils.getSafeFileName(path) 对含 ".." 的路径 replace("..", "")
```

说明：原文仅展示请求与漏洞代码，未给出写入落点的响应/文件列表截图，故本卡 confidence 为 medium；PoC 未在本机执行。

## 变体与关联

- 变体：`../` 层数按 `rootPath + BACKUP_PATH + SITE_FILE_PATH` 到目标目录的实际深度调整；Windows 可用反斜杠或混合分隔符。
- 变体：若目标存在对 `*-site.zip` 备份包的导入/解压功能，可进一步评估 zip 内条目穿越或内容替换带来的二次影响（原文未演示）。
- 关联：[[web-java-component-publiccms-template-replace-traversal-execscript-rce]]（同一后台的模板替换穿越 + execScript 组合 RCE，修复同样依赖 getSafeFileName）、[[web-generic-file-upload-template-relative-path-original-filename-arbitrary-write]]（另一 CMS 的 originalFilename 穿越任意写）。
- 边界：非管理员/无 CSRF token 无法调用；文件名后缀限制使直接落 webshell 不可行；修复版删除 `..` 后穿越失效。

## 检测与防御

- 检测：`doUploadSitefile` 请求的 multipart filename 含 `../`、反斜杠或绝对路径；落盘路径超出站点备份目录；后台日志出现目标异常的 `upload.sitefile` 操作。
- 防御：升级到包含 `getSafeFileName` 修复的版本；对原始文件名只保留 basename 并做规范化（`normalize()`/`toRealPath()` + 前缀校验），拒绝 `..` 与绝对路径。
- 加固：后台管理员强口令 + MFA、CSRF 校验；上传目录与站点数据目录权限最小化；对备份/模板目录做完整性监控。
