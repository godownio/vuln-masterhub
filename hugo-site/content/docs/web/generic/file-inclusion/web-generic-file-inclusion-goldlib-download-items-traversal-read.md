---
id: web-generic-file-inclusion-goldlib-download-items-traversal-read
title: 金盘 download.jsp items 参数路径穿越：ROOTPATH 拼接后直接 FileInputStream 任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: goldlib-download-items-traversal-read
tags:
- web
- file-read
- path-traversal
- java
- jsp
- goldlib
- opac
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:23:01+08:00'
  notes: 已对照原文与图25-26核对：download.jsp 取 items[]，expandFileList 用 parseToPath(ROOTPATH+'/'+filePath)，length==1 且非目录时 new FileInputStream(splitPath+filePath[0]) 输出；未校验 ../，PoC GET items=../../../../etc/passwd 成立。原文未展示实际读取响应，属代码审计确认；未复跑 PoC。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-goldlib-download-items-traversal-read/
draft: false
kb_aliases:
- 金盘任意文件读取
- download.jsp items
- expandFileList 路径穿越
- ROOTPATH 拼接
- pages/admin/tools/file/download.jsp
---

## 一句话结论

金盘图书馆的 `pages/admin/tools/file/download.jsp` 接收 `items` 参数数组，经 `expandFileList` 用 `StringUtil.parseToPath(CommonConstants.ROOTPATH + "/" + filePath)` 拼接后直接 `new FileInputStream(splitPath + filePath[0])` 输出文件，未校验 `../`，构造 `items=../../../../etc/passwd` 即可读取 Web 根之外的任意文件。

## 原理

- **参数与拼接**：JSP 取 `String[] filePath = request.getParameterValues("items")`；`expandFileList(filePath, false)` 对每个元素执行 `filePath = StringUtil.parseToPath(CommonConstants.ROOTPATH + "/" + filePath)`，只是做路径分隔符/点段规范化（`parseToPath` 通常处理 `\`、`//`、`./`），并不会阻止 `../` 越出根目录。
- **读取**：当 `filePath.length == 1` 且目标不是目录时，设置 `Content-Type` 与 `Content-Disposition: attachment`，然后 `new FileInputStream(splitPath + filePath[0])` 逐块写到响应；`splitPath` 为 `CommonConstants.ROOTPATH`，所以最终路径仍是“Web 根 + 用户路径”。
- **为什么成立**：文件路径完全由请求参数控制，代码中没有任何 `canonicalPath.startsWith(root)`、后缀白名单或 `..` 过滤；`expandFileList` 的规范化反而可能把 `..` 保留下来交给 `FileInputStream`。
- **影响**：可读取配置文件（数据库口令、AK/SK）、`/etc/passwd`、Web 源码、日志等；在 Windows 下可读 `C:\Windows\win.ini`、应用配置；为后续 RCE/横向提供凭据。

## 触发条件

- 目标部署了金盘图书馆系统，`pages/admin/tools/file/download.jsp` 可访问（直接访问 JSP 或在 `/pages` 未被 Shiro/CAS 完全拦截时）。
- `items` 参数可控且为单文件（数组长度 1）时走文件读取分支；多文件/目录会走 ZIP 打包分支。
- 运行用户对目标文件有读权限（Web 服务账户通常可读应用配置和系统文件）。
- 若 CAS 开启且未放行 `/pages/**`，需要有效会话或先绕过鉴权。

## 利用步骤

1. 访问 `/pages/admin/tools/file/download.jsp`，确认页面/接口存在（可按金盘指纹与目录结构探测）。
2. 构造 `items=../../../../etc/passwd`（Linux）或 `items=..\..\..\..\Windows\win.ini`（Windows，注意 URL 编码）。
3. 请求并观察响应头 `Content-Disposition: attachment` 与文件内容；若返回 ZIP，说明路径被判定为目录，换更深层文件或调整参数。
4. 读取应用配置（如 `WEB-INF/classes/jdbc.properties`、`web.xml`）获取数据库/中间件凭据，或读取 `/proc/self/environ`、日志。
5. 用读到的凭据进行数据库/后台/横向利用；在授权测试中仅读取证明文件（如 `/etc/passwd`）并立即停止。

## PoC

```http
GET /pages/admin/tools/file/download.jsp?items=../../../../etc/passwd HTTP/1.1
Host: target.example
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

```text
# Windows 目标：
GET /pages/admin/tools/file/download.jsp?items=..%5c..%5c..%5c..%5cWindows%5cwin.ini HTTP/1.1
# 若 parseToPath 把 / 转为 \，可用 ../../../../ 形式尝试。
```

## 变体与关联

- 变体：`items` 传多个值或目录时走 ZIP 打包，可批量下载整个目录（含源码/配置）。
- 变体：`expandFileList` 还会把目录展开为文件列表，若可控制目录，可枚举敏感文件。
- 关联：[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（Java `new File(root + path)` 同类穿越）、[[web-generic-file-inclusion-oa-logfiledownload-createfwfromjoa-arbitrary-read]]（OA 下载接口穿越）、[[web-java-oa-download-servlet-followup-delete-arbitrary-file]]（下载+删除组合）。
- 边界：`parseToPath` 的具体实现若对 `..` 做了拦截则利用失败；CAS/Shiro 可能要求登录；目录分支返回 ZIP 而非单文件。

## 检测与防御

- 检测：请求 `download.jsp` 的 `items` 包含 `../`、`..\`、绝对路径或编码后的点段；响应中出现 `/etc/passwd`、`win.ini`、`WEB-INF` 等敏感内容。
- 修复：对 `items` 做规范化后校验 `canonicalPath` 必须位于允许的下载根目录内；拒绝绝对路径与 `..`；只允许白名单后缀/文件 ID。
- 加固：Web 服务账户最小权限；敏感配置加密；上传/下载目录与 Web 根分离；WAF 拦截路径穿越参数。
