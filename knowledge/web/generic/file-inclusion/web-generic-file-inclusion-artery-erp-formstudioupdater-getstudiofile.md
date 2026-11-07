---
id: web-generic-file-inclusion-artery-erp-formstudioupdater-getstudiofile
title: Artery ERP FormStudioUpdater#getStudioFile 任意文件读取：fileStr 只替换斜杠未过滤 ..\ 穿越
type: scenario
domain: web
path: web/generic/file-inclusion
technique: erp-formstudioupdater-getstudiofile-traversal-read
aliases:
- getStudioFile 任意文件读取
- updater.getStudioFile
- FormStudioUpdater 路径穿越
- fileStr 文件读取
- ERP 任意文件下载
tags:
- web
- file-inclusion
- java
- path-traversal
- erp
- unauth
- formservice
- file-read
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V237
  verified_at: '2026-11-07T09:20:28+08:00'
  notes: 已对照原文核对（33 图）；getStudioFile 仅代码审计、无成功读取截图；同节 JSPX 包已按证据归 uploadStudioFile；dup-scan pair 1 与 uploadStudioFile 为读/写不同链，两卡并列保留。
---

## 一句话结论

ERP 的 `com.artery.form.services.FormStudioUpdater#getStudioFile` 通过 FormService 暴露为 `service=updater.getStudioFile`，第三个参数 `fileStr` 只把 `/` 替换成 `\` 并在前面补 `\`，随后直接拼到 `studioRoot` 后面 `new File(...)` 读取并下载；没有过滤 `..`，攻击者可构造 `..\..\..\` 穿越读取服务器任意文件。

## 原理

- `FormStudioUpdater` 是 `plugins.xml` 中 `updater` 服务对应的类，没有实现 `ISecurityService`（原文称“没有相应的鉴权方法”），因此 FormService 反射调用时跳过 `isAccessible` 匿名校验。
- `getStudioFile(HttpServletRequest request, HttpServletResponse response, String fileStr)` 的处理：
  - `fileStr = fileStr.replace('/', '\\')`：只做斜杠归一，不检查 `..`；
  - 若不以 `\` 开头则补一个 `\`；
  - `this.getStudioRoot(request)` 取工作室根目录，`fileStr = studioRoot + fileStr`；
  - `File file = new File(fileStr)`，存在则设置 `application/octet-stream` 与附件头，循环读入并写入 `response.getOutputStream()`。
- 由于 `fileStr` 中可包含 `..\`，拼接后的路径可跳出 `studioRoot`（例如 `studioRoot + "\..\..\..\windows\win.ini"`），实现任意文件读取/下载；`/` 也会被先转成 `\`，所以 `/../../etc/passwd` 这类写法同样有效。
- 参数传递方式：该方法第三个参数类型为 `String`，FormService 的 `contentType=2`，攻击者用 `content=<路径>` 传入；请求形如 `POST /formservice?service=updater.getStudioFile`，body `content=..%5C..%5C..%5Cwindows%5Cwin.ini`。

## 触发条件

- 目标部署该 ERP/框架，`/formservice` 可访问。
- `updater` 服务存在于 `plugins.xml` 且 `FormStudioUpdater` 未实现有效的 `isAccessible`。
- `getStudioFile` 为 public、参数为 (request, response, String)，且 `studioRoot` 目录之外的目标文件对应用进程可读。
- 攻击者知道/能猜出目标文件路径与 `studioRoot` 层级（可通过报错“找不到指定的文件: <拼接后路径>”泄露绝对路径）。

## 利用步骤

1. 请求 `POST /formservice?service=updater.getStudioFile`，`content` 传一个不存在的文件名，观察报错中的 `studioRoot + fileStr` 绝对路径，确认目录层级。
2. 用 `..\` 逐级回退到目标目录，如 `content=..\..\..\..\windows\win.ini` 或 `content=/../../etc/passwd`。
3. 观察响应是否返回文件内容（`application/octet-stream` 下载）。
4. 读取 `WEB-INF/web.xml`、配置文件、数据库连接串、源码/备份等；配合其他漏洞扩大影响。
5. 记录请求、报错路径与下载内容作为证据，验证后删除本地文件。

## PoC

```http
POST /formservice?service=updater.getStudioFile HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

content=..%5C..%5C..%5C..%5Cwindows%5Cwin.ini
```

```http
POST /formservice?service=updater.getStudioFile HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

content=/../../etc/passwd
```

原文通过代码审计确认 `fileStr` 未过滤 `../`、只做斜杠替换，可目录穿越；未给出该方法的成功下载响应截图（同节的 JSPX 数据包实际调用的是 `uploadStudioFile`）。

## 变体与关联

- 变体：`fileStr` 也可用绝对路径（Windows 盘符）或 UNC 路径，具体取决于 `new File` 的拼接结果与权限。
- 变体：`getStudioRoot` 的取值可能来自配置/请求，若可控则可直接改变根目录。
- 关联：同类的未授权文件写入 [[web-generic-file-upload-artery-erp-formstudioupdater-uploadstudiofile]]；FormService 机制 [[web-java-framework-formservice-reflection-dispatch-unauth]]；通用路径穿越读取 [[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]、[[web-generic-file-inclusion-jhsoft-downloadbgimage-path-read]]。
- 边界：`getStudioFile` 不在服务类 public 方法集合、`fileStr` 被额外规范化/白名单、目标文件无读权限时，利用不成立；原文未展示成功读取，confidence 标 medium。

## 检测与防御

- 检测：`/formservice?service=updater.getStudioFile` 请求；`content` 中出现 `..`、`%5c`、`/../`；响应为 `application/octet-stream` 且文件名异常；错误信息泄露 `studioRoot` 绝对路径。
- 修复：对 `fileStr` 做规范化后校验最终路径必须位于 `studioRoot` 下（`getCanonicalPath().startsWith(root)`），拒绝 `..` 与绝对路径；禁止把文件路径作为 FormService 参数。
- 加固：`FormStudioUpdater` 实现 `ISecurityService` 并正确校验匿名/角色；服务方法白名单；错误信息不回显绝对路径；运行账户最小权限。
