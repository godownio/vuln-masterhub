---
id: web-generic-file-inclusion-cmsv6-downloadlogger-filename-read
title: 通天星 CMSV6 downloadLogger.action 的 fileName 直入文件读取：Windows 绝对路径任意文件下载（win.ini 验证）
type: scenario
domain: web
path: web/generic/file-inclusion
technique: struts2-action-filename-arbitrary-file-read
tags:
- cmsv6
- java
- struts2
- arbitrary-file-read
- file-download
- windows
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T09:02:44+08:00'
  notes: 已对照原文与全部18张图核对：downloadLogger.action?fileName=C://Windows//win.ini的PoC与原文完全一致；原文未给该接口源码/响应截图，卡内已注明按PoC推断。与同文章getImage卡为不同端点/参数/响应方式（附件流 vs 内联image/jpeg），判为并列保留而非同一链。未验证点：未实际请求。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-cmsv6-downloadlogger-filename-read/
draft: false
kb_aliases:
- 通天星 CMSV6 任意文件读取
- downloadLogger 任意文件下载
- DownloadLoggerAction
- CMSV6 日志下载任意读
- logger/downloadLogger.action
---

## 一句话结论

`/808gps/logger/downloadLogger.action` 把请求参数 `fileName` 原样当作待下载文件的路径打开并回传，未做目录约束或后缀白名单，传 `C://Windows//win.ini` 这类 Windows 绝对路径即可读取服务器任意文件；文章 PoC 未携带会话，属于前台可直接调用的文件读取原语。

## 原理

- 入口是 Struts2 的日志下载 Action：`com.gps808.loggerManagement.action.DownloadLoggerAction`。`struts.xml` 的 `808gps/logger` 包中 `getLogger.action` 绑定该类，结果类型为 `stream`，`inputName=inputStream`，`contentDisposition=attachment;filename="${fileName}"`；`downloadLogger.action` 是同一 Action 在包含的 `struts-html-action.xml` 等配置中的另一个动作名（路由规则为「任意路径 + 类名/方法名 + `.action`」）。
- 该 Action 接收 `fileName` 后用它定位文件并写入 `inputStream` 返回给客户端。文章没有贴出该 Action 的源码，但从 PoC 可直接用 `fileName=C://Windows//win.ini` 读到系统文件、且响应以附件流返回，说明路径未被拼接进固定目录，也未做 `normalize()`、`startsWith()` 或后缀校验。
- `C://Windows//win.ini` 能成立的原因是 Java `File`/Windows API 接受正斜杠并把连续分隔符折叠，等价于 `C:\Windows\win.ini`；因此攻击者可以用绝对路径读任意盘符文件，也可以用 `..\..\` 相对路径从应用目录向上跳。
- 与上传/报表等接口组合时，该原语可读取数据库配置、连接串、日志、源码与备份文件；在 Windows 部署下尤其容易读 `win.ini`、Tomcat `conf` 下的配置以及应用 `WEB-INF` 外的属性文件。

## 触发条件

- 目标暴露 `/808gps/logger/downloadLogger.action`（或同 Action 的其他动作名），且该动作不需要登录或可被未授权访问；文章 PoC 无 Cookie。
- 运行用户对目标文件有读权限（Windows 下读 `C:\Windows\win.ini` 通常满足）。
- 请求参数名确为 `fileName`；若目标版本改过参数名，需要按实际 Action 调整。
- 服务器为 Windows 或路径风格兼容（Linux 下改用 `/etc/passwd` 等等价绝对路径）。

## 利用步骤

1. 直接请求 `/808gps/logger/downloadLogger.action?fileName=C://Windows//win.ini`，确认响应是文件内容而非错误页；文章用该请求验证了任意文件读取。
2. 按部署路径读取应用配置：Tomcat `conf/server.xml`、`conf/tomcat-users.xml`、应用 `WEB-INF/classes/*.properties`、数据库连接配置、日志文件等；Windows 下注意用 `//` 或 `\` 转义。
3. 若返回被截断或响应为附件下载，保存响应体后本地查看；必要时用 `fileName=..\\..\\...` 相对路径从应用目录跳出。
4. 读到的凭据可用于登录后台、连接数据库或衔接其他漏洞；读日志可衔接会话劫持（见关联卡）。

## PoC

```http
GET /808gps/logger/downloadLogger.action?fileName=C://Windows//win.ini HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```

响应为 `win.ini` 文件流（`Content-Disposition: attachment;filename="..."`）。Linux 目标把 `fileName` 换成 `/etc/passwd` 即可验证。

## 变体与关联

- 同一产品的 `StandardReportMediaAction_getImage.action` 用 `filePath/fileOffset/fileSize` 读文件，见 `web/generic/file-inclusion` 下 CMSV6 getImage 卡；`StandardLoginAction_downLoad.action` 用 `path` 相对路径读日志，见 CMSV6 downLoad 卡。三者参数名不同但都是「Struts Action 参数直入文件路径」。
- 通用手法：`web/generic/file-inclusion` 下已有大量 `fileName` 直拼下载卡（MES、LuckyFrameWeb 等），本卡差异在产品、Action 与 Windows 绝对路径写法。
- 该原语单独可造成敏感信息泄露；与日志中的 session、数据库口令结合可升级为后台接管或数据库访问。

## 检测与防御

- 修复：不要用请求参数直接构造文件路径；文件名走白名单或 ID 映射，服务端用 `getCanonicalPath()` 后校验 `startsWith(允许目录)`，禁止绝对路径与 `..`。
- 权限：日志与配置文件移出 Web 可读范围，运行账号最小权限；下载接口要求登录与资源归属校验。
- 检测：监控 `fileName`/下载参数中出现 `C:`、`/etc/`、`..\`、`%5c`、`//` 的请求；对下载响应大小、路径异常与高频枚举做告警。
- 排查：检查 Web 访问日志中该 Action 的调用来源与返回大小，核对是否读取了系统文件或配置。
