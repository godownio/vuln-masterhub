---
id: web-generic-file-inclusion-cmsv6-getimage-filepath-offset-read
title: 通天星 CMSV6 StandardReportMediaAction_getImage 的 filePath/fileOffset/fileSize 直读文件：任意文件下载（win.ini 回显）
type: scenario
domain: web
path: web/generic/file-inclusion
technique: struts2-action-filepath-offset-arbitrary-read
tags:
- cmsv6
- java
- struts2
- arbitrary-file-read
- file-download
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T09:03:11+08:00'
  notes: 已对照原文与全部18张图核对：GET /808gps/StandardReportMediaAction_getImage.action?filePath=C://Windows//win.ini&fileOffset=1&fileSize=100、响应200/image/jpeg/Content-Length 759、正文以[fonts][extensions]开头的win.ini内容（图16）均一致。与同文章downloadLogger卡为不同Action/参数（filePath+offset+size vs fileName）与不同响应方式，判为并列保留。未验证点：未实际请求。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-cmsv6-getimage-filepath-offset-read/
draft: false
kb_aliases:
- 通天星 CMSV6 getImage 任意文件下载
- StandardReportMediaAction 任意文件读取
- fileOffset fileSize 任意读取
- CMSV6 报表图片接口读文件
---

## 一句话结论

`/808gps/StandardReportMediaAction_getImage.action` 把 `filePath` 直接当作待读取文件路径，配合 `fileOffset`/`fileSize` 指定读取区间，未做目录约束或后缀校验；传 `filePath=C://Windows//win.ini` 即在响应体中回显系统文件内容，是前台可用的任意文件读取原语。

## 原理

- 入口是 Struts2 的 `com.gps808.report.action.StandardReportMediaAction`。文章通过查看该类的 `extends` 向上追溯到父类中的 `getImage` 方法（Action 名 `StandardReportMediaAction_getImage.action` 对应类名 + 方法名，符合 `struts.xml` 中 `**/*_*.action` 的 `{2}` 类、`{3}` 方法路由规则）。
- `getImage` 接收 `filePath`、`fileOffset`、`fileSize` 三个请求参数：`filePath` 用于定位文件，`fileOffset`/`fileSize` 指定从哪个偏移读、读多少字节。源码未在文章中完整给出，但请求直接把绝对路径交给接口并成功回显文件内容，说明路径没有经过 `getRealPath`/基目录拼接，也没有 `normalize()` 后的目录校验。
- 响应头为 `Content-Type: image/jpeg`、`Content-Disposition: inline`，这是报表图片接口的默认输出设置；读取文本文件时浏览器可能把内容当图片显示，实战应用 `curl`/Burp 直接保存响应体。文章截图用 `filePath=C://Windows//win.ini&fileOffset=1&fileSize=100` 读出的响应体以 `[fonts]`、`[extensions]` 开头，确认为 win.ini 内容。
- Windows 下 `C://Windows//win.ini` 中的正斜杠与重复分隔符会被文件 API 折叠；Linux 下等价地传 `/etc/passwd`。`fileOffset` 从 1 开始还是 0 开始取决于实现，读取二进制/大文件时可用它切片定位。
- 与日志下载接口不同，该接口把内容内联在响应体返回，适合直接读取配置、源码和密钥文件；体积大的文件可用 `fileOffset`+`fileSize` 分段读取。

## 触发条件

- 目标暴露 `/808gps/StandardReportMediaAction_getImage.action`，文章 PoC 未携带 Cookie，属于前台可达。
- 运行账号对目标文件有读权限；Windows 下读 `C:\Windows\win.ini` 通常满足。
- `filePath` 参数名与版本一致；若目标使用其他 Action 名，可尝试同类报表 Action 的 `getImage`。
- 读取二进制文件时需按响应实际字节处理，`fileSize` 控制单次读取范围。

## 利用步骤

1. 发送 `GET /808gps/StandardReportMediaAction_getImage.action?filePath=C://Windows//win.ini&fileOffset=1&fileSize=100`，确认响应体为文件内容而非错误页；文章截图返回 200、`Content-Length: 759`，正文为 win.ini。
2. 读取应用配置与凭据：Tomcat `conf/server.xml`、`conf/tomcat-users.xml`、应用 `WEB-INF` 外的 `*.properties`、数据库连接串、日志文件；按部署路径调整 `filePath`。
3. 大文件用 `fileOffset` 递增、`fileSize` 固定分片读取，拼回完整文件；读取二进制（如密钥库、数据库文件）时保存原始字节，不要按文本解码。
4. 读到的数据库口令、后台账号或 session 可用于后续登录/横向；读日志可衔接会话劫持。

## PoC

```http
GET /808gps/StandardReportMediaAction_getImage.action?filePath=C://Windows//win.ini&fileOffset=1&fileSize=100 HTTP/1.1
Host: 192.168.52.130
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```

响应（节选）：

```http
HTTP/1.1 200
Content-Type: image/jpeg;charset=UTF-8
Content-Disposition: inline
Content-Length: 759

[fonts]
[extensions]
...
```

Linux 目标把 `filePath` 改为 `/etc/passwd`；读取应用配置可改为 `C://...//WEB-INF//...`（注意该接口未像 `downLoad` 那样显式拦截 `WEB-INF`，以实际权限为准）。

## 变体与关联

- 同产品 `downloadLogger.action` 用 `fileName` 读任意文件（附件流），见 CMSV6 downloadLogger 卡；`StandardLoginAction_downLoad.action` 用 `path` 读日志且显式拦截 `WEB-INF/classes/.xml`，见 CMSV6 downLoad 卡。三者参数与响应方式不同，可互为补充：本卡内联回显、适合读配置；downloadLogger 适合下载；downLoad 适合读 Tomcat 日志拿 session。
- 通用手法：`web/generic/file-inclusion` 下已有大量「filePath 直入 FileInputStream」卡，本卡差异在 `fileOffset`/`fileSize` 分段读取与报表图片接口的 `image/jpeg` 包装。
- 若目标有 WAF 拦截 `..`，绝对路径（`C://`、`/etc/`）通常不需要穿越即可命中。

## 检测与防御

- 修复：`filePath` 改为资源 ID 映射或白名单文件名；服务端拼接固定基目录后 `getCanonicalPath()` 校验 `startsWith(base)`；拒绝绝对路径与 `..`；限制可读后缀为图片/报表类型。
- 权限：敏感配置与日志移出应用可读目录；运行账号最小权限；接口要求登录并校验资源归属。
- 检测：监控 `filePath` 含 `C:`、`/etc/`、`..`、`WEB-INF`、`win.ini` 的请求；对返回 `image/jpeg` 但内容为文本/配置的响应做异常检测；统计 `fileOffset` 递增的分片读取行为。
- 排查：检查该 Action 的访问日志与响应大小，核对是否读取了系统文件、配置或密钥材料。
