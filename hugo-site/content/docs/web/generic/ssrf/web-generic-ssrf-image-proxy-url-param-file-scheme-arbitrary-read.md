---
id: web-generic-ssrf-image-proxy-url-param-file-scheme-arbitrary-read
title: 图片代理接口的 url 参数未限制协议：file:// 读取服务器任意文件并列出目录
type: scenario
domain: web
path: web/generic/ssrf
technique: image-proxy-url-param-file-scheme-read
tags:
- ssrf
- file-scheme
- arbitrary-file-read
- image-proxy
- java
- lfi
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T11:32:59+08:00'
  notes: 已对照原文核对：图03 源码注释『存在安全问题，已废弃』指向 Imagefile 接口，图04 /Imagefile?url1=file:///usr/local/tomcat/webapps/ROOT/WEB-INF/classes/com/ctf/help_me/%23java 返回目录列表（.DS_Store/Servlet/Utils），列目录证据确凿；读取 .class 文件为原文文字说明（图05 反编译即成果），文件内容回显截图未单独展示，为未验证点，confidence medium 合理。无 CVE/版本标记，留空正确。
url: /docs/web/generic/ssrf/web-generic-ssrf-image-proxy-url-param-file-scheme-arbitrary-read/
draft: false
kb_aliases:
- 图片代理任意文件读取
- url 参数 file:// 读文件
- /Imagefile?url=file://
- 服务端抓图 SSRF 本地文件
- 目录列举 file://
---

## 一句话结论

图片/资源代理接口把用户传入的 `url` 直接交给 URL 处理器（JDK `URL.openConnection()`/`ImageIO.read(new URL(...))`）去取内容，且没有限制协议，攻击者用 `file://` 即可读取服务器上任意文件——返回内容以图片/文本形式回显，目录路径还会返回文件名列表，等于一个无交互的任意文件读取 + 目录列举原语。

## 原理

- **协议没有白名单**：`java.net.URL` 会根据 URI 的 scheme 选 handler，`http/https/ftp/file/jar` 都在默认 handler 里。代码只要写 `new URL(user_input).openStream()` 或 `ImageIO.read(new URL(user_input))`，就同时接受了 `file:` 和 `jar:`；`file:` 的 `FileURLConnection` 会直接读本地文件字节，对目录则返回目录项列表。
- **回显不需要图片合法**：很多实现把取回的字节约原样写回响应（`response.getOutputStream().write(bytes)`），或在解析图片失败时把原始内容/异常带进页面。于是 `.class`、`.xml`、`.properties`、源码等非图片文件也能完整读出。
- **为什么危害放大**：读 `.class` 后可反编译得到业务源码与配置路径，再顺着配置读到序列化组件（如过滤规则 XML、密钥、数据库口令），把一个「只读」原语变成后续 RCE 的情报基础；读目录则省去盲猜路径。
- **与 SSRF 的关系**：`http://` 分支还能打内网（云元数据 169.254.169.254、内网管理端口），`file://` 分支是本地文件读；两者是同一个「未校验协议/目标」缺陷的两种利用面。

## 触发条件

- 存在以 URL 为参数的抓取型接口（图片代理、缩略图、远程头像、附件预览、`/Imagefile?url=` 等）。
- 服务端用通用 URL/HTTP 客户端取内容，未把 scheme 限制为 `http/https`，也未做内网地址黑名单。
- 取回的内容能回显给攻击者（直接输出、作为图片返回、错误信息回显）。
- 进程对目标文件有读权限（Web 容器用户通常可读应用目录、`WEB-INF` 下的 class 与配置）。

## 利用步骤

1. 找到抓取型参数（本例 `/Imagefile?url1=`，页面注释里还留着「存在安全问题，已废弃」的旧参数名，说明修复只做了参数改名而非协议校验）。
2. 先读一个确定的文件验证回显：`file:///etc/passwd`（Linux）或应用配置文件。
3. 用目录形式列目录：`file:///usr/local/tomcat/webapps/ROOT/WEB-INF/classes/`，从返回的文件名列表定位包结构。
4. 逐个读 `.class`、`web.xml`、过滤规则配置、数据源配置；`.class` 落盘后用反编译器还原源码，找反序列化/命令执行入口。
5. 需要时把 scheme 换成 `http://169.254.169.254/latest/meta-data/` 等验证是否同时具备 SSRF 面。
6. 把读到的情报用于下一阶段（本例据此定位反序列化 Servlet 与其黑名单配置）。

## PoC

```http
GET /Imagefile?url1=file:///etc/passwd HTTP/1.1
Host: target

GET /Imagefile?url1=file:///usr/local/tomcat/webapps/ROOT/WEB-INF/classes/ HTTP/1.1
Host: target
# 返回目录项列表：D5_Store / Servlet / Utils ...

GET /Imagefile?url1=file:///usr/local/tomcat/webapps/ROOT/WEB-INF/classes/com/ctf/help_me/%23java HTTP/1.1
Host: target
# 读取 class 目录下的字节码，落盘后反编译
```

## 变体与关联

- 变体：`jar:file:///path/app.jar!/WEB-INF/classes/x.class` 可直接读压缩包内条目；`file://` 配合 `..` 可跨目录。
- 变体：若框架走 Apache HttpClient/OkHttp，`file:` 通常不被支持，但 `gopher:`/`dict:`/内网重定向仍可能成立，需要按客户端能力测试。
- 变体：图片处理库（ImageIO/ImageMagick）在解析失败时把原始字节写进错误页，是常见的隐式回显通道。
- 关联：[[web-generic-ssrf-file-hosts-internal-segment-recon]]（同为 file:// 读取，用于内网侦察）、[[web-generic-ssrf-url-shortcut-upload-file-scheme-read]]、[[web-generic-file-upload-svg-imagemagick-text-protocol-file-read]]。
- 边界：仅当协议未限制且内容可回显时成立；若返回的是二进制图片流但攻击者能看到字节（下载响应），仍可读文件；若服务端只接受 http/https 或做了目标地址校验，则退化为普通 SSRF 面或不成立。

## 检测与防御

- 检测：URL 参数中出现 `file:`、`jar:`、`gopher:`、`dict:` 等非预期 scheme；同一接口高频读取 `WEB-INF`、`/etc`、`/proc` 路径；响应体为 class/xml 等非图片类型但走图片代理接口。
- 修复：解析前校验 scheme 白名单（只允许 `https`，必要时 `http`）；解析后对目标 IP 做内网/回环/链路本地黑名单并在连接时二次校验（防 DNS rebinding）；不要用 `new URL(user_input)` 直接开流。
- 加固：抓取服务独立进程/容器运行，只挂载必要目录，禁止读取应用代码目录；对返回内容做类型校验（确为图片才输出）；关闭不需要的协议 handler。
