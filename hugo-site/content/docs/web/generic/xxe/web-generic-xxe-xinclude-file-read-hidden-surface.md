---
id: web-generic-xxe-xinclude-file-read-hidden-surface
title: XInclude 注入读取本地文件：控制不了 DOCTYPE 时在数据值内引入 xi:include 命名空间
type: scenario
domain: web
path: web/generic/xxe
technique: xinclude-injection-file-read
tags:
- web
- xxe
- xinclude
- file-read
- xml
- bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V590
  verified_at: '2026-11-12T15:14:21+08:00'
  notes: 已对照原文与42张截图核对：XInclude 机制（xmlns:xi + xi:include parse=text href=file://）、无法控制DOCTYPE的场景定位、PortSwigger 靶场PoC请求与响应（/etc/passwd回显）均一致；XInclude非DTD路线，与 web-generic-xxe-oob-exfil/inband-file-read/dom4j/ooxml 等既有卡不同机制，非重复；通用手法无受影响版本；未实测PoC（靶场非本地环境）
url: /docs/web/generic/xxe/web-generic-xxe-xinclude-file-read-hidden-surface/
draft: false
kb_aliases:
- XInclude 注入
- xi:include
- 无法控制 DOCTYPE 的 XXE
- XInclude 读文件
- XML 子文档包含
---

# 一句话结论

当应用只是把用户数据拼进服务端 XML 再解析、攻击者无法控制整个 XML 文档因而不能写 `DOCTYPE` 时，仍可在数据值里注入带 `xmlns:xi="http://www.w3.org/2001/XInclude"` 的元素和 `<xi:include parse="text" href="file:///etc/passwd"/>`，让解析器在展开 XInclude 时读取本地文件并把内容作为文本并入文档，最终随响应回显。

# 原理

- **XInclude 是 XML 规范的子文档包含机制**：解析器遇到命名空间 `http://www.w3.org/2001/XInclude` 下的 `xi:include` 元素时，会按 `href` 指向的 URI 取回资源并插入当前文档；`parse="text"` 表示把取回内容按纯文本插入，不做 XML 解析。它不依赖 DTD，也不需要在 DOCTYPE 中声明实体。
- **绕过“控制不了 DOCTYPE”的限制**：经典 XXE 需要改整个文档的 `<!DOCTYPE ...>`；当服务端把 `productId` 等单个参数拼进后端 XML（例如 SOAP 请求）再解析时，攻击者只能控制某个元素值。往这个值里塞 `</原标签><foo xmlns:xi="..."><xi:include .../></foo><原标签>` 之类仍能构造出合法 XML 片段，XInclude 元素随解析生效。
- **文件读取成立条件**：`href` 支持 `file://`（及部分实现的 `http://`），解析器需启用 XInclude 处理（如 `DocumentBuilderFactory.setXIncludeAware(true)`、libxml2 的 XINCLUDE 解析选项、.NET 的 XIncludeReader 等），且进程对目标文件有读权限。
- **为什么危害等同于 XXE**：包含发生在解析阶段、在业务逻辑之前，读到的是服务端本地文件/内网响应；`parse="text"` 保证 `/etc/passwd` 这类非 XML 内容也能原样进入结果，随后随业务响应（库存查询结果、评论、错误页）回显；若响应不回显，可把 `href` 指向攻击者 HTTP 服务做 OOB 探测。
- **与 `xi:include` 元素无关的输入点**：XInclude 只要求注入点位于被解析的 XML 文档内，因此 REST XML 接口、SOAP 后端、XML 模板渲染、上传后解析等都可触发。

# 触发条件

- 应用将用户可控数据嵌入服务端 XML 文档后交给支持 XInclude 的解析器解析。
- 攻击者无法或无需修改 DOCTYPE（该场景正是被“不能控制整个文档”逼出的替代路径）。
- 解析器启用了 XInclude（不少框架/SOAP 栈默认开启或因功能需要开启）。
- 进程对目标文件有读权限；有回显则直接读取，无回显可配 `http://` 做带外。

# 利用步骤

1. 找到把用户输入拼进 XML 后解析的入口（如库存查询的参数被放入后端 SOAP/XML 请求）。
2. 用普通字符串确认参数确实进入 XML 并被解析（返回格式错误、字段解析异常等）。
3. 在参数值中注入 XInclude 元素：
   ```xml
   <foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
   ```
   若该值被嵌入到已有元素内部，先闭合原元素再注入并保持整体 XML 合法。
4. 观察响应是否包含文件内容（如库存结果里出现 `root:x:0:0:`）。
5. 需要更多数据时，把 `href` 换成其他 `file://` 路径；探测内网时换成 `http://内网地址`，或在无回显时指向攻击者服务做带外确认。

# PoC

```http
POST /product/stock HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

```text
# 响应（库存检查结果）中出现：
# Invalid product ID: root:x:0:0:root:/root:/bin/bash ...
```

# 变体与关联

- 变体：`href="http://169.254.169.254/latest/meta-data/"` 把文件读取换成内网/云元数据探测；`parse="text"` 不变。
- 变体：同一注入点也可改用 XSLT `document()`、外部实体（若能影响 DOCTYPE）、SVG 等其它 XML 特性。
- 关联：[[web-generic-xxe-inband-file-read-default-insecure]]（能控制 DOCTYPE 时的经典带内 XXE）、[[web-generic-xxe-oob-exfil]]（无回显时的带外外带）、[[web-generic-xxe-svg-upload-inband-file-read]]（SVG 上传面）。
- 边界：解析器未启用 XInclude（如 Java `setXIncludeAware(false)` 为默认）、或显式拒绝 `xi:include` 时无效；部分实现只允许相对 URI 或禁 `file://`。

# 检测与防御

- 检测：请求体/参数值中出现 `xmlns:xi`、`xi:include`、`XInclude`、`href="file://`、`href="http://`，尤其是出现在本应是普通业务字段的位置；响应中出现系统文件内容；解析器对非预期 URI 发起请求。
- 防御：不需要 XInclude 时显式关闭（Java `DocumentBuilderFactory.setXIncludeAware(false)`，对应解析栈关闭 XInclude 解析选项）；同时按 XXE 基线禁用 `DOCTYPE`/外部实体/外部参数实体；不要用字符串拼接构造 XML，改用安全的 XML 构造 API 并对用户值做转义；限制进程文件读权限与出网。
