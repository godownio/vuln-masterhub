---
id: web-generic-file-upload-jsp-java-unicode-escape-waf-bypass
title: JSP/Java Unicode 转义绕过 WAF：Runtime 与多重 u（\uuuu0074）在词法分析前还原关键字
type: scenario
domain: web
path: web/generic/file-upload
technique: jsp-java-unicode-escape-waf-bypass
tags:
- web
- file-upload
- jsp
- java
- waf-bypass
- unicode
- obfuscation
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V481
  verified_at: '2026-11-10T20:33:09+08:00'
  notes: 已对照幻灯片25核对：单u转义（Run\u0074ime/e\u0078ec）与多重u（\uuuuuuuuu0074，JavaUnicodeReader 循环跳过连续u的代码截图）与卡片一致；JLS 词法分析前还原、可只转义部分token属实。未验证点：未在真实 JSP 容器执行，多重u兼容性以 Jasper 实现为准（卡内已注明）。
url: /docs/web/generic/file-upload/web-generic-file-upload-jsp-java-unicode-escape-waf-bypass/
draft: false
kb_aliases:
- Java unicode 转义
- t 绕过
- 多重 u 转义
- JSP 代码编码
- JavaUnicodeReader
- JSP 免杀 unicode
---

## 一句话结论

在 JSP scriptlet 里用 Java Unicode 转义写关键字：`Run\u0074ime.getRun\u0074ime().e\u0078ec("whoami")`，甚至用多个 u 的 `Run\uuuuuuuuu0074ime`——WAF 看到的是 `\u0074` 这类 ASCII 文本，而 Java 编译器在词法分析前就把 Unicode 转义还原成字符，最终执行的是 `Runtime.getRuntime().exec("whoami")`，内容规则完全匹配不到。

## 原理

- **JLS 的转义时机**：Java 规范要求 Unicode 转义（`\uXXXX`）在词法分析**之前**被转换为对应字符，且转义可以出现在源码任何位置——包括标识符/关键字内部（`Run\u0074ime` 等价于 `Runtime`）。因此源码文本与编译后的标识符是两套表示，WAF 按文本匹配 `Runtime` 必然失效。
- **多重 u 合法**：JLS 允许 `\u` 后跟一个或多个 `u`（为工具链历史兼容），如 `\uuuu0074` 仍表示字符 `t`。很多 WAF/正则只识别单个 `\uXXXX` 或完全不处理 Java 转义，多重 u 可以再叠一层绕过。
- **JSP 引擎的处理**：Jasper 在读取 JSP 源码时使用 `JavaUnicodeReader`（幻灯片展示了其逻辑：遇到 `\` 后循环跳过连续 `u`，再读 4 位十六进制），因此 JSP 中的 scriptlet 与 `.java` 源码一样会先做 Unicode 转义翻译，再交给 Java 编译器；容器不会因为转义形式而拒绝。
- **为什么服务端仍执行**：翻译后 `Run\u0074ime` → `Runtime`、`e\u0078ec` → `exec`，标识符和方法名完全合法；文件里却没有任何连续的 `Runtime`/`exec` 关键字，敏感词、正则、语法高亮都无法识别其真实语义。
- **可组合性**：Unicode 转义可与模板拼接（`<% %>` 拆 token）、JSPX、文件编码等手法叠加，进一步提高检测难度。

## 触发条件

- 目标允许上传 JSP（或可解析为 JSP 的后缀/路径）且文件会被编译执行；
- WAF/检测规则按原始文本匹配 Java 关键字，未先做 Java Unicode 转义归一化；
- 目标容器使用 Jasper/兼容 JSP 引擎（主流 Java Web 容器均支持）。

## 利用步骤

1. 选取要隐藏的关键字：类名 `Runtime`、方法名 `exec`、甚至 `getRuntime` 中的任意字符，替换为 `\uXXXX` 或 `\uuuuXXXX`。
2. 构造 JSP：
   ```jsp
   <% Runtime.getRuntime().exec("whoami"); %>
   ```
   单 u 转义版本：
   ```jsp
   <% Run\u0074ime.getRun\u0074ime().e\u0078ec("whoami"); %>
   ```
   多重 u 版本：
   ```jsp
   <% Run\uuuuuuuuu0074ime.getRun\uuuuuuuuu0074ime().e\uuuuuuuuu0078ec("whoami"); %>
   ```
3. 上传并按目标解析规则访问，确认命令执行（whoami/写文件/反弹 shell）。
4. 如需回显，继续用同样方式转义流读取相关类名/方法名，或与模板拼接组合。
5. 若被拦截，检查是否被解码后匹配：换用多重 u、转义更多字符、或改走 EL/标签/JSPX 路线。

## PoC

```jsp
<% Runtime.getRuntime().exec("whoami"); %>
```

```jsp
<% Run\u0074ime.getRun\u0074ime().e\u0078ec("whoami"); %>
```

```jsp
<% Run\uuuuuuuuu0074ime.getRun\uuuuuuuuu0074ime().e\uuuuuuuuu0078ec("whoami"); %>
```

幻灯片中对应的演进链：`Runtime.getRuntime().exec("xxx")` → `Run\u0074ime.getRun\u0074ime().e\u0078ec("xxx")` → `Run\uuuuuuuuu0074ime...`。以上未在真实目标执行；JSP 引擎版本对多重 u 的支持以 Jasper 实现为准（幻灯片给出的 JavaUnicodeReader 会跳过连续 u）。

## 变体与关联

- 变体：只转义部分字符（`Run\u0074ime`）、转义点号/括号（`.`、`(`）等 Unicode 转义允许出现在任何位置的字符；也可转义字符串内容。
- 变体：在 `.java` 源码、JSP scriptlet、JSPX scriptlet 中使用；JSP 模板文本中的 `\uXXXX` 不会按 Java 规则翻译（不在 scriptlet 内）。
- 关联：[[web-generic-file-upload-jspx-xml-pi-entity-cdata-waf-bypass]]（XML 实体/PI 拆分）、[[web-generic-file-upload-jsp-multi-encoding-pageencoding-waf-bypass]]（文件级编码混淆）。
- 关联：[[web-java-rce-jsp-godzilla-godmode-unicode-escape-static-bypass]]——哥斯拉上帝模式对整个 JSP 逐字符 `stringToUnicode` 的自动化版本；本卡是手工按 token 转义（可只转义部分字符）并利用多重 u 的通用手法，适用于任意手写 JSP/上传内容。
- 边界：若 WAF 先做 Java Unicode 解码再匹配则失效；转义不得破坏 Java 标识符合法性（转义后必须是合法字符）；非 Java 的 JSP 实现可能不支持多重 u。

## 检测与防御

- 检测（WAF）：对上文件先做 Java Unicode 转义归一化——按 JLS 规则把 `\u+([0-9a-fA-F]{4})`（含多 u）替换为字符，再匹配关键字；归一化后再做自研语法检查/编译感知检测。
- 检测（主机）：JSP 编译缓存（work 目录）里出现 `Runtime.getRuntime().exec`；Web 目录 JSP 源码含大量 `\u` 转义与脚本特征；访问后产生异常子进程。
- 防御：禁止上传/执行 JSP；上传目录不可执行并移出 Web 根；WAF 以解码归一化后的内容为准；启用 JSP 源码审计与编译事件监控。
