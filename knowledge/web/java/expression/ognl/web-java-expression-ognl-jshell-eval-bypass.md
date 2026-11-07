---
id: web-java-expression-ognl-jshell-eval-bypass
title: OGNL 黑名单 JShell 绕过：@jdk.jshell.JShell@create().eval() 执行任意 Java
type: scenario
domain: web
path: web/java/expression/ognl
technique: ognl-jshell-eval-bypass
aliases:
- JShell OGNL 绕过
- jdk.jshell.JShell eval
- OGNL 高版本 JShell
- JShell 表达式注入
- JDK9 JShell RCE
tags:
- java
- ognl
- expression-injection
- jshell
- jdk9
- waf-bypass
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: JDK 9+（jdk.jshell 模块；文章实测 JDK 11）
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:27:36+08:00'
  notes: 已对照原文核对：图24实测 JDK11 下 @jdk.jshell.JShell@create().eval('Runtime.getRuntime().exec("calc");') 返回SnippetEvent且Process[pid=28072]，与卡内PoC一致；黑名单未含jdk.jshell的论述与图08一致。未验证点：未在本机复跑PoC；frontmatter无sources/source_url；JDK9+模块可用性依环境。
---

## 一句话结论

OGNL 高版本黑名单封禁了 Runtime/ClassLoader/ProcessBuilder 等类，但没有封禁 JDK 9+ 自带的 `jdk.jshell.JShell`；用 `@jdk.jshell.JShell@create().eval('Runtime.getRuntime().exec("calc");')` 即可让 JShell 编译执行任意 Java 代码，绕过 OGNL 的 `invokeMethod` 限制。

## 原理

- `jdk.jshell.JShell` 是 JDK 9 引入的 REPL API，`JShell.create()` 返回实例，`eval(String)` 接收一段 Java 代码并当场编译、执行，返回执行结果/SnippetEvent。
- OGNL 的黑名单只覆盖 `Runtime`、`ClassLoader`、`ProcessBuilder`、`AccessibleObjectHandler`、`MemberAccess`、`OgnlContext` 等声明类；`jdk.jshell.JShell` 不在其中，`create()`/`eval()` 可被正常调用。
- 真正的代码执行发生在 JShell 内部（它自己编译并加载 snippet），不经过 OGNL 的 `invokeMethod`，因此 `Runtime.getRuntime().exec()` 这段代码不受 OGNL 黑名单约束。
- 这与“反射 Method.invoke”绕过的区别：不需要逐层找黑名单外的反射原语，直接把完整 Java 代码作为字符串交给 JShell；代价是依赖 JDK 9+ 且 jdk.jshell 模块可用。

## 触发条件

- 存在 OGNL 表达式注入点（Struts2、Confluence 等）。
- 目标运行 JDK 9+，且包含 `jdk.jshell` 模块（完整 JDK 通常自带；精简 JRE 可能没有）。
- OGNL 版本启用了更严格的调用黑名单（3.1.25/3.2.12+），但未额外封禁 `jdk.jshell`。
- WAF 未拦截 `JShell`/`eval` 关键字（可配合字符串拆分/变量拼接绕过）。

## 利用步骤

1. 确认 OGNL 注入点与 JDK 大版本（`java.version` 可通过表达式或错误信息获取）。
2. 构造 `@jdk.jshell.JShell@create().eval('...')`，在 eval 的字符串中写任意 Java 代码（命令执行、反弹 shell、内存马）。
3. 发送表达式；JShell 返回 SnippetEvent，命令已执行。
4. 若无回显，用 DNS/延时/写文件验证。
5. 若关键字被拦截，可拆分 `JShell`/`eval` 字符串或用变量拼接。

## PoC

```text
@jdk.jshell.JShell@create().eval('Runtime.getRuntime().exec("calc");')
```

等价的多语句执行：

```text
@jdk.jshell.JShell@create().eval('var p = Runtime.getRuntime().exec("id"); p.waitFor();')
```

文章在 JDK 11 环境验证成功，控制台返回 `SnippetEvent(snippet=Snippet:VariableKey($1)#1-Runtime.getRuntime().exec("calc");, ... causeSnippet=null, value=Process[pid=28072, exitValue=...])`。

## 变体与关联

- 变体：用 JShell 执行内存马注册、文件读写、反弹 shell 等任意 Java 代码。
- 变体：`javax.script.ScriptEngineManager`（Nashorn，JDK 15 前）等脚本引擎也可能不在黑名单，可作为同类绕过。
- 关联：[[web-java-expression-ognl-high-version-reflection-invoke-bypass]]（同版本黑名单的反射绕过）、[[web-java-framework-struts2-s2-067-ognl-upload-filename-bypass]]。
- 边界：仅 JRE 或裁剪掉 `jdk.jshell` 模块的环境不可用；JDK 8 无 JShell。

## 检测与防御

- 在 OGNL `MemberAccess`/白名单中禁止 `jdk.jshell.**`、`javax.script.**` 等可执行代码的 JDK 工具类，不要只维护 Runtime/ProcessBuilder 黑名单。
- 生产环境使用不含 `jdk.jshell` 的裁剪 JRE；限制 `eval`/`create` 等敏感方法。
- WAF/SAST 检测 `@jdk.jshell.JShell@`、`.eval(`、`JShell.create` 等特征；监控 JShell 实例创建与 snippet 编译。
- 禁止不可信输入进入 OGNL，及时升级 Struts2/Confluence 等框架；部署 RASP 拦截表达式求值。
- 纵深防御：限制进程创建与文件写入权限，降低代码执行后的影响。
