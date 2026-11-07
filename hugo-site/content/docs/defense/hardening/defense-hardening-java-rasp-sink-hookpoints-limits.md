---
id: defense-hardening-java-rasp-sink-hookpoints-limits
title: Java RASP 通防的 sink hook 布局与盲区：FileInputStream/JNDI/ProcessImpl/ObjectInputStream/SpEL/MySQL 六类 hook 及 native 绕过
type: scenario
domain: defense
path: defense/hardening
technique: java-rasp-sink-hookpoints-and-limits
tags:
- java
- rasp
- hardening
- jvm
- javassist
- instrumentation
- awd
- hook
- defense
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V241
  verified_at: '2026-11-07T13:11:05+08:00'
  notes: 已对照原文与3张图核对；premain/retransform、六类 hook 与 shiro 拦截结果一致；native forkAndExec 绕过为原文自述限制，未独立验证。
url: /docs/defense/hardening/defense-hardening-java-rasp-sink-hookpoints-limits/
draft: false
kb_aliases:
- AWD-RASP
- Java RASP 通防
- RASP hook 点
- premain Javassist 插桩
- Java AWD 防御
---

## 一句话结论

Java RASP 通防在 `premain` 阶段用 `Instrumentation.addTransformer` + `retransformClasses` 对六类关键 sink 做 Javassist 运行时代理（FileInputStream 构造、InitialContext.lookup、ProcessImpl.start/UnixProcess、ObjectInputStream.resolveClass/Hessian getDeserializer、TemplateAwareExpressionParser.parseExpression、MySQL Statement/PreparedStatement），再用 JSON 配置黑白名单；它能降低 AWD/AWDP 中的误报并在漏洞未修时拦截已知利用链，但只覆盖预定义 sink 与黑名单，native `forkAndExec`、未列入黑名单的 gadget、黑名单子串/白名单存在性匹配等是主要盲区。

## 原理

- **RASP 的插桩入口**：`premain(String, Instrumentation)` 从 `rasp-plugins.jar` 中反射加载所有 `com/rasp/hooks/*` 类并 `addTransformer`；随后遍历 `getAllLoadedClasses()`，对可修改的类（排除 `java.lang.invoke.LambdaForm`）调用 `retransformClasses`，让已加载的 `FileInputStream` 等类也被重新插桩。
- **为什么用 RASP 而不是 WAF**：RASP 在 JVM 内部、在业务调用的真实上下文里判断，能感知调用栈、参数与线程；对外部 WAF 难以区分的业务命令/正常 SQL 误报更低。AWD/AWDP 中误报（ban 业务）比漏报更严重，所以项目选择非预判式、只覆盖比赛常见利用链的轻量 hook。
- **六类 hook 点**：
  - `FileHook`：hook `java.io.FileInputStream` 构造方法，检查路径穿越、JSON 中 `dangerPaths`、以及路径是否包含 `flag`。
  - `JNDIHook`：hook `javax.naming.InitialContext.lookup`，检查协议是否为 `rmi`/`ldap`/`ldaps`。
  - `RCEHook`：Windows 下 hook `ProcessImpl.start(String[] cmdarray, Map env, String dir, Redirect[] redirects, boolean redirectErrorStream)`，把 `cmdarray` 用空格拼成命令后走 `checkCmd`；Linux 的 `UnixProcess.forkAndExec` 是 native 方法，无法用 Javassist 改字节码（见盲区）。
  - `SerialHook`：hook 原生反序列化 `java.io.ObjectInputStream.resolveClass` 与 Hessian `com.caucho.hessian.io.SerializerFactory.getDeserializer`，用 `dangerClasses` 黑名单；`serialClassName` 允许把 hook 适配到框架自定义的 `ObjectInputStream` 子类（例如 Shiro 的 `ClassResolvingObjectInputStream`）。
  - `SpELHook`：hook `org.springframework.expression.common.TemplateAwareExpressionParser.parseExpression`，用 `dangerSpELs` 做子串包含匹配。
  - `SqlHook`：hook `com.mysql.jdbc.StatementImpl.executeQuery` 与 `com.mysql.cj.jdbc.ClientPreparedStatement` 构造，规则复用 Druid `WallUtils`；即使是 PreparedStatement 也检查，因为实际代码中常见先拼接再传参。
- **配置驱动**：每个 hook 类在 static 块用 gson 读取同目录 `hook.json`，把开关、白名单、黑名单、危险路径等注入静态变量；不重新编译即可按题目调整。
- **成立条件**：JVM 支持 `-javaagent` 与 `retransformClasses`（Java 8/11/17 已测试；理论上 Java 8~17 之间可行）；`rasp-main.jar`、`rasp-plugins.jar`、`hook.json` 同目录；应用类未被更强保护（如自定义 ClassLoader 拒绝 transform）阻断。

## 触发条件

- AWD/AWDP Java 题，漏洞点通常是反序列化、SpEL、JNDI、命令执行、SQL 注入、任意文件读取；赛制允许/不检测 `-javaagent` 通防。
- 需要在不修改业务 Jar 字节码的前提下临时拦截利用链，且可接受只覆盖已知 sink。
- 运维能重启应用并带上 `-javaagent`、`-Xbootclasspath/a` 参数。

## 利用步骤

1. 编译/打包：`mvn clean install`、`mvn clean package`，得到 `rasp-main.jar` 与 `rasp-plugins.jar`；或直接使用 Java 8/11/17 的 release。
2. 把 `rasp-main.jar`、`rasp-plugins.jar`、`hook.json` 放到同一目录。
3. 写 `hook.json`：按题目开启 FileHook/JNDIHook/RCEHook/SerialHook/SpELHook/SqlHook，填写 `dangerPaths`、`safeCommands`、`dangerClasses`、`serialClassName`、`dangerSpELs` 等。
4. 以 agent 方式启动应用：
   ```bash
   java -javaagent:rasp-main.jar -Xbootclasspath/a:rasp-plugins.jar -jar app.jar
   ```
   注意 `-Xbootclasspath/a` 把插件 jar 追加到 bootstrap classpath，保证 `rasp-main` 的 ClassLoader 能加载到 hook 类；`-javaagent` 让 `premain` 在 main 之前执行。
5. 用已知 PoC（如 Shiro rememberMe + CommonsBeanutils）验证拦截：命中时应用抛 `SecurityException: Illegal Deserialization Class: ...`，利用链在反序列化阶段被终止。
6. 按业务命令/正常 SQL 调整白名单与开关，避免误伤；记录被拦截的类名/表达式/命令，作为赛事中的攻击面情报。
7. 赛后复盘：核对未覆盖的 sink 与绕过路径，补充规则或改用其他防护。

## PoC

无攻击 PoC（防御工具）。最小启动与配置示例：

```json
{
  "FileHook":  {"doFileHook": true,  "dangerPaths": ["/etc/passwd", "/root/"]},
  "JNDIHook":  {"doJNDIHook": true},
  "RCEHook":   {"doRCEHook": true,   "safeCommands": ["ping 127.0.0.1"]},
  "SerialHook":{"doSerialHook": true,
                "serialClassName": "org/apache/shiro/io/ClassResolvingObjectInputStream",
                "dangerClasses": ["org.apache.commons.beanutils.BeanComparator"]},
  "SpELHook":  {"doSpELHook": true,  "dangerSpELs": ["java.lang.Runtime", "java.lang.ProcessBuilder"]},
  "SqlHook":   {"doSqlHook": true}
}
```

```bash
java -javaagent:rasp-main.jar -Xbootclasspath/a:rasp-plugins.jar -jar shiro-login-demo-1.0.0.jar
```

命中示例（应用日志）：

```text
Caused by: java.lang.SecurityException: Illegal Deserialization Class: org.apache.commons.beanutils.BeanComparator
    at com.rasp.hooks.SerialHook.checkName(SerialHook.java:196)
```

## 变体与关联

- **native 绕过**：`UnixProcess.forkAndExec` 是 native 方法，Javassist 无法改其字节码；若只 hook `UnixProcess` 构造方法，攻击者可在已有 Java 代码执行后反射直连内部进程创建路径。该文明确承认此限制并选择“不解决”（AWD 场景不做预判式 hook）；具体反射构造器原语见 [[web-java-rce-processimpl-constructor-reflect-exec]]。
- **线程上下文绕过**：只按线程名/调用栈判断请求上下文的 RASP，可被新线程/线程池绕过；见 [[web-java-rce-rasp-http-thread-context-new-thread-bypass]]。
- **native/FFM 绕过**：Java FFM 直接调用 libc `system`/`fork+execve` 不经过 `Runtime.exec`/`ProcessBuilder`；见 [[web-java-rce-ffm-native-system-rasp-bypass]]。
- **黑名单/白名单盲区**：`SpELHook` 与 `SerialHook` 使用 `contains`/类名列表匹配，`RCEHook` 用 `safeCommands` 存在性判断；拼接命令、未列出的 gadget 类、框架子类或替代表达式都可能绕过。文章也把“Shiro 被 BeanComparator 拦截后如何读 Windows 环境变量”留作思考题，未给出验证过的绕过。
- **FileHook 盲区**：只按 `dangerPaths` 与路径包含 `flag` 判断，未覆盖的敏感文件、编码/规范化差异可能通过；应结合最小权限与文件系统 ACL。
- **JNDIHook 盲区**：只检查 `rmi`/`ldap`/`ldaps` 协议；其他命名协议或本地对象工厂调用不在覆盖内。
- **边界**：RASP 是临时缓解，不是漏洞修复；应用存在自定义 ClassLoader/字节码保护、或 JVM 不支持 retransform 时 hook 可能失效。

## 检测与防御

- **规则设计**：优先用允许列表（精确函数/类/协议/路径）而非子串黑名单；对命令执行同时 hook `Runtime.exec`、`ProcessBuilder.start`、`ProcessImpl`/`UNIXProcess` 的构造与 native wrapper，并对 `forkAndExec` 调用者做白名单。
- **配置管理**：`hook.json` 与 jar 同目录且权限最小化，防止被攻击者篡改；对配置变更做审计。
- **纵深**：RASP 之外仍需网络隔离、最小权限、及时打补丁；不要把它当作唯一安全边界。
- **检测信号**：JVM 启动参数出现 `-javaagent`/`-Xbootclasspath/a`；hook 类加载日志；RASP 抛出的 `SecurityException`；应用日志中异常的 `Illegal Deserialization Class`/`illegal expression`。
- **赛事运维**：先小流量验证白名单，避免误伤正常业务命令/SQL；赛后复盘被绕过的 sink，更新规则或改用更彻底的修复。
